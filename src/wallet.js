// BIP84 (native segwit, p2wpkh) HD wallet core.
//
// Derivation:  m / 84' / coin' / 0' / chain / index
//   chain 0 = receive (external) addresses
//   chain 1 = change  (internal) addresses
//
// All signing uses witnessUtxo only (script + amount). That is all segwit needs,
// which is what makes offline signing easy: we never have to fetch full previous
// transactions, only the (txid, vout, value, address) of each UTXO.

import { HDKey } from '@scure/bip32';
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { hex, base64urlnopad, base32nopad, base58check } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';
import { scrypt } from '@noble/hashes/scrypt';
import { randomBytes } from '@noble/hashes/utils';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { utf8ToBytes, bytesToUtf8 } from '@noble/ciphers/utils.js';
import * as btc from '@scure/btc-signer';
import { p2wpkh } from '@scure/btc-signer/payment';
import { concatBytes } from '@scure/btc-signer/utils.js';

import { Api, pool, getBackend, explorerWeb, electrumCandidates, spIndexerUrl } from './api.js';
import { ElectrumApi } from './electrum.js';
import { NostrSync, getSyncConfig, npubOf } from './nostr.js';
import { isSilentPaymentAddress, decodeSilentPaymentAddress, silentPaymentScripts, silentPaymentPlaceholder, deriveSilentPaymentKeys, encodeSilentPaymentAddress, silentPaymentScan, silentPaymentOutputPrivKey, silentPaymentCandidate, bloomHas } from './silentpay.js';
import { schnorr } from '@noble/curves/secp256k1';

// Resolve a same-origin '/path' WebSocket URL to an absolute ws(s):// URL against
// the page. The regtest backends are proxied through the dev server as relative
// paths (e.g. '/electrum') so the app works from a phone over the LAN/Tailscale;
// absolute URLs (real deployments, tests) pass through untouched.
function absWsUrl(u) {
  if (u && u[0] === '/' && typeof location !== 'undefined') {
    return (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + u;
  }
  return u;
}

// No look-ahead: stop scanning a chain at the first unused address. This wallet
// only ever exposes ONE unused address at a time (freshReceive = first unused;
// there is no "generate another address" button), so used addresses stay
// contiguous and there is never a gap to look past. Keeps scans tiny.
const GAP_LIMIT = 1;

// Extra pause after finding a used address, before querying the next index —
// keeps us gentle on the explorers' rate limits when a wallet has activity.
const USED_HIT_DELAY_MS = 500;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Silent-payment catch-up dust limit (sats): the indexer drops tweaks for txs
// whose taproot outputs are all below this, cutting the candidate math on a big
// scan. 0 = receive everything (default, so no small payment is ever missed).
const SP_DUST_LIMIT = 0;

const NETS = {
  mainnet: { net: btc.NETWORK, coin: 0 },
  testnet: { net: btc.TEST_NETWORK, coin: 1 },
  // mutinynet is a signet — same address format / version bytes / coin type as
  // testnet (`tb` HRP); only the chain + servers differ.
  mutinynet: { net: btc.TEST_NETWORK, coin: 1 },
  // Regtest shares testnet's version bytes / coin type; only the bech32 HRP
  // differs (`bcrt`). @scure/btc-signer derives addresses + validates from this.
  regtest: { net: { ...btc.TEST_NETWORK, bech32: 'bcrt' }, coin: 1 },
};

export function newMnemonic(strengthBits = 128) {
  return generateMnemonic(wordlist, strengthBits);
}

// The base localStorage cache key for a wallet identity (xpub, xprv, or
// seed-id) — mirrors Wallet#_cacheKey, so app code can target a specific
// account's cached state (e.g. to wipe it on log-out).
export function cacheKeyFor(id) {
  return 'btc-wallet-cache:' + hex.encode(sha256(new TextEncoder().encode(id))).slice(0, 32);
}

// Account-level xpub for a seed/key without constructing a Wallet — used to
// verify an entered recovery phrase matches a watch-only account before
// upgrading it to spendable.
export function accountXpubFor({ mnemonic, passphrase = '', xprv } = {}, netName = 'mainnet') {
  const { coin } = NETS[netName];
  let acct;
  if (xprv) {
    const node = HDKey.fromExtendedKey(xprv);
    acct = node.depth === 0 ? node.derive(`m/84'/${coin}'/0'`) : node;
  } else {
    acct = HDKey.fromMasterSeed(mnemonicToSeedSync(mnemonic, passphrase)).derive(`m/84'/${coin}'/0'`);
  }
  return acct.publicExtendedKey;
}

export function isValidMnemonic(m) {
  try {
    return validateMnemonic(m.trim().replace(/\s+/g, ' '), wordlist);
  } catch {
    return false;
  }
}

export class Wallet {
  constructor() {
    this.mnemonic = '';
    this.passphrase = '';
    this.netName = 'mainnet';
    // Feature-registered providers of coin ids to exclude from spending and
    // the spendable balance (e.g. coins reserved behind unclaimed gift links).
    this._coinLocks = [];

    this.api = new Api('mainnet');
    this.offline = false;

    // Scanned chains: arrays of { chain, index, address, used }
    this.receive = [];
    this.change = [];
    this.addrMap = new Map(); // address -> { chain, index }

    this.utxos = []; // { txid, vout, value, address, chain, index, confirmed }
    this.txs = []; // aggregated history
    this.feeRates = null;
    this.confirmed = 0;
    this.pending = 0;
    // Silent-payment (BIP-352) receiving: outputs we found by scanning the
    // indexer. Kept in their own bucket (one-time taproot keys, not BIP84
    // addresses); { txid, vout, value, confirmed, tweak, xonly, address }.
    this.spUtxos = [];
    this.lastSpScan = 0; // highest block height scanned for silent payments
    this.spScanning = false;

    this.scanning = false;
    this.loaded = false; // true once a scan/snapshot has populated balances once
    this.historyLoading = false; // history is still being fetched in the background
    this._refreshing = false; // a scan/refresh is in flight
    this.nextReceiveIndex = 0;
    this.nextChangeIndex = 0;

    this._account = null;
    this._accountKey = '';
    this._addrCache = new Map();

    // Realtime (mempool.space WebSocket)
    this.live = false;
    this._ws = null;
    this._wsWant = false;
    this._wsRetry = null;
    this._refreshTimer = null;
    this._pollTimer = null;
    this._deepTimer = null; // periodic full-scan safety net
    this._polling = false; // a light poll is in flight
    this._lastPoll = 0; // last frontier poll (throttles the adaptive poll timer)
    this._hbTimer = null; // heartbeat / liveness watchdog
    this._lastMsg = 0; // time of last WS message (incl. pong)
    this._wakeHooked = false;

    // Encrypted cross-device state sync over Nostr.
    this.nostr = new NostrSync();
    this._savedAt = 0;
    this._nostrPubTimer = null;

    this._subs = new Set();
  }

  // --- reactive glue (tiny pub/sub; the UI re-renders on change) ----------
  subscribe(fn) {
    this._subs.add(fn);
    return () => this._subs.delete(fn);
  }
  emit() {
    for (const fn of this._subs) fn(this);
  }

  // --- setup --------------------------------------------------------------
  load({ mnemonic = '', passphrase = '', xpub = '', xprv = '', netName = 'mainnet', offline = false, spFresh = false }) {
    this.stopRealtime();
    // A freshly-generated wallet can't have received silent payments before it
    // existed, so we start its SP watermark at the current tip (no history scan).
    this._spFresh = spFresh;
    this.mnemonic = (mnemonic || '').trim().replace(/\s+/g, ' ');
    this.passphrase = passphrase;
    this.xpub = xpub || '';
    this.xprv = xprv || ''; // spending wallet imported from an extended private key
    this.watchOnly = !!this.xpub && !this.mnemonic && !this.xprv; // view/receive only
    this.netName = netName;
    this.offline = offline;
    this._buildApi();
    this.api.offline = offline;
    this._account = null;
    this._accountKey = null;
    this._addrCache.clear();
    this._reserved = null; // gift coins set aside from spending (lazy-loaded)
    this._reclaimed = null; // gift coins freed for spending but link still live
    this._savedAt = 0;
    try {
      if (this.mnemonic) this.nostr.load(this.mnemonic, this.passphrase);
      else this.nostr.unload();
    } catch {}
    this.reset();
  }

  reset() {
    this.receive = [];
    this.change = [];
    this.addrMap = new Map();
    this.utxos = [];
    this.txs = [];
    this.confirmed = 0;
    this.pending = 0;
    this.spUtxos = [];
    this.lastSpScan = 0;
    this.loaded = false;
    this.nextReceiveIndex = 0;
    this.nextChangeIndex = 0;
  }

  setOffline(off) {
    this.offline = off;
    this.api.offline = off;
    if (off) this.stopRealtime();
    this.emit();
  }

  // Build the data backend for the current setting: Esplora REST (`Api`) or a
  // full Electrum-over-WS server (`ElectrumApi`), which routes its data calls
  // over this wallet's realtime socket via _rpcCall.
  _buildApi() {
    if (getBackend() === 'electrum') {
      this.api = new ElectrumApi({
        call: (m, p) => this._rpcCall(m, p),
        network: this.netCfg.net,
        testnet: this.netName !== 'mainnet',
        explorerWeb: explorerWeb(),
      });
    } else {
      this.api = new Api(this.netName);
    }
    this.api.offline = this.offline;
  }

  // Rebuild the backend against the current settings, then rescan and reconnect
  // realtime (called when the user switches explorer/backend in Settings).
  async reloadExplorer() {
    this.stopRealtime();
    this._buildApi();
    if (this.offline) return;
    // Electrum's data rides the socket, so connect first, then scan.
    if (getBackend() === 'electrum') this.startRealtime();
    try {
      await this.scan();
    } catch {}
    if (getBackend() !== 'electrum') this.startRealtime();
  }

  get netCfg() {
    return NETS[this.netName];
  }

  // --- derivation ---------------------------------------------------------
  account() {
    const { coin } = this.netCfg;
    // Cache key identifies the source so a reload rebuilds when it changes.
    const key = this.watchOnly ? 'pub:' + this.xpub
      : this.xprv ? 'prv:' + this.xprv
      : `${this.netName}|${this.mnemonic}|${this.passphrase}`;
    if (this._account && this._accountKey === key) return this._account;
    let acct;
    if (this.watchOnly) {
      acct = HDKey.fromExtendedKey(this.xpub); // account-level public key
    } else if (this.xprv) {
      // A master xprv (depth 0) needs the BIP84 account path derived from it;
      // an already account-level xprv is used as-is.
      const node = HDKey.fromExtendedKey(this.xprv);
      acct = node.depth === 0 ? node.derive(`m/84'/${coin}'/0'`) : node;
    } else {
      acct = HDKey.fromMasterSeed(mnemonicToSeedSync(this.mnemonic, this.passphrase)).derive(`m/84'/${coin}'/0'`);
    }
    this._account = acct;
    this._accountKey = key;
    this._addrCache.clear();
    return acct;
  }

  // The account-level extended public key (xpub / zpub) for export → watch-only.
  accountXpub() {
    return this.account().publicExtendedKey;
  }

  // BIP-352 scan/spend keys, derived from the master seed (m/352' paths) — so
  // they need the mnemonic (or a depth-0 master xprv); watch-only and account-
  // level imported keys can't do silent payments. Cached per account.
  silentPaymentKeys() {
    if (this.watchOnly) return null;
    const coin = NETS[this.netName].coin;
    const ck = `sp|${this.netName}|${this.mnemonic}|${this.passphrase}|${this.xprv}`;
    if (this._spKeys && this._spKeysKey === ck) return this._spKeys;
    let master = null;
    if (this.mnemonic) master = HDKey.fromMasterSeed(mnemonicToSeedSync(this.mnemonic, this.passphrase));
    else if (this.xprv) { const n = HDKey.fromExtendedKey(this.xprv); if (n.depth === 0) master = n; }
    this._spKeys = master ? deriveSilentPaymentKeys(master, coin) : null;
    this._spKeysKey = ck;
    this._spScanCache = new Map(); // per-tweak scan results are keyed to these keys
    this._spCandCache = new Map();
    return this._spKeys;
  }

  // Scan one tweak's outputs for our payments, memoized by tweak — the EC
  // point-multiplication is the cost, and a tweak's outcome never changes, so
  // repeated mempool pushes (which re-send the same tweaks) stay cheap.
  _spScan(tweakHex, outputs) {
    const keys = this.silentPaymentKeys(); // resets the caches if keys changed
    if (!keys) return [];
    let m = this._spScanCache.get(tweakHex);
    if (m) return m;
    if (this._spScanCache.size > 100000) this._spScanCache.clear(); // bound memory over long sessions
    m = silentPaymentScan({ scanPriv: keys.scanPriv, spendPub: keys.spendPub, tweak: hex.decode(tweakHex), outputs });
    this._spScanCache.set(tweakHex, m);
    return m;
  }

  // Our candidate key for a tweak (for the Bloom pre-filter), memoized likewise.
  _spCandidate(tweakHex) {
    const keys = this.silentPaymentKeys();
    if (!keys) return null;
    let c = this._spCandCache.get(tweakHex);
    if (c) return c;
    if (this._spCandCache.size > 100000) this._spCandCache.clear(); // bound memory over long sessions
    c = silentPaymentCandidate({ scanPriv: keys.scanPriv, spendPub: keys.spendPub, tweak: hex.decode(tweakHex) });
    this._spCandCache.set(tweakHex, c);
    return c;
  }

  // Spawn (once) the scanning worker and keep its keys current. Returns null if
  // workers are unavailable or the embedded bundle is missing — callers then fall
  // back to scanning on the main thread (still cached + yielding).
  _ensureSpWorker() {
    if (this._spWorkerFailed || typeof Worker === 'undefined') return null;
    const keys = this.silentPaymentKeys();
    if (!keys) return null;
    if (!this._spWorker) {
      try {
        const b64 = globalThis.__SP_WORKER__;
        if (!b64) { this._spWorkerFailed = true; return null; }
        const bytes = Uint8Array.from(atob(b64), (ch) => ch.charCodeAt(0));
        const w = new Worker(URL.createObjectURL(new Blob([bytes], { type: 'text/javascript' })));
        this._spPending = new Map();
        this._spReqId = 0;
        w.onmessage = (e) => { const p = this._spPending.get(e.data.id); if (p) { this._spPending.delete(e.data.id); e.data.error ? p.rej(new Error(e.data.error)) : p.res(e.data); } };
        w.onerror = () => { this._spWorkerFailed = true; try { w.terminate(); } catch {} this._spWorker = null; for (const p of this._spPending.values()) p.rej(new Error('sp worker error')); this._spPending.clear(); };
        this._spWorker = w;
        this._spWorkerKeysSig = null;
      } catch { this._spWorkerFailed = true; return null; }
    }
    if (this._spWorkerKeysSig !== this._spKeysKey) {
      this._spWorkerKeysSig = this._spKeysKey;
      this._spWorker.postMessage({ id: ++this._spReqId, op: 'keys', scanPriv: keys.scanPriv, spendPub: keys.spendPub });
    }
    return this._spWorker;
  }

  _spCall(op, data) {
    return new Promise((res, rej) => {
      const id = ++this._spReqId;
      this._spPending.set(id, { res, rej });
      this._spWorker.postMessage({ id, op, ...data });
      setTimeout(() => { if (this._spPending.has(id)) { this._spPending.delete(id); rej(new Error('sp worker timeout')); } }, 30000);
    });
  }

  // Block heights whose Bloom filter might hold one of our outputs (worker if
  // available, else a cached + yielding main-thread loop).
  async _spHitBlocks(blocks) {
    if (!blocks.length) return new Set();
    const w = this._ensureSpWorker();
    if (w) { try { return new Set((await this._spCall('candidates', { blocks })).hits || []); } catch {} }
    const hits = new Set();
    let i = 0;
    for (const b of blocks) {
      if (++i % 8 === 0) await new Promise((r) => setTimeout(r, 0));
      for (const tw of b.tweaks) { if (bloomHas(b.filter, this._spCandidate(tw))) { hits.add(b.height); break; } }
    }
    return hits;
  }

  // Full-scan items → our resolved utxos {txid,vout,value,xonly,tweak} (worker if
  // available, else a cached + yielding main-thread loop).
  async _spScanItems(items) {
    if (!items.length) return [];
    const w = this._ensureSpWorker();
    if (w) { try { return (await this._spCall('scan', { items })).found || []; } catch {} }
    const found = [];
    let i = 0;
    for (const it of items) {
      if (++i % 50 === 0) await new Promise((r) => setTimeout(r, 0));
      const matches = this._spScan(it.tweak, it.outputs.map((o) => o.xonly));
      for (const m of matches) { const o = it.outputs.find((x) => x.xonly === m.output); if (o) found.push({ txid: it.txid, vout: o.vout, value: o.value, xonly: m.output, tweak: m.tweak }); }
    }
    return found;
  }

  // Our silent-payment address (sp1…/tsp1…), or null if this wallet can't do SP.
  silentPaymentAddress() {
    const k = this.silentPaymentKeys();
    return k ? encodeSilentPaymentAddress(k.scanPub, k.spendPub, { testnet: this.netName !== 'mainnet' }) : null;
  }

  // True if addr is a valid on-chain address for this wallet's network.
  isOnchainAddress(addr) {
    try { btc.Address(this.netCfg.net).decode((addr || '').trim()); return true; } catch { return false; }
  }

  // Is SP receiving available here? (we can derive keys AND an indexer is set)
  silentPaymentsAvailable() {
    return !!(this.silentPaymentKeys() && spIndexerUrl(this.netName));
  }

  // Total received via silent payments: { confirmed, pending, count } over the
  // unspent SP outputs we've found.
  spBalance() {
    let confirmed = 0, pending = 0;
    for (const u of this.spUtxos) { if (u.confirmed) confirmed += u.value; else pending += u.value; }
    return { confirmed, pending, count: this.spUtxos.length };
  }

  // Received silent payments as history rows (one per tx; multiple outputs to us
  // sum into one received entry) so they appear in history like normal payments.
  spTxRows() {
    const byTx = new Map();
    for (const u of this.spUtxos) {
      const e = byTx.get(u.txid) || { txid: u.txid, net: 0, confirmed: true, firstSeen: u.firstSeen || Date.now() };
      e.net += u.value;
      if (!u.confirmed) e.confirmed = false;
      e.firstSeen = Math.min(e.firstSeen, u.firstSeen || e.firstSeen);
      byTx.set(u.txid, e);
    }
    return [...byTx.values()].map((e) => ({
      txid: e.txid, net: e.net, fee: 0, vsize: 0, sp: true,
      confirmed: e.confirmed,
      blockTime: e.confirmed ? Math.floor(e.firstSeen / 1000) : 0,
      blockHeight: 0,
      firstSeen: e.firstSeen,
    }));
  }

  // History for display: BIP84 txs + silent-payment receipts, newest first. (SP
  // receipts pay one-time taproot keys, never our BIP84 addresses, so no overlap.)
  get history() {
    const rows = [...this.txs, ...this.spTxRows()];
    rows.sort((a, b) => {
      if (a.confirmed !== b.confirmed) return a.confirmed ? 1 : -1; // pending first
      if (a.confirmed) return (b.blockTime || 0) - (a.blockTime || 0);
      return (b.firstSeen || 0) - (a.firstSeen || 0);
    });
    return rows;
  }

  // The taproot address for an x-only output key (for backend UTXO lookups).
  _spAddress(xonly) {
    return btc.Address(this.netCfg.net).encode(btc.OutScript.decode(btc.OutScript.encode({ type: 'tr', pubkey: hex.decode(xonly) })));
  }

  // Scan the configured SP indexer from the last-scanned height to the tip, find
  // outputs paying our scan/spend keys, and verify each is unspent via the chain
  // backend (the indexer only does discovery). Updates this.spUtxos.
  async scanSilentPayments({ rescan = false, silent = false } = {}) {
    const keys = this.silentPaymentKeys();
    const indexer = spIndexerUrl(this.netName);
    if (!keys || !indexer || this.offline) return { unavailable: true };
    if (this._spScanBusy) return { busy: true };
    // Fresh wallet, never scanned: set the watermark to the current tip instead of
    // scanning all history (nothing predates the wallet). New blocks + mempool
    // arrive via the live push from here on.
    if (this._spFresh && !this.lastSpScan && !rescan) {
      this._spFresh = false;
      try { this.lastSpScan = (await (await fetch(`${indexer}/height`)).json()).height || 0; this.saveCache(); } catch {}
      return { fresh: true };
    }
    this._spScanBusy = true;
    // Only a manual scan shows the visible "Scanning…" state; auto-scans are
    // invisible (setting spScanning for them left the card stuck on "Scanning…").
    if (!silent) { this.spScanning = true; this.emit(); }
    try {
      if (rescan) { this.spUtxos = []; this.lastSpScan = 0; }
      const from = (this.lastSpScan || 0) + 1;
      // Catch-up: per block we get tweaks + a Bloom filter (no outputs). Derive a
      // candidate key per tweak, test the filter, and only fetch the full block on
      // a hit — so most blocks cost just the candidate math, no download/scan.
      const res = await (await fetch(`${indexer}/scan/${from}?dustLimit=${SP_DUST_LIMIT}`)).json();
      const tip = res.tip || 0;
      const have = new Set(this.spUtxos.map((u) => `${u.txid}:${u.vout}`));
      const found = [];
      const hits = await this._spHitBlocks(res.blocks || []);
      for (const block of res.blocks || []) {
        if (!hits.has(block.height)) continue;
        const blk = await (await fetch(`${indexer}/block/${block.height}`)).json();
        for (const f of await this._spScanItems(blk.items || [])) {
          const id = `${f.txid}:${f.vout}`;
          if (have.has(id)) continue;
          have.add(id);
          found.push(f);
        }
      }
      if (tip > this.lastSpScan) this.lastSpScan = tip;
      // Verify newly-found outputs are unspent + get confirmation status.
      for (const f of found) {
        const address = this._spAddress(f.xonly);
        try {
          const us = await this.api.addressUtxos(address);
          const u = us.find((x) => x.txid === f.txid && x.vout === f.vout);
          if (u) this.spUtxos.push({ ...f, address, confirmed: !!(u.status && u.status.confirmed), firstSeen: Date.now() });
        } catch {}
      }
      await this._refreshSpUtxos();
      this._recomputeBalanceFromChains(); // fold found SP value into the displayed balance
      this.saveCache();
      return { found: found.length, scanned: tip };
    } finally {
      this._spScanBusy = false;
      this.spScanning = false;
      this.emit(); // always refresh (balance + clears any "Scanning…")
    }
  }

  // Re-check tracked SP outputs against the backend: drop spent ones, refresh
  // confirmation status.
  async _refreshSpUtxos() {
    const next = [];
    for (const u of this.spUtxos) {
      try {
        const us = await this.api.addressUtxos(u.address);
        const live = us.find((x) => x.txid === u.txid && x.vout === u.vout);
        if (live) next.push({ ...u, confirmed: !!(live.status && live.status.confirmed) });
      } catch { next.push(u); } // backend hiccup: keep as-is
    }
    this.spUtxos = next;
  }

  // Live silent-payment push: subscribe to the indexer's WebSocket so each new
  // block's SP items are scanned on arrival instead of polling. Catches up via a
  // /scan on connect (covers anything missed while disconnected) and reconnects.
  _spConnect() {
    if (this.offline) return;
    const base = spIndexerUrl(this.netName);
    if (!base || !this.silentPaymentKeys()) return;
    const url = base.replace(/^http/, 'ws') + '/ws';
    if (this._spWs && this._spWsUrl === url) return;
    this._spDisconnect();
    this._spWsUrl = url;
    let ws;
    try { ws = new WebSocket(absWsUrl(url)); } catch { return; }
    this._spWs = ws;
    ws.onopen = () => {
      this.spLive = true;
      this.scanSilentPayments({ silent: true }).catch(() => {}); // confirmed catch-up
      // Pending (mempool) catch-up.
      fetch(`${base}/mempool`).then((r) => r.json()).then((d) => this._scanSpMempool(d.items || [])).catch(() => {});
    };
    ws.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(typeof ev.data === 'string' ? ev.data : new TextDecoder().decode(ev.data)); } catch { return; }
      if (!msg || !Array.isArray(msg.items)) return;
      if (msg.type === 'block') this._scanSpItems(msg.items, msg.height).catch(() => {});
      else if (msg.type === 'mempool') this._scanSpMempool(msg.items).catch(() => {});
    };
    ws.onerror = () => { try { ws.close(); } catch {} };
    ws.onclose = () => {
      if (this._spWs !== ws) return;
      this.spLive = false; this._spWs = null;
      if (!this.offline) this._spReconnect = setTimeout(() => this._spConnect(), 3000);
    };
  }

  _spDisconnect() {
    clearTimeout(this._spReconnect);
    this.spLive = false;
    const ws = this._spWs;
    this._spWs = null; this._spWsUrl = null;
    if (ws) { try { ws.onclose = null; ws.close(); } catch {} }
  }

  // Scan a confirmed block's pushed items and upsert ours into spUtxos as
  // confirmed (a previously-pending mempool entry is promoted to confirmed).
  async _scanSpItems(items, height) {
    const keys = this.silentPaymentKeys();
    if (!keys) return;
    let changed = false;
    for (const f of await this._spScanItems(items)) {
      const existing = this.spUtxos.find((u) => u.txid === f.txid && u.vout === f.vout);
      if (existing) { if (!existing.confirmed) { existing.confirmed = true; changed = true; } }
      else { this.spUtxos.push({ txid: f.txid, vout: f.vout, value: f.value, xonly: f.xonly, tweak: f.tweak, address: this._spAddress(f.xonly), confirmed: true, firstSeen: Date.now() }); changed = true; }
    }
    if (height && height > this.lastSpScan) this.lastSpScan = height;
    if (changed) this._recomputeBalanceFromChains();
    this.saveCache();
    if (changed) this.emit();
  }

  // Scan the current mempool's pushed items and rebuild our pending (unconfirmed)
  // SP set — so payments show the moment they're broadcast. Confirmed entries are
  // kept; the unconfirmed set is replaced, which also drops vanished/RBF'd ones.
  async _scanSpMempool(items) {
    // Coalesce: pushes arrive faster than a cold (mainnet) scan completes, so
    // keep only the latest set and never run two scans at once.
    this._spMempoolLatest = items;
    if (this._spMempoolBusy) return;
    this._spMempoolBusy = true;
    try {
      if (!this.silentPaymentKeys()) return;
      while (this._spMempoolLatest) {
        const cur = this._spMempoolLatest;
        this._spMempoolLatest = null;
        const priorSeen = new Map(this.spUtxos.map((u) => [`${u.txid}:${u.vout}`, u.firstSeen]));
        const confirmedIds = new Set(this.spUtxos.filter((u) => u.confirmed).map((u) => `${u.txid}:${u.vout}`));
        const pending = [];
        for (const f of await this._spScanItems(cur)) {
          const id = `${f.txid}:${f.vout}`;
          if (confirmedIds.has(id)) continue;
          pending.push({ txid: f.txid, vout: f.vout, value: f.value, xonly: f.xonly, tweak: f.tweak, address: this._spAddress(f.xonly), confirmed: false, firstSeen: priorSeen.get(id) || Date.now() });
        }
        // Re-read confirmed (a block push may have landed during a yield) and drop
        // any pending that just confirmed, so an outpoint never appears twice.
        const confNow = this.spUtxos.filter((u) => u.confirmed);
        const confNowIds = new Set(confNow.map((u) => `${u.txid}:${u.vout}`));
        const oldPendingIds = new Set(this.spUtxos.filter((u) => !u.confirmed).map((u) => `${u.txid}:${u.vout}`));
        const freshPending = pending.filter((p) => !confNowIds.has(`${p.txid}:${p.vout}`));
        // Only emit when our pending set actually changed — the mempool churns
        // constantly, and a no-op emit would re-render and steal input focus.
        const changed = freshPending.length !== oldPendingIds.size || freshPending.some((p) => !oldPendingIds.has(`${p.txid}:${p.vout}`));
        this.spUtxos = [...confNow, ...freshPending];
        if (changed) { this._recomputeBalanceFromChains(); this.saveCache(); this.emit(); }
      }
    } finally {
      this._spMempoolBusy = false;
    }
  }

  node(chain, index) {
    // Relative derivation from the account node (chain/index are non-hardened).
    return this.account().deriveChild(chain).deriveChild(index);
  }

  // Returns { address, script, pubkey }
  derive(chain, index) {
    const cacheKey = `${chain}/${index}`;
    const hit = this._addrCache.get(cacheKey);
    if (hit) return hit;
    const node = this.node(chain, index);
    const pay = p2wpkh(node.publicKey, this.netCfg.net);
    const info = { address: pay.address, script: pay.script, pubkey: node.publicKey, chain, index };
    this._addrCache.set(cacheKey, info);
    return info;
  }

  // Derive a window of addresses on both chains and (re)build addrMap. Used in
  // offline mode where we cannot scan for usage but still must map a UTXO's
  // address back to its derivation path in order to sign it.
  deriveWindow(count) {
    this.addrMap = new Map();
    for (const chain of [0, 1]) {
      for (let i = 0; i < count; i++) {
        const { address } = this.derive(chain, i);
        this.addrMap.set(address, { chain, index: i });
      }
    }
  }

  // --- online scan --------------------------------------------------------
  // Query one address at a time; stop at the first unused one (no look-ahead).
  async scanChain(chain) {
    const found = [];
    let gap = 0;
    let i = 0;
    while (gap < GAP_LIMIT) {
      const { address } = this.derive(chain, i);
      const info = await this.api.addressInfo(address);
      const cs = info.chain_stats || {};
      const ms = info.mempool_stats || {};
      const used = (cs.tx_count || 0) > 0 || (ms.tx_count || 0) > 0;
      const hasMempool = (ms.tx_count || 0) > 0;
      // Balance straight from chain_stats — no need to fetch /utxo just to total.
      const confirmed = (cs.funded_txo_sum || 0) - (cs.spent_txo_sum || 0);
      const pending = (ms.funded_txo_sum || 0) - (ms.spent_txo_sum || 0);
      found.push({ chain, index: i, address, used, confirmed, pending, hasMempool });
      this.addrMap.set(address, { chain, index: i });
      if (used) {
        gap = 0;
        await sleep(USED_HIT_DELAY_MS); // slow down before fetching the next one
      } else {
        gap += 1;
      }
      i++;
    }
    return found;
  }

  // A short signature of the user-visible state, so background ("silent")
  // refreshes only re-render when something actually changed.
  _sig() {
    return JSON.stringify({
      bc: this.confirmed,
      bp: this.pending,
      u: this.utxos.map((u) => `${u.txid}:${u.vout}:${u.value}:${u.confirmed ? 1 : 0}`),
      t: this.txs.map((t) => `${t.txid}:${t.confirmed ? 1 : 0}`),
      r: this.nextReceiveIndex,
      c: this.nextChangeIndex,
    });
  }

  _addrInfo(chain, index) {
    const arr = chain === 0 ? this.receive : this.change;
    return arr.find((a) => a.index === index);
  }

  // Light poll: only check the fresh frontier — the next receive and change
  // address — for new activity. Already-scanned addresses are never re-polled;
  // changes to them (spends) arrive over the WebSocket while connected, and a
  // manual rescan covers anything missed (e.g. address reuse). If the frontier
  // moved, escalate to a full scan once to reconcile.
  async refreshLive() {
    if (this.offline || this._refreshing || this._polling) return;
    this._polling = true;
    this._lastPoll = Date.now(); // any refresh (poll OR socket-open) resets the
    // poll clock, so the two don't both fire back-to-back on load.
    let changed = false;
    try {
      const fresh = []; // frontier addresses found to be active this pass
      for (const chain of [0, 1]) {
        let idx = chain === 0 ? this.nextReceiveIndex : this.nextChangeIndex;
        // Walk forward from the frontier while addresses are used; stop at the
        // first unused one. Never revisits already-passed (cached) addresses.
        for (let guard = 0; guard < 100; guard++) {
          const { address } = this.derive(chain, idx);
          const info = await this.api.addressInfo(address);
          const cs = info.chain_stats || {};
          const ms = info.mempool_stats || {};
          const used = (cs.tx_count || 0) > 0 || (ms.tx_count || 0) > 0;
          const confirmed = (cs.funded_txo_sum || 0) - (cs.spent_txo_sum || 0);
          const pending = (ms.funded_txo_sum || 0) - (ms.spent_txo_sum || 0);

          const arr = chain === 0 ? this.receive : this.change;
          let entry = arr.find((a) => a.index === idx);
          if (!entry) {
            entry = { chain, index: idx, address };
            arr.push(entry);
            this.addrMap.set(address, { chain, index: idx });
          }
          if (entry.used !== used || entry.confirmed !== confirmed || entry.pending !== pending) {
            changed = true;
            if (used) fresh.push({ chain, index: idx, address });
          }
          entry.used = used;
          entry.confirmed = confirmed;
          entry.pending = pending;

          if (!used) break; // frontier still fresh — done with this chain
          idx++;
        }
        if (chain === 0) this.nextReceiveIndex = idx;
        else this.nextChangeIndex = idx;
      }

      // Fetch coins + history for ONLY the newly-active frontier addresses.
      for (const a of fresh) {
        const us = await this.api.addressUtxos(a.address);
        this.utxos = this.utxos.filter((u) => u.address !== a.address);
        for (const u of us) {
          this.utxos.push({
            txid: u.txid,
            vout: u.vout,
            value: u.value,
            address: a.address,
            chain: a.chain,
            index: a.index,
            confirmed: !!u.status.confirmed,
          });
        }
        const list = await this.api.addressTxs(a.address);
        for (const tx of list) {
          const summary = this._txSummary(tx);
          const at = this.txs.findIndex((t) => t.txid === tx.txid);
          // Refresh in place so a tx that has since confirmed loses its pending
          // status — not just append new ones (which left confirmations stale).
          if (at >= 0) this.txs[at] = summary;
          else this.txs.push(summary);
        }
      }

      // Re-verify the addresses that currently hold coins, to catch spends from
      // an already-scanned address (the frontier walk above only looks forward,
      // so a coin spent here — including by a tx broadcast on another device —
      // would otherwise never reconcile without a full rescan).
      if (await this._reconcileHeld()) changed = true;

      if (changed) {
        this.utxos.sort((x, y) => y.value - x.value);
        this._sortTxs();
        this._recomputeBalanceFromChains();
        this.loaded = true;
        this.saveCache();
        this.retrack(); // a new pending coin may have changed the watched set
        this.emit();
      }
    } catch {
      /* transient; next poll/ws retries */
    } finally {
      this._polling = false;
    }
  }

  // Enable/disable fast polling of the fresh receive address — set while the
  // Receive tab is open so a deposit shows near-instantly even if the WS doesn't
  // push it. Toggling on triggers an immediate check.
  setWatchReceive(on) {
    on = !!on;
    if (on === !!this._watchReceive) return; // no change — avoid re-triggering
    this._watchReceive = on;
    if (on) { this._lastReceivePoll = 0; this.pollReceiveFrontier(); }
  }

  // Cheap single-address check of the next receive address. If it has activity,
  // hand off to the full refreshLive (which pulls the coin + history and advances
  // the frontier); otherwise do nothing. One request per call.
  async pollReceiveFrontier() {
    if (this.offline || this._polling || this._refreshing) return;
    const idx = this.nextReceiveIndex;
    const { address } = this.derive(0, idx);
    try {
      const info = await this.api.addressInfo(address);
      const cs = info.chain_stats || {};
      const ms = info.mempool_stats || {};
      const used = (cs.tx_count || 0) > 0 || (ms.tx_count || 0) > 0;
      if (used) await this.refreshLive();
    } catch {
      /* transient; next tick retries */
    }
  }

  // Re-check every address that currently holds a UTXO: refresh its balance from
  // chain/mempool stats and rebuild its UTXOs. This is what reconciles spends
  // (a held coin that's now gone) — confirmed or still in the mempool, regardless
  // of which device broadcast the spending transaction. Returns true if anything
  // changed. Only touches addresses we already know, so it stays cheap.
  async _reconcileHeld() {
    const addrs = [...new Set(this.utxos.map((u) => u.address))];
    let changed = false;
    for (const address of addrs) {
      const p = this.addrMap.get(address);
      if (!p) continue;
      let info;
      try {
        info = await this.api.addressInfo(address);
      } catch {
        continue;
      }
      const cs = info.chain_stats || {};
      const ms = info.mempool_stats || {};
      const confirmed = (cs.funded_txo_sum || 0) - (cs.spent_txo_sum || 0);
      const pending = (ms.funded_txo_sum || 0) - (ms.spent_txo_sum || 0);
      const arr = p.chain === 0 ? this.receive : this.change;
      const entry = arr.find((e) => e.index === p.index);
      if (entry && entry.confirmed === confirmed && entry.pending === pending) continue;

      let us;
      try {
        us = await this.api.addressUtxos(address);
      } catch {
        continue;
      }
      // Derive the entry's balance from the ACTUAL unspent coins, not from
      // get_balance/address-stats: a confirmed coin that's being spent by an
      // unconfirmed tx still shows as "confirmed" there (with a compensating
      // negative unconfirmed), so trusting it would keep a just-spent coin in the
      // headline balance on another device. listunspent excludes spent coins.
      this.utxos = this.utxos.filter((u) => u.address !== address);
      let eConf = 0, ePend = 0;
      for (const u of us) {
        const conf = !!(u.status && u.status.confirmed);
        if (conf) eConf += u.value; else ePend += u.value;
        this.utxos.push({ txid: u.txid, vout: u.vout, value: u.value, address, chain: p.chain, index: p.index, confirmed: conf });
      }
      if (entry) { entry.confirmed = eConf; entry.pending = ePend; }
      // Also refresh this address's tx history so a pending→confirmed transition
      // shows in History on the next poll — not only via the realtime push,
      // which regtest / custom-explorer (non-WS) backends don't have.
      try {
        const list = await this.api.addressTxs(address);
        for (const tx of list) {
          const summary = this._txSummary(tx);
          const at = this.txs.findIndex((t) => t.txid === tx.txid);
          if (at >= 0) this.txs[at] = summary; else this.txs.push(summary);
        }
      } catch {}
      changed = true;
    }
    return changed;
  }

  // Every address the wallet currently knows about (scanned receive + change),
  // sorted by chain then index, for the per-address rescan list in Settings.
  knownAddresses() {
    const mk = (e, chain) => ({ chain, index: e.index, address: e.address, used: !!e.used, balance: (e.confirmed || 0) + (e.pending || 0) });
    return [
      ...this.receive.map((e) => mk(e, 0)),
      ...this.change.map((e) => mk(e, 1)),
    ].sort((a, b) => a.chain - b.chain || a.index - b.index);
  }

  // Re-query a single address and reconcile just its coins/history into state —
  // the targeted alternative to a full rescan, for recovering a deposit to a
  // reused old address. Returns whether the address is used.
  async rescanAddress(chain, index) {
    const { address } = this.derive(chain, index);
    const info = await this.api.addressInfo(address);
    const cs = info.chain_stats || {};
    const ms = info.mempool_stats || {};
    const used = (cs.tx_count || 0) > 0 || (ms.tx_count || 0) > 0;
    const confirmed = (cs.funded_txo_sum || 0) - (cs.spent_txo_sum || 0);
    const pending = (ms.funded_txo_sum || 0) - (ms.spent_txo_sum || 0);

    const arr = chain === 0 ? this.receive : this.change;
    let entry = arr.find((e) => e.index === index);
    if (!entry) { entry = { chain, index, address }; arr.push(entry); arr.sort((a, b) => a.index - b.index); }
    this.addrMap.set(address, { chain, index });
    entry.used = used;
    entry.confirmed = confirmed;
    entry.pending = pending;

    const us = await this.api.addressUtxos(address);
    this.utxos = this.utxos.filter((u) => u.address !== address);
    for (const u of us) this.utxos.push({ txid: u.txid, vout: u.vout, value: u.value, address, chain, index, confirmed: !!u.status.confirmed });

    const list = await this.api.addressTxs(address);
    for (const tx of list) {
      const summary = this._txSummary(tx);
      const at = this.txs.findIndex((t) => t.txid === tx.txid);
      if (at >= 0) this.txs[at] = summary;
      else this.txs.push(summary);
    }

    this.nextReceiveIndex = firstUnused(this.receive);
    this.nextChangeIndex = firstUnused(this.change);
    this.utxos.sort((x, y) => y.value - x.value);
    this._sortTxs();
    this._recomputeBalanceFromChains();
    this.loaded = true;
    this.saveCache();
    this.retrack(); // watch this address over the socket if its coin is pending
    this.emit();
    return used;
  }

  // silent=false: foreground load (shows loading state, always re-renders).
  // silent=true:  background refresh (poll / WS) — no spinner, and only emits
  //               if the visible state changed, so it never disrupts typing.
  async scan({ silent = false } = {}) {
    if (this.offline || this._refreshing) return;
    this._refreshing = true;
    const before = silent ? this._sig() : null;
    if (!silent) {
      this.scanning = true;
      this.emit();
    }
    try {
      const prevBal = `${this.confirmed}|${this.pending}|${this.nextReceiveIndex}|${this.nextChangeIndex}`;
      this.addrMap = new Map();
      // Probe both chains at once — they're independent, so interleaving lets
      // their per-hit delays overlap instead of running back-to-back.
      const [receive, change] = await Promise.all([this.scanChain(0), this.scanChain(1)]);
      this.receive = receive;
      this.change = change;
      this.nextReceiveIndex = firstUnused(this.receive);
      this.nextChangeIndex = firstUnused(this.change);
      this._recomputeBalanceFromChains();

      // Only pull /utxo and /txs (the heavy part) on first load or when the
      // balance/addresses actually changed. Idle polls stay /address-only.
      const balanceChanged =
        `${this.confirmed}|${this.pending}|${this.nextReceiveIndex}|${this.nextChangeIndex}` !== prevBal;
      // Always re-pull history while any tx is still pending, so confirmations
      // get reconciled even when the balance itself hasn't changed (e.g. a
      // received coin that simply moved from mempool to a block).
      const hasPending = this.txs.some((t) => !t.confirmed);
      if (!silent || balanceChanged || !this.loaded || hasPending) {
        // Balance + receive address are already known from the chain_stats above.
        // Show them right away so the wallet looks ready, then keep loading the
        // heavier UTXO set and full history in the background.
        if (!silent) {
          this.loaded = true;
          this.historyLoading = true;
          this.emit();
        }
        if (!silent || !this.feeRates) this.feeRates = await this.api.feeRates();
        await this.refreshUtxos();
        await this.refreshHistory(!silent);
      }
      this.loaded = true;
      this.saveCache();
      this.scanSilentPayments({ silent: true }).catch(() => {}); // fold in any silent-payment receipts
    } finally {
      this._refreshing = false;
      this.historyLoading = false; // clear even if an earlier step threw
      if (!silent) {
        this.scanning = false;
        this.emit();
      } else if (this._sig() !== before) {
        this.emit();
      }
    }
  }

  usedAddresses() {
    return [...this.receive, ...this.change].filter((a) => a.used);
  }

  async refreshUtxos() {
    // An address whose confirmed balance is 0 and which has no mempool activity
    // is fully spent and settled — it cannot hold any UTXOs, so skip the /utxo
    // round-trip for it. In a wallet with history most addresses are spent, so
    // this avoids the bulk of the requests (and the 429s that come with them).
    const used = this.usedAddresses().filter(
      (a) => (a.confirmed || 0) > 0 || a.hasMempool
    );
    const lists = await pool(used, (a) => this.api.addressUtxos(a.address));
    const utxos = [];
    used.forEach((a, idx) => {
      for (const u of lists[idx]) {
        utxos.push({
          txid: u.txid,
          vout: u.vout,
          value: u.value,
          address: a.address,
          chain: a.chain,
          index: a.index,
          confirmed: !!u.status.confirmed,
        });
      }
    });
    utxos.sort((a, b) => b.value - a.value);
    this.utxos = utxos;
  }

  // Summarize a raw esplora tx into our history shape (net to us, fee, status).
  _txSummary(tx) {
    const mine = new Set(this.addrMap.keys());
    let received = 0;
    let sent = 0;
    for (const vin of tx.vin || []) {
      const a = vin.prevout && vin.prevout.scriptpubkey_address;
      if (a && mine.has(a)) sent += vin.prevout.value;
    }
    for (const vout of tx.vout || []) {
      if (vout.scriptpubkey_address && mine.has(vout.scriptpubkey_address)) received += vout.value;
    }
    const confirmed = !!(tx.status && tx.status.confirmed);
    // Preserve when we first saw it pending, so we can later judge a stuck tx.
    const prior = this.txs.find((t) => t.txid === tx.txid);
    // A tx we built + broadcast (local) already has the true net + fee from
    // applySentTx; don't recompute them — a rescan can under-count inputs whose
    // address isn't on the scanned frontier (e.g. a swap-claim coin), which would
    // understate the amount sent. Only the confirmation status changes.
    const local = !!(prior && prior.local);
    return {
      txid: tx.txid,
      net: local ? prior.net : received - sent, // >0 incoming, <0 outgoing
      fee: local && prior.fee ? prior.fee : tx.fee || 0,
      vsize: tx.weight ? Math.ceil(tx.weight / 4) : (prior && prior.vsize) || 0,
      confirmed,
      blockTime: (tx.status && tx.status.block_time) || 0,
      blockHeight: (tx.status && tx.status.block_height) || 0,
      firstSeen: confirmed ? 0 : (prior && prior.firstSeen) || Date.now(),
      local,
    };
  }

  // A pending tx is "stuck" once it's waited ~10 blocks (≈100 min) and its fee
  // rate is below the mempool's current floor (minimumFee) — i.e. it's been
  // purged and won't confirm without a bump (RBF/CPFP). We stop actively
  // monitoring these (no socket slot, no fast poll); the slow reconcile still
  // picks it up if the floor later drops and it confirms after all.
  isStuck(tx) {
    if (!tx || tx.confirmed || !tx.firstSeen || !tx.vsize) return false;
    if (Date.now() - tx.firstSeen < 100 * 60000) return false; // give it ~10 blocks
    const floor = (this.feeRates && this.feeRates.minimumFee) || 1;
    return tx.fee / tx.vsize < floor;
  }
  _stuckTxids() {
    const s = new Set();
    for (const tx of this.txs) if (this.isStuck(tx)) s.add(tx.txid);
    return s;
  }

  _sortTxs() {
    this.txs.sort((a, b) => {
      if (a.confirmed !== b.confirmed) return a.confirmed ? 1 : -1; // pending first
      // Pending txs share blockTime 0, so order them by when we first saw them
      // (newest on top); confirmed txs go by block time (newest on top).
      if (!a.confirmed) return (b.firstSeen || 0) - (a.firstSeen || 0);
      return (b.blockTime || 0) - (a.blockTime || 0);
    });
  }

  // progressive: emit after each address resolves so the History tab fills in
  // as transactions arrive (foreground load) instead of all at once at the end.
  async refreshHistory(progressive = false) {
    const used = this.usedAddresses();
    this.historyLoading = true;
    const seen = new Set(); // txids found in this pass (a tx can touch >1 address)
    try {
      await pool(used, async (a) => {
        const list = await this.api.addressTxs(a.address);
        let added = false;
        for (const tx of list) {
          if (seen.has(tx.txid)) continue;
          seen.add(tx.txid);
          const summary = this._txSummary(tx);
          const at = this.txs.findIndex((t) => t.txid === tx.txid);
          if (at >= 0) this.txs[at] = summary; // refresh confirmations/fee
          else { this.txs.push(summary); added = true; }
        }
        if (added && progressive) {
          this._sortTxs();
          this.emit();
        }
      });
      // Drop anything that no longer appears in any address's history.
      this.txs = this.txs.filter((t) => seen.has(t.txid));
      this._sortTxs();
    } finally {
      this.historyLoading = false;
    }
  }

  // --- balances -----------------------------------------------------------
  // confirmed/pending are plain fields, set from chain_stats during scan (and
  // from UTXOs when restoring an offline snapshot). total is derived.
  get total() {
    return this.confirmed + this.pending;
  }

  // The spendable headline: confirmed coins plus our own unconfirmed change (the
  // remainder of a spend we just made, so the spend debits immediately), minus
  // anything locked in gifts. Unconfirmed *incoming* receives are NOT counted
  // here — they show as pending until they confirm.
  get spendable() {
    const res = this.lockedCoinIds();
    return this.utxos.reduce((s, u) => {
      if (res.has(utxoId(u))) return s;
      if (u.confirmed || u.chain === 1) return s + u.value;
      return s;
    }, 0) + this.spBalance().confirmed; // confirmed silent-payment receipts are spendable
  }
  // Unconfirmed incoming receives (not our change, not gift-locked) — shown as a
  // separate pending line, kept out of the spendable headline. Includes pending
  // (mempool) silent-payment receipts.
  get pendingIncoming() {
    const res = this.lockedCoinIds();
    return this.utxos.reduce((s, u) => s + ((!u.confirmed && u.chain === 0 && !res.has(utxoId(u))) ? u.value : 0), 0) + this.spBalance().pending;
  }

  _recomputeBalanceFromChains() {
    let c = 0;
    let p = 0;
    for (const a of [...this.receive, ...this.change]) {
      c += a.confirmed || 0;
      p += a.pending || 0;
    }
    const sp = this.spBalance();
    this.confirmed = c + sp.confirmed;
    this.pending = p + sp.pending;
  }

  _recomputeBalanceFromUtxos() {
    const sp = this.spBalance();
    this.confirmed = this.utxos.reduce((s, u) => s + (u.confirmed ? u.value : 0), 0) + sp.confirmed;
    this.pending = this.utxos.reduce((s, u) => s + (u.confirmed ? 0 : u.value), 0) + sp.pending;
  }

  freshReceive() {
    return this.derive(0, this.nextReceiveIndex);
  }
  freshChange() {
    return this.derive(1, this.nextChangeIndex);
  }

  // --- spending -----------------------------------------------------------
  // recipients: [{ address, amount(sats) }]
  // coinIds: optional array of "txid:vout" to force manual coin control.
  // sendMax: drain all selected coins to the single recipient.
  buildTx({ recipients, feeRate, coinIds = null, sendMax = false, noSort = false }) {
    const pool_ = coinIds
      ? this.utxos.filter((u) => coinIds.includes(utxoId(u)))
      : (() => { const locked = this.lockedCoinIds(); return this.utxos.filter((u) => !locked.has(utxoId(u))); })(); // skip locked coins (gift reservations, ...)
    // Received silent-payment outputs are spendable too — one-time taproot keys,
    // signed by sign() with the per-output key. Excluded when paying an sp1…
    // recipient (funding an SP send from a taproot input needs BIP-352 even-Y
    // key handling we don't do yet), so those sends use BIP84 coins.
    // Confirmed SP coins are spendable like any other coin — including to fund a
    // silent payment. Unconfirmed ones are excluded (the sender's tx could be
    // replaced, invalidating our spend).
    const confirmedSp = this.spUtxos.filter((u) => u.confirmed);
    const spPool = coinIds ? confirmedSp.filter((u) => coinIds.includes(utxoId(u))) : confirmedSp.slice();
    if (!pool_.length && !spPool.length) throw new Error('No spendable coins selected.');

    const inputs = [
      ...pool_.map((u) => {
        const { pubkey } = this.derive(u.chain, u.index);
        const pay = p2wpkh(pubkey, this.netCfg.net);
        return {
          ...pay,
          txid: u.txid,
          index: u.vout,
          sequence: 0xfffffffd, // signal opt-in RBF (BIP125) so sends are bumpable
          witnessUtxo: { script: pay.script, amount: BigInt(u.value) },
        };
      }),
      ...spPool.map((u) => ({
        txid: u.txid,
        index: u.vout,
        sequence: 0xfffffffd,
        witnessUtxo: { script: btc.OutScript.encode({ type: 'tr', pubkey: hex.decode(u.xonly) }), amount: BigInt(u.value) },
        // Present so the fee estimator sizes a key-path (64-byte) witness; the
        // value is unused (SP outputs are signed raw in sign(), via tapKeySig).
        tapInternalKey: hex.decode(u.xonly),
      })),
    ];

    const changeAddress = this.freshChange().address;
    const feePerByte = BigInt(Math.max(1, Math.round(feeRate)));

    // Silent payment (sp1…) recipients: the real taproot output can only be
    // derived once coin selection fixes the input set (it commits to every
    // input), so we select against a same-size placeholder taproot output and
    // swap in the derived script afterward.
    const spOuts = []; // { placeholder, scan, spend }
    if (recipients.some((r) => isSilentPaymentAddress(r.address)) && this.watchOnly)
      throw new Error('Silent payments require a wallet with keys.');

    if (sendMax) {
      if (recipients.length !== 1)
        throw new Error('Send-max requires exactly one recipient.');
      // Drain everything: use the recipient as the "change" address with no
      // fixed outputs, so the estimator sends (total − exact fee) to them.
      let dest = recipients[0].address;
      if (isSilentPaymentAddress(dest)) {
        const { scan, spend } = decodeSilentPaymentAddress(dest);
        const placeholder = silentPaymentPlaceholder(0);
        spOuts.push({ placeholder, scan, spend, address: dest });
        dest = btc.Address(this.netCfg.net).encode(btc.OutScript.decode(placeholder));
      }
      const sel = btc.selectUTXO(inputs, [], 'all', {
        changeAddress: dest,
        feePerByte,
        network: this.netCfg.net,
        createTx: true,
        bip69: true,
        disableScriptCheck: true,
      });
      if (!sel || !sel.tx) throw new Error('Fee exceeds balance.');
      if (spOuts.length) this._applySilentPayments(sel.tx, spOuts);
      const sweepSummary = summarize(sel, this.netCfg.net);
      this._tagSilentOutputs(sweepSummary, spOuts);
      return sweepSummary;
    }

    const outputs = recipients.map((r) => {
      if (isSilentPaymentAddress(r.address)) {
        const { scan, spend } = decodeSilentPaymentAddress(r.address);
        const placeholder = silentPaymentPlaceholder(spOuts.length);
        spOuts.push({ placeholder, scan, spend, address: r.address });
        return { script: placeholder, amount: BigInt(r.amount) };
      }
      return { address: r.address, amount: BigInt(r.amount) };
    });
    const strategy = coinIds ? 'all' : 'default';
    const sel = btc.selectUTXO(inputs, outputs, strategy, {
      changeAddress,
      feePerByte,
      network: this.netCfg.net,
      createTx: true,
        // noSort keeps recipients at their given indexes (change appended last) —
        // required when an output's position is protocol-relevant (Ark board
        // funding must sit at vout 0).
        bip69: !noSort,
        disableScriptCheck: true,
    });
    if (!sel || !sel.tx)
      throw new Error('Insufficient funds for amount + fee.');
    if (spOuts.length) this._applySilentPayments(sel.tx, spOuts);
    const summary = summarize(sel, this.netCfg.net);
    this._tagSilentOutputs(summary, spOuts);
    return summary;
  }

  // Mark summary outputs that fund a silent payment with the sp1… address the
  // user actually typed (the on-chain output is a derived one-time taproot addr).
  _tagSilentOutputs(summary, spOuts) {
    for (const s of spOuts) {
      if (!s.derivedAddress) continue;
      const o = summary.outputs.find((o) => o.address === s.derivedAddress && !o.silent);
      if (o) o.silent = s.address;
    }
  }

  // Replace each placeholder silent-payment output in a freshly-selected (still
  // unsigned) tx with its real one-time taproot script, derived from the tx's
  // actual inputs per BIP-352.
  _applySilentPayments(tx, spOuts) {
    const byOutpoint = new Map();
    for (const u of this.utxos) byOutpoint.set(utxoId(u), { u, sp: false });
    for (const u of this.spUtxos) byOutpoint.set(utxoId(u), { u, sp: true });
    const spKeys = this.silentPaymentKeys();
    const inputs = [];
    for (let i = 0; i < tx.inputsLength; i++) {
      const inp = tx.getInput(i);
      const e = byOutpoint.get(`${hex.encode(inp.txid)}:${inp.index}`);
      if (!e) throw new Error('Missing key for a silent payment input.');
      // Our own SP coins can fund a silent payment too — they're taproot inputs
      // whose key is d = spend_priv + t_k (committed to with even Y by the script).
      if (e.sp) {
        if (!spKeys) throw new Error('Missing keys for a silent payment input.');
        inputs.push({ txid: e.u.txid, vout: e.u.vout, priv: silentPaymentOutputPrivKey(spKeys.spendPriv, hex.decode(e.u.tweak)), taproot: true });
      } else {
        inputs.push({ txid: e.u.txid, vout: e.u.vout, priv: this.node(e.u.chain, e.u.index).privateKey });
      }
    }
    const scripts = silentPaymentScripts(inputs, spOuts.map((s) => ({ scan: s.scan, spend: s.spend })));
    spOuts.forEach((s, k) => {
      const ph = hex.encode(s.placeholder);
      const idx = tx.outputs.findIndex((o) => hex.encode(o.script) === ph);
      if (idx < 0) throw new Error('Silent payment output not found after selection.');
      tx.updateOutput(idx, { script: scripts[k], amount: tx.outputs[idx].amount }, true);
      s.derivedAddress = btc.Address(this.netCfg.net).encode(btc.OutScript.decode(scripts[k]));
    });
  }

  // True if a built tx spends any of our still-unconfirmed coins — meaning it
  // can't confirm until that parent (ancestor) transaction confirms first.
  spendsUnconfirmed(tx) {
    const pending = new Set(this.utxos.filter((u) => !u.confirmed).map((u) => utxoId(u)));
    if (!pending.size) return false;
    for (let i = 0; i < tx.inputsLength; i++) {
      const inp = tx.getInput(i);
      if (pending.has(`${hex.encode(inp.txid)}:${inp.index}`)) return true;
    }
    return false;
  }

  // Sign every input of an already-built Transaction. BIP84 inputs sign with the
  // matching HD key; received silent-payment outputs are taproot key-path spends
  // signed manually with d = spend_priv + t_k (the output key is used raw, with
  // no BIP-341 tweak, so btc-signer's auto key-path signing doesn't apply).
  sign(tx) {
    if (this.watchOnly) throw new Error('Watch-only wallet — no keys to sign with.');
    const bip84 = new Map();
    for (const u of this.utxos) bip84.set(utxoId(u), u);
    const sp = new Map();
    for (const u of this.spUtxos) sp.set(utxoId(u), u);
    // Prevout scripts + amounts for any taproot (SP) sighash.
    const prevScripts = [];
    const amounts = [];
    for (let i = 0; i < tx.inputsLength; i++) {
      const w = tx.getInput(i).witnessUtxo;
      prevScripts.push(w.script);
      amounts.push(w.amount);
    }
    const spKeys = sp.size ? this.silentPaymentKeys() : null;
    for (let i = 0; i < tx.inputsLength; i++) {
      const inp = tx.getInput(i);
      const id = `${hex.encode(inp.txid)}:${inp.index}`;
      if (bip84.has(id)) {
        const u = bip84.get(id);
        tx.signIdx(this.node(u.chain, u.index).privateKey, i);
      } else if (sp.has(id)) {
        const u = sp.get(id);
        const d = silentPaymentOutputPrivKey(spKeys.spendPriv, hex.decode(u.tweak));
        const hash = tx.preimageWitnessV1(i, prevScripts, btc.SigHash.DEFAULT, amounts);
        tx.updateInput(i, { tapKeySig: schnorr.sign(hash, d) }, true);
      } else {
        throw new Error(`Cannot find key for input ${id}`);
      }
    }
    tx.finalize();
    return tx.hex;
  }

  async broadcast(hexTx) {
    return this.api.broadcast(hexTx);
  }

  // Parse a raw (signed) transaction hex — used by scan-to-broadcast to show a
  // confirmation (txid + outputs) before relaying someone's exported tx.
  parseRawTx(rawHex) {
    const tx = btc.Transaction.fromRaw(hex.decode(rawHex.trim()), { allowUnknownOutputs: true });
    const network = NETS[this.netName].net;
    const outputs = [];
    let total = 0;
    for (let i = 0; i < tx.outputsLength; i++) {
      const o = tx.getOutput(i);
      total += Number(o.amount);
      let address = '';
      try {
        address = btc.Address(network).encode(btc.OutScript.decode(o.script));
      } catch {}
      outputs.push({ address, value: Number(o.amount) });
    }
    return { txid: tx.id, total, outputs };
  }

  // RBF fee bumping, in three steps so the UI can preview a fee per rate before
  // building: prepareBump() fetches + reconstructs the original (async), then
  // planBump()/buildBump() are pure and reuse that prep.

  // Fetch an unconfirmed outgoing tx and reconstruct what's needed to replace it.
  async prepareBump(origTxid) {
    const orig = await this.api.getTx(origTxid);
    if (orig.status && orig.status.confirmed) throw new Error('Transaction already confirmed.');

    const ins = [];
    let totalIn = 0;
    for (const vin of orig.vin || []) {
      const a = vin.prevout && vin.prevout.scriptpubkey_address;
      const p = a && this.addrMap.get(a);
      if (!p) throw new Error('Can only bump your own transactions.');
      totalIn += vin.prevout.value;
      ins.push({ txid: vin.txid, vout: vin.vout, value: vin.prevout.value, chain: p.chain, index: p.index });
    }

    // Our first change-chain output is the change we'll shrink; the rest are
    // recipients and stay fixed.
    const recipients = [];
    let outTotal = 0;
    let changeSeen = false;
    for (const o of orig.vout || []) {
      outTotal += o.value;
      const p = o.scriptpubkey_address && this.addrMap.get(o.scriptpubkey_address);
      if (p && p.chain === 1 && !changeSeen) { changeSeen = true; continue; }
      recipients.push({ address: o.scriptpubkey_address, value: o.value });
    }
    const usedIds = new Set(ins.map((i) => `${i.txid}:${i.vout}`));
    const spare = this.utxos.filter((u) => u.confirmed && !usedIds.has(utxoId(u)));
    return {
      txid: origTxid,
      ins,
      recipients,
      totalIn,
      recipTotal: recipients.reduce((s, r) => s + r.value, 0),
      oldFee: totalIn - outTotal,
      spare,
    };
  }

  // Pure: pick the fee/change (and any extra inputs) for a given rate.
  planBump(prep, feeRate) {
    const rate = Math.max(1, Math.round(feeRate));
    const DUST = 294; // p2wpkh dust
    const vsizeOf = (nIn, nOut) => 11 + 68 * nIn + 31 * nOut;
    const spare = prep.spare.slice();
    const extra = [];
    const compute = () => {
      const nIn = prep.ins.length + extra.length;
      const inAmt = prep.totalIn + extra.reduce((s, u) => s + u.value, 0);
      let nOut = prep.recipients.length + 1;
      let fee = Math.ceil(vsizeOf(nIn, nOut) * rate);
      let change = inAmt - prep.recipTotal - fee;
      if (change < DUST) { nOut = prep.recipients.length; fee = inAmt - prep.recipTotal; change = 0; }
      const minFee = prep.oldFee + vsizeOf(nIn, nOut); // BIP125 incremental relay
      if (change > 0 && fee < minFee) {
        fee = minFee; change = inAmt - prep.recipTotal - fee;
        if (change < DUST) { fee = inAmt - prep.recipTotal; change = 0; }
      }
      return { fee, change, ok: inAmt - prep.recipTotal >= fee && fee > prep.oldFee };
    };
    let pl = compute();
    while (!pl.ok && spare.length) { extra.push(spare.shift()); pl = compute(); }
    return { fee: pl.fee, change: pl.change, extra, ok: pl.ok, rate };
  }

  // Build + sign the replacement at a rate. Returns { hex, txid, fee, oldFee, ... }.
  buildBump(prep, feeRate) {
    const pl = this.planBump(prep, feeRate);
    if (!pl.ok) throw new Error('Not enough funds to bump at this rate. Try a lower rate or CPFP.');
    const allIns = [...prep.ins, ...pl.extra.map((u) => ({ txid: u.txid, vout: u.vout, value: u.value, chain: u.chain, index: u.index }))];
    const t = new btc.Transaction();
    for (const i of allIns) {
      const pay = p2wpkh(this.derive(i.chain, i.index).pubkey, this.netCfg.net);
      t.addInput({ ...pay, txid: i.txid, index: i.vout, sequence: 0xfffffffd, witnessUtxo: { script: pay.script, amount: BigInt(i.value) } });
    }
    for (const r of prep.recipients) t.addOutputAddress(r.address, BigInt(r.value), this.netCfg.net);
    const changeAddr = this.freshChange().address;
    if (pl.change > 0) t.addOutputAddress(changeAddr, BigInt(pl.change), this.netCfg.net);
    for (let k = 0; k < allIns.length; k++) t.signIdx(this.node(allIns[k].chain, allIns[k].index).privateKey, k);
    t.finalize();

    const outputs = prep.recipients.map((r) => ({ address: r.address, value: r.value }));
    if (pl.change > 0) outputs.push({ address: changeAddr, value: pl.change, change: true });
    return { hex: t.hex, txid: t.id, fee: pl.fee, oldFee: prep.oldFee, feeRate: pl.rate, outputs, replaces: prep.txid };
  }

  _loadSet(key) {
    try {
      return new Set(JSON.parse(localStorage.getItem(key) || '[]'));
    } catch {
      return new Set();
    }
  }

  // ---- optional-feature seams ---------------------------------------------
  // Coin locks: features contribute sets of coin ids that spending and the
  // balance treat as unavailable.
  registerCoinLock(fn) { this._coinLocks.push(fn); }
  lockedCoinIds() {
    const all = new Set();
    for (const fn of this._coinLocks) { try { for (const id of fn()) all.add(id); } catch {} }
    return all;
  }
  // Namespaced per-wallet persisted state for features (swaps, ark, ...).
  featureStateKey(name) { return this._cacheKey() + ':' + name; }
  loadFeatureState(name, fallback = null) {
    try { const v = JSON.parse(localStorage.getItem(this.featureStateKey(name)) || 'null'); return v == null ? fallback : v; } catch { return fallback; }
  }
  saveFeatureState(name, value) {
    try { localStorage.setItem(this.featureStateKey(name), JSON.stringify(value)); } catch {}
  }









  // Number of unreserved spendable coins (for the consolidate prompt/action).
  spendableCoinCount() {
    const locked = this.lockedCoinIds();
    return this.utxos.filter((u) => !locked.has(utxoId(u)) && (u.confirmed || u.chain === 1)).length;
  }

  // Merge all unreserved spendable coins into one, via a max self-send. Leaves
  // the wallet with a single coin so future sends/gifts use one input.
  async consolidate(feeRate) {
    const rate = Math.max(1, Math.round(feeRate));
    const draft = this.buildTx({ recipients: [{ address: this.freshReceive().address }], feeRate: rate, sendMax: true });
    const hex = this.sign(draft.tx);
    await this.broadcast(hex);
    return { txid: draft.tx.id, inputs: draft.inputsCount };
  }




  // Our nostr identity (used to DM a locked gift's claim code to the recipient).
  nostrPubkey() { return (this.nostr && this.nostr.pk) || null; }
  nostrNpub() { const pk = this.nostrPubkey(); return pk ? npubOf(pk) : null; }
  // Send a nostr DM (e.g. a locked gift's claim code) to a recipient pubkey.
  async sendNostrDM(recipientPkHex, text) {
    return this.nostr && this.nostr.sk ? this.nostr.sendDM(recipientPkHex, text) : false;
  }


  // --- realtime (mempool.space WebSocket) ---------------------------------
  // Pushes us new mempool/confirmed transactions for our addresses so history
  // and balances update with no polling.
  wsUrl() {
    // Electrum backend (any network): pick the current failover candidate for the
    // active network (rotated on failure). Esplora backend has no push → poll.
    if (getBackend() === 'electrum') {
      if (!this._wsCandidates || !this._wsCandidates.length) { this._wsCandidates = electrumCandidates(this.netName); this._wsCandIdx = 0; }
      const list = this._wsCandidates;
      return list.length ? absWsUrl(list[(this._wsCandIdx || 0) % list.length]) : null;
    }
    return null;
  }

  // What realtime watches: the fresh frontier (next receive + next change), plus
  // any address holding an unconfirmed coin — so a pending deposit's confirmation
  // pushes instantly instead of waiting for a poll. Returns derivation targets
  // ({chain,index}); Electrum/Fulcrum handles many subscriptions, but our watched
  // set is naturally small so we cap generously.
  _watchedTargets() {
    const seen = new Set();
    const out = [];
    const add = (chain, index) => {
      const k = chain + '/' + index;
      if (!seen.has(k)) { seen.add(k); out.push({ chain, index }); }
    };
    add(0, this.nextReceiveIndex);
    add(1, this.nextChangeIndex);
    const stuck = this._stuckTxids();
    for (const u of this.utxos) {
      if (out.length >= 25) break;
      if (!u.confirmed && !stuck.has(u.txid)) add(u.chain, u.index);
    }
    return out;
  }
  watchedAddresses() {
    return this._watchedTargets().map((t) => this.derive(t.chain, t.index).address);
  }
  // Electrum scripthash for one of our addresses: sha256(scriptPubKey), reversed,
  // hex. This is what Fulcrum subscribes on.
  _scripthash(chain, index) {
    const h = sha256(this.derive(chain, index).script);
    h.reverse();
    return hex.encode(h);
  }
  watchedScripthashes() {
    // Also (re)build the scripthash -> derivation map so a data-carrying
    // notification can be credited without re-deriving or hitting REST.
    const map = new Map();
    const shes = this._watchedTargets().map((t) => {
      const sh = this._scripthash(t.chain, t.index);
      map.set(sh, { chain: t.chain, index: t.index, address: this.derive(t.chain, t.index).address });
      return sh;
    });
    this._shToTarget = map;
    return shes;
  }

  // Apply a watcher push directly (no REST). The push carries the matched
  // outputs (vout + value), the confirmed flag, and — when confirmed — the block
  // time. Returns false only if we can't map the scripthash (caller then scans).
  _applyTxNotification(sh, data) {
    const tgt = this._shToTarget && this._shToTarget.get(sh);
    if (!tgt || !data || !Array.isArray(data.outputs)) return false;
    let changed = false;

    // (1) Confirmation of a tx we already track: flip its history row and coins
    // to confirmed. Works for incoming AND outgoing — it only flips flags (no new
    // coin), so there's no overcount risk regardless of chain.
    if (data.confirmed) {
      const tx = this.txs.find((t) => t.txid === data.txid);
      if (tx && !tx.confirmed) {
        tx.confirmed = true;
        if (data.blockTime) tx.blockTime = data.blockTime;
        changed = true;
      }
      for (const o of data.outputs) {
        const u = this.utxos.find((x) => utxoId(x) === `${data.txid}:${o.vout}`);
        if (u && !u.confirmed) {
          u.confirmed = true;
          const e = (u.chain === 0 ? this.receive : this.change).find((a) => a.index === u.index);
          if (e) { e.pending = Math.max(0, (e.pending || 0) - o.value); e.confirmed = (e.confirmed || 0) + o.value; }
          changed = true;
        }
      }
    }

    // (2) New incoming receive (chain 0 only): credit the coin + a pending
    // history row so the balance and "payment received" fire instantly. Change
    // (chain 1) is our own send — its spent input isn't in the push, so crediting
    // it alone would transiently overcount; the backstop poll reconciles it.
    if (tgt.chain === 0) {
      let entry = this.receive.find((e) => e.index === tgt.index);
      if (!entry) {
        entry = { chain: 0, index: tgt.index, address: tgt.address, used: false, confirmed: 0, pending: 0 };
        this.receive.push(entry);
        this.addrMap.set(tgt.address, { chain: 0, index: tgt.index });
      }
      let credited = 0;
      for (const o of data.outputs) {
        if (this.utxos.find((u) => utxoId(u) === `${data.txid}:${o.vout}`)) continue;
        this.utxos.push({ txid: data.txid, vout: o.vout, value: o.value, address: tgt.address, chain: 0, index: tgt.index, confirmed: !!data.confirmed });
        entry.used = true;
        if (data.confirmed) entry.confirmed = (entry.confirmed || 0) + o.value;
        else entry.pending = (entry.pending || 0) + o.value;
        credited += o.value;
        changed = true;
      }
      if (credited > 0 && !this.txs.find((t) => t.txid === data.txid)) {
        this.txs.push({ txid: data.txid, net: credited, fee: 0, vsize: 0, confirmed: !!data.confirmed, blockTime: data.blockTime || 0, blockHeight: 0, firstSeen: data.confirmed ? 0 : Date.now() });
      }
    }

    if (!changed) return true; // nothing new (duplicate push) — handled, no scan
    this.nextReceiveIndex = firstUnused(this.receive);
    this.nextChangeIndex = firstUnused(this.change);
    this.utxos.sort((a, b) => b.value - a.value);
    this._sortTxs();
    this._recomputeBalanceFromUtxos();
    this.loaded = true;
    this.saveCache();
    this.retrack(); // a new frontier address may need subscribing
    this.emit();    // UI updates NOW; the 30s backstop poll fills blockHeight/fee
    return true;
  }

  // Credit an on-chain receive we produced ourselves (a reverse-swap claim) the
  // instant we broadcast it — so the balance + generic "payment received" fire
  // without waiting for the next scan, exactly like the watcher does for inbound
  // payments. `address` must be one of our receive (chain-0) addresses; returns
  // false (caller relies on the scan) if it isn't known or the coin already exists.
  creditReceive({ txid, vout, value, address }) {
    let entry = this.receive.find((e) => e.address === address);
    if (!entry) {
      const info = this.addrMap.get(address);
      if (info && info.chain === 0) entry = this.receive.find((e) => e.index === info.index);
    }
    if (!entry) return false;
    if (this.utxos.find((u) => utxoId(u) === `${txid}:${vout}`)) return false;
    this.utxos.push({ txid, vout, value, address, chain: 0, index: entry.index, confirmed: false });
    entry.used = true;
    entry.pending = (entry.pending || 0) + value;
    if (!this.txs.find((t) => t.txid === txid)) {
      this.txs.push({ txid, net: value, fee: 0, vsize: 0, confirmed: false, blockTime: 0, blockHeight: 0, firstSeen: Date.now() });
    }
    this.nextReceiveIndex = firstUnused(this.receive);
    this.utxos.sort((a, b) => b.value - a.value);
    this._sortTxs();
    this._recomputeBalanceFromUtxos();
    this.loaded = true;
    this.saveCache();
    this.retrack();
    this.emit();
    return true;
  }

  // Optimistically reflect a just-broadcast outgoing tx so the balance and
  // history update instantly instead of waiting for the post-send rescan: drop
  // the spent coins, credit our change as pending, and add a pending history
  // row. The realtime watcher / backstop poll reconciles it (and fills in the
  // confirmation) once the explorer has indexed the tx. `tx` is the finalized
  // btc.Transaction we just signed and broadcast.
  applySentTx(tx) {
    const txid = tx.id;
    if (this.txs.find((t) => t.txid === txid)) return; // already applied
    const byOutpoint = new Map();
    for (const u of this.utxos) byOutpoint.set(utxoId(u), u);

    let inSum = 0;
    const spent = new Set();
    for (let i = 0; i < tx.inputsLength; i++) {
      const inp = tx.getInput(i);
      const id = `${hex.encode(inp.txid)}:${inp.index}`;
      const u = byOutpoint.get(id);
      if (!u) {
        // Not in our current utxo set (e.g. dropped by a concurrent rescan), but
        // we built + signed this tx so the input is ours — count its value from
        // the witness utxo so the spend total isn't undercounted.
        if (inp.witnessUtxo) inSum += Number(inp.witnessUtxo.amount);
        continue;
      }
      inSum += u.value;
      spent.add(id);
      const e = (u.chain === 0 ? this.receive : this.change).find((a) => a.index === u.index);
      if (e) { if (u.confirmed) e.confirmed = Math.max(0, (e.confirmed || 0) - u.value); else e.pending = Math.max(0, (e.pending || 0) - u.value); }
    }
    this.utxos = this.utxos.filter((u) => !spent.has(utxoId(u)));

    let outSum = 0, change = 0;
    for (let i = 0; i < tx.outputsLength; i++) {
      const o = tx.getOutput(i);
      outSum += Number(o.amount);
      let addr;
      try { addr = btc.Address(this.netCfg.net).encode(btc.OutScript.decode(o.script)); } catch {}
      const info = addr && this.addrMap.get(addr);
      if (!info) continue; // recipient output — not ours
      this.utxos.push({ txid, vout: i, value: Number(o.amount), address: addr, chain: info.chain, index: info.index, confirmed: false });
      const e = (info.chain === 0 ? this.receive : this.change).find((a) => a.index === info.index);
      if (e) { e.pending = (e.pending || 0) + Number(o.amount); e.used = true; }
      change += Number(o.amount);
    }

    this.txs.unshift({ txid, net: change - inSum, fee: inSum - outSum, vsize: tx.weight ? Math.ceil(tx.weight / 4) : 0, confirmed: false, blockTime: 0, blockHeight: 0, firstSeen: Date.now(), local: true });
    this.nextReceiveIndex = firstUnused(this.receive);
    this.nextChangeIndex = firstUnused(this.change);
    this.utxos.sort((a, b) => b.value - a.value);
    this._sortTxs();
    this._recomputeBalanceFromUtxos();
    this.loaded = true;
    this.saveCache();
    this.retrack();
    this.emit();
  }

  startRealtime() {
    if (this.offline) return;
    this.stopRealtime();
    this._wsCandidates = null; // rebuild the failover list fresh (picks up config), prefer primary
    this._wsCandIdx = 0;
    // Frontier poll — now purely a safety net. The watcher pushes incoming
    // payments AND confirmations instantly with full data (credited via the WS
    // with no REST), so when the socket is live we poll rarely (~30s) just in
    // case a push was missed. When the socket is DOWN we poll faster: ~5s on the
    // Receive tab (user is actively waiting) or while a coin is unconfirmed, else
    // ~10s. This keeps mempool.space REST (and its 429s) to a trickle.
    this._pollTimer = setInterval(() => {
      if (this.offline) return;
      const stuck = this._stuckTxids();
      const pending = this.utxos.some((u) => !u.confirmed && !stuck.has(u.txid));
      let due;
      if (this.live) {
        due = 30000; // WS handles the real work; this is a backstop only
      } else if (this._watchReceive || pending) {
        due = 5000;  // socket down + actively waiting → poll responsively
      } else {
        due = 10000;
      }
      if (Date.now() - (this._lastPoll || 0) < due) return;
      this._lastPoll = Date.now();
      this.refreshLive();
      // SP receipts arrive via the indexer WebSocket (_spConnect); only poll for
      // them as a fallback when that socket isn't live.
      if (!this.spLive) this.scanSilentPayments({ silent: true }).catch(() => {});
    }, 1000);
    this._spConnect(); // live push of silent-payment receipts
    // No periodic full re-scan: the WS (and the frontier poll above) keep the
    // balance current, and refreshLive's _reconcileHeld catches spends of held
    // coins. The only thing neither covers is a deposit to a reused old address,
    // which is handled on demand via per-address rescan in Settings.
    // Only mempool.space has a live socket; other explorers rely on the poll
    // above (wsUrl returns null → no socket).
    if (typeof WebSocket === 'undefined' || !this.wsUrl()) return;
    this._wsWant = true;

    // Heartbeat: ping every 10s; if nothing comes back (incl. our own pong) for
    // 21s the socket is half-open (died without firing onclose) — recycle it.
    // The trigger is two unanswered pings, so one slow round-trip won't churn,
    // but a silently-dead socket now recovers in ~20s instead of ~45s.
    this._hbTimer = setInterval(() => {
      if (this.offline || !this._ws || this._ws.readyState !== 1) return;
      if (Date.now() - this._lastMsg > 21000) {
        this._reconnectNow();
      } else {
        this._rpcSend('server.ping', []);
      }
    }, 10000);

    // Reconnect + refresh when the tab refocuses or the network returns.
    if (!this._wakeHooked && typeof document !== 'undefined') {
      this._wakeHooked = true;
      const wake = () => {
        if (this.offline || !this._wsWant) return;
        if (!this._ws || this._ws.readyState !== 1) this._reconnectNow();
        this.scan({ silent: true }).catch(() => {});
      };
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') wake();
      });
      window.addEventListener('online', wake);
    }

    this._connectWs();
  }

  _reconnectNow() {
    clearTimeout(this._wsRetry);
    if (this._ws) {
      try {
        this._ws.onclose = null;
        this._ws.close();
      } catch {}
      this._ws = null;
    }
    // onclose was nulled above so it won't fire — fail in-flight calls here too.
    this._rejectPending('socket recycled');
    this.live = false;
    this._connectWs();
  }

  _connectWs() {
    if (!this._wsWant) return;
    let ws;
    try {
      ws = new WebSocket(this.wsUrl());
    } catch {
      this._scheduleReconnect();
      return;
    }
    this._ws = ws;
    this._wsBuf = '';            // partial-line accumulator (newline-delimited JSON-RPC)
    this._subscribed = new Set(); // scripthashes subscribed on this connection
    this._wsOpenedAt = 0;        // set on open; used to judge a healthy connection for failover
    if (this._rpcId == null) this._rpcId = 0; // monotonic across reconnects (don't alias pending ids)
    ws.onopen = () => {
      this.live = true;
      this._wsOpenedAt = Date.now();
      this._wsBackoff = 0; // healthy again — reset the reconnect backoff
      this._lastMsg = Date.now();
      // Electrum handshake, then subscribe our watched scripthashes.
      this._rpcSend('server.version', ['halwallet', '1.4']);
      // Flush any data calls queued while the socket was down.
      if (this._callQueue && this._callQueue.length) {
        for (const payload of this._callQueue) { try { ws.send(payload); } catch {} }
        this._callQueue = [];
      }
      this.retrack();
      this.emit();
      // The server only pushes activity AFTER we subscribe, so reconcile once on
      // open to catch anything that landed while we were disconnected.
      this.refreshLive().catch(() => {});
    };
    ws.onmessage = (ev) => {
      this._lastMsg = Date.now();
      this._wsBuf += (typeof ev.data === 'string' ? ev.data : new TextDecoder().decode(ev.data));
      // Robustly extract every complete top-level JSON object from the buffer,
      // regardless of framing: newline-delimited (coinos watcher), one-per-frame
      // without a newline (electrs), several concatenated in one frame, or a
      // single object split across frames. Brace-depth scan, string-aware.
      const s = this._wsBuf;
      let depth = 0, inStr = false, esc = false, start = -1, consumed = 0;
      for (let i = 0; i < s.length; i++) {
        const ch = s[i];
        if (inStr) { if (esc) esc = false; else if (ch === '\\') esc = true; else if (ch === '"') inStr = false; continue; }
        if (ch === '"') inStr = true;
        else if (ch === '{') { if (depth === 0) start = i; depth++; }
        else if (ch === '}' && depth > 0) { if (--depth === 0 && start >= 0) { this._handleRpc(s.slice(start, i + 1)); consumed = i + 1; start = -1; } }
      }
      this._wsBuf = s.slice(consumed);
      if (this._wsBuf.length > 1 << 20) this._wsBuf = ''; // runaway guard
    };
    ws.onerror = () => {
      try {
        ws.close();
      } catch {}
    };
    ws.onclose = () => {
      this.live = false;
      this._ws = null;
      // Fail any in-flight data calls so the _rpcCall pump frees its slots
      // immediately; otherwise dead calls hold the pump until they time out and
      // the post-reconnect refresh stalls behind them (~10s of stale UI).
      this._rejectPending('socket closed');
      this.emit();
      this._scheduleReconnect();
    };
  }

  // Send an Electrum JSON-RPC request (fire-and-forget; we react to notifications,
  // not responses). Newline-terminated per the protocol.
  _rpcSend(method, params) {
    if (!this._ws || this._ws.readyState !== 1) return;
    // Coerce to a number defensively: a non-numeric _rpcId serializes id as
    // null, which the response matcher (msg.id != null) drops — silently
    // breaking every data call (and thus reconciles).
    const id = (this._rpcId = (this._rpcId || 0) + 1);
    try {
      this._ws.send(JSON.stringify({ id, method, params }) + '\n');
    } catch {}
    return id;
  }

  // Electrum request/response (used by the ElectrumApi data backend). Resolves
  // when the matching id comes back; queues until the socket is open, and times
  // out so a wedged call can't hang a scan. ids are monotonic for the session so
  // they never alias a fire-and-forget _rpcSend id.
  // Public Electrum entry point. Throttled so a scan doesn't fire a burst that a
  // rate-limited public server would drop — Electrum pipelines requests, so a few
  // in flight is plenty (and fast). Excess calls queue for a free slot.
  _rpcCall(method, params) {
    return new Promise((resolve, reject) => {
      (this._rpcQueue || (this._rpcQueue = [])).push({ method, params, resolve, reject });
      this._rpcPump();
    });
  }
  _rpcPump() {
    if (this._rpcActive == null) this._rpcActive = 0;
    const MAX = 4;
    while (this._rpcActive < MAX && this._rpcQueue && this._rpcQueue.length) {
      const job = this._rpcQueue.shift();
      this._rpcActive++;
      this._rpcSendCall(job.method, job.params).then(job.resolve, job.reject).finally(() => { this._rpcActive--; this._rpcPump(); });
    }
  }
  // The actual request: send, await the matching response, time out, and retry a
  // couple of times on a fresh id (a public server can drop a response or the
  // socket can flap mid-call).
  _rpcSendCall(method, params, attempt = 0) {
    return new Promise((resolve, reject) => {
      if (this.offline) { reject(new Error('offline')); return; }
      const id = (this._rpcId = (this._rpcId || 0) + 1);
      if (!this._pending) this._pending = new Map();
      const timer = setTimeout(() => {
        if (!this._pending.delete(id)) return;
        if (attempt < 2 && !this.offline) this._rpcSendCall(method, params, attempt + 1).then(resolve, reject);
        else reject(new Error('electrum timeout: ' + method));
      }, 12000);
      this._pending.set(id, { resolve, reject, timer });
      const payload = JSON.stringify({ id, method, params }) + '\n';
      if (this._ws && this._ws.readyState === 1) {
        try { this._ws.send(payload); } catch {}
      } else {
        (this._callQueue = this._callQueue || []).push(payload);
      }
    });
  }

  _rejectPending(reason) {
    if (this._pending) {
      for (const { reject, timer } of this._pending.values()) { clearTimeout(timer); try { reject(new Error(reason)); } catch {} }
      this._pending.clear();
    }
    if (this._rpcQueue) {
      for (const job of this._rpcQueue) { try { job.reject(new Error(reason)); } catch {} }
      this._rpcQueue = [];
    }
    this._rpcActive = 0;
  }

  // A notification means a tx touched one of our addresses (a deposit, or a
  // confirmation). If it carries the tx data (our watcher does), credit it
  // instantly with no REST on the critical path; otherwise just trigger a scan.
  _handleRpc(line) {
    let msg;
    try { msg = JSON.parse(line); } catch { return; }
    if (!msg) return;
    // Response to a data call (ElectrumApi backend)?
    if (msg.id != null && this._pending && this._pending.has(msg.id)) {
      const p = this._pending.get(msg.id);
      this._pending.delete(msg.id);
      clearTimeout(p.timer);
      if (msg.error) p.reject(new Error(typeof msg.error === 'string' ? msg.error : (msg.error.message || JSON.stringify(msg.error))));
      else p.resolve(msg.result);
      return;
    }
    // Subscription notification: a tx touched a watched address. Our coinos
    // watcher carries the tx data (credit instantly); a real Electrum server
    // sends only [scripthash, status], so reconcile via the data backend.
    if (msg.method !== 'blockchain.scripthash.subscribe') return;
    const sh = msg.params && msg.params[0];
    if (msg.data && sh && this._applyTxNotification(sh, msg.data)) return;
    this._scheduleRefresh();
  }

  // Subscribe any watched scripthashes not yet subscribed on this connection.
  // Reset on reconnect (_subscribed is cleared in _connectWs), so a fresh socket
  // re-subscribes the full set.
  retrack() {
    if (!this._ws || this._ws.readyState !== 1) return;
    if (!this._subscribed) this._subscribed = new Set();
    for (const sh of this.watchedScripthashes()) {
      if (this._subscribed.has(sh)) continue;
      this._subscribed.add(sh);
      this._rpcSend('blockchain.scripthash.subscribe', [sh]);
    }
  }

  _scheduleReconnect() {
    if (!this._wsWant) return;
    // Electrum failover: if this connection never became healthy (failed to open,
    // or died within a few seconds), advance to the next candidate server.
    if (getBackend() === 'electrum' && this._wsCandidates && this._wsCandidates.length > 1) {
      if (!this._wsOpenedAt || Date.now() - this._wsOpenedAt < 5000) this._wsCandIdx = (this._wsCandIdx || 0) + 1;
    }
    clearTimeout(this._wsRetry);
    // Exponential backoff starting small, so a first attempt that's transiently
    // rejected (e.g. a stale rate-limit) retries in ~0.6s instead of a flat 4s —
    // the wallet reaches Live quickly. Reset to 0 on a successful open.
    this._wsBackoff = Math.min((this._wsBackoff || 0) + 1, 6);
    const delay = Math.min(600 * 2 ** (this._wsBackoff - 1), 15000);
    this._wsRetry = setTimeout(() => this._connectWs(), delay);
  }

  // Debounced: a payment may touch several of our addresses in one go.
  // Reconcile incrementally (frontier only) — never re-scans old coins.
  _scheduleRefresh() {
    clearTimeout(this._refreshTimer);
    this._refreshTimer = setTimeout(async () => {
      try {
        await this.refreshLive();
        this.retrack();
      } catch {}
    }, 400);
  }

  stopRealtime() {
    this._wsWant = false;
    this.live = false;
    this._spDisconnect();
    this._rejectPending('realtime stopped'); // fail any in-flight Electrum data calls
    this._callQueue = [];
    clearTimeout(this._wsRetry);
    clearTimeout(this._refreshTimer);
    clearInterval(this._pollTimer);
    clearInterval(this._deepTimer);
    clearInterval(this._hbTimer);
    clearTimeout(this._nostrPubTimer);
    if (this._ws) {
      try {
        this._ws.onclose = null;
        this._ws.close();
      } catch {}
      this._ws = null;
    }
  }

  // --- local history cache ------------------------------------------------
  // Cache the scanned state in localStorage, keyed by a hash of the seed (the
  // seed itself is never stored). Re-importing the same seed in this browser
  // then shows the last-known balance/history instantly while a fresh scan
  // runs in the background.
  _cacheKey() {
    const id = this.watchOnly ? this.xpub : this.xprv ? this.xprv : `${this.mnemonic}\n${this.passphrase}`;
    const bytes = new TextEncoder().encode(id);
    return 'btc-wallet-cache:' + hex.encode(sha256(bytes)).slice(0, 32);
  }

  // The fresh receive index the "payment received" screen has been shown for.
  // Persisted (and advanced as soon as the celebration appears) so a payment
  // celebrates once and never reappears on a refresh or reopen.
  getReceiveAck() {
    try {
      const v = localStorage.getItem(this._cacheKey() + ':ack');
      return v == null ? null : Number(v);
    } catch {
      return null;
    }
  }

  setReceiveAck(i) {
    try {
      localStorage.setItem(this._cacheKey() + ':ack', String(i));
    } catch {}
  }

  // The serializable wallet state, shared by the localStorage cache and the
  // Nostr sync. savedAt lets us pick the newest copy across devices.
  _snapshot() {
    return {
      v: 1,
      savedAt: Date.now(),
      receive: this.receive,
      change: this.change,
      utxos: this.utxos,
      txs: this.txs,
      nextReceiveIndex: this.nextReceiveIndex,
      nextChangeIndex: this.nextChangeIndex,
      feeRates: this.feeRates,
      spUtxos: this.spUtxos,
      lastSpScan: this.lastSpScan,
    };
  }

  _applySnapshot(d) {
    this.receive = d.receive || [];
    this.change = d.change || [];
    this.utxos = d.utxos || [];
    this.txs = d.txs || [];
    this._sortTxs(); // a cache saved before the firstSeen-ordering fix may be stale
    this.nextReceiveIndex = d.nextReceiveIndex || 0;
    this.nextChangeIndex = d.nextChangeIndex || 0;
    this.feeRates = d.feeRates || this.feeRates;
    this.spUtxos = d.spUtxos || [];
    this.lastSpScan = d.lastSpScan || 0;
    this.addrMap = new Map();
    for (const a of [...this.receive, ...this.change]) {
      this.addrMap.set(a.address, { chain: a.chain, index: a.index });
    }
    this._recomputeBalanceFromChains();
    this._savedAt = d.savedAt || 0;
    this.loaded = true;
  }

  // A cache key derived from the account xpub (not the seed) — the same key a
  // watch-only load of this wallet would use. A full wallet also writes its cache
  // here so that, if the session is wiped and the wallet reopens as watch-only,
  // its balance/history shows instantly instead of needing a rescan.
  _xpubCacheKey() {
    const bytes = new TextEncoder().encode(this.accountXpub());
    return 'btc-wallet-cache:' + hex.encode(sha256(bytes)).slice(0, 32);
  }

  saveCache() {
    const snap = this._snapshot();
    this._savedAt = snap.savedAt;
    try {
      localStorage.setItem(this._cacheKey(), JSON.stringify(snap));
      const xk = this._xpubCacheKey();
      if (xk !== this._cacheKey()) localStorage.setItem(xk, JSON.stringify(snap)); // watch-only mirror
    } catch {}
    // Push to the configured relays too (debounced), so other devices get the
    // update — unless cross-device sync is turned off.
    const sync = getSyncConfig();
    if (!this.offline && sync.enabled) {
      this.nostr.setRelays(sync.relays);
      clearTimeout(this._nostrPubTimer);
      this._nostrPubTimer = setTimeout(() => this.nostr.publish(snap), 2500);
    }
  }

  restoreCache() {
    try {
      let raw = localStorage.getItem(this._cacheKey());
      // A wallet just upgraded from watch-only (seed re-entered) has no seed-keyed
      // cache yet — fall back to the xpub mirror so it shows instantly.
      if (!raw && !this.watchOnly) raw = localStorage.getItem(this._xpubCacheKey());
      if (!raw) return false;
      this._applySnapshot(JSON.parse(raw));
      this.emit();
      return true;
    } catch {
      return false;
    }
  }

  // Pull the latest state from Nostr; apply it if it's newer than what we have.
  // Returns true if state was applied (so the caller can skip a full scan).
  async syncFromNostr() {
    const sync = getSyncConfig();
    if (this.offline || !sync.enabled) return false;
    this.nostr.setRelays(sync.relays);
    let remote;
    try {
      remote = await this.nostr.fetch();
    } catch {
      return false;
    }
    if (!remote) return false;
    if ((remote.savedAt || 0) > (this._savedAt || 0)) {
      this._applySnapshot(remote);
      this.saveCache(); // mirror into localStorage
      this.emit();
      return true;
    }
    // Our local copy is newer (or equal) — push it up so the relay catches up.
    if ((this._savedAt || 0) > (remote.savedAt || 0)) this.saveCache();
    return true; // remote existed, so no full scan needed
  }

  // --- offline snapshot ---------------------------------------------------
  // Exported on the ONLINE device. Contains no secrets — just what an offline
  // signer needs: coins, fee rates, and which addresses are next/fresh.
  exportSnapshot() {
    return {
      app: 'bitcoin-wallet',
      version: 1,
      netName: this.netName,
      exportedAt: new Date().toISOString(),
      feeRates: this.feeRates,
      nextReceiveIndex: this.nextReceiveIndex,
      nextChangeIndex: this.nextChangeIndex,
      utxos: this.utxos.map((u) => ({
        txid: u.txid,
        vout: u.vout,
        value: u.value,
        address: u.address,
        confirmed: u.confirmed,
      })),
    };
  }

  // Imported on the OFFLINE device (which already has the seed loaded).
  importSnapshot(snap) {
    if (!snap || !Array.isArray(snap.utxos))
      throw new Error('Not a valid wallet snapshot file.');
    if (snap.netName && snap.netName !== this.netName)
      throw new Error(
        `Snapshot is for ${snap.netName} but wallet is ${this.netName}.`
      );

    this.feeRates = snap.feeRates || this.feeRates;
    this.nextReceiveIndex = snap.nextReceiveIndex || 0;
    this.nextChangeIndex = snap.nextChangeIndex || 0;

    // Derive a generous window so every UTXO address resolves to a path.
    const maxIdx = snap.utxos.reduce((m, _u) => m, 0);
    const window = Math.max(this.nextReceiveIndex, this.nextChangeIndex, maxIdx) + GAP_LIMIT + 5;
    this.deriveWindow(window);

    const utxos = [];
    const unmatched = [];
    for (const u of snap.utxos) {
      const path = this.addrMap.get(u.address);
      if (!path) {
        unmatched.push(u.address);
        continue;
      }
      utxos.push({
        txid: u.txid,
        vout: u.vout,
        value: u.value,
        address: u.address,
        chain: path.chain,
        index: path.index,
        confirmed: !!u.confirmed,
      });
    }
    utxos.sort((a, b) => b.value - a.value);
    this.utxos = utxos;
    this._recomputeBalanceFromUtxos();
    this.loaded = true;
    this.emit();
    return { imported: utxos.length, unmatched };
  }
}

export function utxoId(u) {
  return `${u.txid}:${u.vout}`;
}

// Watch-only: accept a native-segwit account xpub or zpub and normalize it to
// xpub version bytes (the key material is identical; only the prefix differs),
// so HDKey can load it. Throws on anything else (private keys, wrong type).
const _b58c = base58check(sha256);
const _XPUB_VER = Uint8Array.from([0x04, 0x88, 0xb2, 0x1e]);
const _ZPUB_VER = Uint8Array.from([0x04, 0xb2, 0x47, 0x46]);
const _XPRV_VER = Uint8Array.from([0x04, 0x88, 0xad, 0xe4]);
const _ZPRV_VER = Uint8Array.from([0x04, 0xb2, 0x43, 0x0c]);

// Classify a pasted extended key. xpub/zpub → public (watch-only); xprv/zprv →
// private (spending). Version bytes are normalized to the standard xpub/xprv set
// (key material is identical; only the prefix differs) so HDKey can load it.
// Returns { kind: 'xpub' | 'xprv', key } or throws.
export function parseExtendedKey(s) {
  let data;
  try {
    data = _b58c.decode((s || '').trim());
  } catch {
    throw new Error('Not a valid recovery phrase or key.');
  }
  if (data.length !== 78) throw new Error('Not a valid recovery phrase or key.');
  const ver = hex.encode(data.slice(0, 4));
  let kind, norm;
  if (ver === hex.encode(_XPUB_VER) || ver === hex.encode(_ZPUB_VER)) { kind = 'xpub'; norm = _XPUB_VER; }
  else if (ver === hex.encode(_XPRV_VER) || ver === hex.encode(_ZPRV_VER)) { kind = 'xprv'; norm = _XPRV_VER; }
  else throw new Error('Unrecognized key type — use a native-segwit xpub/zpub or xprv/zprv.');
  const out = new Uint8Array(data);
  out.set(norm, 0);
  const key = _b58c.encode(out);
  try {
    HDKey.fromExtendedKey(key);
  } catch {
    throw new Error('Not a valid extended key.');
  }
  return { kind, key };
}

// Encrypted vault for persisting seed-bearing accounts on this device. Key is
// scrypt(password, salt); payload is XChaCha20-Poly1305 (authenticated, so a
// wrong password fails to decrypt rather than returning garbage). All fields
// are hex so the blob is JSON-serializable for localStorage.
const _SCRYPT = { N: 2 ** 15, r: 8, p: 1, dkLen: 32 };
function _vaultKey(password, salt) {
  return scrypt(utf8ToBytes(password), salt, _SCRYPT);
}
export function encryptVault(obj, password) {
  const salt = randomBytes(16);
  const nonce = randomBytes(24);
  const ct = xchacha20poly1305(_vaultKey(password, salt), nonce).encrypt(utf8ToBytes(JSON.stringify(obj)));
  return { v: 1, salt: hex.encode(salt), nonce: hex.encode(nonce), ct: hex.encode(ct) };
}
export function decryptVault(blob, password) {
  const pt = xchacha20poly1305(_vaultKey(password, hex.decode(blob.salt)), hex.decode(blob.nonce)).decrypt(hex.decode(blob.ct));
  return JSON.parse(bytesToUtf8(pt));
}

// Convert a standard account xpub to a BIP84 zpub for export/interop.
export function xpubToZpub(xpub) {
  const data = new Uint8Array(_b58c.decode(xpub));
  data.set(_ZPUB_VER, 0);
  return _b58c.encode(data);
}



function firstUnused(chain) {
  const u = chain.find((a) => !a.used);
  return u ? u.index : chain.length;
}

function summarize(sel, network) {
  const outputs = sel.tx.outputs.map((o) => ({
    address: btc.Address(network).encode(btc.OutScript.decode(o.script)),
    amount: Number(o.amount),
  }));
  return {
    tx: sel.tx,
    fee: Number(sel.fee),
    hasChange: !!sel.change,
    inputsCount: sel.tx.inputsLength,
    outputs,
    weight: sel.weight,
    vsize: Math.ceil(Number(sel.weight) / 4),
  };
}

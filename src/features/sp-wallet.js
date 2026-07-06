// Silent payments (BIP-352) wallet engine — key derivation, indexer scanning
// (worker-accelerated with an inline fallback), the live indexer WebSocket,
// SP outputs as spendable coins, sp1 send preparation, and per-output-key
// signing. Installed onto the core wallet by the sp feature, wired through the
// wallet's generic seams so a build without sp ships none of this.

import * as btc from '@scure/btc-signer';
import { hex } from '@scure/base';
import { schnorr } from '@noble/curves/secp256k1';
import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync } from '@scure/bip39';
import {
  isSilentPaymentAddress, decodeSilentPaymentAddress, silentPaymentScripts,
  silentPaymentPlaceholder, deriveSilentPaymentKeys, encodeSilentPaymentAddress,
  silentPaymentScan, silentPaymentOutputPrivKey, silentPaymentCandidate, bloomHas,
} from '../silentpay.js';
import { spIndexerUrl } from '../api.js';
import { utxoId, absWsUrl, NETS } from '../wallet.js';

const SP_DUST_LIMIT = 0;

export function installSpWallet(wallet) {
  if (wallet.scanSilentPayments) return; // already installed
  wallet.spUtxos = [];
  wallet.lastSpScan = 0; // highest block height scanned for silent payments
  wallet.spScanning = false;

  Object.assign(wallet, {
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
    },

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
    },

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
    },

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
    },

    _spCall(op, data) {
      return new Promise((res, rej) => {
        const id = ++this._spReqId;
        this._spPending.set(id, { res, rej });
        this._spWorker.postMessage({ id, op, ...data });
        setTimeout(() => { if (this._spPending.has(id)) { this._spPending.delete(id); rej(new Error('sp worker timeout')); } }, 30000);
      });
    },

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
    },

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
    },

    // Our silent-payment address (sp1…/tsp1…), or null if this wallet can't do SP.
    silentPaymentAddress() {
      const k = this.silentPaymentKeys();
      return k ? encodeSilentPaymentAddress(k.scanPub, k.spendPub, { testnet: this.netName !== 'mainnet' }) : null;
    },

    // Is SP receiving available here? (we can derive keys AND an indexer is set)
    silentPaymentsAvailable() {
      return !!(this.silentPaymentKeys() && spIndexerUrl(this.netName));
    },

    // Total received via silent payments: { confirmed, pending, count } over the
    // unspent SP outputs we've found.
    spBalance() {
      let confirmed = 0, pending = 0;
      for (const u of this.spUtxos) { if (u.confirmed) confirmed += u.value; else pending += u.value; }
      return { confirmed, pending, count: this.spUtxos.length };
    },

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
    },

    // The taproot address for an x-only output key (for backend UTXO lookups).
    _spAddress(xonly) {
      return btc.Address(this.netCfg.net).encode(btc.OutScript.decode(btc.OutScript.encode({ type: 'tr', pubkey: hex.decode(xonly) })));
    },

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
      // Two tabs on the same wallet must not both grind the catch-up: a
      // localStorage lease (refreshed per chunk) lets the second tab yield.
      const leaseKey = this._cacheKey() + ':spscan-lease';
      try {
        if (!rescan && Date.now() - (parseInt(localStorage.getItem(leaseKey), 10) || 0) < 30000) {
          return { busy: true };
        }
        localStorage.setItem(leaseKey, String(Date.now()));
      } catch {}
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
        const blocks = res.blocks || [];
        // Process in chunks. An imported wallet's first catch-up can be the
        // indexer's whole window (hundreds of thousands of tweaks, ~25MB) —
        // sent as ONE worker message it blew the 30s worker timeout, fell
        // back to the inline loop (janking the UI for minutes while the
        // worker kept grinding the orphaned request), and held the giant
        // buffers live the whole time. Chunks keep each call sub-second, let
        // the scan watermark advance as blocks complete (interruptions
        // resume instead of restarting), and free memory as they go.
        const CHUNK = 100;
        for (let c = 0; c < blocks.length; c += CHUNK) {
          const slice = blocks.slice(c, c + CHUNK);
          const hits = await this._spHitBlocks(slice);
          for (const block of slice) {
            if (!hits.has(block.height)) continue;
            const blk = await (await fetch(`${indexer}/block/${block.height}`)).json();
            for (const f of await this._spScanItems(blk.items || [])) {
              const id = `${f.txid}:${f.vout}`;
              if (have.has(id)) continue;
              have.add(id);
              found.push(f);
            }
          }
          const maxH = slice[slice.length - 1].height;
          if (maxH > (this.lastSpScan || 0)) { this.lastSpScan = maxH; this.saveCache(); } // checkpoint
          try { localStorage.setItem(leaseKey, String(Date.now())); } catch {} // keep the lease
          await new Promise((r) => setTimeout(r, 0)); // let the UI breathe
        }
        if (tip > (this.lastSpScan || 0)) this.lastSpScan = tip;
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
    },

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
    },

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
    },

    _spDisconnect() {
      clearTimeout(this._spReconnect);
      this.spLive = false;
      const ws = this._spWs;
      this._spWs = null; this._spWsUrl = null;
      if (ws) { try { ws.onclose = null; ws.close(); } catch {} }
    },

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
    },

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
    },

    // Mark summary outputs that fund a silent payment with the sp1… address the
    // user actually typed (the on-chain output is a derived one-time taproot addr).
    _tagSilentOutputs(summary, spOuts) {
      for (const s of spOuts) {
        if (!s.derivedAddress) continue;
        const o = summary.outputs.find((o) => o.address === s.derivedAddress && !o.silent);
        if (o) o.silent = s.address;
      }
    },

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
    },
  });

  // -- seam registrations -----------------------------------------------
  wallet.registerBalanceExtra(() => wallet.spBalance());
  wallet.registerHistoryProvider(() => wallet.spTxRows());
  wallet.registerScanHook(() => wallet.scanSilentPayments({ silent: true }).catch(() => {}));
  wallet.registerRealtimeHook({
    start: () => wallet._spConnect(), // live push of silent-payment receipts
    stop: () => wallet._spDisconnect(),
    // WS is primary; the heartbeat poll is the fallback when it isn't live.
    poll: () => { if (!wallet.spLive) wallet.scanSilentPayments({ silent: true }).catch(() => {}); },
  });
  wallet.registerLoadHook(({ spFresh }) => {
    // A freshly-generated wallet can't have received silent payments before it
    // existed, so its SP watermark starts at the current tip (no history scan).
    wallet._spFresh = !!spFresh;
    wallet.spUtxos = [];
    wallet.lastSpScan = 0;
  });
  wallet.registerCacheExtension({
    save: () => ({ spUtxos: wallet.spUtxos, lastSpScan: wallet.lastSpScan }),
    load: (d) => { wallet.spUtxos = d.spUtxos || []; wallet.lastSpScan = d.lastSpScan || 0; },
  });
  // Confirmed SP coins are spendable like any other coin — including to fund a
  // silent payment. Unconfirmed ones are excluded (the sender's tx could be
  // replaced, invalidating our spend).
  wallet.registerInputProvider(({ coinIds }) => {
    const confirmedSp = wallet.spUtxos.filter((u) => u.confirmed);
    const pool = coinIds ? confirmedSp.filter((u) => coinIds.includes(utxoId(u))) : confirmedSp;
    return pool.map((u) => ({
      txid: u.txid,
      index: u.vout,
      sequence: 0xfffffffd,
      witnessUtxo: { script: btc.OutScript.encode({ type: 'tr', pubkey: hex.decode(u.xonly) }), amount: BigInt(u.value) },
      // Present so the fee estimator sizes a key-path (64-byte) witness; the
      // value is unused (SP inputs are signed raw below, via tapKeySig).
      tapInternalKey: hex.decode(u.xonly),
    }));
  });
  // sp1… recipients: the real taproot output commits to the final input set,
  // so buildTx selects against a placeholder and swaps the derived script in.
  wallet.registerSendPreparer(() => {
    const spOuts = []; // { placeholder, scan, spend, address }
    return {
      match: (addr) => isSilentPaymentAddress(addr),
      prepare(addr) {
        if (wallet.watchOnly) throw new Error('Silent payments require a wallet with keys.');
        const { scan, spend } = decodeSilentPaymentAddress(addr);
        const placeholder = silentPaymentPlaceholder(spOuts.length);
        spOuts.push({ placeholder, scan, spend, address: addr });
        return placeholder;
      },
      apply(tx) { if (spOuts.length) wallet._applySilentPayments(tx, spOuts); },
      tag(summary) { wallet._tagSilentOutputs(summary, spOuts); },
    };
  });
  // Received SP outputs sign with d = spend_priv + t_k (raw output key —
  // no BIP-341 tweak, so btc-signer's auto key-path signing doesn't apply).
  wallet.registerInputSigner((tx, i, id, { prevScripts, amounts }) => {
    const u = wallet.spUtxos.find((x) => utxoId(x) === id);
    if (!u) return false;
    const d = silentPaymentOutputPrivKey(wallet.silentPaymentKeys().spendPriv, hex.decode(u.tweak));
    const hash = tx.preimageWitnessV1(i, prevScripts, btc.SigHash.DEFAULT, amounts);
    tx.updateInput(i, { tapKeySig: schnorr.sign(hash, d) }, true);
    return true;
  });
}

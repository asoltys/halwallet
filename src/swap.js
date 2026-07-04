// Boltz submarine + reverse swap support for Hal — fully client-side and
// non-custodial. Hal holds the swap key + preimage and can always claim
// (reverse) or refund (submarine) on-chain via the Taproot SCRIPT PATH, so an
// uncooperative/offline Boltz can never strand funds. The cooperative MuSig2
// key-path spend (smaller witness) is a future optimization; correctness here
// relies only on the script path.
//
// Tapscript byte layouts and the two-leaf tree are replicated exactly from
// boltz-core (src/bitcoin/scripts/{swap_tree,reverse_tree,tree}.rs) and unit-
// tested against its published test vectors (see tools/swap-vectors.test.js).

import * as btc from '@scure/btc-signer';
import { p2tr, taprootListToTree, tapLeafHash as scureTapLeafHash } from '@scure/btc-signer/payment';
import { keyAggregate, keyAggExport, sortKeys } from '@scure/btc-signer/musig2';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha2';
import { ripemd160 } from '@noble/hashes/legacy';
import { hexToBytes, bytesToHex, concatBytes } from '@noble/hashes/utils';
import { bech32 } from '@scure/base';

export { hexToBytes, bytesToHex };

// Regtest network object (same version bytes as testnet, `bcrt` HRP).
export const REGTEST = { ...btc.TEST_NETWORK, bech32: 'bcrt' };
// mutinynet is a signet — same address params as testnet (tb1…), matching Boltz's
// bitcoinSignet. Without this entry netFor() falls back to mainnet and the swap
// P2TR address is computed wrong → "lockup address mismatch".
const NETS = { mainnet: btc.NETWORK, testnet: btc.TEST_NETWORK, mutinynet: btc.TEST_NETWORK, regtest: REGTEST };
export const netFor = (name) => NETS[name] || btc.NETWORK;

const TAP_LEAF_VERSION = 0xc0;

export const hash160 = (b) => ripemd160(sha256(b));
const sha256d = (b) => sha256(b);

// BIP340/341 tagged hash: sha256(sha256(tag) || sha256(tag) || msg).
function taggedHash(tag, ...msgs) {
  const tagHash = sha256(new TextEncoder().encode(tag));
  return sha256(concatBytes(tagHash, tagHash, ...msgs));
}

// Minimal CScriptNum push of a non-negative locktime, as bitcoin's
// script::Builder::push_lock_time / push_int produces (used in the refund leaf).
function pushScriptNum(n) {
  if (n === 0) return Uint8Array.of(0x00); // OP_0
  if (n >= 1 && n <= 16) return Uint8Array.of(0x50 + n); // OP_1..OP_16
  const out = [];
  let v = n;
  while (v > 0) { out.push(v & 0xff); v >>= 8; }
  if (out[out.length - 1] & 0x80) out.push(0x00); // sign byte for positives
  return concatBytes(Uint8Array.of(out.length), Uint8Array.from(out));
}

// data push of a byte slice with its OP_PUSHBYTES_N length prefix (slices here
// are always < 76 bytes: a 20-byte hash160 or a 32-byte x-only key).
const pushData = (b) => concatBytes(Uint8Array.of(b.length), b);

const OP = { HASH160: 0xa9, EQUALVERIFY: 0x88, CHECKSIG: 0xac, CHECKSIGVERIFY: 0xad, CLTV: 0xb1, SIZE: 0x82 };

// Submarine claim leaf: OP_HASH160 <h160> OP_EQUALVERIFY <claimX> OP_CHECKSIG
export function submarineClaimLeaf(preimageHash160, claimXonly) {
  return concatBytes(
    Uint8Array.of(OP.HASH160), pushData(preimageHash160), Uint8Array.of(OP.EQUALVERIFY),
    pushData(claimXonly), Uint8Array.of(OP.CHECKSIG),
  );
}

// Reverse claim leaf: OP_SIZE <32> OP_EQUALVERIFY OP_HASH160 <h160> OP_EQUALVERIFY <claimX> OP_CHECKSIG
export function reverseClaimLeaf(preimageHash160, claimXonly) {
  return concatBytes(
    Uint8Array.of(OP.SIZE), pushData(Uint8Array.of(32)), Uint8Array.of(OP.EQUALVERIFY),
    Uint8Array.of(OP.HASH160), pushData(preimageHash160), Uint8Array.of(OP.EQUALVERIFY),
    pushData(claimXonly), Uint8Array.of(OP.CHECKSIG),
  );
}

// Refund leaf (both kinds): <refundX> OP_CHECKSIGVERIFY <locktime> OP_CLTV
export function refundLeaf(refundXonly, lockTime) {
  return concatBytes(
    pushData(refundXonly), Uint8Array.of(OP.CHECKSIGVERIFY),
    pushScriptNum(lockTime), Uint8Array.of(OP.CLTV),
  );
}

// Use @scure's BIP341 leaf hash (handles the compact-size encoding + tag).
export function tapLeafHash(script) {
  return scureTapLeafHash(script, TAP_LEAF_VERSION);
}

// Two-leaf Taproot merkle root: TapBranch of the lexicographically-sorted
// (claim, refund) leaf hashes (BIP341).
export function swapMerkleRoot(claimLeafScript, refundLeafScript) {
  const a = tapLeafHash(claimLeafScript);
  const b = tapLeafHash(refundLeafScript);
  const [lo, hi] = compareBytes(a, b) <= 0 ? [a, b] : [b, a];
  return taggedHash('TapBranch', lo, hi);
}

function compareBytes(a, b) {
  for (let i = 0; i < a.length; i++) { if (a[i] !== b[i]) return a[i] - b[i]; }
  return 0;
}

// Build the full swap tree for a given kind from Hal's own inputs. Returns the
// leaf scripts + merkle root so the caller can verify Boltz's lockup address
// and later construct a script-path spend.
export function buildSwapTree(kind, preimageHash160, claimXonly, refundXonly, lockTime) {
  const claim = kind === 'reverse'
    ? reverseClaimLeaf(preimageHash160, claimXonly)
    : submarineClaimLeaf(preimageHash160, claimXonly);
  const refund = refundLeaf(refundXonly, lockTime);
  return { claimLeaf: claim, refundLeaf: refund, merkleRoot: swapMerkleRoot(claim, refund) };
}

// Taproot internal key = MuSig2 aggregate of the two 33-byte pubkeys, x-only,
// in the FIXED order [boltzKey, halKey] (no sort). Boltz builds the musig as
// Musig.create(ourPriv, [ourPub, theirPub]) without sorting, and "ours" is
// always Boltz, so the address is agg([boltzPub, halPub]). Verified live
// against Boltz's lockupAddress (6/6; sorted fails when key order differs).
export function swapInternalKey(boltzPub33, halPub33) {
  return keyAggExport(keyAggregate([boltzPub33, halPub33]));
}

// Full swap P2TR for either flow. Roles by kind:
//   reverse   — hal CLAIMS (preimage), Boltz REFUNDS  → claim leaf = halKey,   refund leaf = boltzKey
//   submarine — Boltz CLAIMS (preimage), hal REFUNDS  → claim leaf = boltzKey, refund leaf = halKey
// Internal key is always agg([boltzKey, halKey]). Pubkeys are 33-byte compressed.
// Returns the address + @scure p2tr payment (for control blocks/spending) + leaves.
export function swapP2TR({ kind, preimageHash160, boltzPub33, halPub33, lockTime, network = 'regtest' }) {
  const claimPub = kind === 'reverse' ? halPub33 : boltzPub33;   // who can claim
  const refundPub = kind === 'reverse' ? boltzPub33 : halPub33;  // who can refund
  const claim = kind === 'reverse'
    ? reverseClaimLeaf(preimageHash160, claimPub.slice(1))
    : submarineClaimLeaf(preimageHash160, claimPub.slice(1));
  const refund = refundLeaf(refundPub.slice(1), lockTime);
  const internalKey = swapInternalKey(boltzPub33, halPub33);
  const tree = taprootListToTree([{ script: claim }, { script: refund }]);
  const pay = p2tr(internalKey, tree, netFor(network), true);
  return { address: pay.address, script: pay.script, pay, internalKey, claimLeaf: claim, refundLeaf: refund };
}

const eqBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

// Build a signed taproot SCRIPT-PATH spend of a swap lockup output. This is the
// non-custodial path that needs no Boltz cooperation:
//   reverse claim  — witness [sig, preimage, claimLeaf, controlBlock]
//   submarine refund — witness [sig, refundLeaf, controlBlock], nLockTime=lockTime
// `leaf` is the leaf script being spent; `preimage` is required for a claim and
// omitted for a refund. Returns the raw signed tx hex ready to broadcast.
export function buildSwapSpend({
  pay, leaf, halPriv, preimage = null,
  lockupTxid, lockupVout, lockupValue, destAddress,
  fee, lockTime = 0, network = 'regtest',
}) {
  const net = netFor(network);
  const isRefund = preimage === null;
  // Find the @scure leaf entry (control block + script||version) for this leaf.
  const idx = pay.leaves.findIndex((l) => eqBytes(l.script, leaf));
  if (idx < 0) throw new Error('leaf not found in swap tree');
  const controlBlock = pay.leaves[idx].controlBlock;

  const tx = new btc.Transaction({ allowUnknownOutputs: true, version: 2 });
  tx.addInput({
    txid: lockupTxid, index: lockupVout,
    witnessUtxo: { script: pay.script, amount: BigInt(lockupValue) },
    tapLeafScript: [pay.tapLeafScript[idx]],
    tapInternalKey: pay.tapInternalKey,
    sequence: isRefund ? 0xfffffffd : 0xffffffff, // refund: non-final for CLTV
  });
  if (isRefund && lockTime) tx.lockTime = lockTime;
  tx.addOutputAddress(destAddress, BigInt(lockupValue - fee), net);

  // Sighash for the leaf (BIP341 script path, SIGHASH_DEFAULT) + schnorr sig.
  const sighash = tx.preimageWitnessV1(
    0, [pay.script], btc.SigHash.DEFAULT, [BigInt(lockupValue)],
    undefined, leaf, TAP_LEAF_VERSION,
  );
  const sig = schnorr.sign(sighash, halPriv);

  // Assemble the witness manually (preimage inserted for a claim).
  const witness = isRefund
    ? [sig, leaf, controlBlock]
    : [sig, preimage, leaf, controlBlock];
  tx.updateInput(0, { finalScriptWitness: witness });
  return tx.hex;
}

// ---------------------------------------------------------------------------
// Boltz api-v2 client + bolt11 decode + SwapManager (polling-based).
// ---------------------------------------------------------------------------

async function boltzReq(apiBase, path, body) {
  const opt = body
    ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }
    : {};
  const r = await fetch(apiBase.replace(/\/+$/, '') + path, opt);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j?.error || `boltz ${path}: ${r.status}`);
  return j;
}

function convertBits(data, from, to) {
  let acc = 0, bits = 0; const out = []; const maxv = (1 << to) - 1;
  for (const v of data) { acc = (acc << from) | v; bits += from; while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); } }
  return Uint8Array.from(out);
}

// Decode the payment hash (+ amount in msat, best-effort) from a bolt11 invoice.
export function decodeBolt11(invoice) {
  const dec = bech32.decode(invoice.toLowerCase(), 4000);
  const words = dec.words;
  const m = dec.prefix.match(/^ln[a-z]+?(\d+)([munp])?$/);
  let amountMsat = null;
  if (m && m[1]) {
    const n = BigInt(m[1]);
    if (m[2] === 'p') amountMsat = n / 10n;
    else amountMsat = n * ({ m: 100000000n, u: 100000n, n: 100n }[m[2]] ?? 100000000000n);
  }
  let payHash = null;
  const end = words.length - 104; // last 104 words = signature
  for (let i = 7; i + 3 <= end;) {
    const type = words[i];
    const len = (words[i + 1] << 5) | words[i + 2];
    if (type === 1 && len === 52) payHash = convertBits(words.slice(i + 3, i + 3 + len), 5, 8).slice(0, 32);
    i += 3 + len;
  }
  if (!payHash) throw new Error('invoice missing payment hash');
  return { paymentHash: payHash, amountMsat };
}

// Orchestrates non-custodial swaps: creates them via Boltz, verifies the lockup
// address locally before any funds move, then polls the chain (via the wallet's
// esplora api) to claim (reverse) or detect success/refund (submarine). DOM-free.
// Wallet storage/key helpers for this feature, installed onto the core
// wallet instance so a build without the feature ships none of it.
export function installSwapWallet(wallet) {
  if (wallet.loadSwaps) return; // already installed
  Object.assign(wallet, {
    // ---- Boltz swap support ----------------------------------------------
    // Persisted swap records (public metadata only — keys/preimage are re-derived
    // deterministically from the seed via swapNode, so nothing secret is stored).
    _swapKey() { return this._cacheKey() + ':swaps'; },
    loadSwaps() {
      try { return JSON.parse(localStorage.getItem(this._swapKey()) || '[]'); } catch { return []; }
    },
    saveSwaps(list) {
      try { localStorage.setItem(this._swapKey(), JSON.stringify(list)); } catch {}
    },
    _swapIdxKey() { return this._cacheKey() + ':swapidx'; },
    // Reserve the next swap index: monotonic + persisted on every call. A reverse/
    // submarine attempt that fails AFTER Boltz created the swap (a later validation
    // throw, a dropped response) still burns its index, so a retry can't reuse the
    // same deterministic preimage (Boltz rejects "swap with this preimage exists").
    // Seeded from saved swaps so existing wallets don't regress.
    nextSwapIndex() {
      const fromSaved = this.loadSwaps().reduce((m, s) => Math.max(m, (s.swapIndex ?? -1) + 1), 0);
      let stored = 0;
      try { stored = parseInt(localStorage.getItem(this._swapIdxKey()) || '0', 10) || 0; } catch {}
      const idx = Math.max(fromSaved, stored);
      try { localStorage.setItem(this._swapIdxKey(), String(idx + 1)); } catch {}
      return idx;
    },
    // Deterministic swap keypair on a dedicated chain (2) so swap keys never
    // collide with receive (0) / change (1). Returns the HDKey node (has
    // privateKey + publicKey, 33-byte compressed).
    swapNode(index) {
      return this.account().deriveChild(2).deriveChild(index);
    },
  });
}

export class SwapManager {
  constructor({ wallet, network = 'regtest', getApi, feeRate = 2, onUpdate }) {
    this.wallet = wallet;
    this.network = network;
    this.getApi = getApi;                 // () => boltz REST base url
    this.feeRate = feeRate;               // sat/vB for funding + claim/refund
    this.onUpdate = onUpdate || (() => {});
    this.timers = new Map();
  }

  list() { return this.wallet.loadSwaps(); }
  // The swap (if any) an on-chain tx belongs to — its lockup funding (submarine),
  // claim (reverse), or refund. Lets the tx detail screen show the swap context.
  findByTxid(txid) { return this.list().find((s) => s.fundTxid === txid || s.claimTxid === txid || s.refundTxid === txid) || null; }
  _get(id) { return this.wallet.loadSwaps().find((s) => s.id === id); }
  _save(rec) {
    const list = this.wallet.loadSwaps();
    const i = list.findIndex((s) => s.id === rec.id);
    if (i >= 0) list[i] = rec; else list.push(rec);
    this.wallet.saveSwaps(list);
    this.onUpdate(rec);
  }
  _stop(id) { const t = this.timers.get(id); if (t) clearInterval(t); this.timers.delete(id); }
  _spendFee() { return Math.max(250, Math.ceil(170 * this.feeRate)); } // ~1-input taproot spend

  // The selected provider's reverse-swap limits (sat), fetched + cached per API.
  // Lets the UI bound the amount to what the provider actually accepts instead of
  // a hardcoded guess (providers + networks differ). Falls back conservatively.
  async reverseLimits() {
    const api = this.getApi();
    if (this._revLim && this._revLimApi === api) return this._revLim;
    let lim = { min: 25000, max: 25000000 };
    try {
      const res = await boltzReq(api, '/v2/swap/reverse');
      const b = res && res.BTC && res.BTC.BTC && res.BTC.BTC.limits;
      if (b && b.minimal) lim = { min: b.minimal, max: b.maximal };
    } catch {}
    this._revLim = lim; this._revLimApi = api;
    return lim;
  }

  // REVERSE: hal receives over Lightning. Returns a record whose `.invoice`
  // (bolt11) the user has someone pay; hal then claims the lockup on-chain.
  async startReverse(amountSat) {
    const w = this.wallet, net = this.network;
    let idx, node, preimage, res;
    // Our preimage is deterministic per swap index. If a prior attempt burned this
    // index at Boltz ("swap with this preimage exists"), nextSwapIndex has advanced,
    // so just retry with the next one.
    for (let attempt = 0; ; attempt++) {
      idx = w.nextSwapIndex();
      node = w.swapNode(idx);
      preimage = sha256(node.privateKey);
      try {
        res = await boltzReq(this.getApi(), '/v2/swap/reverse', {
          invoiceAmount: amountSat, from: 'BTC', to: 'BTC',
          claimPublicKey: bytesToHex(node.publicKey), preimageHash: bytesToHex(sha256(preimage)),
        });
        break;
      } catch (e) {
        if (attempt < 5 && /preimage|already exist/i.test(String(e?.message || e))) continue;
        throw e;
      }
    }
    const d = swapP2TR({ kind: 'reverse', preimageHash160: hash160(preimage), boltzPub33: hexToBytes(res.refundPublicKey), halPub33: node.publicKey, lockTime: res.timeoutBlockHeight, network: net });
    if (d.address !== res.lockupAddress) throw new Error('lockup address mismatch — not paying');
    if (bytesToHex(decodeBolt11(res.invoice).paymentHash) !== bytesToHex(sha256(preimage))) throw new Error('invoice hash mismatch');
    const rec = { id: res.id, kind: 'reverse', swapIndex: idx, status: 'awaiting-payment', network: net, invoice: res.invoice, lockupAddress: res.lockupAddress, onchainAmount: res.onchainAmount, refundPublicKey: res.refundPublicKey, timeoutBlockHeight: res.timeoutBlockHeight, createdAt: Date.now() };
    this._save(rec);
    this._watchReverse(rec.id);
    return rec;
  }

  _watchReverse(id) {
    if (this.timers.has(id)) return;
    const w = this.wallet, net = this.network;
    const tick = async () => {
      const rec = this._get(id);
      if (!rec || ['claimed', 'failed'].includes(rec.status)) return this._stop(id);
      try {
        const utxos = await w.api.addressUtxos(rec.lockupAddress);
        if (!utxos || !utxos.length) return;
        const u = utxos[0];
        const node = w.swapNode(rec.swapIndex);
        const preimage = sha256(node.privateKey);
        const d = swapP2TR({ kind: 'reverse', preimageHash160: hash160(preimage), boltzPub33: hexToBytes(rec.refundPublicKey), halPub33: node.publicKey, lockTime: rec.timeoutBlockHeight, network: net });
        const fee = this._spendFee();
        const destAddress = w.freshReceive().address;
        const hex = buildSwapSpend({ pay: d.pay, leaf: d.claimLeaf, halPriv: node.privateKey, preimage, lockupTxid: u.txid, lockupVout: u.vout, lockupValue: u.value, destAddress, fee, network: net });
        const txid = await w.api.broadcast(hex);
        rec.status = 'claimed'; rec.claimTxid = txid; rec.received = u.value - fee;
        this._save(rec); this._stop(id);
        // Credit the claimed coin (single output → destAddress) now, so the balance
        // + generic "payment received" fire instantly instead of waiting for a scan.
        if (w.creditReceive) w.creditReceive({ txid, vout: 0, value: rec.received, address: destAddress });
      } catch (e) { rec.lastError = String(e?.message || e); this.onUpdate(rec); }
    };
    this.timers.set(id, setInterval(tick, 3000)); tick();
  }

  // SUBMARINE: hal spends over Lightning. Funds the lockup from the wallet;
  // Boltz pays the invoice + claims. On failure, refund after the timeout.
  async startSubmarine(invoice) {
    return this.fundQuotedSubmarine(await this.quoteSubmarine(invoice));
  }

  // Quote a submarine swap WITHOUT committing funds: ask Boltz for the lockup
  // amount + build (but don't broadcast) the funding tx, so the UI can show an
  // itemized cost (amount + Boltz fee + on-chain network fee) before the user
  // pays. Returns everything fundQuotedSubmarine() needs.
  async quoteSubmarine(invoice) {
    const w = this.wallet, net = this.network;
    const dec = decodeBolt11(invoice);
    const idx = w.nextSwapIndex();
    const node = w.swapNode(idx);
    const res = await boltzReq(this.getApi(), '/v2/swap/submarine', { invoice, from: 'BTC', to: 'BTC', refundPublicKey: bytesToHex(node.publicKey) });
    const d = swapP2TR({ kind: 'submarine', preimageHash160: ripemd160(dec.paymentHash), boltzPub33: hexToBytes(res.claimPublicKey), halPub33: node.publicKey, lockTime: res.timeoutBlockHeight, network: net });
    if (d.address !== res.address) throw new Error('lockup address mismatch — not funding');
    const draft = w.buildTx({ recipients: [{ address: res.address, amount: res.expectedAmount }], feeRate: this.feeRate });
    const invoiceAmount = dec.amountMsat ? Number(dec.amountMsat / 1000n) : null;
    return {
      invoice, id: res.id, swapIndex: idx, lockupAddress: res.address, expectedAmount: res.expectedAmount,
      claimPublicKey: res.claimPublicKey, timeoutBlockHeight: res.timeoutBlockHeight, paymentHash: bytesToHex(dec.paymentHash),
      invoiceAmount, networkFee: draft.fee, boltzFee: invoiceAmount != null ? res.expectedAmount - invoiceAmount : null,
      total: res.expectedAmount + draft.fee, _draft: draft,
    };
  }

  // Broadcast the funding tx for a previously-quoted submarine swap + watch it.
  async fundQuotedSubmarine(q) {
    const w = this.wallet, net = this.network;
    const rec = { id: q.id, kind: 'submarine', swapIndex: q.swapIndex, status: 'funding', network: net, paymentHash: q.paymentHash, lockupAddress: q.lockupAddress, expectedAmount: q.expectedAmount, claimPublicKey: q.claimPublicKey, timeoutBlockHeight: q.timeoutBlockHeight, invoiceAmount: q.invoiceAmount, createdAt: Date.now() };
    this._save(rec);
    const fundTxid = await w.broadcast(w.sign(q._draft.tx));
    if (w.applySentTx) w.applySentTx(q._draft.tx);
    rec.fundTxid = fundTxid; rec.status = 'paying'; this._save(rec);
    this._watchSubmarine(rec.id);
    return rec;
  }

  _watchSubmarine(id) {
    if (this.timers.has(id)) return;
    // For a submarine swap the success moment is invoice.paid — Boltz has paid the
    // Lightning invoice (the whole point). It then claims its on-chain lockup
    // (transaction.claim.pending → claimed), often deferred to a later batch, but
    // our funds are already gone to the LN destination, so we're done either way.
    const done = new Set(['invoice.paid', 'transaction.claim.pending', 'transaction.claimed', 'invoice.settled']);
    const bad = new Set(['invoice.failedToPay', 'swap.expired', 'transaction.lockupFailed', 'transaction.refunded']);
    const tick = async () => {
      const rec = this._get(id);
      if (!rec || ['success', 'refunded', 'failed'].includes(rec.status)) return this._stop(id);
      try {
        const s = await boltzReq(this.getApi(), `/v2/swap/${rec.id}`);
        rec.boltzStatus = s.status;
        if (done.has(s.status)) { rec.status = 'success'; this._save(rec); this._stop(id); return; }
        if (bad.has(s.status)) { rec.status = 'refundable'; this._save(rec); this._stop(id); return; }
        this._save(rec);
      } catch (e) { rec.lastError = String(e?.message || e); this.onUpdate(rec); }
    };
    this.timers.set(id, setInterval(tick, 3000)); tick();
  }

  // Refund a failed submarine swap on-chain via the timeout script path. Only
  // succeeds once chain height >= timeoutBlockHeight (CLTV).
  async refundSubmarine(id) {
    const w = this.wallet, net = this.network;
    const rec = this._get(id);
    if (!rec || rec.kind !== 'submarine') throw new Error('not a submarine swap');
    const utxos = await w.api.addressUtxos(rec.lockupAddress);
    if (!utxos || !utxos.length) throw new Error('no lockup utxo to refund');
    const u = utxos[0];
    const node = w.swapNode(rec.swapIndex);
    const d = swapP2TR({ kind: 'submarine', preimageHash160: ripemd160(hexToBytes(rec.paymentHash)), boltzPub33: hexToBytes(rec.claimPublicKey), halPub33: node.publicKey, lockTime: rec.timeoutBlockHeight, network: net });
    const fee = this._spendFee();
    const hex = buildSwapSpend({ pay: d.pay, leaf: d.refundLeaf, halPriv: node.privateKey, preimage: null, lockupTxid: u.txid, lockupVout: u.vout, lockupValue: u.value, destAddress: w.freshReceive().address, fee, lockTime: rec.timeoutBlockHeight, network: net });
    const txid = await w.api.broadcast(hex);
    rec.status = 'refunded'; rec.refundTxid = txid; this._save(rec);
    return txid;
  }

  // Re-attach watchers to non-final swaps after a page reload.
  resumeAll() {
    for (const rec of this.list()) {
      if (rec.kind === 'reverse' && !['claimed', 'failed'].includes(rec.status)) this._watchReverse(rec.id);
      else if (rec.kind === 'submarine' && ['funding', 'paying'].includes(rec.status)) this._watchSubmarine(rec.id);
    }
  }
}

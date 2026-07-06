// Gift wallet primitives — coin reservation, gift creation (incl. the
// split-first flow), the compact gift codec, claiming, and nostr-locked
// gifts. Installed onto the Wallet instance by the gifts feature so a build
// without gifts ships none of this.

import * as btc from '@scure/btc-signer';
import { hex, base64urlnopad, base32nopad } from '@scure/base';
import { utxoId } from '../wallet.js';
import { encryptGiftPayload } from '../nostr.js';
import { p2wpkh } from '@scure/btc-signer/payment';
import { concatBytes } from '@noble/hashes/utils';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));


export function installGiftWallet(wallet) {
  if (wallet.createGift) return; // already installed
  Object.assign(wallet, {
    // Confirmed coins locked behind unclaimed gift links. The whole source coin is
    // committed until the gift is claimed (our change only comes back in the
    // claimer's tx), so it's already excluded from spending — and from the
    // spendable balance below.
    giftLockedValue() {
      const res = this.reservedSet();
      return this.utxos.reduce((s, u) => s + (res.has(utxoId(u)) ? u.value : 0), 0);
    },

    // --- gift links (coins backing claimable presigned transactions) ---------
    // A gift coin is either RESERVED (set aside, skipped by coin selection) or
    // RECLAIMED (freed for spending, but its link stays live until the coin is
    // actually spent). Both are "outstanding"; both are persisted per-wallet.
    _giftKey() {
      return this._cacheKey() + ':gift';
    },

    _reclaimedKey() {
      return this._cacheKey() + ':giftfree';
    },

    reservedSet() {
      if (!this._reserved) this._reserved = this._loadSet(this._giftKey());
      return this._reserved;
    },

    reclaimedSet() {
      if (!this._reclaimed) this._reclaimed = this._loadSet(this._reclaimedKey());
      return this._reclaimed;
    },

    _saveReserved() {
      try { localStorage.setItem(this._giftKey(), JSON.stringify([...this.reservedSet()])); } catch {}
    },

    _saveReclaimed() {
      try { localStorage.setItem(this._reclaimedKey(), JSON.stringify([...this.reclaimedSet()])); } catch {}
    },

    isReserved(id) {
      return this.reservedSet().has(id);
    },

    // Passive reclaim: free the coin for spending but keep tracking the live link
    // so it can still be revoked later (until the coin is spent).
    unreserve(id) {
      this.reservedSet().delete(id);
      this.reclaimedSet().add(id);
      this._saveReserved();
      this._saveReclaimed();
      try { this.saveCache(); } catch {} // publish the gift-state change to sync
    },

    // Truly revoke an unclaimed gift: spend its coin back into our own wallet,
    // which double-spends the gift's presigned input so the link can't be claimed
    // once this confirms. Uses a high fee to win any race with a claimer.
    async revokeGift(id, feeRate) {
      const draft = this.buildTx({ recipients: [{ address: this.freshChange().address }], feeRate, coinIds: [id], sendMax: true });
      const hexTx = this.sign(draft.tx);
      const txid = await this.broadcast(hexTx);
      this.reservedSet().delete(id);
      this.reclaimedSet().delete(id);
      this._saveReserved();
      this._saveReclaimed();
      try { this.saveCache(); } catch {}
      return txid;
    },

    giftLink(id) { return this.giftRecords()[id] || null; },

    markGiftRevoked(id) { const r = this.giftRecords()[id]; if (r) { r.revoked = true; this._saveGiftRecords(); try { this.saveCache(); } catch {} } },

    giftRecords() {
      if (!this._giftRecords) { try { this._giftRecords = JSON.parse(localStorage.getItem(this._giftRecordsKey()) || '{}'); } catch { this._giftRecords = {}; } }
      return this._giftRecords;
    },

    _saveGiftRecords() { try { localStorage.setItem(this._giftRecordsKey(), JSON.stringify(this.giftRecords())); } catch {} },

    // Remember which tx claimed a gift (resolved lazily via outspend) so the
    // history can merge the gift row with its claim transaction.
    setGiftClaimTx(id, txid) {
      const recs = this.giftRecords();
      if (recs[id] && recs[id].claimTxid !== txid) {
        recs[id].claimTxid = txid;
        this._saveGiftRecords();
      }
    },

    // Outstanding gifts (reserved + reclaimed) whose coin is still unspent; prunes
    // any whose coin has since been claimed/spent. { id, reserved, value }.
    outstandingGifts() {
      const live = new Set(this.utxos.map((u) => utxoId(u)));
      const res = this.reservedSet();
      const rec = this.reclaimedSet();
      let changed = false;
      for (const id of [...res]) if (!live.has(id)) { res.delete(id); changed = true; }
      for (const id of [...rec]) if (!live.has(id)) { rec.delete(id); changed = true; }
      if (changed) { this._saveReserved(); this._saveReclaimed(); }
      return [...new Set([...res, ...rec])].map((id) => ({
        id,
        reserved: res.has(id),
        value: (this.utxos.find((u) => utxoId(u) === id) || {}).value,
      }));
    },

    // Gifts whose coin has been spent and weren't revoked by us → claimed. (Only
    // once scanned, so an un-synced wallet doesn't mislabel everything as claimed.)
    claimedGifts() {
      if (!this.loaded) return [];
      const live = new Set(this.utxos.map((u) => utxoId(u)));
      return Object.values(this.giftRecords())
        .filter((r) => !r.revoked && r.outpoints && !r.outpoints.some((o) => live.has(o)))
        .map((r) => ({ id: r.id, amount: r.amount, locked: r.locked, created: r.created, claimTxid: r.claimTxid || null, outpoints: r.outpoints }))
        .sort((a, b) => (b.created || 0) - (a.created || 0));
    },

    // Best-fit coin selection for a gift of `gift` sats (needs gift + a dust
    // change): the smallest single confirmed coin that covers it — one input and
    // the least value locked until claim — else the fewest large coins. Returns
    // the selected UTXOs, or null if confirmed funds are insufficient.
    _selectGiftCoins(gift) {
      const DUST = 294n;
      const need = gift + DUST;
      const avail = this.utxos.filter((u) => !this.isReserved(utxoId(u)) && (u.confirmed || u.chain === 1));
      const single = avail.filter((u) => BigInt(u.value) >= need).sort((a, b) => a.value - b.value)[0];
      if (single) return [single];
      const sel = [];
      let sum = 0n;
      for (const u of [...avail].sort((a, b) => b.value - a.value)) {
        sel.push(u);
        sum += BigInt(u.value);
        if (sum >= need) return sel;
      }
      return null; // insufficient confirmed funds
    },

    // Build a gift link from a best-fit coin, locking the least value. No fee is
    // reserved here: the claimer's wallet looks up the fee rate at claim time and
    // subtracts it from the amount.
    createGift(amountSats, feeRate) {
      const gift = BigInt(Math.round(amountSats));
      const rate = Math.max(1, Math.round(feeRate));
      if (gift < BigInt(giftMinimum(rate))) throw new Error('Gift amount is too small.');
      const sel = this._selectGiftCoins(gift);
      if (!sel) throw new Error('Not enough confirmed funds for that gift amount.');
      return this._buildGiftPsbt(sel, gift);
    },

    // Gift the entire spendable balance: a no-change sweep of all unreserved
    // spendable coins (confirmed, plus our own unconfirmed change). The claimer
    // receives the whole amount minus their claim fee.
    createGiftAll(feeRate) {
      const rate = Math.max(1, Math.round(feeRate));
      const sel = this.utxos.filter((u) => !this.isReserved(utxoId(u)) && (u.confirmed || u.chain === 1));
      if (!sel.length) throw new Error('No coins available to gift.');
      const sum = sel.reduce((s, u) => s + BigInt(u.value), 0n);
      if (sum < BigInt(giftMinimum(rate))) throw new Error('Gift amount is too small.');
      return this._buildGiftPsbt(sel, sum); // change = 0 → no-change sweep
    },

    // Split + gift in one shot, with no confirmation wait: broadcast a self-send
    // that carves out a gift+dust coin, then build the gift spending that
    // still-unconfirmed carve-out. The funding and the claim form a chain that
    // confirms together; the recipient just sees a pending balance until the
    // split confirms. Lets the sender lock only ~the gift amount (instead of a
    // whole large coin) without waiting for the split to confirm first.
    async createGiftFromSplit(amountSats, feeRate) {
      const gift = Math.round(amountSats);
      const rate = Math.max(1, Math.round(feeRate));
      if (BigInt(gift) < BigInt(giftMinimum(rate))) throw new Error('Gift amount is too small.');
      const DUST = 294;
      const recvIndex = this.nextReceiveIndex;
      const carveAddr = this.derive(0, recvIndex).address;
      const changeIndex = this.nextChangeIndex;

      // Carve out exactly gift + dust to one of our own addresses; the rest comes
      // back as change. buildTx already spends confirmed coins largest-first.
      const draft = this.buildTx({ recipients: [{ address: carveAddr, amount: gift + DUST }], feeRate: rate });
      const carveIdx = draft.outputs.findIndex((o) => o.address === carveAddr);
      if (carveIdx < 0) throw new Error('Could not size the split output.');
      const hexTx = this.sign(draft.tx);
      const splitTxid = draft.tx.id;
      await this.broadcast(hexTx);

      // Wait until the carve-out is actually visible in the mempool before we
      // build the gift on top of it and reserve it. Otherwise a background refresh
      // could rebuild the address from a not-yet-indexed API response, transiently
      // drop the coin, and prune the reservation — risking a double-spend.
      let seen = false;
      for (let i = 0; i < 8 && !seen; i++) {
        await sleep(i === 0 ? 400 : 900);
        try {
          const us = await this.api.addressUtxos(carveAddr);
          seen = us.some((u) => u.txid === splitTxid && u.vout === carveIdx);
        } catch {}
      }
      if (!seen) throw new Error('The split is taking a while to propagate. Once it confirms, create the gift from the new coin.');

      // Reflect the split in our coin set — drop the spent inputs, add the
      // (now mempool-visible) carve-out and change — so balances and gift tracking
      // are correct immediately; a background scan reconciles the rest.
      const spent = new Set();
      for (let i = 0; i < draft.tx.inputsLength; i++) {
        const inp = draft.tx.getInput(i);
        spent.add(`${hex.encode(inp.txid)}:${inp.index}`);
      }
      this.utxos = this.utxos.filter((u) => !spent.has(utxoId(u)));
      this.utxos.push({ txid: splitTxid, vout: carveIdx, value: gift + DUST, address: carveAddr, chain: 0, index: recvIndex, confirmed: false });
      const changeIdx = draft.outputs.findIndex((o, i) => i !== carveIdx);
      if (changeIdx >= 0) {
        const co = draft.outputs[changeIdx];
        this.utxos.push({ txid: splitTxid, vout: changeIdx, value: co.amount, address: co.address, chain: 1, index: changeIndex, confirmed: false });
      }
      this._recomputeBalanceFromUtxos();

      return this._buildGiftPsbt([{ txid: splitTxid, vout: carveIdx, value: gift + DUST, chain: 0, index: recvIndex }], BigInt(gift));
    },

    // The coins a gift of this amount would lock: total value + how many inputs.
    // A high input count means a costly-to-claim gift (each input adds to the
    // claimer's fee) — the UI uses it to recommend splitting/consolidating first.
    giftCoinSummary(amountSats) {
      const sel = this._selectGiftCoins(BigInt(Math.round(amountSats)));
      return sel ? { lock: sel.reduce((s, u) => s + u.value, 0), count: sel.length } : null;
    },


    // Persistent gift records (per account): the shareable link/code + amount, so a
    // gift's link/QR can be re-viewed later and a claimed one identified in history.
    _giftRecordsKey() { return this._cacheKey() + ':giftrec'; },

    recordGift({ code, locked, amount, claimCode, outpoints }) {
      if (!outpoints || !outpoints.length) return;
      this.giftRecords()[outpoints[0]] = { id: outpoints[0], code, locked: !!locked, amount, claimCode: claimCode || null, outpoints, created: Date.now(), revoked: false };
      this._saveGiftRecords();
      try { this.saveCache(); } catch {} // publish the new gift to cross-device sync
    },

    // Sats that creating this gift right now would lock (the selected coins'
    // total), or null if confirmed funds are insufficient. Lets the UI warn when
    // the lock would dwarf the gift and offer to split a coin first.
    giftLockPreview(amountSats) {
      const sel = this._selectGiftCoins(BigInt(Math.round(amountSats)));
      return sel ? sel.reduce((s, u) => s + u.value, 0) : null;
    },

    // Build a signed gift from already-chosen coins. If the gift leaves a viable
    // (>= dust) change, output0 is that change back to us, cryptographically fixed
    // by signing input0 SIGHASH_SINGLE (the rest SIGHASH_NONE) — so our change is
    // locked while the claimer is free to add their own output. If there's no
    // viable change (a whole-balance gift), there's no output at all and every
    // input is SIGHASH_NONE, so the claimer sweeps the entire amount. Reserves the
    // coins; returns { code, amount, reserved } where amount is what the claimer
    // receives before their fee (the gift, or the whole swept sum).
    _buildGiftPsbt(sel, gift) {
      const DUST = 294n;
      const sum = sel.reduce((s, u) => s + BigInt(u.value), 0n);
      const change = sum - gift;
      const keepChange = change >= DUST;
      const sigOf = (i) => (keepChange && i === 0 ? btc.SigHash.SINGLE : btc.SigHash.NONE);
      const t = new btc.Transaction({ allowUnknownOutputs: true });
      sel.forEach((u, i) => {
        const pay = p2wpkh(this.derive(u.chain, u.index).pubkey, this.netCfg.net);
        t.addInput({ ...pay, txid: u.txid, index: u.vout, sighashType: sigOf(i), witnessUtxo: { script: pay.script, amount: BigInt(u.value) } });
      });
      if (keepChange) t.addOutputAddress(this.freshChange().address, change, this.netCfg.net);
      sel.forEach((u, i) => t.signIdx(this.node(u.chain, u.index).privateKey, i, [sigOf(i)]));

      for (const u of sel) this.reservedSet().add(utxoId(u));
      this._saveReserved();
      return { code: base32nopad.encode(_encodeCompactGift(t)), amount: Number(keepChange ? gift : sum), reserved: sel.map(utxoId) };
    },
  });
  // reserved gift coins are excluded from spending + the spendable balance
  wallet.registerCoinLock(() => wallet.reservedSet());

  // Sync gift state across devices (like ark): the records + reserved/reclaimed
  // coin sets are per-device localStorage, so a gift made on one device was
  // invisible on another. Ride the encrypted snapshot as a merge-safe
  // extension: union records (revoked/claimTxid flags sticky), union both coin
  // sets. Each device's own scan then reconciles which coins are still live.
  wallet.registerCacheExtension({
    mergeAlways: true,
    save: () => ({
      giftState: {
        records: wallet.giftRecords(),
        reserved: [...wallet.reservedSet()],
        reclaimed: [...wallet.reclaimedSet()],
      },
    }),
    load: (d) => {
      if (!d.giftState) return;
      const recs = wallet.giftRecords();
      for (const [id, r] of Object.entries(d.giftState.records || {})) {
        const local = recs[id];
        if (!local) recs[id] = r;
        else { local.revoked = local.revoked || r.revoked; if (!local.claimTxid && r.claimTxid) local.claimTxid = r.claimTxid; }
      }
      wallet._saveGiftRecords();
      const res = wallet.reservedSet(); for (const id of d.giftState.reserved || []) res.add(id);
      const rec = wallet.reclaimedSet(); for (const id of d.giftState.reclaimed || []) rec.add(id);
      wallet._saveReserved(); wallet._saveReclaimed();
    },
  });
}

// Gift-link claiming (sender side is Wallet.createGift). A gift code is a
// base64url PSBT: one SIGHASH_SINGLE-signed input + the sender's change output.
// previewGift reports the room available to the claimer (before their fee);
// buildClaimTx adds the claimer's output and finalizes a broadcastable tx.
// Smallest sensible gift at a given fee rate: dust + one claim fee of headroom
// (floored at 546 sats), so the recipient clears dust even if fees climb.
export function giftMinimum(feeRate) {
  const rate = Math.max(1, Math.round(feeRate));
  const claimFee = Math.ceil((11 + 68 + 31 * 2) * rate);
  return Math.max(546, 294 + claimFee);
}

// ---- compact gift codec ----------------------------------------------------
// A gift link used to carry a full PSBT (verbose). The claimer only needs the
// presigned inputs (outpoint, amount, pubkey, signature) and the sender's
// committed change output, so we serialize just those — ~25% smaller, and (via
// base32 + an uppercase /g/ URL) it scans in the QR's denser alphanumeric mode.
// Legacy base64url-PSBT links still claim; _giftTx auto-detects the format.
const GIFT_MAGIC = 0x01;
const _u8 = (n) => Uint8Array.of(n & 0xff);
const _le32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const _le64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };

function _encodeCompactGift(tx) {
  const hasChange = tx.outputsLength > 0;
  const parts = [_u8(GIFT_MAGIC), _u8(hasChange ? 1 : 0), _u8(tx.inputsLength)];
  for (let i = 0; i < tx.inputsLength; i++) {
    const inp = tx.getInput(i);
    const [pubkey, sig] = inp.partialSig[0]; // pubkey(33), sig = DER + sighash byte
    parts.push(inp.txid, _le32(inp.index), _le64(inp.witnessUtxo.amount), pubkey, _u8(sig.length), sig);
  }
  if (hasChange) {
    const o = tx.getOutput(0); // p2wpkh change: script = [00 14 <20-byte hash>]
    parts.push(_le64(o.amount), o.script.slice(2));
  }
  return concatBytes(...parts);
}

function _decodeCompactGift(bytes) {
  let p = 0;
  const rd = (n) => bytes.slice(p, (p += n));
  const r32 = () => { const v = new DataView(bytes.buffer, bytes.byteOffset + p, 4).getUint32(0, true); p += 4; return v; };
  const r64 = () => { const v = new DataView(bytes.buffer, bytes.byteOffset + p, 8).getBigUint64(0, true); p += 8; return v; };
  p++; // magic
  const hasChange = !!(bytes[p++] & 1);
  const n = bytes[p++];
  const t = new btc.Transaction({ allowUnknownOutputs: true });
  for (let i = 0; i < n; i++) {
    const txid = rd(32), vout = r32(), amount = r64(), pubkey = rd(33), sigLen = bytes[p++], sig = rd(sigLen);
    const pay = p2wpkh(pubkey, btc.NETWORK); // witness-program .script is network-independent
    // second arg true: re-add an already-signed input without tripping the sign-status guard
    t.addInput({ txid, index: vout, witnessUtxo: { script: pay.script, amount }, sighashType: sig[sig.length - 1], partialSig: [[pubkey, sig]] }, true);
  }
  if (hasChange) {
    const amount = r64();
    const hash = rd(20);
    t.addOutput({ script: concatBytes(_u8(0x00), _u8(0x14), hash), amount }, true);
  }
  return t;
}

// Parse a gift code to a Transaction. New format: base32(compact). Legacy:
// base64url(PSBT). Auto-detected via the compact magic byte.
function _giftTx(code) {
  try {
    const b = base32nopad.decode(code.toUpperCase());
    if (b[0] === GIFT_MAGIC) return _decodeCompactGift(b);
  } catch {}
  return btc.Transaction.fromPSBT(base64urlnopad.decode(code));
}

function _sumInputs(tx) {
  let inAmt = 0n;
  for (let i = 0; i < tx.inputsLength; i++) inAmt += tx.getInput(i).witnessUtxo.amount;
  return inAmt;
}
// The sender's change committed in a gift PSBT, or 0 for a no-change (whole-
// balance) gift that has no outputs at all.
function _giftChange(tx) {
  return tx.outputsLength > 0 ? tx.getOutput(0).amount : 0n;
}
// The gift's funding outpoints (the coins its presigned inputs spend). If any is
// already spent — even by an unconfirmed claim — the gift has been taken and
// re-claiming would be a doomed double-spend. Used to gate the claim screen.
export function giftOutpoints(code) {
  try {
    const tx = _giftTx(code);
    const out = [];
    for (let i = 0; i < tx.inputsLength; i++) {
      const inp = tx.getInput(i);
      out.push({ txid: hex.encode(inp.txid), vout: inp.index });
    }
    return out;
  } catch {
    return [];
  }
}
export function previewGift(code) {
  try {
    const tx = _giftTx(code);
    // room is the full amount the claimer receives (inputs minus our change);
    // the claim fee is subtracted from it at claim time, so report inputs too
    // so the caller can size that fee for this PSBT.
    return { room: Number(_sumInputs(tx) - _giftChange(tx)), inputs: tx.inputsLength };
  } catch {
    return null;
  }
}

export function buildClaimTx(code, toAddress, feeRate, net) {
  const tx = _giftTx(code);
  const room = _sumInputs(tx) - _giftChange(tx);
  const fee = BigInt(Math.max(1, Math.ceil((11 + 68 * tx.inputsLength + 31 * 2) * Math.max(1, Math.round(feeRate)))));
  const out = room - fee;
  if (out < 294n) throw new Error('Gift is too small to claim at this fee rate.');
  tx.addOutputAddress(toAddress, out, net);
  tx.finalize();
  return { hex: tx.hex, txid: tx.id, amount: Number(out), fee: Number(fee) };
}

// A gift locked to a recipient's nostr key. The amount + recipient pubkey are
// public (anyone can see what it is and who it's for), but the claim payload (the
// gift code) is NIP-44-encrypted to the recipient via an ephemeral key — so the
// link can be shared openly yet only the recipient's nostr key can claim it.
const LOCKED_GIFT_VERSION = 1;
// Encrypt the gift's claim payload under a one-time code. The code is delivered
// to the recipient via a nostr DM; the public link carries only the ciphertext.
// Returns { blob (for the /lg/ link), claimCode (to DM) }.
export function lockGift(code, amount, recipientPkHex) {
  const { code: claimCode, ctCode, eph, ctKey } = encryptGiftPayload(code, recipientPkHex);
  const blob = base64urlnopad.encode(new TextEncoder().encode(JSON.stringify({ v: LOCKED_GIFT_VERSION, amount, to: recipientPkHex, ct: ctCode, eph, ctKey })));
  return { blob, claimCode };
}
// The public fields of a locked-gift blob (or null). Decryption needs the code.
export function previewLockedGift(blob) {
  try {
    const o = JSON.parse(new TextDecoder().decode(base64urlnopad.decode(blob)));
    if (o.v === LOCKED_GIFT_VERSION && typeof o.amount === 'number' && o.to && o.ct) return o;
  } catch {}
  return null;
}

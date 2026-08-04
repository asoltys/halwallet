// ArkManager — persistent, crash-safe Ark wallet state on top of the
// src/ark protocol modules. Follows the wallet's SwapManager shape: a class over a
// wallet-scoped storage adapter, driving multi-step actions that are
// checkpointed to storage before and after every server-effectful RPC.
//
// The invariant that matters (learned the hard way on regtest): the ASP marks
// an input spent the moment it cosigns, so every action persists enough state
// BEFORE the effectful call to resume — and signed vtxo bytes are persisted
// the instant they exist.
//
// Keys: vtxo keys on account chain 3 (index 0 = the receive address key,
// 1.. = change/refresh outputs), mailbox key on chain 4. Chains 0-2 are used
// by the wallet for receive/change/swaps.

import { hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';
import { secp256k1 } from '@noble/curves/secp256k1';
import * as musig2 from '@scure/btc-signer/musig2';

import {
  getArkInfo, handshake, encodeAddress, decodeAddress, blindMailboxId,
  readMailbox, decodeVtxo, arkIdFromServerPubkey, GrpcError,
  grpcStream, decodeMailboxMessage, mailboxRequestBytes,
  getVtxoStatus, VTXO_STATE_SPENT,
} from './proto.js';
import {
  buildArkoorSend, cosignWithServer, buildAllSignedVtxos,
  registerVtxoTransactions, postArkoorMessage, txid,
  genUserNonces, cosignPartBytes, combineCosign,
} from './send.js';
import {
  decodeBolt11, lnSendFee, lnReceiveFee,
  requestLightningPayHtlcCosign, initiateLightningPayment, checkLightningPayment,
  requestLightningPayHtlcRevocation, startLightningReceive, checkLightningReceive,
  prepareLightningReceiveClaim, claimLightningReceive, cancelLightningReceive,
  lightningReceiveAttestation,
} from './lightning.js';
import {
  boardFee, p2trAddress, buildBoard, requestBoardCosign,
  combineBoardSignature, encodeBoardVtxo, registerBoardVtxo,
} from './board.js';
import {
  submitRoundParticipation, roundParticipationStatus, parseTx,
  cosignHarkLeaf, requestForfeitNonces, forfeitBundle, forfeitVtxos,
  encodeVtxoFromDecoded,
} from './refresh.js';
import {
  getOffboardFeeRate, feeRateKwu, offboardFee, offboardAttestation,
  prepareOffboard, validateOffboardTx, signOffboardForfeits, finishOffboard,
  P2TR_DUST,
} from './offboard.js';
import { signedExitTxs } from './exit.js';
import { validateVtxo, VtxoValidationError } from './validate.js';

const EMPTY_STATE = () => ({
  v: 1,
  serverPubkey: null, // which ASP this state belongs to (guarded in init)
  mailboxCheckpoint: 0,
  nextKeyIndex: 1, // 0 is the receive-address key
  vtxos: [],       // { id, bytes, keyIndex, amountSat, expiryHeight, state }
  actions: [],     // { id, type, step, ... }
  movements: [],   // { id, type, amountSat, ts, status, detail }
});

export class ArkManager {
  constructor({ account, storage, arkUrl, esploraUrl, network = 'regtest', onUpdate }) {
    this.account = account;       // HDKey node; ark keys derived beneath it
    this.storage = storage;       // { load(): obj|null, save(obj): void }
    this.arkUrl = arkUrl;
    this.esploraUrl = esploraUrl;
    this.network = network;
    this.onUpdate = onUpdate || (() => {});
    this.state = null;
    this.info = null;
    this._lnDriving = new Set(); // re-entrancy guard: sync poll vs UI fast-poll vs mailbox push
  }

  // ---- keys ----
  _key(index) {
    const node = this.account.deriveChild(3).deriveChild(index);
    return { privkey: node.privateKey, pubkey: secp256k1.getPublicKey(node.privateKey, true) };
  }
  _mailboxKey() {
    const node = this.account.deriveChild(4).deriveChild(0);
    return { privkey: node.privateKey, pubkey: secp256k1.getPublicKey(node.privateKey, true) };
  }
  _keyForVtxo(v) { return this._key(v.keyIndex); }

  // ---- lifecycle ----
  async init() {
    const loaded = this.storage.load();
    this.state = loaded || EMPTY_STATE();
    // A wallet opening on a device for the first time (a fresh import, a new
    // browser) is about to discover its whole history at once, and every
    // movement it records gets stamped with the moment it was found — so
    // without this, a week-old payment looks like it just arrived. Mark the
    // first catch-up as history: only what turns up afterwards is news.
    if (!loaded) this.state.baselinePending = true;
    // drop duplicate receive movements (same vtxo) left by the former
    // poll/stream race; the vtxo set itself was always deduped
    const seen = new Set();
    this.state.movements = this.state.movements.filter((m) => {
      if (m.type !== 'receive' || !m.vtxoId) return true;
      if (seen.has(m.vtxoId)) return false;
      seen.add(m.vtxoId);
      return true;
    });
    this.info = await getArkInfo(this.arkUrl);
    const hs = await handshake(this.arkUrl).catch(() => null);
    this.psa = hs?.psa;
    this.serverPub = hex.decode(this.info.serverPubkey);

    // Pre-namespacing state can now be proven to belong to this server (the
    // vtxo wire format names its cosigner), so claim it before deciding.
    if (!this.state.serverPubkey && this.storage.adopt) {
      const adopted = this.storage.adopt(this.info.serverPubkey);
      if (adopted) this.state = adopted;
    }

    // A vtxo is only meaningful against the server that cosigned it. State
    // carried over from a different ASP (a provider switch, or a snapshot
    // adopted from the pre-namespacing key) would show phantom balance and
    // try to resume actions this server has never heard of — so drop it.
    // Nothing is lost: the other ASP's state lives under its own key.
    // Decisive check: whatever any stamp claims, a vtxo names its own
    // cosigner. If these coins were signed by a different server they are not
    // spendable here and must not be shown.
    const coinOwner = (() => {
      const v = (this.state.vtxos || []).find((x) => x.bytes);
      try { return v ? decodeVtxo(hex.decode(v.bytes)).serverPubkey : null; } catch { return null; }
    })();
    if ((this.state.serverPubkey && this.state.serverPubkey !== this.info.serverPubkey)
        || (coinOwner && coinOwner !== this.info.serverPubkey)) {
      this.state = EMPTY_STATE();
    }
    if (!this.state.serverPubkey) {
      this.state.serverPubkey = this.info.serverPubkey;
      this._save();
    }
    return this;
  }

  _save() {
    this.storage.save(this.state);
    this.onUpdate(this);
  }
  _movement(m) {
    this.state.movements.push({ id: `${Date.now()}-${this.state.movements.length}`, ts: Date.now(), ...m });
  }
  _vtxo(id) { return this.state.vtxos.find((v) => v.id === id); }
  _addVtxo(decoded, bytes, keyIndex, state = 'spendable') {
    if (this._vtxo(decoded.id)) return false;
    this.state.vtxos.push({
      id: decoded.id, bytes: hex.encode(bytes), keyIndex,
      amountSat: decoded.amountSat, expiryHeight: decoded.expiryHeight, state,
    });
    return true;
  }
  _decoded(v) { return decodeVtxo(hex.decode(v.bytes)); }

  // ---- chain adapter (esplora REST, same API the wallet already speaks) ----
  get chain() {
    const base = this.esploraUrl;
    return {
      tipHeight: async () => Number(await fetch(`${base}/blocks/tip/height`).then((r) => r.text())),
      getTxStatus: async (txid) => fetch(`${base}/tx/${txid}/status`).then((r) => r.ok ? r.json() : null),
      getTxHex: async (txid) => fetch(`${base}/tx/${txid}/hex`).then((r) => r.ok ? r.text() : null),
      broadcastTx: async (txHex) => {
        const r = await fetch(`${base}/tx`, { method: 'POST', body: txHex });
        const body = await r.text();
        // a rebroadcast after a crash is fine — the tx being known already IS success
        if (!r.ok && !/already/i.test(body)) throw new Error(`broadcast failed: ${body.slice(0, 120)}`);
        return body.trim();
      },
    };
  }

  // ---- public surface ----
  address() {
    const k0 = this._key(0);
    const blinded = blindMailboxId(this._mailboxKey().pubkey, hex.decode(this.info.mailboxPubkey), k0.privkey);
    return encodeAddress({
      testnet: this.info.network !== 'bitcoin',
      serverPubkey: this.serverPub,
      userPubkey: k0.pubkey,
      blindedMailboxId: blinded,
    });
  }

  balance() {
    const sum = (st) => this.state.vtxos.filter((v) => v.state === st).reduce((n, v) => n + v.amountSat, 0);
    // Boards whose funding tx is broadcast but whose vtxo isn't registered yet:
    // the sats have left the on-chain balance, so surface them here instead of
    // letting them vanish until the board completes.
    const boardingSat = this.state.actions
      .filter((a) => a.type === 'board' && a.fundingTxid && !['done', 'failed'].includes(a.step))
      .reduce((n, a) => n + (a.amountSat - a.feeSat), 0);
    return { spendableSat: sum('spendable'), pendingSat: sum('pending'), boardingSat };
  }

  // Receives newer than the last acknowledgement — the UI's "Payment
  // received!" celebration. Recency-guarded like the on-chain equivalent so an
  // old payment never celebrates when a wallet is opened much later.
  unseenReceives() {
    const ack = this.state.receiveAckTs || 0;
    const cutoff = Date.now() - 2 * 3600 * 1000;
    return this.state.movements.filter((m) =>
      ['receive', 'ln-receive'].includes(m.type) && m.status === 'complete' && m.ts > ack && m.ts > cutoff);
  }
  ackReceives() {
    this.state.receiveAckTs = Date.now();
    this._save();
  }
  vtxos() { return this.state.vtxos.slice(); }
  movements() { return this.state.movements.slice(); }
  pendingActions() { return this.state.actions.filter((a) => !['done', 'failed'].includes(a.step)); }

  // Read new mailbox messages, fully validate incoming vtxos, then push any
  // in-flight actions forward.
  async sync() {
    const baselining = !!this.state.baselinePending;
    const mailbox = this._mailboxKey();
    const { messages } = await readMailbox(this.arkUrl, mailbox, this.state.mailboxCheckpoint);
    let changed = false;
    for (const m of messages) changed = (await this._processMailboxMessage(m)) || changed;
    // Everything the first catch-up found is history, not news.
    if (baselining) {
      this.state.receiveAckTs = Date.now();
      delete this.state.baselinePending;
      changed = true;
    }
    if (changed) this._save();
    await this.resumePending();
  }

  // Handle one mailbox message (from a poll or the live stream). Returns
  // whether state changed; the caller saves. Duplicate-safe: vtxos dedupe by
  // id and the checkpoint only moves forward.
  async _processMailboxMessage(m) {
    let changed = false;
    if (m.checkpoint > this.state.mailboxCheckpoint) { this.state.mailboxCheckpoint = m.checkpoint; changed = true; }
    if (m.kind === 'lnSendFinished') {
      const a = this.state.actions.find((x) =>
        x.type === 'ln-pay' && x.paymentHash === m.paymentHash && !['done', 'failed'].includes(x.step));
      if (a && m.preimage && a.step === 'initiated'
          && hex.encode(sha256(hex.decode(m.preimage))) === a.paymentHash) {
        this._settleLnPay(a, m.preimage);
        changed = true;
      } else if (a && !m.preimage && a.step === 'initiated') {
        a.step = 'revoking';
        changed = true;
        this._driveLnPay(a).catch(() => {}); // revocation retried on sync if this fails
      }
      return changed;
    }
    if (m.kind === 'lnIncoming') {
      const a = this.state.actions.find((x) =>
        x.type === 'ln-recv' && x.paymentHash === m.paymentHash && !['done', 'failed'].includes(x.step));
      if (a) this._driveLnRecv(a).catch(() => {}); // claim promptly; sync poll is the fallback
      return changed;
    }
    if (m.kind !== 'arkoor') return changed;
    const ourKeys = [hex.encode(this._key(0).pubkey)];
    for (const v of m.vtxos) {
      if (this._vtxo(v.id)) continue;
      try {
        await validateVtxo(v, { serverPubkey: this.serverPub, chain: this.chain, expectPubkeys: ourKeys });
      } catch (e) {
        if (e instanceof VtxoValidationError) {
          this._movement({ type: 'receive', amountSat: v.amountSat, status: 'rejected', detail: e.message });
          changed = true;
          continue;
        }
        throw e; // network errors etc: retry next sync
      }
      // _addVtxo dedupes by id — the poll and the live stream can process the
      // same message concurrently (validation awaits in between), and only the
      // copy that actually added the vtxo may record the receive movement.
      if (!this._addVtxo(v, v._raw.bytes, 0)) continue;
      this._movement({ type: 'receive', amountSat: v.amountSat, status: 'complete', vtxoId: v.id });
      changed = true;
    }
    return changed;
  }

  // Live mailbox push via the SubscribeMailbox gRPC stream — receives land the
  // moment the sender delivers, instead of on the next poll. Reconnects with a
  // short backoff until stopMailboxStream().
  startMailboxStream() {
    if (this._streaming) return;
    this._streaming = true;
    const loop = async () => {
      while (this._streaming) {
        try {
          this._streamAbort = new AbortController();
          await grpcStream(
            this.arkUrl,
            'mailbox_server.MailboxService/SubscribeMailbox',
            mailboxRequestBytes(this._mailboxKey(), this.state.mailboxCheckpoint),
            {
              signal: this._streamAbort.signal,
              onMessage: (bytes) => {
                this._processMailboxMessage(decodeMailboxMessage(bytes))
                  .then((changed) => { if (changed) this._save(); })
                  .catch(() => {}); // validation retried by the next poll
              },
            },
          );
        } catch {}
        if (this._streaming) await new Promise((r) => setTimeout(r, 3000));
      }
    };
    loop();
  }
  stopMailboxStream() {
    this._streaming = false;
    try { this._streamAbort?.abort(); } catch {}
    this._streamAbort = null;
  }

  // Check every locally-spendable vtxo against the server's authoritative
  // off-chain ledger and flip the ones it reports spent (state drift from the
  // same seed active elsewhere, or a restored state snapshot). Trust flows one
  // way — spendable -> spent — so a lying server can hide balance from the UI
  // but never mint it, and the signed bytes stay held for unilateral exit.
  async reconcile() {
    const candidates = this.state.vtxos.filter((v) => v.state === 'spendable');
    const states = await Promise.all(candidates.map((v) =>
      getVtxoStatus(this.arkUrl, this._decoded(v).point.raw, this._keyForVtxo(v).privkey)
        .catch(() => null))); // unreachable/erroring server changes nothing
    let changed = false;
    candidates.forEach((v, i) => {
      if (states[i] !== VTXO_STATE_SPENT) return;
      v.state = 'spent';
      this._movement({ type: 'reconcile', amountSat: v.amountSat, status: 'complete', vtxoId: v.id, detail: 'spent elsewhere (server vtxo status)' });
      changed = true;
    });
    if (changed) this._save();
    return changed;
  }

  async resumePending() {
    for (const action of this.pendingActions()) {
      try {
        if (action.type === 'send') await this._driveSend(action);
        if (action.type === 'board') await this._driveBoard(action);
        if (action.type === 'refresh') await this._driveRefresh(action);
        if (action.type === 'offboard') await this._driveOffboard(action);
        if (action.type === 'ln-pay') await this._driveLnPay(action);
        if (action.type === 'ln-recv') await this._driveLnRecv(action);
        if (action.lastError) { delete action.lastError; this._save(); }
      } catch (e) {
        // transient errors leave the action where it is; a later sync retries
        if (!(e instanceof GrpcError)) throw e;
        if (action.type.startsWith('ln-')) { action.lastError = e.message; this._save(); }
      }
    }
  }

  // ---- unilateral exit ----
  // Marks the vtxo pending and records the action. The ark FEATURE drives the
  // steps (it owns the on-chain wallet needed for fee-bump coins and the
  // claim destination); crash-safety comes from the persisted action like
  // every other flow. signedExitTxs() up front validates the chain is fully
  // signed before anything is committed.
  startExit(vtxoId) {
    const v = this._vtxo(vtxoId);
    if (!v || v.state !== 'spendable') throw new Error('vtxo is not spendable');
    const txs = signedExitTxs(this._decoded(v), this.serverPub);
    const action = {
      id: `exit-${Date.now()}-${vtxoId.slice(0, 8)}`, type: 'exit', step: 'chain',
      vtxoId, amountSat: v.amountSat, txids: txs.map((t) => t.txid),
    };
    v.state = 'pending';
    this.state.actions.push(action);
    this._save();
    return action;
  }

  // ---- offboard (collaborative exit: spendable vtxos -> one on-chain output) ----
  // Whole vtxos only — there is no change on this path. Default is everything
  // spendable; vtxoIds selects a subset (the feature splits an exact-amount
  // vtxo first via a self-send when the user asks for a partial move).
  async startOffboard(spk, address, vtxoIds) {
    if (this.pendingActions().some((a) => a.type === 'offboard')) {
      throw new Error('an offboard is already in progress');
    }
    const inputs = vtxoIds
      ? vtxoIds.map((id) => this._vtxo(id))
      : this.state.vtxos.filter((v) => v.state === 'spendable');
    if (!inputs.length) throw new Error('no spendable ark balance');
    if (inputs.some((v) => !v || v.state !== 'spendable')) throw new Error('vtxo not spendable');
    if (this.info.maxOffboardInputs && inputs.length > this.info.maxOffboardInputs) {
      throw new Error(`too many coins for one offboard (${inputs.length}) — refresh/consolidate first`);
    }
    const tip = await this.chain.tipHeight();
    const satVkb = await getOffboardFeeRate(this.arkUrl);
    const grossSat = inputs.reduce((n, v) => n + v.amountSat, 0);
    const feeSat = offboardFee({
      spkLen: spk.length, satVkb, fees: this.info.offboardFees, tip,
      inputs: inputs.map((v) => ({ amountSat: v.amountSat, expiryHeight: v.expiryHeight })),
    });
    const netSat = grossSat - feeSat;
    if (netSat < P2TR_DUST) throw new Error('ark balance too small to offboard after fees');
    const action = {
      id: `offboard-${Date.now()}`, type: 'offboard', step: 'created',
      inputIds: inputs.map((v) => v.id), address, spkHex: hex.encode(spk),
      grossSat, feeSat, netSat, rateKwu: feeRateKwu(satVkb),
    };
    for (const v of inputs) v.state = 'pending';
    this.state.actions.push(action);
    this._save();
    await this._driveOffboard(action);
    return action;
  }

  async _driveOffboard(action) {
    const inputRecs = action.inputIds.map((id) => this._vtxo(id));
    if (action.step === 'created') {
      const decoded = inputRecs.map((v) => this._decoded(v));
      const keys = inputRecs.map((v) => this._keyForVtxo(v));
      const spk = hex.decode(action.spkHex);
      const inputIdRaws = decoded.map((d) => d.point.raw);
      await registerVtxoTransactions(this.arkUrl, inputRecs.map((v) => hex.decode(v.bytes)));
      const attestations = keys.map((k) =>
        offboardAttestation({ netSat: action.netSat, spk, inputIdRaws }, k.privkey));
      const { txBytes, serverNonces } = await prepareOffboard(this.arkUrl, {
        netSat: action.netSat, spk, rateKwu: action.rateKwu, inputIdRaws, attestations,
      });
      const parsed = parseTx(txBytes);
      validateOffboardTx(parsed, { netSat: action.netSat, spk, nInputs: decoded.length });
      const { pubNonces, partials, offboardTxidInternal } = signOffboardForfeits({
        inputs: decoded, keys, serverPub: this.serverPub, parsed, serverNonces,
      });
      // the server holds our forfeits after FinishOffboard: persist the txid
      // first so a crash mid-call can still find the tx on chain
      action.txid = parsed.txid;
      action.step = 'finishing';
      this._save();
      const signed = await finishOffboard(this.arkUrl, { offboardTxidInternal, pubNonces, partials });
      if (parseTx(signed).txid !== action.txid) throw new Error('server returned a different offboard tx');
      action.txHex = hex.encode(signed);
      for (const v of inputRecs) v.state = 'spent';
      action.step = 'signed';
      this._save();
    }
    if (action.step === 'finishing') {
      // crashed between FinishOffboard and persisting its result. The server
      // broadcasts the offboard tx itself after a successful finish, so ask it
      // whether the inputs were forfeited: spent means the finish landed (wait
      // for the server's broadcast to confirm); still-spendable means it never
      // did — start the action over.
      const probe = await getVtxoStatus(this.arkUrl,
        this._decoded(inputRecs[0]).point.raw, this._keyForVtxo(inputRecs[0]).privkey);
      if (probe === VTXO_STATE_SPENT) {
        for (const v of inputRecs) v.state = 'spent';
        action.step = 'broadcast';
        this._movement({
          type: 'offboard', amountSat: action.netSat, status: 'complete',
          txid: action.txid, detail: `fee ${action.feeSat} sat`, to: action.address,
        });
        this._save();
      } else {
        action.step = 'created';
        this._save();
        return; // retried on the next sync
      }
    }
    if (action.step === 'signed') {
      await this.chain.broadcastTx(action.txHex);
      action.step = 'broadcast';
      this._movement({
        type: 'offboard', amountSat: action.netSat, status: 'complete',
        txid: action.txid, detail: `fee ${action.feeSat} sat`, to: action.address,
      });
      this._save();
    }
    if (action.step === 'broadcast') {
      const st = await this.chain.getTxStatus(action.txid);
      if (!st?.confirmed) return; // retried on sync
      action.step = 'done';
      this._save();
    }
  }

  // ---- send ----
  _selectInput(amountSat) {
    const candidates = this.state.vtxos
      .filter((v) => v.state === 'spendable' && v.amountSat >= amountSat)
      .sort((a, b) => a.amountSat - b.amountSat);
    if (!candidates.length) {
      const total = this.balance().spendableSat;
      throw new Error(total >= amountSat
        ? 'no single vtxo covers this amount — consolidate with refresh() first'
        : 'insufficient ark balance');
    }
    return candidates[0];
  }

  async send(addrString, amountSat) {
    const dest = decodeAddress(addrString);
    if (dest.arkId !== hex.encode(arkIdFromServerPubkey(this.serverPub))) {
      throw new Error('address belongs to a different ark server');
    }
    const mailboxDelivery = dest.delivery.find((d) => d.type === 1);
    if (!mailboxDelivery) throw new Error('address has no mailbox delivery mechanism');

    const input = this._selectInput(amountSat);
    const changeSat = input.amountSat - amountSat;
    const action = {
      id: `send-${Date.now()}`, type: 'send', step: 'created',
      inputId: input.id, amountSat, destAddress: addrString,
      destPubkey: dest.userPubkey, destBlindedId: mailboxDelivery.data,
      changeIndex: changeSat > 0 ? this.state.nextKeyIndex++ : null, changeSat,
    };
    input.state = 'pending';
    this.state.actions.push(action);
    this._save();
    await this._driveSend(action);
    return action.id;
  }

  _sendOutputs(action) {
    const outputs = [{ amountSat: action.amountSat, userPubkey: hex.decode(action.destPubkey) }];
    if (action.changeSat > 0) {
      outputs.push({ amountSat: action.changeSat, userPubkey: this._key(action.changeIndex).pubkey });
    }
    return outputs;
  }

  async _driveSend(action) {
    if (action.step === 'created') {
      const inputRec = this._vtxo(action.inputId);
      const input = this._decoded(inputRec);
      const keys = this._keyForVtxo(inputRec);
      const outputs = this._sendOutputs(action);
      await registerVtxoTransactions(this.arkUrl, [input._raw.bytes]);
      const build = buildArkoorSend({ input, outputs, serverPubkey: this.serverPub, vtxoKeys: keys });
      let sigs;
      try {
        sigs = await cosignWithServer(this.arkUrl, build, { input, outputs, vtxoKeys: keys, serverPubkey: this.serverPub });
      } catch (e) {
        const spent = e instanceof GrpcError && /already spent|not spendable/i.test(e.message);
        if (spent || (e instanceof GrpcError && e.grpcStatus === 3)) {
          // "already spent": the input is gone (possibly a prior crashed
          // attempt). Status 3: the server rejected the cosign outright, so
          // the input is untouched and returns to spendable. Neither retries.
          inputRec.state = spent ? 'spent' : 'spendable';
          action.step = 'failed';
          action.error = e.message;
          this._movement({ type: 'send', amountSat: action.amountSat, status: 'failed', detail: e.message });
          this._save();
          return;
        }
        throw e;
      }
      // the input is spent server-side from this moment: persist immediately.
      // Dust padding may SPLIT the destination or change across two vtxos —
      // classify results by policy key rather than by output index.
      const all = buildAllSignedVtxos({ input, build, finalSigs: sigs, serverPubkey: this.serverPub })
        .map((bytes) => ({ bytes, v: decodeVtxo(bytes) }));
      const dest = all.filter((x) => x.v.policy.userPubkey === action.destPubkey);
      const change = all.filter((x) => x.v.policy.userPubkey !== action.destPubkey);
      action.destBytesList = dest.map((x) => hex.encode(x.bytes));
      action.changeBytesList = change.map((x) => hex.encode(x.bytes));
      for (const x of change) this._addVtxo(x.v, x.bytes, action.changeIndex, 'pending');
      inputRec.state = 'spent';
      action.step = 'cosigned';
      this._save();
    }
    // legacy single-field actions (pre-dust-isolation) resume transparently
    const destList = () => action.destBytesList || [action.destBytes];
    const changeList = () => action.changeBytesList || (action.changeBytes ? [action.changeBytes] : []);
    if (action.step === 'cosigned') {
      await registerVtxoTransactions(this.arkUrl,
        [...destList(), ...changeList()].map((b) => hex.decode(b)));
      action.step = 'registered';
      this._save();
    }
    if (action.step === 'registered') {
      // a pouch-bound send has no mailbox to deliver to — the caller takes
      // the bytes from the returned action instead
      if (action.destBlindedId) {
        await postArkoorMessage(this.arkUrl, hex.decode(action.destBlindedId),
          destList().map((b) => hex.decode(b)));
      }
      for (const b of changeList()) {
        const change = this._vtxo(decodeVtxo(hex.decode(b)).id);
        if (change && change.state === 'pending') change.state = 'spendable';
      }
      action.step = 'done';
      this._movement({
        type: 'send', amountSat: action.amountSat, status: 'complete',
        to: action.destAddress, vtxoId: decodeVtxo(hex.decode(destList()[0])).id,
      });
      this._save();
    }
  }

  // ---- lightning (the ASP is the swap counterparty; see ark/lightning.js) ----

  // Deterministic receive preimage: no secret ever hits storage — only the
  // derivation index does, so a restored seed can always re-derive it.
  _lnPreimage(idx) {
    return sha256(this.account.deriveChild(5).deriveChild(idx).privateKey);
  }

  _expiryMargin() { return this.network === 'regtest' ? 12 : 144; }

  lnAction(id) {
    return this.state.actions.find((a) => a.id === id && a.type.startsWith('ln-'));
  }

  // Drive one lightning action forward (the UI's fast poll while its screen
  // is open); transient gRPC errors are recorded, not thrown.
  async driveLn(id) {
    const a = this.lnAction(id);
    if (!a || ['done', 'failed'].includes(a.step)) return a;
    try {
      if (a.type === 'ln-pay') await this._driveLnPay(a);
      else await this._driveLnRecv(a);
      if (a.lastError) { delete a.lastError; this._save(); }
    } catch (e) {
      if (!(e instanceof GrpcError)) throw e;
      a.lastError = e.message;
      this._save();
    }
    return a;
  }

  // Pay a bolt11 invoice with ark funds. Returns the action id; drive to a
  // terminal step ('done' | 'failed') via driveLn()/sync.
  async payLnInvoice(invoice, { amountSat: userAmountSat } = {}) {
    const dec = decodeBolt11(invoice);
    const expectNet = { bitcoin: 'mainnet', regtest: 'regtest', signet: 'signet', testnet: 'testnet' }[this.info.network];
    if (expectNet && dec.network !== expectNet) throw new Error(`invoice is for ${dec.network}, wallet is on ${expectNet}`);
    const amountSat = dec.amountSat ?? userAmountSat;
    if (!amountSat || amountSat <= 0) throw new Error('invoice has no amount');
    if (this.state.actions.some((a) =>
      a.type === 'ln-pay' && a.paymentHash === dec.paymentHash && a.step !== 'failed')) {
      throw new Error('this invoice was already paid or is being paid');
    }
    const tip = await this.chain.tipHeight();
    // smallest single vtxo that covers amount + its expiry-dependent fee
    const candidates = this.state.vtxos
      .filter((v) => v.state === 'spendable')
      .sort((a, b) => a.amountSat - b.amountSat);
    let input = null, feeSat = 0;
    for (const v of candidates) {
      const fee = lnSendFee(amountSat, this.info.lnSendFees, [v], tip);
      if (v.amountSat >= amountSat + fee) { input = v; feeSat = fee; break; }
    }
    if (!input) {
      const total = this.balance().spendableSat;
      throw new Error(total >= amountSat
        ? 'no single vtxo covers this amount — consolidate with refresh() first'
        : 'insufficient ark balance');
    }
    const action = {
      id: `lnpay-${Date.now()}`, type: 'ln-pay', step: 'created',
      invoice, paymentHash: dec.paymentHash, amountSat, feeSat,
      inputId: input.id,
      htlcKeyIndex: this.state.nextKeyIndex++, // HTLC lock key, reused for change (bark does the same)
      revKeyIndex: this.state.nextKeyIndex++,
      htlcExpiry: tip + (this.info.htlcSendExpiryDelta || 258),
      changeSat: input.amountSat - amountSat - feeSat,
    };
    input.state = 'pending';
    this.state.actions.push(action);
    this._save();
    await this._driveLnPay(action);
    return action.id;
  }

  async _driveLnPay(action) {
    if (this._lnDriving.has(action.id)) return;
    this._lnDriving.add(action.id);
    try { await this._driveLnPayInner(action); } finally { this._lnDriving.delete(action.id); }
  }

  async _driveLnPayInner(action) {
    if (action.step === 'created') {
      const inputRec = this._vtxo(action.inputId);
      const input = this._decoded(inputRec);
      const keys = this._keyForVtxo(inputRec);
      const htlcKey = this._key(action.htlcKeyIndex);
      const outputs = [{
        amountSat: action.amountSat + action.feeSat,
        policy: {
          type: 'serverHtlcSend', userPubkey: hex.encode(htlcKey.pubkey),
          paymentHash: action.paymentHash, htlcExpiry: action.htlcExpiry,
        },
      }];
      if (action.changeSat > 0) outputs.push({ amountSat: action.changeSat, userPubkey: htlcKey.pubkey });
      await registerVtxoTransactions(this.arkUrl, [input._raw.bytes]);
      const build = buildArkoorSend({ input, outputs, serverPubkey: this.serverPub, vtxoKeys: keys });
      const nonces = genUserNonces(build, keys);
      let resp;
      try {
        // idempotent on payment hash server-side: a re-drive after a crash
        // gets fresh partials for fresh nonces
        [resp] = await requestLightningPayHtlcCosign(this.arkUrl,
          [cosignPartBytes({ build, input, vtxoKeys: keys, nonces })]);
      } catch (e) {
        // INVALID_ARGUMENT (status 3): the server rejected the cosign outright
        // — nothing was spent, so the input goes back to spendable instead of
        // rotting in pending. "already spent" means the input really is gone.
        const spent = e instanceof GrpcError && /already spent|not spendable/i.test(e.message);
        if (spent || (e instanceof GrpcError && e.grpcStatus === 3)) {
          inputRec.state = spent ? 'spent' : 'spendable';
          action.step = 'failed';
          action.error = e.message;
          this._movement({ type: 'ln-send', amountSat: action.amountSat, status: 'failed', detail: e.message });
          this._save();
          return;
        }
        throw e;
      }
      if (!resp) throw new Error('empty cosign response');
      const sigs = combineCosign({ build, nonces, serverResp: resp, vtxoKeys: keys, serverPubkey: this.serverPub });
      // the input is spent server-side from this moment: persist immediately.
      // Dust padding may split the HTLC (or change) across two vtxos —
      // classify by policy type.
      const all = buildAllSignedVtxos({ input, build, finalSigs: sigs, serverPubkey: this.serverPub })
        .map((bytes) => ({ bytes, v: decodeVtxo(bytes) }));
      const htlcs = all.filter((x) => x.v.policy.type === 'serverHtlcSend');
      const changes = all.filter((x) => x.v.policy.type !== 'serverHtlcSend');
      action.htlcBytesList = htlcs.map((x) => hex.encode(x.bytes));
      action.htlcVtxoIds = htlcs.map((x) => x.v.id);
      action.changeBytesList = changes.map((x) => hex.encode(x.bytes));
      for (const x of all) this._addVtxo(x.v, x.bytes, action.htlcKeyIndex, 'pending');
      inputRec.state = 'spent';
      action.step = 'cosigned';
      this._save();
    }
    // legacy single-field actions resume transparently
    const htlcList = () => action.htlcBytesList || [action.htlcBytes];
    const htlcIds = () => action.htlcVtxoIds || [action.htlcVtxoId];
    const changeList = () => action.changeBytesList || (action.changeBytes ? [action.changeBytes] : []);
    if (action.step === 'cosigned') {
      await registerVtxoTransactions(this.arkUrl,
        [...htlcList(), ...changeList()].map((b) => hex.decode(b))).catch(() => {}); // best-effort (bark warns too)
      // the change is a plain cosigned vtxo, good regardless of what the
      // payment does from here
      for (const b of changeList()) {
        const change = this._vtxo(decodeVtxo(hex.decode(b)).id);
        if (change && change.state === 'pending') change.state = 'spendable';
      }
      try {
        await initiateLightningPayment(this.arkUrl, {
          invoice: action.invoice,
          htlcVtxoIdRaws: htlcList().map((b) => decodeVtxo(hex.decode(b)).point.raw),
          amountSat: action.amountSat,
          mailboxPubkey: this._mailboxKey().pubkey,
        });
        action.step = 'initiated';
        this._save();
      } catch (e) {
        // INVALID_ARGUMENT: the server itself deems the invoice unpayable —
        // retrying can never succeed, revoke the HTLC instead
        if (e instanceof GrpcError && e.grpcStatus === 3) {
          action.error = e.message;
          action.step = 'revoking';
          this._save();
        } else {
          throw e;
        }
      }
    }
    if (action.step === 'initiated') {
      const res = await checkLightningPayment(this.arkUrl, hex.decode(action.paymentHash), false);
      if (res.status === 'success' && res.preimage
          && hex.encode(sha256(hex.decode(res.preimage))) === action.paymentHash) {
        this._settleLnPay(action, res.preimage);
        return;
      }
      if (res.status === 'failed') {
        action.step = 'revoking';
        this._save();
      } else {
        // still pending: past the HTLC expiry the payment can't complete — revoke
        const tip = await this.chain.tipHeight();
        if (tip <= action.htlcExpiry) return; // poll again next sync
        action.step = 'revoking';
        this._save();
      }
    }
    if (action.step === 'revoking') await this._revokeLnPay(action);
  }

  _settleLnPay(action, preimageHex) {
    for (const id of action.htlcVtxoIds || [action.htlcVtxoId]) {
      const htlc = this._vtxo(id);
      if (htlc) htlc.state = 'spent';
    }
    action.preimage = preimageHex;
    action.step = 'done';
    this._movement({
      type: 'ln-send', amountSat: action.amountSat, status: 'complete',
      detail: action.feeSat ? `fee ${action.feeSat} sat` : undefined,
      invoice: action.invoice, preimage: preimageHex,
    });
    this._save();
  }

  // Payment failed: ask the server to cosign the HTLC vtxo back to a fresh
  // pubkey vtxo of ours. A refusing/unreachable server leaves the action in
  // 'revoking' (retried every sync); near expiry the remaining option is a
  // unilateral exit of the HTLC vtxo.
  async _revokeLnPay(action) {
    const keys = this._key(action.htlcKeyIndex);
    const revKey = this._key(action.revKeyIndex);
    const inputs = (action.htlcBytesList || [action.htlcBytes])
      .map((b) => decodeVtxo(hex.decode(b)));
    const builds = inputs.map((input) => buildArkoorSend({
      input,
      outputs: [{ amountSat: input.amountSat, userPubkey: revKey.pubkey }],
      serverPubkey: this.serverPub, vtxoKeys: keys,
    }));
    const noncesList = builds.map((b) => genUserNonces(b, keys));
    const parts = builds.map((b, i) =>
      cosignPartBytes({ build: b, input: inputs[i], vtxoKeys: keys, nonces: noncesList[i] }));
    const resps = await requestLightningPayHtlcRevocation(this.arkUrl, parts);
    if (resps.length !== builds.length) throw new Error('bad revocation cosign response');
    for (let i = 0; i < builds.length; i++) {
      const sigs = combineCosign({
        build: builds[i], nonces: noncesList[i], serverResp: resps[i],
        vtxoKeys: keys, serverPubkey: this.serverPub,
      });
      const outBytes = buildAllSignedVtxos({
        input: inputs[i], build: builds[i], finalSigs: sigs, serverPubkey: this.serverPub,
      });
      await registerVtxoTransactions(this.arkUrl, outBytes).catch(() => {});
      const htlcRec = this._vtxo(inputs[i].id);
      if (htlcRec) htlcRec.state = 'spent';
      for (const bts of outBytes) this._addVtxo(decodeVtxo(bts), bts, action.revKeyIndex);
    }
    action.step = 'failed';
    action.error = action.error || 'payment failed';
    this._movement({
      type: 'ln-send', amountSat: action.amountSat, status: 'failed',
      detail: 'payment failed — funds returned', invoice: action.invoice,
    });
    this._save();
  }

  // Mint a bolt11 invoice payable to this wallet's ark balance.
  async createLnInvoice(amountSat, description) {
    if (!(amountSat > 0)) throw new Error('invalid amount');
    // CLTV budget: exit delta + server htlc delta + exit margin + claim delta
    // + 2-block prepare leniency (bark's composition, defaults inlined)
    const minCltvDelta = (this.info.vtxoExitDelta || 0) + (this.info.htlcExpiryDelta || 6) + 12 + 18 + 2;
    if (this.info.maxUserInvoiceCltvDelta && minCltvDelta > this.info.maxUserInvoiceCltvDelta) {
      throw new Error('server max invoice CLTV delta is too low');
    }
    const idx = this.state.nextLnRecvIndex || 0;
    this.state.nextLnRecvIndex = idx + 1;
    const keyIndex = this.state.nextKeyIndex++;
    const paymentHash = sha256(this._lnPreimage(idx));
    const invoice = await startLightningReceive(this.arkUrl, {
      paymentHash, amountSat, minCltvDelta,
      mailboxPubkey: this._mailboxKey().pubkey, description,
    });
    const decInv = decodeBolt11(invoice);
    if (decInv.paymentHash !== hex.encode(paymentHash)) {
      throw new Error('server invoice payment hash mismatch');
    }
    const action = {
      id: `lnrecv-${Date.now()}`, type: 'ln-recv', step: 'awaiting',
      paymentHash: hex.encode(paymentHash), preimageIndex: idx, keyIndex,
      amountSat, minCltvDelta, invoice, expiresAt: decInv.expiresAt,
    };
    this.state.actions.push(action);
    this._save();
    return action;
  }

  // Cancel an unpaid invoice. Only valid before HTLCs are granted; the server
  // cancel is best-effort (an abandoned hold invoice expires server-side).
  async cancelLnInvoice(id) {
    const a = this.lnAction(id);
    if (!a || a.type !== 'ln-recv') throw new Error('unknown invoice');
    if (a.step !== 'awaiting') throw new Error('receive already in progress');
    await cancelLightningReceive(this.arkUrl, hex.decode(a.paymentHash)).catch(() => {});
    a.step = 'failed';
    a.error = 'canceled';
    this._save();
  }

  async _driveLnRecv(action) {
    if (this._lnDriving.has(action.id)) return;
    this._lnDriving.add(action.id);
    try { await this._driveLnRecvInner(action); } finally { this._lnDriving.delete(action.id); }
  }

  async _driveLnRecvInner(action) {
    if (action.step === 'awaiting') {
      const st = await checkLightningReceive(this.arkUrl, hex.decode(action.paymentHash));
      if (st.status === 'canceled') {
        action.step = 'failed';
        action.error = 'canceled server-side';
        this._save();
        return;
      }
      if (st.status === 'created') {
        // unpaid past the invoice expiry (+grace): reap
        if (action.expiresAt && Date.now() > action.expiresAt + 60_000) {
          action.step = 'failed';
          action.error = 'invoice expired';
          this._save();
        }
        return;
      }
      if (st.status === 'settled') {
        // settled without us claiming — shouldn't happen; surface it
        action.step = 'failed';
        action.error = 'settled server-side without local claim';
        this._save();
        return;
      }
      // accepted | htlcsReady: ask for our HTLC vtxos and validate them
      const tip = await this.chain.tipHeight();
      const keys = this._key(action.keyIndex);
      // anchor the requested expiry on the FIRST attempt: the server's grant
      // is fixed by the inbound HTLC, so recomputing from a later tip would
      // inflate our own requirement until it exceeds the grant
      if (!action.htlcRecvExpiry) {
        action.htlcRecvExpiry = tip + action.minCltvDelta;
        this._save();
      }
      const htlcRecvExpiry = action.htlcRecvExpiry;
      let antiDos = null;
      if (this.info.lnReceiveAntiDosRequired) {
        const proof = this.state.vtxos.filter((v) => v.state === 'spendable')
          .map((v) => ({ v, d: this._decoded(v) }))
          .find(({ d }) => d.expiryHeight > tip + 2);
        if (proof) {
          antiDos = {
            vtxoIdRaw: proof.d.point.raw,
            attestation: lightningReceiveAttestation(
              hex.decode(action.paymentHash), proof.d.point.raw, this._keyForVtxo(proof.v).privkey),
          };
        }
      }
      const res = await prepareLightningReceiveClaim(this.arkUrl, {
        paymentHash: hex.decode(action.paymentHash),
        userPubkey: keys.pubkey, htlcRecvExpiry, antiDos,
      });
      if (!res.htlcVtxos.length) return; // not ready after all; retry on sync
      let total = 0;
      for (const b of res.htlcVtxos) {
        const v = decodeVtxo(b);
        if (v.policy.type !== 'serverHtlcRecv') throw new Error('unexpected HTLC vtxo policy from server');
        if (v.policy.paymentHash !== action.paymentHash) throw new Error('HTLC vtxo payment hash mismatch');
        if (v.policy.userPubkey !== hex.encode(keys.pubkey)) throw new Error('HTLC vtxo pubkey mismatch');
        if (v.policy.htlcExpiry < htlcRecvExpiry) throw new Error('HTLC vtxo expiry lower than requested');
        try {
          await validateVtxo(v, { serverPubkey: this.serverPub, chain: this.chain, allowPolicies: ['serverHtlcRecv'] });
        } catch (e) {
          // a granted vtxo can anchor to a round the chain hasn't confirmed
          // yet — park (no preimage revealed, nothing at risk) and retry on
          // sync; the invoice-expiry reap bounds how long we'll wait
          if (e instanceof VtxoValidationError) {
            action.lastError = e.message;
            this._save();
            return;
          }
          throw e;
        }
        total += v.amountSat;
      }
      if (total + lnReceiveFee(action.amountSat, this.info.lnReceiveFees) < action.amountSat) {
        throw new Error('server returned insufficient HTLC value');
      }
      action.htlcBytes = res.htlcVtxos.map((b) => hex.encode(b));
      action.step = 'htlcsReady';
      this._save();
    }
    if (action.step === 'htlcsReady') {
      const keys = this._key(action.keyIndex);
      const decoded = action.htlcBytes.map((b) => decodeVtxo(hex.decode(b)))
        .sort((a, b) => (a.id < b.id ? -1 : 1));
      // preimage not revealed yet + HTLCs near expiry: abandon rather than
      // commit (the inbound HTLC times out and the sender is refunded)
      if (!action.preimageRevealed) {
        const tip = await this.chain.tipHeight();
        if (tip > decoded[0].policy.htlcExpiry - this._expiryMargin()) {
          action.step = 'failed';
          action.error = 'HTLCs near expiry — abandoned before preimage reveal';
          this._movement({ type: 'ln-receive', amountSat: action.amountSat, status: 'failed', detail: action.error });
          this._save();
          return;
        }
      }
      const builds = decoded.map((input) => buildArkoorSend({
        input,
        outputs: [{ amountSat: input.amountSat, userPubkey: keys.pubkey }],
        serverPubkey: this.serverPub, vtxoKeys: keys,
      }));
      const noncesList = builds.map((b) => genUserNonces(b, keys));
      const parts = builds.map((b, i) =>
        cosignPartBytes({ build: b, input: decoded[i], vtxoKeys: keys, nonces: noncesList[i] }));
      // past this point the preimage is out; the claim is idempotent
      // server-side, so persist the fact and retry until it lands
      action.preimageRevealed = true;
      this._save();
      const resps = await claimLightningReceive(this.arkUrl, {
        paymentHash: hex.decode(action.paymentHash),
        preimage: this._lnPreimage(action.preimageIndex),
        parts,
      });
      if (resps.length !== builds.length) throw new Error('bad claim cosign response');
      const outBytes = builds.map((b, i) => {
        const sigs = combineCosign({
          build: b, nonces: noncesList[i], serverResp: resps[i],
          vtxoKeys: keys, serverPubkey: this.serverPub,
        });
        return buildAllSignedVtxos({ input: decoded[i], build: b, finalSigs: sigs, serverPubkey: this.serverPub })[0];
      });
      await registerVtxoTransactions(this.arkUrl, outBytes).catch(() => {});
      let total = 0;
      for (const bts of outBytes) {
        const v = decodeVtxo(bts);
        this._addVtxo(v, bts, action.keyIndex);
        total += v.amountSat;
      }
      action.step = 'done';
      this._movement({ type: 'ln-receive', amountSat: total, status: 'complete', invoice: action.invoice });
      this._save();
    }
  }

  // ---- third-party HTLCs (trustless swaps with a non-ASP counterparty) ----
  // These are the primitives a submarine swap with an external bridge needs:
  // lock funds into an HTLC only the counterparty can claim (with the
  // preimage) and only we can reclaim (after expiry). Requires a server that
  // supports VtxoPolicy::Htlc — see docs/third-party-htlc.md.

  // Lock `amountSat` into an HTLC claimable by `claimPubkey` against
  // `paymentHash`, refundable by us after `htlcExpiry`. Returns the signed
  // HTLC vtxo bytes (hand these to the counterparty) plus our refund key
  // index so the refund can be driven later.
  async htlcLock({ amountSat, claimPubkey, paymentHash, htlcExpiry }) {
    const input = this._selectInput(amountSat);
    const inputRec = input;
    const decoded = this._decoded(inputRec);
    const keys = this._keyForVtxo(inputRec);
    const refundIndex = this.state.nextKeyIndex++;
    const changeSat = inputRec.amountSat - amountSat;
    const outputs = [{
      amountSat,
      policy: {
        type: 'htlc',
        claimPubkey: typeof claimPubkey === 'string' ? claimPubkey : hex.encode(claimPubkey),
        refundPubkey: hex.encode(this._key(refundIndex).pubkey),
        paymentHash: typeof paymentHash === 'string' ? paymentHash : hex.encode(paymentHash),
        htlcExpiry,
      },
    }];
    if (changeSat > 0) outputs.push({ amountSat: changeSat, userPubkey: this._key(refundIndex).pubkey });

    await registerVtxoTransactions(this.arkUrl, [decoded._raw.bytes]);
    const build = buildArkoorSend({ input: decoded, outputs, serverPubkey: this.serverPub, vtxoKeys: keys });
    const sigs = await cosignWithServer(this.arkUrl, build, {
      input: decoded, vtxoKeys: keys, serverPubkey: this.serverPub,
    });
    const all = buildAllSignedVtxos({ input: decoded, build, finalSigs: sigs, serverPubkey: this.serverPub })
      .map((bytes) => ({ bytes, v: decodeVtxo(bytes) }));
    const htlcs = all.filter((x) => x.v.policy.type === 'htlc');
    const change = all.filter((x) => x.v.policy.type !== 'htlc');
    inputRec.state = 'spent';
    // the HTLC output isn't ours to spend (only to refund), so it is NOT
    // added to the wallet's spendable set; change is
    for (const x of change) this._addVtxo(x.v, x.bytes, refundIndex);
    await registerVtxoTransactions(this.arkUrl, all.map((x) => x.bytes)).catch(() => {});
    this._movement({
      type: 'htlc-lock', amountSat, status: 'complete',
      detail: `htlc expiry ${htlcExpiry}`,
    });
    this._save();
    return {
      htlcVtxos: htlcs.map((x) => hex.encode(x.bytes)),
      refundIndex,
      htlcExpiry,
    };
  }

  // Claim an HTLC vtxo made out to one of our keys by revealing `preimage`.
  // The server verifies the hash lock before cosigning, and records the
  // preimage for the counterparty to fetch.
  async htlcClaim({ htlcVtxoBytes, claimKeyIndex, preimage, destPubkey }) {
    const input = decodeVtxo(hex.decode(htlcVtxoBytes));
    if (input.policy.type !== 'htlc') throw new Error('not an htlc vtxo');
    const keys = this._key(claimKeyIndex);
    if (input.policy.claimPubkey !== hex.encode(keys.pubkey)) throw new Error('htlc not claimable by this key');
    if (hex.encode(sha256(hex.decode(preimage))) !== input.policy.paymentHash) {
      throw new Error('preimage does not match the htlc payment hash');
    }
    const outIndex = destPubkey ? null : this.state.nextKeyIndex++;
    const outPub = destPubkey
      ? (typeof destPubkey === 'string' ? hex.decode(destPubkey) : destPubkey)
      : this._key(outIndex).pubkey;
    await registerVtxoTransactions(this.arkUrl, [input._raw.bytes]).catch(() => {});
    const build = buildArkoorSend({
      input, outputs: [{ amountSat: input.amountSat, userPubkey: outPub }],
      serverPubkey: this.serverPub, vtxoKeys: keys,
    });
    const sigs = await cosignWithServer(this.arkUrl, build, {
      input, vtxoKeys: keys, serverPubkey: this.serverPub, preimage,
    });
    const outBytes = buildAllSignedVtxos({ input, build, finalSigs: sigs, serverPubkey: this.serverPub });
    await registerVtxoTransactions(this.arkUrl, outBytes).catch(() => {});
    if (outIndex != null) {
      for (const b of outBytes) this._addVtxo(decodeVtxo(b), b, outIndex);
      this._movement({ type: 'htlc-claim', amountSat: input.amountSat, status: 'complete' });
      this._save();
    }
    return outBytes.map((b) => hex.encode(b));
  }

  // Cooperatively hand an HTLC back to its refunder. Called by the CLAIMER
  // (who holds the taproot keyspend path with the server) — typically a swap
  // provider releasing a swap it couldn't complete.
  //
  // This is safe to expose publicly: the server only cosigns a preimage-less
  // spend of an HTLC when every output pays the refund pubkey, so the claimer
  // has no way to redirect the funds. If the claimer never calls this, the
  // refunder's guaranteed fallback is a unilateral exit through the refund
  // tapscript leaf after `htlcExpiry` — no permission required.
  async htlcCosignRefund({ htlcVtxoBytes, claimKeyIndex }) {
    const input = decodeVtxo(hex.decode(htlcVtxoBytes));
    if (input.policy.type !== 'htlc') throw new Error('not an htlc vtxo');
    const keys = this._key(claimKeyIndex);
    if (input.policy.claimPubkey !== hex.encode(keys.pubkey)) throw new Error('htlc not held by this key');
    await registerVtxoTransactions(this.arkUrl, [input._raw.bytes]).catch(() => {});
    const build = buildArkoorSend({
      input,
      outputs: [{ amountSat: input.amountSat, userPubkey: hex.decode(input.policy.refundPubkey) }],
      serverPubkey: this.serverPub, vtxoKeys: keys,
    });
    const sigs = await cosignWithServer(this.arkUrl, build, {
      input, vtxoKeys: keys, serverPubkey: this.serverPub, // no preimage: refund-only
    });
    const outBytes = buildAllSignedVtxos({ input, build, finalSigs: sigs, serverPubkey: this.serverPub });
    await registerVtxoTransactions(this.arkUrl, outBytes).catch(() => {});
    return outBytes.map((b) => hex.encode(b));
  }

  // Take ownership of refunded HTLC vtxos handed back by the claimer (they
  // pay our refund key, so they're ours to spend once validated).
  async acceptHtlcRefund({ vtxoBytesList, refundIndex }) {
    const expect = hex.encode(this._key(refundIndex).pubkey);
    let total = 0;
    for (const b of vtxoBytesList) {
      const bytes = hex.decode(b);
      const v = decodeVtxo(bytes);
      if (v.policy.type !== 'pubkey' || v.policy.userPubkey !== expect) {
        throw new Error('refund vtxo is not paid to our refund key');
      }
      await validateVtxo(v, { serverPubkey: this.serverPub, chain: this.chain, expectPubkeys: [expect] });
      if (this._addVtxo(v, bytes, refundIndex)) total += v.amountSat;
    }
    if (total) {
      this._movement({ type: 'htlc-refund', amountSat: total, status: 'complete' });
      this._save();
    }
    return total;
  }

  // ---- board ----
  // Returns the onchain funding address; the onchain wallet pays it (the
  // board output MUST be vout 0), then completeBoard(actionId, txid).
  async startBoard(amountSat) {
    if (amountSat < this.info.minBoardAmountSat) {
      throw new Error(`board minimum is ${this.info.minBoardAmountSat} sat`);
    }
    const feeSat = boardFee(amountSat, this.info.boardFees);
    const tip = await this.chain.tipHeight();
    const action = {
      id: `board-${Date.now()}`, type: 'board', step: 'created',
      amountSat, feeSat, expiryHeight: tip + this.info.vtxoExpiryDelta,
      keyIndex: this.state.nextKeyIndex++,
    };
    this.state.actions.push(action);
    this._save();
    const keys = this._key(action.keyIndex);
    const probe = buildBoard({
      userPub: keys.pubkey, serverPub: this.serverPub, amountSat, feeSat,
      expiryHeight: action.expiryHeight, exitDelta: this.info.vtxoExitDelta,
      fundingOutpointRaw: new Uint8Array(36),
    });
    const hrp = { bitcoin: 'bc', regtest: 'bcrt' }[this.info.network] || 'tb';
    return { actionId: action.id, fundingAddress: p2trAddress(probe.fundingTaproot.outputXOnly, hrp), feeSat };
  }

  async completeBoard(actionId, fundingTxid) {
    const action = this.state.actions.find((a) => a.id === actionId);
    if (!action || action.type !== 'board') throw new Error('unknown board action');
    if (action.step === 'created') {
      action.fundingTxid = fundingTxid;
      action.step = 'funded';
      this._save();
    }
    await this._driveBoard(action);
    return action;
  }

  async _driveBoard(action) {
    if (action.step === 'created') return; // waiting for funding txid
    const keys = this._key(action.keyIndex);
    if (action.step === 'funded') {
      const status = await this.chain.getTxStatus(action.fundingTxid);
      if (!status?.confirmed) return; // wait for confirmations; retried on sync
      const tip = await this.chain.tipHeight();
      if (tip - status.block_height + 1 < this.info.requiredBoardConfirmations) return;

      const fundingOutpointRaw = new Uint8Array(36);
      fundingOutpointRaw.set(hex.decode(action.fundingTxid).reverse(), 0); // vout 0
      const board = buildBoard({
        userPub: keys.pubkey, serverPub: this.serverPub,
        amountSat: action.amountSat, feeSat: action.feeSat,
        expiryHeight: action.expiryHeight, exitDelta: this.info.vtxoExitDelta,
        fundingOutpointRaw,
      });
      const nonces = musig2.nonceGen(keys.pubkey, keys.privkey, undefined, board.sighash);
      const cosign = await requestBoardCosign(this.arkUrl, {
        amountSat: action.amountSat, fundingOutpointRaw,
        expiryHeight: action.expiryHeight, userPub: keys.pubkey, pubNonce: nonces.public,
      });
      const finalSig = combineBoardSignature({ board, serverCosign: cosign, userNonces: nonces, vtxoKeys: keys, serverPub: this.serverPub });
      action.vtxoBytes = hex.encode(encodeBoardVtxo({
        userPub: keys.pubkey, serverPub: this.serverPub,
        amountSat: action.amountSat, feeSat: action.feeSat,
        expiryHeight: action.expiryHeight, exitDelta: this.info.vtxoExitDelta,
        fundingOutpointRaw, exitTxidInternal: txid(board.exitTx), finalSig,
      }));
      action.step = 'cosigned';
      this._save();
    }
    if (action.step === 'cosigned') {
      const bytes = hex.decode(action.vtxoBytes);
      await registerBoardVtxo(this.arkUrl, bytes);
      const decoded = decodeVtxo(bytes);
      this._addVtxo(decoded, bytes, action.keyIndex);
      action.step = 'done';
      this._movement({ type: 'board', amountSat: decoded.amountSat, status: 'complete', txid: action.fundingTxid, vtxoId: decoded.id });
      this._save();
    }
  }

  // ---- refresh (also the consolidation primitive) ----
  refreshFee(inputs, tip) {
    const table = this.info.refreshFees.ppmExpiryTable;
    let fee = this.info.refreshFees.baseFeeSat;
    for (const v of inputs) {
      const blocks = v.expiryHeight - tip;
      const entry = table.filter((e) => e.thresholdBlocks <= blocks).pop();
      fee += Math.floor((v.amountSat * (entry?.ppm ?? 0)) / 1_000_000);
    }
    return fee;
  }

  async refresh(vtxoIds) {
    const inputs = (vtxoIds
      ? vtxoIds.map((id) => this._vtxo(id))
      : this.state.vtxos.filter((v) => v.state === 'spendable'));
    if (!inputs.length || inputs.some((v) => !v || v.state !== 'spendable')) {
      throw new Error('no spendable vtxos to refresh');
    }
    const tip = await this.chain.tipHeight();
    const totalSat = inputs.reduce((n, v) => n + v.amountSat, 0);
    const feeSat = this.refreshFee(inputs, tip);
    // The server refuses round outputs under P2TR dust (330), so a wallet
    // this small can't renew — fail before the action marks coins pending.
    if (totalSat - feeSat < 330) {
      throw new Error(`balance too small to refresh: ${totalSat} sat minus ${feeSat} sat fee is under the 330 sat minimum`);
    }
    const action = {
      id: `refresh-${Date.now()}`, type: 'refresh', step: 'created',
      inputIds: inputs.map((v) => v.id),
      outKeyIndex: this.state.nextKeyIndex++,
      outAmountSat: totalSat - feeSat, feeSat,
    };
    for (const v of inputs) v.state = 'pending';
    this.state.actions.push(action);
    this._save();
    await this._driveRefresh(action);
    return action.id;
  }

  _refreshOutputs(action) {
    return [{ amountSat: action.outAmountSat, userPubkey: this._key(action.outKeyIndex).pubkey }];
  }

  async _driveRefresh(action) {
    const outputs = this._refreshOutputs(action);
    const inputRecs = action.inputIds.map((id) => this._vtxo(id));

    if (action.step === 'created') {
      const inputBytes = inputRecs.map((v) => hex.decode(v.bytes));
      await registerVtxoTransactions(this.arkUrl, inputBytes);
      const unlockHash = await submitRoundParticipation(this.arkUrl, {
        inputs: inputRecs.map((v) => ({ vtxo: this._decoded(v), keys: this._keyForVtxo(v) })),
        outputs,
      });
      action.unlockHash = hex.encode(unlockHash);
      action.step = 'submitted';
      this._save();
    }
    if (action.step === 'submitted') {
      const status = await roundParticipationStatus(this.arkUrl, hex.decode(action.unlockHash));
      if (status.status === 0 || !status.fundingTx) return; // round pending; retry on next sync
      const fundingTx = parseTx(status.fundingTx);
      const confirmed = await this.chain.getTxStatus(fundingTx.txid);
      if (!confirmed?.confirmed) return; // wait for funding confirmations
      action.fundingTxHex = hex.encode(status.fundingTx);
      action.outputVtxos = status.outputVtxos.map((b) => hex.encode(b));
      action.step = 'issued';
      this._save();
    }
    if (action.step === 'issued') {
      const outKeys = this._key(action.outKeyIndex);
      const fundingTx = parseTx(hex.decode(action.fundingTxHex));
      const unlockHash = hex.decode(action.unlockHash);
      const newVtxos = action.outputVtxos.map((b) => decodeVtxo(hex.decode(b)));
      // leaf cosign + forfeit are both idempotent server-side
      const leafSigs = [];
      for (const v of newVtxos) {
        leafSigs.push(await cosignHarkLeaf(this.arkUrl, v, fundingTx, outKeys, this.serverPub));
      }
      const serverNonces = await requestForfeitNonces(this.arkUrl, unlockHash,
        inputRecs.map((v) => this._decoded(v).point.raw));
      const bundles = inputRecs.map((v, i) => forfeitBundle({
        input: this._decoded(v), unlockHash,
        vtxoKeys: this._keyForVtxo(v), serverPub: this.serverPub, serverNonce: serverNonces[i],
      }));
      const preimage = await forfeitVtxos(this.arkUrl, bundles);
      if (hex.encode(sha256(preimage)) !== action.unlockHash) {
        throw new Error('unlock preimage does not match hash');
      }
      for (let i = 0; i < newVtxos.length; i++) {
        const v = newVtxos[i];
        const last = v.genesis[v.genesis.length - 1];
        last.transition.signature = hex.encode(leafSigs[i]);
        last.transition.unlock = { preimage: hex.encode(preimage) };
        const bytes = encodeVtxoFromDecoded(v);
        this._addVtxo(decodeVtxo(bytes), bytes, action.outKeyIndex);
      }
      for (const v of inputRecs) v.state = 'spent';
      action.step = 'done';
      this._movement({ type: 'refresh', amountSat: action.outAmountSat, status: 'complete', detail: `${inputRecs.length} in -> ${newVtxos.length} out` });
      this._save();
    }
  }
}

// ArkManager — persistent, crash-safe Ark wallet state on top of the
// src/ark protocol modules. Follows hal's SwapManager shape: a class over a
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
// by hal for receive/change/swaps.

import { hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';
import { secp256k1 } from '@noble/curves/secp256k1';
import * as musig2 from '@scure/btc-signer/musig2';

import {
  getArkInfo, handshake, encodeAddress, decodeAddress, blindMailboxId,
  readMailbox, decodeVtxo, arkIdFromServerPubkey, GrpcError,
} from './proto.js';
import {
  buildArkoorSend, cosignWithServer, buildSignedVtxoBytes,
  registerVtxoTransactions, postArkoorMessage, txid,
} from './send.js';
import {
  boardFee, p2trAddress, buildBoard, requestBoardCosign,
  combineBoardSignature, encodeBoardVtxo, registerBoardVtxo,
} from './board.js';
import {
  submitRoundParticipation, roundParticipationStatus, parseTx,
  cosignHarkLeaf, requestForfeitNonces, forfeitBundle, forfeitVtxos,
  encodeVtxoFromDecoded,
} from './refresh.js';
import { validateVtxo, VtxoValidationError } from './validate.js';

const EMPTY_STATE = () => ({
  v: 1,
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
    this.state = this.storage.load() || EMPTY_STATE();
    this.info = await getArkInfo(this.arkUrl);
    const hs = await handshake(this.arkUrl).catch(() => null);
    this.psa = hs?.psa;
    this.serverPub = hex.decode(this.info.serverPubkey);
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

  // ---- chain adapter (esplora REST, same API hal already speaks) ----
  get chain() {
    const base = this.esploraUrl;
    return {
      tipHeight: async () => Number(await fetch(`${base}/blocks/tip/height`).then((r) => r.text())),
      getTxStatus: async (txid) => fetch(`${base}/tx/${txid}/status`).then((r) => r.ok ? r.json() : null),
      getTxHex: async (txid) => fetch(`${base}/tx/${txid}/hex`).then((r) => r.ok ? r.text() : null),
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
    return { spendableSat: sum('spendable'), pendingSat: sum('pending') };
  }

  // Receives newer than the last acknowledgement — the UI's "Payment
  // received!" celebration. Recency-guarded like the on-chain equivalent so an
  // old payment never celebrates when a wallet is opened much later.
  unseenReceives() {
    const ack = this.state.receiveAckTs || 0;
    const cutoff = Date.now() - 2 * 3600 * 1000;
    return this.state.movements.filter((m) =>
      m.type === 'receive' && m.status === 'complete' && m.ts > ack && m.ts > cutoff);
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
    const mailbox = this._mailboxKey();
    const { messages } = await readMailbox(this.arkUrl, mailbox, this.state.mailboxCheckpoint);
    const ourKeys = [hex.encode(this._key(0).pubkey)];
    let changed = false;
    for (const m of messages) {
      if (m.checkpoint > this.state.mailboxCheckpoint) this.state.mailboxCheckpoint = m.checkpoint;
      if (m.kind !== 'arkoor') { changed = true; continue; }
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
        this._addVtxo(v, v._raw.bytes, 0);
        this._movement({ type: 'receive', amountSat: v.amountSat, status: 'complete', vtxoId: v.id });
        changed = true;
      }
      changed = true;
    }
    if (changed) this._save();
    await this.resumePending();
  }

  async resumePending() {
    for (const action of this.pendingActions()) {
      try {
        if (action.type === 'send') await this._driveSend(action);
        if (action.type === 'board') await this._driveBoard(action);
        if (action.type === 'refresh') await this._driveRefresh(action);
      } catch (e) {
        // transient errors leave the action where it is; a later sync retries
        if (!(e instanceof GrpcError)) throw e;
      }
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
        if (e instanceof GrpcError && /already spent/i.test(e.message)) {
          // the input is gone (possibly a prior crashed attempt) — don't retry
          inputRec.state = 'spent';
          action.step = 'failed';
          action.error = e.message;
          this._movement({ type: 'send', amountSat: action.amountSat, status: 'failed', detail: e.message });
          this._save();
          return;
        }
        throw e;
      }
      // the input is spent server-side from this moment: persist immediately
      action.destBytes = hex.encode(buildSignedVtxoBytes({ input, outputs, build, finalSigs: sigs, serverPubkey: this.serverPub, idx: 0 }));
      if (action.changeSat > 0) {
        const changeBytes = buildSignedVtxoBytes({ input, outputs, build, finalSigs: sigs, serverPubkey: this.serverPub, idx: 1 });
        action.changeBytes = hex.encode(changeBytes);
        this._addVtxo(decodeVtxo(changeBytes), changeBytes, action.changeIndex, 'pending');
      }
      inputRec.state = 'spent';
      action.step = 'cosigned';
      this._save();
    }
    if (action.step === 'cosigned') {
      const list = [hex.decode(action.destBytes)];
      if (action.changeBytes) list.push(hex.decode(action.changeBytes));
      await registerVtxoTransactions(this.arkUrl, list);
      action.step = 'registered';
      this._save();
    }
    if (action.step === 'registered') {
      await postArkoorMessage(this.arkUrl, hex.decode(action.destBlindedId), [hex.decode(action.destBytes)]);
      if (action.changeBytes) {
        const change = this._vtxo(decodeVtxo(hex.decode(action.changeBytes)).id);
        if (change) change.state = 'spendable';
      }
      action.step = 'done';
      this._movement({
        type: 'send', amountSat: action.amountSat, status: 'complete',
        to: action.destAddress, vtxoId: decodeVtxo(hex.decode(action.destBytes)).id,
      });
      this._save();
    }
  }

  // ---- board ----
  // Returns the onchain funding address; hal's onchain wallet pays it (the
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

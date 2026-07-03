// Native-JS delegated round refresh (hArk): submit participation, poll the
// round result, MuSig2-cosign the hash-locked leaf, forfeit the old VTXO in
// exchange for the unlock preimage, and finalize the refreshed VTXO.
//
// Mirrors bark's bark/src/round/mod.rs (join_next_round_delegated /
// progress_delegated / hark_vtxo_swap) and lib/src/{forfeit.rs,tree/signed.rs}.

import { hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import * as musig2 from '@scure/btc-signer/musig2';

import { grpcCall, pbWriter, pbFields, concatBytes, reader } from './proto.js';
import { musigInternalKey, taprootSighash, txid, P2A_SCRIPT, pubkeyPolicyTaproot } from './send.js';

const te = new TextEncoder();
const u32le = (n) => Uint8Array.of(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff);
const u64le = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };
const u64be = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), false); return b; };
const u16le = (n) => Uint8Array.of(n & 0xff, (n >> 8) & 0xff);
const varint = (n) => {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return concatBytes(Uint8Array.of(0xfd), u16le(n));
  return concatBytes(Uint8Array.of(0xfe), u32le(n));
};
const taggedHash = (tag, ...data) => {
  const th = sha256(te.encode(tag));
  return sha256(concatBytes(th, th, ...data));
};

// ---------------------------------------------------------------------------
// scripts + taproots for round vtxo chain reconstruction
// ---------------------------------------------------------------------------

function pushInt(n) {
  if (n === 0) return Uint8Array.of(0x00);
  if (n >= 1 && n <= 16) return Uint8Array.of(0x50 + n);
  const bytes = [];
  let v = n;
  while (v > 0) { bytes.push(v & 0xff); v >>= 8; }
  if (bytes[bytes.length - 1] & 0x80) bytes.push(0x00);
  return Uint8Array.of(bytes.length, ...bytes);
}

const timelockSignScript = (height, xonlyKey) =>
  concatBytes(pushInt(height), Uint8Array.of(0xb1, 0x75, 0x20), xonlyKey, Uint8Array.of(0xac));
const delayedSignScript = (delta, xonlyKey) =>
  concatBytes(pushInt(delta), Uint8Array.of(0xb2, 0x75, 0x20), xonlyKey, Uint8Array.of(0xac));
// OP_HASH160 <ripemd160(hash)> OP_EQUALVERIFY <xonly> OP_CHECKSIG
const hashSignScript = (unlockHash, xonlyKey) =>
  concatBytes(Uint8Array.of(0xa9, 0x14), ripemd160(unlockHash), Uint8Array.of(0x88, 0x20), xonlyKey, Uint8Array.of(0xac));

export const tapLeafHash = (script) =>
  taggedHash('TapLeaf', Uint8Array.of(0xc0), varint(script.length), script);

const byteCompare = (a, b) => {
  for (let i = 0; i < a.length; i++) { if (a[i] !== b[i]) return a[i] - b[i]; }
  return 0;
};
const tapBranch = (a, b) => {
  const [lo, hi] = byteCompare(a, b) <= 0 ? [a, b] : [b, a];
  return taggedHash('TapBranch', lo, hi);
};

function taprootFromMerkle(internalXOnly, merkleRoot) {
  const tapTweak = taggedHash('TapTweak', internalXOnly, ...(merkleRoot ? [merkleRoot] : []));
  const P = secp256k1.ProjectivePoint;
  const internalPoint = P.fromHex(concatBytes(Uint8Array.of(0x02), internalXOnly));
  const outputPoint = internalPoint.add(P.BASE.multiply(BigInt('0x' + hex.encode(tapTweak))));
  const outputXOnly = outputPoint.toRawBytes(true).slice(1);
  return { tapTweak, outputXOnly, scriptPubKey: concatBytes(hex.decode('5120'), outputXOnly) };
}

// Cosigned transition input: internal = musig(pubkeys), one timelock leaf
function cosignedInputTaproot(pubkeys, serverPub, expiryHeight) {
  const { internalXOnly } = musigInternalKey(pubkeys);
  const leaf = tapLeafHash(timelockSignScript(expiryHeight, serverPub.slice(1)));
  return taprootFromMerkle(internalXOnly, leaf);
}

// HashLockedCosigned transition input: hArk leaf output —
// internal = musig(user, server); leaves: expiry (server) + unlock (agg key)
export function harkLeafTaproot(userPub, serverPub, expiryHeight, unlockHash) {
  const { internalXOnly } = musigInternalKey([userPub, serverPub]);
  const expiryLeaf = tapLeafHash(timelockSignScript(expiryHeight, serverPub.slice(1)));
  const unlockScript = hashSignScript(unlockHash, internalXOnly);
  const unlockLeaf = tapLeafHash(unlockScript);
  return { ...taprootFromMerkle(internalXOnly, tapBranch(expiryLeaf, unlockLeaf)), unlockScript, internalXOnly };
}

// Forfeit claim output: internal = musig(user, server);
// leaves: delayed exit (user) + unlock (server key)
function forfeitClaimTaproot(userPub, serverPub, exitDelta, unlockHash) {
  const { internalXOnly } = musigInternalKey([userPub, serverPub]);
  const exitLeaf = tapLeafHash(delayedSignScript(exitDelta, userPub.slice(1)));
  const unlockLeaf = tapLeafHash(hashSignScript(unlockHash, serverPub.slice(1)));
  return taprootFromMerkle(internalXOnly, tapBranch(exitLeaf, unlockLeaf));
}

// ---------------------------------------------------------------------------
// vtxo tx-chain reconstruction (VtxoTxIter)
// ---------------------------------------------------------------------------

const otherSum = (item) =>
  item.feeSat + item.otherOutputs.reduce((n, o) => n + o.valueSat, 0);

export function transitionInputTxout(transition, amountSat, serverPub, expiryHeight) {
  if (transition.type === 'cosigned') {
    const pubkeys = transition.pubkeys.map((p) => hex.decode(p));
    return { valueSat: amountSat, scriptPubKey: cosignedInputTaproot(pubkeys, serverPub, expiryHeight).scriptPubKey };
  }
  if (transition.type === 'hashLockedCosigned') {
    const hash = hex.decode(transition.unlock.hash ?? sha256Hex(transition.unlock.preimage));
    const tp = harkLeafTaproot(hex.decode(transition.userPubkey), serverPub, expiryHeight, hash);
    return { valueSat: amountSat, scriptPubKey: tp.scriptPubKey };
  }
  if (transition.type === 'arkoor') {
    // output key = musig(cosigners + server) with the stored x-only taptweak
    const keys = musig2.sortKeys([...transition.clientCosigners.map((p) => hex.decode(p)), serverPub]);
    const ctx = musig2.keyAggregate(keys, [hex.decode(transition.tapTweak)], [true]);
    const outputXOnly = musig2.keyAggExport(ctx);
    return { valueSat: amountSat, scriptPubKey: concatBytes(hex.decode('5120'), outputXOnly) };
  }
  throw new Error('input_txout unsupported for transition ' + transition.type);
}
const sha256Hex = (h) => hex.encode(sha256(hex.decode(h)));

export const vtxoAnchorAmount = (vtxo) =>
  vtxo.amountSat + vtxo.genesis.reduce((n, it) => n + otherSum(it), 0);

// Walk the genesis chain, returning [{tx, outputIdx}] like Vtxo::transactions()
export function vtxoTransactions(vtxo, serverPub) {
  const anchorAmount = vtxoAnchorAmount(vtxo);
  let prev = vtxo.anchorPoint.raw;
  let currentAmount = anchorAmount;
  const items = [];
  for (let i = 0; i < vtxo.genesis.length; i++) {
    const item = vtxo.genesis[i];
    const nextAmount = currentAmount - otherSum(item);
    const nextOutput = i + 1 < vtxo.genesis.length
      ? transitionInputTxout(vtxo.genesis[i + 1].transition, nextAmount, serverPub, vtxo.expiryHeight)
      : { valueSat: vtxo.amountSat,
          scriptPubKey: pubkeyPolicyTaproot(hex.decode(vtxo.policy.userPubkey), serverPub, vtxo.exitDelta).scriptPubKey };
    // decoded txouts carry hex-string scripts — normalize to bytes
    const others = item.otherOutputs.map((o) => ({ valueSat: o.valueSat, scriptPubKey: hex.decode(o.scriptPubKey) }));
    const outs = [
      ...others.slice(0, item.outputIdx),
      nextOutput,
      ...others.slice(item.outputIdx),
      { valueSat: item.feeSat, scriptPubKey: P2A_SCRIPT },
    ];
    const tx = { version: 3, locktime: 0, inputs: [{ prevout: prev, sequence: 0 }], outputs: outs };
    const id = txid(tx);
    prev = concatBytes(id, u32le(item.outputIdx));
    currentAmount = nextAmount;
    items.push({ tx, outputIdx: item.outputIdx });
  }
  return items;
}

// BIP-341 script-spend sighash (SIGHASH_DEFAULT, single input, no annex)
export function taprootScriptSighash(tx, prevouts, leafHash) {
  const base = taprootSighashFields(tx, prevouts);
  return taggedHash('TapSighash',
    ...base,
    Uint8Array.of(0x02), // spend type: ext_flag=1 (script), no annex
    u32le(0),            // input index
    leafHash, Uint8Array.of(0x00), u32le(0xffffffff), // ext: leaf, key ver, codesep
  );
}
function taprootSighashFields(tx, prevouts) {
  const shaPrevouts = sha256(concatBytes(...tx.inputs.map((i) => i.prevout)));
  const shaAmounts = sha256(concatBytes(...prevouts.map((p) => u64le(p.valueSat))));
  const shaScripts = sha256(concatBytes(...prevouts.map((p) => concatBytes(varint(p.scriptPubKey.length), p.scriptPubKey))));
  const shaSequences = sha256(concatBytes(...tx.inputs.map((i) => u32le(i.sequence))));
  const shaOutputs = sha256(concatBytes(...tx.outputs.map((o) => concatBytes(u64le(o.valueSat), varint(o.scriptPubKey.length), o.scriptPubKey))));
  return [Uint8Array.of(0x00), Uint8Array.of(0x00), u32le(tx.version), u32le(tx.locktime),
    shaPrevouts, shaAmounts, shaScripts, shaSequences, shaOutputs];
}

// ---------------------------------------------------------------------------
// consensus tx parsing (for the round funding tx)
// ---------------------------------------------------------------------------

export function parseTx(bytes) {
  const r = reader(bytes);
  const version = r.u32();
  let marker = false;
  let inCount = r.compactSize();
  if (inCount === 0) { // segwit marker
    const flag = r.u8();
    if (flag !== 1) throw new Error('bad segwit flag');
    marker = true;
    inCount = r.compactSize();
  }
  const inputs = [];
  for (let i = 0; i < inCount; i++) {
    const prevout = r.bytes(36);
    const scriptSig = r.bytes(r.compactSize());
    const sequence = r.u32();
    inputs.push({ prevout, scriptSig, sequence });
  }
  const outCount = r.compactSize();
  const outputs = [];
  for (let i = 0; i < outCount; i++) {
    const valueSat = Number(r.u64());
    const scriptPubKey = r.bytes(r.compactSize());
    outputs.push({ valueSat, scriptPubKey });
  }
  if (marker) for (let i = 0; i < inCount; i++) {
    const n = r.compactSize();
    for (let j = 0; j < n; j++) r.bytes(r.compactSize());
  }
  const locktime = r.u32();
  // txid over the stripped serialization
  const stripped = concatBytes(
    u32le(version), varint(inputs.length),
    ...inputs.flatMap((i) => [i.prevout, varint(i.scriptSig.length), i.scriptSig, u32le(i.sequence)]),
    varint(outputs.length),
    ...outputs.flatMap((o) => [u64le(o.valueSat), varint(o.scriptPubKey.length), o.scriptPubKey]),
    u32le(locktime),
  );
  const id = sha256(sha256(stripped));
  return { version, inputs, outputs, locktime, txidInternal: id, txid: hex.encode(id.slice().reverse()) };
}

// ---------------------------------------------------------------------------
// vtxo re-encoding from decoded form (to patch leaf sig + preimage)
// ---------------------------------------------------------------------------

const encodeTransition = (t) => {
  const sig = t.signature ? hex.decode(t.signature) : new Uint8Array(64);
  if (t.type === 'cosigned') {
    return concatBytes(Uint8Array.of(0x01), varint(t.pubkeys.length),
      ...t.pubkeys.map((p) => hex.decode(p)), sig);
  }
  if (t.type === 'arkoor') {
    return concatBytes(Uint8Array.of(0x02), varint(t.clientCosigners.length),
      ...t.clientCosigners.map((p) => hex.decode(p)), hex.decode(t.tapTweak), sig);
  }
  if (t.type === 'hashLockedCosigned') {
    const [tag, val] = t.unlock.preimage != null
      ? [0, hex.decode(t.unlock.preimage)] : [1, hex.decode(t.unlock.hash)];
    return concatBytes(Uint8Array.of(0x03), hex.decode(t.userPubkey), sig, Uint8Array.of(tag), val);
  }
  throw new Error('unknown transition type ' + t.type);
};

export function encodeVtxoFromDecoded(v) {
  return concatBytes(
    u16le(2), u64le(v.amountSat), u32le(v.expiryHeight),
    hex.decode(v.serverPubkey), u16le(v.exitDelta), v.anchorPoint.raw,
    varint(v.genesis.length),
    ...v.genesis.map((item) => concatBytes(
      encodeTransition(item.transition),
      Uint8Array.of(item.nbOutputs, item.outputIdx),
      ...item.otherOutputs.map((o) => concatBytes(u64le(o.valueSat), varint(hex.decode(o.scriptPubKey).length), hex.decode(o.scriptPubKey))),
      u64le(item.feeSat),
    )),
    Uint8Array.of(0x00), hex.decode(v.policy.userPubkey),
    v.point.raw,
  );
}

// ---------------------------------------------------------------------------
// RPCs + ceremonies
// ---------------------------------------------------------------------------

const PARTICIPATION_ATTESTATION_PREFIX = te.encode('hArk round join ownership proof ');

// NB this attestation uses BIG-endian integers (unlike the arkoor one)
export function participationAttestation(inputVtxoIdRaw, outputs, vtxoPrivkey) {
  const msg = sha256(concatBytes(
    PARTICIPATION_ATTESTATION_PREFIX,
    inputVtxoIdRaw,
    u64be(outputs.length),
    ...outputs.flatMap((o) => [u64be(o.amountSat), concatBytes(Uint8Array.of(0x00), o.userPubkey)]),
  ));
  return schnorr.sign(msg, vtxoPrivkey);
}

// inputs: [{ vtxo, keys }] — each input's attestation is signed by its own key
export async function submitRoundParticipation(ark, { inputs, outputs }) {
  const w = pbWriter();
  for (const { vtxo, keys } of inputs) {
    const iv = pbWriter();
    iv.bytesField(1, vtxo.point.raw);
    iv.bytesField(2, participationAttestation(vtxo.point.raw, outputs, keys.privkey));
    w.bytesField(2, iv.finish());
  }
  for (const o of outputs) {
    const vr = pbWriter();
    vr.varintField(1, o.amountSat);
    vr.bytesField(2, concatBytes(Uint8Array.of(0x00), o.userPubkey));
    w.bytesField(3, vr.finish());
  }
  const resp = await grpcCall(ark, 'bark_server.ArkService/SubmitRoundParticipation', w.finish());
  for (const { field, value } of pbFields(resp)) if (field === 1) return value; // unlock_hash
  throw new Error('no unlock hash in response');
}

export async function roundParticipationStatus(ark, unlockHash) {
  const w = pbWriter();
  w.bytesField(1, unlockHash);
  const resp = await grpcCall(ark, 'bark_server.ArkService/RoundParticipationStatus', w.finish());
  const out = { status: 0, outputVtxos: [] };
  for (const { field, value } of pbFields(resp)) {
    if (field === 1) out.status = Number(value);
    if (field === 2) out.fundingTx = value;
    if (field === 3) out.outputVtxos.push(value);
    if (field === 4) out.unlockPreimage = value;
  }
  return out;
}

// MuSig2 script-spend cosign of the hash-locked leaf (NO taptweak)
export async function cosignHarkLeaf(ark, vtxo, fundingTx, vtxoKeys, serverPub) {
  const last = vtxo.genesis[vtxo.genesis.length - 1];
  if (last.transition.type !== 'hashLockedCosigned') throw new Error('not a hark leaf vtxo');
  const unlockHash = hex.decode(last.transition.unlock.hash);

  // leaf tx + the output it spends
  const chain = vtxoTransactions(vtxo, serverPub);
  const leaf = chain[chain.length - 1];
  const preleafTxout = chain.length >= 2
    ? chain[chain.length - 2].tx.outputs[chain[chain.length - 2].outputIdx]
    : fundingTx.outputs[vtxo.anchorPoint.vout];

  const tp = harkLeafTaproot(vtxoKeys.pubkey, serverPub, vtxo.expiryHeight, unlockHash);
  const sighash = taprootScriptSighash(leaf.tx, [preleafTxout], tapLeafHash(tp.unlockScript));

  const nonces = musig2.nonceGen(vtxoKeys.pubkey, vtxoKeys.privkey, undefined, sighash);
  const w = pbWriter();
  w.bytesField(1, vtxo.point.raw);
  w.bytesField(2, nonces.public);
  const resp = await grpcCall(ark, 'bark_server.ArkService/RequestLeafVtxoCosign', w.finish());
  let serverNonce, serverPartial;
  for (const { field, value } of pbFields(resp)) {
    if (field === 1) serverNonce = value;
    if (field === 2) serverPartial = value;
  }

  const { sortedKeys } = musigInternalKey([vtxoKeys.pubkey, serverPub]);
  const aggNonce = musig2.nonceAggregate([nonces.public, serverNonce]);
  const session = new musig2.Session(aggNonce, sortedKeys, sighash); // no tweak: script spend
  const serverIdx = sortedKeys.findIndex((k) => hex.encode(k) === hex.encode(serverPub));
  const noncesInKeyOrder = serverIdx === 0 ? [serverNonce, nonces.public] : [nonces.public, serverNonce];
  if (!session.partialSigVerify(serverPartial, noncesInKeyOrder, serverIdx)) {
    throw new Error('server leaf partial signature invalid');
  }
  const userPartial = session.sign(nonces.secret, vtxoKeys.privkey);
  const finalSig = session.partialSigAgg([userPartial, serverPartial]);
  if (!schnorr.verify(finalSig, sighash, tp.internalXOnly)) {
    throw new Error('combined leaf signature does not verify against agg key');
  }
  return finalSig;
}

export async function requestForfeitNonces(ark, unlockHash, vtxoIdRaws) {
  const w = pbWriter();
  w.bytesField(1, unlockHash);
  for (const id of vtxoIdRaws) w.bytesField(2, id);
  const resp = await grpcCall(ark, 'bark_server.ArkService/RequestForfeitNonces', w.finish());
  const nonces = [];
  for (const { field, value } of pbFields(resp)) if (field === 1) nonces.push(value);
  return nonces;
}

// Sign the forfeit tx for `input` and build the wire bundle
export function forfeitBundle({ input, unlockHash, vtxoKeys, serverPub, serverNonce }) {
  const inputTaproot = pubkeyPolicyTaproot(vtxoKeys.pubkey, serverPub, input.exitDelta);
  const claim = forfeitClaimTaproot(vtxoKeys.pubkey, serverPub, input.exitDelta, unlockHash);
  const forfeitTx = {
    version: 3, locktime: 0,
    inputs: [{ prevout: input.point.raw, sequence: 0xffffffff }],
    outputs: [
      { valueSat: input.amountSat, scriptPubKey: claim.scriptPubKey },
      { valueSat: 0, scriptPubKey: P2A_SCRIPT },
    ],
  };
  const prevout = { valueSat: input.amountSat, scriptPubKey: inputTaproot.scriptPubKey };
  const sighash = taprootSighash(forfeitTx, [prevout]);

  const nonces = musig2.nonceGen(vtxoKeys.pubkey, vtxoKeys.privkey, undefined, sighash);
  const aggNonce = musig2.nonceAggregate([nonces.public, serverNonce]);
  const session = new musig2.Session(aggNonce, inputTaproot.sortedKeys, sighash, [inputTaproot.tapTweak], [true]);
  const partial = session.sign(nonces.secret, vtxoKeys.privkey);

  return concatBytes(Uint8Array.of(0x01), input.point.raw, unlockHash, nonces.public, partial);
}

export async function forfeitVtxos(ark, bundles) {
  const w = pbWriter();
  for (const b of bundles) w.bytesField(1, b);
  const resp = await grpcCall(ark, 'bark_server.ArkService/ForfeitVtxos', w.finish());
  for (const { field, value } of pbFields(resp)) if (field === 1) return value; // preimage
  throw new Error('no unlock preimage in response');
}

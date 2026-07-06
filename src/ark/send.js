// Native-JS arkoor send: checkpoint + arkoor transaction construction,
// BIP-341 sighashes, MuSig2 cosign ceremony with the ASP, and signed-VTXO
// assembly. Mirrors bark's lib/src/arkoor/mod.rs ArkoorBuilder (checkpoint
// mode, no dust isolation).

import { hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import * as musig2 from '@scure/btc-signer/musig2';

import { concatBytes, reader, grpcCall, pbWriter, pbFields } from './proto.js';

const te = new TextEncoder();

// ---------------------------------------------------------------------------
// small bitcoin helpers
// ---------------------------------------------------------------------------

const u16le = (n) => Uint8Array.of(n & 0xff, (n >> 8) & 0xff);
const u32le = (n) => Uint8Array.of(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff);
const u64le = (n) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
};
const varint = (n) => {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return concatBytes(Uint8Array.of(0xfd), u16le(n));
  return concatBytes(Uint8Array.of(0xfe), u32le(n));
};

const sha256d = (b) => sha256(sha256(b));

const taggedHash = (tag, ...data) => {
  const th = sha256(te.encode(tag));
  return sha256(concatBytes(th, th, ...data));
};

// minimal script-number push (as bitcoin's push_int)
function pushInt(n) {
  if (n === 0) return Uint8Array.of(0x00); // OP_0
  if (n >= 1 && n <= 16) return Uint8Array.of(0x50 + n); // OP_1..OP_16
  const bytes = [];
  let v = n;
  while (v > 0) { bytes.push(v & 0xff); v >>= 8; }
  if (bytes[bytes.length - 1] & 0x80) bytes.push(0x00);
  return Uint8Array.of(bytes.length, ...bytes);
}

const OP = { CSV: 0xb2, CLTV: 0xb1, DROP: 0x75, CHECKSIG: 0xac };
export const P2A_SCRIPT = hex.decode('51024e73');

// delayed_sign: <csv> OP_CSV OP_DROP <xonly> OP_CHECKSIG
const delayedSignScript = (delta, xonly) =>
  concatBytes(pushInt(delta), Uint8Array.of(OP.CSV, OP.DROP, 0x20), xonly, Uint8Array.of(OP.CHECKSIG));

// timelock_sign: <height> OP_CLTV OP_DROP <xonly> OP_CHECKSIG
const timelockSignScript = (height, xonly) =>
  concatBytes(pushInt(height), Uint8Array.of(OP.CLTV, OP.DROP, 0x20), xonly, Uint8Array.of(OP.CHECKSIG));

// ---------------------------------------------------------------------------
// taproot + musig key aggregation
// ---------------------------------------------------------------------------

const xonly = (pub33) => pub33.slice(1);

// bark: musig::combine_keys — KeySort then KeyAgg, no tweak
export function musigInternalKey(keys) {
  const sorted = musig2.sortKeys(keys.map((k) => Uint8Array.from(k)));
  const ctx = musig2.keyAggregate(sorted);
  return { sortedKeys: sorted, internalXOnly: musig2.keyAggExport(ctx) }; // 32B x-only
}

const tapLeafHash = (script) =>
  taggedHash('TapLeaf', Uint8Array.of(0xc0), varint(script.length), script);

// One-leaf taproot around a musig2 internal key.
// Returns everything both tx-building and signing need.
export function taprootOneLeaf(userPub, serverPub, leafScript) {
  const { sortedKeys, internalXOnly } = musigInternalKey([userPub, serverPub]);
  const merkleRoot = tapLeafHash(leafScript);
  const tapTweak = taggedHash('TapTweak', internalXOnly, merkleRoot);
  const P = secp256k1.ProjectivePoint;
  // lift internal x-only, add tweak*G
  const internalPoint = P.fromHex(concatBytes(Uint8Array.of(0x02), internalXOnly));
  const outputPoint = internalPoint.add(P.BASE.multiply(BigInt('0x' + hex.encode(tapTweak))));
  const outputCompressed = outputPoint.toRawBytes(true);
  const outputXOnly = outputCompressed.slice(1);
  const scriptPubKey = concatBytes(hex.decode('5120'), outputXOnly);
  const outputParity = outputCompressed[0] === 0x03 ? 1 : 0; // for script-path control blocks
  return { sortedKeys, internalXOnly, merkleRoot, tapTweak, outputXOnly, outputParity, scriptPubKey };
}

// PubkeyVtxoPolicy: keyspend musig(user,server); leaf = delayed_sign(exit_delta, user).
// leafScript is returned so a unilateral exit can claim through it after the CSV.
export const pubkeyPolicyTaproot = (userPub, serverPub, exitDelta) => {
  const leafScript = delayedSignScript(exitDelta, xonly(userPub));
  return { ...taprootOneLeaf(userPub, serverPub, leafScript), leafScript };
};

// CheckpointVtxoPolicy: keyspend musig(user,server); leaf = timelock_sign(expiry, server)
export const checkpointPolicyTaproot = (userPub, serverPub, expiryHeight) =>
  taprootOneLeaf(userPub, serverPub, timelockSignScript(expiryHeight, xonly(serverPub)));

// ---------------------------------------------------------------------------
// transactions (version 3, zero locktime, sequence 0)
// ---------------------------------------------------------------------------

const serializeTx = (tx) => concatBytes(
  u32le(tx.version),
  varint(tx.inputs.length),
  ...tx.inputs.flatMap((i) => [i.prevout, Uint8Array.of(0x00), u32le(i.sequence)]),
  varint(tx.outputs.length),
  ...tx.outputs.flatMap((o) => [u64le(o.valueSat), varint(o.scriptPubKey.length), o.scriptPubKey]),
  u32le(tx.locktime),
);

export const txid = (tx) => sha256d(serializeTx(tx)); // internal byte order

const outpointBytes = (txidInternal, vout) => concatBytes(txidInternal, u32le(vout));

// BIP-341 key-spend sighash, SIGHASH_DEFAULT, single input
export function taprootSighash(tx, prevouts) {
  const shaPrevouts = sha256(concatBytes(...tx.inputs.map((i) => i.prevout)));
  const shaAmounts = sha256(concatBytes(...prevouts.map((p) => u64le(p.valueSat))));
  const shaScripts = sha256(concatBytes(...prevouts.map((p) =>
    concatBytes(varint(p.scriptPubKey.length), p.scriptPubKey))));
  const shaSequences = sha256(concatBytes(...tx.inputs.map((i) => u32le(i.sequence))));
  const shaOutputs = sha256(concatBytes(...tx.outputs.map((o) =>
    concatBytes(u64le(o.valueSat), varint(o.scriptPubKey.length), o.scriptPubKey))));
  return taggedHash('TapSighash',
    Uint8Array.of(0x00), // sighash epoch
    Uint8Array.of(0x00), // hash type: default
    u32le(tx.version), u32le(tx.locktime),
    shaPrevouts, shaAmounts, shaScripts, shaSequences, shaOutputs,
    Uint8Array.of(0x00), // spend type: key path, no annex
    u32le(0),            // input index
  );
}

// ---------------------------------------------------------------------------
// VTXO encoding (mirror of decodeVtxo)
// ---------------------------------------------------------------------------

const encodePubkeyPolicy = (pub33) => concatBytes(Uint8Array.of(0x00), pub33);

// GenesisTransition::Arkoor
const encodeArkoorTransition = ({ cosigners, tapTweak, signature }) => concatBytes(
  Uint8Array.of(0x02),
  varint(cosigners.length), ...cosigners,
  tapTweak,
  signature ?? new Uint8Array(64),
);

const encodeGenesisItem = ({ transition, nbOutputs, outputIdx, otherOutputs, feeSat }) => concatBytes(
  transition,
  Uint8Array.of(nbOutputs, outputIdx),
  ...otherOutputs.map((o) => concatBytes(u64le(o.valueSat), varint(o.scriptPubKey.length), o.scriptPubKey)),
  u64le(feeSat),
);

// Assemble a Vtxo<Full> from the spent input's raw genesis bytes + new items.
function encodeVtxo({ amountSat, expiryHeight, serverPubkey, exitDelta, anchorPointRaw,
                      inputGenesisRaw, inputGenesisCount, newItems, policyBytes, pointRaw }) {
  return concatBytes(
    u16le(2), // encoding version
    u64le(amountSat),
    u32le(expiryHeight),
    serverPubkey,
    u16le(exitDelta),
    anchorPointRaw,
    varint(inputGenesisCount + newItems.length),
    inputGenesisRaw,
    ...newItems,
    policyBytes,
    pointRaw,
  );
}

// ---------------------------------------------------------------------------
// the send itself
// ---------------------------------------------------------------------------

// Build everything for a checkpointed single-input arkoor send.
// input: decoded vtxo (from decodeVtxo, with _raw), owned by keys.vtxo
// outputs: [{ amountSat, userPubkey (33B) }...] — destination first, change last
export function buildArkoorSend({ input, outputs, serverPubkey, vtxoKeys }) {
  const userPub = vtxoKeys.pubkey;
  if (hex.encode(userPub) !== input.policy.userPubkey) throw new Error('input not owned by our key');

  const inputTaproot = pubkeyPolicyTaproot(userPub, serverPubkey, input.exitDelta);
  const checkpointTaproot = checkpointPolicyTaproot(userPub, serverPubkey, input.expiryHeight);

  // checkpoint tx: spends the input vtxo, one output per destination
  // (all with the checkpoint policy spk) + P2A fee anchor
  const checkpointTx = {
    version: 3, locktime: 0,
    inputs: [{ prevout: input.point.raw, sequence: 0 }],
    outputs: [
      ...outputs.map((o) => ({ valueSat: o.amountSat, scriptPubKey: checkpointTaproot.scriptPubKey })),
      { valueSat: 0, scriptPubKey: P2A_SCRIPT },
    ],
  };
  const checkpointTxid = txid(checkpointTx);

  // one arkoor tx per output, spending checkpoint:vout
  const arkoorTxs = outputs.map((o, vout) => {
    const destTaproot = pubkeyPolicyTaproot(o.userPubkey, serverPubkey, input.exitDelta);
    return {
      version: 3, locktime: 0,
      inputs: [{ prevout: outpointBytes(checkpointTxid, vout), sequence: 0 }],
      outputs: [
        { valueSat: o.amountSat, scriptPubKey: destTaproot.scriptPubKey },
        { valueSat: 0, scriptPubKey: P2A_SCRIPT },
      ],
    };
  });

  // sighashes: [checkpoint spend of input, arkoor_i spend of checkpoint:i]
  const inputPrevout = { valueSat: input.amountSat, scriptPubKey: inputTaproot.scriptPubKey };
  const sighashes = [
    taprootSighash(checkpointTx, [inputPrevout]),
    ...arkoorTxs.map((tx, i) => taprootSighash(tx, [checkpointTx.outputs[i]])),
  ];
  // taptweaks per signature (bark: taptweak_at)
  const tweaks = [inputTaproot.tapTweak, ...arkoorTxs.map(() => checkpointTaproot.tapTweak)];

  return { checkpointTx, checkpointTxid, arkoorTxs, sighashes, tweaks, inputTaproot, checkpointTaproot };
}

// "arkoor cosign attestation       " — 32-byte prefix
const ATTESTATION_PREFIX = te.encode('arkoor cosign attestation       ');

export function cosignAttestation(inputVtxoIdRaw, outputs, vtxoPrivkey) {
  const msg = sha256(concatBytes(
    ATTESTATION_PREFIX,
    inputVtxoIdRaw,
    u32le(outputs.length),
    ...outputs.flatMap((o) => [u64le(o.amountSat), encodePubkeyPolicy(o.userPubkey)]),
  ));
  return schnorr.sign(msg, vtxoPrivkey);
}

// full MuSig2 ceremony over the ASP's RequestArkoorCosign
export async function cosignWithServer(ark, build, { input, outputs, vtxoKeys, serverPubkey }) {
  const nSigs = build.sighashes.length;

  // 1. nonces, bound to each sighash
  const nonces = build.sighashes.map((sh) =>
    musig2.nonceGen(vtxoKeys.pubkey, vtxoKeys.privkey, undefined, sh));

  // 2. request
  const part = pbWriter();
  part.bytesField(1, input.point.raw); // vtxo id = outpoint bytes
  for (const o of outputs) {
    const dest = pbWriter();
    dest.varintField(1, o.amountSat);
    dest.bytesField(2, encodePubkeyPolicy(o.userPubkey));
    part.bytesField(2, dest.finish());
  }
  for (const n of nonces) part.bytesField(3, n.public);
  part.varintField(5, 1); // use_checkpoint = true
  part.bytesField(6, cosignAttestation(input.point.raw, outputs, vtxoKeys.privkey));

  const req = pbWriter();
  req.bytesField(1, part.finish());
  const respBytes = await grpcCall(ark, 'bark_server.ArkService/RequestArkoorCosign', req.finish());

  // 3. parse response
  const serverNonces = [], serverPartials = [];
  for (const { field, value } of pbFields(respBytes)) {
    if (field !== 1) continue;
    for (const f of pbFields(value)) {
      if (f.field === 1) serverNonces.push(f.value);
      if (f.field === 2) serverPartials.push(f.value);
    }
  }
  if (serverNonces.length !== nSigs || serverPartials.length !== nSigs) {
    throw new Error(`bad cosign response: ${serverNonces.length} nonces, ${serverPartials.length} partials, wanted ${nSigs}`);
  }

  // 4. combine: session per sighash with the taptweak as x-only tweak
  const finalSigs = [];
  for (let i = 0; i < nSigs; i++) {
    const aggNonce = musig2.nonceAggregate([nonces[i].public, serverNonces[i]]);
    const session = new musig2.Session(
      aggNonce, build.inputTaproot.sortedKeys, build.sighashes[i], [build.tweaks[i]], [true],
    );
    // verify the server's partial before combining (bark does the same)
    const serverIdx = build.inputTaproot.sortedKeys.findIndex(
      (k) => hex.encode(k) === hex.encode(serverPubkey));
    const noncesInKeyOrder = serverIdx === 0
      ? [serverNonces[i], nonces[i].public] : [nonces[i].public, serverNonces[i]];
    if (!session.partialSigVerify(serverPartials[i], noncesInKeyOrder, serverIdx)) {
      throw new Error(`server partial signature ${i} is invalid`);
    }
    const userPartial = session.sign(nonces[i].secret, vtxoKeys.privkey);
    const finalSig = session.partialSigAgg([userPartial, serverPartials[i]]);
    // self-check against the taproot output key this signature must satisfy
    const outputKey = i === 0 ? build.inputTaproot.outputXOnly : build.checkpointTaproot.outputXOnly;
    if (!schnorr.verify(finalSig, build.sighashes[i], outputKey)) {
      throw new Error(`combined signature ${i} does not verify against taproot output key`);
    }
    finalSigs.push(finalSig);
  }
  return finalSigs;
}

// assemble the final signed Vtxo<Full> bytes for output `idx`
export function buildSignedVtxoBytes({ input, outputs, build, finalSigs, serverPubkey, idx }) {
  const o = outputs[idx];
  // NB nb_outputs on the wire counts own output + other_outputs — the P2A
  // fee anchor is excluded (bark: other_outputs.len() + 1).
  const checkpointOthers = build.checkpointTx.outputs.filter((out, i) =>
    i !== idx && hex.encode(out.scriptPubKey) !== hex.encode(P2A_SCRIPT));
  const checkpointItem = encodeGenesisItem({
    transition: encodeArkoorTransition({
      cosigners: [Uint8Array.from(hex.decode(input.policy.userPubkey))],
      tapTweak: build.inputTaproot.tapTweak,
      signature: finalSigs[0],
    }),
    nbOutputs: checkpointOthers.length + 1,
    outputIdx: idx,
    otherOutputs: checkpointOthers,
    feeSat: 0,
  });
  const arkoorItem = encodeGenesisItem({
    transition: encodeArkoorTransition({
      cosigners: [Uint8Array.from(hex.decode(input.policy.userPubkey))],
      tapTweak: build.checkpointTaproot.tapTweak,
      signature: finalSigs[1 + idx],
    }),
    nbOutputs: 1,
    outputIdx: 0,
    otherOutputs: [],
    feeSat: 0,
  });

  const raw = input._raw;
  return encodeVtxo({
    amountSat: o.amountSat,
    expiryHeight: input.expiryHeight,
    serverPubkey,
    exitDelta: input.exitDelta,
    anchorPointRaw: input.anchorPoint.raw,
    inputGenesisRaw: raw.bytes.slice(raw.itemsStart, raw.itemsEnd),
    inputGenesisCount: raw.nItems,
    newItems: [checkpointItem, arkoorItem],
    policyBytes: encodePubkeyPolicy(o.userPubkey),
    pointRaw: outpointBytes(txid(build.arkoorTxs[idx]), 0),
  });
}

// ---------------------------------------------------------------------------
// remaining RPCs
// ---------------------------------------------------------------------------

export async function registerVtxoTransactions(ark, vtxoBytesList) {
  const w = pbWriter();
  for (const v of vtxoBytesList) w.bytesField(1, v);
  await grpcCall(ark, 'bark_server.ArkService/RegisterVtxoTransactions', w.finish());
}

export async function postArkoorMessage(ark, blindedId, vtxoBytesList) {
  const w = pbWriter();
  w.bytesField(1, blindedId);
  for (const v of vtxoBytesList) w.bytesField(2, v);
  await grpcCall(ark, 'mailbox_server.MailboxService/PostArkoorMessage', w.finish());
}

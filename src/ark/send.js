// Native-JS arkoor send: checkpoint + arkoor transaction construction,
// BIP-341 sighashes, MuSig2 cosign ceremony with the ASP, and signed-VTXO
// assembly. Mirrors bark's lib/src/arkoor/mod.rs ArkoorBuilder (checkpoint
// mode, no dust isolation).

import { hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import * as musig2 from '@scure/btc-signer/musig2';

import { concatBytes, reader, grpcCall, pbWriter, pbFields } from './proto.js';

// hex string or byte array -> bytes (decoded vtxos carry hex-string fields)
const asBytes = (v) => (typeof v === 'string' ? hex.decode(v) : Uint8Array.from(v));

// The key that cosigns arkoor spends of a vtxo with this policy (bark's
// VtxoPolicy::arkoor_pubkey).
export const policyOwnerPubkey = (policy) => policy.userPubkey;

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

const OP = { CSV: 0xb2, CLTV: 0xb1, DROP: 0x75, CHECKSIG: 0xac, HASH160: 0xa9, EQUALVERIFY: 0x88, SIZE: 0x82 };
export const P2A_SCRIPT = hex.decode('51024e73');

// delayed_sign: <csv> OP_CSV OP_DROP <xonly> OP_CHECKSIG
const delayedSignScript = (delta, xonly) =>
  concatBytes(pushInt(delta), Uint8Array.of(OP.CSV, OP.DROP, 0x20), xonly, Uint8Array.of(OP.CHECKSIG));

// timelock_sign: <height> OP_CLTV OP_DROP <xonly> OP_CHECKSIG
const timelockSignScript = (height, xonly) =>
  concatBytes(pushInt(height), Uint8Array.of(OP.CLTV, OP.DROP, 0x20), xonly, Uint8Array.of(OP.CHECKSIG));

// hash_delay_sign_v0: <csv> OP_CSV OP_DROP OP_HASH160 <ripemd160(hash)> OP_EQUALVERIFY <xonly> OP_CHECKSIG
// (the witness reveals the 32B preimage; HASH160(preimage) = ripemd160(sha256(preimage)))
const hashDelaySignScript = (paymentHash, delta, xonly) => concatBytes(
  pushInt(delta), Uint8Array.of(OP.CSV, OP.DROP, OP.HASH160, 0x14), ripemd160(paymentHash),
  Uint8Array.of(OP.EQUALVERIFY, 0x20), xonly, Uint8Array.of(OP.CHECKSIG));

// hash_delay_sign (v1, pver 5): same, but the preimage's size is checked to be
// 32 bytes before hashing — OP_SIZE <32> OP_EQUALVERIFY inserted after the
// timelock, mirroring Lightning's own on-chain check.
const hashDelaySignScriptV1 = (paymentHash, delta, xonly) => concatBytes(
  pushInt(delta), Uint8Array.of(OP.CSV, OP.DROP, OP.SIZE, 0x01, 0x20, OP.EQUALVERIFY, OP.HASH160, 0x14),
  ripemd160(paymentHash),
  Uint8Array.of(OP.EQUALVERIFY, 0x20), xonly, Uint8Array.of(OP.CHECKSIG));

// delay_timelock_sign: <height> OP_CLTV OP_DROP <csv> OP_CSV OP_DROP <xonly> OP_CHECKSIG
const delayTimelockSignScript = (height, delta, xonly) => concatBytes(
  pushInt(height), Uint8Array.of(OP.CLTV, OP.DROP), pushInt(delta),
  Uint8Array.of(OP.CSV, OP.DROP, 0x20), xonly, Uint8Array.of(OP.CHECKSIG));

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

// BIP-341 branch hash: children sorted lexicographically
const tapBranch = (a, b) => {
  let swap = false;
  for (let i = 0; i < 32; i++) { if (a[i] !== b[i]) { swap = a[i] > b[i]; break; } }
  return swap ? taggedHash('TapBranch', b, a) : taggedHash('TapBranch', a, b);
};

// Taproot around a musig2(user,server) internal key with 1 or 2 script leaves
// (two leaves sit at depth 1, mirroring bark's TaprootBuilder usage).
// Returns everything both tx-building and signing need.
export function taprootFromLeaves(userPub, serverPub, leafScripts) {
  const { sortedKeys, internalXOnly } = musigInternalKey([userPub, serverPub]);
  const leafHashes = leafScripts.map(tapLeafHash);
  const merkleRoot = leafHashes.length === 1 ? leafHashes[0] : tapBranch(leafHashes[0], leafHashes[1]);
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

export const taprootOneLeaf = (userPub, serverPub, leafScript) =>
  taprootFromLeaves(userPub, serverPub, [leafScript]);

// PubkeyVtxoPolicy: keyspend musig(user,server); leaf = delayed_sign(exit_delta, user).
// leafScript is returned so a unilateral exit can claim through it after the CSV.
export const pubkeyPolicyTaproot = (userPub, serverPub, exitDelta) => {
  const leafScript = delayedSignScript(exitDelta, xonly(userPub));
  return { ...taprootOneLeaf(userPub, serverPub, leafScript), leafScript };
};

// CheckpointVtxoPolicy: keyspend musig(user,server); leaf = timelock_sign(expiry, server)
export const checkpointPolicyTaproot = (userPub, serverPub, expiryHeight) =>
  taprootOneLeaf(userPub, serverPub, timelockSignScript(expiryHeight, xonly(serverPub)));

// Taproot for any user-facing VTXO policy (mirror of bark's VtxoPolicy::taproot).
// policy fields may be hex strings (decoded form) or byte arrays.
export function policyTaproot(policy, serverPub, exitDelta) {
  const user = asBytes(policy.userPubkey);
  if (policy.type === 'pubkey') return pubkeyPolicyTaproot(user, serverPub, exitDelta);
  // The bare types are the 0.6.0 (pver 5) policies whose hashlock leaves
  // check the preimage size; _v0 keeps building the legacy scripts so vtxos
  // minted before the upgrade still reconstruct, sign, and exit correctly.
  if (policy.type === 'serverHtlcSend' || policy.type === 'serverHtlcSend_v0') {
    const hashDelay = policy.type === 'serverHtlcSend' ? hashDelaySignScriptV1 : hashDelaySignScript;
    const hash = asBytes(policy.paymentHash);
    // leaf 1: server spends with preimage after exit_delta
    // leaf 2: user refund after htlc expiry + 2*exit_delta delay
    const serverClaim = hashDelay(hash, exitDelta, xonly(serverPub));
    const userRefund = delayTimelockSignScript(policy.htlcExpiry, 2 * exitDelta, xonly(user));
    return { ...taprootFromLeaves(user, serverPub, [serverClaim, userRefund]), serverClaim, userRefund };
  }
  if (policy.type === 'serverHtlcRecv' || policy.type === 'serverHtlcRecv_v0') {
    const hashDelay = policy.type === 'serverHtlcRecv' ? hashDelaySignScriptV1 : hashDelaySignScript;
    const hash = asBytes(policy.paymentHash);
    // leaf 1: server reclaim after htlc expiry + exit_delta delay
    // leaf 2: user spends with preimage after htlc_expiry_delta + exit_delta
    const serverRefund = delayTimelockSignScript(policy.htlcExpiry, exitDelta, xonly(serverPub));
    const userClaim = hashDelay(hash, policy.htlcExpiryDelta + exitDelta, xonly(user));
    return { ...taprootFromLeaves(user, serverPub, [serverRefund, userClaim]), serverRefund, userClaim };
  }
  throw new Error('unsupported vtxo policy type ' + policy.type);
}

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

// Serialize any user-facing VtxoPolicy (mirror of proto.js decodePolicy).
export function encodePolicy(p) {
  const user = asBytes(p.userPubkey);
  if (p.type === 'pubkey') return encodePubkeyPolicy(user);
  if (p.type === 'serverHtlcSend') {
    return concatBytes(Uint8Array.of(0x09), user, asBytes(p.paymentHash), u32le(p.htlcExpiry));
  }
  if (p.type === 'serverHtlcRecv') {
    return concatBytes(Uint8Array.of(0x08), user, asBytes(p.paymentHash),
      u32le(p.htlcExpiry), u16le(p.htlcExpiryDelta));
  }
  if (p.type === 'serverHtlcSend_v0') {
    return concatBytes(Uint8Array.of(0x01), user, asBytes(p.paymentHash), u32le(p.htlcExpiry));
  }
  if (p.type === 'serverHtlcRecv_v0') {
    return concatBytes(Uint8Array.of(0x02), user, asBytes(p.paymentHash),
      u32le(p.htlcExpiry), u16le(p.htlcExpiryDelta));
  }
  throw new Error('unsupported vtxo policy type ' + p.type);
}

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

const DUST_SAT = 330; // P2TR dust threshold

// Mirror of bark's ArkoorBuilder::new_isolate_dust: the server rejects an
// arkoor whose outputs mix dust and non-dust, so dust outputs are routed
// through a combined isolation output (spent by a fanout tx). When the dust
// alone can't reach the threshold, a non-dust output is split to pad it.
function isolateDust(outputs) {
  const sum = (l) => l.reduce((n, o) => n + o.amountSat, 0);
  const dust = outputs.filter((o) => o.amountSat < DUST_SAT);
  const nonDust = outputs.filter((o) => o.amountSat >= DUST_SAT);
  if (!dust.length || !nonDust.length) return { outs: outputs, isolated: [] };
  if (sum(dust) >= DUST_SAT) return { outs: nonDust, isolated: dust };
  // if breaking a vtxo would just create more dust, accept the mix
  if (sum(nonDust) < 2 * DUST_SAT) return { outs: outputs, isolated: [] };
  const deficit = DUST_SAT - sum(dust);
  const idx = nonDust.findIndex((o) => o.amountSat - deficit >= DUST_SAT);
  if (idx < 0) return { outs: [...nonDust, ...dust], isolated: [] };
  const outs = nonDust.slice();
  outs[idx] = { amountSat: outs[idx].amountSat - deficit, policy: outs[idx].policy };
  return { outs, isolated: [{ amountSat: deficit, policy: nonDust[idx].policy }, ...dust] };
}

// Build everything for a checkpointed single-input arkoor send.
// input: decoded vtxo (from decodeVtxo, with _raw), owned by keys.vtxo
// outputs: [{ amountSat, userPubkey (33B) }...] or [{ amountSat, policy }...]
// — destination first, change last. NB an output may come back SPLIT across
// two result vtxos (dust padding), so callers should consume
// buildAllSignedVtxos() and classify by policy rather than by index.
export function buildArkoorSend({ input, outputs, serverPubkey, vtxoKeys }) {
  const userPub = vtxoKeys.pubkey;
  if (hex.encode(userPub) !== policyOwnerPubkey(input.policy)) throw new Error('input not owned by our key');

  // normalize plain-pubkey outputs to policy form, then split off dust
  const normalized = outputs.map((o) => ({
    amountSat: o.amountSat,
    policy: o.policy || { type: 'pubkey', userPubkey: hex.encode(o.userPubkey) },
  }));
  const { outs, isolated } = isolateDust(normalized);
  const isolationSat = isolated.reduce((n, o) => n + o.amountSat, 0);

  const inputTaproot = policyTaproot(input.policy, serverPubkey, input.exitDelta);
  const checkpointTaproot = checkpointPolicyTaproot(userPub, serverPubkey, input.expiryHeight);

  // checkpoint tx: spends the input vtxo, one output per destination plus the
  // combined dust isolation output (all with the checkpoint policy spk) + P2A
  const checkpointTx = {
    version: 3, locktime: 0,
    inputs: [{ prevout: input.point.raw, sequence: 0 }],
    outputs: [
      ...outs.map((o) => ({ valueSat: o.amountSat, scriptPubKey: checkpointTaproot.scriptPubKey })),
      ...(isolated.length ? [{ valueSat: isolationSat, scriptPubKey: checkpointTaproot.scriptPubKey }] : []),
      { valueSat: 0, scriptPubKey: P2A_SCRIPT },
    ],
  };
  const checkpointTxid = txid(checkpointTx);

  // one arkoor tx per non-dust output, spending checkpoint:vout
  const arkoorTxs = outs.map((o, vout) => {
    const destTaproot = policyTaproot(o.policy, serverPubkey, input.exitDelta);
    return {
      version: 3, locktime: 0,
      inputs: [{ prevout: outpointBytes(checkpointTxid, vout), sequence: 0 }],
      outputs: [
        { valueSat: o.amountSat, scriptPubKey: destTaproot.scriptPubKey },
        { valueSat: 0, scriptPubKey: P2A_SCRIPT },
      ],
    };
  });

  // fanout tx: spends the isolation output, one output per isolated dest
  const fanoutTx = isolated.length ? {
    version: 3, locktime: 0,
    inputs: [{ prevout: outpointBytes(checkpointTxid, outs.length), sequence: 0 }],
    outputs: [
      ...isolated.map((o) => ({
        valueSat: o.amountSat,
        scriptPubKey: policyTaproot(o.policy, serverPubkey, input.exitDelta).scriptPubKey,
      })),
      { valueSat: 0, scriptPubKey: P2A_SCRIPT },
    ],
  } : null;

  // sighashes: [checkpoint spend of input, arkoor_i of checkpoint:i, fanout?]
  const inputPrevout = { valueSat: input.amountSat, scriptPubKey: inputTaproot.scriptPubKey };
  const sighashes = [
    taprootSighash(checkpointTx, [inputPrevout]),
    ...arkoorTxs.map((tx, i) => taprootSighash(tx, [checkpointTx.outputs[i]])),
    ...(fanoutTx ? [taprootSighash(fanoutTx, [checkpointTx.outputs[outs.length]])] : []),
  ];
  // taptweaks per signature (bark: taptweak_at) — everything after the input
  // spends a checkpoint-policy output
  const tweaks = [inputTaproot.tapTweak, ...sighashes.slice(1).map(() => checkpointTaproot.tapTweak)];

  return {
    outputs: outs, isolated, checkpointTx, checkpointTxid, arkoorTxs, fanoutTx,
    sighashes, tweaks, inputTaproot, checkpointTaproot,
  };
}

// "arkoor cosign attestation       " — 32-byte prefix
const ATTESTATION_PREFIX = te.encode('arkoor cosign attestation       ');

// outputs here = regular outputs followed by isolated outputs (bark's
// all_outputs() order)
export function cosignAttestation(inputVtxoIdRaw, outputs, vtxoPrivkey) {
  const msg = sha256(concatBytes(
    ATTESTATION_PREFIX,
    inputVtxoIdRaw,
    u32le(outputs.length),
    ...outputs.flatMap((o) => [u64le(o.amountSat), encodePolicy(o.policy)]),
  ));
  return schnorr.sign(msg, vtxoPrivkey);
}

// One musig2 nonce per sighash, bound to it.
export const genUserNonces = (build, vtxoKeys) =>
  build.sighashes.map((sh) => musig2.nonceGen(vtxoKeys.pubkey, vtxoKeys.privkey, undefined, sh));

// Serialize one ArkoorCosignRequest part for a built arkoor spend.
// `preimage` (32B) is required when the input carries an HTLC policy and the
// claimer is claiming it; omitting it restricts the spend to a full refund.
export function cosignPartBytes({ build, input, vtxoKeys, nonces, preimage }) {
  const destBytes = (o) => {
    const dest = pbWriter();
    dest.varintField(1, o.amountSat);
    dest.bytesField(2, encodePolicy(o.policy));
    return dest.finish();
  };
  const part = pbWriter();
  part.bytesField(1, input.point.raw); // vtxo id = outpoint bytes
  for (const o of build.outputs) part.bytesField(2, destBytes(o));
  for (const n of nonces) part.bytesField(3, n.public);
  for (const o of build.isolated) part.bytesField(4, destBytes(o)); // dust isolation
  part.varintField(5, 1); // use_checkpoint = true
  part.bytesField(6, cosignAttestation(
    input.point.raw, [...build.outputs, ...build.isolated], vtxoKeys.privkey));
  if (preimage) part.bytesField(7, asBytes(preimage));
  return part.finish();
}

// Parse an ArkoorPackageCosignResponse into per-part nonce/partial lists.
export function parsePackageCosignResponse(respBytes) {
  const parts = [];
  for (const { field, value } of pbFields(respBytes)) {
    if (field !== 1) continue;
    const p = { serverNonces: [], serverPartials: [] };
    for (const f of pbFields(value)) {
      if (f.field === 1) p.serverNonces.push(f.value);
      if (f.field === 2) p.serverPartials.push(f.value);
    }
    parts.push(p);
  }
  return parts;
}

// Combine our partials with the server's into final schnorr signatures,
// verifying the server partial and the combined signature along the way.
export function combineCosign({ build, nonces, serverResp, vtxoKeys, serverPubkey }) {
  const nSigs = build.sighashes.length;
  const { serverNonces, serverPartials } = serverResp;
  if (serverNonces.length !== nSigs || serverPartials.length !== nSigs) {
    throw new Error(`bad cosign response: ${serverNonces.length} nonces, ${serverPartials.length} partials, wanted ${nSigs}`);
  }
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

// full MuSig2 ceremony over the ASP's RequestArkoorCosign
export async function cosignWithServer(ark, build, { input, vtxoKeys, serverPubkey, preimage }) {
  const nonces = genUserNonces(build, vtxoKeys);
  const req = pbWriter();
  req.bytesField(1, cosignPartBytes({ build, input, vtxoKeys, nonces, preimage }));
  const respBytes = await grpcCall(ark, 'bark_server.ArkService/RequestArkoorCosign', req.finish());
  const [serverResp] = parsePackageCosignResponse(respBytes);
  if (!serverResp) throw new Error('empty cosign response');
  return combineCosign({ build, nonces, serverResp, vtxoKeys, serverPubkey });
}

// assemble the final signed Vtxo<Full> bytes for output `idx`, where idx
// indexes [regular outputs..., isolated outputs...]
export function buildSignedVtxoBytes({ input, build, finalSigs, serverPubkey, idx }) {
  const isP2a = (out) => hex.encode(out.scriptPubKey) === hex.encode(P2A_SCRIPT);
  const cosigners = [Uint8Array.from(hex.decode(policyOwnerPubkey(input.policy)))];
  const raw = input._raw;
  const finish = (o, items, pointRaw) => encodeVtxo({
    amountSat: o.amountSat,
    expiryHeight: input.expiryHeight,
    serverPubkey,
    exitDelta: input.exitDelta,
    anchorPointRaw: input.anchorPoint.raw,
    inputGenesisRaw: raw.bytes.slice(raw.itemsStart, raw.itemsEnd),
    inputGenesisCount: raw.nItems,
    newItems: items,
    policyBytes: encodePolicy(o.policy),
    pointRaw,
  });

  // NB nb_outputs on the wire counts own output + other_outputs — the P2A
  // fee anchor is excluded (bark: other_outputs.len() + 1).
  if (idx < build.outputs.length) {
    // regular output: input -> checkpoint (own vout idx) -> arkoor
    const o = build.outputs[idx];
    const checkpointOthers = build.checkpointTx.outputs.filter((out, i) => i !== idx && !isP2a(out));
    const checkpointItem = encodeGenesisItem({
      transition: encodeArkoorTransition({
        cosigners, tapTweak: build.inputTaproot.tapTweak, signature: finalSigs[0],
      }),
      nbOutputs: checkpointOthers.length + 1,
      outputIdx: idx,
      otherOutputs: checkpointOthers,
      feeSat: 0,
    });
    const arkoorItem = encodeGenesisItem({
      transition: encodeArkoorTransition({
        cosigners, tapTweak: build.checkpointTaproot.tapTweak, signature: finalSigs[1 + idx],
      }),
      nbOutputs: 1,
      outputIdx: 0,
      otherOutputs: [],
      feeSat: 0,
    });
    return finish(o, [checkpointItem, arkoorItem], outpointBytes(txid(build.arkoorTxs[idx]), 0));
  }

  // isolated output: input -> checkpoint (isolation vout) -> fanout (own vout)
  const j = idx - build.outputs.length;
  const o = build.isolated[j];
  const isolationIdx = build.outputs.length;
  const fanoutSigIdx = 1 + build.outputs.length;
  const checkpointOthers = build.checkpointTx.outputs.filter((out, i) => i !== isolationIdx && !isP2a(out));
  const checkpointItem = encodeGenesisItem({
    transition: encodeArkoorTransition({
      cosigners, tapTweak: build.inputTaproot.tapTweak, signature: finalSigs[0],
    }),
    nbOutputs: checkpointOthers.length + 1,
    outputIdx: isolationIdx,
    otherOutputs: checkpointOthers,
    feeSat: 0,
  });
  const fanoutOthers = build.fanoutTx.outputs.filter((out, i) => i !== j && !isP2a(out));
  const fanoutItem = encodeGenesisItem({
    transition: encodeArkoorTransition({
      cosigners, tapTweak: build.checkpointTaproot.tapTweak, signature: finalSigs[fanoutSigIdx],
    }),
    nbOutputs: fanoutOthers.length + 1,
    outputIdx: j,
    otherOutputs: fanoutOthers,
    feeSat: 0,
  });
  return finish(o, [checkpointItem, fanoutItem], outpointBytes(txid(build.fanoutTx), j));
}

// All result vtxos of an arkoor build (regular then isolated), signed.
export function buildAllSignedVtxos({ input, build, finalSigs, serverPubkey }) {
  const n = build.outputs.length + build.isolated.length;
  return Array.from({ length: n }, (_, idx) =>
    buildSignedVtxoBytes({ input, build, finalSigs, serverPubkey, idx }));
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

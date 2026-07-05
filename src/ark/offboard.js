// Collaborative offboard — move whole VTXOs back to an on-chain output with
// the server's cooperation. Two RPCs: PrepareOffboard (server builds the
// on-chain tx and sends forfeit cosign nonces) and FinishOffboard (we
// countersign a musig forfeit per input; server returns the fully-signed tx
// for us to broadcast). Mirrors bark lib/src/offboard.rs.
//
// The fee math must match the server BIT FOR BIT: captaind recomputes the fee
// and rejects the request unless net_amount == gross - fee exactly
// (server/src/offboards.rs). Rounding mirrors rust-bitcoin 0.32 + bark:
// weight fee rounds up ((rate*wu + 999) / 1000), ppm fees round down.

import { hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import * as musig2 from '@scure/btc-signer/musig2';

import { concatBytes, grpcCall, pbWriter, pbFields } from './proto.js';
import { P2A_SCRIPT, pubkeyPolicyTaproot, taprootSighash, txid } from './send.js';

const te = new TextEncoder();
export const P2TR_DUST = 330;
const OFFBOARD_VOUT = 0;
const CONNECTOR_VOUT = 1;

const u32le = (n) => Uint8Array.of(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff);
const u64le = (n) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
};
const varint = (n) => {
  if (n < 0xfd) return Uint8Array.of(n);
  throw new Error('script longer than 252 bytes not supported');
};
const taggedHash = (tag, ...data) => {
  const th = sha256(te.encode(tag));
  return sha256(concatBytes(th, th, ...data));
};

// ScriptBuf::new_p2tr(key, None): x-only key tweaked by H_TapTweak(key), no
// script tree — the forfeit tx pays the server this way.
export function bareP2tr(pub33) {
  const x = pub33.slice(1);
  const tweak = taggedHash('TapTweak', x);
  const P = secp256k1.ProjectivePoint;
  const out = P.fromHex(concatBytes(Uint8Array.of(0x02), x))
    .add(P.BASE.multiply(BigInt('0x' + hex.encode(tweak))));
  return concatBytes(hex.decode('5120'), out.toRawBytes(true).slice(1));
}

// Current offboard fee rate in sat/kvB.
export async function getOffboardFeeRate(ark) {
  const data = await grpcCall(ark, 'bark_server.ArkService/GetOffboardFeeRate', new Uint8Array(0));
  for (const { field, value } of pbFields(data)) if (field === 1) return Number(value);
  return 0;
}

// bark: FeeRate::from_sat_per_kwu(sat_vkb / 4)
export const feeRateKwu = (satVkb) => Math.floor(satVkb / 4);

// OffboardFees::calculate — base + ceil(rate * weight) + per-vtxo ppm-by-expiry.
// inputs: [{ amountSat, expiryHeight }]; fees: info.offboardFees.
export function offboardFee({ spkLen, satVkb, fees, tip, inputs }) {
  const wu = (fees.fixedAdditionalVb + spkLen) * 4;
  const weightFee = Math.floor((feeRateKwu(satVkb) * wu + 999) / 1000);
  let ppmFee = 0;
  for (const v of inputs) {
    const blocks = Math.max(0, v.expiryHeight - tip);
    const entry = [...fees.ppmExpiryTable].reverse().find((e) => blocks >= e.thresholdBlocks);
    if (entry) ppmFee += Math.floor((v.amountSat * entry.ppm) / 1_000_000);
  }
  return fees.baseFeeSat + weightFee + ppmFee;
}

// OffboardRequestAttestation: BIP340 signature over
// sha256(prefix32 || txout(net, spk) || u32le(n) || vtxo ids), per input key.
const OFFBOARD_ATT_PREFIX = te.encode('Ark offboard request challenge  '); // 32 bytes

export function offboardAttestation({ netSat, spk, inputIdRaws }, privkey) {
  const msg = sha256(concatBytes(
    OFFBOARD_ATT_PREFIX,
    u64le(netSat), varint(spk.length), spk,
    u32le(inputIdRaws.length),
    ...inputIdRaws,
  ));
  return schnorr.sign(msg, privkey);
}

export async function prepareOffboard(ark, { netSat, spk, rateKwu, inputIdRaws, attestations }) {
  const req = pbWriter();
  req.varintField(1, netSat);
  req.bytesField(2, spk);
  req.varintField(3, 1); // deduct_fees_from_gross_amount
  req.varintField(5, rateKwu);
  const w = pbWriter();
  w.bytesField(1, req.finish());
  for (const id of inputIdRaws) w.bytesField(2, id);
  for (const a of attestations) w.bytesField(3, a);
  const data = await grpcCall(ark, 'bark_server.ArkService/PrepareOffboard', w.finish());
  let txBytes = null;
  const serverNonces = [];
  for (const { field, value } of pbFields(data)) {
    if (field === 1) txBytes = value;
    if (field === 2) serverNonces.push(value);
  }
  if (!txBytes || serverNonces.length !== inputIdRaws.length) {
    throw new Error('malformed PrepareOffboard response');
  }
  return { txBytes, serverNonces };
}

// The user-side checks from OffboardForfeitContext::validate_offboard_tx.
export function validateOffboardTx(parsed, { netSat, spk, nInputs }) {
  const out = parsed.outputs[OFFBOARD_VOUT];
  if (!out || out.valueSat !== netSat || hex.encode(out.scriptPubKey) !== hex.encode(spk)) {
    throw new Error('offboard tx output does not match request');
  }
  const conn = parsed.outputs[CONNECTOR_VOUT];
  if (!conn || conn.valueSat !== P2TR_DUST * nInputs) {
    throw new Error('offboard tx has insufficient connector value');
  }
}

// Sign one forfeit per input. Each forfeit spends [vtxo, connector] and pays
// vtxo.amount + dust to the server's bare key. With >1 input the connectors
// come from a deterministic fanout tx that splits the offboard tx's single
// connector output into one dust output per input.
export function signOffboardForfeits({ inputs, keys, serverPub, parsed, serverNonces }) {
  const offTxidInternal = hex.decode(parsed.txid).reverse();
  const connSpk = parsed.outputs[CONNECTOR_VOUT].scriptPubKey;
  const outpoint = (txidInt, vout) => concatBytes(txidInt, u32le(vout));

  let connectors;
  if (inputs.length === 1) {
    connectors = [{ raw: outpoint(offTxidInternal, CONNECTOR_VOUT), txout: parsed.outputs[CONNECTOR_VOUT] }];
  } else {
    const fanout = {
      version: 3, locktime: 0,
      inputs: [{ prevout: outpoint(offTxidInternal, CONNECTOR_VOUT), sequence: 0xffffffff }],
      outputs: [
        ...inputs.map(() => ({ valueSat: P2TR_DUST, scriptPubKey: connSpk })),
        { valueSat: 0, scriptPubKey: P2A_SCRIPT },
      ],
    };
    const fanTxid = txid(fanout);
    // The forfeits spend the fanout's outputs (one dust each) — the sighash
    // commits to prevout values, so it must be the per-output dust, not the
    // combined connector sum.
    connectors = inputs.map((_, i) => ({
      raw: outpoint(fanTxid, i),
      txout: { valueSat: P2TR_DUST, scriptPubKey: connSpk },
    }));
  }

  const pubNonces = [];
  const partials = [];
  inputs.forEach((input, i) => {
    const k = keys[i];
    const tap = pubkeyPolicyTaproot(k.pubkey, serverPub, input.exitDelta);
    const forfeitTx = {
      version: 3, locktime: 0,
      inputs: [
        { prevout: input.point.raw, sequence: 0xffffffff },
        { prevout: connectors[i].raw, sequence: 0xffffffff },
      ],
      outputs: [
        { valueSat: input.amountSat + P2TR_DUST, scriptPubKey: bareP2tr(serverPub) },
        { valueSat: 0, scriptPubKey: P2A_SCRIPT },
      ],
    };
    const prevouts = [
      { valueSat: input.amountSat, scriptPubKey: tap.scriptPubKey },
      connectors[i].txout,
    ];
    const sighash = taprootSighash(forfeitTx, prevouts);
    const nonces = musig2.nonceGen(k.pubkey, k.privkey, undefined, sighash);
    const aggNonce = musig2.nonceAggregate([nonces.public, serverNonces[i]]);
    const session = new musig2.Session(aggNonce, tap.sortedKeys, sighash, [tap.tapTweak], [true]);
    partials.push(session.sign(nonces.secret, k.privkey));
    pubNonces.push(nonces.public);
  });
  return { pubNonces, partials, offboardTxidInternal: offTxidInternal };
}

export async function finishOffboard(ark, { offboardTxidInternal, pubNonces, partials }) {
  const w = pbWriter();
  w.bytesField(1, offboardTxidInternal);
  for (const n of pubNonces) w.bytesField(2, n);
  for (const p of partials) w.bytesField(3, p);
  const data = await grpcCall(ark, 'bark_server.ArkService/FinishOffboard', w.finish());
  for (const { field, value } of pbFields(data)) if (field === 1) return value;
  throw new Error('no signed offboard tx in response');
}

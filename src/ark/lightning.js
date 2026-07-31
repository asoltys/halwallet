// Native-JS Ark <-> Lightning via the ASP (captaind's built-in submarine-swap
// flows): bolt11 decoding, the lightning fee schedules, and the gRPC-web
// wrappers for the pay (HTLC-out) and receive (HTLC-in) protocols.
//
// Mirrors bark's bark/src/actions/lightning/{pay,receive}.rs and
// server-rpc/protos/bark_server.proto. The ASP is the HTLC counterparty:
// paying converts pubkey vtxos into ServerHtlcSend vtxos the server can only
// claim by revealing the invoice preimage; receiving grants ServerHtlcRecv
// vtxos we claim by revealing our preimage. Worst case either side falls back
// to a unilateral on-chain exit — same trust class as a Boltz submarine swap.

import { bech32, hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';
import { schnorr } from '@noble/curves/secp256k1';

import { concatBytes, grpcCall, pbWriter, pbFields } from './proto.js';
import { parsePackageCosignResponse } from './send.js';

const te = new TextEncoder();
const td = new TextDecoder();

// ---------------------------------------------------------------------------
// bolt11 (decode only: payment hash, amount, expiry, network)
// ---------------------------------------------------------------------------

function convertBits(data, from, to) {
  let acc = 0, bits = 0; const out = []; const maxv = (1 << to) - 1;
  for (const v of data) { acc = (acc << from) | v; bits += from; while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); } }
  return Uint8Array.from(out);
}

export function decodeBolt11(invoice) {
  const inv = String(invoice || '').trim().toLowerCase().replace(/^lightning:/, '');
  const dec = bech32.decode(inv, 4000);
  const m = dec.prefix.match(/^ln(bcrt|bc|tbs|tb)(\d+)?([munp])?$/);
  if (!m) throw new Error('not a bolt11 invoice');
  const network = { bc: 'mainnet', tb: 'testnet', tbs: 'signet', bcrt: 'regtest' }[m[1]];
  let amountMsat = null;
  if (m[2]) {
    const n = BigInt(m[2]);
    amountMsat = m[3] === 'p' ? n / 10n : n * ({ m: 100000000n, u: 100000n, n: 100n }[m[3]] ?? 100000000000n);
  }
  const words = dec.words;
  let ts = 0;
  for (let i = 0; i < 7; i++) ts = ts * 32 + words[i];
  let payHash = null, expiry = 3600;
  const end = words.length - 104; // last 104 words = signature
  for (let i = 7; i + 3 <= end;) {
    const type = words[i];
    const len = (words[i + 1] << 5) | words[i + 2];
    const data = words.slice(i + 3, i + 3 + len);
    if (type === 1 && len === 52) payHash = convertBits(data, 5, 8).slice(0, 32);
    if (type === 6) { expiry = 0; for (const w of data) expiry = expiry * 32 + w; }
    i += 3 + len;
  }
  if (!payHash) throw new Error('invoice missing payment hash');
  return {
    network,
    paymentHash: hex.encode(payHash),
    amountMsat,
    amountSat: amountMsat != null ? Number(amountMsat / 1000n) : null,
    expiresAt: (ts + expiry) * 1000,
  };
}

// Decoded invoice or null — the "is this a bolt11?" test.
export function maybeBolt11(text) {
  try { return decodeBolt11(text); } catch { return null; }
}

// ---------------------------------------------------------------------------
// fee schedules (ArkInfo.fees.lightning_send / lightning_receive)
// ---------------------------------------------------------------------------

// Send fee: base + ppm on the paid amount, ppm entry picked per input vtxo by
// its blocks-to-expiry (ascending table, last entry <= blocks wins), floored
// at min. Rounded up — never undershoots what the server will charge.
export function lnSendFee(amountSat, fees, inputs, tip) {
  let remaining = amountSat;
  let ppmMicro = 0n;
  for (const v of inputs) {
    const charge = Math.min(v.amountSat, remaining);
    remaining -= charge;
    const blocks = v.expiryHeight - tip;
    const entry = (fees.ppmExpiryTable || []).filter((e) => blocks >= e.thresholdBlocks).pop();
    if (entry) ppmMicro += BigInt(charge) * BigInt(entry.ppm);
  }
  const ppmFee = Number((ppmMicro + 999_999n) / 1_000_000n);
  return Math.max(fees.minFeeSat || 0, (fees.baseFeeSat || 0) + ppmFee);
}

export const lnReceiveFee = (amountSat, fees) =>
  (fees.baseFeeSat || 0) + Math.ceil((amountSat * (fees.ppm || 0)) / 1_000_000);

// ---------------------------------------------------------------------------
// pay (HTLC-out)
// ---------------------------------------------------------------------------

// Cosign the conversion of input vtxos into ServerHtlcSend vtxos.
// parts: serialized ArkoorCosignRequest messages (send.js cosignPartBytes).
export async function requestLightningPayHtlcCosign(ark, parts) {
  const req = pbWriter();
  for (const p of parts) req.bytesField(2, p); // LightningPayHtlcCosignRequest.parts = 2
  const resp = await grpcCall(ark, 'bark_server.ArkService/RequestLightningPayHtlcCosign', req.finish());
  return parsePackageCosignResponse(resp);
}

export async function initiateLightningPayment(ark, { invoice, htlcVtxoIdRaws, amountSat, mailboxPubkey }) {
  const w = pbWriter();
  w.stringField(1, invoice);
  for (const id of htlcVtxoIdRaws) w.bytesField(2, id);
  w.varintField(3, amountSat);
  if (mailboxPubkey) w.bytesField(4, mailboxPubkey);
  await grpcCall(ark, 'bark_server.ArkService/InitiateLightningPayment', w.finish());
}

// -> { status: 'pending'|'success'|'failed', preimage? (hex) }
export async function checkLightningPayment(ark, paymentHash, wait = false) {
  const w = pbWriter();
  w.bytesField(1, paymentHash);
  if (wait) w.varintField(2, 1);
  const data = await grpcCall(ark, 'bark_server.ArkService/CheckLightningPayment', w.finish());
  for (const { field, value } of pbFields(data)) {
    if (field === 2) {
      let preimage = null;
      for (const f of pbFields(value)) if (f.field === 1) preimage = hex.encode(f.value);
      return { status: 'success', preimage };
    }
    if (field === 3) return { status: 'failed' };
  }
  return { status: 'pending' };
}

// Cosign the revocation of failed-payment HTLC vtxos back to a pubkey policy.
export async function requestLightningPayHtlcRevocation(ark, parts) {
  const req = pbWriter();
  for (const p of parts) req.bytesField(1, p); // ArkoorPackageCosignRequest.parts = 1
  const resp = await grpcCall(ark, 'bark_server.ArkService/RequestLightningPayHtlcRevocation', req.finish());
  return parsePackageCosignResponse(resp);
}

// ---------------------------------------------------------------------------
// receive (HTLC-in)
// ---------------------------------------------------------------------------

export const LN_RECV_STATUS = ['created', 'accepted', 'htlcsReady', 'settled', 'canceled'];

export async function startLightningReceive(ark, { paymentHash, amountSat, minCltvDelta, mailboxPubkey, description }) {
  const w = pbWriter();
  w.bytesField(1, paymentHash);
  w.varintField(2, amountSat);
  w.varintField(3, minCltvDelta);
  if (mailboxPubkey) w.bytesField(4, mailboxPubkey);
  if (description) w.stringField(5, description);
  const data = await grpcCall(ark, 'bark_server.ArkService/StartLightningReceive', w.finish());
  for (const { field, value } of pbFields(data)) if (field === 1) return td.decode(value);
  throw new Error('server returned no invoice');
}

function decodeReceiveStatus(value) {
  const out = { invoice: null, amountSat: 0, status: 'created', htlcVtxos: [] };
  for (const f of pbFields(value)) {
    if (f.field === 1) out.invoice = td.decode(f.value);
    if (f.field === 2) out.amountSat = Number(f.value);
    if (f.field === 3) out.status = LN_RECV_STATUS[Number(f.value)] || 'created';
    if (f.field === 4) out.htlcVtxos.push(f.value);
  }
  return out;
}

export async function checkLightningReceive(ark, paymentHash) {
  const w = pbWriter();
  w.bytesField(1, paymentHash);
  const data = await grpcCall(ark, 'bark_server.ArkService/CheckLightningReceive', w.finish());
  return decodeReceiveStatus(data);
}

// "Lightning receive VTXO challenge" — 32-byte prefix (anti-DoS ownership proof)
const LN_RECV_ATTESTATION_PREFIX = te.encode('Lightning receive VTXO challenge');

export const lightningReceiveAttestation = (paymentHash, vtxoIdRaw, vtxoPrivkey) =>
  schnorr.sign(sha256(concatBytes(LN_RECV_ATTESTATION_PREFIX, paymentHash, vtxoIdRaw)), vtxoPrivkey);

// antiDos: { vtxoIdRaw, attestation } | { token } | null
export async function prepareLightningReceiveClaim(ark, { paymentHash, userPubkey, htlcRecvExpiry, antiDos }) {
  const w = pbWriter();
  w.bytesField(1, paymentHash);
  w.bytesField(2, userPubkey);
  w.varintField(3, htlcRecvExpiry);
  if (antiDos && antiDos.vtxoIdRaw) {
    const iv = pbWriter();
    iv.bytesField(1, antiDos.vtxoIdRaw);
    iv.bytesField(2, antiDos.attestation);
    w.bytesField(4, iv.finish());
  } else if (antiDos && antiDos.token) {
    w.stringField(5, antiDos.token);
  }
  const data = await grpcCall(ark, 'bark_server.ArkService/PrepareLightningReceiveClaim', w.finish());
  const out = { receive: null, htlcVtxos: [] };
  for (const { field, value } of pbFields(data)) {
    if (field === 1) out.receive = decodeReceiveStatus(value);
    if (field === 2) out.htlcVtxos.push(value);
  }
  return out;
}

// Reveal the preimage in exchange for a cosigned claim of the HTLC vtxos.
// parts: serialized ArkoorCosignRequest messages. Idempotent server-side.
export async function claimLightningReceive(ark, { paymentHash, preimage, parts }) {
  const pkg = pbWriter();
  for (const p of parts) pkg.bytesField(1, p);
  const w = pbWriter();
  w.bytesField(1, paymentHash);
  w.bytesField(2, preimage);
  w.bytesField(4, pkg.finish());
  const resp = await grpcCall(ark, 'bark_server.ArkService/ClaimLightningReceive', w.finish());
  return parsePackageCosignResponse(resp);
}

export async function cancelLightningReceive(ark, paymentHash) {
  const w = pbWriter();
  w.bytesField(1, paymentHash);
  await grpcCall(ark, 'bark_server.ArkService/CancelLightningReceive', w.finish());
}

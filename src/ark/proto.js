// Minimal native-JS Ark (bark/captaind) client primitives — receive-only spike.
//
// Speaks gRPC-web directly to the ASP with hand-rolled protobuf, encodes ark
// addresses, blinds mailbox identifiers, signs mailbox read authorizations,
// and decodes the bark ProtocolEncoding VTXO wire format (version 2).
//
// Wire formats mirrored from github.com/ark-bitcoin/bark:
//   lib/src/address.rs, lib/src/mailbox.rs, lib/src/encode.rs, lib/src/vtxo/mod.rs

import { bech32m, hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';

const te = new TextEncoder();
const td = new TextDecoder();

export const concatBytes = (...arrs) => {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
};

// ---------------------------------------------------------------------------
// protobuf (proto3) mini codec — just what the ark RPCs need
// ---------------------------------------------------------------------------

export function pbWriter() {
  const chunks = [];
  const varint = (n) => {
    n = BigInt(n);
    const bs = [];
    do { let b = Number(n & 0x7fn); n >>= 7n; if (n) b |= 0x80; bs.push(b); } while (n);
    chunks.push(Uint8Array.from(bs));
  };
  return {
    varintField(field, n) { varint((field << 3) | 0); varint(n); },
    bytesField(field, bytes) { varint((field << 3) | 2); varint(bytes.length); chunks.push(bytes); },
    stringField(field, s) { this.bytesField(field, te.encode(s)); },
    finish: () => concatBytes(...chunks),
  };
}

export function* pbFields(buf) {
  let i = 0;
  const varint = () => {
    let v = 0n, s = 0n;
    for (;;) {
      const b = buf[i++];
      v |= BigInt(b & 0x7f) << s;
      if (!(b & 0x80)) return v;
      s += 7n;
    }
  };
  while (i < buf.length) {
    const tag = Number(varint());
    const field = tag >> 3, wire = tag & 7;
    if (wire === 0) yield { field, value: varint() };
    else if (wire === 2) {
      const len = Number(varint());
      yield { field, value: buf.slice(i, i + len) };
      i += len;
    } else if (wire === 5) { yield { field, value: buf.slice(i, i + 4) }; i += 4; }
    else if (wire === 1) { yield { field, value: buf.slice(i, i + 8) }; i += 8; }
    else throw new Error('unsupported protobuf wire type ' + wire);
  }
}

// ---------------------------------------------------------------------------
// gRPC-web transport (unary) — plain fetch, works in any browser
// ---------------------------------------------------------------------------

// Ark protocol version we speak (server advertises min/max in Handshake).
export const PVER = 3;

export class GrpcError extends Error {
  constructor(status, message, method) {
    super(`grpc ${method}: status ${status}${message ? ': ' + message : ''}`);
    this.grpcStatus = status;
  }
}

export async function grpcCall(base, method, reqBytes) {
  const frame = new Uint8Array(5 + reqBytes.length);
  new DataView(frame.buffer).setUint32(1, reqBytes.length);
  frame.set(reqBytes, 5);

  const resp = await fetch(`${base}/${method}`, {
    method: 'POST',
    headers: { 'content-type': 'application/grpc-web+proto', 'x-grpc-web': '1', 'pver': String(PVER) },
    body: frame,
  });
  if (!resp.ok) throw new Error(`${method}: http ${resp.status}`);

  const body = new Uint8Array(await resp.arrayBuffer());
  let i = 0, data = null;
  const trailers = {};
  // headers may carry grpc-status when there is no trailer frame
  for (const [k, v] of resp.headers) trailers[k] = v;
  while (i < body.length) {
    const flag = body[i];
    const len = new DataView(body.buffer, body.byteOffset + i + 1, 4).getUint32(0);
    const payload = body.slice(i + 5, i + 5 + len);
    if (flag & 0x80) {
      for (const line of td.decode(payload).trim().split('\r\n')) {
        const c = line.indexOf(':');
        if (c > 0) trailers[line.slice(0, c).trim()] = line.slice(c + 1).trim();
      }
    } else data = payload;
    i += 5 + len;
  }
  const status = Number(trailers['grpc-status'] ?? 0);
  if (status !== 0) {
    throw new GrpcError(status, decodeURIComponent(trailers['grpc-message'] || ''), method);
  }
  return data ?? new Uint8Array(0);
}

// Server-streaming gRPC-web call: onMessage fires per data frame as it
// arrives; resolves when the stream ends (throws GrpcError on bad status).
export async function grpcStream(base, method, reqBytes, { onMessage, signal }) {
  const frame = new Uint8Array(5 + reqBytes.length);
  new DataView(frame.buffer).setUint32(1, reqBytes.length);
  frame.set(reqBytes, 5);
  const resp = await fetch(`${base}/${method}`, {
    method: 'POST',
    headers: { 'content-type': 'application/grpc-web+proto', 'x-grpc-web': '1', 'pver': String(PVER) },
    body: frame,
    signal,
  });
  if (!resp.ok) throw new Error(`${method}: http ${resp.status}`);
  const reader = resp.body.getReader();
  let buf = new Uint8Array(0);
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf = concatBytes(buf, value);
    for (;;) {
      if (buf.length < 5) break;
      const len = new DataView(buf.buffer, buf.byteOffset + 1, 4).getUint32(0);
      if (buf.length < 5 + len) break;
      const flag = buf[0];
      const payload = buf.slice(5, 5 + len);
      buf = buf.slice(5 + len);
      if (flag & 0x80) {
        const trailers = {};
        for (const line of td.decode(payload).trim().split('\r\n')) {
          const c = line.indexOf(':');
          if (c > 0) trailers[line.slice(0, c).trim()] = line.slice(c + 1).trim();
        }
        const status = Number(trailers['grpc-status'] ?? 0);
        if (status !== 0) throw new GrpcError(status, decodeURIComponent(trailers['grpc-message'] || ''), method);
      } else {
        onMessage(payload);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// byte reader + bitcoin primitives (CompactSize, OutPoint, TxOut)
// ---------------------------------------------------------------------------

export function reader(buf) {
  let i = 0;
  const r = {
    get pos() { return i; },
    get remaining() { return buf.length - i; },
    bytes(n) {
      if (i + n > buf.length) throw new Error('unexpected end of data');
      const b = buf.slice(i, i + n); i += n; return b;
    },
    u8: () => r.bytes(1)[0],
    u16: () => { const b = r.bytes(2); return b[0] | (b[1] << 8); },
    u32: () => { const b = r.bytes(4); return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0; },
    u64: () => { const b = r.bytes(8); let v = 0n; for (let k = 7; k >= 0; k--) v = (v << 8n) | BigInt(b[k]); return v; },
    i64: () => { const v = r.u64(); return v > 0x7fffffffffffffffn ? v - 0x10000000000000000n : v; },
    compactSize() {
      const b = r.u8();
      if (b < 0xfd) return b;
      if (b === 0xfd) return r.u16();
      if (b === 0xfe) return r.u32();
      return Number(r.u64());
    },
    outPoint() {
      const raw = r.bytes(36);
      const txid = raw.slice(0, 32); // internal byte order
      const vout = raw[32] | (raw[33] << 8) | (raw[34] << 16) | (raw[35] << 24);
      return { txid: hex.encode(txid.slice().reverse()), vout, raw };
    },
    txOut() {
      const valueSat = r.u64();
      const script = r.bytes(r.compactSize());
      return { valueSat: Number(valueSat), scriptPubKey: hex.encode(script) };
    },
  };
  return r;
}

export const i64le = (n) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigInt64(0, BigInt(n), true);
  return b;
};

// ---------------------------------------------------------------------------
// ark address (lib/src/address.rs) — bech32m, HRP ark/tark, version 'p'
// ---------------------------------------------------------------------------

const ADDR_VERSION_POLICY = 1; // bech32 char 'p'
const DELIVERY_MAILBOX = 0x01;
const POLICY_PUBKEY = 0x00;
const BECH32_LIMIT = 1023;

const compactSizeBytes = (n) => {
  if (n < 0xfd) return Uint8Array.of(n);
  throw new Error('compact size > 252 not needed here');
};

export const arkIdFromServerPubkey = (serverPubkey /* 33B */) => sha256(serverPubkey).slice(0, 4);

export function encodeAddress({ testnet, serverPubkey, userPubkey, blindedMailboxId }) {
  const policy = concatBytes(Uint8Array.of(POLICY_PUBKEY), userPubkey);
  const delivery = concatBytes(Uint8Array.of(DELIVERY_MAILBOX), blindedMailboxId);
  const payload = concatBytes(
    arkIdFromServerPubkey(serverPubkey),
    compactSizeBytes(policy.length), policy,
    compactSizeBytes(delivery.length), delivery,
  );
  const words = [ADDR_VERSION_POLICY, ...bech32m.toWords(payload)];
  return bech32m.encode(testnet ? 'tark' : 'ark', words, BECH32_LIMIT);
}

export function decodeAddress(addr) {
  const { prefix, words } = bech32m.decode(addr, BECH32_LIMIT);
  if (prefix !== 'ark' && prefix !== 'tark') throw new Error('bad hrp: ' + prefix);
  if (words[0] !== ADDR_VERSION_POLICY) throw new Error('unsupported address version ' + words[0]);
  const payload = bech32m.fromWords(words.slice(1));
  const r = reader(payload);
  const arkId = hex.encode(r.bytes(4));
  const policyBytes = r.bytes(r.compactSize());
  if (policyBytes[0] !== POLICY_PUBKEY) throw new Error('unsupported policy type ' + policyBytes[0]);
  const userPubkey = hex.encode(policyBytes.slice(1, 34));
  const delivery = [];
  while (r.remaining > 0) {
    const d = r.bytes(r.compactSize());
    delivery.push({ type: d[0], data: hex.encode(d.slice(1)) });
  }
  return { testnet: prefix === 'tark', arkId, userPubkey, delivery };
}

// ---------------------------------------------------------------------------
// mailbox (lib/src/mailbox.rs)
// ---------------------------------------------------------------------------

// blinded_id = mailbox_pubkey + ECDH(server_pubkey, vtxo_privkey) as points
export function blindMailboxId(mailboxPubkey, serverPubkey, vtxoPrivkey) {
  const P = secp256k1.ProjectivePoint;
  const dh = P.fromHex(serverPubkey).multiply(secp256k1.utils.normPrivateKeyToScalar(vtxoPrivkey));
  const blinded = P.fromHex(mailboxPubkey).add(dh);
  return blinded.toRawBytes(true);
}

const MAILBOX_AUTH_PREFIX = te.encode('Ark VTXO mailbox authorization: '); // 32 bytes

// serialized MailboxAuthorization: pubkey(33) || expiry i64 LE || schnorr sig(64)
export function mailboxAuthorization(mailboxPrivkey, mailboxPubkey, expiryUnixSec) {
  const msg = sha256(concatBytes(MAILBOX_AUTH_PREFIX, i64le(expiryUnixSec)));
  const sig = schnorr.sign(msg, mailboxPrivkey);
  return concatBytes(mailboxPubkey, i64le(expiryUnixSec), sig);
}

// ---------------------------------------------------------------------------
// VTXO decoding (lib/src/vtxo/mod.rs, ProtocolEncoding version 2)
// ---------------------------------------------------------------------------

const ZERO_SIG = new Uint8Array(64);
const optSignature = (r) => {
  const sig = r.bytes(64);
  return sig.every((b) => b === 0) ? null : hex.encode(sig);
};

function decodeGenesisTransition(r) {
  const type = r.u8();
  if (type === 1) { // Cosigned
    const n = r.compactSize();
    const pubkeys = [];
    for (let k = 0; k < n; k++) pubkeys.push(hex.encode(r.bytes(33)));
    return { type: 'cosigned', pubkeys, signature: optSignature(r) };
  }
  if (type === 2) { // Arkoor
    const n = r.compactSize();
    const clientCosigners = [];
    for (let k = 0; k < n; k++) clientCosigners.push(hex.encode(r.bytes(33)));
    const tapTweak = hex.encode(r.bytes(32));
    return { type: 'arkoor', clientCosigners, tapTweak, signature: optSignature(r) };
  }
  if (type === 3) { // HashLockedCosigned
    const userPubkey = hex.encode(r.bytes(33));
    const signature = optSignature(r);
    const tag = r.u8();
    const unlock = { [tag === 0 ? 'preimage' : 'hash']: hex.encode(r.bytes(32)) };
    return { type: 'hashLockedCosigned', userPubkey, signature, unlock };
  }
  throw new Error('unknown genesis transition type ' + type);
}

function decodePolicy(r) {
  const type = r.u8();
  if (type === 0x00) return { type: 'pubkey', userPubkey: hex.encode(r.bytes(33)) };
  if (type === 0x01) return {
    type: 'serverHtlcSend', userPubkey: hex.encode(r.bytes(33)),
    paymentHash: hex.encode(r.bytes(32)), htlcExpiry: r.u32(),
  };
  if (type === 0x02) return {
    type: 'serverHtlcRecv', userPubkey: hex.encode(r.bytes(33)),
    paymentHash: hex.encode(r.bytes(32)), htlcExpiry: r.u32(), htlcExpiryDelta: r.u16(),
  };
  throw new Error('unknown vtxo policy type ' + type);
}

export function decodeVtxo(bytes) {
  const r = reader(bytes);
  const version = r.u16();
  if (version !== 2) throw new Error('unsupported vtxo encoding version ' + version);
  const amountSat = Number(r.u64());
  const expiryHeight = r.u32();
  const serverPubkey = hex.encode(r.bytes(33));
  const exitDelta = r.u16();
  const anchorPoint = r.outPoint();

  const genesisStart = r.pos; // after this sits compactSize(nItems) + items
  const nItems = r.compactSize();
  const itemsStart = r.pos;
  const genesis = [];
  for (let k = 0; k < nItems; k++) {
    const transition = decodeGenesisTransition(r);
    const nbOutputs = r.u8();
    const outputIdx = r.u8();
    const otherOutputs = [];
    for (let j = 0; j < nbOutputs - 1; j++) otherOutputs.push(r.txOut());
    const feeSat = Number(r.u64());
    genesis.push({ transition, nbOutputs, outputIdx, otherOutputs, feeSat });
  }

  const itemsEnd = r.pos;
  const policy = decodePolicy(r);
  const point = r.outPoint();
  if (r.remaining !== 0) throw new Error(`trailing vtxo bytes: ${r.remaining}`);

  return {
    id: `${point.txid}:${point.vout}`,
    amountSat, expiryHeight, serverPubkey, exitDelta,
    anchorPoint, genesis, policy, point,
    // raw material for re-encoding when this vtxo is used as a spend input
    _raw: { bytes, nItems, itemsStart, itemsEnd, genesisStart },
  };
}

// ---------------------------------------------------------------------------
// RPCs
// ---------------------------------------------------------------------------

export async function getArkInfo(ark) {
  const data = await grpcCall(ark, 'bark_server.ArkService/GetArkInfo', new Uint8Array(0));
  // Fee schedules a server never sends (or sends all-zero) mean "free".
  const info = { boardFees: {}, refreshFees: { baseFeeSat: 0, ppmExpiryTable: [] } };
  for (const { field, value } of pbFields(data)) {
    if (field === 1) info.network = td.decode(value);
    if (field === 2) info.serverPubkey = hex.encode(value);
    if (field === 3) info.roundIntervalSecs = Number(value);
    if (field === 5) info.vtxoExitDelta = Number(value);
    if (field === 6) info.vtxoExpiryDelta = Number(value);
    if (field === 10) info.requiredBoardConfirmations = Number(value);
    if (field === 13) info.minBoardAmountSat = Number(value);
    if (field === 16) info.mailboxPubkey = hex.encode(value);
    if (field === 18) { // FeeSchedule
      for (const f of pbFields(value)) {
        if (f.field === 1) { // board
          const b = {};
          for (const g of pbFields(f.value)) {
            if (g.field === 1) b.minFeeSat = Number(g.value);
            if (g.field === 2) b.baseFeeSat = Number(g.value);
            if (g.field === 3) b.ppm = Number(g.value);
          }
          info.boardFees = b;
        }
        if (f.field === 3) { // refresh
          const rf = { baseFeeSat: 0, ppmExpiryTable: [] };
          for (const g of pbFields(f.value)) {
            if (g.field === 1) rf.baseFeeSat = Number(g.value);
            if (g.field === 2) {
              const e = { thresholdBlocks: 0, ppm: 0 };
              for (const h of pbFields(g.value)) {
                if (h.field === 1) e.thresholdBlocks = Number(h.value);
                if (h.field === 2) e.ppm = Number(h.value);
              }
              rf.ppmExpiryTable.push(e);
            }
          }
          info.refreshFees = rf;
        }
      }
    }
  }
  return info;
}

export async function handshake(ark, version = 'hal-ark-spike/0.0.1') {
  const w = pbWriter();
  w.stringField(1, version);
  const data = await grpcCall(ark, 'bark_server.ArkService/Handshake', w.finish());
  const out = {};
  for (const { field, value } of pbFields(data)) {
    if (field === 1) out.minProtocolVersion = Number(value);
    if (field === 2) out.maxProtocolVersion = Number(value);
    if (field === 3) out.psa = td.decode(value);
  }
  return out;
}

// Read the mailbox; returns { messages: [{checkpoint, vtxos: [decoded]}], haveMore }
export async function readMailbox(ark, mailbox, checkpoint = 0) {
  const data = await grpcCall(ark, 'mailbox_server.MailboxService/ReadMailbox', mailboxRequestBytes(mailbox, checkpoint));

  const messages = [];
  let haveMore = false;
  for (const { field, value } of pbFields(data)) {
    if (field === 2) haveMore = Number(value) !== 0;
    if (field === 1) messages.push(decodeMailboxMessage(value));
  }
  return { messages, haveMore };
}

// Decode one MailboxMessage (also the unit of the SubscribeMailbox stream).
export function decodeMailboxMessage(value) {
  const msg = { checkpoint: 0, vtxos: [], kind: 'other' };
  for (const f of pbFields(value)) {
    if (f.field === 2) msg.checkpoint = Number(f.value);
    if (f.field === 1) { // ArkoorMessage
      msg.kind = 'arkoor';
      for (const a of pbFields(f.value)) {
        if (a.field === 1) msg.vtxos.push(decodeVtxo(a.value));
      }
    }
  }
  return msg;
}

// VtxoSpendState values from GetVtxoStatus (bark_server.proto).
export const VTXO_STATE_SPENDABLE = 1;
export const VTXO_STATE_SPENT = 2;

const VTXO_STATUS_PREFIX = te.encode('Ark VTXO status query challenge '); // 32 bytes

// Ask the server for a vtxo's authoritative spend state. The attestation is a
// BIP340 signature with the vtxo's user key, so only the owner can query.
export async function getVtxoStatus(ark, vtxoIdRaw /* 36B outpoint */, vtxoPrivkey) {
  const attestation = schnorr.sign(sha256(concatBytes(VTXO_STATUS_PREFIX, vtxoIdRaw)), vtxoPrivkey);
  const w = pbWriter();
  w.bytesField(1, vtxoIdRaw);
  w.bytesField(2, attestation);
  const data = await grpcCall(ark, 'bark_server.ArkService/GetVtxoStatus', w.finish());
  for (const { field, value } of pbFields(data)) if (field === 1) return Number(value);
  return 0; // proto3 omits a zero enum: UNSPECIFIED
}

// Build an authenticated MailboxRequest (shared by read + subscribe).
export function mailboxRequestBytes(mailbox, checkpoint = 0) {
  const expiry = Math.floor(Date.now() / 1000) + 60;
  const auth = mailboxAuthorization(mailbox.privkey, mailbox.pubkey, expiry);
  const w = pbWriter();
  w.bytesField(1, mailbox.pubkey);
  w.bytesField(2, auth);
  if (checkpoint) w.varintField(3, checkpoint);
  return w.finish();
}

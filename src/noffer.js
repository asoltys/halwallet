// CLINK offer codes (`noffer1…`) — a static, nostr-native payment code.
// Bech32 over TLV: 0 = service pubkey (32B), 1 = relay url, 2 = offer id,
// 3 = pricing type (2 = payer chooses the amount). A payer decodes this,
// sends a NIP-44-encrypted kind-21001 request to the pubkey via the relay,
// and gets an invoice back — no web server involved.

import { bech32 } from '@scure/base';
import { hex } from '@scure/base';

const te = new TextEncoder();
const td = new TextDecoder();

function tlv(items) {
  const parts = [];
  for (const [type, value] of items) {
    if (value.length > 255) throw new Error('tlv value too long');
    parts.push(new Uint8Array([type, value.length]), value);
  }
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

export function encodeNoffer({ pubkey, relay, offerId, priceType = 2 }) {
  const data = tlv([
    [0, hex.decode(pubkey)],
    [1, te.encode(relay)],
    [2, te.encode(offerId)],
    [3, new Uint8Array([priceType])],
  ]);
  return bech32.encode('noffer', bech32.toWords(data), 2000);
}

export function decodeNoffer(str) {
  const { prefix, words } = bech32.decode(String(str).trim(), 2000);
  if (prefix !== 'noffer') throw new Error('not an offer code');
  const data = bech32.fromWords(words);
  const out = {};
  let off = 0;
  while (off + 2 <= data.length) {
    const type = data[off], len = data[off + 1];
    const value = data.slice(off + 2, off + 2 + len);
    off += 2 + len;
    if (type === 0) out.pubkey = hex.encode(value);
    else if (type === 1) out.relay = td.decode(value);
    else if (type === 2) out.offerId = td.decode(value);
    else if (type === 3) out.priceType = value[0];
    else if (type === 4) out.priceSats = [...value].reduce((n, b) => n * 256 + b, 0);
    else if (type === 5) out.currency = td.decode(value);
  }
  if (!out.pubkey) throw new Error('offer code has no pubkey');
  return out;
}

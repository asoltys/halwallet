// LNURL-pay + NIP-57 ("lightning zap") logic — no DOM, so it stays testable.
//
// The wallet already pays bolt11 invoices over a Boltz submarine swap; this
// module is the missing front half of a zap: turn an npub / lightning address
// / lnurl into a bolt11 to pay, attaching a signed kind-9734 zap request so the
// recipient's LNURL server publishes a public zap receipt (kind 9735).
//
// Flow (NIP-57 appendix): resolve target → GET the LNURL-pay params → build &
// sign a zap request → GET the callback with amount(+nostr) → receive `pr`
// (bolt11) → hand that to the swap engine. The recipient's server is the one
// that broadcasts the receipt; we only sign the request.

import { bech32 } from '@scure/base';
import { parseNostrPubkey } from './nostr.js';

const enc = new TextEncoder();
const dec = new TextDecoder();

// bech32 with a generous limit — LNURLs are long.
export function decodeLnurl(s) {
  const { prefix, words } = bech32.decode(String(s || '').trim().toLowerCase(), 2000);
  if (prefix !== 'lnurl') throw new Error('not an lnurl');
  return dec.decode(new Uint8Array(bech32.fromWords(words)));
}
export function encodeLnurl(url) {
  return bech32.encode('lnurl', bech32.toWords(enc.encode(url)), 2000);
}

const LN_ADDRESS_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
export function isLightningAddress(s) { return LN_ADDRESS_RE.test((s || '').trim()); }

// A lightning address (name@domain) → its LNURL-pay .well-known URL. Onion
// hosts speak http; everything else https.
export function lnAddressToUrl(addr) {
  const [name, domain] = (addr || '').trim().split('@');
  const scheme = /\.onion$/i.test(domain) ? 'http' : 'https';
  return `${scheme}://${domain}/.well-known/lnurlp/${encodeURIComponent(name)}`;
}

// Resolve any zap-able input into { url, lnurlBech32, pk } — pk is the
// recipient's nostr pubkey when we know it (needed to attribute a real zap).
// Returns null if the input isn't a zap target at all.
export function parseZapTarget(input, { pk = null } = {}) {
  const s = (input || '').trim().replace(/^lightning:/i, '');
  if (!s) return null;
  // An npub/hex pubkey — the caller resolves lud16/lud06 from the profile and
  // calls fromProfile() below; here we just report the shape.
  const npk = parseNostrPubkey(s);
  if (npk) return { kind: 'npub', pk: npk };
  if (isLightningAddress(s)) return { kind: 'lnaddr', url: lnAddressToUrl(s), lnurlBech32: safeEncode(lnAddressToUrl(s)), pk };
  if (/^lnurl1[ac-hj-np-z02-9]+$/i.test(s)) {
    try { const url = decodeLnurl(s); return { kind: 'lnurl', url, lnurlBech32: s.toLowerCase(), pk }; } catch { return null; }
  }
  return null;
}

// Build a zap target from a profile's lud16/lud06 (for an npub send).
export function zapTargetFromProfile(profile, pk) {
  if (profile && profile.lud16 && isLightningAddress(profile.lud16)) {
    const url = lnAddressToUrl(profile.lud16);
    return { kind: 'lnaddr', url, lnurlBech32: safeEncode(url), pk, address: profile.lud16 };
  }
  if (profile && profile.lud06) {
    try { const url = decodeLnurl(profile.lud06); return { kind: 'lnurl', url, lnurlBech32: profile.lud06.toLowerCase(), pk }; } catch {}
  }
  return null;
}

function safeEncode(url) { try { return encodeLnurl(url); } catch { return null; } }

async function fetchJson(url, ms = 8000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    const r = await fetch(url, { signal: ctrl.signal, headers: { Accept: 'application/json' } });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return await r.json();
  } finally { clearTimeout(timer); }
}

// GET the LNURL-pay params. Normalizes the bits we use; keeps `callback`.
export async function fetchPayParams(url) {
  const d = await fetchJson(url);
  if (!d || d.tag !== 'payRequest' || !d.callback) {
    if (d && d.status === 'ERROR') throw new Error(d.reason || 'LNURL error');
    throw new Error('not a Lightning pay endpoint');
  }
  return {
    callback: d.callback,
    minSendable: Number(d.minSendable) || 0, // millisats
    maxSendable: Number(d.maxSendable) || 0, // millisats
    commentAllowed: Number(d.commentAllowed) || 0,
    // NIP-57: server publishes a zap receipt when it accepts a zap request.
    allowsNostr: !!d.allowsNostr,
    nostrPubkey: typeof d.nostrPubkey === 'string' ? d.nostrPubkey : null,
    metadata: d.metadata || '',
  };
}

// A signed kind-9734 zap request (NIP-57). signFn(partial) → finalized event.
export function buildZapRequest({ amountMsat, relays, lnurlBech32, recipientPk, eventId, comment, signFn }) {
  const tags = [['relays', ...relays], ['amount', String(amountMsat)], ['p', recipientPk]];
  if (lnurlBech32) tags.push(['lnurl', lnurlBech32]);
  if (eventId) tags.push(['e', eventId]);
  return signFn({ kind: 9734, content: comment || '', tags });
}

// GET the callback for a bolt11. When zapRequest is present this is a real zap;
// otherwise a plain LNURL-pay (comment attached if the server allows one).
export async function requestInvoice(params, { amountMsat, zapRequest = null, lnurlBech32 = null, comment = '' }) {
  const url = new URL(params.callback);
  url.searchParams.set('amount', String(amountMsat));
  if (zapRequest) {
    url.searchParams.set('nostr', JSON.stringify(zapRequest));
    if (lnurlBech32) url.searchParams.set('lnurl', lnurlBech32);
  } else if (comment && params.commentAllowed > 0) {
    url.searchParams.set('comment', comment.slice(0, params.commentAllowed));
  }
  const d = await fetchJson(url.toString());
  if (!d || d.status === 'ERROR') throw new Error((d && d.reason) || 'invoice request failed');
  if (!d.pr || typeof d.pr !== 'string') throw new Error('no invoice returned');
  return d.pr;
}

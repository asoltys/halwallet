// BIP-353 DNS payment instructions — resolving ₿name@domain to a BIP-21 URI.
//
// The record lives at <name>.user._bitcoin-payment.<domain> as a DNSSEC-signed
// TXT containing one `bitcoin:` URI. Browsers can't do raw DNS, so we resolve
// over DNS-over-HTTPS. TRUST LEVEL, stated honestly: full client-side DNSSEC
// validation (what the BIP ultimately wants) is not implemented yet — instead
// we require agreement between TWO independent validating resolvers
// (Cloudflare and Google), each reporting the answer DNSSEC-authenticated
// (AD flag). Collusion or simultaneous compromise of both is the residual
// risk; a native chain validator is the follow-up.

const RESOLVERS = [
  'https://cloudflare-dns.com/dns-query',
  'https://dns.google/resolve',
];

// "a" "b" quoted character-strings → concatenated payload
function txtPayload(data) {
  const parts = [...String(data).matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1].replace(/\\(.)/g, '$1'));
  return parts.length ? parts.join('') : String(data);
}

async function queryOne(base, label) {
  const r = await fetch(`${base}?name=${label}&type=TXT`, { headers: { accept: 'application/dns-json' } });
  if (!r.ok) throw new Error(`resolver ${r.status}`);
  const j = await r.json();
  const uris = (j.Answer || [])
    .filter((a) => a.type === 16)
    .map((a) => txtPayload(a.data))
    .filter((t) => /^bitcoin:/i.test(t));
  // BIP-353: multiple bitcoin: TXT records at one label are invalid
  if (uris.length > 1) throw new Error('multiple payment records');
  return { uri: uris[0] || null, ad: !!j.AD };
}

// name like "adam", domain like "halwallet.app" → the bitcoin: URI, or null
// when no record exists. Throws when resolution can't be trusted.
export async function resolveBip353(name, domain) {
  const label = `${name}.user._bitcoin-payment.${domain}`;
  const results = await Promise.allSettled(RESOLVERS.map((r) => queryOne(r, label)));
  const ok = results.filter((r) => r.status === 'fulfilled').map((r) => r.value);
  if (ok.length < 2) {
    // one resolver down: accept a single authenticated answer, refuse a
    // single unauthenticated one
    if (ok.length === 1 && ok[0].uri && ok[0].ad) return ok[0].uri;
    if (ok.length === 1 && !ok[0].uri) return null;
    throw new Error('could not resolve the name');
  }
  if (ok[0].uri !== ok[1].uri) throw new Error('resolvers disagree — refusing');
  if (!ok[0].uri) return null;
  if (!ok[0].ad || !ok[1].ad) throw new Error('name is not DNSSEC-signed');
  return ok[0].uri;
}

// A pasted payment name: optional ₿, user@domain with a real-looking TLD.
export function parsePaymentName(text) {
  const m = String(text || '').trim().match(/^₿?\s*([a-z0-9._-]{1,64})@([a-z0-9-]+(?:\.[a-z0-9-]+)+)$/i);
  return m ? { name: m[1].toLowerCase(), domain: m[2].toLowerCase() } : null;
}

// bitcoin:<onchain?>?ark=...&lno=...&sp=... → { onchain, params }
export function parseBip21(uri) {
  const m = String(uri || '').match(/^bitcoin:([^?]*)(?:\?(.*))?$/i);
  if (!m) return null;
  const params = {};
  for (const kv of (m[2] || '').split('&')) {
    if (!kv) continue;
    const eq = kv.indexOf('=');
    if (eq < 0) continue;
    params[decodeURIComponent(kv.slice(0, eq)).toLowerCase()] = decodeURIComponent(kv.slice(eq + 1));
  }
  return { onchain: m[1] ? decodeURIComponent(m[1]) : '', params };
}

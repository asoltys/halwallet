// BIP-353 DNS payment instructions — resolving name@domain to a BIP-21 URI.
//
// The record lives at <name>.user._bitcoin-payment.<domain> as a DNSSEC-signed
// TXT containing one `bitcoin:` URI. Resolution runs full client-side DNSSEC
// chain validation (src/dnssec.js): the DoH resolver is untrusted transport,
// and every answer we act on is provably signed from the ICANN root down.

import { resolveTxtValidated } from './dnssec.js';

// name like "adam", domain like "halwallet.app" → the bitcoin: URI, or null
// when no record exists. Throws when the answer can't be proven authentic.
export async function resolveBip353(name, domain) {
  const label = `${name}.user._bitcoin-payment.${domain}`;
  let res;
  try {
    res = await resolveTxtValidated(label);
  } catch (e) {
    if (/^no TXT record/.test(e.message)) return null;
    throw e;
  }
  const uris = res.txts.filter((t) => /^bitcoin:/i.test(t));
  if (!uris.length) return null;
  // BIP-353: multiple bitcoin: TXT records at one label are invalid
  if (uris.length > 1) throw new Error('multiple payment records — invalid');
  return uris[0];
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

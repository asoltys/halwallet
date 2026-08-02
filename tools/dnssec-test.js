// DNSSEC chain validation against LIVE DNS. Needs network.
// Run: bun tools/dnssec-test.js
import { resolveTxtValidated } from '../src/dnssec.js';

let fails = 0;
const check = (name, ok, detail = '') => {
  console.log(` ${ok ? '✓' : '✗'} ${name}${detail ? ' — ' + String(detail).slice(0, 140) : ''}`);
  if (!ok) fails++;
};

// The canonical BIP-353 record: ₿matt@mattcorallo.com (alg 8 chain).
try {
  const { txts } = await resolveTxtValidated('matt.user._bitcoin-payment.mattcorallo.com');
  const uri = txts.find((t) => t.toLowerCase().startsWith('bitcoin:'));
  check('validates matt@mattcorallo.com (RSA chain)', !!uri, (uri || '').slice(0, 60) + '…');
} catch (e) { check('validates matt@mattcorallo.com (RSA chain)', false, e.message); }

// A Cloudflare-signed TXT (alg 13 chain): cloudflare.com SPF record.
try {
  const { txts } = await resolveTxtValidated('cloudflare.com');
  check('validates cloudflare.com TXT (ECDSA chain)', txts.length > 0, txts[0]);
} catch (e) { check('validates cloudflare.com TXT (ECDSA chain)', false, e.message); }

// An unsigned zone must FAIL closed, not pass quietly.
try {
  await resolveTxtValidated('google.com'); // google.com is famously unsigned
  check('unsigned zone fails closed', false, 'validated?!');
} catch (e) {
  check('unsigned zone fails closed', /not in a signed zone|no DNSKEY|fails/.test(e.message), e.message);
}

// A missing record must throw, not return empty-and-valid.
try {
  await resolveTxtValidated('definitely-not-real.user._bitcoin-payment.mattcorallo.com');
  check('missing record throws', false);
} catch (e) { check('missing record throws', true, e.message); }

console.log(fails ? `\n❌ ${fails} failure(s)` : '\n✅ DNSSEC validation behaves');
process.exit(fails ? 1 : 0);

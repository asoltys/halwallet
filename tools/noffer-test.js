// CLINK offer codes + the offer service: TLV roundtrip, and a full
// kind-21001 request/response through the nwc feature with a fake transport.
// Run: bun tools/noffer-test.js
import { hex } from '@scure/base';
import * as nip44 from 'nostr-tools/nip44';
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { encodeNoffer, decodeNoffer } from '../src/noffer.js';
import { nwcFeature } from '../src/features/nwc.js';

let fails = 0;
const check = (name, ok, detail = '') => {
  console.log(` ${ok ? '✓' : '✗'} ${name}${detail ? ' — ' + String(detail).slice(0, 120) : ''}`);
  if (!ok) fails++;
};

console.log('[offer code TLV]');
const pk = getPublicKey(generateSecretKey());
const code = encodeNoffer({ pubkey: pk, relay: 'wss://relay.coinos.io', offerId: 'zap_default', priceType: 2 });
check('encodes to noffer1…', code.startsWith('noffer1'), code.slice(0, 24));
const dec = decodeNoffer(code);
check('pubkey roundtrips', dec.pubkey === pk);
check('relay roundtrips', dec.relay === 'wss://relay.coinos.io');
check('offer id roundtrips', dec.offerId === 'zap_default');
check('price type roundtrips', dec.priceType === 2);

console.log('\n[offer service]');
// harness mirroring tools/nwc-test.js
const store = {};
let subHandlers = []; // every listen() subscription callback
const published = [];
const nwcTransport = {
  subscribe: (relays, filter, on) => { subHandlers.push({ filter, on }); return () => {}; },
  publish: async (relays, evt) => { published.push(evt); return true; },
  query: async () => [],
};
const wallet = {
  watchOnly: false,
  loadFeatureState: (n, fb) => JSON.parse(store['fs:' + n] || 'null') || fb,
  saveFeatureState: (n, st) => { store['fs:' + n] = JSON.stringify(st); },
  _cacheKey: () => 'w1',
  account: () => null,
  saveCache: () => {},
  registerCacheExtension: () => {},
};
const hooks = {
  arkReady: () => true,
  arkMakeInvoice: async (sat, desc) => ({ invoice: 'lnbc_mock_' + sat, paymentHash: 'cd'.repeat(32), amountSat: sat }),
  arkMovements: () => [],
  arkBgWrite: async () => {},
  arkBgSpendableSat: async () => 0,
};
const ctx = {
  h: () => null, ui: {}, render: () => {}, wallet,
  hook: (n, ...a) => (hooks[n] ? hooks[n](...a) : null),
  fmtAmount: String, unitLabel: () => 'sats', copyBtn: () => null, toast: () => {}, nwcTransport,
};
const f = nwcFeature(ctx);
f.init();
await new Promise((r) => setTimeout(r, 50));

const offerCode = f.nwcOfferString();
check('feature mints an offer code', !!offerCode && offerCode.startsWith('noffer1'), (offerCode || '').slice(0, 24));
const offer = decodeNoffer(offerCode);
const offerSub = subHandlers.find((s2) => (s2.filter.kinds || []).includes(21001));
check('subscribed for offer requests', !!offerSub && offerSub.filter['#p'][0] === offer.pubkey);

// a payer requests 21 sats with a zap attached
const payerSk = generateSecretKey();
const zapReq = finalizeEvent({ kind: 9734, created_at: Math.floor(Date.now() / 1000),
  tags: [['p', 'ab'.repeat(32)], ['relays', 'wss://relay.damus.io']], content: '' }, payerSk);
const reqPayload = { offer: 'zap_default', amount_sats: 21, zap: JSON.stringify(zapReq) };
const convKey = nip44.getConversationKey(payerSk, offer.pubkey);
const reqEv = finalizeEvent({
  kind: 21001, created_at: Math.floor(Date.now() / 1000),
  tags: [['p', offer.pubkey], ['clink_version', '1']],
  content: nip44.encrypt(JSON.stringify(reqPayload), convKey),
}, payerSk);
await offerSub.on(reqEv);
await new Promise((r) => setTimeout(r, 100));

const resp = published.find((e) => e.kind === 21001);
check('offer request answered', !!resp);
if (resp) {
  const body = JSON.parse(nip44.decrypt(resp.content, convKey));
  check('response carries the invoice', body.bolt11 === 'lnbc_mock_21', JSON.stringify(body));
  check('response e-tags the request', resp.tags.some((t) => t[0] === 'e' && t[1] === reqEv.id));
  check('response signed by the offer key', resp.pubkey === offer.pubkey);
}
const st = JSON.parse(store['fs:nwc']);
check('zap held for its receipt', (st.zapPending || []).length === 1 && st.zapPending[0].invoice === 'lnbc_mock_21');

// replay: same event must not be answered twice
const before = published.filter((e) => e.kind === 21001).length;
await offerSub.on(reqEv);
await new Promise((r) => setTimeout(r, 60));
check('replayed request ignored', published.filter((e) => e.kind === 21001).length === before);

console.log(fails ? `\n❌ ${fails} failure(s)` : '\n✅ offer service behaves');
process.exit(fails ? 1 : 0);

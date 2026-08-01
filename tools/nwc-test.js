// Drive the NWC feature as a real NIP-47 client would:
//   bun tools/nwc-test.js
// encrypted 23194
// requests in, encrypted 23195 responses out, both nip04 and nip44.
import { hex } from '@scure/base';
import { nwcFeature } from '/home/adam/halwallet/src/features/nwc.js';
import { nip04, nip44, getPublicKey, finalizeEvent, generateSecretKey } from '/home/adam/halwallet/src/nostr.js';

let ok = true;
const check = (n, c, d='') => { console.log(` ${c?'✓':'✗'} ${n}${d?' — '+d:''}`); if(!c) ok=false; };

const store = {};
globalThis.localStorage = { getItem:k=>k in store?store[k]:null, setItem:(k,v)=>{store[k]=v;}, removeItem:k=>{delete store[k];} };

let subHandler = null;
const published = [];
// fake relay transport: capture the subscription handler and any replies
const nwcTransport = {
  subscribe: (relays, filter, on) => { subHandler = on; return () => { subHandler = null; }; },
  publish: async (relays, evt) => { published.push(evt); return true; },
};
let paid = [];
const wallet = {
  watchOnly: false,
  loadFeatureState: (n, d) => (store['fs:'+n] ? JSON.parse(store['fs:'+n]) : d),
  saveFeatureState: (n, v) => { store['fs:'+n] = JSON.stringify(v); },
  nostrRelays: () => ['wss://relay.example'],
  nostrSubscribe: (filter, on) => { subHandler = on; return () => { subHandler = null; }; },
  nostrPublishSigned: async (evt) => { published.push(evt); return true; },
};
const hooks = {
  arkReady: () => true,
  arkSpendableSat: () => 42000,
  arkPayInvoice: async (inv, opts) => { paid.push({ inv, opts }); return { preimage: 'ab'.repeat(32), feeSat: 1, amountSat: 25 }; },
  arkMakeInvoice: async (sat) => ({ invoice: 'lnbc'+sat, paymentHash: 'cd'.repeat(32), amountSat: sat }),
  arkMovements: () => ([{ type:'ln-send', status:'complete', amountSat: 25, ts: Date.now(), invoice:'lnbc250n1', preimage:'ef'.repeat(32) }]),
};
const ctx = { h:()=>null, ui:{}, render:()=>{}, wallet, hook:(n,...a)=>hooks[n]?hooks[n](...a):null,
  fmtAmount:(n)=>String(n), unitLabel:()=>'sats', copyBtn:()=>null, toast:()=>{}, nwcTransport };

const f = nwcFeature(ctx);
f.init();

// create a connection the way the UI does
const st = { conns: [] };
// invoke via the settings card is awkward headless; call through the module's
// exported behaviour by simulating what createConn does: use the feature's card
// action indirectly — instead drive persistence directly then re-init.
const serviceSk = generateSecretKey(), clientSk = generateSecretKey();
const conn = {
  id: 'test1', name: 'TestApp',
  serviceSk: hex.encode(serviceSk), servicePk: getPublicKey(serviceSk),
  secret: hex.encode(clientSk), clientPk: getPublicKey(clientSk),
  maxSat: 1000, dailySat: 2000, spentToday: 0, spentDate: null, created: Date.now(), revoked: false,
};
store['fs:nwc'] = JSON.stringify({ conns: [conn] });
f.stop(); f.init();
check('subscribed for requests', typeof subHandler === 'function');

async function request(method, params, scheme='nip44_v2') {
  const payload = JSON.stringify({ method, params });
  const content = scheme === 'nip44_v2'
    ? nip44.encrypt(payload, nip44.getConversationKey(clientSk, conn.servicePk))
    : await nip04.encrypt(clientSk, conn.servicePk, payload);
  const ev = finalizeEvent({ kind: 23194, created_at: Math.floor(Date.now()/1000),
    tags: [['p', conn.servicePk], ...(scheme==='nip44_v2'?[['encryption','nip44_v2']]:[])], content }, clientSk);
  const before = published.length;
  await subHandler(ev);
  for (let i=0;i<40 && published.length===before;i++) await new Promise(r=>setTimeout(r,50));
  const res = published[published.length-1];
  if (!res) return null;
  const txt = scheme === 'nip44_v2'
    ? nip44.decrypt(res.content, nip44.getConversationKey(clientSk, conn.servicePk))
    : await nip04.decrypt(clientSk, conn.servicePk, res.content);
  return JSON.parse(txt);
}

console.log('\n[nip44 requests]');
let r = await request('get_info', {});
check('get_info lists methods', r?.result?.methods?.includes('pay_invoice'), JSON.stringify(r?.result?.methods));
r = await request('get_balance', {});
check('get_balance in msat', r?.result?.balance === 42000*1000, String(r?.result?.balance));
r = await request('pay_invoice', { invoice: 'lnbc250n1p4xu9wtsp5t5c9w2qlv4mkngwn6txm4' });
check('pay_invoice rejects an unparseable invoice', !!r?.error, JSON.stringify(r?.error));

console.log('\n[budget enforcement]');
// a real-looking 25-sat invoice from earlier in this session
const INV25 = 'lnbc250n1p4xu9wtsp5t5c9w2qlv4mkngwn6txm4';
r = await request('pay_invoice', { invoice: 'lnbc50u1p4xu8whsp5jjnp3jzhjrgp3992dhurhryued5dhk0fvp7jexkjtd86czhwu77spp5dg2d76m6cjl5s6s6m2sffeux746ha345cmmmu2ttgjs0mu2gnkfsdqcdemkxgrzw4jxwet5yp6x2um5xqyjw5qcqpjrzjqgfffll4jmjf0tffqtx47xt886gzp9fajp3966xz96gm2xj9cqedxr4zxyqq3vgqqqqqqqqqqqqqrssqyg9qxpqysgq0g76kefudlp6z9qp3xypghqvqtkgtz3cwc89f76x4wzkvnx2lmu9azt8ewnet7avrhxek62sdm67zx72mnntldarhlsdkcna9k9r4uqqe5lr3p' });  // 5000 sat, over the 1000 limit
check('over-limit payment refused', r?.error?.code === 'QUOTA_EXCEEDED', JSON.stringify(r?.error));
check('nothing was paid', paid.length === 0);

console.log('\n[nip04 fallback]');
r = await request('get_balance', {}, 'nip04');
check('nip04 request answered', r?.result?.balance === 42000*1000);

console.log('\n[other methods]');
r = await request('make_invoice', { amount: 21000 });
check('make_invoice returns a bolt11', !!r?.result?.invoice, r?.result?.invoice);
r = await request('list_transactions', {});
check('list_transactions returns history', Array.isArray(r?.result?.transactions) && r.result.transactions.length === 1);
r = await request('pay_keysend', {});
check('unsupported method errors cleanly', r?.error?.code === 'NOT_IMPLEMENTED');

console.log('\n[isolation]');
const strangerSk = generateSecretKey();
const payload = JSON.stringify({ method: 'get_balance', params: {} });
const ev = finalizeEvent({ kind: 23194, created_at: Math.floor(Date.now()/1000),
  tags: [['p', conn.servicePk], ['encryption','nip44_v2']],
  content: nip44.encrypt(payload, nip44.getConversationKey(strangerSk, conn.servicePk)) }, strangerSk);
const before = published.length;
await subHandler(ev);
await new Promise(r=>setTimeout(r,300));
check('request from an unauthorized key is ignored', published.length === before);

console.log(ok ? '\n✅ NWC service behaves' : '\n❌ failed');
process.exit(ok?0:1);

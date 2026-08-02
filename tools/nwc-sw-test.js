// The service worker's pouch responder, headless: request decrypt, balance,
// budgets, answered-elsewhere suppression, fallbacks. The bridge/ASP pay path
// itself is covered by the manager and bridge tests. Run: bun tools/nwc-sw-test.js
import { hex } from '@scure/base';
import * as nip04 from 'nostr-tools/nip04';
import * as nip44 from 'nostr-tools/nip44';
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { respondFromPouch } from '../src/nwc-respond.js';

let fails = 0;
const check = (name, ok, detail = '') => {
  console.log(` ${ok ? '✓' : '✗'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) fails++;
};

const serviceSk = generateSecretKey();
const clientSk = generateSecretKey();
const conn = {
  id: 'c1', servicePk: getPublicKey(serviceSk), serviceSk: hex.encode(serviceSk),
  clientPk: getPublicKey(clientSk), maxSat: 1000, dailySat: 2000,
};
const basePouch = () => ({
  v: 2,
  ark: { arkUrl: 'http://ark.test', esploraUrl: 'http://esp.test', network: 'mainnet', serverPubkey: 'ab'.repeat(32) },
  bridge: { url: 'http://bridge.test', token: '' },
  vtxos: [{ id: 'v1', bytes: '00', keyIndex: 0, amountSat: 5000, expiryHeight: 1 }],
  keys: { 0: hex.encode(generateSecretKey()) },
  nextKeyIndex: 20,
  connections: [conn],
  spends: [],
});

function makeReq(method, params = {}, scheme = 'nip44_v2', ageSec = 0) {
  const payload = JSON.stringify({ method, params });
  const content = scheme === 'nip44_v2'
    ? nip44.encrypt(payload, nip44.getConversationKey(clientSk, conn.servicePk))
    : nip04.encrypt(clientSk, conn.servicePk, payload);
  return finalizeEvent({
    kind: 23194, created_at: Math.floor(Date.now() / 1000) - ageSec,
    tags: [['p', conn.servicePk], ...(scheme === 'nip44_v2' ? [['encryption', 'nip44_v2']] : [])],
    content,
  }, clientSk);
}

function harness({ pouch = basePouch(), answered = false } = {}) {
  const published = [];
  const fetchFn = async (url, opts) => {
    if (url.includes('/publish')) {
      published.push(JSON.parse(opts.body).event);
      return { ok: true, json: async () => ({ ok: true }) };
    }
    if (url.includes('/answered')) return { ok: true, json: async () => ({ answered }) };
    throw new Error('unexpected fetch ' + url);
  };
  const deps = {
    notifier: 'http://notif.test',
    fetchFn,
    pouchesFn: async () => [{ walletKey: 'w1', pouch }],
    saveFn: async () => {},
  };
  const decryptReply = (ev) => {
    const scheme = ev.tags.find((t) => t[0] === 'encryption')?.[1];
    return JSON.parse(scheme === 'nip44_v2'
      ? nip44.decrypt(ev.content, nip44.getConversationKey(clientSk, conn.servicePk))
      : nip04.decrypt(clientSk, conn.servicePk, ev.content));
  };
  return { deps, published, decryptReply };
}

const ev = (e) => JSON.parse(JSON.stringify(e)); // strip verified symbol like a push payload would

console.log('[balance + info]');
{
  const { deps, published, decryptReply } = harness();
  const handled = await respondFromPouch({ type: 'nwc', event: ev(makeReq('get_balance')) }, deps);
  check('get_balance handled', handled === true);
  const r = decryptReply(published[0]);
  check('pouch balance in msat', r.result?.balance === 5000000, JSON.stringify(r));
}
{
  const { deps, published, decryptReply } = harness();
  await respondFromPouch({ type: 'nwc', event: ev(makeReq('get_info', {}, 'nip04')) }, deps);
  const r = decryptReply(published[0]);
  check('nip04 get_info answered in nip04', r.result?.alias === 'Hal' && published[0].tags.find((t) => t[0] === 'encryption')[1] === 'nip04');
}

console.log('\n[guards]');
{
  const { deps } = harness();
  const stale = ev(makeReq('get_balance', {}, 'nip44_v2', 300));
  check('stale request refused', (await respondFromPouch({ type: 'nwc', event: stale }, deps)) === false);
}
{
  const { deps } = harness();
  const foreign = ev(finalizeEvent({
    kind: 23194, created_at: Math.floor(Date.now() / 1000),
    tags: [['p', conn.servicePk]], content: 'junk',
  }, generateSecretKey()));
  check('foreign signer refused', (await respondFromPouch({ type: 'nwc', event: foreign }, deps)) === false);
}
{
  const { deps } = harness();
  check('no payload event → wake the user', (await respondFromPouch({ type: 'nwc', servicePubkey: conn.servicePk }, deps)) === false);
}

console.log('\n[pay budgets]');
// a real (long-expired) 21-sat invoice — decode only, nothing is paid
const INV21 = 'lnbc210n1p4xuk2wpp506wkjr0xk3677nu7je9c55vq4lzlkyd0ztcq2mlvumap0zpe3alqhp5ppg7g8qwpdv34hgpymhw446y37duzwcn388yp3pw05n7tlulyn2scqzysxqrrssrzjqv3dpepm8kfdxrk3sl6wzqdf49s9c0h9ljtjrek6c08r6aejlwcnur0dwyqqvusqqqqqqqlgqqqq86qqjqsp5dc0jrq94ke2f4dzx8c2dwqsc6a65eu56dt2j599l7kxp7q2hs6zq9qxpqysgqdjeft8gkl0uga24e502pvcp5vgsfap3dxuutcpgfaj33fffuqs9psmnrklshp3fg3py7vlnzsea90vj9ahqq5t9xuy67u3pk0sfnheqpn95f2g';
{
  const pouch = basePouch();
  pouch.connections = [{ ...conn, maxSat: 10 }];
  const { deps, published, decryptReply } = harness({ pouch });
  const handled = await respondFromPouch({ type: 'nwc', event: ev(makeReq('pay_invoice', { invoice: INV21 })) }, deps);
  check('over per-payment limit refused', handled && decryptReply(published[0]).error?.code === 'QUOTA_EXCEEDED');
}
{
  const pouch = basePouch();
  pouch.spends = [{ connId: 'c1', amountSat: 1990, feeSat: 0, ts: Date.now() }];
  const { deps, published, decryptReply } = harness({ pouch });
  const handled = await respondFromPouch({ type: 'nwc', event: ev(makeReq('pay_invoice', { invoice: INV21 })) }, deps);
  check('over daily budget refused', handled && decryptReply(published[0]).error?.code === 'QUOTA_EXCEEDED');
}
{
  const { deps, published } = harness({ answered: true });
  const handled = await respondFromPouch({ type: 'nwc', event: ev(makeReq('pay_invoice', { invoice: INV21 })) }, deps);
  check('answered elsewhere → silent', handled === true && published.length === 0);
}
{
  const pouch = basePouch();
  pouch.bridge = null;
  const { deps } = harness({ pouch });
  const handled = await respondFromPouch({ type: 'nwc', event: ev(makeReq('pay_invoice', { invoice: INV21 })) }, deps);
  check('no bridge → wake the user', handled === false);
}

console.log(fails ? `\n❌ ${fails} failure(s)` : '\n✅ pouch responder behaves');
process.exit(fails ? 1 : 0);

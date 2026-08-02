// NWC auto-answer from the pouch — the half of background wallet-connect
// that pays without a tap. Runs inside the service worker's push handler:
// the push payload carries the encrypted request event, the pouch (IndexedDB)
// carries the connection service keys and a bounded set of coins, and the
// reply goes back through the notifier's /publish endpoint — no WebSocket,
// no seed, nothing outside the pouch's blast radius.
//
// Trust: the notifier transports ciphertext both ways. Requests arrive
// nip04/nip44-encrypted and signed by the client; replies leave encrypted and
// signed by the per-connection service key. The notifier can neither read nor
// forge either. Spending happens directly against the ASP/bridge over fetch.
//
// Anything this module can't handle returns false, and the caller falls back
// to today's behavior: a notification that opens the wallet.

import { hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';
import * as nip04 from 'nostr-tools/nip04';
import * as nip44 from 'nostr-tools/nip44';
import { finalizeEvent } from 'nostr-tools/pure';
import { ArkManager } from './ark/manager.js';
import { maybeBolt11 } from './ark/lightning.js';
import { allPouches, savePouch, POUCH_KEY_WINDOW, POUCH_CHANGE_BASE } from './nwc-pouch.js';

const MAX_AGE_SEC = 120;
const nowSec = () => Math.floor(Date.now() / 1000);
const errRes = (t, code, message) => ({ result_type: t, error: { code, message } });

const decrypt = async (scheme, skHex, pk, ct) => (scheme === 'nip44_v2'
  ? nip44.decrypt(ct, nip44.getConversationKey(hex.decode(skHex), pk))
  : Promise.resolve(nip04.decrypt(hex.decode(skHex), pk, ct)));

async function buildReply(conn, ev, scheme, payload) {
  const sk = hex.decode(conn.serviceSk);
  const content = scheme === 'nip44_v2'
    ? nip44.encrypt(JSON.stringify(payload), nip44.getConversationKey(sk, ev.pubkey))
    : await Promise.resolve(nip04.encrypt(sk, ev.pubkey, JSON.stringify(payload)));
  return finalizeEvent({
    kind: 23195, created_at: nowSec(),
    tags: [['p', ev.pubkey], ['e', ev.id], ['encryption', scheme]],
    content,
  }, sk);
}

const seedState = (pouch) => ({
  v: 1,
  serverPubkey: pouch.ark.serverPubkey || null,
  mailboxCheckpoint: 0,
  nextKeyIndex: pouch.nextKeyIndex || POUCH_CHANGE_BASE,
  vtxos: (pouch.vtxos || []).map((v) => ({ ...v, state: v.state || 'spendable' })),
  actions: [],
  movements: [],
});

const spendableVtxos = (pouch) =>
  ((pouch.mgr && pouch.mgr.vtxos) || seedState(pouch).vtxos).filter((v) => v.state === 'spendable');

// data: the push payload { type:'nwc', servicePubkey, event }. Returns true
// when the request was fully dealt with (reply published or deliberately
// left to another device); false means "wake the user instead".
export async function respondFromPouch(data, {
  notifier, fetchFn = fetch, pouchesFn = allPouches, saveFn = savePouch, log = () => {},
} = {}) {
  const ev = data && data.event;
  if (!ev || ev.kind !== 23194 || !ev.id || !ev.pubkey) return false;
  if (nowSec() - (ev.created_at || 0) > MAX_AGE_SEC) return false;

  const target = (ev.tags?.find((t) => t[0] === 'p') || [])[1];
  if (!target) return false;
  let walletKey = null, pouch = null, conn = null;
  for (const p of await pouchesFn()) {
    const c = (p.pouch.connections || []).find((x) => x.servicePk === target);
    if (c) { walletKey = p.walletKey; pouch = p.pouch; conn = c; break; }
  }
  if (!conn) return false;
  if (ev.pubkey !== conn.clientPk) return false;

  const scheme = ev.tags?.find((x) => x[0] === 'encryption')?.[1] === 'nip44_v2' ? 'nip44_v2' : 'nip04';
  let req;
  try { req = JSON.parse(await decrypt(scheme, conn.serviceSk, ev.pubkey, ev.content)); } catch { return false; }
  const method = req?.method;
  const params = req?.params || {};

  const publish = async (payload) => {
    const evt = await buildReply(conn, ev, scheme, payload);
    const r = await fetchFn(`${notifier}/publish`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ event: evt }),
    });
    if (!r.ok) throw new Error(`publish refused: ${r.status}`);
    return true;
  };
  // Another device (an open tab elsewhere) may have answered already — a
  // paid zap must never be shouted over with a late error, and paying twice
  // wastes a lock cycle. The notifier tracks recent reply e-tags.
  const answered = async () => {
    try {
      const r = await fetchFn(`${notifier}/answered?event=${ev.id}`);
      return !!(await r.json()).answered;
    } catch { return false; }
  };

  if (method === 'get_info') {
    await publish({
      result_type: 'get_info',
      result: {
        alias: 'Hal', color: '#f7931a',
        network: pouch.ark.network === 'mainnet' ? 'mainnet' : pouch.ark.network,
        block_height: 0, block_hash: '',
        methods: ['get_info', 'get_balance', 'pay_invoice', 'list_transactions'],
      },
    });
    return true;
  }
  if (method === 'get_balance') {
    const sat = spendableVtxos(pouch).reduce((n, v) => n + (v.amountSat || 0), 0);
    await publish({ result_type: 'get_balance', result: { balance: sat * 1000 } });
    return true;
  }
  if (method === 'list_transactions') {
    const txs = (pouch.spends || []).slice(-(params.limit || 20)).map((s) => ({
      type: 'outgoing', invoice: s.invoice || '', preimage: s.preimage || '',
      amount: (s.amountSat || 0) * 1000, fees_paid: (s.feeSat || 0) * 1000,
      created_at: Math.floor((s.ts || Date.now()) / 1000),
      settled_at: Math.floor((s.ts || Date.now()) / 1000),
      description: '',
    }));
    await publish({ result_type: 'list_transactions', result: { transactions: txs } });
    return true;
  }
  if (method !== 'pay_invoice') {
    await publish(errRes(method, 'NOT_IMPLEMENTED', 'not available while the wallet is closed'));
    return true;
  }

  // ---- pay_invoice ------------------------------------------------------
  if (await answered()) { log('already answered elsewhere'); return true; }

  const invoice = params.invoice;
  const dec = invoice && maybeBolt11(invoice);
  if (!dec) { await publish(errRes('pay_invoice', 'OTHER', 'not a bolt11 invoice')); return true; }
  if (!dec.amountSat) { await publish(errRes('pay_invoice', 'OTHER', 'zero-amount invoices are not supported')); return true; }
  if (dec.amountSat > conn.maxSat) {
    await publish(errRes('pay_invoice', 'QUOTA_EXCEEDED', `over the ${conn.maxSat} sat per-payment limit`));
    return true;
  }
  const today = new Date().toISOString().slice(0, 10);
  const spentToday = (pouch.spends || [])
    .filter((s) => s.connId === conn.id && new Date(s.ts).toISOString().slice(0, 10) === today)
    .reduce((n, s) => n + (s.amountSat || 0) + (s.feeSat || 0), 0);
  if (spentToday + dec.amountSat > conn.dailySat) {
    await publish(errRes('pay_invoice', 'QUOTA_EXCEEDED', `over the remaining daily budget (${Math.max(0, conn.dailySat - spentToday)} sat)`));
    return true;
  }

  // The worker only pays through the bridge (one HTLC lock, one HTTP swap).
  // No bridge, no coins, or an exhausted key window → wake the user instead.
  if (!pouch.bridge || !pouch.bridge.url) return false;
  const nextIdx = (pouch.mgr && pouch.mgr.nextKeyIndex) || pouch.nextKeyIndex || POUCH_CHANGE_BASE;
  if (nextIdx >= POUCH_KEY_WINDOW - 1) { log('pouch key window exhausted'); return false; }

  const auth = pouch.bridge.token ? { authorization: `Bearer ${pouch.bridge.token}` } : {};
  let quote;
  try {
    const r = await fetchFn(`${pouch.bridge.url}/quote?invoice=${encodeURIComponent(invoice)}`, { headers: auth });
    quote = await r.json();
    if (!r.ok || quote.error) throw new Error(quote.error || `quote failed (${r.status})`);
  } catch (e) { log('quote failed: ' + e.message); return false; }
  if (!spendableVtxos(pouch).some((v) => v.amountSat >= quote.totalSat)) {
    log('pouch cannot cover ' + quote.totalSat);
    return false; // underfunded pouch: the user should top up — notify
  }

  const storage = {
    load: () => pouch.mgr || seedState(pouch),
    save: (s) => { pouch.mgr = s; saveFn(walletKey, pouch).catch(() => {}); },
  };
  const keyShim = { deriveChild: () => ({ deriveChild: (i) => ({ privateKey: hex.decode(pouch.keys[String(i)] || pouch.keys['0']) }) }) };
  let mgr;
  try {
    mgr = await new ArkManager({
      account: keyShim, storage,
      arkUrl: pouch.ark.arkUrl, esploraUrl: pouch.ark.esploraUrl, network: pouch.ark.network,
    }).init();
  } catch (e) { log('ark init failed: ' + e.message); return false; }

  let lock;
  try {
    lock = await mgr.htlcLock({
      amountSat: quote.totalSat, claimPubkey: quote.claimPubkey,
      paymentHash: quote.paymentHash, htlcExpiry: quote.htlcExpiry,
    });
  } catch (e) { log('htlc lock failed: ' + e.message); return false; }

  // Persist the swap BEFORE handing it to the bridge: if we die mid-flight,
  // the app finds the record on next open and runs its refund machinery.
  pouch.swaps = pouch.swaps || [];
  const rec = {
    paymentHash: quote.paymentHash, invoice, bridgeUrl: pouch.bridge.url,
    amountSat: quote.amountSat, feeSat: quote.feeSat,
    htlcVtxo: lock.htlcVtxos[0], refundIndex: lock.refundIndex,
    htlcExpiry: quote.htlcExpiry, step: 'submitted', ts: Date.now(),
  };
  pouch.swaps.push(rec);
  await saveFn(walletKey, pouch);

  let res;
  try {
    const r = await fetchFn(`${pouch.bridge.url}/swap`, {
      method: 'POST', headers: { 'content-type': 'application/json', ...auth },
      body: JSON.stringify({ invoice, htlcVtxo: lock.htlcVtxos[0] }),
    });
    res = await r.json();
    if (!r.ok || res.error) throw new Error(res.error || `bridge error (${r.status})`);
    if (res.step !== 'done') throw new Error(res.error || 'bridge did not pay');
    if (!res.preimage || hex.encode(sha256(hex.decode(res.preimage))) !== quote.paymentHash) {
      throw new Error('bridge returned an invalid preimage');
    }
  } catch (e) {
    rec.step = 'refundable';
    rec.error = e.message;
    await saveFn(walletKey, pouch);
    // the winner may have paid while we were locking — never shout over it
    if (!(await answered())) {
      await publish(errRes('pay_invoice', 'INTERNAL', e.message)).catch(() => {});
    }
    return true;
  }

  rec.step = 'done';
  rec.preimage = res.preimage;
  pouch.spends = pouch.spends || [];
  pouch.spends.push({
    connId: conn.id, amountSat: quote.amountSat, feeSat: quote.feeSat,
    paymentHash: quote.paymentHash, preimage: res.preimage, invoice, ts: Date.now(),
  });
  if (pouch.spends.length > 200) pouch.spends = pouch.spends.slice(-200);
  await saveFn(walletKey, pouch);
  await publish({
    result_type: 'pay_invoice',
    result: { preimage: res.preimage, fees_paid: (quote.feeSat || 0) * 1000 },
  });
  log(`paid ${quote.amountSat} sat via bridge from the pouch`);
  return true;
}

// NWC auto-answer while the app is closed. Runs inside the service worker's
// push handler: the push payload carries the encrypted request event, the
// background record (IndexedDB) carries the connection service keys and a
// mirror of the wallet's ark state, and the reply goes back through the
// notifier's /publish endpoint — no WebSocket, no seed.
//
// Trust: the notifier transports ciphertext both ways. Requests arrive
// nip04/nip44-encrypted and signed by the client; replies leave encrypted and
// signed by the per-connection service key. The notifier can neither read nor
// forge either. Payments run the ASP's own Lightning send directly over
// fetch — the same path the open app uses.
//
// Anything this module can't handle returns false, and the caller falls back
// to a notification that opens the wallet.

import { hex } from '@scure/base';
import * as nip04 from 'nostr-tools/nip04';
import * as nip44 from 'nostr-tools/nip44';
import { finalizeEvent } from 'nostr-tools/pure';
import { ArkManager } from './ark/manager.js';
import { maybeBolt11 } from './ark/lightning.js';
import { allBgs, saveBg } from './nwc-bg.js';

const MAX_AGE_SEC = 120;
const PAY_WAIT_MS = 20_000; // inside the SW's ~30s budget, with reply margin
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

const spendableSat = (rec) =>
  ((rec.mgr && rec.mgr.vtxos) || []).filter((v) => v.state === 'spendable')
    .reduce((n, v) => n + (v.amountSat || 0), 0);

// The worker can't derive keys — the mirror carries them per chain:
// 3 = coins/change, 4/0 = mailbox, 5 = receive preimages.
function shimAccount(rec) {
  const byChain = (chain, i) => {
    const k = chain === 5 ? rec.keys5?.[String(i)]
      : chain === 4 ? rec.key4
      : rec.keys[String(i)];
    if (!k) throw new Error(`chain ${chain} index ${i} outside the mirrored window`);
    return hex.decode(k);
  };
  return { deriveChild: (chain) => ({ deriveChild: (i) => ({ privateKey: byChain(chain, i) }) }) };
}

async function bgManager(rec, walletKey, saveFn) {
  const storage = {
    load: () => rec.mgr,
    save: (s) => { rec.mgr = s; saveFn(walletKey, rec).catch(() => {}); },
  };
  return new ArkManager({
    account: shimAccount(rec), storage,
    arkUrl: rec.ark.arkUrl, esploraUrl: rec.ark.esploraUrl, network: rec.ark.network,
  }).init();
}

// A CLINK offer request (kind 21001): mint an invoice against the mirrored
// wallet and reply. The payment itself arrives later over the ASP's hold
// invoice — the app claims it on next open, so we also ask the caller to
// raise a "money incoming" notification.
async function respondOffer(ev, rec, walletKey, { notifier, fetchFn, saveFn, log }) {
  const offer = rec.offer;
  if (!offer || !offer.sk) return false;
  const sk = hex.decode(offer.sk);
  let req;
  try { req = JSON.parse(nip44.decrypt(ev.content, nip44.getConversationKey(sk, ev.pubkey))); } catch { return false; }
  const publish = async (payload) => {
    const content = nip44.encrypt(JSON.stringify(payload), nip44.getConversationKey(sk, ev.pubkey));
    const evt = finalizeEvent({
      kind: 21001, created_at: nowSec(),
      tags: [['p', ev.pubkey], ['e', ev.id], ['clink_version', '1']],
      content,
    }, sk);
    const r = await fetchFn(`${notifier}/publish`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ event: evt }),
    });
    if (!r.ok) throw new Error(`publish refused: ${r.status}`);
  };
  try {
    const answered = await fetchFn(`${notifier}/answered?event=${ev.id}`).then((r) => r.json()).catch(() => ({}));
    if (answered.answered) return true;
    const sat = Math.floor(req.amount_sats || 0);
    if (!sat || sat < 1) { await publish({ error: 'Invalid Amount', code: 5, range: { min: 1, max: 1000000 } }); return true; }
    if (!rec.keys5 || !rec.key4) return false; // old mirror: wake the user
    if (!rec.keys5[String(rec.mgr.nextLnRecvIndex || 0)]) return false; // preimage window exhausted
    const mgr = await bgManager(rec, walletKey, saveFn);
    const a = await mgr.createLnInvoice(sat, (req.description || '').slice(0, 100));
    // pending zap receipts are published by the app when it claims — stash
    // what it needs alongside the mirror
    if (req.zap) {
      rec.zapPending = rec.zapPending || [];
      rec.zapPending.push({ zap: req.zap, invoice: a.invoice, ts: Date.now() });
      if (rec.zapPending.length > 50) rec.zapPending = rec.zapPending.slice(-50);
    }
    await saveFn(walletKey, rec);
    await publish({ bolt11: a.invoice });
    log(`minted ${sat} sat offer invoice while closed`);
    return { notify: { title: 'Incoming payment', body: 'Someone is paying you — open Coinos to receive it.' } };
  } catch (e) {
    log('offer mint failed: ' + e.message);
    await publish({ error: 'Temporary Failure', code: 2 }).catch(() => {});
    return true;
  }
}

// data: the push payload { type:'nwc', servicePubkey, event }. Returns true
// when the request was fully dealt with (reply published or deliberately
// left to another device); false means "wake the user instead".
export async function respondFromBg(data, {
  notifier, fetchFn = fetch, recordsFn = allBgs, saveFn = saveBg, log = () => {},
} = {}) {
  const ev = data && data.event;
  if (!ev || !ev.id || !ev.pubkey) return false;
  if (nowSec() - (ev.created_at || 0) > MAX_AGE_SEC) return false;

  const target = (ev.tags?.find((t) => t[0] === 'p') || [])[1];
  if (!target) return false;

  // CLINK offer requests route by the offer service pubkey.
  if (ev.kind === 21001) {
    for (const r of await recordsFn()) {
      if (r.rec.v >= 3 && r.rec.offer?.pk === target) {
        return respondOffer(ev, r.rec, r.walletKey, { notifier, fetchFn, saveFn, log });
      }
    }
    return false;
  }

  if (ev.kind !== 23194) return false;
  let walletKey = null, rec = null, conn = null;
  for (const r of await recordsFn()) {
    const c = (r.rec.connections || []).find((x) => x.servicePk === target);
    if (c && r.rec.v >= 3) { walletKey = r.walletKey; rec = r.rec; conn = c; break; }
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
  // wastes funds-in-flight. The notifier tracks recent reply e-tags.
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
        alias: 'Coinos', color: '#f7931a',
        network: rec.ark.network === 'mainnet' ? 'mainnet' : rec.ark.network,
        block_height: 0, block_hash: '',
        methods: ['get_info', 'get_balance', 'pay_invoice', 'list_transactions'],
      },
    });
    return true;
  }
  if (method === 'get_balance') {
    await publish({ result_type: 'get_balance', result: { balance: spendableSat(rec) * 1000 } });
    return true;
  }
  if (method === 'list_transactions') {
    const txs = (rec.spends || []).slice(-(params.limit || 20)).map((s) => ({
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
  const spentToday = (rec.spends || [])
    .filter((s) => s.connId === conn.id && new Date(s.ts).toISOString().slice(0, 10) === today)
    .reduce((n, s) => n + (s.amountSat || 0) + (s.feeSat || 0), 0);
  if (spentToday + dec.amountSat > conn.dailySat) {
    await publish(errRes('pay_invoice', 'QUOTA_EXCEEDED', `over the remaining daily budget (${Math.max(0, conn.dailySat - spentToday)} sat)`));
    return true;
  }
  if (spendableSat(rec) < dec.amountSat) return false; // stale/empty mirror: wake the user

  // The ASP's own Lightning send, over the mirrored state. Change and HTLC
  // outputs allocate from nextKeyIndex, which must stay inside the key
  // window the app pre-derived; if it ran out, wake the user instead.
  if (!rec.keys[String(rec.mgr.nextKeyIndex || 1)]) { log('key window exhausted'); return false; }
  let mgr;
  try {
    mgr = await bgManager(rec, walletKey, saveFn);
  } catch (e) { log('ark init failed: ' + e.message); return false; }

  let id;
  try {
    id = await mgr.payLnInvoice(invoice);
  } catch (e) {
    if (!(await answered())) {
      await publish(errRes('pay_invoice', 'INTERNAL', e.message)).catch(() => {});
    }
    return true;
  }
  const deadline = Date.now() + PAY_WAIT_MS;
  let a = mgr.lnAction(id);
  while (a && !['done', 'failed'].includes(a.step) && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 1500));
    await mgr.driveLn(id).catch(() => {});
    a = mgr.lnAction(id);
  }
  if (!a || a.step === 'failed') {
    if (!(await answered())) {
      await publish(errRes('pay_invoice', 'INTERNAL', (a && a.error) || 'payment failed')).catch(() => {});
    }
    return true;
  }
  if (a.step !== 'done') {
    // still in flight as our budget runs out: the app resumes it from the
    // mirrored state on next open — wake the user rather than guess.
    log('payment still pending at SW deadline');
    return false;
  }

  rec.spends = rec.spends || [];
  rec.spends.push({
    connId: conn.id, amountSat: a.amountSat || dec.amountSat, feeSat: a.feeSat || 0,
    paymentHash: dec.paymentHash, preimage: a.preimage, invoice, ts: Date.now(),
  });
  if (rec.spends.length > 200) rec.spends = rec.spends.slice(-200);
  await saveFn(walletKey, rec);
  await publish({
    result_type: 'pay_invoice',
    result: { preimage: a.preimage, fees_paid: (a.feeSat || 0) * 1000 },
  });
  log(`paid ${a.amountSat || dec.amountSat} sat via the ASP from the background mirror`);
  return true;
}

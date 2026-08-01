// Nostr Wallet Connect (NIP-47) — hal as a *wallet service*.
//
// Other apps (Damus, Amethyst, Alby, a website) connect to your hal wallet
// over nostr and can ask it to pay invoices or report a balance, without ever
// touching your keys. You hand out a connection string; hal answers requests
// signed by that connection, inside the budget you set, and you can revoke it
// at any time.
//
// hal holds no native Lightning balance, so every Lightning operation here
// runs over Ark: paying goes through the swap bridge when one is configured
// and falls back to the ASP's own lightning-send, and receiving mints an
// invoice on the ASP. That means NWC availability tracks Ark availability —
// no Ark server, no wallet service.
//
// Shape of the protocol (mirrors coinos-server/lib/nwc.ts):
//   kind 13194  info event, content = space-separated supported methods
//   kind 23194  request  (client -> wallet), encrypted to the wallet key
//   kind 23195  response (wallet -> client), same encryption scheme back
// Encryption is nip04 unless the request carries `["encryption","nip44_v2"]`.
//
// IMPORTANT limitation, surfaced in the UI: hal is a web wallet, so it only
// answers while a tab is open. It is not an always-on wallet service.

import { hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';
import {
  nip04, nip44, getPublicKey, finalizeEvent, generateSecretKey,
  subscribeOn, publishOn,
} from '../nostr.js';
import { t } from '../i18n.js';
import { qrSvg } from '../qr.js';
import { getNetwork } from '../api.js';
import { maybeBolt11 } from '../ark/lightning.js';

const REQ_KIND = 23194;
const RES_KIND = 23195;
const INFO_KIND = 13194;

// What we can actually honour. No pay_keysend (Ark can't), no multi_pay.
const METHODS = ['get_info', 'get_balance', 'pay_invoice', 'make_invoice', 'list_transactions'];

// Requests older than this are ignored — a relay replaying history must not
// re-trigger payments.
const MAX_AGE_SEC = 120;

const nowSec = () => Math.floor(Date.now() / 1000);
const errRes = (code, message) => ({ error: { code, message } });

export function nwcFeature(ctx) {
  const { h, ui, render, wallet, hook, fmtAmount, unitLabel, copyBtn, toast } = ctx;
  // Relay transport, injectable so the protocol can be driven in tests
  // without a live relay.
  const { subscribe = subscribeOn, publish = publishOn } = ctx.nwcTransport || {};

  // ---- persisted connections -------------------------------------------
  // { id, name, secret (client sk hex), clientPk, servicePk, serviceSk,
  //   maxSat, dailySat, spentToday, spentDate, created, lastUsed, revoked }
  const load = () => wallet.loadFeatureState('nwc', { conns: [] });
  const save = (st) => wallet.saveFeatureState('nwc', st);
  const conns = () => (load().conns || []).filter((c) => !c.revoked);

  function updateConn(id, patch) {
    const st = load();
    const c = (st.conns || []).find((x) => x.id === id);
    if (!c) return null;
    Object.assign(c, patch);
    save(st);
    return c;
  }

  // Budget accounting, reset on date change.
  function spendRoom(c) {
    const today = new Date().toISOString().slice(0, 10);
    const spent = c.spentDate === today ? (c.spentToday || 0) : 0;
    return { today, spent, left: Math.max(0, (c.dailySat || 0) - spent) };
  }
  function recordSpend(c, sat) {
    const { today, spent } = spendRoom(c);
    updateConn(c.id, { spentDate: today, spentToday: spent + sat, lastUsed: Date.now() });
  }

  // The relays advertised in the URI MUST be the ones we listen on, or a
  // client will publish its request somewhere we aren't and wait forever.
  // Deliberately independent of the device-sync relay setting.
  const NWC_RELAYS = ['wss://relay.coinos.io', 'wss://relay.damus.io', 'wss://nos.lol'];
  const relays = () => NWC_RELAYS;

  // The string the user pastes into another app.
  function uriFor(c) {
    const rs = relays().map((r) => `relay=${encodeURIComponent(r)}`).join('&');
    return `nostr+walletconnect://${c.servicePk}?${rs}&secret=${c.secret}`;
  }

  function createConn({ name, maxSat, dailySat }) {
    const st = load();
    st.conns = st.conns || [];
    // A dedicated service key per connection: revoking one can't affect the
    // others, and none of them is the user's own nostr identity.
    const serviceSk = generateSecretKey();
    const clientSk = generateSecretKey();
    const c = {
      id: hex.encode(sha256(new Uint8Array([...serviceSk, ...clientSk]))).slice(0, 12),
      name: name || 'App',
      serviceSk: hex.encode(serviceSk),
      servicePk: getPublicKey(serviceSk),
      secret: hex.encode(clientSk),
      clientPk: getPublicKey(clientSk),
      maxSat: maxSat || 10000,
      dailySat: dailySat || 50000,
      spentToday: 0,
      spentDate: null,
      created: Date.now(),
      revoked: false,
    };
    st.conns.push(c);
    save(st);
    publishInfo(c).catch(() => {});
    listen();
    return c;
  }

  // ---- protocol ---------------------------------------------------------

  async function publishInfo(c) {
    const sk = hex.decode(c.serviceSk);
    const evt = finalizeEvent({
      kind: INFO_KIND,
      created_at: nowSec(),
      tags: [['p', c.clientPk], ['encryption', 'nip44_v2 nip04']],
      content: METHODS.join(' '),
    }, sk);
    return publish(NWC_RELAYS, evt);
  }

  const decrypt = (scheme, sk, pk, ct) => (scheme === 'nip44_v2'
    ? nip44.decrypt(ct, nip44.getConversationKey(sk, pk))
    : nip04.decrypt(sk, pk, ct));
  const encrypt = (scheme, sk, pk, txt) => (scheme === 'nip44_v2'
    ? nip44.encrypt(txt, nip44.getConversationKey(sk, pk))
    : nip04.encrypt(sk, pk, txt));

  // Every request gets a reply, including failures — a client that never
  // hears back just hangs.
  async function reply(c, ev, scheme, payload) {
    const sk = hex.decode(c.serviceSk);
    try {
      const content = await encrypt(scheme, sk, ev.pubkey, JSON.stringify(payload));
      const evt = finalizeEvent({
        kind: RES_KIND,
        created_at: nowSec(),
        tags: [['p', ev.pubkey], ['e', ev.id], ['encryption', scheme]],
        content,
      }, sk);
      await publish(NWC_RELAYS, evt);
    } catch (e) {
      console.warn('nwc: could not reply', e.message);
    }
  }

  const handled = new Set(); // request ids seen this session (replay guard)

  async function onRequest(c, ev) {
    if (ev.kind !== REQ_KIND) return;
    if (handled.has(ev.id)) return;
    handled.add(ev.id);
    if (handled.size > 500) handled.clear();
    if (ev.created_at && nowSec() - ev.created_at > MAX_AGE_SEC) return;
    // only the client this connection was issued to
    if (ev.pubkey !== c.clientPk) return;

    const scheme = ev.tags?.find((x) => x[0] === 'encryption')?.[1] === 'nip44_v2'
      ? 'nip44_v2' : 'nip04';
    let req;
    try {
      req = JSON.parse(await decrypt(scheme, hex.decode(c.serviceSk), ev.pubkey, ev.content));
    } catch { return; } // undecryptable: not for us
    const { method, params = {} } = req || {};
    if (!METHODS.includes(method)) {
      return reply(c, ev, scheme, { result_type: method, ...errRes('NOT_IMPLEMENTED', 'method not supported') });
    }
    updateConn(c.id, { lastUsed: Date.now() });

    try {
      const out = await handle(c, method, params);
      await reply(c, ev, scheme, { result_type: method, ...out });
    } catch (e) {
      await reply(c, ev, scheme, { result_type: method, ...errRes('INTERNAL', e.message || 'failed') });
    }
    render();
  }

  async function handle(c, method, params) {
    if (!hook('arkReady')) return errRes('UNAUTHORIZED', 'Ark is not configured in this wallet');

    if (method === 'get_info') {
      return {
        result: {
          alias: 'Hal', color: '#f7931a', network: getNetwork() === 'mainnet' ? 'mainnet' : getNetwork(),
          block_height: 0, block_hash: '', methods: METHODS,
        },
      };
    }

    if (method === 'get_balance') {
      // NIP-47 reports millisats
      return { result: { balance: (hook('arkSpendableSat') || 0) * 1000 } };
    }

    if (method === 'pay_invoice') {
      const invoice = params.invoice;
      if (!invoice) return errRes('OTHER', 'missing invoice');
      // Enforce limits BEFORE spending anything — an over-budget request must
      // be refused, not paid and then regretted.
      const dec = maybeBolt11(invoice);
      if (!dec) return errRes('OTHER', 'not a bolt11 invoice');
      if (!dec.amountSat) return errRes('OTHER', 'zero-amount invoices are not supported');
      const { left } = spendRoom(c);
      if (dec.amountSat > c.maxSat) {
        return errRes('QUOTA_EXCEEDED', `over the ${c.maxSat} sat per-payment limit`);
      }
      if (dec.amountSat > left) {
        return errRes('QUOTA_EXCEEDED', `over the remaining daily budget (${left} sat)`);
      }
      const res = await hook('arkPayInvoice', invoice, { maxAmountSat: c.maxSat });
      // the ark seam throws on failure, so reaching here means it settled
      recordSpend(c, (res.amountSat || 0) + (res.feeSat || 0));
      return { result: { preimage: res.preimage, fees_paid: (res.feeSat || 0) * 1000 } };
    }

    if (method === 'make_invoice') {
      const sat = Math.floor((params.amount || 0) / 1000);
      if (!sat) return errRes('OTHER', 'amount required (msat)');
      const inv = await hook('arkMakeInvoice', sat, params.description || '');
      return {
        result: {
          type: 'incoming', invoice: inv.invoice, payment_hash: inv.paymentHash,
          amount: sat * 1000, created_at: nowSec(), description: params.description || '',
        },
      };
    }

    if (method === 'list_transactions') {
      const movements = hook('arkMovements') || [];
      const txs = movements
        .filter((m) => ['ln-send', 'ln-receive'].includes(m.type) && m.status === 'complete')
        .slice(-(params.limit || 20))
        .map((m) => ({
          type: m.type === 'ln-receive' ? 'incoming' : 'outgoing',
          invoice: m.invoice || '', preimage: m.preimage || '',
          amount: (m.amountSat || 0) * 1000, fees_paid: 0,
          created_at: Math.floor((m.ts || Date.now()) / 1000),
          settled_at: Math.floor((m.ts || Date.now()) / 1000),
          description: m.detail || '',
        }));
      return { result: { transactions: txs } };
    }

    return errRes('NOT_IMPLEMENTED', 'method not supported');
  }

  // ---- lifecycle --------------------------------------------------------

  let unsubs = [];
  function stop() {
    for (const u of unsubs) { try { u(); } catch {} }
    unsubs = [];
  }
  function listen() {
    stop();
    if (wallet.watchOnly) return;
    const list = conns();
    if (!list.length) return;
    for (const c of list) {
      unsubs.push(subscribe(
        NWC_RELAYS,
        { kinds: [REQ_KIND], '#p': [c.servicePk], since: nowSec() - MAX_AGE_SEC },
        (ev) => { onRequest(c, ev).catch(() => {}); },
      ));
      // Republish the capability event on every start: a client that can't
      // find kind 13194 just spins, and a single publish at creation time can
      // easily have been missed by a relay.
      publishInfo(c).catch(() => {});
    }
  }

  // ---- UI ---------------------------------------------------------------

  function nwcCard() {
    if (!hook('arkReady')) return null;
    const list = conns();
    const st = ui.nwcNew;
    return h('div', { class: 'card col' },
      h('h3', { class: 'row gap6', style: 'align-items:center' }, '🔌', t('nwcTitle')),
      h('p', { class: 'small muted', style: 'margin:0' }, t('nwcDesc')),
      h('div', { class: 'small faint' }, t('nwcTabWarning')),
      ...list.map((c) => {
        const { spent } = spendRoom(c);
        return h('div', { class: 'col', style: 'gap:4px;border-top:1px solid var(--border,rgba(128,128,128,.2));padding-top:8px' },
          h('div', { class: 'row between' },
            h('span', {}, c.name),
            h('span', { class: 'linklike small', onClick: () => {
              updateConn(c.id, { revoked: true }); listen(); render();
              toast(t('nwcRevoked', { name: c.name }));
            } }, t('nwcRevoke'))),
          h('div', { class: 'small faint' },
            t('nwcLimits', { max: fmtAmount(c.maxSat), day: fmtAmount(c.dailySat), spent: fmtAmount(spent) })),
          ui.nwcShow === c.id
            ? h('div', { class: 'col', style: 'gap:6px;align-items:center' },
                h('div', { html: qrSvg(uriFor(c)) }),
                h('div', { class: 'addr-box break', style: 'width:100%;font-size:10px' }, uriFor(c)),
                copyBtn(uriFor(c), t('nwcCopy')))
            : h('button', { class: 'btn-sm', onClick: () => { ui.nwcShow = c.id; render(); } }, t('nwcShow')));
      }),
      st
        ? h('div', { class: 'col', style: 'gap:6px;border-top:1px solid var(--border,rgba(128,128,128,.2));padding-top:8px' },
            h('input', { type: 'text', placeholder: t('nwcAppName'), value: st.name,
              onInput: (e) => { st.name = e.target.value; } }),
            h('label', { class: 'field' }, h('span', { class: 'lab' }, t('nwcMaxPayment')),
              h('input', { type: 'number', min: '1', value: st.maxSat,
                onInput: (e) => { st.maxSat = e.target.value; } })),
            h('label', { class: 'field' }, h('span', { class: 'lab' }, t('nwcDailyBudget')),
              h('input', { type: 'number', min: '1', value: st.dailySat,
                onInput: (e) => { st.dailySat = e.target.value; } })),
            h('div', { class: 'row gap6' },
              h('button', { class: 'btn-ghost', onClick: () => { ui.nwcNew = null; render(); } }, t('cancel')),
              h('button', { class: 'btn-primary grow', onClick: () => {
                const c = createConn({
                  name: st.name, maxSat: parseInt(st.maxSat, 10) || 10000,
                  dailySat: parseInt(st.dailySat, 10) || 50000,
                });
                ui.nwcNew = null; ui.nwcShow = c.id; render();
              } }, t('nwcCreate'))))
        : h('button', { class: 'btn-ghost btn-block', onClick: () => {
            ui.nwcNew = { name: '', maxSat: '10000', dailySat: '50000' }; render();
          } }, t('nwcAdd')));
  }

  return {
    id: 'nwc',
    init() { listen(); },
    stop() { stop(); },
    settingsCards() { return [nwcCard()]; },
  };
}

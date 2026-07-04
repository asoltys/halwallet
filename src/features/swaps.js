// Lightning swaps feature (Boltz reverse/submarine) — receive over LN,
// pay bolt11 invoices, provider settings. Extracted from app.js; the
// protocol layer lives in ../swap.js.

import { SwapManager } from '../swap.js';
import { getNetwork, getBoltzApi, BOLTZ_PRESETS, getBoltzProviderId, setBoltzProviderId, getBoltzCustom, setBoltzCustom } from '../api.js';
import { t } from '../i18n.js';
import { qrSvg } from '../qr.js';
import { fmtBtc } from '../format.js';

// A bolt11 Lightning invoice (any network prefix); long ln-prefixed bech32 string.
function isLnInvoice(v) { v = (v || '').trim(); return /^ln[a-z0-9]+$/i.test(v) && v.length > 50; }

export function swapsFeature(ctx) {
  const { h, ui, render, wallet, blankSend, fmtAmount, unitLabel, copyBtn } = ctx;

  // Boltz swap orchestrator (reverse = receive over LN, submarine = spend over LN).
  const swaps = new SwapManager({
    wallet, network: getNetwork(), getApi: getBoltzApi,
    feeRate: 2, onUpdate: () => render(),
  });

  function lnReceiveContent() {
    if (!ui.swapLimits && !ui._swapLimitsLoading) {
      ui._swapLimitsLoading = true;
      swaps.reverseLimits().then((l) => { ui.swapLimits = l; ui._swapLimitsLoading = false; render(); }).catch(() => { ui._swapLimitsLoading = false; });
    }
    const lim = ui.swapLimits;
    let rec = ui.lnReceiveId ? swaps.list().find((s) => s.id === ui.lnReceiveId) : null;
    if (rec && ['claimed', 'success'].includes(rec.status)) {
      // Claimed — the coin is credited on-chain (swap.js → creditReceive), so the
      // generic "Payment received!" celebration shows it like any receive. Just
      // reset the Lightning flow back to its form.
      ui.lnReceiveId = null;
      rec = null;
    }
    if (rec) {
      let svg = null;
      try { svg = qrSvg(rec.invoice.toUpperCase(), { ec: 'L', mode: 'Alphanumeric' }); } catch {}
      return [
        h('p', { class: 'small muted', style: 'margin:0;text-align:center' }, t('lnReceiveAwaiting')),
        svg ? h('div', { html: svg }) : null,
        h('div', { class: 'addr-box break', style: 'width:100%;font-size:11px' }, rec.invoice),
        copyBtn(rec.invoice, t('copyInvoice')),
        h('div', { class: 'row gap6', style: 'align-items:center' }, h('span', { class: 'spinner sm' }), h('span', { class: 'small muted' }, t('lnReceiveWatching'))),
        h('button', { class: 'btn-ghost btn-block', onClick: () => { ui.lnReceiveId = null; ui.swapReverseAmt = ''; ui.swapError = ''; render(); } }, t('back')),
      ];
    }
    return [
      h('p', { class: 'small muted', style: 'margin:0;text-align:center' }, t('lnReceiveIntro')),
      h('label', { class: 'field', style: 'width:100%' },
        h('span', { class: 'lab' }, t('amountSatsLabel')),
        h('input', { type: 'number', inputmode: 'numeric', placeholder: '', value: ui.swapReverseAmt || '', onInput: (e) => { ui.swapReverseAmt = e.target.value; } }),
        lim ? h('span', { class: 'small muted' }, `Min ${lim.min.toLocaleString()} · max ${lim.max.toLocaleString()} sats`) : null),
      ui.swapError ? h('div', { class: 'notice err' }, ui.swapError) : null,
      h('button', { class: 'btn-primary btn-block', disabled: !!ui.swapBusy, onClick: doReverse }, ui.swapBusy ? h('span', { class: 'spinner' }) : t('lnCreateInvoice')),
    ];
  }

  async function doReverse() {
    const amt = parseInt((ui.swapReverseAmt || '').trim(), 10);
    const lim = ui.swapLimits || (ui.swapLimits = await swaps.reverseLimits());
    if (!amt || amt < lim.min || amt > lim.max) { ui.swapError = `Enter ${lim.min.toLocaleString()}–${lim.max.toLocaleString()} sats`; return render(); }
    ui.swapError = ''; ui.swapBusy = true; render();
    try { const rec = await swaps.startReverse(amt); ui.lnReceiveId = rec.id; ui.swapReverseAmt = ''; }
    catch (e) { ui.swapError = e.message; }
    ui.swapBusy = false; render();
  }

  async function doRefund(id) {
    ui.swapError = ''; ui.swapBusy = true; render();
    try { await swaps.refundSubmarine(id); }
    catch (e) { ui.swapError = e.message; }
    ui.swapBusy = false; render();
  }

  function boltzProviderCard() {
    const id = getBoltzProviderId();
    const custom = getBoltzCustom();
    return h(
      'div',
      { class: 'card col' },
      h('h3', {}, '⚡ Swap provider'),
      h('p', { class: 'small muted', style: 'margin:0' }, 'Boltz-compatible provider for Lightning swaps. Non-custodial: a provider can fail a swap but never take your funds.'),
      h('select', { onChange: (e) => { setBoltzProviderId(e.target.value); ui.swapLimits = null; render(); } },
        BOLTZ_PRESETS.map((p) => h('option', { value: p.id, selected: p.id === id }, p.label))),
      id === 'custom'
        ? h('div', { class: 'col', style: 'gap:8px' },
            h('label', { class: 'field' },
              h('span', { class: 'lab' }, 'API URL'),
              h('input', {
                type: 'text', class: 'mono-input', placeholder: 'https://api.example.com',
                autocapitalize: 'none', autocomplete: 'off', spellcheck: 'false', value: custom.api,
                onChange: (e) => { setBoltzCustom({ api: e.target.value.trim(), ws: custom.ws }); ui.swapLimits = null; render(); },
              })),
            h('label', { class: 'field' },
              h('span', { class: 'lab' }, 'WebSocket URL (optional)'),
              h('input', {
                type: 'text', class: 'mono-input', placeholder: 'wss://api.example.com/v2/ws',
                autocapitalize: 'none', autocomplete: 'off', spellcheck: 'false', value: custom.ws,
                onChange: (e) => { setBoltzCustom({ api: custom.api, ws: e.target.value.trim() }); render(); },
              }),
              h('div', { class: 'small faint' }, 'Left blank, the WS is derived from the API URL.')))
        : h('div', { class: 'small faint', style: 'word-break:break-all' }, getBoltzApi())
    );
  }

  function swapTxDetailSection(swap, tx) {
    const u = ' ' + unitLabel();
    const line = (k, v) => h('div', { class: 'line' }, h('span', { class: 'k' }, k), h('span', { class: 'v' }, v));
    const head = (txt) => h('div', { style: 'font-weight:600;margin:12px 0 2px' }, txt);
    if (swap.refundTxid === tx.txid)
      return h('div', { class: 'summary col', style: 'gap:0' }, head('↩ Lightning swap refund'), line(t('status'), 'Refunded ✓'));
    if (swap.kind === 'submarine') {
      const fee = (swap.expectedAmount || 0) - (swap.invoiceAmount || 0);
      const st = swap.status === 'success' ? 'Invoice paid ✓'
        : swap.status === 'refundable' ? 'Payment failed — refundable'
        : swap.status === 'refunded' ? 'Refunded' : 'Paying…';
      return h('div', { class: 'summary col', style: 'gap:0' },
        head('⚡ Paid over Lightning'),
        swap.invoiceAmount != null ? line('Invoice', fmtAmount(swap.invoiceAmount) + u) : null,
        fee > 0 ? line('Swap fee', fmtAmount(fee) + u) : null,
        line(t('status'), st),
        swap.status === 'refundable'
          ? h('button', { class: 'btn-sm btn-block', style: 'margin-top:8px', disabled: !!ui.swapBusy, onClick: () => doRefund(swap.id) }, 'Refund on-chain')
          : null);
    }
    // reverse swap claim
    return h('div', { class: 'summary col', style: 'gap:0' },
      head('⚡ Received over Lightning'),
      line(t('status'), swap.status === 'claimed' ? 'Settled ✓' : swap.status));
  }

  async function startLnSend(invoice) {
    ui.sendError = ''; ui.lnSend = null; ui.lnSent = null; ui.lnSendBusy = true; render();
    try { ui.lnSend = await swaps.quoteSubmarine(invoice); }
    catch (e) { ui.sendError = e.message; }
    ui.lnSendBusy = false; render();
  }

  async function doLnPay() {
    if (!ui.lnSend) return;
    ui.sendError = ''; ui.lnSendBusy = true; render();
    try { const rec = await swaps.fundQuotedSubmarine(ui.lnSend); ui.lnSent = { amount: ui.lnSend.invoiceAmount, id: rec.id }; }
    catch (e) { ui.sendError = e.message; }
    ui.lnSendBusy = false; render();
  }

  function lnSendReview() {
    const u = ' ' + unitLabel();
    if (ui.lnSent) {
      return h('div', { class: 'col', style: 'gap:16px' },
        h('div', { class: 'card col', style: 'align-items:center;text-align:center;gap:8px' },
          h('div', { class: 'check-badge' }, '⚡'),
          h('h2', { style: 'margin:0' }, t('lnPaySentTitle')),
          ui.lnSent.amount ? h('div', { class: 'amount-pos', style: 'font-size:18px' }, fmtAmount(ui.lnSent.amount) + u) : null,
          h('p', { class: 'muted', style: 'margin:0' }, t('lnPaySentBody'))),
        h('button', { class: 'btn-primary btn-block', onClick: () => { ui.lnSent = null; ui.lnSend = null; ui.send = blankSend(); ui.tab = 'history'; render(); } }, t('done')));
    }
    const q = ui.lnSend;
    const row = (label, sats, bold) => h('div', { class: 'row', style: 'justify-content:space-between' + (bold ? ';font-weight:600' : '') },
      h('span', { class: bold ? '' : 'small muted' }, label), h('span', {}, fmtAmount(sats) + u));
    return h('div', { class: 'col', style: 'gap:12px' },
      h('div', { class: 'card col', style: 'gap:10px' },
        h('h3', { style: 'margin:0' }, t('lnPayTitle')),
        q.invoiceAmount != null ? row(t('lnPayAmount'), q.invoiceAmount) : null,
        q.boltzFee != null ? row(t('lnPayBoltzFee'), q.boltzFee) : null,
        row(t('lnPayNetworkFee'), q.networkFee),
        h('div', { style: 'border-top:1px solid var(--line, #ddd);margin:2px 0' }),
        row(t('lnPayTotal'), q.total, true)),
      ui.sendError ? h('div', { class: 'notice err' }, ui.sendError) : null,
      h('button', { class: 'btn-primary btn-block', disabled: !!ui.lnSendBusy, onClick: doLnPay }, ui.lnSendBusy ? h('span', { class: 'spinner' }) : t('lnPayConfirm')),
      h('button', { class: 'btn-ghost btn-block', onClick: () => { ui.lnSend = null; ui.sendError = ''; render(); } }, t('back')));
  }

  return {
    id: 'swaps',
    // wallet activated: re-attach in-flight swap watchers
    init() {
      swaps.network = getNetwork();
      if (!wallet.watchOnly) { try { swaps.resumeAll(); } catch {} }
    },
    networkChanged(net) { swaps.network = net; ui.swapLimits = null; },
    receiveModes() {
      // a reverse swap needs our keys to claim on-chain
      if (wallet.watchOnly) return [];
      return [{
        id: 'ln', label: t('receiveLnTab'),
        render: (seg) => h('div', { class: 'card col', style: 'align-items:center;gap:14px' }, seg, ...lnReceiveContent()),
      }];
    },
    // a pasted/typed/scanned bolt11 auto-advances to its own confirmation
    matchSendText(text) {
      const inv = (text || '').trim().replace(/^lightning:/i, '');
      if (ui.send.recipients.length === 1 && !ui.lnSendBusy && !ui.lnSend && isLnInvoice(inv)) {
        startLnSend(inv);
        return true;
      }
      return false;
    },
    interceptReview(s) {
      const target = s.recipients.length === 1 ? (s.recipients[0].address || '').trim().replace(/^lightning:/i, '') : '';
      if (isLnInvoice(target)) { startLnSend(target); return true; }
      return false;
    },
    sendView() {
      if (ui.lnSent || ui.lnSend) return lnSendReview();
      if (ui.lnSendBusy) return h('div', { class: 'card col', style: 'align-items:center;gap:14px;padding:32px 14px' }, h('span', { class: 'spinner' }), h('p', { class: 'muted', style: 'margin:0' }, t('lnQuoting')));
      return null;
    },
    txDetailSection(tx) {
      const swap = swaps.findByTxid(tx.txid);
      return swap ? swapTxDetailSection(swap, tx) : null;
    },
    findByTxid(txid) { return swaps.findByTxid(txid); },
    settingsCards() { return [boltzProviderCard()]; },
  };
}

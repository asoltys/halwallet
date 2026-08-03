// NIP-57 Lightning zaps — pay an npub / lightning address / lnurl over
// Lightning, attaching a signed zap request so the recipient's server posts a
// public zap receipt. This feature only does the *resolution* half (target →
// LNURL params → signed request → bolt11); the actual payment reuses the swaps
// feature's Boltz submarine flow via the `startLnPay` hook, so there's one
// tested LN pay/review/confirm/success path.
//
// Routing (see features/index.js order): a bolt11 is caught by swaps first; an
// npub is caught by ark first (an instant free Ark zap) when Ark is available,
// and only reaches here otherwise — plus ark's "no Ark address" screen hands
// off to us explicitly via the lnZapNpub hook. Lightning addresses and lnurls
// land here directly.

import { t } from '../i18n.js';
import { npubOf } from '../nostr.js';
import { parseZapTarget, zapTargetFromProfile, fetchPayParams, buildZapRequest, requestInvoice } from '../lnurl.js';

export function zapsFeature(ctx) {
  const { h, ui, render, wallet, blankSend, parseAmount, getUnit, unitTag, hook } = ctx;

  // Lightning payment has to be possible for a zap to make sense.
  const canPay = () => !wallet.watchOnly && !!hook('canLnPay');

  const shortNpub = (npub) => (npub && npub.length > 16 ? npub.slice(0, 12) + '…' + npub.slice(-6) : npub);

  // Kick off resolution of a parsed target. `display` is what we show as the
  // recipient until a profile name arrives.
  function begin(target, display) {
    ui.arkZap = null; ui.arkZapped = null; // in case we were handed off from ark
    ui.sendError = '';
    const z = (ui.zap = { status: 'resolving', target, name: display, address: target.address || null, amount: '', comment: '' });
    render();
    resolve(z).catch((e) => { if (ui.zap === z) { z.status = 'error'; z.error = e.message; render(); } });
  }

  async function resolve(z) {
    let target = z.target;
    // An npub needs a profile lookup to find its lud16/lud06.
    if (target.kind === 'npub') {
      const profile = await wallet.nostrProfile(target.pk);
      if (profile && profile.name) z.name = profile.name;
      const lnTarget = zapTargetFromProfile(profile, target.pk);
      if (!lnTarget) { z.status = 'error'; z.error = t('lnZapNoAddress'); render(); return; }
      z.target = target = lnTarget;
      z.address = lnTarget.address || z.address;
    }
    const params = await fetchPayParams(target.url);
    if (ui.zap !== z) return; // user navigated away
    z.params = params;
    z.status = 'ready';
    render();
  }

  async function confirm() {
    const z = ui.zap;
    if (!z || z.status !== 'ready') return;
    const sats = parseAmount(z.amount, getUnit());
    const p = z.params;
    if (!sats || sats <= 0) { z.error = t('enterValidAmtForN', { n: 1 }); return render(); }
    const msat = sats * 1000;
    if (msat < p.minSendable || msat > p.maxSendable) {
      z.error = t('lnZapRange', { min: Math.ceil(p.minSendable / 1000).toLocaleString(), max: Math.floor(p.maxSendable / 1000).toLocaleString() });
      return render();
    }
    z.error = ''; z.status = 'invoicing'; render();
    try {
      // Attribute a real zap only when the server supports it and we know the
      // recipient's nostr key; otherwise fall back to a plain LNURL-pay.
      let zapRequest = null;
      const canZap = p.allowsNostr && z.target.pk && wallet.nostrSign;
      if (canZap) {
        zapRequest = buildZapRequest({
          amountMsat: msat, relays: wallet.nostrRelays(), lnurlBech32: z.target.lnurlBech32,
          recipientPk: z.target.pk, comment: z.comment, signFn: (partial) => wallet.nostrSign(partial),
        });
      }
      const invoice = await requestInvoice(p, { amountMsat: msat, zapRequest, lnurlBech32: z.target.lnurlBech32, comment: z.comment });
      const meta = { name: z.name, address: z.address, pk: z.target.pk || null, comment: canZap ? z.comment : '', isZap: !!zapRequest };
      ui.zap = null;
      // Hand the bolt11 to the swaps feature's pay flow (review → confirm).
      hook('startLnPay', invoice, meta);
      render();
    } catch (e) {
      z.status = 'ready'; z.error = e.message; render();
    }
  }

  function zapView() {
    const z = ui.zap;
    if (!z) return null;
    const back = () => { ui.zap = null; ui.sendError = ''; ui.send = blankSend(); render(); };
    if (z.status === 'resolving' || z.status === 'invoicing') {
      return h('div', { class: 'card col', style: 'align-items:center;gap:14px;padding:32px 14px' },
        h('span', { class: 'spinner' }),
        h('p', { class: 'muted', style: 'margin:0' }, z.status === 'invoicing' ? t('lnZapRequesting') : t('lnZapResolving')));
    }
    if (z.status === 'error') {
      return h('div', { class: 'card col', style: 'gap:12px' },
        h('h3', {}, '⚡ ' + t('lnZapTitle')),
        h('div', { class: 'small muted', style: 'word-break:break-all' }, z.name || ''),
        h('div', { class: 'notice err' }, z.error || t('lnZapFailed')),
        h('button', { class: 'btn-ghost btn-block', onClick: back }, t('back')));
    }
    // ready: amount + optional comment
    const p = z.params;
    const min = Math.ceil(p.minSendable / 1000), max = Math.floor(p.maxSendable / 1000);
    const commentOk = p.allowsNostr || p.commentAllowed > 0;
    return h('div', { class: 'card col', style: 'gap:12px' },
      h('h3', {}, '⚡ ' + t('lnZapTitle')),
      h('div', { class: 'small muted', style: 'word-break:break-all' }, z.name || z.address || ''),
      h('div', { class: 'col gap6' },
        h('div', { class: 'input-group' },
          h('input', { type: 'number', min: '0', inputmode: 'decimal', placeholder: t('lnPayAmount'), value: z.amount,
            onInput: (e) => { z.amount = e.target.value; } }),
          h('div', { style: 'display:flex;align-items:center' }, unitTag())),
        h('div', { class: 'small faint' }, `Min ${min.toLocaleString()} · max ${max.toLocaleString()} sats`),
        commentOk
          ? h('input', { type: 'text', class: 'mono-input', placeholder: t('arkZapCommentPh'), value: z.comment,
              maxlength: p.allowsNostr ? '280' : String(p.commentAllowed || 280),
              onInput: (e) => { z.comment = e.target.value; } })
          : null,
        h('div', { class: 'small faint' }, p.allowsNostr ? t('lnZapHintNostr') : t('lnZapHintPlain'))),
      z.error ? h('div', { class: 'notice err' }, z.error) : null,
      h('div', { class: 'row gap6' },
        h('button', { class: 'btn-ghost', onClick: back }, t('back')),
        h('button', { class: 'btn-primary grow', onClick: confirm }, t('arkZapBtn'))));
  }

  return {
    id: 'zaps',
    // A lightning address / lnurl (always), or an npub that Ark didn't claim.
    matchSendText(text, typed) {
      if (!canPay() || !ui.send || ui.send.recipients.length !== 1) return false;
      const target = parseZapTarget(text);
      if (!target) return false;
      // npub with no nostr seam to look up a profile → can't resolve here.
      if (target.kind === 'npub' && !wallet.nostrProfile) return false;
      // A TYPED lightning address matches mid-keystroke (`a@b.co` before the
      // user finishes `.com`), so never auto-advance while typing — the send
      // form offers a zap button via sendFormNote instead. Pasted/scanned
      // text is complete and advances immediately; npub/lnurl carry a bech32
      // checksum and only ever match when complete.
      if (typed && target.kind === 'lnaddr') return false;
      const display = target.kind === 'npub' ? shortNpub(npubOf(target.pk) || text.trim()) : (target.address || text.trim());
      begin(target, display);
      return true;
    },
    // The typed-lightning-address affordance on the send form.
    sendFormNote(a) {
      if (!canPay() || !ui.send || ui.send.recipients.length !== 1) return null;
      const target = parseZapTarget(a);
      if (!target || target.kind === 'npub') return null;
      const display = target.address || String(a || '').trim();
      return h('button', {
        type: 'button', class: 'btn-primary btn-block',
        onClick: () => begin(target, display),
      }, '⚡ ' + t('lnZapOffer', { addr: display }));
    },
    // The names feature resolves user@domain over DNS first (BIP-353) and
    // lands here when the name has no DNS record — the classic LNURL path.
    lnAddressFallback(text) {
      if (!canPay() || !ui.send || ui.send.recipients.length !== 1) return false;
      const target = parseZapTarget(text);
      if (!target || target.kind === 'npub') return false;
      begin(target, target.address || String(text).trim());
      return true;
    },
    // True when an npub can be zapped over Lightning from this build/wallet —
    // ark's "no Ark address" screen checks this before offering the fallback.
    canLnZap() { return canPay() && !!wallet.nostrProfile; },
    // Ark's "no Ark address published" screen offers a Lightning fallback,
    // which lands here with the recipient's pubkey.
    lnZapNpub(pk, npub) {
      if (!canPay() || !wallet.nostrProfile) return false;
      begin({ kind: 'npub', pk }, shortNpub(npub || npubOf(pk)));
      return true;
    },
    sendView() { return zapView(); },
  };
}

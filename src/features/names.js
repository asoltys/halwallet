// Payment names — BIP-353 DNS payment instructions.
//
// Receiving: claim ₿name@halwallet.app. The claim is signed with the wallet's
// nostr key and the registrar publishes a DNSSEC-signed TXT record whose
// BIP-21 URI carries this wallet's (reusable) ark address. The name follows
// the wallet: if the ark address changes (new ASP), the record re-registers
// itself on the next open. Users with their own domain point a single CNAME
// at our record and their name verifies just the same.
//
// Sending: paste name@domain (or ₿name@domain) and it resolves over DNS
// first — an ark= instruction pays natively over Ark; a name with no BIP-353
// record falls back to the Lightning-address flow (zaps feature).

import { resolveBip353, parsePaymentName, parseBip21 } from '../bip353.js';
import { nip98Header } from '../nostr-login.js';
import { qrSvg } from '../qr.js';
import { isArkAddress } from './ark.js';
import { getNetwork } from '../api.js';
import { t } from '../i18n.js';

const REGISTRAR = 'https://names.coinos.io';
const DOMAIN = 'coinos.io';
const AUTH_KIND = 21353;

export function namesFeature(ctx) {
  const { h, ui, render, wallet, hook, toast, copyBtn } = ctx;

  // The wallet's own key signs registrar requests: it's the one key that is
  // always available — offline, in the background, with no signer attached.
  const walletSigner = () => ({
    pubkey: wallet.nostrPubkey && wallet.nostrPubkey(),
    signEvent: async (e) => wallet.nostrSign(e),
  });

  // Nothing here may hang: a stuck signer prompt or a dead endpoint must
  // surface as an error, not as a spinner that never stops.
  const withTimeout = (p, ms, what) => Promise.race([
    p, new Promise((_, rej) => setTimeout(() => rej(new Error(`${what} timed out`)), ms)),
  ]);

  async function post(path, method, payload, signer) {
    const url = `${REGISTRAR}${path}`;
    const hasBody = method !== 'GET';
    const body = hasBody ? JSON.stringify(payload) : '';
    const auth = await withTimeout(nip98Header(signer || walletSigner(), url, method, body), 12000, 'signing');
    const r = await withTimeout(fetch(url, {
      method, headers: { 'content-type': 'application/json', authorization: auth }, ...(hasBody ? { body } : {}),
    }), 12000, 'registrar');
    const j = await r.json().catch(() => ({}));
    if (!r.ok || j.error) throw new Error(j.error || `registrar refused (${r.status})`);
    return j;
  }

  const load = () => wallet.loadFeatureState('names', {});
  const save = (st) => wallet.saveFeatureState('names', st);

  const available = () => getNetwork() === 'mainnet' && !wallet.watchOnly
    && !!wallet.nostrSign && !!hook('arkReady');

  async function currentUri() {
    const addr = await withTimeout(hook('arkStaticAddress'), 12000, 'ark');
    return addr ? `bitcoin:?ark=${encodeURIComponent(addr)}` : null;
  }

  async function claim(name, { signer, manager } = {}) {
    const uri = await currentUri();
    if (!uri) throw new Error(t('namesNeedArk'));
    const j = await post('/register', 'POST', {
      name, uri, domain: DOMAIN,
      // lets the address take Lightning payments from LNURL-only wallets:
      // the registrar asks this key for an invoice before minting its own
      ...(hook('nwcOfferPubkey') ? { offerPk: hook('nwcOfferPubkey') } : {}),
      // when the login identity claims its own npub name, it nominates the
      // wallet key to keep the record updated afterwards
      ...(manager ? { manager } : {}),
    }, signer);
    const prev = load().name;
    save({ name, domain: DOMAIN, uri, offerPk: hook('nwcOfferPubkey') || null, updated: Date.now() });
    if (prev && prev !== name) {
      post('/register', 'DELETE', { name: prev, domain: DOMAIN }).catch(() => {});
    }
    return j;
  }

  async function release() {
    const st = load();
    if (!st.name) return;
    await post('/register', 'DELETE', { name: st.name, domain: st.domain || DOMAIN }).catch(() => {});
    save({});
  }

  // An imported seed (or a new browser) doesn't know its username — the
  // registrar does. Ask by the wallet's nostr pubkey and adopt the answer
  // before deciding whether anything needs claiming.
  async function lookupMine() {
    try {
      const pk = wallet.nostrPubkey && wallet.nostrPubkey();
      if (!pk) return;
      const r = await withTimeout(
        fetch(`${REGISTRAR}/pubkey/${pk}`).then((x) => x.json()), 12000, 'registrar');
      if (r && r.name) save({ ...load(), name: r.name, domain: r.domain || DOMAIN, uri: r.uri });
    } catch (e) { console.warn('names: lookup failed —', e.message); }
  }

  // Everyone gets an address without being asked: the default username is a
  // prefix of the wallet's npub — unique, boring, and free. Custom names are
  // an optional change (and may cost something one day, to keep squatters
  // out), so nothing here ever blocks the wallet.
  let checked = false;   // setup finished (the pane waits on this)
  let retryTimer = null;
  let deadline = null;
  let lastError = null;
  async function refresh(attempt = 0) {
    clearTimeout(retryTimer);
    // Whatever goes wrong, stop claiming to be "setting up" after a minute
    // and show the user the manual form instead.
    if (!deadline) {
      deadline = setTimeout(() => { checked = true; clearTimeout(retryTimer); render(); }, 12000);
    }
    try {
      if (!available()) {
        // Ark connects lazily AFTER the wallet opens, so the first pass
        // usually lands too early. Keep looking for a while rather than
        // giving up and leaving the user staring at a claim box.
        if (attempt < 40) { retryTimer = setTimeout(() => refresh(attempt + 1), 3000); return; }
        checked = true; render(); return;
      }
      let st = load();
      if (!st.name) { await lookupMine(); st = load(); }
      if (!st.name) {
        // The address people see should be the identity they know the user
        // by: their real npub when a nostr account is linked, else the
        // wallet's own. Claiming the real one has to be SIGNED by that
        // identity (the registrar won't let anyone else take an npub-shaped
        // name), so it needs a live signer — after a reload an extension can
        // usually be re-attached silently; anything else falls back to the
        // wallet's own identity rather than retrying a claim that can only
        // ever fail.
        // Claim with the WALLET's own key: it needs no signer, prompts
        // nobody, and always works. Tying the address to the user's real
        // npub happens at login instead (adoptIdentity below), where a
        // signer is already live — an address must never wait on a popup.
        const own = wallet.nostrNpub && wallet.nostrNpub();
        if (own) { await claim(own.slice(0, 12), {}); st = load(); }
      }
      checked = true;
      clearTimeout(deadline); deadline = null;
      render();
      if (!st.name) return;
      const uri = await currentUri();
      // Re-publish when the address changed OR when the registrar doesn't yet
      // know this wallet's offer key — that key is what lets an incoming
      // Lightning payment be delivered straight to us instead of waiting on
      // the operator's float.
      const offerPk = hook('nwcOfferPubkey') || null;
      if (uri && (uri !== st.uri || (offerPk && st.offerPk !== offerPk))) await claim(st.name);
    } catch (e) {
      console.warn('names: refresh failed —', e.message);
      lastError = e.message;
      if (attempt < 3) { retryTimer = setTimeout(() => refresh(attempt + 1), 4000); return; }
      checked = true;
      render();
    }
  }

  // Called right after a nostr login, while that signer is definitely live:
  // move the payment address onto the user's real npub and nominate the
  // wallet key to keep the record updated afterwards.
  async function adoptIdentity(signer, npub) {
    if (!signer || !npub || !available()) return null;
    const name = npub.slice(0, 12);
    if (load().name === name) return name;
    await claim(name, { signer, manager: wallet.nostrPubkey() });
    render();
    return name;
  }

  // ---- sending to a name -------------------------------------------------

  function beginResolve(text) {
    const parsed = parsePaymentName(text);
    if (!parsed) return false;
    ui.nameResolve = { text, status: 'resolving' };
    render();
    (async () => {
      let uri = null;
      try { uri = await resolveBip353(parsed.name, parsed.domain); } catch (e) {
        if (ui.nameResolve?.text !== text) return;
        ui.nameResolve = null;
        ui.sendError = `${parsed.name}@${parsed.domain}: ${e.message}`;
        render();
        return;
      }
      if (ui.nameResolve?.text !== text) return;
      ui.nameResolve = null;
      if (uri) {
        const dec = parseBip21(uri);
        const ark = dec?.params?.ark;
        if (ark && isArkAddress(ark) && hook('arkReady')) {
          ui.send.recipients[0].address = ark;
          render();
          return;
        }
        if (dec?.onchain) {
          ui.send.recipients[0].address = dec.onchain;
          render();
          return;
        }
        ui.sendError = t('namesNoUsableInstruction');
        render();
        return;
      }
      // no BIP-353 record: hand off to the Lightning-address flow
      if (!hook('lnAddressFallback', text)) {
        ui.sendError = t('namesNotFound', { name: `${parsed.name}@${parsed.domain}` });
      }
      render();
    })();
    return true;
  }

  // ---- UI ---------------------------------------------------------------

  function claimForm(big) {
    return h('div', { class: 'col', style: 'gap:8px;width:100%' },
      ui.nameClaimError ? h('div', { class: 'notice err' }, ui.nameClaimError) : null,
      h('div', { class: 'row gap6' },
        h('input', {
          type: 'text', placeholder: t('namesPlaceholder'), style: 'flex:1' + (big ? ';font-size:18px' : ''),
          autocapitalize: 'none', autocomplete: 'off', spellcheck: 'false',
          value: ui.nameClaim || '',
          onInput: (e) => { ui.nameClaim = e.target.value.toLowerCase().trim(); },
        }),
        h('span', { class: 'muted', style: 'align-self:center' }, '@' + DOMAIN)),
      h('button', { class: 'btn-primary btn-block', disabled: ui.busy, onClick: async () => {
        const name = (ui.nameClaim || '').toLowerCase().trim();
        if (!name) return;
        ui.busy = true; ui.nameClaimError = null; render();
        try {
          await claim(name);
          ui.nameClaim = '';
          toast(t('namesClaimed', { name: `${name}@${DOMAIN}` }));
        } catch (e) { ui.nameClaimError = e.message; }
        ui.busy = false; render();
      } }, ui.busy ? h('span', { class: 'spinner' }) : t('namesClaim')));
  }

  function namesCard() {
    if (!available()) return null;
    const st = load();
    if (st.name) {
      const addr = `${st.name}@${st.domain || DOMAIN}`;
      return h('div', { class: 'card col' },
        h('h3', {}, t('namesTitle')),
        h('div', { class: 'addr-box break', style: 'font-size:14px' }, addr),
        h('div', { class: 'row gap6' },
          copyBtn(`${st.name}@${st.domain || DOMAIN}`, t('namesCopy')),
          h('button', { class: 'btn-ghost btn-sm', onClick: async () => {
            await release(); toast(t('namesReleased')); render();
          } }, t('namesRelease'))),
        h('details', { class: 'small faint' },
          h('summary', {}, t('namesCustom')),
          h('p', { style: 'margin:4px 0' }, t('namesCustomHow')),
          claimForm(false)),
        (() => {
          const code = hook('nwcOfferString');
          return code ? h('details', { class: 'small faint' },
            h('summary', {}, t('namesZapCode')),
            h('p', { style: 'margin:4px 0' }, t('namesZapCodeHow')),
            h('div', { class: 'addr-box break', style: 'font-size:10px' }, code),
            copyBtn(code, t('namesZapCodeCopy'))) : null;
        })(),
        h('details', { class: 'small faint' },
          h('summary', {}, t('namesOwnDomain')),
          h('p', { style: 'margin:4px 0' }, t('namesOwnDomainHow')),
          h('div', { class: 'addr-box break', style: 'font-size:11px' },
            `${st.name}.user._bitcoin-payment.yourdomain.com. CNAME ${st.name}.user._bitcoin-payment.${st.domain || DOMAIN}.`)));
    }
    return h('div', { class: 'card col' },
      h('h3', {}, t('namesTitle')),
      h('p', { class: 'small muted', style: 'margin:0' }, t('namesDesc')),
      claimForm(false));
  }

  // The Receive tab's default pane: your name, big and scannable.
  function namePane(seg) {
    const st = load();
    if (!st.name && !checked) {
      return h('div', { class: 'card col', style: 'align-items:center;gap:10px' },
        seg, h('span', { class: 'spinner' }),
        h('div', { class: 'small muted' }, t('namesSettingUp')));
    }
    if (!st.name) {
      return h('div', { class: 'card col', style: 'gap:10px' },
        seg,
        lastError ? h('div', { class: 'notice err small' }, t('namesAutoFailed', { why: lastError })) : null,
        h('p', { class: 'small muted', style: 'margin:0' }, t('namesDesc')),
        claimForm(false));
    }
    const addr = `${st.name}@${st.domain || DOMAIN}`;
    return h('div', { class: 'card col', style: 'align-items:center;gap:14px' },
      seg,
      h('div', { html: qrSvg(addr) }),
      h('div', { class: 'addr-box', style: 'width:100%;text-align:center;font-size:16px' }, addr),
      copyBtn(addr, t('namesCopy')),
      offerSection());
  }

  // ---- BOLT 12 offers with a memo ----------------------------------------
  // A reusable offer some payers want instead of a lightning address (mining
  // pools like Ocean pay to one, and the memo is how you label the payout).
  // Settled offer payments ride the registrar's forwarder into Spending, the
  // same path the address already uses.
  async function loadOffers() {
    if (ui.namesOffers) return;
    ui.namesOffers = 'loading';
    try {
      const j = await post('/offer', 'GET');
      ui.namesOffers = j.offers || [];
    } catch (e) {
      ui.namesOffers = [];
      ui.namesOfferError = e.message;
    }
    render();
  }

  async function createOffer() {
    const memo = (ui.namesOfferMemo || '').trim();
    ui.namesOfferBusy = true; ui.namesOfferError = null; render();
    try {
      const j = await post('/offer', 'POST', { memo });
      ui.namesOffers = [
        ...(Array.isArray(ui.namesOffers) ? ui.namesOffers.filter((o) => o.offerId !== j.offerId) : []),
        { offerId: j.offerId, memo: j.memo, bolt12: j.bolt12 },
      ];
      ui.namesOfferMemo = '';
    } catch (e) {
      ui.namesOfferError = e.message;
    }
    ui.namesOfferBusy = false; render();
  }

  function offerSection() {
    if (!ui.namesOfferOpen) {
      return h('button', {
        class: 'linklike small',
        onClick: () => { ui.namesOfferOpen = true; loadOffers(); render(); },
      }, t('namesOfferOpen'));
    }
    const offers = Array.isArray(ui.namesOffers) ? ui.namesOffers : [];
    return h('div', { class: 'col', style: 'gap:10px;width:100%' },
      h('div', { class: 'divider' }),
      h('div', { class: 'row between', style: 'align-items:baseline' },
        h('strong', {}, t('namesOfferTitle')),
        h('button', { class: 'linklike small', onClick: () => { ui.namesOfferOpen = false; render(); } }, t('hide'))),
      h('p', { class: 'small muted', style: 'margin:0' }, t('namesOfferDesc')),
      h('div', { class: 'row gap6' },
        h('input', {
          type: 'text', class: 'grow', maxlength: '120',
          placeholder: t('namesOfferMemoPh'),
          value: ui.namesOfferMemo || '',
          onInput: (e) => { ui.namesOfferMemo = e.target.value; },
        }),
        h('button', { class: 'btn-sm', disabled: !!ui.namesOfferBusy, onClick: createOffer },
          ui.namesOfferBusy ? h('span', { class: 'spinner sm' }) : t('namesOfferCreate'))),
      ui.namesOfferError ? h('div', { class: 'notice err small' }, ui.namesOfferError) : null,
      ui.namesOffers === 'loading' ? h('span', { class: 'spinner sm' }) : null,
      ...offers.map((o) =>
        h('div', { class: 'col', style: 'gap:6px;width:100%' },
          h('div', { class: 'small muted' }, o.memo || t('namesOfferNoMemo')),
          h('div', { class: 'addr-box break', style: 'width:100%;font-size:11px' }, o.bolt12),
          h('div', { class: 'row gap6' },
            copyBtn(o.bolt12, t('copy')),
            h('button', { class: 'btn-sm', onClick: () => { ui.namesOfferQr = ui.namesOfferQr === o.offerId ? null : o.offerId; render(); } }, t('namesOfferQr'))),
          ui.namesOfferQr === o.offerId
            ? h('div', { style: 'align-self:center', html: qrSvg(o.bolt12.toUpperCase(), { ec: 'L', mode: 'Alphanumeric' }) })
            : null)));
  }

  return {
    id: 'names',
    init() { checked = false; lastError = null; refresh(); },
    namesAdoptIdentity(signer, npub) { return adoptIdentity(signer, npub); },
    // the claimed payment address, for anyone prefilling a lightning address
    namesAddress() { const st = load(); return st.name ? `${st.name}@${st.domain || DOMAIN}` : null; },
    // the onboarding wizard renders the same claim form on its username step
    namesClaimForm() { return claimForm(true); },
    stop() { clearTimeout(retryTimer); clearTimeout(deadline); deadline = null; },
    receiveModes() {
      if (!available()) return [];
      return [{
        id: 'name', label: t('receiveNameTab'),
        icon: '<svg viewBox="0 0 72 72" width="18" height="18" fill="currentColor"><path fill-rule="evenodd" d="M36 4.2C18.5 4.2 4.2 18.5 4.2 36S18.5 67.8 36 67.8 67.8 53.5 67.8 36 53.5 4.2 36 4.2ZM0 36C0 16.1 16.1 0 36 0s36 16.1 36 36-16.1 36-36 36S0 55.9 0 36Z"/><path fill-rule="evenodd" d="M36 58.6c12.5 0 22.6-10.1 22.6-22.6S48.5 13.4 36 13.4 13.4 23.5 13.4 36 23.5 58.6 36 58.6ZM36 54c9.9 0 18-8.1 18-18s-8.1-18-18-18-18 8.1-18 18 8.1 18 18 18Z"/><path d="M36 22.9c-7.2 0-13.1 5.9-13.1 13.1S28.8 49.1 36 49.1V22.9Z"/></svg>',
        render: (seg) => namePane(seg),
      }];
    },
    // BEFORE zaps in the registry: a pasted user@domain tries DNS first.
    matchSendText(text, typed) {
      if (typed) return false; // don't yank the form away mid-keystroke
      if (!ui.send || ui.send.recipients.length !== 1) return false;
      return beginResolve(text);
    },
    settingsCards() { return [namesCard()]; },
  };
}

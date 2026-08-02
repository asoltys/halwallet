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
import { qrSvg } from '../qr.js';
import { isArkAddress } from './ark.js';
import { getNetwork } from '../api.js';
import { t } from '../i18n.js';

const REGISTRAR = 'https://names.coinos.io';
const DOMAIN = 'coinos.io';
const AUTH_KIND = 21353;

export function namesFeature(ctx) {
  const { h, ui, render, wallet, hook, toast, copyBtn } = ctx;

  const load = () => wallet.loadFeatureState('names', {});
  const save = (st) => wallet.saveFeatureState('names', st);

  const available = () => getNetwork() === 'mainnet' && !wallet.watchOnly
    && !!wallet.nostrSign && !!hook('arkReady');

  async function currentUri() {
    const addr = await hook('arkStaticAddress');
    return addr ? `bitcoin:?ark=${encodeURIComponent(addr)}` : null;
  }

  async function claim(name) {
    const uri = await currentUri();
    if (!uri) throw new Error(t('namesNeedArk'));
    const auth = wallet.nostrSign({
      kind: AUTH_KIND, created_at: Math.floor(Date.now() / 1000), tags: [],
      content: JSON.stringify({ action: 'register', name, uri, domain: DOMAIN }),
    });
    if (!auth) throw new Error('wallet cannot sign');
    const r = await fetch(`${REGISTRAR}/register`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ auth }),
    });
    const j = await r.json();
    if (!r.ok || j.error) throw new Error(j.error || `registrar refused (${r.status})`);
    save({ name, domain: DOMAIN, uri, updated: Date.now() });
    return j;
  }

  async function release() {
    const st = load();
    if (!st.name) return;
    const auth = wallet.nostrSign({
      kind: AUTH_KIND, created_at: Math.floor(Date.now() / 1000), tags: [],
      content: JSON.stringify({ action: 'delete', name: st.name, domain: st.domain || DOMAIN }),
    });
    await fetch(`${REGISTRAR}/register`, {
      method: 'DELETE', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ auth }),
    }).catch(() => {});
    save({});
  }

  // An imported seed doesn't know its username — the registrar does. Ask by
  // the wallet's nostr pubkey and adopt what it says before deciding whether
  // onboarding needs to prompt.
  let checked = false; // lookup completed (gate stays closed until then)
  async function lookupMine() {
    try {
      const pk = wallet.nostrPubkey && wallet.nostrPubkey();
      if (!pk) return;
      const r = await fetch(`${REGISTRAR}/pubkey/${pk}`).then((x) => x.json());
      if (r && r.name) save({ ...load(), name: r.name, domain: r.domain || DOMAIN, uri: r.uri });
    } catch {}
  }

  // The record must track the wallet: re-register when the ark address moved.
  async function refresh() {
    try {
      if (!available()) { checked = true; render(); return; }
      let st = load();
      if (!st.name) { await lookupMine(); st = load(); }
      checked = true;
      render();
      if (!st.name) return;
      const uri = await currentUri();
      if (uri && uri !== st.uri) await claim(st.name);
    } catch (e) { checked = true; console.warn('names: refresh failed', e.message); }
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
    if (!st.name) {
      return h('div', { class: 'card col', style: 'gap:10px' },
        seg,
        h('p', { class: 'small muted', style: 'margin:0' }, t('namesDesc')),
        claimForm(false));
    }
    const addr = `${st.name}@${st.domain || DOMAIN}`;
    return h('div', { class: 'card col', style: 'align-items:center;gap:14px' },
      seg,
      h('div', { html: qrSvg(addr) }),
      h('div', { class: 'addr-box', style: 'width:100%;text-align:center;font-size:16px' }, addr),
      copyBtn(addr, t('namesCopy')));
  }

  return {
    id: 'names',
    init() { checked = false; refresh(); },
    receiveModes() {
      if (!available()) return [];
      return [{
        id: 'name', label: t('receiveNameTab'),
        icon: '<svg viewBox="0 0 72 72" width="18" height="18" fill="currentColor"><path fill-rule="evenodd" d="M36 4.2C18.5 4.2 4.2 18.5 4.2 36S18.5 67.8 36 67.8 67.8 53.5 67.8 36 53.5 4.2 36 4.2ZM0 36C0 16.1 16.1 0 36 0s36 16.1 36 36-16.1 36-36 36S0 55.9 0 36Z"/><path fill-rule="evenodd" d="M36 58.6c12.5 0 22.6-10.1 22.6-22.6S48.5 13.4 36 13.4 13.4 23.5 13.4 36 23.5 58.6 36 58.6ZM36 54c9.9 0 18-8.1 18-18s-8.1-18-18-18-18 8.1-18 18 8.1 18 18 18Z"/><path d="M36 22.9c-7.2 0-13.1 5.9-13.1 13.1S28.8 49.1 36 49.1V22.9Z"/></svg>',
        render: (seg) => namePane(seg),
      }];
    },
    // New wallets must pick a username before using the wallet; imported
    // seeds recover theirs from the registrar and skip straight through.
    onboardingView() {
      if (!available() || !checked) return null;
      if (load().name || ui.namesLater) return null;
      return h('div', { class: 'card col', style: 'gap:12px' },
        h('h2', { style: 'margin:0' }, t('namesOnboardTitle')),
        h('p', { class: 'muted', style: 'margin:0' }, t('namesOnboardDesc')),
        claimForm(true),
        ui.nameClaimError
          ? h('button', { class: 'linklike small', onClick: () => { ui.namesLater = true; render(); } }, t('namesOnboardLater'))
          : null);
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

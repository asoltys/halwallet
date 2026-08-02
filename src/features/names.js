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
import { isArkAddress } from './ark.js';
import { getNetwork } from '../api.js';
import { t } from '../i18n.js';

const REGISTRAR = 'https://names.halwallet.app';
const DOMAIN = 'halwallet.app';
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
      content: JSON.stringify({ action: 'register', name, uri }),
    });
    if (!auth) throw new Error('wallet cannot sign');
    const r = await fetch(`${REGISTRAR}/register`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ auth }),
    });
    const j = await r.json();
    if (!r.ok || j.error) throw new Error(j.error || `registrar refused (${r.status})`);
    save({ name, uri, updated: Date.now() });
    return j;
  }

  async function release() {
    const st = load();
    if (!st.name) return;
    const auth = wallet.nostrSign({
      kind: AUTH_KIND, created_at: Math.floor(Date.now() / 1000), tags: [],
      content: JSON.stringify({ action: 'delete', name: st.name }),
    });
    await fetch(`${REGISTRAR}/register`, {
      method: 'DELETE', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ auth }),
    }).catch(() => {});
    save({});
  }

  // The record must track the wallet: re-register when the ark address moved.
  async function refresh() {
    try {
      const st = load();
      if (!st.name || !available()) return;
      const uri = await currentUri();
      if (uri && uri !== st.uri) await claim(st.name);
    } catch (e) { console.warn('names: refresh failed', e.message); }
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

  function namesCard() {
    if (!available()) return null;
    const st = load();
    if (st.name) {
      const addr = `₿${st.name}@${DOMAIN}`;
      return h('div', { class: 'card col' },
        h('h3', {}, t('namesTitle')),
        h('div', { class: 'addr-box break', style: 'font-size:14px' }, addr),
        h('div', { class: 'row gap6' },
          copyBtn(`${st.name}@${DOMAIN}`, t('namesCopy')),
          h('button', { class: 'btn-ghost btn-sm', onClick: async () => {
            await release(); toast(t('namesReleased')); render();
          } }, t('namesRelease'))),
        h('details', { class: 'small faint' },
          h('summary', {}, t('namesOwnDomain')),
          h('p', { style: 'margin:4px 0' }, t('namesOwnDomainHow')),
          h('div', { class: 'addr-box break', style: 'font-size:11px' },
            `${st.name}.user._bitcoin-payment.yourdomain.com. CNAME ${st.name}.user._bitcoin-payment.${DOMAIN}.`)));
    }
    return h('div', { class: 'card col' },
      h('h3', {}, t('namesTitle')),
      h('p', { class: 'small muted', style: 'margin:0' }, t('namesDesc')),
      ui.nameClaimError ? h('div', { class: 'notice err' }, ui.nameClaimError) : null,
      h('div', { class: 'row gap6' },
        h('input', {
          type: 'text', placeholder: t('namesPlaceholder'), style: 'flex:1',
          autocapitalize: 'none', autocomplete: 'off', spellcheck: 'false',
          value: ui.nameClaim || '',
          onInput: (e) => { ui.nameClaim = e.target.value.toLowerCase().trim(); },
        }),
        h('button', { class: 'btn-primary', disabled: ui.busy, onClick: async () => {
          const name = (ui.nameClaim || '').toLowerCase().trim();
          if (!name) return;
          ui.busy = true; ui.nameClaimError = null; render();
          try {
            await claim(name);
            ui.nameClaim = '';
            toast(t('namesClaimed', { name: `${name}@${DOMAIN}` }));
          } catch (e) { ui.nameClaimError = e.message; }
          ui.busy = false; render();
        } }, t('namesClaim'))));
  }

  return {
    id: 'names',
    init() { refresh(); },
    // BEFORE zaps in the registry: a pasted user@domain tries DNS first.
    matchSendText(text, typed) {
      if (typed) return false; // don't yank the form away mid-keystroke
      if (!ui.send || ui.send.recipients.length !== 1) return false;
      return beginResolve(text);
    },
    settingsCards() { return [namesCard()]; },
  };
}

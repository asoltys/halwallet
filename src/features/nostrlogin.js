// "Log in with Nostr" — open (or create) a wallet from a nostr identity, and
// link an existing wallet to one after the fact.
//
// The mechanics and their tradeoffs live in ../nostr-login.js. In short: a
// pasted key DERIVES its wallet deterministically; an extension or remote
// signer ASSOCIATES one via a seed published encrypted to the user's own key.
// The second is what makes "log in on a new device" work without the key
// ever reaching us, and it is spelled out in the UI before anything is
// published, because it means the nostr key can recover the money.

import { newMnemonic } from '../wallet.js';
import { npubOf } from '../nostr.js';
import { t } from '../i18n.js';
import {
  extensionSigner, bunkerSigner, keySigner, parseNostrSecret,
  walletForSigner, publishWalletBackup,
} from '../nostr-login.js';

// The nostr ostrich, in the brand's monochrome.
const OSTRICH = '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" style="vertical-align:-3px"><path d="M6.6 2.2c1.5 0 2.8 1.2 2.8 2.8v.6h1.9c2.7 0 4.9 2.2 4.9 4.9 0 .7-.5 1.2-1.2 1.2h-2.3c-.5 0-.9.4-.9.9v1.1c0 1.6.5 3.1 1.4 4.4l1.3 1.8c.3.4 0 1-.5 1H9.2c-.4 0-.7-.3-.7-.7 0-2.6-.9-5.1-2.6-7.1A6.9 6.9 0 0 1 3.8 8.4V5c0-1.6 1.3-2.8 2.8-2.8Zm.2 2.1a.8.8 0 1 0 0 1.6.8.8 0 0 0 0-1.6Z"/></svg>';

export function nostrLoginFeature(ctx) {
  const { h, ui, render, wallet, toast } = ctx;

  const load = () => wallet.loadFeatureState('nostrlogin', {});
  const save = (st) => wallet.saveFeatureState('nostrlogin', st);

  // The signer that opened this session, kept so the names feature can claim
  // the user's real npub as their payment address (and nominate the wallet
  // key as manager, so later updates work without the signer).
  let live = null;

  const busy = (v) => { ui.nostrLoginBusy = v; render(); };
  const fail = (e) => { ui.nostrLoginError = e.message || String(e); busy(false); };

  // Open the wallet a signer identifies. New accounts confirm first, because
  // publishing an encrypted seed to relays deserves an explicit yes.
  async function loginWith(makeSigner) {
    ui.nostrLoginError = '';
    busy(true);
    let signer;
    try {
      signer = await makeSigner();
      const res = await walletForSigner(signer);
      if (res.mode === 'new') {
        // no wallet on this identity yet — ask before publishing one
        ui.nostrLoginNew = { signer, npub: npubOf(signer.pubkey) };
        busy(false);
        return;
      }
      // Same wallet however you log in: a key-derived seed is published too,
      // so an extension login later finds this wallet instead of making a new
      // one. Costs nothing — anyone with the key could derive it anyway.
      if (res.publish) await publishWalletBackup(signer, { mnemonic: res.mnemonic }).catch(() => {});
      live = signer;
      await ctx.openMnemonic(res.mnemonic, res.passphrase || '', { nostrPubkey: signer.pubkey });
      save({ ...load(), pubkey: signer.pubkey, linked: Date.now() });
      // claim the real npub as the payment address while this signer is live
      ctx.hook('namesAdoptIdentity', signer, npubOf(signer.pubkey))?.catch?.(() => {});
      toast(res.mode === 'derived' ? t('nlOpenedDerived') : t('nlOpenedRestored'));
      busy(false);
    } catch (e) { fail(e); }
  }

  async function createForSigner() {
    const st = ui.nostrLoginNew;
    if (!st) return;
    busy(true);
    try {
      const mnemonic = newMnemonic();
      await publishWalletBackup(st.signer, { mnemonic });
      ui.nostrLoginNew = null;
      live = st.signer;
      await ctx.openMnemonic(mnemonic, '', { nostrPubkey: st.signer.pubkey });
      save({ ...load(), pubkey: st.signer.pubkey, linked: Date.now() });
      ctx.hook('namesAdoptIdentity', st.signer, npubOf(st.signer.pubkey))?.catch?.(() => {});
      toast(t('nlCreated'));
      busy(false);
    } catch (e) { fail(e); }
  }

  // Link the wallet that's already open to a nostr identity, so logging in
  // with it on another device opens this same wallet.
  async function linkOpenWallet(makeSigner) {
    ui.nostrLoginError = '';
    busy(true);
    let signer;
    try {
      signer = await makeSigner();
      if (!wallet.mnemonic) throw new Error(t('nlNeedSeed'));
      const existing = await walletForSigner(signer);
      if (existing.mnemonic && existing.mnemonic !== wallet.mnemonic) {
        throw new Error(t('nlAlreadyLinked'));
      }
      await publishWalletBackup(signer, { mnemonic: wallet.mnemonic, passphrase: wallet.passphrase || '' });
      live = signer;
      save({ ...load(), pubkey: signer.pubkey, linked: Date.now() });
      ctx.hook('namesAdoptIdentity', signer, npubOf(signer.pubkey))?.catch?.(() => {});
      toast(t('nlLinked'));
      busy(false);
    } catch (e) { fail(e); }
  }

  // ---- UI ---------------------------------------------------------------

  // The three ways in, as buttons. `run` receives a signer factory.
  function signerButtons(run) {
    const hasExt = typeof window !== 'undefined' && !!window.nostr;
    return h('div', { class: 'col', style: 'gap:8px' },
      hasExt
        ? h('button', { class: 'btn-block', disabled: ui.nostrLoginBusy,
            onClick: () => run(() => extensionSigner()) }, t('nlExtension'))
        : null,
      h('div', { class: 'row gap6' },
        h('input', {
          type: 'password', placeholder: t('nlKeyOrBunker'), style: 'flex:1',
          autocapitalize: 'none', autocomplete: 'off', spellcheck: 'false',
          value: ui.nostrLoginInput || '',
          onInput: (e) => { ui.nostrLoginInput = e.target.value.trim(); },
        }),
        h('button', { class: 'btn-sm', disabled: ui.nostrLoginBusy, onClick: () => {
          const v = (ui.nostrLoginInput || '').trim();
          const sk = parseNostrSecret(v);
          if (sk) return run(() => keySigner(sk));
          if (/^bunker:\/\//i.test(v)) {
            return run(() => bunkerSigner(v, { onAuth: (url) => { ui.nostrLoginAuthUrl = url; render(); } }));
          }
          ui.nostrLoginError = t('nlUnrecognized');
          render();
        } }, ui.nostrLoginBusy ? h('span', { class: 'spinner' }) : t('nlGo'))),
      h('div', { class: 'small faint' }, t('nlHint')),
      ui.nostrLoginAuthUrl
        ? h('a', { href: ui.nostrLoginAuthUrl, target: '_blank', class: 'small' }, t('nlApprove'))
        : null,
      ui.nostrLoginError ? h('div', { class: 'notice err' }, ui.nostrLoginError) : null);
  }

  // Shown under the create/import tabs on the unlock screen.
  function unlockExtra() {
    if (ui.nostrLoginNew) {
      return h('div', { class: 'card col', style: 'gap:10px' },
        h('h3', { style: 'margin:0' }, t('nlNewTitle')),
        h('div', { class: 'small muted' }, ui.nostrLoginNew.npub || ''),
        h('p', { class: 'small muted', style: 'margin:0' }, t('nlNewDesc')),
        h('div', { class: 'notice info small' }, t('nlBackupWarning')),
        ui.nostrLoginError ? h('div', { class: 'notice err' }, ui.nostrLoginError) : null,
        h('div', { class: 'row gap6' },
          h('button', { class: 'btn-ghost', onClick: () => {
            if (ui.nostrLoginNew.signer.close) ui.nostrLoginNew.signer.close();
            ui.nostrLoginNew = null; render();
          } }, t('cancel')),
          h('button', { class: 'btn-primary grow', disabled: ui.nostrLoginBusy, onClick: createForSigner },
            ui.nostrLoginBusy ? h('span', { class: 'spinner' }) : t('nlCreateBtn'))));
    }
    // Collapsed by default: one button, expanded only when asked for.
    if (!ui.nostrLoginOpen) {
      return h('button', {
        class: 'btn-block row gap6', style: 'align-items:center;justify-content:center',
        onClick: () => { ui.nostrLoginOpen = true; ui.nostrLoginError = ''; render(); },
      }, h('span', { html: OSTRICH }), t('nlSignIn'));
    }
    return h('div', { class: 'card col', style: 'gap:10px' },
      h('div', { class: 'row between' },
        h('h3', { style: 'margin:0' }, t('nlTitle')),
        h('span', { class: 'linklike small', onClick: () => { ui.nostrLoginOpen = false; render(); } }, t('cancel'))),
      h('p', { class: 'small muted', style: 'margin:0' }, t('nlDesc')),
      signerButtons(loginWith));
  }

  function settingsCard() {
    if (wallet.watchOnly || !wallet.mnemonic) return null;
    const st = load();
    if (st.pubkey) {
      return h('div', { class: 'card col' },
        h('h3', {}, t('nlLinkTitle')),
        h('div', { class: 'small muted break' }, npubOf(st.pubkey) || st.pubkey),
        h('p', { class: 'small faint', style: 'margin:0' }, t('nlLinkedDesc')));
    }
    return h('div', { class: 'card col' },
      h('h3', {}, t('nlLinkTitle')),
      h('p', { class: 'small muted', style: 'margin:0' }, t('nlLinkDesc')),
      h('div', { class: 'notice info small' }, t('nlBackupWarning')),
      signerButtons(linkOpenWallet));
  }

  return {
    id: 'nostrlogin',
    // The nostr identity this session is logged in as, for features that
    // should speak as the user (the payment address defaults to this npub).
    nostrLoginIdentity() {
      const st = load();
      if (!st.pubkey) return null;
      return { pubkey: st.pubkey, npub: npubOf(st.pubkey), signer: live };
    },
    // A page reload loses the signer. An installed extension can usually be
    // re-attached without prompting, which is what lets the payment address
    // stay tied to the user's real identity across reloads. Returns null for
    // signers we cannot silently reattach (pasted keys, bunkers).
    async nostrLoginResume() {
      if (live) return live;
      const st = load();
      if (!st.pubkey || typeof window === 'undefined' || !window.nostr) return null;
      try {
        const s = await extensionSigner();
        if (s.pubkey !== st.pubkey) return null;
        live = s;
        return s;
      } catch { return null; }
    },
    unlockExtra() { return unlockExtra(); },
    settingsCards() { return [settingsCard()]; },
  };
}

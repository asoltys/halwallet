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

export function nostrLoginFeature(ctx) {
  const { h, ui, render, wallet, toast } = ctx;

  const load = () => wallet.loadFeatureState('nostrlogin', {});
  const save = (st) => wallet.saveFeatureState('nostrlogin', st);

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
      await ctx.hook('openMnemonic', res.mnemonic, res.passphrase || '', { nostrPubkey: signer.pubkey });
      toast(res.mode === 'derived' ? t('nlOpenedDerived') : t('nlOpenedRestored'));
      busy(false);
    } catch (e) { fail(e); }
    finally { if (signer && signer.close && !ui.nostrLoginNew) signer.close(); }
  }

  async function createForSigner() {
    const st = ui.nostrLoginNew;
    if (!st) return;
    busy(true);
    try {
      const mnemonic = newMnemonic();
      await publishWalletBackup(st.signer, { mnemonic });
      ui.nostrLoginNew = null;
      await ctx.hook('openMnemonic', mnemonic, '', { nostrPubkey: st.signer.pubkey });
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
      save({ ...load(), pubkey: signer.pubkey, linked: Date.now() });
      toast(t('nlLinked'));
      busy(false);
    } catch (e) { fail(e); }
    finally { if (signer && signer.close) signer.close(); }
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
    return h('div', { class: 'card col', style: 'gap:10px' },
      h('h3', { style: 'margin:0' }, t('nlTitle')),
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
    unlockExtra() { return unlockExtra(); },
    settingsCards() { return [settingsCard()]; },
  };
}

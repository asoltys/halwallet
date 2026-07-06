// Cross-device sync feature — encrypted wallet state on Nostr relays
// (NIP-44 to self, replaceable kind 30078) plus the wallet's nostr identity
// (used e.g. to DM locked-gift claim codes). Installed onto the core wallet;
// a build without sync ships none of it and never talks to a relay.

import { NostrSync, getSyncConfig, setSyncConfig, npubOf, syncDtag } from '../nostr.js';
import { t } from '../i18n.js';

export function installSyncWallet(wallet) {
  if (wallet.syncFromNostr) return; // already installed
  wallet.nostr = new NostrSync();
  wallet._nostrPubTimer = null;

  Object.assign(wallet, {
    // Our nostr identity (used to DM a locked gift's claim code to the recipient).
    nostrPubkey() { return (this.nostr && this.nostr.pk) || null; },

    nostrNpub() { const pk = this.nostrPubkey(); return pk ? npubOf(pk) : null; },

    // Send a nostr DM (e.g. a locked gift's claim code) to a recipient pubkey.
    async sendNostrDM(recipientPkHex, text) {
      return this.nostr && this.nostr.sk ? this.nostr.sendDM(recipientPkHex, text) : false;
    },

    // Pull the latest state from Nostr; apply it if it's newer than what we have.
    // Returns true if state was applied (so the caller can skip a full scan).
    async syncFromNostr() {
      const sync = getSyncConfig();
      if (this.offline || !sync.enabled) return false;
      this.nostr.setRelays(sync.relays);
      this.nostr.setDtag(syncDtag(this.netName));
      let remote;
      try {
        remote = await this.nostr.fetch();
      } catch {
        return false;
      }
      if (!remote) return false;
      // A snapshot for another network must never apply here. Legacy events
      // (published before snapshots carried netName) are ambiguous — they can
      // hold ANY network's state under the shared d-tag, and applying one
      // poisoned a mainnet wallet with regtest coins — so they are never
      // applied either; a full scan is safer than a wrong snapshot.
      if (remote.netName !== this.netName) return false;
      if ((remote.savedAt || 0) > (this._savedAt || 0)) {
        this._applySnapshot(remote);
        this.saveCache(); // mirror into localStorage
        this.emit();
        return true;
      }
      // Our local copy is newer (or equal) — push it up so the relay catches up.
      if ((this._savedAt || 0) > (remote.savedAt || 0)) this.saveCache();
      return true; // remote existed, so no full scan needed
    },
  });

  // identity follows the open wallet
  wallet.registerLoadHook(() => {
    if (wallet.mnemonic) wallet.nostr.load(wallet.mnemonic, wallet.passphrase);
    else wallet.nostr.unload();
  });
  // push every saved snapshot to the relays (debounced) unless sync is off
  wallet.registerCacheSavedHook((snap) => {
    const sync = getSyncConfig();
    if (wallet.offline || !sync.enabled) return;
    wallet.nostr.setRelays(sync.relays);
    // bind the d-tag now: the debounced publish must keep this snapshot's
    // network even if the wallet switches networks before the timer fires
    const dtag = syncDtag(wallet.netName);
    clearTimeout(wallet._nostrPubTimer);
    wallet._nostrPubTimer = setTimeout(() => wallet.nostr.publish(snap, dtag), 2500);
  });
  wallet.registerRealtimeHook({ stop: () => clearTimeout(wallet._nostrPubTimer) });
}

export function syncFeature(ctx) {
  const { h, ui, render, wallet } = ctx;
  installSyncWallet(wallet);

  // Cross-device sync settings: toggle + editable relay list (default coinos).
  function syncCard() {
    const cfg = getSyncConfig();
    const setEnabled = (enabled) => {
      if (enabled === cfg.enabled) return;
      setSyncConfig({ enabled, relays: cfg.relays });
      render();
      // On enable, pull anything newer from the relays, then push our copy up.
      if (enabled && !wallet.offline) {
        wallet.syncFromNostr().catch(() => {}).finally(() => wallet.saveCache());
      }
    };
    return h(
      'div',
      { class: 'card col' },
      h('h3', {}, t('deviceSync')),
      h('p', { class: 'small muted', style: 'margin:0' }, t('deviceSyncDesc')),
      h('div', { class: 'row between' },
        h('span', { class: 'lab', style: 'margin:0' }, t('syncAcross')),
        h('div', { class: 'seg' },
          h('button', { type: 'button', class: cfg.enabled ? 'active' : '', onClick: () => setEnabled(true) }, t('syncOn')),
          h('button', { type: 'button', class: !cfg.enabled ? 'active' : '', onClick: () => setEnabled(false) }, t('syncOff'))
        )
      ),
      cfg.enabled
        ? h('label', { class: 'field' },
            h('span', { class: 'lab' }, t('relaysLabel')),
            h('textarea', {
              placeholder: 'wss://relay.example.com',
              autocapitalize: 'none', autocomplete: 'off', spellcheck: 'false',
              style: 'min-height:64px',
              value: cfg.relays.join('\n'),
              onInput: (e) => {
                const relays = e.target.value.split('\n').map((s) => s.trim()).filter(Boolean);
                setSyncConfig({ enabled: true, relays });
              },
            }),
            h('div', { class: 'small faint' }, t('relaysHint'))
          )
        : null
    );
  }

  return {
    id: 'sync',
    settingsCards() {
      return wallet.watchOnly || !wallet.mnemonic ? [] : [syncCard()];
    },
  };
}

// Cross-device sync feature — encrypted wallet state on Nostr relays
// (NIP-44 to self, replaceable kind 30078) plus the wallet's nostr identity
// (used e.g. to DM locked-gift claim codes). Installed onto the core wallet;
// a build without sync ships none of it and never talks to a relay.

import { NostrSync, getSyncConfig, setSyncConfig, npubOf, syncDtag, deviceDtag, isOurDtag } from '../nostr.js';
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

    // Generic event publish/fetch on the configured sync relays — the seam
    // other features (ark zaps) use to speak their own kinds. No-ops when
    // sync is disabled or the wallet is offline.
    async nostrPublish(partial) {
      const sync = getSyncConfig();
      if (this.offline || !sync.enabled || !this.nostr.sk) return null;
      this.nostr.setRelays(sync.relays);
      return this.nostr.publishEvent(partial);
    },
    async nostrFetch(filter, maxWait) {
      const sync = getSyncConfig();
      if (this.offline || !sync.enabled) return [];
      this.nostr.setRelays(sync.relays);
      return this.nostr.fetchEvents(filter, maxWait);
    },
    nostrSubscribe(filter, onEvent) {
      const sync = getSyncConfig();
      if (this.offline || !sync.enabled) return () => {};
      this.nostr.setRelays(sync.relays);
      return this.nostr.subscribeEvents(filter, onEvent);
    },

    // Pull the latest state from Nostr; apply it if it's newer than what we have.
    // Returns true if state was applied (so the caller can skip a full scan).
    async syncFromNostr() {
      const sync = getSyncConfig();
      if (this.offline || !sync.enabled) return false;
      this.nostr.setRelays(sync.relays);
      let all;
      try {
        all = await this.nostr.fetchAllStates();
      } catch {
        return false;
      }
      // Each device publishes to its OWN slot now, so there can be several
      // snapshots for this network. Keep only ours-for-this-network: the
      // netName inside is the real guard against cross-network bleed (legacy
      // shared-tag events are ambiguous), the d-tag check filters the rest.
      const mine = all.filter((s) => s.state.netName === this.netName && isOurDtag(s.dtag, this.netName));
      if (!mine.length) return false;
      // Merge every device's merge-safe extension state (ark vtxos union) — a
      // device sees ALL devices' coins, not only the newest snapshot's.
      for (const s of mine) this._mergeSnapshotExtensions(s.state);
      // Apply the newest FULL snapshot for the rescannable on-chain state.
      const newest = mine[0].state; // fetchAllStates returns newest-first
      if ((newest.savedAt || 0) > (this._savedAt || 0)) {
        this._applySnapshot(newest); // re-runs extension loads (idempotent merge)
        this.emit();
      }
      this.saveCache(); // persist the merged result + republish our own slot
      return true;
    },
  });

  // identity follows the open wallet
  wallet.registerLoadHook(() => {
    if (wallet.mnemonic) wallet.nostr.load(wallet.mnemonic, wallet.passphrase);
    else wallet.nostr.unload();
  });
  // Live cross-device state: subscribe to ALL our devices' slots so a save on
  // another device merges here within seconds. Merge-safe extension state (ark
  // vtxos union) applies live; full snapshots stay a load-time affair. With
  // per-device slots no device overwrites another's, so this only ever adds.
  let stateUnsub = null;
  wallet.registerRealtimeHook({
    start: () => {
      const sync = getSyncConfig();
      if (!sync.enabled || !wallet.nostr.pk) return;
      wallet.nostr.setRelays(sync.relays);
      if (stateUnsub) { try { stateUnsub(); } catch {} }
      stateUnsub = wallet.nostr.subscribeStates((v, dtag) => {
        if (!v.netName || v.netName !== wallet.netName) return;
        if (!isOurDtag(dtag, wallet.netName)) return;
        if (dtag === deviceDtag(wallet.netName) && (v.savedAt || 0) === (wallet._savedAt || 0)) return; // our own echo
        wallet._mergeSnapshotExtensions(v);
      });
    },
    stop: () => { if (stateUnsub) { try { stateUnsub(); } catch {} stateUnsub = null; } },
  });

  // push every saved snapshot to the relays (debounced) unless sync is off —
  // to THIS DEVICE's own slot, so it never clobbers another device's.
  wallet.registerCacheSavedHook((snap) => {
    const sync = getSyncConfig();
    if (wallet.offline || !sync.enabled) return;
    wallet.nostr.setRelays(sync.relays);
    // bind the per-device d-tag now: the debounced publish must keep this
    // snapshot's network even if the wallet switches networks before it fires
    const dtag = deviceDtag(wallet.netName);
    console.log('[syncdbg] cacheSaved scheduling publish', dtag, 'hasArk?', !!snap.arkState, 'sk?', !!wallet.nostr.sk);
    clearTimeout(wallet._nostrPubTimer);
    wallet._nostrPubTimer = setTimeout(() => { console.log('[syncdbg] publishing now', dtag); wallet.nostr.publish(snap, dtag); }, 2500);
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

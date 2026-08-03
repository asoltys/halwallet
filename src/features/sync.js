// Cross-device sync feature — encrypted wallet state on Nostr relays
// (NIP-44 to self, replaceable kind 30078) plus the wallet's nostr identity
// (used e.g. to DM locked-gift claim codes). Installed onto the core wallet;
// a build without sync ships none of it and never talks to a relay.

import {
  NostrSync, getSyncConfig, setSyncConfig, npubOf, syncDtag, deviceDtag,
  domainDtag, isOurDtag, isCoreDtag, isOwnDeviceDtag,
  fetchNostrProfile, PROFILE_RELAYS, DEFAULT_SYNC_RELAYS, queryOn, publishOn,
  finalizeEvent,
} from '../nostr.js';
import { t } from '../i18n.js';

// Keep a published snapshot under the relay's event-size cap. relay.coinos.io
// rejects events over 64KB and nip44 expands the plaintext ~1.5x, so the JSON
// must stay under ~40KB. The on-chain tx history is the main unbounded growth;
// drop the oldest (this.txs is newest-first) — another device backfills the
// rest with a rescan. Only trims oversized snapshots, so typical wallets are
// untouched.
const RELAY_JSON_BUDGET = 40000;
function trimForRelay(snap) {
  if (JSON.stringify(snap).length <= RELAY_JSON_BUDGET) return snap;
  const s = { ...snap };
  let txs = (s.txs || []).slice();
  while (txs.length > 25 && JSON.stringify(s).length > RELAY_JSON_BUDGET) {
    txs = txs.slice(0, Math.max(25, txs.length - 25));
    s.txs = txs;
  }
  return s;
}

// Split a snapshot into per-domain pieces, each published as its own
// replaceable event: an extension registered with a `domain` claims its keys,
// everything left is the core wallet. Every piece carries netName + savedAt so
// readers can apply the same guards as for full snapshots. Small events scale
// on vanilla relays (no special size rules) and only changed domains
// republish, so a payment burst no longer re-uploads the whole wallet.
export function splitSnapshotDomains(snap, extensions = []) {
  const core = { ...snap };
  const out = {};
  for (const e of extensions) {
    if (!e.domain || !e.save) continue;
    let obj;
    try { obj = e.save(); } catch { continue; }
    const keys = Object.keys(obj || {});
    if (!keys.length) continue;
    out[e.domain] = { netName: snap.netName, savedAt: snap.savedAt, ...obj };
    for (const k of keys) delete core[k];
  }
  out.core = core;
  return out;
}

export function installSyncWallet(wallet) {
  if (wallet.syncFromNostr) return; // already installed
  wallet.nostr = new NostrSync();
  wallet._nostrPubTimer = null;

  Object.assign(wallet, {
    // Our nostr identity (used to DM a locked gift's claim code to the recipient).
    nostrPubkey() { return (this.nostr && this.nostr.pk) || null; },

    nostrNpub() { const pk = this.nostrPubkey(); return pk ? npubOf(pk) : null; },

    // Send a nostr DM (e.g. a locked gift's claim code) to a recipient pubkey.

    // Generic event publish/fetch on the configured sync relays — the seam
    // other features (ark zaps) use to speak their own kinds. No-ops when
    // sync is disabled or the wallet is offline.
    async nostrPublish(partial) {
      const sync = getSyncConfig();
      if (this.offline || !sync.enabled || !this.nostr.sk) return null;
      this.nostr.setRelays(sync.relays);
      return this.nostr.publishEvent(partial);
    },
    // Publish an event signed by another key (the NWC wallet service keys).
    async nostrPublishSigned(evt) {
      const sync = getSyncConfig();
      if (this.offline || !sync.enabled) return null;
      this.nostr.setRelays(sync.relays);
      return this.nostr.publishSigned(evt);
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

    // Sign an event with our nostr key without publishing (NIP-57 zap request).
    nostrSign(partial) { return this.nostr ? this.nostr.signEvent(partial) : null; },

    // Fetch a pubkey's profile (name/picture + lud16/lud06 for zaps) from the
    // broad profile relays — independent of whether cross-device sync is on.
    async nostrProfile(pkHex) {
      if (this.offline) return null;
      return fetchNostrProfile(pkHex);
    },

    // Relays to advertise in a zap request so we can later find the receipt:
    // our sync relays plus the broad profile relays.
    nostrRelays() {
      const sync = getSyncConfig();
      const base = sync.enabled ? sync.relays : [];
      return [...new Set([...base, ...PROFILE_RELAYS])].slice(0, 8);
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
      // device sees ALL devices' coins, not only the newest snapshot's. Domain
      // fragments route themselves: an extension's load() only reads its keys.
      for (const s of mine) this._mergeSnapshotExtensions(s.state);
      // Apply the newest CORE-carrying snapshot for the rescannable on-chain
      // state. Domain fragments (ark/nwc slices) must never be applied as a
      // full snapshot — they'd blank the core fields they don't carry.
      const fulls = mine.filter((s) => isCoreDtag(s.dtag, this.netName));
      const newest = fulls[0] && fulls[0].state; // fetchAllStates returns newest-first
      if (newest && (newest.savedAt || 0) > (this._savedAt || 0)) {
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
    wallet._syncPubSeen = {}; // a new identity has published nothing yet
    adoptSyncRelays().catch(() => {});
  });

  // Sync rides the user's own relays: their NIP-65 (kind 10002) write set —
  // the login npub's first, else the wallet key's — falling back to the
  // coinos relay. A wallet key with no NIP-65 gets one published (default
  // relay, signed silently) so other clients can find this identity's events.
  async function adoptSyncRelays() {
    if (wallet.offline || !wallet.nostr.pk) return;
    const pks = [];
    try {
      const login = wallet.loadFeatureState('nostrlogin', {});
      if (login && /^[0-9a-f]{64}$/.test(login.pubkey || '')) pks.push(login.pubkey);
    } catch {}
    pks.push(wallet.nostr.pk);
    const evs = await queryOn([...new Set([...PROFILE_RELAYS, ...DEFAULT_SYNC_RELAYS])], { kinds: [10002], authors: pks }, 3500);
    const newestFor = (pk) => evs.filter((e) => e.pubkey === pk).sort((a, b) => b.created_at - a.created_at)[0];
    const writeRelays = (e) => e.tags
      .filter((x) => x[0] === 'r' && x[1] && (!x[2] || x[2] === 'write'))
      .map((x) => x[1].trim()).filter((r) => /^wss?:\/\//.test(r)).slice(0, 4);
    for (const pk of pks) {
      const e = newestFor(pk);
      const relays = e && writeRelays(e);
      if (relays && relays.length) {
        setSyncConfig({ enabled: true, relays: [...new Set([...relays, ...DEFAULT_SYNC_RELAYS])].slice(0, 5) });
        break;
      }
    }
    // a brand-new wallet identity: announce its relays (NIP-65)
    if (wallet.nostr.sk && !newestFor(wallet.nostr.pk)) {
      const evt = finalizeEvent({
        kind: 10002, content: '',
        tags: DEFAULT_SYNC_RELAYS.map((r) => ['r', r]),
        created_at: Math.floor(Date.now() / 1000),
      }, wallet.nostr.sk);
      publishOn([...new Set([...PROFILE_RELAYS, ...DEFAULT_SYNC_RELAYS])], evt);
    }
  }
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
        if (isOwnDeviceDtag(dtag, wallet.netName) && (v.savedAt || 0) === (wallet._savedAt || 0)) return; // our own echo
        wallet._mergeSnapshotExtensions(v);
      });
    },
    stop: () => { if (stateUnsub) { try { stateUnsub(); } catch {} stateUnsub = null; } },
  });

  // push every saved snapshot to the relays (debounced) unless sync is off —
  // split into per-domain slots on THIS DEVICE's tags, publishing only the
  // domains whose content actually changed since the last publish.
  wallet._syncPubSeen = {}; // domain -> last published JSON (per identity)
  wallet.registerCacheSavedHook((snap) => {
    const sync = getSyncConfig();
    if (wallet.offline || !sync.enabled) return;
    wallet.nostr.setRelays(sync.relays);
    // bind the network now: the debounced publish must keep this snapshot's
    // network even if the wallet switches networks before the timer fires
    const net = wallet.netName;
    clearTimeout(wallet._nostrPubTimer);
    wallet._nostrPubTimer = setTimeout(async () => {
      const domains = splitSnapshotDomains(snap, wallet._cacheExtensions || []);
      domains.core = trimForRelay(domains.core);
      for (const [name, obj] of Object.entries(domains)) {
        const json = JSON.stringify(obj);
        const slot = `${net}:${name}`;
        if (wallet._syncPubSeen[slot] === json) continue; // unchanged
        const ok = await wallet.nostr.publish(obj, domainDtag(net, name));
        if (ok) wallet._syncPubSeen[slot] = json; // a refused publish retries next save
      }
    }, 2500);
  });
  wallet.registerRealtimeHook({ stop: () => clearTimeout(wallet._nostrPubTimer) });
}

export function syncFeature(ctx) {
  const { h, ui, render, wallet } = ctx;
  installSyncWallet(wallet);

  return {
    id: 'sync',
  };
}

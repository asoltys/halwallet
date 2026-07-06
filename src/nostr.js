// Encrypted cross-device state sync via Nostr (opt-out, configurable relays).
//
// The wallet's Nostr identity is derived from the same seed (NIP-06,
// m/44'/1237'/0'/0/0). Wallet state is encrypted to ourselves (NIP-44) and
// published as a single parameterized-replaceable event (kind 30078, NIP-78)
// to the configured relays — so any device with the seed can pull the latest
// state without re-scanning, and a relay only ever keeps the newest copy.
//
// Sync is on by default (relay.coinos.io) but can be turned off or pointed at
// other relays in Settings; the preference lives in localStorage.

import * as nip06 from 'nostr-tools/nip06';
import * as nip44 from 'nostr-tools/nip44';
import { wrapEvent as nip17WrapEvent } from 'nostr-tools/nip17';
import { getPublicKey, finalizeEvent, generateSecretKey } from 'nostr-tools/pure';
import { decode as nip19decode, npubEncode } from 'nostr-tools/nip19';
import { SimplePool } from 'nostr-tools/pool';
import { randomBytes } from '@noble/hashes/utils';
import { base64urlnopad } from '@scure/base';

// One shared pool for all relay I/O — it manages connection lifecycles (and the
// CLOSE-after-EOSE handshake) cleanly, so we never send on a half-closed socket.
const pool = new SimplePool();

// --- locking a gift to a recipient's Nostr key ---------------------------
// An npub or 64-hex nostr pubkey → hex, or null if it isn't one.
export function parseNostrPubkey(input) {
  const s = (input || '').trim();
  if (/^[0-9a-f]{64}$/i.test(s)) return s.toLowerCase();
  try { const d = nip19decode(s); if (d.type === 'npub') return d.data; } catch {}
  return null;
}
export function npubOf(pkHex) { try { return npubEncode(pkHex); } catch { return null; } }

// Encrypt a gift payload two ways: (1) under a fresh one-time code, delivered to
// the recipient out-of-band via a nostr DM — the manual path; and (2) to the
// recipient's nostr pubkey via an ephemeral key, so a NIP-07 browser extension
// can decrypt it in-place with no code. Both decrypt to the same payload.
export function encryptGiftPayload(plaintext, recipientPkHex) {
  const codeKey = randomBytes(32);
  const ephSk = generateSecretKey();
  return {
    code: base64urlnopad.encode(codeKey),
    ctCode: nip44.encrypt(plaintext, codeKey),
    eph: getPublicKey(ephSk),
    ctKey: nip44.encrypt(plaintext, nip44.getConversationKey(ephSk, recipientPkHex)),
  };
}
export function decryptWithCode(code, ct) {
  return nip44.decrypt(ct, base64urlnopad.decode((code || '').trim()));
}

// Profiles live across the network, so look them up on popular relays (broader
// than the sync relays).
export const PROFILE_RELAYS = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net', 'wss://relay.coinos.io'];
// Fetch a recipient's profile (name + picture) for a pubkey, newest across relays.
export async function fetchNostrProfile(pubkeyHex, relays = PROFILE_RELAYS) {
  let events;
  try { events = await pool.querySync(relays, { kinds: [0], authors: [pubkeyHex] }, { maxWait: 5000 }); } catch { return null; }
  const best = events.sort((a, b) => b.created_at - a.created_at)[0];
  if (!best) return null;
  try {
    const m = JSON.parse(best.content);
    return { name: m.display_name || m.name || null, picture: m.picture || null, nip05: m.nip05 || null };
  } catch { return null; }
}

// Where to deliver a DM to a pubkey: prefer their NIP-17 DM relay list (kind
// 10050), else their NIP-65 read relays (kind 10002), else [] (caller falls back).
export async function fetchInboxRelays(pubkeyHex, relays = PROFILE_RELAYS) {
  let events;
  try { events = await pool.querySync(relays, { kinds: [10002, 10050], authors: [pubkeyHex] }, { maxWait: 5000 }); } catch { return []; }
  const newest = (kind) => events.filter((e) => e.kind === kind).sort((a, b) => b.created_at - a.created_at)[0];
  const dm = newest(10050);
  if (dm) { const r = dm.tags.filter((t) => t[0] === 'relay' && t[1]).map((t) => t[1]); if (r.length) return r; }
  const nip65 = newest(10002);
  if (nip65) { const r = nip65.tags.filter((t) => t[0] === 'r' && t[1] && (!t[2] || t[2] === 'read')).map((t) => t[1]); if (r.length) return r; }
  return [];
}

const DTAG = 'bitcoin-wallet';
// Each network syncs under its own d-tag base — a shared one would let a signet
// snapshot overwrite mainnet state (and vice versa). Mainnet keeps the bare tag
// existing wallets already publish under.
export const syncDtag = (netName) => (!netName || netName === 'mainnet' ? DTAG : `${DTAG}:${netName}`);

// Per-DEVICE d-tag: every device publishes to its OWN replaceable-event slot
// (`<base>:d:<deviceId>`), so no device can ever clobber another's snapshot.
// Readers pull ALL of the identity's kind-30078 events and merge across them,
// so a device sees every other device's coins. The legacy shared-tag events
// (from before this) are still read and merged — they just never get written
// to again.
const DEVICE_KEY = 'btc-wallet-device-id';
function deviceId() {
  try {
    let id = localStorage.getItem(DEVICE_KEY);
    if (!id) { id = bytesToHexLocal(randomBytes(8)); localStorage.setItem(DEVICE_KEY, id); }
    return id;
  } catch { return 'ephemeral'; }
}
const bytesToHexLocal = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
export const deviceDtag = (netName) => `${syncDtag(netName)}:d:${deviceId()}`;
// True if `evtDtag` is one of OUR slots for `netName` (our device, another
// device, or the legacy shared tag) — used to select events to merge.
export const isOurDtag = (evtDtag, netName) => {
  const base = syncDtag(netName);
  return evtDtag === base || evtDtag.startsWith(base + ':d:');
};
const SYNC_KEY = 'btc-wallet-sync';
export const DEFAULT_SYNC_RELAYS = ['wss://relay.coinos.io'];

// --- sync preference (enabled + relays), global, persisted in localStorage ---
export function getSyncConfig() {
  try {
    const raw = localStorage.getItem(SYNC_KEY);
    if (raw) {
      const c = JSON.parse(raw);
      const relays = Array.isArray(c.relays) ? c.relays : [];
      return {
        enabled: c.enabled !== false,
        relays: relays.length ? relays : DEFAULT_SYNC_RELAYS,
      };
    }
  } catch {}
  return { enabled: true, relays: DEFAULT_SYNC_RELAYS }; // default: on, coinos relay
}

export function setSyncConfig({ enabled, relays }) {
  try {
    localStorage.setItem(SYNC_KEY, JSON.stringify({ enabled: !!enabled, relays: relays || DEFAULT_SYNC_RELAYS }));
  } catch {}
}

export class NostrSync {
  constructor() {
    this.sk = null;
    this.pk = null;
    this.ck = null; // self conversation key for NIP-44
    this.relays = DEFAULT_SYNC_RELAYS;
    this.dtag = DTAG;
  }

  setDtag(d) { this.dtag = d || DTAG; }

  load(mnemonic, passphrase = '') {
    this.sk = nip06.privateKeyFromSeedWords(mnemonic, passphrase || undefined);
    this.pk = getPublicKey(this.sk);
    this.ck = nip44.getConversationKey(this.sk, this.pk);
  }

  unload() { this.sk = this.pk = this.ck = null; }

  setRelays(relays) {
    this.relays = Array.isArray(relays) && relays.length ? relays : DEFAULT_SYNC_RELAYS;
  }

  // Encrypt + publish the latest state to every relay (best-effort). The d-tag
  // is passed in so a debounced publish keeps the tag of the network the
  // snapshot was taken on, even if the wallet switched networks meanwhile.
  async publish(stateObj, dtag = this.dtag) {
    if (!this.sk) return;
    let evt;
    try {
      const content = nip44.encrypt(JSON.stringify(stateObj), this.ck);
      evt = finalizeEvent({ kind: 30078, created_at: Math.floor(Date.now() / 1000), tags: [['d', dtag]], content }, this.sk);
    } catch { return; }
    await Promise.allSettled(pool.publish(this.relays, evt));
  }

  // Deliver an encrypted DM (a locked gift's claim code) as a NIP-17 gift wrap
  // (kind 1059) — the modern standard every current client supports. Goes to the
  // recipient's published inbox relays (NIP-17/65) plus a broad fallback. Returns
  // true if ≥1 relay accepted it.
  async sendDM(recipientPkHex, text, relays = null) {
    if (!this.sk) return false;
    let evt;
    try { evt = nip17WrapEvent(this.sk, { publicKey: recipientPkHex }, text); } catch { return false; }
    let targets = relays;
    if (!targets) {
      const inbox = await fetchInboxRelays(recipientPkHex);
      targets = [...new Set([...inbox, ...PROFILE_RELAYS])].slice(0, 8); // recipient's inbox + safety net
    }
    const res = await Promise.allSettled(pool.publish(targets, evt));
    return res.some((x) => x.status === 'fulfilled');
  }

  // Publish an arbitrary event (finalized here with our key) to the relays.
  // Used by features that speak their own event kinds (e.g. ark zaps).
  async publishEvent(partial) {
    if (!this.sk) return null;
    let evt;
    try {
      evt = finalizeEvent({ created_at: Math.floor(Date.now() / 1000), tags: [], content: '', ...partial }, this.sk);
    } catch { return null; }
    await Promise.allSettled(pool.publish(this.relays, evt));
    return evt;
  }

  // Fetch events matching a filter from the relays (best-effort).
  async fetchEvents(filter, maxWait = 5000) {
    try { return await pool.querySync(this.relays, filter, { maxWait }); } catch { return []; }
  }

  // Live subscription; returns an unsubscribe function.
  subscribeEvents(filter, onEvent) {
    try {
      const sub = pool.subscribeMany(this.relays, [filter], { onevent: onEvent });
      return () => { try { sub.close(); } catch {} };
    } catch { return () => {}; }
  }

  // Live subscription to ALL our devices' state events (no #d filter), each
  // decrypted and delivered. A save on any device — under any per-device tag —
  // arrives here within seconds. The caller filters by network.
  subscribeStates(onState) {
    if (!this.pk) return () => {};
    return this.subscribeEvents(
      { kinds: [30078], authors: [this.pk] },
      (ev) => {
        try {
          const v = JSON.parse(nip44.decrypt(ev.content, this.ck));
          const dtag = (ev.tags.find((t) => t[0] === 'd') || [])[1] || '';
          if (v) onState(v, dtag);
        } catch {}
      });
  }

  // Fetch the newest decrypted state (kept for callers that want a single
  // best snapshot). Prefers our own device's slot, else the newest of ours.
  async fetch() {
    const all = await this.fetchAllStates();
    return all.length ? all[0].state : null;
  }

  // All of this identity's decrypted state snapshots, newest first, each with
  // its d-tag. The reader merges ark state across every device and applies the
  // newest full snapshot for the (rescannable) on-chain state.
  async fetchAllStates() {
    if (!this.sk) return [];
    let events;
    try { events = await pool.querySync(this.relays, { kinds: [30078], authors: [this.pk] }, { maxWait: 6000 }); } catch { return []; }
    const out = [];
    for (const e of events.sort((a, b) => b.created_at - a.created_at)) {
      try {
        const state = JSON.parse(nip44.decrypt(e.content, this.ck));
        if (state) out.push({ state, dtag: (e.tags.find((t) => t[0] === 'd') || [])[1] || '', created_at: e.created_at });
      } catch {}
    }
    return out;
  }
}

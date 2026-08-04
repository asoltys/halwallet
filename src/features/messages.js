// Messages — Concord community chat (CORD-01..05) + NIP-17 private DMs.
//
// Communities are end-to-end private: there is no global discovery in
// Concord, membership travels by invite. coinos ships with one built-in
// community (below) so every user starts somewhere; beyond it users join by
// invite link, by direct invite (giftwrapped to their npub), or by founding
// their own community in-app.
//
// Identity: the session's nostr login when a signer is live, else the
// wallet's NIP-06 key. Community traffic encrypts under stream keys the app
// holds (signers only sign seals); DMs seal to the peer, which is what the
// widened signer adapters (encryptTo/decryptFrom) exist for. The DM inbox
// listens for both identities and decrypts with whichever keys are present.

import {
  subscribeOn, publishOn, queryOn, fetchNostrProfile, fetchInboxRelays,
  npubOf, parseNostrPubkey, generateSecretKey, getPublicKey, finalizeEvent, nip44,
  PROFILE_RELAYS,
} from '../nostr.js';
import {
  channelKey, controlKey, guestbookKey, openWrap, wrapRumor,
  foldControl, foldGuestbook, observeAuthor, eventMs, msTags, makeEdition,
  communityId, parseInviteLink, makeInviteLink, makeInviteBundleEvent, openInviteBundle,
} from '../concord.js';
import { makeDM, unwrapDM, wrapDM } from '../dm.js';
import { saveInbox } from '../dm-inbox.js';
import { makeSearcher, resultRows, fallbackAvatar } from '../recipient-search.js';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils';
import { t } from '../i18n.js';

// Genesis output of tools/concord-genesis.js — the coinos community's join
// material (CORD-02 §8). The community_root here is deliberately public-ish:
// every coinos user is meant to be a member of the default community.
const COMMUNITY = {
  community_id: 'b517fb4ba04c4c4eac2bd486ee800d1a8644fcdca5c5643098062e7733ee4986',
  owner: '98ae4da926c471c23fd12d1ebdd5839ba82917baa618e184e0c9916d93dcf4f7',
  owner_salt: '466450cd6cd0e6991a5acea091c5bc9e9a1c1ba27a970e64d2af4860e7f60cb1',
  community_root: '58b2ce26eba30fbd19d9a57bce4c61e65838686998f10bba1d3e822fb72b372e',
  root_epoch: 0,
  channels: [{ id: '56bf8b96c1a3768c85444873df507cdbc3275fcbc21996af09e60003f850f85c', name: 'general' }],
  relays: ['wss://relay.coinos.io', 'wss://nos.lol'],
  name: 'coinos',
};

const EPOCH = 0;
const DM_RELAYS = ['wss://relay.coinos.io', 'wss://nos.lol'];
const NOTIFIER = 'https://nwcpush.coinos.io';
const APP_BASE = 'https://v3.coinos.io';
const CACHE_MAX = 50; // messages kept per channel / per DM thread in feature state

export function messagesFeature(ctx) {
  const { h, ui, render, wallet, toast, hook } = ctx;

  // ---- persisted state ----------------------------------------------------

  const st = () => {
    const s = wallet.loadFeatureState('messages', {});
    s.joined ||= {}; // { [cid]: { [pubkey]: true } }
    s.cache ||= {}; // { [channelId]: [msgs] }
    s.communities ||= []; // join material beyond the built-in
    s.invites ||= {}; // { [cid]: { sk, token, url } } — minted links
    s.dms ||= {}; // { [peerPk]: [{ id, from, text, t }] }
    s.declined ||= {}; // direct-invite rumor ids dismissed
    s.tombstones ||= {}; // { [cid]: removed_at ms } — left communities (CORD-02 §8)
    s.read ||= {}; // { ['dm:'+pk | 'ch:'+id]: created_at } — last message we've seen
    s.notify ||= {}; // { [cid]: true } — communities that may buzz your phone (opt-in)
    for (const c of s.communities) c.added_at ||= Date.now();
    // pre-multi-community shape: joined was { [pubkey]: true } for coinos
    for (const k of Object.keys(s.joined))
      if (s.joined[k] === true) { (s.joined[COMMUNITY.community_id] ||= {})[k] = true; delete s.joined[k]; }
    return s;
  };
  const save = (s) => wallet.saveFeatureState('messages', s);

  const communities = () => [COMMUNITY, ...st().communities];

  // ---- unread -------------------------------------------------------------
  // A conversation is unread when its newest message from someone else is
  // newer than the last one we looked at. The watermark is the rumor's own
  // created_at, not a local clock, so it means the same thing on every device
  // the state syncs to. Our own messages never count — sending isn't reading,
  // but you've obviously seen what you wrote.

  const dmRead = (pk) => 'dm:' + pk;
  const chRead = (id) => 'ch:' + id;
  // The list screen has a watermark of its own: standing on it answers the
  // header dot ("someone's waiting" — you've now been shown who), while each
  // row keeps its own dot until that conversation is actually opened.
  const HOME_READ = 'home';

  const newestFrom = (entries, theirs) => {
    let ts = 0;
    for (const m of entries) if (theirs(m)) ts = Math.max(ts, m.rumor.created_at || 0);
    return ts;
  };

  function markRead(key, ts) {
    const s = st();
    if (!ts || (s.read[key] || 0) >= ts) return;
    s.read[key] = ts;
    save(s);
  }

  // Per-conversation dots for the list screen: newer than when we last had
  // that thread (or any channel of that room) open.
  const dmUnread = (pk, msgs) =>
    newestFrom(msgs.values(), (m) => !m.mine) > (st().read[dmRead(pk)] || 0);
  function roomUnread(room) {
    const s = st();
    const my = myPubkeys();
    for (const [id, msgs] of room.byChannel)
      if (newestFrom(msgs.values(), (m) => !my.includes(m.author)) > (s.read[chRead(id)] || 0)) return true;
    return false;
  }

  // How many conversations are waiting on us — the header only draws a dot, but
  // a count keeps the door open for a number later. Floored by the list-screen
  // watermark: once you've seen the list, the header stops repeating it.
  function unreadCount() {
    const s = st();
    const my = myPubkeys();
    const seen = s.read[HOME_READ] || 0;
    let n = 0;
    for (const [pk, msgs] of threads)
      if (newestFrom(msgs.values(), (m) => !m.mine) > Math.max(seen, s.read[dmRead(pk)] || 0)) n++;
    for (const room of rooms.values())
      for (const [id, msgs] of room.byChannel)
        if (newestFrom(msgs.values(), (m) => !my.includes(m.author)) > Math.max(seen, s.read[chRead(id)] || 0)) n++;
    return n;
  }
  const communityById = (cid) => communities().find((c) => c.community_id === cid);

  // ---- identity -----------------------------------------------------------

  // Who we speak as. If the user logged in with a nostr account we speak as
  // that account or not at all — falling back to the wallet's own key would
  // sign under a pubkey that isn't the one their avatar and profile show,
  // which reads to everyone else as a different person entirely.
  async function identity() {
    const id = hook('nostrLoginIdentity');
    if (id) {
      const signer = id.signer || (await hook('nostrLoginResume'));
      return signer ? { pubkey: id.pubkey, signer } : null;
    }
    if (wallet.nostr && wallet.nostr.sk) return { pubkey: wallet.nostr.pk, signer: wallet.nostr.sk };
    return null;
  }
  const myPubkeys = () => {
    const pks = [];
    const id = hook('nostrLoginIdentity');
    if (id) pks.push(id.pubkey);
    if (wallet.nostr && wallet.nostr.pk && !pks.includes(wallet.nostr.pk)) pks.push(wallet.nostr.pk);
    return pks;
  };
  const isMe = (pk) => myPubkeys().includes(pk);

  // ---- shared runtime -----------------------------------------------------

  const rooms = new Map(); // cid -> room runtime
  const threads = new Map(); // peerPk -> Map(rumorId -> { rumor, mine })
  const pendingDirect = new Map(); // rumor id -> { bundle, from }
  const profiles = new Map(); // pubkey -> profile | null while loading
  const seenWraps = new Set();
  let dmStarted = false;
  let allUnsubs = [];

  let repaintTimer = null;
  const scheduleRepaint = () => {
    if (repaintTimer) return;
    repaintTimer = setTimeout(() => {
      repaintTimer = null;
      if (ui.screen === 'wallet') render();
    }, 80);
  };

  // Profiles persist across sessions (capped) so known faces paint right
  // away instead of flashing the punk fallback; entries refresh in the
  // background once a day.
  const PROFILE_TTL = 24 * 3600_000;
  let profilesWarmed = false;
  function warmProfiles() {
    if (profilesWarmed) return;
    profilesWarmed = true;
    const cached = wallet.loadFeatureState('profiles', {});
    for (const [pk, p] of Object.entries(cached)) if (!profiles.has(pk)) profiles.set(pk, p);
  }
  function persistProfile(pk, p) {
    const s = wallet.loadFeatureState('profiles', {});
    s[pk] = { name: p.name || null, picture: p.picture || null, t: Date.now() };
    const keys = Object.keys(s);
    if (keys.length > 150) {
      for (const k of keys.sort((a, b) => (s[a].t || 0) - (s[b].t || 0)).slice(0, keys.length - 150)) delete s[k];
    }
    wallet.saveFeatureState('profiles', s);
  }
  function profileOf(pk) {
    warmProfiles();
    const cur = profiles.get(pk);
    if (cur !== undefined && (cur === null || Date.now() - (cur.t || 0) < PROFILE_TTL)) return cur;
    profiles.set(pk, cur || null); // null = loading, no fallback art yet
    fetchNostrProfile(pk).then((p) => {
      const entry = { ...(p || {}), t: Date.now() };
      profiles.set(pk, entry);
      persistProfile(pk, entry);
      scheduleRepaint();
    }).catch(() => profiles.set(pk, { t: Date.now() }));
    return cur || null;
  }
  const displayName = (pk) => {
    const p = profileOf(pk);
    if (p && p.name) return p.name;
    const npub = npubOf(pk);
    return npub ? npub.slice(0, 12) : pk.slice(0, 12);
  };

  // ---- community rooms ----------------------------------------------------

  function ensureRoom(jm) {
    let room = rooms.get(jm.community_id);
    if (room) return room;
    const root = hexToBytes(jm.community_root);
    room = {
      jm,
      control: controlKey(root, jm.community_id, jm.root_epoch || EPOCH),
      guestbook: guestbookKey(root, jm.community_id, jm.root_epoch || EPOCH),
      chStream: (id) => channelKey(root, id, EPOCH),
      folded: null,
      controlEntries: [],
      guestEntries: [],
      members: new Map(),
      byChannel: new Map(),
      edits: new Map(),
      deletes: new Set(),
      reactions: new Map(),
      presence: new Map(), // pubkey -> ms of their last beat (this session only)
      typing: new Map(), // pubkey -> { ch, t }
      subbed: new Set(),
      relays: jm.relays && jm.relays.length ? jm.relays : DM_RELAYS,
    };
    rooms.set(jm.community_id, room);

    const refold = () => { room.folded = foldControl(room.controlEntries, { ownerHex: jm.owner, cid: jm.community_id }); };
    const refoldGuestbook = () => {
      room.members = foldGuestbook(room.guestEntries, { nowMs: Date.now(), banned: room.folded?.banned });
      for (const [, msgs] of room.byChannel)
        for (const { rumor, author } of msgs.values()) {
          const tms = eventMs(rumor);
          if (tms) observeAuthor(room.members, author, tms);
        }
    };

    allUnsubs.push(
      subscribeOn(room.relays, { kinds: [1059], authors: [room.control.pk], limit: 500 }, (wrap) => {
        if (seenWraps.has(wrap.id)) return;
        seenWraps.add(wrap.id);
        const opened = openWrap(wrap, room.control);
        if (!opened || opened.rumor.kind !== 3308) return;
        room.controlEntries.push(opened);
        refold();
        scheduleRepaint();
      }),
      subscribeOn(room.relays, { kinds: [1059], authors: [room.guestbook.pk], limit: 500 }, (wrap) => {
        if (seenWraps.has(wrap.id)) return;
        seenWraps.add(wrap.id);
        const opened = openWrap(wrap, room.guestbook);
        if (!opened) return;
        room.guestEntries.push(opened);
        refoldGuestbook();
        scheduleRepaint();
      })
    );
    for (const c of jm.channels || []) subChannel(room, c.id);
    // warm from local cache so the page paints before relays answer
    const cached = st().cache;
    for (const c of jm.channels || [])
      for (const m of cached[c.id] || []) {
        const msgs = room.byChannel.get(c.id) || room.byChannel.set(c.id, new Map()).get(c.id);
        if (!msgs.has(m.rumor.id)) msgs.set(m.rumor.id, m);
      }
    return room;
  }

  function subChannel(room, id) {
    if (room.subbed.has(id)) return;
    room.subbed.add(id);
    allUnsubs.push(subscribeOn(room.relays, { kinds: [1059, 21059], authors: [room.chStream(id).pk], limit: 200 }, (wrap) => {
      if (seenWraps.has(wrap.id)) return;
      seenWraps.add(wrap.id);
      const opened = openWrap(wrap, room.chStream(id));
      if (!opened) return;
      onChat(room, id, opened);
    }));
  }

  function onChat(room, channelId, { rumor, author }) {
    const tag = (k) => rumor.tags?.find((x) => x[0] === k);
    // CORD-03 §3: the rumor must commit to the channel/epoch that decrypted it
    if (tag('channel')?.[1] !== channelId || tag('epoch')?.[1] !== String(EPOCH)) return;
    if (room.folded && room.folded.banned.has(author)) return;
    if (rumor.kind === PRESENCE || rumor.kind === TYPING) {
      // Dated by the beat itself, never by arrival. Relays hand back stored
      // beats when we subscribe, and treating those as "just now" would light
      // up the whole member list as online. Clamped to now so a fast clock
      // can't hold someone online forever.
      const ts = Math.min(Date.now(), eventMs(rumor) || rumor.created_at * 1000);
      if (ts > (room.presence.get(author) || 0)) room.presence.set(author, ts);
      if (rumor.kind === TYPING && Date.now() - ts < TYPING_MS) {
        room.typing.set(author, { ch: channelId, t: ts });
        setTimeout(scheduleRepaint, TYPING_MS + 100); // clear itself when it lapses
      }
      scheduleRepaint();
      return;
    }
    if (rumor.kind === 9) {
      const msgs = room.byChannel.get(channelId) || room.byChannel.set(channelId, new Map()).get(channelId);
      msgs.set(rumor.id, { rumor, author });
      room.typing.delete(author); // the message itself ends the "typing…"
    } else if (rumor.kind === 5) {
      for (const e of rumor.tags.filter((x) => x[0] === 'e')) {
        const m = room.byChannel.get(channelId)?.get(e[1]);
        if (!m || m.author === author) room.deletes.add(e[1]);
      }
    } else if (rumor.kind === 3302) {
      const target = tag('e')?.[1];
      if (target) {
        const cur = room.edits.get(target);
        if (!cur || eventMs(rumor) > eventMs(cur.rumor)) room.edits.set(target, { rumor, author });
      }
    } else if (rumor.kind === 7) {
      const target = tag('e')?.[1];
      if (target) {
        const r = room.reactions.get(target) || room.reactions.set(target, new Map()).get(target);
        r.set(author, rumor.content);
      }
    }
    const tms = eventMs(rumor);
    if (tms) observeAuthor(room.members, author, tms);
    scheduleRepaint();
  }

  const roomChannels = (room) => {
    if (room.folded && room.folded.channels.size)
      return [...room.folded.channels.entries()].map(([id, c]) => ({ id, name: c.name }));
    return room.jm.channels || [];
  };

  function persistCache(room) {
    const s = st();
    for (const [chId, msgs] of room.byChannel) {
      s.cache[chId] = [...msgs.values()]
        .filter((m) => !room.deletes.has(m.rumor.id))
        .sort((a, b) => eventMs(a.rumor) - eventMs(b.rumor))
        .slice(-CACHE_MAX);
    }
    save(s);
  }

  async function ensureJoined(room, id) {
    const s = st();
    const j = (s.joined[room.jm.community_id] ||= {});
    if (j[id.pubkey]) return;
    const { created_at, ms } = msTags(Date.now());
    const tags = [ms];
    if (room.jm.invitedBy) tags.push(['invite', room.jm.invitedBy, room.jm.inviteLabel || '']);
    const wrap = await wrapRumor({ kind: 3306, pubkey: id.pubkey, content: 'join', tags, created_at }, id.signer, room.guestbook);
    publishOn(room.relays, wrap);
    j[id.pubkey] = true;
    save(s);
  }

  async function sendMessage(room, chId) {
    const text = (ui.msgDraft || '').trim();
    if (!text || ui.msgSending) return;
    const id = await identity();
    if (!id) { toast(t('msgNoIdentity')); return; }
    ui.msgSending = true;
    render();
    try {
      const { created_at, ms } = msTags(Date.now());
      const rumor = {
        kind: 9, pubkey: id.pubkey, content: text,
        tags: [['channel', chId], ['epoch', String(EPOCH)], ms], created_at,
      };
      const wrap = await wrapRumor(rumor, id.signer, room.chStream(chId));
      // optimistic insert (the relay echo will dedupe on wrap id)
      const opened = openWrap(wrap, room.chStream(chId));
      if (opened) {
        seenWraps.add(wrap.id);
        const msgs = room.byChannel.get(chId) || room.byChannel.set(chId, new Map()).get(chId);
        msgs.set(opened.rumor.id, opened);
      }
      ui.msgDraft = '';
      const ok = await publishOn(room.relays, wrap);
      if (!ok) toast(t('msgSendFailed'));
      ensureJoined(room, id).catch(() => {});
      persistCache(room);
    } catch (e) {
      toast(e.message || String(e));
    } finally {
      ui.msgSending = false;
      ui.msgStick = true;
      render();
    }
  }

  async function deleteMessage(room, chId, m) {
    const id = await identity();
    if (!id || id.pubkey !== m.author) return;
    const { created_at, ms } = msTags(Date.now());
    const rumor = {
      kind: 5, pubkey: id.pubkey, content: '',
      tags: [['channel', chId], ['epoch', String(EPOCH)], ['e', m.rumor.id], ['k', '9'], ms], created_at,
    };
    const wrap = await wrapRumor(rumor, id.signer, room.chStream(chId));
    room.deletes.add(m.rumor.id);
    render();
    publishOn(room.relays, wrap);
    persistCache(room);
  }

  // ---- founding a community (CORD-02 genesis) -----------------------------

  async function createCommunity(name) {
    const id = await identity();
    if (!id) { toast(t('msgNoIdentity')); return; }
    name = name.trim().slice(0, 64);
    if (!name) return;
    const ownerSalt = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
    const rootBytes = crypto.getRandomValues(new Uint8Array(32));
    const cid = communityId(id.pubkey, ownerSalt);
    const generalId = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
    const control = controlKey(rootBytes, cid, 0);
    const guestbook = guestbookKey(rootBytes, cid, 0);
    const now = Date.now();
    const relays = DM_RELAYS;
    const meta = { ...makeEdition({ vsk: 0, eid: cid, version: 1, content: JSON.stringify({ name, relays }) }, now), pubkey: id.pubkey };
    const general = { ...makeEdition({ vsk: 2, eid: generalId, version: 1, content: JSON.stringify({ name: 'general', private: false }) }, now + 1), pubkey: id.pubkey };
    const { created_at, ms } = msTags(now + 2);
    const join = { kind: 3306, pubkey: id.pubkey, content: 'join', tags: [ms], created_at };
    const events = [
      await wrapRumor(meta, id.signer, control, { plaintext: true }),
      await wrapRumor(general, id.signer, control, { plaintext: true }),
      await wrapRumor(join, id.signer, guestbook),
    ];
    for (const e of events) await publishOn(relays, e);
    const jm = {
      community_id: cid, owner: id.pubkey, owner_salt: ownerSalt,
      community_root: bytesToHex(rootBytes), root_epoch: 0,
      channels: [{ id: generalId, name: 'general' }], relays, name,
      added_at: Date.now(),
    };
    const s = st();
    s.communities.push(jm);
    (s.joined[cid] ||= {})[id.pubkey] = true;
    save(s);
    publishLists();
    registerPush().catch(() => {});
    ensureRoom(jm);
    ui.msgView = 'room';
    ui.msgCommunity = cid;
    ui.msgChannel = null;
    ui.msgNewName = '';
    ui.msgHomePanel = null;
    render();
  }

  // A new channel is one owner-signed ChannelMetadata edition (CORD-03 §2);
  // the control-plane fold picks it up and every member's switcher grows.
  async function createChannel(room, name) {
    name = (name || '').trim().slice(0, 64);
    if (!name) return;
    const id = await identity();
    if (!id || id.pubkey !== room.jm.owner) { toast(t('msgOwnerOnly')); return; }
    const chId = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
    const edition = {
      ...makeEdition({ vsk: 2, eid: chId, version: 1, content: JSON.stringify({ name: name.replace(/^#/, ''), private: false }) }, Date.now()),
      pubkey: id.pubkey,
    };
    const wrap = await wrapRumor(edition, id.signer, room.control, { plaintext: true });
    const ok = await publishOn(room.relays, wrap);
    if (!ok) { toast(t('msgSendFailed')); return; }
    ui.msgNewChannel = '';
    ui.msgChannelPanel = false; // the field has done its job — put it away
    toast('#' + name.replace(/^#/, ''));
  }

  // ---- invites ------------------------------------------------------------

  function bundleFor(room, creatorPk) {
    return {
      community_id: room.jm.community_id, owner: room.jm.owner, owner_salt: room.jm.owner_salt,
      community_root: room.jm.community_root, root_epoch: room.jm.root_epoch || 0,
      channels: roomChannels(room).map((c) => ({ id: c.id, name: c.name })),
      relays: room.relays, name: (room.folded?.metadata?.name) || room.jm.name,
      creator_npub: creatorPk,
    };
  }

  async function mintInviteLink(room) {
    const id = await identity();
    if (!id) { toast(t('msgNoIdentity')); return null; }
    const s = st();
    const existing = s.invites[room.jm.community_id];
    if (existing) return existing.url;
    const linkSk = generateSecretKey();
    const token = crypto.getRandomValues(new Uint8Array(16));
    const evt = makeInviteBundleEvent(linkSk, bundleFor(room, id.pubkey), token);
    const ok = await publishOn(room.relays, evt);
    if (!ok) { toast(t('msgSendFailed')); return null; }
    const url = makeInviteLink(APP_BASE, getPublicKey(linkSk), room.relays, token);
    s.invites[room.jm.community_id] = { sk: bytesToHex(linkSk), token: bytesToHex(token), url, created_at: Math.floor(Date.now() / 1000) };
    save(s);
    publishLists();
    return url;
  }

  async function sendDirectInvite(room, input) {
    const peer = parseNostrPubkey(input);
    if (!peer) { toast(t('msgBadNpub')); return; }
    const id = await identity();
    if (!id) { toast(t('msgNoIdentity')); return; }
    if (!(id.signer instanceof Uint8Array) && !id.signer.encryptTo) { toast(t('msgSignerNoDm')); return; }
    const rumor = {
      kind: 3313, pubkey: id.pubkey,
      content: JSON.stringify(bundleFor(room, id.pubkey)),
      tags: [], created_at: Math.floor(Date.now() / 1000),
    };
    const wrap = await wrapDM(id.signer, peer, rumor, [['k', '3313']]);
    const inbox = (await fetchInboxRelays(peer)).slice(0, 4);
    const ok = await publishOn([...new Set([...inbox, ...DM_RELAYS])], wrap);
    toast(ok ? t('msgInviteSent') : t('msgSendFailed'));
  }

  function acceptBundle(b, { invitedBy, inviteLabel } = {}) {
    const s = st();
    if (!communityById(b.community_id)) {
      const jm = {
        community_id: b.community_id, owner: b.owner, owner_salt: b.owner_salt,
        community_root: b.community_root, root_epoch: b.root_epoch || 0,
        channels: (b.channels || []).map((c) => ({ id: c.id, name: c.name })),
        relays: (b.relays || []).slice(0, 5), name: b.name || 'community',
        invitedBy, inviteLabel, added_at: Date.now(),
      };
      s.communities.push(jm);
      save(s);
      publishLists();
    }
    const room = ensureRoom(communityById(b.community_id));
    identity().then((id) => id && ensureJoined(room, id)).catch(() => {});
    registerPush().catch(() => {});
    ui.msgView = 'room';
    ui.msgCommunity = b.community_id;
    ui.msgChannel = null;
    ui.msgHomePanel = null;
    pendingLink = null;
    render();
  }

  // A link invite being previewed (pasted or arrived via /invite/<naddr>#…).
  let pendingLink = null; // { parsed, state: 'loading'|'ready'|'error', bundle?, error? }

  async function loadLinkInvite(parsed) {
    pendingLink = { parsed, state: 'loading' };
    scheduleRepaint();
    const relays = [...new Set([...(parsed.relays || []), ...DM_RELAYS])];
    const evts = await queryOn(relays, { kinds: [33301], authors: [parsed.signerPk] }, 4000);
    const newest = evts.sort((a, b) => b.created_at - a.created_at)[0];
    const b = newest && openInviteBundle(newest, parsed.token);
    if (!b) pendingLink = { parsed, state: 'error', error: t('msgInviteNotFound') };
    else if (b.revoked) pendingLink = { parsed, state: 'error', error: t('msgInviteRevoked') };
    else if (b.expired) pendingLink = { parsed, state: 'error', error: t('msgInviteExpired') };
    else pendingLink = { parsed, state: 'ready', bundle: b };
    scheduleRepaint();
  }

  function joinFromText(text) {
    const parsed = parseInviteLink(text);
    if (!parsed) { toast(t('msgBadInvite')); return; }
    ui.msgJoinText = '';
    ui.msgHomePanel = null;
    loadLinkInvite(parsed);
  }

  // An invite link opened in the browser lands here before the wallet exists.
  const urlInvite = typeof location !== 'undefined' ? parseInviteLink(location.href) : null;
  if (urlInvite) { try { history.replaceState(null, '', '/'); } catch {} }

  // ---- push notifications -------------------------------------------------
  // The nwcpush notifier watches relays for what it can see without keys:
  // kind-1059 wraps p-tagged at us (DMs, direct invites), zap receipts
  // (payments), and wraps authored by our communities' channel keys (chat).
  // It pushes a typed nudge; the service worker shows a generic notification
  // unless a window is visible. Payment pushes also arrive server-to-server
  // from the names registrar when a lightning-address receive settles.

  const b64ToBytes = (b64) => {
    const pad = '='.repeat((4 - (b64.length % 4)) % 4);
    const raw = atob((b64 + pad).replace(/-/g, '+').replace(/_/g, '/'));
    return Uint8Array.from(raw, (c) => c.charCodeAt(0));
  };

  // What the notifier is allowed to wake us for. Communities are opt-in and
  // off by default: a busy room would otherwise buzz a phone all day for
  // conversations that aren't addressed to anyone in particular.
  function pushWatch() {
    const on = st().notify;
    const authors = [];
    for (const jm of communities()) {
      if (!on[jm.community_id]) continue;
      const root = hexToBytes(jm.community_root);
      for (const c of (jm.channels || []).slice(0, 8)) authors.push(channelKey(root, c.id, EPOCH).pk);
    }
    return { ptags: myPubkeys(), authors };
  }

  const roomNotify = (cid) => !!st().notify[cid];
  async function toggleRoomNotify(cid) {
    const s = st();
    if (s.notify[cid]) delete s.notify[cid]; else s.notify[cid] = true;
    save(s);
    render();
    // The server keeps the watch list, so the change only lands once we
    // re-register. Asking for permission is fair here — they just opted in.
    const ok = await registerPush({ interactive: !!s.notify[cid] });
    if (!ok && s.notify[cid]) {
      const s2 = st();
      delete s2.notify[cid];
      save(s2);
      toast(t('msgPushFailed'));
      render();
    }
  }

  // Hand the service worker what it needs to tell a friend's DM from a
  // stranger's: our key (only if we actually hold one), who we follow, and the
  // names we already know. See dm-inbox.js for the threat model — a remote
  // signer stores no key here and simply gets unfiltered notifications.
  let inboxAt = 0;
  async function syncInbox({ force = false } = {}) {
    if (!force && Date.now() - inboxAt < 5 * 60_000) return;
    inboxAt = Date.now();
    try {
      const id = await identity();
      if (!id) return;
      const evs = await queryOn([...new Set([...PROFILE_RELAYS, ...DM_RELAYS])],
        { kinds: [3], authors: [id.pubkey] }, 4000);
      const newest = evs.sort((a, b) => b.created_at - a.created_at)[0];
      const follows = newest
        ? [...new Set(newest.tags.filter((x) => x[0] === 'p' && /^[0-9a-f]{64}$/.test(x[1] || '')).map((x) => x[1]))]
        : [];
      const known = [...threads.keys()];
      const names = {};
      for (const pk of [...follows, ...known]) {
        const p = profiles.get(pk);
        if (p && p.name) names[pk] = p.name;
      }
      await saveInbox(wallet._cacheKey(), {
        pubkey: id.pubkey,
        sk: id.signer instanceof Uint8Array ? bytesToHex(id.signer) : null,
        follows, known, names, hasList: !!newest, updated: Date.now(),
      });
    } catch { inboxAt = 0; }
  }

  async function registerPush({ interactive = false } = {}) {
    try {
      if (typeof Notification === 'undefined' || !('serviceWorker' in navigator) || !('PushManager' in window)) return false;
      if (Notification.permission !== 'granted') {
        if (!interactive) return false;
        if ((await Notification.requestPermission()) !== 'granted') return false;
      }
      const reg = await navigator.serviceWorker.ready;
      let sub = await reg.pushManager.getSubscription();
      if (!sub) {
        const { publicKey } = await (await fetch(`${NOTIFIER}/vapid`)).json();
        sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64ToBytes(publicKey) });
      }
      const r = await fetch(`${NOTIFIER}/register`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ subscription: sub.toJSON(), notify: pushWatch() }),
      });
      if (!r.ok) return false;
      const s = st();
      if (!s.push) { s.push = true; save(s); }
      return true;
    } catch {
      return false;
    }
  }

  // ---- device sync: Community List (13302) + Invite List (13303) ----------
  // Self-encrypted replaceables (CORD-02 §8 / CORD-05 §4) so memberships and
  // minted link keys follow the user to any device or client. Published under
  // every identity we can encrypt for: the wallet key is the cross-device
  // constant (same seed on every device), the login npub makes the list
  // readable by other Concord clients serving the same identity.

  async function selfCryptors() {
    const out = [];
    if (wallet.nostr && wallet.nostr.sk && wallet.nostr.ck) out.push({
      pk: wallet.nostr.pk,
      sign: async (e) => finalizeEvent(e, wallet.nostr.sk),
      enc: async (txt) => nip44.encrypt(txt, wallet.nostr.ck),
      dec: async (ct) => nip44.decrypt(ct, wallet.nostr.ck),
    });
    const login = hook('nostrLoginIdentity');
    if (login && login.signer && login.signer.encryptSelf) out.push({
      pk: login.pubkey,
      sign: (e) => login.signer.signEvent(e),
      enc: (txt) => login.signer.encryptSelf(txt),
      dec: (ct) => login.signer.decryptSelf(ct),
    });
    return out;
  }

  // Join material subset (never the icon, never link fields). We only run
  // epoch 0 today, so seed and current coincide.
  const jmSubset = (jm) => ({
    community_id: jm.community_id, owner: jm.owner, owner_salt: jm.owner_salt,
    community_root: jm.community_root, root_epoch: jm.root_epoch || 0,
    channels: (jm.channels || []).map((c) => ({ id: c.id, name: c.name })),
    relays: jm.relays, name: jm.name,
  });

  const buildCommunityList = (s) => JSON.stringify({
    entries: s.communities.slice(0, 50).map((jm) => ({
      community_id: jm.community_id, seed: jmSubset(jm), current: jmSubset(jm), added_at: jm.added_at || 0,
    })),
    tombstones: Object.entries(s.tombstones).map(([community_id, removed_at]) => ({ community_id, removed_at })),
  });

  const buildInviteList = (s) => JSON.stringify({
    entries: Object.entries(s.invites).map(([community_id, inv]) => ({
      token: inv.token, signer_sk: inv.sk, community_id, url: inv.url, created_at: inv.created_at || 0,
    })),
    tombstones: [],
  });

  function mergeCommunityList(doc) {
    const s = st();
    let changed = false;
    for (const tb of doc.tombstones || []) {
      if ((tb.removed_at || 0) > (s.tombstones[tb.community_id] || 0)) {
        s.tombstones[tb.community_id] = tb.removed_at;
        changed = true;
      }
    }
    for (const e of (doc.entries || []).slice(0, 50)) {
      const jm = e.current || e.seed;
      if (!jm || jm.community_id !== e.community_id) continue;
      if (jm.community_id === COMMUNITY.community_id) continue; // built-in
      if ((e.added_at || 0) <= (s.tombstones[e.community_id] || 0)) continue; // tombstone wins
      if (s.communities.some((c) => c.community_id === e.community_id)) continue;
      if (communityId(jm.owner, jm.owner_salt) !== jm.community_id) continue; // self-certify before adopting keys
      if (!/^[0-9a-f]{64}$/.test(jm.community_root || '')) continue;
      s.communities.push({ ...jmSubset(jm), added_at: e.added_at || Date.now() });
      changed = true;
    }
    // a tombstone newer than an entry's added_at removes it locally too
    const keep = s.communities.filter((c) => (s.tombstones[c.community_id] || 0) <= (c.added_at || 0));
    if (keep.length !== s.communities.length) { s.communities = keep; changed = true; }
    if (changed) save(s);
    return changed;
  }

  function mergeInviteList(doc) {
    const s = st();
    let changed = false;
    for (const e of doc.entries || []) {
      if (!e.token || !e.community_id || !e.signer_sk) continue;
      if (!s.invites[e.community_id]) {
        s.invites[e.community_id] = { sk: e.signer_sk, token: e.token, url: e.url, created_at: e.created_at };
        changed = true;
      }
    }
    if (changed) save(s);
    return changed;
  }

  async function publishLists() {
    const ids = await selfCryptors();
    const s = st();
    const docs = [[13302, buildCommunityList(s)], [13303, buildInviteList(s)]];
    for (const id of ids)
      for (const [kind, doc] of docs) {
        try {
          const evt = await id.sign({
            kind, content: await id.enc(doc), tags: [], created_at: Math.floor(Date.now() / 1000),
          });
          publishOn(DM_RELAYS, evt);
        } catch {}
      }
  }

  let listsSynced = false;
  async function syncLists() {
    if (listsSynced) return;
    const ids = await selfCryptors();
    if (!ids.length) return;
    listsSynced = true;
    const evs = await queryOn(DM_RELAYS, { kinds: [13302, 13303], authors: ids.map((i) => i.pk) }, 3500);
    let changed = false;
    const remoteDocs = new Set();
    for (const kind of [13302, 13303])
      for (const id of ids) {
        const newest = evs.filter((e) => e.kind === kind && e.pubkey === id.pk).sort((a, b) => b.created_at - a.created_at)[0];
        if (!newest) continue;
        try {
          const raw = await id.dec(newest.content);
          remoteDocs.add(kind + ':' + raw);
          const doc = JSON.parse(raw);
          if (kind === 13302) changed = mergeCommunityList(doc) || changed;
          else changed = mergeInviteList(doc) || changed;
        } catch {}
      }
    if (changed) {
      for (const jm of communities()) ensureRoom(jm);
      scheduleRepaint();
    }
    // republish when any identity's copy is missing or stale
    const s = st();
    const current = [[13302, buildCommunityList(s)], [13303, buildInviteList(s)]];
    const anyMissing = ids.length * 2 > remoteDocs.size
      || current.some(([kind, doc]) => !remoteDocs.has(kind + ':' + doc));
    if (anyMissing && (s.communities.length || Object.keys(s.invites).length || Object.keys(s.tombstones).length))
      publishLists();
  }

  async function leaveCommunity(room) {
    const cid = room.jm.community_id;
    const id = await identity();
    const s = st();
    s.tombstones[cid] = Date.now();
    s.communities = s.communities.filter((c) => c.community_id !== cid);
    delete s.joined[cid];
    save(s);
    if (id) {
      const { created_at, ms } = msTags(Date.now());
      wrapRumor({ kind: 3306, pubkey: id.pubkey, content: 'leave', tags: [ms], created_at }, id.signer, room.guestbook)
        .then((w) => publishOn(room.relays, w)).catch(() => {});
    }
    rooms.delete(cid);
    publishLists();
    ui.msgView = 'home';
    ui.msgLeaveArm = false;
    ui.msgInvitePanel = false;
    render();
  }

  // ---- DMs ----------------------------------------------------------------

  const threadOf = (peer) => threads.get(peer) || threads.set(peer, new Map()).get(peer);

  function noteDM(peer, rumor, mine) {
    if (!peer || !rumor.id) return;
    threadOf(peer).set(rumor.id, { rumor, mine });
    scheduleRepaint();
  }

  async function handleInboxWrap(wrap) {
    if (seenWraps.has(wrap.id)) return;
    seenWraps.add(wrap.id);
    const decryptors = [];
    if (wallet.nostr && wallet.nostr.sk) decryptors.push(wallet.nostr.sk);
    const login = hook('nostrLoginIdentity');
    if (login && login.signer && login.signer.decryptFrom) decryptors.push(login.signer);
    for (const d of decryptors) {
      const got = await unwrapDM(wrap, d).catch(() => null);
      if (!got) continue;
      if (got.rumor.kind === 14) {
        noteDM(got.peer, got.rumor, isMe(got.author));
        persistDms();
      } else if (got.rumor.kind === 3313 && !isMe(got.author)) {
        try {
          const b = openDirectBundle(got.rumor.content);
          if (b && !st().declined[got.rumor.id] && !communityById(b.community_id))
            pendingDirect.set(got.rumor.id, { bundle: b, from: got.author, rid: got.rumor.id });
          scheduleRepaint();
        } catch {}
      }
      return;
    }
  }

  function openDirectBundle(json) {
    const b = JSON.parse(json);
    if (communityId(b.owner, b.owner_salt) !== b.community_id) return null;
    if (!/^[0-9a-f]{64}$/.test(b.community_root || '')) return null;
    if (!Array.isArray(b.channels) || b.channels.length > 256) return null;
    if (b.expires_at && Date.now() > b.expires_at) return null;
    return b;
  }

  function startDMs() {
    if (dmStarted) return;
    const pks = myPubkeys();
    if (!pks.length) return;
    dmStarted = true;
    // warm threads from the local cache
    const s = st();
    for (const [peer, list] of Object.entries(s.dms))
      for (const m of list)
        threadOf(peer).set(m.id, { rumor: { id: m.id, pubkey: m.from, content: m.text, created_at: m.t, kind: 14 }, mine: isMe(m.from) });
    allUnsubs.push(subscribeOn(DM_RELAYS, { kinds: [1059], '#p': pks, limit: 400 }, (wrap) => {
      handleInboxWrap(wrap).catch(() => {});
    }));
    ensureDmRelayList().catch(() => {});
  }

  // Publish a kind 10050 DM-relay list for the wallet key if none exists, so
  // other NIP-17 clients can find our inbox. Never touch a login npub's list
  // — the user's other clients own that.
  async function ensureDmRelayList() {
    if (!wallet.nostr || !wallet.nostr.sk) return;
    const pk = wallet.nostr.pk;
    const existing = await queryOn(DM_RELAYS, { kinds: [10050], authors: [pk] }, 2500);
    if (existing.length) return;
    const evt = finalizeEvent({
      kind: 10050,
      content: '',
      tags: DM_RELAYS.map((r) => ['relay', r]),
      created_at: Math.floor(Date.now() / 1000),
    }, wallet.nostr.sk);
    publishOn(DM_RELAYS, evt);
  }

  async function sendDM(peer) {
    const text = (ui.msgDraft || '').trim();
    if (!text || ui.msgSending) return;
    const id = await identity();
    if (!id) { toast(t('msgNoIdentity')); return; }
    if (!(id.signer instanceof Uint8Array) && !id.signer.encryptTo) { toast(t('msgSignerNoDm')); return; }
    ui.msgSending = true;
    render();
    try {
      const { rumor, toPeer, toSelf } = await makeDM(id.signer, peer, text);
      noteDM(peer, rumor, true);
      ui.msgDraft = '';
      const inbox = (await fetchInboxRelays(peer)).slice(0, 4);
      const ok = await publishOn([...new Set([...inbox, ...DM_RELAYS])], toPeer);
      publishOn(DM_RELAYS, toSelf);
      if (!ok) toast(t('msgSendFailed'));
      persistDms();
    } catch (e) {
      toast(e.message || String(e));
    } finally {
      ui.msgSending = false;
      ui.msgStick = true;
      render();
    }
  }

  function persistDms() {
    const s = st();
    const byRecent = [...threads.entries()]
      .map(([peer, m]) => [peer, [...m.values()].sort((a, b) => a.rumor.created_at - b.rumor.created_at)])
      .sort((a, b) => (b[1].at(-1)?.rumor.created_at || 0) - (a[1].at(-1)?.rumor.created_at || 0))
      .slice(0, 30);
    s.dms = {};
    for (const [peer, list] of byRecent)
      s.dms[peer] = list.slice(-CACHE_MAX).map((m) => ({ id: m.rumor.id, from: m.rumor.pubkey, text: m.rumor.content, t: m.rumor.created_at }));
    save(s);
  }

  // ---- views --------------------------------------------------------------

  const timeLabel = (tms) => {
    const d = new Date(tms);
    const today = new Date().toDateString() === d.toDateString();
    return today
      ? d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
      : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) +
        ' ' + d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  };

  const avatar = (pk, cls = 'chat-avatar', clickable = true) => {
    const p = profileOf(pk);
    // While the profile is in flight, a quiet empty circle — the punk is a
    // statement about having no picture, not a loading state.
    const node = p === null
      ? h('div', { class: cls + ' fallback loading' })
      : p.picture
        // A background paints synchronously from cache; a fresh <img> decodes
        // async, so recreating one per render made avatars visibly flash.
        ? h('div', { class: cls + ' ava-img', style: `background-image:url(${JSON.stringify(p.picture)})` })
        : fallbackAvatar(h, pk, p.name, cls);
    if (clickable) {
      node.classList.add('clickable');
      node.addEventListener('click', (e) => { e.stopPropagation(); openProfile(pk); });
    }
    return node;
  };

  // ---- profiles: view + own kind-0 editor ---------------------------------

  const fullProfiles = new Map(); // pk -> { raw kind0 content object, fetched_at }
  function openProfile(pk) {
    ui.profilePk = pk;
    ui.profEdit = null;
    render();
    if (!fullProfiles.has(pk)) {
      queryOn([...new Set([...PROFILE_RELAYS, ...DM_RELAYS])], { kinds: [0], authors: [pk] }, 3500).then((evs) => {
        const newest = evs.sort((a, b) => b.created_at - a.created_at)[0];
        let m = {};
        try { m = newest ? JSON.parse(newest.content) : {}; } catch {}
        fullProfiles.set(pk, m);
        profiles.set(pk, { name: m.display_name || m.name || null, picture: m.picture || null });
        if (ui.profilePk === pk) render();
      }).catch(() => fullProfiles.set(pk, {}));
    }
  }

  async function saveProfile() {
    const id = await identity();
    if (!id) { toast(t('msgNoIdentity')); return; }
    const e = ui.profEdit;
    ui.profSaving = true;
    render();
    try {
      // merge over the newest published kind 0 so unknown fields round-trip
      const evs = await queryOn([...new Set([...PROFILE_RELAYS, ...DM_RELAYS])], { kinds: [0], authors: [id.pubkey] }, 3000);
      const newest = evs.sort((a, b) => b.created_at - a.created_at)[0];
      let base = {};
      try { base = newest ? JSON.parse(newest.content) : {}; } catch {}
      const merged = { ...base };
      for (const [k, v] of [['name', e.name], ['about', e.about], ['picture', e.picture]]) {
        if (v.trim()) merged[k] = v.trim();
        else delete merged[k];
      }
      // Not an editable field: someone else's lightning address is theirs to
      // manage, and editing it here reads like renaming their coinos account.
      // We only fill one in when the profile has none, so zaps can find them.
      if (!merged.lud16) {
        const addr = hook('namesAddress');
        if (addr) merged.lud16 = addr;
      }
      if (merged.name) merged.display_name = merged.name;
      const partial = { kind: 0, content: JSON.stringify(merged), tags: [], created_at: Math.floor(Date.now() / 1000) };
      const evt = id.signer instanceof Uint8Array ? finalizeEvent(partial, id.signer) : await id.signer.signEvent(partial);
      const ok = await publishOn([...new Set([...PROFILE_RELAYS, ...DM_RELAYS])], evt);
      if (!ok) throw new Error(t('msgSendFailed'));
      fullProfiles.set(id.pubkey, merged);
      profiles.set(id.pubkey, { name: merged.name || null, picture: merged.picture || null });
      ui.profEdit = null;
      toast(t('profSaved'));
    } catch (err) {
      toast(err.message || String(err));
    } finally {
      ui.profSaving = false;
      render();
    }
  }

  function profileScreen() {
    const pk = ui.profilePk;
    const mine = isMe(pk);
    const full = fullProfiles.get(pk);
    // Your own profile IS the editor — the form appears prefilled as soon as
    // the published kind 0 arrives, no Edit step.
    if (mine && !ui.profEdit && full !== undefined) {
      ui.profEdit = {
        name: full.display_name || full.name || '',
        about: full.about || '',
        picture: full.picture || '',
      };
    }
    const name = displayName(pk);
    const npub = npubOf(pk) || pk;
    const field = (label, key, ph = '', multi = false) => h('label', { class: 'field' },
      h('span', { class: 'lab' }, label),
      h(multi ? 'textarea' : 'input', {
        ...(multi ? { rows: '4', style: 'font-family:var(--sans);min-height:72px' } : { type: 'text' }),
        placeholder: ph, value: ui.profEdit[key],
        onInput: (ev) => { ui.profEdit[key] = ev.target.value; },
      }));
    // A lightning address worth showing: not an npub-shaped machine address
    // (npub1…@some.relay duplicates the npub below) and not the same string
    // as the nip05 already on screen.
    const nip05 = full && full.nip05 ? String(full.nip05).replace(/^_@/, '') : null;
    const lud16 = full && full.lud16 ? String(full.lud16) : null;
    const showLud = lud16 && !/^npub1/i.test(lud16) && lud16 !== nip05;
    // an about of "~" or a lone character is noise, not a bio
    const about = full && typeof full.about === 'string' ? full.about.trim() : '';
    const showAbout = about.length > 1;
    return h('div', { class: 'col', style: 'gap:16px' },
      ctx.brandHeader(false),
      h('div', { class: 'card col', style: 'gap:12px' },
        h('div', { class: 'row gap6', style: 'align-items:center' },
          avatar(pk, 'chat-avatar profile-avatar', false),
          h('div', { class: 'col grow', style: 'min-width:0;gap:2px' },
            h('div', { class: 'chat-title' }, name),
            nip05 ? h('div', { class: 'muted small break' }, nip05) : null,
            showLud ? h('div', { class: 'muted small break' }, '⚡ ' + lud16) : null)),
        full === undefined
          ? h('div', { class: 'row gap6', style: 'align-items:center' }, h('span', { class: 'spinner sm' }))
          // the editor's About textarea IS the bio here — no static copy above it
          : showAbout && !ui.profEdit ? h('p', { class: 'small', style: 'margin:0;white-space:pre-wrap' }, about.slice(0, 1000)) : null,
        // your own npub stays out of the editor — it means nothing to most
        // people, and the account settings still show it to those who care
        mine ? null : h('div', { class: 'addr-box break npub-box', style: 'font-size:11px' },
          h('span', { class: 'grow', style: 'min-width:0' }, npub),
          h('button', {
            class: 'copy-ico', title: t('copy'),
            onClick: async () => { try { await navigator.clipboard.writeText(npub); toast(t('copied')); } catch {} },
            html: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
          })),
        ui.profEdit
          ? h('div', { class: 'col', style: 'gap:8px' },
              field(t('profName'), 'name'),
              field(t('profAbout'), 'about', '', true),
              field(t('profPicture'), 'picture', 'https://…'),
              h('button', { class: 'btn-primary btn-block', disabled: ui.profSaving, onClick: saveProfile },
                ui.profSaving ? h('span', { class: 'spinner sm' }) : t('save')))
          : mine
            ? null // the editor renders above once the kind 0 loads
            : h('div', { class: 'row gap6 wrap' },
                h('button', { class: 'btn-primary grow', onClick: () => {
                  const peer = pk;
                  ui.profilePk = null;
                  ui.chatOpen = true;
                  ui.msgView = 'dm';
                  ui.msgPeer = peer;
                  ui.msgStick = true;
                  render();
                } }, t('msgDmsTitle')),
                h('button', { class: 'grow', onClick: () => {
                  const npubStr = npubOf(pk);
                  ui.profilePk = null;
                  ui.chatOpen = false;
                  ui.tab = 'send';
                  render();
                  hook('matchSendText', npubStr);
                } }, t('profPay')))),
      h('button', { class: 'btn-ghost btn-block', onClick: () => { ui.profilePk = null; ui.profEdit = null; render(); } }, t('back')));
  }

  const backBtn = (onClick) => h('button', { class: 'iconbtn chat-back', onClick }, '‹');

  // ---- presence & typing --------------------------------------------------
  // Both ride the channel stream as 21059 wraps, so they stay inside the
  // community's encryption — who's around is members-only, not a public
  // status broadcast. 21059 sits in NIP-01's ephemeral range, but measured
  // against the relays we actually use (relay.coinos.io, nos.lol) neither
  // drops them, so they carry a NIP-40 expiration and relay.coinos.io sweeps
  // the kind on a timer; nothing here may assume the relay forgets.
  // Presence only exists while someone is watching a room. A member nobody
  // saw beat is dated by their last message instead, the way an offline
  // contact still shows a last-seen.

  const PRESENCE = 20100;
  const TYPING = 20101;
  const BEAT_MS = 60_000; // how often we announce ourselves
  const ONLINE_MS = 100_000; // a beat older than this is no longer "online"
  const TYPING_MS = 7_000; // how long a typing ping stands
  const TYPE_THROTTLE = 5_000; // and how rarely we send one

  const lastPing = new Map(); // channelId + kind -> ms

  async function ping(room, chId, kind) {
    const key = chId + ':' + kind;
    const gap = kind === PRESENCE ? BEAT_MS : TYPE_THROTTLE;
    if (Date.now() - (lastPing.get(key) || 0) < gap) return;
    lastPing.set(key, Date.now());
    try {
      const id = await identity();
      if (!id) return;
      const { created_at, ms } = msTags(Date.now());
      const rumor = {
        kind, pubkey: id.pubkey, content: '',
        tags: [['channel', chId], ['epoch', String(EPOCH)], ms], created_at,
      };
      // NIP-40: a beat is worthless once it's stale, so relays that honour
      // expiration may drop it instead of keeping it forever.
      const wrap = await wrapRumor(rumor, id.signer, room.chStream(chId),
        { ephemeral: true, expiration: created_at + 300 });
      await publishOn(room.relays, wrap);
    } catch { lastPing.delete(key); }
  }

  // Keep beating while a room is on screen — otherwise everyone would look
  // online for exactly one render and then go dark.
  let beatTimer = null;
  function keepBeating() {
    if (beatTimer) return;
    beatTimer = setInterval(() => {
      if (!ui.chatOpen || ui.msgView !== 'room') return;
      const jm = communityById(ui.msgCommunity) || COMMUNITY;
      const room = rooms.get(jm.community_id);
      if (!room) return;
      const chans = roomChannels(room);
      const ch = chans.find((c) => c.id === ui.msgChannel) || chans[0];
      if (ch) ping(room, ch.id, PRESENCE);
      scheduleRepaint(); // let "online" lapse into "last seen" on its own
    }, 30_000);
  }

  // When we last had any sign of someone: a beat, or failing that the newest
  // thing they said anywhere in the community.
  function lastSeenMs(room, pk) {
    let ts = room.presence.get(pk) || 0;
    for (const msgs of room.byChannel.values())
      for (const m of msgs.values())
        if (m.author === pk) ts = Math.max(ts, eventMs(m.rumor) || 0);
    return ts;
  }

  const isOnline = (room, pk) => Date.now() - (room.presence.get(pk) || 0) < ONLINE_MS;

  function typingNow(room, chId) {
    const my = myPubkeys();
    const out = [];
    for (const [pk, ts] of room.typing)
      if (ts.ch === chId && Date.now() - ts.t < TYPING_MS && !my.includes(pk)) out.push(pk);
    return out;
  }

  // Telegram's wording, and its kindness: exact minutes while it's fresh,
  // then a vague "recently" rather than advertising how long someone's been away.
  function seenLabel(room, pk) {
    if (isOnline(room, pk)) return t('msgOnline');
    const ts = lastSeenMs(room, pk);
    if (!ts) return t('msgSeenRecently');
    const mins = Math.floor((Date.now() - ts) / 60_000);
    if (mins < 1) return t('msgSeenJustNow');
    if (mins < 60) return t('msgSeenMins', { n: mins });
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return t('msgSeenHours', { n: hrs });
    const days = Math.floor(hrs / 24);
    if (days <= 7) return t('msgSeenDays', { n: days });
    return t('msgSeenRecently');
  }

  // Recipient search for New message: debounced, sequenced, cached upstream.
  const dmSearch = { rows: null, busy: false };
  const dmSearcher = makeSearcher((q, rows) => {
    dmSearch.rows = rows;
    dmSearch.busy = false;
    scheduleRepaint();
  });
  const dmSearcherUpdate = dmSearcher.update.bind(dmSearcher);
  dmSearcher.update = (q) => {
    const willSearch = q && q.trim().length >= 2;
    if (willSearch) { dmSearch.busy = dmSearch.rows === null || !dmSearch.rows.length; }
    dmSearcherUpdate(q);
  };

  const stickToBottom = () => {
    queueMicrotask(() => {
      const log = document.querySelector('.chat-log');
      if (log && ui.msgStick !== false) log.scrollTop = log.scrollHeight;
    });
  };

  // The chat card is sized to the viewport, so the mobile keyboard shrinks it:
  // the composer stays on screen, but the log keeps its old scroll offset and
  // the newest messages vanish under the fold. Follow the bottom edge through
  // every viewport change (keyboard, rotation, browser chrome) — unless the
  // user has deliberately scrolled up, which msgStick already remembers.
  const onViewportResize = () => { if (ui.chatOpen) stickToBottom(); };

  // A remote signer that a reload dropped: say so where the typing happens,
  // rather than letting someone write a message and only then be told. The
  // identity itself is still known — it's the ability to sign as it that's
  // missing — so this offers to fetch it back rather than to log in again.
  function signerNotice() {
    const id = hook('nostrLoginIdentity');
    if (!id || id.signer) return null;
    return h('div', { class: 'row gap6 chat-signer-off', style: 'align-items:center' },
      h('span', { class: 'small muted grow' }, t('msgSignerOff')),
      h('button', {
        class: 'btn-sm', disabled: !!ui.msgReconnecting,
        onClick: async () => {
          ui.msgReconnecting = true; render();
          const s = await hook('nostrLoginResume');
          ui.msgReconnecting = false;
          // Success needs no announcement — the notice itself goes away.
          if (!s) { ui.chatOpen = false; ui.screen = 'wallet'; ui.tab = 'settings'; ui.settingsPage = 'nostr'; }
          render();
        },
      }, ui.msgReconnecting ? h('span', { class: 'spinner sm' }) : t('msgReconnect')));
  }

  const composer = (placeholder, onSend, onType) =>
    h('div', { class: 'col', style: 'gap:6px' },
      signerNotice(),
    h('div', { class: 'chat-compose' },
      h('input', {
        class: 'grow', type: 'text', id: 'msg-draft', placeholder,
        value: ui.msgDraft || '', maxlength: '2000',
        onInput: (e) => { ui.msgDraft = e.target.value; if (onType && e.target.value) onType(); },
        onKeydown: (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); onSend(); } },
        // Focus summons the keyboard; some browsers resize only after its
        // animation, so re-stick once now and once when it has settled.
        onFocus: () => { stickToBottom(); setTimeout(stickToBottom, 350); },
      }),
      h('button', { class: 'btn-primary btn-sm', disabled: ui.msgSending, onClick: onSend },
        ui.msgSending ? h('span', { class: 'spinner sm' }) : t('msgSend'))));

  // ---- home ---------------------------------------------------------------

  function homeView() {
    startDMs();
    // Threads you've since replied to should stop being strangers to the
    // worker; throttled inside, so this is cheap on every render.
    syncInbox().catch(() => {});
    for (const jm of communities()) ensureRoom(jm);

    const dmRows = [...threads.entries()]
      .map(([peer, m]) => {
        const last = [...m.values()].sort((a, b) => a.rumor.created_at - b.rumor.created_at).at(-1);
        return { peer, last, unread: dmUnread(peer, m) };
      })
      .filter((x) => x.last)
      .sort((a, b) => b.last.rumor.created_at - a.last.rumor.created_at);

    // Being here answers the header dot — including anything that lands while
    // the list is open, since arrivals repaint it and the rows below say who.
    {
      const my = myPubkeys();
      let newest = 0;
      for (const msgs of threads.values())
        newest = Math.max(newest, newestFrom(msgs.values(), (m) => !m.mine));
      for (const room of rooms.values())
        for (const msgs of room.byChannel.values())
          newest = Math.max(newest, newestFrom(msgs.values(), (m) => !my.includes(m.author)));
      markRead(HOME_READ, newest);
    }

    const kids = [];

    // Chat takes the whole screen, so home carries the way back to the wallet.
    kids.push(h('div', { class: 'row gap6', style: 'align-items:center' },
      backBtn(() => { ui.chatOpen = false; render(); }),
      h('h3', { style: 'margin:0' }, t('tabMessages'))));

    if (pendingLink) kids.push(linkInviteCard());
    for (const [rid, inv] of pendingDirect) kids.push(directInviteCard(rid, inv));

    // offer push once — it covers messages AND payments
    if (typeof Notification !== 'undefined' && Notification.permission === 'default' && !st().pushDismissed)
      kids.push(h('div', { class: 'notice info col', style: 'gap:8px' },
        h('div', {}, t('msgPushOffer')),
        h('div', { class: 'row gap6' },
          h('button', {
            class: 'btn-primary btn-sm',
            onClick: async () => { const ok = await registerPush({ interactive: true }); toast(ok ? t('msgPushOn') : t('msgPushFailed')); render(); },
          }, t('msgPushEnable')),
          h('button', {
            class: 'btn-ghost btn-sm',
            onClick: () => { const s = st(); s.pushDismissed = true; save(s); render(); },
          }, t('msgDismiss')))));

    // ---- DMs
    kids.push(h('div', { class: 'row between', style: 'align-items:baseline' },
      h('h3', { style: 'margin:0' }, t('msgDmsTitle')),
      h('button', { class: 'btn-sm', onClick: () => { ui.msgHomePanel = ui.msgHomePanel === 'newdm' ? null : 'newdm'; render(); } }, t('msgNewDm'))));
    if (ui.msgHomePanel === 'newdm') {
      const openThread = (pk) => {
        dmSearcher.clear();
        ui.msgNewDmTo = '';
        ui.msgHomePanel = null;
        ui.msgView = 'dm';
        ui.msgPeer = pk;
        ui.msgStick = true;
        render();
      };
      kids.push(h('div', { class: 'col gap6' },
        h('div', { class: 'row gap6' },
          h('input', {
            class: 'grow', type: 'text', placeholder: t('msgSearchPlaceholder'),
            value: ui.msgNewDmTo || '',
            onInput: (e) => { ui.msgNewDmTo = e.target.value; dmSearcher.update(e.target.value); },
          }),
          h('button', {
            class: 'btn-sm', onClick: () => {
              const pk = parseNostrPubkey(ui.msgNewDmTo);
              if (!pk) { toast(t('msgBadNpub')); return; }
              openThread(pk);
            },
          }, t('msgOpen'))),
        dmSearch.rows === null ? null
          : dmSearch.busy ? h('div', { class: 'row gap6', style: 'align-items:center;padding:4px 0' },
              h('span', { class: 'spinner sm' }), h('span', { class: 'small muted' }, t('msgSearching')))
          : dmSearch.rows.length
            ? h('div', { class: 'list' }, resultRows(h, dmSearch.rows, (r) => openThread(r.pk)))
            : h('div', { class: 'small muted' }, t('msgNoMatches'))));
    }
    // A long DM history must not bury the communities below it: past a
    // handful, the rest waits behind "show all". (No cap for barely-over —
    // a "show 2 more" button costs more than the rows it hides.)
    const DM_PREVIEW = 5;
    const shownDms = (ui.msgAllDms || dmRows.length <= DM_PREVIEW + 2) ? dmRows : dmRows.slice(0, DM_PREVIEW);
    kids.push(
      dmRows.length
        ? h('div', { class: 'list' }, shownDms.map(({ peer, last, unread }) =>
            h('div', {
              class: 'item chat-thread-row' + (unread ? ' unread' : ''),
              onClick: () => { ui.msgView = 'dm'; ui.msgPeer = peer; ui.msgStick = true; render(); },
            },
            avatar(peer),
            h('div', { class: 'col grow', style: 'min-width:0;gap:1px' },
              h('div', { class: 'row between' },
                h('span', { class: 'chat-name' }, displayName(peer)),
                h('span', { class: 'chat-time thread-when' },
                  timeLabel(last.rumor.created_at * 1000),
                  unread ? h('i', { class: 'thread-dot' }) : null)),
              h('div', { class: 'muted small chat-preview' }, (last.mine ? t('msgYouPrefix') + ' ' : '') + last.rumor.content)))))
        : h('div', { class: 'muted small' }, t('msgNoDms')));
    if (shownDms.length < dmRows.length)
      kids.push(h('button', { class: 'linklike small', onClick: () => { ui.msgAllDms = true; render(); } },
        t('msgShowAllDms', { n: dmRows.length })));
    else if (ui.msgAllDms && dmRows.length > DM_PREVIEW + 2)
      kids.push(h('button', { class: 'linklike small', onClick: () => { ui.msgAllDms = false; render(); } },
        t('msgShowFewerDms')));

    // ---- communities
    kids.push(h('div', { class: 'row between mt16', style: 'align-items:baseline' },
      h('h3', { style: 'margin:0' }, t('msgCommunitiesTitle')),
      h('div', { class: 'row gap6' },
        h('button', { class: 'btn-sm', onClick: () => { ui.msgHomePanel = ui.msgHomePanel === 'join' ? null : 'join'; render(); } }, t('msgJoin')),
        h('button', { class: 'btn-sm', onClick: () => { ui.msgHomePanel = ui.msgHomePanel === 'create' ? null : 'create'; render(); } }, t('msgCreate')))));
    if (ui.msgHomePanel === 'join')
      kids.push(h('div', { class: 'row gap6' },
        h('input', {
          class: 'grow', type: 'text', placeholder: t('msgInvitePlaceholder'),
          value: ui.msgJoinText || '', onInput: (e) => { ui.msgJoinText = e.target.value; },
        }),
        h('button', { class: 'btn-sm', onClick: () => joinFromText(ui.msgJoinText) }, t('msgJoin'))));
    if (ui.msgHomePanel === 'create')
      kids.push(h('div', { class: 'row gap6' },
        h('input', {
          class: 'grow', type: 'text', placeholder: t('msgNamePlaceholder'), maxlength: '64',
          value: ui.msgNewName || '', onInput: (e) => { ui.msgNewName = e.target.value; },
        }),
        h('button', { class: 'btn-sm', onClick: () => createCommunity(ui.msgNewName || '') }, t('msgCreate'))));
    kids.push(h('div', { class: 'list' }, communities().map((jm) => {
      const room = rooms.get(jm.community_id);
      const name = room?.folded?.metadata?.name || jm.name;
      const memberCount = room ? [...room.members.values()].filter((m) => m.state === 'join').length : 0;
      const unread = room ? roomUnread(room) : false;
      return h('div', {
        class: 'item chat-thread-row' + (unread ? ' unread' : ''),
        onClick: () => { ui.msgView = 'room'; ui.msgCommunity = jm.community_id; ui.msgChannel = null; ui.msgStick = true; render(); },
      },
      h('div', { class: 'chat-avatar fallback' }, name.slice(0, 2)),
      h('div', { class: 'col grow', style: 'min-width:0;gap:1px' },
        h('div', { class: 'row between' },
          h('span', { class: 'chat-name' }, name),
          unread ? h('i', { class: 'thread-dot' }) : null),
        h('div', { class: 'muted small' },
          memberCount ? t('msgMembers', { n: memberCount }) : t('msgEncrypted'))));
    })));

    return h('div', { class: 'card col', style: 'gap:10px' }, ...kids);
  }

  function linkInviteCard() {
    const pl = pendingLink;
    return h('div', { class: 'notice info col', style: 'gap:8px' },
      pl.state === 'loading' ? h('div', { class: 'row gap6' }, h('span', { class: 'spinner sm' }), t('msgInviteLoading'))
      : pl.state === 'error' ? h('div', { class: 'row between' },
          h('span', {}, pl.error),
          h('button', { class: 'linklike', onClick: () => { pendingLink = null; render(); } }, t('msgDismiss')))
      : h('div', { class: 'col', style: 'gap:8px' },
          h('div', {}, t('msgInviteTo', { name: pl.bundle.name || 'community' })),
          h('div', { class: 'muted small' }, t('msgInviteFounder', { npub: (npubOf(pl.bundle.owner) || '').slice(0, 16) + '…' })),
          h('div', { class: 'row gap6' },
            h('button', { class: 'btn-primary btn-sm', onClick: () => acceptBundle(pl.bundle, { invitedBy: pl.bundle.creator_npub }) }, t('msgJoin')),
            h('button', { class: 'btn-ghost btn-sm', onClick: () => { pendingLink = null; render(); } }, t('msgDismiss')))));
  }

  function directInviteCard(rid, inv) {
    return h('div', { class: 'notice info col', style: 'gap:8px' },
      h('div', {}, t('msgDirectInvite', { name: inv.bundle.name || 'community', from: displayName(inv.from) })),
      h('div', { class: 'row gap6' },
        h('button', {
          class: 'btn-primary btn-sm',
          onClick: () => { pendingDirect.delete(rid); acceptBundle(inv.bundle, { invitedBy: inv.from }); },
        }, t('msgJoin')),
        h('button', {
          class: 'btn-ghost btn-sm',
          onClick: () => { const s = st(); s.declined[rid] = 1; save(s); pendingDirect.delete(rid); render(); },
        }, t('msgDismiss'))));
  }

  // ---- room ---------------------------------------------------------------

  function messageRows(room, chId) {
    const my = myPubkeys();
    const msgs = [...(room.byChannel.get(chId)?.values() || [])]
      .filter((m) => !room.deletes.has(m.rumor.id))
      .filter((m) => !(room.folded && room.folded.banned.has(m.author)))
      .sort((a, b) => eventMs(a.rumor) - eventMs(b.rumor));
    markRead(chRead(chId), newestFrom(msgs, (m) => !my.includes(m.author)));
    if (!msgs.length)
      return [h('div', { class: 'muted small', style: 'text-align:center;padding:24px 0' }, t('msgEmpty'))];
    let lastAuthor = null, lastT = 0;
    return msgs.map((m) => {
      const tms = eventMs(m.rumor);
      const mine = my.includes(m.author);
      const edit = room.edits.get(m.rumor.id);
      const text = edit && edit.author === m.author ? edit.rumor.content : m.rumor.content;
      const grouped = m.author === lastAuthor && tms - lastT < 5 * 60_000;
      lastAuthor = m.author; lastT = tms;
      const reacts = room.reactions.get(m.rumor.id);
      const counts = new Map();
      if (reacts) for (const emoji of reacts.values()) counts.set(emoji, (counts.get(emoji) || 0) + 1);
      return h(
        'div', { class: 'chat-row' + (mine ? ' mine' : '') + (grouped ? ' grouped' : '') },
        grouped ? h('div', { class: 'chat-avatar spacer' }) : avatar(m.author),
        h('div', { class: 'chat-body' },
          grouped ? null : h('div', { class: 'chat-meta' },
            h('span', {
              class: 'chat-name clickable' + (m.author === room.jm.owner ? ' owner' : ''),
              onClick: () => openProfile(m.author),
            },
              displayName(m.author),
              m.author === room.jm.owner ? h('span', { class: 'chat-badge' }, t('msgAdmin')) : null),
            h('span', { class: 'chat-time' }, timeLabel(tms))),
          h('div', { class: 'chat-bubble' },
            text,
            edit ? h('span', { class: 'chat-edited' }, ' ', t('msgEdited')) : null,
            mine
              ? h('button', { class: 'chat-del', title: t('msgDelete'), onClick: () => deleteMessage(room, chId, m) }, '×')
              : null),
          counts.size
            ? h('div', { class: 'chat-reacts' },
                [...counts.entries()].map(([emoji, n]) =>
                  h('span', { class: 'chat-react' }, emoji, n > 1 ? ' ' + n : '')))
            : null)
      );
    });
  }

  function roomView() {
    const jm = communityById(ui.msgCommunity) || COMMUNITY;
    const room = ensureRoom(jm);
    const chans = roomChannels(room);
    const ch = chans.find((c) => c.id === ui.msgChannel) || chans[0];
    const name = room.folded?.metadata?.name || jm.name;
    const members = [...room.members.entries()].filter(([, m]) => m.state === 'join');
    const memberCount = members.length;
    const onlineCount = members.filter(([pk]) => isOnline(room, pk)).length;
    stickToBottom();
    keepBeating();
    if (ch) ping(room, ch.id, PRESENCE);

    return h('div', { class: 'card col chat-card' },
      h('div', { class: 'row between chat-head' },
        h('div', { class: 'row gap6', style: 'align-items:center;min-width:0' },
          backBtn(() => { ui.msgView = 'home'; render(); }),
          h('div', {
            class: 'col clickable', style: 'gap:2px;min-width:0',
            onClick: () => { ui.msgMembers = !ui.msgMembers; render(); },
          },
            h('div', { class: 'chat-title' }, name),
            h('div', { class: 'muted small' },
              memberCount ? t('msgMembers', { n: memberCount }) : t('msgEncrypted'),
              onlineCount ? h('span', { class: 'online-count' }, ' · ', t('msgNOnline', { n: onlineCount })) : null))),
        h('div', { class: 'row gap6', style: 'align-items:center' },
          // One channel needs no label — naming it only asks people to notice a
          // choice they don't have. Several become a picker.
          chans.length > 1
            ? h('select', {
                class: 'chan-pick',
                onChange: (e) => { ui.msgChannel = e.target.value; ui.msgStick = true; subChannel(room, e.target.value); render(); },
              }, chans.map((c) => h('option', { value: c.id, selected: c.id === ch?.id }, '#' + c.name)))
            : null,
          h('button', {
            class: 'iconbtn bell' + (roomNotify(jm.community_id) ? ' on' : ''),
            title: roomNotify(jm.community_id) ? t('msgNotifyOn') : t('msgNotifyOff'),
            onClick: () => toggleRoomNotify(jm.community_id),
            html: roomNotify(jm.community_id)
              ? '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 0 1-3.4 0" fill="none"/></svg>'
              : '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M13.7 21a2 2 0 0 1-3.4 0"/><path d="M18 8a6 6 0 0 0-9.3-5"/><path d="M6.3 6.3A6 6 0 0 0 6 8c0 7-3 9-3 9h15"/><path d="m2 2 20 20"/></svg>',
          }),
          h('button', {
            class: 'btn-sm', title: t('msgInviteTitle'),
            onClick: () => { ui.msgInvitePanel = !ui.msgInvitePanel; render(); },
          }, t('msgAddPerson')))),
      ui.msgInvitePanel ? invitePanel(room) : null,
      ui.msgMembers ? memberPanel(room, members) : null,
      h('div', {
        class: 'chat-log',
        onScroll: (e) => {
          const el = e.target;
          ui.msgStick = el.scrollHeight - el.scrollTop - el.clientHeight < 60;
        },
      }, ...(ch ? messageRows(room, ch.id) : [])),
      ch ? typingLine(room, ch.id) : null,
      composer(
        chans.length > 1 ? t('msgPlaceholder', { channel: ch ? ch.name : '' }) : t('msgPlaceholderPlain'),
        () => ch && sendMessage(room, ch.id),
        () => ch && ping(room, ch.id, TYPING)));
  }

  // "Alice is typing…" — named up to two, counted beyond that.
  function typingLine(room, chId) {
    const who = typingNow(room, chId);
    if (!who.length) return null;
    const label = who.length === 1 ? t('msgTyping', { name: displayName(who[0]) })
      : who.length === 2 ? t('msgTyping2', { a: displayName(who[0]), b: displayName(who[1]) })
      : t('msgTypingMany', { n: who.length });
    return h('div', { class: 'chat-typing' },
      h('span', { class: 'typing-dots' }, h('i'), h('i'), h('i')),
      h('span', { class: 'small muted' }, label));
  }

  function memberPanel(room, members) {
    const rows = members
      .map(([pk]) => ({ pk, online: isOnline(room, pk), seen: lastSeenMs(room, pk) }))
      .sort((a, b) => (b.online - a.online) || (b.seen - a.seen));
    return h('div', { class: 'col chat-members' },
      ...rows.map((r) => h('div', {
        class: 'item chat-thread-row',
        onClick: () => openProfile(r.pk),
      },
        h('span', { class: 'ava-wrap' + (r.online ? ' online' : '') }, avatar(r.pk)),
        h('div', { class: 'col grow', style: 'min-width:0;gap:1px' },
          h('div', { class: 'row gap6', style: 'align-items:center;min-width:0' },
            h('span', { class: 'chat-name' }, displayName(r.pk)),
            r.pk === room.jm.owner ? h('span', { class: 'chat-badge' }, t('msgAdmin')) : null),
          h('div', { class: 'muted small' + (r.online ? ' is-online' : '') }, seenLabel(room, r.pk))))));
  }

  function invitePanel(room) {
    const builtin = room.jm.community_id === COMMUNITY.community_id;
    return h('div', { class: 'col chat-invite', style: 'gap:8px' },
      h('div', { class: 'row gap6' },
        h('button', {
          class: 'btn-sm', disabled: ui.msgMinting,
          onClick: async () => {
            ui.msgMinting = true; render();
            try {
              const url = await mintInviteLink(room);
              if (url) { await navigator.clipboard.writeText(url); toast(t('msgLinkCopied')); }
            } finally { ui.msgMinting = false; render(); }
          },
        }, ui.msgMinting ? h('span', { class: 'spinner sm' }) : t('msgCopyInvite')),
        h('input', {
          class: 'grow', type: 'text', placeholder: t('msgNpubPlaceholder'),
          value: ui.msgInviteTo || '', onInput: (e) => { ui.msgInviteTo = e.target.value; },
        }),
        h('button', {
          class: 'btn-sm',
          onClick: () => { sendDirectInvite(room, ui.msgInviteTo); ui.msgInviteTo = ''; render(); },
        }, t('msgSend'))),
      // Owners can add channels (an owner-signed control edition), but a naming
      // field sitting open is a question nobody asked — it reads as something
      // you're meant to fill in right after making a community.
      myPubkeys().includes(room.jm.owner)
        ? (ui.msgChannelPanel
            ? h('div', { class: 'row gap6' },
                h('input', {
                  class: 'grow', type: 'text', placeholder: t('msgChannelPlaceholder'), maxlength: '64',
                  value: ui.msgNewChannel || '', onInput: (e) => { ui.msgNewChannel = e.target.value; },
                  onKeydown: (e) => { if (e.key === 'Enter') createChannel(room, ui.msgNewChannel); },
                }),
                h('button', { class: 'btn-sm', onClick: () => createChannel(room, ui.msgNewChannel) }, t('msgCreate')),
                h('button', { class: 'btn-ghost btn-sm', onClick: () => { ui.msgChannelPanel = false; render(); } }, t('cancel')))
            : h('div', { class: 'row' },
                h('button', {
                  class: 'btn-sm',
                  onClick: () => { ui.msgChannelPanel = true; render(); },
                }, t('msgNewChannel'))))
        : null,
      // leaving discards the keys on this identity — two taps, default community exempt
      builtin ? null : h('div', { class: 'row' },
        h('button', {
          class: 'btn-ghost btn-sm ' + (ui.msgLeaveArm ? 'btn-danger' : ''),
          onClick: () => {
            if (ui.msgLeaveArm) leaveCommunity(room);
            else { ui.msgLeaveArm = true; render(); }
          },
        }, ui.msgLeaveArm ? t('msgLeaveConfirm') : t('msgLeave'))));
  }

  // ---- dm thread ----------------------------------------------------------

  function dmView() {
    startDMs();
    const peer = ui.msgPeer;
    if (!peer) { ui.msgView = 'home'; return homeView(); }
    const msgs = [...(threads.get(peer)?.values() || [])].sort((a, b) => a.rumor.created_at - b.rumor.created_at);
    // Looking at the thread is reading it — including anything that lands while
    // it's still open, since every arrival repaints us.
    markRead(dmRead(peer), newestFrom(msgs, (m) => !m.mine));
    stickToBottom();
    return h('div', { class: 'card col chat-card' },
      h('div', { class: 'row chat-head gap6', style: 'align-items:center' },
        backBtn(() => { ui.msgView = 'home'; render(); }),
        avatar(peer),
        h('div', { class: 'col clickable', style: 'gap:2px;min-width:0', onClick: () => openProfile(peer) },
          h('div', { class: 'chat-title' }, displayName(peer)),
          h('div', { class: 'muted small' }, t('msgDmEncrypted')))),
      h('div', {
        class: 'chat-log',
        onScroll: (e) => {
          const el = e.target;
          ui.msgStick = el.scrollHeight - el.scrollTop - el.clientHeight < 60;
        },
      },
      ...(msgs.length
        ? msgs.map((m) =>
            h('div', { class: 'chat-row dm' + (m.mine ? ' mine' : '') },
              h('div', { class: 'chat-body' },
                h('div', { class: 'chat-bubble' + (m.mine ? ' me' : '') }, m.rumor.content),
                h('div', { class: 'chat-time' }, timeLabel(m.rumor.created_at * 1000)))))
        : [h('div', { class: 'muted small', style: 'text-align:center;padding:24px 0' }, t('msgNoDmsYet'))])),
      composer(t('msgDmPlaceholder'), () => sendDM(peer)));
  }

  // ---- feature ------------------------------------------------------------

  function messagesTab() {
    if (ui.msgView === 'room') return roomView();
    if (ui.msgView === 'dm') return dmView();
    return homeView();
  }

  return {
    id: 'messages',
    // Chat lives behind a header button and takes over the whole screen —
    // no balance card, no tabs; each view carries its own way back.
    // The bare avatar node for the app header's identity menu.
    // The header rebuilds every render; recreating the <img> each time makes
    // the picture visibly flash during boot's render bursts. There is exactly
    // one header avatar, so the node itself is reused until the profile
    // (or account) actually changes.
    headerAvatar(pk) {
      const p = profileOf(pk);
      const key = pk + '|' + (p === null ? 'loading' : p.picture || 'fb:' + (p.name || ''));
      if (!this._headerAva || this._headerAvaKey !== key) {
        this._headerAvaKey = key;
        this._headerAva = avatar(pk, 'chat-avatar header-ava', false);
      }
      return this._headerAva;
    },
    // Conversations waiting on us, for the header's message button.
    unreadMessages() { return unreadCount(); },
    screenView() {
      if (ui.screen !== 'wallet') return null;
      if (ui.profilePk) return profileScreen();
      if (!ui.chatOpen) return null;
      return h('div', { class: 'col', style: 'gap:16px' },
        ctx.brandHeader(true),
        messagesTab());
    },
    // Anyone (ark's history, other features) can open a profile or render a
    // small clickable identity chip.
    showProfile(pk) { openProfile(pk); return true; },
    // Publish (merge) kind-0 fields for the current identity — the onboarding
    // wizard sets name + picture through this.
    async publishProfile(fields, opts = {}) {
      const id = await identity();
      if (!id) throw new Error(t('msgNoIdentity'));
      const evs = await queryOn([...new Set([...PROFILE_RELAYS, ...DM_RELAYS])], { kinds: [0], authors: [id.pubkey] }, 3000);
      const newest = evs.sort((a, b) => b.created_at - a.created_at)[0];
      let base = {};
      try { base = newest ? JSON.parse(newest.content) : {}; } catch {}
      const merged = { ...base };
      // fillOnly fields are offers, not orders: the onboarding wizard suggests
      // a name and a punk for profiles that have none — it must never RENAME
      // (or re-face) an identity that already has one.
      const fill = new Set(opts.fillOnly || []);
      const taken = (k) => (k === 'name' ? !!(base.name || base.display_name) : !!base[k]);
      for (const [k, v] of Object.entries(fields || {})) {
        if (!v) continue;
        if (fill.has(k) && taken(k)) continue;
        merged[k] = v;
      }
      if (merged.name && !(fill.has('name') && taken('name'))) merged.display_name = merged.name;
      if (JSON.stringify(merged) === JSON.stringify(base)) return true; // nothing to say
      const partial = { kind: 0, content: JSON.stringify(merged), tags: [], created_at: Math.floor(Date.now() / 1000) };
      const evt = id.signer instanceof Uint8Array ? finalizeEvent(partial, id.signer) : await id.signer.signEvent(partial);
      const ok = await publishOn([...new Set([...PROFILE_RELAYS, ...DM_RELAYS])], evt);
      if (!ok) throw new Error(t('msgSendFailed'));
      fullProfiles.set(id.pubkey, merged);
      profiles.set(id.pubkey, { name: merged.name || null, picture: merged.picture || null, t: Date.now() });
      return true;
    },
    profileChip(pk, size) {
      const big = size === 'lg';
      return h('span', {
        class: 'zap-chip' + (big ? ' lg' : ''),
        onClick: (e) => { e.stopPropagation(); openProfile(pk); },
      }, avatar(pk, 'chat-avatar ' + (big ? 'chip-lg' : 'mini'), false),
        h('span', { class: big ? '' : 'small' }, displayName(pk)));
    },
    init() {
      if (urlInvite && !pendingLink) {
        loadLinkInvite(urlInvite);
        setTimeout(() => { ui.chatOpen = true; ui.msgView = 'home'; render(); }, 0);
      }
      window.addEventListener('resize', onViewportResize);
      window.visualViewport?.addEventListener('resize', onViewportResize);
      allUnsubs.push(() => {
        window.removeEventListener('resize', onViewportResize);
        window.visualViewport?.removeEventListener('resize', onViewportResize);
      });
      startDMs();
      // Communities subscribe up front too, not just when chat opens — the
      // header's unread dot can't report a room nobody is listening to.
      for (const jm of communities()) { try { ensureRoom(jm); } catch {} }
      syncLists().catch(() => {});
      syncInbox().catch(() => {});
      registerPush().catch(() => {}); // silent refresh when permission already granted
    },
    stop() {
      for (const u of allUnsubs) { try { u(); } catch {} }
      allUnsubs = [];
      rooms.clear();
      threads.clear();
      pendingDirect.clear();
      dmStarted = false;
      listsSynced = false;
    },
  };
}

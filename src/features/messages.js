// Messages — encrypted community chat over the Concord protocol (CORD-01..04),
// the successor to Marmot/White Noise for Discord-shaped rooms on nostr.
//
// hal ships with one built-in community: "coinos". Its join material (below)
// includes the community_root, so holding the app is holding membership —
// relays only ever see kind-1059 wraps signed by derived stream keys. The
// community was founded by Adam's npub, which makes him owner (position 0)
// and sole authority for the control plane fold.
//
// Messages are signed by the session's nostr login identity when a signer is
// live (extension, or a pasted key before reload), else by the wallet's
// NIP-06 key — both only ever *sign* the seal; all encryption happens under
// stream keys hal already holds, so remote signers need no nip44 round-trips.

import { subscribeOn, publishOn, fetchNostrProfile, npubOf } from '../nostr.js';
import {
  channelKey, controlKey, guestbookKey, openWrap, wrapRumor,
  foldControl, foldGuestbook, observeAuthor, eventMs, msTags,
} from '../concord.js';
import { hexToBytes } from '@noble/hashes/utils';
import { t } from '../i18n.js';

// Genesis output of tools/concord-genesis.js — the coinos community's join
// material (CORD-02 §8). The community_root here is deliberately public-ish:
// every hal user is meant to be a member of the default community.
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
const CACHE_MAX = 50; // messages kept per channel in feature state

export function messagesFeature(ctx) {
  const { h, ui, render, wallet, toast, hook } = ctx;

  const root = hexToBytes(COMMUNITY.community_root);
  const cid = COMMUNITY.community_id;
  const control = controlKey(root, cid, EPOCH);
  const guestbook = guestbookKey(root, cid, EPOCH);
  const chStream = (id) => channelKey(root, id, EPOCH);

  // ---- state ------------------------------------------------------------

  let folded = null; // control-plane fold: { metadata, channels, banned, ... }
  let controlEntries = [];
  let guestEntries = [];
  let byChannel = new Map(); // channelId -> Map(rumorId -> {rumor, author})
  let edits = new Map(); // target rumor id -> latest edit rumor
  let deletes = new Set(); // rumor ids deleted by their author
  let reactions = new Map(); // target rumor id -> Map(author -> emoji)
  let seenWraps = new Set();
  let unsubs = [];
  let started = false;

  const profiles = new Map(); // pubkey -> {name, picture} | null while loading
  const st = () => wallet.loadFeatureState('messages', { joined: {}, cache: {} });
  const save = (s) => wallet.saveFeatureState('messages', s);

  const channels = () => {
    // The control plane is the authority; the baked-in list covers the gap
    // until the first fold lands (offline, cold relays).
    if (folded && folded.channels.size)
      return [...folded.channels.entries()].map(([id, c]) => ({ id, name: c.name }));
    return COMMUNITY.channels;
  };
  const currentChannel = () =>
    channels().find((c) => c.id === ui.msgChannel) || channels()[0];

  // ---- identity ----------------------------------------------------------

  async function identity() {
    const id = hook('nostrLoginIdentity');
    if (id) {
      const signer = id.signer || (await hook('nostrLoginResume'));
      if (signer) return { pubkey: id.pubkey, signer };
    }
    if (wallet.nostr && wallet.nostr.sk) return { pubkey: wallet.nostr.pk, signer: wallet.nostr.sk };
    return null;
  }

  // ---- inbound -----------------------------------------------------------

  const refold = () => {
    folded = foldControl(controlEntries, { ownerHex: COMMUNITY.owner, cid });
  };

  const onChat = (channelId) => (wrap) => {
    if (seenWraps.has(wrap.id)) return;
    seenWraps.add(wrap.id);
    const opened = openWrap(wrap, chStream(channelId));
    if (!opened) return;
    const { rumor, author } = opened;
    const tag = (k) => rumor.tags?.find((x) => x[0] === k);
    // CORD-03 §3: the rumor must commit to the channel/epoch that decrypted it
    if (tag('channel')?.[1] !== channelId || tag('epoch')?.[1] !== String(EPOCH)) return;
    if (folded && folded.banned.has(author)) return;
    if (rumor.kind === 9) {
      let msgs = byChannel.get(channelId) || byChannel.set(channelId, new Map()).get(channelId);
      msgs.set(rumor.id, { rumor, author });
    } else if (rumor.kind === 5) {
      for (const e of rumor.tags.filter((x) => x[0] === 'e')) {
        const m = byChannel.get(channelId)?.get(e[1]);
        if (!m || m.author === author) deletes.add(e[1]);
      }
    } else if (rumor.kind === 3302) {
      const target = tag('e')?.[1];
      if (target) {
        const cur = edits.get(target);
        if (!cur || eventMs(rumor) > eventMs(cur.rumor)) edits.set(target, { rumor, author });
      }
    } else if (rumor.kind === 7) {
      const target = tag('e')?.[1];
      if (target) {
        let r = reactions.get(target) || reactions.set(target, new Map()).get(target);
        r.set(author, rumor.content);
      }
    }
    const tms = eventMs(rumor);
    if (tms) observeAuthor(members, author, tms);
    scheduleRepaint();
  };

  let members = new Map();
  const refoldGuestbook = () => {
    members = foldGuestbook(guestEntries, { nowMs: Date.now(), banned: folded?.banned });
    for (const [, msgs] of byChannel)
      for (const { rumor, author } of msgs.values()) {
        const tms = eventMs(rumor);
        if (tms) observeAuthor(members, author, tms);
      }
  };

  // Coalesce repaints: relays replay history in a burst on subscribe.
  let repaintTimer = null;
  const scheduleRepaint = () => {
    if (repaintTimer) return;
    repaintTimer = setTimeout(() => {
      repaintTimer = null;
      if (ui.screen === 'wallet' && ui.tab === 'messages') render();
    }, 80);
  };

  function start() {
    if (started) return;
    started = true;
    const relays = COMMUNITY.relays;
    unsubs.push(
      subscribeOn(relays, { kinds: [1059], authors: [control.pk], limit: 500 }, (wrap) => {
        if (seenWraps.has(wrap.id)) return;
        seenWraps.add(wrap.id);
        const opened = openWrap(wrap, control);
        if (!opened || opened.rumor.kind !== 3308) return;
        controlEntries.push(opened);
        refold();
        scheduleRepaint();
      })
    );
    unsubs.push(
      subscribeOn(relays, { kinds: [1059], authors: [guestbook.pk], limit: 500 }, (wrap) => {
        if (seenWraps.has(wrap.id)) return;
        seenWraps.add(wrap.id);
        const opened = openWrap(wrap, guestbook);
        if (!opened) return;
        guestEntries.push(opened);
        refoldGuestbook();
        scheduleRepaint();
      })
    );
    for (const c of COMMUNITY.channels) subChannel(c.id);
    // warm the timeline from the local cache so the page paints instantly
    const cached = st().cache;
    for (const [chId, list] of Object.entries(cached || {}))
      for (const m of list) {
        let msgs = byChannel.get(chId) || byChannel.set(chId, new Map()).get(chId);
        if (!msgs.has(m.rumor.id)) msgs.set(m.rumor.id, m);
      }
  }

  const subbed = new Set();
  function subChannel(id) {
    if (subbed.has(id)) return;
    subbed.add(id);
    unsubs.push(subscribeOn(COMMUNITY.relays, { kinds: [1059], authors: [chStream(id).pk], limit: 200 }, onChat(id)));
  }

  function persistCache() {
    const s = st();
    s.cache = {};
    for (const [chId, msgs] of byChannel) {
      const list = [...msgs.values()]
        .filter((m) => !deletes.has(m.rumor.id))
        .sort((a, b) => eventMs(a.rumor) - eventMs(b.rumor))
        .slice(-CACHE_MAX);
      s.cache[chId] = list;
    }
    save(s);
  }

  // ---- outbound ----------------------------------------------------------

  async function ensureJoined(id) {
    const s = st();
    if (s.joined[id.pubkey]) return;
    const { created_at, ms } = msTags(Date.now());
    const rumor = { kind: 3306, pubkey: id.pubkey, content: 'join', tags: [ms], created_at };
    const wrap = await wrapRumor(rumor, id.signer, guestbook);
    publishOn(COMMUNITY.relays, wrap);
    s.joined[id.pubkey] = true;
    save(s);
  }

  async function sendMessage() {
    const text = (ui.msgDraft || '').trim();
    const ch = currentChannel();
    if (!text || !ch || ui.msgSending) return;
    const id = await identity();
    if (!id) { toast(t('msgNoIdentity')); return; }
    ui.msgSending = true;
    render();
    try {
      const { created_at, ms } = msTags(Date.now());
      const rumor = {
        kind: 9, pubkey: id.pubkey, content: text,
        tags: [['channel', ch.id], ['epoch', String(EPOCH)], ms], created_at,
      };
      const wrap = await wrapRumor(rumor, id.signer, chStream(ch.id));
      // optimistic insert (the relay echo will dedupe on wrap id)
      const opened = openWrap(wrap, chStream(ch.id));
      if (opened) {
        seenWraps.add(wrap.id);
        let msgs = byChannel.get(ch.id) || byChannel.set(ch.id, new Map()).get(ch.id);
        msgs.set(opened.rumor.id, opened);
      }
      ui.msgDraft = '';
      const ok = await publishOn(COMMUNITY.relays, wrap);
      if (!ok) toast(t('msgSendFailed'));
      ensureJoined(id).catch(() => {});
      persistCache();
    } catch (e) {
      toast(e.message || String(e));
    } finally {
      ui.msgSending = false;
      ui.msgStick = true;
      render();
    }
  }

  async function deleteMessage(m) {
    const id = await identity();
    if (!id || id.pubkey !== m.author) return;
    const ch = currentChannel();
    const { created_at, ms } = msTags(Date.now());
    const rumor = {
      kind: 5, pubkey: id.pubkey, content: '',
      tags: [['channel', ch.id], ['epoch', String(EPOCH)], ['e', m.rumor.id], ['k', '9'], ms], created_at,
    };
    const wrap = await wrapRumor(rumor, id.signer, chStream(ch.id));
    deletes.add(m.rumor.id);
    render();
    publishOn(COMMUNITY.relays, wrap);
    persistCache();
  }

  // ---- profiles ----------------------------------------------------------

  function profileOf(pk) {
    if (profiles.has(pk)) return profiles.get(pk);
    profiles.set(pk, null);
    fetchNostrProfile(pk).then((p) => {
      profiles.set(pk, p || {});
      scheduleRepaint();
    }).catch(() => profiles.set(pk, {}));
    return null;
  }

  const displayName = (pk) => {
    const p = profileOf(pk);
    if (p && p.name) return p.name;
    return npubOf(pk).slice(0, 12) + '…';
  };

  // ---- view --------------------------------------------------------------

  const timeLabel = (tms) => {
    const d = new Date(tms);
    const today = new Date().toDateString() === d.toDateString();
    return today
      ? d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
      : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) +
        ' ' + d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  };

  function messageRows(chId, myPk) {
    const msgs = [...(byChannel.get(chId)?.values() || [])]
      .filter((m) => !deletes.has(m.rumor.id))
      .filter((m) => !(folded && folded.banned.has(m.author)))
      .sort((a, b) => eventMs(a.rumor) - eventMs(b.rumor));
    if (!msgs.length)
      return [h('div', { class: 'muted small', style: 'text-align:center;padding:24px 0' }, t('msgEmpty'))];
    let lastAuthor = null, lastT = 0;
    return msgs.map((m) => {
      const tms = eventMs(m.rumor);
      const mine = m.author === myPk;
      const edit = edits.get(m.rumor.id);
      const text = edit && edit.author === m.author ? edit.rumor.content : m.rumor.content;
      const grouped = m.author === lastAuthor && tms - lastT < 5 * 60_000;
      lastAuthor = m.author; lastT = tms;
      const p = profileOf(m.author);
      const reacts = reactions.get(m.rumor.id);
      const counts = new Map();
      if (reacts) for (const emoji of reacts.values()) counts.set(emoji, (counts.get(emoji) || 0) + 1);
      return h(
        'div', { class: 'chat-row' + (mine ? ' mine' : '') + (grouped ? ' grouped' : '') },
        grouped
          ? h('div', { class: 'chat-avatar spacer' })
          : p && p.picture
            ? h('img', { class: 'chat-avatar', src: p.picture, alt: '' })
            : h('div', { class: 'chat-avatar fallback' }, displayName(m.author).slice(0, 2)),
        h('div', { class: 'chat-body' },
          grouped ? null : h('div', { class: 'chat-meta' },
            h('span', { class: 'chat-name' + (m.author === COMMUNITY.owner ? ' owner' : '') },
              displayName(m.author),
              m.author === COMMUNITY.owner ? h('span', { class: 'chat-badge' }, t('msgAdmin')) : null),
            h('span', { class: 'chat-time' }, timeLabel(tms))),
          h('div', { class: 'chat-bubble' },
            text,
            edit ? h('span', { class: 'chat-edited' }, ' ', t('msgEdited')) : null,
            mine
              ? h('button', {
                  class: 'chat-del', title: t('msgDelete'),
                  onClick: () => deleteMessage(m),
                }, '×')
              : null),
          counts.size
            ? h('div', { class: 'chat-reacts' },
                [...counts.entries()].map(([emoji, n]) =>
                  h('span', { class: 'chat-react' }, emoji, n > 1 ? ' ' + n : '')))
            : null)
      );
    });
  }

  function messagesTab() {
    start();
    const ch = currentChannel();
    const myId = hook('nostrLoginIdentity');
    const myPk = myId ? myId.pubkey : wallet.nostr && wallet.nostr.pk;
    const name = (folded && folded.metadata && folded.metadata.name) || COMMUNITY.name;
    const memberCount = [...members.values()].filter((m) => m.state === 'join').length;

    // pin to bottom once the burst of history lands, unless the user scrolled up
    queueMicrotask(() => {
      const log = document.querySelector('.chat-log');
      if (log && ui.msgStick !== false) log.scrollTop = log.scrollHeight;
    });

    return h('div', { class: 'card col chat-card' },
      h('div', { class: 'row between chat-head' },
        h('div', { class: 'col', style: 'gap:2px' },
          h('div', { class: 'chat-title' }, name),
          h('div', { class: 'muted small' },
            memberCount ? t('msgMembers', { n: memberCount }) : t('msgEncrypted'))),
        channels().length > 1
          ? h('div', { class: 'seg' },
              channels().map((c) =>
                h('button', {
                  class: c.id === ch.id ? 'active' : '',
                  onClick: () => { ui.msgChannel = c.id; ui.msgStick = true; subChannel(c.id); render(); },
                }, '#' + c.name)))
          : h('div', { class: 'tag' }, '#' + ch.name)),
      h('div', {
        class: 'chat-log',
        onScroll: (e) => {
          const el = e.target;
          ui.msgStick = el.scrollHeight - el.scrollTop - el.clientHeight < 60;
        },
      }, ...(ch ? messageRows(ch.id, myPk) : [])),
      h('div', { class: 'chat-compose' },
        h('input', {
          class: 'grow', type: 'text', id: 'msg-draft',
          placeholder: t('msgPlaceholder', { channel: ch ? ch.name : '' }),
          value: ui.msgDraft || '',
          maxlength: '2000',
          onInput: (e) => { ui.msgDraft = e.target.value; },
          onKeydown: (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } },
        }),
        h('button', {
          class: 'btn-primary btn-sm', disabled: ui.msgSending,
          onClick: sendMessage,
        }, ui.msgSending ? h('span', { class: 'spinner sm' }) : t('msgSend'))));
  }

  return {
    id: 'messages',
    tabs: () => [['messages', t('tabMessages')]],
    tabContent(tab) {
      if (tab !== 'messages') return null;
      return messagesTab();
    },
    stop() {
      for (const u of unsubs) { try { u(); } catch {} }
      unsubs = [];
      started = false;
      subbed.clear();
      if (byChannel.size) { try { persistCache(); } catch {} }
    },
  };
}

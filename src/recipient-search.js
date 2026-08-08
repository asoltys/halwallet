// Recipient search, shared by chat (New message) and the Send form.
//
// Sources, best first: an exact npub/hex paste; coinos usernames from the
// names registrar (prefix search, authoritative for our users); NIP-50
// full-text profile search on a search relay (the approach Coracle/Snort
// take — most relays don't index, so a dedicated one is queried). Results
// merge by pubkey, profiles fill in one batched kind-0 fetch, and per-query
// results are cached so narrowing a query never re-hits the network for
// prefixes already seen.

import { queryOn, parseNostrPubkey, npubOf, PROFILE_RELAYS } from './nostr.js';

// coinos punks: the deterministic default avatar — same formula the coinos
// app uses (last byte of the pubkey picks one of 64). Initials show through
// if the image can't load (offline).
// Self-hosted (dist/punks) — coinos.io's own copies 502 for a third of the
// set. Same deterministic formula the coinos app uses.
export const punkUrl = (pk) =>
  `punks/${Math.floor((parseInt(pk.slice(-2), 16) / 256) * 64) + 1}.webp`;

export const fallbackAvatar = (h, pk, name, cls) =>
  h('div', { class: cls + ' fallback' },
    h('img', { class: 'punk', src: punkUrl(pk), alt: '', onError: (e) => { e.target.style.display = 'none'; } }),
    (name || npubOf(pk) || '??').slice(0, 2));

const REGISTRAR = 'https://names.coinos.io';
const SEARCH_RELAYS = ['wss://search.nos.today', 'wss://relay.nostr.band'];
const PRIMAL_CACHE = 'wss://cache2.primal.net/v1';
const MAX_RESULTS = 8;

// Primal's public cache API has the best-ranked user search on nostr (it's
// what the Primal client itself uses): a custom REQ that answers with plain
// kind-0 events. Nonstandard, so the NIP-50 relays stay as fallback.
// One socket serves the whole typing session — the per-query handshake used
// to cost more than the query itself. Idle for a minute, it closes itself.
let pws = null, pwsN = 0, pwsIdle = null;
const pwsSubs = new Map(); // sub id -> { rows, finish }
function primalSearch(q, limit = MAX_RESULTS) {
  return new Promise((resolve) => {
    const sid = 'rs' + ++pwsN;
    const rows = [];
    const finish = () => { clearTimeout(to); pwsSubs.delete(sid); resolve(rows); };
    const to = setTimeout(finish, 3500);
    pwsSubs.set(sid, { rows, finish });
    clearTimeout(pwsIdle);
    pwsIdle = setTimeout(() => { try { pws?.close(); } catch {} pws = null; }, 60_000);
    const send = () => { try { pws.send(JSON.stringify(['REQ', sid, { cache: ['user_search', { query: q, limit }] }])); } catch { finish(); } };
    if (pws && pws.readyState === 1) return send();
    if (!pws || pws.readyState > 1) {
      try { pws = new WebSocket(PRIMAL_CACHE); } catch { pws = null; return finish(); }
      pws.onmessage = (ev) => {
        try {
          const m = JSON.parse(ev.data);
          const sub = pwsSubs.get(m[1]);
          if (!sub) return;
          if (m[0] === 'EVENT' && m[2] && m[2].kind === 0) sub.rows.push(m[2]);
          if (m[0] === 'EOSE') sub.finish();
        } catch {}
      };
      pws.onerror = pws.onclose = () => {
        pws = null;
        const waiting = [...pwsSubs.values()];
        pwsSubs.clear();
        for (const s of waiting) s.finish();
      };
    }
    pws.addEventListener('open', send, { once: true });
  });
}

// Caches survive reloads: a name searched yesterday paints instantly today.
// Profiles cap at 200 by recency; whole-query results keep for 12 hours.
const PROF_KEY = 'btc-wallet-search-profiles';
const QUERY_KEY = 'btc-wallet-search-queries';
const QUERY_TTL = 12 * 3600_000;
const profileCache = new Map(); // pk -> { name, picture }
const queryCache = new Map(); // q -> rows
const queryAt = new Map(); // q -> when the rows were fetched
try {
  for (const [pk, v] of Object.entries(JSON.parse(localStorage.getItem(PROF_KEY) || '{}'))) profileCache.set(pk, v);
  const now = Date.now();
  for (const [q, e] of Object.entries(JSON.parse(localStorage.getItem(QUERY_KEY) || '{}')))
    if (e && Array.isArray(e.rows) && now - (e.t || 0) < QUERY_TTL) { queryCache.set(q, e.rows); queryAt.set(q, e.t); }
} catch {}
let persistTimer = null;
function persistCaches() {
  clearTimeout(persistTimer);
  persistTimer = setTimeout(() => {
    try {
      const prof = {};
      for (const [pk, v] of [...profileCache].slice(-200)) prof[pk] = { name: v.name || null, picture: v.picture || null };
      localStorage.setItem(PROF_KEY, JSON.stringify(prof));
      const qs = {};
      for (const [q, rows] of [...queryCache].slice(-60)) qs[q] = { t: queryAt.get(q) || Date.now(), rows };
      localStorage.setItem(QUERY_KEY, JSON.stringify(qs));
    } catch {}
  }, 800);
}

// Worth searching? A partial username or npub — never an address, invoice,
// or key the Send form knows how to handle whole. Known payment prefixes are
// excluded so typing an address never triggers a search.
export function searchable(qRaw) {
  const q = (qRaw || '').trim().toLowerCase();
  if (/^(npub1|nprofile1)[a-z0-9]{6,}$/.test(q)) return true;
  if (q.length < 2 || q.length > 30) return false;
  if (/^(bc1|tb1|bcrt1|lnbc|lntb|lnurl|bitcoin:|lightning:|sp1q|ark1|xpub|zpub|xprv|zprv|nsec1|bunker:)/.test(q)) return false;
  if (/^[0-9a-f]{40,}$/.test(q)) return false; // raw hex key/txid
  return /^[a-z0-9._-]+$/.test(q);
}

async function fillProfiles(rows) {
  const missing = rows.filter((r) => !r.picture && !profileCache.has(r.pk));
  if (missing.length) {
    const evs = await queryOn(PROFILE_RELAYS, { kinds: [0], authors: missing.map((r) => r.pk) }, 2500);
    const newest = new Map();
    for (const e of evs) if (!newest.has(e.pubkey) || e.created_at > newest.get(e.pubkey).created_at) newest.set(e.pubkey, e);
    for (const [pk, e] of newest) {
      try {
        const m = JSON.parse(e.content);
        profileCache.set(pk, { name: m.display_name || m.name || null, picture: m.picture || null });
      } catch {}
    }
  }
  for (const r of rows) {
    const p = profileCache.get(r.pk);
    if (p) { r.picture ||= p.picture; r.name ||= p.name; }
  }
}

// onPartial (optional) receives the current best rows as each source lands,
// so the UI paints the fast sources (registrar, cached profiles) without
// waiting for the slow ones. The returned promise still resolves with the
// final, profile-filled rows.
export async function searchRecipients(qRaw, onPartial = null) {
  const q = qRaw.trim().toLowerCase();
  if (queryCache.has(q)) return queryCache.get(q);
  const out = new Map(); // pk -> { pk, name, address, picture, pri }
  const add = (pk, row, pri) => {
    if (!/^[0-9a-f]{64}$/.test(pk || '')) return;
    const cur = out.get(pk);
    if (cur) Object.assign(cur, { ...row, ...Object.fromEntries(Object.entries(cur).filter(([, v]) => v != null)), pri: Math.min(cur.pri, pri) });
    else out.set(pk, { pk, ...row, pri });
  };

  // Within a source, a name that actually contains the query outranks the
  // search relay's looser relevance matches.
  const score = (r) => ((r.name || '').toLowerCase().includes(q) || (r.address || r.nip05 || '').toLowerCase().includes(q)) ? 0 : 1;
  const snapshot = () => {
    const rows = [...out.values()].sort((a, b) => a.pri - b.pri || score(a) - score(b)).slice(0, MAX_RESULTS);
    for (const r of rows) {
      const p = profileCache.get(r.pk);
      if (p) { r.picture ||= p.picture; r.name ||= p.name; }
    }
    return rows;
  };
  const emit = () => { if (onPartial && out.size) onPartial(snapshot()); };

  const exact = parseNostrPubkey(q);
  if (exact) { add(exact, {}, 0); emit(); }

  await Promise.allSettled([
    fetch(`${REGISTRAR}/search?q=${encodeURIComponent(q)}`)
      .then((r) => r.json())
      .then((j) => { (j.results || []).forEach((r) => add(r.pubkey, { name: r.name, address: r.address }, 1)); emit(); }),
    (async () => {
      if (exact) return; // an npub needs no full-text search
      const noteKind0 = (e, pri) => {
        try {
          const m = JSON.parse(e.content);
          profileCache.set(e.pubkey, { name: m.display_name || m.name || null, picture: m.picture || null });
          add(e.pubkey, { name: m.display_name || m.name, picture: m.picture, nip05: typeof m.nip05 === 'string' ? m.nip05.replace(/^_@/, '') : undefined }, pri);
        } catch {}
      };
      const primal = await primalSearch(q);
      for (const e of primal) noteKind0(e, 2);
      if (!primal.length) {
        const evs = await queryOn(SEARCH_RELAYS, { kinds: [0], search: q, limit: MAX_RESULTS }, 3500);
        for (const e of evs) noteKind0(e, 3);
      }
      emit();
    })(),
  ]);

  const rows = snapshot();
  await fillProfiles(rows).catch(() => {});
  if (queryCache.size > 200) { queryCache.clear(); queryAt.clear(); }
  queryCache.set(q, rows);
  queryAt.set(q, Date.now());
  persistCaches();
  return rows;
}

// Debounced controller: one per call site. onUpdate(q, rows|null) fires with
// null when the query isn't searchable (hide the panel), [] while nothing
// matched, rows otherwise. Stale responses are dropped by sequence.
export function makeSearcher(onUpdate) {
  let timer = null;
  let seq = 0;
  return {
    update(q) {
      clearTimeout(timer);
      const my = ++seq;
      if (!searchable(q)) { onUpdate(q, null); return; }
      const s = q.trim().toLowerCase();
      // Get something on screen fast, then relax: the first short query fires
      // almost immediately (that's the wait the user actually feels), while
      // longer ones — mid-word keystrokes — wait long enough to skip the
      // characters still being typed. Cached prefixes are instant.
      const wait = queryCache.has(s) ? 0 : s.length <= 3 ? 120 : 300;
      timer = setTimeout(async () => {
        // partial results paint as each source lands; the final call settles it
        const rows = await searchRecipients(q, (partial) => { if (my === seq) onUpdate(q, partial); }).catch(() => []);
        if (my === seq) onUpdate(q, rows);
      }, wait);
    },
    clear() { seq++; clearTimeout(timer); onUpdate('', null); },
  };
}

// Candidate rows (avatar + name + address/npub), styled with the chat list
// classes both pages already ship.
export function resultRows(h, rows, onPick) {
  return rows.map((r) =>
    h('div', { class: 'item chat-thread-row', onClick: () => onPick(r) },
      r.picture
        // background, not <img>: paints synchronously from cache, so rows
        // re-rendered per keystroke don't flash their avatars
        ? h('div', { class: 'chat-avatar ava-img', style: `background-image:url(${JSON.stringify(r.picture)})` })
        : fallbackAvatar(h, r.pk, r.name, 'chat-avatar'),
      h('div', { class: 'col grow', style: 'min-width:0;gap:1px' },
        h('div', { class: 'chat-name' }, r.name || (npubOf(r.pk) || '').slice(0, 12)),
        h('div', { class: 'muted small chat-preview' }, r.address || r.nip05 || (npubOf(r.pk) || '').slice(0, 24) + '…'))));
}

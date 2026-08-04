// NWC push notifier — step 1 of making hal answer wallet-connect requests
// while it is closed.
//
// hal is a web wallet: a service worker cannot hold a relay socket open, so
// something has to tell the browser "a request arrived, wake up". That is all
// this does. It watches the relays for NIP-47 requests (kind 23194) addressed
// to the wallet-service pubkeys a device has registered, and sends that device
// a Web Push. The service worker then does the actual work — fetch, decrypt,
// pay, reply — in the browser, with the keys never leaving it.
//
// WHAT THIS SERVICE LEARNS: the wallet-service pubkeys you register, and the
// timing of requests to them. That is a real metadata leak and is the price of
// push. It never sees request contents (encrypted to keys it does not have),
// never sees your wallet seed, and can never move funds. The worst it can do
// is fail to wake you, or lie about a wake-up — both of which cost nothing.
//
// Deliberately dumb: no database, no accounts. Registrations live in one JSON
// file and expire if a device stops refreshing them.

import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { SimplePool } from 'nostr-tools/pool';
import { verifyEvent } from 'nostr-tools/pure';
import webpush from 'web-push';

// crude per-IP publish limiter: 20/min is far above a wallet's real reply rate
const pubRate = new Map();
function rateOk(ip) {
  const now = Date.now();
  const arr = (pubRate.get(ip) || []).filter((t) => t > now - 60_000);
  if (arr.length >= 20) return false;
  arr.push(now);
  pubRate.set(ip, arr);
  if (pubRate.size > 500) for (const [k, v] of pubRate) { if (!v.some((t) => t > now - 60_000)) pubRate.delete(k); }
  return true;
}

const CFG = JSON.parse(readFileSync(process.env.NWCPUSH_CONFIG
  || join(import.meta.dir, 'config.json'), 'utf8'));
//  { port, relays: [...], vapid: { publicKey, privateKey, subject },
//    stateFile, maxPubkeysPerDevice, staleDays }

const RELAYS = CFG.relays || ['wss://relay.coinos.io', 'wss://relay.damus.io', 'wss://nos.lol'];
const STATE = CFG.stateFile || join(import.meta.dir, 'data', 'registrations.json');
const MAX_PK = CFG.maxPubkeysPerDevice || 20;
const STALE_MS = (CFG.staleDays || 30) * 86400_000;
const REQ_KIND = 23194;
const OFFER_KIND = 21001;

webpush.setVapidDetails(CFG.vapid.subject, CFG.vapid.publicKey, CFG.vapid.privateKey);
const log = (...a) => console.log(new Date().toISOString(), ...a);

// ---------------------------------------------------------------------------
// registrations: { [servicePubkey]: [{ sub, id, updated }] }
// ---------------------------------------------------------------------------

let regs = {};
// user-facing notifications: { [endpointId]: { sub, ptags: [], authors: [], updated } }
// ptags → DMs / zap receipts p-tagged at the user; authors → community
// stream pubkeys (kind 1059 wraps authored by a channel's derived key).
let notifyRegs = {};
(() => {
  try {
    const raw = JSON.parse(readFileSync(STATE, 'utf8'));
    if (raw && raw.nwc) { regs = raw.nwc; notifyRegs = raw.notify || {}; }
    else regs = raw || {}; // pre-notify state file
  } catch {}
})();
function persist() {
  mkdirSync(dirname(STATE), { recursive: true });
  const tmp = STATE + '.tmp';
  writeFileSync(tmp, JSON.stringify({ nwc: regs, notify: notifyRegs }));
  renameSync(tmp, STATE);
}
// A device that stops refreshing drops off, so a stale endpoint can't keep us
// subscribed to a pubkey forever.
function prune() {
  const cutoff = Date.now() - STALE_MS;
  let dropped = 0;
  for (const pk of Object.keys(regs)) {
    regs[pk] = (regs[pk] || []).filter((r) => (r.updated || 0) > cutoff);
    if (!regs[pk].length) { delete regs[pk]; dropped++; }
  }
  for (const id of Object.keys(notifyRegs)) {
    if ((notifyRegs[id].updated || 0) <= cutoff) { delete notifyRegs[id]; dropped++; }
  }
  if (dropped) { persist(); log(`pruned ${dropped} stale registration(s)`); resubscribe(); }
}

const watchedPubkeys = () => Object.keys(regs);

// ---------------------------------------------------------------------------
// relay watcher
// ---------------------------------------------------------------------------

const pool = new SimplePool();
let sub = null;
let lastResub = 0;

const notifyPtags = () => [...new Set(Object.values(notifyRegs).flatMap((r) => r.ptags || []))];
const notifyAuthors = () => [...new Set(Object.values(notifyRegs).flatMap((r) => r.authors || []))];

let notifySub = null;
function resubscribeNotify() {
  try { notifySub?.close(); } catch {}
  notifySub = null;
  const ptags = notifyPtags();
  const authors = notifyAuthors();
  if (!ptags.length && !authors.length) return;
  const filters = [];
  // DMs / direct invites / zap receipts land p-tagged at the user
  if (ptags.length) filters.push({ kinds: [1059, 9735, 9737], '#p': ptags, since: Math.floor(Date.now() / 1000) });
  // community chat: wraps authored by a channel's derived stream key
  if (authors.length) filters.push({ kinds: [1059], authors, since: Math.floor(Date.now() / 1000) });
  // one sub per filter — the pool API takes a single filter object
  notifySub = filters.map((f) => pool.subscribeMany(RELAYS, f, { onevent: onNotifyEvent }));
  notifySub.close = function () { for (const x of this) { try { x.close(); } catch {} } };
  log(`notify: watching ${ptags.length} ptag(s), ${authors.length} stream author(s)`);
}

// throttle: chat bursts collapse to one push per device per window
// DMs are throttled barely at all now: the device drops the ones it decides
// are noise (a stranger, or our own sent-copy), and a server-side cooldown
// would let a discarded push swallow the friend's message that followed it.
const COOLDOWN = { payment: 10_000, dm: 1_000, chat: 90_000 };
const lastPush = new Map(); // endpointId:reason -> ts
const seenNotifyEvents = new Map(); // event id -> ts
function onNotifyEvent(ev) {
  if (seenNotifyEvents.has(ev.id)) return;
  seenNotifyEvents.set(ev.id, Date.now());
  if (seenNotifyEvents.size > 4000) {
    const cut = Date.now() - 600_000;
    for (const [k, t] of seenNotifyEvents) if (t < cut) seenNotifyEvents.delete(k);
  }
  const p = ev.tags?.find((t) => t[0] === 'p')?.[1];
  const reason = ev.kind === 9735 || ev.kind === 9737 ? 'payment'
    : p && notifyPtags().includes(p) ? 'dm' : 'chat';
  // A wrapped DM hides its sender from us by design, so we can't decide here
  // whether it's from a friend or a stranger — we hand the whole wrap to the
  // device, which holds the only key that can open it. Web Push tops out
  // around 4KB after encryption; anything larger goes as a bare nudge and the
  // device shows its generic notification.
  const extra = reason === 'dm' && JSON.stringify(ev).length < 3500 ? { wrap: ev } : {};
  for (const [id, r] of Object.entries(notifyRegs)) {
    const hit = reason === 'chat'
      ? (r.authors || []).includes(ev.pubkey)
      : p && (r.ptags || []).includes(p);
    if (hit) pushNotify(id, r, reason, extra).catch(() => {});
  }
}

async function pushNotify(id, r, reason, extra) {
  const key = id + ':' + reason;
  const last = lastPush.get(key) || 0;
  if (Date.now() - last < (COOLDOWN[reason] || 10_000)) return;
  lastPush.set(key, Date.now());
  const payload = JSON.stringify({ type: 'notify', reason, ...extra });
  try {
    try {
      await webpush.sendNotification(r.sub, payload, { TTL: 3600, urgency: 'normal' });
    } catch (e) {
      // A payload the push service won't take (413, or the library refusing
      // the size) must not cost the notification itself — send the bare nudge
      // and let the device show its generic message.
      if (!extra.wrap || (e.statusCode && e.statusCode !== 413)) throw e;
      log(`notify(dm): payload rejected (${e.statusCode || e.message}), retrying bare`);
      await webpush.sendNotification(r.sub, JSON.stringify({ type: 'notify', reason }), { TTL: 3600, urgency: 'normal' });
    }
    log(`notify(${reason}) -> device ${id}`);
  } catch (e) {
    if (e.statusCode === 404 || e.statusCode === 410) {
      delete notifyRegs[id];
      persist();
      resubscribeNotify();
      log(`dropped an expired notify endpoint ${id}`);
    } else {
      log(`notify(${reason}) push failed for ${id}: ${e.statusCode || e.message}`);
    }
  }
}

function resubscribe() {
  resubscribeNotify();
  const pks = watchedPubkeys();
  try { sub?.close(); } catch {}
  sub = null;
  if (!pks.length) { log('nothing registered for nwc; not subscribed'); return; }
  lastResub = Date.now();
  sub = pool.subscribeMany(
    RELAYS,
    // only live traffic: a replayed old request must not wake devices.
    // NOTE: nostr-tools ≥2.23 wants a single filter object, NOT an array —
    // an array serializes as an invalid REQ that relays reject with CLOSED.
    { kinds: [REQ_KIND, OFFER_KIND], '#p': pks, since: Math.floor(Date.now() / 1000) },
    {
      onevent: (ev) => {
        const target = ev.tags?.find((t) => t[0] === 'p')?.[1];
        if (target) { noteRequest(ev.id); wake(target, ev.id, ev).catch(() => {}); }
      },
    },
  );
  // Track replies for the requests we forwarded, so an auto-answering worker
  // can ask "was this already answered by an open device elsewhere?" before
  // it pays. Only e-tags of requests we have seen are recorded.
  try { answeredSub?.close(); } catch {}
  answeredSub = pool.subscribeMany(
    RELAYS,
    { kinds: [RES_KIND, OFFER_KIND], since: Math.floor(Date.now() / 1000) },
    {
      onevent: (ev) => {
        for (const t of ev.tags || []) {
          if (t[0] === 'e' && recentReqs.has(t[1])) answeredIds.set(t[1], Date.now());
        }
      },
    },
  );
  log(`subscribed for ${pks.length} service pubkey(s) on ${RELAYS.length} relays`);
}

// requests we pushed recently, and which of them got a reply
const RES_KIND = 23195;
let answeredSub = null;
const recentReqs = new Map();  // request event id -> ts
const answeredIds = new Map(); // request event id -> ts a 23195 e-tagged it
function noteRequest(id) {
  recentReqs.set(id, Date.now());
  if (recentReqs.size > 2000) {
    const cut = Date.now() - 300_000;
    for (const [k, t] of recentReqs) if (t < cut) recentReqs.delete(k);
    for (const [k, t] of answeredIds) if (t < cut) answeredIds.delete(k);
  }
}

// De-dupe: the same event arrives from several relays.
const recentlyWoken = new Map();
async function wake(servicePk, eventId, ev) {
  const key = servicePk + ':' + eventId;
  if (recentlyWoken.has(key)) return;
  recentlyWoken.set(key, Date.now());
  if (recentlyWoken.size > 2000) {
    const cut = Date.now() - 300_000;
    for (const [k, t] of recentlyWoken) if (t < cut) recentlyWoken.delete(k);
  }

  const targets = regs[servicePk] || [];
  if (!targets.length) return;
  // The payload carries the (still encrypted, still client-signed) request
  // event so an auto-answering service worker can act on it without holding
  // a relay socket. Web Push payloads cap around 4KB — an oversized event is
  // omitted and the worker falls back to waking the user.
  const clean = ev && {
    id: ev.id, pubkey: ev.pubkey, created_at: ev.created_at,
    kind: ev.kind, tags: ev.tags, content: ev.content, sig: ev.sig,
  };
  let payload = JSON.stringify({ type: 'nwc', servicePubkey: servicePk, event: clean });
  if (payload.length > 3800) payload = JSON.stringify({ type: 'nwc', servicePubkey: servicePk });
  let ok = 0;
  for (const r of targets) {
    try {
      await webpush.sendNotification(r.sub, payload, { TTL: 60, urgency: 'high' });
      ok++;
    } catch (e) {
      // 404/410 mean the browser dropped the subscription: forget it.
      if (e.statusCode === 404 || e.statusCode === 410) {
        regs[servicePk] = (regs[servicePk] || []).filter((x) => x.id !== r.id);
        if (!regs[servicePk].length) delete regs[servicePk];
        persist();
        log(`dropped an expired push endpoint for ${servicePk.slice(0, 12)}`);
      } else {
        log('push failed:', e.statusCode || e.message);
      }
    }
  }
  log(`woke ${ok}/${targets.length} device(s) for ${servicePk.slice(0, 12)}`);
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: {
    'content-type': 'application/json',
    'access-control-allow-origin': '*',
    'access-control-allow-headers': 'content-type',
    'access-control-allow-methods': 'GET,POST,DELETE,OPTIONS',
  },
});

const server = Bun.serve({
  port: CFG.port || 8797,
  async fetch(req) {
    const url = new URL(req.url);
    if (req.method === 'OPTIONS') return json({});

    if (url.pathname === '/health') {
      return json({
        ok: true, relays: RELAYS, watching: watchedPubkeys().length,
        subscribed: !!sub, lastResub,
      });
    }

    // The browser needs this to create a PushSubscription.
    if (url.pathname === '/vapid') return json({ publicKey: CFG.vapid.publicKey });

    // Publish-back for the auto-answering service worker: it cannot hold a
    // relay socket, so it hands us its (encrypted, service-key-signed) reply.
    // Strictly kind 23195, size-capped, signature-verified, rate-limited —
    // this is a reply pipe, not an open relay proxy.
    if (url.pathname === '/publish' && req.method === 'POST') {
      const ip = req.headers.get('cf-connecting-ip') || req.headers.get('x-forwarded-for') || 'local';
      if (!rateOk(ip)) return json({ error: 'rate limited' }, 429);
      const body = await req.json().catch(() => null);
      const ev = body?.event;
      if (!ev || ![RES_KIND, OFFER_KIND].includes(ev.kind)) return json({ error: 'kind 23195/21001 events only' }, 400);
      if (JSON.stringify(ev).length > 4096) return json({ error: 'event too large' }, 400);
      if (!verifyEvent(ev)) return json({ error: 'bad signature' }, 400);
      const eTag = (ev.tags || []).find((t) => t[0] === 'e')?.[1];
      try { await Promise.allSettled(pool.publish(RELAYS, ev)); } catch {}
      if (eTag) answeredIds.set(eTag, Date.now());
      log(`published a reply for request ${(eTag || '?').slice(0, 12)}`);
      return json({ ok: true });
    }

    // Server-to-server: the names registrar reports a settled receive for a
    // pubkey. Token-gated; pushes 'payment received' to that user's devices.
    if (url.pathname === '/notify' && req.method === 'POST') {
      const body = await req.json().catch(() => null);
      if (!CFG.notifyToken || body?.token !== CFG.notifyToken) return json({ error: 'forbidden' }, 403);
      const pk = body?.pubkey;
      if (!/^[0-9a-f]{64}$/.test(pk || '')) return json({ error: 'pubkey required' }, 400);
      let n = 0;
      for (const [id, r] of Object.entries(notifyRegs)) {
        if ((r.ptags || []).includes(pk)) { pushNotify(id, r, 'payment', { amountSat: Number(body.amountSat) || undefined }).catch(() => {}); n++; }
      }
      return json({ ok: true, devices: n });
    }

    // Was a request we pushed already answered by someone? Lets a worker
    // avoid double-paying (or shouting an error over) another device's reply.
    if (url.pathname === '/answered') {
      const id = url.searchParams.get('event') || '';
      return json({ answered: answeredIds.has(id) });
    }

    // A device registers its push endpoint plus the wallet-service pubkeys it
    // wants woken for. Re-post periodically to stay alive.
    if (url.pathname === '/register' && req.method === 'POST') {
      const body = await req.json().catch(() => null);
      const sub_ = body?.subscription;
      const hasNwc = Array.isArray(body?.servicePubkeys);
      const pks = (body?.servicePubkeys || []).filter((p) => /^[0-9a-f]{64}$/.test(p));
      // user-facing notification watch (messages + payments) — independent of
      // the NWC registration so either can refresh without clobbering the other
      if (body?.notify && sub_?.endpoint) {
        const hex = (a, cap) => [...new Set((a || []).filter((p) => /^[0-9a-f]{64}$/.test(p)))].slice(0, cap);
        const id = Bun.hash(sub_.endpoint).toString(36);
        notifyRegs[id] = {
          sub: sub_, updated: Date.now(),
          ptags: hex(body.notify.ptags, 8),
          authors: hex(body.notify.authors, 64),
        };
        persist();
        resubscribeNotify();
        if (!hasNwc) return json({ ok: true, notify: true });
      }
      if (!sub_?.endpoint || !pks.length) return json({ error: 'subscription and servicePubkeys required' }, 400);
      if (pks.length > MAX_PK) return json({ error: `at most ${MAX_PK} pubkeys` }, 400);
      // one id per endpoint so re-registering replaces rather than duplicates
      const id = Bun.hash(sub_.endpoint).toString(36);
      const known = new Set(pks);
      for (const pk of pks) {
        regs[pk] = (regs[pk] || []).filter((r) => r.id !== id);
        regs[pk].push({ sub: sub_, id, updated: Date.now() });
      }
      // drop this device from pubkeys it no longer cares about
      for (const pk of Object.keys(regs)) {
        if (known.has(pk)) continue;
        const before = regs[pk].length;
        regs[pk] = regs[pk].filter((r) => r.id !== id);
        if (!regs[pk].length) delete regs[pk];
        if (before !== (regs[pk]?.length ?? 0)) { /* changed */ }
      }
      persist();
      resubscribe();
      return json({ ok: true, watching: pks.length });
    }

    if (url.pathname === '/register' && req.method === 'DELETE') {
      const body = await req.json().catch(() => null);
      if (!body?.endpoint) return json({ error: 'endpoint required' }, 400);
      const id = Bun.hash(body.endpoint).toString(36);
      for (const pk of Object.keys(regs)) {
        regs[pk] = regs[pk].filter((r) => r.id !== id);
        if (!regs[pk].length) delete regs[pk];
      }
      delete notifyRegs[id];
      persist();
      resubscribe();
      return json({ ok: true });
    }

    return json({ error: 'not found' }, 404);
  },
});

log(`nwc push notifier on :${server.port}`);
log(`  relays: ${RELAYS.join(' ')}`);
log(`  watching ${watchedPubkeys().length} service pubkey(s)`);
resubscribe();
setInterval(prune, 3600_000);
// relays drop long-lived subs; re-arm periodically
setInterval(() => { if (watchedPubkeys().length) resubscribe(); }, 15 * 60_000);

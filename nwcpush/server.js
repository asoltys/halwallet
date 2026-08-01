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
import webpush from 'web-push';

const CFG = JSON.parse(readFileSync(process.env.NWCPUSH_CONFIG
  || join(import.meta.dir, 'config.json'), 'utf8'));
//  { port, relays: [...], vapid: { publicKey, privateKey, subject },
//    stateFile, maxPubkeysPerDevice, staleDays }

const RELAYS = CFG.relays || ['wss://relay.coinos.io', 'wss://relay.damus.io', 'wss://nos.lol'];
const STATE = CFG.stateFile || join(import.meta.dir, 'data', 'registrations.json');
const MAX_PK = CFG.maxPubkeysPerDevice || 20;
const STALE_MS = (CFG.staleDays || 30) * 86400_000;
const REQ_KIND = 23194;

webpush.setVapidDetails(CFG.vapid.subject, CFG.vapid.publicKey, CFG.vapid.privateKey);
const log = (...a) => console.log(new Date().toISOString(), ...a);

// ---------------------------------------------------------------------------
// registrations: { [servicePubkey]: [{ sub, id, updated }] }
// ---------------------------------------------------------------------------

let regs = (() => {
  try { return JSON.parse(readFileSync(STATE, 'utf8')); } catch { return {}; }
})();
function persist() {
  mkdirSync(dirname(STATE), { recursive: true });
  const tmp = STATE + '.tmp';
  writeFileSync(tmp, JSON.stringify(regs));
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
  if (dropped) { persist(); log(`pruned ${dropped} stale pubkey(s)`); resubscribe(); }
}

const watchedPubkeys = () => Object.keys(regs);

// ---------------------------------------------------------------------------
// relay watcher
// ---------------------------------------------------------------------------

const pool = new SimplePool();
let sub = null;
let lastResub = 0;

function resubscribe() {
  const pks = watchedPubkeys();
  try { sub?.close(); } catch {}
  sub = null;
  if (!pks.length) { log('nothing registered; not subscribed'); return; }
  lastResub = Date.now();
  sub = pool.subscribeMany(
    RELAYS,
    // only live traffic: a replayed old request must not wake devices
    [{ kinds: [REQ_KIND], '#p': pks, since: Math.floor(Date.now() / 1000) }],
    {
      onevent: (ev) => {
        const target = ev.tags?.find((t) => t[0] === 'p')?.[1];
        if (target) wake(target, ev.id).catch(() => {});
      },
    },
  );
  log(`subscribed for ${pks.length} service pubkey(s) on ${RELAYS.length} relays`);
}

// De-dupe: the same event arrives from several relays.
const recentlyWoken = new Map();
async function wake(servicePk, eventId) {
  const key = servicePk + ':' + eventId;
  if (recentlyWoken.has(key)) return;
  recentlyWoken.set(key, Date.now());
  if (recentlyWoken.size > 2000) {
    const cut = Date.now() - 300_000;
    for (const [k, t] of recentlyWoken) if (t < cut) recentlyWoken.delete(k);
  }

  const targets = regs[servicePk] || [];
  if (!targets.length) return;
  // The payload carries no request content — only enough for the service
  // worker to know which connection to go look at.
  const payload = JSON.stringify({ type: 'nwc', servicePubkey: servicePk });
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

    // A device registers its push endpoint plus the wallet-service pubkeys it
    // wants woken for. Re-post periodically to stay alive.
    if (url.pathname === '/register' && req.method === 'POST') {
      const body = await req.json().catch(() => null);
      const sub_ = body?.subscription;
      const pks = (body?.servicePubkeys || []).filter((p) => /^[0-9a-f]{64}$/.test(p));
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

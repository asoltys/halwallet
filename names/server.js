// BIP-353 name registrar for halwallet.app — gives every hal user a
// ₿name@halwallet.app payment address.
//
// A name is a DNSSEC-signed TXT record at
//   <name>.user._bitcoin-payment.halwallet.app
// whose content is a BIP-21 `bitcoin:` URI (for hal users: an ark address,
// extensible later with lno= etc). This service is the write path: it
// validates a claim signed by the wallet's nostr key, enforces first-come
// ownership by that key, and mirrors the record into Cloudflare DNS.
//
// WHAT THIS SERVICE LEARNS: name ↔ nostr pubkey ↔ payment URI. All of it is
// public by construction (DNS is public). It cannot spend anything.
//
// Deliberately dumb: one JSON state file, no accounts, no email.

import { readFileSync, writeFileSync, renameSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { verifyEvent } from 'nostr-tools/pure';

const CFG = JSON.parse(readFileSync(process.env.NAMES_CONFIG
  || join(import.meta.dir, 'config.json'), 'utf8'));
// { port, domain, zoneId, cfEmail, cfKey, stateFile }

const DOMAIN = CFG.domain || 'halwallet.app';
const STATE = CFG.stateFile || join(import.meta.dir, 'data', 'names.json');
const AUTH_KIND = 21353;         // arbitrary custom kind for signed claims
const MAX_SKEW_SEC = 600;        // claim events must be fresh
const TTL = 300;                 // record TTL: BIP-353 wallets cache by this

const log = (...a) => console.log(new Date().toISOString(), ...a);

// names that must never be claimable
const RESERVED = new Set([
  'admin', 'administrator', 'root', 'hal', 'halwallet', 'www', 'mail', 'help',
  'support', 'info', 'pay', 'payments', 'wallet', 'staging', 'names', 'api',
  'user', 'users', 'coinos', 'nostr', 'ark', 'test', 'dev', 'security', 'abuse',
]);
const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,29}$/;

let state = (() => {
  try { return JSON.parse(readFileSync(STATE, 'utf8')); } catch { return { names: {} }; }
})();
function persist() {
  mkdirSync(dirname(STATE), { recursive: true });
  const tmp = STATE + '.tmp';
  writeFileSync(tmp, JSON.stringify(state));
  renameSync(tmp, STATE);
}

// ---------------------------------------------------------------------------
// Cloudflare DNS
// ---------------------------------------------------------------------------

const CF = 'https://api.cloudflare.com/client/v4';
const cfHeaders = {
  'X-Auth-Email': CFG.cfEmail, 'X-Auth-Key': CFG.cfKey, 'content-type': 'application/json',
};
const recordName = (name) => `${name}.user._bitcoin-payment.${DOMAIN}`;

async function cfWrite(name, uri, existingId) {
  const body = JSON.stringify({
    type: 'TXT', name: recordName(name), content: `"${uri}"`, ttl: TTL,
  });
  const url = existingId
    ? `${CF}/zones/${CFG.zoneId}/dns_records/${existingId}`
    : `${CF}/zones/${CFG.zoneId}/dns_records`;
  const r = await fetch(url, { method: existingId ? 'PUT' : 'POST', headers: cfHeaders, body });
  const j = await r.json();
  if (!j.success) throw new Error('dns write failed: ' + JSON.stringify(j.errors).slice(0, 200));
  return j.result.id;
}
async function cfDelete(recordId) {
  const r = await fetch(`${CF}/zones/${CFG.zoneId}/dns_records/${recordId}`, {
    method: 'DELETE', headers: cfHeaders,
  });
  const j = await r.json();
  if (!j.success) throw new Error('dns delete failed');
}

// ---------------------------------------------------------------------------
// claims
// ---------------------------------------------------------------------------

// The claim is a signed nostr event: proof the caller controls the wallet's
// nostr key, which becomes (or must match) the name's owner.
function checkAuth(auth) {
  if (!auth || auth.kind !== AUTH_KIND) return 'bad auth kind';
  if (Math.abs(Date.now() / 1000 - (auth.created_at || 0)) > MAX_SKEW_SEC) return 'auth event too old';
  if (!verifyEvent(auth)) return 'bad signature';
  return null;
}

const validUri = (u) => typeof u === 'string' && /^bitcoin:/i.test(u) && u.length <= 480
  && !/[\s"\\]/.test(u);

// crude per-IP limiter
const rate = new Map();
function rateOk(ip, limit = 10) {
  const now = Date.now();
  const arr = (rate.get(ip) || []).filter((t) => t > now - 60_000);
  if (arr.length >= limit) return false;
  arr.push(now);
  rate.set(ip, arr);
  if (rate.size > 1000) for (const [k, v] of rate) { if (!v.some((t) => t > now - 60_000)) rate.delete(k); }
  return true;
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

Bun.serve({
  port: CFG.port || 8798,
  async fetch(req) {
    const url = new URL(req.url);
    if (req.method === 'OPTIONS') return json({});
    const ip = req.headers.get('cf-connecting-ip') || req.headers.get('x-forwarded-for') || 'local';

    if (url.pathname === '/health') {
      return json({ ok: true, domain: DOMAIN, names: Object.keys(state.names).length });
    }

    // Availability / lookup. Public data (it's DNS).
    const m = url.pathname.match(/^\/name\/([a-z0-9._-]{1,30})$/);
    if (m && req.method === 'GET') {
      const rec = state.names[m[1]];
      if (!rec) return json({ name: m[1], taken: false, reserved: RESERVED.has(m[1]) || !NAME_RE.test(m[1]) });
      return json({ name: m[1], taken: true, pubkey: rec.pubkey, uri: rec.uri });
    }

    if (url.pathname === '/register' && req.method === 'POST') {
      if (!rateOk(ip)) return json({ error: 'rate limited' }, 429);
      const body = await req.json().catch(() => null);
      const auth = body?.auth;
      const authErr = checkAuth(auth);
      if (authErr) return json({ error: authErr }, 400);
      let claim;
      try { claim = JSON.parse(auth.content); } catch { return json({ error: 'bad claim content' }, 400); }
      const name = String(claim.name || '').toLowerCase();
      if (!NAME_RE.test(name)) return json({ error: 'invalid name (a-z, 0-9, . _ -, max 30)' }, 400);
      if (RESERVED.has(name)) return json({ error: 'name is reserved' }, 400);
      if (claim.action !== 'register') return json({ error: 'wrong action' }, 400);
      if (!validUri(claim.uri)) return json({ error: 'uri must be a bitcoin: URI' }, 400);

      const existing = state.names[name];
      if (existing && existing.pubkey !== auth.pubkey) return json({ error: 'name is taken' }, 409);

      const recordId = await cfWrite(name, claim.uri, existing?.recordId);
      state.names[name] = { pubkey: auth.pubkey, uri: claim.uri, recordId, updated: Date.now() };
      persist();
      log(`${existing ? 'updated' : 'registered'} ${name} for ${auth.pubkey.slice(0, 12)}`);
      return json({ ok: true, name, address: `${name}@${DOMAIN}`, record: recordName(name) });
    }

    if (url.pathname === '/register' && req.method === 'DELETE') {
      if (!rateOk(ip)) return json({ error: 'rate limited' }, 429);
      const body = await req.json().catch(() => null);
      const auth = body?.auth;
      const authErr = checkAuth(auth);
      if (authErr) return json({ error: authErr }, 400);
      let claim;
      try { claim = JSON.parse(auth.content); } catch { return json({ error: 'bad claim content' }, 400); }
      const name = String(claim.name || '').toLowerCase();
      if (claim.action !== 'delete') return json({ error: 'wrong action' }, 400);
      const existing = state.names[name];
      if (!existing) return json({ error: 'unknown name' }, 404);
      if (existing.pubkey !== auth.pubkey) return json({ error: 'not your name' }, 403);
      await cfDelete(existing.recordId).catch(() => {});
      delete state.names[name];
      persist();
      log(`released ${name}`);
      return json({ ok: true });
    }

    return json({ error: 'not found' }, 404);
  },
});

log(`names registrar for ${DOMAIN} on :${CFG.port || 8798} — ${Object.keys(state.names).length} name(s)`);

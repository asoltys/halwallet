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
import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync } from '@scure/bip39';
import { lnBackend } from '../bridge/ln.js';
import { ArkManager } from '../src/ark/manager.js';

const CFG = JSON.parse(readFileSync(process.env.NAMES_CONFIG
  || join(import.meta.dir, 'config.json'), 'utf8'));
// { port, domain, zoneId, cfEmail, cfKey, stateFile,
//   ln: { kind:'socket', path } — the ASP's CLN, for per-name bolt12 offers,
//   forwarder: { mnemonic, ark, esplora, network } — a small float ark wallet
//     that forwards settled offer payments to the name's ark address }

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
  // TXT character-strings cap at 255 bytes; BIP-353 readers concatenate the
  // chunks in order, so a long ark+lno URI just spans several quoted strings.
  const chunks = uri.match(/.{1,255}/g).map((c) => `"${c}"`).join(' ');
  const body = JSON.stringify({
    type: 'TXT', name: recordName(name), content: chunks, ttl: TTL,
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
// bolt12 offers + the settle forwarder
// ---------------------------------------------------------------------------
// Each name gets a static BOLT 12 offer on the ASP's CLN, published in the
// DNS record as lno=. Offer payments land on the ASP node, so a forwarder
// pushes each settled payment on to the name's ark address from a small
// float wallet (an ordinary arkoor send — free). Custody window: the seconds
// between LN settle and the ark send. The float must be topped up by the
// operator; LN income accrues on the node as the offset.

const ln = CFG.ln ? lnBackend(CFG.ln) : null;
let fwd = null; // the float ark wallet
if (CFG.forwarder?.mnemonic) {
  const account = HDKey.fromMasterSeed(mnemonicToSeedSync(CFG.forwarder.mnemonic)).derive("m/86'/0'/9'");
  fwd = await new ArkManager({
    account,
    storage: {
      load: () => state.fwdArk || null,
      save: (s) => { state.fwdArk = s; persist(); },
    },
    arkUrl: CFG.forwarder.ark, esploraUrl: CFG.forwarder.esplora, network: CFG.forwarder.network || 'mainnet',
  }).init();
  log(`forwarder ark wallet ready — float ${fwd.balance().spendableSat} sat, receive ${fwd.address().slice(0, 24)}…`);
}

async function makeOffer(name) {
  if (!ln) return null;
  const o = await ln.call('offer', { amount: 'any', description: `${name}@${DOMAIN}` });
  return { offerId: o.offer_id, bolt12: o.bolt12 };
}

const arkParamOf = (uri) => {
  const m = String(uri).match(/[?&]ark=([^&]+)/);
  return m ? decodeURIComponent(m[1]) : null;
};

// Forward one settled offer payment; queue it on failure (empty float, etc).
async function forward(name, sat) {
  const rec = state.names[name];
  const dest = rec && arkParamOf(rec.uri);
  if (!dest) { log(`forward: no ark destination for ${name}, dropping ${sat} sat`); return; }
  if (!fwd) throw new Error('no forwarder wallet');
  await fwd.send(dest, sat);
  log(`forwarded ${sat} sat to ${name}`);
}

async function settleLoop() {
  if (!ln || !fwd) return;
  state.lastPayIndex = state.lastPayIndex || 0;
  for (;;) {
    let inv;
    try {
      inv = await ln.call('waitanyinvoice', { lastpay_index: state.lastPayIndex, timeout: 120 });
    } catch (e) {
      if (!/timed out|Timed out/i.test(e.message)) await new Promise((r) => setTimeout(r, 5000));
      continue;
    }
    state.lastPayIndex = inv.pay_index || state.lastPayIndex;
    persist();
    const offerId = inv.local_offer_id;
    const name = offerId && Object.keys(state.names).find((n) => state.names[n].offerId === offerId);
    if (!name) continue; // not one of ours (e.g. the ASP's own invoices)
    const sat = Math.floor((inv.amount_received_msat?.msat ?? inv.amount_received_msat ?? 0) / 1000);
    if (!sat) continue;
    try {
      await forward(name, sat);
    } catch (e) {
      log(`forward failed for ${name} (${sat} sat): ${e.message} — queued`);
      state.pending = state.pending || [];
      state.pending.push({ name, sat, ts: Date.now() });
      persist();
    }
  }
}
// retry queued forwards (e.g. after the float is topped up)
setInterval(async () => {
  const q = state.pending || [];
  if (!q.length || !fwd) return;
  const still = [];
  for (const p of q) {
    try { await forward(p.name, p.sat); } catch { still.push(p); }
  }
  state.pending = still;
  persist();
}, 60_000);

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
      return json({
        ok: true, domain: DOMAIN, names: Object.keys(state.names).length,
        offers: !!ln, floatSat: fwd ? fwd.balance().spendableSat : null,
        floatAddress: fwd ? fwd.address() : null,
        pendingForwards: (state.pending || []).length,
      });
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
      if (/[?&]lno=/.test(claim.uri)) return json({ error: 'lno is added by the registrar' }, 400);

      // Every name also gets a static Lightning offer on our node; payments
      // to it are forwarded to the ark destination in the claim.
      let offer = existing?.offerId ? { offerId: existing.offerId, bolt12: existing.bolt12 } : null;
      if (!offer) { try { offer = await makeOffer(name); } catch (e) { log('offer creation failed: ' + e.message); } }
      const published = offer ? `${claim.uri}${claim.uri.includes('?') ? '&' : '?'}lno=${offer.bolt12}` : claim.uri;

      const recordId = await cfWrite(name, published, existing?.recordId);
      state.names[name] = {
        pubkey: auth.pubkey, uri: published, recordId, updated: Date.now(),
        offerId: offer?.offerId, bolt12: offer?.bolt12,
      };
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
      if (existing.offerId && ln) await ln.call('disableoffer', { offer_id: existing.offerId }).catch(() => {});
      delete state.names[name];
      persist();
      log(`released ${name}`);
      return json({ ok: true });
    }

    return json({ error: 'not found' }, 404);
  },
});

settleLoop().catch((e) => log('settle loop died:', e.message));
log(`names registrar for ${DOMAIN} on :${CFG.port || 8798} — ${Object.keys(state.names).length} name(s), offers ${ln ? 'on' : 'off'}, forwarder ${fwd ? 'on' : 'off'}`);

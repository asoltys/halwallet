// BIP-353 name registrar for halwallet.app — gives every hal user a
// ₿name@halwallet.app payment address.
//
// Auth on every write is NIP-98 (HTTP Auth, kind 27235).
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
import { npubEncode } from 'nostr-tools/nip19';
import { createHash } from 'node:crypto';
import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync } from '@scure/bip39';
import { lnBackend } from '../bridge/ln.js';
import { ArkManager } from '../src/ark/manager.js';

const CFG = JSON.parse(readFileSync(process.env.NAMES_CONFIG
  || join(import.meta.dir, 'config.json'), 'utf8'));
// { port, domains: { '<domain>': { zoneId } }, domain (default), cfEmail, cfKey, stateFile,
//   ln: { kind:'socket', path } — the ASP's CLN, for per-name bolt12 offers,
//   forwarder: { mnemonic, ark, esplora, network } — a small float ark wallet
//     that forwards settled offer payments to the name's ark address }

const DOMAIN = CFG.domain || 'coinos.io'; // the default domain for claims
const DOMAINS = CFG.domains || { [DOMAIN]: { zoneId: CFG.zoneId } };
const STATE = CFG.stateFile || join(import.meta.dir, 'data', 'names.json');
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
const recordName = (name, domain) => `${name}.user._bitcoin-payment.${domain}`;

async function cfWrite(name, domain, uri, existingId) {
  // TXT character-strings cap at 255 bytes; BIP-353 readers concatenate the
  // chunks in order, so a long ark+lno URI just spans several quoted strings.
  const zoneId = DOMAINS[domain]?.zoneId;
  if (!zoneId) throw new Error('unknown domain');
  const chunks = uri.match(/.{1,255}/g).map((c) => `"${c}"`).join(' ');
  const body = JSON.stringify({
    type: 'TXT', name: recordName(name, domain), content: chunks, ttl: TTL,
  });
  const url = existingId
    ? `${CF}/zones/${zoneId}/dns_records/${existingId}`
    : `${CF}/zones/${zoneId}/dns_records`;
  const r = await fetch(url, { method: existingId ? 'PUT' : 'POST', headers: cfHeaders, body });
  const j = await r.json();
  if (!j.success) throw new Error('dns write failed: ' + JSON.stringify(j.errors).slice(0, 200));
  return j.result.id;
}
async function cfDelete(domain, recordId) {
  const zoneId = DOMAINS[domain]?.zoneId;
  if (!zoneId) throw new Error('unknown domain');
  const r = await fetch(`${CF}/zones/${zoneId}/dns_records/${recordId}`, {
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

async function makeOffer(address) { // "name@domain"
  if (!ln) return null;
  const o = await ln.call('offer', { amount: 'any', description: address });
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

// NIP-98 HTTP Auth (kind 27235). The signature covers this exact URL, method
// and body hash, so a captured header is useless anywhere else.
async function checkNip98(req, url, bodyText) {
  const h = req.headers.get('authorization') || '';
  const m = h.match(/^Nostr\s+(.+)$/i);
  if (!m) return { error: 'missing Nostr authorization' };
  let evt;
  try { evt = JSON.parse(Buffer.from(m[1], 'base64').toString('utf8')); } catch { return { error: 'bad auth encoding' }; }
  if (evt.kind !== 27235) return { error: 'auth must be kind 27235' };
  if (Math.abs(Date.now() / 1000 - (evt.created_at || 0)) > 60) return { error: 'auth event expired' };
  if (!verifyEvent(evt)) return { error: 'bad signature' };
  const tag = (k) => (evt.tags.find((x) => x[0] === k) || [])[1];
  if ((tag('method') || '').toUpperCase() !== req.method) return { error: 'method mismatch' };
  let got;
  try { got = new URL(tag('u') || ''); } catch { return { error: 'bad url tag' }; }
  if (got.pathname !== url.pathname) return { error: 'url mismatch' };
  if (bodyText) {
    const want = createHash('sha256').update(bodyText).digest('hex');
    if (tag('payload') !== want) return { error: 'payload hash mismatch' };
  }
  return { pubkey: evt.pubkey };
}

// npub-prefix names are the free default everyone gets, so they must not be
// squattable: a name that looks like one may only be claimed by that very
// identity — or by a key that identity nominated as its manager (the wallet
// key, which is always available, even offline and in the service worker).
const npubPrefixOwner = (name) => (/^npub1[a-z0-9]+$/.test(name) ? name : null);

// coinos.io names that belong to existing coinos users are reserved for
// them until the migration gives those users a way to claim their own.
async function takenByCoinosUser(domain, name) {
  if (domain !== 'coinos.io') return false;
  try {
    const r = await fetch(`https://coinos.io/api/users/${encodeURIComponent(name)}`);
    return r.status === 200;
  } catch { return true; } // can't verify → refuse rather than squat
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
      const domain = (url.searchParams.get('domain') || DOMAIN).toLowerCase();
      const rec = state.names[`${m[1]}@${domain}`];
      if (rec) return json({ name: m[1], domain, taken: true, pubkey: rec.pubkey, uri: rec.uri });
      const reserved = RESERVED.has(m[1]) || !NAME_RE.test(m[1]) || await takenByCoinosUser(domain, m[1]);
      return json({ name: m[1], domain, taken: reserved, reserved });
    }

    // Which name(s) does a wallet key own? Lets an imported seed find its
    // username again without the user retyping it. Public data (DNS is public).
    const pm = url.pathname.match(/^\/pubkey\/([0-9a-f]{64})$/);
    if (pm && req.method === 'GET') {
      const mine = Object.entries(state.names)
        .filter(([, r]) => r.pubkey === pm[1])
        .sort((a, b) => (b[1].updated || 0) - (a[1].updated || 0));
      if (!mine.length) return json({});
      const [key, r] = mine[0];
      const [name, domain] = key.split('@');
      return json({ name, domain, uri: r.uri });
    }

    if (url.pathname === '/register' && req.method === 'POST') {
      if (!rateOk(ip)) return json({ error: 'rate limited' }, 429);
      const bodyText = await req.text();
      const a = await checkNip98(req, url, bodyText);
      if (a.error) return json({ error: a.error }, 401);
      let claim;
      try { claim = JSON.parse(bodyText); } catch { return json({ error: 'bad body' }, 400); }
      const auth = { pubkey: a.pubkey };
      const name = String(claim.name || '').toLowerCase();
      const domain = String(claim.domain || 'halwallet.app').toLowerCase();
      if (!DOMAINS[domain]) return json({ error: 'unknown domain' }, 400);
      if (!NAME_RE.test(name)) return json({ error: 'invalid name (a-z, 0-9, . _ -, max 30)' }, 400);
      if (RESERVED.has(name)) return json({ error: 'name is reserved' }, 400);
      if (!validUri(claim.uri)) return json({ error: 'uri must be a bitcoin: URI' }, 400);

      const key = `${name}@${domain}`;
      const existing = state.names[key];
      // owner OR the manager key the owner nominated may update a record
      if (existing && existing.pubkey !== auth.pubkey && existing.manager !== auth.pubkey) {
        return json({ error: 'name is taken' }, 409);
      }
      if (!existing && await takenByCoinosUser(domain, name)) return json({ error: 'name is taken' }, 409);
      // an npub-shaped name belongs to that identity alone
      if (npubPrefixOwner(name)) {
        const managerOk = existing && existing.manager === auth.pubkey;
        if (!npubEncode(auth.pubkey).startsWith(name) && !managerOk) {
          return json({ error: 'that name belongs to another Nostr identity' }, 403);
        }
      }
      if (/[?&]lno=/.test(claim.uri)) return json({ error: 'lno is added by the registrar' }, 400);

      // Every name also gets a static Lightning offer on our node; payments
      // to it are forwarded to the ark destination in the claim.
      let offer = existing?.offerId ? { offerId: existing.offerId, bolt12: existing.bolt12 } : null;
      if (!offer) { try { offer = await makeOffer(key); } catch (e) { log('offer creation failed: ' + e.message); } }
      const published = offer ? `${claim.uri}${claim.uri.includes('?') ? '&' : '?'}lno=${offer.bolt12}` : claim.uri;

      const recordId = await cfWrite(name, domain, published, existing?.recordId);
      state.names[key] = {
        pubkey: existing?.pubkey || auth.pubkey,
        // the owner may nominate a key that manages the record from here on
        manager: (claim.manager && /^[0-9a-f]{64}$/.test(claim.manager) && auth.pubkey !== claim.manager)
          ? claim.manager : existing?.manager,
        uri: published, recordId, updated: Date.now(), domain,
        offerId: offer?.offerId, bolt12: offer?.bolt12,
      };
      persist();
      log(`${existing ? 'updated' : 'registered'} ${key} for ${auth.pubkey.slice(0, 12)}`);
      return json({ ok: true, name, address: key, record: recordName(name, domain) });
    }

    if (url.pathname === '/register' && req.method === 'DELETE') {
      if (!rateOk(ip)) return json({ error: 'rate limited' }, 429);
      const bodyText = await req.text();
      const a = await checkNip98(req, url, bodyText);
      if (a.error) return json({ error: a.error }, 401);
      let claim;
      try { claim = JSON.parse(bodyText); } catch { return json({ error: 'bad body' }, 400); }
      const auth = { pubkey: a.pubkey };
      const name = String(claim.name || '').toLowerCase();
      const domain = String(claim.domain || 'halwallet.app').toLowerCase();
      const key = `${name}@${domain}`;
      const existing = state.names[key];
      if (!existing) return json({ error: 'unknown name' }, 404);
      if (existing.pubkey !== auth.pubkey && existing.manager !== auth.pubkey) return json({ error: 'not your name' }, 403);
      await cfDelete(domain, existing.recordId).catch(() => {});
      if (existing.offerId && ln) await ln.call('disableoffer', { offer_id: existing.offerId }).catch(() => {});
      delete state.names[key];
      persist();
      log(`released ${key}`);
      return json({ ok: true });
    }

    return json({ error: 'not found' }, 404);
  },
});

settleLoop().catch((e) => log('settle loop died:', e.message));
log(`names registrar for ${DOMAIN} on :${CFG.port || 8798} — ${Object.keys(state.names).length} name(s), offers ${ln ? 'on' : 'off'}, forwarder ${fwd ? 'on' : 'off'}`);

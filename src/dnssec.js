// Client-side DNSSEC validation — the trust layer BIP-353 requires.
//
// A payment name maps to money, so the DNS answer must be provably signed by
// the zone owner all the way from the ICANN root, not vouched for by whoever
// answered the HTTP request. This module speaks DoH in *wireformat* (binary
// DNS messages), parses them itself, and walks the chain:
//
//   root trust anchor (hardcoded KSK DS digests)
//     → root DNSKEY (RRSIG self-signed by the anchored KSK)
//       → DS for the TLD (signed in the root zone)
//         → TLD DNSKEY … and so on down to the zone holding the record
//           → RRSIG over the final TXT/CNAME RRset
//
// The resolver becomes untrusted transport: it can lie only by omission
// (denial), never by forgery. Algorithms: 8 (RSA/SHA-256) — the root and
// most TLDs — and 13 (ECDSA P-256/SHA-256) — most hosted zones. Both verify
// through WebCrypto, so this works in pages, workers, and Bun alike.
//
// Deliberately NOT implemented: NSEC/NSEC3 denial proofs. We never need to
// prove a name does NOT exist — an unsigned or missing chain simply fails
// closed ("not provably signed"), which is the right answer for payments.

import { sha256 } from '@noble/hashes/sha256';

const DOH = 'https://cloudflare-dns.com/dns-query';
const DOH_FALLBACK = 'https://dns.google/dns-query';

// ICANN root KSK trust anchors (DS rdata: keytag, alg, digest type 2 SHA-256).
const ROOT_ANCHORS = [
  { keyTag: 20326, algorithm: 8, digest: 'e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d' },
  { keyTag: 38696, algorithm: 8, digest: '683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16' },
];

const TYPE = { A: 1, CNAME: 5, TXT: 16, DS: 43, RRSIG: 46, DNSKEY: 48, OPT: 41 };
const now = () => Math.floor(Date.now() / 1000);
const CLOCK_SKEW = 3600;

// ---------------------------------------------------------------------------
// wire encoding/decoding
// ---------------------------------------------------------------------------

const te = new TextEncoder();
function nameToWire(name) {
  const out = [];
  for (const label of name.replace(/\.$/, '').split('.').filter(Boolean)) {
    const b = te.encode(label.toLowerCase());
    if (b.length > 63) throw new Error('label too long');
    out.push(b.length, ...b);
  }
  out.push(0);
  return new Uint8Array(out);
}

function buildQuery(name, qtype) {
  const qname = nameToWire(name);
  const head = new Uint8Array(12);
  // id 0 (required for DoH GET caching), RD=1
  head[2] = 0x01;
  const q = new Uint8Array(qname.length + 4);
  q.set(qname, 0);
  const dv = new DataView(q.buffer);
  dv.setUint16(qname.length, qtype);
  dv.setUint16(qname.length + 2, 1); // IN
  // EDNS OPT with DO=1, 4096-byte payload:
  // name(00) type(0029) class=payload(1000) ttl=[ercode 00, ver 00, flags 8000] rdlen(0000)
  const opt = new Uint8Array([0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00]);
  const msg = new Uint8Array(12 + q.length + opt.length);
  msg.set(head, 0);
  const mdv = new DataView(msg.buffer);
  mdv.setUint16(4, 1);  // qdcount
  mdv.setUint16(10, 1); // arcount (OPT)
  msg.set(q, 12);
  msg.set(opt, 12 + q.length);
  return msg;
}

function readName(msg, off) {
  const labels = [];
  let jumped = false, next = off, guard = 0;
  while (guard++ < 200) {
    const len = msg[off];
    if (len === 0) { if (!jumped) next = off + 1; break; }
    if ((len & 0xc0) === 0xc0) {
      const ptr = ((len & 0x3f) << 8) | msg[off + 1];
      if (!jumped) next = off + 2;
      jumped = true;
      off = ptr;
      continue;
    }
    labels.push(new TextDecoder().decode(msg.slice(off + 1, off + 1 + len)));
    off += 1 + len;
  }
  return { name: labels.join('.').toLowerCase(), next };
}

function parseMessage(buf) {
  const msg = new Uint8Array(buf);
  const dv = new DataView(msg.buffer, msg.byteOffset, msg.byteLength);
  const qd = dv.getUint16(4), an = dv.getUint16(6), ns = dv.getUint16(8), ar = dv.getUint16(10);
  const rcode = dv.getUint16(2) & 0x0f;
  let off = 12;
  for (let i = 0; i < qd; i++) { off = readName(msg, off).next + 4; }
  const rrs = [];
  const total = an + ns + ar;
  for (let i = 0; i < total; i++) {
    const { name, next } = readName(msg, off);
    off = next;
    const type = dv.getUint16(off);
    const cls = dv.getUint16(off + 2);
    const ttl = dv.getUint32(off + 4);
    const rdlen = dv.getUint16(off + 8);
    const rdStart = off + 10;
    const rdata = msg.slice(rdStart, rdStart + rdlen);
    rrs.push({
      name, type, cls, ttl, rdata, section: i < an ? 'answer' : i < an + ns ? 'authority' : 'additional',
      // rdata with any compressed names expanded (needed for canonical forms)
      rdataExpanded: expandRdata(msg, type, rdStart, rdlen),
    });
    off = rdStart + rdlen;
  }
  return { rcode, rrs };
}

// CNAME rdata may use compression pointers; canonical form needs it expanded.
function expandRdata(msg, type, rdStart, rdlen) {
  if (type === TYPE.CNAME) return nameToWire(readName(msg, rdStart).name);
  return msg.slice(rdStart, rdStart + rdlen);
}

async function dohQuery(name, qtype, base = DOH) {
  const q = buildQuery(name, qtype);
  const b64 = btoa(String.fromCharCode(...q)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const r = await fetch(`${base}?dns=${b64}`, { headers: { accept: 'application/dns-message' } });
  if (!r.ok) throw new Error(`DoH ${r.status}`);
  return parseMessage(await r.arrayBuffer());
}
async function query(name, qtype) {
  try { return await dohQuery(name, qtype, DOH); } catch { return dohQuery(name, qtype, DOH_FALLBACK); }
}

// ---------------------------------------------------------------------------
// RRSIG verification (RFC 4034)
// ---------------------------------------------------------------------------

function parseRrsig(rdata) {
  const dv = new DataView(rdata.buffer, rdata.byteOffset, rdata.byteLength);
  const { name: signer, next } = readName(rdata, 18);
  return {
    typeCovered: dv.getUint16(0), algorithm: rdata[2], labels: rdata[3],
    origTtl: dv.getUint32(4), expiration: dv.getUint32(8), inception: dv.getUint32(12),
    keyTag: dv.getUint16(16), signer,
    signature: rdata.slice(next),
    signedPart: rdata.slice(0, next), // rdata up to and including signer name
  };
}

function parseDnskey(rdata) {
  const dv = new DataView(rdata.buffer, rdata.byteOffset, rdata.byteLength);
  return { flags: dv.getUint16(0), protocol: rdata[2], algorithm: rdata[3], publicKey: rdata.slice(4) };
}

function keyTag(rdata) {
  let ac = 0;
  for (let i = 0; i < rdata.length; i++) ac += (i & 1) ? rdata[i] : rdata[i] << 8;
  ac += (ac >> 16) & 0xffff;
  return ac & 0xffff;
}

const hexOf = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
const b64url = (u8) => btoa(String.fromCharCode(...u8)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function verifySig(algorithm, publicKey, data, signature) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error('WebCrypto unavailable');
  if (algorithm === 13) { // ECDSA P-256 / SHA-256; key = x||y (64b), sig = r||s (64b)
    if (publicKey.length !== 64 || signature.length !== 64) throw new Error('bad P-256 material');
    const key = await subtle.importKey('jwk', {
      kty: 'EC', crv: 'P-256', x: b64url(publicKey.slice(0, 32)), y: b64url(publicKey.slice(32)),
    }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signature, data);
  }
  if (algorithm === 8) { // RSASSA-PKCS1-v1_5 / SHA-256; key = expLen|exp|modulus
    let expLen = publicKey[0], off = 1;
    if (expLen === 0) { expLen = (publicKey[1] << 8) | publicKey[2]; off = 3; }
    const e = publicKey.slice(off, off + expLen);
    const n = publicKey.slice(off + expLen);
    if (n.length < 128) throw new Error('RSA key under 1024 bits'); // BIP-353 floor
    const key = await subtle.importKey('jwk', {
      kty: 'RSA', n: b64url(n), e: b64url(e),
    }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    return subtle.verify('RSASSA-PKCS1-v1_5', key, signature, data);
  }
  throw new Error(`unsupported DNSSEC algorithm ${algorithm}`);
}

// The RRSIG-signed data: RRSIG rdata (sans signature) + canonical RRset.
function signedData(rrsig, rrs) {
  // canonical owner: lowercase; wildcard expansion drops leftmost labels
  const canonOwner = (name) => {
    const labels = name.replace(/\.$/, '').split('.').filter(Boolean);
    const owner = labels.length > rrsig.labels ? ['*', ...labels.slice(labels.length - rrsig.labels)] : labels;
    return nameToWire(owner.join('.'));
  };
  const parts = [rrsig.signedPart];
  const canon = rrs.map((rr) => {
    const owner = canonOwner(rr.name);
    const rdata = rr.rdataExpanded;
    const head = new Uint8Array(owner.length + 10);
    head.set(owner, 0);
    const dv = new DataView(head.buffer);
    dv.setUint16(owner.length, rr.type);
    dv.setUint16(owner.length + 2, rr.cls);
    dv.setUint32(owner.length + 4, rrsig.origTtl);
    dv.setUint16(owner.length + 8, rdata.length);
    const whole = new Uint8Array(head.length + rdata.length);
    whole.set(head, 0);
    whole.set(rdata, head.length);
    return whole;
  }).sort((a, b) => { // canonical rdata order
    for (let i = 0; i < Math.min(a.length, b.length); i++) { if (a[i] !== b[i]) return a[i] - b[i]; }
    return a.length - b.length;
  });
  parts.push(...canon);
  const total = parts.reduce((n2, p) => n2 + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

// Verify an RRset against a set of trusted DNSKEYs of its zone.
async function verifyRrset(rrs, rrsigs, trustedKeys, zone) {
  const t = now();
  for (const sigRr of rrsigs) {
    const sig = parseRrsig(sigRr.rdataExpanded);
    if (sig.typeCovered !== rrs[0].type) continue;
    if (sig.signer !== zone) continue;
    if (sig.inception > t + CLOCK_SKEW || sig.expiration < t - CLOCK_SKEW) continue;
    for (const k of trustedKeys) {
      if (k.tag !== sig.keyTag || k.parsed.algorithm !== sig.algorithm) continue;
      try {
        if (await verifySig(sig.algorithm, k.parsed.publicKey, signedData(sig, rrs), sig.signature)) return true;
      } catch {}
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// the chain walk
// ---------------------------------------------------------------------------

// Establish this zone's trusted DNSKEY set from DS records validated in the
// parent (or the hardcoded root anchors for '.').
async function trustedZoneKeys(zone, dsSet) {
  const resp = await query(zone || '.', TYPE.DNSKEY);
  const keyRrs = resp.rrs.filter((r) => r.type === TYPE.DNSKEY && r.name === zone && r.section === 'answer');
  const sigRrs = resp.rrs.filter((r) => r.type === TYPE.RRSIG && r.name === zone && r.section === 'answer');
  if (!keyRrs.length) throw new Error(`no DNSKEY for ${zone || '.'}`);
  const keys = keyRrs.map((r) => ({ rr: r, parsed: parseDnskey(r.rdataExpanded), tag: keyTag(r.rdataExpanded) }));
  // Which keys are anchored by DS? DS digest = SHA-256(owner wire | DNSKEY rdata)
  const anchored = keys.filter((k) => (k.parsed.flags & 0x0001) && dsSet.some((ds) => {
    if (ds.keyTag !== k.tag || ds.algorithm !== k.parsed.algorithm) return false;
    const owner = nameToWire(zone || '.');
    const buf = new Uint8Array(owner.length + k.rr.rdataExpanded.length);
    buf.set(owner, 0);
    buf.set(k.rr.rdataExpanded, owner.length);
    return hexOf(sha256(buf)) === ds.digest;
  }));
  if (!anchored.length) throw new Error(`no DNSKEY matches DS for ${zone || '.'}`);
  // The whole DNSKEY RRset must be signed by an anchored key.
  if (!(await verifyRrset(keyRrs, sigRrs, anchored, zone))) {
    throw new Error(`DNSKEY RRset for ${zone || '.'} fails validation`);
  }
  return keys; // all keys (KSK+ZSK) are now trusted for this zone
}

function parseDs(rdata) {
  const dv = new DataView(rdata.buffer, rdata.byteOffset, rdata.byteLength);
  return { keyTag: dv.getUint16(0), algorithm: rdata[2], digestType: rdata[3], digest: hexOf(rdata.slice(4)) };
}

// Fetch DS for `child` and validate it in the (already-trusted) parent zone.
async function validatedDs(child, parentZone, parentKeys) {
  const resp = await query(child, TYPE.DS);
  const dsRrs = resp.rrs.filter((r) => r.type === TYPE.DS && r.name === child && r.section === 'answer');
  if (!dsRrs.length) return null; // unsigned delegation (or none) — fail closed upstream
  const sigRrs = resp.rrs.filter((r) => r.type === TYPE.RRSIG && r.name === child && r.section === 'answer');
  if (!(await verifyRrset(dsRrs, sigRrs, parentKeys, parentZone))) {
    throw new Error(`DS for ${child} fails validation`);
  }
  const all = dsRrs.map((r) => parseDs(r.rdataExpanded));
  const usable = all.filter((d) => d.digestType === 2); // BIP-353: no SHA-1
  if (!usable.length) throw new Error(`no SHA-256 DS for ${child}`);
  return usable;
}

// Trusted DNSKEY set for the zone containing `name`, walking down from the
// root. Zone cuts are discovered by trying DS at each label boundary.
async function keysForName(name) {
  let zone = '';
  let keys = await trustedZoneKeys('', ROOT_ANCHORS.map((a) => ({ ...a, digest: a.digest.toLowerCase() })));
  const labels = name.replace(/\.$/, '').split('.').filter(Boolean);
  for (let i = labels.length - 1; i >= 0; i--) {
    const child = labels.slice(i).join('.');
    const ds = await validatedDs(child, zone, keys);
    if (!ds) continue; // not a signed zone cut — stays in the current zone
    keys = await trustedZoneKeys(child, ds);
    zone = child;
  }
  return { zone, keys };
}

// ---------------------------------------------------------------------------
// public API
// ---------------------------------------------------------------------------

// Resolve TXT at `name` with full DNSSEC validation, following CNAMEs.
// Returns { txts: string[] } — every returned string is provably signed.
// Throws when the chain does not validate. (No NSEC support: a missing or
// unsigned record throws rather than proving absence — fail closed.)
export async function resolveTxtValidated(name, { maxCnames = 5 } = {}) {
  let target = name.toLowerCase().replace(/\.$/, '');
  for (let hop = 0; hop <= maxCnames; hop++) {
    const resp = await query(target, TYPE.TXT);
    const txtRrs = resp.rrs.filter((r) => r.type === TYPE.TXT && r.name === target && r.section === 'answer');
    const cnameRrs = resp.rrs.filter((r) => r.type === TYPE.CNAME && r.name === target && r.section === 'answer');
    const sigRrs = resp.rrs.filter((r) => r.type === TYPE.RRSIG && r.name === target && r.section === 'answer');
    if (txtRrs.length) {
      const { zone, keys } = await keysForName(target);
      if (!zone) throw new Error('record is not in a signed zone');
      if (!(await verifyRrset(txtRrs, sigRrs, keys, zone))) {
        throw new Error(`TXT for ${target} fails DNSSEC validation`);
      }
      const txts = txtRrs.map((rr) => {
        const rd = rr.rdataExpanded;
        let off = 0, out = '';
        while (off < rd.length) { const l = rd[off]; out += new TextDecoder().decode(rd.slice(off + 1, off + 1 + l)); off += 1 + l; }
        return out;
      });
      return { txts };
    }
    if (cnameRrs.length) {
      const { zone, keys } = await keysForName(target);
      if (!zone) throw new Error('CNAME is not in a signed zone');
      if (!(await verifyRrset(cnameRrs, sigRrs, keys, zone))) {
        throw new Error(`CNAME at ${target} fails DNSSEC validation`);
      }
      target = readName(cnameRrs[0].rdataExpanded, 0).name;
      continue;
    }
    throw new Error(`no TXT record at ${target}`);
  }
  throw new Error('too many CNAME hops');
}

// Concord (CORD-01..06) — private communities on nostr
// https://github.com/concord-protocol/concord
//
// Core derivations and envelope crypto. Everything here is protocol-pure:
// no DOM, no app state. The messages feature builds on top of this.

import { sha256 } from "@noble/hashes/sha256";
import { hkdf } from "@noble/hashes/hkdf";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { finalizeEvent, generateSecretKey, getPublicKey, getEventHash, verifyEvent } from "nostr-tools/pure";
import { nip44 } from "nostr-tools";
import * as nip19 from "nostr-tools/nip19";
import { base64urlnopad } from "@scure/base";

const utf8 = (s) => new TextEncoder().encode(s);

export const PERM = {
  MANAGE_ROLES: 1n << 0n,
  MANAGE_CHANNELS: 1n << 1n,
  MANAGE_METADATA: 1n << 2n,
  KICK: 1n << 3n,
  BAN: 1n << 4n,
  MANAGE_MESSAGES: 1n << 5n,
  CREATE_INVITE: 1n << 6n,
  VIEW_AUDIT_LOG: 1n << 8n,
  MENTION_EVERYONE: 1n << 9n,
};

// ---- Appendix A derivations (frozen) ----

const be64 = (n) => {
  let b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n));
  return b;
};

const concat = (...arrs) => {
  let out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let o = 0;
  for (let a of arrs) out.set(a, o), (o += a.length);
  return out;
};

// A.1: info = utf8(label) || 0x00 || id[32] || epoch_be[8]?  (|| counter byte on scalar retry)
const hkdf32 = (secret, label, id, epoch, counter) => {
  let info = concat(utf8(label), new Uint8Array([0]), id);
  if (epoch !== undefined) info = concat(info, be64(epoch));
  if (counter !== undefined) info = concat(info, new Uint8Array([counter]));
  return hkdf(sha256, secret, undefined, info, 32);
};

const isValidScalar = (b) => {
  let n = BigInt("0x" + bytesToHex(b));
  return n > 0n && n < secp256k1.CURVE.n;
};

// A.2 + A.3: derive a keypair whose x-only pubkey is the stream address
export const groupKey = (label, secret, id, epoch) => {
  let sk = hkdf32(secret, label, id, epoch);
  for (let c = 0; !isValidScalar(sk); c++) sk = hkdf32(secret, label, id, epoch, c);
  let pk = bytesToHex(schnorr.getPublicKey(sk));
  return { sk, pk, convKey: nip44.getConversationKey(sk, pk) };
};

// A.4
export const communityId = (ownerHex, saltHex) =>
  bytesToHex(sha256(concat(utf8("concord/community"), hexToBytes(ownerHex), hexToBytes(saltHex))));

const ZERO32 = new Uint8Array(32);

export const controlKey = (root, cid, epoch = 0) =>
  groupKey("concord/control", root, hexToBytes(cid), epoch);
export const guestbookKey = (root, cid, epoch = 0) =>
  groupKey("concord/guestbook", root, hexToBytes(cid), epoch);
export const channelKey = (secret, channelId, epoch = 0) =>
  groupKey("concord/channel", secret, hexToBytes(channelId), epoch);
export const grantEid = (cid, memberHex) =>
  bytesToHex(hkdf32(hexToBytes(cid), "concord/grant", hexToBytes(memberHex)));
export const banlistEid = (cid) => bytesToHex(hkdf32(hexToBytes(cid), "concord/banlist", ZERO32));

// ---- CORD-01 envelope ----
// wrap(1059, signed by stream key) > seal(20013 encrypted | 20014 plaintext, author-signed) > rumor

const rumorWithId = (rumor) => ({ ...rumor, id: getEventHash({ ...rumor, tags: rumor.tags || [] }) });

// Sign a seal around a rumor. `signer` is a raw secret key (Uint8Array) or a
// { signEvent } adapter (nostr-login extension/bunker). Plaintext seals
// (control plane) carry the rumor JSON verbatim; encrypted seals
// nip44-encrypt it under the stream conversation key.
export const makeSeal = async (rumor, signer, streamConvKey, { plaintext = false } = {}) => {
  let r = rumorWithId(rumor);
  let content = plaintext ? JSON.stringify(r) : nip44.encrypt(JSON.stringify(r), streamConvKey);
  let seal = { kind: plaintext ? 20014 : 20013, content, tags: [], created_at: rumor.created_at };
  return signer instanceof Uint8Array ? finalizeEvent(seal, signer) : signer.signEvent(seal);
};

export const makeWrap = (seal, stream, { ephemeral = false } = {}) => {
  let wrap = {
    kind: ephemeral ? 21059 : 1059,
    content: nip44.encrypt(JSON.stringify(seal), stream.convKey),
    tags: [["p", getPublicKey(generateSecretKey())]],
    created_at: seal.created_at,
  };
  return finalizeEvent(wrap, stream.sk);
};

export const wrapRumor = async (rumor, signer, stream, opts = {}) =>
  makeWrap(await makeSeal(rumor, signer, stream.convKey, opts), stream, opts);

// Open a 1059/21059 wrap fetched at a stream address. Returns { rumor, author, seal }
// or null if any layer fails to parse, decrypt, or verify.
export const openWrap = (wrap, stream) => {
  try {
    let seal = JSON.parse(nip44.decrypt(wrap.content, stream.convKey));
    if (seal.kind !== 20013 && seal.kind !== 20014) return null;
    if (!verifyEvent(seal)) return null;
    let raw = seal.kind === 20014 ? seal.content : nip44.decrypt(seal.content, stream.convKey);
    let rumor = JSON.parse(raw);
    if (rumor.pubkey !== seal.pubkey) return null;
    if (rumor.id !== getEventHash({ ...rumor, tags: rumor.tags || [] })) return null;
    return { rumor, author: seal.pubkey, seal, raw };
  } catch {
    return null;
  }
};

// millisecond ordering: created_at * 1000 + ms tag (CORD-02 §4)
export const eventMs = (rumor) => {
  let ms = +(rumor.tags?.find((t) => t[0] === "ms")?.[1] ?? 0);
  if (!(ms >= 0 && ms <= 999)) return null;
  return rumor.created_at * 1000 + ms;
};

export const msTags = (nowMs) => {
  let created_at = Math.floor(nowMs / 1000);
  return { created_at, ms: ["ms", String(nowMs % 1000)] };
};

// ---- CORD-04 editions ----

// edition_hash: sha256 over the length-prefixed, domain-separated preimage
export const editionHash = (eidHex, version, prevHex, contentStr) => {
  let label = utf8("vector-community/v1/edition");
  let content = utf8(contentStr);
  return bytesToHex(
    sha256(
      concat(
        be64(label.length), label,
        hexToBytes(eidHex),
        be64(version),
        prevHex ? concat(new Uint8Array([1]), hexToBytes(prevHex)) : concat(new Uint8Array([0]), ZERO32),
        be64(content.length), content
      )
    )
  );
};

export const makeEdition = ({ vsk, eid, version, prev, content, vac }, nowMs) => {
  let { created_at, ms } = msTags(nowMs);
  let tags = [["vsk", String(vsk)], ["eid", eid], ["ev", String(version)], ms];
  if (prev) tags.push(["ep", prev]);
  if (vac) tags.push(["vac", ...vac]);
  return { kind: 3308, content, tags, created_at };
};

// Fold control-plane rumors into per-entity heads.
// Authority: owner-rooted; we accept owner-signed editions always, and
// non-owner editions only when a fold of grants/roles authorizes them.
// Returns { metadata, channels: Map(channelId -> meta), roles, grants, banned:Set }.
export const foldControl = (entries, { ownerHex, cid }) => {
  // entries: [{ rumor, author }] — group by (vsk, eid), take highest intact version
  let byEntity = new Map();
  for (let e of entries) {
    let tag = (k) => e.rumor.tags?.find((t) => t[0] === k)?.[1];
    let vsk = tag("vsk"), eid = tag("eid"), ev = +tag("ev");
    if (vsk === undefined || !eid || !(ev >= 1)) continue;
    let key = vsk + ":" + eid;
    let cur = byEntity.get(key);
    // Highest version wins; ties: authority first (owner beats non-owner), then lower rumor id.
    let better =
      !cur ||
      ev > cur.ev ||
      (ev === cur.ev &&
        ((e.author === ownerHex) > (cur.author === ownerHex) ||
          (e.author === ownerHex) === (cur.author === ownerHex) && e.rumor.id < cur.rumor.id));
    if (better) byEntity.set(key, { ...e, vsk, eid, ev });
  }

  let state = { metadata: null, channels: new Map(), roles: new Map(), grants: new Map(), banned: new Set() };
  let parse = (e) => { try { return JSON.parse(e.rumor.content); } catch { return null; } };

  // Roles and grants first so later authority checks could use them; for now
  // coinos only honors owner-signed authority (the coinos community's owner is
  // its sole admin) plus grants the owner signed.
  for (let e of byEntity.values()) {
    if (e.author !== ownerHex) continue; // non-owner authority: future work (vac/roster walk)
    let c = parse(e);
    if (e.vsk === "1" && c) state.roles.set(e.eid, c);
    else if (e.vsk === "3" && c) state.grants.set(e.eid, c);
  }
  for (let e of byEntity.values()) {
    if (e.author !== ownerHex) continue;
    let c = parse(e);
    if (e.vsk === "0" && c && e.eid === cid) state.metadata = c;
    else if (e.vsk === "2" && c) state.channels.set(e.eid, c);
    else if (e.vsk === "4" && Array.isArray(c)) state.banned = new Set(c);
  }
  for (let [, ch] of [...state.channels]) if (ch.deleted) state.channels.delete(ch.channel_id);
  return state;
};

// ---- CORD-02 §5 guestbook fold ----
// entries: [{ rumor, author }], returns Map(npub -> { state: 'join'|'leave'|'kick', t })
export const foldGuestbook = (entries, { nowMs, banned = new Set() } = {}) => {
  let members = new Map();
  let consider = (npub, state, t, id) => {
    let cur = members.get(npub);
    if (!cur || t > cur.t || (t === cur.t && id < cur.id)) members.set(npub, { state, t, id });
  };
  for (let { rumor, author } of entries) {
    let t = eventMs(rumor);
    if (t === null || (nowMs && t > nowMs + 3600_000)) continue;
    if (rumor.kind === 3306 && (rumor.content === "join" || rumor.content === "leave"))
      consider(author, rumor.content, t, rumor.id);
    // kicks (3309) and snapshots (3312): honored later with roster ranks; skipped for now
  }
  for (let b of banned) members.delete(b);
  return members;
};

// Observed presence: any decrypted chat author newer than their latest leave re-enters (CORD-02 §5)
export const observeAuthor = (members, author, t) => {
  let cur = members.get(author);
  if (!cur || (cur.state !== "join" && t > cur.t)) members.set(author, { state: "join", t, id: "" });
};

// ---- CORD-05 invite links ----
// A link is $BASE/invite/<naddr>#<fragment>: the naddr names the bundle's
// addressable coordinate (kind 33301, per-link signer, empty d), the fragment
// carries [version=4][flags][relays?][token:16] base64url. The token derives
// the bundle's decrypt key and never reaches any server.

export const inviteKey = (token) => hkdf32(token, "concord/invite-key", ZERO32);

// Our relays aren't in the stock dictionary (CORD-05 §3), so encode them as
// wss-implied literals (leading 0) — dictionary ids still decode.
const INVITE_DICT = { 1: "wss://jskitty.com/nostr", 2: "wss://asia.vectorapp.io/nostr", 3: "wss://relay.ditto.pub", 4: "wss://relay.dreamith.to" };

export const encodeInviteFragment = (relays, token) => {
  let parts = [new Uint8Array([4, 0, Math.min(relays.length, 3)])];
  for (let url of relays.slice(0, 3)) {
    let m = url.match(/^wss:\/\/(.+)$/);
    let bytes = utf8(m ? m[1] : url);
    parts.push(new Uint8Array([m ? 0 : 255, bytes.length]), bytes);
  }
  parts.push(token);
  return base64urlnopad.encode(concat(...parts));
};

export const decodeInviteFragment = (frag) => {
  try {
    let b = base64urlnopad.decode(frag);
    if (b[0] < 4) return null; // legacy dictionary generation
    let relays = [], i = 2;
    if (b[1] & 1) relays = [INVITE_DICT[1], INVITE_DICT[2], INVITE_DICT[3], INVITE_DICT[4]];
    else {
      let count = b[i++];
      for (let n = 0; n < count && i < b.length; n++) {
        let lead = b[i++];
        if (lead >= 1 && lead <= 254) { if (INVITE_DICT[lead]) relays.push(INVITE_DICT[lead]); continue; }
        let len = b[i++];
        let s = new TextDecoder().decode(b.slice(i, i + len));
        i += len;
        relays.push(lead === 0 ? "wss://" + s : s);
      }
    }
    let token = b.slice(i, i + 16);
    if (token.length !== 16) return null;
    return { relays, token };
  } catch {
    return null;
  }
};

// Parse any invite URL or bare "naddr…#fragment" into its protocol parts.
export const parseInviteLink = (text) => {
  let m = String(text || "").trim().match(/(?:invite\/)?(naddr1[02-9ac-hj-np-z]+)#([A-Za-z0-9_-]+)/);
  if (!m) return null;
  try {
    let d = nip19.decode(m[1]);
    if (d.type !== "naddr" || d.data.kind !== 33301) return null;
    let frag = decodeInviteFragment(m[2]);
    if (!frag) return null;
    return { signerPk: d.data.pubkey, naddr: m[1], fragment: m[2], ...frag };
  } catch {
    return null;
  }
};

export const makeInviteLink = (base, signerPk, relays, token) =>
  `${base}/invite/${nip19.naddrEncode({ kind: 33301, pubkey: signerPk, identifier: "" })}#${encodeInviteFragment(relays, token)}`;

// The kind 33301 addressable bundle event, signed by the per-link keypair.
export const makeInviteBundleEvent = (linkSk, bundle, token) =>
  finalizeEvent(
    {
      kind: 33301,
      content: nip44.encrypt(JSON.stringify(bundle), inviteKey(token)),
      tags: [["d", ""], ["vsk", "6"]],
      created_at: Math.floor(Date.now() / 1000),
    },
    linkSk
  );

// Decrypt + validate a fetched bundle. Returns the bundle, { revoked: true },
// or null. The community_id self-certifies the owner (CORD-05 §1), and bounds
// apply before anything allocates.
export const openInviteBundle = (evt, token) => {
  if (evt.tags?.some((t) => t[0] === "vsk" && t[1] === "9")) return { revoked: true };
  try {
    let b = JSON.parse(nip44.decrypt(evt.content, inviteKey(token)));
    if (communityId(b.owner, b.owner_salt) !== b.community_id) return null;
    if (!/^[0-9a-f]{64}$/.test(b.community_root)) return null;
    if (!Array.isArray(b.channels) || b.channels.length > 256) return null;
    b.relays = (b.relays || []).slice(0, 5);
    if (b.expires_at && Date.now() > b.expires_at) return { expired: true, name: b.name };
    return b;
  } catch {
    return null;
  }
};

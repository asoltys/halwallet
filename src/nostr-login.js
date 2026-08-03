// Log in with Nostr.
//
// Three ways to prove control of a nostr identity, in descending order of how
// much the browser gets to see:
//
//   extension  NIP-07 (Alby, nos2x, …) — the key stays in the extension
//   bunker     NIP-46 remote signer (Amber, Amethyst, nsec.app) — the key
//              stays on the signing device
//   key        a pasted nsec / hex private key — held in memory for this
//              session only, NEVER written to storage
//
// HOW A NOSTR ACCOUNT GETS A WALLET
// Two mechanisms, because the two situations are genuinely different:
//
// 1. We hold the private key (pasted nsec). The wallet seed is DERIVED from
//    it: entropy = sha256("coinos:wallet-seed:v1" | privkey). Deterministic,
//    so the same nostr key always opens the same wallet, on any device,
//    with nothing stored anywhere by anyone.
//
// 2. We only have a signer (extension/bunker). Deriving is impossible — we
//    never see the key, and neither signatures (random aux) nor NIP-44
//    ciphertexts (random nonce) are reproducible. So instead the wallet seed
//    is ASSOCIATED: a random seed is generated once and published as a
//    replaceable event encrypted to the user's own nostr key, which only
//    their signer can decrypt. Logging in later anywhere finds and decrypts
//    it, opening the same wallet.
//
// THE TRADEOFF, PLAINLY: mechanism 2 means whoever controls the nostr key can
// recover the wallet seed from public relays. That is a real escalation —
// a nostr key is usually treated as an identity, not as money. It is the
// price of "log in on a new device and your wallet is there" without the key
// itself ever reaching us. Mechanism 1 has no such exposure. The UI says so
// before publishing anything.

import { hex, bech32 } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';
import { entropyToMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { getPublicKey, finalizeEvent, nip44 } from './nostr.js';
import { SimplePool } from 'nostr-tools/pool';
import { BunkerSigner, parseBunkerInput, createNostrConnectURI } from 'nostr-tools/nip46';
import { generateSecretKey } from 'nostr-tools/pure';

const SEED_DTAG = 'coinos:wallet:v1';
const BACKUP_KIND = 30078;
const DERIVE_TAG = 'coinos:wallet-seed:v1';

export const BACKUP_RELAYS = [
  'wss://relay.coinos.io', 'wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net',
];

// nsec1… or 64-hex → 32-byte secret key, else null.
export function parseNostrSecret(input) {
  const s = String(input || '').trim();
  if (/^[0-9a-f]{64}$/i.test(s)) return hex.decode(s.toLowerCase());
  try {
    const { prefix, words } = bech32.decode(s, 1000);
    if (prefix !== 'nsec') return null;
    const b = bech32.fromWords(words);
    return b.length === 32 ? Uint8Array.from(b) : null;
  } catch { return null; }
}

// Mechanism 1: the same nostr key always yields the same wallet.
export function seedFromNostrKey(sk) {
  const tag = new TextEncoder().encode(DERIVE_TAG);
  const buf = new Uint8Array(tag.length + sk.length);
  buf.set(tag, 0);
  buf.set(sk, tag.length);
  return entropyToMnemonic(sha256(buf).slice(0, 16), wordlist); // 12 words
}

// ---- signers -------------------------------------------------------------
// Every signer exposes: pubkey, signEvent, encryptSelf, decryptSelf, label.

export async function extensionSigner() {
  const nostr = typeof window !== 'undefined' && window.nostr;
  if (!nostr) throw new Error('no nostr extension found in this browser');
  const pubkey = await nostr.getPublicKey();
  const canNip44 = !!(nostr.nip44 && nostr.nip44.encrypt && nostr.nip44.decrypt);
  if (!canNip44) throw new Error('this extension cannot encrypt (NIP-44 support required)');
  return {
    kind: 'extension', pubkey, label: 'browser extension',
    signEvent: (e) => nostr.signEvent(e),
    encryptSelf: (txt) => nostr.nip44.encrypt(pubkey, txt),
    decryptSelf: (ct) => nostr.nip44.decrypt(pubkey, ct),
    // peer variants: NIP-17 DMs seal to the recipient, not to self
    encryptTo: (peer, txt) => nostr.nip44.encrypt(peer, txt),
    decryptFrom: (peer, ct) => nostr.nip44.decrypt(peer, ct),
  };
}

export async function bunkerSigner(uri, { onAuth } = {}) {
  const bp = await parseBunkerInput(String(uri || '').trim());
  if (!bp) throw new Error('not a bunker:// address');
  if (!bp.relays || !bp.relays.length) throw new Error('that bunker address lists no relays');
  const local = generateSecretKey();
  // NB the pointer goes through fromBunker — the constructor takes params
  // only, and passing the pointer there leaves the signer without one.
  const signer = BunkerSigner.fromBunker(local, bp, {
    onauth: (url) => { if (onAuth) onAuth(url); else if (typeof window !== 'undefined') window.open(url, '_blank'); },
  });
  await signer.connect();
  const pubkey = await signer.getPublicKey();
  return bunkerAdapter(signer, pubkey);
}

function bunkerAdapter(signer, pubkey) {
  return {
    kind: 'bunker', pubkey, label: 'remote signer',
    signEvent: (e) => signer.signEvent(e),
    encryptSelf: (txt) => signer.nip44Encrypt(pubkey, txt),
    decryptSelf: (ct) => signer.nip44Decrypt(pubkey, ct),
    encryptTo: (peer, txt) => signer.nip44Encrypt(peer, txt),
    decryptFrom: (peer, ct) => signer.nip44Decrypt(peer, ct),
    close: () => { try { signer.close(); } catch {} },
  };
}

// Client-initiated NIP-46: WE mint a nostrconnect:// URI; a signer app
// (Amber, nsec.app, …) opens or scans it and connects back to us over the
// relay — no bunker URL to copy. Returns the URI (render it as a deep link
// and a QR), a promise that resolves to a signer adapter when the app
// answers, and a cancel.
export function nostrConnect({ relays = ['wss://relay.coinos.io', 'wss://nos.lol'], timeoutMs = 180_000 } = {}) {
  const local = generateSecretKey();
  const secret = hex.encode(crypto.getRandomValues(new Uint8Array(16)));
  const uri = createNostrConnectURI({
    clientPubkey: getPublicKey(local),
    relays,
    secret,
    name: 'coinos',
    url: 'https://v3.coinos.io',
    perms: ['get_public_key', 'sign_event', 'nip44_encrypt', 'nip44_decrypt'],
  }) + '&callbackUrl=' + encodeURIComponent('https://v3.coinos.io/');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error('signer connect timed out')), timeoutMs);
  const ready = (async () => {
    const signer = await BunkerSigner.fromURI(local, uri, {}, controller.signal);
    const pubkey = await signer.getPublicKey();
    return bunkerAdapter(signer, pubkey);
  })();
  ready.finally(() => clearTimeout(timer)).catch(() => {});
  return { uri, ready, cancel: (reason) => controller.abort(reason || new Error('cancelled')) };
}

// A pasted key: signing happens locally, and the key is never persisted.
export function keySigner(sk) {
  const pubkey = getPublicKey(sk);
  const conv = nip44.getConversationKey(sk, pubkey);
  return {
    kind: 'key', pubkey, label: 'private key', secret: sk,
    signEvent: async (e) => finalizeEvent(e, sk),
    encryptSelf: async (txt) => nip44.encrypt(txt, conv),
    decryptSelf: async (ct) => nip44.decrypt(ct, conv),
    encryptTo: async (peer, txt) => nip44.encrypt(txt, nip44.getConversationKey(sk, peer)),
    decryptFrom: async (peer, ct) => nip44.decrypt(ct, nip44.getConversationKey(sk, peer)),
  };
}

// ---- the encrypted wallet association (mechanism 2) ----------------------

// Look for a wallet this nostr account already published. Returns the
// mnemonic, or null when the account has no wallet yet.
export async function fetchWalletBackup(signer, relays = BACKUP_RELAYS) {
  const pool = new SimplePool();
  try {
    const evs = await pool.querySync(relays,
      { kinds: [BACKUP_KIND], authors: [signer.pubkey], '#d': [SEED_DTAG] }, { maxWait: 6000 });
    const newest = evs.sort((a, b) => b.created_at - a.created_at)[0];
    if (!newest) return null;
    const body = JSON.parse(await signer.decryptSelf(newest.content));
    return body && body.mnemonic ? body : null;
  } catch { return null; } finally { try { pool.close(relays); } catch {} }
}

// Publish (or replace) the encrypted wallet association for this account.
export async function publishWalletBackup(signer, { mnemonic, passphrase }, relays = BACKUP_RELAYS) {
  const content = await signer.encryptSelf(JSON.stringify({ mnemonic, passphrase: passphrase || '' }));
  const evt = await signer.signEvent({
    kind: BACKUP_KIND, created_at: Math.floor(Date.now() / 1000),
    tags: [['d', SEED_DTAG]], content,
  });
  const pool = new SimplePool();
  try {
    const res = await Promise.allSettled(pool.publish(relays, evt));
    if (!res.some((r) => r.status === 'fulfilled')) throw new Error('no relay accepted the backup');
  } finally { try { pool.close(relays); } catch {} }
  return true;
}

// The whole login: given a signer, produce the wallet mnemonic to open.
// `mode` reports what happened so the UI can be honest about it.
//
// ONE flow for all three signer kinds, because an identity must open the
// SAME wallet however you log into it: look for the published association
// FIRST (that's where the money already is), and only then fall back to
// deriving (key in hand) or generating (signer only).
export async function walletForSigner(signer) {
  const found = await fetchWalletBackup(signer);
  if (found) return { mnemonic: found.mnemonic, passphrase: found.passphrase, mode: 'restored' };
  if (signer.secret) {
    // Publishing the derived seed costs nothing: the derivation is public,
    // so anyone holding this key could compute it anyway. It buys the thing
    // that matters — an extension login later finds this same wallet.
    return { mnemonic: seedFromNostrKey(signer.secret), mode: 'derived', publish: true };
  }
  return { mnemonic: null, mode: 'new' }; // caller decides + confirms publishing
}

// NIP-98 HTTP Auth (kind 27235): the standard way to authenticate an HTTP
// request with a nostr key. `u` and `method` bind the signature to this exact
// request and `payload` to its body, so a captured header can't be replayed
// against a different endpoint or a tampered body.
export async function nip98Header(signer, url, method, bodyText) {
  const tags = [['u', url], ['method', method.toUpperCase()]];
  if (bodyText) tags.push(['payload', hex.encode(sha256(new TextEncoder().encode(bodyText)))]);
  const evt = await signer.signEvent({
    kind: 27235, created_at: Math.floor(Date.now() / 1000), tags, content: '',
  });
  return 'Nostr ' + btoa(JSON.stringify(evt));
}

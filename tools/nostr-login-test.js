// Nostr login: key parsing, deterministic seed derivation, and the encrypted
// wallet association round-trip through a signer.
// Run: bun tools/nostr-login-test.js
import { hex, bech32 } from '@scure/base';
import { validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import {
  parseNostrSecret, seedFromNostrKey, keySigner, walletForSigner,
} from '../src/nostr-login.js';

let fails = 0;
const check = (name, ok, detail = '') => {
  console.log(` ${ok ? '✓' : '✗'} ${name}${detail ? ' — ' + String(detail).slice(0, 100) : ''}`);
  if (!ok) fails++;
};

console.log('[key parsing]');
const sk = generateSecretKey();
const nsec = bech32.encode('nsec', bech32.toWords(sk), 1000);
check('parses an nsec', parseNostrSecret(nsec) && hex.encode(parseNostrSecret(nsec)) === hex.encode(sk));
check('parses hex', hex.encode(parseNostrSecret(hex.encode(sk))) === hex.encode(sk));
check('rejects an npub', parseNostrSecret(bech32.encode('npub', bech32.toWords(sk), 1000)) === null);
check('rejects junk', parseNostrSecret('hello world') === null);

console.log('\n[seed derivation]');
const m1 = seedFromNostrKey(sk);
const m2 = seedFromNostrKey(sk);
check('is a valid 12-word mnemonic', validateMnemonic(m1, wordlist) && m1.split(' ').length === 12, m1.split(' ').slice(0, 3).join(' ') + '…');
check('is deterministic', m1 === m2);
const other = seedFromNostrKey(generateSecretKey());
check('differs per nostr key', other !== m1);
check('does not leak the key', !m1.includes(hex.encode(sk).slice(0, 8)));

console.log('\n[login modes]');
const signer = keySigner(sk);
check('key signer exposes the right pubkey', signer.pubkey === getPublicKey(sk));
const res = await walletForSigner(signer);
check('a pasted key derives (no lookup)', res.mode === 'derived' && res.mnemonic === m1);

console.log('\n[encrypted association]');
// a signer that can't hand over its key — like an extension or bunker
const remote = { ...keySigner(sk), secret: undefined };
const stored = [];
const backupSigner = {
  ...remote,
  encryptSelf: remote.encryptSelf, decryptSelf: remote.decryptSelf,
};
const ct = await backupSigner.encryptSelf(JSON.stringify({ mnemonic: m1, passphrase: '' }));
stored.push(ct);
const back = JSON.parse(await backupSigner.decryptSelf(stored[0]));
check('seed survives encrypt→decrypt to self', back.mnemonic === m1);
check('ciphertext hides the mnemonic', !ct.includes(m1.split(' ')[0]));
const stranger = keySigner(generateSecretKey());
let denied = false;
try { await stranger.decryptSelf(ct); } catch { denied = true; }
check('another account cannot decrypt it', denied);

console.log('\n[NIP-98 auth]');
{
  const { nip98Header } = await import('../src/nostr-login.js');
  const { verifyEvent } = await import('nostr-tools/pure');
  const { sha256: sha } = await import('@noble/hashes/sha256');
  const body = JSON.stringify({ name: 'x' });
  const hdr = await nip98Header(keySigner(sk), 'https://names.coinos.io/register', 'POST', body);
  check('header uses the Nostr scheme', hdr.startsWith('Nostr '));
  const evt = JSON.parse(Buffer.from(hdr.slice(6), 'base64').toString('utf8'));
  check('is kind 27235', evt.kind === 27235);
  check('signature verifies', verifyEvent(evt));
  const tag = (k) => (evt.tags.find((x) => x[0] === k) || [])[1];
  check('binds the url', tag('u') === 'https://names.coinos.io/register');
  check('binds the method', tag('method') === 'POST');
  check('binds the body hash', tag('payload') === hex.encode(sha(new TextEncoder().encode(body))));
}

console.log(fails ? `\n❌ ${fails} failure(s)` : '\n✅ nostr login behaves');
process.exit(fails ? 1 : 0);

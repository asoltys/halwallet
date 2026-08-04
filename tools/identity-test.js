// Who the chat speaks as. If you logged in with a nostr account, everything
// this app signs must be signed by THAT account — the alternative is what
// people actually saw: their own avatar in the header, and their messages
// arriving under the wallet key's pubkey, looking like a stranger.
// Run: bun tools/identity-test.js
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { messagesFeature } from '../src/features/messages.js';

let fails = 0;
const check = (name, ok, detail = '') => {
  console.log(` ${ok ? '✓' : '✗'} ${name}${detail ? ' — ' + String(detail).slice(0, 120) : ''}`);
  if (!ok) fails++;
};

globalThis.localStorage = {
  _d: {}, getItem(k) { return this._d[k] ?? null; }, setItem(k, v) { this._d[k] = String(v); },
  removeItem(k) { delete this._d[k]; }, key(i) { return Object.keys(this._d)[i] ?? null; },
  get length() { return Object.keys(this._d).length; },
};
globalThis.fetch = async () => { throw new Error('offline'); };

const walletSk = generateSecretKey();
const walletPk = getPublicKey(walletSk);
const loginSk = generateSecretKey();
const loginPk = getPublicKey(loginSk);

// Build the feature with a given login situation and see which key it would
// sign a profile with — publishProfile is the shortest path through identity().
function build({ login, resume }) {
  const store = {};
  const signed = [];
  const wallet = {
    mnemonic: 'x '.repeat(11) + 'y', utxos: [], txs: [],
    nostr: { sk: walletSk, pk: walletPk, ck: new Uint8Array(32) },
    loadFeatureState: (n, fb) => JSON.parse(store[n] || 'null') || fb,
    saveFeatureState: (n, s) => { store[n] = JSON.stringify(s); },
    _cacheKey: () => 'identity-test', saveCache: () => {},
    registerCacheExtension: () => {}, registerLoadHook: () => {},
  };
  const feature = messagesFeature({
    h: (tag, attrs, ...kids) => ({ tag, attrs, kids }),
    ui: {}, render: () => {}, wallet, toast: () => {}, brandHeader: () => null,
    hook: (name) => {
      if (name === 'nostrLoginIdentity') return login;
      if (name === 'nostrLoginResume') return resume;
      return null;
    },
  });
  return { feature, signed };
}

console.log('[logged in with nostr, signer live]');
{
  const signer = { pubkey: loginPk, signEvent: async (e) => ({ ...e, pubkey: loginPk, id: 'x', sig: 'y' }) };
  const { feature } = build({ login: { pubkey: loginPk, signer }, resume: null });
  let signedBy = null;
  try { await feature.publishProfile({ name: 'me' }); } catch (e) { signedBy = e.message; }
  // it fails at the relay (offline), but only AFTER choosing an identity —
  // what matters is that it never refused for want of one
  check('does not refuse for want of an identity', !/signer isn't connected/i.test(signedBy || ''), signedBy || 'reached the relay');
}

console.log('\n[logged in with nostr, signer lost to a reload]');
{
  const { feature } = build({ login: { pubkey: loginPk, signer: null }, resume: null });
  let err = null;
  try { await feature.publishProfile({ name: 'me' }); } catch (e) { err = e.message; }
  check('refuses rather than signing as someone else', /signer isn't connected/i.test(err || ''), err || 'no error!');
}

console.log('\n[logged in with nostr, signer resumes]');
{
  const signer = { pubkey: loginPk, signEvent: async (e) => ({ ...e, pubkey: loginPk, id: 'x', sig: 'y' }) };
  const { feature } = build({ login: { pubkey: loginPk, signer: null }, resume: Promise.resolve(signer) });
  let err = null;
  try { await feature.publishProfile({ name: 'me' }); } catch (e) { err = e.message; }
  check('a resumed signer is accepted', !/signer isn't connected/i.test(err || ''), err || 'reached the relay');
}

console.log('\n[no nostr login at all]');
{
  const { feature } = build({ login: null, resume: null });
  let err = null;
  try { await feature.publishProfile({ name: 'me' }); } catch (e) { err = e.message; }
  check('the wallet key still speaks for a plain seed wallet', !/signer isn't connected/i.test(err || ''), err || 'reached the relay');
}

console.log(fails ? `\n${fails} failing` : '\nall passing');
process.exit(fails ? 1 : 0);

// Gift records must not follow you from one wallet into the next.
//
// The records live under a seed-derived localStorage key, so on disk they were
// always separate. The leak was in memory: giftRecords() caches the parsed blob
// on the wallet object, the app runs a single Wallet for its whole lifetime,
// and load() never dropped that cache. Switch wallets and the old wallet's
// gifts were still sitting there — every one of them rendering as "claimed",
// since none of their outpoints are live in the new wallet.
import { Wallet } from '../src/wallet.js';
import { installGiftWallet } from '../src/features/gifts-wallet.js';

const store = new Map();
globalThis.localStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
};

const A = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const B = 'legal winner thank year wave sausage worth useful legal winner thank yellow';

const wallet = new Wallet();
installGiftWallet(wallet);

let failures = 0;
const check = (name, ok, detail) => {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${ok || !detail ? '' : ` — ${detail}`}`);
  if (!ok) failures++;
};

// Wallet A creates a gift and its record is cached in memory.
wallet.load({ mnemonic: A });
wallet.giftRecords()['g1'] = {
  id: 'g1', amount: 2100, created: Date.now() - 28 * 864e5, outpoints: ['deadbeef:0'],
};
wallet._saveGiftRecords();
check('wallet A sees its own gift', Object.keys(wallet.giftRecords()).length === 1);

// Switch to a brand new wallet B.
wallet.load({ mnemonic: B });
const leaked = Object.keys(wallet.giftRecords());
check('wallet B starts with no gift records', leaked.length === 0, `saw ${JSON.stringify(leaked)}`);

// And B must not write A's records under its own key.
wallet.giftRecords()['g2'] = { id: 'g2', amount: 500, created: Date.now(), outpoints: ['cafe:1'] };
wallet._saveGiftRecords();
wallet.load({ mnemonic: A });
const backInA = Object.keys(wallet.giftRecords());
check('wallet A is untouched by B', backInA.length === 1 && backInA[0] === 'g1', `saw ${JSON.stringify(backInA)}`);

wallet.load({ mnemonic: B });
const backInB = Object.keys(wallet.giftRecords());
check('wallet B kept only its own', backInB.length === 1 && backInB[0] === 'g2', `saw ${JSON.stringify(backInB)}`);

// Records an older build already wrote under the wrong key are forgotten on
// sight: their funding tx isn't in this wallet's history.
wallet.load({ mnemonic: B });
store.set(wallet._giftRecordsKey(), JSON.stringify({
  'aa:0': { id: 'aa:0', amount: 2100, created: Date.now() - 28 * 864e5, outpoints: ['aa:0'] },
  'bb:0': { id: 'bb:0', amount: 2100, created: Date.now() - 28 * 864e5, outpoints: ['bb:0'] },
}));
wallet.loaded = true;
wallet.txs = [];
check('foreign records are dropped from history', wallet.claimedGifts().length === 0);
check('and purged from storage', JSON.parse(store.get(wallet._giftRecordsKey())) &&
  !Object.keys(JSON.parse(store.get(wallet._giftRecordsKey()))).length);

// But a gift this wallet really did issue still shows.
wallet.load({ mnemonic: B });
store.set(wallet._giftRecordsKey(), JSON.stringify({
  'cc:0': { id: 'cc:0', amount: 2100, created: Date.now() - 864e5, outpoints: ['cc:0'] },
}));
wallet.loaded = true;
wallet.txs = [{ txid: 'cc' }];
wallet.utxos = [];
check('our own claimed gift survives', wallet.claimedGifts().length === 1);

console.log(failures ? `\n${failures} failing` : '\nall passing');
process.exit(failures ? 1 : 0);

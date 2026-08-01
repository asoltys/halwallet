// Pouch: key isolation + IndexedDB round trip (fake-indexeddb not available,
// so exercise the pure logic and assert the key branch is separate).
import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync, generateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { hex } from '@scure/base';
import { pouchKey, buildPouch, pouchBalance, POUCH_CHAIN } from '/home/adam/halwallet/src/nwc-pouch.js';
import { secp256k1 } from '@noble/curves/secp256k1';

let ok = true; const check=(n,c,d='')=>{console.log(` ${c?'✓':'✗'} ${n}${d?' — '+d:''}`); if(!c) ok=false;};
const account = HDKey.fromMasterSeed(mnemonicToSeedSync(generateMnemonic(wordlist))).derive("m/86'/0'/9'");

// the pouch branch must never collide with the branches that hold real coins
const arkKey = (i) => account.deriveChild(3).deriveChild(i).privateKey;
const mailbox = account.deriveChild(4).deriveChild(0).privateKey;
const preimg  = account.deriveChild(5).deriveChild(0).privateKey;
check('pouch chain is 6', POUCH_CHAIN === 6);
const p0 = pouchKey(account, 0).privkey;
check('pouch key != ark vtxo key', hex.encode(p0) !== hex.encode(arkKey(0)));
check('pouch key != mailbox key', hex.encode(p0) !== hex.encode(mailbox));
check('pouch key != ln preimage key', hex.encode(p0) !== hex.encode(preimg));
check('pouch indices differ', hex.encode(pouchKey(account,0).privkey) !== hex.encode(pouchKey(account,1).privkey));

// buildPouch must export exactly the keys for the vtxos it carries — and no seed
const vtxos = [
  { id: 'a:0', bytes: 'deadbeef', keyIndex: 0, amountSat: 5000, expiryHeight: 100 },
  { id: 'b:0', bytes: 'cafebabe', keyIndex: 1, amountSat: 2000, expiryHeight: 100 },
];
const pouch = buildPouch({
  arkUrl: 'https://ark.coinos.io', esploraUrl: 'https://mempool.space/api',
  network: 'mainnet', serverPubkey: '03ff', vtxos, account,
  connections: [{ id:'c1', servicePk:'aa', serviceSk:'bb', clientPk:'cc', maxSat:1000, dailySat:5000 }],
});
check('pouch carries both vtxos', pouch.vtxos.length === 2);
check('pouch balance sums', pouchBalance(pouch) === 7000, String(pouchBalance(pouch)));
check('one key per vtxo index', Object.keys(pouch.keys).sort().join() === '0,1');
const blob = JSON.stringify(pouch);
check('NO seed/mnemonic in the pouch', !/mnemonic|seed|xprv/i.test(blob));
// the exported keys must actually correspond to the pouch pubkeys
const derived = secp256k1.getPublicKey(hex.decode(pouch.keys['0']), true);
check('exported key matches its pouch pubkey', hex.encode(derived) === hex.encode(pouchKey(account,0).pubkey));
// and must NOT be able to sign for an ordinary ark vtxo
check('pouch key cannot control chain-3 coins',
  hex.encode(secp256k1.getPublicKey(hex.decode(pouch.keys['0']), true))
  !== hex.encode(secp256k1.getPublicKey(arkKey(0), true)));
check('connection service keys travel with it', pouch.connections[0].serviceSk === 'bb');

console.log(ok ? '\n✅ pouch isolates correctly' : '\n❌ failed'); process.exit(ok?0:1);

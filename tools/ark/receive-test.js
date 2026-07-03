// Regtest end-to-end test for the native-JS Ark receive path.
//
// 1. Derive vtxo + mailbox keys from a mnemonic (hal-style @scure stack)
// 2. Encode an ark address with a blinded mailbox delivery
// 3. Pay it from the bark CLI wallet (alice)
// 4. Read the mailbox over gRPC-web, decode the VTXO, validate it
//
// Usage: bun tools/ark/receive-test.js  (from the halwallet repo root)

import { execSync } from 'node:child_process';
import { mnemonicToSeedSync } from '@scure/bip39';
import { HDKey } from '@scure/bip32';
import { hex } from '@scure/base';
import { secp256k1 } from '@noble/curves/secp256k1';

import {
  getArkInfo, handshake, encodeAddress, decodeAddress,
  blindMailboxId, readMailbox,
} from '../../src/ark/proto.js';

const ARK = process.env.ARK_URL || 'http://127.0.0.1:3535';
const ESPLORA = process.env.ESPLORA_URL || 'http://127.0.0.1:30002';
const BARK = `${process.env.HOME}/bark/target/debug/bark`;
const ALICE = `${BARK} --datadir ${process.env.HOME}/ark-regtest/alice -q`;
const AMOUNT_SAT = 12345;

const MNEMONIC = 'rug rebuild abstract kiwi rifle vast food robust rifle spirit dilemma stumble';

// --- keys: our own derivation scheme (the ASP doesn't care) ---
const seed = mnemonicToSeedSync(MNEMONIC);
const master = HDKey.fromMasterSeed(seed);
const vtxoKey = master.derive("m/350'/0'/0'");
const mailboxKey = master.derive("m/350'/1'/0'");
const keys = {
  vtxo: { privkey: vtxoKey.privateKey, pubkey: secp256k1.getPublicKey(vtxoKey.privateKey, true) },
  mailbox: { privkey: mailboxKey.privateKey, pubkey: secp256k1.getPublicKey(mailboxKey.privateKey, true) },
};

// --- 1. ark info + handshake ---
const info = await getArkInfo(ARK);
console.log('ark info:', info);
const hs = await handshake(ARK);
console.log('handshake:', hs);

// --- 2. build our address ---
// NB the blinding DH partner is the *mailbox service* pubkey from ArkInfo,
// not the server identity pubkey.
const blindedId = blindMailboxId(keys.mailbox.pubkey, hex.decode(info.mailboxPubkey), keys.vtxo.privkey);
const address = encodeAddress({
  testnet: info.network !== 'bitcoin',
  serverPubkey: hex.decode(info.serverPubkey),
  userPubkey: keys.vtxo.pubkey,
  blindedMailboxId: blindedId,
});
console.log('\nour ark address:', address);
console.log('round-trip decode:', decodeAddress(address));

// --- 3. pay it from the bark CLI ---
console.log(`\npaying ${AMOUNT_SAT} sat from alice (bark CLI)...`);
execSync(`${ALICE} send ${address} "${AMOUNT_SAT} sat"`, { stdio: 'inherit' });

// --- 4. read mailbox, decode, validate ---
let received = null;
for (let attempt = 0; attempt < 15 && !received; attempt++) {
  const { messages } = await readMailbox(ARK, keys.mailbox);
  for (const m of messages) {
    if (m.kind === 'arkoor' && m.vtxos.length) received = m;
  }
  if (!received) await new Promise((res) => setTimeout(res, 2000));
}
if (!received) {
  console.error('❌ no arkoor message in mailbox after 30s');
  process.exit(1);
}

console.log(`\nmailbox message (checkpoint ${received.checkpoint}), ${received.vtxos.length} vtxo(s):`);
const ourPub = hex.encode(keys.vtxo.pubkey);
let ok = true;
const check = (name, cond, detail = '') => {
  console.log(` ${cond ? '✓' : '✗'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!cond) ok = false;
};

for (const v of received.vtxos) {
  console.log(`\nvtxo ${v.id}`);
  console.log(`  amount: ${v.amountSat} sat, expiry height: ${v.expiryHeight}, exit delta: ${v.exitDelta}`);
  console.log(`  anchor: ${v.anchorPoint.txid}:${v.anchorPoint.vout}, genesis depth: ${v.genesis.length}`);
  console.log(`  transitions: ${v.genesis.map((g) => g.transition.type).join(' -> ')}`);

  check('policy is pubkey', v.policy.type === 'pubkey', v.policy.type);
  check('paid to our key', v.policy.userPubkey === ourPub, v.policy.userPubkey);
  check('amount matches', v.amountSat === AMOUNT_SAT, String(v.amountSat));
  check('server pubkey matches ark info', v.serverPubkey === info.serverPubkey);
  check('all genesis transitions signed', v.genesis.every((g) => g.transition.signature));

  const st = await fetch(`${ESPLORA}/tx/${v.anchorPoint.txid}/status`).then((r) => r.json());
  check('chain anchor tx confirmed onchain', st.confirmed === true, `esplora height ${st.block_height}`);

  const tip = await fetch(`${ESPLORA}/blocks/tip/height`).then((r) => r.text());
  check('not expired', v.expiryHeight > Number(tip), `expires ${v.expiryHeight}, tip ${tip}`);
}

console.log(ok
  ? `\n✅ SUCCESS: native-JS client received + decoded + validated an off-chain Ark payment (balance: ${received.vtxos.reduce((n, v) => n + v.amountSat, 0)} sat)`
  : '\n❌ some checks failed');
process.exit(ok ? 0 : 1);

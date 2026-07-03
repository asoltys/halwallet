// Regtest end-to-end test for the native-JS arkoor SEND path (MuSig2 cosign).
//
// Spends the VTXO received in receive-test.js: pays alice (bark CLI) 4000 sat
// with change back to a fresh key of ours, entirely from JS.
//
// Usage: bun tools/ark/send-test.js  (run receive-test.js first to get funded)

import { execSync } from 'node:child_process';
import { mnemonicToSeedSync } from '@scure/bip39';
import { HDKey } from '@scure/bip32';
import { hex } from '@scure/base';
import { secp256k1 } from '@noble/curves/secp256k1';

import { getArkInfo, decodeAddress, readMailbox, decodeVtxo } from '../../src/ark/proto.js';
import {
  buildArkoorSend, cosignWithServer, buildSignedVtxoBytes,
  registerVtxoTransactions, postArkoorMessage,
} from '../../src/ark/send.js';

const ARK = process.env.ARK_URL || 'http://127.0.0.1:3535';
const BARK = `${process.env.HOME}/bark/target/debug/bark`;
const ALICE = `${BARK} --datadir ${process.env.HOME}/ark-regtest/alice`;
const SEND_SAT = 4000;

const MNEMONIC = 'rug rebuild abstract kiwi rifle vast food robust rifle spirit dilemma stumble';
const seed = mnemonicToSeedSync(MNEMONIC);
const master = HDKey.fromMasterSeed(seed);
const kp = (path) => {
  const k = master.derive(path);
  return { privkey: k.privateKey, pubkey: secp256k1.getPublicKey(k.privateKey, true) };
};
const keys = { vtxo: kp("m/350'/0'/0'"), mailbox: kp("m/350'/1'/0'"), change: kp("m/350'/0'/1'") };

const info = await getArkInfo(ARK);
const serverPubkey = hex.decode(info.serverPubkey);

// --- find our latest vtxo from the mailbox ---
const { messages } = await readMailbox(ARK, keys.mailbox);
const vtxos = messages.filter((m) => m.kind === 'arkoor').flatMap((m) => m.vtxos)
  .filter((v) => v.policy.userPubkey === hex.encode(keys.vtxo.pubkey));
if (!vtxos.length) { console.error('no vtxos in mailbox — run receive-test.js first'); process.exit(1); }
const input = vtxos[vtxos.length - 1];
console.log(`input vtxo: ${input.id} (${input.amountSat} sat, genesis depth ${input.genesis.length})`);

// --- alice's address -> destination pubkey + her blinded mailbox id ---
const aliceAddr = execSync(`${ALICE} -q address`).toString().trim();
const alice = decodeAddress(aliceAddr);
console.log(`alice pubkey: ${alice.userPubkey}`);
const aliceBlindedId = hex.decode(alice.delivery.find((d) => d.type === 1).data);

const outputs = [
  { amountSat: SEND_SAT, userPubkey: hex.decode(alice.userPubkey) },
  { amountSat: input.amountSat - SEND_SAT, userPubkey: keys.change.pubkey },
];

const aliceBalanceBefore = JSON.parse(execSync(`${ALICE} -q balance`).toString()).spendable_sat;

// --- 1. pre-register our input chain ---
await registerVtxoTransactions(ARK, [input._raw.bytes]);
console.log('input chain registered with server');

// --- 2. build txs + sighashes ---
const build = buildArkoorSend({ input, outputs, serverPubkey, vtxoKeys: keys.vtxo });
console.log(`checkpoint txid: ${hex.encode(build.checkpointTxid.slice().reverse())}`);
console.log(`sighashes: ${build.sighashes.length} (1 checkpoint + ${outputs.length} arkoor)`);

// --- 3. MuSig2 cosign ceremony with the ASP ---
const finalSigs = await cosignWithServer(ARK, build, { input, outputs, vtxoKeys: keys.vtxo, serverPubkey });
console.log(`✓ ${finalSigs.length} MuSig2 signatures combined and verified against taproot output keys`);

// --- 4. assemble signed vtxos, round-trip check, register, deliver ---
const destBytes = buildSignedVtxoBytes({ input, outputs, build, finalSigs, serverPubkey, idx: 0 });
const changeBytes = buildSignedVtxoBytes({ input, outputs, build, finalSigs, serverPubkey, idx: 1 });
const dest = decodeVtxo(destBytes); // local round-trip sanity check
console.log(`destination vtxo: ${dest.id} (${dest.amountSat} sat, depth ${dest.genesis.length})`);
const change = decodeVtxo(changeBytes);
console.log(`change vtxo:      ${change.id} (${change.amountSat} sat) -> our change key`);

await registerVtxoTransactions(ARK, [destBytes, changeBytes]);
console.log('signed vtxos registered with server');

await postArkoorMessage(ARK, aliceBlindedId, [destBytes]);
console.log('posted to alice\'s mailbox');

// --- 5. verify alice received it (balance triggers a wallet sync) ---
const aliceBalanceAfter = JSON.parse(execSync(`${ALICE} -q balance`).toString()).spendable_sat;
console.log(`\nalice balance: ${aliceBalanceBefore} -> ${aliceBalanceAfter} sat`);

if (aliceBalanceAfter === aliceBalanceBefore + SEND_SAT) {
  console.log(`\n✅ SUCCESS: native-JS wallet sent ${SEND_SAT} sat over Ark via MuSig2 cosign — bark CLI accepted the vtxo`);
} else {
  console.log('\n❌ alice balance did not increase as expected');
  process.exit(1);
}

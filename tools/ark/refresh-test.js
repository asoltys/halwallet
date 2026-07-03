// Regtest end-to-end test for the native-JS DELEGATED ROUND REFRESH (hArk),
// proven by spending the refreshed vtxo:
//
// 1. alice (bark CLI) funds us with a fresh vtxo
// 2. Submit delegated round participation; wait for the round to execute
// 3. Mine confirmations for the round funding tx
// 4. MuSig2-cosign the hash-locked leaf, forfeit the old vtxo, get the preimage
// 5. Patch + validate the refreshed vtxo, then arkoor-spend it back to alice
//
// Usage: bun tools/ark/refresh-test.js

import { execSync } from 'node:child_process';
import { mnemonicToSeedSync } from '@scure/bip39';
import { HDKey } from '@scure/bip32';
import { hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';
import { secp256k1 } from '@noble/curves/secp256k1';

import { getArkInfo, encodeAddress, blindMailboxId, readMailbox, decodeVtxo, decodeAddress } from '../../src/ark/proto.js';
import {
  buildArkoorSend, cosignWithServer, buildSignedVtxoBytes,
  registerVtxoTransactions, postArkoorMessage,
} from '../../src/ark/send.js';
import {
  submitRoundParticipation, roundParticipationStatus, parseTx,
  cosignHarkLeaf, requestForfeitNonces, forfeitBundle, forfeitVtxos,
  encodeVtxoFromDecoded,
} from '../../src/ark/refresh.js';

const ARK = process.env.ARK_URL || 'http://127.0.0.1:3535';
const BARK = `${process.env.HOME}/bark/target/debug/bark`;
const ALICE = `${BARK} --datadir ${process.env.HOME}/ark-regtest/alice`;
const BCLI = `bitcoin-cli -regtest -datadir=${process.env.HOME}/ark-regtest/bitcoind -rpcport=18543 -rpcwallet=miner`;
const FUND_SAT = 12345;
const SPEND_SAT = 3000;

const MNEMONIC = 'rug rebuild abstract kiwi rifle vast food robust rifle spirit dilemma stumble';
const master = HDKey.fromMasterSeed(mnemonicToSeedSync(MNEMONIC));
const kp = (path) => {
  const k = master.derive(path);
  return { privkey: k.privateKey, pubkey: secp256k1.getPublicKey(k.privateKey, true) };
};
const keys = { vtxo: kp("m/350'/0'/5'"), mailbox: kp("m/350'/1'/0'"), change: kp("m/350'/0'/6'") };

const info = await getArkInfo(ARK);
const serverPub = hex.decode(info.serverPubkey);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --- 1. get funded on a fresh key ---
const blinded = blindMailboxId(keys.mailbox.pubkey, hex.decode(info.mailboxPubkey), keys.vtxo.privkey);
const addr = encodeAddress({
  testnet: true, serverPubkey: serverPub, userPubkey: keys.vtxo.pubkey, blindedMailboxId: blinded,
});
execSync(`${ALICE} -q send ${addr} "${FUND_SAT} sat"`, { stdio: 'ignore' });
let input = null;
for (let i = 0; i < 10 && !input; i++) {
  const { messages } = await readMailbox(ARK, keys.mailbox);
  const mine = messages.filter((m) => m.kind === 'arkoor').flatMap((m) => m.vtxos)
    .filter((v) => v.policy.userPubkey === hex.encode(keys.vtxo.pubkey));
  input = mine[mine.length - 1] ?? null;
  if (!input) await sleep(1500);
}
if (!input) { console.error('funding vtxo never arrived'); process.exit(1); }
console.log(`input vtxo: ${input.id} (${input.amountSat} sat, expiry ${input.expiryHeight})`);

// --- 2. refresh fee + participation ---
const tipNow = Number(execSync(`${BCLI} getblockcount`).toString().trim());
const expiryBlocks = input.expiryHeight - tipNow;
const entry = info.refreshFees.ppmExpiryTable.filter((e) => e.thresholdBlocks <= expiryBlocks).pop();
const fee = info.refreshFees.baseFeeSat + Math.floor((input.amountSat * (entry?.ppm ?? 0)) / 1_000_000);
const outputs = [{ amountSat: input.amountSat - fee, userPubkey: keys.vtxo.pubkey }];
console.log(`refresh fee: ${fee} sat (ppm ${entry?.ppm}, ${expiryBlocks} blocks to expiry) -> requesting ${outputs[0].amountSat} sat`);

await registerVtxoTransactions(ARK, [input._raw.bytes]);
const unlockHash = await submitRoundParticipation(ARK, { inputs: [{ vtxo: input, keys: keys.vtxo }], outputs });
console.log(`participation submitted, unlock hash ${hex.encode(unlockHash)}`);

// --- 3. wait for the round, confirm the funding tx ---
let status;
for (let i = 0; i < 40; i++) {
  status = await roundParticipationStatus(ARK, unlockHash);
  if (status.status !== 0 && status.fundingTx) break;
  await sleep(2000);
}
if (!status?.fundingTx) { console.error('round never executed'); process.exit(1); }
const fundingTx = parseTx(status.fundingTx);
console.log(`round executed: funding tx ${fundingTx.txid}, ${status.outputVtxos.length} output vtxo(s)`);
execSync(`${BCLI} generatetoaddress 2 $(${BCLI} getnewaddress) >/dev/null`, { shell: '/bin/bash' });
await sleep(2000);

const newVtxo = decodeVtxo(status.outputVtxos[0]);
console.log(`new vtxo: ${newVtxo.id} (${newVtxo.amountSat} sat, expiry ${newVtxo.expiryHeight}, transitions: ${newVtxo.genesis.map((g) => g.transition.type).join(' -> ')})`);
if (newVtxo.amountSat !== outputs[0].amountSat) throw new Error('unexpected new vtxo amount');
if (newVtxo.policy.userPubkey !== hex.encode(keys.vtxo.pubkey)) throw new Error('new vtxo not ours');

// --- 4. leaf cosign + forfeit dance ---
const leafSig = await cosignHarkLeaf(ARK, newVtxo, fundingTx, keys.vtxo, serverPub);
console.log('✓ hash-locked leaf MuSig2 cosigned (script-spend, no tweak)');

const [serverNonce] = await requestForfeitNonces(ARK, unlockHash, [input.point.raw]);
const bundle = forfeitBundle({ input, unlockHash, vtxoKeys: keys.vtxo, serverPub, serverNonce });
const preimage = await forfeitVtxos(ARK, [bundle]);
if (hex.encode(sha256(preimage)) !== hex.encode(unlockHash)) throw new Error('preimage does not match unlock hash');
console.log(`✓ old vtxo forfeited, unlock preimage received: ${hex.encode(preimage)}`);

// --- 5. patch the vtxo with sig + preimage, then spend it to alice ---
const last = newVtxo.genesis[newVtxo.genesis.length - 1];
last.transition.signature = hex.encode(leafSig);
last.transition.unlock = { preimage: hex.encode(preimage) };
const refreshed = decodeVtxo(encodeVtxoFromDecoded(newVtxo));
console.log(`refreshed vtxo finalized: ${refreshed.id} (${refreshed.amountSat} sat)`);

const aliceAddr = execSync(`${ALICE} -q address`).toString().trim();
const alice = decodeAddress(aliceAddr);
const aliceBlinded = hex.decode(alice.delivery.find((d) => d.type === 1).data);
const balBefore = JSON.parse(execSync(`${ALICE} -q balance`).toString()).spendable_sat;

const spendOutputs = [
  { amountSat: SPEND_SAT, userPubkey: hex.decode(alice.userPubkey) },
  { amountSat: refreshed.amountSat - SPEND_SAT, userPubkey: keys.change.pubkey },
];
await registerVtxoTransactions(ARK, [refreshed._raw.bytes]);
const build = buildArkoorSend({ input: refreshed, outputs: spendOutputs, serverPubkey: serverPub, vtxoKeys: keys.vtxo });
const sigs = await cosignWithServer(ARK, build, { input: refreshed, outputs: spendOutputs, vtxoKeys: keys.vtxo, serverPubkey: serverPub });
const destBytes = buildSignedVtxoBytes({ input: refreshed, outputs: spendOutputs, build, finalSigs: sigs, serverPubkey: serverPub, idx: 0 });
const changeBytes = buildSignedVtxoBytes({ input: refreshed, outputs: spendOutputs, build, finalSigs: sigs, serverPubkey: serverPub, idx: 1 });
await registerVtxoTransactions(ARK, [destBytes, changeBytes]);
await postArkoorMessage(ARK, aliceBlinded, [destBytes]);

const balAfter = JSON.parse(execSync(`${ALICE} -q balance`).toString()).spendable_sat;
console.log(`alice balance: ${balBefore} -> ${balAfter} sat`);

if (balAfter === balBefore + SPEND_SAT) {
  console.log('\n✅ SUCCESS: native-JS delegated refresh (round + forfeit) -> refreshed vtxo spent to bark CLI');
} else {
  console.log('\n❌ alice balance did not increase as expected');
  process.exit(1);
}

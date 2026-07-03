// Regtest end-to-end test for the native-JS BOARD path, proven by spending:
//
// 1. Build the board funding taproot address from our key + the server's
// 2. Fund it onchain (miner wallet, board output forced to vout 0)
// 3. MuSig2-cosign the exit tx via RequestBoardCosign, register the vtxo
// 4. Mine a confirmation, then ARKOOR-SPEND the fresh board vtxo to alice
//
// Usage: bun tools/ark/board-test.js

import { execSync } from 'node:child_process';
import { mnemonicToSeedSync } from '@scure/bip39';
import { HDKey } from '@scure/bip32';
import { hex } from '@scure/base';
import { secp256k1 } from '@noble/curves/secp256k1';
import * as musig2 from '@scure/btc-signer/musig2';

import { getArkInfo, decodeAddress, decodeVtxo } from '../../src/ark/proto.js';
import {
  buildArkoorSend, cosignWithServer, buildSignedVtxoBytes,
  registerVtxoTransactions, postArkoorMessage, txid,
} from '../../src/ark/send.js';
import {
  boardFee, p2trAddress, buildBoard, requestBoardCosign,
  combineBoardSignature, encodeBoardVtxo, registerBoardVtxo,
} from '../../src/ark/board.js';

const ARK = process.env.ARK_URL || 'http://127.0.0.1:3535';
const ESPLORA = process.env.ESPLORA_URL || 'http://127.0.0.1:30002';
const BARK = `${process.env.HOME}/bark/target/debug/bark`;
const ALICE = `${BARK} --datadir ${process.env.HOME}/ark-regtest/alice`;
const BCLI = `bitcoin-cli -regtest -datadir=${process.env.HOME}/ark-regtest/bitcoind -rpcport=18543 -rpcwallet=miner`;
const BOARD_SAT = 30000;
const SPEND_SAT = 5000;

const MNEMONIC = 'rug rebuild abstract kiwi rifle vast food robust rifle spirit dilemma stumble';
const master = HDKey.fromMasterSeed(mnemonicToSeedSync(MNEMONIC));
const kp = (path) => {
  const k = master.derive(path);
  return { privkey: k.privateKey, pubkey: secp256k1.getPublicKey(k.privateKey, true) };
};
// fresh key for the board vtxo so this test is independent of prior spikes
const keys = { vtxo: kp("m/350'/0'/2'"), change: kp("m/350'/0'/3'") };

const info = await getArkInfo(ARK);
const serverPub = hex.decode(info.serverPubkey);
const tip = Number(await fetch(`${ESPLORA}/blocks/tip/height`).then((r) => r.text()));
const expiryHeight = tip + info.vtxoExpiryDelta;
const feeSat = boardFee(BOARD_SAT, info.boardFees);
console.log(`boarding ${BOARD_SAT} sat (fee ${feeSat}), expiry height ${expiryHeight} (tip ${tip})`);

// --- 1. funding address ---
const probe = buildBoard({
  userPub: keys.vtxo.pubkey, serverPub, amountSat: BOARD_SAT, feeSat,
  expiryHeight, exitDelta: info.vtxoExitDelta, fundingOutpointRaw: new Uint8Array(36),
});
const fundingAddr = p2trAddress(probe.fundingTaproot.outputXOnly);
console.log('funding address:', fundingAddr);

// --- 2. fund it, board output at vout 0 ---
const btc = (BOARD_SAT / 1e8).toFixed(8);
const raw = execSync(`${BCLI} createrawtransaction '[]' '[{"${fundingAddr}":${btc}}]'`).toString().trim();
const funded = JSON.parse(execSync(`${BCLI} fundrawtransaction ${raw} '{"changePosition":1}'`).toString());
const signed = JSON.parse(execSync(`${BCLI} signrawtransactionwithwallet ${funded.hex}`).toString());
const fundingTxid = execSync(`${BCLI} sendrawtransaction ${signed.hex}`).toString().trim();
console.log(`funding tx broadcast: ${fundingTxid}`);

const fundingOutpointRaw = new Uint8Array(36);
fundingOutpointRaw.set(hex.decode(fundingTxid).reverse(), 0); // vout 0

// --- 3. cosign the exit tx ---
const board = buildBoard({
  userPub: keys.vtxo.pubkey, serverPub, amountSat: BOARD_SAT, feeSat,
  expiryHeight, exitDelta: info.vtxoExitDelta, fundingOutpointRaw,
});
const nonces = musig2.nonceGen(keys.vtxo.pubkey, keys.vtxo.privkey, undefined, board.sighash);
const cosign = await requestBoardCosign(ARK, {
  amountSat: BOARD_SAT, fundingOutpointRaw, expiryHeight,
  userPub: keys.vtxo.pubkey, pubNonce: nonces.public,
});
const finalSig = combineBoardSignature({ board, serverCosign: cosign, userNonces: nonces, vtxoKeys: keys.vtxo, serverPub });
console.log('✓ board exit tx MuSig2 signature combined and verified');

const exitTxidInternal = txid(board.exitTx);
const vtxoBytes = encodeBoardVtxo({
  userPub: keys.vtxo.pubkey, serverPub, amountSat: BOARD_SAT, feeSat,
  expiryHeight, exitDelta: info.vtxoExitDelta, fundingOutpointRaw, exitTxidInternal, finalSig,
});
const vtxo = decodeVtxo(vtxoBytes); // round-trip sanity
console.log(`board vtxo: ${vtxo.id} (${vtxo.amountSat} sat)`);

// --- 4. confirm, register, prove spendability by paying alice ---
execSync(`${BCLI} generatetoaddress 2 $(${BCLI} getnewaddress) >/dev/null`, { shell: '/bin/bash' });
await new Promise((r) => setTimeout(r, 2000)); // let the server index the blocks
console.log('mined 2 blocks (board confirmed)');

await registerBoardVtxo(ARK, vtxoBytes);
console.log('board vtxo registered with server');

const aliceAddr = execSync(`${ALICE} -q address`).toString().trim();
const alice = decodeAddress(aliceAddr);
const aliceBlindedId = hex.decode(alice.delivery.find((d) => d.type === 1).data);
const balBefore = JSON.parse(execSync(`${ALICE} -q balance`).toString()).spendable_sat;

const outputs = [
  { amountSat: SPEND_SAT, userPubkey: hex.decode(alice.userPubkey) },
  { amountSat: vtxo.amountSat - SPEND_SAT, userPubkey: keys.change.pubkey },
];
await registerVtxoTransactions(ARK, [vtxoBytes]);
const build = buildArkoorSend({ input: vtxo, outputs, serverPubkey: serverPub, vtxoKeys: keys.vtxo });
const sigs = await cosignWithServer(ARK, build, { input: vtxo, outputs, vtxoKeys: keys.vtxo, serverPubkey: serverPub });
const destBytes = buildSignedVtxoBytes({ input: vtxo, outputs, build, finalSigs: sigs, serverPubkey: serverPub, idx: 0 });
const changeBytes = buildSignedVtxoBytes({ input: vtxo, outputs, build, finalSigs: sigs, serverPubkey: serverPub, idx: 1 });
await registerVtxoTransactions(ARK, [destBytes, changeBytes]);
await postArkoorMessage(ARK, aliceBlindedId, [destBytes]);
console.log(`spent board vtxo: ${SPEND_SAT} sat to alice, ${vtxo.amountSat - SPEND_SAT} sat change`);

const balAfter = JSON.parse(execSync(`${ALICE} -q balance`).toString()).spendable_sat;
console.log(`alice balance: ${balBefore} -> ${balAfter} sat`);

if (balAfter === balBefore + SPEND_SAT) {
  console.log('\n✅ SUCCESS: native-JS board -> confirmed onchain -> arkoor-spent to bark CLI');
} else {
  console.log('\n❌ alice balance did not increase as expected');
  process.exit(1);
}

// End-to-end test of the persistent ArkManager on regtest:
//
//   receive (full validation) -> send -> CRASH mid-send + resume from storage
//   -> board -> refresh/consolidate -> spend consolidated -> reload wallet
//
// Storage is JSON-round-tripped on every save (like localStorage would),
// and "restarts" build a brand-new manager over the same stored bytes.
//
// Usage: bun tools/ark/manager-test.js

import { execSync } from 'node:child_process';
import { generateMnemonic, mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { HDKey } from '@scure/bip32';
import { hex } from '@scure/base';

import { ArkManager } from '../../src/ark/manager.js';
import { decodeVtxo } from '../../src/ark/proto.js';
import { validateVtxo } from '../../src/ark/validate.js';

const ARK = process.env.ARK_URL || 'http://127.0.0.1:3535';
const ESPLORA = process.env.ESPLORA_URL || 'http://127.0.0.1:30002';
const BARK = `${process.env.HOME}/bark/target/debug/bark`;
const ALICE = `${BARK} --datadir ${process.env.HOME}/ark-regtest/alice`;
const BCLI = `bitcoin-cli -regtest -datadir=${process.env.HOME}/ark-regtest/bitcoind -rpcport=18543 -rpcwallet=miner`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sh = (cmd) => execSync(cmd, { shell: '/bin/bash' }).toString().trim();
const aliceBalance = () => JSON.parse(sh(`${ALICE} -q balance`)).spendable_sat;
const mine = (n = 1) => sh(`${BCLI} generatetoaddress ${n} $(${BCLI} getnewaddress) >/dev/null`);

let ok = true;
const check = (name, cond, detail = '') => {
  console.log(` ${cond ? '✓' : '✗'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!cond) ok = false;
};

// localStorage-faithful storage: JSON round-trip on both directions
const store = { raw: null };
const storage = {
  load: () => store.raw ? JSON.parse(store.raw) : null,
  save: (s) => { store.raw = JSON.stringify(s); },
};

// fresh wallet every run so the test is re-runnable
const mnemonic = generateMnemonic(wordlist);
const account = HDKey.fromMasterSeed(mnemonicToSeedSync(mnemonic)).derive("m/86'/0'/9'");
const newManager = () => new ArkManager({ account, storage, arkUrl: ARK, esploraUrl: ESPLORA }).init();

let mgr = await newManager();

// --- 1. receive with full validation ---
console.log('\n[1] receive');
const addr = mgr.address();
sh(`${ALICE} -q send ${addr} "20000 sat"`);
for (let i = 0; i < 10 && !mgr.balance().spendableSat; i++) { await mgr.sync(); await sleep(1500); }
check('received 20000 sat', mgr.balance().spendableSat === 20000, JSON.stringify(mgr.balance()));
check('movement logged', mgr.movements().some((m) => m.type === 'receive' && m.status === 'complete'));

// tampered vtxo must fail validation
const rec = mgr.vtxos()[0];
const tampered = hex.decode(rec.bytes);
tampered[tampered.length - 100] ^= 0xff; // corrupt inside the genesis data
let rejected = false;
try {
  await validateVtxo(decodeVtxo(tampered), { serverPubkey: mgr.serverPub, chain: mgr.chain });
} catch { rejected = true; }
check('tampered vtxo rejected by validator', rejected);

// --- 2. plain send ---
console.log('\n[2] send');
const aliceAddr = () => sh(`${ALICE} -q address`);
let before = aliceBalance();
await mgr.send(aliceAddr(), 5000);
check('alice +5000', aliceBalance() === before + 5000);
check('change tracked', mgr.balance().spendableSat === 15000, JSON.stringify(mgr.balance()));

// --- 3. crash mid-send: kill the network after cosign, resume from storage ---
console.log('\n[3] crash mid-send + resume');
before = aliceBalance();
const realFetch = globalThis.fetch;
let registerCalls = 0;
globalThis.fetch = (url, opts) => {
  if (String(url).includes('RegisterVtxoTransactions') && ++registerCalls === 2) {
    // the register of the signed outputs — the state is already 'cosigned'
    return Promise.reject(new Error('simulated crash: network down'));
  }
  return realFetch(url, opts);
};
let crashed = false;
try { await mgr.send(aliceAddr(), 4000); } catch { crashed = true; }
globalThis.fetch = realFetch;
check('send crashed mid-flight', crashed);
check('action persisted at cosigned', JSON.parse(store.raw).actions.some((a) => a.step === 'cosigned'));

// "restart": brand-new manager over the same stored bytes
mgr = await newManager();
await mgr.sync(); // resumes pending actions
check('resumed send completed', mgr.pendingActions().length === 0);
check('alice +4000 after resume', aliceBalance() === before + 4000);
check('balance after resumed send', mgr.balance().spendableSat === 11000, JSON.stringify(mgr.balance()));

// --- 4. board ---
console.log('\n[4] board');
const { actionId, fundingAddress, feeSat } = await mgr.startBoard(30000);
const raw = sh(`${BCLI} createrawtransaction '[]' '[{"${fundingAddress}":0.00030000}]'`);
const funded = JSON.parse(sh(`${BCLI} fundrawtransaction ${raw} '{"changePosition":1}'`));
const signed = JSON.parse(sh(`${BCLI} signrawtransactionwithwallet ${funded.hex}`));
const fundingTxid = sh(`${BCLI} sendrawtransaction ${signed.hex}`);
await mgr.completeBoard(actionId, fundingTxid);
check('board waits for confirmations', mgr.pendingActions().length === 1);
mine(2);
await sleep(2000);
await mgr.sync();
check('board vtxo spendable', mgr.balance().spendableSat === 11000 + 30000 - feeSat, JSON.stringify(mgr.balance()));

// --- 5. refresh: consolidate everything into one vtxo ---
console.log('\n[5] refresh / consolidate');
const vtxosBefore = mgr.vtxos().filter((v) => v.state === 'spendable').length;
await mgr.refresh();
for (let i = 0; i < 40 && mgr.pendingActions().length; i++) {
  await sleep(2000);
  mine(1); // keep confirming the round funding tx
  await mgr.sync();
}
const spendable = mgr.vtxos().filter((v) => v.state === 'spendable');
check('refresh completed', mgr.pendingActions().length === 0);
check(`consolidated ${vtxosBefore} vtxos into 1`, spendable.length === 1, `${spendable.length} spendable`);
console.log(`   balance after refresh: ${mgr.balance().spendableSat} sat`);

// --- 6. spend the consolidated vtxo, then reload wallet from storage ---
console.log('\n[6] spend consolidated + reload');
before = aliceBalance();
await mgr.send(aliceAddr(), 6000);
check('alice +6000 from consolidated vtxo', aliceBalance() === before + 6000);

const balBefore = mgr.balance();
mgr = await newManager(); // reload
check('state survives reload', JSON.stringify(mgr.balance()) === JSON.stringify(balBefore), JSON.stringify(mgr.balance()));
check('movement history intact', mgr.movements().length >= 5, `${mgr.movements().length} movements`);

console.log(ok ? '\n✅ SUCCESS: ArkManager receive/send/crash-resume/board/refresh/reload all pass'
              : '\n❌ some checks failed');
process.exit(ok ? 0 : 1);

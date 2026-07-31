// FULL end-to-end lightning-over-ark test against the regtest stack:
// captaind wired to a dedicated CLN node (cln-ark, hold plugin + xpay) with a
// direct channel to the coinos dev node `clc` as counterparty.
//
//   pay:     ark vtxo -> HTLC cosign -> captaind pays clc's invoice via xpay
//            -> preimage settles the action, clc sees the invoice paid
//   receive: hal mints a hold invoice -> clc pays it -> captaind grants
//            HTLC-recv vtxos -> hal claims with the preimage -> spendable
//
// Usage: bun tools/ark/ln-e2e-test.js   (stack up, alice funded)

import { execSync, spawn } from 'node:child_process';
import { generateMnemonic, mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { HDKey } from '@scure/bip32';
import { hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';

import { ArkManager } from '../../src/ark/manager.js';
import { lnReceiveFee } from '../../src/ark/lightning.js';

const ARK = process.env.ARK_URL || 'http://127.0.0.1:3535';
const ESPLORA = process.env.ESPLORA_URL || 'http://127.0.0.1:30002';
const BARK = `${process.env.HOME}/bark/target/debug/bark`;
const ALICE = `${BARK} --datadir ${process.env.HOME}/ark-regtest/alice`;
const CLC = 'docker exec clc lightning-cli --regtest';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sh = (cmd) => execSync(cmd, { shell: '/bin/bash' }).toString().trim();
const clc = (cmd) => JSON.parse(sh(`${CLC} ${cmd}`));

let ok = true;
const check = (name, cond, detail = '') => {
  console.log(` ${cond ? '✓' : '✗'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!cond) ok = false;
};

const store = { raw: null };
const storage = {
  load: () => (store.raw ? JSON.parse(store.raw) : null),
  save: (s) => { store.raw = JSON.stringify(s); },
};
const mnemonic = generateMnemonic(wordlist);
const account = HDKey.fromMasterSeed(mnemonicToSeedSync(mnemonic)).derive("m/86'/0'/9'");
const mgr = await new ArkManager({ account, storage, arkUrl: ARK, esploraUrl: ESPLORA }).init();

console.log('\n[0] fund manager from alice');
sh(`${ALICE} -q send ${mgr.address()} "25000 sat"`);
for (let i = 0; i < 10 && !mgr.balance().spendableSat; i++) { await mgr.sync(); await sleep(1500); }
check('funded 25000 sat', mgr.balance().spendableSat === 25000, JSON.stringify(mgr.balance()));

// ---------------------------------------------------------------------------
console.log('\n[1] PAY: hal (ark) pays a 5000-sat invoice minted by clc');
const label = `arkpay-${Date.now()}`;
const invRes = clc(`invoice 5000000 ${label} ark-e2e-pay`);
console.log('   clc invoice:', invRes.bolt11.slice(0, 50) + '…');

const payId = await mgr.payLnInvoice(invRes.bolt11);
let a = mgr.lnAction(payId);
console.log('   after first drive: step =', a.step);
for (let i = 0; i < 40 && !['done', 'failed'].includes(mgr.lnAction(payId).step); i++) {
  await sleep(1500);
  await mgr.driveLn(payId);
}
a = mgr.lnAction(payId);
console.log('   terminal:', JSON.stringify({ step: a.step, error: a.error, lastError: a.lastError, feeSat: a.feeSat }));
check('payment settled', a.step === 'done', a.step);
check('preimage matches payment hash', a.preimage && hex.encode(sha256(hex.decode(a.preimage))) === a.paymentHash);
const clcInv = clc(`listinvoices ${label}`).invoices[0];
check('clc invoice paid', clcInv.status === 'paid', clcInv.status);
check('balance decremented by amount+fee', mgr.balance().spendableSat === 25000 - 5000 - a.feeSat,
  JSON.stringify(mgr.balance()));
check('ln-send movement complete', mgr.movements().some((m) => m.type === 'ln-send' && m.status === 'complete'));

// ---------------------------------------------------------------------------
console.log('\n[1b] PAY dust: 25-sat zap-size invoice (HTLC output < dust -> isolation)');
const label2 = `arkdust-${Date.now()}`;
const invDust = clc(`invoice 25000 ${label2} ark-e2e-dust`);
const balBeforeDust = mgr.balance().spendableSat;
const dustId = await mgr.payLnInvoice(invDust.bolt11);
for (let i = 0; i < 40 && !['done', 'failed'].includes(mgr.lnAction(dustId).step); i++) {
  await sleep(1500);
  await mgr.driveLn(dustId);
}
const d = mgr.lnAction(dustId);
console.log('   terminal:', JSON.stringify({ step: d.step, error: d.error, lastError: d.lastError, feeSat: d.feeSat, htlcs: (d.htlcVtxoIds || []).length }));
check('dust payment settled', d.step === 'done', d.step + (d.lastError ? ' / ' + d.lastError : ''));
check('clc dust invoice paid', clc(`listinvoices ${label2}`).invoices[0].status === 'paid');
check('dust balance decremented correctly', mgr.balance().spendableSat === balBeforeDust - 25 - d.feeSat,
  `${balBeforeDust} -> ${mgr.balance().spendableSat}, fee ${d.feeSat}`);

// ---------------------------------------------------------------------------
console.log('\n[1c] tiny plain ark send (100 sat with change -> isolation)');
const aliceBefore = JSON.parse(sh(`${ALICE} -q balance`)).spendable_sat;
const tinyAddr = sh(`${ALICE} -q address | grep -o 'tark1[a-z0-9]*'`);
await mgr.send(tinyAddr, 100);
const aliceAfter = JSON.parse(sh(`${ALICE} -q balance`)).spendable_sat;
check('alice +100 from tiny send', aliceAfter === aliceBefore + 100, `${aliceBefore} -> ${aliceAfter}`);

// ---------------------------------------------------------------------------
console.log('\n[2] RECEIVE: clc pays a 4000-sat invoice minted by hal (hold flow)');
const balBefore = mgr.balance().spendableSat;
const recv = await mgr.createLnInvoice(4000, 'ark-e2e-receive');
console.log('   hal invoice:', recv.invoice.slice(0, 50) + '…');

// clc's pay blocks until we claim (hold invoice) — run it in the background
const payer = spawn('docker', ['exec', 'clc', 'lightning-cli', '--regtest', 'pay', recv.invoice]);
let payerOut = '';
payer.stdout.on('data', (d) => { payerOut += d; });
payer.stderr.on('data', (d) => { payerOut += d; });
const payerDone = new Promise((r) => payer.on('close', (code) => r(code)));

for (let i = 0; i < 40 && !['done', 'failed'].includes(mgr.lnAction(recv.id).step); i++) {
  await sleep(1500);
  await mgr.driveLn(recv.id);
}
const r = mgr.lnAction(recv.id);
console.log('   terminal:', JSON.stringify({ step: r.step, error: r.error, lastError: r.lastError }));
check('receive claimed', r.step === 'done', r.step);

const payerCode = await Promise.race([payerDone, sleep(20000).then(() => 'timeout')]);
check('clc pay completed', payerCode === 0, `exit ${payerCode}: ${payerOut.slice(0, 120)}`);

const fee = lnReceiveFee(4000, mgr.info.lnReceiveFees);
check(`balance grew by 4000 - ${fee} fee`, mgr.balance().spendableSat === balBefore + 4000 - fee,
  `${balBefore} -> ${mgr.balance().spendableSat}`);
check('ln-receive movement complete', mgr.movements().some((m) => m.type === 'ln-receive' && m.status === 'complete'));
check('receive counts as unseen (celebration)', mgr.unseenReceives().length >= 1);

// ---------------------------------------------------------------------------
console.log('\n[3] spend the claimed vtxos back to alice (they must be real)');
const aliceAddr = sh(`${ALICE} -q address | grep -o 'tark1[a-z0-9]*'`);
await mgr.send(aliceAddr, 2000);
check('claimed funds spendable', mgr.movements().some((m) => m.type === 'send' && m.status === 'complete' && m.amountSat === 2000));

console.log(ok ? '\n✅ SUCCESS: full ark<->lightning round trip' : '\n❌ some checks failed');
process.exit(ok ? 0 : 1);

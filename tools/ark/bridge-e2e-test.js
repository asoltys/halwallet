// End-to-end test of the swap bridge over its real HTTP API, against the
// patched regtest ASP (VtxoPolicy::Htlc).
//
//   user wallet  --HTLC-->  bridge  --pays bolt11-->  clb (invoice issuer)
//                           bridge  --claims w/ preimage
//
// Also asserts the failure path: an unpayable invoice leaves the user's money
// untouched and refundable, and the refund really lands back in their wallet.
//
// Usage: bun tools/ark/bridge-e2e-test.js   (regtest stack + cln-ark up)

import { execSync, spawn } from 'node:child_process';
import { writeFileSync, readFileSync, rmSync, mkdirSync } from 'node:fs';
import { generateMnemonic, mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { HDKey } from '@scure/bip32';
import { hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';

import { ArkManager } from '../../src/ark/manager.js';
import { decodeBolt11 } from '../../src/ark/lightning.js';

const ARK = 'http://127.0.0.1:3535';
const ESPLORA = 'http://127.0.0.1:30002';
const BRIDGE = 'http://127.0.0.1:8791';
const BARK = `${process.env.HOME}/bark/target/debug/bark`;
const ALICE_CLI = `${BARK} --datadir ${process.env.HOME}/ark-regtest/alice`;
const DIR = '/tmp/claude-1000/-home-adam-halwallet/f5f3f3a1-dd64-470c-80d8-1b1a87700326/scratchpad/bridge-test';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sh = (cmd) => execSync(cmd, { shell: '/bin/bash' }).toString().trim();
const cln = (node, cmd) => {
  const out = sh(`docker exec ${node} lightning-cli --regtest ${cmd}`);
  return JSON.parse(out.slice(out.indexOf('{')));
};

let ok = true;
const check = (name, cond, detail = '') => {
  console.log(` ${cond ? '✓' : '✗'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!cond) ok = false;
};

// --- bridge wallet + config ------------------------------------------------
rmSync(DIR, { recursive: true, force: true });
mkdirSync(DIR, { recursive: true });
const bridgeMnemonic = generateMnemonic(wordlist);
// the bridge pays from clc, which has ~406k sat outbound toward cln-ark —
// so cln-ark plays the role of the merchant being paid. clb has no route
// from clc (zero outbound toward the hub), which we use for the failure case.
writeFileSync(`${DIR}/config.json`, JSON.stringify({
  port: 8791, network: 'regtest', ark: ARK, esplora: ESPLORA,
  mnemonic: bridgeMnemonic,
  stateFile: `${DIR}/bridge.json`,
  ln: { kind: 'docker', container: 'clc', network: 'regtest' },
  fee: { baseSat: 0, ppm: 1000, minSat: 1 },
  limits: { minSat: 1, maxSat: 1000000, htlcBlocks: 144 },
  tokens: ['test-token'],
}, null, 1));

// fund the bridge's ark wallet so it can pay out claims / hold float
const bridgeAccount = HDKey.fromMasterSeed(mnemonicToSeedSync(bridgeMnemonic)).derive("m/86'/0'/9'");
const bridgeWallet = await new ArkManager({
  account: bridgeAccount, storage: { load: () => null, save: () => {} },
  arkUrl: ARK, esploraUrl: ESPLORA, network: 'regtest',
}).init();

console.log('\n[0] fund the user and the bridge');
const user = await new ArkManager({
  account: HDKey.fromMasterSeed(mnemonicToSeedSync(generateMnemonic(wordlist))).derive("m/86'/0'/9'"),
  storage: { load: () => null, save: () => {} },
  arkUrl: ARK, esploraUrl: ESPLORA, network: 'regtest',
}).init();
sh(`${ALICE_CLI} -q send ${user.address()} "30000 sat"`);
for (let i = 0; i < 12 && !user.balance().spendableSat; i++) { await user.sync(); await sleep(1500); }
check('user funded', user.balance().spendableSat === 30000, JSON.stringify(user.balance()));

// --- start the bridge ------------------------------------------------------
const proc = spawn('bun', ['bridge/server.js'], {
  cwd: `${process.env.HOME}/halwallet`,
  env: { ...process.env, BRIDGE_CONFIG: `${DIR}/config.json` },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let blog = '';
proc.stdout.on('data', (d) => { blog += d; });
proc.stderr.on('data', (d) => { blog += d; });
let info = null;
for (let i = 0; i < 40; i++) {
  try { info = await (await fetch(`${BRIDGE}/info`)).json(); break; } catch {}
  await sleep(500);
}
if (!info) { console.log(blog.slice(-2000)); throw new Error('bridge did not start'); }
console.log('\n[1] bridge up');
check('info reports our claim pubkey', /^0[23][0-9a-f]{64}$/.test(info.claimPubkey || ''), info.claimPubkey);
check('fee policy is cheap', info.fee.minSat === 1 && info.fee.ppm === 1000, JSON.stringify(info.fee));
check('token required', info.requiresToken === true);
console.log(`   outbound liquidity: ${info.outboundSat} sat`);

// --- quote -----------------------------------------------------------------
console.log('\n[2] quote a 25-sat zap (the case the ASP charges 20 sat for)');
const zapInv = cln('cln-ark', 'invoice 25000 zap-' + Date.now() + ' bridge-zap').bolt11;
const quote = await (await fetch(`${BRIDGE}/quote?invoice=${zapInv}`)).json();
check('quote returned', quote.amountSat === 25, JSON.stringify(quote).slice(0, 160));
check('fee is 1 sat (vs the ASP\'s 20)', quote.feeSat === 1, `${quote.feeSat} sat`);
check('quote gives claim pubkey + expiry', !!quote.claimPubkey && quote.htlcExpiry > 0);

// --- the swap --------------------------------------------------------------
console.log('\n[3] user locks an HTLC and the bridge pays the invoice');
const before = user.balance().spendableSat;
const lock = await user.htlcLock({
  amountSat: quote.totalSat,
  claimPubkey: quote.claimPubkey,
  paymentHash: quote.paymentHash,
  htlcExpiry: quote.htlcExpiry,
});
check('user locked the HTLC', lock.htlcVtxos.length === 1);

// unauthorized attempt first
const unauth = await fetch(`${BRIDGE}/swap`, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ invoice: zapInv, htlcVtxo: lock.htlcVtxos[0] }),
});
check('bridge rejects a swap without a token', unauth.status === 401, `HTTP ${unauth.status}`);

const res = await (await fetch(`${BRIDGE}/swap`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', authorization: 'Bearer test-token' },
  body: JSON.stringify({ invoice: zapInv, htlcVtxo: lock.htlcVtxos[0] }),
})).json();
console.log('   swap result:', JSON.stringify(res));
check('swap completed', res.step === 'done', res.step + (res.error ? ' / ' + res.error : ''));
check('bridge returned the preimage', !!res.preimage
  && hex.encode(sha256(hex.decode(res.preimage))) === quote.paymentHash);
check('invoice really paid at the far end',
  cln('cln-ark', 'listinvoices').invoices.some((i) => i.bolt11 === zapInv && i.status === 'paid'));
check('user paid amount + 1 sat fee', user.balance().spendableSat === before - 26,
  `${before} -> ${user.balance().spendableSat}`);
// read the bridge's own persisted wallet state: the claimed HTLC must have
// landed as a spendable vtxo worth the swap total
const bstate = JSON.parse(readFileSync(`${DIR}/bridge.json`, 'utf8'));
const bsat = (bstate.ark?.vtxos || []).filter((v) => v.state === 'spendable')
  .reduce((n, v) => n + v.amountSat, 0);
check('bridge holds the claimed HTLC value', bsat === quote.totalSat, `${bsat} sat spendable`);

// --- idempotency -----------------------------------------------------------
const again = await (await fetch(`${BRIDGE}/swap`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', authorization: 'Bearer test-token' },
  body: JSON.stringify({ invoice: zapInv, htlcVtxo: lock.htlcVtxos[0] }),
})).json();
check('resubmitting the same swap is idempotent', again.step === 'done' && again.preimage === res.preimage);

// --- failure + refund ------------------------------------------------------
console.log('\n[4] unpayable invoice: user must get their money back');
// clb is unreachable from clc (clc has no outbound toward the hub), so this
// is a genuinely unroutable payment rather than a contrived error
const badInv = cln('clb', 'invoice 5000000 unpay-' + Date.now() + ' unpayable').bolt11;
const badDec = decodeBolt11(badInv);
const beforeBad = user.balance().spendableSat;
const badQuote = await (await fetch(`${BRIDGE}/quote?invoice=${badInv}`)).json();
if (badQuote.error) {
  // the bridge refused up front on liquidity — the best possible outcome
  check('bridge refuses a swap it cannot route (no funds at risk)', true, badQuote.error);
  check('user balance untouched', user.balance().spendableSat === beforeBad);
} else {
  const badLock = await user.htlcLock({
    amountSat: badQuote.totalSat, claimPubkey: badQuote.claimPubkey,
    paymentHash: badQuote.paymentHash, htlcExpiry: badQuote.htlcExpiry,
  });
  const badRes = await (await fetch(`${BRIDGE}/swap`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer test-token' },
    body: JSON.stringify({ invoice: badInv, htlcVtxo: badLock.htlcVtxos[0] }),
  })).json();
  check('swap reported refundable, not done', badRes.step === 'refundable', badRes.step);
  const refund = await (await fetch(`${BRIDGE}/refund`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ paymentHash: badDec.paymentHash }),
  })).json();
  check('bridge cosigned a refund', refund.step === 'refunded', JSON.stringify(refund).slice(0, 120));
  const got = await user.acceptHtlcRefund({
    vtxoBytesList: refund.refundVtxos, refundIndex: badLock.refundIndex,
  });
  check('user got every sat back', got === badQuote.totalSat, `${got} of ${badQuote.totalSat}`);
  check('user whole again', user.balance().spendableSat === beforeBad, `${beforeBad} -> ${user.balance().spendableSat}`);
}

proc.kill();
console.log(ok ? '\n✅ SUCCESS: bridge swaps a 25-sat zap for 1 sat, trustlessly' : '\n❌ some checks failed');
if (!ok) console.log('\n--- bridge log tail ---\n' + blog.slice(-1500));
process.exit(ok ? 0 : 1);

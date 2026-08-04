// Does the ASP keep honoring a sub-dust vtxo PAST its expiry height?
//
// Needs captaind running with a short vtxo_lifetime (e.g. 40 blocks) so the
// test can mine past expiry without aging the rest of the regtest chain.
//
//   board fresh coins -> dust to a bearer key -> mine past expiry (watchman
//   sweeps the board) -> bearer sweeps its expired dust to a claimer
//   -> claimer's client validates it (dust exemption) -> and for contrast,
//   an expired NON-dust spend, to document the server's actual policy.
//
// Usage: bun tools/ark/expired-dust-test.js

import { execSync } from 'node:child_process';
import { generateMnemonic, mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { HDKey } from '@scure/bip32';

import { ArkManager } from '/home/adam/coinosv3/src/ark/manager.js';

const ARK = 'http://127.0.0.1:3535';
const ESPLORA = 'http://127.0.0.1:30002';
const BCLI = `docker exec bc bitcoin-cli -rpcwallet=coinos`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sh = (cmd) => execSync(cmd, { shell: '/bin/bash' }).toString().trim();
const mine = (n = 1) => sh(`${BCLI} -generate ${n} >/dev/null`);

let ok = true;
const check = (name, cond, detail = '') => {
  console.log(` ${cond ? '✓' : '✗'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!cond) ok = false;
};

const newWallet = async () => {
  const store = { raw: null };
  const storage = { load: () => (store.raw ? JSON.parse(store.raw) : null), save: (s) => { store.raw = JSON.stringify(s); } };
  const account = HDKey.fromMasterSeed(mnemonicToSeedSync(generateMnemonic(wordlist))).derive("m/86'/0'/9'");
  return new ArkManager({ account, storage, arkUrl: ARK, esploraUrl: ESPLORA }).init();
};
const waitBalance = async (mgr, want, tries = 15) => {
  for (let i = 0; i < tries && mgr.balance().spendableSat < want; i++) { await mgr.sync(); await sleep(1500); }
  return mgr.balance().spendableSat;
};

console.log('[setup] board fresh coins under the short lifetime');
const S = await newWallet();
const G1 = await newWallet(); // 1-sat bearer "gift" key
const C = await newWallet(); // claimer
check('server lifetime is short', S.info.vtxoExpiryDelta <= 60, `vtxoExpiryDelta=${S.info.vtxoExpiryDelta}`);

const { actionId, fundingAddress, feeSat } = await S.startBoard(20000);
const raw = sh(`${BCLI} createrawtransaction '[]' '[{"${fundingAddress}":0.00020000}]'`);
const funded = JSON.parse(sh(`${BCLI} fundrawtransaction ${raw} '{"changePosition":1}'`));
const signed = JSON.parse(sh(`${BCLI} signrawtransactionwithwallet ${funded.hex}`));
const fundingTxid = sh(`${BCLI} sendrawtransaction ${signed.hex}`);
await S.completeBoard(actionId, fundingTxid);
mine(2);
for (let i = 0; i < 20 && S.pendingActions().length; i++) { await sleep(2000); await S.sync(); }
check('boarded', S.balance().spendableSat === 20000 - feeSat, JSON.stringify(S.balance()));

console.log('\n[pre-expiry] 1-sat gift to the bearer key');
await S.send(G1.address(), 1);
check('bearer holds 1 sat', (await waitBalance(G1, 1)) === 1);
const expiry = G1.vtxos()[0].expiryHeight;
let tip = await S.chain.tipHeight();
console.log(`   dust vtxo expires at ${expiry}, tip ${tip}`);

console.log('\n[expire] mining past expiry, waiting for the watchman to CLAIM the board');
mine(expiry - tip + 5);
// esplora indexes the fresh blocks with a lag — poll until it catches up
for (let i = 0; i < 20 && (tip = await S.chain.tipHeight()) <= expiry; i++) await sleep(1500);
check('tip is past expiry', tip > expiry, `tip ${tip} vs expiry ${expiry}`);
// the watchman's claim spends the board funding output — poll for it, mining
// now and then so its claim tx also confirms (process_interval is 60s)
let sweptAt = null;
for (let i = 0; i < 15 && !sweptAt; i++) {
  await sleep(20000);
  mine(1);
  try {
    const o = await fetch(`${ESPLORA}/tx/${fundingTxid}/outspend/0`).then((r) => r.json());
    if (o.spent) sweptAt = o.txid;
  } catch {}
}
check('watchman claimed the expired board on-chain', !!sweptAt, sweptAt || 'not swept after 5 min — claim below tests pre-sweep behavior only');

console.log('\n[claim] bearer sweeps its EXPIRED dust to the claimer');
let claimErr = null;
try { await G1.send(C.address(), 1); } catch (e) { claimErr = e.message; }
check('server cosigned the expired-dust claim', !claimErr, claimErr || '');
if (!claimErr) {
  const got = await waitBalance(C, 1);
  check('claimer validated + received the expired dust', got === 1, `${got} sat`);
}

console.log('\n[contrast] expired NON-dust spend from the sender');
const alice = `${process.env.HOME}/bark/target/debug/bark --datadir ${process.env.HOME}/ark-regtest/alice`;
let bigErr = null;
try { await S.send(sh(`${alice} -q address`), 1000); } catch (e) { bigErr = e.message; }
console.log(`   server ${bigErr ? 'REJECTED: ' + bigErr : 'accepted the expired non-dust spend'}`);

console.log(ok ? '\n✅ expired dust stays spendable' : '\n❌ see failures above');
process.exit(ok ? 0 : 1);

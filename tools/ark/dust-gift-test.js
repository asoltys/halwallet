// Can a sub-dust ark gift be CLAIMED with the current architecture?
//
// Gift create: sender -> fresh bearer key (send has change, isolateDust pads).
// Gift claim:  bearer key -> claimer, sweeping its ONLY (sub-dust) vtxo:
//              a single all-dust output with no non-dust sibling. This is the
//              step the 330-sat floor exists to protect. Does captaind cosign?
//
// Usage: bun /path/to/dust-gift-test.js   (run from coinosv3 root)

import { execSync } from 'node:child_process';
import { generateMnemonic, mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { HDKey } from '@scure/bip32';

import { ArkManager } from '/home/adam/coinosv3/src/ark/manager.js';

const ARK = 'http://127.0.0.1:3535';
const ESPLORA = 'http://127.0.0.1:30002';
const BARK = `${process.env.HOME}/bark/target/debug/bark`;
const ALICE = `${BARK} --datadir ${process.env.HOME}/ark-regtest/alice`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sh = (cmd) => execSync(cmd, { shell: '/bin/bash' }).toString().trim();

let ok = true;
const check = (name, cond, detail = '') => {
  console.log(` ${cond ? '✓' : '✗'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!cond) ok = false;
};

const newWallet = async (label) => {
  const store = { raw: null };
  const storage = {
    load: () => (store.raw ? JSON.parse(store.raw) : null),
    save: (s) => { store.raw = JSON.stringify(s); },
  };
  const account = HDKey.fromMasterSeed(mnemonicToSeedSync(generateMnemonic(wordlist))).derive("m/86'/0'/9'");
  const mgr = await new ArkManager({ account, storage, arkUrl: ARK, esploraUrl: ESPLORA }).init();
  mgr._label = label;
  return mgr;
};

const waitBalance = async (mgr, want, tries = 12) => {
  for (let i = 0; i < tries && mgr.balance().spendableSat < want; i++) { await mgr.sync(); await sleep(1500); }
  return mgr.balance().spendableSat;
};

console.log('[setup] sender, two bearer "gift" keys, claimer');
const sender = await newWallet('sender');
const gift1 = await newWallet('gift-1sat');
const gift329 = await newWallet('gift-329sat');
const claimer = await newWallet('claimer');

sh(`${ALICE} -q send ${sender.address()} "10000 sat"`);
check('sender funded 10000', (await waitBalance(sender, 10000)) === 10000);

// --- gift CREATION at 1 sat and 329 sat (sender has change to pad with) ---
console.log('\n[create] sub-dust gifts (sender change pads the isolation output)');
let createErr = null;
try {
  await sender.send(gift1.address(), 1);
  await sender.send(gift329.address(), 329);
} catch (e) { createErr = e.message; }
check('1-sat + 329-sat gift creation accepted', !createErr, createErr || '');
check('1-sat bearer vtxo arrived', (await waitBalance(gift1, 1)) === 1);
check('329-sat bearer vtxo arrived', (await waitBalance(gift329, 329)) === 329);

// --- gift CLAIM: sweep the bearer key's only, sub-dust vtxo ---
console.log('\n[claim] all-dust sweep from the bearer key (the risky step)');
let claim1Err = null;
try { await gift1.send(claimer.address(), 1); } catch (e) { claim1Err = e.message; }
check('1-sat claim cosigned by server', !claim1Err, claim1Err || '');

let claim329Err = null;
try { await gift329.send(claimer.address(), 329); } catch (e) { claim329Err = e.message; }
check('329-sat claim cosigned by server', !claim329Err, claim329Err || '');

const got = await waitBalance(claimer, (claim1Err ? 0 : 1) + (claim329Err ? 0 : 329));
console.log(`   claimer balance: ${got} sat`);

// --- can the claimer spend a wallet made ONLY of claimed dust? ---
// (sends are single-input, so spend the 1-sat vtxo by itself first)
if (!claim1Err) {
  console.log('\n[respend] claimer re-spends the claimed 1-sat vtxo to alice');
  const before = JSON.parse(sh(`${ALICE} -q balance`)).spendable_sat;
  let respendErr = null;
  try { await claimer.send(sh(`${ALICE} -q address`), 1); } catch (e) { respendErr = e.message; }
  check('1-sat dust vtxo spends onward', !respendErr, respendErr || '');
  if (!respendErr) {
    await sleep(2000);
    const after = JSON.parse(sh(`${ALICE} -q balance`)).spendable_sat;
    check('alice +1', after === before + 1, `${before} -> ${after}`);
  }
}

// --- rounds are how vtxos renew before expiry; how does dust fare there? ---
const mine = () => sh(`docker exec bc bitcoin-cli -rpcwallet=coinos -generate 1 >/dev/null`);

// dust-only wallet: expected to be turned away (fresh wallet so the failed
// action doesn't pollute the mixed-refresh test below)
console.log('\n[refresh: dust-only] 50-sat wallet asks to join a round');
const gift50 = await newWallet('gift-50sat');
await sender.send(gift50.address(), 50);
await waitBalance(gift50, 50);
let dustOnlyErr = null;
try { await gift50.refresh(); } catch (e) { dustOnlyErr = e.message; }
check('dust-only refresh refused cleanly (as expected)', /too small to refresh/.test(dustOnlyErr || ''), dustOnlyErr || 'accepted?!');

// mixed wallet: the case hal actually hits — a dust coin refreshed alongside
// the rest of the balance
console.log('\n[refresh: mixed] claimer holds {329 dust, 5000}; consolidate both');
sh(`${ALICE} -q send ${claimer.address()} "5000 sat"`);
await waitBalance(claimer, 5329);
let mixedErr = null;
try {
  await claimer.refresh();
  for (let i = 0; i < 40 && claimer.pendingActions().length; i++) { await sleep(2000); mine(); await claimer.sync(); }
} catch (e) { mixedErr = e.message; }
const consolidated = claimer.vtxos().filter((v) => v.state === 'spendable');
const outAmount = claimer.state.actions.filter((a) => a.type === 'refresh').at(-1)?.outAmountSat;
check('mixed refresh completed', !mixedErr && claimer.pendingActions().length === 0, mixedErr || '');
check('dust folded into one vtxo (5329 minus round fee)',
  consolidated.length === 1 && claimer.balance().spendableSat === outAmount,
  `${consolidated.length} vtxos, ${JSON.stringify(claimer.balance())}, expected ${outAmount}`);

console.log(ok ? '\n✅ dust gifts are claimable with the CURRENT architecture'
              : '\n❌ see failures above');
process.exit(ok ? 0 : 1);

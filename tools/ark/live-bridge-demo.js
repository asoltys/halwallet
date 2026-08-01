// Live demo of the trustless Ark->Lightning bridge against the coinos
// mutinynet ASP. This is the reference run to point upstream at: everything
// here is public infrastructure, no regtest, no local shortcuts.
//
//   wallet  --HTLC--> arkswap-staging.coinos.io --pays bolt11--> cl-mut
//                     bridge claims with the preimage
//
// Usage: BRIDGE_TOKEN=... bun tools/ark/live-bridge-demo.js

import { execSync } from 'node:child_process';
import { generateMnemonic, mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { HDKey } from '@scure/bip32';
import { hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';

import { ArkManager } from '../../src/ark/manager.js';
import { getHtlcPreimage } from '../../src/ark/lightning.js';

const ARK = process.env.ARK_URL || 'https://ark-staging.coinos.io';
const ESPLORA = process.env.ESPLORA_URL || 'https://mutinynet.com/api';
const BRIDGE = process.env.BRIDGE_URL || 'https://arkswap-staging.coinos.io';
const TOKEN = process.env.BRIDGE_TOKEN || '';

const sh = (c) => execSync(c, { shell: '/bin/bash' }).toString().trim();
// invoices come from cl-mut, the same node the bridge pays from — on a demo
// network that's the only node we control; the payment is still a real
// bolt11 settlement observable in listinvoices.
const clmut = (c) => {
  const out = sh(`ssh cs 'docker exec cl-mut lightning-cli --signet ${c}'`);
  return JSON.parse(out.slice(out.indexOf('{')));
};
const mut = (c) => sh(`ssh cs 'docker exec mut bitcoin-cli -signet -rpcwallet=mutiny ${c}'`);
// A board's funding output MUST be vout 0 (captaind rejects it otherwise) and
// sendtoaddress randomizes output order, so funding goes through a helper on
// cs that pins change to position 1.
const fundBoard = (address, btc) => sh(`ssh cs '~/ark/fund-board.sh ${address} ${btc}'`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let ok = true;
const check = (n, c, d = '') => { console.log(` ${c ? '✓' : '✗'} ${n}${d ? ' — ' + d : ''}`); if (!c) ok = false; };

const wallet = await new ArkManager({
  account: HDKey.fromMasterSeed(mnemonicToSeedSync(generateMnemonic(wordlist))).derive("m/86'/0'/9'"),
  storage: { load: () => null, save: () => {} },
  arkUrl: ARK, esploraUrl: ESPLORA, network: 'mutinynet',
}).init();

console.log('\n[0] a fresh wallet boards onto the coinos ASP');
const { actionId, fundingAddress, feeSat } = await wallet.startBoard(25000);
const txid = fundBoard(fundingAddress, '0.00025');
console.log("   funding txid", txid.slice(0, 20));
await wallet.completeBoard(actionId, txid);
for (let i = 0; i < 60 && wallet.pendingActions().length; i++) {
  await sleep(5000);
  await wallet.sync().catch((e) => console.log('   sync:', e.message));
  if (i % 6 === 5) console.log(`   ...step=${wallet.pendingActions()[0]?.step} bal=${JSON.stringify(wallet.balance())}`);
}
check('boarded', wallet.balance().spendableSat === 25000 - feeSat, JSON.stringify(wallet.balance()));
if (!wallet.balance().spendableSat) { console.log('board did not complete; aborting'); process.exit(1); }

console.log('\n[1] the bridge advertises itself');
const info = await (await fetch(`${BRIDGE}/info`)).json();
check('bridge is on our ASP', info.ark.includes('captaind-mut') || info.ark.includes('ark-staging'), info.ark);
check('has outbound liquidity', info.outboundSat > 0, `${info.outboundSat} sat`);

console.log('\n[2] quote a 25-sat zap');
const label = `demo-${Date.now()}`;
const inv = clmut(`invoice 25000 ${label} ark-bridge-demo`).bolt11;
const quote = await (await fetch(`${BRIDGE}/quote?invoice=${inv}`)).json();
check('quoted', quote.amountSat === 25, JSON.stringify(quote).slice(0, 120));
console.log(`   bridge fee ${quote.feeSat} sat  (second's mainnet ASP floor: 20 sat)`);
check('cheaper than the ASP floor', quote.feeSat < 20, `${quote.feeSat} sat`);

console.log('\n[3] lock the HTLC and let the bridge pay');
const before = wallet.balance().spendableSat;
const lock = await wallet.htlcLock({
  amountSat: quote.totalSat, claimPubkey: quote.claimPubkey,
  paymentHash: quote.paymentHash, htlcExpiry: quote.htlcExpiry,
});
const res = await (await fetch(`${BRIDGE}/swap`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', ...(TOKEN ? { authorization: `Bearer ${TOKEN}` } : {}) },
  body: JSON.stringify({ invoice: inv, htlcVtxo: lock.htlcVtxos[0] }),
})).json();
console.log('   ', JSON.stringify(res));
check('swap completed', res.step === 'done', res.step + (res.error ? ' / ' + res.error : ''));
check('preimage proves payment', !!res.preimage
  && hex.encode(sha256(hex.decode(res.preimage))) === quote.paymentHash);
check('invoice settled on the Lightning node',
  clmut(`listinvoices ${label}`).invoices[0].status === 'paid');
check('wallet debited exactly amount + fee',
  wallet.balance().spendableSat === before - quote.totalSat,
  `${before} -> ${wallet.balance().spendableSat}`);

console.log('\n[4] the ASP publishes the revealed preimage');
const revealed = await getHtlcPreimage(ARK, hex.decode(quote.paymentHash));
check('GetHtlcPreimage returns it', revealed === res.preimage, `${revealed}`);

console.log(ok
  ? `\n✅ 25 sat zap paid over Lightning for a ${quote.feeSat} sat fee, trustlessly, on public infra`
  : '\n❌ some checks failed');
process.exit(ok ? 0 : 1);

// Trustless third-party ark<->LN swap, end to end against a patched captaind
// (VtxoPolicy::Htlc — see docs/third-party-htlc.md).
//
// Two independent hal wallets play the roles:
//   alice  = user paying a Lightning invoice with ark funds
//   bridge = third-party swap provider (NOT the ASP)
//
// Happy path (submarine swap, ark -> LN):
//   1. alice locks funds in an HTLC claimable by the bridge against the
//      invoice's payment hash, refundable by alice after expiry
//   2. bridge validates the HTLC, pays the bolt11 (here: clc's invoice),
//      learns the preimage, claims the HTLC by revealing it
//   3. alice reads the preimage back from the ASP as proof of payment
//
// Security properties the ASP must enforce (each asserted here):
//   - a claim with a WRONG preimage is rejected
//   - the bridge cannot spend the HTLC to itself without the preimage
//     (theft attempt) — only a full refund to alice is allowed
//   - the cooperative refund path works and pays alice
//
// Usage: bun tools/ark/htlc-bridge-test.js   (regtest stack + cln-ark up)

import { execSync } from 'node:child_process';
import { generateMnemonic, mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { HDKey } from '@scure/bip32';
import { hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';

import { ArkManager } from '../../src/ark/manager.js';
import { buildArkoorSend, cosignWithServer } from '../../src/ark/send.js';
import { decodeVtxo } from '../../src/ark/proto.js';
import { validateVtxo } from '../../src/ark/validate.js';
import { getHtlcPreimage, decodeBolt11 } from '../../src/ark/lightning.js';

const ARK = process.env.ARK_URL || 'http://127.0.0.1:3535';
const ESPLORA = process.env.ESPLORA_URL || 'http://127.0.0.1:30002';
const BARK = `${process.env.HOME}/bark/target/debug/bark`;
const ALICE_CLI = `${BARK} --datadir ${process.env.HOME}/ark-regtest/alice`;
const CLC = 'docker exec clc lightning-cli --regtest';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sh = (cmd) => execSync(cmd, { shell: '/bin/bash' }).toString().trim();
// lightning-cli prints progress lines before the JSON body on some commands
const clc = (cmd) => {
  const out = sh(`${CLC} ${cmd}`);
  return JSON.parse(out.slice(out.indexOf('{')));
};

let ok = true;
const check = (name, cond, detail = '') => {
  console.log(` ${cond ? '✓' : '✗'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!cond) ok = false;
};

// two independent wallets
function newWallet() {
  const store = { raw: null };
  const account = HDKey.fromMasterSeed(mnemonicToSeedSync(generateMnemonic(wordlist)))
    .derive("m/86'/0'/9'");
  return new ArkManager({
    account,
    storage: { load: () => (store.raw ? JSON.parse(store.raw) : null), save: (s) => { store.raw = JSON.stringify(s); } },
    arkUrl: ARK, esploraUrl: ESPLORA,
  }).init();
}

const alice = await newWallet();
const bridge = await newWallet();

console.log('\n[0] fund both wallets from the bark CLI wallet');
sh(`${ALICE_CLI} -q send ${alice.address()} "30000 sat"`);
sh(`${ALICE_CLI} -q send ${bridge.address()} "30000 sat"`);
for (let i = 0; i < 12 && (!alice.balance().spendableSat || !bridge.balance().spendableSat); i++) {
  await alice.sync(); await bridge.sync(); await sleep(1500);
}
check('alice funded', alice.balance().spendableSat === 30000, JSON.stringify(alice.balance()));
check('bridge funded', bridge.balance().spendableSat === 30000, JSON.stringify(bridge.balance()));

const tip = await alice.chain.tipHeight();
// bridge's claim key: index 0 of its own vtxo key chain
const bridgeClaimIndex = 0;
const bridgeClaimPub = hex.encode(bridge._key(bridgeClaimIndex).pubkey);

// ---------------------------------------------------------------------------
console.log('\n[1] SUBMARINE SWAP: alice pays a clc invoice through the bridge');
const label = `htlcswap-${Date.now()}`;
const inv = clc(`invoice 5000000 ${label} third-party-htlc-swap`);
const paymentHash = decodeBolt11(inv.bolt11).paymentHash;
console.log('   invoice payment hash:', paymentHash.slice(0, 16) + '…');

// 1. alice locks: 5000 sat + a 5 sat bridge fee (undercutting the ASP's 20)
const swapAmount = 5005;
const lock = await alice.htlcLock({
  amountSat: swapAmount,
  claimPubkey: bridgeClaimPub,
  paymentHash,
  htlcExpiry: tip + 100,
});
check('alice locked into an HTLC', lock.htlcVtxos.length === 1, `${lock.htlcVtxos.length} vtxos`);
const htlcBytes = lock.htlcVtxos[0];
const htlcVtxo = decodeVtxo(hex.decode(htlcBytes));
check('htlc policy encodes both parties', htlcVtxo.policy.type === 'htlc'
  && htlcVtxo.policy.claimPubkey === bridgeClaimPub
  && htlcVtxo.policy.refundPubkey === hex.encode(alice._key(lock.refundIndex).pubkey),
  JSON.stringify(htlcVtxo.policy).slice(0, 120));
check('alice debited', alice.balance().spendableSat === 30000 - swapAmount, JSON.stringify(alice.balance()));

// 2. the bridge independently validates the HTLC before paying anything
await validateVtxo(htlcVtxo, {
  serverPubkey: bridge.serverPub, chain: bridge.chain, allowPolicies: ['htlc'],
});
check('bridge validated the htlc vtxo chain', true);
check('htlc amount + hash as agreed', htlcVtxo.amountSat === swapAmount
  && htlcVtxo.policy.paymentHash === paymentHash);

// 3. ATTACK: wrong preimage must be rejected by the ASP
let wrongRejected = false;
try {
  await bridge.htlcClaim({
    htlcVtxoBytes: htlcBytes, claimKeyIndex: bridgeClaimIndex,
    preimage: hex.encode(sha256(new TextEncoder().encode('not-the-preimage'))),
  });
} catch (e) {
  wrongRejected = /preimage does not match/i.test(e.message);
  if (!wrongRejected) console.log('   unexpected error:', e.message);
}
check('ASP rejects a claim with the wrong preimage', wrongRejected);

// 4. ATTACK: bridge tries to take the funds without the preimage. Built
// straight against the protocol layer — a malicious bridge wouldn't be
// running our client-side guards, so the ASP has to be the one that refuses.
let theftRejected = false;
try {
  const keys = bridge._key(bridgeClaimIndex);
  const build = buildArkoorSend({
    input: htlcVtxo,
    outputs: [{ amountSat: htlcVtxo.amountSat, userPubkey: bridge._key(1).pubkey }],
    serverPubkey: bridge.serverPub, vtxoKeys: keys,
  });
  await cosignWithServer(ARK, build, {
    input: htlcVtxo, vtxoKeys: keys, serverPubkey: bridge.serverPub, // no preimage
  });
} catch (e) {
  theftRejected = /refund pubkey|requires every/i.test(e.message);
  if (!theftRejected) console.log('   unexpected error:', e.message);
}
check('ASP rejects a preimage-less spend to the bridge itself (theft)', theftRejected);

// 5. the bridge pays the invoice for real over Lightning, learning the preimage
const payRes = clc(`pay ${inv.bolt11}`);
check('bridge paid the invoice over LN', payRes.status === 'complete', payRes.status);
const preimage = payRes.payment_preimage;
check('preimage matches the payment hash', hex.encode(sha256(hex.decode(preimage))) === paymentHash);

// 6. bridge claims the HTLC by revealing the preimage to the ASP
const claimed = await bridge.htlcClaim({
  htlcVtxoBytes: htlcBytes, claimKeyIndex: bridgeClaimIndex, preimage,
});
check('bridge claimed the htlc', claimed.length === 1);
check('bridge credited', bridge.balance().spendableSat === 30000 + swapAmount,
  JSON.stringify(bridge.balance()));

// 7. alice reads the preimage back from the ASP: proof her payment happened
const revealed = await getHtlcPreimage(ARK, hex.decode(paymentHash));
check('ASP publishes the revealed preimage', revealed === preimage, `${revealed}`);
check('clc invoice is paid', clc(`listinvoices ${label}`).invoices[0].status === 'paid');

// ---------------------------------------------------------------------------
console.log('\n[2] REFUND PATH: a swap the bridge cannot complete');
const preimage2 = sha256(new TextEncoder().encode('never-revealed-' + Date.now()));
const hash2 = hex.encode(sha256(preimage2));
const beforeRefund = alice.balance().spendableSat;
const lock2 = await alice.htlcLock({
  amountSat: 3000, claimPubkey: bridgeClaimPub, paymentHash: hash2, htlcExpiry: tip + 100,
});
check('alice locked the second htlc', lock2.htlcVtxos.length === 1);
check('alice debited again', alice.balance().spendableSat === beforeRefund - 3000);

// the bridge gives up and cooperatively refunds — the ASP constrains the
// outputs to alice's refund key, so this is safe to expose as a public API
const refundVtxos = await bridge.htlcCosignRefund({
  htlcVtxoBytes: lock2.htlcVtxos[0], claimKeyIndex: bridgeClaimIndex,
});
const refunded = await alice.acceptHtlcRefund({
  vtxoBytesList: refundVtxos, refundIndex: lock2.refundIndex,
});
check('alice got her sats back', refunded === 3000, `${refunded} sat`);
check('alice whole again', alice.balance().spendableSat === beforeRefund,
  JSON.stringify(alice.balance()));

// ---------------------------------------------------------------------------
console.log('\n[3] the swapped funds are ordinary spendable vtxos');
const aliceAddr = sh(`${ALICE_CLI} -q address | grep -o 'tark1[a-z0-9]*'`);
const cliBefore = JSON.parse(sh(`${ALICE_CLI} -q balance`)).spendable_sat;
await bridge.send(aliceAddr, 2000);
const cliAfter = JSON.parse(sh(`${ALICE_CLI} -q balance`)).spendable_sat;
check('bridge can spend claimed funds onward', cliAfter === cliBefore + 2000, `${cliBefore} -> ${cliAfter}`);

console.log(ok ? '\n✅ SUCCESS: trustless third-party ark<->LN swap works' : '\n❌ some checks failed');
process.exit(ok ? 0 : 1);

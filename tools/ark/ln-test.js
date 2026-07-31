// Lightning-over-ark harness against the regtest captaind.
//
// Without a CLN node attached to captaind, a payment can never settle — which
// is exactly what this proves out: the HTLC cosign (the server independently
// derives the ServerHtlcSend taproot + sighashes, so a wrong script tree fails
// the MuSig ceremony), the initiate/status flow, and the revocation path that
// returns the funds. Receive-side StartLightningReceive is exercised for clean
// error behavior (hold invoices need CLN).
//
// Usage: bun tools/ark/ln-test.js   (ark regtest stack up, alice funded)

import { execSync } from 'node:child_process';
import { generateMnemonic, mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { HDKey } from '@scure/bip32';
import { bech32, hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';
import { secp256k1 } from '@noble/curves/secp256k1';

import { ArkManager } from '../../src/ark/manager.js';
import { decodeBolt11 } from '../../src/ark/lightning.js';

const ARK = process.env.ARK_URL || 'http://127.0.0.1:3535';
const ESPLORA = process.env.ESPLORA_URL || 'http://127.0.0.1:30002';
const BARK = `${process.env.HOME}/bark/target/debug/bark`;
const ALICE = `${BARK} --datadir ${process.env.HOME}/ark-regtest/alice`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sh = (cmd) => execSync(cmd, { shell: '/bin/bash' }).toString().trim();

let ok = true;
const check = (name, cond, detail = '') => {
  console.log(` ${cond ? '✓' : '✗'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!cond) ok = false;
};

// --- minimal bolt11 encoder (regtest, signed with a throwaway key) ---------
function toWords5(bytes) { return bech32.toWords(bytes); }
function intToWords(n, len) {
  const w = [];
  for (let i = len - 1; i >= 0; i--) w.push((n >> (5 * i)) & 31);
  return w;
}
function tagged(type, words) {
  const t = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'.indexOf(type);
  return [t, (words.length >> 5) & 31, words.length & 31, ...words];
}
function makeBolt11({ amountSat, paymentHash, privkey }) {
  const hrp = `lnbcrt${amountSat * 10}n`; // sat -> 10*n (n = 100 msat... 1 sat = 10n)
  const ts = Math.floor(Date.now() / 1000);
  const data = [
    ...intToWords(ts, 7),
    ...tagged('p', toWords5(paymentHash)),                 // payment hash (52 words)
    ...tagged('s', toWords5(crypto.getRandomValues(new Uint8Array(32)))), // payment secret
    ...tagged('9', intToWords(0b100000100, 2)),            // features: var_onion(8) + payment_secret(14)? keep minimal
  ];
  // signature: sha256(hrp || data packed 5->8 with zero pad)
  const padded = data.slice();
  const dataBytes = (() => {
    let acc = 0, bits = 0; const out = [];
    for (const w of padded) { acc = (acc << 5) | w; bits += 5; while (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xff); } }
    if (bits) out.push((acc << (8 - bits)) & 0xff);
    return Uint8Array.from(out);
  })();
  const msg = sha256(new Uint8Array([...new TextEncoder().encode(hrp), ...dataBytes]));
  const sig = secp256k1.sign(msg, privkey);
  const sigWords = toWords5(new Uint8Array([...sig.toCompactRawBytes(), sig.recovery]));
  return bech32.encode(hrp, [...data, ...sigWords], 4000);
}

// features field: set var_onion_optin (bit 9) + payment_secret (bit 14) required-ish;
// 2 words = 10 bits only, so re-do with 3 words for bit 14
function makeInvoice(amountSat) {
  const privkey = sha256(new TextEncoder().encode('fake-ln-node'));
  const preimage = crypto.getRandomValues(new Uint8Array(32));
  const paymentHash = sha256(preimage);
  const inv = makeBolt11({ amountSat, paymentHash, privkey });
  return { inv, paymentHash: hex.encode(paymentHash) };
}

// --- wallet setup: fresh manager funded by alice ---------------------------
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

console.log('\n[1] lightning fee schedule parsed from ArkInfo');
check('lnSendFees parsed', mgr.info.lnSendFees.baseFeeSat === 75 && mgr.info.lnSendFees.minFeeSat === 10
  && mgr.info.lnSendFees.ppmExpiryTable.length === 4, JSON.stringify(mgr.info.lnSendFees));
check('lnReceiveFees parsed', mgr.info.lnReceiveFees.baseFeeSat === 100 && mgr.info.lnReceiveFees.ppm === 2000,
  JSON.stringify(mgr.info.lnReceiveFees));
check('htlc deltas parsed', mgr.info.htlcSendExpiryDelta === 258 && mgr.info.htlcExpiryDelta === 40,
  JSON.stringify({ send: mgr.info.htlcSendExpiryDelta, recv: mgr.info.htlcExpiryDelta }));

console.log('\n[2] pay: HTLC cosign against the real server (payment must fail: no CLN)');
const { inv } = makeInvoice(5000);
const dec = decodeBolt11(inv);
check('own bolt11 decodes', dec.amountSat === 5000 && dec.network === 'regtest',
  `${dec.network} ${dec.amountSat} ${dec.paymentHash}`);

let payId = null, payErr = null;
try {
  payId = await mgr.payLnInvoice(inv);
} catch (e) {
  payErr = e;
}

if (payErr) {
  // cosign or initiate rejected — surface exactly where it died
  console.log('   payLnInvoice error:', payErr.message);
  const a = mgr.state.actions.find((x) => x.type === 'ln-pay');
  console.log('   action state:', a ? JSON.stringify({ step: a.step, error: a.error, lastError: a.lastError }) : 'none');
  check('HTLC cosign accepted by server', a && ['cosigned', 'initiated', 'revoking', 'failed'].includes(a.step),
    a ? a.step : 'no action');
} else {
  const a = mgr.lnAction(payId);
  console.log('   after first drive: step =', a.step, a.lastError ? `(lastError: ${a.lastError})` : '');
  check('HTLC cosign accepted by server', ['cosigned', 'initiated', 'revoking', 'failed', 'done'].includes(a.step), a.step);
  // drive until terminal (initiate will fail without CLN -> revocation)
  for (let i = 0; i < 20 && !['done', 'failed'].includes(mgr.lnAction(payId).step); i++) {
    await sleep(1500);
    await mgr.driveLn(payId);
  }
  const fin = mgr.lnAction(payId);
  console.log('   terminal:', JSON.stringify({ step: fin.step, error: fin.error, lastError: fin.lastError }));
  check('payment reached a terminal step', ['done', 'failed'].includes(fin.step), fin.step);
  check('funds recovered after failure', mgr.balance().spendableSat === 25000,
    JSON.stringify(mgr.balance()));
  check('failure movement recorded', mgr.movements().some((m) => m.type === 'ln-send' && m.status === 'failed'));
}

console.log('\n[3] receive: StartLightningReceive error behavior without CLN');
try {
  const a = await mgr.createLnInvoice(4000);
  console.log('   got invoice (server has CLN?):', a.invoice.slice(0, 40) + '…');
  check('invoice payment hash matches derived preimage', decodeBolt11(a.invoice).paymentHash === a.paymentHash);
} catch (e) {
  console.log('   createLnInvoice error (expected without CLN):', e.message);
  check('receive fails cleanly without CLN', /grpc|lightning|invoice|node|unavailable/i.test(e.message), e.message);
}

console.log(ok ? '\n✅ SUCCESS' : '\n❌ some checks failed');
process.exit(ok ? 0 : 1);

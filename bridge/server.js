// Trustless Ark -> Lightning swap bridge.
//
// A third-party swap provider: users pay bolt11 invoices out of their Ark
// balance without the ASP being the counterparty and without trusting us with
// custody. Requires an ASP supporting VtxoPolicy::Htlc (see the upstream
// proposal in bark's docs/third-party-htlc.md).
//
// Why only ark -> LN: an ASP's lightning *receive* is already free (0 base,
// 0 ppm on mainnet today). The expensive direction is *send*, which has a
// 20 sat floor — 80% of a 25 sat zap. That's the leg worth undercutting; the
// receive leg stays on the ASP's native path.
//
// The swap:
//   1. GET  /quote?invoice=...   -> amount, fee, our claim pubkey, expiry
//   2. POST /swap {invoice, htlcVtxo}
//        the user has locked funds in an HTLC that only we can claim, and
//        only by revealing the invoice preimage. We validate it, pay the
//        invoice, then claim with the preimage.
//   3. POST /refund {paymentHash}
//        we couldn't pay: we cosign the HTLC back to the user's refund key.
//        The ASP constrains such a spend to pay only the refunder, so this
//        endpoint cannot be turned into a redirect.
//
// What the user risks: nothing. If we vanish between lock and claim, the HTLC
// expires and they exit through the refund leaf. We cannot take the funds
// without the preimage, which we only have if we paid their invoice.
//
// What WE risk: paying an invoice and then failing to claim. Mitigated by
// validating before paying, claiming immediately after, and retrying on
// resume — we hold the preimage, so the claim stays available (worst case
// through an on-chain exit of the HTLC leaf).

import { readFileSync, writeFileSync, renameSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';
import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync } from '@scure/bip39';

import { ArkManager } from '../src/ark/manager.js';
import { decodeVtxo } from '../src/ark/proto.js';
import { validateVtxo } from '../src/ark/validate.js';
import { decodeBolt11 } from '../src/ark/lightning.js';
import { lnBackend } from './ln.js';

// ---------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------

const CONFIG_PATH = process.env.BRIDGE_CONFIG || join(import.meta.dir, 'config.json');
const cfg = JSON.parse(readFileSync(CONFIG_PATH, 'utf8'));
//   {
//     "port": 8790, "network": "regtest",
//     "ark": "http://127.0.0.1:3535", "esplora": "http://127.0.0.1:30002",
//     "mnemonic": "...", "stateFile": "./data/bridge.json",
//     "ln": { "kind": "docker", "container": "clc", "network": "regtest" },
//     "fee": { "baseSat": 0, "ppm": 1000, "minSat": 1 },
//     "limits": { "minSat": 1, "maxSat": 1000000, "htlcBlocks": 144 },
//     "tokens": ["..."]           // omit or empty to run open
//   }

const FEE = { baseSat: 0, ppm: 1000, minSat: 1, ...(cfg.fee || {}) };
const LIMITS = { minSat: 1, maxSat: 1_000_000, htlcBlocks: 144, ...(cfg.limits || {}) };
const TOKENS = new Set(cfg.tokens || []);
const STATE_PATH = cfg.stateFile || join(import.meta.dir, 'data', 'bridge.json');

const log = (...a) => console.log(new Date().toISOString(), ...a);

// The fee we charge for a swap. Deliberately simple and cheap: our real cost
// is the routing fee plus an amortized slice of rebalancing.
const swapFee = (amountSat) =>
  Math.max(FEE.minSat, FEE.baseSat + Math.ceil((amountSat * FEE.ppm) / 1_000_000));

// ---------------------------------------------------------------------------
// state (swap records, crash-safe via atomic replace)
// ---------------------------------------------------------------------------

function loadState() {
  try { return JSON.parse(readFileSync(STATE_PATH, 'utf8')); } catch { return { swaps: {} }; }
}
let state = loadState();
function saveState() {
  mkdirSync(dirname(STATE_PATH), { recursive: true });
  const tmp = STATE_PATH + '.tmp';
  writeFileSync(tmp, JSON.stringify(state, null, 1));
  renameSync(tmp, STATE_PATH); // atomic
}

// ---------------------------------------------------------------------------
// wallets
// ---------------------------------------------------------------------------

const account = HDKey.fromMasterSeed(mnemonicToSeedSync(cfg.mnemonic)).derive("m/86'/0'/9'");
const arkStore = {
  load: () => state.ark || null,
  save: (s) => { state.ark = s; saveState(); },
};
const ark = await new ArkManager({
  account, storage: arkStore, arkUrl: cfg.ark, esploraUrl: cfg.esplora, network: cfg.network,
}).init();
const ln = lnBackend(cfg.ln);

// Our HTLC claim key. Fixed index so it survives restarts and users can pin it.
const CLAIM_INDEX = 0;
const claimPubkey = hex.encode(ark._key(CLAIM_INDEX).pubkey);

// ---------------------------------------------------------------------------
// swap engine
// ---------------------------------------------------------------------------

const swap = (hash) => state.swaps[hash];
function putSwap(hash, patch) {
  state.swaps[hash] = { ...(state.swaps[hash] || {}), ...patch, updated: Date.now() };
  saveState();
  return state.swaps[hash];
}

// Validate a user's HTLC lock. Everything here must pass BEFORE we spend a
// satoshi on Lightning — this is the only thing standing between us and
// paying an invoice against a worthless VTXO.
async function validateLock({ htlcVtxoBytes, invoice, dec }) {
  const bytes = hex.decode(htlcVtxoBytes);
  const v = decodeVtxo(bytes);

  if (v.policy.type !== 'htlc') throw new Error('vtxo is not an HTLC policy');
  if (v.policy.claimPubkey !== claimPubkey) throw new Error('HTLC is not claimable by this bridge');
  if (v.policy.paymentHash !== dec.paymentHash) throw new Error('HTLC payment hash does not match the invoice');

  const amountSat = dec.amountSat;
  const fee = swapFee(amountSat);
  if (v.amountSat < amountSat + fee) {
    throw new Error(`HTLC underfunded: ${v.amountSat} < ${amountSat} + ${fee} fee`);
  }

  // Expiry must leave us enough room to pay and claim. Too short and we could
  // pay an invoice and then watch the user refund it out from under us.
  const tip = await ark.chain.tipHeight();
  const left = v.policy.htlcExpiry - tip;
  if (left < Math.floor(LIMITS.htlcBlocks / 2)) {
    throw new Error(`HTLC expires too soon (${left} blocks left)`);
  }

  // Full chain validation against the ASP + the chain: this proves the VTXO
  // exists, is properly cosigned and is anchored on-chain.
  await validateVtxo(v, {
    serverPubkey: ark.serverPub, chain: ark.chain, allowPolicies: ['htlc'],
  });

  return { vtxo: v, amountSat, fee };
}

// Drive one swap to a terminal state. Idempotent and safe to re-enter: each
// step checks reality (has the invoice been paid? is the HTLC already spent?)
// rather than trusting the stored step alone.
async function driveSwap(hash) {
  const s = swap(hash);
  if (!s || ['done', 'refunded', 'failed'].includes(s.step)) return s;

  // Never pay twice: ask the node what it actually did.
  if (s.step === 'validated' || s.step === 'paying') {
    const already = await ln.paidPreimage(hash);
    if (already) putSwap(hash, { step: 'paid', preimage: already });
    else if (await ln.isPending(hash)) return swap(hash); // in flight; come back later
  }

  if (swap(hash).step === 'validated') {
    putSwap(hash, { step: 'paying' });
    try {
      const { preimage, feeSat } = await ln.pay(s.invoice, { maxfeeSat: s.fee });
      if (hex.encode(sha256(hex.decode(preimage))) !== hash) {
        throw new Error('node returned a preimage that does not match the payment hash');
      }
      putSwap(hash, { step: 'paid', preimage, routingFeeSat: feeSat });
      log(`paid ${hash.slice(0, 12)} amount=${s.amountSat} routing=${feeSat} charged=${s.fee}`);
    } catch (e) {
      // The payment failed; the user's money is untouched. Offer the refund.
      log(`pay failed ${hash.slice(0, 12)}: ${e.message}`);
      putSwap(hash, { step: 'refundable', error: e.message });
      return swap(hash);
    }
  }

  if (swap(hash).step === 'paid') {
    // We hold the preimage, so this claim can always be made — retry until it
    // lands (and in the worst case it is claimable on-chain via the leaf).
    try {
      await ark.htlcClaim({
        htlcVtxoBytes: swap(hash).htlcVtxo,
        claimKeyIndex: CLAIM_INDEX,
        preimage: swap(hash).preimage,
      });
      putSwap(hash, { step: 'done' });
      log(`claimed ${hash.slice(0, 12)} — swap complete`);
    } catch (e) {
      if (/already spent|not spendable/i.test(e.message)) {
        putSwap(hash, { step: 'done', note: 'htlc already spent' });
      } else {
        putSwap(hash, { claimError: e.message });
        log(`claim failed ${hash.slice(0, 12)} (will retry): ${e.message}`);
      }
    }
  }

  return swap(hash);
}

// Resume anything in flight, then keep nudging.
async function resumeAll() {
  for (const hash of Object.keys(state.swaps)) {
    await driveSwap(hash).catch((e) => log('resume error', hash.slice(0, 12), e.message));
  }
}

// ---------------------------------------------------------------------------
// HTTP API
// ---------------------------------------------------------------------------

const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: {
    'content-type': 'application/json',
    'access-control-allow-origin': '*',
    'access-control-allow-headers': 'content-type,authorization',
    'access-control-allow-methods': 'GET,POST,OPTIONS',
  },
});
const fail = (msg, status = 400) => json({ error: msg }, status);

function authed(req) {
  if (!TOKENS.size) return true; // open mode
  const h = req.headers.get('authorization') || '';
  return TOKENS.has(h.replace(/^Bearer\s+/i, '').trim());
}

const server = Bun.serve({
  port: cfg.port || 8790,
  async fetch(req) {
    const url = new URL(req.url);
    if (req.method === 'OPTIONS') return json({});

    try {
      // Public: what this bridge is and what it charges.
      if (url.pathname === '/info') {
        return json({
          network: cfg.network,
          ark: cfg.ark,
          claimPubkey,
          fee: FEE,
          limits: LIMITS,
          requiresToken: TOKENS.size > 0,
          outboundSat: await ln.outboundSat().catch(() => null),
        });
      }

      if (url.pathname === '/quote') {
        const invoice = url.searchParams.get('invoice');
        if (!invoice) return fail('missing invoice');
        let dec;
        try { dec = decodeBolt11(invoice); } catch (e) { return fail('bad invoice: ' + e.message); }
        if (!dec.amountSat) return fail('invoice has no amount');
        if (dec.amountSat < LIMITS.minSat || dec.amountSat > LIMITS.maxSat) {
          return fail(`amount out of range (${LIMITS.minSat}–${LIMITS.maxSat} sat)`);
        }
        if (Date.now() > dec.expiresAt) return fail('invoice expired');
        const outbound = await ln.outboundSat().catch(() => 0);
        if (outbound < dec.amountSat) return fail('insufficient outbound liquidity', 503);
        const tip = await ark.chain.tipHeight();
        return json({
          amountSat: dec.amountSat,
          feeSat: swapFee(dec.amountSat),
          totalSat: dec.amountSat + swapFee(dec.amountSat),
          paymentHash: dec.paymentHash,
          claimPubkey,
          htlcExpiry: tip + LIMITS.htlcBlocks,
        });
      }

      if (url.pathname === '/swap' && req.method === 'POST') {
        if (!authed(req)) return fail('unauthorized', 401);
        const body = await req.json();
        const { invoice, htlcVtxo } = body || {};
        if (!invoice || !htlcVtxo) return fail('missing invoice or htlcVtxo');

        let dec;
        try { dec = decodeBolt11(invoice); } catch (e) { return fail('bad invoice: ' + e.message); }
        const hash = dec.paymentHash;

        const existing = swap(hash);
        if (existing) {
          // idempotent: same swap resubmitted (client retry / crash recovery)
          return json(publicSwap(hash, await driveSwap(hash)));
        }
        if (!dec.amountSat) return fail('invoice has no amount');
        if (Date.now() > dec.expiresAt) return fail('invoice expired');

        let checked;
        try {
          checked = await validateLock({ htlcVtxoBytes: htlcVtxo, invoice, dec });
        } catch (e) {
          return fail('invalid HTLC: ' + e.message);
        }

        putSwap(hash, {
          step: 'validated', invoice, htlcVtxo,
          amountSat: checked.amountSat, fee: checked.fee,
          htlcAmountSat: checked.vtxo.amountSat,
          created: Date.now(),
        });
        log(`accepted ${hash.slice(0, 12)} amount=${checked.amountSat} fee=${checked.fee}`);

        return json(publicSwap(hash, await driveSwap(hash)));
      }

      // Poll a swap (or nudge a stuck one forward).
      if (url.pathname === '/swap' && req.method === 'GET') {
        const hash = url.searchParams.get('paymentHash');
        if (!hash || !swap(hash)) return fail('unknown swap', 404);
        return json(publicSwap(hash, await driveSwap(hash)));
      }

      // Give up on a swap we couldn't pay: cosign the HTLC back to the user.
      // Safe to expose — the ASP only cosigns a preimage-less HTLC spend when
      // every output pays the refund pubkey, so we cannot redirect it.
      if (url.pathname === '/refund' && req.method === 'POST') {
        const body = await req.json();
        const hash = body?.paymentHash;
        const s = hash && swap(hash);
        if (!s) return fail('unknown swap', 404);
        if (s.step === 'done') return fail('swap already completed');
        if (s.step === 'paid') return fail('invoice was paid; the swap will complete');
        if (await ln.isPending(hash)) return fail('payment still in flight, try again shortly', 409);
        if (s.step === 'refunded') return json({ paymentHash: hash, step: 'refunded', refundVtxos: s.refundVtxos });

        const refundVtxos = await ark.htlcCosignRefund({
          htlcVtxoBytes: s.htlcVtxo, claimKeyIndex: CLAIM_INDEX,
        });
        putSwap(hash, { step: 'refunded', refundVtxos });
        log(`refunded ${hash.slice(0, 12)}`);
        return json({ paymentHash: hash, step: 'refunded', refundVtxos });
      }

      return fail('not found', 404);
    } catch (e) {
      log('handler error:', e.stack || e.message);
      return fail('internal error: ' + e.message, 500);
    }
  },
});

// What we tell the client — never the raw stored record.
function publicSwap(hash, s = swap(hash)) {
  return {
    paymentHash: hash,
    step: s.step,
    amountSat: s.amountSat,
    feeSat: s.fee,
    preimage: s.preimage || null,     // the user's proof of payment
    error: s.error || s.claimError || null,
    refundable: s.step === 'refundable',
  };
}

log(`bridge listening on :${server.port}`);
log(`  network=${cfg.network} ark=${cfg.ark}`);
log(`  claim pubkey ${claimPubkey}`);
log(`  ark balance ${ark.balance().spendableSat} sat`);
log(`  fee: max(${FEE.minSat}, ${FEE.baseSat} + ${FEE.ppm}ppm)`);
try { log(`  ln node ${(await ln.info()).id.slice(0, 16)}… outbound=${await ln.outboundSat()} sat`); }
catch (e) { log('  WARNING: lightning backend unreachable:', e.message); }

await resumeAll();
setInterval(() => { resumeAll().catch(() => {}); }, 15_000);
setInterval(() => { ark.sync().catch(() => {}); }, 30_000);

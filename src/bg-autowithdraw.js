// Auto-withdraw while the app is closed.
//
// The service worker can't watch a relay or resolve a nostr profile, so it
// doesn't try: the app resolves the destination to something concrete (an ark
// address, a lightning address, or an on-chain address) and mirrors it into
// IndexedDB alongside the keys. All this does is the arithmetic and the
// payment — the same ArkManager the background NWC payer uses.
//
// It runs on a push wake-up, which in practice is exactly when it matters: a
// payment just landed. Anything unexpected returns quietly and the next open
// app picks it up.

import { bgManager } from './nwc-respond.js';
import { allBgs, saveBg } from './nwc-bg.js';

const DUST = 330;
const FAIL_BACKOFF_MS = 15 * 60_000;

const spendableOf = (mgr) => (mgr.state.vtxos || [])
  .filter((v) => v.state === 'spendable')
  .reduce((n, v) => n + (v.amountSat || 0), 0);

// Same gate as the foreground (see maybeAutoWithdraw in features/ark.js).
export function bgShouldWithdraw(aw, spendable, actions, now = Date.now()) {
  if (!aw || !aw.on || !aw.target || !aw.target.address) return 0;
  if (now - (aw.failedAt || 0) < FAIL_BACKOFF_MS) return 0;
  if ((actions || []).some((a) => !['done', 'failed'].includes(a.step))) return 0;
  const threshold = Number(aw.threshold) || 0;
  const keep = Math.max(0, Number(aw.keep) || 0);
  if (!threshold || spendable < threshold) return 0;
  const amount = spendable - keep;
  return amount >= DUST ? amount : 0;
}

async function payTarget(mgr, target, amountSat, fetchFn) {
  if (target.kind === 'ark') return mgr.send(target.address, amountSat);
  if (target.kind === 'lnaddr' || target.kind === 'lnurl') {
    const url = target.url;
    if (!url) throw new Error('no lnurl endpoint mirrored');
    const p = await fetchFn(url).then((r) => r.json());
    if (!p || p.tag !== 'payRequest' || !p.callback) throw new Error('bad pay endpoint');
    const msat = amountSat * 1000;
    if (msat < p.minSendable || msat > p.maxSendable) throw new Error('amount outside limits');
    const sep = p.callback.includes('?') ? '&' : '?';
    const inv = await fetchFn(`${p.callback}${sep}amount=${msat}`).then((r) => r.json());
    if (!inv || !inv.pr) throw new Error('no invoice');
    const id = await mgr.payLnInvoice(inv.pr, { amountSat });
    await mgr.driveLn(id).catch(() => {});
    return id;
  }
  // on-chain: only when it's the whole balance. Carving an exact vtxo needs a
  // round trip the worker's budget can't promise, so a partial on-chain
  // forward waits for the app.
  if (target.kind === 'onchain') {
    if (!target.spkHex) throw new Error('no script mirrored');
    if (amountSat !== spendableOf(mgr)) throw new Error('partial on-chain forward needs the app');
    const spk = Uint8Array.from(target.spkHex.match(/../g).map((b) => parseInt(b, 16)));
    return mgr.startOffboard(spk, target.address);
  }
  throw new Error(`unknown destination kind ${target.kind}`);
}

// Run auto-withdraw for every mirrored wallet that wants it. Returns a summary
// for the caller to log or notify with.
export async function bgAutoWithdraw({ fetchFn = fetch, saveFn = saveBg, log = () => {} } = {}) {
  let sent = 0;
  let records;
  try { records = await allBgs(); } catch { return { sent: 0 }; }
  for (const { walletKey: key, rec } of records || []) {
    const aw = rec && rec.autowithdraw;
    if (!aw || !aw.on || !rec.mgr) continue;
    let mgr;
    try { mgr = await bgManager(rec, key, saveFn); } catch { continue; }
    let amount = bgShouldWithdraw(aw, spendableOf(mgr), mgr.state.actions);
    if (!amount) continue;
    try {
      await mgr.sync().catch(() => {});
      amount = bgShouldWithdraw(aw, spendableOf(mgr), mgr.state.actions); // recheck after sync
      if (!amount) continue;
      log(`auto-withdraw: sending ${amount} to ${aw.target.kind}`);
      await payTarget(mgr, aw.target, amount, fetchFn);
      rec.autowithdraw = { ...aw, lastAt: Date.now(), lastSat: amount, failedAt: 0, error: '' };
      sent += amount;
    } catch (e) {
      rec.autowithdraw = { ...aw, failedAt: Date.now(), error: (e && e.message) || String(e) };
      log(`auto-withdraw failed: ${(e && e.message) || e}`);
    }
    await saveFn(key, rec).catch(() => {});
  }
  return { sent };
}

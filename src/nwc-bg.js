// Background NWC spending state — what the service worker answers (and pays)
// from while the app is closed.
//
// The record mirrors the wallet's REAL ark state: its vtxos (with the signed
// bytes), the chain-3 private keys for exactly those coins plus a window of
// upcoming indices for change, the NWC connections' service keys, and the
// worker's spend log. The seed itself never leaves localStorage.
//
// THREAT MODEL, stated plainly. Anything with same-origin script access, or
// a stolen unlocked device, can read IndexedDB and therefore spend the ark
// balance. That is the accepted cost of a wallet that answers while closed —
// the ark balance is treated as walking-around money, and the on-chain wallet
// (whose keys are never mirrored) stays out of reach. Per-connection NWC
// budgets are enforced by the worker before it pays. A user who does not
// enable background answering has no record here and loses nothing.

const DB = 'hal-nwc-pouch'; // name kept from the pouch era so upgrades are seamless
const STORE = 'pouch';
const VERSION = 1;

function openDb() {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined') return reject(new Error('IndexedDB unavailable'));
    const req = indexedDB.open(DB, VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function tx(mode, fn) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const t = db.transaction(STORE, mode);
      const s = t.objectStore(STORE);
      let out;
      Promise.resolve(fn(s)).then((v) => { out = v; }).catch(reject);
      t.oncomplete = () => resolve(out);
      t.onerror = () => reject(t.error);
      t.onabort = () => reject(t.error);
    });
  } finally { db.close(); }
}
const get = (s, k) => new Promise((res, rej) => { const r = s.get(k); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });

// One record per wallet, keyed by the wallet's cache key.
export async function loadBg(walletKey) {
  try { return (await tx('readonly', (s) => get(s, walletKey))) || null; } catch { return null; }
}
export async function saveBg(walletKey, rec) {
  return tx('readwrite', (s) => { s.put(rec, walletKey); });
}
export async function clearBg(walletKey) {
  return tx('readwrite', (s) => { s.delete(walletKey); });
}
// The service worker doesn't know wallet cache keys — it finds the right
// record by the connection's service pubkey across all of them.
export async function allBgs() {
  try {
    return await tx('readonly', (s) => new Promise((res, rej) => {
      const out = [];
      const cur = s.openCursor();
      cur.onsuccess = () => {
        const c = cur.result;
        if (!c) return res(out);
        out.push({ walletKey: c.key, rec: c.value });
        c.continue();
      };
      cur.onerror = () => rej(cur.error);
    }));
  } catch { return []; }
}

// How many upcoming change/refund indices travel with the record: the worker
// cannot derive keys, so its allocations must land inside this window.
export const BG_KEY_LOOKAHEAD = 25;

// { ark } endpoints, the manager state to mirror, and a keyFor(chain, index)
// derive function (the caller owns the account node — it never enters this
// module). Chain 3 covers coins + change, chain 4/0 the mailbox, chain 5 a
// window of receive preimages — everything the worker needs to pay AND to
// mint invoices while the app is closed.
export function buildBg({ ark, mgrState, keyFor, connections, offer }) {
  const keys = {};
  const idx = new Set((mgrState.vtxos || []).filter((v) => v.state !== 'spent').map((v) => v.keyIndex));
  for (let i = 0; i < BG_KEY_LOOKAHEAD; i++) idx.add((mgrState.nextKeyIndex || 1) + i);
  idx.add(0); // the receive-address key: mailbox/refund defaults land on it
  for (const i of idx) keys[String(i)] = keyFor(3, i);
  const keys5 = {};
  for (let i = 0; i < 15; i++) {
    const n = (mgrState.nextLnRecvIndex || 0) + i;
    keys5[String(n)] = keyFor(5, n);
  }
  return {
    v: 3,
    updated: Date.now(),
    ark,
    mgr: mgrState,
    keys,
    keys5,
    key4: keyFor(4, 0),
    offer: offer || null, // { sk, pk } — the CLINK offer service keypair
    connections: (connections || []).map((c) => ({
      id: c.id, servicePk: c.servicePk, serviceSk: c.serviceSk, clientPk: c.clientPk,
      maxSat: c.maxSat, dailySat: c.dailySat,
    })),
  };
}

export const bgSpendableSat = (rec) =>
  ((rec && rec.mgr && rec.mgr.vtxos) || []).filter((v) => v.state === 'spendable')
    .reduce((n, v) => n + (v.amountSat || 0), 0);

// The worker records what it spent so the app can absorb it into budgets and
// history on next open.
export async function noteBgSpend(walletKey, spend) {
  const rec = await loadBg(walletKey);
  if (!rec) return null;
  rec.spends = rec.spends || [];
  rec.spends.push({ ...spend, ts: Date.now() });
  if (rec.spends.length > 200) rec.spends = rec.spends.slice(-200);
  await saveBg(walletKey, rec);
  return rec;
}

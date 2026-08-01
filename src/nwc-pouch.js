// The NWC "pouch": a small, bounded spending capability that a service
// worker can use while the wallet itself stays out of reach.
//
// WHY THIS EXISTS
// hal keeps the seed in localStorage, which service workers cannot read — by
// design, and we are not changing that. But answering a wallet-connect
// request while the app is closed means signing in a service worker. So
// instead of exposing the wallet, we carve off a deliberately small pouch:
//
//   * its own key branch (account chain 6), never used for ordinary coins
//   * only the pouch's PRIVATE KEYS and vtxo bytes go into IndexedDB, which
//     the service worker can read — never the seed, never chain 3
//   * it holds only what the user puts in it
//
// THREAT MODEL, stated plainly. Anything with same-origin script access, or
// a stolen unlocked device, can read IndexedDB and therefore spend the pouch.
// That is the accepted cost of answering while closed. It is bounded: the
// pouch is the blast radius, the rest of the wallet is not reachable from it.
// A user who does not enable background NWC has no pouch and loses nothing.
//
// This module owns the storage and key derivation only. Funding it is an
// ordinary arkoor send from the main wallet (see the ark feature); spending
// from it lives in the service worker (step 3).

import { hex } from '@scure/base';
import { secp256k1 } from '@noble/curves/secp256k1';

const DB = 'hal-nwc-pouch';
const STORE = 'pouch';
const VERSION = 1;

// Chain 6 is the pouch. Chains 0-2 are hal's on-chain use, 3 ark vtxo keys,
// 4 the ark mailbox, 5 lightning-receive preimages — 6 must stay distinct so
// a leaked pouch key can never sign for an ordinary coin.
export const POUCH_CHAIN = 6;

export function pouchKey(account, index) {
  const node = account.deriveChild(POUCH_CHAIN).deriveChild(index);
  return { privkey: node.privateKey, pubkey: secp256k1.getPublicKey(node.privateKey, true) };
}

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

// One record per wallet, keyed by the wallet's cache key so several wallets
// on one device keep separate pouches.
export async function loadPouch(walletKey) {
  try { return (await tx('readonly', (s) => get(s, walletKey))) || null; } catch { return null; }
}
export async function savePouch(walletKey, pouch) {
  return tx('readwrite', (s) => { s.put(pouch, walletKey); });
}
export async function clearPouch(walletKey) {
  return tx('readwrite', (s) => { s.delete(walletKey); });
}

// Everything the service worker needs to spend, and nothing more: the ASP
// endpoints, the pouch vtxos with their bytes, and the private keys for
// exactly those vtxos.
export function buildPouch({ arkUrl, esploraUrl, network, serverPubkey, vtxos, account, connections }) {
  const keys = {};
  for (const v of vtxos) {
    const k = pouchKey(account, v.keyIndex);
    keys[String(v.keyIndex)] = hex.encode(k.privkey);
  }
  return {
    v: 1,
    updated: Date.now(),
    ark: { arkUrl, esploraUrl, network, serverPubkey },
    // [{ id, bytes, keyIndex, amountSat, expiryHeight }]
    vtxos: vtxos.map((v) => ({
      id: v.id, bytes: v.bytes, keyIndex: v.keyIndex,
      amountSat: v.amountSat, expiryHeight: v.expiryHeight,
    })),
    keys,
    // service keys for the connections the SW may answer for, so it can
    // decrypt requests and sign replies without the wallet
    connections: (connections || []).map((c) => ({
      id: c.id, servicePk: c.servicePk, serviceSk: c.serviceSk, clientPk: c.clientPk,
      maxSat: c.maxSat, dailySat: c.dailySat,
    })),
  };
}

export const pouchBalance = (pouch) =>
  (pouch?.vtxos || []).reduce((n, v) => n + (v.amountSat || 0), 0);

// The service worker records what it spent so the app can reconcile and the
// daily budget survives a restart.
export async function notePouchSpend(walletKey, { connId, amountSat, paymentHash, preimage }) {
  const p = await loadPouch(walletKey);
  if (!p) return null;
  p.spends = p.spends || [];
  p.spends.push({ connId, amountSat, paymentHash, preimage, ts: Date.now() });
  if (p.spends.length > 200) p.spends = p.spends.slice(-200);
  await savePouch(walletKey, p);
  return p;
}

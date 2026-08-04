// What the service worker needs to tell a friend's DM from a stranger's.
//
// A NIP-17 wrap is signed by a throwaway key and the sender's identity sits
// under two layers of nip44, so no server can filter DMs by who sent them —
// only the recipient's own key can open one. The notifier therefore ships the
// wrap inside the push payload and the decision happens here, on the device.
//
// THREAT MODEL, stated plainly. This record holds the nostr identity secret,
// so anything with same-origin script access or a stolen unlocked device can
// read every DM this account can read. That is not a new exposure for a
// seed-derived identity — localStorage already holds the seed that key comes
// from — but it is a second copy, and it exists only to keep strangers from
// buzzing the phone. A remote signer (bunker/extension) never hands over its
// key: those wallets store no secret here and fall back to a generic
// notification instead of a filtered one.

import { unwrapDM } from './dm.js';

const DB = 'coinos-dm-inbox';
const STORE = 'inbox';
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

// One record per wallet: { sk, pubkey, follows: [hex], names: { hex: name } }.
// `sk` is null when the identity lives behind a remote signer.
export async function saveInbox(walletKey, rec) {
  return tx('readwrite', (s) => { s.put(rec, walletKey); });
}
export async function clearInbox(walletKey) {
  return tx('readwrite', (s) => { s.delete(walletKey); });
}
export async function allInboxes() {
  try {
    return await tx('readonly', (s) => new Promise((res, rej) => {
      const out = [];
      const cur = s.openCursor();
      cur.onsuccess = () => {
        const c = cur.result;
        if (!c) return res(out);
        out.push(c.value);
        c.continue();
      };
      cur.onerror = () => rej(cur.error);
    }));
  } catch { return []; }
}

const unhex = (h) => Uint8Array.from(h.match(/.{2}/g).map((b) => parseInt(b, 16)));

// Open a wrap against every identity we hold a key for. Returns
// { author, followed, name, mine } for the first one that opens it, or null
// if none can — which includes every remote-signer wallet, so a null means
// "we don't know", never "it's a stranger".
export async function classifyDm(wrap, inboxes) {
  for (const rec of inboxes) {
    if (!rec || !rec.sk) continue;
    let sk;
    try { sk = unhex(rec.sk); } catch { continue; }
    const opened = await unwrapDM(wrap, sk);
    if (!opened) continue;
    const author = opened.author;
    return {
      author,
      mine: author === rec.pubkey,
      followed: (rec.follows || []).includes(author),
      // Someone you're already talking to is not a stranger, whether or not
      // you ever followed them.
      known: (rec.known || []).includes(author),
      // No contact list published at all: there's nothing to filter against,
      // and silence would be worse than noise.
      hasList: !!rec.hasList,
      name: (rec.names || {})[author] || null,
      content: opened.rumor && opened.rumor.kind === 14 ? opened.rumor.content : '',
    };
  }
  return null;
}

// Should this DM interrupt someone? Our own sent-copy never should — every
// NIP-17 message is wrapped to the sender too, and being notified about what
// you just typed is pure noise. Anything we couldn't open stays notifiable:
// better a generic buzz than a silent drop.
export function shouldNotifyDm(verdict) {
  if (!verdict) return true;
  if (verdict.mine) return false;
  if (verdict.followed || verdict.known) return true;
  return !verdict.hasList;
}

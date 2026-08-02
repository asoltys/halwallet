// Every feature must survive being built, started, rendered and stopped
// against a stubbed wallet — the cheap check that catches typos and
// undefined helpers that only bite at runtime in the browser.
// Run: bun tools/features-smoke-test.js
import { buildFeatures } from '../src/features/index.js';

let fails = 0;
const check = (name, ok, detail = '') => {
  console.log(` ${ok ? '✓' : '✗'} ${name}${detail ? ' — ' + String(detail).slice(0, 160) : ''}`);
  if (!ok) fails++;
};

// Nothing may reach the network in a smoke test; failing fast also exercises
// each feature's error path, which is where the runtime typos hide.
const realFetch = globalThis.fetch;
globalThis.fetch = async () => { throw new Error('offline (smoke test)'); };
globalThis.window = undefined;
globalThis.localStorage = {
  _d: {}, getItem(k) { return this._d[k] ?? null; }, setItem(k, v) { this._d[k] = String(v); },
  removeItem(k) { delete this._d[k]; }, key(i) { return Object.keys(this._d)[i] ?? null; },
  get length() { return Object.keys(this._d).length; },
};

const errors = [];
const store = {};
const wallet = {
  watchOnly: false, offline: false, mnemonic: 'x '.repeat(11) + 'y',
  utxos: [], txs: [], receive: [], change: [],
  account: () => null,
  loadFeatureState: (n, fb) => JSON.parse(store[n] || 'null') || fb,
  saveFeatureState: (n, st) => { store[n] = JSON.stringify(st); },
  _cacheKey: () => 'smoke', saveCache: () => {},
  nostrPubkey: () => 'ab'.repeat(32),
  nostrNpub: () => 'npub1smoketestsmoketestsmoketestsmoketestsmoketestsmoke',
  nostrSign: (e) => ({ ...e, id: 'ab'.repeat(32), pubkey: 'ab'.repeat(32), sig: 'cd'.repeat(64) }),
  registerCacheExtension: () => {}, registerRealtimeHook: () => {}, registerLoadHook: () => {},
  registerScanHook: () => {}, registerCacheSavedHook: () => {}, registerCoinLock: () => {},
  loadArkState: () => null, saveArkState: () => {}, _arkNs: () => 'ns', _arkKey: () => 'k',
  _arkHoldKey: () => 'h', _arkVtxoOwner: () => null, adoptArkState: () => null,
  freshReceive: () => ({ address: 'bc1qsmoke' }), freshChange: () => ({ address: 'bc1qchange' }),
  balance: () => ({ spendableSat: 0 }), emit: () => {}, on: () => {},
};
const ctx = {
  h: (tag, attrs, ...kids) => ({ tag, attrs, kids }),
  ui: {}, render: () => {}, wallet,
  hook: () => null, openMnemonic: async () => {},
  fmtAmount: String, unitLabel: () => 'sats', unitTag: () => 'sats', getUnit: () => 'sats',
  parseAmount: (v) => parseInt(v, 10) || 0,
  copyBtn: () => null, pasteBtn: () => null, toast: () => {}, blankSend: () => ({}),
  openExternal: () => {},
};

let features = [];
try {
  features = buildFeatures(ctx);
  check('all features construct', features.length > 0, `${features.length} features`);
} catch (e) { check('all features construct', false, e.message); }

// Surface async failures (an undefined helper inside an async init shows up
// as an unhandled rejection, not a throw).
process.on('unhandledRejection', (e) => errors.push(String(e && e.message || e)));

for (const f of features) {
  for (const m of ['init', 'settingsCards', 'receiveModes', 'historyEntries', 'stop']) {
    if (typeof f[m] !== 'function') continue;
    try { f[m](); } catch (e) { errors.push(`${f.id}.${m}: ${e.message}`); }
  }
}
await new Promise((r) => setTimeout(r, 300)); // let async inits settle

const runtime = errors.filter((e) => /is not defined|is not a function|Cannot read/.test(e));
check('no undefined identifiers at runtime', runtime.length === 0, runtime.join(' | '));
if (errors.length && !runtime.length) console.log(`   (${errors.length} benign offline error(s) ignored)`);

globalThis.fetch = realFetch;
console.log(fails ? `\n❌ ${fails} failure(s)` : '\n✅ features survive a cold start');
process.exit(fails ? 1 : 0);

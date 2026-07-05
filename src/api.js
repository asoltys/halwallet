// Wrapper around Esplora-compatible block explorer APIs (mempool.space and
// Blockstream — same REST shape). Every outgoing request goes through one
// rate-aware proxy (#run) so that:
//   - offline mode can be enforced in a single place,
//   - requests are serialized and spaced (one at a time), and
//   - a 429 from ANY request immediately backs off ALL subsequent requests
//     (global exponential pause), easing back as requests succeed.

// Block explorer selection, stored per network (see the per-network presets +
// nk() helper below). Each network defaults to its first esplora preset; users
// can pick another or a custom Esplora/electrs REST URL (their own node).
const EXPLORER_KEY = 'btc-wallet-explorer';

export function getExplorerConfig(net = getNetwork()) {
  try {
    const c = JSON.parse(localStorage.getItem(nk(EXPLORER_KEY, net)) || 'null');
    if (c && c.server) return { server: c.server, url: c.url || '' };
  } catch {}
  return { server: netDefaults(net).explorer, url: '' };
}

export function setExplorerConfig({ server, url }, net = getNetwork()) {
  try {
    localStorage.setItem(nk(EXPLORER_KEY, net), JSON.stringify({ server, url: url || '' }));
  } catch {}
}

// Active Bitcoin network, persisted globally. mutinynet is a public signet (30s
// blocks) for testing — same address format as testnet, its own explorer at
// mutinynet.com. Data-source choices are stored per network (see nk()).
const NETWORK_KEY = 'btc-wallet-network';
export const NETWORKS = [
  { id: 'mainnet', label: 'Mainnet' },
  { id: 'testnet', label: 'Testnet' },
  { id: 'signet', label: 'Signet' },
  { id: 'mutinynet', label: 'Mutinynet' },
  { id: 'regtest', label: 'Regtest' },
];
export function getNetwork() {
  try {
    const n = localStorage.getItem(NETWORK_KEY);
    if (NETWORKS.some((x) => x.id === n)) return n;
  } catch {}
  return 'mainnet';
}
export function setNetwork(net) {
  try { localStorage.setItem(NETWORK_KEY, net); } catch {}
}

// Per-network data-source presets — the single place network-specific endpoints
// live (so there are no duplicate URL fields elsewhere). Each network has its own
// Electrum servers and block explorers; the selection is stored per network, so
// switching networks remembers each one's choice. 'custom' points at your node.
// One unified list of data sources per network. Each entry knows its type —
// electrum (an Electrum-over-WS server: data + instant push) or esplora (a block
// explorer's REST API: data only, polled). The UI shows a single list; the wallet
// derives the backend from the selected source's type. A custom source's type is
// detected from its URL scheme (ws/wss → electrum, http/https → esplora).
const DATA_SOURCES_BY_NET = {
  mainnet: [
    { id: 'coinos', label: 'coinos', type: 'electrum', url: 'wss://electrum.coinos.io' },
    { id: 'mempool', label: 'mempool.space', type: 'esplora', base: 'https://mempool.space/api', web: 'https://mempool.space', kind: 'mempool' },
    { id: 'blockstream', label: 'blockstream.info', type: 'esplora', base: 'https://blockstream.info/api', web: 'https://blockstream.info', kind: 'esplora' },
    { id: 'electroncash', label: 'btc.electroncash.dk', type: 'electrum', url: 'wss://btc.electroncash.dk:60004' },
    { id: 'jochen', label: 'electrum.jochen-hoenicke.de', type: 'electrum', url: 'wss://electrum.jochen-hoenicke.de:50010' },
    { id: 'mempoolguide', label: 'mempool.guide', type: 'electrum', url: 'wss://mempool.guide/electrum-websocket/' },
    { id: 'custom', label: 'Custom', type: 'auto', url: '' },
  ],
  testnet: [
    { id: 'mempool', label: 'mempool.space', type: 'esplora', base: 'https://mempool.space/testnet/api', web: 'https://mempool.space/testnet', kind: 'mempool' },
    { id: 'blockstream', label: 'blockstream.info', type: 'esplora', base: 'https://blockstream.info/testnet/api', web: 'https://blockstream.info/testnet', kind: 'esplora' },
    { id: 'blockstreamel', label: 'blockstream.info (Electrum)', type: 'electrum', url: 'wss://blockstream.info/testnet/electrum-websocket/' },
    { id: 'custom', label: 'Custom', type: 'auto', url: '' },
  ],
  signet: [
    { id: 'mempool', label: 'mempool.space', type: 'esplora', base: 'https://mempool.space/signet/api', web: 'https://mempool.space/signet', kind: 'mempool' },
    { id: 'second', label: 'esplora.signet.2nd.dev', type: 'esplora', base: 'https://esplora.signet.2nd.dev', web: 'https://mempool.space/signet', kind: 'esplora' },
    { id: 'custom', label: 'Custom', type: 'auto', url: '' },
  ],
  mutinynet: [
    { id: 'mutinynet', label: 'mutinynet.com', type: 'esplora', base: 'https://mutinynet.com/api', web: 'https://mutinynet.com', kind: 'esplora' },
    { id: 'custom', label: 'Custom', type: 'auto', url: '' },
  ],
  regtest: [
    { id: 'local', label: 'Local Fulcrum', type: 'electrum', url: '/electrum' },
    { id: 'localesplora', label: 'Local Esplora', type: 'esplora', base: '/esplora', web: 'http://localhost:3000', kind: 'esplora' },
    { id: 'custom', label: 'Custom', type: 'auto', url: '' },
  ],
};
const DATA_SOURCE_DEFAULT = { mainnet: 'coinos', testnet: 'mempool', signet: 'mempool', mutinynet: 'mutinynet', regtest: 'local' };
export function dataSources(net = getNetwork()) { return DATA_SOURCES_BY_NET[net] || DATA_SOURCES_BY_NET.mainnet; }
const detectType = (url) => (/^wss?:\/\//i.test((url || '').trim()) ? 'electrum' : 'esplora');

// Old per-network defaults (mode + server id) — kept only so the one-time
// migration from the old split electrum/explorer settings can read them.
const NET_DEFAULTS = {
  mainnet: { mode: 'electrum', electrum: 'coinos', explorer: 'mempool' },
  testnet: { mode: 'esplora', electrum: 'blockstreamel', explorer: 'mempool' },
  signet: { mode: 'esplora', electrum: 'custom', explorer: 'mempool' },
  mutinynet: { mode: 'esplora', electrum: 'custom', explorer: 'mutinynet' },
  regtest: { mode: 'electrum', electrum: 'local', explorer: 'localesplora' },
};
function netDefaults(net) { return NET_DEFAULTS[net] || NET_DEFAULTS.mainnet; }
// Internal filtered views (electrum fallover list + esplora host resolution).
export function electrumPresets(net = getNetwork()) { return dataSources(net).filter((x) => x.type === 'electrum'); }
export function explorerPresets(net = getNetwork()) { return dataSources(net).filter((x) => x.type === 'esplora'); }

// The selected data source, resolved to a full entry. Migrates from the old split
// settings the first time (until the user picks a source, which writes SOURCE_KEY).
const SOURCE_KEY = 'btc-wallet-source';
export function getSource(net = getNetwork()) {
  let sel = null;
  try { sel = JSON.parse(localStorage.getItem(nk(SOURCE_KEY, net)) || 'null'); } catch {}
  if (!sel || !sel.id) sel = migrateSource(net);
  const list = dataSources(net);
  if (sel.id === 'custom') {
    const url = (sel.url || '').trim();
    const type = detectType(url);
    if (type === 'electrum') return { id: 'custom', label: 'Custom', type, url };
    const base = url.replace(/\/+$/, '');
    return { id: 'custom', label: 'Custom', type, url, base, web: base.replace(/\/api$/, ''), kind: 'esplora' };
  }
  return list.find((x) => x.id === sel.id) || list.find((x) => x.id === DATA_SOURCE_DEFAULT[net]) || list[0];
}
export function setSource({ id, url }, net = getNetwork()) {
  try { localStorage.setItem(nk(SOURCE_KEY, net), JSON.stringify({ id, url: url || '' })); } catch {}
}
function migrateSource(net) {
  const list = dataSources(net);
  const has = (id) => list.some((x) => x.id === id);
  try {
    if (getDataMode(net) === 'electrum') {
      const ec = getElectrumServerConfig(net);
      if (ec.server === 'custom' && ec.url) return { id: 'custom', url: ec.url };
      if (has(ec.server)) return { id: ec.server };
    } else {
      const xc = getExplorerConfig(net);
      if (xc.server === 'custom' && xc.url) return { id: 'custom', url: xc.url };
      if (has(xc.server)) return { id: xc.server };
    }
  } catch {}
  return { id: DATA_SOURCE_DEFAULT[net] || list[0].id };
}
// Per-network storage keys: mainnet keeps the bare key (backward compat), others
// get a ":<net>" suffix.
function nk(base, net) { return net === 'mainnet' ? base : `${base}:${net}`; }

// Boltz swap provider — the api-v2 REST endpoint the SwapManager talks to; the
// swap-status WebSocket is derived from it (http->ws + /v2/ws) unless given.
// Presets are independent Boltz-compatible instances from SwapMarket's list
// (swapmarket.github.io); `local` is the regtest stack. Non-custodial either
// way: a provider can fail a swap but never steal (we claim/refund on-chain).
export const BOLTZ_PRESETS = [
  { id: 'local', label: 'Local (regtest)', api: '/boltz', ws: 'ws://localhost:9004/v2/ws' },
  { id: 'staging', label: 'coinos staging (mutinynet)', api: 'https://swap-staging.coinos.io', ws: 'wss://swap-staging.coinos.io/v2/ws' },
  { id: 'coinos', label: 'coinos (swap.coinos.io)', api: 'https://swap.coinos.io', ws: 'wss://swap.coinos.io/v2/ws' },
  { id: 'boltz', label: 'Boltz Exchange', api: 'https://api.boltz.exchange' },
  { id: 'middleway', label: 'Middle Way', api: 'https://api.middle-way.space' },
  { id: 'zeus', label: 'ZEUS Swaps', api: 'https://swaps.zeuslsp.com/api' },
  { id: 'eldamar', label: 'Eldamar', api: 'https://boltz-api.eldamar.icu' },
  { id: 'custom', label: 'Custom…', api: '', ws: '' },
];
const BOLTZ_PROVIDER_KEY = 'btc-wallet-boltz-provider'; // selected preset id
const BOLTZ_CUSTOM_KEY = 'btc-wallet-boltz-custom';     // { api, ws } for custom

export function getBoltzCustom() {
  try { const c = JSON.parse(localStorage.getItem(BOLTZ_CUSTOM_KEY) || 'null'); if (c) return { api: c.api || '', ws: c.ws || '' }; } catch {}
  return { api: '', ws: '' };
}
export function setBoltzCustom({ api, ws }) {
  try { localStorage.setItem(BOLTZ_CUSTOM_KEY, JSON.stringify({ api: (api || '').trim(), ws: (ws || '').trim() })); } catch {}
}
export function getBoltzProviderId() {
  try { const id = localStorage.getItem(BOLTZ_PROVIDER_KEY); if (id && BOLTZ_PRESETS.some((p) => p.id === id)) return id; } catch {}
  const net = getNetwork(); // default per network
  // Mainnet defaults to public Boltz Exchange until our own swap.coinos.io
  // node ('coinos') has channel liquidity; flip this to 'coinos' once funded.
  // No Boltz-compatible instance runs on signet, so it defaults to custom/empty.
  return net === 'regtest' ? 'local' : net === 'mutinynet' ? 'staging' : net === 'signet' ? 'custom' : 'boltz';
}
export function setBoltzProviderId(id) { try { localStorage.setItem(BOLTZ_PROVIDER_KEY, id); } catch {} }

export function getBoltzProvider() {
  const p = BOLTZ_PRESETS.find((x) => x.id === getBoltzProviderId()) || BOLTZ_PRESETS[1];
  if (p.id === 'custom') { const c = getBoltzCustom(); return { id: 'custom', api: c.api, ws: c.ws }; }
  return { id: p.id, api: p.api, ws: p.ws || '' };
}
const deriveBoltzWs = (api) => api ? api.replace(/^http/, 'ws').replace(/\/+$/, '') + '/v2/ws' : '';
export function getBoltzApi() { return getBoltzProvider().api; }
export function getBoltzWs() { const p = getBoltzProvider(); return p.ws || deriveBoltzWs(p.api); }

// Ark server (ASP) — Second's bark/captaind protocol, spoken natively over
// gRPC-web (src/ark). Off by default: enabling Ark is an explicit opt-in per
// network. The esplora URL is the chain source the Ark client checks anchors
// and confirmations against (independent from the wallet's own data source so
// each preset ships a known-good pairing).
const ARK_PRESETS_BY_NET = {
  mainnet: [
    { id: 'off', label: 'Off', ark: '', esplora: '' },
    { id: 'second', label: 'Second (ark.second.tech)', ark: 'https://ark.second.tech', esplora: 'https://mempool.second.tech/api' },
    { id: 'custom', label: 'Custom…', ark: '', esplora: '' },
  ],
  // No public ASP on these networks (Second runs signet + mainnet only) —
  // custom lets you point at a self-hosted captaind.
  testnet: [
    { id: 'off', label: 'Off', ark: '', esplora: '' },
    { id: 'custom', label: 'Custom…', ark: '', esplora: '' },
  ],
  signet: [
    { id: 'off', label: 'Off', ark: '', esplora: '' },
    { id: 'second', label: 'Second (ark.signet.2nd.dev)', ark: 'https://ark.signet.2nd.dev', esplora: 'https://esplora.signet.2nd.dev' },
    { id: 'custom', label: 'Custom…', ark: '', esplora: '' },
  ],
  mutinynet: [
    { id: 'off', label: 'Off', ark: '', esplora: '' },
    { id: 'custom', label: 'Custom…', ark: '', esplora: '' },
  ],
  regtest: [
    { id: 'off', label: 'Off', ark: '', esplora: '' },
    { id: 'local', label: 'Local (regtest)', ark: 'http://localhost:3535', esplora: 'http://localhost:30002' },
    { id: 'custom', label: 'Custom…', ark: '', esplora: '' },
  ],
};
// On by default where a known-good server exists; the Settings card can
// always turn it off.
const ARK_DEFAULT = { mainnet: 'second', testnet: 'off', signet: 'second', mutinynet: 'off', regtest: 'local' };
const ARK_PROVIDER_KEY = 'btc-wallet-ark-provider'; // selected preset id, per network
const ARK_CUSTOM_KEY = 'btc-wallet-ark-custom';     // { ark, esplora } for custom, per network

export function arkPresets(net = getNetwork()) {
  return ARK_PRESETS_BY_NET[net] || ARK_PRESETS_BY_NET.mainnet;
}
export function getArkProviderId(net = getNetwork()) {
  try {
    const id = localStorage.getItem(nk(ARK_PROVIDER_KEY, net));
    if (id && arkPresets(net).some((p) => p.id === id)) return id;
  } catch {}
  return ARK_DEFAULT[net] || 'off';
}
export function setArkProviderId(id, net = getNetwork()) {
  try { localStorage.setItem(nk(ARK_PROVIDER_KEY, net), id); } catch {}
}
export function getArkCustom(net = getNetwork()) {
  try { const c = JSON.parse(localStorage.getItem(nk(ARK_CUSTOM_KEY, net)) || 'null'); if (c) return { ark: c.ark || '', esplora: c.esplora || '' }; } catch {}
  return { ark: '', esplora: '' };
}
export function setArkCustom({ ark, esplora }, net = getNetwork()) {
  try { localStorage.setItem(nk(ARK_CUSTOM_KEY, net), JSON.stringify({ ark: (ark || '').trim(), esplora: (esplora || '').trim() })); } catch {}
}
// The active Ark endpoints, or null when Ark is off / incompletely configured.
export function getArkConfig(net = getNetwork()) {
  const id = getArkProviderId(net);
  if (id === 'off') return null;
  const p = arkPresets(net).find((x) => x.id === id);
  const cfg = p.id === 'custom' ? getArkCustom(net) : { ark: p.ark, esplora: p.esplora };
  return cfg.ark && cfg.esplora ? cfg : null;
}

// Silent-payment (BIP-352) tweak indexer — a separate, optional endpoint used
// only for SP receiving. It serves public tweak/UTXO data (the scan key never
// leaves the device), but a public one can observe which blocks hold your
// outputs, so self-hosting is the privacy-max option. Per network; an empty URL
// means SP receiving is unavailable on that network.
const SP_INDEXER_PRESETS_BY_NET = {
  mainnet: [{ id: 'coinos', label: 'coinos', url: 'https://sp.coinos.io' }, { id: 'custom', label: 'Custom', url: '' }],
  testnet: [{ id: 'custom', label: 'Custom', url: '' }],
  signet: [{ id: 'custom', label: 'Custom', url: '' }],
  mutinynet: [{ id: 'custom', label: 'Custom', url: '' }],
  regtest: [{ id: 'local', label: 'Local (proxied)', url: '/sp' }, { id: 'custom', label: 'Custom', url: '' }],
};
const SP_INDEXER_DEFAULT = { mainnet: 'coinos', testnet: 'custom', signet: 'custom', mutinynet: 'custom', regtest: 'local' };
const SP_INDEXER_KEY = 'btc-wallet-sp-indexer';
export function spIndexerPresets(net = getNetwork()) { return SP_INDEXER_PRESETS_BY_NET[net] || SP_INDEXER_PRESETS_BY_NET.mainnet; }
export function getSpIndexerConfig(net = getNetwork()) {
  try {
    const c = JSON.parse(localStorage.getItem(nk(SP_INDEXER_KEY, net)) || 'null');
    if (c && c.server) return { server: c.server, url: c.url || '' };
  } catch {}
  return { server: SP_INDEXER_DEFAULT[net] || 'custom', url: '' };
}
export function setSpIndexerConfig({ server, url }, net = getNetwork()) {
  try { localStorage.setItem(nk(SP_INDEXER_KEY, net), JSON.stringify({ server, url: url || '' })); } catch {}
}
// The resolved indexer base URL for a network, or '' if none is configured.
export function spIndexerUrl(net = getNetwork()) {
  const cfg = getSpIndexerConfig(net);
  if (cfg.server === 'custom') return cfg.url.trim().replace(/\/+$/, '');
  const p = spIndexerPresets(net).find((x) => x.id === cfg.server);
  return p && p.url ? p.url.replace(/\/+$/, '') : '';
}
// SP receiving is available only when an indexer is configured for this network.
export function spReceiveEnabled(net = getNetwork()) { return !!spIndexerUrl(net); }

// Resolve the configured explorer to the host list the Api tries in order.
function resolveHosts(net) {
  const src = getSource(net);
  const mk = (p) => ({ base: p.base, kind: p.kind || 'esplora', web: p.web || (p.base || '').replace(/\/api$/, ''), cooldownUntil: 0 });
  if (src.type === 'esplora' && src.base) {
    // Mainnet silently fails mempool.space over to blockstream.info.
    if (net === 'mainnet' && src.id === 'mempool') { const bs = dataSources(net).find((x) => x.id === 'blockstream'); return bs ? [mk(src), mk(bs)] : [mk(src)]; }
    return [mk(src)];
  }
  // Electrum (or an empty custom) selected: no esplora data host, but tx links
  // still need a web base, so use the network's default explorer host.
  const def = dataSources(net).find((x) => x.type === 'esplora');
  return [def ? mk(def) : { base: '', kind: 'esplora', web: 'https://mempool.space', cooldownUntil: 0 }];
}

// The "data source" setting (stored per network) picks where chain data +
// payment notifications come from:
//   electrum — an Electrum-over-WS server for both data and instant push. The
//              default server is coinos's own Fulcrum on mainnet (see the
//              per-network presets), or point it at your own node.
//   explorer — block-explorer REST data only; polls for payments, no node.
// getBackend() derives from it. Old global 'coinos' mode maps to 'electrum'.
const DATA_MODE_KEY = 'btc-wallet-mode';
export function getDataMode(net = getNetwork()) {
  try {
    const m = localStorage.getItem(nk(DATA_MODE_KEY, net));
    if (m === 'electrum' || m === 'explorer') return m;
    if (m === 'coinos') return 'electrum'; // coinos is now the default Electrum server
  } catch {}
  return netDefaults(net).mode;
}
export function setDataMode(m, net = getNetwork()) {
  try { localStorage.setItem(nk(DATA_MODE_KEY, net), m === 'explorer' ? 'explorer' : 'electrum'); } catch {}
}

export function getBackend() {
  return getSource().type === 'electrum' ? 'electrum' : 'esplora';
}
// The legacy coinos watcher shim is retired (coinos is a full Electrum server
// now); 'explorer' mode polls for payments instead of subscribing.
export function getRealtimeEnabled() { return false; }

const ELECTRUM_SERVER_KEY = 'btc-wallet-electrum-server';
export function getElectrumServerConfig(net = getNetwork()) {
  try {
    const c = JSON.parse(localStorage.getItem(nk(ELECTRUM_SERVER_KEY, net)) || 'null');
    if (c && c.server) return { server: c.server, url: c.url || '' };
  } catch {}
  return { server: netDefaults(net).electrum, url: '' };
}
export function setElectrumServerConfig({ server, url }, net = getNetwork()) {
  try { localStorage.setItem(nk(ELECTRUM_SERVER_KEY, net), JSON.stringify({ server, url: url || '' })); } catch {}
}
// Ordered Electrum WS candidates for the current selection — the wallet tries
// them in turn, advancing when one fails to connect. A named public preset falls
// over to the network's other public servers for resilience; a custom your-node
// URL does NOT fall over — we won't silently leak your addresses to a server you
// didn't pick.
const PUBLIC_ELECTRUM = (net) => electrumPresets(net).filter((x) => x.url).map((x) => x.url);
export function electrumCandidates(net = getNetwork()) {
  const src = getSource(net);
  if (src.type !== 'electrum' || !src.url) return [];
  if (src.id === 'custom') return [src.url]; // your node — don't fall over to public servers
  return [src.url, ...PUBLIC_ELECTRUM(net).filter((u) => u !== src.url)];
}
export function resolveElectrumUrl() {
  return electrumCandidates()[0] || null;
}

// The Electrum backend (data + realtime push) selects/rotates candidates in the
// wallet via electrumCandidates(); the esplora backend has no push and polls. So
// there's no separate watcher URL anymore — wsUrl is always null.
export function wsUrl() { return null; }

// Web base for tx links (Electrum has no web UI — reuse the chosen explorer host).
export function explorerWeb(net = getNetwork()) {
  const hosts = resolveHosts(net);
  return (hosts[0] && hosts[0].web) || 'https://mempool.space';
}

const REQUEST_TIMEOUT_MS = 10000;

export class Api {
  constructor(net = 'mainnet') {
    this.net = net;
    this.offline = false;

    // Hosts are tried in order; a host that 429s is parked on cooldown so we
    // stop hammering it (Blockstream rate-limits aggressively).
    this._hosts = resolveHosts(net);
    this._timeoutMs = REQUEST_TIMEOUT_MS;

    // Serialized scheduler: one request at a time, min gap between starts.
    this._active = 0;
    this._maxConcurrent = 1;
    this._minGapMs = 500;
    this._nextStart = 0;
    this._queue = [];

    // Global rate-limit state, shared across every request and host.
    this._pauseUntil = 0; // no request may start before this time
    this._penalty = 0; // current backoff level
    this._okStreak = 0; // consecutive successes (used to ease the penalty)
  }

  explorerTx(txid) {
    // web already carries any network path prefix (e.g. .../testnet, mutinynet.com).
    const web = (this._hosts[0] && this._hosts[0].web) || 'https://mempool.space';
    return web + '/tx/' + txid;
  }

  get isRegtest() { return this.net === 'regtest'; }

  // ---- rate-aware global scheduler --------------------------------------
  #schedule(task) {
    return new Promise((resolve, reject) => {
      this._queue.push({ task, resolve, reject });
      this.#pump();
    });
  }

  #pump() {
    while (this._active < this._maxConcurrent && this._queue.length) {
      const { task, resolve, reject } = this._queue.shift();
      this._active++;
      const now = Date.now();
      // Respect both the per-request spacing AND any global backoff pause.
      const startAt = Math.max(now, this._nextStart, this._pauseUntil);
      this._nextStart = startAt + this._minGapMs;
      setTimeout(() => {
        Promise.resolve()
          .then(task)
          .then(resolve, reject)
          .finally(() => {
            this._active--;
            this.#pump();
          });
      }, startAt - now);
    }
  }

  // A 429 anywhere → pause every outgoing request, growing the pause each time.
  #penalize() {
    this._penalty = Math.min(this._penalty + 1, 6);
    this._okStreak = 0;
    const backoff = Math.min(2000 * 2 ** (this._penalty - 1), 30000); // 2s→30s
    this._pauseUntil = Date.now() + backoff;
  }

  #reward() {
    if (this._penalty === 0) return;
    if (++this._okStreak >= 4) {
      this._penalty--;
      this._okStreak = 0;
    }
  }

  // The single choke-point: fetch a given host through the scheduler. A 429
  // parks that host on cooldown (so we route away from it) and triggers the
  // global backoff pause.
  async #run(host, path, opts) {
    if (this.offline) throw new Error('offline');
    return this.#schedule(async () => {
      // Hard timeout: an unresponsive host must not stall the (serialized)
      // queue. On timeout/network error, park the host and fail over.
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), this._timeoutMs);
      let res;
      try {
        res = await fetch(host.base + path, { ...opts, signal: ctrl.signal });
      } catch (e) {
        host.cooldownUntil = Date.now() + 20000; // unresponsive — route away
        throw e;
      } finally {
        clearTimeout(timer);
      }
      if (res.status === 429) {
        host.cooldownUntil = Date.now() + 30000;
        this.#penalize();
        const e = new Error('rate limited');
        e.rateLimited = true;
        throw e;
      }
      this.#reward();
      return res;
    });
  }

  // First host not on cooldown (mempool preferred), or null if all are cooling.
  #pickHost() {
    const now = Date.now();
    for (const h of this._hosts) if (h.cooldownUntil <= now) return h;
    return null;
  }

  async #get(path, asText = false) {
    if (this.offline) throw new Error('offline');
    let lastErr;
    for (let attempt = 0; attempt < 6; attempt++) {
      let host = this.#pickHost();
      if (!host) {
        // Every host is cooling down — wait for the soonest to recover.
        const soonest = Math.min(...this._hosts.map((h) => h.cooldownUntil));
        await sleep(Math.max(300, soonest - Date.now()));
        host = this.#pickHost() || this._hosts[0];
      }
      try {
        const res = await this.#run(host, path);
        if (!res.ok) throw new Error(`${res.status} ${res.statusText}: ${path}`);
        return asText ? await res.text() : await res.json();
      } catch (e) {
        lastErr = e;
        if (!e.rateLimited) await sleep(300);
      }
    }
    throw lastErr;
  }

  // chain_stats / mempool_stats tell us whether an address has ever been used.
  addressInfo(address) {
    return this.#get(`/address/${address}`);
  }

  addressUtxos(address) {
    return this.#get(`/address/${address}/utxo`);
  }

  // Spend status of one output: { spent, txid (spender), vin, status }. Reports
  // a spend even by an unconfirmed tx — used to tell if a gift was already claimed.
  outspend(txid, vout) {
    return this.#get(`/tx/${txid}/outspend/${vout}`);
  }

  addressTxs(address) {
    return this.#get(`/address/${address}/txs`);
  }

  // Full transaction (vin with prevouts, vout, status) — used for fee bumping.
  getTx(txid) {
    return this.#get(`/tx/${txid}`);
  }

  async feeRates() {
    for (const host of this._hosts) {
      if (host.cooldownUntil > Date.now()) continue;
      const isMempool = host.kind === 'mempool';
      try {
        const res = await this.#run(host, isMempool ? '/v1/fees/recommended' : '/fee-estimates');
        if (!res.ok) continue;
        const data = await res.json();
        if (isMempool && data && data.halfHourFee) return data;
        if (!isMempool && data) return mapEsploraFees(data);
      } catch {
        /* try next host */
      }
    }
    return { fastestFee: 20, halfHourFee: 10, hourFee: 5, economyFee: 2, minimumFee: 1 };
  }

  // Broadcast to ALL explorers in parallel (not via the throttle — a send is
  // urgent) so the tx is visible regardless of which explorer the recipient
  // watches. Resolves with the txid if any accept it; rejects only if all fail.
  async broadcast(hexTx) {
    if (this.offline) throw new Error('offline');
    const attempts = this._hosts.map(async (host) => {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), this._timeoutMs);
      try {
        // Keep the abort timer active across BOTH the request and the body read —
        // a stalled response body must not hang the broadcast forever.
        const res = await fetch(host.base + '/tx', { method: 'POST', body: hexTx, signal: ctrl.signal });
        const body = await res.text();
        if (res.status === 429) {
          host.cooldownUntil = Date.now() + 30000;
          this.#penalize();
        }
        if (!res.ok) throw new Error(body || `${res.status} broadcast failed`);
        return body.trim(); // txid
      } finally {
        clearTimeout(timer);
      }
    });
    const results = await Promise.allSettled(attempts);
    const ok = results.find((r) => r.status === 'fulfilled');
    if (ok) return ok.value;
    throw (results.find((r) => r.status === 'rejected') || {}).reason || new Error('broadcast failed');
  }
}

// Esplora /fee-estimates is { blockTarget: sat/vB }. Map to the named tiers the
// UI expects. Round up so we never underpay.
function mapEsploraFees(est) {
  const at = (n, d) => Math.max(1, Math.ceil(est[n] || d));
  return {
    fastestFee: at(1, 10),
    halfHourFee: at(3, 5),
    hourFee: at(6, 3),
    economyFee: at(144, 2),
    minimumFee: at(1008, 1),
  };
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// Run async jobs with a small concurrency cap. (The global scheduler is the
// real limiter; this just bounds how many are queued at once.)
export async function pool(items, worker, concurrency = 4) {
  const results = new Array(items.length);
  let next = 0;
  async function run() {
    while (next < items.length) {
      const i = next++;
      results[i] = await worker(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, run));
  return results;
}

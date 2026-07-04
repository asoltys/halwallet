// Bitcoin Wallet — UI controller (vanilla DOM, no framework).
//
// State lives in `ui` + the singleton `wallet`. Mutating handlers call render(),
// which rebuilds the active screen. Text inputs write back into `ui` on `input`
// (without re-rendering) so their values survive structural re-renders.

import { Wallet, newMnemonic, isValidMnemonic, accountXpubFor, cacheKeyFor, utxoId, previewGift, giftOutpoints, buildClaimTx, giftMinimum, parseExtendedKey, xpubToZpub, encryptVault, decryptVault, lockGift, previewLockedGift } from './wallet.js';
import { qrSvg } from './qr.js';
import { scanQr } from './scan.js';
import { getSyncConfig, setSyncConfig, parseNostrPubkey, npubOf, fetchNostrProfile, decryptWithCode } from './nostr.js';
import { dataSources, getSource, setSource, getNetwork, setNetwork, NETWORKS, getSpIndexerConfig, setSpIndexerConfig, spIndexerPresets, getBoltzApi, BOLTZ_PRESETS, getBoltzProviderId, setBoltzProviderId, getBoltzCustom, setBoltzCustom, arkPresets, getArkProviderId, setArkProviderId, getArkCustom, setArkCustom, getArkConfig } from './api.js';
import { SwapManager } from './swap.js';
import { ArkManager } from './ark/manager.js';
import { isSilentPaymentAddress } from './silentpay.js';
import { t, LANGS, getLang, setLang, isRTL, loadLocale } from './i18n.js';
import {
  fmtBtc,
  fmtSats,
  parseAmount,
  shortAddr,
  shortTxid,
  timeAgo,
  SATS,
} from './format.js';

const wallet = new Wallet();
// Boltz swap orchestrator (reverse = receive over LN, submarine = spend over LN).
const swaps = new SwapManager({
  wallet, network: getNetwork(), getApi: getBoltzApi,
  feeRate: 2, onUpdate: () => render(),
});

// Ark (off-chain payments via an ASP, spoken natively — see src/ark). One
// manager per open wallet; null when Ark is off in Settings, watch-only, or
// still connecting. State persists under the wallet's cache key.
let ark = null;
let arkTimer = null;
let arkConnectPromise = null;
let arkInitGen = 0; // guards against a stale init() resolving after a wallet switch

function stopArk() {
  arkInitGen++;
  if (arkTimer) clearInterval(arkTimer);
  arkTimer = null;
  ark = null;
  arkConnectPromise = null;
}

// Ark is available (a server is configured and we hold keys), even if we
// haven't dialed the server yet — gates the UI entry points.
function arkAvailable() {
  return !!getArkConfig() && !wallet.watchOnly && !!wallet.account;
}

// Whether this wallet has used Ark before (coins, unfinished operations, or
// history). Only then does opening the wallet dial the server on its own —
// fresh wallets stay silent until the user first touches an Ark feature.
function arkWanted() {
  const st = wallet.loadArkState();
  return !!(st && ((st.vtxos || []).length || (st.movements || []).length
    || (st.actions || []).some((a) => !['done', 'failed'].includes(a.step))));
}

function initArk() {
  stopArk();
  ui.arkError = '';
  if (arkAvailable() && arkWanted()) connectArk().catch(() => {});
}

// Connect on demand; idempotent (returns the live manager or the in-flight
// connection). Callers surface ui.arkError on failure.
function connectArk() {
  if (ark) return Promise.resolve(ark);
  if (arkConnectPromise) return arkConnectPromise;
  if (!arkAvailable()) return Promise.reject(new Error(t('arkNotConnected')));
  const cfg = getArkConfig();
  const gen = arkInitGen;
  const mgr = new ArkManager({
    account: wallet.account(),
    storage: { load: () => wallet.loadArkState(), save: (s) => wallet.saveArkState(s) },
    arkUrl: cfg.ark,
    esploraUrl: cfg.esplora,
    network: getNetwork(),
    onUpdate: () => render(),
  });
  ui.arkError = '';
  arkConnectPromise = mgr.init().then(() => {
    if (gen !== arkInitGen) throw new Error('superseded'); // wallet switched mid-connect
    ark = mgr;
    const tick = () => mgr.sync().catch(() => {});
    tick();
    // Regtest rounds are seconds apart; on mainnet a slower poll is plenty.
    arkTimer = setInterval(() => { if (ark === mgr) tick(); }, getNetwork() === 'regtest' ? 5000 : 30000);
    render();
    return mgr;
  }).catch((e) => {
    if (gen === arkInitGen) { ui.arkError = e.message; render(); }
    throw e;
  }).finally(() => { arkConnectPromise = null; });
  render();
  return arkConnectPromise;
}

// The spendable Ark balance (sats), or null when Ark isn't active.
function arkBalance() {
  if (!ark || !ark.state) return null;
  return ark.balance();
}

// t?ark1… bech32m — an Ark address for this or another ASP.
function isArkAddress(a) { return /^t?ark1[a-z0-9]{20,}$/i.test((a || '').trim()); }

const ui = {
  screen: 'unlock', // 'unlock' | 'wallet' | 'claim' | 'howItWorks'
  claimStep: null, // 'welcome' | 'backup' when opening a gift link
  claimChecking: false, // verifying the gift's funding coin is still unspent
  claimTaken: null, // { txid } if the gift was already claimed (coin spent)
  returnScreen: 'unlock', // where 'howItWorks' returns to (Back / logo)
  unlockTab: 'create', // 'create' | 'import' | 'watch'
  watchXpub: '', // watch-only xpub/zpub input
  watchLabel: '', // watch-only account label input
  fromWallet: false, // unlock screen reached as "add wallet" (show a back button)
  pw: null, // { purpose, accId, mode, v1, v2, error } — vault password prompt
  vaultPw: '', // on-open vault unlock input
  vaultError: '',
  confirmClear: false, // "Clear all" confirmation shown
  editId: null, // account being renamed
  editLabel: '',
  createStep: 'gen', // 'gen' | 'confirm'
  draftMnemonic: '',
  confirm: [], // [{ index, value }]
  confirmPass: '', // re-entered passphrase on the verify step
  importText: '',
  passphrase: '',
  showPass: false,
  revealShown: false, // recovery phrase unmasked on the Backup tab (after the warning)
  pubkeyShown: false, // account public key revealed in Settings
  giftMode: false, // gift sub-view active on the Send page
  giftAmount: '', // gift-create amount input
  giftLockNpub: '', // optional: lock the gift to this recipient nostr npub
  giftLocked: false, // the just-created gift is locked to a nostr key
  giftClaimCode: null, // the one-time claim code DM'd to the recipient (fallback)
  giftDmStatus: null, // 'sending' | 'sent' | 'failed' — nostr DM of the claim code
  claimLocked: null, // a locked gift being opened: { v, amount, to, ct }
  claimCodeInput: '', // the claim code the recipient pastes from their nostr DM
  consolidateError: null, // error from a coin-consolidation attempt
  viewGift: null, // re-viewing a previously created gift's link/QR { code, locked, amount, claimCode }
  claimChoose: null, // opening a gift with existing wallets present: { code } — pick a target
  giftCode: null, // last-created gift PSBT code
  giftError: '',
  giftMax: false, // gift the whole spendable balance (no-change sweep)
  giftSplitOffer: null, // { amt, lock, freed, fee } when offering to split a coin first
  revokeId: null, // outpoint of a gift being revoked (confirm state)
  claimCode: null, // gift code being claimed (opened from a #gift= link)
  claimedAmount: 0,
  claimError: '',
  offlineFallback: false, // auto-entered offline because the network was unreachable
  unlockError: '',

  tab: 'receive', // receive | send | history | settings
  receiveSeenIndex: null, // fresh receive index the user has acknowledged
  txDetail: null, // txid being viewed in the history detail view
  txPage: 0, // History: current page of transactions (10 per page)
  giftsAll: false, // History: showing the full paginated list of sent gifts
  giftsPage: 0, // History: current page within the all-gifts list
  addrScan: false, // Settings: showing the per-address rescan list
  addrScanPage: 0, // Settings: current page within the address list
  rescanning: new Set(), // 'chain/index' ids queued/in-flight for rescan
  send: blankSend(),
  draft: null, // built tx summary awaiting review
  broadcastTx: null, // scanned signed tx awaiting broadcast confirmation
  bump: null, // RBF bump in progress: { prep, feeChoice, customFee }
  sendError: '',
  sendResult: null, // { txid } | { signedHex, txid }
  busy: false,
};

function blankSend() {
  return {
    recipients: [{ address: '', amount: '' }],
    unit: 'btc',
    max: false,
    feeChoice: 'halfHourFee',
    customFee: '',
    manual: false,
    coins: new Set(),
  };
}

// ---------------------------------------------------------------- DOM helper
function h(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k === 'html') e.innerHTML = v;
    else if (k === 'value') e.value = v;
    else if (k === 'checked' || k === 'disabled' || k === 'selected') e[k] = !!v;
    else if (k.startsWith('on') && typeof v === 'function')
      e.addEventListener(k.slice(2).toLowerCase(), v);
    else e.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false || c === true) continue;
    e.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return e;
}

const root = document.getElementById('app');
function footer() {
  return h(
    'div',
    { class: 'footer small muted center' },
    h(
      'div',
      {},
      t('footerMadeBy') + ' ',
      h('a', { href: 'https://adamsoltys.com', target: '_blank', rel: 'noopener' }, 'Adam Soltys'),
      h('span', { class: 'faint' }, ' · '),
      t('footerSourceOn') + ' ',
      h('a', { href: 'https://github.com/asoltys/halwallet', target: '_blank', rel: 'noopener' }, 'GitHub')
    ),
    h(
      'div',
      { style: 'margin-top:4px' },
      h('button', { class: 'linklike', style: 'font-weight:400', onClick: openHowItWorks }, t('howItWorks')),
      // Chrome no longer prompts to install on its own — surface our own link
      // once it reports the app is installable. We render from a persisted flag
      // (not the live event) so the link is present on the first paint after a
      // refresh, avoiding a layout shift when beforeinstallprompt fires late.
      installable()
        ? h('span', {}, h('span', { class: 'faint' }, ' · '),
            h('button', { class: 'linklike', style: 'font-weight:400', onClick: triggerInstall }, t('installApp')))
        : null,
      h('span', { class: 'faint' }, ' · '),
      h('button', { class: 'linklike', style: 'font-weight:400', onClick: toggleTheme }, resolvedTheme() === 'dark' ? t('lightMode') : t('darkMode'))
    ),
    h('div', { style: 'margin-top:8px' }, languagePicker())
  );
}

const THEME_KEY = 'btc-wallet-theme';
function resolvedTheme() {
  try {
    const s = localStorage.getItem(THEME_KEY);
    if (s === 'dark' || s === 'light') return s;
  } catch {}
  try { return matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'; } catch {}
  return 'light';
}
function applyTheme() {
  try { document.documentElement.dataset.theme = resolvedTheme(); } catch {}
}
function toggleTheme() {
  try { localStorage.setItem(THEME_KEY, resolvedTheme() === 'dark' ? 'light' : 'dark'); } catch {}
  applyTheme();
  render();
}

// PWA install. Chrome fires beforeinstallprompt when the app qualifies; we stash
// the event and reveal an "Install app" link, then replay it on a user tap (the
// browser requires a gesture). The link's visibility is driven by a persisted
// flag rather than the live event so it's present on the first paint after a
// refresh (no layout shift); the event only supplies the prompt to replay.
// We deliberately do NOT call e.preventDefault(): modern Chrome shows no banner
// of its own to suppress, and preventDefault-without-prompt() logs a console
// warning. The event stays usable for our own e.prompt() on tap.
const INSTALLABLE_KEY = 'btc-wallet-installable';
let installPrompt = null;
function isStandalone() {
  try {
    return matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
  } catch { return false; }
}
function installable() {
  if (isStandalone()) return false;
  try { return localStorage.getItem(INSTALLABLE_KEY) === '1'; } catch { return false; }
}
function setInstallable(v) {
  try {
    if (v) localStorage.setItem(INSTALLABLE_KEY, '1');
    else localStorage.removeItem(INSTALLABLE_KEY);
  } catch {}
}
if (typeof window !== 'undefined') {
  window.addEventListener('beforeinstallprompt', (e) => {
    installPrompt = e;
    // Only re-render if this changes what's on screen; on a refresh the link is
    // already shown from the persisted flag, so nothing moves.
    const wasShown = installable();
    setInstallable(true);
    if (!wasShown) render();
  });
  window.addEventListener('appinstalled', () => {
    installPrompt = null;
    setInstallable(false);
    render();
  });
}
async function triggerInstall() {
  const e = installPrompt;
  // The prompt event may not have fired yet this load even though the link is
  // shown from the persisted flag; bail quietly if so.
  if (!e) return;
  installPrompt = null;
  e.prompt();
  try {
    await e.userChoice;
  } catch {}
}

// Open the How it works page, remembering where to return to.
function openHowItWorks() {
  if (ui.screen === 'howItWorks') return;
  ui.returnScreen = ui.screen;
  ui.screen = 'howItWorks';
  render();
}

// Per-tab session nav (tab + open tx), so a refresh keeps the user's place.
const NAV_KEY = 'btc-wallet-nav';

// Index path from #app down to a node, and back — used to re-find the focused
// field after a full rebuild (a background re-render produces the same structure).
function focusPath(el) {
  const path = [];
  for (let n = el; n && n !== root; n = n.parentNode) {
    const p = n.parentNode;
    if (!p) return null;
    path.unshift(Array.prototype.indexOf.call(p.children, n));
  }
  return path;
}
function nodeAtPath(path) {
  let n = root;
  for (const i of path) n = n && n.children[i];
  return n || null;
}

function render() {
  // Preserve focus + caret across the rebuild, so a background update (poll, a
  // payment push, an SP scan) can't kick the user out of a field they're editing.
  const a = document.activeElement;
  let fpath = null, selStart = null, selEnd = null;
  if (a && root.contains(a) && /^(INPUT|SELECT|TEXTAREA)$/.test(a.tagName)) {
    fpath = focusPath(a);
    try { selStart = a.selectionStart; selEnd = a.selectionEnd; } catch {}
  }
  const screen =
    ui.claimLocked
      ? lockedGiftClaimView()
    : ui.viewGift
      ? viewGiftView()
    : ui.claimChoose
      ? claimChooseView()
    : ui.screen === 'wallet'
      ? walletScreen()
      : ui.screen === 'accounts'
        ? accountsScreen()
        : ui.screen === 'accountSettings'
          ? accountSettingsScreen()
        : ui.screen === 'vault'
          ? vaultScreen()
          : ui.screen === 'claim'
          ? claimScreen()
          : ui.screen === 'howItWorks'
            ? howItWorksScreen()
            : unlockScreen();
  root.replaceChildren(screen, footer());
  if (fpath) {
    const el = nodeAtPath(fpath);
    if (el && el !== a && /^(INPUT|SELECT|TEXTAREA)$/.test(el.tagName)) {
      try { el.focus({ preventScroll: true }); if (selStart != null && el.setSelectionRange) el.setSelectionRange(selStart, selEnd); } catch {}
    }
  }
  // Fast-poll the receive address only while the user is actually watching for a
  // payment (wallet screen, Receive tab, online). Idempotent — safe each render.
  wallet.setWatchReceive(ui.screen === 'wallet' && ui.tab === 'receive' && !wallet.offline);
  if (ui.screen === 'wallet') {
    commitAccount(); // entering the wallet (any path) keeps a provisional gift account
    // Remember where we are so a refresh restores it (only meaningful on the wallet).
    try { sessionStorage.setItem(NAV_KEY, JSON.stringify({ tab: ui.tab, txDetail: ui.txDetail })); } catch {}
  }
  syncHistory(); // mirror the current screen into browser history (Back/Forward)
}
wallet.subscribe(render);

// ---- browser-history navigation ------------------------------------------
// Mirror the app's screen position into the browser history so the Back/Forward
// buttons (and Android/system back) move between screens we've actually viewed.
// We snapshot only the navigation-relevant `ui` fields, so incidental re-renders
// (typing, polling, balance updates) don't create history entries.
const NAV_FIELDS = ['screen', 'tab', 'txDetail', 'bump', 'giftsAll', 'giftMode', 'claimStep'];
function navSnapshot() {
  const s = {};
  for (const f of NAV_FIELDS) s[f] = ui[f] ?? null;
  return s;
}
const navSig = (s) => JSON.stringify(s);
let navStack = []; // in-memory mirror of the history entries (to detect an in-app Back)
let navIndex = -1;
let restoringHistory = false; // true while applying a popstate (suppresses pushing)

function syncHistory() {
  if (restoringHistory) return;
  try {
    const snap = navSnapshot();
    const sig = navSig(snap);
    if (navIndex >= 0 && sig === navSig(navStack[navIndex])) return; // no navigation change
    // Every screen change is a new history entry. (We deliberately don't try to
    // detect in-app "back" navigations — an A→B→A pattern is indistinguishable
    // from a genuine back, so guessing corrupts the stack. An in-app back just
    // adds an entry; Back/Forward still walk the screens correctly.)
    navStack = navStack.slice(0, navIndex + 1); // drop any forward entries
    navStack.push(snap);
    navIndex++;
    const entry = { nav: snap, i: navIndex };
    if (navIndex === 0) history.replaceState(entry, '');
    else history.pushState(entry, '');
  } catch {} // history API failures must never break a render
}

window.addEventListener('popstate', (e) => {
  const st = e.state;
  const snap = (st && st.nav) || navSnapshot();
  restoringHistory = true;
  try {
    for (const f of NAV_FIELDS) ui[f] = f in snap ? snap[f] : null;
    if (st && typeof st.i === 'number') navIndex = st.i;
    else { const i = navStack.findIndex((s) => navSig(s) === navSig(snap)); if (i >= 0) navIndex = i; }
    render();
  } finally {
    restoringHistory = false;
  }
});

// In-app "back" buttons call this instead of mutating ui + render() directly, so
// they POP the history entry they're leaving rather than pushing a duplicate.
// When there's no in-app entry to pop (e.g. the page was reloaded straight into a
// sub-screen), fall back to navigating to the explicit parent.
function goBack(toParent) {
  if (navIndex > 0) history.back();
  else { toParent(); render(); }
}

// ---------------------------------------------------------------- utilities
let toastTimer;
function toast(msg) {
  let t = document.querySelector('.toast');
  if (!t) {
    t = h('div', { class: 'toast' });
    document.body.append(t);
  }
  t.textContent = msg;
  requestAnimationFrame(() => t.classList.add('show'));
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 1600);
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = h('textarea', { value: text });
    document.body.append(ta);
    ta.select();
    try {
      document.execCommand('copy');
    } catch {}
    ta.remove();
  }
  toast(t('copied'));
}

// Open a URL in a new window/tab. window.open is more reliable than an
// <a target="_blank"> inside an installed PWA (standalone mode), where the link
// can otherwise navigate the app away instead of opening externally.
function openExternal(url) {
  try { window.open(url, '_blank', 'noopener,noreferrer'); } catch {}
}

function download(filename, text, mime = 'application/json') {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = h('a', { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// --- nostr profiles (avatar + name) — cached, lazily fetched, re-renders ----
const _profileCache = new Map(); // pubkeyHex -> profile | null | 'loading'
function nostrProfile(pkHex) {
  if (_profileCache.has(pkHex)) return _profileCache.get(pkHex);
  _profileCache.set(pkHex, 'loading');
  fetchNostrProfile(pkHex).then((p) => { _profileCache.set(pkHex, p || null); render(); }).catch(() => { _profileCache.set(pkHex, null); render(); });
  return 'loading';
}
// A row showing the recipient's avatar + name (or a shortened npub fallback).
function profileChip(pkHex, { size = 30 } = {}) {
  const p = nostrProfile(pkHex);
  const npub = npubOf(pkHex) || pkHex;
  const short = npub.slice(0, 12) + '…' + npub.slice(-4);
  const avatar = (pic) =>
    pic
      ? h('img', { src: pic, style: `width:${size}px;height:${size}px;border-radius:50%;object-fit:cover;flex:0 0 auto`, onError: (e) => { e.target.style.visibility = 'hidden'; } })
      : h('div', { style: `width:${size}px;height:${size}px;border-radius:50%;background:#9993;flex:0 0 auto` });
  if (p === 'loading') return h('div', { class: 'row gap6', style: 'align-items:center' }, h('span', { class: 'spinner sm' }), h('span', { class: 'small muted' }, short));
  const name = (p && p.name) || short;
  return h('div', { class: 'row gap6', style: 'align-items:center;min-width:0' },
    avatar(p && p.picture),
    h('span', { class: p && p.name ? '' : 'small muted', style: 'overflow:hidden;text-overflow:ellipsis;white-space:nowrap' }, name));
}

function copyBtn(text, label = t('copy')) {
  return h('button', { class: 'btn-sm', onClick: () => copy(text) }, label);
}

// A small "paste from clipboard" button; apply(text) receives the trimmed text.
// Returns null where the Clipboard read API isn't available (the catch keeps it
// silent if a browser blocks the read).
function pasteBtn(apply) {
  if (typeof navigator === 'undefined' || !navigator.clipboard || !navigator.clipboard.readText) return null;
  return h('button', {
    type: 'button', class: 'btn-sm', title: t('paste'),
    onClick: async () => { try { const txt = await navigator.clipboard.readText(); if (txt) apply(txt.trim()); } catch {} },
    html: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/></svg>',
  });
}

// ---------------------------------------------------------------- display unit
// Global BTC/sats preference, persisted in localStorage across refreshes and
// logouts. Every unit label on the site is clickable to toggle it.
const UNIT_KEY = 'btc-wallet-unit';
let unit = (() => {
  // Default to sats for first-time users; only an explicit 'btc' choice sticks.
  try {
    return localStorage.getItem(UNIT_KEY) === 'btc' ? 'btc' : 'sats';
  } catch {
    return 'sats';
  }
})();

function toggleUnit() {
  unit = unit === 'btc' ? 'sats' : 'btc';
  try {
    localStorage.setItem(UNIT_KEY, unit);
  } catch {}
  render();
}

const unitLabel = () => (unit === 'sats' ? 'sats' : 'BTC');
const fmtAmount = (sats) => (unit === 'sats' ? fmtSats(sats) : fmtBtc(sats));

// A clickable unit label. cls lets callers inherit surrounding sizing.
function unitTag(cls = '') {
  return h('button', { type: 'button', class: 'unit-tag ' + cls, title: t('switchUnit'), onClick: toggleUnit }, unitLabel());
}

// ================================================================ UNLOCK
function unlockScreen() {
  return h(
    'div',
    { class: 'col', style: 'gap:16px' },
    brandHeader(false),
    h(
      'div',
      { class: 'card col' },
      h(
        'div',
        { class: 'tabs' },
        tabBtn(t('createNew'), ui.unlockTab === 'create', () => { ui.unlockTab = 'create'; ui.unlockError = ''; render(); }),
        tabBtn(t('importExisting'), ui.unlockTab === 'import', () => { ui.unlockTab = 'import'; ui.unlockError = ''; render(); })
      ),
      ui.unlockTab === 'create' ? createPane() : importPane(),
      ui.unlockError && h('div', { class: 'notice err' }, ui.unlockError)
    ),
    ui.fromWallet && accounts.length
      ? h('button', { class: 'btn-ghost btn-block', onClick: () => { ui.fromWallet = false; ui.screen = 'wallet'; ui.unlockError = ''; render(); } }, t('back'))
      : null
  );
}

// ================================================================ HOW IT WORKS
function howItWorksScreen() {
  const back = () => {
    ui.screen = ui.returnScreen === 'wallet' ? 'wallet' : 'unlock';
    render();
  };
  const para = (key) => h('p', { class: 'muted', style: 'margin:0' }, ...linkify(t(key)));
  return h(
    'div',
    { class: 'col', style: 'gap:16px' },
    brandHeader(false),
    h(
      'div',
      { class: 'card col', style: 'gap:14px' },
      h('h3', {}, t('hiwBasicsTitle')),
      para('hiwBasics1'),
      para('hiwBasics2'),
      para('hiwBasics3'),
      para('hiwBasics4'),
      para('hiwBasics5'),
      h('p', { class: 'small muted hiw-tribute', style: 'margin:0' }, ...linkify(t('hiwTribute')))
    ),
    h('button', { class: 'btn-block', onClick: back }, t('back'))
  );
}

// Turn known tokens (e.g. mempool.space) into links within a plain string,
// returning an array of text + anchor nodes. Keeps i18n strings link-free.
const HIW_LINKS = [
  ['mempool.space', 'https://mempool.space'],
  ['Hal Finney', 'https://en.wikipedia.org/wiki/Hal_Finney_(computer_scientist)'],
];
function linkify(text) {
  const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp('(' + HIW_LINKS.map(([tok]) => esc(tok)).join('|') + ')', 'g');
  const out = [];
  let last = 0;
  let m;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const href = HIW_LINKS.find(([tok]) => tok === m[0])[1];
    out.push(h('a', { href, target: '_blank', rel: 'noopener' }, m[0]));
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

function tabBtn(label, active, onClick) {
  return h('button', { class: active ? 'active' : '', onClick }, label);
}

function createPane() {
  if (ui.createStep === 'gen') {
    if (!ui.draftMnemonic) {
      return h(
        'div',
        { class: 'col' },
        h('p', { class: 'muted' }, t('genIntro')),
        h(
          'button',
          {
            class: 'btn-primary btn-block',
            onClick: () => {
              ui.draftMnemonic = newMnemonic();
              render();
            },
          },
          t('generateSeed')
        )
      );
    }
    const words = ui.draftMnemonic.split(' ');
    return h(
      'div',
      { class: 'col' },
      h('div', { class: 'warn-box' }, t('writeDownWarn')),
      h(
        'div',
        { class: 'words' },
        words.map((w, i) =>
          h('div', { class: 'w' }, h('span', { class: 'n' }, i + 1), h('span', { class: 't' }, w))
        )
      ),
      h(
        'div',
        { class: 'row gap6' },
        copyBtn(ui.draftMnemonic, t('copyPhrase')),
        h(
          'button',
          {
            class: 'btn-ghost btn-sm',
            onClick: () => {
              ui.draftMnemonic = newMnemonic();
              render();
            },
          },
          t('regenerate')
        )
      ),
      optionsPanel(),
      h(
        'button',
        {
          class: 'btn-primary btn-block',
          onClick: () => {
            ui.confirm = pickConfirm(words);
            ui.confirmPass = '';
            ui.unlockError = '';
            ui.createStep = 'confirm';
            render();
          },
        },
        t('verifyBackup')
      ),
      h(
        'button',
        { class: 'btn-block', onClick: () => openWallet(ui.draftMnemonic, { generated: true }) },
        t('skipVerification')
      )
    );
  }

  // confirm step (optional — reachable via "Verify backup")
  const hasPass = !!ui.passphrase;
  return h(
    'div',
    { class: 'col' },
    h('p', { class: 'muted' }, t('confirmBackupIntro')),
    ...ui.confirm.map((c, i) =>
      h(
        'label',
        { class: 'field' },
        h('span', { class: 'lab' }, t('wordN', { n: c.index + 1 })),
        h('input', {
          type: 'text',
          class: 'mono-input',
          autocapitalize: 'none',
          autocomplete: 'off',
          spellcheck: 'false',
          value: c.value,
          onInput: (e) => (ui.confirm[i].value = e.target.value.trim()),
        })
      )
    ),
    // Only verify the passphrase if one was actually entered.
    hasPass &&
      h(
        'label',
        { class: 'field' },
        h('span', { class: 'lab' }, t('reenterPassphrase')),
        h('input', {
          type: 'password',
          class: 'mono-input',
          autocomplete: 'off',
          value: ui.confirmPass,
          onInput: (e) => (ui.confirmPass = e.target.value),
        })
      ),
    h('div', { class: 'row gap6' },
      h('button', { class: 'btn-ghost', onClick: () => { ui.createStep = 'gen'; render(); } }, t('back')),
      h('button', {
        class: 'btn-primary grow',
        onClick: () => {
          const words = ui.draftMnemonic.split(' ');
          const ok = ui.confirm.every((c) => c.value.toLowerCase() === words[c.index]);
          if (!ok) { ui.unlockError = t('wordsMismatch'); render(); return; }
          if (hasPass && ui.confirmPass !== ui.passphrase) {
            ui.unlockError = t('passphraseMismatch'); render(); return;
          }
          openWallet(ui.draftMnemonic, { generated: true });
        },
      }, t('openWallet'))
    ),
    h('button', { class: 'btn-block', onClick: () => openWallet(ui.draftMnemonic, { generated: true }) }, t('skipVerification'))
  );
}

function pickConfirm(words) {
  const idx = new Set();
  while (idx.size < 3) idx.add(Math.floor(Math.random() * words.length));
  return [...idx].sort((a, b) => a - b).map((index) => ({ index, value: '' }));
}

function importPane() {
  const ta = h('textarea', {
    placeholder: t('importPlaceholder'),
    autocapitalize: 'none',
    autocomplete: 'off',
    spellcheck: 'false',
    value: ui.importText,
    onInput: (e) => (ui.importText = e.target.value),
  });
  return h(
    'div',
    { class: 'col' },
    h(
      'label',
      { class: 'field' },
      h('div', { class: 'row between' },
        h('span', { class: 'lab' }, t('importLabel')),
        pasteBtn((text) => { ta.value = text; ui.importText = text; })
      ),
      ta
    ),
    optionsPanel(),
    h('button', { class: 'btn-primary btn-block', onClick: () => openWallet(ui.importText) }, t('openWallet'))
  );
}

function optionsPanel() {
  return h(
    'label',
    { class: 'field' },
    h('span', { class: 'lab' }, t('passphrase')),
    h(
      'div',
      { class: 'input-group' },
      h('input', {
        type: ui.showPass ? 'text' : 'password',
        class: 'mono-input',
        autocomplete: 'off',
        value: ui.passphrase,
        onInput: (e) => (ui.passphrase = e.target.value),
      }),
      h('button', { class: 'btn-sm', type: 'button', onClick: () => { ui.showPass = !ui.showPass; render(); } }, ui.showPass ? t('hide') : t('show'))
    )
  );
}

// Import accepts a recovery phrase, an xpub/zpub (watch-only), or an xprv/zprv
// (full spending). Classify the pasted text and open the right kind of wallet.
async function openWallet(input, opts = {}) {
  ui.unlockError = '';
  const raw = (input || '').trim();
  const m = raw.replace(/\s+/g, ' ');
  if (isValidMnemonic(m)) { await enterWallet(m, ui.passphrase, { generated: opts.generated }); ui.draftMnemonic = ''; return; } // discard the used draft so the next "Add wallet" generates a fresh seed
  let pk;
  try { pk = parseExtendedKey(raw); } catch { ui.unlockError = t('invalidImport'); render(); return; }
  const acc = pk.kind === 'xpub'
    ? addOrGetAccount({ type: 'watch', label: defaultLabel('watch'), xpub: pk.key })
    : addOrGetAccount({ type: 'full', label: defaultLabel('full'), xprv: pk.key });
  ui.fromWallet = false;
  await activateAccount(acc, { fresh: true });
}

// Register a full (seed) wallet as an account and open it.
async function enterWallet(mnemonic, passphrase, opts = {}) {
  const acc = addOrGetAccount({
    type: 'full',
    label: defaultLabel('full'),
    mnemonic: (mnemonic || '').trim().replace(/\s+/g, ' '),
    passphrase: passphrase || '',
  });
  await activateAccount(acc, { ...opts, fresh: true });
}

// Load an account into the wallet and start scanning. Full-account seeds are
// kept in sessionStorage (ephemeral); a refresh restores the open account.
async function activateAccount(acc, opts = {}) {
  activeId = acc.id;
  // A gift link generates this wallet only to claim into. Keep it provisional
  // until the user commits (claims, or chooses to keep it / enters the wallet),
  // so bailing from an already-claimed gift doesn't leave an empty account.
  if (opts.gift && !opts.existingClaim) acc.provisional = true;
  const netName = getNetwork();
  if (acc.type === 'watch') wallet.load({ xpub: acc.xpub, netName, offline: false });
  else if (acc.xprv) wallet.load({ xprv: acc.xprv, netName, offline: false });
  else wallet.load({ mnemonic: acc.mnemonic, passphrase: acc.passphrase || '', netName, offline: false, spFresh: !!opts.generated });
  // Record the account-level xpub so this wallet survives a session wipe as a
  // watch-only entry (see the durable account directory) — you keep seeing your
  // balance/history and re-enter the seed to spend again.
  if (acc.type !== 'watch' && !acc.provisional) acc.xpub = wallet.accountXpub();
  persistAccounts();
  swaps.network = getNetwork();
  if (!wallet.watchOnly) { try { swaps.resumeAll(); } catch {} } // re-attach in-flight swap watchers
  initArk(); // connect to the Ark server (no-op when Ark is off in Settings)
  const hadCache = wallet.restoreCache(); // show last-known balance/history instantly
  // An opened gift link starts on a claim/back-up screen instead of the wallet.
  ui.screen = opts.gift ? 'claim' : 'wallet';
  ui.claimStep = 'welcome';
  ui.claimCode = opts.gift || null;
  ui.claimError = '';
  ui.claimTaken = null;
  ui.claimChecking = !!opts.gift; // gate the Claim button until we've checked
  // Restore the tab / open tx from the last session so a refresh keeps the
  // user's place. A gift link always opens the claim screen instead.
  const nav = (() => { try { return JSON.parse(sessionStorage.getItem(NAV_KEY) || 'null'); } catch { return null; } })();
  ui.tab = (!opts.gift && nav && nav.tab) || 'receive';
  ui.txDetail = (!opts.gift && nav && nav.txDetail) || null;
  // Not baselined yet — stays null until the scan + ack logic below sets it,
  // so the celebration never fires for payments that were already there at
  // import (the index only looks "advanced" because the scan hadn't run yet).
  ui.receiveSeenIndex = null;
  ui.send = blankSend();
  ui.draft = null;
  ui.sendResult = null;
  ui.giftMode = false;
  ui.offlineFallback = false;
  render();
  if (ui.txDetail) openTx(ui.txDetail); // restored a tx detail — fill in fee/details if missing

  // No manual offline switch: try to scan, and if the network is unreachable,
  // fall back to offline mode automatically.
  if (typeof navigator !== 'undefined' && navigator.onLine === false) {
    enterOfflineFallback();
    return;
  }
  try {
    // Celebration baseline. Opening/importing/switching a wallet (opts.fresh)
    // baselines to the current frontier, so payments already received before
    // opening never trigger the "payment received" screen. On a same-session
    // refresh we restore the persisted ack — which is advanced the moment the
    // celebration is shown, so a payment celebrates once and never reappears.
    let ack;
    if (opts.fresh) {
      ack = wallet.nextReceiveIndex;
      wallet.setReceiveAck(ack);
    } else {
      ack = wallet.getReceiveAck();
      if (ack == null) {
        ack = wallet.nextReceiveIndex;
        wallet.setReceiveAck(ack);
      }
    }
    // For a fresh open, leave receiveSeenIndex null until the post-scan baseline
    // below. Setting it now (to the pre-scan frontier) lets the socket's reconcile
    // credit a deposit that predates this open and briefly flash the "payment
    // received" screen before the baseline catches up. A same-session refresh
    // uses the persisted ack right away.
    if (!opts.fresh) ui.receiveSeenIndex = ack;

    // Go Live immediately: the socket must not wait on Nostr (up to 6s) or any
    // discovery scan. The cache/Nostr state is already on screen.
    wallet.startRealtime();

    // Opened a gift link? Verify its funding coin is still unspent before letting
    // the claim proceed — so a second opener can't try to race/double-spend.
    if (opts.gift) checkGiftClaimed(opts.gift);

    // Cross-device state in the background. State comes from the local cache or
    // Nostr — both restore the full balance, coins, and history — so a full API
    // scan runs ONLY when we have neither (e.g. a seed imported on a fresh device
    // with no synced state); that's what discovers the used addresses. Otherwise
    // the socket + frontier poll keep us current with no refresh-time burst.
    const hadNostr = wallet.watchOnly ? false : await wallet.syncFromNostr();
    if (!hadCache && !hadNostr) {
      await wallet.scan({ silent: false });
    }
    // Re-baseline a fresh open against the final frontier (Nostr or the discovery
    // scan may have advanced it) so payments that predate the open don't celebrate.
    if (opts.fresh) { ack = wallet.nextReceiveIndex; wallet.setReceiveAck(ack); ui.receiveSeenIndex = ack; }
    wallet.retrack(); // re-subscribe to the latest frontier (Nostr/scan may have moved it)
  } catch {
    enterOfflineFallback();
  }
}

// --- accounts -------------------------------------------------------------
// The working set of wallets you can switch between. Full (seed-bearing)
// accounts live only in sessionStorage — ephemeral, wiped when the browser
// closes (no seed on disk by default). Watch-only accounts hold just an xpub,
// so they're additionally persisted in localStorage and reload across restarts.
const ACCOUNTS_KEY = 'btc-wallet-accounts'; // sessionStorage: session list + active
const WATCH_KEY = 'btc-wallet-watch'; // localStorage: persisted watch-only accounts

let accounts = [];
let activeId = null;

const genId = () => 'a' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
const credId = (a) => (a.type === 'watch' ? 'w:' + a.xpub : a.xprv ? 'x:' + a.xprv : 'f:' + a.mnemonic + '|' + (a.passphrase || ''));
const activeAccount = () => accounts.find((a) => a.id === activeId) || null;

function defaultLabel(type) {
  const n = accounts.filter((a) => a.type === type).length + 1;
  return t(type === 'watch' ? 'watchLabelN' : 'walletLabelN', { n });
}

// The durable account directory (localStorage): a view-only mirror of every
// account — id, label, and account xpub, never a seed. So a wallet survives a
// session wipe (browser closed without "Save to device") as a watch-only entry:
// you keep seeing balance/history and re-enter the seed to spend again.
function loadWatchAccounts() {
  try {
    const dir = JSON.parse(localStorage.getItem(WATCH_KEY) || '[]');
    return dir.filter((d) => d.xpub).map((d) => ({ id: d.id, label: d.label, type: 'watch', xpub: d.xpub, autoLock: d.autoLock || 0 }));
  } catch { return []; }
}
function saveDirectory() {
  try {
    const dir = accounts.filter((a) => a.xpub && !a.provisional).map((a) => ({ id: a.id, label: a.label, xpub: a.xpub, autoLock: a.autoLock || 0 }));
    localStorage.setItem(WATCH_KEY, JSON.stringify(dir));
  } catch {}
}
function persistAccounts() {
  try { sessionStorage.setItem(ACCOUNTS_KEY, JSON.stringify({ accounts, activeId })); } catch {}
  saveDirectory();
}
function clearAccounts() {
  accounts = [];
  activeId = null;
  try { sessionStorage.removeItem(ACCOUNTS_KEY); } catch {}
}

// Add an account (deduped by credential), returning the stored object.
function addOrGetAccount(partial) {
  const cid = credId(partial);
  let acc = accounts.find((a) => credId(a) === cid);
  if (!acc) {
    acc = { id: genId(), ...partial };
    accounts.push(acc);
    persistAccounts();
  }
  return acc;
}

// Commit the active account — clear the "provisional" gift flag so it's no
// longer discarded on bail. Called once the user claims, keeps, or enters it.
function commitAccount() {
  const a = accounts.find((x) => x.id === activeId);
  if (a && a.provisional) {
    delete a.provisional;
    if (a.type !== 'watch') a.xpub = wallet.accountXpub(); // now eligible for the durable directory
    persistAccounts();
  }
}

function removeAccount(id) {
  const acc = accounts.find((a) => a.id === id);
  if (!acc) return;
  accounts = accounts.filter((a) => a.id !== id);
  persistAccounts();
  if (activeId === id) {
    if (accounts.length) activateAccount(accounts[0], { fresh: true });
    else lock();
  } else {
    render();
  }
}

function switchAccount(id) {
  const acc = accounts.find((a) => a.id === id);
  if (acc) activateAccount(acc, { fresh: true });
}

// Restore accounts after a refresh (sessionStorage); on a fresh session, prompt
// to unlock the encrypted vault if there is one, else seed from watch-only
// accounts. Returns true if it handled the entry (opened or showed a prompt).
function restoreAccountsState() {
  let sess = null;
  try { sess = JSON.parse(sessionStorage.getItem(ACCOUNTS_KEY) || 'null'); } catch {}
  if (sess && Array.isArray(sess.accounts) && sess.accounts.length) {
    accounts = sess.accounts;
    const active = accounts.find((a) => a.id === sess.activeId) || accounts[0];
    activateAccount(active);
    return true;
  }
  if (hasVault()) {
    // A blank (optional) vault password unlocks seamlessly with no prompt.
    if (attemptVaultUnlock('')) {
      if (accounts.length) activateAccount(accounts[0], { fresh: true });
      else { ui.screen = 'unlock'; render(); }
      return true;
    }
    ui.screen = 'vault'; render(); return true;
  }
  const watch = loadWatchAccounts();
  if (watch.length) {
    accounts = watch.slice();
    activateAccount(accounts[0], { fresh: true });
    return true;
  }
  return false;
}

// --- encrypted vault (optional password-persisted full accounts) ----------
const VAULT_KEY = 'btc-wallet-vault';
let vaultPassword = null; // in memory once unlocked/set this session; cleared on lock

function loadVaultBlob() {
  try { return JSON.parse(localStorage.getItem(VAULT_KEY) || 'null'); } catch { return null; }
}
function hasVault() { return !!loadVaultBlob(); }

// Re-encrypt the vault from the currently-persisted full accounts (needs the
// in-memory password). Removes the blob when nothing is persisted.
function writeVault() {
  if (vaultPassword == null) return;
  const list = accounts.filter((a) => a.type === 'full' && a.persisted)
    .map((a) => (a.xprv ? { label: a.label, xprv: a.xprv } : { label: a.label, mnemonic: a.mnemonic, passphrase: a.passphrase || '' }));
  try {
    if (!list.length) localStorage.removeItem(VAULT_KEY);
    else localStorage.setItem(VAULT_KEY, JSON.stringify(encryptVault(list, vaultPassword)));
  } catch {}
}

// Bring vault-saved seeds into the session. Each upgrades the matching watch-only
// directory entry (by xpub) to a spendable full account so wallets aren't
// duplicated; one with no directory entry is added fresh.
function mergeVaultList(list) {
  for (const v of list) {
    const xpub = v.xprv ? accountXpubFor({ xprv: v.xprv }) : accountXpubFor({ mnemonic: v.mnemonic, passphrase: v.passphrase || '' });
    const existing = accounts.find((a) => a.xpub === xpub);
    if (existing) {
      existing.type = 'full';
      if (v.xprv) { existing.xprv = v.xprv; delete existing.mnemonic; delete existing.passphrase; }
      else { existing.mnemonic = v.mnemonic; existing.passphrase = v.passphrase || ''; delete existing.xprv; }
      if (v.label) existing.label = v.label;
      existing.persisted = true;
    } else {
      const acc = addOrGetAccount(
        v.xprv
          ? { type: 'full', label: v.label || defaultLabel('full'), xprv: v.xprv, xpub }
          : { type: 'full', label: v.label || defaultLabel('full'), mnemonic: v.mnemonic, passphrase: v.passphrase || '', xpub }
      );
      acc.persisted = true;
    }
  }
}

// Toggle persistence on a full account. Prompts for the vault password when it
// isn't unlocked this session ('set' the first time, 'enter' if a vault exists).
function startSave(id) {
  const acc = accounts.find((a) => a.id === id);
  if (!acc || acc.type !== 'full') return;
  if (vaultPassword != null) { acc.persisted = true; writeVault(); persistAccounts(); render(); return; }
  ui.pw = { purpose: 'save', accId: id, mode: hasVault() ? 'enter' : 'set', v1: '', v2: '', error: '' };
  render();
}
// --- load a seed into a watch-only account (make it spendable) --------------
function startLoadSeed(opts = {}) {
  // accId lets the per-wallet settings page import a seed for a specific
  // (possibly non-active) watch-only wallet; defaults to the active one.
  ui.loadSeed = { value: '', passphrase: '', save: !!opts.save, error: '', accId: opts.accId || activeId };
  render();
}
function cancelLoadSeed() { ui.loadSeed = null; render(); }
async function doLoadSeed() {
  const ls = ui.loadSeed;
  const acc = (ls && accounts.find((a) => a.id === ls.accId)) || activeAccount();
  if (!ls || !acc || !acc.xpub) return;
  const raw = (ls.value || '').trim().replace(/\s+/g, ' ');
  if (!raw) { ls.error = t('enterSeedToSpend'); render(); return; }
  let next = null;
  try {
    if (isValidMnemonic(raw)) {
      if (accountXpubFor({ mnemonic: raw, passphrase: ls.passphrase || '' }) !== acc.xpub) { ls.error = t('seedMismatch'); render(); return; }
      next = { mnemonic: raw, passphrase: ls.passphrase || '' };
    } else {
      const pk = parseExtendedKey(raw); // throws if not an extended key
      if (pk.kind !== 'xprv') { ls.error = t('seedNeedsPrivate'); render(); return; }
      if (accountXpubFor({ xprv: pk.key }) !== acc.xpub) { ls.error = t('seedMismatch'); render(); return; }
      next = { xprv: pk.key };
    }
  } catch { ls.error = t('seedInvalid'); render(); return; }
  // Upgrade in place — keep id/label/xpub so the cache, directory entry and
  // history all carry over; the account is now spendable.
  acc.type = 'full';
  if (next.mnemonic) { acc.mnemonic = next.mnemonic; acc.passphrase = next.passphrase; delete acc.xprv; }
  else { acc.xprv = next.xprv; delete acc.mnemonic; delete acc.passphrase; }
  const save = ls.save;
  ui.loadSeed = null;
  await activateAccount(acc, { fresh: false });
  if (save) startSave(acc.id); // opens the Save-to-device (vault) flow
  else render();
}

function startForget(id) {
  if (vaultPassword != null) {
    const acc = accounts.find((a) => a.id === id);
    if (acc) acc.persisted = false;
    writeVault(); persistAccounts(); render();
    return;
  }
  ui.pw = { purpose: 'forget', accId: id, mode: 'enter', v1: '', v2: '', error: '' };
  render();
}
function cancelPw() { ui.pw = null; render(); }
function startChangePw() {
  ui.pw = { purpose: 'change', mode: 'change', v0: '', v1: '', v2: '', error: '' };
  render();
}
function submitPw() {
  const p = ui.pw;
  if (p.purpose === 'change') {
    // Re-encrypt the actual vault (decrypt with the current password, encrypt
    // with the new one) so we never drop wallets that aren't in this session.
    let list;
    try { list = decryptVault(loadVaultBlob(), p.v0 || ''); } catch { p.error = t('pwWrong'); render(); return; }
    if (p.v1 !== p.v2) { p.error = t('pwMismatch'); render(); return; }
    try { localStorage.setItem(VAULT_KEY, JSON.stringify(encryptVault(list, p.v1 || ''))); } catch {}
    if (vaultPassword != null) vaultPassword = p.v1 || ''; // keep the unlocked session in sync
    ui.pw = null;
    render();
    toast(t('pwChanged'));
    return;
  }
  if (p.mode === 'set') {
    // Password is optional — a blank one just persists without protection.
    if (p.v1 !== p.v2) { p.error = t('pwMismatch'); render(); return; }
    vaultPassword = p.v1 || '';
  } else {
    let list;
    try { list = decryptVault(loadVaultBlob(), p.v1); } catch { p.error = t('pwWrong'); render(); return; }
    vaultPassword = p.v1;
    mergeVaultList(list); // bring existing persisted accounts into the session
  }
  const acc = accounts.find((a) => a.id === p.accId);
  if (acc) acc.persisted = p.purpose === 'save';
  writeVault();
  persistAccounts();
  ui.pw = null;
  render();
}

// Try to decrypt the vault with the given password; on success, seed the
// accounts (watch-only directory + the unlocked full wallets). Returns success.
function attemptVaultUnlock(password) {
  let list;
  try { list = decryptVault(loadVaultBlob(), password); } catch { return false; }
  vaultPassword = password;
  // Start from the durable directory (watch-only views of every known wallet),
  // then upgrade the vault-saved ones to spendable — so non-saved wallets still
  // appear (watch-only) instead of vanishing.
  accounts = loadWatchAccounts();
  mergeVaultList(list);
  // Now that we have the password, finish signing out any saved wallets whose
  // timer expired while we were away (couldn't re-encrypt the vault until now).
  if (_bootAwayMs) {
    const due = accounts.filter((a) => accAutoLock(a) > 0 && _bootAwayMs >= accAutoLock(a));
    for (const a of due) { wipeAccountCache(a); accounts = accounts.filter((x) => x.id !== a.id); }
    if (due.some((a) => a.persisted)) writeVault();
    _bootAwayMs = 0;
  }
  return true;
}

// On-open vault unlock (password prompt).
function unlockVault() {
  if (!attemptVaultUnlock(ui.vaultPw)) { ui.vaultError = t('pwWrong'); render(); return; }
  ui.vaultPw = '';
  ui.vaultError = '';
  if (accounts.length) activateAccount(accounts[0], { fresh: true });
  else lock(); // everything got signed out by the timer
}
function skipVault() {
  ui.vaultPw = '';
  ui.vaultError = '';
  const watch = loadWatchAccounts();
  if (watch.length) { accounts = watch.slice(); activateAccount(accounts[0], { fresh: true }); }
  else { ui.screen = 'unlock'; render(); }
}

function enterOfflineFallback() {
  wallet.setOffline(true);
  wallet.deriveWindow(40);
  ui.offlineFallback = true;
  ui.claimChecking = false; // can't verify a gift offline; don't hang on the loader
  ui.tab = 'settings';
  render();
}

async function retryOnline() {
  ui.offlineFallback = false;
  wallet.setOffline(false);
  ui.tab = 'receive';
  render();
  try {
    await wallet.scan();
    wallet.startRealtime();
  } catch {
    enterOfflineFallback();
  }
}

// --- auto log-out, per wallet ----------------------------------------------
// Each account can choose how long the app may sit in the background before that
// wallet is signed out (removed from this device — session, directory, cache,
// and its vault entry). Other wallets are untouched. The countdown only runs
// while the app is hidden/unfocused, never while you're looking at it. 0 = never.
const AUTOLOCK_OPTIONS = [
  { ms: 0, label: 'autolockNever' },
  { ms: 60_000, label: 'autolock1m' },
  { ms: 300_000, label: 'autolock5m' },
  { ms: 3_600_000, label: 'autolock1h' },
  { ms: 86_400_000, label: 'autolock1d' },
];
const accAutoLock = (a) => (a && Number(a.autoLock)) || 0;

const AWAY_AT_KEY = 'btc-wallet-bg-at';
let _awayTimer = null;
let _bootAwayMs = 0; // away duration carried into the vault-unlock check this session
const _awayAt = () => { try { return Number(localStorage.getItem(AWAY_AT_KEY)) || 0; } catch { return 0; } };
const _clearAwayAt = () => { try { localStorage.removeItem(AWAY_AT_KEY); } catch {} };

// Remove one wallet's cached state — the xpub mirror plus its seed-keyed cache
// (when the seed is at hand), including the :ack/:gift suffixes.
function wipeAccountCache(acc) {
  if (!acc) return;
  const ids = [];
  if (acc.xpub) ids.push(acc.xpub);
  if (acc.xprv) ids.push(acc.xprv);
  else if (acc.mnemonic) ids.push(`${acc.mnemonic}\n${acc.passphrase || ''}`);
  const bases = ids.map(cacheKeyFor);
  try {
    const keys = [];
    for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); if (k && bases.some((b) => k.startsWith(b))) keys.push(k); }
    keys.forEach((k) => localStorage.removeItem(k));
  } catch {}
}

// Sign out a single wallet: remove it from the device entirely (session,
// directory, cache, and the vault if it was saved). Others are left alone.
function wipeAccount(id) {
  const acc = accounts.find((a) => a.id === id);
  if (!acc) return;
  const wasActive = activeId === id;
  wipeAccountCache(acc);
  const wasPersisted = acc.persisted;
  accounts = accounts.filter((a) => a.id !== id);
  if (wasPersisted && vaultPassword != null) writeVault(); // re-encrypt the vault without it
  persistAccounts(); // refresh the durable directory
  if (wasActive) {
    if (accounts.length) activateAccount(accounts[0], { fresh: true });
    else lock();
  }
}

// Sign out every loaded wallet whose timer has elapsed for the given away time.
function evaluateOverdue(away) {
  const due = accounts.filter((a) => accAutoLock(a) > 0 && away >= accAutoLock(a)).map((a) => a.id);
  for (const id of due) wipeAccount(id);
}

// Arm a timer for the soonest-due wallet so a blurred-but-visible window still
// signs out on time (the timestamp covers throttled/backgrounded tabs).
function armAwayTimer() {
  clearTimeout(_awayTimer); _awayTimer = null;
  const awayAt = _awayAt();
  if (!awayAt) return;
  const locks = accounts.map(accAutoLock).filter((ms) => ms > 0);
  if (!locks.length) return;
  const elapsed = Date.now() - awayAt;
  if (locks.some((ms) => elapsed >= ms)) { evaluateOverdue(elapsed); armAwayTimer(); return; }
  const next = Math.min(...locks.map((ms) => ms - elapsed));
  _awayTimer = setTimeout(() => { evaluateOverdue(Date.now() - awayAt); armAwayTimer(); }, Math.max(0, next));
}

function onAppHidden() {
  try { localStorage.setItem(AWAY_AT_KEY, String(Date.now())); } catch {}
  armAwayTimer();
}
function onAppVisible() {
  clearTimeout(_awayTimer); _awayTimer = null;
  const awayAt = _awayAt(); _clearAwayAt();
  if (awayAt) evaluateOverdue(Date.now() - awayAt);
}

// At boot the in-memory timer is gone (reload / discarded tab). Drop overdue
// wallets from the persisted session and directory before anything is restored;
// overdue saved wallets are removed from the vault when it's unlocked.
function applyBootAutoLogout() {
  const awayAt = _awayAt(); _clearAwayAt();
  if (!awayAt) return;
  const away = Date.now() - awayAt;
  _bootAwayMs = away;
  const overdue = (a) => { const ms = Number(a.autoLock) || 0; return ms > 0 && away >= ms; };
  try {
    const sess = JSON.parse(sessionStorage.getItem(ACCOUNTS_KEY) || 'null');
    if (sess && Array.isArray(sess.accounts)) {
      const keep = sess.accounts.filter((a) => { if (overdue(a)) { wipeAccountCache(a); return false; } return true; });
      sess.accounts = keep;
      if (!keep.find((a) => a.id === sess.activeId)) sess.activeId = keep[0] ? keep[0].id : null;
      sessionStorage.setItem(ACCOUNTS_KEY, JSON.stringify(sess));
    }
  } catch {}
  try {
    const dir = JSON.parse(localStorage.getItem(WATCH_KEY) || '[]');
    const keep = dir.filter((d) => { if (overdue(d)) { wipeAccountCache(d); return false; } return true; });
    localStorage.setItem(WATCH_KEY, JSON.stringify(keep));
  } catch {}
}

function lock() {
  wallet.stopRealtime();
  clearAccounts();
  vaultPassword = null;
  wallet.load({ mnemonic: '', passphrase: '', netName: getNetwork(), offline: false });
  wallet.mnemonic = '';
  ui.screen = hasVault() ? 'vault' : 'unlock';
  ui.unlockTab = 'create';
  ui.fromWallet = false;
  ui.watchXpub = '';
  ui.watchLabel = '';
  ui.pw = null;
  ui.vaultPw = '';
  ui.vaultError = '';
  ui.confirmClear = false;
  ui.confirmRemove = null;
  ui.editId = null;
  ui.editLabel = '';
  ui.createStep = 'gen';
  ui.draftMnemonic = '';
  ui.importText = '';
  ui.passphrase = '';
  ui.confirm = [];
  ui.revealShown = false;
  ui.pubkeyShown = false;
  ui.giftMode = false;
  ui.giftAmount = '';
  ui.giftCode = null;
  ui.giftError = '';
  ui.giftMax = false;
  ui.giftSplitOffer = null;
  ui.revokeId = null;
  ui.receiveSeenIndex = null;
  ui.txDetail = null;
  ui.broadcastTx = null;
  ui.bump = null;
  render();
}

// ================================================================ WALLET
function brandHeader(withLock) {
  const acc = activeAccount();
  return h(
    'div',
    { class: 'row between' },
    h(
      'div',
      { class: 'brand', style: 'cursor:pointer', title: t('home'), onClick: goHome },
      h('div', { class: 'logo' }, '₿'),
      h('h1', {}, t('appTitle'))
    ),
    withLock &&
      h('button', { class: 'btn-sm', onClick: () => { ui.screen = 'accounts'; render(); } },
        acc ? acc.label : t('accounts'))
  );
}

// Settings tab — view the recovery phrase (+ passphrase) again (important for
// users who skipped backup verification) and the offline snapshot transfer.
// The phrase is gated: the real words are never put in the DOM until "Reveal",
// so the warning is read first.
// Rescan a single address on demand — recovers a deposit to a reused old
// address without a full wallet rescan. Multiple can be queued at once; the
// API layer's global scheduler serializes and spaces the underlying requests
// (and backs off on 429), so a flurry of clicks stays within the rate limit.
async function doRescanAddress(chain, index) {
  if (wallet.offline) { toast(t('scanOffline')); return; }
  const id = chain + '/' + index;
  if (ui.rescanning.has(id)) return; // already queued
  ui.rescanning.add(id);
  render();
  try {
    await wallet.rescanAddress(chain, index);
  } catch (e) {
    toast(e.message || t('rescanFailed'));
  }
  ui.rescanning.delete(id);
  render();
}

// Paginated list of every known address, each with its own rescan button.
function addressScanView() {
  const addrs = wallet.knownAddresses();
  const pages = Math.ceil(addrs.length / PAGE_SIZE) || 1;
  const page = Math.min(ui.addrScanPage, pages - 1);
  const slice = addrs.slice(page * PAGE_SIZE, page * PAGE_SIZE + PAGE_SIZE);
  return h(
    'div',
    { class: 'col', style: 'gap:16px' },
    h('div', { class: 'card col', style: 'gap:12px' },
      h('div', { class: 'row between' },
        h('h3', { style: 'margin:0' }, t('rescanAddresses')),
        h('button', { class: 'btn-sm', onClick: () => { ui.addrScan = false; render(); } }, t('back'))
      ),
      h('p', { class: 'small muted', style: 'margin:0' }, t('rescanAddrDesc')),
      h('div', { class: 'list' },
        ...slice.map((a) => {
          const id = a.chain + '/' + a.index;
          const busy = ui.rescanning.has(id);
          return h('div', { class: 'item' },
            h('div', { class: 'grow' },
              h('div', { class: 'mono small break' }, shortAddr(a.address, 16, 10),
                a.used ? null : h('span', { class: 'badge off dot', style: 'font-size:10px;margin-left:6px;padding:1px 7px' }, t('unusedTag'))),
              h('div', { class: 'path' }, `${a.chain}/${a.index}` + (a.balance ? ' · ' + fmtAmount(a.balance) + ' ' + unitLabel() : ''))
            ),
            busy
              ? h('button', { class: 'btn-sm', disabled: true }, h('span', { class: 'spinner sm' }))
              : h('button', { class: 'btn-sm', onClick: () => doRescanAddress(a.chain, a.index) }, t('rescanOne'))
          );
        })
      ),
      pager(page, addrs.length, (p) => { ui.addrScanPage = p; render(); })
    )
  );
}

function settingsTab() {
  if (ui.addrScan && !wallet.offline) return addressScanView();
  return h(
    'div',
    { class: 'col', style: 'gap:16px' },
    // Quick link to the active wallet's own settings (name, seed, pubkey, auto-logout).
    activeAccount()
      ? h('div', { class: 'card col' },
          h('h3', {}, activeAccount().label),
          h('p', { class: 'small muted', style: 'margin:0' }, t('walletSettingsDesc')),
          h('button', { class: 'btn-primary btn-block', onClick: () => openAccountSettings(activeId) }, '⚙ ' + t('walletSettings'))
        )
      : null,
    // Recovery phrase + public key live on each wallet's own settings page now
    // (Accounts → ⚙). Watch-only wallets can still add their seed here.
    wallet.watchOnly
      ? (ui.loadSeed
          ? loadSeedCard()
          : h('div', { class: 'card col' },
              h('h3', {}, t('watchOnly')),
              h('p', { class: 'small muted', style: 'margin:0' }, t('watchOnlyNote')),
              activeAccount() && activeAccount().xpub
                ? h('button', { class: 'btn-primary btn-block', style: 'margin-top:4px', onClick: () => startLoadSeed() }, t('loadSeedBtn'))
                : null
            ))
      : null,
    wallet.watchOnly
      ? null
      : h(
          'div',
          { class: 'card col' },
          h('h3', {}, t('offlineTransfer')),
          snapshotActions()
        ),
    h(
      'div',
      { class: 'card col' },
      h('h3', {}, t('rescan')),
      h('p', { class: 'small muted', style: 'margin:0' }, t('rescanDesc')),
      wallet.offline
        ? null
        : h('button', { onClick: () => { ui.addrScan = true; ui.addrScanPage = 0; render(); } }, t('rescanAddresses'))
    ),
    networkCard(),
    boltzProviderCard(),
    arkCard(),
    consolidateCard(),
    explorerCard(),
    spIndexerCard(),
    wallet.watchOnly || !wallet.mnemonic ? null : syncCard()
  );
}

// Merge many small coins into one. Useful after lots of small receives/gifts —
// keeps future sends/gifts to a single input (cheaper, smaller gift QR).
function consolidateCard() {
  if (wallet.watchOnly) return null;
  const n = wallet.spendableCoinCount ? wallet.spendableCoinCount() : 0;
  if (n < 2) return null;
  return h('div', { class: 'card col' },
    h('h3', {}, t('consolidateTitle')),
    h('p', { class: 'small muted', style: 'margin:0' }, t('consolidateDesc', { n })),
    ui.consolidateError && h('div', { class: 'notice err' }, ui.consolidateError),
    h('button', { class: 'btn-block', disabled: ui.busy || wallet.offline, onClick: doConsolidate }, ui.busy ? h('span', { class: 'spinner' }) : t('consolidateAction', { n })));
}
async function doConsolidate() {
  if (wallet.offline) { ui.consolidateError = t('scanOffline'); render(); return; }
  ui.busy = true; ui.consolidateError = ''; render();
  try {
    const rate = (wallet.feeRates && wallet.feeRates.halfHourFee) || 5;
    await wallet.consolidate(rate);
    toast(t('consolidateDone'));
    wallet.scan().catch(() => {});
  } catch (e) {
    ui.consolidateError = e.message || t('consolidateFailed');
  }
  ui.busy = false;
  render();
}


// Gift link: presign a chosen amount as a #gift= PSBT that whoever opens claims
// into a fresh wallet only they control. The coin is reserved until claimed.
function giftUrl() {
  return `${location.origin}/${ui.giftLocked ? 'lg' : 'g'}/${ui.giftCode}`;
}
function giftRate() {
  return (wallet.feeRates && wallet.feeRates.halfHourFee) || 5;
}
function createGiftLink() {
  const rate = giftRate();
  if (ui.giftMax) { doCreateGiftAll(rate); return; }
  const min = giftMinimum(rate);
  const amt = parseAmount(ui.giftAmount, unit); // entered in the current display unit
  if (!amt || amt < min) { ui.giftError = t('giftAmountInvalid', { n: fmtAmount(min) + ' ' + unitLabel() }); render(); return; }
  const spendable = wallet.spendable;
  if (amt > spendable) { ui.giftError = t('giftExceedsBalance'); render(); return; }
  // A specific-amount gift must leave us a dust change output (the gift PSBT
  // commits one). If the amount is so close to the balance that no dust change
  // is possible, point the user at Max to gift the whole balance instead.
  const summary = wallet.giftCoinSummary(amt);
  if (summary == null) {
    ui.giftError = t('giftNeedsHeadroom', { n: fmtAmount(Math.max(0, spendable - 294)) + ' ' + unitLabel() });
    render();
    return;
  }
  const lock = summary.lock;
  // Offer to split/consolidate into one coin first when it would free meaningful
  // change OR when the gift would otherwise bundle several coins — a many-input
  // gift is costly to claim (each input adds to the claimer's fee) and its link
  // can outgrow a QR. Splitting absorbs the fragmentation into the funding tx and
  // leaves the claimer a clean single-input gift.
  const splitFee = Math.ceil((11 + 68 + 31 * 2) * Math.max(1, Math.round(rate)));
  const freed = lock - amt - 294;
  if ((freed > splitFee || summary.count >= 3) && !wallet.offline) {
    ui.giftSplitOffer = { amt, lock, freed: Math.max(0, freed), fee: splitFee, count: summary.count };
    ui.giftError = '';
    render();
    return;
  }
  doCreateGift(amt, rate);
}
// Finalize a freshly-built gift. With a recipient npub it's a locked gift: the
// claim payload is encrypted under a one-time code, the link carries only the
// ciphertext, and the code is DM'd to the recipient over nostr. Without, it's a
// plain bearer gift.
function finishGift(g, fallbackAmt) {
  const amount = g.amount || fallbackAmt || 0;
  const pk = ui.giftLockNpub.trim() ? parseNostrPubkey(ui.giftLockNpub) : null;
  if (!pk) {
    ui.giftCode = g.code; ui.giftLocked = false; ui.giftClaimCode = null; ui.giftDmStatus = null;
    wallet.recordGift({ code: g.code, locked: false, amount, outpoints: g.reserved });
    return;
  }
  const { blob, claimCode } = lockGift(g.code, amount, pk);
  ui.giftCode = blob; ui.giftLocked = true; ui.giftClaimCode = claimCode; ui.giftDmStatus = 'sending';
  wallet.recordGift({ code: blob, locked: true, amount, claimCode, outpoints: g.reserved });
  const dmText = t('giftDmText', { amount: fmtAmount(amount) + ' ' + unitLabel(), link: giftUrl(), code: claimCode });
  wallet.sendNostrDM(pk, dmText).then((ok) => { ui.giftDmStatus = ok ? 'sent' : 'failed'; render(); }).catch(() => { ui.giftDmStatus = 'failed'; render(); });
}
function doCreateGift(amt, rate) {
  try {
    finishGift(wallet.createGift(amt, rate), amt);
    ui.giftError = '';
    ui.giftSplitOffer = null;
  } catch (e) {
    ui.giftError = e.message;
    ui.giftSplitOffer = null;
  }
  render();
}
// Gift the whole spendable balance as a no-change sweep (the recipient receives
// everything minus their claim fee).
function doCreateGiftAll(rate) {
  try {
    finishGift(wallet.createGiftAll(rate));
    ui.giftError = '';
    ui.giftMax = false;
    ui.giftSplitOffer = null;
  } catch (e) {
    ui.giftError = e.message;
  }
  render();
}
// Split + gift in one tap: broadcast a self-send carving out a right-sized
// coin, then immediately build the gift from that (unconfirmed) carve-out, so
// only ~the gift amount is locked and there's no confirmation wait. The link is
// ready right away; the recipient sees a pending balance until the split lands.
async function doSplitForGift(amt) {
  if (wallet.offline) { ui.giftError = t('scanOffline'); render(); return; }
  ui.busy = true; ui.giftError = ''; render();
  try {
    const rate = (wallet.feeRates && wallet.feeRates.halfHourFee) || 5;
    finishGift(await wallet.createGiftFromSplit(amt, rate), amt);
    ui.giftSplitOffer = null;
    ui.giftError = '';
  } catch (e) {
    ui.giftError = e.message || t('giftSplitFailed');
  }
  ui.busy = false;
  wallet.scan().catch(() => {}); // reconcile the split from the mempool
  render();
}
function giftCard() {
  const active = wallet.outstandingGifts();
  return h(
    'div',
    { class: 'card col' },
    h('h3', {}, t('giftLink')),
    ui.giftCode
      ? h('div', { class: 'col', style: 'align-items:center;gap:10px' },
          ui.giftLocked && (() => {
            const lk = previewLockedGift(ui.giftCode);
            if (!lk) return null;
            return h('div', { class: 'col gap6', style: 'width:100%;align-items:center' },
              h('div', { class: 'row gap6', style: 'align-items:center' }, h('span', { class: 'small muted' }, t('giftLockedTo')), profileChip(lk.to)),
              ui.giftDmStatus === 'sent' ? h('div', { class: 'small', style: 'color:var(--ok,#2a8)' }, t('giftDmSent'))
                : ui.giftDmStatus === 'failed' ? h('div', { class: 'col gap6', style: 'align-items:center' }, h('div', { class: 'small err' }, t('giftDmFailed')), ui.giftClaimCode ? copyBtn(ui.giftClaimCode, t('giftCopyCode')) : null)
                : h('div', { class: 'row gap6', style: 'align-items:center' }, h('span', { class: 'spinner sm' }), h('span', { class: 'small muted' }, t('giftDmSending'))));
          })(),
          // A bearer gift uppercases the URL for a smaller alphanumeric QR (the
          // base32 code is case-insensitive). A locked gift's payload is
          // case-sensitive base64url, so it uses a plain byte-mode QR. A large
          // (many-input) gift can exceed QR capacity — then fall back to the link.
          (() => {
            let svg = null;
            try { svg = ui.giftLocked ? qrSvg(giftUrl()) : qrSvg(giftUrl().toUpperCase(), { ec: 'L', mode: 'Alphanumeric' }); } catch {}
            return svg ? h('div', { html: svg }) : h('div', { class: 'small faint', style: 'text-align:center;padding:8px' }, t('giftQrTooLong'));
          })(),
          h('div', { class: 'addr-box break', style: 'width:100%;font-size:12px' }, giftUrl()),
          h('div', { class: 'row gap6 wrap' },
            copyBtn(giftUrl(), t('copyLink')),
            h('button', { class: 'btn-sm grow', onClick: () => { ui.giftCode = null; ui.giftAmount = ''; ui.giftMax = false; ui.giftLockNpub = ''; ui.giftLocked = false; ui.giftClaimCode = null; ui.giftDmStatus = null; render(); } }, t('giftAnother'))
          )
        )
      : ui.giftSplitOffer
      ? (() => {
          const o = ui.giftSplitOffer;
          const u = ' ' + unitLabel();
          const manyCoins = (o.count || 0) >= 3;
          return h('div', { class: 'col gap6' },
            h('div', { class: 'small muted' },
              manyCoins
                ? t('giftConsolidateExplain', { count: o.count, fee: fmtAmount(o.fee) + u })
                : t('giftSplitExplain', { lock: fmtAmount(o.lock) + u, change: fmtAmount(o.lock - o.amt) + u, fee: fmtAmount(o.fee) + u })),
            ui.giftError && h('div', { class: 'notice err' }, ui.giftError),
            ui.busy
              ? h('button', { class: 'btn-primary btn-block', disabled: true }, h('span', { class: 'spinner' }))
              : h('div', { class: 'col gap6' },
                  h('button', { class: 'btn-primary btn-block', onClick: () => doSplitForGift(o.amt) }, manyCoins ? t('giftConsolidateFirst') : t('giftSplitFirst')),
                  h('button', { class: 'btn-block', onClick: () => doCreateGift(o.amt, giftRate()) }, manyCoins ? t('giftUseManyCoins', { count: o.count }) : t('giftLockWhole', { n: fmtAmount(o.lock) + u })),
                  h('button', { class: 'linklike small', style: 'align-self:center', onClick: () => { ui.giftSplitOffer = null; render(); } }, t('back'))
                )
          );
        })()
      : h('div', { class: 'col gap6' },
          h('div', { class: 'input-group' },
            h('input', { type: 'number', step: unit === 'sats' ? '1' : '0.00000001', min: '0', inputmode: 'decimal', placeholder: t('giftAmountLabel'),
              disabled: ui.giftMax,
              value: ui.giftMax ? (unit === 'sats' ? String(wallet.spendable) : fmtBtc(wallet.spendable)) : ui.giftAmount,
              onInput: (e) => (ui.giftAmount = e.target.value) }),
            h('button', { type: 'button', class: ui.giftMax ? 'btn-primary' : '', onClick: () => { ui.giftMax = !ui.giftMax; ui.giftError = ''; render(); } }, t('max')),
            h('div', { style: 'display:flex;align-items:center' }, unitTag())
          ),
          h('div', { class: 'small faint' }, ui.giftMax ? t('giftAllNote') : t('giftMinNote', { n: fmtAmount(giftMinimum(giftRate())) + ' ' + unitLabel() })),
          (() => {
            const raw = ui.giftLockNpub.trim();
            const pk = raw ? parseNostrPubkey(raw) : null;
            return h('div', { class: 'col gap6' },
              h('input', { type: 'text', class: 'mono-input', placeholder: t('giftLockPlaceholder'),
                autocapitalize: 'none', autocomplete: 'off', spellcheck: 'false', value: ui.giftLockNpub,
                onInput: (e) => { ui.giftLockNpub = e.target.value; render(); } }),
              !raw ? h('div', { class: 'small faint' }, t('giftLockHint'))
                : pk ? h('div', { class: 'row gap6', style: 'align-items:center' }, h('span', { class: 'small muted' }, t('giftLockTo')), profileChip(pk))
                : h('div', { class: 'small err' }, t('giftLockInvalid')));
          })(),
          ui.giftError && h('div', { class: 'notice err' }, ui.giftError),
          h('button', { class: 'btn-block', onClick: createGiftLink }, t('giftLinkReveal'))
        ),
    active.length
      ? h('div', { class: 'col gap6', style: 'margin-top:4px' },
          h('span', { class: 'small muted' }, t('giftReserved', { n: active.length })),
          ...active.map((g) => {
            const amt = g.value != null ? fmtAmount(g.value) + ' ' + unitLabel() : g.id.slice(0, 12) + '…';
            const label = amt + (g.reserved ? '' : ' · ' + t('giftReclaimedTag'));
            if (ui.revokeId === g.id) {
              return h('div', { class: 'col gap6' },
                h('span', { class: 'small muted' }, g.reserved ? t('giftReclaimPrompt') : t('giftRevokeConfirm')),
                ui.busy
                  ? h('button', { class: 'btn-primary btn-block', disabled: true }, h('span', { class: 'spinner' }))
                  : h('div', { class: 'row gap6' },
                      g.reserved ? h('button', { class: 'btn-ghost grow', onClick: () => doReclaim(g.id) }, t('giftReclaim')) : null,
                      h('button', { class: 'btn-primary grow', onClick: () => doRevoke(g.id) }, t('giftRevoke'))
                    ),
                ui.busy ? null : h('button', { class: 'btn-ghost btn-block', onClick: () => { ui.revokeId = null; render(); } }, t('back'))
              );
            }
            return h('div', { class: 'row between' },
              h('span', { class: 'small mono' }, label),
              h('button', { class: 'btn-sm', onClick: () => { ui.revokeId = g.id; render(); } }, g.reserved ? t('giftReclaim') : t('giftRevoke'))
            );
          })
        )
      : null
  );
}

// Passive reclaim: just free the coin for a future payment (no fee, no
// broadcast). The link stays claimable until the coin is actually spent.
function doReclaim(id) {
  wallet.unreserve(id);
  ui.revokeId = null;
  toast(t('giftReclaimed'));
  render();
}

// Active revoke: spend the coin back now (pays a fee), killing the link.
async function doRevoke(id) {
  if (wallet.offline) { toast(t('scanOffline')); return; }
  ui.busy = true;
  render();
  try {
    const rate = (wallet.feeRates && wallet.feeRates.fastestFee) || 10;
    await wallet.revokeGift(id, rate);
    wallet.markGiftRevoked(id); // we took it back — don't later mislabel it as claimed
    ui.revokeId = null;
    toast(t('giftRevoked'));
    wallet.scan().catch(() => {});
  } catch (e) {
    toast(e.message);
  }
  ui.busy = false;
  render();
}

// Switch the active Bitcoin network. Changes addresses/balances entirely, so we
// persist the choice and reload the active account (or empty wallet) under it.
function changeNetwork(net) {
  if (net === getNetwork()) return;
  setNetwork(net);
  swaps.network = net;
  ui.swapLimits = null; // limits differ per network's provider
  const acc = accounts.find((a) => a.id === activeId);
  if (acc) activateAccount(acc); else render();
}

// Swap provider selector. Boltz-compatible providers (from SwapMarket) plus a
// custom option. Swaps stay non-custodial regardless of provider.
function boltzProviderCard() {
  const id = getBoltzProviderId();
  const custom = getBoltzCustom();
  return h(
    'div',
    { class: 'card col' },
    h('h3', {}, '⚡ Swap provider'),
    h('p', { class: 'small muted', style: 'margin:0' }, 'Boltz-compatible provider for Lightning swaps. Non-custodial: a provider can fail a swap but never take your funds.'),
    h('select', { onChange: (e) => { setBoltzProviderId(e.target.value); ui.swapLimits = null; render(); } },
      BOLTZ_PRESETS.map((p) => h('option', { value: p.id, selected: p.id === id }, p.label))),
    id === 'custom'
      ? h('div', { class: 'col', style: 'gap:8px' },
          h('label', { class: 'field' },
            h('span', { class: 'lab' }, 'API URL'),
            h('input', {
              type: 'text', class: 'mono-input', placeholder: 'https://api.example.com',
              autocapitalize: 'none', autocomplete: 'off', spellcheck: 'false', value: custom.api,
              onChange: (e) => { setBoltzCustom({ api: e.target.value.trim(), ws: custom.ws }); ui.swapLimits = null; render(); },
            })),
          h('label', { class: 'field' },
            h('span', { class: 'lab' }, 'WebSocket URL (optional)'),
            h('input', {
              type: 'text', class: 'mono-input', placeholder: 'wss://api.example.com/v2/ws',
              autocapitalize: 'none', autocomplete: 'off', spellcheck: 'false', value: custom.ws,
              onChange: (e) => { setBoltzCustom({ api: custom.api, ws: e.target.value.trim() }); render(); },
            }),
            h('div', { class: 'small faint' }, 'Left blank, the WS is derived from the API URL.')))
      : h('div', { class: 'small faint', style: 'word-break:break-all' }, getBoltzApi())
  );
}

// Ark server selector + wallet panel. Off by default; picking a server spins
// up the ArkManager for this wallet (off-chain balance, board, refresh).
function arkCard() {
  const net = getNetwork();
  const id = getArkProviderId(net);
  const custom = getArkCustom(net);
  const presets = arkPresets(net);
  const applyProvider = (v) => {
    setArkProviderId(v, net);
    ui.receiveType = null;
    initArk();
    render();
  };
  const head = [
    h('h3', {}, '⚔ Ark'),
    h('p', { class: 'small muted', style: 'margin:0' }, t('arkDesc')),
    h('select', { onChange: (e) => applyProvider(e.target.value) },
      presets.map((p) => h('option', { value: p.id, selected: p.id === id }, p.label))),
    id === 'custom'
      ? h('div', { class: 'col', style: 'gap:8px' },
          h('label', { class: 'field' },
            h('span', { class: 'lab' }, t('arkServerUrl')),
            h('input', {
              type: 'text', class: 'mono-input', placeholder: 'https://ark.example.com',
              autocapitalize: 'none', autocomplete: 'off', spellcheck: 'false', value: custom.ark,
              onChange: (e) => { setArkCustom({ ark: e.target.value.trim(), esplora: custom.esplora }, net); initArk(); render(); },
            })),
          h('label', { class: 'field' },
            h('span', { class: 'lab' }, t('arkEsploraUrl')),
            h('input', {
              type: 'text', class: 'mono-input', placeholder: 'https://mempool.example.com/api',
              autocapitalize: 'none', autocomplete: 'off', spellcheck: 'false', value: custom.esplora,
              onChange: (e) => { setArkCustom({ ark: custom.ark, esplora: e.target.value.trim() }, net); initArk(); render(); },
            })))
      : null,
    ui.arkError ? h('div', { class: 'notice err' }, ui.arkError) : null,
  ];
  if (id === 'off' || wallet.watchOnly) {
    return h('div', { class: 'card col' }, ...head,
      wallet.watchOnly && id !== 'off' ? h('div', { class: 'small faint' }, t('arkWatchOnly')) : null);
  }
  if (!ark || !ark.state) {
    return h('div', { class: 'card col' }, ...head,
      arkConnectPromise
        ? h('div', { class: 'row gap6', style: 'align-items:center' },
            h('span', { class: 'spinner sm' }), h('span', { class: 'small muted' }, t('arkConnecting')))
        : h('button', { class: 'btn-ghost btn-block', onClick: () => connectArk().catch(() => {}) }, t('arkConnectBtn')));
  }

  const bal = ark.balance();
  const spendables = ark.vtxos().filter((v) => v.state === 'spendable');
  const pendingActions = ark.pendingActions();
  const row = (k, v) => h('div', { class: 'row between' }, h('span', { class: 'small muted' }, k), h('span', { class: 'small' }, v));

  return h(
    'div',
    { class: 'card col', style: 'gap:10px' },
    ...head,
    row(t('arkBalance'), fmtAmount(bal.spendableSat) + ' ' + unitLabel() + (bal.pendingSat ? ` (+${fmtAmount(bal.pendingSat)} ${t('pending').toLowerCase()})` : '')),
    spendables.length ? row(t('arkVtxos'), String(spendables.length)) : null,
    pendingActions.length
      ? h('div', { class: 'small muted' }, t('arkPendingActions', { n: pendingActions.length }) + ' — ' + pendingActions.map((a) => `${a.type}:${a.step}`).join(', '))
      : null,

    // Board: move on-chain sats into the Ark (one on-chain tx, then confirms).
    h('div', { class: 'input-group' },
      h('input', {
        type: 'number', inputmode: 'numeric', min: '0',
        placeholder: t('arkBoardPlaceholder', { n: (ark.info.minBoardAmountSat || 0).toLocaleString() }),
        value: ui.arkBoardAmt || '',
        onInput: (e) => { ui.arkBoardAmt = e.target.value; },
      }),
      h('button', { class: 'btn-sm', disabled: !!ui.arkBusy, onClick: doArkBoard }, ui.arkBusy === 'board' ? h('span', { class: 'spinner sm' }) : t('arkBoardBtn'))),

    spendables.length >= 1
      ? h('button', { class: 'btn-ghost btn-block', disabled: !!ui.arkBusy, onClick: doArkRefresh },
          ui.arkBusy === 'refresh' ? h('span', { class: 'spinner sm' }) : t('arkRefreshBtn', { n: spendables.length }))
      : null
  );
}

// Board: startBoard() gives the funding address; hal's own on-chain wallet pays
// it (recipient pinned to vout 0 — the ASP requires the board output there),
// then the manager waits for confirmations and registers via the sync loop.
async function doArkBoard() {
  const sats = parseInt((ui.arkBoardAmt || '').trim(), 10);
  if (!sats) return;
  ui.arkBusy = 'board'; ui.arkError = ''; render();
  try {
    const { actionId, fundingAddress } = await ark.startBoard(sats);
    const feeRate = (wallet.feeRates && wallet.feeRates.halfHourFee) || 5;
    const draft = wallet.buildTx({ recipients: [{ address: fundingAddress, amount: sats }], feeRate, noSort: true });
    const hexTx = wallet.sign(draft.tx);
    const txid = await wallet.broadcast(hexTx);
    await ark.completeBoard(actionId, txid);
    ui.arkBoardAmt = '';
    toast(t('arkBoardStarted'));
    wallet.scan().catch(() => {});
  } catch (e) {
    ui.arkError = e.message;
  }
  ui.arkBusy = null; render();
}

async function doArkRefresh() {
  ui.arkBusy = 'refresh'; ui.arkError = ''; render();
  try {
    await ark.refresh();
    toast(t('arkRefreshStarted'));
  } catch (e) {
    ui.arkError = e.message;
  }
  ui.arkBusy = null; render();
}

// Network selector. Per-network endpoints (Electrum server / block explorer) are
// configured in the Data source card below — no duplicate URL fields here.
function networkCard() {
  const net = getNetwork();
  return h(
    'div',
    { class: 'card col' },
    h('h3', {}, 'Network'),
    h('p', { class: 'small muted', style: 'margin:0' }, 'Bitcoin network this wallet operates on. Pick its servers under Data source.'),
    h('select', { onChange: (e) => changeNetwork(e.target.value) },
      NETWORKS.map((n) => h('option', { value: n.id, selected: net === n.id }, n.label)))
  );
}

function explorerCard() {
  const net = getNetwork();
  const src = getSource();
  const sources = dataSources(net);
  const pick = (id) => {
    setSource({ id, url: '' });
    render();
    // Switching source can swap the whole backend (electrum⇄esplora), so rebuild
    // + rescan — except an empty custom (wait for the URL).
    if (id !== 'custom' && !wallet.offline) wallet.reloadExplorer();
  };
  const typeDesc = t(src.type === 'electrum' ? 'detectedElectrum' : 'detectedEsplora');
  return h(
    'div',
    { class: 'card col' },
    h('h3', {}, t('dataSource')),
    h('p', { class: 'small muted', style: 'margin:0' }, t('dataSourceDesc')),
    h('select', { onChange: (e) => pick(e.target.value) },
      sources.map((o) => h('option', { value: o.id, selected: o.id === src.id }, o.id === 'custom' ? o.label : (o.url || o.base).replace(/^\w+:\/\//, '')))),
    src.id === 'custom'
      ? h('label', { class: 'field' },
          h('span', { class: 'lab' }, t('sourceUrl')),
          h('input', {
            type: 'text', class: 'mono-input', placeholder: 'wss://your-node:50004  ·  https://your-esplora/api',
            autocapitalize: 'none', autocomplete: 'off', spellcheck: 'false', value: src.url || '',
            onChange: (e) => { const url = e.target.value.trim(); setSource({ id: 'custom', url }); render(); if (!wallet.offline) wallet.reloadExplorer(); },
          }),
          h('div', { class: 'small faint' }, src.url ? typeDesc : t('sourceUrlHint'))
        )
      : h('div', { class: 'small faint' }, typeDesc)
  );
}

// Cross-device sync settings: toggle + editable relay list (default coinos).
function syncCard() {
  const cfg = getSyncConfig();
  const setEnabled = (enabled) => {
    if (enabled === cfg.enabled) return;
    setSyncConfig({ enabled, relays: cfg.relays });
    render();
    // On enable, pull anything newer from the relays, then push our copy up.
    if (enabled && !wallet.offline) {
      wallet.syncFromNostr().catch(() => {}).finally(() => wallet.saveCache());
    }
  };
  return h(
    'div',
    { class: 'card col' },
    h('h3', {}, t('deviceSync')),
    h('p', { class: 'small muted', style: 'margin:0' }, t('deviceSyncDesc')),
    h('div', { class: 'row between' },
      h('span', { class: 'lab', style: 'margin:0' }, t('syncAcross')),
      h('div', { class: 'seg' },
        h('button', { type: 'button', class: cfg.enabled ? 'active' : '', onClick: () => setEnabled(true) }, t('syncOn')),
        h('button', { type: 'button', class: !cfg.enabled ? 'active' : '', onClick: () => setEnabled(false) }, t('syncOff'))
      )
    ),
    cfg.enabled
      ? h('label', { class: 'field' },
          h('span', { class: 'lab' }, t('relaysLabel')),
          h('textarea', {
            placeholder: 'wss://relay.example.com',
            autocapitalize: 'none', autocomplete: 'off', spellcheck: 'false',
            style: 'min-height:64px',
            value: cfg.relays.join('\n'),
            onInput: (e) => {
              const relays = e.target.value.split('\n').map((s) => s.trim()).filter(Boolean);
              setSyncConfig({ enabled: true, relays });
            },
          }),
          h('div', { class: 'small faint' }, t('relaysHint'))
        )
      : null
  );
}

// Language selector. Changing it persists the choice, flips text direction for
// RTL languages, and re-renders the whole app in the new language.
function languagePicker() {
  return h(
    'select',
    {
      value: getLang(),
      onChange: async (e) => {
        const code = e.target.value;
        setLang(code);
        await loadLocale(code); // fetch the locale's strings before re-rendering
        applyDir();
        render();
      },
    },
    LANGS.map(([code, name]) => h('option', { value: code, selected: code === getLang() }, name))
  );
}

// Reflect the active language's writing direction on <html> (rtl for ar/ur).
function applyDir() {
  try {
    document.documentElement.dir = isRTL() ? 'rtl' : 'ltr';
    document.documentElement.lang = getLang();
  } catch {}
}

function goHome() {
  // Bailing from an unclaimed gift — discard the provisional wallet it generated.
  const active = accounts.find((a) => a.id === activeId);
  if (active && active.provisional) {
    accounts = accounts.filter((a) => a.id !== active.id);
    persistAccounts();
    activeId = accounts[0] ? accounts[0].id : null;
  }
  // A wallet is open → home is its Receive page (not the create/import screen),
  // so the logo is always a way back to your wallet.
  if (activeAccount()) {
    ui.screen = 'wallet';
    ui.tab = wallet.offline ? 'settings' : 'receive';
    ui.draft = null;
    ui.sendResult = null;
    ui.sendError = '';
    ui.fromWallet = false;
  } else {
    ui.screen = 'unlock';
    ui.unlockTab = 'create';
    ui.createStep = 'gen';
    ui.draftMnemonic = '';
    ui.confirm = [];
    ui.unlockError = '';
  }
  render();
}

// ================================================================ GIFT / CLAIM
// Read a gift link, returning the code (and scrubbing it from the URL so the
// bearer instrument doesn't linger in the address bar / history). New links are
// /g/<base32-compact>; legacy links are #gift=<base64url-psbt>. Both validate by
// decoding to a real gift.
function readGiftHash() {
  try {
    let code = null;
    const pm = location.pathname.match(/^\/g\/([A-Za-z0-9]+)\/?$/i); // new path form
    if (pm) code = pm[1];
    else {
      const hm = location.hash.match(/^#gift=([A-Za-z0-9_-]+)$/); // legacy hash form
      if (hm) code = hm[1];
    }
    if (!code) return null;
    history.replaceState(null, '', '/');
    return previewGift(code) ? code : null;
  } catch {
    return null;
  }
}

// A gift locked to a nostr key: /lg/<base64url>. Returns the public preview
// ({ amount, to, eph, ct }) — claimed by the recipient's own wallet, not a fresh
// one, so we don't auto-create a wallet here.
function readLockedGiftHash() {
  try {
    const m = location.pathname.match(/^\/lg\/([A-Za-z0-9_-]+)\/?$/);
    if (!m) return null;
    history.replaceState(null, '', '/');
    return previewLockedGift(m[1]);
  } catch {
    return null;
  }
}

// Re-view a previously created gift's link + QR (from its stored record), so the
// sender can re-share an unclaimed gift. For a locked gift, also surfaces the
// claim code that was DM'd, in case it needs re-sending.
function viewGiftView() {
  const g = ui.viewGift; // { code, locked, amount, claimCode }
  const url = `${location.origin}/${g.locked ? 'lg' : 'g'}/${g.code}`;
  let svg = null;
  try { svg = g.locked ? qrSvg(url) : qrSvg(url.toUpperCase(), { ec: 'L', mode: 'Alphanumeric' }); } catch {}
  return h('div', { class: 'col', style: 'gap:16px;padding:16px;max-width:460px;margin:0 auto;width:100%' },
    h('div', { class: 'card col', style: 'gap:12px;align-items:center' },
      h('h3', { style: 'margin:0' }, t('giftView')),
      g.amount != null ? h('div', { class: 'amt' }, fmtAmount(g.amount), ' ', unitTag()) : null,
      svg ? h('div', { html: svg }) : h('div', { class: 'small faint', style: 'text-align:center;padding:8px' }, t('giftQrTooLong')),
      h('div', { class: 'addr-box break', style: 'width:100%;font-size:12px' }, url),
      copyBtn(url, t('copyLink')),
      g.locked && g.claimCode
        ? h('div', { class: 'col gap6', style: 'width:100%;align-items:center' }, h('div', { class: 'small muted' }, t('giftCodeLabel')), copyBtn(g.claimCode, t('giftCopyCode')))
        : null,
      h('button', { class: 'btn-ghost btn-block', onClick: () => { ui.viewGift = null; render(); } }, t('back'))
    )
  );
}

// A locked gift opened from a link: the amount + recipient are public. The
// recipient pastes the claim code from their nostr DM; that decrypts the payload,
// then it's claimed into a fresh wallet exactly like a normal gift.
function lockedGiftClaimView() {
  const lk = ui.claimLocked;
  // NIP-07: if a nostr browser extension is present, the recipient can decrypt
  // in-place — no code needed.
  const hasExt = !!(typeof globalThis !== 'undefined' && globalThis.nostr && lk.eph && lk.ctKey);
  return h('div', { class: 'col', style: 'gap:16px;padding:16px;max-width:460px;margin:0 auto;width:100%' },
    h('div', { class: 'card col', style: 'gap:14px;align-items:center' },
      h('h3', { style: 'margin:0' }, t('giftForYou')),
      h('div', { class: 'amt' }, fmtAmount(lk.amount), ' ', unitTag()),
      h('div', { class: 'row gap6', style: 'align-items:center' },
        h('span', { class: 'small muted' }, t('giftLockedTo')),
        profileChip(lk.to, { size: 36 })),
      ui.claimError && h('div', { class: 'notice err' }, ui.claimError),
      hasExt ? h('button', { class: 'btn-primary btn-block', disabled: ui.busy, onClick: claimViaExtension }, ui.busy ? h('span', { class: 'spinner' }) : t('claimWithExtension')) : null,
      hasExt ? h('div', { class: 'small faint', style: 'text-align:center' }, t('orEnterCode')) : h('p', { class: 'small muted', style: 'text-align:center;margin:0' }, t('giftCodeHint')),
      h('input', { type: 'text', class: 'mono-input', style: 'width:100%', placeholder: t('claimCodePlaceholder'),
        autocapitalize: 'none', autocomplete: 'off', spellcheck: 'false', value: ui.claimCodeInput,
        onInput: (e) => { ui.claimCodeInput = e.target.value; } }),
      h('button', { class: (hasExt ? '' : 'btn-primary ') + 'btn-block', onClick: submitLockedCode }, t('claimGift')),
      h('button', { class: 'btn-ghost btn-block', onClick: () => { ui.claimLocked = null; ui.claimCodeInput = ''; ui.claimError = ''; render(); } }, t('dismiss'))
    )
  );
}
async function claimViaExtension() {
  const ext = typeof globalThis !== 'undefined' && globalThis.nostr;
  if (!ext) return;
  ui.busy = true; ui.claimError = ''; render();
  try {
    const pk = await ext.getPublicKey();
    if (pk !== ui.claimLocked.to) { ui.claimError = t('extWrongAccount'); ui.busy = false; render(); return; }
    if (!ext.nip44 || !ext.nip44.decrypt) { ui.claimError = t('extNoNip44'); ui.busy = false; render(); return; }
    const payload = await ext.nip44.decrypt(ui.claimLocked.eph, ui.claimLocked.ctKey);
    if (!payload || !previewGift(payload)) { ui.claimError = t('extDecryptFailed'); ui.busy = false; render(); return; }
    ui.busy = false; ui.claimLocked = null; ui.claimCodeInput = ''; ui.claimError = '';
    claimGift(payload); // claim into an existing wallet or a fresh one
  } catch {
    ui.busy = false; ui.claimError = t('extDecryptFailed'); render();
  }
}
function submitLockedCode() {
  const code = (ui.claimCodeInput || '').trim();
  if (!code) return;
  let payload = null;
  try { payload = decryptWithCode(code, ui.claimLocked.ct); } catch {}
  if (!payload || !previewGift(payload)) { ui.claimError = t('claimCodeWrong'); render(); return; }
  ui.claimLocked = null; ui.claimCodeInput = ''; ui.claimError = '';
  claimGift(payload); // claim into an existing wallet or a fresh one
}

// Has this gift already been claimed? Its funding coin being spent — even by an
// unconfirmed claim — means the gift is gone; show the "already claimed" screen
// rather than let the user attempt a doomed double-spend.
async function checkGiftClaimed(code) {
  const ops = giftOutpoints(code);
  if (!ops.length) { ui.claimChecking = false; render(); return; }
  try {
    const res = await wallet.api.outspend(ops[0].txid, ops[0].vout);
    if (res && res.spent) ui.claimTaken = { txid: res.txid || null };
  } catch {
    // Couldn't check (offline/transient) — leave it claimable; the broadcast in
    // doClaim is the final guard (a double-spend is rejected by the network).
  }
  ui.claimChecking = false;
  render();
}

// Broadcast the presigned gift to this fresh wallet's first receive address.
async function doClaim() {
  if (wallet.offline) { ui.claimError = t('scanOffline'); render(); return; }
  if (ui.claimChecking || ui.claimTaken) return; // not verified / already taken
  ui.busy = true;
  ui.claimError = '';
  render();
  try {
    const rate = (wallet.feeRates && wallet.feeRates.halfHourFee) || 5;
    const to = wallet.receive[0] ? wallet.receive[0].address : wallet.derive(0, 0).address;
    const claim = buildClaimTx(ui.claimCode, to, rate, wallet.netCfg.net);
    await wallet.broadcast(claim.hex);
    ui.claimedAmount = claim.amount;
    const wasProvisional = !!(activeAccount() && activeAccount().provisional);
    commitAccount(); // claimed — keep a fresh gift wallet (no-op for an existing one)
    if (wasProvisional) {
      ui.claimStep = 'backup'; // fresh wallet — show the new seed to back up
    } else {
      ui.screen = 'wallet'; // existing wallet — straight into it, no new seed to back up
      ui.claimStep = null;
      toast(t('giftClaimedToast'));
    }
    wallet.scan().catch(() => {});
  } catch (e) {
    // Broadcast failed — most likely someone claimed it in the race window.
    // Re-check the funding coin and, if spent, show the "already claimed" screen.
    const ops = giftOutpoints(ui.claimCode);
    if (ops.length) {
      try {
        const res = await wallet.api.outspend(ops[0].txid, ops[0].vout);
        if (res && res.spent) ui.claimTaken = { txid: res.txid || null };
      } catch {}
    }
    if (!ui.claimTaken) ui.claimError = t('claimFailed');
  }
  ui.busy = false;
  render();
}

// Wallets a gift could be claimed into: full accounts open this session plus the
// durable directory (every wallet's xpub, watch-only), deduped by xpub. Claiming
// sends the gift to the wallet's address; a watch-only one then needs the seed
// re-entered to spend. Empty for a first-time recipient.
function claimTargets() {
  let sess = null;
  try { sess = JSON.parse(sessionStorage.getItem(ACCOUNTS_KEY) || 'null'); } catch {}
  const open = ((sess && Array.isArray(sess.accounts)) ? sess.accounts : []).filter((a) => !a.provisional);
  const seen = new Set(open.map((a) => a.xpub).filter(Boolean));
  return [...open, ...loadWatchAccounts().filter((w) => !seen.has(w.xpub))];
}

// Entry point for claiming a gift code. If the recipient already has wallet(s),
// offer to claim into one or make a new one; otherwise go straight to a fresh
// wallet (the original first-timer flow).
function claimGift(code) {
  ui.claimLocked = null;
  const targets = claimTargets();
  if (targets.length) { accounts = targets; ui.claimChoose = { code }; render(); }
  else enterWallet(newMnemonic(), '', { gift: code });
}

// Claim a gift into an existing wallet (no new seed). activateAccount loads it and
// opens the claim screen; existingClaim keeps it committed and, in doClaim, skips
// the seed-backup step.
function claimIntoAccount(acc, code) {
  ui.claimChoose = null;
  activateAccount(acc, { gift: code, existingClaim: true, fresh: true });
}

// Pick where to receive a gift: an existing wallet, or a brand-new one.
function claimChooseView() {
  const code = ui.claimChoose.code;
  const pv = previewGift(code);
  return h(
    'div',
    { class: 'col', style: 'gap:16px' },
    brandHeader(false),
    h('div', { class: 'card col', style: 'align-items:center;text-align:center;gap:12px' },
      h('div', { class: 'check-badge', style: 'background:var(--accent)' }, '🎁'),
      h('h2', { style: 'margin:0' }, t('giftWelcome')),
      pv ? h('div', { class: 'amt', style: 'font-size:30px' }, h('span', { class: 'amount-pos' }, fmtAmount(pv.room)), ' ', unitTag('unit')) : null,
      h('p', { class: 'muted', style: 'margin:0' }, t('claimIntoPrompt'))
    ),
    h('div', { class: 'card col gap6' },
      ...accounts.map((a) =>
        h('button', { class: 'btn-block', style: 'text-align:left', onClick: () => claimIntoAccount(a, code) },
          a.label,
          a.type === 'watch' ? h('span', { class: 'small faint', style: 'margin-left:6px' }, '(' + t('watchOnly') + ')') : null)
      ),
      h('button', { class: 'btn-primary btn-block', onClick: () => { ui.claimChoose = null; enterWallet(newMnemonic(), '', { gift: code }); } }, t('claimNewWallet'))
    )
  );
}

// Gift-claim flow: a fresh wallet only the claimer controls. Step 'welcome'
// shows the amount + a Claim button; 'backup' (after a successful claim) shows
// the fresh recovery phrase to write down.
function claimScreen() {
  if (ui.claimStep === 'backup') {
    const words = wallet.mnemonic.split(' ');
    const claimed = ui.claimedAmount > 0; // false when "create a wallet anyway"
    return h(
      'div',
      { class: 'col', style: 'gap:16px' },
      brandHeader(false),
      h('div', { class: 'card col', style: 'align-items:center;text-align:center;gap:8px' },
        h('div', { style: 'font-size:72px;line-height:1' + (claimed ? ';color:var(--green)' : '') }, claimed ? '✓' : '🔑'),
        h('h2', { style: 'margin:0' }, claimed ? t('claimedTitle') : t('newWalletTitle')),
        h('p', { class: 'muted', style: 'margin:0' }, claimed ? t('claimedBody') : t('newWalletBody'))
      ),
      h('div', { class: 'card col' },
        h('h3', {}, t('recoveryPhrase')),
        h('div', { class: 'warn-box' }, t('writeDownWarn')),
        h('div', { class: 'words' },
          words.map((w, i) => h('div', { class: 'w' }, h('span', { class: 'n' }, i + 1), h('span', { class: 't' }, w)))
        ),
        h('div', { class: 'row gap6' }, copyBtn(wallet.mnemonic, t('copyPhrase'))),
        h('button', { class: 'btn-primary btn-block', onClick: () => { ui.confirm = pickConfirm(words); ui.claimError = ''; ui.claimStep = 'verify'; render(); } }, t('verifyBackup')),
        h('button', { class: 'btn-block', onClick: () => { ui.screen = 'wallet'; ui.claimStep = null; render(); } }, t('skipVerification'))
      )
    );
  }
  if (ui.claimStep === 'verify') {
    // Same word-confirmation as new-wallet creation: prove the recipient wrote
    // the phrase down before sending them off into their freshly funded wallet.
    const words = wallet.mnemonic.split(' ');
    return h(
      'div',
      { class: 'col', style: 'gap:16px' },
      brandHeader(false),
      h('div', { class: 'card col' },
        h('h3', { style: 'margin-top:0' }, t('recoveryPhrase')),
        h('p', { class: 'muted', style: 'margin:0' }, t('confirmBackupIntro')),
        ...ui.confirm.map((c, i) =>
          h('label', { class: 'field' },
            h('span', { class: 'lab' }, t('wordN', { n: c.index + 1 })),
            h('input', {
              type: 'text', class: 'mono-input', autocapitalize: 'none', autocomplete: 'off', spellcheck: 'false',
              value: c.value, onInput: (e) => (ui.confirm[i].value = e.target.value.trim()),
            })
          )
        ),
        ui.claimError && h('div', { class: 'notice err' }, ui.claimError),
        h('div', { class: 'row gap6' },
          h('button', { class: 'btn-ghost', onClick: () => { ui.claimStep = 'backup'; ui.claimError = ''; render(); } }, t('back')),
          h('button', {
            class: 'btn-primary grow',
            onClick: () => {
              const ok = ui.confirm.every((c) => c.value.toLowerCase() === words[c.index]);
              if (!ok) { ui.claimError = t('wordsMismatch'); render(); return; }
              ui.screen = 'wallet'; ui.claimStep = null; ui.claimError = '';
              render();
            },
          }, t('openWallet'))
        ),
        h('button', { class: 'btn-block', onClick: () => { ui.screen = 'wallet'; ui.claimStep = null; render(); } }, t('skipVerification'))
      )
    );
  }
  // While verifying the gift is still unclaimed, show a loading screen rather
  // than flashing the claimable amount (which would then jump to "already
  // claimed" for a spent gift).
  if (ui.claimChecking) {
    return h(
      'div',
      { class: 'col', style: 'gap:16px' },
      brandHeader(false),
      h('div', { class: 'card col', style: 'align-items:center;text-align:center;gap:14px;padding:32px 14px' },
        h('span', { class: 'spinner' }),
        h('p', { class: 'muted', style: 'margin:0' }, t('giftChecking'))
      )
    );
  }
  // Already claimed (funding coin spent, possibly only in the mempool) — show a
  // dead end with a link to the claim, instead of a claimable amount.
  if (ui.claimTaken) {
    return h(
      'div',
      { class: 'col', style: 'gap:16px' },
      brandHeader(false),
      h('div', { class: 'card col', style: 'align-items:center;text-align:center;gap:12px' },
        h('div', { style: 'font-size:56px;line-height:1' }, '🎁'),
        h('h2', { style: 'margin:0' }, t('giftTakenTitle')),
        h('p', { class: 'muted', style: 'margin:0' }, t('giftTakenBody'))
      ),
      // A fresh wallet was already generated for the claim — offer to keep it,
      // view the claim on a block explorer, or head back to the home screen.
      h('button', { class: 'btn-primary btn-block', onClick: () => {
          ui.claimTaken = null; ui.claimedAmount = 0;
          if (activeAccount() && activeAccount().provisional) { ui.claimStep = 'backup'; commitAccount(); }
          else { ui.screen = 'wallet'; ui.claimStep = null; }
          render();
        } }, activeAccount() && activeAccount().provisional ? t('createWalletAnyway') : t('goToWallet')),
      ui.claimTaken.txid
        ? h('a', { class: 'btn btn-block', href: wallet.api.explorerTx(ui.claimTaken.txid), target: '_blank', rel: 'noopener', onClick: (e) => { e.preventDefault(); openExternal(wallet.api.explorerTx(ui.claimTaken.txid)); } }, t('viewOnMempool'))
        : null,
      h('button', { class: 'btn-ghost btn-block', onClick: goHome }, t('goToHome'))
    );
  }
  const pv = previewGift(ui.claimCode);
  // The headline is the full amount received (inputs minus the sender's change).
  // The network fee is determined now, at claim time, and comes out of that
  // amount — we surface the estimate on the Claim button so it isn't a surprise.
  const rate = Math.max(1, Math.round((wallet.feeRates && wallet.feeRates.halfHourFee) || 5));
  const estFee = pv ? Math.ceil((11 + 68 * pv.inputs + 31 * 2) * rate) : 0;
  const total = pv ? pv.room : 0;
  return h(
    'div',
    { class: 'col', style: 'gap:16px' },
    brandHeader(false),
    h('div', { class: 'card col', style: 'align-items:center;text-align:center;gap:12px' },
      h('div', { class: 'check-badge', style: 'background:var(--accent)' }, '🎁'),
      h('h2', { style: 'margin:0' }, t('giftWelcome')),
      h('div', { class: 'amt', style: 'font-size:30px' },
        h('span', { class: 'amount-pos' }, fmtAmount(total)), ' ', unitTag('unit')
      ),
      h('p', { class: 'muted', style: 'margin:0' }, t('claimBody'))
    ),
    ui.claimError && h('div', { class: 'notice err' }, ui.claimError),
    ui.busy || ui.claimChecking
      ? h('button', { class: 'btn-primary btn-block', disabled: true }, h('span', { class: 'spinner' }))
      : h('button', { class: 'btn-primary btn-block', onClick: doClaim },
          t('claimBtn'), ' ',
          h('span', { style: 'font-size:0.85em;opacity:0.9' }, '(' + t('claimFeeNote', { n: fmtAmount(estFee) + ' ' + unitLabel() }) + ')'))
  );
}

// Account switcher: pick a wallet, add another, or lock the session.
function accountsScreen() {
  if (ui.pw) return h('div', { class: 'col', style: 'gap:16px' }, brandHeader(false), pwPromptCard());
  if (ui.confirmClear) {
    return h('div', { class: 'col', style: 'gap:16px' },
      brandHeader(false),
      h('div', { class: 'card col' },
        h('h3', {}, t('clearAll')),
        h('div', { class: 'warn-box' }, t('clearAllWarn')),
        h('div', { class: 'row gap6' },
          h('button', { class: 'btn-ghost grow', onClick: () => { ui.confirmClear = false; render(); } }, t('back')),
          h('button', { class: 'btn-primary grow', onClick: clearAll }, t('clearAll'))
        )
      )
    );
  }
  if (ui.confirmRemove) {
    const acc = accounts.find((a) => a.id === ui.confirmRemove);
    return h('div', { class: 'col', style: 'gap:16px' },
      brandHeader(false),
      h('div', { class: 'card col' },
        h('h3', {}, t('removeWalletTitle')),
        h('div', { class: 'warn-box' }, t('removeWalletWarn', { name: acc ? acc.label : '' })),
        h('div', { class: 'row gap6' },
          h('button', { class: 'btn-ghost grow', onClick: () => { ui.confirmRemove = null; render(); } }, t('back')),
          h('button', { class: 'btn-primary grow', onClick: () => { const id = ui.confirmRemove; ui.confirmRemove = null; removeAccount(id); } }, t('remove'))
        )
      )
    );
  }
  return h(
    'div',
    { class: 'col', style: 'gap:16px' },
    brandHeader(false),
    h('div', { class: 'card col' },
      h('h3', {}, t('accounts')),
      h('div', { class: 'col', style: 'gap:0' },
        accounts.map((a) => {
          const isActive = a.id === activeId;
          const tag = a.type === 'watch' ? ' · ' + t('watchOnlyTag') : ''; // "saved" shown in the link below, not the title
          if (ui.editId === a.id) {
            return h('div', { class: 'row gap6', style: 'padding:10px 0; border-bottom:1px solid var(--line)' },
              h('input', { type: 'text', style: 'flex:1', value: ui.editLabel, autofocus: true,
                onInput: (e) => (ui.editLabel = e.target.value),
                onKeyDown: (e) => { if (e.key === 'Enter') renameAccount(a.id); } }),
              h('button', { class: 'btn-sm', onClick: () => renameAccount(a.id) }, t('save')),
              h('button', { class: 'btn-sm', onClick: () => { ui.editId = null; render(); } }, t('back'))
            );
          }
          return h('div', { class: 'col', style: 'gap:4px; padding:10px 0; border-bottom:1px solid var(--line)' },
            h('div', { class: 'row between' },
              h('button', {
                class: 'linklike', style: 'text-align:left;flex:1;font-size:15px;' + (isActive ? 'font-weight:600' : ''),
                onClick: () => { if (isActive) { ui.screen = 'wallet'; render(); } else switchAccount(a.id); },
              }, (isActive ? '● ' : '○ ') + a.label + tag),
              h('button', { class: 'btn-sm', title: t('walletSettings'), onClick: () => openAccountSettings(a.id) }, '⚙'),
              h('button', { class: 'btn-sm', title: t('remove'), onClick: () => { ui.confirmRemove = a.id; render(); } }, '✕')
            ),
            a.type === 'full'
              ? h('button', { class: 'linklike small', style: 'align-self:flex-start', onClick: () => (a.persisted ? startForget(a.id) : startSave(a.id)) },
                  a.persisted ? t('forgetDevice') : t('saveDevice'))
              : null
          );
        })
      ),
      h('button', { class: 'btn-block', onClick: () => { ui.draftMnemonic = ''; ui.createStep = 'gen'; ui.confirm = []; ui.screen = 'unlock'; ui.unlockTab = 'create'; ui.fromWallet = true; ui.unlockError = ''; render(); } }, t('addWallet')),
      hasVault() ? h('button', { class: 'btn-ghost btn-block', onClick: startChangePw }, t('changePassword')) : null,
      h('button', { class: 'btn-ghost btn-block', onClick: () => { ui.confirmClear = true; render(); } }, t('clearAll'))
    ),
    h('button', { class: 'btn-ghost btn-block', onClick: () => goBack(() => { ui.screen = 'wallet'; }) }, t('back'))
  );
}

function renameAccount(id) {
  const acc = accounts.find((a) => a.id === id);
  if (acc) {
    const v = (ui.editLabel || '').trim();
    if (v) acc.label = v;
    persistAccounts();
    if (acc.persisted) writeVault();
  }
  ui.editId = null;
  render();
}

// Open the per-wallet settings page for an account.
function openAccountSettings(id) {
  ui.settingsId = id;
  ui.editLabel = null;
  ui.revealShown = false;
  ui.pubkeyShown = false;
  ui.loadSeed = null;
  ui.screen = 'accountSettings';
  render();
}

// Per-wallet settings: name, auto-logout, recovery phrase, and public key — for
// any account (not just the active one; full accounts keep their seed in memory).
function accountSettingsScreen() {
  const a = accounts.find((x) => x.id === ui.settingsId) || activeAccount();
  if (!a) { ui.screen = 'accounts'; return accountsScreen(); }
  const isWatch = a.type === 'watch' || (!a.mnemonic && !a.xprv);
  const shown = ui.revealShown;
  const words = a.mnemonic ? a.mnemonic.split(' ') : [];
  let zpub = '';
  try { if (a.xpub) zpub = xpubToZpub(a.xpub); } catch {}
  const saveName = () => {
    const v = (ui.editLabel || '').trim();
    if (v && v !== a.label) { a.label = v; persistAccounts(); if (a.persisted) writeVault(); }
    ui.editLabel = null;
    render();
  };
  return h(
    'div',
    { class: 'col', style: 'gap:16px' },
    brandHeader(false),
    // Recovery phrase (top)
    isWatch
      ? (ui.loadSeed && ui.loadSeed.accId === a.id
          ? loadSeedCard()
          : h('div', { class: 'card col' },
              h('h3', {}, t('recoveryPhrase')),
              h('p', { class: 'small muted', style: 'margin:0' }, t('watchOnlyNote')),
              a.xpub
                ? h('button', { class: 'btn-primary btn-block', style: 'margin-top:4px', onClick: () => startLoadSeed({ accId: a.id }) }, t('loadSeedBtn'))
                : null
            ))
      : !a.mnemonic
        ? h('div', { class: 'card col' }, h('h3', {}, t('importedKey')), h('p', { class: 'small muted', style: 'margin:0' }, t('importedKeyNote')))
        : h('div', { class: 'card col' },
            h('h3', {}, t('recoveryPhrase')),
            h('div', { class: 'warn-box' }, t('recoveryWarn')),
            h('div', { class: 'words' }, words.map((w, i) =>
              h('div', { class: 'w' + (shown ? '' : ' masked') }, h('span', { class: 'n' }, i + 1), h('span', { class: 't' }, shown ? w : '••••••')))),
            shown && a.passphrase
              ? h('div', { class: 'col gap6' }, h('span', { class: 'lab' }, t('bip39Passphrase')), h('div', { class: 'addr-box' }, a.passphrase))
              : null,
            shown
              ? h('div', { class: 'row gap6 wrap' },
                  copyBtn(a.mnemonic, t('copyPhrase')),
                  a.passphrase ? copyBtn(a.passphrase, t('copyPassphrase')) : null,
                  h('button', { class: 'btn-sm grow', onClick: () => { ui.revealShown = false; render(); } }, t('hide')))
              : h('button', { class: 'btn-primary btn-block', onClick: () => { ui.revealShown = true; render(); } }, t('revealRecovery'))
          ),
    // Name
    h('div', { class: 'card col' },
      h('h3', {}, t('walletName')),
      h('div', { class: 'row gap6' },
        h('input', { type: 'text', style: 'flex:1', value: ui.editLabel != null ? ui.editLabel : a.label,
          onInput: (e) => { ui.editLabel = e.target.value; },
          onKeyDown: (e) => { if (e.key === 'Enter') saveName(); } }),
        h('button', { class: 'btn-sm', onClick: saveName }, t('save'))
      )
    ),
    // Public key (zpub)
    h('div', { class: 'card col' },
      h('h3', {}, t('publicKey')),
      h('p', { class: 'small muted', style: 'margin:0' }, t('publicKeyDesc')),
      ui.pubkeyShown
        ? h('div', { class: 'col gap6' },
            h('div', { class: 'addr-box break', style: 'font-size:12px' }, zpub),
            h('div', { class: 'row gap6 wrap' },
              copyBtn(zpub, t('copyKey')),
              h('button', { class: 'btn-sm grow', onClick: () => { ui.pubkeyShown = false; render(); } }, t('hide'))))
        : h('button', { class: 'btn-block', onClick: () => { ui.pubkeyShown = true; render(); } }, t('showPublicKey'))
    ),
    // Nostr address — share it so others can send you locked gifts.
    (a.id === activeId && wallet.nostrNpub())
      ? h('div', { class: 'card col' },
          h('h3', {}, t('nostrKeyTitle')),
          h('p', { class: 'small muted', style: 'margin:0' }, t('nostrKeyDesc')),
          h('div', { class: 'addr-box break', style: 'font-size:12px' }, wallet.nostrNpub()),
          copyBtn(wallet.nostrNpub(), t('copyKey')))
      : null,
    // Auto-logout (bottom)
    h('div', { class: 'card col' },
      h('h3', {}, t('autolockTitle')),
      h('p', { class: 'small muted', style: 'margin:0' }, t('autolockDesc')),
      h('select', { onChange: (e) => { a.autoLock = Number(e.target.value) || 0; persistAccounts(); if (a.persisted) writeVault(); render(); } },
        AUTOLOCK_OPTIONS.map((o) => h('option', { value: String(o.ms), selected: o.ms === accAutoLock(a) }, t(o.label))))
    ),
    h('button', { class: 'btn-ghost btn-block', onClick: () => { ui.editLabel = null; ui.revealShown = false; ui.pubkeyShown = false; ui.loadSeed = null; goBack(() => { ui.screen = 'accounts'; }); } }, t('back'))
  );
}

// Wipe every wallet from this device: session accounts, the encrypted vault,
// and saved watch-only accounts. Unbacked-up seeds are unrecoverable after this.
function clearAll() {
  try { localStorage.removeItem(VAULT_KEY); } catch {}
  try { localStorage.removeItem(WATCH_KEY); } catch {}
  ui.confirmClear = false;
  lock();
}

function pwPromptCard() {
  const p = ui.pw;
  const change = p.purpose === 'change';
  const newish = change || p.mode === 'set'; // entering a (new) password with confirm
  return h('div', { class: 'card col' },
    h('h3', {}, change ? t('changePassword') : p.mode === 'set' ? t('setPassword') : t('enterPassword')),
    h('p', { class: 'small muted', style: 'margin:0' }, change ? t('changePasswordDesc') : p.mode === 'set' ? t('setPasswordDesc') : t('enterPasswordDesc')),
    change ? h('input', { type: 'password', placeholder: t('currentPassword'), value: p.v0, onInput: (e) => (p.v0 = e.target.value) }) : null,
    h('input', { type: 'password', placeholder: newish ? t('passwordOptional') : t('password'), value: p.v1, onInput: (e) => (p.v1 = e.target.value) }),
    newish ? h('input', { type: 'password', placeholder: t('confirmPassword'), value: p.v2, onInput: (e) => (p.v2 = e.target.value) }) : null,
    p.error && h('div', { class: 'notice err' }, p.error),
    h('div', { class: 'row gap6' },
      h('button', { class: 'btn-ghost grow', onClick: cancelPw }, t('back')),
      h('button', { class: 'btn-primary grow', onClick: submitPw }, newish ? t('save') : t('unlock'))
    )
  );
}

function vaultScreen() {
  return h(
    'div',
    { class: 'col', style: 'gap:16px' },
    brandHeader(false),
    h('div', { class: 'card col' },
      h('h3', {}, t('unlockSaved')),
      h('p', { class: 'small muted', style: 'margin:0' }, t('unlockSavedDesc')),
      h('input', { type: 'password', placeholder: t('password'), value: ui.vaultPw,
        onInput: (e) => (ui.vaultPw = e.target.value), onKeyDown: (e) => { if (e.key === 'Enter') unlockVault(); } }),
      ui.vaultError && h('div', { class: 'notice err' }, ui.vaultError),
      h('button', { class: 'btn-primary btn-block', onClick: unlockVault }, t('unlock')),
      h('button', { class: 'btn-ghost btn-block', onClick: skipVault }, t('useAnotherWallet'))
    )
  );
}

function walletScreen() {
  return h(
    'div',
    { class: 'col', style: 'gap:0' },
    brandHeader(true),
    h('div', { class: 'mt16' }, balanceCard()),
    ui.offlineFallback && wallet.offline ? offlineBanner() : null,
    tabsBar(),
    tabContent()
  );
}

function offlineBanner() {
  return h(
    'div',
    { class: 'notice info row between', style: 'margin:12px 0 0' },
    h('span', {}, t('offlineBanner')),
    h('button', { class: 'btn-sm', onClick: retryOnline }, t('retry'))
  );
}

function balanceCard() {
  // Only dim on the very first load; background updates happen silently.
  const firstLoad = wallet.scanning && !wallet.loaded;
  const locked = wallet.lockedValue;
  const pending = wallet.pendingIncoming;
  const b = arkBalance();
  const arkBal = b && (b.spendableSat + b.pendingSat) > 0 ? b : null;
  return h(
    'div',
    { class: 'card balance' },
    h('div', { class: 'small faint', style: 'text-transform:uppercase;letter-spacing:.05em' }, t('balance')),
    // Headline is the spendable balance: confirmed coins plus our own pending
    // change, minus gift locks — so a pending spend debits immediately, while a
    // pending incoming receive stays out of it until it confirms.
    h('div', { class: 'amt', style: firstLoad ? 'opacity:.3' : '' }, fmtAmount(wallet.spendable), ' ', unitTag('unit')),
    pending > 0 || locked > 0 || arkBal
      ? h(
          'div',
          { class: 'split' },
          pending > 0
            ? h('div', {}, h('div', { class: 'k' }, t('pending')), h('div', { class: 'v pending' }, fmtAmount(pending), ' ', unitTag()))
            : null,
          locked > 0
            ? h('div', {}, h('div', { class: 'k' }, t('lockedInGifts')), h('div', { class: 'v' }, fmtAmount(locked), ' ', unitTag()))
            : null,
          arkBal
            ? h('div', {}, h('div', { class: 'k' }, t('arkBalance')), h('div', { class: 'v' }, fmtAmount(arkBal.spendableSat + arkBal.pendingSat), ' ', unitTag()))
            : null
        )
      : null
  );
}

async function doReverse() {
  const amt = parseInt((ui.swapReverseAmt || '').trim(), 10);
  const lim = ui.swapLimits || (ui.swapLimits = await swaps.reverseLimits());
  if (!amt || amt < lim.min || amt > lim.max) { ui.swapError = `Enter ${lim.min.toLocaleString()}–${lim.max.toLocaleString()} sats`; return render(); }
  ui.swapError = ''; ui.swapBusy = true; render();
  try { const rec = await swaps.startReverse(amt); ui.lnReceiveId = rec.id; ui.swapReverseAmt = ''; }
  catch (e) { ui.swapError = e.message; }
  ui.swapBusy = false; render();
}

async function doRefund(id) {
  ui.swapError = ''; ui.swapBusy = true; render();
  try { await swaps.refundSubmarine(id); }
  catch (e) { ui.swapError = e.message; }
  ui.swapBusy = false; render();
}

function tabsBar() {
  const tabs = [
    ['receive', t('tabReceive')],
    // Watch-only wallets show Send too — it prompts to load the seed to spend.
    ['send', t('tabSend')],
    ['history', t('tabHistory')],
    ['settings', t('tabSettings')],
  ];
  return h(
    'div',
    { class: 'tabs' },
    tabs.map(([id, label]) =>
      tabBtn(label, ui.tab === id, () => {
        ui.tab = id;
        ui.revealShown = false; // re-mask the recovery phrase whenever tabs change
        ui.txDetail = null; // back to the history list when leaving/returning
        ui.giftsAll = false; // and back to the paged history, not the all-gifts view
        ui.addrScan = false; // and back to the main Settings, not the address list
        ui.bump = null;
        ui.giftMode = false;
        render();
      })
    )
  );
}

function tabContent() {
  switch (ui.tab) {
    case 'receive': return receiveTab();
    case 'send': return sendTab();
    case 'history': return historyTab();
    case 'settings': return settingsTab();
  }
}

// A payment is "recent" enough to celebrate if it's still pending or confirmed
// within the last couple hours. This is a hard guard so an old payment can never
// trigger the celebration on import, regardless of receive-index bookkeeping.
function hasRecentIncoming() {
  const now = Date.now() / 1000;
  return wallet.txs.some((tx) => tx.net > 0 && (!tx.confirmed || (tx.blockTime && now - tx.blockTime < 2 * 3600)));
}

// ---------------------------------------------------------------- Receive
function receiveTab() {
  // An Ark payment landed — same celebration as an on-chain receive, dismissed
  // with a tap (the ack persists in the ark state so it shows exactly once).
  const arkUnseen = ark && ark.state ? ark.unseenReceives() : [];
  if (arkUnseen.length) {
    const amt = arkUnseen.reduce((n, m) => n + m.amountSat, 0);
    return h(
      'div',
      {
        class: 'card col',
        style: 'align-items:center;text-align:center;gap:14px;cursor:pointer;padding:48px 20px',
        onClick: () => { ark.ackReceives(); render(); },
      },
      h('div', { class: 'check-badge' }, '✓'),
      h('h2', { style: 'margin:0' }, t('paymentReceived')),
      amt ? h('div', { class: 'amount-pos', style: 'font-size:18px' }, '+' + fmtAmount(amt) + ' ' + unitLabel()) : null,
      h('div', { class: 'small muted' }, t('tapToProceed'))
    );
  }

  // A payment landed on the shown address (the fresh index advanced past what
  // the user last saw) — celebrate, and wait for a tap before showing the next.
  // Until receiveSeenIndex has been baselined (post-scan, in enterWallet) it
  // stays null and we never celebrate. The recency guard additionally ensures an
  // already-old payment never celebrates when a wallet is opened.
  if (ui.receiveSeenIndex != null && wallet.nextReceiveIndex > ui.receiveSeenIndex && hasRecentIncoming()) {
    // Mark it acknowledged as soon as it's shown — so a refresh or navigating
    // away (without tapping) won't bring the celebration back. It stays visible
    // this session (ui.receiveSeenIndex is unchanged) until the tap below.
    wallet.setReceiveAck(wallet.nextReceiveIndex);
    let amt = 0;
    for (let i = ui.receiveSeenIndex; i < wallet.nextReceiveIndex; i++) {
      const e = wallet._addrInfo(0, i);
      if (e) amt += (e.confirmed || 0) + (e.pending || 0);
    }
    return h(
      'div',
      {
        class: 'card col',
        style: 'align-items:center;text-align:center;gap:14px;cursor:pointer;padding:48px 20px',
        onClick: () => { ui.receiveSeenIndex = wallet.nextReceiveIndex; wallet.setReceiveAck(wallet.nextReceiveIndex); render(); },
      },
      h('div', { class: 'check-badge' }, '✓'),
      h('h2', { style: 'margin:0' }, t('paymentReceived')),
      amt ? h('div', { class: 'amount-pos', style: 'font-size:18px' }, '+' + fmtAmount(amt) + ' ' + unitLabel()) : null,
      h('div', { class: 'small muted' }, t('tapToProceed'))
    );
  }

  // One card with a toggle: on-chain address, Lightning (a Boltz reverse swap),
  // and the silent-payment address — each shown only when available.
  const fresh = wallet.freshReceive();
  const spAddr = wallet.silentPaymentsAvailable() ? wallet.silentPaymentAddress() : null;
  const canLn = !wallet.watchOnly; // a reverse swap needs our keys to claim on-chain
  let mode = ui.receiveType || 'address';
  if (mode === 'sp' && !spAddr) mode = 'address';
  if (mode === 'ln' && !canLn) mode = 'address';
  if (mode === 'ark' && !arkAvailable()) mode = 'address';
  // A compact dropdown (not a 3-button segmented control) so it fits on mobile and
  // scales if more address types are added.
  const opts = [['address', t('receiveAddressTab')]];
  if (canLn) opts.push(['ln', t('receiveLnTab')]);
  if (spAddr) opts.push(['sp', t('receiveSpTab')]);
  if (arkAvailable()) opts.push(['ark', t('receiveArkTab')]);
  const seg = opts.length > 1
    ? h('select', { style: 'width:100%', onChange: (e) => { ui.receiveType = e.target.value; render(); } },
        opts.map(([id, label]) => h('option', { value: id, selected: mode === id }, label)))
    : null;
  if (mode === 'ln') {
    return h('div', { class: 'card col', style: 'align-items:center;gap:14px' }, seg, ...lnReceiveContent());
  }
  if (mode === 'ark') {
    if (!ark) {
      connectArk().catch(() => {});
      return h(
        'div',
        { class: 'card col', style: 'align-items:center;gap:14px' },
        seg,
        ui.arkError
          ? h('div', { class: 'notice err', style: 'width:100%' }, ui.arkError)
          : h('div', { class: 'row gap6', style: 'align-items:center;padding:24px 0' },
              h('span', { class: 'spinner sm' }), h('span', { class: 'small muted' }, t('arkConnecting')))
      );
    }
    const arkAddr = ark.address();
    return h(
      'div',
      { class: 'card col', style: 'align-items:center;gap:14px' },
      seg,
      h('p', { class: 'small muted', style: 'margin:0;text-align:center' }, t('arkReceiveIntro')),
      h('div', { html: qrSvg(arkAddr) }),
      h('div', { class: 'addr-box break', style: 'width:100%;font-size:11px' }, arkAddr),
      copyBtn(arkAddr, t('copyAddress'))
    );
  }
  const addr = mode === 'sp' ? spAddr : fresh.address;
  return h(
    'div',
    { class: 'card col', style: 'align-items:center;gap:14px' },
    seg,
    h('div', { html: qrSvg(addr) }),
    h('div', { class: 'addr-box' + (mode === 'sp' ? ' break' : ''), style: 'width:100%' + (mode === 'sp' ? ';font-size:12px' : '') }, addr),
    copyBtn(addr, t('copyAddress'))
  );
}

// Lightning receive = a Boltz reverse swap: show a bolt11 the user shares; when
// it's paid, Boltz locks up on-chain and the SwapManager claims it into this
// wallet automatically. Returns the card's inner children.
function lnReceiveContent() {
  if (!ui.swapLimits && !ui._swapLimitsLoading) {
    ui._swapLimitsLoading = true;
    swaps.reverseLimits().then((l) => { ui.swapLimits = l; ui._swapLimitsLoading = false; render(); }).catch(() => { ui._swapLimitsLoading = false; });
  }
  const lim = ui.swapLimits;
  let rec = ui.lnReceiveId ? swaps.list().find((s) => s.id === ui.lnReceiveId) : null;
  if (rec && ['claimed', 'success'].includes(rec.status)) {
    // Claimed — the coin is credited on-chain (swap.js → creditReceive), so the
    // generic "Payment received!" celebration shows it like any receive. Just
    // reset the Lightning flow back to its form.
    ui.lnReceiveId = null;
    rec = null;
  }
  if (rec) {
    let svg = null;
    try { svg = qrSvg(rec.invoice.toUpperCase(), { ec: 'L', mode: 'Alphanumeric' }); } catch {}
    return [
      h('p', { class: 'small muted', style: 'margin:0;text-align:center' }, t('lnReceiveAwaiting')),
      svg ? h('div', { html: svg }) : null,
      h('div', { class: 'addr-box break', style: 'width:100%;font-size:11px' }, rec.invoice),
      copyBtn(rec.invoice, t('copyInvoice')),
      h('div', { class: 'row gap6', style: 'align-items:center' }, h('span', { class: 'spinner sm' }), h('span', { class: 'small muted' }, t('lnReceiveWatching'))),
      h('button', { class: 'btn-ghost btn-block', onClick: () => { ui.lnReceiveId = null; ui.swapReverseAmt = ''; ui.swapError = ''; render(); } }, t('back')),
    ];
  }
  return [
    h('p', { class: 'small muted', style: 'margin:0;text-align:center' }, t('lnReceiveIntro')),
    h('label', { class: 'field', style: 'width:100%' },
      h('span', { class: 'lab' }, t('amountSatsLabel')),
      h('input', { type: 'number', inputmode: 'numeric', placeholder: '', value: ui.swapReverseAmt || '', onInput: (e) => { ui.swapReverseAmt = e.target.value; } }),
      lim ? h('span', { class: 'small muted' }, `Min ${lim.min.toLocaleString()} · max ${lim.max.toLocaleString()} sats`) : null),
    ui.swapError ? h('div', { class: 'notice err' }, ui.swapError) : null,
    h('button', { class: 'btn-primary btn-block', disabled: !!ui.swapBusy, onClick: doReverse }, ui.swapBusy ? h('span', { class: 'spinner' }) : t('lnCreateInvoice')),
  ];
}

// Silent-payment tweak indexer picker (per network) — the endpoint used to scan
// for received silent payments. Only shown for wallets that can derive SP keys.
function spIndexerCard() {
  if (!wallet.silentPaymentKeys || !wallet.silentPaymentKeys()) return null;
  const net = getNetwork();
  const cfg = getSpIndexerConfig(net);
  return h(
    'div',
    { class: 'card col' },
    h('h3', {}, t('spIndexerTitle')),
    h('p', { class: 'small muted', style: 'margin:0' }, t('spIndexerDesc')),
    h('select', { onChange: (e) => { setSpIndexerConfig({ server: e.target.value, url: cfg.url }, net); render(); } },
      spIndexerPresets(net).map((o) => h('option', { value: o.id, selected: o.id === cfg.server }, o.id === 'custom' ? o.label : o.url.replace(/^\w+:\/\//, '')))),
    cfg.server === 'custom'
      ? h('label', { class: 'field' },
          h('span', { class: 'lab' }, t('spIndexerUrl')),
          h('input', {
            type: 'text', class: 'mono-input', placeholder: 'https://your-indexer:8888',
            autocapitalize: 'none', autocomplete: 'off', spellcheck: 'false', value: cfg.url,
            onChange: (e) => { setSpIndexerConfig({ server: 'custom', url: e.target.value.trim() }, net); render(); },
          }),
          h('div', { class: 'small faint' }, t('spIndexerHint')))
      : null
  );
}

// ---------------------------------------------------------------- Send
// Form to enter a recovery phrase / xprv and make a watch-only wallet spendable.
// Shared by the Send tab and Settings. The entered seed must derive to this
// account's xpub — you can't load the wrong wallet's seed.
function loadSeedCard() {
  const ls = ui.loadSeed;
  const seedTa = h('textarea', {
    class: 'mono-input', rows: '3', placeholder: t('seedPlaceholder'),
    autocapitalize: 'none', autocomplete: 'off', spellcheck: 'false', value: ls.value,
    onInput: (e) => { ls.value = e.target.value; },
  });
  return h(
    'div',
    { class: 'card col' },
    h('div', { class: 'row between' },
      h('h3', { style: 'margin:0' }, t('loadSeedTitle')),
      pasteBtn((text) => { seedTa.value = text; ls.value = text; })
    ),
    h('p', { class: 'small muted', style: 'margin:0' }, t('loadSeedDesc')),
    seedTa,
    h('input', {
      type: 'password', class: 'mono-input', placeholder: t('bip39PassphraseOpt'),
      autocapitalize: 'none', autocomplete: 'off', value: ls.passphrase,
      onInput: (e) => { ls.passphrase = e.target.value; },
    }),
    h('label', { class: 'row gap6', style: 'align-items:center;cursor:pointer' },
      h('input', { type: 'checkbox', checked: ls.save, onChange: (e) => { ls.save = e.target.checked; } }),
      h('span', { class: 'small' }, t('alsoSaveDevice'))
    ),
    ls.error ? h('div', { class: 'notice err' }, ls.error) : null,
    h('div', { class: 'row gap6' },
      h('button', { class: 'btn-ghost', onClick: cancelLoadSeed }, t('cancel')),
      h('button', { class: 'btn-primary grow', onClick: doLoadSeed }, t('loadSeedBtn'))
    )
  );
}

function sendTab() {
  // Watch-only wallet (e.g. restored after a session wipe without "Save to
  // device"): prompt to re-enter the seed before spending.
  if (wallet.watchOnly) {
    if (ui.loadSeed) return loadSeedCard();
    return h('div', { class: 'card col', style: 'gap:12px' },
      h('h3', {}, t('watchOnlySendTitle')),
      h('p', { class: 'small muted', style: 'margin:0' }, t('watchOnlySendDesc')),
      h('button', { class: 'btn-primary btn-block', onClick: () => startLoadSeed() }, t('loadSeedBtn'))
    );
  }
  if (ui.sendResult) return sendResultView();
  if (ui.broadcastTx) return broadcastConfirmView();
  if (ui.arkSent || ui.arkSend) return arkSendReview();
  if (ui.lnSent || ui.lnSend) return lnSendReview();
  if (ui.lnSendBusy) return h('div', { class: 'card col', style: 'align-items:center;gap:14px;padding:32px 14px' }, h('span', { class: 'spinner' }), h('p', { class: 'muted', style: 'margin:0' }, t('lnQuoting')));
  if (ui.draft) return reviewView();
  if (ui.giftMode) return giftView();
  return sendForm();
}

// The gift UI as a send-page sub-view (entered from a link on the send form).
function giftView() {
  return h(
    'div',
    { class: 'col', style: 'gap:12px' },
    giftCard(),
    // The split-offer card has its own Back; don't show a second one under it.
    ui.giftSplitOffer ? null : h('button', { class: 'btn-ghost btn-block', onClick: () => { ui.giftCode = null; ui.giftError = ''; ui.giftMax = false; ui.giftSplitOffer = null; ui.revokeId = null; goBack(() => { ui.giftMode = false; }); } }, t('back'))
  );
}

// QR scanning is only possible in a secure context with a camera.
const canScan = () =>
  typeof navigator !== 'undefined' && !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia);

// Open the camera, then route the decoded payload: a BIP21 URI or address fills
// the form; a raw signed-tx hex goes to a broadcast confirmation.
async function scanIntoSend() {
  let text;
  try {
    text = await scanQr(t);
  } catch (e) {
    ui.sendError = e.message;
    render();
    return;
  }
  if (text) handleScanned(text);
}

function handleScanned(raw) {
  const text = raw.trim();
  const s = ui.send;
  ui.sendError = '';

  // A scanned bolt11 (optionally lightning:-prefixed) → pay it over Lightning.
  const lnInv = text.replace(/^lightning:/i, '');
  if (isLnInvoice(lnInv)) { startLnSend(lnInv); return; }

  if (/^bitcoin:/i.test(text)) {
    const { address, amount } = parseBip21(text);
    if (!address) {
      ui.sendError = t('scanUnrecognized');
      render();
      return;
    }
    s.recipients[0].address = address;
    if (amount != null) {
      s.recipients[0].amount = amount;
      s.max = false;
    }
    render();
    return;
  }

  // A raw signed transaction (hex) — confirm before broadcasting.
  const compact = text.replace(/\s+/g, '');
  if (/^[0-9a-fA-F]+$/.test(compact) && compact.length >= 100 && compact.length % 2 === 0) {
    try {
      const info = wallet.parseRawTx(compact);
      ui.broadcastTx = { hex: compact, ...info };
      render();
      return;
    } catch {
      /* not a parseable tx — fall through and treat as an address */
    }
  }

  // Otherwise treat it as an address (review will validate it).
  s.recipients[0].address = text;
  render();
}

// bitcoin:<address>?amount=<btc>&label=... — amount is in BTC; convert to the
// current display unit so it lands in the form's amount field correctly.
function parseBip21(uri) {
  const m = /^bitcoin:([^?]*)(?:\?(.*))?$/i.exec(uri.trim());
  if (!m) return {};
  const address = decodeURIComponent((m[1] || '').trim());
  let amount = null;
  if (m[2]) {
    const amt = new URLSearchParams(m[2]).get('amount');
    if (amt && isFinite(Number(amt)) && Number(amt) > 0) {
      const sats = Math.round(Number(amt) * SATS);
      amount = unit === 'sats' ? String(sats) : String(Number(amt));
    }
  }
  return { address, amount };
}

function broadcastConfirmView() {
  const b = ui.broadcastTx;
  return h(
    'div',
    { class: 'card col' },
    h('h3', {}, t('broadcastScanned')),
    h(
      'div',
      { class: 'summary col', style: 'gap:0' },
      ...b.outputs.map((o) =>
        h('div', { class: 'line' },
          h('span', { class: 'k mono break' }, o.address ? shortAddr(o.address, 14, 8) : '—'),
          h('span', { class: 'v' }, fmtAmount(o.value), ' ', unitTag())
        )
      ),
      h('div', { class: 'line' },
        h('span', { class: 'k' }, t('transactionId')),
        h('span', { class: 'v mono break' }, shortTxid(b.txid))
      )
    ),
    ui.sendError && h('div', { class: 'notice err' }, ui.sendError),
    h('div', { class: 'row gap6' },
      h('button', { class: 'btn-ghost', onClick: () => { ui.broadcastTx = null; ui.sendError = ''; render(); } }, t('back')),
      ui.busy
        ? h('button', { class: 'btn-primary grow', disabled: true }, h('span', { class: 'spinner' }))
        : h('button', { class: 'btn-primary grow', onClick: broadcastScanned }, t('broadcastNow'))
    )
  );
}

// --- RBF fee bump (with a fee-rate picker) ---------------------------------
function bumpRate() {
  const s = ui.bump;
  if (s.feeChoice === 'custom') return Math.max(1, Math.round(Number(s.customFee) || 1));
  const fr = wallet.feeRates;
  return (fr && fr[s.feeChoice]) || 5;
}

// Open the bump screen: fetch + reconstruct the original, default to Priority.
async function bumpFee(txid) {
  if (wallet.offline) { toast(t('scanOffline')); return; }
  ui.busy = true;
  render();
  try {
    const prep = await wallet.prepareBump(txid);
    ui.bump = { prep, feeChoice: 'fastestFee', customFee: '' };
    ui.sendError = '';
  } catch (e) {
    toast(e.message);
  }
  ui.busy = false;
  render();
}

function bumpView() {
  const s = ui.bump;
  const feeOpts = [
    ['economyFee', t('feeEconomy')],
    ['halfHourFee', t('feeNormal')],
    ['fastestFee', t('feePriority')],
    ['custom', t('feeCustom')],
  ];
  const rate = bumpRate();
  let pl = null;
  try { pl = wallet.planBump(s.prep, rate); } catch {}
  const newFee = pl && pl.ok ? pl.fee : null;
  const planErr = pl && !pl.ok ? t('bumpInsufficient') : '';
  return h(
    'div',
    { class: 'card col' },
    h('h3', {}, t('bumpConfirm')),
    h('div', { class: 'summary col', style: 'gap:0' },
      ...s.prep.recipients.map((r) =>
        h('div', { class: 'line' },
          h('span', { class: 'k mono break' }, r.address ? shortAddr(r.address, 14, 8) : '—'),
          h('span', { class: 'v' }, fmtAmount(r.value), ' ', unitTag())
        )
      ),
      h('div', { class: 'line' },
        h('span', { class: 'k' }, t('networkFee')),
        h('span', { class: 'v' }, fmtAmount(s.prep.oldFee) + ' → ' + (newFee != null ? fmtAmount(newFee) : '—') + ' ' + unitLabel())
      )
    ),
    h('div', { class: 'field' },
      h('span', { class: 'lab' }, t('feeRate')),
      h('div', { class: 'seg', style: 'display:flex;width:100%' },
        feeOpts.map(([k, label]) =>
          h('button', {
            type: 'button', class: (s.feeChoice === k ? 'active ' : '') + 'grow',
            onClick: () => { s.feeChoice = k; if (k === 'custom' && !s.customFee) s.customFee = String(rate); render(); },
          }, label)
        )
      ),
      s.feeChoice === 'custom'
        ? h('div', { class: 'input-group mt8' },
            h('input', { type: 'number', min: '1', placeholder: 'sat/vB', value: s.customFee,
              onInput: (e) => (s.customFee = e.target.value), onChange: () => render() }),
            h('span', { class: 'small muted', style: 'align-self:center' }, 'sat/vB'))
        : h('div', { class: 'small faint mt8' }, t('selectedRate', { n: rate }))
    ),
    (ui.sendError || planErr) && h('div', { class: 'notice err' }, ui.sendError || planErr),
    h('div', { class: 'row gap6' },
      h('button', { class: 'btn-ghost', onClick: () => { ui.sendError = ''; goBack(() => { ui.bump = null; }); } }, t('back')),
      ui.busy
        ? h('button', { class: 'btn-primary grow', disabled: true }, h('span', { class: 'spinner' }))
        : h('button', { class: 'btn-primary grow', disabled: !newFee, onClick: doBump }, t('replaceTx'))
    )
  );
}

async function doBump() {
  ui.busy = true;
  ui.sendError = '';
  render();
  try {
    const d = wallet.buildBump(ui.bump.prep, bumpRate());
    const txid = await wallet.broadcast(d.hex);
    ui.sendResult = { txid };
    ui.bump = null;
    ui.txDetail = null;
    ui.tab = 'send';
    await wallet.scan().catch(() => {});
  } catch (e) {
    ui.sendError = t('broadcastFailed', { msg: e.message });
  }
  ui.busy = false;
  render();
}

async function broadcastScanned() {
  if (wallet.offline) { ui.sendError = t('scanOffline'); render(); return; }
  ui.busy = true;
  ui.sendError = '';
  render();
  try {
    const txid = await wallet.broadcast(ui.broadcastTx.hex);
    ui.sendResult = { txid };
    ui.broadcastTx = null;
    await wallet.scan().catch(() => {});
  } catch (e) {
    ui.sendError = t('broadcastFailed', { msg: e.message });
  }
  ui.busy = false;
  render();
}

// Full address as wrapping nodes, first/last 6 chars emphasized — readable
// without horizontally scrolling the input. Returns DOM nodes for in-place
// updates (the address input doesn't re-render on every keystroke).
function addrVerifyNodes(a) {
  const n = 6;
  if (!a) return [];
  if (a.length <= n * 2) return [document.createTextNode(a)];
  return [
    h('span', { class: 'hl' }, a.slice(0, n)),
    document.createTextNode(a.slice(n, -n)),
    h('span', { class: 'hl' }, a.slice(-n)),
  ];
}

// True once the destination is a real on-chain or silent-payment address — used to
// progressively reveal the amount/fee/coin controls. A Lightning invoice instead
// auto-advances to its own confirmation, so it never needs them.
function destReady(a) {
  a = (a || '').trim();
  return !!a && (wallet.isOnchainAddress(a) || isSilentPaymentAddress(a) || (isArkAddress(a) && arkAvailable()));
}

// One recipient: address + amount. Max is only offered for a single recipient.
function recipientRow(s, r, i) {
  const single = s.recipients.length === 1;
  const maxOn = single && s.max;
  r._ready = destReady(r.address); // reflected each render; onInput re-renders on a flip

  // Updated imperatively on input (and on render) so paste, typing, and scan
  // all reflect immediately without disrupting the input's focus/cursor.
  const check = h('div', { class: 'addr-check' });
  const syncCheck = () => {
    const a = r.address.trim();
    const nodes = addrVerifyNodes(a);
    check.replaceChildren(...nodes);
    check.style.display = a ? '' : 'none';
  };

  // A pasted/typed/scanned bolt11 → jump straight to the Lightning confirmation
  // (a submarine swap), so its baked-in amount is used and the amount field skipped.
  const tryLn = (v) => {
    const inv = (v || '').trim().replace(/^lightning:/i, '');
    if (s.recipients.length === 1 && !ui.lnSendBusy && !ui.lnSend && isLnInvoice(inv)) { startLnSend(inv); return true; }
    return false;
  };
  const addrInput = h('input', {
    type: 'text', class: 'mono-input grow', placeholder: i === 0 ? t('destPlaceholder') : 'bc1q…',
    autocapitalize: 'none', autocomplete: 'off', spellcheck: 'false', value: r.address,
    onInput: (e) => {
      const v = e.target.value;
      r.address = v; syncCheck();
      if (tryLn(v)) return;                    // a bolt11 advances to its own confirmation
      if (destReady(v) !== r._ready) render();  // reveal/hide amount + controls as validity flips
    },
  });
  const row = h(
    'div',
    { class: 'col gap6' },
    h('div', { class: 'input-group' },
      addrInput,
      pasteBtn((text) => { addrInput.value = text; r.address = text; syncCheck(); if (!tryLn(text) && destReady(text) !== r._ready) render(); }),
      i === 0 && canScan() && h('button', {
        type: 'button', class: 'btn-sm', title: t('scanQr'), onClick: scanIntoSend,
        html: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 8V5a1 1 0 0 1 1-1h3M16 4h3a1 1 0 0 1 1 1v3M20 16v3a1 1 0 0 1-1 1h-3M8 20H5a1 1 0 0 1-1-1v-3"/></svg>',
      }),
      !single && h('button', { type: 'button', class: 'btn-sm', title: t('remove'), onClick: () => { s.recipients.splice(i, 1); render(); } }, '✕')
    ),
    check,
    r._ready ? h('div', { class: 'input-group' },
      h('input', {
        type: 'number', step: unit === 'sats' ? '1' : '0.00000001', min: '0',
        placeholder: unit === 'sats' ? '0' : '0.00000000',
        disabled: maxOn,
        value: maxOn
          ? (unit === 'sats' ? String(estimatedMaxSats()) : fmtBtc(estimatedMaxSats()))
          : r.amount,
        onInput: (e) => {
          let v = e.target.value;
          // Chrome emits scientific notation when stepping tiny BTC amounts.
          if (v && /e/i.test(v)) {
            const n = Number(v);
            if (isFinite(n)) {
              v = unit === 'sats' ? String(Math.round(n)) : n.toFixed(8).replace(/\.?0+$/, '');
              e.target.value = v;
            }
          }
          r.amount = v;
        },
      }),
      h('button', { type: 'button', title: t('switchUnit'), onClick: toggleUnit }, unitLabel()),
      single && h('button', { type: 'button', class: s.max ? 'btn-primary' : '', onClick: () => { s.max = !s.max; render(); } }, t('max'))
    ) : null
  );
  syncCheck();
  return row;
}

function sendForm() {
  const s = ui.send;
  // Progressive disclosure: until the destination is a valid on-chain/SP address,
  // show only the destination input (a Lightning invoice auto-advances instead).
  const ready = destReady((s.recipients[0] || {}).address);
  const feeOpts = [
    ['economyFee', t('feeEconomy')],
    ['halfHourFee', t('feeNormal')],
    ['fastestFee', t('feePriority')],
    ['custom', t('feeCustom')],
  ];
  return h(
    'div',
    { class: 'card col' },
    h(
      'div',
      { class: 'field' },
      h('span', { class: 'lab' }, s.recipients.length > 1 ? t('recipients') : t('recipient')),
      h('div', { class: 'col', style: 'gap:14px' },
        s.recipients.map((r, i) => recipientRow(s, r, i))
      ),
      ready && s.recipients.length < 10 &&
        h('button', {
          type: 'button', class: 'linklike small mt8',
          onClick: () => { s.recipients.push({ address: '', amount: '' }); s.max = false; render(); },
        }, t('addRecipient'))
    ),
    ready && h(
      'div',
      { class: 'field' },
      h('span', { class: 'lab' }, t('feeRate')),
      h(
        'div',
        { class: 'seg', style: 'display:flex;width:100%' },
        feeOpts.map(([k, label]) =>
          h('button', {
            type: 'button', class: (s.feeChoice === k ? 'active ' : '') + 'grow',
            onClick: () => {
              s.feeChoice = k;
              if (k === 'custom' && !s.customFee) {
                s.customFee = String((wallet.feeRates && wallet.feeRates.economyFee) || 1);
              }
              render();
            },
          }, label)
        )
      ),
      s.feeChoice === 'custom' &&
        h('div', { class: 'input-group mt8' },
          h('input', { type: 'number', min: '1', placeholder: 'sat/vB', value: s.customFee, onInput: (e) => (s.customFee = e.target.value) }),
          h('span', { class: 'small muted', style: 'align-self:center' }, 'sat/vB')
        ),
      s.feeChoice !== 'custom' &&
        h('div', { class: 'small faint mt8' }, t('selectedRate', { n: currentFeeRate() }))
    ),
    ready ? coinControl() : null,
    ui.sendError && h('div', { class: 'notice err' }, ui.sendError),
    ready && h('button', { class: 'btn-primary btn-block', onClick: reviewSend }, t('reviewTx')),
    h('button', { class: 'linklike small', style: 'align-self:center;margin-top:2px', onClick: () => { ui.giftMode = true; ui.sendError = ''; render(); } }, '🎁 ' + t('giftLink'))
  );
}

function coinControl() {
  const s = ui.send;
  const head = h(
    'div',
    { class: 'row between' },
    h('span', { class: 'lab', style: 'margin:0' }, t('coinSelection')),
    h(
      'div',
      { class: 'seg' },
      h('button', { type: 'button', class: !s.manual ? 'active' : '', onClick: () => { s.manual = false; render(); } }, t('automatic')),
      h('button', { type: 'button', class: s.manual ? 'active' : '', onClick: () => { s.manual = true; render(); } }, t('manual'))
    )
  );
  if (!s.manual) return h('div', { class: 'col gap6' }, head);

  if (!wallet.utxos.length)
    return h('div', { class: 'col gap6' }, head, h('div', { class: 'small muted' }, t('noCoins')));

  let selTotal = 0;
  const rows = wallet.utxos.map((u) => {
    const id = utxoId(u);
    const checked = s.coins.has(id);
    if (checked) selTotal += u.value;
    return h(
      'label',
      { class: 'coin' },
      h('input', {
        type: 'checkbox', checked,
        onChange: (e) => { e.target.checked ? s.coins.add(id) : s.coins.delete(id); render(); },
      }),
      h('div', { class: 'grow' },
        h('div', { class: 'mono small break' }, shortAddr(u.address, 14, 10),
          !u.confirmed ? h('span', { class: 'tag pending', style: 'margin-left:6px' }, t('pendingTag')) : null),
        h('div', { class: 'path' }, `${u.chain}/${u.index} · ${shortTxid(u.txid)}:${u.vout}`)
      ),
      h('div', { class: 'amount small' }, fmtAmount(u.value))
    );
  });
  return h(
    'div',
    { class: 'col gap6' },
    head,
    h('div', { class: 'list' }, rows),
    h('div', { class: 'row between small' },
      h('span', { class: 'muted' }, t('nSelected', { n: s.coins.size })),
      h('span', { class: 'amount' }, fmtAmount(selTotal), ' ', unitTag())
    )
  );
}

// Coins that a send would draw from (all, or the manually-selected subset).
function spendableCoins() {
  const s = ui.send;
  return s.manual ? wallet.utxos.filter((u) => s.coins.has(utxoId(u))) : wallet.utxos;
}

// Estimated max sendable = selected total − fee for (n inputs, 1 output).
function estimatedMaxSats() {
  const coins = spendableCoins();
  const total = coins.reduce((a, u) => a + u.value, 0);
  const vbytes = 11 + 68 * coins.length + 31;
  const fee = Math.ceil(vbytes * currentFeeRate());
  return Math.max(0, total - fee);
}

function currentFeeRate() {
  const s = ui.send;
  if (s.feeChoice === 'custom') return Math.max(1, Math.round(Number(s.customFee) || 1));
  const fr = wallet.feeRates;
  if (fr && fr[s.feeChoice]) return fr[s.feeChoice];
  return 5;
}

function reviewSend() {
  ui.sendError = '';
  try {
    const s = ui.send;
    // A bolt11 invoice in the recipient field → pay it over Lightning via a Boltz
    // submarine swap, shown with an itemized cost. To the user it's just a payment.
    const lnTarget = s.recipients.length === 1 ? (s.recipients[0].address || '').trim().replace(/^lightning:/i, '') : '';
    if (isLnInvoice(lnTarget)) { startLnSend(lnTarget); return; }
    // An Ark address → instant off-chain send, no mining fee; its own confirmation.
    if (s.recipients.length === 1 && isArkAddress(s.recipients[0].address)) {
      if (!arkAvailable()) throw new Error(t('arkNotConnected'));
      const sats = parseAmount(s.recipients[0].amount, unit);
      if (!sats || sats <= 0) throw new Error(t('enterValidAmtForN', { n: 1 }));
      ui.arkSend = { address: s.recipients[0].address.trim(), amountSat: sats };
      return render();
    }
    const feeRate = currentFeeRate();
    let coinIds = null;
    if (s.manual) {
      coinIds = [...s.coins];
      if (!coinIds.length) throw new Error(t('selectCoin'));
    }
    let recipients, sendMax = false;
    if (s.max && s.recipients.length === 1) {
      const addr = s.recipients[0].address.trim();
      if (!addr) throw new Error(t('enterRecipientAddr'));
      recipients = [{ address: addr, amount: 0 }];
      sendMax = true;
    } else {
      recipients = s.recipients.map((r, i) => {
        const addr = r.address.trim();
        if (!addr) throw new Error(t('enterAddrForN', { n: i + 1 }));
        const sats = parseAmount(r.amount, unit);
        if (!sats || sats <= 0) throw new Error(t('enterValidAmtForN', { n: i + 1 }));
        return { address: addr, amount: sats };
      });
    }
    ui.draft = wallet.buildTx({ recipients, feeRate, coinIds, sendMax });
  } catch (e) {
    ui.draft = null;
    ui.sendError = e.message;
  }
  render();
}

// Ark send confirmation: amount + destination, zero fees, instant. After the
// send, a simple success view (there is no on-chain txid to link).
function arkSendReview() {
  if (ui.arkSent) {
    return h(
      'div',
      { class: 'card col', style: 'align-items:center;text-align:center;gap:14px;padding:40px 20px' },
      h('div', { class: 'check-badge' }, '✓'),
      h('h2', { style: 'margin:0' }, t('arkSentTitle')),
      h('div', { class: 'amount-pos', style: 'font-size:18px' }, '-' + fmtAmount(ui.arkSent.amountSat) + ' ' + unitLabel()),
      h('button', { class: 'btn-primary btn-block', onClick: () => { ui.arkSent = null; ui.send = blankSend(); render(); } }, t('done'))
    );
  }
  const a = ui.arkSend;
  const row = (k, v) => h('div', { class: 'row between' }, h('span', { class: 'small muted' }, k), h('span', { class: 'small' }, v));
  return h(
    'div',
    { class: 'card col', style: 'gap:12px' },
    h('h3', {}, t('arkSendTitle')),
    row(t('lnPayAmount'), fmtAmount(a.amountSat) + ' ' + unitLabel()),
    row(t('arkPayTo'), shortAddr(a.address, 14)),
    row(t('networkFee'), t('arkNoFee')),
    ui.sendError ? h('div', { class: 'notice err' }, ui.sendError) : null,
    h('div', { class: 'row gap6' },
      h('button', { class: 'btn-ghost', onClick: () => { ui.arkSend = null; ui.sendError = ''; render(); } }, t('back')),
      ui.busy
        ? h('button', { class: 'btn-primary grow', disabled: true }, h('span', { class: 'spinner' }))
        : h('button', { class: 'btn-primary grow', onClick: doArkSend }, t('arkSendBtn'))
    )
  );
}

async function doArkSend() {
  const a = ui.arkSend;
  ui.busy = true; ui.sendError = ''; render();
  try {
    const mgr = await connectArk();
    await mgr.send(a.address, a.amountSat);
    ui.arkSent = { amountSat: a.amountSat };
    ui.arkSend = null;
  } catch (e) {
    ui.sendError = e.message;
  }
  ui.busy = false; render();
}

// A bolt11 Lightning invoice (any network prefix); long ln-prefixed bech32 string.
function isLnInvoice(t) { t = (t || '').trim(); return /^ln[a-z0-9]+$/i.test(t) && t.length > 50; }

// Quote a submarine swap for a pasted invoice, then show the itemized cost.
async function startLnSend(invoice) {
  ui.sendError = ''; ui.lnSend = null; ui.lnSent = null; ui.lnSendBusy = true; render();
  try { ui.lnSend = await swaps.quoteSubmarine(invoice); }
  catch (e) { ui.sendError = e.message; }
  ui.lnSendBusy = false; render();
}

async function doLnPay() {
  if (!ui.lnSend) return;
  ui.sendError = ''; ui.lnSendBusy = true; render();
  try { const rec = await swaps.fundQuotedSubmarine(ui.lnSend); ui.lnSent = { amount: ui.lnSend.invoiceAmount, id: rec.id }; }
  catch (e) { ui.sendError = e.message; }
  ui.lnSendBusy = false; render();
}

// Lightning send review: itemized cost (amount + Boltz fee + network fee → total),
// then a success card once funded. The provider pays the invoice after it confirms.
function lnSendReview() {
  const u = ' ' + unitLabel();
  if (ui.lnSent) {
    return h('div', { class: 'col', style: 'gap:16px' },
      h('div', { class: 'card col', style: 'align-items:center;text-align:center;gap:8px' },
        h('div', { class: 'check-badge' }, '⚡'),
        h('h2', { style: 'margin:0' }, t('lnPaySentTitle')),
        ui.lnSent.amount ? h('div', { class: 'amount-pos', style: 'font-size:18px' }, fmtAmount(ui.lnSent.amount) + u) : null,
        h('p', { class: 'muted', style: 'margin:0' }, t('lnPaySentBody'))),
      h('button', { class: 'btn-primary btn-block', onClick: () => { ui.lnSent = null; ui.lnSend = null; ui.send = blankSend(); ui.tab = 'history'; render(); } }, t('done')));
  }
  const q = ui.lnSend;
  const row = (label, sats, bold) => h('div', { class: 'row', style: 'justify-content:space-between' + (bold ? ';font-weight:600' : '') },
    h('span', { class: bold ? '' : 'small muted' }, label), h('span', {}, fmtAmount(sats) + u));
  return h('div', { class: 'col', style: 'gap:12px' },
    h('div', { class: 'card col', style: 'gap:10px' },
      h('h3', { style: 'margin:0' }, t('lnPayTitle')),
      q.invoiceAmount != null ? row(t('lnPayAmount'), q.invoiceAmount) : null,
      q.boltzFee != null ? row(t('lnPayBoltzFee'), q.boltzFee) : null,
      row(t('lnPayNetworkFee'), q.networkFee),
      h('div', { style: 'border-top:1px solid var(--line, #ddd);margin:2px 0' }),
      row(t('lnPayTotal'), q.total, true)),
    ui.sendError ? h('div', { class: 'notice err' }, ui.sendError) : null,
    h('button', { class: 'btn-primary btn-block', disabled: !!ui.lnSendBusy, onClick: doLnPay }, ui.lnSendBusy ? h('span', { class: 'spinner' }) : t('lnPayConfirm')),
    h('button', { class: 'btn-ghost btn-block', onClick: () => { ui.lnSend = null; ui.sendError = ''; render(); } }, t('back')));
}

function reviewView() {
  const d = ui.draft;
  const changeAddr = wallet.freshChange().address;
  const outs = d.outputs.filter((o) => o.address !== changeAddr);
  return h(
    'div',
    { class: 'card col' },
    h('h3', {}, t('reviewTx')),
    h(
      'div',
      { class: 'summary col', style: 'gap:0' },
      ...outs.map((o) =>
        h('div', { class: 'line' },
          o.silent
            ? h('span', { class: 'k col', style: 'gap:2px;align-items:flex-start' },
                h('span', { class: 'mono break' }, shortAddr(o.silent, 12, 8)),
                h('span', { class: 'small faint' }, t('silentPaymentNote'))
              )
            : h('span', { class: 'k mono break' }, shortAddr(o.address, 14, 8)),
          h('span', { class: 'v' }, fmtAmount(o.amount), ' ', unitTag())
        )
      ),
      h('div', { class: 'line' },
        h('span', { class: 'k' }, t('networkFee')),
        h('span', { class: 'v' }, fmtAmount(d.fee), ' ', unitTag())
      )
    ),
    ui.sendError && h('div', { class: 'notice err' }, ui.sendError),
    wallet.spendsUnconfirmed(d.tx)
      ? h('div', { class: 'notice info' }, t('unconfirmedInputWarn'))
      : null,
    wallet.offline
      ? h('div', { class: 'notice info' }, t('offlineSignNote'))
      : null,
    h(
      'div',
      { class: 'row gap6' },
      h('button', { class: 'btn-ghost', onClick: () => { ui.draft = null; ui.sendError = ''; render(); } }, t('back')),
      ui.busy
        ? h('button', { class: 'btn-primary grow', disabled: true }, h('span', { class: 'spinner' }))
        : wallet.offline
          ? h('button', { class: 'btn-primary grow', onClick: signForExport }, t('signTx'))
          : h('button', { class: 'btn-primary grow', onClick: broadcast }, t('signBroadcast'))
    ),
    // Online: also allow signing without broadcasting, to relay the signed tx
    // from another device (air-gapped, or a different network).
    !wallet.offline && !ui.busy
      ? h('button', { class: 'btn-block', style: 'margin-top:8px', onClick: signForExport }, t('signExport'))
      : null
  );
}

async function broadcast() {
  ui.busy = true;
  ui.sendError = '';
  render();
  try {
    const hexTx = wallet.sign(ui.draft.tx);
    const txid = await Promise.race([
      wallet.broadcast(hexTx),
      new Promise((_, rej) => setTimeout(() => rej(new Error(t('broadcastTimeout'))), 30000)),
    ]);
    wallet.applySentTx(ui.draft.tx); // update balance/history locally, right now
    ui.sendResult = { txid };
    ui.draft = null;
    ui.send = blankSend();
    ui.busy = false;
    render(); // the realtime watcher / backstop poll reconciles + confirms later
    return;
  } catch (e) {
    ui.sendError = t('broadcastFailed', { msg: e.message });
  }
  ui.busy = false;
  render();
}

function signForExport() {
  ui.sendError = '';
  try {
    const tx = ui.draft.tx;
    const hexTx = wallet.sign(tx);
    ui.sendResult = { signedHex: hexTx, txid: tx.id };
    ui.draft = null;
    ui.send = blankSend();
  } catch (e) {
    ui.sendError = t('signingFailed', { msg: e.message });
  }
  render();
}

function sendResultView() {
  const r = ui.sendResult;
  const again = h('button', { class: 'btn-block mt8', onClick: () => { ui.sendResult = null; render(); } }, t('done'));
  if (r.signedHex) {
    return h(
      'div',
      { class: 'card col' },
      h('div', { class: 'warn-box' }, t('txSignedNote')),
      h('div', { class: 'small muted' }, t('transactionId')),
      h('div', { class: 'addr-box' }, r.txid),
      h('div', { class: 'small muted mt8' }, t('signedTxRaw')),
      h('textarea', { readonly: true, style: 'min-height:120px', value: r.signedHex }),
      h('div', { class: 'row gap6' },
        copyBtn(r.signedHex, t('copyHex')),
        h('button', { class: 'btn-sm', onClick: () => download(`tx-${r.txid.slice(0, 8)}.txt`, r.signedHex, 'text/plain') }, t('downloadLabel')),
        h('div', { class: 'grow', html: '' })
      ),
      h('details', { class: 'mt8' }, h('summary', { class: 'small muted' }, t('showQrAirgap')), h('div', { style: 'margin-top:10px', html: qrSvg(r.signedHex) })),
      again
    );
  }
  return h(
    'div',
    { class: 'card col', style: 'align-items:center' },
    h('div', { class: 'notice ok', style: 'width:100%' }, t('txBroadcast')),
    h('div', { class: 'small muted' }, t('transactionId')),
    h('div', { class: 'addr-box' }, r.txid),
    h('div', { class: 'row gap6' },
      copyBtn(r.txid, t('copyTxid')),
      h('a', { class: 'btn btn-sm', href: wallet.api.explorerTx(r.txid), target: '_blank', rel: 'noopener', onClick: (e) => { e.preventDefault(); openExternal(wallet.api.explorerTx(r.txid)); } }, t('viewOnMempool'))
    ),
    again
  );
}

// ---------------------------------------------------------------- History
// An outstanding sent gift shown in History: tappable to cancel (reclaim the
// coin for a future payment, or revoke the link on-chain) without going through
// the Send → gift card. Reuses the same confirm state and handlers.
function giftHistoryItem(g) {
  if (ui.revokeId === g.id) {
    return h('div', { class: 'item col', style: 'align-items:stretch;gap:8px' },
      h('span', { class: 'small muted' }, g.reserved ? t('giftReclaimPrompt') : t('giftRevokeConfirm')),
      ui.busy
        ? h('button', { class: 'btn-primary btn-block', disabled: true }, h('span', { class: 'spinner' }))
        : h('div', { class: 'row gap6' },
            g.reserved ? h('button', { class: 'btn-ghost grow', onClick: () => doReclaim(g.id) }, t('giftReclaim')) : null,
            h('button', { class: 'btn-primary grow', onClick: () => doRevoke(g.id) }, t('giftRevoke'))
          ),
      ui.busy ? null : h('button', { class: 'btn-ghost btn-block', onClick: () => { ui.revokeId = null; render(); } }, t('back'))
    );
  }
  const amt = g.value != null ? g.value : g.amount;
  const rec = g.claimed ? null : wallet.giftLink(g.id);
  return h('div', { class: 'item' },
    h('div', { class: 'ico out' }, '🎁'),
    h('div', { class: 'grow' },
      h('div', { class: 'row gap6' }, t('giftHistoryTitle'),
        h('span', { class: 'tag ' + (g.claimed ? 'conf' : 'pending') }, g.claimed ? t('giftClaimedTag') : g.reserved ? t('giftUnclaimedTag') : t('giftReclaimedTag'))),
      !g.claimed && g.reserved ? h('div', { class: 'small faint' }, t('lockedInGifts')) : null
    ),
    h('div', { style: 'text-align:right' },
      amt != null ? h('div', { class: 'amount' }, fmtAmount(amt)) : null,
      g.claimed ? null : h('div', { class: 'row gap6', style: 'justify-content:flex-end;margin-top:4px' },
        rec ? h('button', { class: 'btn-sm', onClick: () => { ui.viewGift = rec; render(); } }, t('giftView')) : null,
        h('button', { class: 'btn-sm', onClick: () => { ui.revokeId = g.id; render(); } }, t('giftCancel')))
    )
  );
}

// An Ark movement (receive / send / board) as a history row. No txid to open —
// these are off-chain; the Settings card shows the fuller activity detail.
function arkHistoryItem(m) {
  const incoming = m.type !== 'send';
  const label = m.type === 'receive' ? t('received') : m.type === 'board' ? t('arkBoarded') : t('sent');
  return h(
    'div',
    { class: 'item' },
    h('div', { class: `ico ${incoming ? 'in' : 'out'}` }, incoming ? '↓' : '↑'),
    h('div', { class: 'grow' },
      h('div', { class: 'row gap6' },
        label,
        h('span', { class: 'tag' }, 'Ark'),
        m.status !== 'complete' ? h('span', { class: 'tag pending' }, m.status) : null),
      h('div', { class: 'small faint' }, timeAgo(m.ts / 1000))),
    h('div', { style: 'text-align:right' },
      h('div', { class: incoming ? 'amount-pos' : 'amount-neg' }, (incoming ? '+' : '-') + fmtAmount(m.amountSat)))
  );
}

function txHistoryItem(tx) {
  const incoming = tx.net >= 0;
  const stuck = !tx.confirmed && wallet.isStuck(tx);
  return h(
    'div',
    { class: 'item', style: 'cursor:pointer', onClick: () => openTx(tx.txid) },
    h('div', { class: `ico ${incoming ? 'in' : 'out'}` }, incoming ? '↓' : '↑'),
    h('div', { class: 'grow' },
      h('div', { class: 'row gap6' },
        incoming ? t('received') : t('sent'),
        tx.confirmed ? null
          : stuck ? h('span', { class: 'tag', style: 'background:var(--red-soft);color:var(--red)' }, t('stuckTag'))
          : h('span', { class: 'tag pending' }, t('pendingTag'))
      ),
      h('div', { class: 'small faint' }, tx.confirmed ? timeAgo(tx.blockTime) : stuck ? t('stuckNote') : t('awaitingConfirmation'))
    ),
    h('div', { style: 'text-align:right' },
      h('div', { class: incoming ? 'amount-pos' : 'amount-neg' }, (incoming ? '+' : '') + fmtAmount(tx.net)),
      !incoming && tx.fee ? h('div', { class: 'small faint' }, t('feeShort', { x: fmtAmount(tx.fee) })) : null
    )
  );
}

// Prev / page-of / next controls. Returns null when there's only one page.
const PAGE_SIZE = 10;
function pager(page, total, onPage) {
  const pages = Math.ceil(total / PAGE_SIZE);
  if (pages <= 1) return null;
  return h('div', { class: 'row between', style: 'align-items:center;padding-top:10px' },
    h('button', { class: 'btn-sm', disabled: page <= 0, onClick: () => onPage(page - 1) }, t('prevPage')),
    h('span', { class: 'small muted' }, t('pageXofY', { x: page + 1, y: pages })),
    h('button', { class: 'btn-sm', disabled: page >= pages - 1, onClick: () => onPage(page + 1) }, t('nextPage'))
  );
}

// Full paginated list of outstanding sent gifts, reached via "View all" when
// there are more than fit inline on the History page.
function giftsAllView(gifts) {
  const pages = Math.ceil(gifts.length / PAGE_SIZE);
  const page = Math.min(ui.giftsPage, Math.max(0, pages - 1));
  const slice = gifts.slice(page * PAGE_SIZE, page * PAGE_SIZE + PAGE_SIZE);
  return h(
    'div',
    { class: 'card col', style: 'gap:12px' },
    h('div', { class: 'row between' },
      h('h3', { style: 'margin:0' }, t('giftReserved', { n: gifts.length })),
      h('button', { class: 'btn-sm', onClick: () => { ui.revokeId = null; goBack(() => { ui.giftsAll = false; }); } }, t('back'))
    ),
    h('div', { class: 'list' }, ...slice.map(giftHistoryItem)),
    pager(page, gifts.length, (p) => { ui.giftsPage = p; render(); })
  );
}

function historyTab() {
  if (ui.bump) return bumpView();
  const txs = wallet.history; // BIP84 txs + silent-payment receipts, newest first
  if (ui.txDetail) {
    const tx = txs.find((x) => x.txid === ui.txDetail);
    if (tx) return txDetailView(tx);
    ui.txDetail = null;
  }
  if (wallet.offline)
    return h('div', { class: 'card' }, h('p', { class: 'muted center', style: 'margin:0' }, t('historyOffline')));
  if ((wallet.scanning && !wallet.loaded) || (wallet.historyLoading && !txs.length))
    return h(
      'div',
      { class: 'card center col', style: 'align-items:center;gap:10px' },
      h('span', { class: 'spinner' }),
      wallet.historyLoading ? h('p', { class: 'small muted', style: 'margin:0' }, t('loadingHistory')) : null
    );
  // Outstanding sent gifts (reserved/reclaimed but unclaimed) sit above the
  // on-chain history; they aren't transactions until claimed or revoked.
  const gifts = wallet.loaded
    ? [...wallet.outstandingGifts(), ...wallet.claimedGifts().map((c) => ({ ...c, claimed: true }))]
    : [];
  if (ui.giftsAll && gifts.length) return giftsAllView(gifts);
  // Ark receives/sends/boards interleave with on-chain txs by time. (Refreshes
  // are internal churn — they stay in the Settings activity list only.)
  const arkMoves = ark && ark.state
    ? ark.movements().filter((m) => ['receive', 'send', 'board'].includes(m.type) && m.status === 'complete')
    : [];
  if (!txs.length && !gifts.length && !arkMoves.length)
    return h('div', { class: 'card' }, h('p', { class: 'muted center', style: 'margin:0' }, t('noTxYet')));

  // Show at most 3 gifts inline; the rest live behind "View all". Transactions
  // and Ark movements merge into one timeline, paginated 10 at a time.
  const giftsHead = gifts.slice(0, 3);
  const entries = [
    ...txs.map((tx) => ({ time: tx.confirmed ? (tx.blockTime || 0) * 1000 : Date.now(), render: () => txHistoryItem(tx) })),
    ...arkMoves.map((m) => ({ time: m.ts, render: () => arkHistoryItem(m) })),
  ].sort((a, b) => b.time - a.time);
  const txPages = Math.ceil(entries.length / PAGE_SIZE);
  const txPage = Math.min(ui.txPage, Math.max(0, txPages - 1));
  const txSlice = entries.slice(txPage * PAGE_SIZE, txPage * PAGE_SIZE + PAGE_SIZE);
  return h(
    'div',
    { class: 'card' },
    h('div', { class: 'list' },
      ...giftsHead.map(giftHistoryItem),
      ...txSlice.map((e) => e.render())
    ),
    gifts.length > 3
      ? h('button', { class: 'btn-sm btn-block', style: 'margin-top:8px', onClick: () => { ui.giftsAll = true; ui.giftsPage = 0; ui.revokeId = null; render(); } }, t('viewAllGifts', { n: gifts.length }))
      : null,
    pager(txPage, entries.length, (p) => { ui.txPage = p; render(); }),
    wallet.historyLoading
      ? h(
          'div',
          { class: 'row gap6', style: 'padding:10px 0 2px;justify-content:center' },
          h('span', { class: 'spinner sm' }),
          h('span', { class: 'small muted' }, t('loadingHistory'))
        )
      : null
  );
}

// Open a tx's detail view, lazily fetching its fee/details if we don't have them
// yet. A watcher-credited receive arrives with no fee (the push can't compute it
// from the raw tx), so fill it in from the explorer on demand — works for pending
// mempool txs too.
async function openTx(txid) {
  ui.txDetail = txid;
  render();
  const tx = wallet.history.find((t) => t.txid === txid);
  if (!tx || tx.sp || tx.fee || wallet.offline) return;
  try {
    const full = await wallet.api.getTx(txid);
    if (!full || ui.txDetail !== txid) return;
    if (full.fee != null) tx.fee = full.fee;
    if (full.weight) tx.vsize = Math.ceil(full.weight / 4);
    if (full.status && full.status.confirmed) {
      tx.confirmed = true;
      tx.blockHeight = full.status.block_height || tx.blockHeight;
      tx.blockTime = full.status.block_time || tx.blockTime;
    }
    wallet.saveCache();
    render();
  } catch {}
}

// Lightning-swap context shown inside a tx's detail screen (the on-chain tx is the
// swap's lockup funding, claim, or refund). Replaces the old standalone Swap list.
function swapTxDetailSection(swap, tx) {
  const u = ' ' + unitLabel();
  const line = (k, v) => h('div', { class: 'line' }, h('span', { class: 'k' }, k), h('span', { class: 'v' }, v));
  const head = (txt) => h('div', { style: 'font-weight:600;margin:12px 0 2px' }, txt);
  if (swap.refundTxid === tx.txid)
    return h('div', { class: 'summary col', style: 'gap:0' }, head('↩ Lightning swap refund'), line(t('status'), 'Refunded ✓'));
  if (swap.kind === 'submarine') {
    const fee = (swap.expectedAmount || 0) - (swap.invoiceAmount || 0);
    const st = swap.status === 'success' ? 'Invoice paid ✓'
      : swap.status === 'refundable' ? 'Payment failed — refundable'
      : swap.status === 'refunded' ? 'Refunded' : 'Paying…';
    return h('div', { class: 'summary col', style: 'gap:0' },
      head('⚡ Paid over Lightning'),
      swap.invoiceAmount != null ? line('Invoice', fmtAmount(swap.invoiceAmount) + u) : null,
      fee > 0 ? line('Swap fee', fmtAmount(fee) + u) : null,
      line(t('status'), st),
      swap.status === 'refundable'
        ? h('button', { class: 'btn-sm btn-block', style: 'margin-top:8px', disabled: !!ui.swapBusy, onClick: () => doRefund(swap.id) }, 'Refund on-chain')
        : null);
  }
  // reverse swap claim
  return h('div', { class: 'summary col', style: 'gap:0' },
    head('⚡ Received over Lightning'),
    line(t('status'), swap.status === 'claimed' ? 'Settled ✓' : swap.status));
}

function txDetailView(tx) {
  const incoming = tx.net >= 0;
  const swap = swaps.findByTxid(tx.txid); // this tx's swap (Lightning), if any
  const line = (k, v) => h('div', { class: 'line' }, h('span', { class: 'k' }, k), h('span', { class: 'v' }, v));
  return h(
    'div',
    { class: 'card col' },
    h('div', { class: 'row between' },
      h('h3', {}, incoming ? t('received') : t('sent')),
      h('span', { class: `tag ${tx.confirmed ? 'conf' : 'pending'}` }, tx.confirmed ? t('confirmedTag') : t('pendingTag'))
    ),
    h('div', { class: 'amt', style: 'font-size:30px' },
      h('span', { class: incoming ? 'amount-pos' : 'amount-neg' }, (incoming ? '+' : '') + fmtAmount(tx.net)),
      ' ', unitTag('unit')
    ),
    h('div', { class: 'summary col', style: 'gap:0' },
      line(t('status'), tx.confirmed ? t('confirmed') : t('pending')),
      tx.confirmed ? line(t('block'), String(tx.blockHeight || '—')) : null,
      tx.confirmed && tx.blockTime ? line(t('date'), new Date(tx.blockTime * 1000).toLocaleString()) : null,
      tx.fee ? line(t('networkFee'), fmtAmount(tx.fee) + ' ' + unitLabel()) : null
    ),
    swap ? swapTxDetailSection(swap, tx) : null,
    !tx.confirmed && wallet.isStuck(tx)
      ? h('div', { class: 'warn-box' }, incoming ? t('stuckIncomingNote') : t('stuckOutgoingNote'))
      : null,
    h('div', { class: 'col gap6' },
      h('span', { class: 'lab' }, t('transactionId')),
      h('div', { class: 'addr-box', style: 'font-size:13px' }, tx.txid)
    ),
    h('div', { class: 'row gap6 wrap' },
      copyBtn(tx.txid, t('copyId')),
      h('a', { class: 'btn btn-sm', href: wallet.api.explorerTx(tx.txid), target: '_blank', rel: 'noopener', onClick: (e) => { e.preventDefault(); openExternal(wallet.api.explorerTx(tx.txid)); } }, t('viewOnMempool'))
    ),
    // RBF: an unconfirmed send can be rebroadcast at a higher fee.
    !tx.confirmed && !incoming && !wallet.offline
      ? (ui.busy
          ? h('button', { class: 'btn-primary btn-block', disabled: true }, h('span', { class: 'spinner' }))
          : h('button', { class: 'btn-primary btn-block', onClick: () => bumpFee(tx.txid) }, t('bumpFee')))
      : null,
    h('button', { class: 'btn-ghost btn-block', onClick: () => goBack(() => { ui.txDetail = null; }) }, t('backToHistory'))
  );
}

// Offline snapshot exchange: export coins on an online device, import on an
// offline (air-gapped) one to sign without internet.
function snapshotActions() {
  return h(
    'div',
    { class: 'col gap6' },
    h('p', { class: 'small muted', style: 'margin:0' },
      t('offlineTransferDesc')),
    h('div', { class: 'row gap6 wrap' },
      h('button', { class: 'btn-sm', disabled: !wallet.utxos.length, onClick: exportSnapshot }, t('exportSnapshot')),
      h('label', { class: 'btn btn-sm', style: 'cursor:pointer' }, t('importSnapshot'),
        h('input', { type: 'file', accept: 'application/json,.json', style: 'display:none', onChange: importSnapshotFile })
      )
    )
  );
}

function exportSnapshot() {
  const snap = wallet.exportSnapshot();
  const stamp = new Date().toISOString().slice(0, 10);
  download(`wallet-snapshot-${wallet.netName}-${stamp}.json`, JSON.stringify(snap, null, 2));
  toast(t('snapshotExported'));
}

async function importSnapshotFile(e) {
  const file = e.target.files[0];
  if (!file) return;
  try {
    const snap = JSON.parse(await file.text());
    const res = wallet.importSnapshot(snap);
    let msg = t('importedNCoins', { n: res.imported });
    if (res.unmatched.length) msg += t('unmatchedSuffix', { n: res.unmatched.length });
    toast(msg);
    ui.tab = 'settings';
    render();
  } catch (err) {
    toast(t('importFailed', { msg: err.message }));
  }
  e.target.value = '';
}

// ================================================================ start
// Load the active language's strings (English is inline; others are fetched),
// apply text direction, then restore a wallet left open in this tab — otherwise
// show the unlock screen.
applyDir();
// Auto log-out: start the countdown only when the app loses focus / is hidden,
// and cancel it the moment it's focused again. So it never logs out mid-use.
window.addEventListener('blur', onAppHidden);
window.addEventListener('focus', onAppVisible);
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden') onAppHidden();
  else onAppVisible();
});
loadLocale(getLang()).finally(() => {
  applyBootAutoLogout(); // clear an overdue session before we read it for claim targets
  const code = readGiftHash();
  if (code) { claimGift(code); return; } // bearer gift → claim into an existing wallet or a new one
  ui.claimLocked = readLockedGiftHash(); // locked gift → claim with your own wallet
  if (!restoreAccountsState()) render();
});






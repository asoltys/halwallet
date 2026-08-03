// Ark feature — off-chain payments via an ASP (Second's bark/captaind
// protocol, spoken natively by ../ark). Receive address + boarding, instant
// sends, history entries, refresh/consolidation, server settings.

import * as btc from '@scure/btc-signer';
import { HDKey } from '@scure/bip32';
import { hex, base32nopad, bech32 } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';
import { ArkManager } from '../ark/manager.js';
import { loadBg, saveBg, buildBg } from '../nwc-bg.js';
import { boardFee } from '../ark/board.js';
import { maybeBolt11, lnSendFee } from '../ark/lightning.js';
import { decodeVtxo, getVtxoStatus, VTXO_STATE_SPENT, concatBytes } from '../ark/proto.js';
import { signedExitTxs, buildBumpChild, buildExitClaim, submitPackage } from '../ark/exit.js';
import { utxoId } from '../wallet.js';
import {
  getNetwork, setNetwork, getArkProviderId, getArkConfig,
} from '../api.js';
import { t } from '../i18n.js';
import { resolveBip353, parsePaymentName, parseBip21 as parseBip21Uri } from '../bip353.js';
import { shortAddr, shortTxid, timeAgo, ARK_ICON, ARK_MARK } from '../format.js';

// t?ark1… bech32m — an Ark address for this or another ASP.
export function isArkAddress(a) { return /^t?ark1[a-z0-9]{20,}$/i.test((a || '').trim()); }

// Wallet storage/key helpers for this feature, installed onto the core
// wallet instance so a build without the feature ships none of it.
export function installArkWallet(wallet) {
  if (wallet.loadArkState) return; // already installed
  Object.assign(wallet, {
    // ---- Ark support -------------------------------------------------------
    // Persisted ArkManager state (vtxos, in-flight action checkpoints, movement
    // history — no secrets: vtxo keys are re-derived from the seed).
    // Ark state is per WALLET *and* per ASP: vtxos are cosigned by one
    // specific server, so showing another server's coins (or resuming its
    // in-flight board) is meaningless and alarming. Switching providers must
    // therefore switch state, and switching back must restore it.
    _arkNs(url) {
      // short, stable id for an ASP endpoint
      let h = 5381;
      for (const c of String(url || '')) h = ((h * 33) ^ c.charCodeAt(0)) >>> 0;
      return h.toString(36);
    },
    _arkKey(url) { return this._cacheKey() + ':ark:' + this._arkNs(url); },
    _arkLegacyKey() { return this._cacheKey() + ':ark'; },
    // Who really cosigned this state's coins? A vtxo names its server in its
    // own bytes, which is cryptographic fact — unlike the stamp, which is
    // just something we wrote and could have written wrongly.
    _arkVtxoOwner(st) {
      const v = (st?.vtxos || []).find((x) => x.bytes);
      if (!v) return null;
      try { return decodeVtxo(hex.decode(v.bytes)).serverPubkey; } catch { return null; }
    },
    // Park state under the server that actually owns it, until the URL for
    // that server is selected and can adopt it.
    _arkHoldKey(pubkey) { return this._cacheKey() + ':ark:pk:' + String(pubkey).slice(0, 16); },
    loadArkState(url) {
      // NB deliberately no fallback to the legacy key: the UI renders from
      // this before any server is contacted, so returning another ASP's state
      // here is exactly how you get a phantom balance. Pre-namespacing state
      // is claimed via adoptArkState() once we know who cosigned it.
      try {
        const cur = localStorage.getItem(this._arkKey(url));
        if (!cur) return null;
        const st = JSON.parse(cur);
        // Self-repair: an earlier build could stamp state with whichever
        // server happened to be connected, filing one ASP's coins under
        // another. The vtxos themselves settle it — if they disagree with the
        // stamp, this state is misfiled. Move it to its real owner and show
        // nothing here.
        const owner = this._arkVtxoOwner(st);
        if (owner && st.serverPubkey && owner !== st.serverPubkey) {
          st.serverPubkey = owner;
          try {
            localStorage.setItem(this._arkHoldKey(owner), JSON.stringify(st));
            localStorage.removeItem(this._arkKey(url));
          } catch {}
          return null;
        }
        return st;
      } catch { return null; }
    },
    // Offer up pre-namespacing state, but only to the ASP that actually
    // cosigned it. Its owner is read from the state's own stamp, or failing
    // that decoded straight out of a vtxo — the vtxo wire format carries the
    // server pubkey, so this needs no network call and cannot guess wrong.
    adoptArkState(serverPubkey, url) {
      try {
        // state parked by the self-repair above belongs to exactly one server
        const held = localStorage.getItem(this._arkHoldKey(serverPubkey));
        if (held) {
          const st = JSON.parse(held);
          this.saveArkState(st, url);
          localStorage.removeItem(this._arkHoldKey(serverPubkey));
          return st;
        }
        const raw = localStorage.getItem(this._arkLegacyKey());
        if (!raw) return null;
        const st = JSON.parse(raw);
        let owner = st.serverPubkey || null;
        if (!owner) {
          const v = (st.vtxos || []).find((x) => x.bytes);
          if (v) { try { owner = decodeVtxo(hex.decode(v.bytes)).serverPubkey; } catch {} }
        }
        if (owner && owner !== serverPubkey) return null; // belongs to another ASP
        if (!owner) return null;                          // can't prove ownership: leave it
        st.serverPubkey = owner;
        this.saveArkState(st, url);
        localStorage.removeItem(this._arkLegacyKey()); // now safely namespaced
        return st;
      } catch { return null; }
    },
    saveArkState(state, url) {
      try { localStorage.setItem(this._arkKey(url), JSON.stringify(state)); } catch {}
    },
  });
}

// A slim projection of ark state for the sync snapshot — the sync relay caps
// events at 64 KB and the full state (deep-genesis vtxo bytes + done-action
// hex) blew past it, so publishes silently failed and nothing synced. Another
// device needs, per vtxo: id/amount/state (+ bytes ONLY for spendable/pending,
// which it might spend/exit); the movement log (capped) for ark history; and
// done board/offboard/exit actions (stripped of hex) so on-chain rows still
// label. In-flight actions and their signing material stay device-local.
export function slimArkForSync(s) {
  if (!s) return null;
  const HEAVY = ['bytes', 'destBytes', 'changeBytes', 'vtxoBytes', 'txHex', 'fundingTxHex', 'outputVtxos'];
  return {
    v: s.v, serverPubkey: s.serverPubkey, mailboxCheckpoint: s.mailboxCheckpoint, nextKeyIndex: s.nextKeyIndex, receiveAckTs: s.receiveAckTs,
    // Spent stubs and done actions are pure history and grow forever — cap
    // them (newest kept) so the sync event's size is bounded for life.
    vtxos: (() => {
      const live = (s.vtxos || []).filter((v) => v.state !== 'spent');
      const stubs = (s.vtxos || []).filter((v) => v.state === 'spent').slice(-200)
        .map((v) => ({ id: v.id, amountSat: v.amountSat, state: 'spent', keyIndex: v.keyIndex, expiryHeight: v.expiryHeight }));
      return [...live, ...stubs];
    })(),
    actions: (s.actions || [])
      .filter((a) => a.step === 'done' && ['board', 'offboard', 'exit'].includes(a.type))
      .slice(-50)
      .map((a) => { const c = { ...a }; for (const k of HEAVY) delete c[k]; return c; }),
    movements: (s.movements || []).slice(-200).map((m, i, arr) =>
      // Older rows only need to render a history line; the bolt11 (~400 chars
      // each) and preimage are what pushed snapshots past relay size limits.
      (arr.length - i <= 50 ? m : (({ invoice, preimage, ...rest }) => rest)(m))),
    gifts: s.gifts,
  };
}

// Merge two ark states so devices can't clobber each other through the sync
// snapshot: additive union of vtxos (a device keeps its own full copy, gains
// ones it lacks), actions/movements/gifts union by id, counters take the max
// (so two devices never reuse a key index).
export function mergeArkStates(a, b) {
  if (!a) return b;
  if (!b) return a;
  // never fuse state from two different ASPs
  if (a.serverPubkey && b.serverPubkey && a.serverPubkey !== b.serverPubkey) return a;
  const out = { ...a };
  // ADDITIVE union only: bring in vtxos this device is missing (the whole
  // point — board/change coins that live only where they were created), but
  // NEVER let a remote snapshot change the state of a vtxo we already track.
  // Spend detection is each device's own job via reconcile() against the
  // server (the authority), so a stale-or-wrong "spent" on one device can't
  // propagate and permanently poison the others. A newly-merged-in vtxo that
  // was actually spent elsewhere gets caught by the reconcile on next connect
  // / send-intent, exactly like any other drift.
  const vtxos = new Map((a.vtxos || []).map((v) => [v.id, { ...v }]));
  for (const rv of b.vtxos || []) if (!vtxos.has(rv.id)) vtxos.set(rv.id, { ...rv });
  out.vtxos = [...vtxos.values()];
  const unionById = (x = [], y = []) => {
    const ids = new Set(x.map((i) => i.id));
    return [...x, ...y.filter((i) => !ids.has(i.id))];
  };
  out.actions = unionById(a.actions, b.actions);
  out.movements = unionById(a.movements, b.movements).sort((m, n) => (m.ts || 0) - (n.ts || 0));
  const gifts = new Map((a.gifts || []).map((g) => [g.id, { ...g }]));
  for (const rg of b.gifts || []) {
    const lg = gifts.get(rg.id);
    if (!lg) gifts.set(rg.id, { ...rg });
    else { lg.claimed = lg.claimed || rg.claimed; lg.revoked = lg.revoked || rg.revoked; }
  }
  out.gifts = [...gifts.values()];
  out.mailboxCheckpoint = Math.max(a.mailboxCheckpoint || 0, b.mailboxCheckpoint || 0);
  out.nextKeyIndex = Math.max(a.nextKeyIndex || 1, b.nextKeyIndex || 1);
  out.nextLnRecvIndex = Math.max(a.nextLnRecvIndex || 0, b.nextLnRecvIndex || 0);
  out.receiveAckTs = Math.max(a.receiveAckTs || 0, b.receiveAckTs || 0);
  out.serverPubkey = a.serverPubkey || b.serverPubkey || null;
  return out;
}

export function arkFeature(ctx) {
  const { h, ui, render, wallet, blankSend, fmtAmount, unitLabel, unitTag, copyBtn, toast, openExternal } = ctx;
  installArkWallet(wallet); // ark state storage lives outside the core wallet

  // Ride the encrypted sync snapshot so ark funds follow the seed across
  // devices. Board/change vtxo bytes exist only where they were created — a
  // second device can't otherwise see them. All devices share ONE replaceable
  // event slot (same seed -> same nostr key), so a naive publish can clobber
  // another device's coins. Anti-entropy fixes that: on receiving a snapshot,
  // union it with local; if it was missing coins we know (or brought coins we
  // didn't), re-publish the superset. The slot converges to the union no
  // matter who publishes when.
  wallet.registerCacheExtension({
    domain: 'ark', // published as its own sync slot — see splitSnapshotDomains
    mergeAlways: true, // load() is a commutative merge — apply older snapshots too
    save: () => {
      const cfg = getArkConfig();
      const s = cfg && wallet.loadArkState(cfg.ark);
      // tag the snapshot with the ASP it belongs to (see load())
      return s ? { arkState: slimArkForSync(s), arkServer: wallet._arkNs(cfg.ark) } : {};
    },
    load: (d) => {
      if (!d.arkState) return;
      const cfg = getArkConfig();
      if (!cfg) return;
      if (d.arkServer && d.arkServer !== wallet._arkNs(cfg.ark)) return;
      // A snapshot from an older build carries no tag, so the tag alone can't
      // be trusted — ask the vtxos who cosigned them. If they belong to a
      // different ASP (or we can't yet prove they belong to this one), park
      // the snapshot under its real owner instead of merging it in. Merging
      // blind is exactly how another server's balance appears here.
      const owner = d.arkState.serverPubkey || wallet._arkVtxoOwner(d.arkState);
      const mine = (ark && ark.info && ark.info.serverPubkey)
        || (wallet.loadArkState(cfg.ark) || {}).serverPubkey || null;
      if (owner && owner !== mine) {
        try {
          localStorage.setItem(wallet._arkHoldKey(owner),
            JSON.stringify({ ...d.arkState, serverPubkey: owner }));
        } catch {}
        // `mine` is null on a FRESH restore (no local state, not yet
        // connected), so even our own snapshot lands in the hold. Connecting
        // is what resolves it: the manager learns the server's pubkey and
        // adopts the held state if it matches — a seed imported on a new
        // device would otherwise show no ark balance until some manual poke.
        if (!mine) setTimeout(() => maybeInitArk(), 0);
        return;
      }
      const local = wallet.loadArkState(cfg.ark);
      const merged = mergeArkStates(local, d.arkState);
      wallet.saveArkState(merged, cfg.ark);
      const mergedN = (merged.vtxos || []).length;
      const remoteN = (d.arkState.vtxos || []).length;
      const localN = (local && local.vtxos || []).length;
      // We know vtxos this snapshot lacked — push our superset back up so the
      // sender (and the shared slot) learns them. Guarded by mergedN>remoteN so
      // it can't loop once every device has converged to the union.
      if (mergedN > remoteN) { try { wallet.saveCache(); } catch {} }
      // The merge brought vtxos our live manager doesn't have — (re)connect so
      // the balance actually shows.
      const novel = mergedN > localN || (mergedN && (!ark || !ark.state));
      if (mergedN && novel) setTimeout(() => maybeInitArk(), 0);
    },
  });

  // One manager per open wallet; null when Ark is off in Settings, watch-only,
  // or not yet dialed (lazy: fresh wallets connect on first use).
  let ark = null;
  let arkTimer = null;
  let arkConnectPromise = null;
  let arkInitGen = 0; // guards against a stale init() resolving after a wallet switch

  function stopArk() {
    arkInitGen++;
    if (arkTimer) clearInterval(arkTimer);
    arkTimer = null;
    if (ark) ark.stopMailboxStream();
    stopNwcFunding();
    for (const timer of arkLnTimers.values()) clearInterval(timer);
    arkLnTimers.clear();
    ark = null;
    arkConnectPromise = null;
  }

  function arkAvailable() {
    return !!getArkConfig() && !wallet.watchOnly && !!wallet.account;
  }

  function arkWanted() {
    const cfg = getArkConfig();
    const st = cfg && wallet.loadArkState(cfg.ark);
    return !!(st && ((st.vtxos || []).length || (st.movements || []).length
      || (st.actions || []).some((a) => !['done', 'failed'].includes(a.step))));
  }

  function initArk() {
    stopArk();
    ui.arkError = '';
    lastAutoInit = Date.now();
    if (arkAvailable() && arkWanted()) connectArk().catch(() => {});
  }

  // Automatic re-inits (a synced snapshot arriving) must not restart a
  // connection that is already in flight, or retry in a tight loop when the
  // server is unreachable: each one calls stopArk() first, so the settings
  // card's "connecting" indicator flickers on every snapshot. User-driven
  // calls to initArk() stay immediate.
  let lastAutoInit = 0;
  function maybeInitArk() {
    if (ark || arkConnectPromise) return;
    if (Date.now() - lastAutoInit < 20000) return;
    initArk();
  }

  function connectArk() {
    if (ark) return Promise.resolve(ark);
    if (arkConnectPromise) return arkConnectPromise;
    if (!arkAvailable()) return Promise.reject(new Error(t('arkNotConnected')));
    const cfg = getArkConfig();
    const gen = arkInitGen;
    const mgr = new ArkManager({
      account: wallet.account(),
      storage: {
        load: () => wallet.loadArkState(cfg.ark),
        adopt: (serverPubkey) => wallet.adoptArkState(serverPubkey, cfg.ark),
        // merge-on-save: the MANAGER is authoritative for the state of the
        // vtxos it tracks (its reconcile/spends must persist), so its state
        // is the first arg and wins; storage only contributes vtxos the
        // manager hasn't loaded yet (a snapshot merged in from another device
        // between init and the next reinit). saveCache() then carries ark
        // state into the snapshot -> debounced nostr publish.
        save: (s) => {
          wallet.saveArkState(mergeArkStates(s, wallet.loadArkState(cfg.ark)), cfg.ark);
          try { wallet.saveCache(); } catch {}
        },
      },
      arkUrl: cfg.ark,
      esploraUrl: cfg.esplora,
      network: getNetwork(),
      onUpdate: () => render(),
    });
    ui.arkError = '';
    arkConnectPromise = mgr.init().then(() => {
      if (gen !== arkInitGen) throw new Error('superseded'); // wallet switched mid-connect
      ark = mgr;
      announceArkAddress(mgr); // ark zaps: tell nostr where our mailbox lives
      startNwcFunding(mgr);    // NWC bridge: honor funding requests within the allowance
      // Publish this device's ark state to its per-device sync slot on connect.
      // Cross-device sync only re-published on a state CHANGE (a send/board), so
      // an idle device never shared its coins — another device would never see
      // them. Publishing on connect guarantees every device's ark balance
      // reaches the relay (and gets merged) without needing a transaction first.
      if (mgr.state && (mgr.state.vtxos || []).length) { try { wallet.saveCache(); } catch {} }
      const tick = () => mgr.sync().catch(() => {})
        .then(() => driveExits(mgr)).catch(() => {})
        .then(() => { if (ark === mgr) return maybeAutoRefresh(mgr); }).catch(() => {});
      tick();
      // Reconcile once on connect: a vtxo synced in from another device (or
      // one this device held while a spend happened elsewhere) is checked
      // against the server, so a stale spendable is caught here rather than
      // only at send time.
      mgr.reconcile().catch(() => {});
      mergeBgWorkerState(mgr).catch(() => {}); // absorb what the SW did while we were closed
      // Receives arrive in real time over the mailbox stream; the poll is the
      // fallback and what drives in-flight boards/refreshes forward.
      mgr.startMailboxStream();
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

  // The current ark state for READ-ONLY rendering: the live manager if it's
  // connected, else the persisted state straight from storage. Lets the
  // balance and history icons paint immediately on refresh instead of
  // flickering (empty → populated) while the manager connects asynchronously.
  function arkStateNow() {
    if (ark && ark.state) return ark.state;
    // Read persisted state whenever Ark is configured for this network — even
    // watch-only (seed not loaded this session): the balance/history should
    // show read-only, just like the on-chain balance does. Acting on it
    // (send/exit) still requires the seed and is gated separately.
    const cfg = getArkConfig();
    if (!cfg) return null;
    return wallet.loadArkState(cfg.ark);
  }

  function arkBalance() {
    const s = arkStateNow();
    if (!s) return null;
    const sum = (st) => (s.vtxos || []).filter((v) => v.state === st).reduce((n, v) => n + v.amountSat, 0);
    const boardingSat = (s.actions || [])
      .filter((a) => a.type === 'board' && a.fundingTxid && !['done', 'failed'].includes(a.step))
      .reduce((n, a) => n + (a.amountSat - a.feeSat), 0);
    return { spendableSat: sum('spendable'), pendingSat: sum('pending'), boardingSat };
  }

  // An ark address in the send form signals a send is coming: verify our
  // spendable vtxos against the server now, so a stale one (same seed active
  // elsewhere, restored state) is dropped before coin selection instead of
  // failing at cosign time. Throttled — this fires from the render path.
  let arkReconciledAt = 0;
  function maybeReconcile() {
    if (Date.now() - arkReconciledAt < 30_000) return;
    arkReconciledAt = Date.now();
    connectArk().then((mgr) => mgr.reconcile()).catch(() => {});
  }

  function arkSendReview() {
    if (ui.arkSent) {
      return h(
        'div',
        {
          class: 'card col',
          style: 'align-items:center;text-align:center;gap:14px;cursor:pointer;padding:48px 20px',
          onClick: () => { ui.arkSent = null; ui.send = blankSend(); render(); },
        },
        h('div', { class: 'check-badge' }, '✓'),
        h('h2', { style: 'margin:0' }, t('arkSentTitle')),
        h('div', { class: 'amount-neg', style: 'font-size:18px' }, '-' + fmtAmount(ui.arkSent.amountSat) + ' ' + unitLabel()),
        h('div', { class: 'small muted' }, t('tapToProceed'))
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

  // ---- lightning via the ASP (captaind pays/holds invoices natively) -------
  // One poll timer per in-flight lightning action; cleared on settle.
  const arkLnTimers = new Map();
  function stopArkLnPoll(id) {
    const timer = arkLnTimers.get(id);
    if (timer) { clearInterval(timer); arkLnTimers.delete(id); }
  }
  function pollArkLn(id, onSettle) {
    stopArkLnPoll(id);
    arkLnTimers.set(id, setInterval(async () => {
      if (!ark) return;
      const a = await ark.driveLn(id).catch(() => null);
      if (a && ['done', 'failed'].includes(a.step)) {
        stopArkLnPoll(id);
        onSettle(a);
      }
      render();
    }, 2500));
  }

  // ---- background NWC mirror ---------------------------------------------
  // The service worker answers wallet-connect requests while the app is
  // closed, spending the SAME ark balance the app does. The mirror is the
  // full manager state plus the chain-3 keys for its live coins and a window
  // of upcoming change indices (the worker cannot derive). nwc.js decides
  // WHEN to mirror (background answering on) and supplies the connections.
  async function writeBgMirror(connections, offer) {
    const cfg = getArkConfig();
    if (!cfg || !ark || !ark.info || !ark.state) return;
    const prev = await loadBg(wallet._cacheKey());
    const rec = buildBg({
      ark: { arkUrl: cfg.ark, esploraUrl: cfg.esplora, network: getNetwork(), serverPubkey: ark.info.serverPubkey },
      mgrState: ark.state,
      keyFor: (chain, i) => hex.encode(ark.account.deriveChild(chain).deriveChild(i).privateKey),
      connections,
      offer,
    });
    if (prev) rec.spends = prev.spends; // the worker's log survives rewrites
    await saveBg(wallet._cacheKey(), rec);
  }

  // On connect, fold whatever the worker did while we were closed back into
  // the live state: its spent flips and change vtxos merge in (the additive
  // merge never resurrects anything reconcile() disproves), its key
  // allocations advance ours, and its in-flight ln actions become resumable.
  async function mergeBgWorkerState(mgr) {
    const rec = await loadBg(wallet._cacheKey());
    if (!rec) return;
    if (rec.v < 3) {
      await sweepLegacyPouch(rec).catch((e) => console.warn('ark: pouch sweep failed', e.message));
      return;
    }
    if (!rec.mgr) return;
    const merged = mergeArkStates(mgr.state, rec.mgr);
    // the worker's view of OUR vtxos is newer for anything it spent
    const workerState = new Map((rec.mgr.vtxos || []).map((v) => [v.id, v.state]));
    for (const v of merged.vtxos) {
      if (workerState.get(v.id) === 'spent') v.state = 'spent';
    }
    merged.nextKeyIndex = Math.max(merged.nextKeyIndex || 1, rec.mgr.nextKeyIndex || 1);
    mgr.state = merged;
    mgr._save();
    await mgr.reconcile().catch(() => {});
    await mgr.resumePending().catch(() => {});
  }

  // A leftover chain-6 pouch from before whole-balance background spending:
  // sweep its coins home using the keys stored in the record itself, then
  // let the next mirror write replace it.
  async function sweepLegacyPouch(rec) {
    if (!(rec.vtxos || []).some((v) => (v.state || 'spendable') === 'spendable')) return;
    const cfg = getArkConfig();
    const mgr = await connectArk();
    const shim = { deriveChild: () => ({ deriveChild: (i) => ({ privateKey: hex.decode(rec.keys[String(i)] || rec.keys['0']) }) }) };
    let state = {
      v: 1, serverPubkey: rec.ark?.serverPubkey || null, mailboxCheckpoint: 0,
      nextKeyIndex: rec.nextKeyIndex || 20,
      vtxos: (rec.mgr?.vtxos || rec.vtxos || []).map((v) => ({ ...v, state: v.state || 'spendable' })),
      actions: [], movements: [],
    };
    const pm = await new ArkManager({
      account: shim,
      storage: { load: () => state, save: (s2) => { state = s2; } },
      arkUrl: cfg.ark, esploraUrl: cfg.esplora, network: getNetwork(),
    }).init();
    const dest = mgr.address();
    for (let guard = 0; guard < 30; guard++) {
      const v = (pm.state.vtxos || []).find((x) => x.state === 'spendable');
      if (!v) break;
      await pm.send(dest, v.amountSat);
    }
    await saveBg(wallet._cacheKey(), { ...rec, vtxos: [], mgr: state, sweptAt: Date.now() });
  }

  // Pay a bolt11 with no UI at all — used by the NWC wallet service. Same
  // routing as the interactive path: the cheaper bridge first, the ASP's own
  // lightning-send as fallback. Resolves { preimage, feeSat, amountSat }.
  async function payInvoiceHeadless(invoice, { maxAmountSat } = {}) {
    const dec = maybeBolt11(invoice);
    if (!dec) throw new Error('not a bolt11 invoice');
    if (!dec.amountSat) throw new Error('zero-amount invoices are not supported');
    if (maxAmountSat && dec.amountSat > maxAmountSat) {
      throw new Error(`amount ${dec.amountSat} exceeds the limit of ${maxAmountSat} sat`);
    }
    const mgr = await connectArk();
    // The sync merge is additive, so a vtxo spent on another device can sit
    // in local state looking spendable until someone checks. The interactive
    // send path reconciles on intent; this headless path must too, or an NWC
    // payment picks the stale coin and the ASP rejects it ("state: spent").
    await mgr.reconcile().catch(() => {});

    const id = await mgr.payLnInvoice(invoice);
    for (let i = 0; i < 60; i++) {
      const a = mgr.lnAction(id);
      if (!a || a.step === 'done') break;
      if (a.step === 'failed') throw new Error(a.error || 'payment failed');
      await new Promise((r) => setTimeout(r, 2000));
      await mgr.driveLn(id).catch(() => {});
    }
    const a = mgr.lnAction(id);
    if (!a || a.step !== 'done') throw new Error(a?.error || a?.lastError || 'payment did not complete');
    return { preimage: a.preimage, feeSat: a.feeSat, amountSat: a.amountSat };
  }

  // A bolt11 lands in Send (via the swaps feature's delegation hook, or
  // directly when swaps is absent): take over when the ark balance can
  // plausibly cover it, else decline so the Boltz path handles it.
  function startArkLnPay(invoice, meta) {
    const dec = maybeBolt11(invoice);
    if (!dec || !arkAvailable() || wallet.watchOnly) return false;
    const s = arkStateNow();
    const covers = (state, sats) =>
      !!s && (s.vtxos || []).some((v) => v.state === state && v.amountSat >= sats);
    // pending funds count for the take-over decision: an in-flight payment or
    // revocation frees them in seconds, and the Boltz fallback can't do small
    // amounts at all — better to wait for ark than bounce off Boltz's minimum
    if (!covers('spendable', dec.amountSat || 1) && !covers('pending', dec.amountSat || 1)) return false;
    ui.arkLnPay = { invoice, meta: meta || null, amountSat: dec.amountSat, amount: '', feeSat: null, status: 'quote' };
    ui.sendError = '';
    render();
    quoteArkLnPay(invoice, meta).catch((e) => {
      if (ui.arkLnPay && ui.arkLnPay.invoice === invoice) { ui.sendError = e.message; render(); }
    });
    return true;
  }

  // Quote (or re-quote) an in-form lightning pay: smallest vtxo that covers
  // amount + its expiry-based fee. Funds locked by a settling action retry
  // themselves free; genuinely insufficient funds hand off to Boltz.
  async function quoteArkLnPay(invoice, meta) {
    const mgr = await connectArk();
    const p = ui.arkLnPay;
    if (!p || p.invoice !== invoice) return;
    if (!p.amountSat) { p.status = 'ready'; render(); return; }
    const tip = await mgr.chain.tipHeight();
    const candidates = mgr.vtxos().filter((v) => v.state === 'spendable')
      .sort((a, b) => a.amountSat - b.amountSat);
    let fee = null;
    for (const v of candidates) {
      const f = lnSendFee(p.amountSat, mgr.info.lnSendFees, [v], tip);
      if (v.amountSat >= p.amountSat + f) { fee = f; break; }
    }
    if (fee == null) {
      const pendingCover = mgr.vtxos().some((v) => v.state === 'pending' && v.amountSat >= p.amountSat);
      if (pendingCover) {
        p.status = 'fundsPending';
        render();
        mgr.resumePending().catch(() => {}); // nudge whatever holds them
        setTimeout(() => {
          if (ui.arkLnPay === p) quoteArkLnPay(invoice, meta).catch(() => {});
        }, 4000);
        return;
      }
      // can't cover once fees are in
      ui.arkLnPay = null;
      ui.sendError = t('arkLnPayFailed');
      render();
      return;
    }
    p.feeSat = fee;
    p.status = 'ready';
    render();
  }

  async function doArkLnPay() {
    const p = ui.arkLnPay;
    const sats = p.amountSat || ctx.parseAmount(p.amount, ctx.getUnit());
    if (!sats || sats <= 0) { ui.sendError = t('enterValidAmtForN', { n: 1 }); render(); return; }
    ui.busy = true; ui.sendError = ''; render();
    try {
      const mgr = await connectArk();
      const id = await mgr.payLnInvoice(p.invoice, { amountSat: sats });
      const settle = (a) => {
        if (a.step === 'done') {
          ui.arkLnPaid = { amountSat: a.amountSat, meta: p.meta };
          if (p.meta && p.meta.pk) noteZap('inv:' + p.invoice, p.meta.pk);
          ui.arkLnPay = null;
        } else if (ui.arkLnPay) {
          ui.arkLnPay.status = 'ready';
          ui.sendError = a.error === 'payment failed' ? t('arkLnRefunded') : (a.error || t('arkLnPayFailed'));
        }
        render();
      };
      const a = mgr.lnAction(id);
      if (['done', 'failed'].includes(a.step)) settle(a);
      else { p.actionId = id; p.status = 'paying'; pollArkLn(id, settle); }
    } catch (e) {
      ui.sendError = e.message;
    }
    ui.busy = false; render();
  }

  function arkLnPayView() {
    const u = ' ' + unitLabel();
    if (ui.arkLnPaid) {
      const zap = ui.arkLnPaid.meta;
      return h('div', {
        class: 'card col',
        style: 'align-items:center;text-align:center;gap:14px;cursor:pointer;padding:48px 20px',
        onClick: () => { ui.arkLnPaid = null; ui.send = blankSend(); render(); },
      },
        h('div', { class: 'check-badge' }, '⚡'),
        h('h2', { style: 'margin:0' }, zap ? t('arkZapSentTitle') : t('arkLnPaidTitle')),
        zap && zap.name ? h('div', { class: 'small muted' }, zap.name) : null,
        h('div', { class: 'amount-neg', style: 'font-size:18px' }, '-' + fmtAmount(ui.arkLnPaid.amountSat) + u),
        h('div', { class: 'small muted' }, t('tapToProceed')));
    }
    const p = ui.arkLnPay;
    if (!p) return null;
    const zap = p.meta;
    const row = (label, sats, bold) => h('div', { class: 'row between' + (bold ? '' : ''), style: bold ? 'font-weight:600' : '' },
      h('span', { class: bold ? '' : 'small muted' }, label), h('span', {}, fmtAmount(sats) + u));
    const total = (p.amountSat || 0) + (p.feeSat || 0);
    return h('div', { class: 'col', style: 'gap:12px' },
      h('div', { class: 'card col', style: 'gap:10px' },
        h('h3', { style: 'margin:0' }, '⚡ ' + (zap ? t('lnZapReviewTitle') : t('lnPayTitle'))),
        h('div', { class: 'small muted' }, t('arkLnPayVia')),
        zap && (zap.name || zap.address) ? h('div', { class: 'small muted', style: 'word-break:break-all' }, zap.name || zap.address) : null,
        zap && zap.comment ? h('div', { class: 'small faint', style: 'font-style:italic;word-break:break-word' }, '“' + zap.comment + '”') : null,
        p.status === 'quote'
          ? h('div', { class: 'row gap6', style: 'align-items:center' }, h('span', { class: 'spinner sm' }), h('span', { class: 'small muted' }, t('lnQuoting')))
          : null,
        p.status === 'fundsPending'
          ? h('div', { class: 'row gap6', style: 'align-items:center' }, h('span', { class: 'spinner sm' }), h('span', { class: 'small muted' }, t('arkLnFundsPending')))
          : null,
        p.amountSat == null && p.status !== 'quote'
          ? h('div', { class: 'input-group' },
              h('input', { type: 'number', min: '0', inputmode: 'decimal', placeholder: t('lnPayAmount'), value: p.amount,
                onInput: (e) => { p.amount = e.target.value; } }),
              h('div', { style: 'display:flex;align-items:center' }, unitTag()))
          : null,
        p.amountSat != null ? row(t('lnPayAmount'), p.amountSat) : null,
        p.feeSat != null && p.feeSat > 0 ? row(t('arkLnFee'), p.feeSat) : null,
        p.amountSat != null && p.feeSat != null
          ? [h('div', { style: 'border-top:1px solid var(--line, #ddd);margin:2px 0' }), row(t('lnPayTotal'), total, true)]
          : null),
      ui.sendError ? h('div', { class: 'notice err' }, ui.sendError) : null,
      p.status === 'paying'
        ? h('div', { class: 'card row gap6', style: 'align-items:center' },
            h('span', { class: 'spinner sm' }), h('span', { class: 'small muted' }, t('arkLnPaying')))
        : h('button', { class: 'btn-primary btn-block', disabled: !!ui.busy || p.status !== 'ready', onClick: doArkLnPay },
            ui.busy ? h('span', { class: 'spinner' }) : t('lnPayConfirm')),
      p.status !== 'paying'
        ? h('button', { class: 'btn-ghost btn-block', onClick: () => { ui.arkLnPay = null; ui.sendError = ''; ui.send = blankSend(); render(); } }, t('back'))
        : null);
  }

  async function doArkLnInvoice() {
    const sats = parseInt((ui.arkLnRecvAmt || '').trim(), 10);
    if (!sats) return;
    ui.arkBusy = 'lninvoice'; ui.arkError = ''; render();
    try {
      const mgr = await connectArk();
      const a = await mgr.createLnInvoice(sats);
      ui.arkLnRecvId = a.id;
      pollArkLn(a.id, () => render()); // 'done' -> celebration via unseenReceives
    } catch (e) {
      ui.arkError = e.message;
    }
    ui.arkBusy = null; render();
  }


  // Who a zap went to, keyed by what the movement records (the ark address
  // for direct zaps, the invoice for Lightning ones) — enough to put a face
  // on history rows without touching the manager's movement schema.
  const zapNotes = () => wallet.loadFeatureState('zapnotes', {});
  function noteZap(key, pk) {
    const s = zapNotes();
    s[key] = pk;
    const keys = Object.keys(s);
    if (keys.length > 200) for (const k of keys.slice(0, keys.length - 200)) delete s[k];
    wallet.saveFeatureState('zapnotes', s);
  }
  const zapNoteFor = (m) =>
    m.type === 'send' && m.to ? zapNotes()['to:' + m.to]
    : m.type === 'ln-send' && m.invoice ? zapNotes()['inv:' + m.invoice]
    : null;

  function arkHistoryItem(m) {
    const incoming = !['send', 'offboard', 'exit', 'ln-send'].includes(m.type);
    const label = m.type === 'receive' ? t('received') : m.type === 'board' ? t('arkBoarded')
      : m.type === 'ln-send' ? t('arkLnPaidHistory') : m.type === 'ln-receive' ? t('arkLnReceivedHistory')
      : m.type === 'offboard' ? t('arkOffboarded') : m.type === 'exit' ? t('arkExited') : t('sent');
    return h(
      'div',
      { class: 'item', style: 'cursor:pointer', onClick: () => { ui.arkMoveDetail = m.id; render(); } },
      // Ark mark in the (direction-colored) circle carries the rail; the label
      // + signed amount carry direction, so no redundant "Ark" text chip.
      m.type.startsWith('ln-')
        ? h('div', { class: `ico ${incoming ? 'in' : 'out'}` }, '⚡')
        : h('div', { class: `ico ${incoming ? 'in' : 'out'}`, html: ARK_MARK(15) }),
      h('div', { class: 'grow' },
        h('div', { class: 'row gap6', style: 'align-items:center' },
          label,
          (() => { const pk = zapNoteFor(m); return pk ? ctx.hook('profileChip', pk) : null; })(),
          m.status !== 'complete' ? h('span', { class: 'tag pending' }, m.status) : null),
        h('div', { class: 'small faint' }, timeAgo(m.ts / 1000))),
      h('div', { style: 'text-align:right' },
        h('div', { class: incoming ? 'amount-pos' : 'amount-neg' }, (incoming ? '+' : '-') + fmtAmount(m.amountSat)))
    );
  }

  function arkMoveDetailView(m) {
    const incoming = !['send', 'offboard', 'exit', 'ln-send'].includes(m.type);
    const label = m.type === 'receive' ? t('received') : m.type === 'board' ? t('arkBoarded')
      : m.type === 'ln-send' ? t('arkLnPaidHistory') : m.type === 'ln-receive' ? t('arkLnReceivedHistory')
      : m.type === 'offboard' ? t('arkOffboarded') : m.type === 'exit' ? t('arkExited') : t('sent');
    const row = (k, v) => h('div', { class: 'row between', style: 'gap:12px' },
      h('span', { class: 'small muted', style: 'flex-shrink:0' }, k), h('span', { class: 'small', style: 'text-align:right;word-break:break-all' }, v));
    const url = m.txid ? wallet.api.explorerTx(m.txid) : null;
    return h(
      'div',
      { class: 'card col', style: 'gap:10px' },
      h('div', { class: 'row gap6', style: 'align-items:center' },
        h('span', { html: ARK_ICON(18) }),
        h('h3', { style: 'margin:0' }, label),
        m.status !== 'complete' ? h('span', { class: 'tag pending' }, m.status) : null),
      h('div', { class: incoming ? 'amount-pos' : 'amount-neg', style: 'font-size:20px' },
        (incoming ? '+' : '-') + fmtAmount(m.amountSat) + ' ' + unitLabel()),
      row(t('dateLabel'), new Date(m.ts).toLocaleString()),
      m.to ? row(t('arkPayTo'), shortAddr(m.to, 16, 12)) : null,
      m.vtxoId ? row(t('arkVtxoId'), shortTxid(m.vtxoId)) : null,
      m.detail ? row(t('detailsLabel'), m.detail) : null,
      m.txid
        ? h('div', { class: 'col', style: 'gap:6px' },
            h('div', { class: 'small muted' }, t('transactionId')),
            h('div', { class: 'addr-box', style: 'width:100%' }, m.txid),
            h('div', { class: 'row gap6' },
              copyBtn(m.txid, t('copyTxid')),
              h('a', { class: 'btn btn-sm', href: url, target: '_blank', rel: 'noopener', onClick: (e) => { e.preventDefault(); openExternal(url); } }, t('viewOnMempool'))))
        : null,
      m.to ? copyBtn(m.to, t('copyAddress')) : null,
      h('button', { class: 'btn-ghost btn-block', onClick: () => { ui.arkMoveDetail = null; render(); } }, t('back'))
    );
  }

  function arkCard() {
    const net = getNetwork();
    // No provider picker: coinos is the provider (per-network defaults cover
    // dev networks). The card is status only.
    const id = getArkProviderId(net);
    const head = [
      h('h3', { class: 'row gap6', style: 'align-items:center' }, t('arkTitle')),
      h('p', { class: 'small muted', style: 'margin:0' }, t('arkDesc')),
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
  
    const spendables = ark.vtxos().filter((v) => v.state === 'spendable');
    const pendingActions = ark.pendingActions();
    const row = (k, v) => h('div', { class: 'row between' }, h('span', { class: 'small muted' }, k), h('span', { class: 'small' }, v));
  
    return h(
      'div',
      { class: 'card col', style: 'gap:10px' },
      ...head,
      spendables.length ? row(t('arkVtxos'), String(spendables.length)) : null,
      // in-flight operations, summarized in plain words (exits get their own
      // per-exit status lines below)
      (() => {
        const counts = {};
        for (const a of pendingActions) { if (a.type !== 'exit') counts[a.type] = (counts[a.type] || 0) + 1; }
        const LABEL = { board: 'arkOpsBoard', send: 'arkOpsSend', refresh: 'arkOpsRefresh', offboard: 'arkOpsOffboard', 'ln-pay': 'arkOpsLnPay', 'ln-recv': 'arkOpsLnRecv' };
        const parts = Object.entries(counts).map(([type, n]) => t(LABEL[type] || 'arkPendingActions', { n }));
        return parts.length ? h('div', { class: 'small muted' }, parts.join(' · ')) : null;
      })(),
      // Refresh/consolidation is automatic (maybeAutoRefresh) — no button.
      // Moving funds out (cooperative offboard / unilateral exit) lives on its
      // own page, reached from the "Exit" link on the Ark balance line.
      spendables.length >= 1
        ? h('button', { class: 'btn-ghost btn-block', onClick: () => { ui.arkExitPage = true; ui.arkError = ''; render(); } }, t('arkExitPageTitle'))
        : null
    );
  }

  async function doArkBoard() {
    const sats = parseInt((ui.arkBoardAmt || '').trim(), 10);
    if (!sats) return;
    ui.arkBusy = 'board'; ui.arkError = ''; render();
    try {
      const { actionId, fundingAddress, feeSat } = await ark.startBoard(sats);
      const feeRate = (wallet.feeRates && wallet.feeRates.halfHourFee) || 5;
      const draft = wallet.buildTx({ recipients: [{ address: fundingAddress, amount: sats }], feeRate, noSort: true });
      const hexTx = wallet.sign(draft.tx);
      const txid = await wallet.broadcast(hexTx);
      // Like the main send flow: reflect the spend locally and let the
      // poll/watcher reconcile. A scan here would race the explorer's indexing
      // and could resurrect the just-spent coin.
      wallet.applySentTx(draft.tx);
      await ark.completeBoard(actionId, txid);
      ui.arkBoardAmt = '';
      ui.arkBoarded = { txid, netSat: sats - feeSat };
    } catch (e) {
      ui.arkError = e.message;
    }
    ui.arkBusy = null; render();
  }

  // ---- ark zaps (draft protocol, NIP-61-shaped) ----------------------------
  // Lightning zaps (NIP-57) are built around LNURL + bolt11; ark needs
  // neither. Mirroring nutzaps (NIP-61): the recipient announces their ark
  // address as a replaceable event, the sender pays with a plain instant
  // arkoor send and publishes a receipt referencing the delivered vtxo.
  // Kinds are provisional until a NIP lands.
  const ARK_INFO_KIND = 10037; // replaceable: ["ark", <address>], ["network", <net>]
  const ARK_ZAP_KIND = 9737;   // receipt: ["p", pk], ["e", note?], ["amount", sats], ["vtxo", id], ["network", net]

  // npub decode without importing the nostr stack (keeps ark-only builds lean)
  function npubToHex(s) {
    try {
      const { prefix, words } = bech32.decode(String(s || '').trim(), 200);
      if (prefix !== 'npub') return null;
      return hex.encode(new Uint8Array(bech32.fromWords(words)));
    } catch { return null; }
  }

  // Tell the world where our ark mailbox lives (once per address, and only
  // when the sync/nostr feature is present in this build).
  function announceArkAddress(mgr) {
    if (!wallet.nostrPublish) return;
    const addr = mgr.address();
    if (mgr._zapAnnounced === addr) return;
    mgr._zapAnnounced = addr;
    wallet.nostrPublish({ kind: ARK_INFO_KIND, tags: [['ark', addr], ['network', getNetwork()]] }).catch(() => {});
  }

  // Resolve an npub to a same-network ark address via their announcement.
  // Paying a PERSON (an npub): resolve every way they can be paid and take
  // the best — ark over lightning over on-chain.
  //   1. their ark address: the kind-10037 advert, or an ark= instruction in
  //      BIP-353 (their coinos name via the registrar, or their nip05 name's
  //      own DNS record — a bare domain nip05 is the BIP-353 "_" user)
  //   2. lightning: profile lud16/lud06, via the zap flow
  //   3. an on-chain address from the BIP-353 record
  const NAMES_REGISTRAR = 'https://names.coinos.io';
  function startNpubPay(pk, npub) {
    const z = (ui.arkZap = { npub, pk, amount: '', comment: '', status: 'lookup' });
    ui.sendError = '';
    render();
    const live = () => ui.arkZap === z;
    (async () => {
      connectArk().catch(() => {});
      // 1a. ark advert
      const adv = await lookupArkZapTarget(pk).catch(() => ({ status: 'noark' }));
      if (!live()) return;
      if (adv.status === 'ready') { Object.assign(z, adv); render(); return; }
      if (adv.status === 'wrongnet') { Object.assign(z, adv); render(); return; }
      // 1b. BIP-353 with an ark instruction; remember on-chain as last resort
      const uris = [];
      try {
        const j = await (await fetch(`${NAMES_REGISTRAR}/pubkey/${pk}`)).json();
        if (j && j.uri) uris.push(j.uri);
      } catch {}
      const profile = wallet.nostrProfile ? await wallet.nostrProfile(pk).catch(() => null) : null;
      if (!live()) return;
      if (profile && typeof profile.nip05 === 'string' && profile.nip05.trim()) {
        const nip05 = profile.nip05.trim().toLowerCase();
        const parsed = parsePaymentName(nip05.includes('@') ? nip05 : '_@' + nip05);
        if (parsed) {
          try { const uri = await resolveBip353(parsed.name, parsed.domain); if (uri) uris.push(uri); } catch {}
        }
      }
      if (!live()) return;
      let onchain = null;
      for (const uri of uris) {
        const dec = parseBip21Uri(uri);
        if (!dec) continue;
        const arkAddr = dec.params && dec.params.ark;
        if (arkAddr && isArkAddress(arkAddr)) { Object.assign(z, { status: 'ready', address: arkAddr }); render(); return; }
        if (dec.onchain && !onchain) onchain = dec.onchain;
      }
      // 2. lightning via the zap flow (connect first — canLnPay needs it)
      if (profile && (profile.lud16 || profile.lud06)) {
        await connectArk().catch(() => {});
        if (!live()) return;
        if (ctx.hook('canLnZap')) { ctx.hook('lnZapNpub', pk, npub); return; }
      }
      // 3. on-chain fallback
      if (onchain) {
        ui.arkZap = null;
        ui.send.recipients[0].address = onchain;
        render();
        return;
      }
      if (live()) { z.status = 'noark'; render(); }
    })().catch((e) => { if (live()) { z.status = 'noark'; ui.sendError = e.message; render(); } });
  }

  async function lookupArkZapTarget(pk) {
    const events = await wallet.nostrFetch({ kinds: [ARK_INFO_KIND], authors: [pk] }, 6000);
    const ev = (events || []).sort((a, b) => b.created_at - a.created_at)[0];
    if (!ev) return { status: 'noark' };
    const addr = (ev.tags.find((t) => t[0] === 'ark') || [])[1];
    const net = (ev.tags.find((t) => t[0] === 'network') || [])[1];
    if (!addr) return { status: 'noark' };
    if (net && net !== getNetwork()) return { status: 'wrongnet', net };
    return { status: 'ready', address: addr };
  }

  async function doArkZap() {
    const z = ui.arkZap;
    const sats = ctx.parseAmount(z.amount, ctx.getUnit());
    if (!sats || sats <= 0) { ui.sendError = t('enterValidAmtForN', { n: 1 }); render(); return; }
    ui.busy = true; ui.sendError = ''; render();
    try {
      const mgr = await connectArk();
      const actionId = await mgr.send(z.address, sats);
      const action = mgr.state.actions.find((a) => a.id === actionId);
      if (!action || action.step === 'failed') throw new Error(action?.error || t('claimFailed'));
      const vtxoId = decodeVtxo(hex.decode((action.destBytesList || [action.destBytes])[0])).id;
      noteZap('to:' + z.address, z.pk);
      // the receipt is best-effort: the sats are already delivered via mailbox
      await wallet.nostrPublish({
        kind: ARK_ZAP_KIND,
        content: (z.comment || '').slice(0, 280),
        tags: [['p', z.pk], ['amount', String(sats)], ['vtxo', vtxoId], ['network', getNetwork()]],
      }).catch(() => {});
      ui.arkZapped = { amountSat: sats, npub: z.npub };
      ui.arkZap = null;
    } catch (e) {
      ui.sendError = e.message;
    }
    ui.busy = false; render();
  }

  function arkZapView() {
    if (ui.arkZapped) {
      return h('div', {
        class: 'card col',
        style: 'align-items:center;text-align:center;gap:14px;cursor:pointer;padding:48px 20px',
        onClick: () => { ui.arkZapped = null; ui.send = blankSend(); render(); },
      },
        h('div', { class: 'check-badge' }, '⚡'),
        h('h2', { style: 'margin:0' }, t('arkZapSentTitle')),
        h('div', { class: 'amount-neg', style: 'font-size:18px' }, '-' + fmtAmount(ui.arkZapped.amountSat) + ' ' + unitLabel()),
        h('div', { class: 'small muted' }, t('tapToProceed')));
    }
    const z = ui.arkZap;
    if (!z) return null;
    return h('div', { class: 'card col', style: 'gap:12px' },
      h('h3', {}, '⚡ ' + t('arkZapTitle')),
      h('div', { class: 'small muted', style: 'word-break:break-all' }, z.npub),
      z.status === 'lookup' ? h('div', { class: 'row gap6', style: 'align-items:center' }, h('span', { class: 'spinner sm' }), h('span', { class: 'small muted' }, t('arkZapLookup'))) : null,
      z.status === 'noark' ? h('div', { class: 'notice err' }, t('arkZapNoArk')) : null,
      // No Ark address, but they may still take a Lightning zap — hand off to
      // the zaps feature (present alongside swaps).
      (z.status === 'noark' || z.status === 'wrongnet') && ctx.hook('canLnZap')
        ? h('button', { class: 'btn-primary btn-block', onClick: () => { ctx.hook('lnZapNpub', z.pk, z.npub); } }, '⚡ ' + t('lnZapFallback'))
        : null,
      z.status === 'wrongnet' ? h('div', { class: 'notice err' }, t('arkGiftWrongNet', { net: z.net })) : null,
      z.status === 'ready'
        ? h('div', { class: 'col gap6' },
            h('div', { class: 'input-group' },
              h('input', { type: 'number', min: '0', inputmode: 'decimal', placeholder: t('lnPayAmount'), value: z.amount,
                onInput: (e) => { z.amount = e.target.value; } }),
              h('div', { style: 'display:flex;align-items:center' }, unitTag())),
            h('input', { type: 'text', class: 'mono-input', placeholder: t('arkZapCommentPh'), value: z.comment,
              onInput: (e) => { z.comment = e.target.value; } }),
            h('div', { class: 'small faint' }, t('arkZapHint')))
        : null,
      ui.sendError ? h('div', { class: 'notice err' }, ui.sendError) : null,
      h('div', { class: 'row gap6' },
        h('button', { class: 'btn-ghost', onClick: () => { ui.arkZap = null; ui.sendError = ''; ui.send = blankSend(); render(); } }, t('back')),
        z.status === 'ready'
          ? (ui.busy
              ? h('button', { class: 'btn-primary grow', disabled: true }, h('span', { class: 'spinner' }))
              : h('button', { class: 'btn-primary grow', onClick: doArkZap }, t('arkZapBtn')))
          : null));
  }

  // ---- NWC bridge funding (PoC) --------------------------------------------
  // An external NWC wallet service (e.g. coinos) can bridge ark -> lightning:
  // a nostr client asks IT to pay_invoice, it asks US (kind 23196, funding
  // request) to cover the amount over ark, we auto-pay within a user-set
  // allowance and ack (kind 23197). Custody window = seconds in flight.
  // PoC config in localStorage 'btc-wallet-arknwc': { bridgePk, budgetSat }.
  const NWC_FUND_KIND = 23196;
  const NWC_FUND_ACK_KIND = 23197;
  let nwcUnsub = null;
  let nwcSpent = 0;

  function stopNwcFunding() {
    if (nwcUnsub) { try { nwcUnsub(); } catch {} nwcUnsub = null; }
  }

  function startNwcFunding(mgr) {
    if (nwcUnsub || !wallet.nostrSubscribe || !wallet.nostrPubkey || !wallet.nostrPubkey()) return;
    let cfg = null;
    try { cfg = JSON.parse(localStorage.getItem('btc-wallet-arknwc') || 'null'); } catch {}
    if (!cfg || !cfg.bridgePk || !(cfg.budgetSat > 0)) return;
    const seen = new Set();
    nwcUnsub = wallet.nostrSubscribe(
      { kinds: [NWC_FUND_KIND], authors: [cfg.bridgePk], '#p': [wallet.nostrPubkey()] },
      async (ev) => {
        if (seen.has(ev.id)) return;
        seen.add(ev.id);
        let req;
        try { req = JSON.parse(ev.content); } catch { return; }
        const sats = Math.round(req.amountSat || 0);
        if (!sats || !req.address || nwcSpent + sats > cfg.budgetSat) return; // over allowance: bridge times out
        try {
          const actionId = await mgr.send(req.address, sats);
          const action = mgr.state.actions.find((a) => a.id === actionId);
          if (!action || action.step === 'failed') return;
          nwcSpent += sats;
          await wallet.nostrPublish({
            kind: NWC_FUND_ACK_KIND,
            tags: [['p', cfg.bridgePk], ['e', ev.id]],
            content: JSON.stringify({ id: req.id }),
          });
        } catch {}
      });
  }

  // ---- unilateral exit (trustless: no server cooperation) ------------------
  const addrScript = (address) => btc.OutScript.encode(btc.Address(wallet.netCfg.net).decode(address));

  // Smallest confirmed, unreserved coin that can fund a CPFP bump.
  function pickFeeCoin(minSat) {
    return wallet.utxos
      .filter((u) => u.confirmed && !wallet.isReserved(utxoId(u)) && u.value >= minSat)
      .sort((a, b) => a.value - b.value)[0] || null;
  }

  async function doArkExit() {
    ui.arkBusy = 'exit'; ui.arkError = ''; render();
    try {
      const mgr = await connectArk();
      const spendables = mgr.vtxos().filter((v) => v.state === 'spendable');
      if (!spendables.length) throw new Error(t('arkNotConnected'));
      for (const v of spendables) mgr.startExit(v.id);
      toast(t('arkExitStarted', { n: spendables.length }));
      driveExits(mgr).catch(() => {});
    } catch (e) {
      ui.arkError = e.message;
    }
    ui.arkBusy = null; render();
  }

  async function driveExits(mgr) {
    const open = mgr.state.actions.filter((a) => a.type === 'exit' && !['done', 'failed'].includes(a.step));
    for (const a of open) {
      try {
        await driveExit(mgr, a);
        if (a.lastError) { delete a.lastError; delete a.actionable; mgr._save(); } // resolved
      } catch (e) {
        a.lastError = e.message;
        a.actionable = !!e.actionable; // user must act (e.g. fund fees) vs. plain retry
        mgr._save();
      }
    }
  }

  // One tick of an exit's state machine: broadcast the next unconfirmed hop
  // (with its fee child) as a package, then wait out the CSV, then claim.
  async function driveExit(mgr, action) {
    const rec = mgr._vtxo(action.vtxoId);
    const decoded = mgr._decoded(rec);
    if (action.step === 'chain') {
      const txs = signedExitTxs(decoded, mgr.serverPub);
      let lastConfirmedHeight = 0;
      let hopsDone = 0;
      for (const txi of txs) {
        const st = await mgr.chain.getTxStatus(txi.txid);
        if (st?.confirmed) { lastConfirmedHeight = st.block_height; hopsDone++; if (action.hopsDone !== hopsDone) { action.hopsDone = hopsDone; mgr._save(); } continue; }
        // /tx/:txid/status answers {confirmed:false} even for UNKNOWN txids
        // (electrs + mempool.space) — only /tx/:txid 404s definitively
        if (await mgr.chain.getTxHex(txi.txid)) return; // in mempool — wait
        // unknown to the chain: submit this hop + CPFP child as a package
        const feeRate = Math.max(1, (wallet.feeRates && wallet.feeRates.halfHourFee) || 2);
        // the child pays for the whole package (the parent is zero-fee)
        const feeSat = Math.ceil((txi.vsize + 130) * feeRate); // child ≈ 130 vB
        const coin = pickFeeCoin(Math.max(294, feeSat - txi.anchorValue + 294));
        if (!coin) {
          // No on-chain coin for the fee child. Try the hop bare — a node
          // that relays zero-fee txs (regtest with minrelaytxfee=0) needs no
          // bump. If it refuses, this is a PRECONDITION the user must fix,
          // not a transient to retry behind a vague message.
          try {
            await submitPackage(mgr.esploraUrl, [txi.hex]);
            mgr._save();
            return;
          } catch {
            const e = new Error(t('arkExitNoFeeCoin'));
            e.actionable = true;
            throw e;
          }
        }
        const changeAddr = wallet.freshChange().address;
        const child = buildBumpChild({
          parentTxidInternal: txi.txidInternal, anchorVout: txi.anchorVout, anchorValue: txi.anchorValue,
          coin: {
            txid: coin.txid, vout: coin.vout, value: coin.value,
            pubkey: wallet.derive(coin.chain, coin.index).pubkey,
            privkey: wallet.node(coin.chain, coin.index).privateKey,
          },
          changeScript: addrScript(changeAddr), feeSat,
        });
        await submitPackage(mgr.esploraUrl, [txi.hex, child.hex]);
        // reflect the spent fee coin locally so nothing double-spends it
        wallet.utxos = wallet.utxos.filter((u) => !(u.txid === coin.txid && u.vout === coin.vout));
        const ce = wallet.addrMap.get(changeAddr);
        if (ce) wallet.utxos.push({ txid: child.txid, vout: 0, value: child.changeSat, address: changeAddr, chain: ce.chain, index: ce.index, confirmed: false });
        wallet._recomputeBalanceFromUtxos();
        wallet.saveCache();
        action.bumpTxid = child.txid;
        mgr._save();
        return; // one hop per tick (TRUC: single unconfirmed parent)
      }
      // whole chain confirmed — start the CSV clock from the vtxo tx's height
      action.claimableAt = lastConfirmedHeight + decoded.exitDelta;
      action.step = 'timelock';
      mgr._save();
    }
    if (action.step === 'timelock') {
      const tip = await mgr.chain.tipHeight();
      if (action.tipSeen !== tip) { action.tipSeen = tip; mgr._save(); } // for the blocks-left display
      if (tip < action.claimableAt) return;
      const keys = mgr._keyForVtxo(rec);
      const feeRate = Math.max(1, (wallet.feeRates && wallet.feeRates.halfHourFee) || 2);
      const claim = buildExitClaim({
        vtxo: decoded, keys, serverPub: mgr.serverPub,
        destScript: addrScript(wallet.freshReceive().address), feeRate,
      });
      await mgr.chain.broadcastTx(claim.hex);
      rec.state = 'spent';
      action.claimTxid = claim.txid;
      action.step = 'claiming';
      mgr._movement({ type: 'exit', amountSat: claim.amountSat, status: 'complete', txid: claim.txid, detail: `fee ${claim.feeSat} sat` });
      mgr._save();
      wallet.scan().catch(() => {});
    }
    if (action.step === 'claiming') {
      const st = await mgr.chain.getTxStatus(action.claimTxid);
      if (!st?.confirmed) return;
      action.step = 'done';
      mgr._save();
    }
  }

  // ---- ark gifts: bearer-key vtxos ----------------------------------------
  // Ark can't presign a bearer spend (every arkoor needs a live server cosign),
  // so an ark gift is a vtxo sent to an ephemeral ark identity whose seed IS
  // the link. The claimer rebuilds the identity from the code, reads the
  // gift's mailbox for the vtxo, and sweeps it to their own ark address —
  // instant and free. The sender keeps the secret too, which is what makes
  // revoke possible (sweep it back before it's claimed; first cosign wins).
  const AG_MAGIC = 0x11;
  const AG_NET = { mainnet: 0, testnet: 1, signet: 2, mutinynet: 3, regtest: 4 };
  const AG_NET_BY = Object.fromEntries(Object.entries(AG_NET).map(([k, v]) => [v, k]));

  function encodeArkGiftCode(net, amountSat, secret) {
    const b = new Uint8Array(42);
    b[0] = AG_MAGIC;
    b[1] = AG_NET[net] ?? 0;
    new DataView(b.buffer).setBigUint64(2, BigInt(amountSat), true);
    b.set(secret, 10);
    return base32nopad.encode(b);
  }

  function decodeArkGiftCode(code) {
    try {
      const b = base32nopad.decode(String(code || '').toUpperCase());
      if (b.length !== 42 || b[0] !== AG_MAGIC || !(b[1] in AG_NET_BY)) return null;
      return {
        net: AG_NET_BY[b[1]],
        amountSat: Number(new DataView(b.buffer, b.byteOffset).getBigUint64(2, true)),
        secretHex: hex.encode(b.slice(10)),
      };
    } catch { return null; }
  }

  // A manager over the gift identity. State persists per device (keyed by the
  // secret's hash) so a claim interrupted mid-sweep resumes checkpointed.
  async function giftManager(secretHex) {
    const cfg = getArkConfig();
    if (!cfg) throw new Error(t('arkNotConnected'));
    const key = 'btc-wallet-arkgift:' + hex.encode(sha256(hex.decode(secretHex))).slice(0, 24);
    const mgr = new ArkManager({
      account: HDKey.fromMasterSeed(hex.decode(secretHex)),
      storage: {
        load: () => { try { return JSON.parse(localStorage.getItem(key) || 'null'); } catch { return null; } },
        save: (s) => { try { localStorage.setItem(key, JSON.stringify(s)); } catch {} },
      },
      arkUrl: cfg.ark, esploraUrl: cfg.esplora, network: getNetwork(),
    });
    await mgr.init();
    return mgr;
  }

  // The gift vtxo's key/outpoint for direct status checks (receive key 0).
  const giftKey0 = (secretHex) => {
    const n = HDKey.fromMasterSeed(hex.decode(secretHex)).deriveChild(3).deriveChild(0);
    return n.privateKey;
  };
  const pointRawFromId = (id) => {
    const [txid, vout] = id.split(':');
    const raw = new Uint8Array(36);
    raw.set(hex.decode(txid).reverse(), 0);
    new DataView(raw.buffer).setUint32(32, Number(vout), true);
    return raw;
  };

  function arkGiftRecords() {
    if (!ark || !ark.state) return [];
    return (ark.state.gifts = ark.state.gifts || []);
  }

  // Lazily mark records whose vtxo the server reports spent (claimed — or our
  // own revoke). Throttled: this is called from the gift card's render path.
  let arkGiftsCheckedAt = 0;
  function refreshArkGiftRecords() {
    if (!ark || Date.now() - arkGiftsCheckedAt < 30_000) return;
    arkGiftsCheckedAt = Date.now();
    const open = arkGiftRecords().filter((g) => !g.revoked && !g.claimed);
    Promise.all(open.map(async (g) => {
      try {
        const st = await getVtxoStatus(ark.arkUrl, pointRawFromId(g.id), giftKey0(g.secretHex));
        if (st === VTXO_STATE_SPENT) { g.claimed = true; return true; }
      } catch {}
      return false;
    })).then((flags) => { if (flags.some(Boolean)) ark._save(); });
  }

  // Sweep the gift identity's balance to `destAddress`. Shared by claim
  // (recipient's address) and revoke (sender's own address).
  async function sweepArkGift(code, destAddress) {
    const g = decodeArkGiftCode(code);
    if (!g) throw new Error('not an ark gift');
    if (g.net !== getNetwork()) throw new Error(t('arkGiftWrongNet', { net: g.net }));
    const gm = await giftManager(g.secretHex);
    await gm.sync();
    await gm.reconcile().catch(() => {});
    const amount = gm.balance().spendableSat;
    if (!amount) throw Object.assign(new Error(t('giftTakenTitle')), { giftTaken: true });
    await gm.send(destAddress, amount);
    return amount;
  }

  // Offboard the whole ark balance back into this wallet's own on-chain
  // receive address — the mirror image of boarding.
  // Offboard `amountSat` (or everything when omitted). An offboard moves
  // whole vtxos — no change — so a partial amount first mints an exact-amount
  // vtxo via a self-send (regtest-verified: the mailbox delivers self-sends),
  // then exits just that one. The number the user typed is the number that
  // leaves Spending; fees come off what arrives in Savings.
  async function doArkOffboard(amountSat) {
    ui.arkBusy = 'offboard'; ui.arkError = ''; render();
    try {
      const mgr = await connectArk();
      const spendables = () => mgr.state.vtxos.filter((v) => v.state === 'spendable');
      const total = spendables().reduce((n, v) => n + v.amountSat, 0);
      let ids; // undefined = all spendable vtxos
      if (amountSat && amountSat < total) {
        let target = spendables().find((v) => v.amountSat === amountSat);
        if (!target) {
          const before = new Set(spendables().map((v) => v.id));
          await mgr.send(mgr.address(), amountSat);
          for (let i = 0; i < 30 && !target; i++) {
            await new Promise((r) => setTimeout(r, 2000));
            await mgr.sync().catch(() => {});
            target = spendables().find((v) => v.amountSat === amountSat && !before.has(v.id));
          }
          if (!target) throw new Error(t('arkSplitTimeout'));
        }
        ids = [target.id];
      }
      const address = wallet.freshReceive().address;
      const spk = btc.OutScript.encode(btc.Address(wallet.netCfg.net).decode(address));
      const action = await mgr.startOffboard(spk, address, ids);
      ui.arkOffboardAmt = '';
      ui.arkMoveOpen = false;
      ui.arkOffboarded = { txid: action.txid, netSat: action.netSat, feeSat: action.feeSat };
      wallet.scan().catch(() => {}); // surface the incoming pending tx promptly
    } catch (e) {
      ui.arkError = e.message;
    }
    ui.arkBusy = null; render();
  }

  // VTXO upkeep, invisibly: a send needs a single vtxo covering the amount
  // (fragmentation breaks coin selection) and every vtxo expires at
  // expiryHeight (unrenewed, the ASP can eventually sweep it). Rather than
  // exposing a refresh button, consolidate-and-renew automatically when a
  // vtxo is inside the renewal window or fragmentation builds up. The round
  // fee this spends is the cost of keeping the money spendable at all.
  let arkAutoRefreshAt = 0;
  async function maybeAutoRefresh(mgr) {
    if (wallet.watchOnly || !mgr || !mgr.state) return;
    if (Date.now() - arkAutoRefreshAt < 30 * 60_000) return;
    const spendables = (mgr.state.vtxos || []).filter((v) => v.state === 'spendable');
    if (!spendables.length) return;
    // never start a round while any other action is still in flight
    if ((mgr.state.actions || []).some((a) => !['done', 'failed'].includes(a.step))) return;
    arkAutoRefreshAt = Date.now();
    try {
      const tip = await mgr.chain.tipHeight();
      const RENEW_BLOCKS = getNetwork() === 'regtest' ? 24 : 1008; // ~1 week of margin on mainnet
      const expiring = spendables.some((v) => v.expiryHeight && v.expiryHeight - tip < RENEW_BLOCKS);
      const fragmented = spendables.length >= 6;
      if (!expiring && !fragmented) return;
      await mgr.refresh();
    } catch {} // transient — the next throttled attempt retries
  }

  // Moving money between the two balances, in plain terms. This is the only
  // place the two rails meet, and it never names them: Saving is on-chain,
  // Spending is instant, and the wallet handles the rest.
  function boardForm() {
    const minBoard = (ark && ark.info && ark.info.minBoardAmountSat) || 0;
    const canBoard = wallet.spendable >= minBoard;
    return h('div', { class: 'col', style: 'width:100%;gap:8px' },
      h('div', { class: 'input-group' },
        h('input', {
          type: 'number', inputmode: 'numeric', min: '0',
          placeholder: t('arkBoardPlaceholder', { n: minBoard.toLocaleString() }),
          value: ui.arkBoardAmt || '',
          onInput: (e) => { ui.arkBoardAmt = e.target.value; render(); },
        }),
        h('button', { class: 'btn-primary', disabled: !!ui.arkBusy || !canBoard, onClick: doArkBoard },
          ui.arkBusy === 'board' ? h('span', { class: 'spinner sm' }) : t('arkBoardBtn'))),
      (() => {
        const sats = parseInt((ui.arkBoardAmt || '').trim(), 10);
        if (!sats || sats < minBoard || !ark) return null;
        const fee = boardFee(sats, ark.info.boardFees);
        return h('div', { class: 'small muted', style: 'text-align:center' },
          t('arkBoardFeeNote', { fee: fmtAmount(fee), net: fmtAmount(sats - fee) }));
      })(),
      canBoard
        ? h('div', { class: 'small faint', style: 'text-align:center' },
            t('arkBoardAvailable', { n: fmtAmount(wallet.spendable) + ' ' + unitLabel() }))
        : h('div', { class: 'small faint', style: 'text-align:center' },
            t('arkBoardNoFunds', { n: minBoard.toLocaleString() })));
  }

  // Moving money between the two balances, inline on the balance card — the
  // one door between the rails opens right where the balances live.
  function movePanel() {
    if (!ark) connectArk().catch(() => {});
    const dir = ui.arkMoveDir || 'toSpending';
    const b = arkBalance();
    return h('div', { class: 'col balance-move' },
      h('div', { class: 'seg' },
        h('button', { class: dir === 'toSpending' ? 'active' : '', onClick: () => { ui.arkMoveDir = 'toSpending'; ui.arkError = ''; render(); } }, t('moveToSpending')),
        h('button', { class: dir === 'toSaving' ? 'active' : '', onClick: () => { ui.arkMoveDir = 'toSaving'; ui.arkError = ''; render(); } }, t('moveToSaving'))),
      dir === 'toSpending'
        ? h('div', { class: 'col', style: 'gap:8px' },
            h('p', { class: 'small muted', style: 'margin:0' }, t('moveToSpendingDesc')),
            ark ? boardForm() : h('div', { class: 'row gap6', style: 'align-items:center' },
              h('span', { class: 'spinner sm' }), h('span', { class: 'small muted' }, t('arkConnecting'))))
        : h('div', { class: 'col', style: 'gap:8px' },
            h('p', { class: 'small muted', style: 'margin:0' }, t('moveToSavingDesc')),
            // no "X sats in Spending" line — the balance sits right above on this card
            (() => {
              const spendable = b ? b.spendableSat : 0;
              const sats = parseInt((ui.arkOffboardAmt || '').trim(), 10) || 0;
              const valid = sats > 0 && sats <= spendable;
              return h('div', { class: 'col', style: 'gap:8px' },
                h('div', { class: 'input-group' },
                  h('input', {
                    type: 'number', inputmode: 'numeric', min: '0',
                    placeholder: t('arkOffboardAmtPlaceholder'),
                    value: ui.arkOffboardAmt || '',
                    onInput: (e) => { ui.arkOffboardAmt = e.target.value; render(); },
                  }),
                  h('button', { class: 'btn-ghost', onClick: () => { ui.arkOffboardAmt = String(spendable); render(); } }, t('max')),
                  h('button', {
                    class: 'btn-primary', disabled: !!ui.arkBusy || !valid,
                    onClick: () => doArkOffboard(sats),
                  }, ui.arkBusy === 'offboard' ? h('span', { class: 'spinner sm' }) : t('moveToSavingBtn'))),
                ui.arkBusy === 'offboard' && sats < spendable
                  ? h('div', { class: 'small muted', style: 'text-align:center' }, t('arkSplitting'))
                  : null,
                h('button', {
                  class: 'linklike small', style: 'align-self:center',
                  onClick: () => { ui.arkMoveOpen = false; ui.arkExitPage = true; ui.arkError = ''; render(); },
                }, t('arkUniTitle')));
            })()),
      ui.arkError ? h('div', { class: 'notice err' }, ui.arkError) : null);
  }


  // "Payment received!" takeover for unseen Ark receives.
  function arkCelebration() {
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
    return null;
  }

  // Offboard success screen — mirror of the boarded screen.
  function arkOffboardedScreen() {
    if (!ui.arkOffboarded) return null;
    const o = ui.arkOffboarded;
    const url = wallet.api.explorerTx(o.txid);
    return h(
      'div',
      { class: 'card col', style: 'align-items:center;text-align:center;gap:14px;padding:40px 20px' },
      h('div', { class: 'check-badge' }, '✓'),
      h('h2', { style: 'margin:0' }, t('arkOffboardedTitle')),
      h('div', { class: 'amount-pos', style: 'font-size:18px' }, '+' + fmtAmount(o.netSat) + ' ' + unitLabel()),
      h('p', { class: 'small muted', style: 'margin:0' }, t('arkOffboardedNote')),
      o.feeSat ? h('div', { class: 'small faint' }, t('feeShort', { x: fmtAmount(o.feeSat) })) : null,
      h('div', { class: 'addr-box', style: 'width:100%' }, o.txid),
      h('div', { class: 'row gap6' },
        copyBtn(o.txid, t('copyTxid')),
        h('a', { class: 'btn btn-sm', href: url, target: '_blank', rel: 'noopener', onClick: (e) => { e.preventDefault(); openExternal(url); } }, t('viewOnMempool'))),
      h('button', { class: 'btn-primary btn-block', onClick: () => { ui.arkOffboarded = null; ui.arkExitPage = null; render(); } }, t('done'))
    );
  }

  // Boarding success screen (txid + explorer link) until dismissed.
  function arkBoardedScreen() {
    // A board just broadcast — show its success screen until dismissed.
    if (ui.arkBoarded) {
      const b = ui.arkBoarded;
      const url = wallet.api.explorerTx(b.txid);
      return h(
        'div',
        { class: 'card col', style: 'align-items:center;text-align:center;gap:14px;padding:40px 20px' },
        h('div', { class: 'check-badge' }, '✓'),
        h('h2', { style: 'margin:0' }, t('arkBoardedTitle')),
        h('div', { class: 'amount-pos', style: 'font-size:18px' }, '+' + fmtAmount(b.netSat) + ' ' + unitLabel()),
        h('p', { class: 'small muted', style: 'margin:0' }, t('arkBoardedNote')),
        h('div', { class: 'addr-box', style: 'width:100%' }, b.txid),
        h('div', { class: 'row gap6' },
          copyBtn(b.txid, t('copyTxid')),
          h('a', { class: 'btn btn-sm', href: url, target: '_blank', rel: 'noopener', onClick: (e) => { e.preventDefault(); openExternal(url); } }, t('viewOnMempool'))),
        h('button', { class: 'btn-primary btn-block', onClick: () => { ui.arkBoarded = null; render(); } }, t('done'))
      );
    }
    return null;
  }

  // Per-exit progress lines (chain hops / timelock countdown / claiming), with
  // a cancel for an exit that never published. Shown on the exit page.
  function arkExitStatusLines() {
    const s = arkStateNow();
    return ((s && s.actions) || []).filter((a) => a.type === 'exit' && !['done', 'failed'].includes(a.step)).map((a) => {
      const left = a.step === 'timelock' ? Math.max(0, a.claimableAt - (a.tipSeen || 0)) : 0;
      const mins = left * 10;
      const eta = getNetwork() === 'regtest' ? ''
        : mins >= 2880 ? ` (≈ ${Math.round(mins / 1440)} d)`
        : mins >= 120 ? ` (≈ ${Math.round(mins / 60)} h)`
        : ` (≈ ${mins} min)`;
      return h('div', { class: 'small muted', style: 'margin-top:4px' },
        a.step === 'chain' ? t('arkExitChainStatus', { n: fmtAmount(a.amountSat), done: String(a.hopsDone || 0), total: String((a.txids || []).length) })
          : a.step === 'timelock' ? t('arkExitTimelockStatus', { n: fmtAmount(a.amountSat), blocks: String(left), eta })
          : t('arkExitClaimingStatus', { n: fmtAmount(a.amountSat) }),
        a.lastError ? h('div', { class: a.actionable ? 'small err' : 'small faint' }, a.actionable ? a.lastError : t('arkExitRetrying')) : null,
        a.actionable && !(a.hopsDone > 0)
          ? h('button', { class: 'linklike small', onClick: () => {
              a.step = 'failed';
              const v = ark && ark._vtxo(a.vtxoId);
              if (v && v.state === 'pending') v.state = 'spendable';
              if (ark) ark._save();
              render();
            } }, t('arkExitCancel'))
          : null);
    });
  }

  // The exit page: cooperative offboard vs unilateral exit, with explanation.
  // Reached from the "Exit" link on the Ark balance line.
  function arkExitPage() {
    if (ui.arkOffboarded) return arkOffboardedScreen(); // cooperative success takeover
    const b = arkBalance() || { spendableSat: 0, pendingSat: 0 };
    const spendable = b.spendableSat;
    const total = b.spendableSat + b.pendingSat;
    const nSpend = ((arkStateNow() && arkStateNow().vtxos) || []).filter((v) => v.state === 'spendable').length;
    const exits = arkExitStatusLines();
    const back = () => { ui.arkExitPage = null; ui.arkError = ''; render(); };
    return h('div', { class: 'col', style: 'gap:16px' },
      h('div', { class: 'card col', style: 'gap:8px' },
        h('h3', { class: 'row gap6', style: 'align-items:center;margin:0' }, h('span', { html: ARK_ICON(18) }), t('arkExitPageTitle')),
        h('p', { class: 'small muted', style: 'margin:0' }, t('arkExitPageIntro')),
        total > 0 ? h('div', { class: 'row between', style: 'margin-top:4px' },
          h('span', { class: 'small muted' }, t('arkBalance')),
          h('span', { class: 'small' }, fmtAmount(total) + ' ' + unitLabel())) : null),
      // cooperative
      h('div', { class: 'card col', style: 'gap:8px' },
        h('h4', { style: 'margin:0' }, t('arkCoopTitle')),
        h('p', { class: 'small muted', style: 'margin:0' }, t('arkCoopDesc')),
        spendable > 0
          ? h('button', { class: 'btn-primary btn-block', disabled: !!ui.arkBusy, onClick: () => doArkOffboard() },
              ui.arkBusy === 'offboard' ? h('span', { class: 'spinner sm' }) : t('arkOffboardBtn', { n: fmtAmount(spendable) + ' ' + unitLabel() }))
          : h('div', { class: 'small faint' }, t('arkExitNoBalance'))),
      // unilateral
      h('div', { class: 'card col', style: 'gap:8px' },
        h('h4', { style: 'margin:0' }, t('arkUniTitle')),
        h('p', { class: 'small muted', style: 'margin:0' }, t('arkUniDesc')),
        nSpend > 0
          ? h('button', { class: 'btn-ghost btn-block', disabled: !!ui.arkBusy, onClick: doArkExit },
              ui.arkBusy === 'exit' ? h('span', { class: 'spinner sm' }) : t('arkExitBtn', { n: nSpend }))
          : null,
        ...exits),
      ui.arkError ? h('div', { class: 'notice err' }, ui.arkError) : null,
      h('button', { class: 'btn-ghost btn-block', onClick: back }, t('back'))
    );
  }

  return {
    id: 'ark',
    init() { initArk(); },
    stop() { stopArk(); },
    screenView() { return ui.arkExitPage ? arkExitPage() : null; },
    receiveTakeover() {
      const offboarded = arkOffboardedScreen();
      if (offboarded) return offboarded;
      const boarded = arkBoardedScreen();
      if (boarded) return boarded;
      return arkCelebration();
    },
    isSendDest(a) { return isArkAddress(a) && arkAvailable(); },
    hideSendControls(a) { return isArkAddress(a); },
    sendFormNote(a) {
      if (!isArkAddress(a)) return null;
      maybeReconcile();
      return h('div', { class: 'small faint' }, t('arkSendHint'));
    },
    interceptReview(s) {
      if (s.recipients.length === 1) {
        const inv = (s.recipients[0].address || '').trim().replace(/^lightning:/i, '');
        if (maybeBolt11(inv) && startArkLnPay(inv)) return true;
      }
      if (s.recipients.length === 1 && isArkAddress(s.recipients[0].address)) {
        if (!arkAvailable()) throw new Error(t('arkNotConnected'));
        const sats = ctx.parseAmount(s.recipients[0].amount, ctx.getUnit());
        if (!sats || sats <= 0) throw new Error(t('enterValidAmtForN', { n: 1 }));
        ui.arkSend = { address: s.recipients[0].address.trim(), amountSat: sats };
        render();
        return true;
      }
      return false;
    },
    sendView() {
      if (ui.arkLnPaid || ui.arkLnPay) return arkLnPayView();
      if (ui.arkZapped || ui.arkZap) return arkZapView();
      if (ui.arkSent || ui.arkSend) return arkSendReview();
      return null;
    },
    // A bolt11 pays from the ark balance when it can cover it. Reached via the
    // swaps feature's delegation (its matcher runs first) or directly in
    // builds without the swaps feature.
    startArkLnPay(invoice, meta) { return startArkLnPay(invoice, meta); },
    // The zaps feature's generic Lightning seams (once served by the retired
    // swaps feature): the ASP pays invoices natively over ark.
    canLnPay() { return arkAvailable() && !wallet.watchOnly && !!(ark && ark.info); },
    startLnPay(invoice, meta) { return startArkLnPay(invoice, meta); },
    // ---- headless seam for the NWC wallet service ----
    arkPayInvoice(invoice, opts) { return payInvoiceHeadless(invoice, opts); },
    arkSpendableSat() { const b = arkBalance(); return b ? b.spendableSat : 0; },
    arkReady() { return arkAvailable(); },
    async arkMakeInvoice(amountSat, description) {
      const mgr = await connectArk();
      const a = await mgr.createLnInvoice(amountSat, description);
      return { invoice: a.invoice, paymentHash: a.paymentHash, amountSat };
    },
    arkMovements() { const s = arkStateNow(); return s ? (s.movements || []) : []; },
    // The wallet's reusable ark receive address (BIP-353 names publish it).
    async arkStaticAddress() {
      const mgr = await connectArk();
      return mgr.address();
    },
    // Whether background answering can mirror right now.
    arkBgReady() { return !!(ark && ark.info && ark.state); },
    // nwc.js calls this (with its connections) whenever the mirror should
    // refresh: on enable, on connection changes, after payments, on a timer.
    async arkBgWrite(connections, offer) { return writeBgMirror(connections, offer); },
    async arkBgSpendableSat() {
      const rec = await loadBg(wallet._cacheKey());
      return ((rec && rec.mgr && rec.mgr.vtxos) || [])
        .filter((v) => v.state === 'spendable').reduce((n, v) => n + (v.amountSat || 0), 0);
    },
    // Worker payments become ordinary history lines once the app opens.
    async arkBgNoteSpends(spends) {
      const mgr = await connectArk();
      for (const sp of spends) {
        mgr._movement({
          type: 'ln-send', amountSat: sp.amountSat, status: 'complete',
          detail: `while closed · fee ${sp.feeSat || 0} sat`, invoice: sp.invoice || '', preimage: sp.preimage || '',
        });
      }
      mgr._save();
    },
    // An npub pasted into Send becomes an ark zap (needs the nostr seam from
    // the sync feature and a connected-able ark). A bolt11 is handled here
    // only in builds without the swaps feature (whose matcher runs first and
    // delegates back via the startArkLnPay hook).
    matchSendText(text) {
      const inv = (text || '').trim().replace(/^lightning:/i, '');
      if (maybeBolt11(inv)) return startArkLnPay(inv);
      const pk = npubToHex(text);
      if (!pk || !arkAvailable() || !wallet.nostrFetch) return false;
      startNpubPay(pk, String(text).trim());
      return true;
    },
    historyEntries() {
      const s = arkStateNow();
      if (!s) return [];
      return (s.movements || [])
        .filter((m) => ['receive', 'send', 'board', 'offboard', 'exit', 'ln-send', 'ln-receive'].includes(m.type) && m.status === 'complete')
        .map((m) => ({ time: m.ts, render: () => arkHistoryItem(m) }));
    },
    historyDetail() {
      if (!ui.arkMoveDetail) return null;
      const s = arkStateNow();
      const m = s ? (s.movements || []).find((x) => x.id === ui.arkMoveDetail) : null;
      if (m) return arkMoveDetailView(m);
      ui.arkMoveDetail = null;
      return null;
    },
    // The spendable off-chain balance IS the wallet's "Spending" — the balance
    // card shows it by name, so this feature only reports the number.
    // "Move money" under the balance — the one door between the two balances.
    balanceActions() {
      if (wallet.watchOnly || !arkAvailable()) return [];
      return [{
        label: ui.arkMoveOpen ? t('hide') : t('moveMoney'),
        onClick: () => { ui.arkMoveOpen = !ui.arkMoveOpen; ui.arkError = ''; render(); },
      }];
    },
    balanceExtra() {
      if (!ui.arkMoveOpen || wallet.watchOnly || !arkAvailable()) return null;
      return movePanel();
    },
    spendingSat() {
      const b = arkBalance();
      return b ? b.spendableSat + b.pendingSat : 0;
    },
    balanceLines() {
      const b = arkBalance();
      if (!b) return [];
      // Money mid-move: it has left Saving but hasn't landed in Spending, so
      // say where it went rather than letting it vanish for a confirmation.
      return b.boardingSat > 0 ? [{ label: t('movingLabel'), sat: b.boardingSat }] : [];
    },
    decorateTxRow(tx) {
      const s = arkStateNow();
      if (!s) return null;
      const acts = s.actions || [];
      if (tx.net < 0) {
        const a = acts.find((x) => x.type === 'board' && x.fundingTxid === tx.txid);
        return a ? { icon: h('span', { html: ARK_MARK(16) }), label: h('span', {}, t('arkBoardHistory')) } : null;
      }
      const o = acts.find((x) => x.type === 'offboard' && x.txid === tx.txid);
      if (o) return { icon: h('span', { html: ARK_MARK(16) }), label: h('span', {}, t('arkOffboardHistory')) };
      const e = acts.find((x) => x.type === 'exit' && x.claimTxid === tx.txid);
      return e ? { icon: h('span', { html: ARK_MARK(16) }), label: h('span', {}, t('arkExitHistory')) } : null;
    },
    txDetailSection(tx) {
      const s = arkStateNow();
      if (!s) return null;
      const a = (s.actions || []).find((x) => x.type === 'board' && x.fundingTxid === tx.txid);
      if (!a) return null;
      const done = a.step === 'done';
      return h('div', { class: 'summary col', style: 'gap:0' },
        h('div', { class: 'row gap6', style: 'font-weight:600;margin:12px 0 2px;align-items:center' }, h('span', { html: ARK_ICON(16) }), t('arkBoardHistory')),
        h('div', { class: 'line' },
          h('span', { class: 'k' }, t('arkBalance')),
          h('span', { class: 'v' }, '+' + fmtAmount(a.amountSat - a.feeSat) + ' ' + unitLabel())),
        a.feeSat > 0
          ? h('div', { class: 'line' },
              h('span', { class: 'k' }, t('arkBoardFeeLabel')),
              h('span', { class: 'v' }, fmtAmount(a.feeSat) + ' ' + unitLabel()))
          : null,
        done ? null : h('div', { class: 'small muted', style: 'margin-top:2px' }, t('arkBoardedNote')));
    },
    settingsCards() { return [arkCard()]; },

    // ---- ark-gift hooks (called by the gifts feature via ctx.hook) ----
    arkGiftInfo() {
      if (!arkAvailable() || !ark || !ark.state) return null;
      maybeReconcile(); // the gift form is a send-intent signal too (throttled)
      return { spendableSat: ark.balance().spendableSat };
    },
    arkGiftDecode(code) { return decodeArkGiftCode(code); },
    // A fresh visitor (no wallets) opening a gift link lands on the gift's
    // network automatically instead of being told to change Settings.
    arkGiftAdoptNetwork(code) {
      const g = decodeArkGiftCode(code);
      if (!g || g.net === getNetwork()) return false;
      setNetwork(g.net);
      return true;
    },
    async arkGiftCreate(amountSat) {
      const mgr = await connectArk();
      const secret = crypto.getRandomValues(new Uint8Array(32));
      const secretHex = hex.encode(secret);
      const gm = await giftManager(secretHex);
      const actionId = await mgr.send(gm.address(), amountSat);
      const action = mgr.state.actions.find((a) => a.id === actionId);
      if (!action || action.step === 'failed') throw new Error(action?.error || t('claimFailed'));
      const vtxoId = decodeVtxo(hex.decode((action.destBytesList || [action.destBytes])[0])).id;
      arkGiftRecords().push({ id: vtxoId, amountSat, secretHex, created: Date.now(), revoked: false, claimed: false });
      mgr._save();
      return { code: encodeArkGiftCode(getNetwork(), amountSat, secret), amount: amountSat };
    },
    // Claim-side status: claimable (with the live amount), taken, wrongnet, or
    // unknown (not visible here — wrong server or not yet delivered).
    async arkGiftStatus(code) {
      const g = decodeArkGiftCode(code);
      if (!g) return null;
      if (g.net !== getNetwork()) return { state: 'wrongnet', net: g.net, amountSat: g.amountSat };
      const gm = await giftManager(g.secretHex);
      await gm.sync().catch(() => {});
      await gm.reconcile().catch(() => {});
      const amt = gm.balance().spendableSat;
      if (amt > 0) return { state: 'claimable', amountSat: amt };
      const seen = gm.state.vtxos.length > 0;
      return { state: seen ? 'taken' : 'unknown', amountSat: g.amountSat };
    },
    async arkGiftClaim(code) {
      if (wallet.watchOnly) throw new Error(t('arkWatchOnly'));
      const mine = await connectArk();
      const amount = await sweepArkGift(code, mine.address());
      await mine.sync().catch(() => {}); // pull the swept vtxo in right away
      mine.ackReceives(); // the gift UI celebrates; don't double-celebrate here
      return amount;
    },
    arkGiftOutstanding() {
      refreshArkGiftRecords();
      return arkGiftRecords().filter((g) => !g.revoked && !g.claimed)
        .map((g) => ({ id: g.id, amountSat: g.amountSat, created: g.created }));
    },
    async arkGiftRevoke(id) {
      const g = arkGiftRecords().find((x) => x.id === id);
      if (!g) throw new Error('unknown gift');
      const mine = await connectArk();
      const code = encodeArkGiftCode(getNetwork(), g.amountSat, hex.decode(g.secretHex));
      let amount;
      try {
        amount = await sweepArkGift(code, mine.address());
      } catch (e) {
        // beaten by the claimer — record it so the row self-heals immediately
        if (e && e.giftTaken) { g.claimed = true; mine._save(); }
        throw e;
      }
      g.revoked = true;
      mine._save();
      await mine.sync().catch(() => {});
      mine.ackReceives(); // our own sweep-back isn't a "payment received"
      return amount;
    },
  };
}

// Ark feature — off-chain payments via an ASP (Second's bark/captaind
// protocol, spoken natively by ../ark). Receive address + boarding, instant
// sends, history entries, refresh/consolidation, server settings.

import * as btc from '@scure/btc-signer';
import { HDKey } from '@scure/bip32';
import { hex, base32nopad, bech32 } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';
import { ArkManager } from '../ark/manager.js';
import { boardFee } from '../ark/board.js';
import { decodeVtxo, getVtxoStatus, VTXO_STATE_SPENT, concatBytes } from '../ark/proto.js';
import { signedExitTxs, buildBumpChild, buildExitClaim, submitPackage } from '../ark/exit.js';
import { utxoId } from '../wallet.js';
import { getNetwork, setNetwork, arkPresets, getArkProviderId, setArkProviderId, getArkCustom, setArkCustom, getArkConfig } from '../api.js';
import { t } from '../i18n.js';
import { qrSvg } from '../qr.js';
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
    _arkKey() { return this._cacheKey() + ':ark'; },
    loadArkState() {
      try { return JSON.parse(localStorage.getItem(this._arkKey()) || 'null'); } catch { return null; }
    },
    saveArkState(state) {
      try { localStorage.setItem(this._arkKey(), JSON.stringify(state)); } catch {}
    },
  });
}

// Merge two ark states so devices can't clobber each other through the sync
// snapshot: vtxos union by id with 'spent' winning (a spend on any device
// sticks), actions/movements/gifts union by id, counters take the max (so two
// devices never reuse a key index).
export function mergeArkStates(a, b) {
  if (!a) return b;
  if (!b) return a;
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
  out.receiveAckTs = Math.max(a.receiveAckTs || 0, b.receiveAckTs || 0);
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
    mergeAlways: true, // load() is a commutative merge — apply older snapshots too
    save: () => {
      const s = wallet.loadArkState();
      return s ? { arkState: s } : {};
    },
    load: (d) => {
      if (!d.arkState) return;
      const local = wallet.loadArkState();
      const merged = mergeArkStates(local, d.arkState);
      wallet.saveArkState(merged);
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
      if (mergedN && novel) setTimeout(() => initArk(), 0);
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
    ark = null;
    arkConnectPromise = null;
  }

  function arkAvailable() {
    return !!getArkConfig() && !wallet.watchOnly && !!wallet.account;
  }

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

  function connectArk() {
    if (ark) return Promise.resolve(ark);
    if (arkConnectPromise) return arkConnectPromise;
    if (!arkAvailable()) return Promise.reject(new Error(t('arkNotConnected')));
    const cfg = getArkConfig();
    const gen = arkInitGen;
    const mgr = new ArkManager({
      account: wallet.account(),
      storage: {
        load: () => wallet.loadArkState(),
        // merge-on-save: the MANAGER is authoritative for the state of the
        // vtxos it tracks (its reconcile/spends must persist), so its state
        // is the first arg and wins; storage only contributes vtxos the
        // manager hasn't loaded yet (a snapshot merged in from another device
        // between init and the next reinit). saveCache() then carries ark
        // state into the snapshot -> debounced nostr publish.
        save: (s) => {
          wallet.saveArkState(mergeArkStates(s, wallet.loadArkState()));
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
      const tick = () => mgr.sync().catch(() => {}).then(() => driveExits(mgr)).catch(() => {});
      tick();
      // Reconcile once on connect: a vtxo synced in from another device (or
      // one this device held while a spend happened elsewhere) is checked
      // against the server, so a stale spendable is caught here rather than
      // only at send time.
      mgr.reconcile().catch(() => {});
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
    if (!getArkConfig()) return null;
    return wallet.loadArkState();
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

  function arkHistoryItem(m) {
    const incoming = !['send', 'offboard', 'exit'].includes(m.type);
    const label = m.type === 'receive' ? t('received') : m.type === 'board' ? t('arkBoarded')
      : m.type === 'offboard' ? t('arkOffboarded') : m.type === 'exit' ? t('arkExited') : t('sent');
    return h(
      'div',
      { class: 'item', style: 'cursor:pointer', onClick: () => { ui.arkMoveDetail = m.id; render(); } },
      // Ark mark in the (direction-colored) circle carries the rail; the label
      // + signed amount carry direction, so no redundant "Ark" text chip.
      h('div', { class: `ico ${incoming ? 'in' : 'out'}`, html: ARK_MARK(15) }),
      h('div', { class: 'grow' },
        h('div', { class: 'row gap6' },
          label,
          m.status !== 'complete' ? h('span', { class: 'tag pending' }, m.status) : null),
        h('div', { class: 'small faint' }, timeAgo(m.ts / 1000))),
      h('div', { style: 'text-align:right' },
        h('div', { class: incoming ? 'amount-pos' : 'amount-neg' }, (incoming ? '+' : '-') + fmtAmount(m.amountSat)))
    );
  }

  function arkMoveDetailView(m) {
    const incoming = !['send', 'offboard', 'exit'].includes(m.type);
    const label = m.type === 'receive' ? t('received') : m.type === 'board' ? t('arkBoarded')
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
      h('h3', { class: 'row gap6', style: 'align-items:center' }, h('span', { html: ARK_MARK(18) }), 'Ark'),
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
        const LABEL = { board: 'arkOpsBoard', send: 'arkOpsSend', refresh: 'arkOpsRefresh', offboard: 'arkOpsOffboard' };
        const parts = Object.entries(counts).map(([type, n]) => t(LABEL[type] || 'arkPendingActions', { n }));
        return parts.length ? h('div', { class: 'small muted' }, parts.join(' · ')) : null;
      })(),
      spendables.length >= 1
        ? h('button', { class: 'btn-ghost btn-block', disabled: !!ui.arkBusy, onClick: doArkRefresh },
            ui.arkBusy === 'refresh' ? h('span', { class: 'spinner sm' }) : t('arkRefreshBtn', { n: spendables.length }))
        : null,
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
      const vtxoId = decodeVtxo(hex.decode(action.destBytes)).id;
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
  async function doArkOffboard() {
    ui.arkBusy = 'offboard'; ui.arkError = ''; render();
    try {
      const mgr = await connectArk();
      const address = wallet.freshReceive().address;
      const spk = btc.OutScript.encode(btc.Address(wallet.netCfg.net).decode(address));
      const action = await mgr.startOffboard(spk, address);
      ui.arkOffboarded = { txid: action.txid, netSat: action.netSat, feeSat: action.feeSat };
      wallet.scan().catch(() => {}); // surface the incoming pending tx promptly
    } catch (e) {
      ui.arkError = e.message;
    }
    ui.arkBusy = null; render();
  }

  async function doArkRefresh() {
    ui.arkBusy = 'refresh'; ui.arkError = ''; render();
    try {
      await ark.refresh();
      toast(t('arkRefreshStarted'), 5000);
    } catch (e) {
      ui.arkError = e.message;
    }
    ui.arkBusy = null; render();
  }

  // The Ark receive pane: connect-on-demand, then address + board form.
  function arkReceivePane(seg) {
  if (true) {
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
      const minBoard = ark.info.minBoardAmountSat || 0;
      const canBoard = wallet.spendable >= minBoard;
      return h(
        'div',
        { class: 'card col', style: 'align-items:center;gap:14px' },
        seg,
        h('p', { class: 'small muted', style: 'margin:0;text-align:center' }, t('arkReceiveIntro')),
        h('div', { html: qrSvg(arkAddr) }),
        h('div', { class: 'addr-box break', style: 'width:100%;font-size:11px' }, arkAddr),
        copyBtn(arkAddr, t('copyAddress')),
        // Board: fund your Ark balance from this wallet's on-chain coins.
        h('div', { class: 'col', style: 'width:100%;gap:8px;border-top:1px solid var(--border,rgba(128,128,128,.2));padding-top:14px' },
          h('div', { class: 'small muted', style: 'text-align:center' }, t('arkBoardIntro')),
          h('div', { class: 'input-group' },
            h('input', {
              type: 'number', inputmode: 'numeric', min: '0',
              placeholder: t('arkBoardPlaceholder', { n: minBoard.toLocaleString() }),
              value: ui.arkBoardAmt || '',
              onInput: (e) => { ui.arkBoardAmt = e.target.value; render(); },
            }),
            h('button', { class: 'btn-sm', disabled: !!ui.arkBusy || !canBoard, onClick: doArkBoard },
              ui.arkBusy === 'board' ? h('span', { class: 'spinner sm' }) : t('arkBoardBtn'))),
          // show the server's board fee BEFORE the money moves, not after
          (() => {
            const sats = parseInt((ui.arkBoardAmt || '').trim(), 10);
            if (!sats || sats < minBoard) return null;
            const fee = boardFee(sats, ark.info.boardFees);
            return h('div', { class: 'small muted', style: 'text-align:center' },
              t('arkBoardFeeNote', { fee: fmtAmount(fee), net: fmtAmount(sats - fee) }));
          })(),
          canBoard
            ? h('div', { class: 'small faint', style: 'text-align:center' }, t('arkBoardAvailable', { n: fmtAmount(wallet.spendable) + ' ' + unitLabel() }))
            : h('div', { class: 'small faint', style: 'text-align:center' }, t('arkBoardNoFunds', { n: minBoard.toLocaleString() })),
          ui.arkError ? h('div', { class: 'notice err' }, ui.arkError) : null)
      );
    }
    throw new Error('unreachable');
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
          ? h('button', { class: 'btn-primary btn-block', disabled: !!ui.arkBusy, onClick: doArkOffboard },
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
    receiveModes() {
      if (!arkAvailable()) return [];
      return [{ id: 'ark', label: t('receiveArkTab'), icon: ARK_MARK(18), render: (seg) => arkReceivePane(seg) }];
    },
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
      if (ui.arkZapped || ui.arkZap) return arkZapView();
      if (ui.arkSent || ui.arkSend) return arkSendReview();
      return null;
    },
    // An npub pasted into Send becomes an ark zap (needs the nostr seam from
    // the sync feature and a connected-able ark).
    matchSendText(text) {
      const pk = npubToHex(text);
      if (!pk || !arkAvailable() || !wallet.nostrFetch) return false;
      ui.arkZap = { npub: String(text).trim(), pk, amount: '', comment: '', status: 'lookup' };
      ui.sendError = '';
      render();
      Promise.all([connectArk(), lookupArkZapTarget(pk)])
        .then(([, res]) => { if (ui.arkZap && ui.arkZap.pk === pk) { Object.assign(ui.arkZap, res); render(); } })
        .catch((e) => { if (ui.arkZap && ui.arkZap.pk === pk) { ui.arkZap.status = 'noark'; ui.sendError = e.message; render(); } });
      return true;
    },
    historyEntries() {
      const s = arkStateNow();
      if (!s) return [];
      return (s.movements || [])
        .filter((m) => ['receive', 'send', 'board', 'offboard', 'exit'].includes(m.type) && m.status === 'complete')
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
    balanceLines() {
      const b = arkBalance();
      if (!b) return [];
      const lines = [];
      if (b.spendableSat + b.pendingSat > 0) {
        // "Ark balance … Exit" — the exit link opens the offboard/exit page.
        // Watch-only wallets can't move funds, so they just show the balance.
        const label = wallet.watchOnly
          ? t('arkBalance')
          : h('span', { class: 'row gap6', style: 'align-items:center' },
              t('arkBalance'),
              h('span', { class: 'linklike', style: 'font-size:12px', onClick: () => { ui.arkExitPage = true; ui.arkError = ''; render(); } }, t('arkExitLink')));
        lines.push({ label, sat: b.spendableSat + b.pendingSat });
      }
      // A board in flight: the sats already left the on-chain balance, so show
      // where they went instead of having them silently disappear.
      if (b.boardingSat > 0) lines.push({ label: t('arkBoarding'), sat: b.boardingSat });
      return lines;
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
      const vtxoId = decodeVtxo(hex.decode(action.destBytes)).id;
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

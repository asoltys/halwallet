// Ark feature — off-chain payments via an ASP (Second's bark/captaind
// protocol, spoken natively by ../ark). Receive address + boarding, instant
// sends, history entries, refresh/consolidation, server settings.

import * as btc from '@scure/btc-signer';
import { ArkManager } from '../ark/manager.js';
import { getNetwork, arkPresets, getArkProviderId, setArkProviderId, getArkCustom, setArkCustom, getArkConfig } from '../api.js';
import { t } from '../i18n.js';
import { qrSvg } from '../qr.js';
import { shortAddr, shortTxid, timeAgo } from '../format.js';

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

export function arkFeature(ctx) {
  const { h, ui, render, wallet, blankSend, fmtAmount, unitLabel, unitTag, copyBtn, toast, openExternal } = ctx;
  installArkWallet(wallet); // ark state storage lives outside the core wallet

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

  function arkBalance() {
    if (!ark || !ark.state) return null;
    return ark.balance();
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
    const incoming = !['send', 'offboard'].includes(m.type);
    const label = m.type === 'receive' ? t('received') : m.type === 'board' ? t('arkBoarded')
      : m.type === 'offboard' ? t('arkOffboarded') : t('sent');
    return h(
      'div',
      { class: 'item', style: 'cursor:pointer', onClick: () => { ui.arkMoveDetail = m.id; render(); } },
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

  function arkMoveDetailView(m) {
    const incoming = !['send', 'offboard'].includes(m.type);
    const label = m.type === 'receive' ? t('received') : m.type === 'board' ? t('arkBoarded')
      : m.type === 'offboard' ? t('arkOffboarded') : t('sent');
    const row = (k, v) => h('div', { class: 'row between', style: 'gap:12px' },
      h('span', { class: 'small muted', style: 'flex-shrink:0' }, k), h('span', { class: 'small', style: 'text-align:right;word-break:break-all' }, v));
    const url = m.txid ? wallet.api.explorerTx(m.txid) : null;
    return h(
      'div',
      { class: 'card col', style: 'gap:10px' },
      h('div', { class: 'row gap6', style: 'align-items:center' },
        h('h3', { style: 'margin:0' }, label),
        h('span', { class: 'tag' }, 'Ark'),
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
  
    const spendables = ark.vtxos().filter((v) => v.state === 'spendable');
    const pendingActions = ark.pendingActions();
    const row = (k, v) => h('div', { class: 'row between' }, h('span', { class: 'small muted' }, k), h('span', { class: 'small' }, v));
  
    return h(
      'div',
      { class: 'card col', style: 'gap:10px' },
      ...head,
      spendables.length ? row(t('arkVtxos'), String(spendables.length)) : null,
      pendingActions.length
        ? h('div', { class: 'small muted' }, t('arkPendingActions', { n: pendingActions.length }) + ' — ' + pendingActions.map((a) => `${a.type}:${a.step}`).join(', '))
        : null,
      spendables.length >= 1
        ? h('button', { class: 'btn-ghost btn-block', disabled: !!ui.arkBusy, onClick: doArkRefresh },
            ui.arkBusy === 'refresh' ? h('span', { class: 'spinner sm' }) : t('arkRefreshBtn', { n: spendables.length }))
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
              onInput: (e) => { ui.arkBoardAmt = e.target.value; },
            }),
            h('button', { class: 'btn-sm', disabled: !!ui.arkBusy || !canBoard, onClick: doArkBoard },
              ui.arkBusy === 'board' ? h('span', { class: 'spinner sm' }) : t('arkBoardBtn'))),
          canBoard
            ? h('div', { class: 'small faint', style: 'text-align:center' }, t('arkBoardAvailable', { n: fmtAmount(wallet.spendable) + ' ' + unitLabel() }))
            : h('div', { class: 'small faint', style: 'text-align:center' }, t('arkBoardNoFunds', { n: minBoard.toLocaleString() })),
          // ...and the way back out: offboard the whole ark balance on-chain.
          ark.balance().spendableSat > 0
            ? h('button', { class: 'btn-ghost btn-block', disabled: !!ui.arkBusy, onClick: doArkOffboard },
                ui.arkBusy === 'offboard'
                  ? h('span', { class: 'spinner sm' })
                  : t('arkOffboardBtn', { n: fmtAmount(ark.balance().spendableSat) + ' ' + unitLabel() }))
            : null,
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
      h('button', { class: 'btn-primary btn-block', onClick: () => { ui.arkOffboarded = null; render(); } }, t('done'))
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

  return {
    id: 'ark',
    init() { initArk(); },
    stop() { stopArk(); },
    receiveModes() {
      if (!arkAvailable()) return [];
      return [{ id: 'ark', label: t('receiveArkTab'), render: (seg) => arkReceivePane(seg) }];
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
      if (ui.arkSent || ui.arkSend) return arkSendReview();
      return null;
    },
    historyEntries() {
      if (!ark || !ark.state) return [];
      return ark.movements()
        .filter((m) => ['receive', 'send', 'board', 'offboard'].includes(m.type) && m.status === 'complete')
        .map((m) => ({ time: m.ts, render: () => arkHistoryItem(m) }));
    },
    historyDetail() {
      if (!ui.arkMoveDetail) return null;
      const m = ark && ark.state ? ark.movements().find((x) => x.id === ui.arkMoveDetail) : null;
      if (m) return arkMoveDetailView(m);
      ui.arkMoveDetail = null;
      return null;
    },
    balanceLines() {
      const b = arkBalance();
      if (!b) return [];
      const lines = [];
      if (b.spendableSat + b.pendingSat > 0) lines.push({ label: t('arkBalance'), sat: b.spendableSat + b.pendingSat });
      // A board in flight: the sats already left the on-chain balance, so show
      // where they went instead of having them silently disappear.
      if (b.boardingSat > 0) lines.push({ label: t('arkBoarding'), sat: b.boardingSat });
      return lines;
    },
    decorateTxRow(tx) {
      if (!ark || !ark.state) return null;
      if (tx.net < 0) {
        const a = ark.state.actions.find((x) => x.type === 'board' && x.fundingTxid === tx.txid);
        return a ? { icon: '⚔', label: h('span', {}, t('arkBoardHistory')) } : null;
      }
      const o = ark.state.actions.find((x) => x.type === 'offboard' && x.txid === tx.txid);
      return o ? { icon: '⚔', label: h('span', {}, t('arkOffboardHistory')) } : null;
    },
    txDetailSection(tx) {
      if (!ark || !ark.state) return null;
      const a = ark.state.actions.find((x) => x.type === 'board' && x.fundingTxid === tx.txid);
      if (!a) return null;
      const done = a.step === 'done';
      return h('div', { class: 'summary col', style: 'gap:0' },
        h('div', { style: 'font-weight:600;margin:12px 0 2px' }, '⚔ ' + t('arkBoardHistory')),
        h('div', { class: 'line' },
          h('span', { class: 'k' }, t('arkBalance')),
          h('span', { class: 'v' }, '+' + fmtAmount(a.amountSat - a.feeSat) + ' ' + unitLabel())),
        done ? null : h('div', { class: 'small muted', style: 'margin-top:2px' }, t('arkBoardedNote')));
    },
    settingsCards() { return [arkCard()]; },
  };
}

// Gifts feature — presigned bearer gift links (create, share, revoke,
// reclaim) and the claim flow (fresh or existing wallet, nostr-locked gifts,
// claim codes / NIP-07 extension). Gift primitives live in ../wallet.js.

import { newMnemonic } from '../wallet.js';
import { getNetwork } from '../api.js';
import { installGiftWallet, previewGift, giftOutpoints, buildClaimTx, giftMinimum } from './gifts-wallet.js';
import { t } from '../i18n.js';
import { qrSvg } from '../qr.js';
import { fmtBtc, timeAgo, shortAddr } from '../format.js';

export function giftsFeature(ctx) {
  const {
    h, ui, render, wallet, toast, copyBtn, pasteBtn, blankSend, goBack, goHome, openExternal,
    fmtAmount, unitLabel, unitTag, parseAmount, getUnit, toggleUnit, download,
    brandHeader, activeAccount, setAccounts, getAccounts, claimTargets,
    enterWallet, activateAccount, commitAccount,
  } = ctx;
  installGiftWallet(wallet); // gift primitives live outside the core wallet
  // Ark-gift support comes from the ark feature (when this build ships it);
  // every call degrades to null in an on-chain-only build.
  const hook = ctx.hook || (() => null);
  const arkGiftOf = (code) => hook('arkGiftDecode', code);

  // ================================================================ GIFT / CLAIM
  // Read a gift link, returning the code (and scrubbing it from the URL so the
  // bearer instrument doesn't linger in the address bar / history). New links are
  // /g/<base32-compact>; legacy links are #gift=<base64url-psbt>. Both validate by
  // decoding to a real gift.
  function readGiftHash() {
    try {
      const am = location.pathname.match(/^\/ag\/([A-Za-z0-9]+)\/?$/i); // ark gift
      if (am) {
        history.replaceState(null, '', '/');
        return arkGiftOf(am[1]) ? am[1] : null;
      }
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

  // Entry point for claiming a gift code. If the recipient already has wallet(s),
  // offer to claim into one or make a new one; otherwise go straight to a fresh
  // wallet (the original first-timer flow).
  function claimGift(code) {
    ui.claimArkAmount = null;
    ui.claimAuto = false;
    // An ark gift can only land in a wallet on ITS network — other wallets
    // aren't valid claim targets. (On-chain gift codes don't carry a network.)
    const all = claimTargets();
    const ag = arkGiftOf(code);
    const usable = all.filter((a) => !ag || (a.network || getNetwork()) === ag.net);
    if (all.length) setAccounts(all); // keep the full wallet list in the session
    if (usable.length) { ui.claimChoose = { code }; render(); return; }
    // No usable wallet on this device: adopt the gift's network so a
    // first-timer (or a wrong-network device) never has to visit Settings.
    // Per-wallet networks make this safe — other wallets keep their own.
    hook('arkGiftAdoptNetwork', code);
    enterWallet(newMnemonic(), '', { gift: code, generated: true });
  }

  // Claim a gift into an existing wallet (no new seed). activateAccount loads it and
  // opens the claim screen; existingClaim keeps it committed and, in doClaim, skips
  // the seed-backup step.
  function claimIntoAccount(acc, code) {
    ui.claimChoose = null;
    ui.claimAuto = true; // one-step: claim as soon as the gift verifies unspent
    activateAccount(acc, { gift: code, existingClaim: true, fresh: true });
  }

  // The claim fee for a gift, and a display note ('' when free / ark).
  function claimFeeNote(code) {
    if (arkGiftOf(code)) return t('claimArkFree');
    const pv = previewGift(code);
    if (!pv) return '';
    const rate = Math.max(1, Math.round((wallet.feeRates && wallet.feeRates.halfHourFee) || 5));
    const fee = Math.ceil((11 + 68 * pv.inputs + 31 * 2) * rate);
    return t('claimFeeNote', { n: fmtAmount(fee) + ' ' + unitLabel() });
  }

  // Pick where to receive a gift: an existing wallet, or a brand-new one.
  function claimChooseView() {
    const code = ui.claimChoose.code;
    const ag = arkGiftOf(code);
    const pv = ag ? { room: ag.amountSat } : previewGift(code);
    return h(
      'div',
      { class: 'col', style: 'gap:16px' },
      brandHeader(false),
      h('div', { class: 'card col', style: 'align-items:center;text-align:center;gap:12px' },
        h('div', { class: 'check-badge', style: 'background:var(--accent)' }, '🎁'),
        h('h2', { style: 'margin:0' }, t('giftWelcome')),
        pv ? h('div', { class: 'amt', style: 'font-size:30px' }, h('span', { class: 'amount-pos' }, fmtAmount(pv.room)), ' ', unitTag('unit')) : null,
        h('div', { class: 'small faint' }, claimFeeNote(code)),
        h('p', { class: 'muted', style: 'margin:0' }, t('claimIntoPrompt'))
      ),
      h('div', { class: 'card col gap6' },
        h('div', { class: 'small muted' }, t('claimIntoExisting')),
        ...getAccounts().filter((a) => !ag || (a.network || getNetwork()) === ag.net).map((a) =>
          h('button', { class: 'btn-block', style: 'display:flex;justify-content:space-between;align-items:center;text-align:left', onClick: () => claimIntoAccount(a, code) },
            h('span', {},
              a.label,
              a.type === 'watch' ? h('span', { class: 'small faint', style: 'margin-left:6px' }, '(' + t('watchOnly') + ')') : null),
            h('span', { class: 'muted', style: 'font-size:18px;line-height:1' }, '\u203a'))
        ),
        h('div', { class: 'small faint', style: 'text-align:center' }, t('claimOr')),
        h('button', { class: 'btn-primary btn-block', onClick: () => { ui.claimChoose = null; hook('arkGiftAdoptNetwork', code); enterWallet(newMnemonic(), '', { gift: code, generated: true }); } }, t('claimNewWallet'))
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
    const ag = arkGiftOf(ui.claimCode);
    const pv = ag ? { room: ui.claimArkAmount ?? ag.amountSat, inputs: 1 } : previewGift(ui.claimCode);
    // The headline is the full amount received (inputs minus the sender's change).
    // The network fee is determined now, at claim time, and comes out of that
    // amount — we surface the estimate on the Claim button so it isn't a
    // surprise. An ark gift sweeps off-chain: no fee at all.
    const rate = Math.max(1, Math.round((wallet.feeRates && wallet.feeRates.halfHourFee) || 5));
    const estFee = ag ? 0 : pv ? Math.ceil((11 + 68 * pv.inputs + 31 * 2) * rate) : 0;
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
        h('p', { class: 'muted', style: 'margin:0' },
          (() => { const acc = activeAccount(); // claiming into an existing wallet vs a brand-new one
            return acc && !acc.provisional ? t('claimBodyExisting', { name: acc.label }) : t('claimBody'); })())
      ),
      ui.claimError && h('div', { class: 'notice err' }, ui.claimError),
      !ui.claimError && ui.claimNotVisible && h('div', { class: 'notice info' }, t('claimNotVisibleBody')),
      ui.busy || ui.claimChecking
        ? h('button', { class: 'btn-primary btn-block', disabled: true }, h('span', { class: 'spinner' }))
        : h('button', { class: 'btn-primary btn-block', onClick: doClaim },
            t('claimBtn'), ' ',
            h('span', { style: 'font-size:0.85em;opacity:0.9' },
              '(' + (ag ? t('claimArkFree') : t('claimFeeNote', { n: fmtAmount(estFee) + ' ' + unitLabel() })) + ')'))
    );
  }

  // Has this gift already been claimed? Its funding coin being spent — even by an
  // unconfirmed claim — means the gift is gone; show the "already claimed" screen
  // rather than let the user attempt a doomed double-spend.
  // End of the pre-claim check: if this is a one-step claim into a chosen
  // wallet, fire the claim now (unless the gift is taken / not visible /
  // errored); otherwise just render the welcome + Claim button.
  function finishGiftCheck() {
    ui.claimChecking = false;
    if (ui.claimAuto && !ui.claimTaken && !ui.claimError && !ui.claimNotVisible) doClaim();
    else render();
  }

  async function checkGiftClaimed(code) {
    if (arkGiftOf(code)) {
      try {
        const st = await hook('arkGiftStatus', code);
        if (st.state === 'taken') ui.claimTaken = {};
        else if (st.state === 'wrongnet') ui.claimError = t('arkGiftWrongNet', { net: st.net });
        else if (st.state === 'unknown') ui.claimNotVisible = true;
        else ui.claimArkAmount = st.amountSat; // live amount (matches the code's)
      } catch {
        // transient — leave claimable; the sweep itself is the final guard
      }
      finishGiftCheck();
      return;
    }
    const ops = giftOutpoints(code);
    if (!ops.length) { finishGiftCheck(); return; }
    try {
      const res = await wallet.api.outspend(ops[0].txid, ops[0].vout);
      if (res && res.spent) ui.claimTaken = { txid: res.txid || null };
      // Unknown txids don't 404 on the status/outspend endpoints, so verify the
      // funding tx is actually visible — if not, the claimer is likely on a
      // different network/data source than the sender (or it hasn't propagated).
      if (!ui.claimTaken) {
        const tx = await wallet.api.getTx(ops[0].txid).catch(() => null);
        ui.claimNotVisible = !tx;
      }
    } catch {
      // Couldn't check (offline/transient) — leave it claimable; the broadcast in
      // doClaim is the final guard (a double-spend is rejected by the network).
    }
    finishGiftCheck();
  }

  // Broadcast the presigned gift to this fresh wallet's first receive address.
  // Shared post-claim navigation: fresh wallets go to seed backup, existing
  // ones straight in with the instant celebration.
  function afterClaim(amount) {
    ui.claimedAmount = amount;
    const wasProvisional = !!(activeAccount() && activeAccount().provisional);
    commitAccount(); // claimed — keep a fresh gift wallet (no-op for an existing one)
    if (wasProvisional) {
      ui.claimStep = 'backup'; // fresh wallet — show the new seed to back up
    } else {
      ui.screen = 'wallet'; // existing wallet — straight into it, no new seed to back up
      ui.claimStep = null;
      ui.tab = 'receive';
      ui.giftJustClaimed = amount; // celebration shows instantly, no scan wait
    }
    return wasProvisional;
  }

  async function doClaim() {
    ui.claimAuto = false; // one-shot; a manual retry shouldn't re-auto-fire
    if (wallet.offline) { ui.claimError = t('scanOffline'); render(); return; }
    if (ui.claimChecking || ui.claimTaken) return; // not verified / already taken
    ui.busy = true;
    ui.claimError = '';
    render();
    if (arkGiftOf(ui.claimCode)) {
      // Ark gift: sweep the bearer vtxo into this wallet's ark balance —
      // off-chain, instant, no fee, works for a brand-new empty wallet.
      try {
        const amount = await hook('arkGiftClaim', ui.claimCode);
        afterClaim(amount);
      } catch (e) {
        if (e && e.giftTaken) ui.claimTaken = {};
        else ui.claimError = e.message || t('claimFailed');
      }
      ui.busy = false;
      render();
      return;
    }
    try {
      const rate = (wallet.feeRates && wallet.feeRates.halfHourFee) || 5;
      const to = wallet.receive[0] ? wallet.receive[0].address : wallet.derive(0, 0).address;
      const claim = buildClaimTx(ui.claimCode, to, rate, wallet.netCfg.net);
      await wallet.broadcast(claim.hex);
      afterClaim(claim.amount);
      wallet.scan().then(() => {
        // The claim credit advances the fresh receive index in the background;
        // ack it so the index-based celebration doesn't fire a second time
        // behind the instant one we're already showing.
        if (ui.giftJustClaimed != null) {
          ui.receiveSeenIndex = wallet.nextReceiveIndex;
          wallet.setReceiveAck(wallet.nextReceiveIndex);
          render();
        }
      }).catch(() => {});
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
      if (!ui.claimTaken) {
        ui.claimError = /missing.?inputs|missingorspent|bad-txns-inputs/i.test(String(e && e.message))
          ? t('claimNotVisibleBody') // funding tx unknown here: wrong chain/source
          : t('claimFailed');
      }
    }
    ui.busy = false;
    render();
  }

  // Re-view a previously created gift's link + QR (from its stored record), so
  // the sender can re-share an unclaimed gift.
  function viewGiftView() {
    const g = ui.viewGift; // { code, locked, amount, claimCode }
    const url = `${location.origin}/g/${g.code}`;
    let svg = null;
    try { svg = qrSvg(url.toUpperCase(), { ec: 'L', mode: 'Alphanumeric' }); } catch {}
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

  // An ark gift: send the amount to a fresh bearer identity, off-chain and
  // instant — no coin locking, no split logic, no claim fee.
  // Gifts go down to 1 sat: the ASP cosigns all-dust arkoor sends, so a
  // sub-dust bearer vtxo sweeps to the claimer fine (regtest-proven —
  // tools/ark/dust-gift-test.js). The trade a sub-330 coin carries — no
  // unilateral exit on its own, renewable in rounds only alongside bigger
  // siblings — is the same one dust zaps already make.
  async function doCreateArkGift() {
    const info = hook('arkGiftInfo');
    const avail = info ? info.spendableSat : 0;
    const amt = ui.giftMax ? avail : parseAmount(ui.giftAmount, getUnit());
    if (!amt || amt < 1) { ui.giftError = t('giftAmountInvalid', { n: fmtAmount(1) + ' ' + unitLabel() }); render(); return; }
    if (amt > avail) { ui.giftError = t('giftExceedsBalance'); render(); return; }
    ui.busy = true; ui.giftError = ''; render();
    try {
      const g = await hook('arkGiftCreate', amt);
      ui.giftIsArk = true;
      finishGift(g, amt);
    } catch (e) {
      ui.giftError = e.message;
    }
    ui.busy = false; render();
  }

  function createGiftLink() {
    if (ui.giftSource === 'ark') { doCreateArkGift(); return; }
    const rate = giftRate();
    if (ui.giftMax) { doCreateGiftAll(rate); return; }
    const min = giftMinimum(rate);
    const amt = parseAmount(ui.giftAmount, getUnit()); // entered in the current display unit
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

  // Finalize a freshly-built gift: a plain bearer link.
  function finishGift(g, fallbackAmt) {
    const amount = g.amount || fallbackAmt || 0;
    ui.giftCode = g.code;
    wallet.recordGift({ code: g.code, locked: false, amount, outpoints: g.reserved });
  }

  function giftCard() {
    const active = wallet.outstandingGifts();
    return h(
      'div',
      { class: 'card col' },
      h('h3', {}, t('giftLink')),
      ui.giftCode
        ? h('div', { class: 'col', style: 'align-items:center;gap:10px' },
            // base32 code is case-insensitive). A locked gift's payload is
            // case-sensitive base64url, so it uses a plain byte-mode QR. A large
            // (many-input) gift can exceed QR capacity — then fall back to the link.
            (() => {
              let svg = null;
              try { svg = qrSvg(giftUrl().toUpperCase(), { ec: 'L', mode: 'Alphanumeric' }); } catch {}
              return svg ? h('div', { html: svg }) : h('div', { class: 'small faint', style: 'text-align:center;padding:8px' }, t('giftQrTooLong'));
            })(),
            h('div', { class: 'addr-box break', style: 'width:100%;font-size:12px' }, giftUrl()),
            h('div', { class: 'row gap6 wrap' },
              copyBtn(giftUrl(), t('copyLink')),
              h('button', { class: 'btn-sm grow', onClick: () => { ui.giftCode = null; ui.giftAmount = ''; ui.giftMax = false; ui.giftIsArk = false; render(); } }, t('giftAnother'))
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
            // The gift's source follows the global account selection: in
            // Spending the gift is an instant ark bearer vtxo, in Savings a
            // presigned on-chain link (coins locked until claim).
            (() => {
              const info = hook('arkGiftInfo');
              ui.giftSource = ctx.getAccount() === 'spending' && info ? 'ark' : 'chain';
              return null;
            })(),
            (() => {
              const isArk = ui.giftSource === 'ark';
              const maxVal = isArk ? (hook('arkGiftInfo')?.spendableSat || 0) : wallet.spendable;
              return h('div', { class: 'input-group' },
                h('input', { type: 'number', step: getUnit() === 'sats' ? '1' : '0.00000001', min: '0', inputmode: 'decimal', placeholder: t('giftAmountLabel'),
                  disabled: ui.giftMax,
                  value: ui.giftMax ? (getUnit() === 'sats' ? String(maxVal) : fmtBtc(maxVal)) : ui.giftAmount,
                  onInput: (e) => (ui.giftAmount = e.target.value) }),
                h('button', { type: 'button', class: ui.giftMax ? 'btn-primary' : '', onClick: () => { ui.giftMax = !ui.giftMax; ui.giftError = ''; render(); } }, t('max')),
                h('div', { style: 'display:flex;align-items:center' }, unitTag())
              );
            })(),
            h('div', { class: 'small faint' },
              ui.giftSource === 'ark' ? t('giftArkNote')
                : ui.giftMax ? t('giftAllNote')
                : t('giftMinNote', { n: fmtAmount(giftMinimum(giftRate())) + ' ' + unitLabel() })),
            ui.giftError && h('div', { class: 'notice err' }, ui.giftError),
            ui.busy
              ? h('button', { class: 'btn-block', disabled: true }, h('span', { class: 'spinner sm' }))
              : h('button', { class: 'btn-block', onClick: createGiftLink }, t('giftLinkReveal'))
          ),
      // Outstanding ark gifts (bearer vtxos we can still revoke by sweeping back)
      (() => {
        const arkGifts = hook('arkGiftOutstanding') || [];
        if (!arkGifts.length) return null;
        return h('div', { class: 'col gap6', style: 'margin-top:4px' },
          h('span', { class: 'small muted' }, t('giftArkOutstanding', { n: arkGifts.length })),
          ...arkGifts.map((g) => h('div', { class: 'row between' },
            h('span', { class: 'small mono' }, fmtAmount(g.amountSat) + ' ' + unitLabel() + ' ', h('span', { class: 'tag' }, 'Ark')),
            ui.busy && ui.revokeId === g.id
              ? h('span', { class: 'spinner sm' })
              : h('button', { class: 'btn-sm', onClick: async () => {
                  ui.revokeId = g.id; ui.busy = true; render();
                  try { await hook('arkGiftRevoke', g.id); toast(t('giftArkRevoked')); }
                  catch (e) { toast(e.message); }
                  ui.busy = false; ui.revokeId = null; render();
                } }, t('giftRevoke'))
          )));
      })(),
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

  // ---------------------------------------------------------------- History
  // An outstanding sent gift shown in History: tappable to cancel (reclaim the
  // coin for a future payment, or revoke the link on-chain) without going through
  // the Send → gift card. Reuses the same confirm state and handlers.
  function giftHistoryItem(g) {
    const amt = g.value != null ? g.value : g.amount;
    const created = (wallet.loaded && (wallet.giftRecords()[g.id] || {}).created) || g.created;
    return h('div', { class: 'item', style: 'cursor:pointer', onClick: () => { ui.giftDetail = g.id; render(); } },
      h('div', { class: 'ico out' }, '🎁'),
      h('div', { class: 'grow' },
        h('div', { class: 'row gap6' }, t('giftHistoryTitle'),
          h('span', { class: 'tag ' + (g.claimed ? 'conf' : 'pending') }, g.claimed ? t('giftClaimedTag') : g.reserved ? t('giftUnclaimedTag') : t('giftReclaimedTag'))),
        h('div', { class: 'small faint' }, created ? timeAgo(created / 1000) : (!g.claimed && g.reserved ? t('lockedInGifts') : ''))
      ),
      h('div', { style: 'text-align:right' },
        amt != null ? h('div', { class: 'amount' }, fmtAmount(amt)) : null)
    );
  }

  // Gift detail page: status + the link itself (unclaimed), cancel/reclaim.
  function giftDetailView(g) {
    const amt = g.value != null ? g.value : g.amount;
    const created = (wallet.loaded && (wallet.giftRecords()[g.id] || {}).created) || g.created;
    const rec = g.claimed ? null : wallet.giftLink(g.id);
    const line = (k, v) => h('div', { class: 'line' }, h('span', { class: 'k' }, k), h('span', { class: 'v' }, v));
    const back = () => { ui.giftDetail = null; ui.revokeId = null; render(); };
    return h(
      'div',
      { class: 'card col' },
      h('div', { class: 'row between' },
        h('h3', {}, '🎁 ' + t('giftHistoryTitle')),
        h('span', { class: 'tag ' + (g.claimed ? 'conf' : 'pending') }, g.claimed ? t('giftClaimedTag') : g.reserved ? t('giftUnclaimedTag') : t('giftReclaimedTag'))),
      amt != null
        ? h('div', { class: 'amt', style: 'font-size:30px' }, h('span', { class: 'amount' }, fmtAmount(amt)), ' ', unitTag('unit'))
        : null,
      // only render the summary box when it has content (an empty gray box
      // otherwise appears for reclaimed gifts with no recorded date)
      created || (!g.claimed && g.reserved)
        ? h('div', { class: 'summary col', style: 'gap:0' },
            created ? line(t('dateLabel'), new Date(created).toLocaleString()) : null,
            !g.claimed && g.reserved ? line(t('status'), t('lockedInGifts')) : null)
        : null,
      // Reclaim/Revoke up front — no confirm step. A reserved gift offers both;
      // an already-reclaimed one only Revoke (its coin is spendable again, only
      // the live link is left to kill).
      g.claimed
        ? null
        : h('div', { class: 'col', style: 'gap:8px' },
            h('span', { class: 'small muted' }, g.reserved ? t('giftReclaimPrompt') : t('giftRevokeConfirm')),
            ui.busy
              ? h('button', { class: 'btn-primary btn-block', disabled: true }, h('span', { class: 'spinner' }))
              // View + Reclaim share a row; Revoke gets its own full-width line
              // so "Revoke now" never squishes/wraps against the others.
              : h('div', { class: 'col', style: 'gap:8px' },
                  (rec || g.reserved)
                    ? h('div', { class: 'row gap6' },
                        rec ? h('button', { class: 'grow', onClick: () => { ui.viewGift = rec; render(); } }, t('giftView')) : null,
                        g.reserved ? h('button', { class: 'btn-ghost grow', onClick: () => doReclaim(g.id) }, t('giftReclaim')) : null)
                    : null,
                  h('button', { class: 'btn-primary btn-block', onClick: () => doRevoke(g.id) }, t('giftRevoke')))),
      h('button', { class: 'btn-ghost btn-block', onClick: back }, t('back'))
    );
  }

  // Gift link: presign a chosen amount as a #gift= PSBT that whoever opens claims
  // into a fresh wallet only they control. The coin is reserved until claimed.
  function giftUrl() {
    return `${location.origin}/${ui.giftIsArk ? 'ag' : 'g'}/${ui.giftCode}`;
  }

  function giftRate() {
    return (wallet.feeRates && wallet.feeRates.halfHourFee) || 5;
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

  function claimCelebration() {
    // A gift was just claimed into this wallet — celebrate immediately (the
    // background scan credits the coin and advances the address meanwhile).
    if (ui.giftJustClaimed != null) {
      const amt = ui.giftJustClaimed;
      return h(
        'div',
        {
          class: 'card col',
          style: 'align-items:center;text-align:center;gap:14px;cursor:pointer;padding:48px 20px',
          onClick: () => {
            ui.giftJustClaimed = null;
            ui.receiveSeenIndex = wallet.nextReceiveIndex;
            wallet.setReceiveAck(wallet.nextReceiveIndex);
            render();
          },
        },
        h('div', { class: 'check-badge' }, '✓'),
        h('h2', { style: 'margin:0' }, t('paymentReceived')),
        amt ? h('div', { class: 'amount-pos', style: 'font-size:18px' }, '+' + fmtAmount(amt) + ' ' + unitLabel()) : null,
        h('div', { class: 'small muted' }, t('tapToProceed'))
      );
    }
    return null;
  }

  return {
    id: 'gifts',
    // opened with ?gift / /g/ / /lg/ in the URL — start the claim flow
    bootUrl() {
      const code = readGiftHash();
      if (code) { claimGift(code); return true; } // bearer gift → claim into an existing wallet or a new one
      return false;
    },
    giftOpened(code) { checkGiftClaimed(code); },
    screenView() {
      if (ui.viewGift) return viewGiftView();
      if (ui.claimChoose) return claimChooseView();
      if (ui.screen === 'claim') return claimScreen();
      return null;
    },
    receiveTakeover() { return claimCelebration(); },
    sendView() { return ui.giftMode ? giftView() : null; },
    sendFormExtras() {
      return h('button', { class: 'linklike small', style: 'align-self:center;margin-top:2px', onClick: () => { ui.giftMode = true; ui.sendError = ''; render(); } }, '🎁 ' + t('giftLink'));
    },
    balanceLines() {
      const locked = wallet.giftLockedValue();
      return locked > 0 ? [{ label: t('lockedInGifts'), sat: locked }] : [];
    },
    historyEntries(txs) {
    // Outstanding sent gifts (reserved/reclaimed but unclaimed) sit above the
    // on-chain history; they aren't transactions until claimed or revoked.
    // A claimed gift merges into its claim transaction's row once we know which
    // tx spent it (resolved lazily below) — no duplicate gift + Sent entries.
    const txids = new Set(txs.map((x) => x.txid));
    const claimed = wallet.loaded ? wallet.claimedGifts() : [];
    for (const c of claimed) {
      if (c.claimTxid || !c.outpoints || !c.outpoints.length) continue;
      if (!ui._giftClaimResolving) ui._giftClaimResolving = new Set();
      if (ui._giftClaimResolving.has(c.id) || wallet.offline) continue;
      ui._giftClaimResolving.add(c.id);
      const [txid, vout] = c.outpoints[0].split(':');
      wallet.api.outspend(txid, Number(vout)).then((res) => {
        if (res && res.spent && res.txid) { wallet.setGiftClaimTx(c.id, res.txid); render(); }
      }).catch(() => {}).finally(() => ui._giftClaimResolving.delete(c.id));
    }
    const gifts = wallet.loaded
      ? [...wallet.outstandingGifts(), ...claimed.filter((c) => !(c.claimTxid && txids.has(c.claimTxid))).map((c) => ({ ...c, claimed: true }))]
      : [];
      const recs2 = wallet.loaded ? wallet.giftRecords() : {};
      const giftTime = (g) => (recs2[g.id] && recs2[g.id].created) || g.created || Date.now();
      return gifts.map((g) => ({ time: giftTime(g), render: () => giftHistoryItem(g) }));
    },
    historyDetail() {
    if (ui.giftDetail) {
      const g = wallet.loaded
        ? [...wallet.outstandingGifts(), ...wallet.claimedGifts().map((c) => ({ ...c, claimed: true }))]
            .find((x) => x.id === ui.giftDetail)
        : null;
      if (g) return giftDetailView(g);
      ui.giftDetail = null;
    }
      return null;
    },
    decorateTxRow(tx) {
      if (tx.net >= 0 || !wallet.loaded) return null;
      const gift = wallet.claimedGifts().find((c) => c.claimTxid === tx.txid);
      if (!gift) return null;
      return {
        icon: '🎁',
        label: h('span', {}, t('giftHistoryTitle'), ' ', h('span', { class: 'tag conf' }, t('giftClaimedTag'))),
      };
    },
    txDetailSection(tx) {
      const gift = wallet.loaded ? wallet.claimedGifts().find((c) => c.claimTxid === tx.txid) : null;
      if (!gift) return null;
      return h('div', { class: 'summary col', style: 'gap:0' },
        h('div', { style: 'font-weight:600;margin:12px 0 2px' }, '🎁 ' + t('giftClaimedContext')),
        gift.amount != null ? h('div', { class: 'line' }, h('span', { class: 'k' }, t('giftAmountLabel')), h('span', { class: 'v' }, fmtAmount(gift.amount) + ' ' + unitLabel())) : null);
    },
  };
}

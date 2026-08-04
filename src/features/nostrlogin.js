// "Log in with Nostr" — open (or create) a wallet from a nostr identity, and
// link an existing wallet to one after the fact.
//
// The mechanics and their tradeoffs live in ../nostr-login.js. In short: a
// pasted key DERIVES its wallet deterministically; an extension or remote
// signer ASSOCIATES one via a seed published encrypted to the user's own key.
// The second is what makes "log in on a new device" work without the key
// ever reaching us, and it is spelled out in the UI before anything is
// published, because it means the nostr key can recover the money.

import { newMnemonic } from '../wallet.js';
import { npubOf } from '../nostr.js';
import { t } from '../i18n.js';
import { qrSvg } from '../qr.js';
import { hex } from '@scure/base';
import {
  extensionSigner, bunkerSigner, keySigner, parseNostrSecret,
  walletForSigner, publishWalletBackup, nostrConnect, resumeBunker } from '../nostr-login.js';

// The nostr ostrich, in the brand's monochrome.
const OSTRICH = '<svg width="23" height="23" style="display:block" viewBox="0 0 2000 2000" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="ng" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#B84FE8"/><stop offset="100%" stop-color="#6D28D9"/></linearGradient></defs><circle cx="1000" cy="1000" r="1000" fill="url(#ng)"/><g transform="translate(1000 1000) scale(0.82) translate(-1000 -1000)"><path d="M1574.29 770.408C1532.04 840.612 1445.92 888.367 1437.96 892.449C1421.84 901.02 1415.92 913.469 1416.94 932.041C1417.96 950.612 1413.47 1042.65 1357.35 1083.27C1328.57 1104.08 1212.45 1131.02 1159.18 1140C1131.84 1144.69 1125.51 1153.06 1110.41 1162.04C1090 1174.69 1017.55 1275.1 1005.31 1297.35C1006.94 1297.14 1233.67 1226.73 1243.88 1225.1C1270.82 1221.02 1291.22 1228.78 1304.49 1248.37C1317.14 1267.14 1329.59 1286.12 1342.04 1305.1C1346.53 1311.84 1350.82 1318.78 1355.1 1325.71L1359.59 1332.86C1361.22 1335.51 1363.47 1338.57 1364.49 1342.65C1365.31 1345.51 1367.14 1355.1 1361.63 1360.82C1356.53 1366.12 1347.76 1366.12 1343.06 1364.9C1338.57 1363.67 1331.84 1361.02 1326.33 1356.53L1318.78 1350.2C1312.86 1345.1 1301.63 1342.65 1292.86 1343.06C1282.65 1343.47 1269.18 1340.2 1262.65 1336.12C1250 1327.96 1246.73 1307.55 1246.73 1307.35C1245.1 1300.61 1240.2 1298.78 1235.71 1298.78C1227.55 1298.57 1221.22 1301.02 1214.69 1302.86C1184.9 1311.84 1155.31 1321.02 1125.51 1330.41L1082.86 1343.67C1061.84 1350.2 1040.82 1356.73 1020 1363.67C1014.29 1365.51 1008.78 1368.37 1002.86 1371.43C1000.41 1372.65 997.959 1373.88 995.51 1375.1C993.061 1376.33 990.408 1377.76 987.959 1379.18C982.449 1382.24 976.531 1385.51 970 1387.35C948.776 1393.67 930.204 1384.49 921.429 1363.27C915.714 1349.59 920.816 1322.45 923.878 1314.49C943.061 1264.69 1005.51 1170.82 1005.51 1170.2C1004.49 1169.8 936.327 1197.14 925.102 1205.71C894.286 1229.18 822.041 1284.69 821.02 1290C816.327 1314.69 801.02 1333.27 777.551 1342.45C760.612 1348.98 750.408 1362.45 740.408 1375.51C740.408 1375.51 559.388 1624.9 547.143 1638.37C543.469 1642.45 509.592 1677.96 500.612 1694.49C498.571 1698.57 490.816 1714.9 488.776 1718.98C487.143 1722.24 483.469 1731.02 469.592 1730.41C455.714 1729.8 455.306 1710.41 454.694 1702.04C453.265 1681.43 457.755 1661.22 468.571 1640C469.592 1637.96 481.837 1619.39 477.347 1604.49C473.265 1591.43 469.388 1571.22 475.51 1561.02C485.102 1544.9 502.041 1544.29 524.694 1540.61C540.408 1537.96 551.837 1530.2 562.857 1514.08C586.122 1480.2 673.674 1355.92 693.469 1327.14C698.776 1319.59 702.857 1309.8 704.694 1300.2C710.408 1271.22 727.959 1251.02 758.571 1238.57C765.102 1235.92 886.939 1134.08 886.939 1121.02C886.939 1111.63 873.674 1106.53 863.469 1103.67C862.041 1103.27 785.51 1083.47 750.612 1067.55C731.633 1058.98 717.347 1051.43 700.408 1039.18C677.347 1022.24 631.225 1030.41 624.49 1031.43C591.837 1036.12 567.551 1050.82 540 1069.39C535.102 1072.86 510 1081.84 497.347 1074.69C472.653 1060.61 418.367 1035.31 398.367 1004.9C389.184 990.816 390.408 967.959 396.939 942.653C417.959 883.878 448.98 857.551 506.327 841.633C547.143 827.551 629.388 824.49 668.98 821.429C671.633 820.612 759.388 818.571 821.02 786.939C862.041 765.918 983.878 684.898 1159.18 690.408C1230 692.653 1363.88 761.837 1415.51 763.878C1468.16 766.122 1494.49 760.204 1524.9 728.776C1533.47 719.796 1570 641.02 1535.51 597.959C1522.65 582.041 1509.39 567.755 1494.08 554.694C1473.47 537.143 1452.04 520.408 1433.47 500.612C1392.45 457.143 1379.8 397.755 1399.18 351.429C1411.63 318.98 1437.76 304.898 1475.51 312.245C1502.04 317.347 1521.43 341.225 1540.41 353.878C1551.02 361.02 1568.78 365.102 1580.41 367.959C1595.1 371.429 1606.12 382.653 1605.51 390.204C1604.9 397.755 1585.51 404.286 1566.94 402.857C1544.9 401.429 1507.14 401.225 1484.49 408.776C1469.39 414.286 1462.65 431.02 1467.14 447.551C1470.82 461.02 1499.59 485.102 1510.41 494.082C1532.04 511.837 1555.1 527.959 1573.06 550.204C1593.27 575.51 1603.88 604.286 1607.14 636.122C1612.04 684.898 1599.18 728.776 1574.29 770.408Z" fill="#fff"/></g></svg>';


export const NOSTR_MARK = OSTRICH;

export function nostrLoginFeature(ctx) {
  const { h, ui, render, wallet, toast, copyBtn } = ctx;

  const load = () => wallet.loadFeatureState('nostrlogin', {});
  const save = (st) => wallet.saveFeatureState('nostrlogin', st);

  // The signer that opened this session, kept so the names feature can claim
  // the user's real npub as their payment address (and nominate the wallet
  // key as manager, so later updates work without the signer).
  let live = null;
  let resuming = null;
  let resumeFailedAt = 0;

  // A remote signer's connection can die quietly — the app is left holding a
  // signer object that will never answer again, and every send after that
  // fails until the page is reloaded. Notice the first failure and drop it, so
  // the next attempt resumes a fresh connection instead.
  const selfHealing = (signer) => {
    if (!signer || signer.kind !== 'bunker') return signer;
    const guard = (fn) => async (...args) => {
      try { return await fn(...args); } catch (e) { if (live === wrapped) live = null; throw e; }
    };
    const wrapped = {
      ...signer,
      signEvent: guard(signer.signEvent.bind(signer)),
      encryptSelf: guard(signer.encryptSelf.bind(signer)),
      decryptSelf: guard(signer.decryptSelf.bind(signer)),
      encryptTo: guard(signer.encryptTo.bind(signer)),
      decryptFrom: guard(signer.decryptFrom.bind(signer)),
    };
    return wrapped;
  };

  // What it takes to be this identity again after a reload. Without it the app
  // shows your face in the header but signs everything else with the wallet's
  // own key — a different pubkey, which is exactly the mismatch people notice
  // when their chat messages come out under a stranger's name.
  //
  // A remote signer stores its NIP-46 client key, which the signer authorised
  // for this app and which cannot sign anything on its own. A pasted key
  // stores the key itself: it is already the seed of everything here (the
  // wallet's mnemonic derives from it), so this is the same secret the app is
  // holding either way, not a new one.
  const sessionOf = (signer) => {
    if (!signer) return {};
    if (signer.session) return { session: signer.session, secret: null };
    if (signer.secret instanceof Uint8Array) return { session: null, secret: hex.encode(signer.secret) };
    return { session: null, secret: null };
  };

  const busy = (v) => { ui.nostrLoginBusy = v; render(); };
  const fail = (e) => { ui.nostrLoginError = e.message || String(e); busy(false); };

  // Open the wallet a signer identifies. New accounts confirm first, because
  // publishing an encrypted seed to relays deserves an explicit yes.
  async function loginWith(makeSigner) {
    ui.nostrLoginError = '';
    busy(true);
    let signer;
    try {
      signer = await makeSigner();
      const res = await walletForSigner(signer);
      if (res.mode === 'new') {
        // no wallet on this identity yet — ask before publishing one
        ui.nostrLoginNew = { signer, npub: npubOf(signer.pubkey) };
        busy(false);
        return;
      }
      // Same wallet however you log in: a key-derived seed is published too,
      // so an extension login later finds this wallet instead of making a new
      // one. Costs nothing — anyone with the key could derive it anyway.
      if (res.publish) await publishWalletBackup(signer, { mnemonic: res.mnemonic }).catch(() => {});
      live = selfHealing(signer);
      await ctx.openMnemonic(res.mnemonic, res.passphrase || '', { nostrPubkey: signer.pubkey });
      save({ ...load(), pubkey: signer.pubkey, linked: Date.now(), ...sessionOf(signer) });
      // claim the real npub as the payment address while this signer is live
      ctx.hook('namesAdoptIdentity', signer, npubOf(signer.pubkey))?.catch?.(() => {});
      toast(res.mode === 'derived' ? t('nlOpenedDerived') : t('nlOpenedRestored'));
      busy(false);
    } catch (e) { fail(e); }
  }

  async function createForSigner() {
    const st = ui.nostrLoginNew;
    if (!st) return;
    busy(true);
    try {
      const mnemonic = newMnemonic();
      await publishWalletBackup(st.signer, { mnemonic });
      ui.nostrLoginNew = null;
      live = selfHealing(st.signer);
      await ctx.openMnemonic(mnemonic, '', { nostrPubkey: st.signer.pubkey });
      save({ ...load(), pubkey: st.signer.pubkey, linked: Date.now(), ...sessionOf(st.signer) });
      ctx.hook('namesAdoptIdentity', st.signer, npubOf(st.signer.pubkey))?.catch?.(() => {});
      toast(t('nlCreated'));
      busy(false);
    } catch (e) { fail(e); }
  }

  // Link the wallet that's already open to a nostr identity, so logging in
  // with it on another device opens this same wallet.
  async function linkOpenWallet(makeSigner) {
    ui.nostrLoginError = '';
    busy(true);
    let signer;
    try {
      signer = await makeSigner();
      if (!wallet.mnemonic) throw new Error(t('nlNeedSeed'));
      const existing = await walletForSigner(signer);
      if (existing.mnemonic && existing.mnemonic !== wallet.mnemonic) {
        throw new Error(t('nlAlreadyLinked'));
      }
      await publishWalletBackup(signer, { mnemonic: wallet.mnemonic, passphrase: wallet.passphrase || '' });
      live = selfHealing(signer);
      save({ ...load(), pubkey: signer.pubkey, linked: Date.now(), ...sessionOf(signer) });
      ctx.hook('namesAdoptIdentity', signer, npubOf(signer.pubkey))?.catch?.(() => {});
      toast(t('nlLinked'));
      busy(false);
    } catch (e) { fail(e); }
  }

  // ---- UI ---------------------------------------------------------------

  // Client-initiated remote signing: one live connect attempt at a time. The
  // URI renders as a deep link (tap launches the signer app) and a QR (scan
  // from another device); when the app connects, login continues by itself.
  let nc = null;
  let ncRun = null;
  function startNostrConnect(run) {
    if (nc) nc.cancel();
    ncRun = run;
    nc = nostrConnect();
    const mine = nc;
    mine.ready.then((signer) => {
      if (nc !== mine || !ncRun) return;
      ui.nostrConnectOpen = false;
      ncRun(() => Promise.resolve(signer));
      nc = null;
    }).catch(() => {
      if (nc === mine) { nc = null; if (ui.nostrConnectOpen) { ui.nostrConnectOpen = false; render(); } }
    });
  }
  function stopNostrConnect() {
    if (nc) { nc.cancel(); nc = null; }
    ncRun = null;
  }

  function nostrConnectSection(run) {
    if (!ui.nostrConnectOpen) {
      return h('button', {
        class: 'btn-block', disabled: ui.nostrLoginBusy,
        onClick: () => { ui.nostrConnectOpen = true; startNostrConnect(run); render(); },
      }, t('nlConnectApp'));
    }
    if (!nc) return null;
    return h('div', { class: 'col', style: 'gap:10px;align-items:center' },
      h('a', {
        class: 'btn btn-block btn-primary', href: nc.uri,
        style: 'text-align:center;display:block;text-decoration:none',
      }, t('nlOpenSigner')),
      h('div', { html: qrSvg(nc.uri) }),
      h('div', { class: 'row gap6', style: 'align-items:center' },
        h('span', { class: 'spinner sm' }),
        h('span', { class: 'small muted' }, t('nlWaitingSigner'))),
      h('div', { class: 'row gap6' },
        copyBtn(nc.uri, t('copy')),
        h('button', { class: 'btn-sm', onClick: () => { stopNostrConnect(); ui.nostrConnectOpen = false; render(); } }, t('cancel'))));
  }

  // The three ways in, as buttons. `run` receives a signer factory.
  function signerButtons(run) {
    const hasExt = typeof window !== 'undefined' && !!window.nostr;
    return h('div', { class: 'col', style: 'gap:8px' },
      hasExt
        ? h('button', { class: 'btn-block', disabled: ui.nostrLoginBusy,
            onClick: () => run(() => extensionSigner()) }, t('nlExtension'))
        : null,
      nostrConnectSection(run),
      h('div', { class: 'row gap6' },
        h('input', {
          type: 'password', placeholder: t('nlKeyOrBunker'), style: 'flex:1',
          autocapitalize: 'none', autocomplete: 'off', spellcheck: 'false',
          value: ui.nostrLoginInput || '',
          onInput: (e) => { ui.nostrLoginInput = e.target.value.trim(); },
        }),
        h('button', { class: 'btn-sm', disabled: ui.nostrLoginBusy, onClick: () => {
          const v = (ui.nostrLoginInput || '').trim();
          const sk = parseNostrSecret(v);
          if (sk) return run(() => keySigner(sk));
          if (/^bunker:\/\//i.test(v)) {
            return run(() => bunkerSigner(v, { onAuth: (url) => { ui.nostrLoginAuthUrl = url; render(); } }));
          }
          ui.nostrLoginError = t('nlUnrecognized');
          render();
        } }, ui.nostrLoginBusy ? h('span', { class: 'spinner' }) : t('nlGo'))),
      h('div', { class: 'small faint' }, t('nlHint')),
      ui.nostrLoginAuthUrl
        ? h('a', { href: ui.nostrLoginAuthUrl, target: '_blank', class: 'small' }, t('nlApprove'))
        : null,
      ui.nostrLoginError ? h('div', { class: 'notice err' }, ui.nostrLoginError) : null);
  }

  // Shown under the create/import tabs on the unlock screen.
  function unlockExtra() {
    if (ui.nostrLoginNew) {
      return h('div', { class: 'card col', style: 'gap:10px' },
        h('h3', { style: 'margin:0' }, t('nlNewTitle')),
        h('div', { class: 'small muted' }, ui.nostrLoginNew.npub || ''),
        h('p', { class: 'small muted', style: 'margin:0' }, t('nlNewDesc')),
        h('div', { class: 'notice info small' }, t('nlBackupWarning')),
        ui.nostrLoginError ? h('div', { class: 'notice err' }, ui.nostrLoginError) : null,
        h('div', { class: 'row gap6' },
          h('button', { class: 'btn-ghost', onClick: () => {
            if (ui.nostrLoginNew.signer.close) ui.nostrLoginNew.signer.close();
            ui.nostrLoginNew = null; render();
          } }, t('cancel')),
          h('button', { class: 'btn-primary grow', disabled: ui.nostrLoginBusy, onClick: createForSigner },
            ui.nostrLoginBusy ? h('span', { class: 'spinner' }) : t('nlCreateBtn'))));
    }
    // Collapsed by default: one button, expanded only when asked for.
    if (!ui.nostrLoginOpen) {
      // NB .btn-block forces display:block, so the flex centering lives on an
      // inner wrapper rather than the button itself.
      return h('button', {
        class: 'btn-block',
        onClick: () => { ui.nostrLoginOpen = true; ui.nostrLoginError = ''; render(); },
      }, h('span', { style: 'display:flex;align-items:center;justify-content:center;gap:8px' },
        h('span', { style: 'display:flex;flex-shrink:0', html: OSTRICH }),
        t('nlSignIn')));
    }
    return h('div', { class: 'card col', style: 'gap:10px' },
      h('div', { class: 'row between' },
        h('h3', { style: 'margin:0' }, t('nlTitle')),
        h('span', { class: 'linklike small', onClick: () => { ui.nostrLoginOpen = false; render(); } }, t('cancel'))),
      h('p', { class: 'small muted', style: 'margin:0' }, t('nlDesc')),
      signerButtons(loginWith));
  }

  function settingsCard() {
    if (wallet.watchOnly || !wallet.mnemonic) return null;
    const st = load();
    if (st.pubkey) {
      return h('div', { class: 'card col' },
        h('h3', {}, t('nlLinkTitle')),
        h('div', { class: 'small muted break' }, npubOf(st.pubkey) || st.pubkey),
        h('p', { class: 'small faint', style: 'margin:0' }, t('nlLinkedDesc')));
    }
    return h('div', { class: 'card col' },
      h('h3', {}, t('nlLinkTitle')),
      h('p', { class: 'small muted', style: 'margin:0' }, t('nlLinkDesc')),
      h('div', { class: 'notice info small' }, t('nlBackupWarning')),
      signerButtons(linkOpenWallet));
  }

  return {
    id: 'nostrlogin',
    stop() { stopNostrConnect(); },
    // The nostr identity this session is logged in as, for features that
    // should speak as the user (the payment address defaults to this npub).
    nostrLoginIdentity() {
      // A just-connected signer counts immediately — the persisted link lands
      // only after the wallet opens, and the header avatar shouldn't show the
      // wallet key's face in the gap.
      if (live) return { pubkey: live.pubkey, npub: npubOf(live.pubkey), signer: live };
      const st = load();
      if (!st.pubkey) return null;
      return { pubkey: st.pubkey, npub: npubOf(st.pubkey), signer: live };
    },
    // A page reload loses the signer. An installed extension can usually be
    // re-attached without prompting, which is what lets the payment address
    // stay tied to the user's real identity across reloads. Returns null for
    // signers we cannot silently reattach (pasted keys, bunkers).
    async nostrLoginResume() {
      if (live) return live;
      const st = load();
      if (!st.pubkey) return null;
      // One attempt at a time, and a pause after a failure: identity() asks on
      // every send, and a signer that isn't answering shouldn't mean a new
      // relay connection per keystroke.
      if (resuming) return resuming;
      if (Date.now() - resumeFailedAt < 20_000) return null;
      resuming = (async () => {
        if (typeof window !== 'undefined' && window.nostr) {
          try {
            const s = await extensionSigner();
            if (s.pubkey === st.pubkey) return (live = s);
          } catch {}
        }
        if (st.secret) {
          try {
            const s = keySigner(hex.decode(st.secret));
            if (s.pubkey === st.pubkey) return (live = s);
          } catch {}
        }
        if (st.session) {
          try {
            const s = await resumeBunker(st.session, { onAuth: (url) => { ui.nostrLoginAuthUrl = url; render(); } });
            if (s && s.pubkey === st.pubkey) return (live = selfHealing(s));
          } catch {}
        }
        return null;
      })();
      try {
        const s = await resuming;
        if (!s) resumeFailedAt = Date.now();
        return s;
      } finally { resuming = null; }
    },
    unlockExtra() { return unlockExtra(); },
    nostrSettingsCards() { return [settingsCard()]; },
  };
}

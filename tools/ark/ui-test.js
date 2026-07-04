// Browser-level e2e of the Ark UI wiring, driven with puppeteer against the
// real dev server + the ark regtest stack:
//
//   import wallet -> ark connects -> receive over Ark (alice pays the address
//   shown in the Receive tab) -> send over Ark from the Send form -> board
//   from the Settings card -> refresh/consolidate -> balances line up.
//
// Usage: bun tools/ark/ui-test.js   (regtest stack up + nothing on :5199)

import { spawn, execSync } from 'node:child_process';
import puppeteer from 'puppeteer-core';
import { generateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

const PORT = 5199;
const APP = `http://localhost:${PORT}`;
const BARK = `${process.env.HOME}/bark/target/debug/bark`;
const ALICE = `${BARK} --datadir ${process.env.HOME}/ark-regtest/alice`;
const BCLI = `bitcoin-cli -regtest -datadir=${process.env.HOME}/ark-regtest/bitcoind -rpcport=18543 -rpcwallet=miner`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sh = (cmd) => execSync(cmd, { shell: '/bin/bash' }).toString().trim();
const mine = (n = 1) => sh(`${BCLI} generatetoaddress ${n} $(${BCLI} getnewaddress) >/dev/null`);
const aliceBalance = () => JSON.parse(sh(`${ALICE} -q balance`)).spendable_sat;

let ok = true;
const check = (name, cond, detail = '') => {
  console.log(` ${cond ? '✓' : '✗'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!cond) ok = false;
};

// --- dev server ---
const dev = spawn('bun', ['run', 'dev'], { cwd: process.env.HOME + '/halwallet', env: { ...process.env, PORT: String(PORT) }, stdio: 'ignore' });
for (let i = 0; i < 30; i++) {
  try { if ((await fetch(APP)).ok) break; } catch {}
  await sleep(500);
}

const browser = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', headless: 'new', args: ['--no-sandbox'] });
const page = await browser.newPage();
page.on('pageerror', (e) => console.log('  [pageerror]', e.message));

// helpers — NB innerText respects CSS text-transform, so match case-insensitively
const bodyText = () => page.evaluate(() => document.body.innerText);
const clickText = async (sel, text) => {
  const found = await page.evaluate((sel, text) => {
    const el = [...document.querySelectorAll(sel)].find((e) => e.textContent.trim().toLowerCase().includes(text.toLowerCase()));
    if (el) { el.click(); return true; }
    return false;
  }, sel, text);
  if (!found) throw new Error(`clickText: no ${sel} with "${text}"`);
};
const waitText = async (text, ms = 20000) => {
  for (let i = 0; i < ms / 250; i++) {
    if ((await bodyText()).toLowerCase().includes(text.toLowerCase())) return true;
    await sleep(250);
  }
  return false;
};
// The number shown next to a label like "ark balance" (sats mode, comma groups)
const labeledNumber = async (label) => {
  const txt = await bodyText();
  const esc = label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const m = txt.match(new RegExp(esc + String.raw`[\s\n]*([\d,]+)`, 'i'));
  return m ? Number(m[1].replaceAll(',', '')) : null;
};
const waitLabeledNumber = async (label, want, ms = 30000) => {
  for (let i = 0; i < ms / 500; i++) {
    if (await labeledNumber(label) === want) return true;
    await sleep(500);
  }
  return false;
};

try {
  // --- configure: regtest, esplora on the ark chain, ark local ---
  await page.goto(APP, { waitUntil: 'domcontentloaded' });
  await page.evaluate(() => {
    localStorage.setItem('btc-wallet-network', 'regtest');
    localStorage.setItem('btc-wallet-source:regtest', JSON.stringify({ id: 'custom', url: 'http://localhost:30002' }));
    localStorage.setItem('btc-wallet-ark-provider:regtest', 'local');
  });
  await page.reload({ waitUntil: 'domcontentloaded' });
  await sleep(500);

  // --- import a fresh wallet ---
  console.log('\n[1] import wallet + ark connects');
  const mnemonic = generateMnemonic(wordlist);
  await clickText('button', 'Import existing');
  await sleep(200);
  await page.type('textarea', mnemonic);
  await clickText('button', 'Open wallet');
  check('wallet opened', await waitText('receive', 15000));

  check('ark connected (receive option present)', await (async () => {
    for (let i = 0; i < 40; i++) {
      const has = await page.evaluate(() => [...document.querySelectorAll('option')].some((o) => o.value === 'ark'));
      if (has) return true;
      await sleep(500);
    }
    return false;
  })());

  // --- receive over ark ---
  console.log('\n[2] receive over Ark');
  await page.select('select', 'ark');
  await sleep(300);
  const arkAddr = await page.evaluate(() => document.querySelector('.addr-box')?.textContent.trim() || '');
  check('ark address shown', /^tark1[a-z0-9]+$/.test(arkAddr), arkAddr.slice(0, 24) + '…');
  sh(`${ALICE} -q send ${arkAddr} "25000 sat"`);
  check('ark balance shows 25,000', await waitLabeledNumber('ark balance', 25000, 30000), String(await labeledNumber('ark balance')));
  check('payment celebration shown', await waitText('Payment received', 10000));
  await clickText('.card', 'Payment received'); // tap to acknowledge
  await sleep(400);
  check('back to receive card after tap', await waitText('tark1', 5000));

  // --- send over ark ---
  console.log('\n[3] send over Ark');
  const aliceAddr = sh(`${ALICE} -q address`);
  const before = aliceBalance();
  await clickText('.tabs button', 'Send');
  await sleep(300);
  await page.type('.mono-input', aliceAddr);
  await sleep(400); // destReady re-render reveals the amount input
  await page.type('input[type="number"]', '7000');
  await clickText('button.btn-primary', 'Review transaction');
  check('ark review shown', await waitText('Send over Ark', 5000));
  await clickText('button.btn-primary', 'Send');
  check('sent view', await waitText('Sent!', 15000));
  check('alice +7000', aliceBalance() === before + 7000, String(aliceBalance() - before));

  // --- board from settings ---
  console.log('\n[4] board');
  await clickText('.tabs button', 'Receive');
  await sleep(300);
  await page.select('select', 'address');
  await sleep(300);
  const onchainAddr = await page.evaluate(() => document.querySelector('.addr-box').textContent.trim());
  sh(`${BCLI} sendtoaddress ${onchainAddr} 0.001`);
  mine(1);
  check('onchain funds arrive', await waitText('100,000', 30000));

  await clickText('.tabs button', 'Settings');
  await sleep(300);
  const preBoard = await labeledNumber('ark balance');
  const boardInput = await page.evaluateHandle(() =>
    [...document.querySelectorAll('input')].find((i) => (i.placeholder || '').toLowerCase().startsWith('board amount')));
  await boardInput.asElement().type('30000');
  await clickText('button', 'Board');
  check('board started', await waitText('Boarding', 20000));
  mine(2);
  check('board vtxo lands (+29,670)', await waitLabeledNumber('ark balance', preBoard + 29670, 40000),
    String(await labeledNumber('ark balance')));

  // --- refresh / consolidate ---
  console.log('\n[5] refresh');
  await clickText('button', 'Refresh / consolidate');
  check('refresh submitted', await waitText('Refresh submitted', 10000));
  const done = await (async () => {
    for (let i = 0; i < 45; i++) {
      mine(1);
      await sleep(2000);
      if (await labeledNumber('coins (vtxos)') === 1 && !(await bodyText()).toLowerCase().includes('in progress')) return true;
    }
    return false;
  })();
  check('refresh consolidated to 1 coin', done, String(await labeledNumber('coins (vtxos)')));
  console.log(`   final ark balance: ${await labeledNumber('ark balance')} sats`);

  console.log(ok ? '\n✅ SUCCESS: Ark UI — receive, send, board, refresh all work in the browser'
                : '\n❌ some checks failed');
} finally {
  await browser.close();
  dev.kill();
}
process.exit(ok ? 0 : 1);

// Silent-payments e2e on regtest, through the real UI (two isolated browser
// contexts = two devices):
//
//   wallet B shows its sp1 address -> wallet A (funded on-chain) pays it ->
//   B's indexer scan finds the payment -> B SPENDS the SP coin (exercises the
//   BIP-352 per-output key signing path) -> miner address receives it.
//
// Needs the ark-regtest stack + the SP indexer:
//   COOKIE=$(cat ~/ark-regtest/bitcoind/regtest/.cookie); \
//   CORE_RPC=http://127.0.0.1:18543 RPC_USER=${COOKIE%%:*} RPC_PASS=${COOKIE#*:} \
//   SP_PORT=8899 START_HEIGHT=<tip> bun tools/sp-indexer.js
//
// Usage: bun tools/sp-test.js

import { spawn, execSync } from 'node:child_process';
import puppeteer from 'puppeteer-core';
import { generateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

const PORT = 5199;
const APP = `http://localhost:${PORT}`;
const BCLI = `bitcoin-cli -regtest -datadir=${process.env.HOME}/ark-regtest/bitcoind -rpcport=18543 -rpcwallet=miner`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sh = (cmd) => execSync(cmd, { shell: '/bin/bash' }).toString().trim();
const mine = (n = 1) => sh(`${BCLI} generatetoaddress ${n} $(${BCLI} getnewaddress) >/dev/null`);

let ok = true;
const check = (name, cond, detail = '') => {
  console.log(` ${cond ? '✓' : '✗'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!cond) ok = false;
};

const dev = spawn('bun', ['run', 'dev'], { cwd: process.env.HOME + '/halwallet', env: { ...process.env, PORT: String(PORT) }, stdio: 'ignore' });
for (let i = 0; i < 30; i++) { try { if ((await fetch(APP)).ok) break; } catch {} await sleep(500); }

const browser = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', headless: 'new', args: ['--no-sandbox'] });

async function newWalletPage() {
  const ctx = await browser.createBrowserContext(); // isolated storage = its own device
  const page = await ctx.newPage();
  page.on('pageerror', (e) => console.log('  [pageerror]', e.message));
  await page.goto(APP, { waitUntil: 'domcontentloaded' });
  await page.evaluate(() => {
    localStorage.setItem('btc-wallet-network', 'regtest');
    localStorage.setItem('btc-wallet-source:regtest', JSON.stringify({ id: 'custom', url: 'http://localhost:30002' }));
    localStorage.setItem('btc-wallet-sp-indexer:regtest', JSON.stringify({ server: 'custom', url: 'http://localhost:8899' }));
  });
  await page.reload({ waitUntil: 'domcontentloaded' });
  await sleep(400);
  const clickText = (sel, text) => page.evaluate((s, x) => {
    const el = [...document.querySelectorAll(s)].find((e) => e.textContent.trim().toLowerCase().includes(x.toLowerCase()));
    if (el) { el.click(); return true; }
    return false;
  }, sel, text);
  const bodyText = () => page.evaluate(() => document.body.innerText);
  const waitText = async (text, ms = 20000) => {
    for (let i = 0; i < ms / 300; i++) {
      if ((await bodyText()).toLowerCase().includes(text.toLowerCase())) return true;
      await sleep(300);
    }
    return false;
  };
  await clickText('button', 'Import existing');
  await sleep(200);
  await page.type('textarea', generateMnemonic(wordlist));
  await clickText('button', 'Open wallet');
  await waitText('receive');
  return { page, clickText, bodyText, waitText };
}

try {
  console.log('\n[1] two wallets');
  const A = await newWalletPage();
  const B = await newWalletPage();

  // B: silent-payment address
  await B.page.select('select', 'sp');
  await sleep(400);
  const spAddr = await B.page.evaluate(() => document.querySelector('.addr-box')?.textContent.trim());
  check('B shows sp1 address', /^t?sp1[a-z0-9]+$/.test(spAddr || ''), (spAddr || '').slice(0, 20) + '…');

  // A: fund on-chain
  const aAddr = await A.page.evaluate(() => document.querySelector('.addr-box')?.textContent.trim());
  sh(`${BCLI} sendtoaddress ${aAddr} 0.001`);
  mine(1);
  check('A funded', await A.waitText('100,000', 30000));
  if (await A.page.evaluate(() => document.body.innerText.includes('Payment received'))) {
    await A.clickText('.card', 'Payment received');
    await sleep(300);
  }

  console.log('\n[2] A pays B\'s silent-payment address');
  await A.clickText('.tabs button', 'Send');
  await sleep(300);
  await A.page.type('.mono-input', spAddr);
  await sleep(500); // destReady render
  await A.page.type('input[type="number"]', '30000');
  await A.clickText('button.btn-primary', 'Review transaction');
  check('review shows SP note', await A.waitText('Silent payment', 8000));
  await A.clickText('button.btn-primary', 'Sign & broadcast');
  const bok = await A.waitText('Transaction ID', 15000);
  if (!bok) console.log('  [A after send]', (await A.bodyText()).slice(0, 320).replace(/\n+/g, ' | '));
  check('broadcast ok', bok);
  mine(1);

  console.log('\n[3] B discovers the payment');
  const found = await (async () => {
    for (let i = 0; i < 25; i++) {
      if ((await B.bodyText()).includes('30,000')) return true;
      await sleep(2000);
    }
    return false;
  })();
  check('B sees 30,000 sats via SP scan', found, (await B.bodyText()).match(/([\d,]+)\s*\n?\s*sats/)?.[1]);

  console.log('\n[4] B spends the SP coin (BIP-352 per-output key signing)');
  if (await B.page.evaluate(() => document.body.innerText.includes('Payment received'))) {
    await B.clickText('.card', 'Payment received');
    await sleep(300);
  }
  mine(1); // confirm the SP receive; unconfirmed SP coins aren't spendable
  await B.waitText('30,000', 15000);
  await sleep(2000);
  const minerAddr = sh(`${BCLI} getnewaddress`);
  await B.clickText('.tabs button', 'Send');
  await sleep(300);
  await B.page.type('.mono-input', minerAddr);
  await sleep(500);
  await B.page.type('input[type="number"]', '20000');
  await B.clickText('button.btn-primary', 'Review transaction');
  await sleep(800);
  await B.clickText('button.btn-primary', 'Sign & broadcast');
  const spent = await B.waitText('Transaction ID', 15000);
  check('SP coin spend broadcast', spent, spent ? '' : (await B.bodyText()).slice(0, 200));
  mine(1);

  console.log(ok ? '\n✅ SUCCESS: SP send, indexer discovery, and SP-input spend all work'
                : '\n❌ some checks failed');
} finally {
  await browser.close();
  dev.kill();
}
process.exit(ok ? 0 : 1);

// Smoke test for the minimal build profile (HAL_FEATURES=none): a plain
// on-chain wallet with no swap/Ark/gift/SP surfaces — and still fully working
// (imports a wallet, receives a payment) against the regtest stack.
//
// Usage: bun tools/minimal-smoke.js

import { execSync } from 'node:child_process';
import puppeteer from 'puppeteer-core';
import { generateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { buildHtml } from '../build.js';

const BCLI = `bitcoin-cli -regtest -datadir=${process.env.HOME}/ark-regtest/bitcoind -rpcport=18543 -rpcwallet=miner`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sh = (cmd) => execSync(cmd, { shell: '/bin/bash' }).toString().trim();

let ok = true;
const check = (name, cond, detail = '') => {
  console.log(` ${cond ? '✓' : '✗'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!cond) ok = false;
};

// --- build the minimal profile and serve it ---
const html = await buildHtml({ minify: true, pwa: false, features: 'none' });
const full = await buildHtml({ minify: true, pwa: false });
console.log(`minimal bundle: ${(html.length / 1024).toFixed(0)}KB (full: ${(full.length / 1024).toFixed(0)}KB)`);
check('meaningfully smaller than full', html.length < full.length * 0.9);
check('no ark protocol code', !html.includes('Ark VTXO mailbox authorization'));
check('no swap protocol code', !html.includes('swap/reverse'));
check('no musig code', !html.includes('MuSig/noncecoef'));

const server = Bun.serve({ port: 5198, fetch: () => new Response(html, { headers: { 'content-type': 'text/html' } }) });

const browser = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', headless: 'new', args: ['--no-sandbox'] });
const page = await browser.newPage();
const errs = [];
page.on('pageerror', (e) => errs.push(e.message));
const bodyText = () => page.evaluate(() => document.body.innerText);
const waitText = async (text, ms = 20000) => {
  for (let i = 0; i < ms / 250; i++) {
    if ((await bodyText()).toLowerCase().includes(text.toLowerCase())) return true;
    await sleep(250);
  }
  return false;
};
const clickText = (sel, text) => page.evaluate((s, x) => {
  const el = [...document.querySelectorAll(s)].find((e) => e.textContent.trim().toLowerCase().includes(x.toLowerCase()));
  if (el) { el.click(); return true; }
  return false;
}, sel, text);

try {
  await page.goto('http://localhost:5198', { waitUntil: 'domcontentloaded' });
  await page.evaluate(() => {
    localStorage.setItem('btc-wallet-network', 'regtest');
    localStorage.setItem('btc-wallet-source:regtest', JSON.stringify({ id: 'custom', url: 'http://localhost:30002' }));
    localStorage.setItem('btc-wallet-ark-provider:regtest', 'local'); // must be ignored by this build
  });
  await page.reload({ waitUntil: 'domcontentloaded' });
  await sleep(400);

  console.log('\n[1] import + core wallet');
  await clickText('button', 'Import existing');
  await sleep(200);
  await page.type('textarea', generateMnemonic(wordlist));
  await clickText('button', 'Open wallet');
  check('wallet opened', await waitText('receive', 15000));

  console.log('\n[2] no feature surfaces');
  await sleep(2500); // give any (wrongly present) feature time to appear
  check('no receive-mode dropdown', await page.evaluate(() =>
    ![...document.querySelectorAll('option')].some((o) => ['ln', 'ark', 'sp'].includes(o.value))));
  await clickText('.tabs button', 'Send');
  await sleep(300);
  check('no gift button', !(await bodyText()).includes('Gift some Bitcoin'));
  await clickText('.tabs button', 'Settings');
  await sleep(300);
  const settings = await bodyText();
  check('no swap provider card', !settings.includes('Swap provider'));
  check('no ark card', !/⚔ Ark/.test(settings));
  check('no sp indexer card', !settings.includes('Silent payment indexer'));

  console.log('\n[3] core receive still works');
  await clickText('.tabs button', 'Receive');
  await sleep(300);
  const addr = await page.evaluate(() => document.querySelector('.addr-box')?.textContent.trim());
  check('onchain address shown', /^bcrt1/.test(addr || ''), (addr || '').slice(0, 16) + '…');
  sh(`${BCLI} sendtoaddress ${addr} 0.0004`);
  sh(`${BCLI} generatetoaddress 1 $(${BCLI} getnewaddress) >/dev/null`);
  check('payment lands', await waitText('40,000', 30000));
  check('no page errors', errs.length === 0, errs.join(' | '));

  console.log(ok ? '\n✅ SUCCESS: minimal profile is a working on-chain-only wallet'
                : '\n❌ some checks failed');
} finally {
  await browser.close();
  server.stop(true);
}
process.exit(ok ? 0 : 1);

// Offline assessment: app loads, wallet opens, on-chain receive works,
// nothing crashes when every network call fails.
import puppeteer from 'puppeteer-core';
import { generateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { buildHtml } from '../build.js';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let ok = true;
const check = (n, c, d='') => { console.log(` ${c ? '✓' : '✗'} ${n}${d?' — '+d:''}`); if (!c) ok = false; };
const html = await buildHtml({ minify: false, pwa: false });
const server = Bun.serve({ port: 5199, fetch: () => new Response(html, { headers: { 'content-type': 'text/html' } }) });
const browser = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', headless: 'new', args: ['--no-sandbox'] });

// ---- scenario A: cold start fully offline (page already cached / file://)
const page = await browser.newPage();
const errs = [];
page.on('pageerror', (e) => errs.push(e.message));
await page.setViewport({ width: 480, height: 900 });
await page.goto('http://localhost:5199', { waitUntil: 'domcontentloaded' });
await sleep(300);
await page.setOfflineMode(true);
const bodyText = () => page.evaluate(() => document.body.innerText);
const waitText = async (t2, ms = 15000) => { for (let i = 0; i < ms/250; i++) { if ((await bodyText()).includes(t2)) return true; await sleep(250); } return false; };
try {
  console.log('[offline import]');
  await page.evaluate(() => [...document.querySelectorAll('button')].find(b => b.textContent.includes('Import existing'))?.click());
  await sleep(200);
  await page.type('textarea', generateMnemonic(wordlist));
  await page.evaluate(() => [...document.querySelectorAll('button')].find(b => b.textContent.includes('Open wallet'))?.click());
  const opened = await waitText('Receive', 25000) || await waitText('Settings', 5000) || await waitText('offline', 5000);
  check('wallet opens offline', opened, (await bodyText()).slice(0, 120).replaceAll('\n',' | '));
  await sleep(4000);
  const body1 = await bodyText();
  console.log('   state:', body1.slice(0, 200).replaceAll('\n', ' | '));
  // try the receive tab
  await page.evaluate(() => [...document.querySelectorAll('.tabs button')].find(b => b.textContent === 'Receive')?.click());
  await sleep(1500);
  const body2 = await bodyText();
  check('on-chain address renders offline', /bc1[a-z0-9]{20,}/.test(body2));
  check('balance card present', await page.evaluate(() => !!document.querySelector('.balance')));
  // settings + advanced (offline transfer)
  await page.evaluate(() => [...document.querySelectorAll('.tabs button')].find(b => b.textContent === 'Settings')?.click());
  await sleep(500);
  await page.evaluate(() => [...document.querySelectorAll('.settings-nav')].find(b => b.textContent.trim() === 'Advanced')?.click());
  await sleep(500);
  check('offline transfer reachable', (await bodyText()).includes('Offline transfer'));
  const fatal = errs.filter((e) => !/net::|WebSocket|Failed to fetch|NetworkError|ERR_INTERNET/i.test(e));
  check('no fatal page errors', !fatal.length, fatal.slice(0, 3).join(' | '));
  console.log('   (network-shaped errors swallowed:', errs.length, ')');
} finally { await browser.close(); server.stop(); }
process.exit(ok ? 0 : 1);

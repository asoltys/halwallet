// Screenshot run: import a wallet, receive over Ark, show the balance card +
// Ark settings card. Writes PNGs to /tmp/ark-ui-*.png.
import { spawn, execSync } from 'node:child_process';
import puppeteer from 'puppeteer-core';
import { generateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

const PORT = 5199;
const APP = `http://localhost:${PORT}`;
const BARK = `${process.env.HOME}/bark/target/debug/bark`;
const ALICE = `${BARK} --datadir ${process.env.HOME}/ark-regtest/alice`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sh = (cmd) => execSync(cmd, { shell: '/bin/bash' }).toString().trim();

const dev = spawn('bun', ['run', 'dev'], { cwd: process.env.HOME + '/halwallet', env: { ...process.env, PORT: String(PORT) }, stdio: 'ignore' });
for (let i = 0; i < 30; i++) { try { if ((await fetch(APP)).ok) break; } catch {} await sleep(500); }

const browser = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', headless: 'new', args: ['--no-sandbox'] });
const page = await browser.newPage();
await page.setViewport({ width: 420, height: 860, deviceScaleFactor: 2 });
const clickText = (sel, text) => page.evaluate((sel, text) => {
  const el = [...document.querySelectorAll(sel)].find((e) => e.textContent.trim().toLowerCase().includes(text.toLowerCase()));
  if (el) el.click();
}, sel, text);

await page.goto(APP, { waitUntil: 'domcontentloaded' });
await page.evaluate(() => {
  localStorage.setItem('btc-wallet-network', 'regtest');
  localStorage.setItem('btc-wallet-source:regtest', JSON.stringify({ id: 'custom', url: 'http://localhost:30002' }));
  localStorage.setItem('btc-wallet-ark-provider:regtest', 'local');
});
await page.reload({ waitUntil: 'domcontentloaded' });
await sleep(500);
await clickText('button', 'Import existing');
await sleep(200);
await page.type('textarea', generateMnemonic(wordlist));
await clickText('button', 'Open wallet');
await sleep(4000);

await page.select('select', 'ark');
await sleep(400);
const addr = await page.evaluate(() => document.querySelector('.addr-box')?.textContent.trim());
await page.screenshot({ path: '/tmp/ark-ui-receive.png' });

sh(`${ALICE} -q send ${addr} "25000 sat"`);
for (let i = 0; i < 30; i++) { await sleep(1000); if ((await page.evaluate(() => document.body.innerText)).toLowerCase().includes('ark balance')) break; }
await sleep(500);
await page.screenshot({ path: '/tmp/ark-ui-balance.png' });

await clickText('.tabs button', 'Settings');
await sleep(500);
await page.evaluate(() => {
  const el = [...document.querySelectorAll('h3')].find((e) => e.textContent.includes('Ark'));
  if (el) el.scrollIntoView({ block: 'start' });
});
await sleep(300);
await page.screenshot({ path: '/tmp/ark-ui-settings.png' });

await browser.close();
dev.kill();
console.log('done');

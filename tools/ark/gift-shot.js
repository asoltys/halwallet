// Screenshot the gift-claim wallet chooser: mint a real gift from a funded
// wallet, open its link in the same browser (wallet 1 still in session),
// capture the "choose where to receive" screen.
import { spawn, execSync } from 'node:child_process';
import puppeteer from 'puppeteer-core';
import { generateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

const PORT = 5199;
const APP = `http://localhost:${PORT}`;
const BCLI = `bitcoin-cli -regtest -datadir=${process.env.HOME}/ark-regtest/bitcoind -rpcport=18543 -rpcwallet=miner`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sh = (cmd) => execSync(cmd, { shell: '/bin/bash' }).toString().trim();

const dev = spawn('bun', ['run', 'dev'], { cwd: process.env.HOME + '/halwallet', env: { ...process.env, PORT: String(PORT) }, stdio: 'ignore' });
for (let i = 0; i < 30; i++) { try { if ((await fetch(APP)).ok) break; } catch {} await sleep(500); }

const browser = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', headless: 'new', args: ['--no-sandbox'] });
const page = await browser.newPage();
await page.setViewport({ width: 420, height: 860, deviceScaleFactor: 2 });
const clickText = (sel, text) => page.evaluate((sel, text) => {
  const el = [...document.querySelectorAll(sel)].find((e) => e.textContent.trim().toLowerCase().includes(text.toLowerCase()));
  if (el) { el.click(); return true; } return false;
}, sel, text);
const waitText = async (text, ms = 20000) => {
  for (let i = 0; i < ms / 250; i++) {
    if (await page.evaluate((t) => document.body.innerText.toLowerCase().includes(t.toLowerCase()), text)) return true;
    await sleep(250);
  }
  return false;
};

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
await waitText('receive');

// fund on-chain, confirmed
const addr = await page.evaluate(() => document.querySelector('.addr-box')?.textContent.trim());
sh(`${BCLI} sendtoaddress ${addr} 0.0005`);
sh(`${BCLI} generatetoaddress 1 $(${BCLI} getnewaddress) >/dev/null`);
await waitText('50,000', 30000);
if (await page.evaluate(() => document.body.innerText.includes('Payment received'))) {
  await clickText('.card', 'Payment received');
  await sleep(300);
}

// make a 2000-sat gift
await clickText('.tabs button', 'Send');
await sleep(300);
await clickText('button', 'Gift some Bitcoin');
await sleep(300);
const amtInput = await page.evaluateHandle(() => [...document.querySelectorAll('input[type="number"]')][0]);
await amtInput.asElement().type('2000');
await clickText('button', 'Create gift link');
await sleep(500);
if (await page.evaluate(() => document.body.innerText.includes('Lock the whole coin'))) {
  await clickText('button', 'Lock the whole coin');
}
await waitText('/g/', 20000);
const link = await page.evaluate(() =>
  [...document.querySelectorAll('.addr-box')].map((e) => e.textContent.trim()).find((x) => x.includes('/g/')));
console.log('gift link:', (link || '').slice(0, 50) + '…');

// open the gift link — wallet 1 exists, so the chooser should appear
await page.goto(link, { waitUntil: 'domcontentloaded' });
const shown = await waitText('Choose where', 15000);
console.log('chooser shown:', shown);
await sleep(400);
await page.screenshot({ path: '/tmp/gift-choose.png' });
// pick the existing wallet and capture the claim screen copy
await clickText('button', 'Wallet 1');
await waitText('Claim it', 15000);
await sleep(400);
await page.screenshot({ path: '/tmp/gift-claim-existing.png' });
console.log('claim copy:', await page.evaluate(() => [...document.querySelectorAll('p')].map((e) => e.textContent).find((x) => x.includes('Claim it'))));
console.log('done');
await browser.close();
dev.kill();

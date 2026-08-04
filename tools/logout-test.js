// Logging out should ask for a password only when there is one.
//
// Wallets save themselves to this device under an empty password unless the
// user sets one, so the unlock screen was demanding a password nobody had
// chosen — which made logout look like it had done something drastic. It
// hasn't: logout keeps every saved wallet, and only "Clear all" deletes them.
//
// Run: bun tools/logout-test.js
import puppeteer from 'puppeteer-core';
import { generateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { buildHtml } from '../build.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let ok = true;
const check = (n, c, d = '') => { console.log(` ${c ? '✓' : '✗'} ${n}${d ? ' — ' + String(d).slice(0, 160) : ''}`); if (!c) ok = false; };

const html = await buildHtml({ minify: true, pwa: false });
const server = Bun.serve({ port: 5235, fetch: () => new Response(html, { headers: { 'content-type': 'text/html' } }) });
const browser = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', headless: 'new', args: ['--no-sandbox'] });
const page = await browser.newPage();
const body = () => page.evaluate(() => document.body.innerText);
const click = (sel, t) => page.evaluate((s, x) => { const e = [...document.querySelectorAll(s)].find((n) => n.textContent.trim().toLowerCase().includes(x.toLowerCase())); if (e) { e.click(); return true; } return false; }, sel, t);
const waitText = async (x, ms = 20000) => { for (let i = 0; i < ms / 250; i++) { if ((await body()).toLowerCase().includes(x.toLowerCase())) return true; await sleep(250); } return false; };
const logout = async () => {
  await page.evaluate(() => document.querySelector('.header-avatar')?.click());
  await sleep(400);
  await click('.icon-select-item', 'Logout');
  await sleep(1500);
};
const vaultSize = () => page.evaluate(() => (localStorage.getItem('btc-wallet-vault') || '').length);

try {
  await page.goto('http://localhost:5235/', { waitUntil: 'domcontentloaded' });
  await page.evaluate(() => localStorage.setItem('btc-wallet-network', 'regtest'));
  await page.reload({ waitUntil: 'domcontentloaded' });
  await sleep(400);
  await click('button', 'I already have a wallet');
  await sleep(300);
  await click('button', 'Import existing');
  await sleep(300);
  await page.waitForSelector('textarea');
  await page.type('textarea', generateMnemonic(wordlist));
  await click('button', 'Open wallet');
  check('wallet open', await waitText('receive', 15000));
  await sleep(2500);
  const savedBytes = await vaultSize();
  check('it saved itself to the device', savedBytes > 0, `${savedBytes} bytes of vault`);

  console.log('\n[logging out with no password set]');
  await logout();
  let txt = await body();
  check('no password is demanded', !/enter your password|unlock saved wallets/i.test(txt), txt.slice(0, 120).replace(/\n+/g, ' | '));
  check('the saved wallet is still there', (await vaultSize()) === savedBytes);
  check('and it is offered back', /wallet 1|wallets/i.test(txt), txt.slice(0, 140).replace(/\n+/g, ' | '));

  const listed = await page.evaluate(() => [...document.querySelectorAll('button, .item, .acct')].map((e) => e.textContent.trim()).filter((x) => /Wallet 1/.test(x)));
  check('and only once — no phantom duplicate', listed.length === 1, JSON.stringify(listed));

  console.log('\n[getting back in]');
  await page.evaluate(() => { const e = [...document.querySelectorAll('*')].find((n) => n.children.length === 0 && /Wallet 1/.test(n.textContent) && n.closest('button, .item, .acct')); if (e) e.closest('button, .item, .acct').click(); });
  await sleep(2000);
  check('one tap returns to the wallet', await waitText('receive', 15000));

  console.log('\n[now with a password]');
  // "Change password" lives on the Wallets screen, behind the header selector
  await page.evaluate(() => { const b = [...document.querySelectorAll('.row.between button')].find((e) => /Wallet/.test(e.textContent)); if (b) b.click(); });
  await sleep(1200);
  check('on the wallets screen', /wallets/i.test(await body()));
  await click('button', 'Change password');
  await sleep(1000);
  const fields = await page.$$('input[type=password]');
  check('the change-password form is up', fields.length >= 3, `${fields.length} field(s)`);
  // current (empty) / new / confirm
  await fields[fields.length - 2].type('hunter22');
  await fields[fields.length - 1].type('hunter22');
  await click('button', 'Save');
  const pwSet = await waitText('password changed', 8000);
  check('a password is actually set', pwSet, (await body()).slice(0, 120).replace(/\n+/g, ' | '));

  // back into the wallet — the Wallets screen has no avatar menu to log out from
  await click('button', 'Back');
  await sleep(1500);
  check('back in the wallet', await waitText('receive', 15000));
  await logout();
  txt = await body();
  check('now it does ask', /unlock saved wallets|enter your password/i.test(txt), txt.slice(0, 120).replace(/\n+/g, ' | '));
  check('the wallet is still saved', (await vaultSize()) > 0);

  console.log('\n[clear all is the destructive one]');
  await click('button', 'Use another wallet');
  await sleep(1500);
  await page.evaluate(() => { const b = [...document.querySelectorAll('.row.between button')].find((e) => /Wallet/.test(e.textContent)); if (b) b.click(); });
  await sleep(1200);
  await click('button', 'Clear all');
  await sleep(800);
  const txt2 = await body();
  check('it warns before wiping', /removes every wallet/i.test(txt2), txt2.slice(0, 140).replace(/\n+/g, ' | '));
  check('and it has not wiped anything yet', (await vaultSize()) > 0);
} catch (e) {
  check('run completed', false, e.message);
} finally {
  await browser.close();
  server.stop(true);
}
console.log(ok ? '\n✅ logout keeps your wallets' : '\n❌ failures above');
process.exit(ok ? 0 : 1);

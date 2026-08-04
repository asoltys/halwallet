// The unread dot either says someone is waiting or it doesn't — it must not
// flash on the way in. render() rebuilds the whole DOM, so any entrance
// animation on the dot replays on every repaint; an earlier build popped it
// seven times in the first seconds after a refresh, which reads as flashing.
//
// Run: bun tools/unread-dot-test.js
import puppeteer from 'puppeteer-core';
import { generateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { buildHtml } from '../build.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let ok = true;
const html = await buildHtml({ minify: true, pwa: false });
const server = Bun.serve({ port: 5233, fetch: () => new Response(html, { headers: { 'content-type': 'text/html' } }) });
const browser = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', headless: 'new', args: ['--no-sandbox'] });
const page = await browser.newPage();
const click = (sel, t) => page.evaluate((s, x) => { const e = [...document.querySelectorAll(s)].find((n) => n.textContent.trim().toLowerCase().includes(x.toLowerCase())); if (e) { e.click(); return true; } return false; }, sel, t);
const waitText = async (x, ms = 25000) => { for (let i = 0; i < ms / 250; i++) { if ((await page.evaluate(() => document.body.innerText)).toLowerCase().includes(x.toLowerCase())) return true; await sleep(250); } return false; };

try {
  await page.goto('http://localhost:5233/', { waitUntil: 'domcontentloaded' });
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
  await waitText('receive', 15000);
  await sleep(10000); // let the coinos room load so there IS unread

  // Now the refresh the report is about.
  await page.evaluate(() => {
    window.__dot = { anims: 0, appear: 0, disappear: 0, renders: 0 };
    addEventListener('animationstart', (e) => { if (e.target && e.target.classList && e.target.classList.contains('header-msgs')) window.__dot.anims++; }, true);
    let had = null;
    new MutationObserver(() => {
      window.__dot.renders++;
      const now = !!document.querySelector('.header-msgs.unread');
      if (had !== null && now !== had) { if (now) window.__dot.appear++; else window.__dot.disappear++; }
      had = now;
    }).observe(document.getElementById('app'), { childList: true, subtree: true });
  });
  await page.reload({ waitUntil: 'domcontentloaded' });
  // re-arm after the reload wipes it
  await page.evaluate(() => {
    window.__dot = { anims: 0, appear: 0, disappear: 0, renders: 0 };
    addEventListener('animationstart', (e) => { if (e.target && e.target.classList && e.target.classList.contains('header-msgs')) window.__dot.anims++; }, true);
    let had = null;
    new MutationObserver(() => {
      window.__dot.renders++;
      const now = !!document.querySelector('.header-msgs.unread');
      if (had !== null && now !== had) { if (now) window.__dot.appear++; else window.__dot.disappear++; }
      had = now;
    }).observe(document.body, { childList: true, subtree: true });
  });
  await sleep(12000);
  const r = await page.evaluate(() => ({ ...window.__dot, dotNow: !!document.querySelector('.header-msgs.unread') }));
  console.log('over 12s after a refresh:');
  const check = (n, c, d = '') => { console.log(` ${c ? '✓' : '✗'} ${n}${d ? ' — ' + d : ''}`); if (!c) ok = false; };
  check('the dot never animates', r.anims === 0, `${r.anims} animation(s) started`);
  check('it settles once and stays', r.appear <= 1 && r.disappear === 0, `+${r.appear} / -${r.disappear}`);
  check('and the repaints it sat through were real', r.renders > 1, `${r.renders} DOM mutations`);
  check('it is showing (there is unread history)', r.dotNow);
} catch (e) {
  console.log(' ✗ run completed —', e.message);
  ok = false;
} finally {
  await browser.close();
  server.stop(true);
}
console.log(ok ? '\n✅ the dot holds still' : '\n❌ failures above');
process.exit(ok ? 0 : 1);

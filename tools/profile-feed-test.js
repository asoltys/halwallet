// A profile screen must show the person's latest nostr posts and replies —
// and a zap button on each note when the wallet can pay. Driven against the
// live coinos community: open chat, tap an avatar, land on their profile.
//
// Run: bun tools/profile-feed-test.js
import puppeteer from 'puppeteer-core';
import { generateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { buildHtml } from '../build.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let ok = true;
const check = (n, c, d = '') => { console.log(` ${c ? '✓' : '✗'} ${n}${d ? ' — ' + d : ''}`); if (!c) ok = false; };

const html = await buildHtml({ minify: true, pwa: false });
const server = Bun.serve({ port: 5234, fetch: () => new Response(html, { headers: { 'content-type': 'text/html' } }) });
const browser = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', headless: 'new', args: ['--no-sandbox'] });
const page = await browser.newPage();
const pageErrors = [];
page.on('pageerror', (e) => pageErrors.push(String(e)));
const click = (sel, t) => page.evaluate((s, x) => { const e = [...document.querySelectorAll(s)].find((n) => n.textContent.trim().toLowerCase().includes(x.toLowerCase())); if (e) { e.click(); return true; } return false; }, sel, t);
const bodyText = () => page.evaluate(() => document.body.innerText);
const waitText = async (x, ms = 20000) => { for (let i = 0; i < ms / 250; i++) { if ((await bodyText()).toLowerCase().includes(x.toLowerCase())) return true; await sleep(250); } return false; };

try {
  await page.goto('http://localhost:5234/', { waitUntil: 'domcontentloaded' });
  await sleep(400);
  await click('button', 'I already have a wallet');
  await sleep(300);
  await click('button', 'Import existing');
  await sleep(300);
  await page.waitForSelector('textarea');
  await page.type('textarea', generateMnemonic(wordlist));
  await click('button', 'Open wallet');
  check('wallet opens', await waitText('receive', 20000));

  await page.evaluate(() => document.querySelector('.header-msgs')?.click());
  await sleep(800);
  check('chat home opens', await waitText('coinos', 10000));
  await click('.item, .chat-thread-row', 'coinos');
  const gotChat = await page.waitForSelector('.chat-avatar.clickable', { timeout: 25000 }).then(() => true).catch(() => false);
  check('community chat shows avatars', gotChat);

  if (gotChat) {
    await page.evaluate(() => document.querySelector('.chat-avatar.clickable')?.click());
    check('profile screen opens', await waitText('back', 10000));
    // the feed: either notes arrive or the explicit empty state shows
    const fed = await waitText('Latest posts', 15000);
    const empty = !fed && (await bodyText()).includes('No recent posts');
    check('note feed resolves', fed || empty, fed ? 'notes shown' : 'no posts for this pk');
    if (fed) {
      const zaps = await page.evaluate(() => [...document.querySelectorAll('button')].filter((b) => b.textContent.trim() === '⚡').length);
      check('zap buttons on notes', zaps > 0, `${zaps} note(s) zappable`);
      const imgsBroken = await page.evaluate(() => [...document.querySelectorAll('.note-img')].some((i) => i.style.display !== 'none' && i.complete && i.naturalWidth === 0));
      check('no broken inline images', !imgsBroken);
      // tap a zap: should land on the send tab's zap card (resolution ladder)
      await page.evaluate(() => [...document.querySelectorAll('button')].find((b) => b.textContent.trim() === '⚡')?.click());
      check('zap flow opens', await waitText('Send a zap', 10000));
    }
  }
  check('no page errors', pageErrors.length === 0, pageErrors.slice(0, 2).join(' | '));
} finally {
  await browser.close();
  server.stop();
}
console.log(ok ? '\n✅ profile feed works' : '\n❌ profile feed broken');
process.exit(ok ? 0 : 1);

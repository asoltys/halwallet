// An npub-locked ark gift link must show who it's for and gate the code
// behind the claim code (or the recipient's NIP-07 key) — a wrong code stays
// on the unlock screen, the right one walks into the ordinary claim flow.
//
// Run: bun tools/locked-gift-test.js
import puppeteer from 'puppeteer-core';
import { hex, base32nopad } from '@scure/base';
import { buildHtml } from '../build.js';
import { lockGift, previewLockedGift } from '../src/features/gifts-wallet.js';
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let ok = true;
const check = (n, c, d = '') => { console.log(` ${c ? '✓' : '✗'} ${n}${d ? ' — ' + d : ''}`); if (!c) ok = false; };

// A syntactically valid mainnet ark gift code (random secret — nothing real).
const secret = crypto.getRandomValues(new Uint8Array(32));
const raw = new Uint8Array(42);
raw[0] = 0x11; raw[1] = 0; // magic, mainnet
new DataView(raw.buffer).setBigUint64(2, 2100n, true);
raw.set(secret, 10);
const giftCode = base32nopad.encode(raw);

const recipientSk = generateSecretKey();
const recipientPk = getPublicKey(recipientSk);
const { blob, claimCode } = lockGift(giftCode, 2100, recipientPk);
check('blob previews', !!previewLockedGift(blob));

const html = await buildHtml({ minify: true, pwa: false });
const server = Bun.serve({ port: 5233, fetch: () => new Response(html, { headers: { 'content-type': 'text/html' } }) });
const browser = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', headless: 'new', args: ['--no-sandbox'] });
const page = await browser.newPage();
const bodyText = () => page.evaluate(() => document.body.innerText);
const setInput = (sel, v) => page.evaluate((s, val) => { const e = document.querySelector(s); if (!e) return false; e.value = val; e.dispatchEvent(new Event('input', { bubbles: true })); return true; }, sel, v);
const click = (t) => page.evaluate((x) => { const e = [...document.querySelectorAll('button')].find((n) => n.textContent.trim().toLowerCase().includes(x.toLowerCase())); if (e) { e.click(); return true; } return false; }, t);
const waitText = async (x, ms = 15000) => { for (let i = 0; i < ms / 250; i++) { if ((await bodyText()).toLowerCase().includes(x.toLowerCase())) return true; await sleep(250); } return false; };

await page.goto(`http://localhost:5233/lg/${blob}`, { waitUntil: 'networkidle2' });
check('unlock screen shows', await waitText('A gift for you'));
check('amount shows', (await bodyText()).includes('2,100') || (await bodyText()).includes('2100'));
check('locked-to line shows', (await bodyText()).toLowerCase().includes('locked to'));
check('code field present', await page.evaluate(() => !!document.querySelector('input.mono-input')));

// wrong code: stay put, say so
check('typed wrong code', await setInput('input.mono-input', 'definitely-not-the-code'));
check('clicked claim', await click('claim it'));
check('wrong code rejected', await waitText('doesn’t unlock', 5000));

// right code: advances into the ordinary gift claim flow (fresh wallet path)
check('typed right code', await setInput('input.mono-input', claimCode));
check('clicked claim again', await click('claim it'));
const advanced = await waitText('checking', 10000) || await waitText('claim', 10000);
const stillLocked = (await bodyText()).includes('A gift for you');
check('unlock advanced to claim flow', advanced && !stillLocked, stillLocked ? 'still on unlock screen' : '');

await browser.close();
server.stop();
console.log(ok ? '\n✅ locked gift unlock flow works' : '\n❌ locked gift flow broken');
process.exit(ok ? 0 : 1);

// A deploy should not refresh the page out from under you.
//
// The app is inlined in the page, so when a new worker takes over, a page
// still running the old build has to reload. But navigations are
// network-first: the refresh that triggered the update has usually already
// fetched the new page, and reloading then is a second, unasked-for refresh a
// beat after your own. Both halves are asserted here — the quiet case and the
// case where a reload is genuinely owed.
//
// Run: bun tools/sw-reload-test.js   (needs a built dist/)
import puppeteer from 'puppeteer-core';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let ok = true;
const check = (n, c, d = '') => { console.log(` ${c ? '✓' : '✗'} ${n}${d ? ' — ' + d : ''}`); if (!c) ok = false; };

const html1 = await Bun.file('dist/index.html').text();
const sw1 = await Bun.file('dist/sw.js').text();
const token = (html1.match(/_v='([a-z0-9]+)'/) || [])[1];
if (!token) { console.log('no build token in dist/index.html — run bun run build'); process.exit(1); }

// A "new deploy" is the same app under a different build token.
const restamp = (tok) => ({ html: html1.replaceAll(token, tok), sw: sw1.replaceAll(token, tok) });
const builds = { v1: { html: html1, sw: sw1 }, v2: restamp('deadbeef00001'), v3: restamp('deadbeef00002') };
let current = builds.v1;

const server = Bun.serve({
  port: 5223,
  fetch(req) {
    const p = new URL(req.url).pathname;
    if (p === '/sw.js') return new Response(current.sw, { headers: { 'content-type': 'text/javascript', 'cache-control': 'no-store' } });
    if (p === '/' || p === '/index.html') return new Response(current.html, { headers: { 'content-type': 'text/html', 'cache-control': 'no-store' } });
    // The worker precaches the shell during install and addAll rejects on any
    // miss — a 404 here means it never activates and the test proves nothing.
    const f = Bun.file('dist' + p);
    return new Response(f, { headers: { 'cache-control': 'no-store' } });
  },
});

const browser = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', headless: 'new', args: ['--no-sandbox'] });
const page = await browser.newPage();
let loads = 0;
page.on('load', () => { loads++; });
page.on('console', (m) => { if (m.type() === 'error') console.log('   [page]', m.text().slice(0, 160)); });
page.on('pageerror', (e) => console.log('   [pageerror]', e.message.slice(0, 160)));

const controlled = async (ms = 15000) => {
  for (let i = 0; i < ms / 250; i++) {
    if (await page.evaluate(() => !!navigator.serviceWorker.controller)) return true;
    await sleep(250);
  }
  return false;
};

try {
  console.log('[first visit]');
  await page.goto('http://localhost:5223/', { waitUntil: 'load' });
  const reg = await page.evaluate(async () => {
    try {
      const r = await navigator.serviceWorker.register('sw.js', { updateViaCache: 'none' });
      return { ok: true, scope: r.scope, active: !!r.active, installing: !!r.installing, waiting: !!r.waiting };
    } catch (e) { return { ok: false, err: String(e).slice(0, 200) }; }
  });
  console.log('   register:', JSON.stringify(reg));
  check('worker takes control', await controlled());
  await sleep(3000);
  check('a first visit does not reload itself', loads === 1, `${loads} load(s)`);

  console.log('\n[refreshing after a deploy]');
  current = builds.v2;
  const before = loads;
  await page.reload({ waitUntil: 'load' });
  await sleep(6000); // well past install + activate + claim
  check('your refresh is the only refresh', loads === before + 1, `${loads - before} load(s) — one is yours`);
  check('and the new build is what is running', await page.evaluate(() => document.documentElement.outerHTML.includes("_v='deadbeef00001'")));

  console.log('\n[a deploy while the page sits open]');
  current = builds.v3;
  const before2 = loads;
  // no navigation: just let the worker notice, the way the periodic update
  // check would
  await page.evaluate(() => navigator.serviceWorker.getRegistration().then((r) => r && r.update()));
  for (let i = 0; i < 40 && loads === before2; i++) await sleep(250);
  check('a stale page still gets reloaded', loads === before2 + 1, `${loads - before2} reload(s)`);
  await sleep(3000);
  check('and only once', loads === before2 + 1, `${loads - before2} reload(s)`);
  check('now running the newest build', await page.evaluate(() => document.documentElement.outerHTML.includes("_v='deadbeef00002'")));
} catch (e) {
  check('run completed', false, e.message);
} finally {
  await browser.close();
  server.stop(true);
}
console.log(ok ? '\n✅ sw reload behaviour is right' : '\n❌ failures above');
process.exit(ok ? 0 : 1);

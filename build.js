// Build a single, self-contained dist/index.html (plus PWA sidecar files).
//
// Everything — app code, the @scure/@noble crypto libs, the QR generator, and
// all CSS — is bundled and inlined so the result is one file you can save and
// open offline straight from the filesystem (file://). No server, no network.
//
// For the hosted site we also emit a web manifest, icons, and a small service
// worker so the page can be installed as a PWA and still work offline once
// installed. index.html stays self-contained; these are optional extras that
// simply 404 (harmlessly) when the file is opened on its own from file://.

import { mkdir, readdir } from 'node:fs/promises';

const FAVICON = 'data:image/svg+xml,%3Csvg%20width%3D%2272%22%20height%3D%2272%22%20viewBox%3D%220%200%2072%2072%22%20fill%3D%22none%22%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%3E%20%3Cpath%20d%3D%22M69.8824%2036C69.8824%2054.7127%2054.7127%2069.8824%2036%2069.8824C17.2873%2069.8824%202.11765%2054.7127%202.11765%2036C2.11765%2017.2873%2017.2873%202.11765%2036%202.11765C54.7127%202.11765%2069.8824%2017.2873%2069.8824%2036Z%22%20fill%3D%22white%22/%3E%20%3Cpath%20fill-rule%3D%22evenodd%22%20clip-rule%3D%22evenodd%22%20d%3D%22M36%204.23529C18.4568%204.23529%204.23529%2018.4568%204.23529%2036C4.23529%2053.5432%2018.4568%2067.7647%2036%2067.7647C53.5432%2067.7647%2067.7647%2053.5432%2067.7647%2036C67.7647%2018.4568%2053.5432%204.23529%2036%204.23529ZM0%2036C0%2016.1177%2016.1177%200%2036%200C55.8823%200%2072%2016.1177%2072%2036C72%2055.8823%2055.8823%2072%2036%2072C16.1177%2072%200%2055.8823%200%2036Z%22%20fill%3D%22black%22/%3E%20%3Cpath%20fill-rule%3D%22evenodd%22%20clip-rule%3D%22evenodd%22%20d%3D%22M36%2058.5882C48.4751%2058.5882%2058.5882%2048.4751%2058.5882%2036C58.5882%2023.5248%2048.4751%2013.4117%2036%2013.4117C23.5249%2013.4117%2013.4118%2023.5248%2013.4118%2036C13.4118%2048.4751%2023.5249%2058.5882%2036%2058.5882ZM36%2054C45.9411%2054%2054%2045.9411%2054%2036C54%2026.0589%2045.9411%2018%2036%2018C26.0589%2018%2018%2026.0589%2018%2036C18%2045.9411%2026.0589%2054%2036%2054Z%22%20fill%3D%22black%22/%3E%20%3Cpath%20fill-rule%3D%22evenodd%22%20clip-rule%3D%22evenodd%22%20d%3D%22M36.0001%2022.8988C36.0001%2022.8988%2036%2022.8988%2036%2022.8988C28.7644%2022.8988%2022.8988%2028.7644%2022.8988%2036C22.8988%2043.2356%2028.7644%2049.1012%2036%2049.1012C36%2049.1012%2036.0001%2049.1012%2036.0001%2049.1012V22.8988Z%22%20fill%3D%22black%22/%3E%20%3C/svg%3E';

// Static assets copied verbatim into dist/ (icons referenced by the manifest).
const STATIC = ['icon-192.png', 'icon-512.png', 'icon-maskable-512.png', 'icon.svg'];

const MANIFEST = {
  id: '/',
  name: 'Coinos',
  short_name: 'Coinos',
  description: 'Self-custody Bitcoin wallet that runs entirely in your browser.',
  start_url: './',
  scope: './',
  display: 'standalone',
  background_color: '#eef0f3',
  theme_color: '#15171a',
  icons: [
    { src: 'icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
    { src: 'icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
    { src: 'icon-maskable-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
  ],
};

// Service worker: precache the app shell, network-first for the page (so a new
// deploy shows up), cache-first for the icons/manifest, and never touch the
// cross-origin explorer/Nostr requests. CACHE carries a build token so each
// deploy supersedes the previous cache. {{VERSION}} is filled in at build time.
const SW = `const CACHE = 'cold-{{VERSION}}';
// jsqr.js is precached so the lazy QR decoder is available offline too (for
// installed PWAs on browsers without a native BarcodeDetector).
const SHELL = ['./', 'manifest.webmanifest', 'icon-192.png', 'icon-512.png', 'jsqr.js'];

self.addEventListener('install', (e) => {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// NWC push handling lives in src/sw-nwc.js (bundled and appended below when
// the nwc+ark features ship): it tries to ANSWER the request from the pouch
// and falls back to a notification. {{NWC_WAKE_FALLBACK}} carries a
// notify-only handler for builds without those features.
{{NWC_WAKE_FALLBACK}}

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  if (new URL(req.url).origin !== self.location.origin) return; // explorer/ws → network

  if (req.mode === 'navigate') {
    e.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put('./', copy));
          return res;
        })
        .catch(() => caches.match('./'))
    );
    return;
  }
  // Cache-first, but cache same-origin assets (e.g. the chosen locale, icons)
  // on first fetch so they're available offline without precaching them all.
  e.respondWith(
    caches.match(req).then(
      (hit) =>
        hit ||
        fetch(req).then((res) => {
          if (res.ok) {
            const copy = res.clone();
            caches.open(CACHE).then((c) => c.put(req, copy));
          }
          return res;
        })
    )
  );
});
`;

const PWA_HEAD = `<link rel="manifest" href="manifest.webmanifest">
<meta name="theme-color" content="#15171a">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="default">
<meta name="apple-mobile-web-app-title" content="Coinos">
<link rel="apple-touch-icon" href="icon-192.png">
`;

// Register with updateViaCache:'none' so the browser always re-fetches sw.js
// (never from HTTP cache) and detects a new build immediately. When the new SW
// takes control (it skipWaiting + clients.claim), reload once so the fresh
// inlined app runs — but only if a SW was already controlling this page, so a
// first-ever visit doesn't reload.
const SW_REGISTER =
  `<script>if('serviceWorker'in navigator){var _had=!!navigator.serviceWorker.controller,_ref=false;` +
  `navigator.serviceWorker.addEventListener('controllerchange',function(){if(_had&&!_ref){_ref=true;location.reload()}});` +
  `addEventListener('load',function(){navigator.serviceWorker.register('sw.js',{updateViaCache:'none'}).catch(function(){})})}</script>`;

// Bundle the standalone jsQR decoder (sets window.jsQR) for lazy loading.
export async function buildJsQr({ minify = true } = {}) {
  const result = await Bun.build({
    entrypoints: ['./src/jsqr-global.js'],
    target: 'browser',
    minify,
  });
  if (!result.success) {
    for (const log of result.logs) console.error(log);
    throw new Error('jsqr bundle failed');
  }
  return result.outputs[0].text();
}

// The notify-only push handler for builds without the ark+nwc features (the
// full builds get the bundled auto-answering handler from src/sw-nwc.js).
const SW_WAKE_ONLY = `self.addEventListener('push', (e) => {
  let data = {};
  try { data = e.data ? e.data.json() : {}; } catch (_) {}
  if (data.type !== 'nwc') return;
  e.waitUntil((async () => {
    const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    if (clients.length) {
      for (const c of clients) c.postMessage({ type: 'nwc-wake', servicePubkey: data.servicePubkey });
      return;
    }
    await self.registration.showNotification('Payment request', {
      body: 'An app is asking your wallet to pay. Open Coinos to approve.',
      icon: 'icon-192.png', badge: 'icon-192.png',
      tag: 'nwc-' + (data.servicePubkey || 'req'), renotify: false,
      data: { url: './' },
    });
  })());
});
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    const open = all.find((c) => 'focus' in c);
    if (open) return open.focus();
    if (self.clients.openWindow) return self.clients.openWindow('./');
  })());
});`;

// The auto-answering NWC worker module, bundled for the SW global scope.
export async function buildSwNwc({ minify = true } = {}) {
  const result = await Bun.build({
    entrypoints: ['./src/sw-nwc.js'],
    target: 'browser',
    minify,
  });
  if (!result.success) {
    for (const log of result.logs) console.error(log);
    throw new Error('sw-nwc bundle failed');
  }
  return result.outputs[0].text();
}

// Optional-feature selection: HAL_FEATURES is a comma list of enabled
// features (gifts,swaps,ark,zaps,sp,nwc). Unset means all; "none"/"" means a minimal
// on-chain-only wallet. A build plugin swaps src/features/index.js for a
// generated module that only imports the enabled features, so a disabled
// feature's code (and its network endpoints) never enters the bundle.
// NB order matters and must match src/features/index.js — nwc sits after ark
// because it drives ark's headless pay/balance seam.
const ALL_FEATURES = { gifts: 'giftsFeature', ark: 'arkFeature', nostrlogin: 'nostrLoginFeature', names: 'namesFeature', zaps: 'zapsFeature', nwc: 'nwcFeature', sync: 'syncFeature', messages: 'messagesFeature' };

export function enabledFeatures(spec = process.env.HAL_FEATURES) {
  if (spec == null) return Object.keys(ALL_FEATURES);
  return spec.split(',').map((x) => x.trim().toLowerCase()).filter((x) => x in ALL_FEATURES);
}

function featureIndexSource(enabled) {
  return enabled.map((f) => `import { ${ALL_FEATURES[f]} } from './${f}.js';`).join('\n')
    + `\nexport function buildFeatures(ctx) { return [${enabled.map((f) => `${ALL_FEATURES[f]}(ctx)`).join(', ')}]; }\n`;
}

const featurePlugin = (enabled) => ({
  name: 'coinos-features',
  setup(b) {
    b.onLoad({ filter: /src[\/\\]features[\/\\]index\.js$/ }, () => ({
      contents: featureIndexSource(enabled),
      loader: 'js',
    }));
  },
});

export async function buildHtml({ minify = true, pwa = minify, features = process.env.HAL_FEATURES } = {}) {
  const result = await Bun.build({
    entrypoints: ['./src/app.js'],
    target: 'browser',
    minify,
    plugins: [featurePlugin(enabledFeatures(features))],
  });
  if (!result.success) {
    for (const log of result.logs) console.error(log);
    throw new Error('bundle failed');
  }
  let js = await result.outputs[0].text();
  // Guard against a literal </script> inside the bundle closing our tag early.
  js = js.replaceAll('</script', '<\\/script');
  const css = await Bun.file('./src/style.css').text();

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<meta name="color-scheme" content="light dark">
<title>Coinos</title>
<link rel="icon" href="${FAVICON}">
<script>try{var t=localStorage.getItem('btc-wallet-theme');if(t!=='dark'&&t!=='light')t=matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light';document.documentElement.dataset.theme=t;}catch(e){}</script>
${pwa ? PWA_HEAD : ''}<style>${css}</style>
</head>
<body>
<div id="app"></div>
<script>${js}</script>
${pwa ? SW_REGISTER + '\n' : ''}</body>
</html>`;
}

if (import.meta.main) {
  await mkdir('dist', { recursive: true });
  const html = await buildHtml({ minify: true });
  await Bun.write('dist/index.html', html);

  // Lazy-loaded QR decoder — kept out of index.html, fetched only when a
  // browser without BarcodeDetector opens the scanner.
  await Bun.write('dist/jsqr.js', await buildJsQr());

  // Per-language strings — fetched on demand so visitors only download theirs.
  await mkdir('dist/locales', { recursive: true });
  const locales = await readdir('src/locales');
  for (const f of locales) await Bun.write('dist/locales/' + f, Bun.file('src/locales/' + f));

  // PWA sidecars.
  await Bun.write('dist/manifest.webmanifest', JSON.stringify(MANIFEST, null, 2));
  const version = Bun.hash(html).toString(36);
  // Full builds get the auto-answering NWC worker; feature-stripped builds
  // keep the notify-only handler (the responder would just dead-weight them).
  const feats = enabledFeatures();
  const nwcSw = feats.includes('nwc') && feats.includes('ark');
  const swBody = SW
    .replace('{{VERSION}}', version)
    .replace('{{NWC_WAKE_FALLBACK}}', nwcSw ? '' : SW_WAKE_ONLY);
  await Bun.write('dist/sw.js', nwcSw ? swBody + '\n' + await buildSwNwc() : swBody);
  for (const f of STATIC) await Bun.write('dist/' + f, Bun.file('static/' + f));

  const kb = (Buffer.byteLength(html) / 1024).toFixed(0);
  console.log(`✓ dist/index.html written (${kb} KB) — open it offline, no server needed`);
  console.log(`✓ PWA: manifest.webmanifest, sw.js (cold-${version}), ${STATIC.length} icons, jsqr.js, ${locales.length} locales`);
}

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

const FAVICON =
  'data:image/svg+xml,' +
  encodeURIComponent(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#f7931a"/><text x="16" y="23" font-size="20" font-family="Arial" font-weight="bold" text-anchor="middle" fill="#fff">₿</text></svg>`
  );

// Static assets copied verbatim into dist/ (icons referenced by the manifest).
const STATIC = ['icon-192.png', 'icon-512.png', 'icon-maskable-512.png', 'icon.svg'];

const MANIFEST = {
  id: '/',
  name: 'Hal',
  short_name: 'Hal',
  description: 'Self-custody Bitcoin wallet that runs entirely in your browser.',
  start_url: './',
  scope: './',
  display: 'standalone',
  background_color: '#eef0f3',
  theme_color: '#f7931a',
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
<meta name="theme-color" content="#f7931a">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="default">
<meta name="apple-mobile-web-app-title" content="Hal">
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

// The silent-payment scanning worker, bundled separately (its own global scope)
// and embedded as base64 so the single-file app can spawn it from a Blob URL.
export async function buildSpWorker({ minify = true } = {}) {
  const result = await Bun.build({
    entrypoints: ['./src/sp-worker.js'],
    target: 'browser',
    minify,
  });
  if (!result.success) {
    for (const log of result.logs) console.error(log);
    throw new Error('sp-worker bundle failed');
  }
  return result.outputs[0].text();
}

// Optional-feature selection: HAL_FEATURES is a comma list of enabled
// features (gifts,swaps,ark,sp). Unset means all; "none"/"" means a minimal
// on-chain-only wallet. A build plugin swaps src/features/index.js for a
// generated module that only imports the enabled features, so a disabled
// feature's code (and its network endpoints) never enters the bundle.
const ALL_FEATURES = { gifts: 'giftsFeature', swaps: 'swapsFeature', ark: 'arkFeature', sp: 'spFeature', sync: 'syncFeature' };

export function enabledFeatures(spec = process.env.HAL_FEATURES) {
  if (spec == null) return Object.keys(ALL_FEATURES);
  return spec.split(',').map((x) => x.trim().toLowerCase()).filter((x) => x in ALL_FEATURES);
}

function featureIndexSource(enabled) {
  return enabled.map((f) => `import { ${ALL_FEATURES[f]} } from './${f}.js';`).join('\n')
    + `\nexport function buildFeatures(ctx) { return [${enabled.map((f) => `${ALL_FEATURES[f]}(ctx)`).join(', ')}]; }\n`;
}

const featurePlugin = (enabled) => ({
  name: 'hal-features',
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
  // The silent-payment scan worker only ships when the sp feature does.
  const workerB64 = enabledFeatures(features).includes('sp')
    ? Buffer.from(await buildSpWorker({ minify })).toString('base64')
    : '';
  const css = await Bun.file('./src/style.css').text();

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<meta name="color-scheme" content="light dark">
<title>Hal</title>
<link rel="icon" href="${FAVICON}">
<script>try{var t=localStorage.getItem('btc-wallet-theme');if(t!=='dark'&&t!=='light')t=matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light';document.documentElement.dataset.theme=t;}catch(e){}</script>
${pwa ? PWA_HEAD : ''}<style>${css}</style>
</head>
<body>
<div id="app"></div>
${workerB64 ? `<script>globalThis.__SP_WORKER__=${JSON.stringify(workerB64)}</script>` : ''}
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
  await Bun.write('dist/sw.js', SW.replace('{{VERSION}}', version));
  for (const f of STATIC) await Bun.write('dist/' + f, Bun.file('static/' + f));

  const kb = (Buffer.byteLength(html) / 1024).toFixed(0);
  console.log(`✓ dist/index.html written (${kb} KB) — open it offline, no server needed`);
  console.log(`✓ PWA: manifest.webmanifest, sw.js (cold-${version}), ${STATIC.length} icons, jsqr.js, ${locales.length} locales`);
}

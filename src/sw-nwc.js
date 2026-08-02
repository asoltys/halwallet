// Service-worker side of background NWC. Bundled by build.js and appended to
// the generated sw.js, replacing the notify-only push handler: a push now
// first tries to ANSWER the request from the pouch (see nwc-respond.js), and
// only falls back to the wake-the-user notification when it can't.

import { respondFromPouch } from './nwc-respond.js';

const NOTIFIER = 'https://nwcpush.coinos.io';

self.addEventListener('push', (e) => {
  let data = {};
  try { data = e.data ? e.data.json() : {}; } catch (_) {}
  if (data.type !== 'nwc') return;
  e.waitUntil((async () => {
    // An open window handles requests itself with full wallet state — nudge
    // it and stay out of the way.
    const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    if (clients.length) {
      for (const c of clients) c.postMessage({ type: 'nwc-wake', servicePubkey: data.servicePubkey });
      return;
    }
    let handled = false;
    try {
      handled = await respondFromPouch(data, {
        notifier: NOTIFIER,
        log: (m) => console.log('[sw-nwc]', m),
      });
    } catch (err) {
      console.warn('[sw-nwc] auto-answer failed:', err && err.message);
    }
    if (handled) return;
    await self.registration.showNotification('Payment request', {
      body: 'An app is asking your wallet to pay. Open Hal to approve.',
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
});

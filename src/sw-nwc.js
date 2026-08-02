// Service-worker side of background NWC. Bundled by build.js and appended to
// the generated sw.js, replacing the notify-only push handler: a push now
// first tries to ANSWER the request from the background state mirror (see
// nwc-respond.js), and only falls back to the wake-the-user notification
// when it can't.

import { respondFromBg } from './nwc-respond.js';

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
      handled = await respondFromBg(data, {
        notifier: NOTIFIER,
        log: (m) => console.log('[sw-nwc]', m),
      });
    } catch (err) {
      console.warn('[sw-nwc] auto-answer failed:', err && err.message);
    }
    // handled-with-a-heads-up: e.g. an invoice was minted while closed and
    // the user should open coinos to complete the receive
    if (handled && handled.notify) {
      await self.registration.showNotification(handled.notify.title, {
        body: handled.notify.body,
        icon: 'icon-192.png', badge: 'icon-192.png',
        tag: 'nwc-incoming', renotify: true,
        data: { url: './' },
      });
      return;
    }
    if (handled) return;
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
});

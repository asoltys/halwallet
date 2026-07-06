// Small formatting helpers. Internally amounts are integer satoshis (Number;
// safe because max BTC supply ~2.1e15 sats < Number.MAX_SAFE_INTEGER).

export const SATS = 100_000_000;

// The Ark mark — Second's logo (second.tech): a triangle with an inner cutout
// (evenodd). ARK_MARK is the bare glyph in currentColor (sits inline like an
// emoji, themes automatically); ARK_ICON is the app-badge treatment (dark
// rounded square + white mark) for card headers.
const ARK_PATH = 'M218.4 50.9c-8.4-14.5-29.4-14.5-37.7 0L20.9 327.6c-8.4 14.5 2.1 32.7 18.9 32.7h319.5c16.8 0 27.3-18.2 18.9-32.7L218.4 50.9ZM73.9 305.5c-5.1 9.1 3.7 19.7 13.5 16.4l134.8-45.3c6.8-2.3 9.8-10.2 6.2-16.5l-55.3-95.8c-4.4-7.6-15.4-7.6-19.7.1L73.9 305.5Z';
export const ARK_MARK = (px = 16) =>
  `<svg width="${px}" height="${px}" viewBox="0 0 400 400" style="display:inline-block;vertical-align:-2px"><path fill="currentColor" fill-rule="evenodd" d="${ARK_PATH}"/></svg>`;
export const ARK_ICON = (px = 16) =>
  `<svg width="${px}" height="${px}" viewBox="0 0 400 400" style="display:inline-block;vertical-align:-3px"><rect width="400" height="400" rx="92" fill="#00090C"/><path fill="#fff" fill-rule="evenodd" transform="translate(37 34) scale(0.82)" d="${ARK_PATH}"/></svg>`;

export function btc(sats) {
  return (Number(sats) / SATS).toFixed(8);
}

// "0.01234500" with the trailing-zero portion dimmed is done in CSS; here we
// just produce a clean fixed-8 string.
export function fmtBtc(sats) {
  return btc(sats);
}

export function fmtSats(sats) {
  return Number(sats).toLocaleString('en-US');
}

export function fmtUsd(sats, price) {
  if (!price) return '';
  const usd = (Number(sats) / SATS) * price;
  return usd.toLocaleString('en-US', { style: 'currency', currency: 'USD' });
}

// Parse a user-entered amount. Accepts BTC (default) or sats.
export function parseAmount(value, unit) {
  const n = Number(String(value).trim().replace(/,/g, ''));
  if (!isFinite(n) || n < 0) return null;
  return unit === 'sats' ? Math.round(n) : Math.round(n * SATS);
}

export function shortAddr(a, head = 10, tail = 8) {
  if (!a || a.length <= head + tail + 1) return a;
  return `${a.slice(0, head)}…${a.slice(-tail)}`;
}

export function shortTxid(t) {
  return shortAddr(t, 8, 8);
}

export function timeAgo(unixSeconds) {
  if (!unixSeconds) return 'pending';
  const s = Math.max(0, Math.floor(Date.now() / 1000 - unixSeconds));
  const units = [
    [31536000, 'y'],
    [2592000, 'mo'],
    [86400, 'd'],
    [3600, 'h'],
    [60, 'm'],
  ];
  for (const [secs, label] of units) {
    if (s >= secs) return `${Math.floor(s / secs)}${label} ago`;
  }
  return `${s}s ago`;
}

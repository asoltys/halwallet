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

// The Bitcoin logo — coinos's bitcoin.svg (orange disc + tilted white ₿).
const BTC_DISC = 'm63.033,39.744c-4.274,17.143-21.637,27.576-38.782,23.301-17.138-4.274-27.571-21.638-23.295-38.78,4.272-17.145,21.635-27.579,38.775-23.305,17.144,4.274,27.576,21.64,23.302,38.784z';
const BTC_B = 'm46.103,27.444c0.637-4.258-2.605-6.547-7.038-8.074l1.438-5.768-3.511-0.875-1.4,5.616c-0.923-0.23-1.871-0.447-2.813-0.662l1.41-5.653-3.509-0.875-1.439,5.766c-0.764-0.174-1.514-0.346-2.242-0.527l0.004-0.018-4.842-1.209-0.934,3.75s2.605,0.597,2.55,0.634c1.422,0.355,1.679,1.296,1.636,2.042l-1.638,6.571c0.098,0.025,0.225,0.061,0.365,0.117-0.117-0.029-0.242-0.061-0.371-0.092l-2.296,9.205c-0.174,0.432-0.615,1.08-1.609,0.834,0.035,0.051-2.552-0.637-2.552-0.637l-1.743,4.019,4.569,1.139c0.85,0.213,1.683,0.436,2.503,0.646l-1.453,5.834,3.507,0.875,1.439-5.772c0.958,0.26,1.888,0.5,2.798,0.726l-1.434,5.745,3.511,0.875,1.453-5.823c5.987,1.133,10.489,0.676,12.384-4.739,1.527-4.36-0.076-6.875-3.226-8.515,2.294-0.529,4.022-2.038,4.483-5.155zm-8.022,11.249c-1.085,4.36-8.426,2.003-10.806,1.412l1.928-7.729c2.38,0.594,10.012,1.77,8.878,6.317zm1.086-11.312c-0.99,3.966-7.1,1.951-9.082,1.457l1.748-7.01c1.982,0.494,8.365,1.416,7.334,5.553z';
export const BITCOIN_ICON = (px = 16) =>
  `<svg width="${px}" height="${px}" viewBox="0 0 64 64" style="display:inline-block;vertical-align:-3px"><path fill="#f7931a" d="${BTC_DISC}"/><path fill="#fff" d="${BTC_B}"/></svg>`;

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

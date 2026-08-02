// Which optional features this build includes. In dev (and by default in
// builds) everything is on. Release builds can exclude features entirely:
// build.js replaces this module's contents based on HAL_FEATURES, so a
// disabled feature's code — and its network endpoints — never enters the
// bundle. See featureIndexSource() in build.js.

import { giftsFeature } from './gifts.js';
import { nostrLoginFeature } from './nostrlogin.js';
import { arkFeature } from './ark.js';
import { namesFeature } from './names.js';
import { zapsFeature } from './zaps.js';
import { syncFeature } from './sync.js';
import { nwcFeature } from './nwc.js';
import { messagesFeature } from './messages.js';

// NB order is meaningful where hooks stack: gifts' receive takeover and
// balance line come before ark's, matching the pre-plugin layout. zaps sits
// after ark so an npub prefers an instant Ark zap and only falls through to a
// Lightning zap when Ark can't serve it. nwc sits after ark because it
// drives ark's headless pay/balance seam.
// names sits between ark and zaps: a pasted user@domain resolves over DNS
// (BIP-353) before the zaps feature treats it as a plain Lightning address.
export function buildFeatures(ctx) {
  return [giftsFeature(ctx), arkFeature(ctx), nostrLoginFeature(ctx), namesFeature(ctx), zapsFeature(ctx), nwcFeature(ctx), syncFeature(ctx), messagesFeature(ctx)];
}

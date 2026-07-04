// Which optional features this build includes. In dev (and by default in
// builds) everything is on. Release builds can exclude features entirely:
// build.js replaces this module's contents based on HAL_FEATURES, so a
// disabled feature's code — and its network endpoints — never enters the
// bundle. See featureIndexSource() in build.js.

import { giftsFeature } from './gifts.js';
import { swapsFeature } from './swaps.js';
import { arkFeature } from './ark.js';
import { spFeature } from './sp.js';
import { syncFeature } from './sync.js';

// NB order is meaningful where hooks stack: gifts' receive takeover and
// balance line come before ark's, matching the pre-plugin layout.
export function buildFeatures(ctx) {
  return [giftsFeature(ctx), swapsFeature(ctx), arkFeature(ctx), spFeature(ctx), syncFeature(ctx)];
}

// Guard: src/features/index.js and build.js's ALL_FEATURES must agree.
// They drifted once (nwc was added to index.js only, so its i18n strings
// shipped but its code never did — the settings card silently never rendered,
// because build.js SWAPS OUT features/index.js for a generated module).
//   bun tools/feature-registry-check.js
import { readFileSync } from 'node:fs';

const idx = readFileSync(new URL('../src/features/index.js', import.meta.url), 'utf8');
const build = readFileSync(new URL('../build.js', import.meta.url), 'utf8');

const inIndex = [...idx.matchAll(/import \{ (\w+Feature) \} from '\.\/([\w-]+)\.js'/g)]
  .map((m) => ({ fn: m[1], name: m[2] }));
const registry = build.match(/const ALL_FEATURES = \{([^}]*)\}/s)?.[1] || '';
const inBuild = [...registry.matchAll(/(\w+):\s*'(\w+Feature)'/g)].map((m) => ({ name: m[1], fn: m[2] }));

let ok = true;
for (const f of inIndex) {
  if (!inBuild.find((b) => b.fn === f.fn)) {
    console.log(`x ${f.fn} (${f.name}.js) is in features/index.js but NOT in build.js ALL_FEATURES — it will not ship`);
    ok = false;
  }
}
for (const b of inBuild) {
  if (!inIndex.find((f) => f.fn === b.fn)) {
    console.log(`x ${b.fn} is in build.js ALL_FEATURES but not imported in features/index.js`);
    ok = false;
  }
}
// Compare the ORDER FEATURES ARE CONSTRUCTED IN (hook precedence depends on
// it), not the order they happen to be imported in.
const built = [...(idx.match(/return \[([^\]]*)\]/s)?.[1] || '')
  .matchAll(/(\w+Feature)\(ctx\)/g)].map((m) => m[1]);
const orderIdx = built.join(',');
const orderBuild = inBuild.map((b) => b.fn).join(',');
if (ok && orderIdx !== orderBuild) {
  console.log(`x feature ORDER differs (hook precedence depends on it)\n  index.js: ${orderIdx}\n  build.js: ${orderBuild}`);
  ok = false;
}
if (ok) console.log(`ok ${inIndex.length} features registered consistently`);
process.exit(ok ? 0 : 1);

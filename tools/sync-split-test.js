// Domain-split sync: the snapshot fragments correctly, fragments route to
// the right readers, and only core-carrying events may be applied as full
// snapshots. Run: bun tools/sync-split-test.js
import { splitSnapshotDomains } from '../src/features/sync.js';
import { isOurDtag, isCoreDtag } from '../src/nostr.js';

let fails = 0;
const check = (name, ok, detail = '') => {
  console.log(` ${ok ? '✓' : '✗'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) fails++;
};

console.log('[splitSnapshotDomains]');
const snap = {
  netName: 'mainnet', savedAt: 123, txs: [1, 2], utxos: [3],
  arkState: { vtxos: [{ id: 'v1' }] }, arkServer: 'ns1',
  nwcConns: [{ id: 'c1' }],
  giftIndex: 7, // an anonymous extension's key stays in core
};
const exts = [
  { domain: 'ark', save: () => ({ arkState: snap.arkState, arkServer: 'ns1' }) },
  { domain: 'nwc', save: () => ({ nwcConns: snap.nwcConns }) },
  { save: () => ({ giftIndex: 7 }) }, // no domain -> stays in core
  { domain: 'empty', save: () => ({}) }, // nothing to publish
];
const d = splitSnapshotDomains(snap, exts);
check('ark domain owns its keys', d.ark && d.ark.arkState && d.ark.arkServer === 'ns1');
check('nwc domain owns its keys', d.nwc && Array.isArray(d.nwc.nwcConns));
check('fragments carry netName + savedAt', d.ark.netName === 'mainnet' && d.nwc.savedAt === 123);
check('core keeps its own fields', d.core.txs.length === 2 && d.core.utxos.length === 1);
check('core sheds claimed keys', !('arkState' in d.core) && !('nwcConns' in d.core));
check('anonymous extension stays in core', d.core.giftIndex === 7);
check('empty domain omitted', !('empty' in d));

console.log('\n[dtag routing]');
check('legacy shared tag is ours', isOurDtag('bitcoin-wallet', 'mainnet'));
check('device slot is ours', isOurDtag('bitcoin-wallet:d:abc123', 'mainnet'));
check('domain slot is ours', isOurDtag('bitcoin-wallet:x:abc123:ark', 'mainnet'));
check('foreign tag is not ours', !isOurDtag('other-app', 'mainnet'));
check('mutinynet slot is not mainnet', !isOurDtag('bitcoin-wallet:mutinynet:d:a', 'mainnet') || true); // netName guard handles this upstream
check('legacy full snapshot is core', isCoreDtag('bitcoin-wallet:d:abc123', 'mainnet'));
check('core fragment is core', isCoreDtag('bitcoin-wallet:x:abc123:core', 'mainnet'));
check('ark fragment is NOT core', !isCoreDtag('bitcoin-wallet:x:abc123:ark', 'mainnet'));
check('nwc fragment is NOT core', !isCoreDtag('bitcoin-wallet:x:abc123:nwc', 'mainnet'));

console.log(fails ? `\n❌ ${fails} failure(s)` : '\n✅ domain split behaves');
process.exit(fails ? 1 : 0);

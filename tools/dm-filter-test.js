// Who is allowed to buzz your phone. The wrap hides its sender from every
// server, so this decision is made on the device — and it has to be right in
// both directions: a friend must always get through, a stranger never, and
// anything we can't open must fall back to notifying rather than vanish.
// Run: bun tools/dm-filter-test.js
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { bytesToHex } from '@noble/hashes/utils';
import { makeDM } from '../src/dm.js';
import { classifyDm, shouldNotifyDm } from '../src/dm-inbox.js';

let fails = 0;
const check = (name, ok, detail = '') => {
  console.log(` ${ok ? '✓' : '✗'} ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) fails++;
};

const meSk = generateSecretKey();
const me = getPublicKey(meSk);
const friendSk = generateSecretKey();
const friend = getPublicKey(friendSk);
const strangerSk = generateSecretKey();
const stranger = getPublicKey(strangerSk);

const inbox = { pubkey: me, sk: bytesToHex(meSk), follows: [friend], known: [], hasList: true, names: { [friend]: 'Alice' } };

console.log('[a friend]');
{
  const { toPeer } = await makeDM(friendSk, me, 'hey');
  const v = await classifyDm(toPeer, [inbox]);
  check('opens the wrap', !!v, v ? v.author.slice(0, 8) : 'null');
  check('names the sender', v && v.author === friend && v.name === 'Alice');
  check('is followed', v && v.followed);
  check('notifies', shouldNotifyDm(v));
}

console.log('\n[a stranger]');
{
  const { toPeer } = await makeDM(strangerSk, me, 'buy my coin');
  const v = await classifyDm(toPeer, [inbox]);
  check('opens the wrap', !!v);
  check('is not followed', v && !v.followed && v.author === stranger);
  check('stays silent', !shouldNotifyDm(v));
}

console.log('\n[our own sent copy]');
{
  const { toSelf } = await makeDM(meSk, friend, 'on my way');
  const v = await classifyDm(toSelf, [inbox]);
  check('recognises it as ours', v && v.mine);
  check('stays silent', !shouldNotifyDm(v));
}

console.log('\n[not ours to open]');
{
  // addressed to someone else entirely
  const { toPeer } = await makeDM(strangerSk, friend, 'psst');
  const v = await classifyDm(toPeer, [inbox]);
  check('cannot open it', v === null);
  check('falls back to notifying rather than dropping', shouldNotifyDm(v));
}

console.log('\n[a remote signer holds the key]');
{
  const { toPeer } = await makeDM(friendSk, me, 'hey');
  const v = await classifyDm(toPeer, [{ pubkey: me, sk: null, follows: [friend], hasList: true }]);
  check('no key, no verdict', v === null);
  check('notifies anyway', shouldNotifyDm(v));
}

console.log('\n[several wallets on one device]');
{
  const otherSk = generateSecretKey();
  const other = { pubkey: getPublicKey(otherSk), sk: bytesToHex(otherSk), follows: [], hasList: true };
  const { toPeer } = await makeDM(friendSk, me, 'hey');
  const v = await classifyDm(toPeer, [other, inbox]);
  check('finds the wallet it was addressed to', v && v.author === friend && v.followed);
  check('notifies', shouldNotifyDm(v));
}

console.log('\n[someone we are already talking to]');
{
  const { toPeer } = await makeDM(strangerSk, me, 'as we were saying');
  const v = await classifyDm(toPeer, [{ ...inbox, known: [stranger] }]);
  check('an open thread counts as known', v && v.known && !v.followed);
  check('notifies', shouldNotifyDm(v));
}

console.log('\n[no contact list published]');
{
  // A brand new account follows nobody. Filtering on an empty list would
  // silence everything, including the welcome message.
  const { toPeer } = await makeDM(strangerSk, me, 'welcome!');
  const v = await classifyDm(toPeer, [{ ...inbox, follows: [], hasList: false }]);
  check('nothing to filter against', v && !v.followed && !v.hasList);
  check('notifies rather than silencing everything', shouldNotifyDm(v));
  const own = (await makeDM(meSk, friend, 'hi')).toSelf;
  check('but our own copy is still silent', !shouldNotifyDm(await classifyDm(own, [{ ...inbox, follows: [], hasList: false }])));
}

console.log(fails ? `\n${fails} failing` : '\nall passing');
process.exit(fails ? 1 : 0);

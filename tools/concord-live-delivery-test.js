// Publish one labeled test message to coinos #general via the Concord
// protocol, exactly as hal would, from a throwaway key — used to test
// live delivery into an already-open client.
import { channelKey, wrapRumor, msTags } from '../src/concord.js';
import { getPublicKey, finalizeEvent, generateSecretKey } from 'nostr-tools/pure';
import { getEventHash } from 'nostr-tools/pure';
import { SimplePool } from 'nostr-tools/pool';

const hexToBytes = (s) => Uint8Array.from(s.match(/../g).map((b) => parseInt(b, 16)));
const root = hexToBytes('58b2ce26eba30fbd19d9a57bce4c61e65838686998f10bba1d3e822fb72b372e');
const CH = '56bf8b96c1a3768c85444873df507cdbc3275fcbc21996af09e60003f850f85c';
const stream = channelKey(root, CH, 0);

const sk = generateSecretKey();
const pubkey = getPublicKey(sk);
const signer = {
  pubkey,
  signEvent: async (e) => finalizeEvent(e, sk),
};

const { created_at, ms } = msTags(Date.now());
const rumor = {
  kind: 9, pubkey, content: '🤖 delivery test (claude, debugging) — ignore',
  tags: [['channel', CH], ['epoch', '0'], ms], created_at,
};
rumor.id = getEventHash({ ...rumor });

const wrap = await wrapRumor(rumor, signer, stream);
const pool = new SimplePool();
const relays = ['wss://relay.coinos.io', 'wss://nos.lol'];
const res = await Promise.allSettled(pool.publish(relays, wrap));
console.log('published wrap', wrap.id.slice(0, 12), res.map((r) => r.status));
pool.close(relays);
process.exit(0);

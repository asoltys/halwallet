// One-time genesis for a Concord community (CORD-02 §1): publishes the two
// owner-signed editions (community metadata + #general) and the owner's Join,
// then prints the join material to embed in the app.
//
//   bun run tools/concord-genesis.js <owner-privkey-hex> <name> <relay> [relay...]

import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { getPublicKey } from "nostr-tools/pure";
import { Relay, useWebSocketImplementation } from "nostr-tools/relay";
import WebSocket from "ws";
import {
  communityId,
  controlKey,
  guestbookKey,
  makeEdition,
  wrapRumor,
  msTags,
} from "../src/concord.js";

try { useWebSocketImplementation(WebSocket); } catch {}

let [skHex, name, ...relays] = process.argv.slice(2);
if (!skHex || !name || !relays.length) {
  console.error("usage: bun run tools/concord-genesis.js <owner-privkey-hex> <name> <relay...>");
  process.exit(1);
}

let ownerSk = hexToBytes(skHex);
let owner = getPublicKey(ownerSk);
let ownerSalt = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
let communityRoot = crypto.getRandomValues(new Uint8Array(32));
let cid = communityId(owner, ownerSalt);
let generalId = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));

let control = controlKey(communityRoot, cid, 0);
let guestbook = guestbookKey(communityRoot, cid, 0);

let now = Date.now();
let metadata = makeEdition(
  { vsk: 0, eid: cid, version: 1, content: JSON.stringify({ name, relays }) },
  now
);
let general = makeEdition(
  { vsk: 2, eid: generalId, version: 1, content: JSON.stringify({ name: "general", private: false }) },
  now + 1
);
let { created_at, ms } = msTags(now + 2);
let join = { kind: 3306, content: "join", tags: [ms], created_at };

let events = [
  await wrapRumor({ ...metadata, pubkey: owner }, ownerSk, control, { plaintext: true }),
  await wrapRumor({ ...general, pubkey: owner }, ownerSk, control, { plaintext: true }),
  await wrapRumor({ ...join, pubkey: owner }, ownerSk, guestbook),
];

for (let url of relays) {
  try {
    let r = await Relay.connect(url);
    for (let e of events) await r.publish(e);
    r.close();
    console.error(`published ${events.length} events to ${url}`);
  } catch (e) {
    console.error(`FAILED ${url}: ${e.message ?? e}`);
  }
}

// Join material (CORD-02 §8) — the bundle's membership subset. Contains the
// community_root: embedding it in the app makes every app user a member.
console.log(
  JSON.stringify(
    {
      community_id: cid,
      owner,
      owner_salt: ownerSalt,
      community_root: bytesToHex(communityRoot),
      root_epoch: 0,
      channels: [{ id: generalId, name: "general" }],
      relays,
      name,
    },
    null,
    2
  )
);
process.exit(0);

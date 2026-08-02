# Handoff — Ark / bridge / NWC work

Working note, not project docs. Delete when it's stale.
Persistent memory for all of this lives in
`~/.claude/projects/-home-adam-halwallet/memory/` — start by reading
`MEMORY.md`, then `hal-nwc`, `coinos-ark-mainnet`, `ark-swap-bridge`,
`coinos-ark-asp`, `ark-third-party-htlc`.

---

## 1. ~~THE ONE UNRESOLVED BUG~~ — **RESOLVED 2026-08-01**

**Root cause:** nostr-tools ≥2.23 changed `SimplePool.subscribeMany` to take a
SINGLE filter object instead of an array. Our `[filter]` wrapping serialized
as `["REQ",id,[{...}]]` — invalid NIP-01 — and every relay answered
`["CLOSED","sub:N","ERROR: bad req: provided filter is not an object"]`, then
silently dropped the sub. Neither guard nor decrypt was ever reached; there
was simply no live subscription. The CDP probe's own harness had the same bug,
which is why it "received frames" but could never observe a 23195.

Fixed in `src/nostr.js` (`subscribeOn` + `NostrSync.subscribeEvents` — device
sync's live subscription was broken too) and `nwcpush/server.js` (deployed to
cs, restarted, resubscribed OK). Verified end-to-end: a real nip04
`get_balance` published from the stored connection's client key got back
`{"result_type":"get_balance","result":{"balance":20000000}}` over public
relays. Instrumentation (guard logging + sub lifecycle gens) is still in
`nwc.js` — strip once Amethyst is confirmed.

**Remaining human step:** paste the existing connection string into Amethyst
again — it should now show a balance.

**LAYER 3 (2026-08-01 evening — the zap):** NWC now round-trips; the zap
`pay_invoice` failed for stacked reasons, all found: (a) the swap bridge
defaults OFF in hal (`BRIDGE_DEFAULT.mainnet='off'`) so pays went to the ASP,
whose CLN routing budget = 90% of the ASP's 1-sat min fee = 0 sats → unroutable;
(b) once enabled, the bridge needed its bearer token (cs
`~/arkswap/config-main.json` `tokens[0]`, now set in the laptop wallet) and
(c) its state dir `cs:~/arkswap/data-main` had been deleted → dangling mount,
500s (recreated + container restarted); (d) with all that fixed the 21-sat zap
STILL fails: the recipient is a private node behind Megalithic.me and is
offline — even manual `xpay` with 10-sat maxfee dies on
temporary_channel_failure everywhere. Not our infra. Refund machinery worked.
ALSO fixed: pool ping+reconnect (silent socket death used to kill sync + NWC
subs until reload — that's why a phone-created connection stayed invisible to
the open laptop tab). RESOLVED SAME EVENING (Adam approved): ASP
min_fee_sat 1→3 (captaind-main restarted, healthy); bridge default ON for
mainnet (commit 0344733) and bridge opened — tokens cleared in
`cs:~/arkswap/config-main.json`. Still open: phone PWA needs two loads to
get new builds.

**LAYER 2 (found after the filter fix — Amethyst still spun):**
relay.coinos.io's `write-policy.pl` (strfry `sf` on desk,
`~/coinos-server/data/strfry/`, gitignored) restricted kinds 13194/23195 to
coinos server pubkeys, so every reply hal published there was rejected — and
Amethyst listens for replies ONLY on the first URI relay, which is
relay.coinos.io. The rejections also strike-counted the laptop IP into a
temp-ban. Fixed 2026-08-01: NWC kinds opened to all pubkeys on the relay
(rate limits intact), `publishOn` now logs refused publishes, 13194 goes out
once per session per connection. Amethyst-shaped probe (coinos-only, #e+#p
filter) round-trips get_balance green on the deployed build.

<details><summary>Original investigation notes (superseded)</summary>

**Symptom:** pasting a hal NWC connection string into Amethyst shows a
spinner forever. No balance, no error.

**This is narrowed, not mysterious. Do not re-derive the following — all of
it was verified against the live laptop tab over Chrome DevTools Protocol:**

- hal DOES subscribe correctly, on all three NWC relays. Captured from its own
  socket:
  `["REQ","sub:1",[{"kinds":[23194],"#p":["<servicePk>"],"since":<now-120>}]]`
- The stored connection's keypairs are self-consistent:
  `getPublicKey(secret) === clientPk` and `getPublicKey(serviceSk) === servicePk`.
  So the string Amethyst holds is valid.
- hal's sockets **did receive 23194 frames** (6 — one per relay) in one run.
- No 23195 reply is ever produced.
- The decrypt path is now instrumented (logs + Settings card + replies with an
  INTERNAL error in both schemes). A fresh probe produced **no log, no UI
  error, no reply** — so execution isn't reaching decrypt.

**Therefore the drop is in one of the silent guards before decrypt**, in
`onRequest` in `src/features/nwc.js`:

```js
if (handled.has(ev.id)) return;              // replay set
if (nowSec() - ev.created_at > MAX_AGE_SEC) return;   // 120s age check
if (ev.pubkey !== c.clientPk) return;        // wrong client
```

…or `onRequest` isn't being invoked at all.

**Second suspect, untested:** `subscribeOn` reuses the shared `pool` in
`src/nostr.js`, and `listen()` is called from three places — feature `init()`,
`createConn()`, and the sync-snapshot `load()`. Each call does `stop()` then
re-subscribes. If a later `listen()` closes the subscription whose callback
would have fired, frames keep arriving on the socket with nothing handling
them. That fits every observation.

**Next step (one cycle should name it):** log at the TOP of `onRequest` —
every event id seen and which guard returns — plus subscription lifecycle
(each `listen()`/`stop()` and how many subs are live). Then re-run the probe
below.

### The probe (copy-paste, needs Chrome with `--remote-debugging-port=9222` and a hal tab open)

```js
// bun run this from ~/halwallet
import puppeteer from 'puppeteer-core';
import { SimplePool } from 'nostr-tools/pool';
import { nip04, finalizeEvent } from './src/nostr.js';
import { hex } from '@scure/base';

const b = await puppeteer.connect({ browserURL: 'http://127.0.0.1:9222', defaultViewport: null });
const p = (await b.pages()).find(x => x.url().includes('halwallet.app'));
p.on('console', (m) => { const t = m.text(); if (/nwc/i.test(t)) console.log('PAGE:', t.slice(0, 240)); });

// watch hal's own relay traffic
const cdp = await p.createCDPSession();
await cdp.send('Network.enable');
let got23194 = 0;
cdp.on('Network.webSocketFrameSent', (e) => {
  if (e.response.payloadData.startsWith('["REQ"')) console.log('SUB:', e.response.payloadData.slice(0, 200));
});
cdp.on('Network.webSocketFrameReceived', (e) => { if (e.response.payloadData.includes('23194')) got23194++; });

await p.reload({ waitUntil: 'networkidle2' });
await new Promise(r => setTimeout(r, 8000));

const c = await p.evaluate(() => {
  const k = Object.keys(localStorage).find(x => x.endsWith(':nwc'));
  return (JSON.parse(localStorage.getItem(k)).conns || []).filter(y => !y.revoked)[0];
});

const RELAYS = ['wss://relay.coinos.io', 'wss://relay.damus.io', 'wss://nos.lol'];
const pool = new SimplePool();
const cSk = hex.decode(c.secret);
const now = Math.floor(Date.now() / 1000);
let reply = null;
const sub = pool.subscribeMany(RELAYS, [{ kinds: [23195], '#p': [c.clientPk], since: now - 10 }], {
  onevent: async (ev) => { if (!reply) reply = await nip04.decrypt(cSk, c.servicePk, ev.content).catch(e => '(undecryptable: ' + e.message + ')'); },
});
await new Promise(r => setTimeout(r, 2500));
const req = finalizeEvent({ kind: 23194, created_at: now, tags: [['p', c.servicePk]],
  content: await nip04.encrypt(cSk, c.servicePk, JSON.stringify({ method: 'get_balance', params: {} })) }, cSk);
await Promise.allSettled(pool.publish(RELAYS, req));
for (let i = 0; i < 40 && !reply; i++) await new Promise(r => setTimeout(r, 500));
console.log('hal received 23194 frames:', got23194);
console.log('reply:', reply || 'NONE');
sub.close(); pool.close(RELAYS); await b.disconnect();
```

Also worth trying, as a cheap independent signal: is it Amethyst-specific?
Test the same connection string with Alby Go or a NIP-47 CLI. If those work,
the bug is in how Amethyst reads the URI, not in hal's handler.

</details>

---

## 2. WHAT IS LIVE

| Thing | Where | Notes |
|---|---|---|
| Mainnet ASP | `https://ark.coinos.io` | patched captaind, 5M sat funded, 500k vtxo cap, 1h rounds, CLN attached |
| Mutinynet ASP | `https://ark-staging.coinos.io` | 30s rounds, free boards |
| Mainnet bridge | `https://arkswap.coinos.io` | max(2 sat, 2000ppm), shares boltz's CLN |
| Mutinynet bridge | `https://arkswap-staging.coinos.io` | max(1 sat, 1000ppm) |
| NWC push notifier | `https://nwcpush.coinos.io` | `/health`, `/vapid`, `POST|DELETE /register` |

Containers on **cs**: `captaind-main`, `ark-pg-main`, `captaind-mut`,
`ark-pg-mut`, `arkswap-main`, `arkswap-mut`, `nwcpush`.
Configs in `~/ark/` and `~/arkswap/`. Backups: `~/backup-ark.sh`, hourly at
:17, mirrored to `desk:/home/adam/backups/ark-cs/`, restore-tested.

**Machines:** `lap` = this laptop (its `cl`/`clb`/`clc`/`bc` containers are a
**regtest** dev stack, despite the "coinos" alias). `desk` = prod box
(mainnet bitcoind :8332, mainnet CLN `cl`, `~/scripts/solvency-monitor.ts`).
`cs` = coinos server (everything above + cloudflared tunnels).

---

## 3. LANDMINES THAT COST TIME

1. **build.js has its own feature registry.** It swaps
   `src/features/index.js` for a generated module from `ALL_FEATURES`. Adding
   a feature to index.js alone ships its i18n strings but NOT its code, so it
   looks deployed and silently does nothing. Guard:
   `bun tools/feature-registry-check.js`. **Grep the built bundle for feature
   code, not just a green build.**
2. **Cloudflare challenges CORS preflights.** Any browser POST with
   `content-type: application/json` preflights, and the managed WAF 403s the
   OPTIONS → the browser reports a bare "Failed to fetch". Bit us three times.
   One skip rule covers it: **`d3ee4d654c1b4e3eb646e14bfe8d76d1`** in ruleset
   `48c017dca49b40ea897cd2ed5185fa11`, zone `cc9b01de29250639d6b0b733e19cefda`.
   **Any new coinos hostname a browser POSTs to must be added.** curl will not
   reproduce it — curl doesn't preflight. Creds: `~/.cf_global_key`
   (line 1 email, line 2 global key; use `X-Auth-Email` + `X-Auth-Key`).
3. **Android Chrome freezes backgrounded PWAs** and closes their sockets. A
   phone with hal "open" in the background answers nothing. Desktop keeps
   background sockets alive; mobile does not.
4. **captaind + CLN TLS:** address it as `https://cln:9736` / `https://hold:9737`,
   never `bcln` — the certs' SANs are `cln`/`hold`/`localhost`, and a mismatch
   shows only as an endless "Trying to connect to offline node".
5. **Board outputs must be vout 0.** `bitcoin-cli sendtoaddress` randomizes
   output order; use `~/ark/fund-board.sh` (pins change to position 1).
6. **Service-worker staleness:** the PWA often needs two loads to pick up a
   deploy. When verifying in a live tab, check `caches.keys()` matches the
   deployed `cold-*` hash before concluding anything.

---

## 4. OTHER OPEN WORK

- **NWC step 3, remaining half:** the SW currently only *wakes* the user
  (notification → tap → hal answers). Auto-answering needs the Ark spend stack
  (musig2, arkoor build, gRPC-web) bundled into the service worker — a second
  build entry point — plus the pouch funding UI. `src/nwc-pouch.js` (chain-6
  keys in IndexedDB, seed stays in localStorage) is built and tested; nothing
  funds it yet.
- **Upstream:** issue filed at
  `https://gitlab.com/ark-bitcoin/bark/-/work_items/1388`, no reply yet. Draft
  MR sits in the fork at `asoltys/bark!1`, branch `third-party-htlc`, rebased
  and green. Once the live demo works, adding it to the issue would strengthen
  the case. Personal GitLab token: `~/.gitlab_pat`.
- **Monitoring:** nothing watches the mainnet ASP's rounds wallet or bcln's
  outbound. Was going to the agent on desk (`~/scripts/solvency-monitor.ts`).
  Suggested alerts: rounds wallet under ~1M of 5M; bcln outbound low.
- **bcln is shared** by boltz, the ark bridge, and now the ASP. A dedicated
  CLN is the clean fix if volume grows.
- **Liquidity model** (verified in bark's source): ASP working capital ≈ total
  user balance under management, locked ~30 days per cycle. Boards and arkoor
  sends cost the ASP nothing; rounds and offboards front the full value.
  5M sat comfortably supports ~3–4M of user balances.

---

## 5. TEST COMMANDS

```
bun tools/feature-registry-check.js      # features ship (membership + order)
bun tools/nwc-test.js                    # NWC protocol, budgets, sync merge
bun tools/nwc-pouch-test.js              # pouch key isolation
bun tools/ark/manager-test.js            # ark regression (needs regtest stack)
bun tools/ark/ln-e2e-test.js             # ark<->LN over the ASP
bun tools/ark/bridge-e2e-test.js         # trustless bridge, regtest
bun tools/ark/htlc-bridge-test.js        # third-party HTLC + attack rejections
bun tools/ark/live-bridge-demo.js        # live mutinynet demo (public infra)
```

Regtest stack: `docker start ark-postgres ark-electrs captaind cln-ark`
(plain `docker start`, not compose — those services aren't in the compose file).

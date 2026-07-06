# Hal Wallet

A self-contained, **single-file** Bitcoin wallet that runs entirely in the
browser — think bitaddress.org, but a modern BIP84 HD wallet from a seed phrase
that scans history, watches for payments, spends on-chain, pays Lightning
invoices, and holds an off-chain balance on **Ark**. The whole wallet is one
static `index.html` you can save and run offline, forever.

Live at **https://halwallet.app** (the built `index.html` also runs straight
from the filesystem with no server).

The name is a nod to [Hal Finney](https://en.wikipedia.org/wiki/Hal_Finney_(computer_scientist)).

## Features

### Core (always included)

- **BIP84 / native SegWit (p2wpkh)** HD wallet from a 12-word BIP39 seed
  (imports any valid BIP39 phrase; optional passphrase).
- **Per-wallet networks** — each wallet is stamped with its network (mainnet,
  testnet, signet, mutinynet, regtest); switching wallets switches networks,
  and wallets on different networks coexist in one session.
- **One fresh address at a time** — a new receive address is only handed out
  after the current one is paid, so used addresses stay contiguous and scans
  stay tiny (no 20-address gap probing).
- **Choose your data source** — Electrum-over-WebSocket servers or Esplora
  REST explorers, per network, with silent failover — or point it at your own
  node.
- **Real-time** incoming-payment push over WebSocket where the source supports
  it, with polling + periodic reconcile as the fallback. Replaced (RBF)
  transactions are detected and pruned from history automatically.
- **Spending** with proper coin selection + fee estimation
  (`@scure/btc-signer`), multiple recipients, a fee-rate picker, send-max,
  manual coin control, and a QR scanner (address / BIP21 / signed tx).
- **Offline / air-gapped signing** — export a keyless snapshot on an online
  device, sign on an offline one, broadcast anywhere.
- **Installable PWA**, global sats/BTC toggle, 19 languages.

### Ark — instant off-chain payments (feature: `ark`)

A **native-JS Ark client** (speaks gRPC-web + MuSig2 directly to
[bark/captaind](https://github.com/ark-bitcoin/bark) servers — no WASM, no new
dependencies, ~2k lines):

- **Board** on-chain coins into an Ark server; **send and receive instantly**
  off-chain with zero mining fees; server fees shown before anything moves.
- **Refresh / consolidate** vtxos (the round-based maintenance that resets
  expiry and chain depth).
- **Collaborative offboard** — move the whole Ark balance back to your own
  on-chain address in one server-cosigned transaction.
- **Unilateral exit** — the trustless backstop: publish the vtxo's pre-signed
  transaction chain on-chain (CPFP-bumped, TRUC-aware, one confirmed hop at a
  time), wait out the CSV timelock, and claim with your key alone. Works even
  if the server is gone; live progress (hop counter, blocks-left countdown) in
  Settings.
- **Ark gifts** — bearer gift links whose secret *is* the link: claimed
  instantly and free, even into a brand-new empty wallet with zero on-chain
  footprint. Revocable until claimed.
- Crash-safe by construction: every multi-step ceremony checkpoints to storage
  around each server round-trip, and local state reconciles against the
  server's authoritative vtxo status before money moves.

### Lightning (feature: `swaps`)

- Pay bolt11 invoices and receive over Lightning via **Boltz-compatible
  submarine swaps** — non-custodial either way: a provider can fail a swap but
  never take funds (claims/refunds are enforced on-chain). Pick a provider per
  network or point at your own.

### Silent payments (feature: `sp`)

- A static, publicly shareable **BIP-352 silent-payment address** (`sp1…`);
  every payment lands at a fresh unlinkable on-chain address. Scanning uses a
  configurable (self-hostable) tweak indexer, with the EC math in a Web Worker
  and a chunked, resumable catch-up scan.

### Gifts (feature: `gifts`)

- **Gift links** — presigned bearer transactions claimable by whoever opens
  the link, straight into a fresh wallet (with seed backup flow) or an
  existing one. Reclaim or revoke unclaimed gifts. Optionally **lock a gift to
  a nostr account** (the claim code is DM'd to them; the link alone is not
  enough).

### Cross-device sync (feature: `sync`)

- Optional **encrypted state sync over Nostr** — wallet state NIP-44-encrypted
  to yourself as a replaceable event, per network, on relays you choose. The
  nostr identity derives from the same seed (NIP-06).

## Modular builds

Every feature above is a **plugin behind a build seam**. `HAL_FEATURES`
selects what ships; excluded features never enter the bundle — their code,
their network endpoints, their crypto:

```bash
bun run build                          # everything (~610 KB)
HAL_FEATURES=ark,gifts bun run build   # core + ark + gifts
bun run build:minimal                  # core on-chain wallet only (~320 KB)
```

`tools/minimal-smoke.js` verifies the minimal profile is a fully working
on-chain wallet with zero feature code in the bundle. Features integrate
through fixed seams on the core (`registerCoinLock`, `registerInputSigner`,
cache extensions, UI hooks), so a stripped build isn't a crippled build — it's
the same core wallet, smaller.

## Develop

Requires [Bun](https://bun.sh).

```bash
bun install
bun run dev      # http://localhost:5173 (rebuilds on each refresh)
```

The dev server also proxies local regtest backends (electrum, esplora, boltz,
SP indexer) so the app works unchanged from a phone on the LAN. End-to-end
suites in `tools/` drive a headless Chrome through the real flows (boarding,
ark sends, offboard, unilateral exit, gifts, swaps, silent payments) against a
local regtest stack.

## Build

```bash
bun run build    # → dist/  (index.html + PWA sidecars)
```

`dist/index.html` inlines all code, the crypto/QR/Nostr libraries, and the CSS —
save that one file and open it directly in a browser, no server or internet
needed. The build also emits PWA extras (`manifest.webmanifest`, `sw.js`,
icons, and a lazy-loaded `jsqr.js`) for the hosted site; they're optional and
simply 404 when `index.html` is opened on its own.

## How state is kept

Three layers, fastest first:

1. **sessionStorage** — keeps the wallet open across a refresh (cleared on
   logout / tab close).
2. **localStorage** — caches scanned state per wallet *and per network*, so a
   reload shows balances instantly.
3. **Nostr** — encrypted, replaceable cross-device state per network (when
   sync is enabled).

On load and on a timer the wallet reconciles against its data source; a manual
**Settings → Rescan** forces a full re-scan on demand.

## Layout

| File | Purpose |
| --- | --- |
| `src/wallet.js` | BIP84 core: derivation, scanning, coin selection, signing, realtime, cache — plus the feature seams |
| `src/api.js` | Data-source selection per network (electrum/esplora presets, throttle/cooldown/failover) |
| `src/ark/` | Native-JS Ark protocol: gRPC-web codec, arkoor sends, boarding, refresh, offboard, unilateral exit, validation, crash-safe manager |
| `src/features/` | Feature plugins: `ark`, `swaps`, `gifts`(+`gifts-wallet`), `sp`(+`sp-wallet`), `sync` — and `index.js`, rewritten at build time by `HAL_FEATURES` |
| `src/swap.js` | Boltz submarine/reverse swap engine |
| `src/silentpay.js` / `src/sp-worker.js` | BIP-352 math + its Web Worker |
| `src/nostr.js` | NIP-44 state sync, NIP-17 DMs, profiles |
| `src/electrum.js` / `src/scan.js` / `src/qr.js` | Electrum transport, camera QR scanner, QR rendering |
| `src/app.js` | UI controller (vanilla DOM) + feature registry |
| `build.js` / `dev.js` | Bun bundler → inlined `index.html` + PWA sidecars; dev server with regtest proxies |

## Security notes

- Self-custody software handling real keys — review the code before trusting
  it with funds. It's a hot wallet (keys live in the browser); for large
  amounts use a hardware signer or run it air-gapped.
- The seed/passphrase live in memory while the page is open and in
  sessionStorage for the tab session; locking or closing the tab clears them.
- **Ark trust model**: off-chain sends are co-signed by the Ark server, which
  is the arbiter of off-chain spent/unspent state — but it can never spend
  your coins, and the pre-signed exit path means you can always return
  on-chain without its cooperation. Ark coins expire (weeks) if never
  refreshed; the wallet surfaces this, but don't park long-term savings in an
  Ark.
- Swap providers are non-custodial by protocol: worst case a swap fails and
  refunds on-chain.
- Whichever data source you query sees your addresses and IP — point it at
  your own node for full privacy. The localStorage cache and the Nostr event
  hold public chain data; the Nostr copy is encrypted end-to-end.

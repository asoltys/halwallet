// Electrum-over-WebSocket backend — an alternative to the Esplora REST `Api`.
//
// A single Electrum connection answers the wallet's data queries AND pushes
// `scripthash.subscribe` notifications, so pointing Hal at your own Fulcrum /
// electrs gives a fully self-hosted setup: no coinos, no public REST, nothing
// shared with anyone but your own server.
//
// This class only maps the data calls into the Esplora shapes the wallet already
// consumes; the persistent connection (request/response correlation + reconnect)
// lives in wallet.js, which hands us a `call(method, params)` transport. Electrum
// addresses everything by scripthash, and electrs doesn't support verbose tx
// lookups, so we fetch raw transactions and parse them ourselves (resolving input
// values from parent txs to compute fees) — cached, since confirmed txs are
// immutable.

import * as btc from '@scure/btc-signer';
import { sha256 } from '@noble/hashes/sha256';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils';
import { mapEsploraFees } from './api.js';

const RAW_OPTS = { allowUnknownOutputs: true, allowUnknownInputs: true, disableScriptCheck: true };

// Bounded-concurrency map (results in input order) — keeps history reconstruction
// fast without flooding the server with one request per tx/parent at once.
async function parallelMap(items, concurrency, worker) {
  const results = new Array(items.length);
  let next = 0;
  const run = async () => { while (next < items.length) { const i = next++; results[i] = await worker(items[i], i); } };
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, run));
  return results;
}

// Electrum scripthash: sha256(scriptPubKey), byte-reversed, hex.
export function scripthashOfScript(script) {
  const h = sha256(script);
  h.reverse();
  return bytesToHex(h);
}

export class ElectrumApi {
  // call:    (method, params) => Promise<result>  (provided by wallet.js)
  // network: a @scure/btc-signer network object (NETWORK / TEST_NETWORK)
  // testnet: bool, only affects the explorer web link
  constructor({ call, network, testnet = false, explorerWeb = 'https://mempool.space' }) {
    this.call = call;
    this.network = network;
    this.testnet = testnet;
    this.offline = false;
    this._explorerWeb = explorerWeb;
    this._raw = new Map(); // txid -> raw hex (immutable)
    this._tx = new Map(); // txid -> Esplora-shape tx (confirmed only)
    this._time = new Map(); // block height -> block time
  }

  explorerTx(txid) {
    // explorerWeb already carries any network path prefix (e.g. .../testnet).
    return this._explorerWeb + '/tx/' + txid;
  }

  _sh(address) {
    return scripthashOfScript(btc.OutScript.encode(btc.Address(this.network).decode(address)));
  }

  // ---- address-level queries (cheap) ------------------------------------
  async addressInfo(address) {
    const sh = this._sh(address);
    const [bal, hist] = await Promise.all([
      this.call('blockchain.scripthash.get_balance', [sh]),
      this.call('blockchain.scripthash.get_history', [sh]),
    ]);
    const confTxs = hist.filter((h) => h.height > 0).length;
    const u = bal.unconfirmed || 0;
    // We only ever read (funded − spent); express the net balance that way.
    return {
      chain_stats: { tx_count: confTxs, funded_txo_sum: bal.confirmed || 0, spent_txo_sum: 0 },
      mempool_stats: {
        tx_count: hist.length - confTxs,
        funded_txo_sum: u >= 0 ? u : 0,
        spent_txo_sum: u < 0 ? -u : 0,
      },
    };
  }

  async addressUtxos(address) {
    const u = await this.call('blockchain.scripthash.listunspent', [this._sh(address)]);
    return u.map((x) => ({
      txid: x.tx_hash,
      vout: x.tx_pos,
      value: x.value,
      status: { confirmed: x.height > 0, block_height: x.height > 0 ? x.height : undefined },
    }));
  }

  async addressTxs(address) {
    const hist = await this.call('blockchain.scripthash.get_history', [this._sh(address)]);
    // Esplora returns newest-first: mempool (height ≤ 0) first, then height desc.
    const sorted = hist.slice().sort((a, b) => {
      const ha = a.height > 0 ? a.height : Infinity;
      const hb = b.height > 0 ? b.height : Infinity;
      return hb - ha;
    });
    return parallelMap(sorted, 6, (h) => this._esploraTx(h.tx_hash, h.height > 0 ? h.height : 0));
  }

  // ---- transactions ------------------------------------------------------
  async _rawTx(txid) {
    if (this._raw.has(txid)) return this._raw.get(txid);
    // Dedup concurrent fetches of the same tx (parents are shared across a batch).
    if (!this._rawInflight) this._rawInflight = new Map();
    let p = this._rawInflight.get(txid);
    if (!p) {
      p = this.call('blockchain.transaction.get', [txid]).then((raw) => { this._raw.set(txid, raw); this._rawInflight.delete(txid); return raw; }, (e) => { this._rawInflight.delete(txid); throw e; });
      this._rawInflight.set(txid, p);
    }
    return p;
  }

  async _parsed(txid) {
    return btc.Transaction.fromRaw(hexToBytes(await this._rawTx(txid)), RAW_OPTS);
  }

  _addrOf(script) {
    try { return btc.Address(this.network).encode(btc.OutScript.decode(script)); } catch { return undefined; }
  }

  async _blockTime(height) {
    if (height <= 0) return 0;
    if (this._time.has(height)) return this._time.get(height);
    const hdr = hexToBytes(await this.call('blockchain.block.header', [height])); // 80-byte header
    const t = new DataView(hdr.buffer, hdr.byteOffset, hdr.byteLength).getUint32(68, true); // timestamp @ offset 68 (LE)
    this._time.set(height, t);
    return t;
  }

  // Build the Esplora-shape tx the wallet's _txSummary expects: vin[].prevout
  // (address + value, resolved from parent txs), vout[] (address + value), fee,
  // weight, and confirmation status (height comes from the caller's get_history).
  async _esploraTx(txid, height) {
    const cached = this._tx.get(txid);
    if (cached) return cached; // only confirmed (immutable) txs are cached
    const tx = await this._parsed(txid);

    const vout = [];
    let outSum = 0n;
    for (let i = 0; i < tx.outputsLength; i++) {
      const o = tx.getOutput(i);
      outSum += o.amount;
      vout.push({ scriptpubkey_address: this._addrOf(o.script), value: Number(o.amount) });
    }

    // Resolve every input's prevout (address + value) from its parent tx, in
    // parallel — needed to compute the fee and which inputs are ours.
    const vin = await parallelMap(Array.from({ length: tx.inputsLength }, (_, i) => i), 6, async (i) => {
      const inp = tx.getInput(i);
      const ptxid = bytesToHex(inp.txid); // btc-signer stores txids in display order
      if (/^0+$/.test(ptxid)) return { is_coinbase: true };
      const ptx = await this._parsed(ptxid);
      const po = ptx.getOutput(inp.index);
      return { txid: ptxid, vout: inp.index, prevout: { scriptpubkey_address: this._addrOf(po.script), value: Number(po.amount) }, _value: po.amount };
    });
    let inSum = 0n;
    let coinbase = false;
    for (const v of vin) { if (v.is_coinbase) coinbase = true; else { inSum += v._value; delete v._value; } }

    const confirmed = height > 0;
    const result = {
      txid,
      vin,
      vout,
      fee: coinbase ? 0 : Number(inSum - outSum),
      weight: tx.weight,
      status: {
        confirmed,
        block_height: confirmed ? height : undefined,
        block_time: confirmed ? await this._blockTime(height) : 0,
      },
    };
    if (confirmed) this._tx.set(txid, result);
    return result;
  }

  // Standalone tx fetch (lazy fee fill / gift check). Electrum's raw tx carries
  // no height, so recover it from an output's scripthash history.
  async getTx(txid) {
    let height = 0;
    try {
      const tx = await this._parsed(txid);
      if (tx.outputsLength) {
        const hist = await this.call('blockchain.scripthash.get_history', [scripthashOfScript(tx.getOutput(0).script)]);
        const e = hist.find((x) => x.tx_hash === txid);
        if (e && e.height > 0) height = e.height;
      }
    } catch {}
    return this._esploraTx(txid, height);
  }

  // Is output (txid:vout) spent? (used to detect an already-claimed gift). Scan
  // the output address's history for a tx that spends this exact outpoint.
  async outspend(txid, vout) {
    const tx = await this._parsed(txid);
    if (vout >= tx.outputsLength) return { spent: false };
    const sh = scripthashOfScript(tx.getOutput(vout).script);
    const hist = await this.call('blockchain.scripthash.get_history', [sh]);
    for (const h of hist) {
      if (h.tx_hash === txid) continue;
      const spender = await this._parsed(h.tx_hash);
      for (let i = 0; i < spender.inputsLength; i++) {
        const inp = spender.getInput(i);
        if (bytesToHex(inp.txid) === txid && inp.index === vout) {
          return { spent: true, txid: h.tx_hash, vin: i, status: { confirmed: h.height > 0, block_height: h.height > 0 ? h.height : undefined } };
        }
      }
    }
    return { spent: false };
  }

  // ---- fees + broadcast --------------------------------------------------
  // Fee rates come from the configured block explorer's live recommendation
  // (mempool.space projects the next block from actual mempool contents), NOT
  // from Fulcrum's blockchain.estimatefee — that wraps Bitcoin Core's
  // estimatesmartfee, which works off historical confirmation data, lags the
  // mempool badly, and floors at 1 sat/vB, so it reports 1 across the board in
  // normal conditions. estimatefee is only the last resort when the explorer is
  // unreachable (regtest, or a self-hosted node with no REST explorer).
  async feeRates() {
    const web = this._explorerWeb;
    if (web && !this.offline) {
      // mempool.space shape first (the live next-block projection)…
      try {
        const r = await fetch(`${web}/api/v1/fees/recommended`);
        if (r.ok) { const d = await r.json(); if (d && d.halfHourFee) return d; }
      } catch {}
      // …then the plain-Esplora /fee-estimates shape.
      try {
        const r = await fetch(`${web}/api/fee-estimates`);
        if (r.ok) { const d = await r.json(); if (d && Object.keys(d).length) return mapEsploraFees(d); }
      } catch {}
    }
    const targets = { fastestFee: 1, halfHourFee: 3, hourFee: 6, economyFee: 144, minimumFee: 1008 };
    const out = {};
    await Promise.all(Object.entries(targets).map(async ([k, n]) => {
      try {
        const perKb = await this.call('blockchain.estimatefee', [n]); // BTC/kB; -1 if unknown
        out[k] = perKb > 0 ? Math.max(1, Math.round(perKb * 1e5)) : 0; // → sat/vB
      } catch { out[k] = 0; }
    }));
    return {
      fastestFee: out.fastestFee || 10,
      halfHourFee: out.halfHourFee || 5,
      hourFee: out.hourFee || 3,
      economyFee: out.economyFee || 2,
      minimumFee: out.minimumFee || 1,
    };
  }

  async broadcast(hexTx) {
    return this.call('blockchain.transaction.broadcast', [hexTx]); // returns txid
  }
}

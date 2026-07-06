// Unilateral exit — put a vtxo on-chain WITHOUT the server's cooperation,
// then claim it through the CSV exit leaf. This is the trustless backstop
// behind "you can always exit on-chain".
//
// The vtxo's genesis chain reconstructs to fully-signed transactions
// (signatures ride in the encoded vtxo). They are zero-fee v3 txs with P2A
// anchors, so each hop needs a CPFP child spending its anchor plus one of the
// wallet's on-chain coins — and TRUC (v3) topology allows only one
// unconfirmed parent, so a deep chain exits one confirmed hop at a time.
// [parent, child] pairs are submitted via esplora's POST /txs/package
// (bitcoind submitpackage). After the vtxo tx confirms and exitDelta blocks
// pass, the claim tx spends it via the delayed_sign leaf with only our key.

import { hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';

import { concatBytes } from './proto.js';
import { pubkeyPolicyTaproot, txid } from './send.js';
import { vtxoTransactions, harkLeafTaproot, tapLeafHash, taprootScriptSighash } from './refresh.js';

const u16le = (n) => Uint8Array.of(n & 0xff, (n >> 8) & 0xff);
const u32le = (n) => Uint8Array.of(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff);
const u64le = (n) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
};
const varint = (n) => {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return concatBytes(Uint8Array.of(0xfd), u16le(n));
  return concatBytes(Uint8Array.of(0xfe), u32le(n));
};
const sha256d = (b) => sha256(sha256(b));

// Segwit serialization: tx is the {version, locktime, inputs, outputs} shape
// the ark modules use; witnesses is one item-array per input ([] = empty).
export function serializeTxW(tx, witnesses) {
  const base = [
    u32le(tx.version),
    varint(tx.inputs.length),
    ...tx.inputs.flatMap((i) => [i.prevout, Uint8Array.of(0x00), u32le(i.sequence)]),
    varint(tx.outputs.length),
    ...tx.outputs.flatMap((o) => [u64le(o.valueSat), varint(o.scriptPubKey.length), o.scriptPubKey]),
  ];
  const wit = witnesses.flatMap((items) => [
    varint(items.length),
    ...items.flatMap((w) => [varint(w.length), w]),
  ]);
  const full = concatBytes(u32le(tx.version), Uint8Array.of(0x00, 0x01),
    ...base.slice(1), ...wit, u32le(tx.locktime));
  const stripped = concatBytes(...base, u32le(tx.locktime));
  const weight = stripped.length * 3 + full.length;
  return { raw: full, vsize: Math.ceil(weight / 4) };
}

// The vtxo's chain as broadcastable transactions, oldest first.
// Throws if any transition lacks its signature (an unsigned chain can't exit).
export function signedExitTxs(vtxo, serverPub) {
  const items = vtxoTransactions(vtxo, serverPub);
  return items.map((it, i) => {
    const t = vtxo.genesis[i].transition;
    let witness;
    if (t.type === 'cosigned' || t.type === 'arkoor') {
      if (!t.signature) throw new Error('vtxo chain is missing a signature — cannot exit');
      witness = [hex.decode(t.signature)];
    } else if (t.type === 'hashLockedCosigned') {
      if (!t.signature || !t.unlock?.preimage) {
        throw new Error('vtxo chain is missing its unlock preimage — cannot exit');
      }
      const preimage = hex.decode(t.unlock.preimage);
      const tp = harkLeafTaproot(hex.decode(t.userPubkey), serverPub, vtxo.expiryHeight, sha256(preimage));
      const cb = concatBytes(Uint8Array.of(0xc0 | tp.outputParity), tp.internalXOnly, tp.expiryLeaf);
      witness = [hex.decode(t.signature), preimage, tp.unlockScript, cb];
    } else {
      throw new Error('unsupported genesis transition: ' + t.type);
    }
    const idInternal = txid(it.tx);
    const { raw, vsize } = serializeTxW(it.tx, [witness]);
    return {
      txid: hex.encode(idInternal.slice().reverse()),
      txidInternal: idInternal,
      hex: hex.encode(raw),
      vsize,
      anchorVout: it.tx.outputs.length - 1,
      anchorValue: it.tx.outputs[it.tx.outputs.length - 1].valueSat,
    };
  });
}

// CPFP child: spends [parent P2A anchor (keyless, empty witness), one wallet
// p2wpkh coin] into a single change output. v3 like its parent (TRUC).
// coin: { txid (display hex), vout, value, pubkey (33B), privkey }.
export function buildBumpChild({ parentTxidInternal, anchorVout, anchorValue, coin, changeScript, feeSat }) {
  const changeSat = coin.value + anchorValue - feeSat;
  if (changeSat < 294) throw new Error('fee coin too small for the exit bump');
  const coinPrevout = concatBytes(hex.decode(coin.txid).reverse(), u32le(coin.vout));
  const tx = {
    version: 3, locktime: 0,
    inputs: [
      { prevout: concatBytes(parentTxidInternal, u32le(anchorVout)), sequence: 0xfffffffd },
      { prevout: coinPrevout, sequence: 0xfffffffd },
    ],
    outputs: [{ valueSat: changeSat, scriptPubKey: changeScript }],
  };
  // BIP143 sighash (ALL) for the p2wpkh input
  const hashPrevouts = sha256d(concatBytes(...tx.inputs.map((i) => i.prevout)));
  const hashSequence = sha256d(concatBytes(...tx.inputs.map((i) => u32le(i.sequence))));
  const hashOutputs = sha256d(concatBytes(...tx.outputs.map((o) =>
    concatBytes(u64le(o.valueSat), varint(o.scriptPubKey.length), o.scriptPubKey))));
  const pkh = ripemd160(sha256(coin.pubkey));
  const scriptCode = concatBytes(hex.decode('1976a914'), pkh, hex.decode('88ac'));
  const preimage = concatBytes(
    u32le(tx.version), hashPrevouts, hashSequence,
    coinPrevout, scriptCode, u64le(coin.value), u32le(tx.inputs[1].sequence),
    hashOutputs, u32le(tx.locktime), u32le(1),
  );
  const sig = secp256k1.sign(sha256d(preimage), coin.privkey, { lowS: true });
  const der = concatBytes(sig.toDERRawBytes ? sig.toDERRawBytes() : sig.toBytes('der'), Uint8Array.of(0x01));
  const { raw, vsize } = serializeTxW(tx, [[], [der, coin.pubkey]]);
  return { hex: hex.encode(raw), txid: hex.encode(txid(tx).slice().reverse()), vsize, changeSat };
}

// The claim: spend the confirmed vtxo output through the delayed_sign leaf
// (CSV = exitDelta) with only the user key, paying destScript.
export function buildExitClaim({ vtxo, keys, serverPub, destScript, feeRate }) {
  const tap = pubkeyPolicyTaproot(keys.pubkey, serverPub, vtxo.exitDelta);
  const cb = concatBytes(Uint8Array.of(0xc0 | tap.outputParity), tap.internalXOnly);
  const prevouts = [{ valueSat: vtxo.amountSat, scriptPubKey: tap.scriptPubKey }];
  const build = (feeSat) => {
    const tx = {
      version: 2, locktime: 0,
      inputs: [{ prevout: vtxo.point.raw, sequence: vtxo.exitDelta }],
      outputs: [{ valueSat: vtxo.amountSat - feeSat, scriptPubKey: destScript }],
    };
    const sighash = taprootScriptSighash(tx, prevouts, tapLeafHash(tap.leafScript));
    const sig = schnorr.sign(sighash, keys.privkey);
    return { tx, witness: [[sig, tap.leafScript, cb]] };
  };
  // two-pass: measure with a real-size witness, then set the fee
  const probe = build(0);
  const vsize = serializeTxW(probe.tx, probe.witness).vsize;
  const feeSat = Math.max(200, Math.ceil(vsize * Math.max(1, feeRate)));
  if (vtxo.amountSat - feeSat < 294) throw new Error('vtxo too small to claim at this fee rate');
  const fin = build(feeSat);
  const { raw } = serializeTxW(fin.tx, fin.witness);
  return { hex: hex.encode(raw), txid: hex.encode(txid(fin.tx).slice().reverse()), feeSat, amountSat: vtxo.amountSat - feeSat, vsize };
}

// Submit a [parent, child] (or single-tx) package via esplora -> bitcoind
// submitpackage. Treats already-known txs as success so retries are safe.
// Esploras without the endpoint (regtest electrs) fall back to sequential
// /tx posts — which relays only if the node accepts zero-fee v3 parents
// (regtest with -minrelaytxfee=0); otherwise the node's error surfaces.
export async function submitPackage(esploraBase, hexes) {
  const r = await fetch(`${esploraBase}/txs/package`, { method: 'POST', body: JSON.stringify(hexes) });
  const body = await r.text();
  if (r.ok || /already|duplicate/i.test(body)) return body;
  if (r.status === 404 || /endpoint does not exist/i.test(body)) {
    for (const hx of hexes) {
      const br = await fetch(`${esploraBase}/tx`, { method: 'POST', body: hx });
      const bb = await br.text();
      if (!br.ok && !/already|duplicate/i.test(bb)) {
        throw new Error(`broadcast failed: ${bb.slice(0, 160)}`);
      }
    }
    return 'sequential';
  }
  throw new Error(`package submit failed: ${body.slice(0, 160)}`);
}

// Full receive-side VTXO validation: reconstruct the entire off-chain
// transaction chain from genesis data, pin it to a confirmed onchain anchor,
// and verify every transition signature. Mirrors bark's
// lib/src/vtxo/validation.rs.
//
// A VTXO that passes here is cryptographically spendable by us alone (given
// the exit-path delays), assuming the anchor doesn't get reorged and no
// prior arkoor double-spend was cosigned by the server before ours.

import { hex } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';
import { schnorr } from '@noble/curves/secp256k1';

import { taprootSighash, txid } from './send.js';
import {
  vtxoTransactions, vtxoAnchorAmount, transitionInputTxout,
  harkLeafTaproot, taprootScriptSighash, tapLeafHash, parseTx,
} from './refresh.js';

export class VtxoValidationError extends Error {}
const fail = (msg) => { throw new VtxoValidationError(msg); };

// chain: an object with getTxHex(txid) -> hex|null and tipHeight() -> number,
// plus getTxStatus(txid) -> {confirmed, block_height} (esplora semantics)
export async function validateVtxo(vtxo, { serverPubkey, chain, expectPubkeys }) {
  const serverHex = hex.encode(serverPubkey);

  // -- structural --
  if (vtxo.policy.type !== 'pubkey') fail(`unsupported policy: ${vtxo.policy.type}`);
  if (vtxo.serverPubkey !== serverHex) fail('vtxo server pubkey does not match ours');
  if (expectPubkeys && !expectPubkeys.includes(vtxo.policy.userPubkey)) {
    fail('vtxo not paid to one of our keys');
  }
  if (!vtxo.genesis.length) fail('vtxo has no genesis transitions');

  // -- expiry --
  const tip = await chain.tipHeight();
  if (vtxo.expiryHeight <= tip) fail(`vtxo expired at ${vtxo.expiryHeight}, tip ${tip}`);

  // -- anchor: onchain, confirmed, and its output matches what the first
  //    transition claims to spend --
  const status = await chain.getTxStatus(vtxo.anchorPoint.txid);
  if (!status?.confirmed) fail(`anchor tx ${vtxo.anchorPoint.txid} not confirmed`);
  const anchorTx = parseTx(hex.decode(await chain.getTxHex(vtxo.anchorPoint.txid)));
  const anchorOut = anchorTx.outputs[vtxo.anchorPoint.vout];
  if (!anchorOut) fail('anchor vout does not exist');
  const expected = transitionInputTxout(
    vtxo.genesis[0].transition, vtxoAnchorAmount(vtxo), serverPubkey, vtxo.expiryHeight,
  );
  if (anchorOut.valueSat !== expected.valueSat
      || hex.encode(anchorOut.scriptPubKey) !== hex.encode(expected.scriptPubKey)) {
    fail('anchor output does not match the genesis chain');
  }

  // -- chain reconstruction must land exactly on the vtxo's outpoint --
  const items = vtxoTransactions(vtxo, serverPubkey);
  const last = items[items.length - 1];
  const lastTxid = hex.encode(txid(last.tx).slice().reverse());
  if (lastTxid !== vtxo.point.txid || last.outputIdx !== vtxo.point.vout) {
    fail(`reconstructed chain tip ${lastTxid}:${last.outputIdx} != vtxo point ${vtxo.id}`);
  }

  // -- every transition signature --
  let prevout = anchorOut;
  for (let i = 0; i < items.length; i++) {
    const t = vtxo.genesis[i].transition;
    const tx = items[i].tx;
    if (!t.signature) fail(`transition ${i} (${t.type}) is unsigned`);
    const sig = hex.decode(t.signature);

    let msg, key;
    if (t.type === 'hashLockedCosigned') {
      // script-spend through the unlock clause; signed by the raw agg key
      const hash = t.unlock.hash ? hex.decode(t.unlock.hash) : sha256(hex.decode(t.unlock.preimage));
      const tp = harkLeafTaproot(hex.decode(t.userPubkey), serverPubkey, vtxo.expiryHeight, hash);
      msg = taprootScriptSighash(tx, [prevout], tapLeafHash(tp.unlockScript));
      key = tp.internalXOnly;
      if (!t.unlock.preimage) fail(`transition ${i} has no unlock preimage`);
      if (hex.encode(sha256(hex.decode(t.unlock.preimage))) !== hex.encode(hash)) {
        fail(`transition ${i} preimage does not match its hash`);
      }
    } else {
      // keyspend of the previous output — the prevout script itself carries
      // the taproot output key the signature must verify against
      msg = taprootSighash(tx, [prevout]);
      key = prevout.scriptPubKey.slice(2); // 5120 || xonly
    }
    if (!schnorr.verify(sig, msg, key)) fail(`transition ${i} (${t.type}) signature invalid`);
    prevout = tx.outputs[items[i].outputIdx];
  }

  return true;
}

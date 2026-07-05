// Native-JS board: move onchain funds into the Ark.
//
// Mirrors bark's lib/src/board.rs BoardBuilder: the funding output pays a
// taproot of musig(user, server) with a server-after-expiry sweep leaf (the
// same shape as the checkpoint policy), the exit tx is cosigned via MuSig2
// through RequestBoardCosign, and the resulting Vtxo<Full> has a single
// Cosigned genesis transition anchored at the funding outpoint.

import { hex, bech32m } from '@scure/base';
import { schnorr } from '@noble/curves/secp256k1';
import * as musig2 from '@scure/btc-signer/musig2';

import { grpcCall, pbWriter, pbFields, concatBytes } from './proto.js';
import { checkpointPolicyTaproot, pubkeyPolicyTaproot, taprootSighash, P2A_SCRIPT } from './send.js';

const u16le = (n) => Uint8Array.of(n & 0xff, (n >> 8) & 0xff);
const u32le = (n) => Uint8Array.of(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff);
const u64le = (n) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
};

// Fee fields are absent when zero (proto3) — e.g. Second's signet server
// boards for free — so every term defaults to 0.
export const boardFee = (amountSat, fees = {}) =>
  Math.max(fees.minFeeSat || 0, (fees.baseFeeSat || 0) + Math.floor((amountSat * (fees.ppm || 0)) / 1_000_000));

export const p2trAddress = (programXOnly, hrp = 'bcrt') =>
  bech32m.encode(hrp, [1, ...bech32m.toWords(programXOnly)], 1023);

// Build the board: funding output spec + exit tx + sighash.
// `fundingOutpointRaw` (36B) is set after the funding tx is known.
export function buildBoard({ userPub, serverPub, amountSat, feeSat, expiryHeight, exitDelta, fundingOutpointRaw }) {
  const fundingTaproot = checkpointPolicyTaproot(userPub, serverPub, expiryHeight);
  const exitTaproot = pubkeyPolicyTaproot(userPub, serverPub, exitDelta);

  const exitTx = {
    version: 3, locktime: 0,
    inputs: [{ prevout: fundingOutpointRaw, sequence: 0 }],
    outputs: [
      { valueSat: amountSat - feeSat, scriptPubKey: exitTaproot.scriptPubKey },
      { valueSat: feeSat, scriptPubKey: P2A_SCRIPT }, // board fee rides the anchor
    ],
  };
  const fundingPrevout = { valueSat: amountSat, scriptPubKey: fundingTaproot.scriptPubKey };
  const sighash = taprootSighash(exitTx, [fundingPrevout]);
  return { fundingTaproot, exitTaproot, exitTx, sighash };
}

export async function requestBoardCosign(ark, { amountSat, fundingOutpointRaw, expiryHeight, userPub, pubNonce }) {
  const w = pbWriter();
  w.varintField(1, amountSat);
  w.bytesField(2, fundingOutpointRaw);
  w.varintField(3, expiryHeight);
  w.bytesField(4, userPub);
  w.bytesField(5, pubNonce);
  const resp = await grpcCall(ark, 'bark_server.ArkService/RequestBoardCosign', w.finish());
  const out = {};
  for (const { field, value } of pbFields(resp)) {
    if (field === 1) out.pubNonce = value;
    if (field === 2) out.partialSig = value;
  }
  return out;
}

// MuSig2: combine our partial with the server's over the exit tx sighash.
export function combineBoardSignature({ board, serverCosign, userNonces, vtxoKeys, serverPub }) {
  const aggNonce = musig2.nonceAggregate([userNonces.public, serverCosign.pubNonce]);
  const session = new musig2.Session(
    aggNonce, board.fundingTaproot.sortedKeys, board.sighash, [board.fundingTaproot.tapTweak], [true],
  );
  const serverIdx = board.fundingTaproot.sortedKeys.findIndex(
    (k) => hex.encode(k) === hex.encode(serverPub));
  const noncesInKeyOrder = serverIdx === 0
    ? [serverCosign.pubNonce, userNonces.public] : [userNonces.public, serverCosign.pubNonce];
  if (!session.partialSigVerify(serverCosign.partialSig, noncesInKeyOrder, serverIdx)) {
    throw new Error('server board partial signature is invalid');
  }
  const userPartial = session.sign(userNonces.secret, vtxoKeys.privkey);
  const finalSig = session.partialSigAgg([userPartial, serverCosign.partialSig]);
  if (!schnorr.verify(finalSig, board.sighash, board.fundingTaproot.outputXOnly)) {
    throw new Error('combined board signature does not verify');
  }
  return finalSig;
}

// Vtxo<Full> bytes for the board: one Cosigned genesis transition.
export function encodeBoardVtxo({ userPub, serverPub, amountSat, feeSat, expiryHeight, exitDelta,
                                  fundingOutpointRaw, exitTxidInternal, finalSig }) {
  const cosignedTransition = concatBytes(
    Uint8Array.of(0x01),          // GenesisTransition::Cosigned
    Uint8Array.of(0x02), userPub, serverPub, // LengthPrefixedVector [user, server]
    finalSig,
  );
  return concatBytes(
    u16le(2),                     // encoding version
    u64le(amountSat - feeSat),
    u32le(expiryHeight),
    serverPub,
    u16le(exitDelta),
    fundingOutpointRaw,           // anchor point = funding utxo
    Uint8Array.of(0x01),          // one genesis item
    cosignedTransition,
    Uint8Array.of(0x01, 0x00),    // nb_outputs=1, output_idx=0
    u64le(feeSat),                // fee_amount
    Uint8Array.of(0x00), userPub, // policy: Pubkey(user)
    exitTxidInternal, u32le(0),   // point = exit_txid:0
  );
}

export async function registerBoardVtxo(ark, vtxoBytes) {
  const w = pbWriter();
  w.bytesField(1, vtxoBytes);
  await grpcCall(ark, 'bark_server.ArkService/RegisterBoardVtxo', w.finish());
}

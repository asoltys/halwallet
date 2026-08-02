// NIP-17 private DMs: kind 14 rumor, kind 13 seal (sender-signed), kind 1059
// wrap under a single-use ephemeral key to the recipient. Interops with
// 0xchat/Amethyst/etc. Works with a raw secret key (Uint8Array) or a
// nostr-login signer adapter carrying { pubkey, signEvent, encryptTo,
// decryptFrom } — the seal is encrypted to the peer, so remote signers need
// the peer variants (added alongside encryptSelf/decryptSelf).

import { finalizeEvent, generateSecretKey, getPublicKey, getEventHash, verifyEvent } from 'nostr-tools/pure';
import * as nip44 from 'nostr-tools/nip44';

const now = () => Math.floor(Date.now() / 1000);
// NIP-59: outer layers carry timestamps tweaked into the past two days so the
// wrap's time reveals nothing; the rumor keeps the true time.
const tweaked = () => now() - Math.floor(Math.random() * 2 * 24 * 3600);

const asSigner = (skOrSigner) =>
  skOrSigner instanceof Uint8Array
    ? {
        pubkey: getPublicKey(skOrSigner),
        signEvent: async (e) => finalizeEvent(e, skOrSigner),
        encryptTo: async (peer, txt) => nip44.encrypt(txt, nip44.getConversationKey(skOrSigner, peer)),
        decryptFrom: async (peer, ct) => nip44.decrypt(ct, nip44.getConversationKey(skOrSigner, peer)),
      }
    : skOrSigner;

// Build the wrap for one receiver (the recipient, or the sender's own copy).
// Returns the kind 1059 event to publish at the receiver's inbox.
// extraTags ride the outer wrap unencrypted — used only for the Direct
// Invite index hint ["k","3313"] (CORD-05 §6); never put content there.
export async function wrapDM(skOrSigner, receiverPk, rumor, extraTags = []) {
  const signer = asSigner(skOrSigner);
  const seal = await signer.signEvent({
    kind: 13,
    content: await signer.encryptTo(receiverPk, JSON.stringify(rumor)),
    tags: [],
    created_at: tweaked(),
  });
  const eph = generateSecretKey();
  return finalizeEvent(
    {
      kind: 1059,
      content: nip44.encrypt(JSON.stringify(seal), nip44.getConversationKey(eph, receiverPk)),
      tags: [['p', receiverPk], ...extraTags],
      created_at: tweaked(),
    },
    eph
  );
}

// A DM to a peer: the kind 14 rumor (unsigned, true timestamp) plus wraps for
// the recipient and for the sender's own inbox (the sent-copy).
export async function makeDM(skOrSigner, peerPk, text) {
  const signer = asSigner(skOrSigner);
  const rumor = {
    kind: 14,
    pubkey: signer.pubkey,
    content: text,
    tags: [['p', peerPk]],
    created_at: now(),
  };
  rumor.id = getEventHash(rumor);
  return {
    rumor,
    toPeer: await wrapDM(signer, peerPk, rumor),
    toSelf: await wrapDM(signer, signer.pubkey, rumor),
  };
}

// Open an inbound kind 1059 addressed to us. Returns
// { rumor, author, peer } or null (not ours / not a DM / bad layer).
// `peer` is the conversation partner: the author for received messages,
// the p-tagged recipient for our own sent-copies.
export async function unwrapDM(wrap, skOrSigner) {
  const signer = asSigner(skOrSigner);
  try {
    const seal = JSON.parse(await signer.decryptFrom(wrap.pubkey, wrap.content));
    if (seal.kind !== 13 || !verifyEvent(seal)) return null;
    const rumor = JSON.parse(await signer.decryptFrom(seal.pubkey, seal.content));
    if (rumor.pubkey !== seal.pubkey) return null;
    if (rumor.id !== getEventHash({ ...rumor, id: undefined })) return null;
    if (rumor.kind !== 14) return { rumor, author: seal.pubkey, peer: null };
    const to = rumor.tags?.find((t) => t[0] === 'p')?.[1];
    const mine = rumor.pubkey === signer.pubkey;
    return { rumor, author: seal.pubkey, peer: mine ? to : rumor.pubkey };
  } catch {
    return null;
  }
}

// Authenticated key exchange: bind the per-session ephemeral public key to a
// long-term, in-person-verified identity. This is what closes the MITM gap.
//
// The signer signs a transcript = DOMAIN || roomId || ephemeralPublicKey using
// BOTH identity keys (Ed25519 + ML-DSA-65). The receiver verifies the dual
// signature against the peer's PINNED identity bundle before trusting the
// ephemeral key. A relay that swaps in its own ephemeral key cannot forge the
// signature, so the swap is detected and the handshake is rejected.
//
// Binding roomId into the transcript prevents replaying a signed key into a
// different room/session.

import { Identity, b64, unb64, concat } from "./identity.js";

const DOMAIN = new TextEncoder().encode("secure-chat/handshake/v1");

function transcript(roomId, ephemeralPubB64) {
  return concat(DOMAIN, new TextEncoder().encode(roomId), unb64(ephemeralPubB64));
}

// Produce the signature bundle for our ephemeral public key.
export async function signHandshake(identity, roomId, ephemeralPubB64) {
  return identity.sign(transcript(roomId, ephemeralPubB64));
}

// Verify a peer's signed ephemeral key against the identity we pinned in
// person. Returns true only if BOTH signatures are valid for THIS transcript.
export async function verifyHandshake(peerBundle, roomId, ephemeralPubB64, sigBundle) {
  return Identity.verify(peerBundle, transcript(roomId, ephemeralPubB64), sigBundle);
}

export { b64, unb64 };

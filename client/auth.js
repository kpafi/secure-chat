// Authenticated key exchange: bind the per-session ephemeral public key to a
// long-term, in-person-verified identity. This is what closes the MITM gap.
//
// The signer signs a transcript = DOMAIN || roomId || foldedNonces ||
// ephemeralPublicKey using BOTH identity keys (Ed25519 + ML-DSA-65). The
// receiver verifies the dual signature against the peer's PINNED identity
// bundle before trusting the ephemeral key. A relay that swaps in its own
// ephemeral key cannot forge the signature, so the swap is detected and the
// handshake is rejected.
//
// Binding roomId into the transcript prevents replaying a signed key into a
// different room. The folded nonces bind FRESHNESS: each peer contributes a
// random per-connection nonce (exchanged in a plaintext "hello" before the
// signed handshake), and the fold is order-independent so both sides sign and
// verify the same bytes. Because my own nonce is fresh every connection, a
// validly-signed handshake captured in an EARLIER session of the same room
// cannot cover it — cross-session handshake replay fails signature
// verification instead of silently desyncing the session keys. The hello
// nonces are unauthenticated in flight, but they are authenticated
// retroactively by the signature that covers them: a relay that tampers with
// a hello only makes the handshake fail loudly (which a relay could always
// force anyway, by dropping frames).

import { Identity, b64, unb64, concat } from "./identity.js";

const DOMAIN = new TextEncoder().encode("secure-chat/handshake/v2");
const NONCE_BYTES = 32;

// A fresh random per-connection nonce (base64). Generate one per connect().
export function freshNonce() {
  return b64(crypto.getRandomValues(new Uint8Array(NONCE_BYTES)));
}

// True iff `n` is a well-formed hello nonce (base64 of exactly 32 bytes).
export function isValidNonce(n) {
  if (typeof n !== "string") return false;
  try {
    return unb64(n).length === NONCE_BYTES;
  } catch {
    return false;
  }
}

// Order-independent fold of the two peers' nonces: sort the base64 strings,
// concatenate the decoded bytes. Both sides compute identical transcript bytes
// regardless of who contributed which nonce.
function foldNonces(aB64, bB64) {
  const [x, y] = [aB64, bB64].sort();
  return concat(unb64(x), unb64(y));
}

function transcript(roomId, nonces, ephemeralPubB64) {
  const [a, b] = nonces;
  if (!isValidNonce(a) || !isValidNonce(b)) {
    throw new Error("handshake transcript requires two valid session nonces");
  }
  return concat(
    DOMAIN,
    new TextEncoder().encode(roomId),
    foldNonces(a, b),
    unb64(ephemeralPubB64),
  );
}

// Produce the signature bundle for our ephemeral public key. `nonces` is the
// pair [myNonce, peerNonce] (order irrelevant).
export async function signHandshake(identity, roomId, nonces, ephemeralPubB64) {
  return identity.sign(transcript(roomId, nonces, ephemeralPubB64));
}

// Verify a peer's signed ephemeral key against the identity we pinned in
// person. Returns true only if BOTH signatures are valid for THIS transcript —
// same room, same pair of per-connection nonces, same ephemeral key.
export async function verifyHandshake(peerBundle, roomId, nonces, ephemeralPubB64, sigBundle) {
  return Identity.verify(peerBundle, transcript(roomId, nonces, ephemeralPubB64), sigBundle);
}

export { b64, unb64 };

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

// v3 (pentest 2026-07-26 P-03) additionally binds the SIGNER'S OWN identity
// bundle into the transcript. Under v2 the bundle was only a verification key,
// never signed input, so `idb.ecdh` / `idb.mlkem` — the long-term ENCRYPTION
// keys used for async sealed mail — rode along unauthenticated. A relay could
// rewrite those two base64 strings in a peer's `key` frame, forge nothing, and
// still pass verification: the live session stayed genuinely secure and showed
// no symptom, but confirming the contact pinned the RELAY's encryption keys and
// every later sealed message went to the relay. Only the human safety-number
// comparison caught it. Binding the bundle makes it a signature failure instead.
// The domain is bumped so a v2 signature can never be read as a v3 one.
const DOMAIN = new TextEncoder().encode("secure-chat/handshake/v3");
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

// `signerBundle` is the public identity bundle of whoever signs this transcript:
// our own when signing, and the RECEIVED `idb` when verifying — so the bundle is
// both the verification key source and a signed input (P-03). Its 32-byte digest
// keeps every field fixed-width, so the concatenation cannot be respliced.
async function transcript(roomId, nonces, ephemeralPubB64, signerBundle) {
  const [a, b] = nonces;
  if (!isValidNonce(a) || !isValidNonce(b)) {
    throw new Error("handshake transcript requires two valid session nonces");
  }
  if (!signerBundle || !signerBundle.ed || !signerBundle.mldsa) {
    throw new Error("handshake transcript requires the signer's identity bundle");
  }
  return concat(
    DOMAIN,
    new TextEncoder().encode(roomId),
    foldNonces(a, b),
    await Identity.bundleDigest(signerBundle),
    unb64(ephemeralPubB64),
  );
}

// Produce the signature bundle for our ephemeral public key. `nonces` is the
// pair [myNonce, peerNonce] (order irrelevant).
export async function signHandshake(identity, roomId, nonces, ephemeralPubB64) {
  return identity.sign(await transcript(roomId, nonces, ephemeralPubB64, identity.publicBundle()));
}

// Verify a peer's signed ephemeral key against the identity we pinned in
// person. Returns true only if BOTH signatures are valid for THIS transcript —
// same room, same pair of per-connection nonces, same ephemeral key, and the
// same identity bundle the peer presented (so a swapped/stripped ecdh/mlkem
// fails here instead of relying on the user to spot it).
export async function verifyHandshake(peerBundle, roomId, nonces, ephemeralPubB64, sigBundle) {
  return Identity.verify(
    peerBundle,
    await transcript(roomId, nonces, ephemeralPubB64, peerBundle),
    sigBundle,
  );
}

// ---- admission proof (pentest 2026-08-07 F-PROTO-001, fix review F1) -------
//
// The owner-side half of P-10 — "refuse a handshake from anyone we did not
// admit" — is enforceable locally, because the owner ran the admit prompt
// itself. The GUEST side had no equivalent: the only evidence it had of having
// been approved was that the relay sent it a `pending` frame and then a
// `joined` frame, both of which the relay writes for free. So a relay that told
// BOTH parties they were guests left neither one asked to approve anybody, and
// an unapproved identity completed the whole handshake.
//
// The first attempt inferred ownership from "we minted this room code", which
// is wrong twice over: the Set is empty after a reload and never holds a pasted
// code (so the attack stayed open in the common workflow), and room ownership
// on an honest relay goes to whoever JOINS FIRST, not to whoever minted the
// code (so it fired on honest traffic). Neither fact is about the code.
//
// This is the evidence that actually exists: when the owner admits a knocker it
// SIGNS that decision, over the admitted bundle and this connection's nonces.
// The guest verifies that signature against the same identity that just passed
// `verifyHandshake`. A relay cannot forge it without the owner's identity key,
// and cannot replay one issued to somebody else because the admitted bundle's
// digest is inside it. In the both-guests configuration neither party ran an
// admit prompt, so neither can produce one and both refuse — which is the whole
// point.
//
// Deliberately a SEPARATE signature rather than a new field in the handshake
// transcript: the transcript is `secure-chat/handshake/v3` and is verified
// byte-for-byte on both sides, so extending it would be a silent wire break
// between client versions. This adds a field that old clients simply never send
// — which a new client refuses, loudly, as an unapproved peer.
//
// Freshness: both per-connection nonces are folded in, so an admission from an
// earlier session of the same room does not verify. Binding: both the admitted
// AND the admitting bundle are covered, so it cannot be re-pointed at another
// identity in either direction.
const ADMISSION_DOMAIN = new TextEncoder().encode("secure-chat/room-admission-proof/v1");

async function admissionTranscript(roomId, nonces, admittedBundle, signerBundle) {
  const [a, b] = nonces;
  if (!isValidNonce(a) || !isValidNonce(b)) {
    throw new Error("admission proof requires two valid session nonces");
  }
  if (!admittedBundle || !admittedBundle.ed || !admittedBundle.mldsa) {
    throw new Error("admission proof requires the admitted identity bundle");
  }
  if (!signerBundle || !signerBundle.ed || !signerBundle.mldsa) {
    throw new Error("admission proof requires the signer's identity bundle");
  }
  return concat(
    ADMISSION_DOMAIN,
    new TextEncoder().encode(roomId),
    foldNonces(a, b),
    await Identity.bundleDigest(admittedBundle),
    await Identity.bundleDigest(signerBundle),
  );
}

// Signed by the OWNER, for the peer it just let in.
export async function signAdmission(identity, roomId, nonces, admittedBundle) {
  return identity.sign(await admissionTranscript(roomId, nonces, admittedBundle, identity.publicBundle()));
}

// Checked by the GUEST: "this peer approved ME, in this room, in this session".
// `myBundle` is the guest's own public bundle — the thing the owner saw in the
// knock and signed over.
export async function verifyAdmission(ownerBundle, roomId, nonces, myBundle, sigBundle) {
  return Identity.verify(
    ownerBundle,
    await admissionTranscript(roomId, nonces, myBundle, ownerBundle),
    sigBundle,
  );
}

// ---- room admission (pentest 2026-07-26 P-08) ------------------------------
// The knock is the introduction a waiting party sends to the room owner, who
// decides whether to let them in. It is signed so the claim "these are my keys"
// costs the sender their private key rather than a copy-paste of someone
// else's public bundle.
//
// HONEST LIMITS, because this signature is weaker than the handshake one and
// must not be mistaken for it:
//   * There is no freshness. The signer and the owner share no nonce yet, and
//     any challenge would come from the relay — the exact party this is meant
//     to constrain. A hostile relay can therefore REPLAY a knock it saw earlier
//     in this room and make the owner see a genuine peer's fingerprint.
//   * It proves nothing about who is on the other end of the socket.
// What actually binds the admission is client-side: app.js pins the bundle it
// admitted and refuses any handshake from a different identity (see
// admittedBundle). This signature only raises the cost of the *claim*, and
// stops one waiting peer from parroting another's bundle within a room.
//
// Its own domain, so a knock signature can never be replayed as a handshake
// signature (or vice versa) — the two transcripts must live in disjoint spaces.
const KNOCK_DOMAIN = new TextEncoder().encode("secure-chat/knock/v1");

async function knockTranscript(roomId, signerBundle) {
  if (!signerBundle || !signerBundle.ed || !signerBundle.mldsa) {
    throw new Error("knock transcript requires the signer's identity bundle");
  }
  return concat(
    KNOCK_DOMAIN,
    new TextEncoder().encode(roomId),
    await Identity.bundleDigest(signerBundle),
  );
}

export async function signKnock(identity, roomId) {
  return identity.sign(await knockTranscript(roomId, identity.publicBundle()));
}

export async function verifyKnock(peerBundle, roomId, sigBundle) {
  return Identity.verify(peerBundle, await knockTranscript(roomId, peerBundle), sigBundle);
}

export { b64, unb64 };

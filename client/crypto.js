// Client-side cryptography for secure-chat.
//
// SECURITY MODEL: the server is a dumb relay and never sees keys or plaintext.
// Everything in this file runs in the user's browser. All primitives come from
// the audited Web Crypto API (crypto.subtle); we implement no crypto by hand.
//
// Each cipher exposes the same small interface so app.js can treat them
// uniformly:
//   needsHandshake   -> bool: must we exchange public keys before sending?
//   ready            -> bool: can we encrypt/decrypt now?
//   init()           -> set up local keys/state
//   handshakePayload() -> base64 string to send as a `key` message (or null)
//   onPeerKey(b64)   -> consume the peer's handshake material
//   encrypt(text)    -> base64 payload for a `msg` (text MUST be printable ASCII)
//   decrypt(b64)     -> recovered plaintext string
//
// All wire payloads are base64 so they satisfy the server's strict base64
// validation. `msg` payloads are base64(JSON) so each mode can carry its own
// small framing (iv, ciphertext, sequence number…) without a custom binary
// format.

import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

// ---- encoding helpers -----------------------------------------------------

const enc = new TextEncoder();
const dec = new TextDecoder();

// Printable ASCII only (0x20..0x7E) — matches the project rule and the server.
const ASCII_RE = /^[\x20-\x7E]*$/;
export function isAscii(s) {
  return ASCII_RE.test(s);
}

export function bufToB64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

// Pentest 2026-07-27 H-1: canonical base64 only. `atob` is WHATWG *forgiving*
// base64 — it strips whitespace, tolerates missing padding, and discards the
// trailing slack bits, so several distinct strings decode to identical bytes.
// Anywhere a value is compared as a STRING (the DHKE reflection guard, the
// pinned bundle, a KEM tag) while it is also verified as BYTES, that slack is a
// wedge a hostile relay can drive between the two checks. Decoding canonically
// removes the wedge: a string that decodes here is the one spelling of its
// bytes. Kept local rather than imported so this module still stands alone; it
// mirrors identity.js `unb64` exactly, and crypto.test.mjs pins both.
const B64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

export function b64ToBuf(b64) {
  if (typeof b64 !== "string" || b64.length % 4 !== 0 || !B64_RE.test(b64)) {
    throw new Error("malformed base64: not canonical");
  }
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  if (bufToB64(bytes) !== b64) throw new Error("malformed base64: not canonical");
  return bytes.buffer;
}

function randomIv() {
  return crypto.getRandomValues(new Uint8Array(12)); // 96-bit GCM nonce
}

function packMsg(obj) {
  return bufToB64(enc.encode(JSON.stringify(obj)));
}

function unpackMsg(b64) {
  return JSON.parse(dec.decode(b64ToBuf(b64)));
}

// ---- per-channel call serialization ----------------------------------------
// The framing channel below updates its anti-replay state (sequence
// counters, chain heads) across `await`ed WebCrypto calls, and its callers do
// not naturally serialize: ws.onmessage fires handlers without awaiting the
// previous one, and the UI can fire overlapping sends. Two interleaved calls
// then read state the other has not committed yet (2026-07-03 pentest): an
// overlapping decrypt() can roll the replay counter back and re-accept an
// already-delivered frame; an overlapping ratchet encrypt() consumes the same
// one-time key twice and permanently desyncs the chain. Every channel
// therefore funnels encrypt/decrypt through a private FIFO queue — one call at
// a time, in arrival order; a rejected call never blocks the queue.

class CallQueue {
  constructor() {
    this._tail = Promise.resolve();
  }
  run(fn) {
    const p = this._tail.then(fn);
    this._tail = p.then(() => {}, () => {}); // keep the queue alive on rejection
    return p;
  }
}

// ---- forward-secret ratchet framing (all modes) -----------------------------
// Every mode frames its messages through a pair of direction-separated
// ONE-WAY HMAC-SHA-256 chains. Every message is encrypted with a one-time
// AES-256-GCM key drawn from the sender's chain:
//
//   msgKey_n = HMAC(chain_{n-1}, 0x01)     chain_n = HMAC(chain_{n-1}, 0x02)
//
// The chain only steps forward (HMAC is one-way) and consumed keys are
// discarded, so ratchet state captured at time T cannot decrypt messages from
// before T. The relay never learns the chains' root, so a forged frame fails
// AEAD authentication; a REFLECTED frame was keyed with the opposite
// direction's chain and fails too; a REPLAYED frame's `n` is not strictly
// increasing (and its one-time key is already gone). A frame whose `n` skips
// ahead (earlier frames dropped or rejected in flight) fast-forwards the
// chain, DISCARDING the skipped keys — bounded by RATCHET_MAX_SKIP so a
// hostile relay cannot force unbounded chain work.
//
// Pentest 2026-07-27 M-6: that bound used to be 1024, and the scratch chain is
// (correctly, for state safety) DISCARDED when the AEAD fails — so every forged
// frame redid the full 2048 HMAC operations, ~60 ms each. At ~17 frames/s
// (~2.4 KiB/s) a hostile relay saturated a core, and because handleMessage is
// FIFO-serialized honest frames queued behind the flood. The window is now 64:
// a gap that large already means the relay is dropping almost everything, and
// the per-forged-frame cost falls ~16x, to a level an attacker could reach just
// by sending ordinary traffic. There is no amplification left to speak of.
//
// The finding's other suggested half — caching the message keys we step OVER,
// so a late frame costs one AEAD open instead of a second walk — is DELIBERATELY
// NOT taken. This ratchet's forward secrecy rests on skipped keys being
// destroyed as the chain steps (crypto.test.mjs asserts a skipped frame is
// permanently undecryptable); a cache would keep up to a window of live message
// keys in memory for frames that may never arrive, trading a real
// confidentiality property against a captured-state adversary for a
// performance win against an adversary the smaller window already handles.
const RATCHET_MAX_SKIP = 64;

const HMAC_CHAIN = { name: "HMAC", hash: "SHA-256", length: 256 };

// Advance a chain head by `steps`, returning the new head plus the final
// step's one-time AES-GCM message key. Intermediate (skipped) message keys are
// never even derived, and each raw byte copy is zeroed once imported — after
// this returns, the caller's old head is the only route back, and dropping it
// makes everything before the new head unrecoverable.
async function chainAdvance(chain, steps, usage) {
  let msgKey = null;
  for (let i = 0; i < steps; i++) {
    if (i === steps - 1) {
      const mk = new Uint8Array(await crypto.subtle.sign("HMAC", chain, new Uint8Array([1])));
      msgKey = await crypto.subtle.importKey("raw", mk, { name: "AES-GCM" }, false, [usage]);
      mk.fill(0);
    }
    const ck = new Uint8Array(await crypto.subtle.sign("HMAC", chain, new Uint8Array([2])));
    chain = await crypto.subtle.importKey("raw", ck, HMAC_CHAIN, false, ["sign"]);
    ck.fill(0);
  }
  return { msgKey, chain };
}

// Key-confirmation domain (pentest 2026-07-27 M-5). Never a single byte, so it
// can never collide with the chain's own 0x01 / 0x02 step inputs.
const CONFIRM_DOMAIN = "secure-chat/key-confirmation/v1";

class RatchetChannel {
  // Use RatchetChannel.create() — the constructor cannot await, and the
  // confirmation tags MUST be computed from the initial chain heads before
  // anything advances them.
  constructor(roomId, domain, sendChain, recvChain) {
    this.roomId = roomId;
    this.domain = domain; // per-mode AD domain, so frames can never cross modes
    this.sendChain = sendChain;
    this.recvChain = recvChain;
    this.sendSeq = 0;
    this.recvSeq = 0;
    // Key confirmation (M-5). `mine` is what we send the peer; `theirs` is what
    // we require back. Computed once, from the chain heads as they are at
    // creation, and only the 32-byte tags are retained — the heads themselves
    // are never stored, so this costs nothing in forward secrecy.
    this.confirmMine = null;
    this.confirmTheirs = null;
    this._q = new CallQueue(); // serializes encrypt/decrypt (see CallQueue)
  }
  static async create(roomId, domain, sendChain, recvChain) {
    const chan = new RatchetChannel(roomId, domain, sendChain, recvChain);
    // Direction-separated exactly like the traffic: our tag comes from the
    // chain we send on, which is the chain the peer receives on — so the peer
    // computing it from THEIR recv chain is proving they derived the same
    // material we did. Revealing one HMAC output under a long, domain-separated
    // input tells an attacker nothing about the chain key, and the chain is
    // stepped only with the one-byte inputs 0x01/0x02.
    const ctx = enc.encode([CONFIRM_DOMAIN, domain, roomId].join("|"));
    chan.confirmMine = bufToB64(await crypto.subtle.sign("HMAC", sendChain, ctx));
    chan.confirmTheirs = bufToB64(await crypto.subtle.sign("HMAC", recvChain, ctx));
    return chan;
  }
  // Canonical additional data: all parts are base64/int, so "|" is unambiguous.
  // Direction is bound by the chain itself (each is derived from its sender).
  _ad(n) {
    return enc.encode([this.domain, this.roomId, n].join("|"));
  }
  encrypt(text) {
    return this._q.run(() => this._encrypt(text));
  }
  decrypt(b64) {
    return this._q.run(() => this._decrypt(b64));
  }
  async _encrypt(text) {
    const step = await chainAdvance(this.sendChain, 1, "encrypt");
    this.sendChain = step.chain; // the key we are about to use is now history
    const n = ++this.sendSeq;
    const iv = randomIv();
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: this._ad(n) },
      step.msgKey,
      enc.encode(text),
    );
    return packMsg({ iv: bufToB64(iv), ct: bufToB64(ct), n });
  }
  async _decrypt(b64) {
    const m = unpackMsg(b64);
    if (!Number.isInteger(m.n) || m.n <= this.recvSeq) throw new Error("replayed frame rejected");
    const steps = m.n - this.recvSeq;
    if (steps > RATCHET_MAX_SKIP) throw new Error("frame sequence too far ahead");
    // Step on a scratch head and commit only after the AEAD authenticates, so
    // a garbage frame from the relay cannot burn keys or wedge the channel.
    const step = await chainAdvance(this.recvChain, steps, "decrypt");
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(b64ToBuf(m.iv)), additionalData: this._ad(m.n) },
      step.msgKey,
      b64ToBuf(m.ct),
    );
    this.recvChain = step.chain; // commit: skipped/used keys are unrecoverable
    this.recvSeq = m.n;
    return this._finish(pt);
  }
  _finish(pt) {
    const text = dec.decode(pt);
    // Pentest 2026-07-26 P-18: enforce the project's printable-ASCII invariant
    // here too. OtpPad._decrypt and both send paths already check it; this path
    // returned whatever TextDecoder produced, and TextDecoder is non-fatal by
    // default, so invalid UTF-8 became U+FFFD silently. Not exploitable (every
    // render path is textContent), but the invariant should hold everywhere.
    if (!isAscii(text)) throw new Error("decrypted content is not ASCII");
    return text;
  }
}

// ---- AES-256 with a shared passphrase ---------------------------------------
// Both users agree on a passphrase out of band; PBKDF2-SHA256 (600k iterations,
// room id as salt) turns it into the mode's root secret with no key material on
// the wire. The ratchet chains are NOT derived from the passphrase alone: both
// peers announce a fresh random session nonce (the app's plaintext `hello`
// exchange), and the chains bind BOTH nonces. Our own nonce is fresh per
// connection and never attacker-controlled, so a frame captured in an earlier
// session (same room + passphrase) can never authenticate in this one — that
// closes the old cross-session-replay residual. The hello is unauthenticated in
// flight (AES256 has no identity requirement); a relay tampering with it only
// desyncs the keys, a loud DoS it could cause anyway.
//
// HONEST FORWARD-SECRECY LIMIT: the ratchet erases the derived base key and
// old message keys, so captured RATCHET STATE cannot decrypt earlier traffic.
// But the passphrase itself is a long-term secret living outside this code (the
// user's head, the input field) and the session nonces cross the relay in the
// clear — an attacker who learns the PASSPHRASE and recorded the ciphertext can
// still re-derive every session, past and future. That is inherent to any
// passphrase-only mode; real forward secrecy needs DHKE or PQKEM.

const AES_CHAIN_INFO = "secure-chat/aes-fs/v1|";
const AES_MSG_DOMAIN = "secure-chat/aes-msg/v2";

class AesPassphrase {
  constructor(roomId, passphrase) {
    this.roomId = roomId;
    this.passphrase = passphrase;
    this.base = null; // HKDF base from the passphrase; erased once chains exist
    this.chan = null;
  }
  get needsHandshake() {
    return false; // no key material crosses the wire…
  }
  get usesNonces() {
    return true;  // …but frame keys need both peers' fresh session nonces
  }
  get ready() {
    return this.chan !== null;
  }
  // Key confirmation (pentest 2026-07-27 M-5): {mine, theirs} once the chains
  // exist. `mine` goes to the peer; a peer that derived the same material sends
  // back exactly `theirs`. See app.js for the exchange and why it gates the
  // in-person verification step.
  get confirmation() {
    return this.chan ? { mine: this.chan.confirmMine, theirs: this.chan.confirmTheirs } : null;
  }
  async init() {
    if (!this.passphrase) throw new Error("passphrase required for AES-256 mode");
    const pw = await crypto.subtle.importKey(
      "raw", enc.encode(this.passphrase), "PBKDF2", false, ["deriveBits"],
    );
    this.passphrase = null; // drop our copy as soon as it is absorbed
    const bits = new Uint8Array(
      await crypto.subtle.deriveBits(
        // 600k PBKDF2-SHA256 iterations (OWASP 2023 guidance). Both peers run
        // this same code, so the derived base matches without negotiation.
        { name: "PBKDF2", salt: enc.encode(this.roomId), iterations: 600000, hash: "SHA-256" },
        pw,
        256,
      ),
    );
    this.base = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
    bits.fill(0);
  }
  handshakePayload() {
    return null;
  }
  async onPeerKey() {}
  // Derive the session's chain heads from the passphrase base + both peers'
  // fresh session nonces (sorted, so the pair is order-independent; each chain
  // bound to its sender's nonce for direction separation), then erase the base.
  async setNonces(myNonce, peerNonce) {
    if (this.chan) return; // first exchange wins; nonces are fixed per session
    if (
      typeof myNonce !== "string" || typeof peerNonce !== "string" ||
      !myNonce || !peerNonce || myNonce === peerNonce
    ) {
      throw new Error("bad session nonces");
    }
    const salt = enc.encode([this.roomId, ...[myNonce, peerNonce].sort()].join("|"));
    const chain = (senderNonce) =>
      crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt, info: enc.encode(AES_CHAIN_INFO + senderNonce) },
        this.base,
        HMAC_CHAIN,
        false,
        ["sign"],
      );
    this.chan = await RatchetChannel.create(this.roomId, AES_MSG_DOMAIN, await chain(myNonce), await chain(peerNonce));
    this.base = null; // only the forward-stepping chains remain
  }
  async encrypt(text) {
    if (!this.chan) throw new Error("session nonces not exchanged yet");
    return this.chan.encrypt(text);
  }
  async decrypt(b64) {
    if (!this.chan) throw new Error("session nonces not exchanged yet");
    return this.chan.decrypt(b64);
  }
}

// ---- DHKE: ephemeral ECDH (P-256) -> forward-secret symmetric ratchet ------
// Each peer makes an ephemeral keypair, swaps public keys via the relay
// (identity-signed at the app layer), and HKDFs the ECDH secret into the two
// direction-separated chain heads of a RatchetChannel (the HKDF info binds
// each chain to its sender's public key). The exchange is symmetric: both
// sides compute the same shared secret whichever offer arrives first, so
// exactly one derivation ever happens (first key wins).
//
// FORWARD SECRECY: the ephemeral keypair gives cross-session secrecy; the
// ratchet (one-time keys, erased as the chain steps) gives IN-SESSION secrecy
// too. The private key and the raw shared-secret bytes are dropped the moment
// the chains exist — nothing retained can reconstruct earlier message keys.

const DHKE_CHAIN_INFO = "secure-chat/dhke-fs/v1|";
const DHKE_MSG_DOMAIN = "secure-chat/dhke-msg/v2";

class Dhke {
  constructor(roomId) {
    this.roomId = roomId;
    this.kp = null;
    this.myPub = null; // my raw ECDH public key (base64), kept after kp is dropped
    this.chan = null;
  }
  get needsHandshake() {
    return true;
  }
  get ready() {
    return this.chan !== null;
  }
  // Key confirmation (pentest 2026-07-27 M-5): {mine, theirs} once the chains
  // exist. `mine` goes to the peer; a peer that derived the same material sends
  // back exactly `theirs`. See app.js for the exchange and why it gates the
  // in-person verification step.
  get confirmation() {
    return this.chan ? { mine: this.chan.confirmMine, theirs: this.chan.confirmTheirs } : null;
  }
  async init() {
    this.kp = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      false, // private key non-extractable
      ["deriveBits"],
    );
    this.myPub = bufToB64(await crypto.subtle.exportKey("raw", this.kp.publicKey));
  }
  async handshakePayload() {
    return this.myPub;
  }
  async onPeerKey(b64) {
    // Our own key echoed back can only be relay mischief: honest peers never
    // share a keypair, and identical pubs would collapse the direction chains.
    //
    // Pentest 2026-07-27 M-4: this guard used to be a bare `b64 === this.myPub`
    // string compare on a malleable encoding, so a re-SPELLED copy of our own
    // signed offer walked straight past it (PQKEM survived only because it
    // compares signature-covered inner JSON fields). The guest then derived
    // a channel with herself and was prompted to verify her OWN fingerprint;
    // clicking through pinned her own bundle as the room's contact. Decode
    // FIRST — b64ToBuf is canonical now (H-1), so the decode rejects every
    // non-canonical spelling — then compare the ECDH POINT, not its encoding.
    const peerRaw = new Uint8Array(b64ToBuf(b64));
    const myRaw = new Uint8Array(b64ToBuf(this.myPub));
    if (bytesEqual(peerRaw, myRaw)) throw new Error("reflected handshake rejected");
    if (this.chan) return; // first key wins: ignore replays of the peer's key
    const peer = await crypto.subtle.importKey(
      "raw", peerRaw, { name: "ECDH", namedCurve: "P-256" }, false, [],
    );
    // Run the raw ECDH secret (the shared point's X coordinate) through HKDF
    // rather than using it directly: proper key separation, with the room id
    // as salt and per-sender chain info — mirrors the other modes.
    const ecdhBits = new Uint8Array(
      await crypto.subtle.deriveBits({ name: "ECDH", public: peer }, this.kp.privateKey, 256),
    );
    const base = await crypto.subtle.importKey("raw", ecdhBits, "HKDF", false, ["deriveKey"]);
    ecdhBits.fill(0);
    // The chain `info` is the sender's public key as a STRING. That is only
    // unambiguous because both spellings that reach here are canonical (H-1) —
    // otherwise two peers holding the same POINT could derive different chains
    // and wedge one direction of a session they both believe is verified (M-5).
    const chain = (senderPubB64) =>
      crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: enc.encode(this.roomId), info: enc.encode(DHKE_CHAIN_INFO + senderPubB64) },
        base,
        HMAC_CHAIN,
        false,
        ["sign"],
      );
    this.chan = await RatchetChannel.create(this.roomId, DHKE_MSG_DOMAIN, await chain(this.myPub), await chain(b64));
    // Only one derivation ever happens (first key wins), so the private key is
    // done the moment the chains exist — drop it for in-session FS.
    this.kp = null;
  }
  async encrypt(text) {
    if (!this.chan) throw new Error("handshake not complete");
    return this.chan.encrypt(text);
  }
  async decrypt(b64) {
    if (!this.chan) throw new Error("handshake not complete");
    return this.chan.decrypt(b64);
  }
}

// ---- shared byte helpers (PQKEM) -------------------------------------------

// Byte equality. Not constant-time and does not need to be: every value
// compared with it is PUBLIC key material already on the wire.
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function concatBytes(parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

async function sha256Hex(bytes) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
}

// ---- RSA key transport: REMOVED (deprecated 2026-08-21) --------------------
// TOMBSTONE. There used to be an `Rsa` cipher here (RSA-OAEP-2048 key transport
// feeding the same forward-secret ratchet as the other modes), plus a partial
// public-key validator (`assertRsaPublicKeyUsable`, SP 800-56B Rev.2 §6.4.2.2)
// and its helpers (base64url->BigInt, bit length, integer n-th root, a small-
// prime sieve). All of it is gone, deliberately. Do not restore it.
//
// WHY (pentest 2026-08-07 F-CRYPTO-009, accepted as a RESIDUAL that validation
// cannot close). In RSA key transport the ROOT secret is chosen by one side and
// encrypted to a modulus chosen by the OTHER side, and that one root is the sole
// HKDF IKM for BOTH direction chains. A counterparty who offers e = 65537 with
// n = <one small factor> x <one large prime> therefore hands the entire session
// — past and future traffic, in both directions — to any passive observer of the
// handshake frame. That variant was demonstrated against this file. Partial
// public-key validation CANNOT catch it: no cheap check certifies that a modulus
// is the product of two large primes, and raising the trial-division bound does
// not help — the attacker simply picks a larger factor. The validator that used
// to live here removed only the trivially catastrophic keys (e in {0,1,2,3},
// even moduli, perfect powers, mis-declared sizes) and was never a defence
// against this; keeping it would have read as "peer RSA keys are validated",
// which was exactly the false assurance the finding is about.
//
// WHY NOT THE OTHER FIX. Making the root contributory (each side wraps its OWN
// secret to the other's key, both folded into the IKM, so one bad key exposes
// only one half) would close it, but it needs a THIRD handshake frame: the
// two-frame offer/answer exchange has nowhere to put the offerer's ciphertext,
// and app.js's "answer the initiator exactly once" invariant forbids adding one.
// The repo owner's decision (2026-08-21) was to drop the mode rather than grow
// the handshake.
//
// WHAT REPLACES IT. DHKE and PQKEM. Neither has a peer-chosen-modulus analogue:
// their peer material is a P-256 point (WebCrypto enforces on-curve and rejects
// the identity; P-256 has prime order, so there is no degenerate-parameter
// choice to make) plus, for PQKEM, an ML-KEM-768 encapsulation key. Both derive
// a CONTRIBUTORY secret — neither side alone fixes it.
//
// HOW THE REFUSAL IS ENFORCED. Three layers, none of them decorative:
//   1. index.html no longer offers an RSA radio, so it cannot be selected.
//   2. makeCipher refuses "RSA" via DEPRECATED_ALGS below, with the reason —
//      never a fallback to another mode (a silent downgrade would be a finding
//      in its own right), and app.js turns the throw into a red hint.
//   3. The implementation is gone, so there is no `case "RSA":` for a future
//      contributor to re-enable one line away from the residual.
// Anchored by rsa-deprecation.test.mjs (all three layers) and by
// e2e/all-modes.mjs (which asserts the mode inventory exhaustively).

// ---- PQKEM: hybrid ECDH P-256 + ML-KEM-768 -> forward-secret ratchet -------
// Post-quantum-secure session root. The ratchet chains are derived
// (HKDF-SHA-256) from BOTH a classical ECDH P-256 secret AND an ML-KEM-768
// (FIPS-203) secret, so they stay secret unless an attacker breaks BOTH —
// i.e. it resists "harvest now, decrypt later" by a future quantum adversary,
// while remaining no weaker than DHKE if ML-KEM were ever faulted.
// Authenticated by the same dual (Ed25519 + ML-DSA-65) identity handshake as
// DHKE (see app.js / auth.js).
//
// The exchange is symmetric: each peer OFFERS an ML-KEM public key, the other
// ENCAPSULATES to it, and the resulting shared secret(s) are folded in keyed by
// a hash of the encapsulation key — so both sides combine the same secrets in
// the same order. This tolerates the relay's join-order race (where both peers'
// offers are delivered) with no role negotiation: in the common case exactly
// one secret is established, in the race two, and both peers agree either way.
//
// FORWARD SECRECY: the handshake material that could replay the key
// schedule from a recorded transcript — the ECDH private key, the KEM secret
// key, and the raw shared secrets — is erased (`_seal`) the moment the first
// real message is sent or received (messaging sits behind the safety-number
// gate, so the race has settled by then; a relay withholding a race answer
// past that point could only cause a loud decrypt failure, which it can
// anyway). From there only the forward-stepping chains remain: state captured
// at time T cannot decrypt traffic from before T, and past sessions were
// always safe (all key material is per-session).

const PQKEM_CHAIN_INFO = "secure-chat/pqkem-fs/v1|";
const PQKEM_MSG_DOMAIN = "secure-chat/pqkem-msg/v2";

class Pqkem {
  constructor(roomId) {
    this.roomId = roomId;
    this.ecdh = null;          // ECDH P-256 keypair (deriveBits)
    this.myEcdhPub = null;     // my raw ECDH public key (base64), kept after seal
    this.kem = null;           // my ML-KEM-768 keypair
    this.myKemPub = null;      // my KEM public key (base64), for reflection checks
    this.peerEcdh = null;      // peer ECDH public key (base64), learned from any msg
    this.secrets = new Map();  // tag (hex of SHA-256(ek)) -> ML-KEM shared secret
    this.answer = null;        // our reply payload, set when we answer a peer offer
    this.chan = null;
    this.sealed = false;       // handshake material erased; ratchet-only from here
    this._derivedFrom = null;  // signature of the inputs the current chains came from
  }
  get needsHandshake() {
    return true;
  }
  get ready() {
    return this.chan !== null;
  }
  // Key confirmation (pentest 2026-07-27 M-5): {mine, theirs} once the chains
  // exist. `mine` goes to the peer; a peer that derived the same material sends
  // back exactly `theirs`. See app.js for the exchange and why it gates the
  // in-person verification step.
  get confirmation() {
    return this.chan ? { mine: this.chan.confirmMine, theirs: this.chan.confirmTheirs } : null;
  }
  async init() {
    this.ecdh = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"],
    );
    this.myEcdhPub = bufToB64(await crypto.subtle.exportKey("raw", this.ecdh.publicKey));
    this.kem = ml_kem768.keygen();
    this.myKemPub = bufToB64(this.kem.publicKey);
  }
  // (Re)derive the direction-separated chain heads from the ECDH secret plus
  // every ML-KEM secret we hold, ordered by tag so both peers feed HKDF
  // identical input. Idempotent: if the inputs are unchanged (e.g. a relay
  // replayed a handshake frame) the existing chains — and their positions —
  // are kept intact.
  async _derive() {
    if (this.peerEcdh === null || this.secrets.size === 0) return;
    // Pentest 2026-07-27 M-5: no LOCAL invariant can tell a healthy handshake
    // from a wedged one here. The honest staggered order (offer -> answer)
    // legitimately leaves each peer holding exactly ONE KEM secret, tagged with
    // the same encapsulation key on both sides; a relay that drops both
    // `reply=true` answers also leaves each peer holding exactly one, tagged
    // with the key IT encapsulated to. The two cases are indistinguishable from
    // inside this function — the difference is only visible when the peers
    // compare something derived from the chains, which is what the explicit key
    // confirmation in app.js does before the session is declared verified.
    const tags = [...this.secrets.keys()].sort();
    const signature = this.peerEcdh + "|" + tags.join(",");
    if (signature === this._derivedFrom) return;
    this._derivedFrom = signature;
    const peer = await crypto.subtle.importKey(
      "raw", b64ToBuf(this.peerEcdh), { name: "ECDH", namedCurve: "P-256" }, false, [],
    );
    const ecdhBits = new Uint8Array(
      await crypto.subtle.deriveBits({ name: "ECDH", public: peer }, this.ecdh.privateKey, 256),
    );
    const ikm = concatBytes([ecdhBits, ...tags.map((t) => this.secrets.get(t))]);
    const base = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
    ecdhBits.fill(0);
    ikm.fill(0);
    const chain = (senderPubB64) =>
      crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: enc.encode(this.roomId), info: enc.encode(PQKEM_CHAIN_INFO + senderPubB64) },
        base,
        HMAC_CHAIN,
        false,
        ["sign"],
      );
    this.chan = await RatchetChannel.create(this.roomId, PQKEM_MSG_DOMAIN, await chain(this.myEcdhPub), await chain(this.peerEcdh));
  }
  async handshakePayload() {
    if (this.answer) return this.answer;                        // reply to a peer offer
    return packMsg({ e: this.myEcdhPub, ek: this.myKemPub });   // initial offer
  }
  async onPeerKey(b64) {
    // Post-seal the chains are final and the decapsulation material is gone; a
    // late handshake frame can only be relay mischief, so ignore it.
    if (this.sealed) return;
    const m = unpackMsg(b64);
    // Our own keys echoed back can only be relay mischief: honest peers never
    // share keypairs, and identical pubs would collapse the direction chains.
    if (m.e === this.myEcdhPub || m.ek === this.myKemPub) {
      throw new Error("reflected handshake rejected");
    }
    if (m.e && this.peerEcdh === null) this.peerEcdh = m.e; // first ECDH pub wins
    if (m.ek) {
      // Peer offered a KEM key: encapsulate to it, answer with the ciphertext.
      // First write wins per encapsulation key, so a replayed offer cannot make
      // us re-encapsulate a fresh secret and rotate (desync) the session key.
      const ek = new Uint8Array(b64ToBuf(m.ek));
      const tag = await sha256Hex(ek);
      if (!this.secrets.has(tag)) {
        const { cipherText, sharedSecret } = ml_kem768.encapsulate(ek);
        this.secrets.set(tag, sharedSecret);
        this.answer = packMsg({ e: this.myEcdhPub, ct: bufToB64(cipherText) });
      }
    } else if (m.ct) {
      // Peer answered our offer: decapsulate with our KEM secret key (once).
      const tag = await sha256Hex(this.kem.publicKey);
      if (!this.secrets.has(tag)) {
        const ss = ml_kem768.decapsulate(new Uint8Array(b64ToBuf(m.ct)), this.kem.secretKey);
        this.secrets.set(tag, ss);
      }
    } else {
      throw new Error("malformed PQKEM handshake message");
    }
    await this._derive();
  }
  // Erase everything that could reconstruct the chains from a recorded
  // transcript: the ECDH private key, the KEM secret key, and the raw shared
  // secrets. From here only the forward-stepping chain heads remain. Runs on
  // the first real message in either direction.
  _seal() {
    for (const s of this.secrets.values()) s.fill(0);
    this.secrets.clear();
    this.kem.secretKey.fill(0);
    this.kem = null;
    this.ecdh = null; // non-extractable; dropping the reference is all JS allows
    this.answer = null;
    this._derivedFrom = null;
    this.sealed = true;
  }
  async encrypt(text) {
    if (!this.chan) throw new Error("handshake not complete");
    if (!this.sealed) this._seal();
    return this.chan.encrypt(text);
  }
  async decrypt(b64) {
    if (!this.chan) throw new Error("handshake not complete");
    const pt = await this.chan.decrypt(b64);
    if (!this.sealed) this._seal();
    return pt;
  }
}

// ---- OTP: pre-shared one-time pad (true XOR) --------------------------------
// A one-time pad shared IN PERSON (generated on one device, exported as an
// encrypted file, imported on the other — see otp.js). This is a genuine XOR
// one-time pad: each plaintext byte is XORed with a fresh pad byte that is never
// reused, so the CONFIDENTIALITY of the content is information-theoretic to the
// extent the pad is truly random. (The pad is generated from the OS CSPRNG,
// hardened with user-drawn entropy, not a certified hardware TRNG, so in
// practice treat it as "at least as strong as the CSPRNG.")
//
// XOR alone has NO integrity — a relay could flip ciphertext bits and flip the
// plaintext bit-for-bit. So each message is authenticated with an HMAC-SHA-256
// tag under a ONE-TIME key also drawn fresh from the pad. That authenticator is
// COMPUTATIONAL, not information-theoretic (an information-theoretic one-time MAC
// would be hand-rolled crypto, which this project forbids); it is the honest,
// documented limit of OTP mode's integrity guarantee.
//
// Two-region split (no reuse across the two senders): the pad is split in half.
// The peer with role 0 sends from region 0 and receives from region 1; role 1 is
// the mirror. Each sender advances a strictly increasing offset in its own
// region, so no pad byte is ever used to encrypt twice. Consumed bytes are
// zeroed as they are used (forward secrecy: device capture at time T cannot
// decrypt earlier traffic — those pad bytes are gone). The receiver only accepts
// a strictly forward offset, which rejects replays and cross-session replays
// (offsets persist per pad, never rewind). Roles/offsets live in the pad record
// (otp.js), which app.js persists after every message.
//
// Per message at region offset o for an L-byte plaintext:
//   macKey    = pad[o .. o+32]            (one-time HMAC key)
//   keystream = pad[o+32 .. o+32+L]
//   ct        = plaintext XOR keystream
//   tag       = HMAC(macKey, domain|room|role|o|L | ct)   (binds position+room)
//   consume 32+L bytes; next offset = o + 32 + L
const OTP_MSG_DOMAIN = "secure-chat/otp-msg/v1";
const OTP_MAC_BYTES = 32;

// True if every byte in [start, end) is zero — i.e. that pad span has already
// been consumed and wiped (see the P-01 guard in OtpPad._encrypt).
function isAllZero(u8, start, end) {
  for (let i = start; i < end; i++) if (u8[i] !== 0) return false;
  return true;
}

class OtpPad {
  constructor(roomId, pad) {
    if (!pad || !(pad.bytes instanceof Uint8Array)) {
      throw new Error("OTP mode requires a loaded pad");
    }
    if (pad.role !== 0 && pad.role !== 1) throw new Error("OTP pad role must be 0 or 1");
    if (!Number.isInteger(pad.regionSize) || pad.regionSize <= OTP_MAC_BYTES) {
      throw new Error("OTP pad region too small");
    }
    if (pad.bytes.length !== 2 * pad.regionSize) throw new Error("OTP pad length mismatch");
    // Pentest 2026-07-29 L-5: validate the offsets like every other field.
    //
    // Not reachable today — otp.js rejects negative offsets before it gets here
    // and v3 keeps them inside the AEAD — but this class is written as though it
    // defends itself against a bad record, and with a negative offset it does
    // not. `sendOffset < 0` makes the P-01 spent-keystream guard return false on
    // its first iteration and makes `slice()` draw the MAC key and keystream
    // from the PEER's region (i.e. keystream the peer will also use to send);
    // `recvHighWater < 0` turns the zeroing `fill()` into a no-op, so consumed
    // keystream is never erased. Both are two-time-pad shaped, so the class
    // should not be relying on a caller to have checked. `| 0` was silently
    // coercing NaN/undefined to 0 as well, which hid a malformed record.
    const inRange = (v) => Number.isInteger(v) && v >= 0 && v <= pad.regionSize;
    if (!inRange(pad.sendOffset)) throw new Error("OTP pad has an invalid send offset");
    if (!inRange(pad.recvHighWater)) throw new Error("OTP pad has an invalid receive high-water mark");
    this.roomId = roomId;
    this.pad = pad.bytes;          // shared reference: app.js persists it (zeroed as consumed)
    this.role = pad.role;
    this.regionSize = pad.regionSize;
    this.sendOffset = pad.sendOffset;       // our position in our send region
    this.recvHighWater = pad.recvHighWater; // highest consumed offset in the peer's region
    this._q = new CallQueue();
  }
  get needsHandshake() { return false; } // the pad is the shared secret; nothing crosses the wire
  get usesNonces() { return false; }
  get ready() { return this.pad !== null; }
  // No key confirmation to do (M-5): nothing was negotiated. Both sides either
  // hold the same pad — carried between the devices in person — or they do not,
  // in which case the very first frame fails its one-time HMAC. There is no
  // state in which two peers "agree" on different key material.
  get confirmation() { return null; }
  async init() {}
  handshakePayload() { return null; }
  async onPeerKey() {}

  // Bytes of send region still usable (each message costs 32 + its length).
  get remainingSend() { return this.regionSize - this.sendOffset; }

  async _mac(keyBytes, role, o, len, ct, usage) {
    const key = await crypto.subtle.importKey(
      "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, [usage],
    );
    const header = enc.encode(`${OTP_MSG_DOMAIN}|${this.roomId}|${role}|${o}|${len}|`);
    return { key, ad: concatBytes([header, ct]) };
  }

  encrypt(text) { return this._q.run(() => this._encrypt(text)); }
  async _encrypt(text) {
    const pt = enc.encode(text);
    const len = pt.length;
    const need = OTP_MAC_BYTES + len;
    if (this.sendOffset + need > this.regionSize) {
      throw new Error("one-time pad exhausted for sending — exchange a new pad in person");
    }
    const o = this.sendOffset;
    const base = this.role * this.regionSize;
    const abs = base + o;
    // Pentest 2026-07-26 P-01 (defense in depth): consumed pad bytes are zeroed
    // in place, so an all-zero span means we are about to "encrypt" with spent
    // keystream — `ct = pt XOR 0` hands the plaintext to the relay. The only way
    // to reach this with a well-formed record is a corrupted/tampered `role` or
    // offset pointing us at the PEER's already-consumed region. Fail closed
    // rather than emit the plaintext. (A genuine unused span is random; the odds
    // of it being 32+ zero bytes are negligible.)
    if (isAllZero(this.pad, abs, abs + need)) {
      throw new Error(
        "refusing to send: this pad region is already spent (the pad's role/offset state looks wrong) — exchange a fresh pad in person",
      );
    }
    const macKeyBytes = this.pad.slice(abs, abs + OTP_MAC_BYTES); // copy (independent of zeroing)
    const ks = this.pad.subarray(abs + OTP_MAC_BYTES, abs + need); // live view, read before zeroing
    const ct = new Uint8Array(len);
    for (let i = 0; i < len; i++) ct[i] = pt[i] ^ ks[i];
    const { key, ad } = await this._mac(macKeyBytes, this.role, o, len, ct, "sign");
    const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, ad));
    // Consume: zero the used pad span + local copies (forward secrecy).
    this.pad.fill(0, abs, abs + need);
    macKeyBytes.fill(0);
    pt.fill(0);
    this.sendOffset += need;
    return packMsg({ r: this.role, o, ct: bufToB64(ct), mac: bufToB64(mac) });
  }

  decrypt(b64) { return this._q.run(() => this._decrypt(b64)); }
  async _decrypt(b64) {
    const p = unpackMsg(b64);
    const peerRegion = 1 - this.role;
    if (p.r !== peerRegion) {
      // Our own region coming back is a relay reflecting our frame; a wrong value
      // is malformed. Either way it is not a genuine peer frame.
      throw new Error("frame from the wrong pad region (reflected or malformed)");
    }
    if (!Number.isInteger(p.o) || p.o < 0) throw new Error("bad pad offset");
    const ct = new Uint8Array(b64ToBuf(p.ct));
    const len = ct.length;
    const need = OTP_MAC_BYTES + len;
    // Strictly forward: rejects replays, overlaps, and cross-session replays
    // (recvHighWater persists per pad and never rewinds).
    if (p.o < this.recvHighWater) throw new Error("pad offset already consumed (replay)");
    if (p.o + need > this.regionSize) throw new Error("pad offset out of range");
    const base = peerRegion * this.regionSize;
    const abs = base + p.o;
    // Pentest 2026-07-27 L-5 (defense in depth): the send path has carried this
    // check since P-01; the receive path did not. Consumed pad is ZEROED, so an
    // all-zero span here means we are about to verify and XOR against keystream
    // that is already spent — the plaintext would fall straight out of the
    // ciphertext. `recvHighWater` should make that unreachable, and no
    // app-internal path to the required state was found; this is the guard for
    // when it is wrong (a hand-edited or corrupted record), and it costs one
    // scan of a span we are reading anyway.
    if (isAllZero(this.pad, abs, abs + need)) {
      throw new Error("pad region already consumed (zeroed) — refusing to decrypt against spent keystream");
    }
    const macKeyBytes = this.pad.slice(abs, abs + OTP_MAC_BYTES);
    const { key, ad } = await this._mac(macKeyBytes, p.r, p.o, len, ct, "verify");
    const ok = await crypto.subtle.verify("HMAC", key, b64ToBuf(p.mac), ad);
    macKeyBytes.fill(0);
    // Auth failure consumes NOTHING (a hostile relay cannot burn pad with forged
    // frames, and a genuine frame is idempotently retryable up to the highwater).
    if (!ok) throw new Error("authentication failed (tampered or forged)");
    const ks = this.pad.subarray(abs + OTP_MAC_BYTES, abs + need);
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) out[i] = ct[i] ^ ks[i];
    const text = dec.decode(out);
    out.fill(0);
    if (!isAscii(text)) throw new Error("decrypted content is not ASCII");
    // Consume through this frame, including any skipped gap (dropped/rejected
    // frames), zeroing it for forward secrecy. Gap bytes are unusable anyway
    // once the highwater passes them.
    this.pad.fill(0, base + this.recvHighWater, abs + need);
    this.recvHighWater = p.o + need;
    return text;
  }
}

// Modes this build refuses to construct, and WHY — the reason is the user-facing
// half of the refusal, so it is written to be read out loud in a red hint.
//
// This replaces the old `UNAVAILABLE = {}` export, which was DEAD: nothing in
// the tree ever read it, yet its comment claimed a mode listed in it "would be
// UI-disabled with the given reason" — a mechanism that did not exist. This
// project treats dead security code as a hazard precisely because a comment
// like that is believed. `DEPRECATED_ALGS` is genuinely consumed: makeCipher
// below is its only reader and refuses on it, so emptying this object visibly
// changes behaviour (and turns rsa-deprecation.test.mjs red).
export const DEPRECATED_ALGS = Object.freeze({
  RSA: "peer-chosen RSA key transport is deprecated: a crafted peer modulus " +
    "(e = 65537, n = small factor x large prime) hands the whole session to a " +
    "passive observer and no validation can catch it (F-CRYPTO-009). " +
    "Use DHKE or PQKEM.",
});

export function makeCipher(alg, roomId, opts = {}) {
  // Checked BEFORE the switch so a deprecated mode reports its actual reason
  // rather than the generic "unsupported" default — and so re-adding a `case`
  // below could not quietly resurrect it. Never falls back to another mode: a
  // silent downgrade is itself a finding in this codebase, so the caller
  // (app.js) surfaces this throw and refuses to connect.
  if (Object.prototype.hasOwnProperty.call(DEPRECATED_ALGS, alg)) {
    throw new Error(`${alg} is no longer supported — ${DEPRECATED_ALGS[alg]}`);
  }
  switch (alg) {
    case "AES256":
      return new AesPassphrase(roomId, opts.passphrase);
    case "DHKE":
      return new Dhke(roomId);
    case "PQKEM":
      return new Pqkem(roomId);
    case "OTP":
      return new OtpPad(roomId, opts.pad);
    default:
      throw new Error(`unsupported or unavailable algorithm: ${alg}`);
  }
}

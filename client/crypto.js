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

export function b64ToBuf(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
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

const RATCHET_MAX_SKIP = 1024;

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

class RatchetChannel {
  constructor(roomId, domain, sendChain, recvChain) {
    this.roomId = roomId;
    this.domain = domain; // per-mode AD domain, so frames can never cross modes
    this.sendChain = sendChain;
    this.recvChain = recvChain;
    this.sendSeq = 0;
    this.recvSeq = 0;
    this._q = new CallQueue(); // serializes encrypt/decrypt (see CallQueue)
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
    return dec.decode(pt);
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
// passphrase-only mode; real forward secrecy needs DHKE/PQKEM/RSA.

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
    this.chan = new RatchetChannel(this.roomId, AES_MSG_DOMAIN, await chain(myNonce), await chain(peerNonce));
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
    if (b64 === this.myPub) throw new Error("reflected handshake rejected");
    if (this.chan) return; // first key wins: ignore replays of the peer's key
    const peer = await crypto.subtle.importKey(
      "raw", b64ToBuf(b64), { name: "ECDH", namedCurve: "P-256" }, false, [],
    );
    // Run the raw ECDH secret (the shared point's X coordinate) through HKDF
    // rather than using it directly: proper key separation, with the room id
    // as salt and per-sender chain info — mirrors the other modes.
    const ecdhBits = new Uint8Array(
      await crypto.subtle.deriveBits({ name: "ECDH", public: peer }, this.kp.privateKey, 256),
    );
    const base = await crypto.subtle.importKey("raw", ecdhBits, "HKDF", false, ["deriveKey"]);
    ecdhBits.fill(0);
    const chain = (senderPubB64) =>
      crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: enc.encode(this.roomId), info: enc.encode(DHKE_CHAIN_INFO + senderPubB64) },
        base,
        HMAC_CHAIN,
        false,
        ["sign"],
      );
    this.chan = new RatchetChannel(this.roomId, DHKE_MSG_DOMAIN, await chain(this.myPub), await chain(b64));
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

// ---- shared byte helpers (RSA + PQKEM) -------------------------------------

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

// ---- RSA: RSA-OAEP-2048 key transport + forward-secret symmetric ratchet ---
// Peers swap per-session RSA public keys (identity-signed at the app layer).
// The handshake ANSWER transports a random 32-byte ROOT secret, RSA-OAEP-
// encrypted to the offerer's public key (`ws`) — classic RSA key transport.
// Both sides HKDF the root into the two chain heads of a RatchetChannel (the
// HKDF info binds each chain to its sender's public key).
//
// FORWARD SECRECY: the ratchet erases consumed keys (see RatchetChannel), and
// because a recorded transcript plus EITHER the root secret OR the RSA private
// key would replay the whole schedule, both are erased (`_seal`) the moment
// the first real message is sent or received — the handshake is settled by
// then (messaging sits behind the safety-number gate; a relay withholding a
// race answer past that point could only ever cause a loud decrypt failure,
// which it can anyway). The RSA keypair is per-session, so today's compromise
// never touches past sessions either. Note the previous design's per-message
// RSA wrapping of the AES key had to go: wrapping every message key to one
// session-long RSA key is exactly what forfeits forward secrecy.
//
// Like PQKEM, the exchange tolerates the join-order race: root secrets are
// folded into HKDF keyed by a hash of the recipient key and sorted, so both
// peers feed HKDF identical input whether one or two secrets were exchanged.

const RSA_CHAIN_INFO = "secure-chat/rsa-fs/v1|";
const RSA_MSG_DOMAIN = "secure-chat/rsa-msg/v2";

class Rsa {
  constructor(roomId) {
    this.roomId = roomId;
    this.kp = null;
    this.myPub = null;        // my SPKI public key (base64)
    this.peerPub = null;      // peer public key (CryptoKey, wraps root secrets)
    this.peerPubB64 = null;
    this.secrets = new Map(); // tag (hex SHA-256 of recipient pub b64) -> root secret
    this.answer = null;       // our reply payload, set when we answer a peer offer
    this.chan = null;
    this.sealed = false;      // handshake material erased; ratchet-only from here
    this._derivedFrom = null; // signature of the inputs the current chains came from
  }
  get needsHandshake() {
    return true;
  }
  get ready() {
    return this.chan !== null;
  }
  async init() {
    this.kp = await crypto.subtle.generateKey(
      { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      false, // private key non-extractable
      ["decrypt"],
    );
    this.myPub = bufToB64(await crypto.subtle.exportKey("spki", this.kp.publicKey));
  }
  async handshakePayload() {
    if (this.answer) return this.answer;   // reply to a peer offer
    return packMsg({ pub: this.myPub });   // initial offer
  }
  async onPeerKey(b64) {
    // Post-seal the key is final and the unwrap/wrap material is gone; a late
    // handshake frame can only be relay mischief, so ignore it (never desync).
    if (this.sealed) return;
    const m = unpackMsg(b64);
    // Our own key echoed back can only be relay mischief: honest peers never
    // share a keypair, and identical pubs would collapse the direction chains.
    if (m.pub === this.myPub) throw new Error("reflected handshake rejected");
    if (m.pub && this.peerPubB64 === null) { // first key wins
      this.peerPub = await crypto.subtle.importKey(
        "spki", b64ToBuf(m.pub), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"],
      );
      this.peerPubB64 = m.pub;
    }
    if (this.peerPubB64 === null) throw new Error("malformed RSA handshake message");
    if (m.ws) {
      // Peer answered our offer: unwrap the root secret sent to our key. First
      // write wins, so a replayed answer cannot diverge the derived chains.
      const tag = await sha256Hex(enc.encode(this.myPub));
      if (!this.secrets.has(tag)) {
        const secret = new Uint8Array(
          await crypto.subtle.decrypt({ name: "RSA-OAEP" }, this.kp.privateKey, b64ToBuf(m.ws)),
        );
        if (secret.length !== 32) throw new Error("bad root secret length");
        this.secrets.set(tag, secret);
      }
    } else {
      // Peer offered their key: choose a root secret, wrap it to them, answer.
      const tag = await sha256Hex(enc.encode(this.peerPubB64));
      if (!this.secrets.has(tag)) {
        this.secrets.set(tag, crypto.getRandomValues(new Uint8Array(32)));
      }
      const ws = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" }, this.peerPub, this.secrets.get(tag),
      );
      this.answer = packMsg({ pub: this.myPub, ws: bufToB64(ws) });
    }
    await this._derive();
  }
  // (Re)derive the direction-separated chain heads from every root secret we
  // hold, ordered by tag so both peers feed HKDF identical input. Idempotent:
  // if the inputs are unchanged (e.g. a relay replayed a handshake frame) the
  // existing chains — and their positions — are kept intact.
  async _derive() {
    if (this.peerPubB64 === null || this.secrets.size === 0) return;
    const tags = [...this.secrets.keys()].sort();
    const signature = tags.join(",");
    if (signature === this._derivedFrom) return;
    this._derivedFrom = signature;
    const ikm = concatBytes(tags.map((t) => this.secrets.get(t)));
    const base = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
    const chain = (senderPubB64) =>
      crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: enc.encode(this.roomId), info: enc.encode(RSA_CHAIN_INFO + senderPubB64) },
        base,
        HMAC_CHAIN,
        false,
        ["sign"],
      );
    this.chan = new RatchetChannel(this.roomId, RSA_MSG_DOMAIN, await chain(this.myPub), await chain(this.peerPubB64));
  }
  // Erase everything that could reconstruct past (or all) message keys: the
  // root secrets and the RSA private key. From here only the forward-stepping
  // chain heads remain. Runs on the first real message in either direction.
  _seal() {
    for (const s of this.secrets.values()) s.fill(0);
    this.secrets.clear();
    this.kp = null;      // per-session; only ever needed to unwrap `ws`
    this.peerPub = null; // only ever needed to wrap `ws`
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

// ---- PQKEM: hybrid ECDH P-256 + ML-KEM-768 -> forward-secret ratchet -------
// Post-quantum-secure session root. The ratchet chains are derived
// (HKDF-SHA-256) from BOTH a classical ECDH P-256 secret AND an ML-KEM-768
// (FIPS-203) secret, so they stay secret unless an attacker breaks BOTH —
// i.e. it resists "harvest now, decrypt later" by a future quantum adversary,
// while remaining no weaker than DHKE if ML-KEM were ever faulted.
// Authenticated by the same dual (Ed25519 + ML-DSA-65) identity handshake as
// DHKE/RSA (see app.js / auth.js).
//
// The exchange is symmetric: each peer OFFERS an ML-KEM public key, the other
// ENCAPSULATES to it, and the resulting shared secret(s) are folded in keyed by
// a hash of the encapsulation key — so both sides combine the same secrets in
// the same order. This tolerates the relay's join-order race (where both peers'
// offers are delivered) with no role negotiation: in the common case exactly
// one secret is established, in the race two, and both peers agree either way.
//
// FORWARD SECRECY: like RSA, the handshake material that could replay the key
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
    this.chan = new RatchetChannel(this.roomId, PQKEM_MSG_DOMAIN, await chain(this.myEcdhPub), await chain(this.peerEcdh));
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

// OTP (pre-shared pad) is deferred by design.
export const UNAVAILABLE = {
  OTP: "One-time-pad mode is deferred (requires in-person pad exchange).",
};

export function makeCipher(alg, roomId, opts = {}) {
  switch (alg) {
    case "AES256":
      return new AesPassphrase(roomId, opts.passphrase);
    case "DHKE":
      return new Dhke(roomId);
    case "RSA":
      return new Rsa(roomId);
    case "PQKEM":
      return new Pqkem(roomId);
    default:
      throw new Error(`unsupported or unavailable algorithm: ${alg}`);
  }
}

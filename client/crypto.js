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
// small framing (iv, ciphertext, wrapped key) without a custom binary format.

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

// AES-256-GCM encrypt/decrypt around a CryptoKey, framed as {iv, ct}.
async function gcmEncrypt(key, text) {
  const iv = randomIv();
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(text));
  return { iv: bufToB64(iv), ct: bufToB64(ct) };
}

async function gcmDecrypt(key, frame) {
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(b64ToBuf(frame.iv)) },
    key,
    b64ToBuf(frame.ct),
  );
  return dec.decode(pt);
}

function packMsg(obj) {
  return bufToB64(enc.encode(JSON.stringify(obj)));
}

function unpackMsg(b64) {
  return JSON.parse(dec.decode(b64ToBuf(b64)));
}

// ---- authenticated symmetric framing (AES256 / DHKE / PQKEM) ---------------
// These three modes all end up with a SINGLE AES-256-GCM key shared in both
// directions. That key by itself lets a malicious relay REFLECT your own
// ciphertext back at you (it would decrypt and render as "peer") or REPLAY an
// old frame. We close both by binding every frame to its SENDER and to a
// per-session SEQUENCE number inside the GCM additional data — AEAD-
// authenticated, so a relay cannot alter either without the key — then reject:
//   * reflection — a frame whose sender tag equals our own random session tag;
//   * replay     — a frame whose sequence number is not strictly increasing
//                  for that sender.
// (RSA has its own per-message HMAC construction and does not use this.)
//
// Residual for AES256 ONLY: its key is static (passphrase-derived, no exchange),
// so this stops in-session reflection/replay but NOT cross-session replay of a
// frame captured under the same passphrase + room id. DHKE/PQKEM use ephemeral
// keys per session and have no such residual.

const MSG_DOMAIN = "secure-chat/msg/v1";

class AuthChannel {
  constructor(roomId, key) {
    this.roomId = roomId;
    this.key = key;
    this.myTag = bufToB64(crypto.getRandomValues(new Uint8Array(16)));
    this.sendSeq = 0;
    this.recvSeq = new Map(); // sender tag -> highest sequence number accepted
  }
  // Canonical additional data: all parts are base64/int, so "|" is unambiguous.
  _ad(tag, n) {
    return enc.encode([MSG_DOMAIN, this.roomId, tag, n].join("|"));
  }
  async encrypt(text) {
    const iv = randomIv();
    const n = ++this.sendSeq;
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: this._ad(this.myTag, n) },
      this.key,
      enc.encode(text),
    );
    return packMsg({ iv: bufToB64(iv), ct: bufToB64(ct), tag: this.myTag, n });
  }
  async decrypt(b64) {
    const m = unpackMsg(b64);
    if (typeof m.tag !== "string" || !Number.isInteger(m.n)) throw new Error("malformed frame");
    if (m.tag === this.myTag) throw new Error("reflected frame rejected");
    if (m.n <= (this.recvSeq.get(m.tag) || 0)) throw new Error("replayed frame rejected");
    // The tag + sequence are in the additional data, so GCM authenticates them
    // as it decrypts: a relay that rewrote either would make this throw.
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(b64ToBuf(m.iv)), additionalData: this._ad(m.tag, m.n) },
      this.key,
      b64ToBuf(m.ct),
    );
    this.recvSeq.set(m.tag, m.n); // advance only after successful authentication
    return dec.decode(pt);
  }
}

// ---- AES-256 with a shared passphrase ------------------------------------
// Both users agree on a passphrase out of band. The key is derived with
// PBKDF2-SHA256 (high iteration count); the room id is used as the salt so the
// two peers derive an identical key without any network exchange.

class AesPassphrase {
  constructor(roomId, passphrase) {
    this.roomId = roomId;
    this.passphrase = passphrase;
    this.chan = null;
  }
  get needsHandshake() {
    return false;
  }
  get ready() {
    return this.chan !== null;
  }
  async init() {
    if (!this.passphrase) throw new Error("passphrase required for AES-256 mode");
    const base = await crypto.subtle.importKey(
      "raw", enc.encode(this.passphrase), "PBKDF2", false, ["deriveKey"],
    );
    const key = await crypto.subtle.deriveKey(
      // 600k PBKDF2-SHA256 iterations (OWASP 2023 guidance). Both peers run this
      // same code, so the derived key matches without any negotiation.
      { name: "PBKDF2", salt: enc.encode(this.roomId), iterations: 600000, hash: "SHA-256" },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    this.chan = new AuthChannel(this.roomId, key);
  }
  handshakePayload() {
    return null;
  }
  async onPeerKey() {}
  async encrypt(text) {
    return this.chan.encrypt(text);
  }
  async decrypt(b64) {
    return this.chan.decrypt(b64);
  }
}

// ---- DHKE: ephemeral ECDH (P-256) -> AES-256-GCM --------------------------
// Each peer makes an ephemeral keypair, swaps public keys via the relay, and
// derives a shared AES-256 key. Ephemeral keys give per-session secrecy and
// the private key is non-extractable.

class Dhke {
  constructor(roomId) {
    this.roomId = roomId;
    this.kp = null;
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
  }
  async handshakePayload() {
    const raw = await crypto.subtle.exportKey("raw", this.kp.publicKey);
    return bufToB64(raw);
  }
  async onPeerKey(b64) {
    if (this.chan) return; // first key wins: ignore replays of the peer's key
    const peer = await crypto.subtle.importKey(
      "raw", b64ToBuf(b64), { name: "ECDH", namedCurve: "P-256" }, false, [],
    );
    // Run the raw ECDH secret (the shared point's X coordinate) through HKDF
    // rather than using it directly as the AES key: proper key separation, with
    // the room id as salt and a domain tag — mirrors PQKEM's derivation.
    const ecdhBits = await crypto.subtle.deriveBits({ name: "ECDH", public: peer }, this.kp.privateKey, 256);
    const base = await crypto.subtle.importKey("raw", ecdhBits, "HKDF", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: enc.encode(this.roomId), info: enc.encode("secure-chat/dhke/v1") },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    this.chan = new AuthChannel(this.roomId, key);
  }
  async encrypt(text) {
    return this.chan.encrypt(text);
  }
  async decrypt(b64) {
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

// ---- RSA: RSA-OAEP-2048 hybrid per-message + HMAC authentication -----------
// Peers swap RSA public keys (identity-signed at the app layer). To send, we
// make a fresh AES-256 key, encrypt the message with it, and RSA-OAEP-encrypt
// that AES key to the peer. Hybrid avoids RSA's small-payload limit.
//
// RSA-OAEP alone provides NO message authenticity: anyone who saw the public
// key cross the relay — the relay itself, notably — could wrap their own AES
// key and inject messages that decrypt cleanly. So the handshake ANSWER also
// transports a random 32-byte MAC secret, RSA-OAEP-encrypted to the offerer's
// public key (`ws`). Both sides HKDF that secret into two direction-separated
// HMAC-SHA-256 keys, and every message carries a strictly increasing sequence
// number `n` plus mac = HMAC(sendKey, domain|room|n|ek|iv|ct). Verify BEFORE
// decrypt. This defeats:
//   * forgery    — the relay never learns the OAEP-wrapped MAC secret;
//   * reflection — your own frames are keyed for the opposite direction;
//   * replay     — stale `n` is rejected (and the secret is per-session).
// Like PQKEM, the exchange tolerates the join-order race: secrets are folded
// into HKDF keyed by a hash of the recipient key and sorted, so both peers
// feed HKDF identical input whether one or two secrets were exchanged.

const RSA_MAC_INFO = "secure-chat/rsa-mac/v1|";
const RSA_MSG_DOMAIN = "secure-chat/rsa-msg/v1";

class Rsa {
  constructor(roomId) {
    this.roomId = roomId;
    this.kp = null;
    this.myPub = null;        // my SPKI public key (base64)
    this.peerPub = null;      // peer public key (CryptoKey, wraps AES keys)
    this.peerPubB64 = null;
    this.secrets = new Map(); // tag (hex SHA-256 of recipient pub b64) -> MAC secret
    this.answer = null;       // our reply payload, set when we answer a peer offer
    this.sendKey = null;      // HMAC key for frames we send
    this.recvKey = null;      // HMAC key for frames we accept
    this.sendSeq = 0;
    this.recvSeq = 0;
  }
  get needsHandshake() {
    return true;
  }
  get ready() {
    return this.peerPub !== null && this.sendKey !== null;
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
    const m = unpackMsg(b64);
    if (m.pub) {
      this.peerPub = await crypto.subtle.importKey(
        "spki", b64ToBuf(m.pub), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"],
      );
      this.peerPubB64 = m.pub;
    }
    if (this.peerPubB64 === null) throw new Error("malformed RSA handshake message");
    if (m.ws) {
      // Peer answered our offer: unwrap the MAC secret sent to our key. First
      // write wins, so a replayed answer cannot diverge the derived keys.
      const tag = await sha256Hex(enc.encode(this.myPub));
      if (!this.secrets.has(tag)) {
        const secret = new Uint8Array(
          await crypto.subtle.decrypt({ name: "RSA-OAEP" }, this.kp.privateKey, b64ToBuf(m.ws)),
        );
        if (secret.length !== 32) throw new Error("bad MAC secret length");
        this.secrets.set(tag, secret);
      }
    } else {
      // Peer offered their key: choose a MAC secret, wrap it to them, answer.
      const tag = await sha256Hex(enc.encode(this.peerPubB64));
      if (!this.secrets.has(tag)) {
        this.secrets.set(tag, crypto.getRandomValues(new Uint8Array(32)));
      }
      const ws = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" }, this.peerPub, this.secrets.get(tag),
      );
      this.answer = packMsg({ pub: this.myPub, ws: bufToB64(ws) });
    }
    await this._deriveMacKeys();
  }
  // (Re)derive the direction-separated HMAC keys from every MAC secret we hold,
  // ordered by tag so both peers feed HKDF identical input. The HKDF info binds
  // each key to its sender's public key, which is what breaks reflection.
  async _deriveMacKeys() {
    if (this.peerPubB64 === null || this.secrets.size === 0) return;
    const tags = [...this.secrets.keys()].sort();
    const ikm = concatBytes(tags.map((t) => this.secrets.get(t)));
    const base = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
    const derive = (senderPubB64, usage) =>
      crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: enc.encode(this.roomId), info: enc.encode(RSA_MAC_INFO + senderPubB64) },
        base,
        { name: "HMAC", hash: "SHA-256", length: 256 },
        false,
        [usage],
      );
    this.sendKey = await derive(this.myPub, "sign");
    this.recvKey = await derive(this.peerPubB64, "verify");
  }
  // Canonical MAC input: all fields are base64/hex/int, so "|" is unambiguous.
  _macBytes(n, ek, iv, ct) {
    return enc.encode([RSA_MSG_DOMAIN, this.roomId, n, ek, iv, ct].join("|"));
  }
  async encrypt(text) {
    const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
    const frame = await gcmEncrypt(aesKey, text);
    const rawAes = await crypto.subtle.exportKey("raw", aesKey);
    const ek = bufToB64(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, this.peerPub, rawAes));
    const n = ++this.sendSeq;
    const mac = bufToB64(
      await crypto.subtle.sign("HMAC", this.sendKey, this._macBytes(n, ek, frame.iv, frame.ct)),
    );
    return packMsg({ ek, iv: frame.iv, ct: frame.ct, n, mac });
  }
  async decrypt(b64) {
    const m = unpackMsg(b64);
    // Authenticate before touching RSA/AES. HMAC verify is constant-time.
    const ok =
      this.recvKey !== null &&
      typeof m.mac === "string" &&
      (await crypto.subtle.verify("HMAC", this.recvKey, b64ToBuf(m.mac), this._macBytes(m.n, m.ek, m.iv, m.ct)));
    if (!ok) throw new Error("message authentication failed");
    if (!(Number.isInteger(m.n) && m.n > this.recvSeq)) throw new Error("replayed message");
    this.recvSeq = m.n;
    const rawAes = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, this.kp.privateKey, b64ToBuf(m.ek));
    const aesKey = await crypto.subtle.importKey("raw", rawAes, { name: "AES-GCM" }, false, ["decrypt"]);
    return gcmDecrypt(aesKey, { iv: m.iv, ct: m.ct });
  }
}

// ---- PQKEM: hybrid ECDH P-256 + ML-KEM-768 -> AES-256-GCM -----------------
// Post-quantum-secure session key. The AES key is derived (HKDF-SHA-256) from
// BOTH a classical ECDH P-256 secret AND an ML-KEM-768 (FIPS-203) secret, so it
// stays secret unless an attacker breaks BOTH — i.e. it resists "harvest now,
// decrypt later" by a future quantum adversary, while remaining no weaker than
// DHKE if ML-KEM were ever faulted. Authenticated by the same dual (Ed25519 +
// ML-DSA-65) identity handshake as DHKE/RSA (see app.js / auth.js).
//
// The exchange is symmetric: each peer OFFERS an ML-KEM public key, the other
// ENCAPSULATES to it, and the resulting shared secret(s) are folded in keyed by
// a hash of the encapsulation key — so both sides combine the same secrets in
// the same order. This tolerates the relay's join-order race (where both peers'
// offers are delivered) with no role negotiation: in the common case exactly
// one secret is established, in the race two, and both peers agree either way.

class Pqkem {
  constructor(roomId) {
    this.roomId = roomId;
    this.ecdh = null;          // ECDH P-256 keypair (deriveBits)
    this.kem = null;           // my ML-KEM-768 keypair
    this.peerEcdh = null;      // peer ECDH public key (base64), learned from any msg
    this.secrets = new Map();  // tag (hex of SHA-256(ek)) -> ML-KEM shared secret
    this.answer = null;        // our reply payload, set when we answer a peer offer
    this.chan = null;
    this._derivedFrom = null;  // signature of the inputs the current key was derived from
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
    this.kem = ml_kem768.keygen();
  }
  async _ecdhPub() {
    return bufToB64(await crypto.subtle.exportKey("raw", this.ecdh.publicKey));
  }
  // Re-derive the AES key from the ECDH secret plus every ML-KEM secret we hold,
  // ordered by tag so both peers feed HKDF identical input. Idempotent: if the
  // inputs are unchanged (e.g. a relay replayed a handshake frame) the existing
  // channel — and its replay counters — are kept intact.
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
    const key = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: enc.encode(this.roomId), info: enc.encode("secure-chat/pqkem/v1") },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    this.chan = new AuthChannel(this.roomId, key);
  }
  async handshakePayload() {
    if (this.answer) return this.answer;                                    // reply to a peer offer
    return packMsg({ e: await this._ecdhPub(), ek: bufToB64(this.kem.publicKey) }); // initial offer
  }
  async onPeerKey(b64) {
    const m = unpackMsg(b64);
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
        this.answer = packMsg({ e: await this._ecdhPub(), ct: bufToB64(cipherText) });
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
  async encrypt(text) {
    return this.chan.encrypt(text);
  }
  async decrypt(b64) {
    return this.chan.decrypt(b64);
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

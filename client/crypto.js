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

// ---- AES-256 with a shared passphrase ------------------------------------
// Both users agree on a passphrase out of band. The key is derived with
// PBKDF2-SHA256 (high iteration count); the room id is used as the salt so the
// two peers derive an identical key without any network exchange.

class AesPassphrase {
  constructor(roomId, passphrase) {
    this.roomId = roomId;
    this.passphrase = passphrase;
    this.key = null;
  }
  get needsHandshake() {
    return false;
  }
  get ready() {
    return this.key !== null;
  }
  async init() {
    if (!this.passphrase) throw new Error("passphrase required for AES-256 mode");
    const base = await crypto.subtle.importKey(
      "raw", enc.encode(this.passphrase), "PBKDF2", false, ["deriveKey"],
    );
    this.key = await crypto.subtle.deriveKey(
      // 600k PBKDF2-SHA256 iterations (OWASP 2023 guidance). Both peers run this
      // same code, so the derived key matches without any negotiation.
      { name: "PBKDF2", salt: enc.encode(this.roomId), iterations: 600000, hash: "SHA-256" },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }
  handshakePayload() {
    return null;
  }
  async onPeerKey() {}
  async encrypt(text) {
    return packMsg(await gcmEncrypt(this.key, text));
  }
  async decrypt(b64) {
    return gcmDecrypt(this.key, unpackMsg(b64));
  }
}

// ---- DHKE: ephemeral ECDH (P-256) -> AES-256-GCM --------------------------
// Each peer makes an ephemeral keypair, swaps public keys via the relay, and
// derives a shared AES-256 key. Ephemeral keys give per-session secrecy and
// the private key is non-extractable.

class Dhke {
  constructor() {
    this.kp = null;
    this.key = null;
  }
  get needsHandshake() {
    return true;
  }
  get ready() {
    return this.key !== null;
  }
  async init() {
    this.kp = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      false, // private key non-extractable
      ["deriveKey"],
    );
  }
  async handshakePayload() {
    const raw = await crypto.subtle.exportKey("raw", this.kp.publicKey);
    return bufToB64(raw);
  }
  async onPeerKey(b64) {
    const peer = await crypto.subtle.importKey(
      "raw", b64ToBuf(b64), { name: "ECDH", namedCurve: "P-256" }, false, [],
    );
    this.key = await crypto.subtle.deriveKey(
      { name: "ECDH", public: peer },
      this.kp.privateKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }
  async encrypt(text) {
    return packMsg(await gcmEncrypt(this.key, text));
  }
  async decrypt(b64) {
    return gcmDecrypt(this.key, unpackMsg(b64));
  }
}

// ---- RSA: RSA-OAEP-2048 public keys, hybrid per-message -------------------
// Peers swap RSA public keys. To send, we make a fresh AES-256 key, encrypt the
// message with it, and RSA-OAEP-encrypt that AES key to the peer. Hybrid avoids
// RSA's small-payload limit and is the standard secure construction.

class Rsa {
  constructor() {
    this.kp = null;
    this.peerPub = null;
  }
  get needsHandshake() {
    return true;
  }
  get ready() {
    return this.peerPub !== null;
  }
  async init() {
    this.kp = await crypto.subtle.generateKey(
      { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      false, // private key non-extractable
      ["decrypt"],
    );
  }
  async handshakePayload() {
    const spki = await crypto.subtle.exportKey("spki", this.kp.publicKey);
    return bufToB64(spki);
  }
  async onPeerKey(b64) {
    this.peerPub = await crypto.subtle.importKey(
      "spki", b64ToBuf(b64), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"],
    );
  }
  async encrypt(text) {
    const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
    const frame = await gcmEncrypt(aesKey, text);
    const rawAes = await crypto.subtle.exportKey("raw", aesKey);
    const ek = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, this.peerPub, rawAes);
    return packMsg({ ek: bufToB64(ek), iv: frame.iv, ct: frame.ct });
  }
  async decrypt(b64) {
    const m = unpackMsg(b64);
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

class Pqkem {
  constructor(roomId) {
    this.roomId = roomId;
    this.ecdh = null;          // ECDH P-256 keypair (deriveBits)
    this.kem = null;           // my ML-KEM-768 keypair
    this.peerEcdh = null;      // peer ECDH public key (base64), learned from any msg
    this.secrets = new Map();  // tag (hex of SHA-256(ek)) -> ML-KEM shared secret
    this.answer = null;        // our reply payload, set when we answer a peer offer
    this.key = null;
  }
  get needsHandshake() {
    return true;
  }
  get ready() {
    return this.key !== null;
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
  // ordered by tag so both peers feed HKDF identical input.
  async _derive() {
    if (this.peerEcdh === null || this.secrets.size === 0) return;
    const peer = await crypto.subtle.importKey(
      "raw", b64ToBuf(this.peerEcdh), { name: "ECDH", namedCurve: "P-256" }, false, [],
    );
    const ecdhBits = new Uint8Array(
      await crypto.subtle.deriveBits({ name: "ECDH", public: peer }, this.ecdh.privateKey, 256),
    );
    const tags = [...this.secrets.keys()].sort();
    const ikm = concatBytes([ecdhBits, ...tags.map((t) => this.secrets.get(t))]);
    const base = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
    this.key = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: enc.encode(this.roomId), info: enc.encode("secure-chat/pqkem/v1") },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }
  async handshakePayload() {
    if (this.answer) return this.answer;                                    // reply to a peer offer
    return packMsg({ e: await this._ecdhPub(), ek: bufToB64(this.kem.publicKey) }); // initial offer
  }
  async onPeerKey(b64) {
    const m = unpackMsg(b64);
    if (m.e) this.peerEcdh = m.e;
    if (m.ek) {
      // Peer offered a KEM key: encapsulate to it, answer with the ciphertext.
      const ek = new Uint8Array(b64ToBuf(m.ek));
      const { cipherText, sharedSecret } = ml_kem768.encapsulate(ek);
      this.secrets.set(await sha256Hex(ek), sharedSecret);
      this.answer = packMsg({ e: await this._ecdhPub(), ct: bufToB64(cipherText) });
    } else if (m.ct) {
      // Peer answered our offer: decapsulate with our KEM secret key.
      const ss = ml_kem768.decapsulate(new Uint8Array(b64ToBuf(m.ct)), this.kem.secretKey);
      this.secrets.set(await sha256Hex(this.kem.publicKey), ss);
    } else {
      throw new Error("malformed PQKEM handshake message");
    }
    await this._derive();
  }
  async encrypt(text) {
    return packMsg(await gcmEncrypt(this.key, text));
  }
  async decrypt(b64) {
    return gcmDecrypt(this.key, unpackMsg(b64));
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
      return new Dhke();
    case "RSA":
      return new Rsa();
    case "PQKEM":
      return new Pqkem(roomId);
    default:
      throw new Error(`unsupported or unavailable algorithm: ${alg}`);
  }
}

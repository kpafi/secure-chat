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
      { name: "PBKDF2", salt: enc.encode(this.roomId), iterations: 310000, hash: "SHA-256" },
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

// Algorithms not yet implemented. PQ KEM (ML-KEM) is not in Web Crypto yet and
// needs a vetted WASM library; OTP (pre-shared pad) is deferred by design.
export const UNAVAILABLE = {
  PQKEM: "Post-quantum KEM needs a vetted WASM library (planned).",
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
    default:
      throw new Error(`unsupported or unavailable algorithm: ${alg}`);
  }
}

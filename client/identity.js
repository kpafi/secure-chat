// Long-term identity keys and in-person verification.
//
// Every account has a DUAL identity keypair:
//   * classical: Ed25519 (Web Crypto, native)
//   * post-quantum: ML-DSA-65 / Dilithium (@noble/post-quantum)
//
// Private keys are generated on the device and never sent to the server. The
// PUBLIC keys are the account's identity; two people verify each other's keys
// IN PERSON by comparing a fingerprint (single identity) or a safety number
// (the pair). Once verified+pinned, these identity keys sign the per-session
// ephemeral key exchange (see auth.js / DHKE), which authenticates the channel
// and defeats a man-in-the-middle relay.
//
// Both signatures must verify for any check to pass: an attacker would have to
// break BOTH a classical AND a post-quantum signature scheme.

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

const enc = new TextEncoder();

// Fixed public-key sizes, mirroring backend/config.py. Used to reject malformed
// bundles before they are hashed into a fingerprint / safety number (F-07).
const ED25519_PUB_BYTES = 32;
const MLDSA65_PUB_BYTES = 1952;
const ECDH_PUB_BYTES = 65;      // P-256 uncompressed point
const MLKEM768_PUB_BYTES = 1184;

// ---- small byte/encoding helpers (kept local so this module stands alone) --

function b64(bytes) {
  let bin = "";
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < u.length; i++) bin += String.fromCharCode(u[i]);
  return btoa(bin);
}
function unb64(s) {
  const bin = atob(s);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
// JWK coordinates are base64URL with the padding stripped (RFC 7515 §2).
function unb64url(s) {
  const pad = s.replace(/-/g, "+").replace(/_/g, "/");
  return unb64(pad + "=".repeat((4 - (pad.length % 4)) % 4));
}
function concat(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}
async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

// Render a digest as human-readable groups for reading aloud / comparing.
function groupHex(bytes, groups = 16) {
  const hex = Array.from(bytes.slice(0, groups), (b) => b.toString(16).padStart(2, "0"));
  const out = [];
  for (let i = 0; i < hex.length; i += 2) out.push((hex[i] + hex[i + 1]).toUpperCase());
  return out.join(" ");
}

// ---- Identity -------------------------------------------------------------

export class Identity {
  constructor({ edPriv, edPubRaw, mldsaSecret, mldsaPub, ecdhPriv, ecdhPubRaw, mlkemSecret, mlkemPub }) {
    this._edPriv = edPriv; // CryptoKey (Ed25519 private)
    this.edPubRaw = edPubRaw; // Uint8Array(32)
    this._mldsaSecret = mldsaSecret; // Uint8Array
    this.mldsaPub = mldsaPub; // Uint8Array(1952)
    // Encryption keys (bundle v2, for the async sealed envelope). SIGNING keys
    // above define the identity (fingerprint/safety number cover only them);
    // these are bound to it by the dual-signed registration bundle.
    this._ecdhPriv = ecdhPriv || null;   // CryptoKey (P-256 ECDH private)
    this.ecdhPubRaw = ecdhPubRaw || null; // Uint8Array(65, uncompressed point)
    this._mlkemSecret = mlkemSecret || null; // Uint8Array
    this.mlkemPub = mlkemPub || null;    // Uint8Array(1184)
    this.upgraded = false; // true when import() added missing encryption keys
  }

  static async _genEncKeys() {
    const ek = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const ecdhPubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", ek.publicKey));
    const kk = ml_kem768.keygen();
    return { ecdhPriv: ek.privateKey, ecdhPubRaw, mlkemSecret: kk.secretKey, mlkemPub: kk.publicKey };
  }

  static async generate() {
    const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const edPubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const mk = ml_dsa65.keygen(seed);
    const encKeys = await Identity._genEncKeys();
    return new Identity({
      edPriv: kp.privateKey,
      edPubRaw,
      mldsaSecret: mk.secretKey,
      mldsaPub: mk.publicKey,
      ...encKeys,
    });
  }

  // The shareable public identity (what the server stores and others pin).
  // `ecdh`/`mlkem` are absent on a pre-upgrade identity that has not been
  // unlocked (and thus upgraded) yet.
  publicBundle() {
    const b = { ed: b64(this.edPubRaw), mldsa: b64(this.mldsaPub) };
    if (this.ecdhPubRaw && this.mlkemPub) {
      b.ecdh = b64(this.ecdhPubRaw);
      b.mlkem = b64(this.mlkemPub);
    }
    return b;
  }

  // ECDH shared secret with a peer's public encryption key (sealed envelope).
  async ecdhSharedBits(peerEcdhPubRaw) {
    if (!this._ecdhPriv) throw new Error("identity has no encryption keys yet");
    const peer = await crypto.subtle.importKey(
      "raw", peerEcdhPubRaw, { name: "ECDH", namedCurve: "P-256" }, false, [],
    );
    return new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: peer }, this._ecdhPriv, 256));
  }

  mlkemDecapsulate(ciphertext) {
    if (!this._mlkemSecret) throw new Error("identity has no encryption keys yet");
    return ml_kem768.decapsulate(ciphertext, this._mlkemSecret);
  }

  // Per-identity fingerprint: read this aloud to confirm a single key is right.
  async fingerprint() {
    return Identity.fingerprintOf(this.publicBundle());
  }

  // Classical-only signature (base64 Ed25519). Used for server account proofs
  // (registration binding, login challenge) where the server is a public-key
  // directory, not the authenticity root — so only the classical key is needed.
  async signEd(msgBytes) {
    return b64(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, this._edPriv, msgBytes)));
  }

  // Dual signature over a message: both schemes sign the same bytes.
  async sign(msgBytes) {
    const edSig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, this._edPriv, msgBytes));
    const mldsaSig = ml_dsa65.sign(msgBytes, this._mldsaSecret);
    return { ed: b64(edSig), mldsa: b64(mldsaSig) };
  }

  // Encrypt the private keys at rest with a passphrase (PBKDF2 -> AES-256-GCM).
  // The result is safe to keep in localStorage; the passphrase never leaves
  // the device and is required to unlock the identity.
  async export(passphrase) {
    if (!passphrase) throw new Error("a passphrase is required to protect the identity");
    const edPkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", await this._reimportExtractable()));
    const inner = {
      edPriv: b64(edPkcs8),
      edPub: b64(this.edPubRaw),
      mldsaSecret: b64(this._mldsaSecret),
      mldsaPub: b64(this.mldsaPub),
    };
    if (this._ecdhPriv) {
      const ecdhPkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", this._ecdhPriv));
      inner.ecdhPriv = b64(ecdhPkcs8);
      inner.ecdhPub = b64(this.ecdhPubRaw);
      inner.mlkemSecret = b64(this._mlkemSecret);
      inner.mlkemPub = b64(this.mlkemPub);
    }
    const plain = enc.encode(JSON.stringify(inner));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const iters = KDF_ITERS;
    const key = await deriveKey(passphrase, salt, iters);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
    // `iters` is stored so the count can be raised over time without breaking
    // existing backups (import reads it; pre-v2 blobs default to the old count).
    // v3 = may carry encryption keys; v2 blobs import fine (keys added then).
    return JSON.stringify({ v: 3, iters, salt: b64(salt), iv: b64(iv), ct: b64(ct) });
  }

  // Ed25519 private keys generated as non-extractable can't be exported; we
  // generate them extractable (see generate) so they can be wrapped at rest.
  async _reimportExtractable() {
    return this._edPriv;
  }

  static async import(blob, passphrase) {
    // Audit 2026-07-18 L-01: cap the file before any parsing/decoding. A
    // genuine backup (incl. ML-DSA/ML-KEM private material) is well under
    // 64 KiB; 256 KiB leaves room for future fields without letting a crafted
    // file drive large JSON/base64 allocations.
    if (typeof blob !== "string" || blob.length > 256 * 1024) {
      throw new Error("not a valid identity backup file");
    }
    const { salt, iv, ct, iters } = JSON.parse(blob);
    const key = await deriveKey(passphrase, unb64(salt), iters || 310000);
    let plain;
    try {
      plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, key, unb64(ct));
    } catch {
      throw new Error("wrong passphrase or corrupted identity");
    }
    const o = JSON.parse(new TextDecoder().decode(plain));
    const edPriv = await crypto.subtle.importKey("pkcs8", unb64(o.edPriv), { name: "Ed25519" }, true, ["sign"]);
    const fields = {
      edPriv,
      edPubRaw: unb64(o.edPub),
      mldsaSecret: unb64(o.mldsaSecret),
      mldsaPub: unb64(o.mldsaPub),
    };
    if (o.ecdhPriv) {
      fields.ecdhPriv = await crypto.subtle.importKey(
        "pkcs8", unb64(o.ecdhPriv), { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"],
      );
      fields.ecdhPubRaw = unb64(o.ecdhPub);
      fields.mlkemSecret = unb64(o.mlkemSecret);
      fields.mlkemPub = unb64(o.mlkemPub);
    }
    const id = new Identity(fields);
    if (!o.ecdhPriv) {
      // Pre-v3 blob: add encryption keys now. The SIGNING identity (and thus
      // fingerprint/safety number/pins) is unchanged; the caller should
      // re-export the blob and re-register so the directory learns the keys.
      Object.assign(id, await Identity._genEncKeys().then((k) => ({
        _ecdhPriv: k.ecdhPriv, ecdhPubRaw: k.ecdhPubRaw,
        _mlkemSecret: k.mlkemSecret, mlkemPub: k.mlkemPub,
      })));
      id.upgraded = true;
    }
    // Pentest 2026-07-26 P-17: prove the imported PUBLIC keys really belong to
    // the imported PRIVATE keys. A truncated, mismatched or hand-edited backup
    // otherwise yields an identity that signs with one key while publishing
    // another: every signature it makes fails verification elsewhere, with no
    // clue why, and the safety number shown to a contact describes a key it
    // cannot actually use. Sign a fixed vector with both signing keys and verify
    // against the stored public bundle — cheap, and it fails closed at import.
    await id._assertKeypairsConsistent();
    return id;
  }

  // Self-test used by import(): prove that EVERY stored public key really
  // corresponds to the stored private key beside it — signing keys by signing
  // and verifying a probe, ML-KEM by an encapsulate/decapsulate round trip, and
  // ECDH by re-deriving the public point from the private key. All four keys are
  // trust anchors (the fingerprint and safety number hash all of them), so a
  // backup that pairs one key with another's public half would show contacts a
  // safety number for a key it cannot actually use.
  async _assertKeypairsConsistent() {
    const probe = new TextEncoder().encode("secure-chat/identity-selftest/v1");
    let ok = false;
    try {
      ok = await Identity.verify(this.publicBundle(), probe, await this.sign(probe));
    } catch {
      ok = false;
    }
    if (!ok) {
      throw new Error(
        "identity backup is inconsistent: its signing public keys do not match its private keys — refusing to load it",
      );
    }
    if (!this.ecdhPubRaw && !this.mlkemPub) return; // signing-only (pre-v2) identity

    if (this.ecdhPubRaw.length !== ECDH_PUB_BYTES) {
      throw new Error("identity backup has a malformed ECDH public key");
    }
    if (this.mlkemPub.length !== MLKEM768_PUB_BYTES) {
      throw new Error("identity backup has a malformed ML-KEM public key");
    }
    // ML-KEM: encapsulating to the stored public key must produce a secret the
    // stored secret key can recover.
    let kemOk = false;
    try {
      const { cipherText, sharedSecret } = ml_kem768.encapsulate(this.mlkemPub);
      const back = ml_kem768.decapsulate(cipherText, this._mlkemSecret);
      kemOk = back.length === sharedSecret.length && back.every((b, i) => b === sharedSecret[i]);
    } catch {
      kemOk = false;
    }
    if (!kemOk) {
      throw new Error(
        "identity backup is inconsistent: its ML-KEM public key does not match its secret key — refusing to load it",
      );
    }
    // ECDH: the private key's own public point must equal the stored one. The
    // key is imported extractable, so JWK export gives x/y directly.
    let ecdhOk = false;
    try {
      const jwk = await crypto.subtle.exportKey("jwk", this._ecdhPriv);
      const x = unb64url(jwk.x);
      const y = unb64url(jwk.y);
      const derived = concat(new Uint8Array([0x04]), x, y); // uncompressed point
      ecdhOk = derived.length === this.ecdhPubRaw.length &&
        derived.every((b, i) => b === this.ecdhPubRaw[i]);
    } catch {
      ecdhOk = false;
    }
    if (!ecdhOk) {
      throw new Error(
        "identity backup is inconsistent: its ECDH public key does not match its private key — refusing to load it",
      );
    }
  }

  // ---- static verification (no private material needed) -------------------

  // Verify a dual signature against a peer's PUBLIC bundle. Returns true only
  // if BOTH the Ed25519 and the ML-DSA signatures are valid.
  static async verify(publicBundle, msgBytes, sigBundle) {
    const edPub = await crypto.subtle.importKey("raw", unb64(publicBundle.ed), { name: "Ed25519" }, true, ["verify"]);
    const edOk = await crypto.subtle.verify({ name: "Ed25519" }, edPub, unb64(sigBundle.ed), msgBytes);
    let pqOk = false;
    try {
      pqOk = ml_dsa65.verify(unb64(sigBundle.mldsa), msgBytes, unb64(publicBundle.mldsa));
    } catch {
      pqOk = false;
    }
    return edOk && pqOk;
  }

  // Canonical bytes covering ALL public keys in a bundle. H-01: the ENCRYPTION
  // keys (ecdh/mlkem) are folded in when present, so an in-person fingerprint /
  // safety-number comparison also authenticates the keys used to seal async
  // messages — a relay that swaps only ecdh/mlkem (keeping the signing
  // identity) produces a DIFFERENT value on the honest peer's device and is
  // caught. A pre-v2 bundle (no enc keys) hashes exactly as before, so legacy
  // fingerprints are unchanged.
  static _bundleBytes(bundle) {
    // Pentest 2026-07-25 F-07: this concatenation is what the fingerprint and
    // safety number hash, so it is the client's canonicalisation boundary. The
    // fields have fixed sizes, which is the only reason two different bundles
    // cannot be made to concatenate identically — enforce that explicitly here
    // rather than leaving it as an emergent property of how the keys are used
    // downstream. A wrong-length key is a malformed bundle, not a comparison.
    const field = (b64s, want, name) => {
      const raw = unb64(b64s);
      if (raw.length !== want) {
        throw new Error(`malformed identity bundle: ${name} is ${raw.length} bytes, expected ${want}`);
      }
      return raw;
    };
    const parts = [
      field(bundle.ed, ED25519_PUB_BYTES, "ed"),
      field(bundle.mldsa, MLDSA65_PUB_BYTES, "mldsa"),
    ];
    if (bundle.ecdh && bundle.mlkem) {
      parts.push(
        field(bundle.ecdh, ECDH_PUB_BYTES, "ecdh"),
        field(bundle.mlkem, MLKEM768_PUB_BYTES, "mlkem"),
      );
    }
    return concat(...parts);
  }

  // Fixed-length (32-byte) commitment to ALL public keys in a bundle. Pentest
  // 2026-07-26 P-03: the handshake transcript binds the signer's own bundle
  // through this rather than through `_bundleBytes` directly, because that
  // function's output length VARIES (1984 bytes for a signing-only bundle, 3233
  // once the encryption keys are present). Concatenating a variable-length field
  // ahead of the ephemeral key would reintroduce exactly the splice ambiguity
  // F-07 removed; a digest is constant-width, so the transcript stays unambiguous.
  static async bundleDigest(publicBundle) {
    return sha256(Identity._bundleBytes(publicBundle));
  }

  static async fingerprintOf(publicBundle) {
    const digest = await Identity.bundleDigest(publicBundle);
    return groupHex(digest);
  }

  // Safety number for a PAIR of identities (Signal-style): order-independent so
  // both people see the same value to compare in person.
  static async safetyNumber(bundleA, bundleB) {
    const a = Identity._bundleBytes(bundleA);
    const b = Identity._bundleBytes(bundleB);
    const [lo, hi] = compareBytes(a, b) <= 0 ? [a, b] : [b, a];
    const digest = await sha256(concat(lo, hi));
    return groupHex(digest, 20);
  }
}

// PBKDF2-SHA256 work factor for identity-at-rest (OWASP 2023 guidance).
const KDF_ITERS = 600000;

// Audit 2026-07-18 L-01: `iters`/`salt` reach deriveKey from imported backup
// files and persistent storage. Bound them BEFORE WebCrypto runs — a crafted
// blob with a huge count would stall the UI for hours, a tiny one would
// silently weaken the KDF. The floor sits below the oldest legacy count
// (310k) so every genuine blob still opens.
const KDF_MIN_ITERS = 100000;
const KDF_MAX_ITERS = 5000000;

function checkKdfParams(salt, iters) {
  if (!Number.isInteger(iters) || iters < KDF_MIN_ITERS || iters > KDF_MAX_ITERS) {
    throw new Error("invalid key-derivation parameters (iteration count)");
  }
  if (!(salt instanceof Uint8Array) || salt.length < 8 || salt.length > 64) {
    throw new Error("invalid key-derivation parameters (salt)");
  }
}

async function deriveKey(passphrase, salt, iters = KDF_ITERS) {
  checkKdfParams(salt, iters);
  const base = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: iters, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function compareBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

export { b64, unb64, concat };

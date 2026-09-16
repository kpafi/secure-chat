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
// Pentest 2026-07-27 H-1: `atob` implements WHATWG *forgiving* base64. It
// strips ASCII whitespace, tolerates missing padding, and — the sharp edge —
// DISCARDS the trailing slack bits instead of rejecting them. Every fixed-size
// key here has a length ≡ 2 (mod 3), i.e. 2 slack bits, so FOUR distinct base64
// strings decode to the identical bytes (256 spellings of a four-field bundle).
//
// That split a single value into two domains: byte checks (bundleDigest, the
// handshake transcript, the safety number, Identity.verify) are encoding-blind
// and PASS on a mutated spelling, while string checks (sameBundle, pin
// persistence, the reflection guard) compare the raw received text and DIVERGE.
// A relay flipping one character could therefore fire false "identity key
// CHANGED" alarms at will, make a guest pin a non-canonical string, and
// permanently break async chats (sealed.js signs the stored string but
// recomputes from canonical bytes). It never yielded a false MATCH — string
// equality is strictly finer than byte equality — but it eroded exactly the
// trust signal the design calls the real boundary.
//
// The fix is to remove the second domain: decoding is CANONICAL, so every
// string that survives it is the unique spelling of its bytes and the two kinds
// of check can no longer disagree. Non-canonical input is a malformed value and
// fails closed here, before any signature, digest or comparison sees it.
const B64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

function unb64(s) {
  if (typeof s !== "string" || s.length % 4 !== 0 || !B64_RE.test(s)) {
    throw new Error("malformed base64: not canonical");
  }
  const bin = atob(s);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  // Re-encode and require an exact match. The alphabet/padding checks above
  // cannot see slack bits; this does, and it is the check that collapses the
  // four spellings of a key back to one.
  if (b64(u) !== s) throw new Error("malformed base64: not canonical");
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
    // Authenticated device facts, carried INSIDE this identity's AEAD.
    //
    // Pentest 2026-08-07 F-ATREST-003/004 (both confirmed). The contact store's
    // anti-deletion control was a witness in localStorage, and its whole truth
    // table bottomed out in "neither store nor witness present -> genuine first
    // run -> proceed". Both are plain localStorage keys and deleting one needs
    // no passphrase, so two `removeItem` calls produced a silent, empty,
    // PIN-LESS store: key-change detection simply off, alarm inverted, evidence
    // healed on the next persist. L-1 raised the cost from one removeItem to
    // two and bought nothing else.
    //
    // The bit that says "a store was established on this device" therefore
    // cannot live in a deletable key. It lives here instead. Contents are
    // one-shot booleans (see contacts.js), so this costs one extra re-export
    // over the life of the device, not one per save.
    //
    // HONEST LIMIT (fix review 2026-08-07, F4). An earlier version of this
    // comment claimed the flag "cannot be deleted without deleting the identity
    // itself", and that is FALSE. An attacker does not have to delete the blob
    // — they roll it back. A restored older `sc.identity.v1` opens with the
    // same passphrase and carries the same keys, fingerprint and safety number,
    // so the user notices nothing; `import` below then reads no `flags`, the
    // anchor reads false, and the contact store's deletion check takes its
    // "genuine first run" path. Cost to the attacker: one setItem plus the two
    // removeItem calls they already had.
    //
    // Note this is not hypothetical for existing devices: every identity blob
    // written before this change has no `flags` field at all, so today's blob
    // IS the archived artifact.
    //
    // The anchor is therefore only as strong as the identity blob's own
    // rollback resistance. F-ATREST-008 (fixed 2026-09-16, see identity-store.js)
    // gives the blob that resistance ON ANDROID: `generation` below is a monotone
    // counter sealed inside this AEAD and mirrored into the device's Keystore-MACed
    // floor after every write, so a restored older blob is one whose counter is
    // BEHIND the floor — and identity-store.js then reads every anchor as
    // established (fails closed) instead of believing the archived copy. In a
    // plain browser there is no floor and the residual stands, exactly as for OTP.
    this.deviceFlags = {};
    // F-ATREST-008. Monotone write counter for the blob AT REST. 0 means "never
    // written with a counter" — every blob from before this change reads as 0,
    // which is deliberately the OLDEST possible value: once a device has recorded
    // any newer generation, the archived pre-fix blob is a rollback and is
    // caught. This class only CARRIES the counter; identity-store.js is what
    // advances it and compares it against the floor (the same split as
    // contacts.js's generation vs. its witness).
    this.generation = 0;
    // What the writer measured about the native floor when this blob was sealed:
    // `true` = a floor slot for the identity existed and was read back, `false`
    // = no floor on that device (a plain browser), "unconfirmed" = a bridge was
    // present but the slot's durable write could not be confirmed. The same three
    // values, for the same reasons, as otp.js's CLAIM_* (A4/F-A3): a floor that
    // was in force and is now ABSENT is evidence of deletion, and "could not
    // arm" must never be spelled the same as "never had one".
    this.floorClaim = false;
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
      // F-ATREST-003/004: inside the AEAD, so it cannot be forged or stripped
      // without the passphrase. (It CAN be rolled back with the whole blob —
      // that is what `gen` below is for; see the constructor.)
      flags: this.deviceFlags || {},
      // F-ATREST-008: both inside the AEAD, so a rolled-back blob carries its
      // own OLD counter and cannot be re-labelled as current without the
      // passphrase.
      gen: this.generation,
      floor: this.floorClaim,
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
    // Absent on any blob written before F-ATREST-003/004, which reads as "this
    // device has not recorded a contact store yet" — the safe default, since a
    // device that genuinely has one will record it on the next unlock.
    id.deviceFlags = (o.flags && typeof o.flags === "object" && !Array.isArray(o.flags)) ? o.flags : {};
    // F-ATREST-008. Absent on every pre-fix blob, and anything that is not a
    // non-negative integer is read as 0 — the OLDEST value, so a malformed
    // counter can only make the blob look older than the device's floor (a
    // rollback verdict, fail-closed), never newer.
    id.generation = (Number.isInteger(o.gen) && o.gen >= 0) ? o.gen : 0;
    // Only the three known claim values are accepted; anything else reads as
    // "unconfirmed", which claims nothing (no deletion alarm can be built on
    // it) but still gets the rollback comparison. It must NOT read as `true`:
    // a blob that claims a floor it never had would raise a false deletion
    // alarm on the device it was written on.
    id.floorClaim = (o.floor === true || o.floor === false) ? o.floor : "unconfirmed";
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

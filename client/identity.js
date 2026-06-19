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

const enc = new TextEncoder();

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
  constructor({ edPriv, edPubRaw, mldsaSecret, mldsaPub }) {
    this._edPriv = edPriv; // CryptoKey (Ed25519 private)
    this.edPubRaw = edPubRaw; // Uint8Array(32)
    this._mldsaSecret = mldsaSecret; // Uint8Array
    this.mldsaPub = mldsaPub; // Uint8Array(1952)
  }

  static async generate() {
    const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const edPubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const mk = ml_dsa65.keygen(seed);
    return new Identity({
      edPriv: kp.privateKey,
      edPubRaw,
      mldsaSecret: mk.secretKey,
      mldsaPub: mk.publicKey,
    });
  }

  // The shareable public identity (what the server stores and others pin).
  publicBundle() {
    return { ed: b64(this.edPubRaw), mldsa: b64(this.mldsaPub) };
  }

  // Per-identity fingerprint: read this aloud to confirm a single key is right.
  async fingerprint() {
    return Identity.fingerprintOf(this.publicBundle());
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
    const plain = enc.encode(
      JSON.stringify({
        edPriv: b64(edPkcs8),
        edPub: b64(this.edPubRaw),
        mldsaSecret: b64(this._mldsaSecret),
        mldsaPub: b64(this.mldsaPub),
      }),
    );
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(passphrase, salt);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
    return JSON.stringify({ v: 1, salt: b64(salt), iv: b64(iv), ct: b64(ct) });
  }

  // Ed25519 private keys generated as non-extractable can't be exported; we
  // generate them extractable (see generate) so they can be wrapped at rest.
  async _reimportExtractable() {
    return this._edPriv;
  }

  static async import(blob, passphrase) {
    const { salt, iv, ct } = JSON.parse(blob);
    const key = await deriveKey(passphrase, unb64(salt));
    let plain;
    try {
      plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, key, unb64(ct));
    } catch {
      throw new Error("wrong passphrase or corrupted identity");
    }
    const o = JSON.parse(new TextDecoder().decode(plain));
    const edPriv = await crypto.subtle.importKey("pkcs8", unb64(o.edPriv), { name: "Ed25519" }, true, ["sign"]);
    return new Identity({
      edPriv,
      edPubRaw: unb64(o.edPub),
      mldsaSecret: unb64(o.mldsaSecret),
      mldsaPub: unb64(o.mldsaPub),
    });
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

  static async fingerprintOf(publicBundle) {
    const digest = await sha256(concat(unb64(publicBundle.ed), unb64(publicBundle.mldsa)));
    return groupHex(digest);
  }

  // Safety number for a PAIR of identities (Signal-style): order-independent so
  // both people see the same value to compare in person.
  static async safetyNumber(bundleA, bundleB) {
    const a = concat(unb64(bundleA.ed), unb64(bundleA.mldsa));
    const b = concat(unb64(bundleB.ed), unb64(bundleB.mldsa));
    const [lo, hi] = compareBytes(a, b) <= 0 ? [a, b] : [b, a];
    const digest = await sha256(concat(lo, hi));
    return groupHex(digest, 20);
  }
}

async function deriveKey(passphrase, salt) {
  const base = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256" },
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

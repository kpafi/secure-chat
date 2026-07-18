// Sealed envelope: asynchronous E2EE to a contact's PUBLIC bundle, no live
// session needed (the transport for the Chats feature).
//
// Construction (hybrid, both legs must break to read):
//   * ephemeral ECDH P-256 against the recipient's registered `ecdh` key
//   * ML-KEM-768 encapsulation against their registered `mlkem` key
//   * key = HKDF-SHA256(ss_ecdh || ss_kem, salt = domain, info = recipient ed)
//   * AES-256-GCM over the inner payload
//
// Sealed sender: the sender's identity bundle and a DUAL signature (Ed25519 +
// ML-DSA-65) live INSIDE the ciphertext — the relay/mailbox never learns who
// wrote a message. The signature covers the domain, the RECIPIENT's identity
// key, the ephemeral key, and the KEM ciphertext, so an envelope cannot be
// re-targeted at someone else or have its key material swapped. Authenticity
// of `from` still follows the app's trust model: the receiving UI must check
// the sender bundle against its own contact pins / safety marks.
//
// Forward secrecy is per-envelope only (fresh ephemeral + KEM secret each
// time); compromise of the recipient's long-term encryption keys exposes past
// envelopes captured on the wire. That is the documented trade-off of
// store-and-forward without a live ratchet.

import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { Identity, b64, unb64, concat } from "./identity.js";

const DOMAIN = "secure-chat/sealed/v1";
const enc = new TextEncoder();
const dec = new TextDecoder();

function signBytes(recipientEdB64, ephB64, kemB64, coreJson) {
  return enc.encode([DOMAIN, recipientEdB64, ephB64, kemB64, coreJson].join("\n"));
}

async function deriveEnvelopeKey(ss1, ss2, recipientEdRaw) {
  const ikm = await crypto.subtle.importKey("raw", concat(ss1, ss2), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: enc.encode(DOMAIN), info: recipientEdRaw },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

// Seal `text` to `recipientBundle` (must carry ecdh+mlkem — bundle v2).
// Returns a JSON string safe to hand to an untrusted mailbox.
// `content` is either a plain string (a text message) or an object
// {kind, ...} for control traffic (mode negotiation). It is placed in the
// signed core, so control messages are authenticated exactly like text.
export async function seal(senderIdentity, recipientBundle, content, senderName = null) {
  if (!recipientBundle.ecdh || !recipientBundle.mlkem) {
    throw new Error("recipient has no encryption keys (they must re-register with the updated app)");
  }
  const eph = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const ephPubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const recipientEcdh = await crypto.subtle.importKey(
    "raw", unb64(recipientBundle.ecdh), { name: "ECDH", namedCurve: "P-256" }, false, [],
  );
  const ss1 = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: recipientEcdh }, eph.privateKey, 256));
  const { cipherText: kemCt, sharedSecret: ss2 } = ml_kem768.encapsulate(unb64(recipientBundle.mlkem));

  const body = typeof content === "string" ? { kind: "msg", msg: content } : content;
  const core = JSON.stringify({
    from: senderIdentity.publicBundle(),
    name: senderName, // self-claimed display name, signed but NOT trust-bearing:
                      // receivers key chats by the bundle, never by this string
    ...body,
    ts: Date.now(),
    id: b64(crypto.getRandomValues(new Uint8Array(16))), // receiver-side dedup
  });
  const ephB64 = b64(ephPubRaw);
  const kemB64 = b64(kemCt);
  const sig = await senderIdentity.sign(signBytes(recipientBundle.ed, ephB64, kemB64, core));

  const key = await deriveEnvelopeKey(ss1, ss2, unb64(recipientBundle.ed));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = enc.encode(JSON.stringify({ core, sig }));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
  return JSON.stringify({ v: 1, eph: ephB64, kem: kemB64, iv: b64(iv), ct: b64(ct) });
}

// Open an envelope addressed to `recipientIdentity`. Verifies the sealed
// sender's dual signature (over OUR identity key — a re-targeted envelope
// fails here). Returns { from, msg, ts, id }; throws on any failure.
export async function open(recipientIdentity, envelopeJson) {
  const env = JSON.parse(envelopeJson);
  if (env.v !== 1) throw new Error("unknown envelope version");
  const ss1 = await recipientIdentity.ecdhSharedBits(unb64(env.eph));
  const ss2 = recipientIdentity.mlkemDecapsulate(unb64(env.kem));
  const key = await deriveEnvelopeKey(ss1, ss2, recipientIdentity.edPubRaw);
  let plain;
  try {
    plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(env.iv) }, key, unb64(env.ct));
  } catch {
    throw new Error("envelope does not decrypt (wrong recipient or tampered)");
  }
  const { core, sig } = JSON.parse(dec.decode(plain));
  const parsed = JSON.parse(core);
  const myEdB64 = b64(recipientIdentity.edPubRaw);
  const ok = await Identity.verify(parsed.from, signBytes(myEdB64, env.eph, env.kem, core), sig);
  if (!ok) throw new Error("sender signature invalid — envelope forged or re-targeted");
  // Whole signed body: {from, name, kind, msg?, mode?, ts, id, …}.
  return { ...parsed, name: parsed.name || null, kind: parsed.kind || "msg" };
}

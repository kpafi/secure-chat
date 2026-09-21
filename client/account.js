// Client side of the passwordless account directory (backend/accounts.py).
//
// The server stores ONLY public identity keys keyed by username. It is a
// discovery convenience and a key directory, NOT a trust root: because it
// shares the relay's origin, a malicious server could serve a fake bundle here
// AND man-in-the-middle the handshake consistently. Authenticity therefore
// still comes from the in-person safety-number check — looking a contact up by
// username only saves you from pasting a raw key bundle.
//
// Registration proves control of BOTH identity keys: the server verifies the
// Ed25519 AND the ML-DSA-65 signature over the bundle (L1). Login uses the
// classical key only (a signed server challenge).
//
// Anti-enumeration (I1): the directory is not enumerable. Registration returns
// a random lookup token; a contact fetches your bundle with the HANDLE
// `username#token`, so a bare username reveals nothing.

import { b64, unb64, concat } from "./identity.js";

const REGISTER_DOMAIN = "secure-chat/register/v1";
const LOGIN_DOMAIN = "secure-chat/login/v1";
const enc = new TextEncoder();
const JSON_HEADERS = { "content-type": "application/json" };

// Username rules mirror the server (config.USERNAME_MIN/MAX + the charset).
const USERNAME_RE = /^[a-z0-9_.-]{3,32}$/;
// A shareable handle is `username#token`; the token is url-safe base64 (no pad).
const HANDLE_RE = /^([a-z0-9_.-]{3,32})#([A-Za-z0-9_-]{1,64})$/;

export function isValidUsername(u) {
  return USERNAME_RE.test(u);
}

// Parse a `username#token` handle into its parts, or null if malformed.
export function parseHandle(handle) {
  const m = HANDLE_RE.exec((handle || "").trim());
  return m ? { username: m[1], token: m[2] } : null;
}

// Exact bytes the server reconstructs in accounts._register_message:
//   DOMAIN \n username \n ed \n mldsa     (ASCII, newline-delimited)
function registerMessageBytes(username, bundle) {
  // Bundle v2 (with encryption keys) signs the extended message under the v2
  // domain — matches accounts._register_message_v2 on the server.
  if (bundle.ecdh && bundle.mlkem) {
    return enc.encode(
      [REGISTER_DOMAIN.replace("/v1", "/v2"), username, bundle.ed, bundle.mldsa, bundle.ecdh, bundle.mlkem].join("\n"),
    );
  }
  return enc.encode([REGISTER_DOMAIN, username, bundle.ed, bundle.mldsa].join("\n"));
}

// Turn an error response into one line of text. The relay's own errors put a
// string in `detail`; a FastAPI validation error (422) puts an ARRAY of
// `{type, loc, msg}` objects there, and before 2026-09-21 that reached the
// screen as "verify failed: [object Object]" (seen on the phone when the new
// dual-signature client met the old relay). Never let a non-string through.
export function formatDetail(detail, status) {
  // Total: whatever shape the relay chooses, this returns a string and never
  // throws (fix review 2026-09-21 L-1: an unguarded JSON.stringify on a deeply
  // nested entry blew the stack, and the throw escaped asError BEFORE
  // `err.status` was set — so a hostile 401 body stopped clearing apiToken).
  // Every piece is coerced (L-2: `msg` or `loc` entries that are objects
  // rendered "[object Object]" — the very bug this function exists to kill).
  let text = "";
  try {
    if (typeof detail === "string") {
      text = detail;
    } else if (Array.isArray(detail)) {
      text = detail.map((d) => {
        if (!d || typeof d !== "object") return String(d);
        const loc = Array.isArray(d.loc)
          ? d.loc.filter((x) => typeof x === "string" && x !== "body").join(".")
          : "";
        const msg = ["msg", "type"].map((k) => d[k]).find((v) => typeof v === "string" && v);
        return (msg || JSON.stringify(d)) + (loc ? " (" + loc + ")" : "");
      }).filter((x) => x).join("; ");
    } else if (detail && typeof detail === "object") {
      text = JSON.stringify(detail);
    }
  } catch {
    text = "";
  }
  return typeof text === "string" && text.trim() ? text : status + "";
}

async function asError(res) {
  let detail = null;
  try {
    const body = await res.json();
    if (body && body.detail) detail = body.detail;
  } catch {
    /* non-JSON error body */
  }
  return formatDetail(detail, res.status);
}

// Claim a username and bind it to this identity's public bundle. The DUAL
// signature (Ed25519 + ML-DSA-65) proves control of BOTH keys (anti-squatting
// + key binding + PQ ownership). Returns { username, lookup_token }.
export async function register(base, identity, username) {
  const bundle = identity.publicBundle();
  const { ed: sig, mldsa: mldsa_sig } = await identity.sign(registerMessageBytes(username, bundle));
  const body = { username, ed: bundle.ed, mldsa: bundle.mldsa, sig, mldsa_sig };
  if (bundle.ecdh && bundle.mlkem) {
    body.ecdh = bundle.ecdh;
    body.mlkem = bundle.mlkem;
  }
  const res = await fetch(base + "/api/register", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const status = res.status; // taken BEFORE the body is read — nothing in asError may lose it
    const err = new Error(await asError(res));
    err.status = status;
    throw err;
  }
  return res.json();
}

// Fetch a peer's public identity bundle from a `username#token` handle. Returns
// null when the handle is unknown OR the token is wrong (the server makes the
// two indistinguishable, so callers just see "no such contact").
export async function fetchBundle(base, handle) {
  const parsed = parseHandle(handle);
  if (!parsed) throw new Error("expected a contact handle of the form username#token");
  const res = await fetch(
    base + "/api/users/" + encodeURIComponent(parsed.username) + "?t=" + encodeURIComponent(parsed.token),
  );
  if (res.status === 404) return null;
  if (!res.ok) throw new Error("lookup failed: " + (await asError(res)));
  const d = await res.json();
  // Pentest 2026-07-29 M-6: canonicalise here, at the boundary where a
  // server-controlled string first enters the client.
  //
  // Every key in a bundle is a byte length ≡2 (mod 3), so four base64 spellings
  // decode to identical bytes. This function used to copy the server's spelling
  // VERBATIM, and `contacts.upsert` decides `keyChanged` by comparing those raw
  // STRINGS while everything downstream compares BYTES. A hostile directory
  // could therefore re-spell a key and, byte-for-byte truthfully, (a) fire
  // "the fetched keys DIFFER from what you verified" at will, stripping the
  // verified mark and every vouch from a contact, (b) PERMANENTLY break sealed
  // messaging to them, because the non-canonical string gets persisted and
  // `seal()` throws on it before sending, and (c) push inbound mail into a new
  // `unknown-…` auto-contact, burning the MAX_AUTO_CONTACTS budget.
  //
  // `unb64` throws on a non-canonical spelling, so a re-spelled bundle is now
  // refused outright instead of being stored as a different-looking key. This
  // is the same gate `app.js`'s canonicalBundle applies to bundles arriving
  // over the wire; the directory path was simply never put behind it.
  // Sizes are fixed by the algorithms, so a wrong length is malformed input and
  // belongs here too (fix review 2026-07-30): canonicalising alone let a
  // correctly-spelled 16-byte "Ed25519 key" through, to fail much later inside
  // Identity.verify or seal() where it reads as a crypto error rather than a bad
  // directory answer. Same boundary, one more check.
  const SIZES = { ed: 32, mldsa: 1952, ecdh: 65, mlkem: 1184 };
  const canon = (v, key, field) => {
    let raw;
    try {
      raw = unb64(v);
    } catch {
      throw new Error(
        `the directory returned a malformed ${field} key for ${parsed.username} — refusing it`,
      );
    }
    if (raw.length !== SIZES[key]) {
      throw new Error(
        `the directory returned a wrong-sized ${field} key for ${parsed.username} ` +
        `(${raw.length} bytes, expected ${SIZES[key]}) — refusing it`,
      );
    }
    return b64(raw);
  };
  const out = {
    username: parsed.username,
    ed: canon(d.ed, "ed", "identity"),
    mldsa: canon(d.mldsa, "mldsa", "post-quantum identity"),
  };
  if (d.ecdh && d.mlkem) {
    // bundle v2: sealed-message encryption keys
    out.ecdh = canon(d.ecdh, "ecdh", "encryption");
    out.mlkem = canon(d.mlkem, "mlkem", "post-quantum encryption");
  }
  return out;
}

// Revoke a session token server-side (pentest 2026-07-29 L-4).
//
// The endpoint answers 200 whether or not the token was real — deliberately, so
// it is not a token-validity oracle — which means there is nothing to check
// here. Best-effort by design: if the request never lands, the token still
// expires at TOKEN_TTL_SEC, and the caller has already dropped it locally.
export async function logout(base, token) {
  if (!token) return;
  try {
    await fetch(base + "/api/auth/logout", {
      method: "POST",
      headers: { authorization: "Bearer " + token },
    });
  } catch {
    /* offline: the token expires on its own, and it is gone from this device */
  }
}

// Prove account control: sign a fresh server challenge, receive a bearer token.
export async function login(base, identity, username) {
  const cRes = await fetch(base + "/api/auth/challenge", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ username }),
  });
  if (!cRes.ok) throw new Error("challenge failed: " + (await asError(cRes)));
  const { challenge } = await cRes.json();

  // Sign under the login domain prefix (matches accounts._login_message) so the
  // signature is bound to the login protocol and can't be cross-used elsewhere.
  // Pentest 2026-08-07 F-RELAY-006: BOTH identity keys sign the challenge, as
  // they do for registration, vouches and the handshake. Login used to be the
  // one Ed25519-only proof, so the directory session (which drains and deletes
  // the mailbox and deletes vouches) fell to a classical-key-only compromise.
  const { ed: sig, mldsa: mldsaSig } = await identity.sign(
    concat(enc.encode(LOGIN_DOMAIN + "\n"), unb64(challenge)),
  );
  const vRes = await fetch(base + "/api/auth/verify", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ username, challenge, sig, mldsa_sig: mldsaSig }),
  });
  if (!vRes.ok) throw new Error("verify failed: " + (await asError(vRes)));
  return vRes.json(); // { token, ttl }
}

// ---- web-of-trust vouches -------------------------------------------------
// A vouch is a dual-signed statement "I verified `target`'s bundle in person".
// Exact bytes the server reconstructs in accounts._vouch_message.

const VOUCH_DOMAIN = "secure-chat/vouch/v1";
const VOUCH_V2_DOMAIN = "secure-chat/vouch/v2";

// H-01 (2026-07-19): a vouch now covers the target's ENCRYPTION keys (ecdh +
// mlkem) when present, not just the signing keys — so a 🟡 mark attests all
// four keys and a malicious directory cannot swap encryption keys under a
// still-valid vouch. Matches accounts._vouch_message: v2 when enc keys exist,
// v1 (signing-only, legacy targets that can't receive sealed mail) otherwise.
export function vouchMessageBytes(targetUsername, targetBundle) {
  if (targetBundle.ecdh && targetBundle.mlkem) {
    return enc.encode(
      [VOUCH_V2_DOMAIN, targetUsername, targetBundle.ed, targetBundle.mldsa,
        targetBundle.ecdh, targetBundle.mlkem].join("\n"),
    );
  }
  return enc.encode([VOUCH_DOMAIN, targetUsername, targetBundle.ed, targetBundle.mldsa].join("\n"));
}

// Publish a vouch for a contact whose bundle WE hold (signed over OUR pinned
// copy — if the directory has a different key for them, the server refuses,
// which is exactly right: never vouch for a key you did not verify).
export async function vouch(base, identity, sessionToken, targetUsername, targetBundle) {
  const { ed: sig, mldsa: mldsa_sig } = await identity.sign(vouchMessageBytes(targetUsername, targetBundle));
  const res = await fetch(base + "/api/vouch", {
    method: "POST",
    headers: { ...JSON_HEADERS, authorization: "Bearer " + sessionToken },
    body: JSON.stringify({ target: targetUsername, sig, mldsa_sig }),
  });
  if (!res.ok) throw new Error("vouch failed: " + (await asError(res)));
  return res.json();
}

export async function unvouch(base, sessionToken, targetUsername) {
  const res = await fetch(base + "/api/vouch/" + encodeURIComponent(targetUsername), {
    method: "DELETE",
    headers: { authorization: "Bearer " + sessionToken },
  });
  if (!res.ok) throw new Error("unvouch failed: " + (await asError(res)));
  return res.json();
}

// Vouches ABOUT a contact (requires their username#token handle, same gate as
// the bundle lookup). Returns the server's raw list — the CALLER must verify
// each signature against its own pinned voucher keys before trusting it.
export async function fetchVouches(base, handle) {
  const parsed = parseHandle(handle);
  if (!parsed) throw new Error("expected a contact handle of the form username#token");
  const res = await fetch(
    base + "/api/users/" + encodeURIComponent(parsed.username) + "/vouches?t=" + encodeURIComponent(parsed.token),
  );
  if (res.status === 404) return null;
  if (!res.ok) throw new Error("vouch lookup failed: " + (await asError(res)));
  return (await res.json()).vouches;
}

// ---- mailbox (store-and-forward for sealed envelopes) ---------------------

// Queue a sealed envelope for a contact (their handle gates the POST — same
// capability as the bundle lookup, so this is not an existence oracle).
export async function sendMail(base, handle, envelope) {
  const parsed = parseHandle(handle);
  if (!parsed) throw new Error("expected a contact handle of the form username#token");
  const res = await fetch(
    base + "/api/mailbox/" + encodeURIComponent(parsed.username) + "?t=" + encodeURIComponent(parsed.token),
    { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ envelope }) },
  );
  if (res.status === 404) throw new Error("recipient unknown (check the handle)");
  if (res.status === 429) throw new Error("recipient inbox full or rate limited — try again later");
  if (!res.ok) throw new Error("send failed: " + (await asError(res)));
  return res.json();
}

// Fetch AND consume my queued envelopes (requires login; the server deletes
// what it returns). Returns [{envelope, created_at}].
export async function fetchMail(base, sessionToken) {
  const res = await fetch(base + "/api/mailbox", {
    headers: { authorization: "Bearer " + sessionToken },
  });
  if (!res.ok) {
    const status = res.status; // taken BEFORE the body is read — nothing in asError may lose it
    const err = new Error("mailbox fetch failed: " + (await asError(res)));
    // Session tokens expire (TOKEN_TTL_SEC). Surface the status so the caller
    // can re-login instead of silently never receiving mail again.
    err.status = status;
    throw err;
  }
  return (await res.json()).messages;
}

// Resolve a bearer token back to a username (sanity check / "who am I").
export async function me(base, token) {
  const res = await fetch(base + "/api/me", {
    headers: { authorization: "Bearer " + token },
  });
  if (!res.ok) throw new Error("me failed: " + (await asError(res)));
  return (await res.json()).username;
}

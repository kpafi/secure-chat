// Client side of the passwordless account directory (backend/accounts.py).
//
// The server stores ONLY public identity keys keyed by username. It is a
// discovery convenience and a key directory, NOT a trust root: because it
// shares the relay's origin, a malicious server could serve a fake bundle here
// AND man-in-the-middle the handshake consistently. Authenticity therefore
// still comes from the in-person safety-number check — looking a contact up by
// username only saves you from pasting a raw key bundle.
//
// All proofs use the CLASSICAL (Ed25519) key only, matching the server, which
// verifies ML-DSA client-side during the handshake rather than at the directory.

import { unb64, concat } from "./identity.js";

const REGISTER_DOMAIN = "secure-chat/register/v1";
const LOGIN_DOMAIN = "secure-chat/login/v1";
const enc = new TextEncoder();
const JSON_HEADERS = { "content-type": "application/json" };

// Username rules mirror the server (config.USERNAME_MIN/MAX + the charset).
const USERNAME_RE = /^[a-z0-9_.-]{3,32}$/;

export function isValidUsername(u) {
  return USERNAME_RE.test(u);
}

// Exact bytes the server reconstructs in accounts._register_message:
//   DOMAIN \n username \n ed \n mldsa     (ASCII, newline-delimited)
function registerMessageBytes(username, bundle) {
  return enc.encode([REGISTER_DOMAIN, username, bundle.ed, bundle.mldsa].join("\n"));
}

async function asError(res) {
  let detail = res.status + "";
  try {
    const body = await res.json();
    if (body && body.detail) detail = body.detail;
  } catch {
    /* non-JSON error body */
  }
  return detail;
}

// Claim a username and bind it to this identity's public bundle. The Ed25519
// signature proves control of the classical key (anti-squatting + key binding).
export async function register(base, identity, username) {
  const bundle = identity.publicBundle();
  const sig = await identity.signEd(registerMessageBytes(username, bundle));
  const res = await fetch(base + "/api/register", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ username, ed: bundle.ed, mldsa: bundle.mldsa, sig }),
  });
  if (!res.ok) {
    const err = new Error(await asError(res));
    err.status = res.status;
    throw err;
  }
  return res.json();
}

// Fetch a peer's public identity bundle by username. Returns null for 404.
export async function fetchBundle(base, username) {
  const res = await fetch(base + "/api/users/" + encodeURIComponent(username));
  if (res.status === 404) return null;
  if (!res.ok) throw new Error("lookup failed: " + (await asError(res)));
  const d = await res.json();
  return { ed: d.ed, mldsa: d.mldsa };
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
  const sig = await identity.signEd(concat(enc.encode(LOGIN_DOMAIN + "\n"), unb64(challenge)));
  const vRes = await fetch(base + "/api/auth/verify", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ username, challenge, sig }),
  });
  if (!vRes.ok) throw new Error("verify failed: " + (await asError(vRes)));
  return vRes.json(); // { token, ttl }
}

// Resolve a bearer token back to a username (sanity check / "who am I").
export async function me(base, token) {
  const res = await fetch(base + "/api/me", {
    headers: { authorization: "Bearer " + token },
  });
  if (!res.ok) throw new Error("me failed: " + (await asError(res)));
  return (await res.json()).username;
}

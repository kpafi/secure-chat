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
//
// Pentest 2026-08-07 F-RELAY-005: a v3 registration appends a monotone counter.
// The dual signature proves control of the identity keys but says nothing about
// WHEN it was made, so every registration a user had ever signed stayed valid
// forever and the server applied whichever arrived last. A hostile relay could
// therefore resend an older one to roll the published encryption keys back to a
// superseded pair, or replay a v1 registration — which carries no encryption
// keys at all — to strip them outright, silently making the account unable to
// receive sealed mail. The counter makes a replay a counter that does not move
// forward, which the server refuses.
function registerMessageBytes(username, bundle, seq) {
  if (bundle.ecdh && bundle.mlkem && Number.isInteger(seq)) {
    return enc.encode(
      [REGISTER_DOMAIN.replace("/v1", "/v3"), username, bundle.ed, bundle.mldsa,
       bundle.ecdh, bundle.mlkem, String(seq)].join("\n"),
    );
  }
  // Bundle v2 (with encryption keys) signs the extended message under the v2
  // domain — matches accounts._register_message_v2 on the server.
  if (bundle.ecdh && bundle.mlkem) {
    return enc.encode(
      [REGISTER_DOMAIN.replace("/v1", "/v2"), username, bundle.ed, bundle.mldsa, bundle.ecdh, bundle.mlkem].join("\n"),
    );
  }
  return enc.encode([REGISTER_DOMAIN, username, bundle.ed, bundle.mldsa].join("\n"));
}

// The counter this device will sign into its next registration (F-RELAY-005).
//
// Kept in localStorage next to the identity and bumped on every registration,
// so it moves forward across re-registrations and key rotations. It is not a
// secret and it does not need to be unforgeable: the SIGNATURE is what the
// server checks, and the counter only has to be strictly greater than the one
// the server already stored. A device whose counter is behind (fresh install,
// cleared storage) gets a 409 naming the stored value, and `register` below
// retries once from there — so this is a convenience, not a trust anchor.
const LS_REG_SEQ = "sc.regseq.v1";

// Pentest 2026-08-08 item 18. The comment above says the counter "does not need
// to be unforgeable". That is true for forgery FORWARD — a bogus value cannot
// forge a registration, because the signature is still checked — and false for
// EXHAUSTION, which is the direction nobody looked.
//
// `sc.regseq.v1` is plaintext and was unbounded. Write `2**53 - 2` into it and
// the next registration signs `2**53 - 1`, which is EXACTLY the server's cap
// (`seq: int | None = Field(..., le=2**53 - 1)` in accounts.py), so it is
// accepted and stored. After that the account's keys are frozen forever:
// anything higher is a 422 from the Pydantic bound, anything at or below is a
// 409 as a replay. The one-shot recovery below only fires on 409 and only
// raises to `Date.now()`, which is ~1.8e12 — six orders of magnitude BELOW the
// poisoned value, so it cannot help. Confirmed end to end against the real
// endpoint: seq=2**53-1 → `200 updated`, then 422 / 409 / 409 forever.
//
// The first repair (pass 2) used two ABSOLUTE bounds — a "sane max" above which
// a stored value was discarded, and a hard cap on what would be signed. Those
// constants are GONE; do not go looking for them. What replaced them, and why, is
// the next paragraph, which describes the code as it actually stands.
//
// `Date.now()` as the floor (not just `cur + 1`) survived from that pass and is
// still here: it is the same trick the 409 retry uses, promoted to the normal
// path, and it keeps the counter ahead across a reinstall or cleared storage
// without a round trip.
//
// Pentest 2026-08-10, second pass: the first repair did NOT close this, and an
// ABSOLUTE ceiling never can — it only relocates the freeze.
//
// The freeze never required reaching the server's Pydantic cap. It only requires
// the server's stored counter to exceed anything this client will sign again.
// With `raw <= 2**43` as an INCLUSIVE acceptance bound, a stored `2**43` was
// used as a floor and signed as `2**43 + 1` — which is ABOVE the bound, so the
// next call discarded it and fell back to `Date.now()`, six orders of magnitude
// below what the server now held. Executed end to end against the real endpoint:
// the account's `ecdh`/`mlkem` could never be republished again, not even after
// a key compromise, and the poisoned value silently overwrote itself so nothing
// on the device showed why. The bug was the ASYMMETRY between what we accept as
// a floor and what we are willing to sign.
//
// So the bound is now RELATIVE and TWO-SIDED, and the same number does both
// jobs: never sign more than `REG_SEQ_SLACK_MS` beyond the current clock, and
// never accept a stored floor above that same line. Two properties follow that
// the absolute version did not have:
//
//   * Nothing this client signs can ever be un-signable later, because the
//     ceiling moves forward with wall-clock. A poisoned store is discarded, and
//     even a value written AT the ceiling stays acceptable a moment later and
//     simply advances by one. There is no self-discarding band left.
//   * An attacker with a localStorage write can push the server's counter at
//     most `REG_SEQ_SLACK_MS` ahead of real time, and the client overtakes it on
//     the next registration rather than being locked out.
//
// RESIDUAL, stated plainly because it needs a protocol change rather than
// tuning: a device whose WALL CLOCK is badly wrong into the future still signs a
// far-future counter, and once the server has stored it no correctly-clocked
// client can overtake it. Nothing here can fix that — the ceiling is computed
// from the same clock that is lying. The real repair is for the server to echo
// its stored counter in the 409 body so a client can resynchronise; today the
// 409 says only "not newer", which is why `Date.now()` had to be guessed at in
// the first place. Recorded in PROGRESS.md as an open item.
const REG_SEQ_SLACK_MS = 7 * 24 * 60 * 60 * 1000;   // one week of clock slack

// The highest counter this device may sign right now, and equally the highest
// stored value it will trust as a floor. One number, so the two can never drift
// apart the way they did in the first repair.
function regSeqCeiling() {
  return Date.now() + REG_SEQ_SLACK_MS;
}

function nextRegSeq() {
  const raw = Number.parseInt(localStorage.getItem(LS_REG_SEQ) || "0", 10);
  const ceiling = regSeqCeiling();
  const cur = Number.isInteger(raw) && raw > 0 && raw <= ceiling ? raw : 0;
  const next = Math.min(Math.max(cur + 1, Date.now()), ceiling);
  // Guard the OUTPUT, not just the stored input (A4 Low). Every caller tests
  // `Number.isInteger(seq)` and silently falls back to a v2, counter-free —
  // i.e. REPLAYABLE — registration when it fails. So a `Date.now()` hooked to
  // return a fraction (a device-local attacker, or a broken polyfill) used to
  // switch this control off with nothing said. The backend stays fail-closed
  // either way, so no key rollback follows; what is unacceptable is the SILENCE.
  // Refusing is safe here because, unlike the stored counter, this value is not
  // attacker-writable — it is computed fresh — so throwing cannot be used to
  // wedge the client.
  if (!Number.isInteger(next) || next < 1) {
    throw new Error("this device's clock produced an unusable registration counter — registration refused rather than sent without replay protection");
  }
  localStorage.setItem(LS_REG_SEQ, String(next));
  return next;
}

// Parse a FastAPI error body into a stable shape, tolerant of BOTH the new
// structured 409 (`detail` is an object: {error, message, stored_seq?}) and the
// older/other paths where `detail` is a plain string. Returns
// { code, storedSeq, message } — code/storedSeq are null when absent. Never
// throws: a hostile relay controls this body, so every field is treated as
// untrusted and only shape-checked here, never trusted for its value.
function parseErrorDetail(detail) {
  if (detail && typeof detail === "object" && !Array.isArray(detail)) {
    const code = typeof detail.error === "string" ? detail.error : null;
    // stored_seq is disclosed only on the stale_counter branch and only to the
    // verified owner; carry it through raw (unvalidated) — register() is the one
    // place that decides whether it is a usable integer before signing it.
    const storedSeq = Object.prototype.hasOwnProperty.call(detail, "stored_seq")
      ? detail.stored_seq
      : null;
    // Clamped (pentest ROUND-4 L-2): this string is relay-chosen and ends up in
    // the client's own status banner, which is trusted chrome. It is rendered with
    // textContent so there is no XSS, but an unbounded value is still a rendering
    // DoS and — worse — room for the relay to write a convincing instruction
    // ("export your identity to…") into UI the user reads as ours.
    const message = typeof detail.message === "string" ? detail.message.slice(0, 200) : null;
    return { code, storedSeq, message };
  }
  // Plain-string detail (older errors, non-409 paths): no machine-readable code.
  return {
    code: null,
    storedSeq: null,
    message: typeof detail === "string" ? detail.slice(0, 200) : null,
  };
}

async function asError(res) {
  let detail = res.status + "";
  try {
    const body = await res.json();
    // The new structured detail is an OBJECT; rendering it straight into an
    // Error used to produce "[object Object]" and swallow the server's message.
    // Pull the human-readable message out of either shape.
    if (body && body.detail) {
      const parsed = parseErrorDetail(body.detail);
      detail = parsed.message || (parsed.code ? parsed.code : detail);
    }
  } catch {
    /* non-JSON error body */
  }
  return detail;
}

// Claim a username and bind it to this identity's public bundle. The DUAL
// signature (Ed25519 + ML-DSA-65) proves control of BOTH keys (anti-squatting
// + key binding + PQ ownership). Returns { username, lookup_token }.
export async function register(base, identity, username) {
  const bundle = identity.publicBundle();
  const hasEncKeys = Boolean(bundle.ecdh && bundle.mlkem);

  const attempt = async (seq) => {
    const { ed: sig, mldsa: mldsa_sig } = await identity.sign(registerMessageBytes(username, bundle, seq));
    const body = { username, ed: bundle.ed, mldsa: bundle.mldsa, sig, mldsa_sig };
    if (hasEncKeys) {
      body.ecdh = bundle.ecdh;
      body.mlkem = bundle.mlkem;
      if (Number.isInteger(seq)) body.seq = seq;
    }
    return fetch(base + "/api/register", {
      method: "POST",
      headers: JSON_HEADERS,
      body: JSON.stringify(body),
    });
  };

  // F-RELAY-005: a bundle with encryption keys registers under v3 with a
  // counter. A pre-v3 identity (no encryption keys yet) has nothing to roll
  // back and keeps using the v1 message.
  let seq = hasEncKeys ? nextRegSeq() : null;
  let res = await attempt(seq);

  // The server refuses a counter that is not ahead of the one it stored. That
  // is the replay defence doing its job, but it also catches an honest device
  // whose local counter fell behind (reinstall, cleared storage), so retry once
  // from a counter that is definitely ahead. The retry is bounded to one and
  // still has to carry a valid signature, so it grants an attacker nothing:
  // they cannot sign the retry.
  //
  // The backend now echoes its stored counter in the stale_counter 409 body
  // (commit ea4afe9). That closes the wrong-clock residual documented above: a
  // device with a skewed or backward clock no longer has to GUESS a value ahead
  // of the server from its own lying clock — it resynchronises to stored_seq+1.
  // But stored_seq arrives over an UNTRUSTED relay, so it is verified and clamped
  // before it is ever signed or persisted; a hostile value falls back to the
  // ceiling jump rather than being trusted.
  if (!res.ok && res.status === 409 && Number.isInteger(seq)) {
    let rawBody = "";
    try { rawBody = await res.clone().text(); } catch { /* unreadable body */ }
    let detailBody = null;
    try { detailBody = JSON.parse(rawBody).detail; } catch { /* non-JSON */ }
    const { code, storedSeq } = parseErrorDetail(detailBody);
    // ROUND-4 L-1: keep the legacy sniff as a FALLBACK. A pre-ea4afe9 relay sends
    // `detail` as a plain string, so `code` is null and a code-only test would
    // silently drop the retry — and client and relay do NOT ship together on every
    // path: the Android APK bundles its own copy of this file and updates
    // independently of the relay it points at. Safe to keep: a legacy body carries
    // no stored_seq, so this can only ever reach the already-untrusted ceiling jump.
    const legacyCounter409 = code === null && /counter/i.test(rawBody);
    if (code === "stale_counter" || legacyCounter409) {
      // Resync target: one past what the server actually holds. This is the real
      // recovery the ceiling-guess used to stand in for — it overtakes the server
      // by exactly one regardless of how wrong this device's clock is.
      const ceiling = regSeqCeiling();
      let retrySeq = null;
      if (Number.isInteger(storedSeq) && storedSeq >= 1 && storedSeq < ceiling && storedSeq + 1 > seq) {
        // Clamp to the ceiling so a hostile relay cannot echo a giant stored_seq
        // and walk us to the server's Pydantic cap (the freeze class this file's
        // comments describe). storedSeq < ceiling guarantees storedSeq+1 <= ceiling
        // stays a legitimately signable, positive integer, and storedSeq+1 > seq
        // guarantees it overtakes the value just refused — a relay that echoes a
        // tiny stored_seq to force a non-advancing retry gets the ceiling instead.
        retrySeq = storedSeq + 1;
      }
      // Fall back to the ceiling jump when stored_seq is missing, non-integer,
      // negative, zero, fractional, beyond the ceiling, or would not advance — i.e.
      // anything we cannot safely trust. regSeqCeiling() is the furthest-ahead
      // value this device may legitimately sign.
      if (!Number.isInteger(retrySeq)) retrySeq = ceiling;
      // The retry MUST advance past the value just refused, and MUST be a positive
      // integer that attempt() will send as body.seq. Never re-send the refused
      // value (an inert round trip, the old M-1 bug) and never let a non-integer
      // slip through — a non-integer seq makes attempt() drop body.seq and
      // registerMessageBytes() sign the counter-free v2 message, a silent replayable
      // downgrade (F-5). If even the ceiling cannot overtake the refused value the
      // device is signing at its maximum and is genuinely stuck (a wall clock far
      // into the future); refuse loudly rather than resend or downgrade.
      if (!Number.isInteger(retrySeq) || retrySeq <= seq) {
        const err = new Error(
          "the directory's stored registration counter is not one this device can overtake — " +
          "registration refused rather than resent without moving the counter forward",
        );
        err.status = 409;
        err.code = "stale_counter";
        throw err;
      }
      seq = retrySeq;
      localStorage.setItem(LS_REG_SEQ, String(seq));
      res = await attempt(seq);
    }
  }

  if (!res.ok) {
    const body = await res.clone().json().catch(() => null);
    const err = new Error(await asError(res));
    err.status = res.status;
    // Surface the machine-readable code so callers can tell the three 409s apart
    // (username_taken vs. a counter still stuck after the retry vs. keys_locked)
    // instead of branching on status alone.
    err.code = parseErrorDetail(body && body.detail).code;
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
  //
  // Pentest 2026-08-07 F-RELAY-006: this used to be the Ed25519 signature ALONE,
  // making the directory session the one place the dual-scheme identity was not
  // AND-composed. Registration proves control of both keys and the handshake
  // requires both signatures; a session token minted on the classical key alone
  // then drained and DELETED the mailbox and deleted the account's vouches. So
  // an adversary who broke Ed25519 — precisely what the ML-DSA half is there to
  // hedge — owned the directory session while every other surface held. Both
  // signatures now, over the identical message.
  const loginMsg = concat(enc.encode(LOGIN_DOMAIN + "\n"), unb64(challenge));
  const { ed: sig, mldsa: mldsa_sig } = await identity.sign(loginMsg);
  const vRes = await fetch(base + "/api/auth/verify", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ username, challenge, sig, mldsa_sig }),
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
    const err = new Error("mailbox fetch failed: " + (await asError(res)));
    // Session tokens expire (TOKEN_TTL_SEC). Surface the status so the caller
    // can re-login instead of silently never receiving mail again.
    err.status = res.status;
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

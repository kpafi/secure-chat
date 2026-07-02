# secure-chat — progress log

Working file so any session can pick up where the last left off. Newest notes
at the top of each section. Dates are absolute (YYYY-MM-DD).

## ⮕ RESUME HERE (snapshot as of 2026-07-02)
**Status:** backend relay + web client working locally; git repo on `master`.
Backend `pytest` = **47 passed**; client offline suite (`npm test`) green
(incl. 4 new RSA attack tests); all 3 live integration suites green.
**2026-07-02:** Security pass (all verified, incl. real-browser checks):
(1) RSA per-message HMAC authentication; (2) verification gate now covers
RECEIVING (inbound `msg` dropped until the safety number is confirmed);
(3) reflection/replay CLOSED for AES256/DHKE/PQKEM via `AuthChannel`;
(4) PQKEM handshake-replay key-desync fixed (first-write-wins); (5) DHKE key now
HKDF-derived; (6) login challenge signature domain-separated; (7) CSP import-map
hash guarded by a test. See dated entries. Client `npm test` + all 3 live
integration suites green; backend `pytest` = **48 passed**. Uncommitted at
session end — commit before continuing.

**UNCOMMITTED files at session end (2026-07-02), all verified & ready to commit:**
`PROGRESS.md`, `README.md`, `backend/accounts.py`, `backend/tests/test_accounts.py`,
`client/account.js`, `client/app.js`, `client/auth.integration.test.mjs`,
`client/crypto.js`, `client/crypto.test.mjs`, and new `backend/tests/test_csp_hash.py`.
(README.md + auth.integration.test.mjs also carry earlier-in-day RSA-HMAC work.)
Suggested one commit: "Close reflection/replay + receive-gate; crypto hardening".

**Done & verified end-to-end (incl. real-browser checks via puppeteer):**
- Dumb-relay backend (strict validation, rate limit, connection cap, join +
  idle timeouts) + passwordless account directory (`/api`, rate-limited + capped).
- Web client: 4 working encryption modes — **AES256, DHKE, RSA, PQKEM**
  (PQKEM = hybrid ECDH P-256 + ML-KEM-768). Identity = Ed25519 + ML-DSA-65,
  passphrase-encrypted at rest (PBKDF2 600k).
- **Authenticated handshake** (dual-sig) + in-person safety-number gate closes
  the relay-MITM gap. Account register/login + fetch-by-username pinning.
- Security review done; M1/M2/L3 fixed, H1 documented (see 2026-06-19 entry).

**Next options (pick one):** (a) OTP mode; (b) Tor `.onion` deployment;
(c) Android app; (d) close accepted-risk items L1 (server-side ML-DSA verify)
/ I1 (kill username enumeration); (e) forward secrecy / ratcheting for
AES256/RSA (and to remove AES256's cross-session-replay residual). Full open
list in TODO at the bottom.

**Run it:** see "How to run (quick ref)" at the bottom of this file.

## Project goal (from the user)
- Website + server backend for **simple ASCII-only text chat**.
- **Security is the #1 priority** in every design and code decision. Small,
  simple, auditable codebase is itself a security feature.
- User picks the encryption: **RSA, AES-256, DHKE, post-quantum key exchange,
  and OTP** (OTP = pre-shared large random pad exchanged when users meet in
  person; lower priority, harder to implement — defer for now).
- Eventual clients: a **Tor `.onion` website** and a dedicated **Android app**.
  The **website is the priority**; the app comes later.
- Order of work: **backend first, locally, for testing.**

## Key architectural decisions (locked)
1. **Stack:** Python + FastAPI (small, readable, easy to audit; strong crypto
   ecosystem for later client-side / PQ work).
2. **Crypto model:** **End-to-end encryption; the server is a dumb relay.**
   The server never sees keys or plaintext. It validates the envelope, enforces
   limits, and forwards opaque ciphertext. A full server compromise leaks only
   ciphertext. => All algorithm choice and crypto logic lives in the CLIENT.
   The server's `alg` field is an advisory tag only and is never acted upon.

## DONE
### 2026-06-19 — backend v0 (local relay)
- Created project at `~/secure-chat`.
- `backend/config.py` — all hard limits in one auditable place (frame size,
  payload size, room id length, max members/rooms, rate-limit params).
- `backend/validation.py` — strict pydantic `Envelope` (extra fields forbidden,
  immutable), printable-ASCII check, base64 payload check, 64-hex room ids,
  enum message types + advisory algorithm enum, payload-presence rules.
- `backend/relay.py` — in-memory `RoomRegistry` (no storage, empty rooms
  deleted) + per-connection `TokenBucket` rate limiter.
- `backend/main.py` — FastAPI app, single `/ws` WebSocket endpoint, `/healthz`,
  security headers, CORS locked shut, docs/openapi disabled, payloads never
  logged, fail-closed validation, size cap before parse, rate limit.
- `backend/tests/test_validation.py` — unit tests for the validation front door.
- `backend/tests/smoke_client.py` — two-client end-to-end relay smoke test.
- `backend/run.sh`, `requirements.txt`, `README.md`, `.gitignore`.

### Security measures already in place (server side)
- Server does no crypto and holds no keys/plaintext (E2EE dumb relay).
- Strict, fail-closed input validation; unknown fields/types rejected.
- ASCII-only enforced on the whole frame.
- Frame size cap (64 KiB) checked before any parsing.
- Payload size cap (~48 KiB) + base64-only payload.
- Per-connection token-bucket rate limiting.
- Global connection cap + per-connection idle read timeout (zombie reaper).
- Global room cap + per-room member cap (DoS/memory bounds).
- Rooms in-memory only; deleted when empty (no data at rest).
- Message payloads never logged; no stack traces leaked to clients.
- CORS disabled; security headers (CSP `default-src 'none'`, nosniff, DENY,
  no-referrer); API docs/OpenAPI endpoints disabled; server header stripped.

### 2026-06-19 — verified locally ✅
- venv created, deps installed.
- `pytest tests/test_validation.py` -> **12 passed**.
- Server started; `/healthz` 200 with all security headers present;
  `/docs` -> 404 (disabled); `Server` header **absent** (stripped via
  `server_header=False` / `--no-server-header`).
- `smoke_client.py` -> two clients joined the same room, opaque base64 payload
  relayed **verbatim** and decoded correctly on the peer. Server log shows
  only connection lifecycle, **no payloads**.

### 2026-06-19 — web client + key exchange + server hardening ✅
- `client/crypto.js` — Web Crypto only (no hand-rolled crypto). Implements:
  - **AES256**: shared passphrase → PBKDF2-SHA256 (310k iters, room id as salt)
    → AES-256-GCM. No network handshake.
  - **DHKE**: ephemeral ECDH P-256 → AES-256-GCM, private key non-extractable.
  - **RSA**: RSA-OAEP-2048 public-key swap, hybrid per-message AES-256-GCM.
  - PQKEM + OTP marked unavailable (documented, UI-disabled).
- `client/index.html` + `style.css` + `app.js` — minimal UI: room id (+256-bit
  generator), encryption selector, passphrase field, message log. No inline
  JS/CSS or inline handlers (CSP-clean). Rendering uses textContent only (no
  innerHTML) → no XSS path.
- Handshake protocol over the relay's `key` message: payload = base64(JSON
  {pub, reply}); `reply` flag makes the early joiner answer exactly once, so
  the exchange converges with no infinite ping-pong (verified).
- Server hardening:
  - **WebSocket Origin allow-list (CSWSH protection)** — present-but-disallowed
    origin → 403; missing Origin (native/CLI) allowed.
  - Static web client served **same-origin** via StaticFiles (path traversal
    blocked); explicit /ws + /healthz routes take precedence.
  - CSP tightened to allow only same-origin script/style/connect, no inline.
- Tests:
  - `client/crypto.test.mjs` — round-trips for all 3 algos + wrong-key reject
    + ascii guard. **All pass** (Node Web Crypto).
  - `client/integration.test.mjs` — two real WebSocket clients through the
    running relay, full handshake + message exchange for all 3 algos.
    **All pass.**
  - curl checks: `/`→200, `/app.js`→200, traversal→404, evil Origin→403,
    CSP header present, relay log shows **no payloads**.

## KNOWN LIMITATIONS / THREAT NOTES (read before trusting E2EE)
- **Key-exchange MITM — CLOSED in the live web client (2026-06-19).** DHKE and
  RSA handshakes are now signed by a long-term identity (Ed25519 + ML-DSA-65)
  and verified against the peer's bundle, gated by an in-person safety-number
  check (option (b) from the original plan). A relay swapping the ephemeral key
  fails signature verification; a relay swapping the whole identity yields
  mismatched safety numbers at the two endpoints. AES256-passphrase mode remains
  not-MITM-able (no key material exchanged). Residual trust assumptions:
  - Users MUST actually compare the safety number out of band; clicking through
    "it matches" without checking reduces this to trust-on-first-use.
  - The account directory (`/api`) is only a convenience for *fetching* a bundle;
    it is not a trust root. Authenticity still comes from the in-person check.
- **No forward secrecy in AES256/RSA modes** (static passphrase / long-lived
  RSA key). DHKE is ephemeral per session (good); could add ratcheting later.
- **AES256 passphrase is offline-attackable by the relay.** The room id (which
  the relay routes on, so it always knows it) is the PBKDF2 salt, and the relay
  sees the ciphertext — so a malicious/compromised relay can mount an offline
  dictionary attack on the passphrase. 600k PBKDF2 iterations slow this, but a
  low-entropy passphrase will fall: AES256 security rests entirely on passphrase
  strength. Prefer a generated high-entropy passphrase, or use DHKE/PQKEM.
- **Reflection/replay — CLOSED for all modes (2026-07-02).** Every mode now
  authenticates the direction + ordering of each frame. RSA uses per-message
  HMAC + sequence numbers; AES256/DHKE/PQKEM use `AuthChannel` (a random
  per-session sender tag + a strictly-increasing sequence number, both bound
  into the AES-GCM additional data), which rejects a relay reflecting your own
  frame back and rejects replays. Residual: AES256's key is static
  (passphrase-derived, no exchange), so it stops in-session reflection/replay
  but NOT cross-session replay of a frame captured under the same passphrase +
  room id; DHKE/PQKEM are ephemeral per session and have no such residual.
- **Metadata:** relay sees room id + timing + ciphertext sizes (padding TBD).

### 2026-06-19 — identity keys + authenticated handshake (MITM gap closed in core) ✅
- Trust model chosen (per user): **simple accounts, each with a long-term
  identity keypair you verify IN PERSON; verified identity keys authenticate
  the per-session key exchange.** Dual keys — classical + post-quantum:
  - **Ed25519** (classical) via Web Crypto (native, 32-byte pub, 64-byte sig).
  - **ML-DSA-65 / Dilithium** (post-quantum) via `@noble/post-quantum`
    (1952-byte pub, 3309-byte sig). Dependency scoped to PQ only.
- `client/identity.js` — `Identity` class: generate, `publicBundle()`,
  `fingerprint()` (per-key, read aloud to verify), `safetyNumber()` (pair,
  order-independent), dual `sign()`, static dual `verify()` (BOTH schemes must
  pass), encrypted `export()/import()` of private keys at rest (PBKDF2 310k →
  AES-256-GCM, passphrase-protected; private keys never leave the device).
- `client/auth.js` — authenticated handshake: signs transcript
  `DOMAIN || roomId || ephemeralPubKey` with the identity; verifier checks the
  dual signature against the PINNED peer identity before trusting the ephemeral
  key. roomId binding prevents cross-room replay.
- `client/identity.test.mjs` — **proves the security property**: simulates a
  malicious relay (Mallory) swapping the ephemeral key; authenticated handshake
  REJECTS (swapped key + old sig, impostor sig, and cross-room replay) and
  ACCEPTS only the genuine signed key. Also covers dual-sig tamper rejection,
  fingerprint determinism, safety-number order-independence, encrypted
  export/import + wrong-passphrase rejection. **All pass.**
- `client/package.json` — `@noble/post-quantum` dep; `npm test` runs crypto +
  identity suites. Installed clean (0 vulnerabilities).
- Library facts (verified in Node 22): Web Crypto Ed25519 = supported;
  `@noble/post-quantum` API is `ml_dsa65.sign(msg, secretKey)` /
  `verify(sig, msg, pubKey)`; ML-KEM-768 available for future PQ key exchange.

### 2026-06-19 — account directory (passwordless, key-based) ✅
- DECIDED with user: **passwordless / key-based login** (server stores only
  public keys; login = sign a server challenge) + **identity key encrypted in
  the browser** (passphrase-unlocked; manual export/import as backup).
- `backend/accounts.py` — SQLite-backed public-key directory + FastAPI router
  under `/api`. Stores only username -> {ed_pub, mldsa_pub}; never secrets.
  Endpoints:
  - `POST /api/register {username, ed, mldsa, sig}` — sig = Ed25519 over
    `secure-chat/register/v1\n<username>\n<ed>\n<mldsa>`; proves control of the
    classical key + binds the bundle (anti-squatting). Strict size checks.
  - `GET /api/users/{username}` — returns the public identity bundle to pin.
  - `POST /api/auth/challenge {username}` — returns a fresh 32-byte nonce (TTL).
  - `POST /api/auth/verify {username, challenge, sig}` — verifies Ed25519 over
    the nonce, one-time-consumes the challenge, issues a bearer token (TTL).
  - `GET /api/me` (Bearer) — resolves token -> username.
- `backend/config.py` — DB path (env `SECURE_CHAT_DB`), username rules, fixed
  key/sig sizes, challenge/token TTLs.
- Server-side crypto: `cryptography==43.*` for Ed25519 verify. (ML-DSA verified
  CLIENT-side in the handshake; server only stores the PQ pubkey — server is
  not the authenticity root, so no native PQ dep needed server-side.)
- `backend/tests/test_accounts.py` — 12 tests: register+lookup, bad sig,
  duplicate, bad username, wrong key size, unknown user, full login flow,
  wrong-sig login, one-time challenge, token required, extra-field rejection.
  **All pass.** Full server suite now **24 passed**.
- Relay `/ws` intentionally stays **anonymous/room-based** (accounts are a key
  directory + auth, not coupled to the relay) to minimize who-talks-to-whom
  metadata. Documented as a deliberate choice.

### 2026-06-19 — browser wiring of identity/auth (live MITM gap CLOSED) ✅
- **Vendored ESM + import map.** Traced the transitive import closure of
  `@noble/post-quantum/ml-dsa.js` (12 files across post-quantum/hashes/curves,
  ~184 KB) and vendored byte-identical copies into `client/vendor/@noble/...`
  (`client/vendor/README.md` records provenance + versions). `index.html` has an
  inline `<script type="importmap">` mapping the three `@noble/` prefixes into
  `vendor/`. Inline import maps are required by spec, so instead of loosening CSP
  it is **pinned by its exact SHA-256 hash** in `script-src` (no `'unsafe-inline'`).
- **Identity UI** (`app.js` + `index.html`): create / unlock / forget / copy-
  backup. Private keys live only inside the passphrase-encrypted blob in
  `localStorage` (`Identity.export/import`); the fingerprint is shown for the
  contact to verify. Identity is **required** for DHKE/RSA, optional for AES256.
- **Authenticated handshake**: the `key` message now carries
  `{pub, reply, idb, sig}`; the receiver runs `verifyHandshake` (dual Ed25519 +
  ML-DSA) against the received bundle before deriving the shared key, and
  refuses + disconnects on failure (visible MITM signal).
- **In-person verification gate**: after the signature verifies, the UI shows
  the safety number and blocks messaging until the user confirms it matches.
  Confirmed bundles are pinned per room id (`sc.pins.v1`); a later session whose
  key differs raises a loud "identity CHANGED" banner and forces re-verification.
- **Tests**: `client/auth.integration.test.mjs` drives two real WebSocket peers
  through the running relay using the exact app.js authenticated protocol and
  asserts both derive the same key + identical safety number (DHKE + RSA). The
  vendored closure was separately proven self-sufficient under import-map-
  equivalent resolution. Existing suites still green (crypto, identity, legacy
  integration; backend pytest **24 passed**); server serves the pinned-hash CSP,
  the import map, and `vendor/@noble/...` same-origin.

### 2026-06-19 — relay WebSocket endpoint tests + deterministic leave-close ✅
- `backend/tests/test_ws.py` — 16 in-process endpoint tests driving the real
  `/ws` loop via Starlette `TestClient`: join→joined, verbatim msg/key relay,
  not-in-room, double-join, wrong-room, room-full (3rd member), leave-closes,
  oversized-frame, non-ascii, bad-envelope (+ connection survives a soft
  reject), extra-field-over-the-wire, rate-limit flood, and the CSWSH origin
  allow-list (disallowed rejected; allowed + missing accepted). Full backend
  suite now **40 passed**.
- `backend/main.py` — on a `leave` message the server now `await ws.close()`s
  explicitly before breaking, instead of relying on the framework's implicit
  close (which left the peer's socket hanging without a close frame). More
  correct relay behaviour and makes leave deterministically observable.

### 2026-06-19 — connection-level abuse / DoS bounds ✅
- `backend/config.py` — `MAX_CONNECTIONS` (global concurrent-socket cap) and
  `IDLE_TIMEOUT_SEC` (per-connection idle read timeout, 15 min default).
- `backend/relay.py` — `ConnectionLimiter` (`try_acquire`/`release`, single-
  event-loop safe) bounding total concurrent connections.
- `backend/main.py` — refuse over-cap connections at the handshake (close 1013)
  before `accept()`; wrap each `receive_text` in `asyncio.wait_for(IDLE_TIMEOUT)`
  to reap half-open/zombie sockets and connect-but-never-join squatters
  (warn + close 1001); release the slot in `finally`.
- Deliberately **did not** add a per-connection lifetime frame cap (the token
  bucket already bounds throughput; a lifetime cap would punish long chats) or
  per-IP limits (behind Tor all traffic appears from loopback, so per-IP is
  meaningless on `.onion`). Both noted inline.
- `backend/tests/test_ws.py` — +2 tests (cap refuses 3rd over a patched cap of
  2; silent socket is idle-timed-out and closed). Full server suite **42 passed**.

### 2026-06-19 — browser account directory integration ✅
- `client/identity.js` — added `signEd()` (classical-only Ed25519 signature) for
  server account proofs; the directory is not the authenticity root, so the PQ
  key isn't needed there.
- `client/account.js` — new module wrapping the `/api` directory protocol:
  `register` (Ed25519 proof binding username→bundle, byte-for-byte matching the
  server's `_register_message`), `fetchBundle` (lookup by username; null on 404),
  `login` (challenge → sign → token), `me`, and a shared username validator.
- `client/app.js` + `index.html` — account panel (claim username / log in) that
  appears once an identity is unlocked and remembers the username locally; an
  optional **Contact username** field in setup (DHKE/RSA only). On connect the
  client fetches that contact's bundle and uses it in the verification gate:
  pins are now keyed `user:<name>` when a username is in play (else `room:<id>`),
  and a live key that disagrees with the directory entry raises a loud mismatch
  banner. The in-person safety number remains the trust anchor.
- `client/accounts.integration.test.mjs` — drives account.js against the live
  server: register→lookup→login→me round-trip, duplicate-username 409, and
  wrong-key login rejection. All pass. (A static check also confirms every
  element id app.js references exists in index.html.)
- No CSP change needed (`connect-src 'self'` already covers the same-origin
  `/api` fetches; account.js/identity.js load under `script-src 'self'`).

### 2026-06-19 — post-quantum key exchange (PQKEM mode) ✅
- Completes the original encryption menu: the **key exchange** is now post-
  quantum too, not just the authentication. (Authentication was already
  one-classical-one-PQ: Ed25519 + ML-DSA-65 dual signatures on the handshake.)
- `client/crypto.js` — new `Pqkem` cipher: **hybrid ECDH P-256 + ML-KEM-768**,
  combined via HKDF-SHA-256 (salt = room id, domain-separated info) into an
  AES-256-GCM key. Secure unless BOTH primitives break ("harvest now, decrypt
  later" resistance) and no weaker than DHKE if ML-KEM were faulted. Vendored
  `@noble/post-quantum/ml-kem.js` (only new file; rest of the closure was shared
  with ml-dsa → 13 vendored files; import map already covers it).
- The exchange is **symmetric and join-order-race tolerant**: each peer offers a
  KEM public key, the other encapsulates, and secrets are folded in keyed by
  `SHA-256(ek)` so both sides combine the same secret(s) in the same order — one
  secret in the normal (staggered-join) case, two in the simultaneous-join race,
  converging either way. The brief two-step settling in the race is covered by
  the manual safety-number gate (no message is sent until the user confirms,
  seconds later, by which point the key is final).
- `client/app.js` + `index.html` — PQKEM enabled in the menu and treated as
  identity-required (authenticated handshake). Removed the per-connection
  handshake-signature cache (`myEph`): PQKEM's offer and answer are distinct
  payloads, each signed fresh; idempotent and harmless for DHKE/RSA.
- Tests: PQKEM added to `crypto.test.mjs` (2-round = the race path, converges),
  `integration.test.mjs`, and `auth.integration.test.mjs` (safety number
  matched). Integration harnesses now **stagger** joins (the realistic order).
  **Verified in a real browser** (Chromium via puppeteer): PQKEM selectable,
  handshake completes, safety numbers match, and messages decrypt **both
  directions** — confirming the vendored ML-KEM loads under CSP + import map.

### 2026-06-19 — security review + hardening (pentest follow-up) ✅
Ran a white-box review + live attack probes. Fixed the actionable findings:
- **M1 — `/api` abuse bounds.** Added a per-client-host token-bucket
  (`KeyedRateLimiter` in relay.py; on Tor it collapses to one global throttle)
  as a router-wide dependency on `/api` → floods now get `429` (confirmed live:
  27/90 blocked; previously 0). Added hard caps: `MAX_ACCOUNTS` (register →
  `503` when full), `MAX_PENDING_CHALLENGES`, `MAX_ACTIVE_TOKENS` (bounds the
  in-memory auth stores so a flood can't exhaust memory even within the TTL).
- **M2 — join deadline.** Split a short `JOIN_TIMEOUT_SEC` (30 s) for pre-join
  sockets from the generous `IDLE_TIMEOUT_SEC` (15 min) for joined peers, so
  "connect but never join" slot-squatters are dropped fast.
- **L3 — KDF work factor.** PBKDF2-SHA256 raised 310k → **600k** (OWASP 2023)
  for AES256 mode and identity-at-rest. Export blob is now `v:2` and stores
  `iters`; import honours it and falls back to 310k for old `v:1` backups
  (regression-tested).
- **H1 — honest trust boundary.** README now scopes "server compromise → only
  ciphertext" to *passive* compromise and documents that the web client trusts
  the server to serve honest code each load (mitigations: Android app, `.onion`,
  reproducible builds). Not a code change — a corrected security claim.
- Tests: +5 backend (`api` rate limit, account/challenge/token caps, join
  timeout) and +1 client (legacy-blob import). Server suite **47 passed**;
  client crypto/identity + all integration suites green.
- **Accepted / deferred (documented, not fixed):** L1 (ML-DSA pubkey ownership
  not proven at registration — needs a native PQ verify; no impersonation
  results since the in-person safety number is the trust root), L2 (room-slot
  squatting if a 256-bit room id leaks), I1/I2 (username enumeration + access-log
  metadata — inherent to a public directory; scrub logs on the `.onion`).

### 2026-07-02 — RSA mode: per-message HMAC authentication (forgery fix) ✅
- **Finding (code review):** RSA mode had NO message authenticity. Each message
  was a fresh AES key RSA-OAEP-wrapped to the recipient's public key — but that
  key crosses the relay in the (unencrypted, only signed) handshake, so the
  relay could wrap its own AES key and inject messages that decrypted cleanly
  and rendered as "peer". Encrypting to a public key proves nothing about the
  sender. (DHKE/PQKEM/AES256 don't have this: their GCM key is a shared secret
  the relay never learns.)
- **Fix (`client/crypto.js`, Rsa class):** the handshake answer now transports
  a random 32-byte MAC secret, RSA-OAEP-encrypted to the offerer's public key
  (`ws` field — covered by the existing identity signature over the whole
  payload, so the relay can't strip/replace it). Both sides HKDF-SHA-256 the
  secret (salt = room id) into TWO direction-separated HMAC-SHA-256 keys (info
  binds the sender's public key). Every message now carries a strictly
  increasing sequence number `n` and `mac = HMAC(sendKey,
  domain|room|n|ek|iv|ct)`; receivers verify the MAC BEFORE any decryption and
  reject stale `n`. Defeats: forgery (relay never learns the wrapped secret),
  reflection (direction keys), replay (seq + per-session secret). Wrapped
  secrets are folded into HKDF keyed by SHA-256(recipient pub), sorted — same
  race-tolerant convergence pattern as PQKEM — and first-write-wins so a
  replayed handshake frame can't diverge the keys.
- RSA's offer/answer are now distinct payloads (like PQKEM); app.js already
  handled that generically, so only comments changed there. `makeCipher` passes
  the room id to `Rsa`. Shared byte helpers (`concatBytes`, `sha256Hex`) moved
  above the RSA section (used by RSA + PQKEM).
- **Tests:** `crypto.test.mjs` + `rsaAttackChecks()` — Mallory-as-relay
  completes her own handshake from B's observed offer and injects a message
  (the exact old attack): REJECTED; reflection of A's own frame: REJECTED;
  replay of a genuine frame: REJECTED; tampered ciphertext: REJECTED (MAC
  checked before decrypt). All suites green after the change: client offline
  (`npm test`), both live integration suites (integration + auth, all algos),
  backend `pytest` 47 passed.
- **Still open (documented in KNOWN LIMITATIONS):** AES256/DHKE/PQKEM still
  lack reflection/replay protection; porting this MAC construction (or an AD/
  direction-key variant) to them is a natural next step.

### 2026-07-02 — verification gate now covers receiving (pre-verify display fix) ✅
- **Finding (code review):** the safety-number gate only blocked SENDING.
  Inbound `msg` frames were decrypted and rendered as "peer" as soon as
  `cipher.ready`, i.e. before the user confirmed the safety number. In the
  exact threat the gate exists for — a relay swapping the whole identity and
  running a MITM session — the swapped bundle carries a valid signature (the
  relay's own key), so the handshake verifies and the attacker could display
  messages as a trusted peer pre-verification (e.g. social-engineering the
  user into clicking through the gate).
- **Fix (`client/app.js`):** new `verified` flag, set only by
  `unlockMessaging()` (pin match / user confirms) and by the AES256 no-gate
  path (its passphrase IS the out-of-band verification); reset on connect and
  on socket close. The `msg` handler drops frames (never decrypts, shows a
  "[dropped]" sys line) while `verified` is false.
- **Verified in a real browser** (Chromium via puppeteer-core, DHKE): a
  Node-side authenticated peer completed the handshake and sent a message
  while Alice's verify panel was open → dropped, not rendered, send still
  locked; after clicking "it matches" a follow-up message rendered normally.
  All existing suites still green (client offline `npm test`, all 3 live
  integration suites, backend pytest 47 passed).

### 2026-07-02 — reflection/replay closed everywhere + crypto hardening ✅
Follow-up review after the receive-gate fix; fixed the remaining findings.
- **Reflection/replay for AES256/DHKE/PQKEM (`client/crypto.js`).** New shared
  `AuthChannel`: each frame carries a random per-session sender tag + a strictly
  increasing sequence number, both folded into the AES-GCM additional data (so
  a relay can't alter them without the key). Decrypt rejects a frame whose tag
  is our own (reflection) or whose sequence isn't advancing (replay). AES256,
  DHKE and PQKEM all route through it; RSA keeps its own HMAC construction.
  Residual documented: AES256's static key still permits cross-session replay.
- **PQKEM handshake-replay desync (confirmed bug).** A relay replaying a peer's
  validly-signed PQKEM offer made the recipient re-encapsulate a fresh secret
  and rotate the live session key (DoS). Fixed with first-write-wins per
  encapsulation key + idempotent `_derive` (skips when inputs are unchanged, so
  the channel and its replay counters survive a replay). DHKE made idempotent
  too (`if (this.chan) return`).
- **DHKE key derivation.** Was using the raw ECDH X-coordinate directly as the
  AES key; now runs it through HKDF (room-id salt + domain tag), matching PQKEM.
  `Dhke` now takes the room id; `makeCipher` passes it.
- **Login challenge domain separation (`accounts.py` + `account.js`).** The
  login signature now covers `secure-chat/login/v1\n` || nonce instead of a bare
  nonce, so it can't be cross-used as any other protocol signature. Backend +
  client updated in lockstep; `test_accounts.py` adjusted.
- **CSP import-map hash guard.** New `backend/tests/test_csp_hash.py` recomputes
  the SHA-256 of the inline importmap in index.html and asserts the served CSP
  still pins it — so editing the import map without regenerating the hash fails
  loudly instead of silently breaking the page.
- **Tests:** `crypto.test.mjs` gained reflection/replay/tamper checks for
  AES256/DHKE/PQKEM and a PQKEM replay-doesn't-desync regression. Verified in a
  real browser (Chromium/puppeteer): DHKE handshake, receive-gate, and a two-way
  message exchange under the new framing all work. All suites green.

## TODO / NEXT (suggested order)
- [x] **Initialize git** in `~/secure-chat` and make the first commit — DONE
      (repo initialized on `master`; initial commit covers backend, client, and
      tests; `.venv`/`node_modules`/DBs/logs ignored).
- [x] **Browser account integration** — DONE (see dated entry above): register /
      login / fetch-by-username with directory-aware pinning, plus an integration
      test for the client directory protocol.
- [x] **Abuse/DoS hardening** — DONE (see dated entry above): global connection
      cap + idle read timeout. Per-IP limits and lifetime frame caps were
      intentionally skipped (see rationale in the entry).
- [x] **Reflection/replay protection for AES256/DHKE/PQKEM** — DONE (2026-07-02):
      `AuthChannel` binds a per-session sender tag + sequence number into the GCM
      additional data. AES256 has a documented cross-session-replay residual
      (static key).
- [ ] **OTP mode** (deferred) — pre-shared pad handling, pad consumption
      tracking, never-reuse enforcement (all client-side).
- [ ] **Tor deployment** — hardened reverse setup, `.onion` service config,
      bind notes; never expose uvicorn directly to a public interface.
- [ ] **Handshake replay across sessions in a reused room (Medium, found
      2026-07-02 pentest)** — `auth.js`'s signed transcript is
      `DOMAIN || roomId || ephemeralPayload`, with no per-connection freshness
      value. A malicious relay can replay a peer's OLD (but validly-signed)
      handshake message from a past session into a NEW session that reuses the
      same room id. The signature still verifies (room+domain match) and, if
      the peer is already pinned, the safety-number gate auto-passes silently
      — so the UI shows "verified" / "secure channel established" while the
      two legitimate parties actually hold desynced session keys and real
      messages fail to decrypt. DHKE's "first key wins" guard means the relay
      doesn't even need to suppress the real handshake message, just deliver
      the stale one first. Affects DHKE/RSA/PQKEM (all use the same transcript
      via `signedHandshake`/`verifyHandshake`). Confirmed via PoC — reproduced
      the desync; also confirmed (via a second PoC) that it does NOT allow
      full session-key reuse or replay of old plaintext-equivalent ciphertext
      into the new session, since each side still mixes in a fresh ephemeral
      private key — impact is integrity/availability + a misleading "verified"
      UI state, not confidentiality loss. Fix: fold a fresh per-connection
      nonce (contributed by both peers, sorted/folded the way RSA/PQKEM already
      fold multi-secret contributions) into the signed transcript, or treat
      room ids as strictly single-use server-side.
- [ ] **AES256 cross-session replay (Low — already documented, re-confirmed
      2026-07-02)** — re-verified via PoC that a captured session-1 frame still
      decrypts again in a fresh session-2 using the same room id + passphrase,
      because `AuthChannel`'s replay counter resets per session while the
      AES256 key is static. Known/accepted residual (see KNOWN LIMITATIONS);
      listed here only as a re-confirmation, not a new finding.

DONE since this list was first written (pruned from the TODOs above): web client
MVP with the WebCrypto encryption menu; the DHKE/RSA/PQ `key`-message handshake
flow (documented + implemented); authenticated key exchange end-to-end in the
browser; the identity model decision (long-term identity keys verified in person,
relay stays anonymous/room-based); and ASGI endpoint tests for the relay.

## Open questions for the user
- Identity model: fully anonymous/ephemeral, or accounts? (Leaning anonymous
  for the privacy goal.)
- How do two people exchange a room id out of band (QR, link, in person)?
- Group chat (>2) ever needed, or strictly 1:1?

## How to run (quick ref)
```bash
cd ~/secure-chat/backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q                          # full server suite (validation + accounts + ws)
./run.sh                           # terminal 1: relay + web client on 127.0.0.1:8000

# client-side (Node 20+), from ~/secure-chat/client:
npm test                           # crypto + identity/auth unit suites (offline)
node integration.test.mjs          # relay round-trip (server running)
node auth.integration.test.mjs     # authenticated handshake through relay (server running)
```

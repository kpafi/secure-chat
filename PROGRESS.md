# secure-chat — progress log

Working file so any session can pick up where the last left off. Newest notes
at the top of each section. Dates are absolute (YYYY-MM-DD).

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
- **No replay/ordering protection** at the app layer yet (relay forwards as-is).
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

## TODO / NEXT (suggested order)
- [x] **Initialize git** in `~/secure-chat` and make the first commit — DONE
      (repo initialized on `master`; initial commit covers backend, client, and
      tests; `.venv`/`node_modules`/DBs/logs ignored).
- [ ] **Browser account integration** — call the existing `/api` register/login
      endpoints from the web client, and optionally fetch a peer's bundle by
      username to pre-fill pinning (still verified in person; the directory is a
      convenience, not a trust root). Server already stores public keys only.
- [x] **Abuse/DoS hardening** — DONE (see dated entry above): global connection
      cap + idle read timeout. Per-IP limits and lifetime frame caps were
      intentionally skipped (see rationale in the entry).
- [ ] **OTP mode** (deferred) — pre-shared pad handling, pad consumption
      tracking, never-reuse enforcement (all client-side).
- [ ] **Tor deployment** — hardened reverse setup, `.onion` service config,
      bind notes; never expose uvicorn directly to a public interface.

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

# secure-chat

A deliberately tiny, security-first text chat. ASCII only. The server is a
**dumb relay**: all encryption happens in the client, and the server only
forwards opaque ciphertext between two parties in a room. The server never
holds keys, never decrypts, and never stores or logs message content.

> Status: **backend relay + web client working locally**, three encryption
> modes verified end-to-end (DHKE, AES-256, RSA). The DHKE/RSA key exchange is
> now **authenticated in the browser client** with long-term identity keys
> (Ed25519 + ML-DSA-65) and an in-person safety-number check, closing the
> relay-MITM gap. See `PROGRESS.md`.

## Why this design
A breach of the server should leak nothing readable. By keeping the server
ignorant of keys and plaintext (end-to-end encryption), the worst a *passive*
attacker who reads everything the server stores or sees obtains is ciphertext
plus minimal routing metadata. The codebase is intentionally small so it can be
audited end to end.

### Trust boundary of the web client (important)
This guarantee covers **passive** compromise. It does **not** mean an *active*
attacker who controls the server gets nothing: the same server also **serves the
client JavaScript** (the crypto, the import map, the page), so a compromised
server can ship backdoored code on the next load and exfiltrate plaintext or
private keys. CSP does not prevent this (the attacker controls the page that
declares the policy), and neither does SRI (it controls the hashes too). This is
the unavoidable trust assumption of *any* web-delivered E2EE app: **you trust the
server to serve honest code every time you load it.** Mitigations on the roadmap:
the dedicated **Android app** (code not server-delivered) and serving over a
hardened **`.onion`**; for the web, reproducible builds + out-of-band code-hash
verification. Treat the web client as "secure against a passive/compromised
*relay*", not against a server actively serving malicious code.

## Architecture (current)
```
Client A --[ciphertext]--> Relay server --[ciphertext]--> Client B
              (FastAPI WebSocket, in-memory rooms, no storage)
```
- Transport: WebSocket (`/ws`).
- Rooms: 256-bit random hex ids, max 2 members, vanish when empty.
- Wire format: strict JSON envelope, printable ASCII only, validated by pydantic.
- The encryption menu (RSA / AES-256 / DHKE / post-quantum KEM / OTP) is a
  **client** concern; the `alg` field is just an advisory tag the server relays.

## Run locally
```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Server-side validation tests:
pytest tests/test_validation.py -q

# Start the relay + web client (loopback only):
./run.sh            # or: python main.py
# Then open http://127.0.0.1:8000 in two browser tabs/windows,
# click Generate in one, copy the room id to the other, pick the same
# encryption mode in both, and Connect.

# Client-side crypto round-trip tests (Node 20+):
node ../client/crypto.test.mjs

# Full-stack integration test (server must be running):
node ../client/integration.test.mjs
# Authenticated-handshake integration test (server must be running):
node ../client/auth.integration.test.mjs
# Account directory integration test (server must be running):
node ../client/accounts.integration.test.mjs

# Legacy two-client smoke test (raw relay, no crypto):
python tests/smoke_client.py
```

## Encryption modes (client-side)
| Mode    | Key agreement                       | Message cipher      | Notes                                       |
|---------|-------------------------------------|---------------------|---------------------------------------------|
| DHKE    | ephemeral ECDH P-256                | AES-256-GCM         | per-session; **identity-authenticated**     |
| AES256  | PBKDF2 from shared passphrase + session nonces | ratcheted AES-256-GCM (one-time keys) | no key swap → not relay-MITM-able |
| RSA     | RSA-OAEP-2048 key transport         | ratcheted AES-256-GCM (one-time keys) | **identity-authenticated**, **forward-secret** |
| PQKEM   | **hybrid ECDH P-256 + ML-KEM-768**  | AES-256-GCM         | post-quantum; **identity-authenticated**    |
| OTP     | —                                   | —                   | deferred (in-person pad exchange)           |

**PQKEM** derives the AES-256 key (via HKDF-SHA-256) from *both* a classical
ECDH P-256 secret *and* an ML-KEM-768 (FIPS-203) secret, so the session stays
confidential unless an attacker breaks **both** — defeating "harvest now,
decrypt later" while remaining no weaker than DHKE if ML-KEM were faulted. It is
authenticated by the same dual (Ed25519 + ML-DSA-65) identity handshake, so the
*authentication* is also one-classical-one-post-quantum.

DHKE and RSA handshakes are signed by a long-term identity (Ed25519 + ML-DSA-65)
that each user generates locally and the other verifies **in person** by
comparing a safety number. A hostile relay that swaps the ephemeral key cannot
forge the signature; one that swaps the whole identity is caught because the two
endpoints then compute different safety numbers. The signed transcript also
covers a fresh random nonce from **each** peer's current connection (exchanged
in a plaintext hello before the handshake), so a captured, validly-signed
handshake from an earlier session of the same room cannot be replayed into a
new one — it can never cover the nonce the victim just generated. Identity
private keys are passphrase-encrypted on the device and never sent to the
server.

**RSA mode** is RSA *key transport* plus a forward-secret symmetric ratchet.
The handshake answer transports an RSA-OAEP-wrapped 32-byte root secret; both
sides HKDF it into two direction-separated HMAC-SHA-256 *chain* keys, and every
message is encrypted with a **one-time AES-256-GCM key** drawn from the
sender's chain (`msgKey = HMAC(chain, 0x01)`, `chain' = HMAC(chain, 0x02)`).
The chain only steps forward and consumed keys are deleted, and the moment real
traffic starts the client erases the root secret *and* the per-session RSA
private key — so compromising a device mid-conversation reveals nothing about
earlier messages (**forward secrecy**), and past sessions are never affected.
Authenticity comes with it: the relay never learns the wrapped root, so forged
frames fail AEAD authentication; direction-separated chains reject reflection;
strictly increasing sequence numbers plus one-time keys reject replay. (The
other modes get forgery protection implicitly: their AES-GCM key is a shared
secret the relay never learns.)

**AES256 mode** runs the same ratchet, rooted in the PBKDF2-derived passphrase
secret **plus a fresh random session nonce from each peer** (exchanged in a
plaintext hello when both join). Your own nonce is fresh every connection, so a
frame captured in an earlier session under the same room + passphrase can never
authenticate in a new one — closing what used to be a documented cross-session
replay residual. Honest limit: the passphrase is a long-term secret that lives
outside the code (your head, the input field), so an attacker who learns *it*
and recorded the ciphertext can still derive every session's keys — the
ratchet's forward secrecy protects only against captured ratchet *state*. For
real forward secrecy use DHKE, PQKEM, or RSA.

## Accounts (optional directory)
The server doubles as a passwordless **public-key directory** under `/api`. From
the client you can claim a username, prove control of it by signing a server
challenge, and look a contact up to pre-fill and pin their identity for the
handshake. The server stores **only public keys** — never passwords, private
keys, or plaintext. The directory is a convenience, not a trust root (it shares
the relay's origin), so the in-person safety-number check still governs trust; a
key that disagrees with the published one is flagged loudly.

**Dual ownership proof at registration.** Claiming a username requires a
signature from **both** identity keys over the bundle — Ed25519 (verified
server-side via `cryptography`) *and* ML-DSA-65 (verified server-side via
`dilithium-py`). This stops a squatter from binding a post-quantum public key
they do not actually control into their directory entry.

**The username namespace is not enumerable.** Registration mints a random
per-account lookup token; a contact fetches your bundle with the **handle**
`username#token`, not the bare username. A lookup with a missing user or a
wrong token returns an identical `404`, and the login challenge/verify
endpoints no longer reveal whether a username exists — so the directory cannot
be walked to harvest who has an account. A dedicated, stricter rate limit
bounds the lookup path on top of the shared `/api` limiter. (Registering a
name that is taken still returns `409` — inherent to a unique namespace — but
each probe costs a full dual-signed proof and is rate-limited.)

## Wire protocol
Client -> server JSON envelope:
| field   | type   | notes                                                        |
|---------|--------|--------------------------------------------------------------|
| type    | enum   | `join` \| `leave` \| `key` \| `msg`                          |
| room    | string | exactly 64 lowercase hex chars (256-bit id)                  |
| payload | string | base64 ciphertext / key material; required for `msg`/`key`   |
| alg     | enum?  | advisory: `RSA`,`AES256`,`DHKE`,`PQKEM`,`OTP` (server ignores)|

Server -> client: `{"type":"joined"}`, relayed envelopes, or
`{"type":"error","reason":"..."}`.

## Metadata & residual risks

**Logging (I2).** The relay writes **no** request or connection metadata to
disk: uvicorn's access log is disabled and connection-lifecycle logging is
lifted to WARNING, so there is no who-connected-when / which-endpoint trail for
a seized `.onion` host to yield. Only genuine error tracebacks are logged, and
those never contain payloads or room ids. `run.sh` carries the matching flags;
a guard test (`tests/test_logging.py`) fails if either is dropped. **Do not
re-enable access logging in production.**

**Room ids are a bearer capability (L2).** A room is joined purely by knowing
its 64-hex (256-bit) id — the relay is intentionally anonymous and performs no
joiner authentication, which is what keeps who-talks-to-whom out of the server.
A room id is therefore a secret: anyone who learns one can take a slot in that
2-member room. The impact of a leaked id is deliberately bounded and does **not**
include confidentiality or impersonation:
- **No plaintext.** Everything the relay forwards is opaque ciphertext; a
  squatter reads nothing.
- **No impersonation.** For DHKE/RSA/PQKEM the key exchange is signed by a
  long-term identity and gated by an in-person safety number, so a squatter
  cannot pose as the real contact — the handshake fails and the UI says so. For
  AES256 the passphrase (never sent) is the gate.
- **Residual = availability + coarse metadata.** A squatter can occupy a slot
  (a self-healing DoS: generate a fresh id and reconnect) and observe ciphertext
  timing/sizes until the handshake fails.

This is inherent to an anonymous, shared-capability relay; "fixing" it with
relay-side admission control would mean binding identities to the relay and
recording exactly the who-talks-to-whom metadata this design omits. The
mitigations are structural and already in place: room ids are **high-entropy
(256-bit, unguessable)** and **single-use/rotatable** (generate a fresh one per
conversation), so treat a room id like a one-time secret and never reuse or
expose one.

**What the relay still sees.** Room id, message timing, and ciphertext sizes
(length padding is a possible future addition). This is the minimal routing
metadata a relay cannot avoid.

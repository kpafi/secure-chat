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
| AES256  | PBKDF2 from shared passphrase       | AES-256-GCM         | no key swap → not relay-MITM-able           |
| RSA     | RSA-OAEP-2048 public-key swap       | hybrid AES-256-GCM  | **identity-authenticated**                  |
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
endpoints then compute different safety numbers. Identity private keys are
passphrase-encrypted on the device and never sent to the server.

## Accounts (optional directory)
The server doubles as a passwordless **public-key directory** under `/api`. From
the client you can claim a username (an Ed25519 signature binds it to your
identity bundle), prove control of it by signing a server challenge, and look a
contact up by username to pre-fill and pin their identity for the handshake. The
server stores **only public keys** — never passwords, private keys, or
plaintext. The directory is a convenience, not a trust root (it shares the
relay's origin), so the in-person safety-number check still governs trust; a key
that disagrees with the published one is flagged loudly.

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

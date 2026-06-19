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
ignorant of keys and plaintext (end-to-end encryption), the worst an attacker
who fully owns the server can obtain is ciphertext plus minimal routing
metadata. The codebase is intentionally small so it can be audited end to end.

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

# Legacy two-client smoke test (raw relay, no crypto):
python tests/smoke_client.py
```

## Encryption modes (client-side)
| Mode    | Key agreement                  | Message cipher      | Notes                                   |
|---------|--------------------------------|---------------------|-----------------------------------------|
| DHKE    | ephemeral ECDH P-256           | AES-256-GCM         | per-session; **identity-authenticated** |
| AES256  | PBKDF2 from shared passphrase  | AES-256-GCM         | no key swap → not relay-MITM-able       |
| RSA     | RSA-OAEP-2048 public-key swap  | hybrid AES-256-GCM  | **identity-authenticated**              |
| PQKEM   | —                              | —                   | planned (needs vetted WASM ML-KEM)      |
| OTP     | —                              | —                   | deferred (in-person pad exchange)       |

DHKE and RSA handshakes are signed by a long-term identity (Ed25519 + ML-DSA-65)
that each user generates locally and the other verifies **in person** by
comparing a safety number. A hostile relay that swaps the ephemeral key cannot
forge the signature; one that swaps the whole identity is caught because the two
endpoints then compute different safety numbers. Identity private keys are
passphrase-encrypted on the device and never sent to the server.

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

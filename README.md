# secure-chat

A deliberately tiny, security-first text chat. ASCII only. The server is a
**dumb relay**: all encryption happens in the client, and the server only
forwards opaque ciphertext between two parties in a room. The server never
holds keys, never decrypts, and never stores or logs message content.

> Status: **backend relay + web client working locally and deployed**, five
> encryption modes verified end-to-end in real browsers (DHKE, AES-256, PQKEM,
> OTP; `e2e/all-modes.mjs`), all forward-secret ratchets. The DHKE/PQKEM key exchange is **authenticated in
> the browser client** with long-term identity keys (Ed25519 + ML-DSA-65) and an
> in-person safety-number check, closing the relay-MITM gap. The relay is
> reachable over a **Tor v3 onion service** as well as clearnet — see
> `deploy/README.md`. See `PROGRESS.md`.

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
server to serve honest code every time you load it.** The mitigation is the
dedicated **Android app** (audited client shipped in the APK, not
server-delivered); for the web, reproducible builds + out-of-band code-hash
verification remain on the roadmap. Treat the web client as "secure against a
passive/compromised *relay*", not against a server actively serving malicious
code.

The relay is also served over a hardened **`.onion`** (live; see
`deploy/README.md`). Be precise about what that buys: the address is
self-authenticating — it *is* an Ed25519 public key — so reaching it trusts no
certificate authority and no DNS, and the relay never learns a client IP. It
does **not** close the gap above, because the onion still serves the
JavaScript. Only the app does that.

## Architecture (current)
```
Client A --[ciphertext]--> Relay server --[ciphertext]--> Client B
              (FastAPI WebSocket, in-memory rooms, no storage)
```
- Transport: WebSocket (`/ws`).
- Rooms: 256-bit random hex ids, max 2 members, vanish when empty.
- **Entry is approved on both devices.** The first party in owns the room;
  anyone else who has the code is queued and must be let in by the owner, who is
  shown that peer's key fingerprint and trust mark. Waiting occupies no member
  slot, so knowing a code no longer lets a stranger take the room from the person
  you invited (pentest P-08). The approval is only as good as its binding: the
  client pins the identity it admitted and refuses a handshake from any other,
  because the relay chooses who is routed to whom.

  Approval is **symmetric**, which is what makes it independent of the relay
  (pentest F-PROTO-001). Each side refuses a handshake from an identity its own
  user never approved: the owner through the queue prompt, the other side
  through the same prompt shown when the peer's signed handshake arrives. One
  thing skips it: a key you have already verified **in person** (🟢 in your users
  list, behind the at-rest passphrase). Everything else — including your first
  chat with a contact you picked by name — costs one approve/deny prompt, shown
  immediately before the safety-number step. Nothing on the wire can switch it
  off, because nothing on the wire is consulted: a relay knows the room code (it
  is the join frame) and can always present itself as a legitimate participant,
  so anything a peer says about its own authority is worthless.

  Picking a contact by name used to skip the prompt too, by matching the peer
  against the bundle fetched for that handle. That was removed (2026-08-08): the
  directory answer carries **no signature**, so nothing binds a handle to its
  key material, and a hostile directory could switch the approval off for exactly
  the flow it was meant to protect. Restoring it needs signed directory answers.
- Wire format: strict JSON envelope, printable ASCII only, validated by pydantic.
- The encryption menu (AES-256 / DHKE / post-quantum KEM / OTP) is a
  **client** concern; the `alg` field is just an advisory tag the server relays.

## Run locally
```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Start the relay + web client (loopback only):
./run.sh            # or: python main.py
# Then open http://127.0.0.1:8000 in two browser tabs/windows,
# click Generate in one, copy the room id to the other, pick the same
# encryption mode in both, and Connect.
```

Tests, from least to most environment:
```bash
cd backend && python -m pytest -q            # server: validation, rate limits, logging guard, ... (165 tests)
cd client  && npm test                       # client crypto/identity/OTP/contacts/chats unit tests (Node 20+)
# with the relay running:
node client/integration.test.mjs             # full-stack relay round trip
node client/auth.integration.test.mjs        # authenticated handshake
node client/accounts.integration.test.mjs    # account directory
# real browsers (see e2e/README.md): two-user flows, room admission, all five modes, hostile relay
```

## Deployment
`deploy/` holds the live server config — the systemd unit, the Tor onion-service
`torrc`, and the Caddy site — copied from the running box so a re-provision
reproduces it. `deploy/README.md` is the recipe.

Two rules that are easy to get wrong and expensive to get wrong:
- **uvicorn binds `127.0.0.1` only.** Caddy (clearnet TLS) and Tor (onion) both
  reach it over loopback; it is never on a public interface.
- **`SECURE_CHAT_TRUSTED_PROXIES` stays unset** while the onion forwards to that
  port. Loopback is no longer proof of "came through Caddy", so trusting it lets
  an onion visitor forge `X-Forwarded-For` and mint a rate-limit bucket per
  request (pentest F-03). Unset, every limiter shares one bucket and fails
  closed. The reasoning and the measured numbers are in `deploy/README.md`.

## Encryption modes (client-side)
| Mode    | Key agreement                       | Message cipher      | Notes                                       |
|---------|-------------------------------------|---------------------|---------------------------------------------|
| DHKE    | ephemeral ECDH P-256                | ratcheted AES-256-GCM (one-time keys) | **identity-authenticated**, **forward-secret** |
| AES256  | PBKDF2 from shared passphrase + session nonces | ratcheted AES-256-GCM (one-time keys) | no key swap → not relay-MITM-able |
| PQKEM   | **hybrid ECDH P-256 + ML-KEM-768**  | ratcheted AES-256-GCM (one-time keys) | post-quantum; **identity-authenticated**, **forward-secret** |
| OTP     | pre-shared pad, exchanged in person | **true XOR one-time pad** + one-time HMAC-SHA-256 tag | information-theoretic *confidentiality* (see caveats); no network key swap → not relay-MITM-able |

Every mode frames its messages through the same **forward-secret ratchet**:
two direction-separated one-way HMAC-SHA-256 chains, a one-time AES-256-GCM
key per message (consumed keys deleted), and strictly increasing sequence
numbers. What differs per mode is only where the chains' root comes from.

**PQKEM** roots the chains (via HKDF-SHA-256) in *both* a classical ECDH P-256
secret *and* an ML-KEM-768 (FIPS-203) secret, so the session stays
confidential unless an attacker breaks **both** — defeating "harvest now,
decrypt later" while remaining no weaker than DHKE if ML-KEM were faulted. It is
authenticated by the same dual (Ed25519 + ML-DSA-65) identity handshake, so the
*authentication* is also one-classical-one-post-quantum. It erases its
handshake material (ECDH private key, KEM secret key, raw shared secrets)
the moment real traffic starts; **DHKE** drops its private key even earlier, as
soon as the chains are derived. So both handshake modes have in-session
*and* cross-session forward secrecy: state captured at time T decrypts nothing
from before T, and never another session.

DHKE and PQKEM handshakes are signed by a long-term identity (Ed25519 + ML-DSA-65)
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

**RSA mode was removed on 2026-08-21** (pentest finding F-CRYPTO-009) and this
build refuses it: it is not offered in the menu, and `makeCipher` throws with
the reason if anything asks for it. RSA *key transport* lets one side choose the
modulus that the other side's root secret is encrypted to, and a counterparty
who offers `e = 65537` with `n = <small factor> x <large prime>` hands the whole
session — both directions, past and future — to any passive observer of the
handshake. No cheap validation can detect that (nothing certifies a modulus is
the product of two large primes), and the alternative fix, making the root
contributory, needs a third handshake frame the protocol has no room for. DHKE
and PQKEM have no analogue: their peer material is a P-256 point (on-curve and
non-identity enforced by WebCrypto, prime order) plus an ML-KEM encapsulation
key, and the secret is contributory. Use those.
(The remaining modes get forgery protection implicitly: their AES-GCM key is a
shared secret the relay never learns.)

**AES256 mode** runs the same ratchet, rooted in the PBKDF2-derived passphrase
secret **plus a fresh random session nonce from each peer** (exchanged in a
plaintext hello when both join). Your own nonce is fresh every connection, so a
frame captured in an earlier session under the same room + passphrase can never
authenticate in a new one — closing what used to be a documented cross-session
replay residual. Honest limit: the passphrase is a long-term secret that lives
outside the code (your head, the input field), so an attacker who learns *it*
and recorded the ciphertext can still derive every session's keys — the
ratchet's forward secrecy protects only against captured ratchet *state*. For
real forward secrecy use DHKE or PQKEM.

**OTP mode** is a genuine **one-time pad**: a large random pad is generated on
one device and carried to the other **in person** (exported as a
passphrase-encrypted file you move over Bluetooth / USB / QR / NFC, then
imported). Each plaintext byte is XORed with a fresh pad byte that is **never
reused**, so the *confidentiality of the content* is information-theoretic — no
computational assumption, no key exchange the relay could MITM. The pad is split
into two halves so the two peers draw from disjoint bytes (no reuse across
senders), a strictly increasing offset rejects replays (including across
sessions), and consumed pad bytes are **zeroed as they are used** (device
capture at time T cannot decrypt earlier traffic). Two honest caveats, both
documented in the client: (1) XOR alone has *no integrity*, so each message
carries an **HMAC-SHA-256 tag under a one-time key also drawn from the pad** —
that authenticator is *computational*, because an information-theoretic one-time
MAC would be hand-rolled crypto this project forbids; and (2) the pad is
generated from the OS CSPRNG (optionally hardened with user-drawn "draw to
generate" entropy), not a certified hardware TRNG, so treat its confidentiality
as *"at least as strong as the CSPRNG"* rather than literally perfect. The pad
is consumed one byte per plaintext byte (+32 per message), so it is a finite
budget the UI shows depleting; when it runs low, exchange a new pad in person.
The pad is stored **encrypted at rest** (PBKDF2-600k → AES-256-GCM under a
per-pad passphrase, like the identity blob), with its consumption offsets inside
the authenticated blob so they can't be rolled back to force reuse; an imported
pad is rejected if it isn't random enough (all-zero/low-entropy); and a pad may
be **live in only one tab/window at a time** (an exclusive same-origin lock),
because two concurrent senders drawing from one pad would be a two-time-pad
break. These last three were added after a self-pentest of the mode (see
`PROGRESS.md`, 2026-07-16).

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

## Contacts, web of trust, and async chats
Beyond the live room, a left-drawer menu opens two more views. Everything they
store on the device — the contact list AND full chat history — is encrypted at
rest with **PBKDF2-600k → AES-256-GCM under your identity passphrase** (the key
lives only in memory while the identity is unlocked), the same posture as the
identity blob and OTP pads.

**Users** — your known contacts with their public keys and a **trust mark**:
🟢 *verified by you* (you compared the fingerprint/safety number in person, or
confirmed it through the live-room gate), 🟡 *vouched* (a contact **you**
verified has published a signed vouch for them — the marker names the voucher),
or ⚪ *unverified*. Vouches are **dual-signed** (Ed25519 + ML-DSA-65) statements
the server verifies before storing, but the server is still not the trust root:
the 🟡 mark is awarded **only** when the client re-checks the signature against
its **own pinned copy** of the voucher's keys, so a lying directory cannot
invent trust.

**Chats** — persistent one-to-one messaging with no shared live room, WhatsApp
style. Messages travel as a **sealed envelope**: hybrid *ephemeral ECDH P-256 +
ML-KEM-768* → HKDF → AES-256-GCM to the recipient's published encryption keys,
with the sender's identity and a dual signature sealed **inside** the ciphertext
(the store-and-forward mailbox never learns who wrote a message). The mailbox
stores only *(recipient, opaque ciphertext, arrival time)*, gated by the
recipient's lookup token to post and their session token to fetch, and deletes
on fetch. Each chat is **locked to a mode** — `SEALED` (default) or `AES256` (an
extra passphrase layer inside the envelope); changing it sends a signed control
message the other side must **accept** before either switches. Trade-off:
sealed messages have per-message ephemerals but no live ratchet, so a
compromise of a recipient's long-term encryption keys can expose past envelopes
captured on the wire — the `AES256` mode's out-of-band passphrase mitigates
exactly this.

## Wire protocol
Client -> server JSON envelope (`backend/validation.py`, `extra="forbid"`):
| field   | type   | notes                                                        |
|---------|--------|--------------------------------------------------------------|
| type    | enum   | `join` \| `leave` \| `key` \| `msg` \| `knock` \| `admit` \| `deny` |
| room    | string | exactly 64 lowercase hex chars (256-bit id)                  |
| payload | string | base64; ciphertext / key material / the knocker's opaque self-introduction |
| alg     | enum?  | advisory: `AES256`,`DHKE`,`PQKEM`,`OTP` (server ignores; the `RSA` member is kept for wire compat with old clients, which this client refuses) |
| jid     | string?| only on `admit`/`deny`: the server-issued join id of the waiting socket |

Server -> client: `{"type":"joined","role":"owner"|"guest"}`,
`{"type":"pending"}` (you are queued), `{"type":"knock","jid":…,"payload":…}`
(owner only), `{"type":"denied"}`, `{"type":"withdrawn","jid":…}` (a knocker
left), `{"type":"turned-away","count":…}`, relayed envelopes, or
`{"type":"error","reason":"..."}`. The admission flow is described under
"Architecture" above.

## Metadata & residual risks

**Logging (I2).** The relay writes **no** request or connection metadata to
disk: uvicorn's access log is disabled and connection-lifecycle logging is
lifted to WARNING, so there is no who-connected-when / which-endpoint trail for
a seized `.onion` host to yield. Only genuine error tracebacks are logged, and
those never contain payloads or room ids. `run.sh` carries the matching flags;
a guard test (`tests/test_logging.py`) fails if either is dropped. **Do not
re-enable access logging in production.** Tor is configured not to undo this:
`SafeLogging 1` and `Log warn syslog`, so the onion daemon adds no
per-connection trail of its own, and Caddy's site log is `output discard`.

**Room ids are a bearer capability (L2).** A room is joined purely by knowing
its 64-hex (256-bit) id — the relay is intentionally anonymous and performs no
joiner authentication, which is what keeps who-talks-to-whom out of the server.
A room id is therefore a secret: anyone who learns one can take a slot in that
2-member room. The impact of a leaked id is deliberately bounded and does **not**
include confidentiality or impersonation:
- **No plaintext.** Everything the relay forwards is opaque ciphertext; a
  squatter reads nothing.
- **No impersonation.** For DHKE/PQKEM the key exchange is signed by a
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

## Security reviews
The project has been pentested repeatedly; every report is in the repo and every
finding's status is tracked in `PROGRESS.md`.

| date | report | scope |
|---|---|---|
| 2026-07-18 | `docs/pentests/secure-chat-security-audit-2026-07-18.md` | external black-box audit of the live web instance (9 items, all addressed — narrative in `docs/security-history.md`) |
| 2026-07-25 | `docs/pentests/secure-chat-pentest-2026-07-25.md` | in-depth pentest; 8 findings (token gate, client canonicalisation), all addressed |
| 2026-07-26 | `docs/pentests/secure-chat-pentest-2026-07-26.md` | first full pentest of the final product (P-08 room admission; OTP at-rest), all fixed |
| 2026-07-27 | `docs/pentests/secure-chat-pentest-2026-07-27.md` | re-test of the 07-26 fixes; 4 High / 7 Medium (OTP rollback H-3/M-7, trust-pin migration H-2), all fixed |
| 2026-07-29 | `docs/pentests/secure-chat-pentest-2026-07-29.md` | whole-project review after the onion deployment; 3 High in the at-rest layer (Android pad floor), rate-limit keying M-1..M-3 |
| 2026-08-07 | `docs/pentests/secure-chat-pentest-2026-08-07.md` | multi-agent red team; no Critical/High, 47 Medium/Low/Info incl. F-PROTO-001 (admission binding). Fixes in progress on `pentest-2026-08-07-fixes` — see `PROGRESS.md` |

`docs/PENTEST-PROMPT.md` is the standing brief for a full review;
`.claude/agents/pentest-new-code.md` is the narrower agent that attacks only
changed code (run it after every fix — a fix is new code).

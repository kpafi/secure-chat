# secure-chat

A deliberately tiny, security-first text chat. ASCII only. The server is a
**dumb relay**: all encryption happens in the client, and the server only
forwards opaque ciphertext between two parties in a room. The server never
holds keys, never decrypts, and never stores or logs message content.

> Status: **backend relay + web client working locally and deployed**, four
> encryption modes verified end-to-end (DHKE, AES-256, RSA, PQKEM), all
> forward-secret ratchets. The DHKE/RSA/PQKEM key exchange is **authenticated in
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
- **Entry is owner-approved.** The first party in owns the room; anyone else who
  has the code is queued and must be let in by the owner, who is shown that
  peer's key fingerprint and trust mark. Waiting occupies no member slot, so
  knowing a code no longer lets a stranger take the room from the person you
  invited (pentest P-08). The approval is only as good as its binding: the
  client pins the identity it admitted and refuses a handshake from any other,
  because the relay chooses who is routed to whom.
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
| RSA     | RSA-OAEP-2048 key transport         | ratcheted AES-256-GCM (one-time keys) | **identity-authenticated**, **forward-secret** |
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
*authentication* is also one-classical-one-post-quantum. Like RSA, it erases
its handshake material (ECDH private key, KEM secret key, raw shared secrets)
the moment real traffic starts; **DHKE** drops its private key even earlier, as
soon as the chains are derived. So all three handshake modes have in-session
*and* cross-session forward secrecy: state captured at time T decrypts nothing
from before T, and never another session.

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
be walked to harvest who has an account. Login itself is a challenge signed by
**both** identity keys (Ed25519 + ML-DSA-65, pentest 2026-08-07 F-RELAY-006);
an unknown username runs the same two verifications against a decoy so the
timing does not tell it apart either. A dedicated, stricter rate limit
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

## External pentest (2026-07-18) — findings & fixes
An independent black-box audit of the live web instance raised nine items;
each has been addressed (see PROGRESS.md for the code):

- **C-01 (critical) — session key not atomically bound to the peer identity.**
  A malicious relay could deliver its own validly-signed handshake first (the
  cipher locks that key, "first key wins") then the real peer's, flipping the
  displayed identity/safety-number to the honest peer while the channel kept the
  attacker's key. **Fixed:** message handling is serialized and the peer
  identity is *pinned on the first accepted handshake*; any later frame from a
  different identity hard-closes the connection. Regression-tested with two
  validly-signed offers from different identities on the same nonces.
- **H-01 (high) — relay could swap the async encryption keys.** Fingerprint and
  safety number covered only the signing keys, so a relay could pair the real
  `ed`/`mldsa` with its own `ecdh`/`mlkem`. **Fixed:** the fingerprint and
  safety number now fold in `ecdh`+`mlkem`, and any change to those keys resets
  a contact's verified state — the in-person check now authenticates the keys
  used to seal async messages.
- **M-02 (medium) — trust pins in plaintext localStorage.** A forged pin could
  auto-unlock a session. **Fixed:** pins moved into the identity-encrypted,
  GCM-authenticated contact store. The one-time migration that read the old
  plaintext key was itself a hole (2026-07-27 **H-2**: it ran on every unlock and
  laundered any planted pin into the authenticated store, inverting the MITM
  alarm) and has been **removed** — the plaintext key is now only deleted, never
  read. The contact store also carries an authenticated generation counter, so
  deleting or rolling it back fails closed instead of quietly disabling
  key-change detection (**L-1**).
- **M-01 (medium) — OTP rollback.** A wholesale restore of an old encrypted pad
  blob reused consumed keystream. **Fixed:** a monotonic high-water tripwire
  refuses a pad whose consumption regressed.
  *Corrected 2026-07-27* — the original wording understated what remained. That
  tripwire was a single **plaintext** integer that read as 0 when absent, so one
  extra `removeItem` restored the full two-time pad (**H-3**, demonstrated: a
  message's plaintext was recovered from two ciphertexts); and it only tracked
  the SEND offset, so a restore taken after a stretch of receiving rewound the
  replay guard (**M-7**). Both are fixed: the watermark is now an AEAD record
  under the pad's own at-rest key, it covers send AND receive, it is mirrored
  inside the pad blob, and a pad that has run on this device but cannot produce
  its watermark refuses to open. The `exported` flag that guards against handing
  one pad to two importers moved inside the AEAD too (**L-3**).
  *Corrected again 2026-07-28* — "a pad that has run on this device but cannot
  produce its watermark refuses to open" held only for **v3** blobs. On a
  **v2-shaped** blob there is no watermark mirrored inside the AEAD, so the whole
  check rested on one deletable plaintext key: restoring a v2 snapshot and
  deleting three keys reopened the pad at offset 0, and the two-time pad was back
  (**F-1**, demonstrated end-to-end). Two things changed:
  * **Adopting a pad with no verifiable usage record is no longer silent.** It
    now takes an explicit confirmation naming the danger, so the attack has to
    get past the user instead of past nobody. In a plain browser that is the only
    control available — every byte of storage is attacker-writable, so no marker
    can be made undeletable, and user attention is the honest answer.
  * **In the Android app the floor moved out of localStorage**, into app-private
    storage behind an AndroidKeyStore HMAC (`android/…/PadFloor.kt`). It is
    monotone — there is no lowering call — unforgeable without the non-exportable
    key, and its absence beside a pad that exists is itself evidence. There the
    attack is refused outright, with no prompt to click through.
  * An unverifiable `exported` flag now resolves to **true**, not to whatever the
    plaintext index says, so it cannot be cleared through the one migrating
    unlock (**F-2**).

  *Residual, genuinely:* an attacker who snapshots **both** the pad blob and its
  watermark and restores both still rewinds undetected. In the browser that
  remains a deletion away, which is why **OTP's guarantee is materially stronger
  in the app** — and pads are exchanged in person, device to device, so the app is
  where they actually live. On Android the bar is now app-data file access
  (root): such an attacker can destroy a floor, which fails closed, but cannot
  rewind one. Closing the browser case would need OS-level trusted monotonic
  storage, which the web platform does not offer.
  * **Pentest 2026-08-07 (F-ATREST-001..005, -007):** the same floor now also
    covers the OTP **receive** high-water mark and the **`exported`** flag, and
    — under a per-identity id — the **contact store** (identity pins) and the
    **chat store** (envelope-replay ring, negotiated modes), which gained the
    contact store's domain tag / generation / witness mechanism. On Android,
    "store + witness both deleted" and "both restored" are refused; a deleted
    store is an explicit *Open anyway* in the Users view, never a silent fresh
    start. Pins are marked revoked by *Unverify* / *Remove* and no longer
    auto-unlock a session. **The same browser residual applies to all of it:**
    with no floor, a coordinated snapshot restore of blob + witness rewinds
    undetected, and "both deleted" is indistinguishable from a first run (the
    app warns when an existing identity finds no store, which is all a browser
    can do).
- **M-03 / L-01 / L-02.** Dedicated stricter rate bucket on `/api/auth/challenge`;
  `Strict-Transport-Security` sent over HTTPS; dev files (`package.json`,
  `*.test.mjs`) are 404'd and removed from the deployed client.
- **H-02 (architecture) — the relay serves the web client.** Unchanged by
  design and documented above ("Trust boundary of the web client"): the web
  client is the *honest-but-curious* model; the **bundled Android app** (audited
  client shipped in the APK, not server-delivered) is the answer for the
  *actively-malicious-relay* model. C-01/H-01 make that app's guarantees hold
  against a hostile relay.
- **L-03 (SSH) / PQ-assurance.** SSH is key-only on a disposable test box
  (accepted); `@noble/post-quantum` is the current self-audited release (no
  constant-time guarantee) — an assurance note, not a known vulnerability.

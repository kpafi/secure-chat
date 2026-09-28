# secure-chat

A deliberately tiny, security-first text chat. ASCII only. The server is a
**dumb relay**: all encryption happens in the client, and the server only
forwards opaque ciphertext between two parties in a room. The server never
holds keys, never decrypts, and never stores or logs message content.

> **Status (v0.5.0):** relay + web client deployed on clearnet and as a
> **Tor v3 onion service**; Android app and iOS app (sideloaded) ship the same
> client. Four encryption modes for the live room (DHKE, AES-256, PQKEM, OTP;
> RSA was removed in package 4 — see below), plus persistent one-to-one chats
> and an optional public-key directory. The DHKE / PQKEM handshakes are
> **authenticated** with long-term identity keys (Ed25519 + ML-DSA-65) and an
> in-person safety-number check.

## Contents of this repository
| path | what |
|---|---|
| `backend/` | the relay: FastAPI WebSocket relay, `/api` directory and mailbox |
| `client/` | the web client (all crypto lives here); shared by every platform |
| `android/` | Android app — the client bundled in the APK ([`android/README.md`](android/README.md)) |
| `ios/` | iOS app and the Home Screen web app ([`ios/README.md`](ios/README.md)) |
| `deploy/` | the live server config and per-release deploy notes ([`deploy/README.md`](deploy/README.md)) |
| `e2e/` | two-browser end-to-end runs ([`e2e/README.md`](e2e/README.md)) |
| `design/` | UI design briefs and reviews ([`design/README.md`](design/README.md)) |
| `secure-chat-*-20*.md` | the audit / pentest reports, one per round |
| `PROGRESS.md` | the working log (long; newest entries at the top) |

## Why this design
A breach of the server should leak nothing readable. By keeping the server
ignorant of keys and plaintext (end-to-end encryption), the worst a *passive*
attacker who reads everything the server stores or sees obtains is ciphertext
plus minimal routing metadata. The codebase is intentionally small so it can be
audited end to end.

### Trust boundary of the web client (important)
This guarantee covers **passive** compromise. An *active* attacker who controls
the server gets more: the same server also **serves the client JavaScript**, so
a compromised server can ship backdoored code on the next load and exfiltrate
plaintext or private keys. CSP and SRI do not help (the attacker controls the
page that declares them). This is the unavoidable trust assumption of *any*
web-delivered E2EE app: **you trust the server to serve honest code every time
you load it.**

The answer is the **apps**: Android and the sideloaded iOS app ship the audited
client inside the package and use the relay only as a dumb endpoint. Treat the
web client (and the iOS Home Screen web app, which loads the same code) as
"secure against a passive relay", not against a server serving malicious code.

The `.onion` address is self-authenticating (it *is* an Ed25519 public key), so
reaching it trusts no certificate authority and no DNS, and the relay never
learns a client IP. It does **not** close the gap above — the onion still
serves the JavaScript.

## Clients
- **Web:** open the relay's address in a browser.
- **Android:** build the APK from `android/` (see [`android/README.md`](android/README.md))
  and set the relay address once under *Relay settings*.
- **iPhone:** two ways with different guarantees — the iOS app (sideloaded with
  SideStore, client code fixed inside the app) or the Home Screen web app
  (Safari → Add to Home Screen; code from the relay on every start). The
  comparison is in [`ios/README.md`](ios/README.md), "Getting it onto an iPhone".

## Architecture
```
Client A --[ciphertext]--> Relay server --[ciphertext]--> Client B
              (FastAPI WebSocket, in-memory rooms, no storage)
```
- Transport: WebSocket (`/ws`).
- Rooms: 256-bit random hex ids, max 2 members, vanish when empty.
- **Entry is owner-approved.** The first party in owns the room; anyone else who
  has the code waits and must be let in by the owner, who is shown that peer's
  key fingerprint and trust mark. Waiting occupies no member slot, so knowing a
  code does not let a stranger take the room from the person you invited. The
  client pins the identity it admitted and refuses a handshake from any other.
- **The guest approves too** (DHKE / PQKEM). Whoever knows the code — the
  relay included — could hold the owner seat, so before the guest's key
  exchange runs it is shown the owner's key fingerprint and trust mark (and a
  warning if that is not the contact it looked up) and decides; Refuse
  disconnects with nothing exchanged, and the approved key is pinned for the
  session like the owner's. No prompt when the key belongs to a contact you
  already verified **in person** and whose pin holds exactly that key (the
  transcript says so). AES-256 / OTP have no identity to show; the shared
  secret is what authenticates them.
- Wire format: strict JSON envelope, printable ASCII only, validated by pydantic
  (see [Wire protocol](#wire-protocol)).
- The encryption mode is a **client** concern; the `alg` field is only an
  advisory tag the server relays.

## Run locally
Needs Python 3.12 and Node 20+.
```bash
# Relay
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q                       # relay test suite
./run.sh                        # relay + web client on http://127.0.0.1:8000

# Client (second terminal)
cd client
npm ci
npm test                        # client unit tests
# with the relay running:
node integration.test.mjs           # every mode end to end through the relay
node auth.integration.test.mjs      # authenticated handshake
node accounts.integration.test.mjs  # account directory
```
To try it by hand, open `http://127.0.0.1:8000` in two browser windows. The
first one gets a room code automatically: copy it into the second, pick the same
encryption mode in both, and press **Connect** — first in the window that made
the code (it becomes the owner), then in the other. The owner is asked to
**Let them in**.

The browser end-to-end runs are described in [`e2e/README.md`](e2e/README.md).
CI (`.github/workflows/backend.yml`) runs the relay suite and the client unit
tests on every push that touches them.

## Deployment
`deploy/` holds the live server config — the systemd unit, the Tor onion-service
`torrc`, and the Caddy site — copied from the running box, plus one release note
and deploy script per release. [`deploy/README.md`](deploy/README.md) is the recipe.

Two rules that are easy to get wrong and expensive to get wrong:
- **uvicorn binds `127.0.0.1` only.** Caddy (clearnet TLS) and Tor (onion) both
  reach it over loopback; it is never on a public interface.
- **`SECURE_CHAT_TRUSTED_PROXIES` stays unset** while the onion forwards to that
  port. Loopback is no longer proof of "came through Caddy", so trusting it lets
  an onion visitor forge `X-Forwarded-For` and get a fresh rate-limit bucket per
  request. Unset, every limiter shares one bucket and fails closed.

## Encryption modes (live room)
| Mode    | Key agreement                       | Message cipher      | Notes                                       |
|---------|-------------------------------------|---------------------|---------------------------------------------|
| DHKE    | ephemeral ECDH P-256                | ratcheted AES-256-GCM | **identity-authenticated**, **forward-secret** |
| PQKEM   | **hybrid ECDH P-256 + ML-KEM-768**  | ratcheted AES-256-GCM | post-quantum; **identity-authenticated**, **forward-secret** |
| AES256  | PBKDF2 from a shared passphrase + session nonces | ratcheted AES-256-GCM | no key exchange → not relay-MITM-able; forward secrecy limited (below) |
| OTP     | pre-shared pad, exchanged in person | **XOR one-time pad** + one-time HMAC-SHA-256 tag | information-theoretic *confidentiality*; no key exchange → not relay-MITM-able |

**The ratchet.** DHKE, PQKEM and AES256 frame their messages through the
same forward-secret ratchet: two direction-separated one-way HMAC-SHA-256
chains, a one-time AES-256-GCM key per message (`msgKey = HMAC(chain, 0x01)`,
`chain' = HMAC(chain, 0x02)`, consumed keys deleted), and strictly increasing
sequence numbers. Forged frames fail AEAD authentication, direction separation
rejects reflection, sequence numbers plus one-time keys reject replay. What
differs per mode is only where the chains' root comes from.

**DHKE / PQKEM.** The root comes from an ephemeral key exchange: ECDH
(DHKE), or *both* ECDH and ML-KEM-768 via HKDF (PQKEM — confidential unless an attacker breaks **both**,
which defeats "harvest now, decrypt later"). Handshake material (ephemeral
private keys, KEM secret, raw shared secrets) is erased once traffic starts, so
state captured at time T decrypts nothing from before T and never another
session.

The handshake is signed by a long-term identity (Ed25519 + ML-DSA-65) that each
user generates locally and the other verifies **in person** by comparing a
safety number. A relay that swaps the ephemeral key cannot forge the signature;
one that swaps the whole identity is caught because the safety numbers differ.
The signed transcript covers a fresh nonce from **each** peer's current
connection, so a captured handshake from an earlier session cannot be replayed
into a new one. Identity private keys are passphrase-encrypted on the device and
never sent to the server.

**AES256.** The root is the PBKDF2-derived passphrase secret plus a fresh
nonce from each peer, so frames from an earlier session never authenticate in a
new one. Honest limit: the passphrase is a long-term secret, so someone who
learns it and recorded the ciphertext can derive every session's keys. For real
forward secrecy use DHKE or PQKEM.

**RSA (removed).** Earlier versions offered RSA-OAEP-2048 key transport. It let
the side that offered its RSA key decide the whole session's secrecy, and a
deliberately weak key (a modulus with a small factor) passes every check a
client can afford (F-CRYPTO-009), so the mode was removed rather than patched.
A contact still on an old version who picks RSA gets one clear line — "the
other side uses RSA mode, which this version no longer supports" — and the
connection closes; both of you then pick DHKE or Post-quantum. The relay still
accepts the `RSA` tag (it never reads it), so that line can be shown at all.

**OTP.** A large random pad is generated on one device and carried to the other
**in person** (a passphrase-encrypted file moved over Bluetooth / USB / QR /
NFC). Each plaintext byte is XORed with a pad byte that is **never reused**:
the two peers draw from disjoint halves, a strictly increasing offset rejects
replays, and consumed bytes are zeroed. The pad is a finite budget (one byte per
plaintext byte, +32 per message) that the UI shows depleting. At rest it is
encrypted (PBKDF2-600k → AES-256-GCM) with its consumption offsets inside the
authenticated blob, a low-entropy import is rejected, and a pad can be open in
only one tab at a time. Honest caveats:
1. XOR has no integrity, so each message carries an HMAC-SHA-256 tag under a
   one-time key from the pad — that tag is *computational*, not
   information-theoretic.
2. The pad comes from the OS CSPRNG (optionally mixed with drawn entropy), not a
   hardware TRNG: treat it as "at least as strong as the CSPRNG".
3. Rollback: restoring an old copy of the pad would reuse keystream. The **apps**
   refuse that with a monotonic counter in app-private storage (Android:
   AndroidKeyStore HMAC; iOS: see `ios/README.md`). A browser has no such
   storage, so there a coordinated restore of the pad *and* its usage record
   still rewinds undetected — use pads in the app.
4. Crashes: `localStorage` is not durable (Chromium commits it in batches, up
   to a minute late), so every pad save also writes a sealed progress record to
   **IndexedDB with strict durability** and waits for it before a message is
   sent or shown or a pad file is handed out. After a crash the pad reopens at
   the highest offset any of its records reached (skipped bytes are harmless;
   reuse is not); the native floor is advanced only after that write. OTP
   therefore needs IndexedDB — without it (some private-browsing modes) OTP is
   refused.

## Accounts (optional directory)
The server doubles as a passwordless **public-key directory** under `/api`. You
can claim a username, prove control of it by signing a server challenge, and
look a contact up to pre-fill and pin their identity. The server stores **only
public keys**. The directory is a convenience, not a trust root (it shares the
relay's origin): the in-person safety-number check still governs trust, and a
key that disagrees with the published one is flagged loudly.

- **Registration and login need both identity keys.** Registration is signed by
  Ed25519 *and* ML-DSA-65 (both verified server-side), so nobody can bind a
  post-quantum key they do not control; login is a challenge signed by both.
- **The namespace is not enumerable.** Contacts are looked up by the handle
  `username#token` (a random per-account token). A missing user and a wrong
  token return the same `404`; login does not reveal whether a username exists,
  even by timing. Lookups have their own stricter rate limit. (Registering a
  taken name still returns `409`, but each probe costs a dual-signed proof.)

## Contacts, web of trust, and async chats
Everything these views store on the device — the contact list and the full chat
history — is encrypted at rest (PBKDF2-600k → AES-256-GCM under your identity
passphrase; the key lives only in memory while the identity is unlocked).
Both stores live in the browser's **IndexedDB**, written with strict
durability (since 0.4.0; the first start moves them there from
`localStorage` once). Going back to an older version after that is **not
supported**: an older client does not look in IndexedDB; it finds only the
generation record kept in `localStorage` and refuses loudly ("your saved
contacts … have been DELETED") rather than starting over. Reload every open tab
after updating: a tab still running the old version that saves afterwards is
either refused ("changed in another tab") or, if its copy is newer, adopted on
the next unlock. Without IndexedDB the stores stay in
`localStorage` and the apps' rollback floor is not advanced for them.

**Users** — your contacts with their public keys and a **trust mark**:
🟢 *verified by you* (compared in person, or confirmed at the live-room gate),
🟡 *vouched* (a contact **you** verified has published a signed vouch for them),
or ⚪ *unverified*. Vouches are dual-signed; the server checks them before
storing, but 🟡 is awarded **only** when the client re-checks the signature
against its **own pinned copy** of the voucher's keys, so a lying directory
cannot invent trust. Tapping a contact opens a short profile with the full
fingerprint and the Verify / Remove actions.

**Chats** — persistent one-to-one messaging without a live room. Messages travel
as a **sealed envelope**: hybrid ephemeral ECDH P-256 + ML-KEM-768 → HKDF →
AES-256-GCM to the recipient's published keys, with the sender's identity and a
dual signature sealed **inside** (the mailbox never learns who wrote a message).
The mailbox stores only *(recipient, ciphertext, arrival time)* and deletes on
fetch. Each chat is locked to a mode — `SEALED` (default) or `AES256` (an extra
passphrase layer); changing it needs the other side's signed acceptance.
Trade-off: sealed messages have no live ratchet, so a compromise of a
recipient's long-term encryption keys can expose past envelopes captured on the
wire — the `AES256` mode's out-of-band passphrase mitigates exactly this.

## Wire protocol
Client → server, one JSON envelope per frame (unknown fields rejected):

| field   | type   | notes |
|---------|--------|-------|
| type    | enum   | `join` \| `leave` \| `key` \| `msg` \| `knock` \| `admit` \| `deny` |
| room    | string | exactly 64 lowercase hex chars (256-bit id) |
| payload | string | base64; required for `key` / `msg` / `knock`, forbidden otherwise |
| alg     | enum?  | advisory: `AES256`, `DHKE`, `PQKEM`, `OTP` (server ignores); `RSA` still accepted from old clients |
| jid     | string?| only on `admit` / `deny`: the server-issued id of a waiting peer |

`knock` is a waiting peer's self-introduction (opaque, forwarded to the owner);
`admit` / `deny` are the owner's verdict.

Server → client: `{"type":"joined","role":"owner"|"guest"}`, `{"type":"pending"}`
(waiting for the owner), `{"type":"denied"}`, and to the owner `knock` (with
`jid`), `withdrawn` (a waiting peer left) and `turned-away` (count of joins
refused while the room was full); otherwise relayed envelopes or
`{"type":"error","reason":"..."}`.

## Metadata & residual risks
**No logs.** The relay writes no request or connection metadata to disk:
uvicorn's access log is off and connection logging is raised to WARNING, so a
seized host yields no who-connected-when trail. Only genuine errors are logged,
never payloads or room ids. `run.sh` carries the flags and
`tests/test_logging.py` fails if either is dropped — **do not re-enable access
logging in production.** Tor runs with `SafeLogging 1`, and Caddy's site log is
discarded.

**Room ids are a bearer capability.** Knowing a room id is enough to *ask* to
join; the owner decides who gets in. A leaked id therefore gives neither
plaintext (everything is ciphertext) nor impersonation (the handshake is signed
and safety-number-checked; for AES256/OTP the secret is never sent). What
remains is availability and coarse metadata. Treat a room id as a one-time
secret and make a new one per conversation.

**What the relay still sees.** Room id, message timing, and ciphertext sizes
(no length padding yet). This is the minimal routing metadata a relay cannot
avoid.

**The identity blob (F-ATREST-008, package 4).** The identity's saved copy
carries a generation inside its encryption. A copy without encryption keys is
never given new ones silently any more: the app asks, says what it costs, and
Cancel changes nothing. On Android the generation is held to a native floor
(the same Keystore-backed record as the pads' and stores'), so an older copy put
back is refused outright — including a keyless one, which a device that has used
the identity with keys never asks about. A browser's `localStorage` write is not
on disk yet when it returns (it can stay in memory for about a minute), so the
blob is also written to the durable IndexedDB store, and the floor is raised
only after THAT write has completed; if the everyday copy is lost in a crash,
the next unlock takes the durable one back — a crash cannot lock you out. In a plain browser
there is no floor: an older copy of the SAME keys is not detectable there, and
for a keyless one the question is the control.

**One tab for contacts and chats (package 4).** Like a one-time pad, your
contacts and chats are open in one tab or window of a browser at a time. A
second tab says so and offers **Use here**, which moves them: the first tab
locks them and says why.

## Known limits
Every pentest finding up to the Phase-7 round (2026-09-16) is either fixed or
listed here (package 6 closed the last Lows and Infos it could). Each entry
says what an attacker needs, what they get, and why it stays.

**Trust and deployment**
- **The web client trusts the server to serve honest code.** Whoever controls
  the relay host (or its TLS) can ship changed JavaScript on the next load and
  read everything that page decrypts. It stays because it is how every
  web-delivered E2EE app works; the Android and iOS apps bundle the client and
  are the answer (see "Trust boundary of the web client").
- **The onion shares a host with the clearnet site**, so it does not hide the
  server's location (`deploy/README.md`).
- **`@noble/post-quantum` has no constant-time guarantee** — an assurance
  note, not a known vulnerability.

**What the relay sees and can do**
- **Metadata.** The relay sees room ids, when each frame is sent and how big
  it is (no padding), which handles you look up and whom you mail. It cannot
  read or forge content. Routing needs this much; hiding it needs a mixnet.
- **It can drop messages — visibly, once a later message arrives.** A relay
  that drops frames in a live chat produces "N message(s) from your contact
  never arrived" (F-CRYPTO-001) — but only above the next genuine message
  that does arrive: the notice needs a later frame to measure the gap by, so
  dropping the LAST messages of a chat (or dropping and then closing the
  connection) leaves no notice. Frames injected before your check do not hide
  drops: only the peer's own frames, checked against the key, count as
  "yours". A gap of 64 or more frames (for example 64+ messages sent while
  the other side had not yet verified) ends that session: every later frame
  is undecryptable, a reconnect fixes it. The window stays 64: lowering it
  would make this happen sooner in honest use (F-CRYPTO-002, reasoning in
  `client/crypto.js`).
- **Rooms: the first joiner owns the room, and the waiting queue can be
  filled (P-08).** Anyone holding a room code can join first and become its
  owner, or fill its few waiting slots with knocks. They get availability only:
  the guest is shown the owner's key before anything is exchanged, and the
  owner sees each knocker's key before letting anyone in. It stays because a
  room code is a bearer capability by design; use a fresh code per chat.
- **A handle holder can suppress a victim's new mail while the victim is
  offline** (package 1, `backend/config.py`). With the victim's
  `username#token` handle and ~65 throwaway accounts, an attacker can keep the
  victim's inbox the heaviest and keep evicting the newest envelope — i.e. new
  honest mail — until the victim comes online. Sealed sender means the relay
  cannot tell padding from mail, so only the eviction order can be chosen;
  older mail survives, senders see their message accepted.
- **Registration replay can roll back published encryption keys
  (F-RELAY-005).** Anyone who captured an older signed registration of an
  account can replay it and put that account's older encryption keys back in
  the directory. It only matters if the account ever published two different
  key pairs; the identity keys cannot change this way, and the client
  re-registers its current bundle on every unlock. Closing it needs a signed
  counter in the registration, a wire change.
- **A port-bearing `X-Forwarded-For` is not caught by the misconfiguration
  detector (F-RELAY-002).** Only on a relay started with proxy headers ON
  without a trusted proxy — which the shipped service never does
  (`--no-proxy-headers`, pinned by `backend/tests/test_service_unit.py`). Then
  a client could mint a fresh rate-limit bucket per forged header.
- **Vouches.** A lookup now names the vouchers it asks about (your own
  in-person verified contacts), so a flood of throwaway vouches cannot bury
  theirs (F-PROTO-007) — but that tells the relay whom you have verified, by
  name, on each re-check. The global vouch table has no eviction: filling it
  (1000 accounts × 200 vouches) stops new vouches relay-wide until an
  operator clears it. A 🟡 counts for 7 days after the last successful check
  (F-PROTO-006), so a relay that answers every re-check with an ERROR can keep
  a retracted vouch on screen for at most that long. A hostile relay can do
  more: a vouch is a signature with no time or version in it, and a
  retraction only deletes the relay's row — so a relay that kept the old
  signature can keep serving it as a valid answer, and the 🟡 stays for as
  long as you still have the voucher verified. Closing that needs a time or
  epoch inside the signed vouch (a wire change); until then, un-verifying the
  voucher is what removes the mark reliably.

**Cryptography, by design**
- **An AES256 room's key-confirmation tag is an offline passphrase verifier
  (F-CRYPTO-004).** The relay (or anyone recording the traffic) can take the
  tag from a session and test passphrase guesses offline against it,
  PBKDF2-600k per guess. Key confirmation needs some value derived from the
  passphrase; the only defence is a strong shared passphrase — the app now
  warns about weak ones.
- **Weak passphrases are warned about, not refused.** Identity, pad, pad-file
  (transfer) and AES256 passphrases shorter than 12 characters, digits only,
  one repeated character, a simple sequence or a common password draw a
  warning. The owner has not decided a hard policy. Everything at rest is
  PBKDF2-SHA256 with 600,000 iterations; Argon2id would need a migration of
  every stored blob and is not planned yet.
- **The PQKEM combiner has no transcript binding (F-CRYPTO-008).** The
  hybrid key is derived from the two raw shared secrets, not from the
  exchanged public keys and ciphertexts. The handshake that carries them is
  signed by both identities, which gives the binding at the protocol layer;
  changing the combiner would break interoperability between old and new
  clients.
- **Sealed (async) mail has no forward secrecy for the recipient
  (F-CRYPTO-011).** Whoever later obtains your identity's encryption keys
  (your device and passphrase) can open every sealed envelope sent to you that
  they recorded. The keys are long-lived by design (they are your published
  address). A chat in AES256 mode adds a shared-passphrase layer inside the
  envelope, which that attacker also needs.
- **The safety number's concatenation is not injective across bundle
  versions (F-CRYPTO-013 / F-P7-21).** A signing-only bundle (1984 bytes) and
  a full one (3233 bytes) can be re-split into a different pair with the same
  bytes. Using that against the in-person check would need private keys for
  public keys equal to chosen byte strings — every key field has a fixed
  length, so that is a key-generation preimage for several schemes at once.
  Owner decision (2026-09-24): the format stays unchanged, documented only.

**This device**
- **Browser storage can be rolled back as a whole.** In a plain browser
  there is no storage the page cannot rewrite, so someone with access to the
  browser profile can restore an OTP pad together with its usage records (key
  reuse, OTP H-3), restore the contact and chat stores together with their
  generation records (older pins and trust marks), or delete a store together
  with every trace of it so the app starts empty (F-ATREST-003 in the
  browser). The apps keep a native floor that refuses all three; use pads and
  contacts in the app.
- **Locking on background is not done** (owner decision). An unlocked
  identity and open stores stay unlocked while the app is in the background;
  a lock would end every live chat, since session keys cannot be derived
  again from the passphrase.

## Security reviews
The project has had one external audit (2026-07-18) and several pentest rounds
(2026-07-25 … 2026-08-07); each report is in the repository root
(`secure-chat-security-audit-*.md`, `secure-chat-pentest-*.md`); the fixes and
what was left open are recorded in `PROGRESS.md`. Everything accepted by
design rather than fixed is listed under "Known limits" above.

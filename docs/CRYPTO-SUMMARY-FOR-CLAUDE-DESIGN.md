# secure-chat — Cryptography Summary (briefing for a design-focused AI)

> **Purpose of this document:** You are receiving this so you can build a
> *visual* summary (diagrams, infographic, interactive page — your call) that
> lets a reader grasp the security concepts of this chat system quickly.
> Every section below gives you (a) the accurate technical facts, (b) an ASCII
> sketch of the concept, and (c) a "**Visual idea**" hint for how to render it.
> The ASCII diagrams are *content references*, not layout mandates — redraw
> them properly. Accuracy matters: do not invent properties the system does
> not have (e.g. it is 1-to-1 only, no group chat; AES256 mode's forward
> secrecy is deliberately limited — see §6).

---

## 1. The one-sentence pitch

A two-person, end-to-end-encrypted ASCII text chat: **all cryptography runs in
the browser**, the server is a **"dumb relay"** that only ever sees ciphertext,
and a man-in-the-middle relay is defeated by **signed handshakes + an
in-person safety-number check**.

Stack: vanilla-JS web client (WebCrypto + @noble/post-quantum) · Python
FastAPI backend · optional Android WebView app that bundles the same client.

---

## 2. Big picture — who sees what

```
  Alice's browser                    RELAY (server)                   Bob's browser
 ┌────────────────┐             ┌─────────────────────┐             ┌────────────────┐
 │ plaintext      │             │  sees ONLY:         │             │ plaintext      │
 │ keys, identity │ ──cipher──▶ │  - room id (random) │ ──cipher──▶ │ keys, identity │
 │ ratchet state  │ ◀─cipher──  │  - base64 blobs     │ ◀─cipher──  │ ratchet state  │
 └────────────────┘             │  - timing/size      │             └────────────────┘
                                │  stores NOTHING,    │
                                │  logs NOTHING       │
                                └─────────────────────┘
```

Facts:
- The relay pairs at most **2 members per room** (room id = 64 hex chars =
  256-bit random, generated client-side) and forwards opaque base64 payloads.
  Rooms exist only in memory and vanish when empty. No message content, no
  request metadata at rest.
- The relay **is assumed hostile** in the threat model: it may drop, replay,
  reflect, reorder or inject frames, and could even try to MITM the handshake.
  Every defense below exists because of that assumption.
- Wire frames are tiny JSON envelopes: `join`, `key` (handshake material),
  `msg` (ciphertext), `error`. The server strictly validates shape/base64 and
  rate-limits everything (token buckets, connection caps, idle timeouts).

**Visual idea:** a three-column "who sees what" panel — glowing plaintext on
the endpoints, greyed-out ciphertext gibberish in the middle column, with a
"the server is the adversary" callout on the relay.

---

## 3. The layer stack (how everything composes)

This is the single most important structural picture. Four layers, each
solving exactly one problem:

```
 ┌──────────────────────────────────────────────────────────────────┐
 │ L4  HUMAN TRUST      safety number compared IN PERSON            │  who is it *really*?
 │     (app.js gate)    → gates sending AND receiving               │
 ├──────────────────────────────────────────────────────────────────┤
 │ L3  IDENTITY         long-term dual keypair Ed25519 + ML-DSA-65  │  who signed this?
 │     (identity.js)    signs the handshake; pinned after verify    │
 ├──────────────────────────────────────────────────────────────────┤
 │ L2  SESSION KEY      one of 4 modes creates a fresh root secret  │  how do we agree
 │     (crypto.js)      AES256 | DHKE | PQKEM | OTP                  │  on a secret?
 ├──────────────────────────────────────────────────────────────────┤
 │ L1  MESSAGE RATCHET  shared RatchetChannel: per-direction HMAC   │  per-message keys,
 │     (crypto.js)      chains → one-time AES-256-GCM keys          │  forward secrecy,
 │                                                                  │  replay rejection
 └──────────────────────────────────────────────────────────────────┘
```

Key insight to convey: **all four session-key modes feed the SAME ratchet
engine** (`RatchetChannel`). The modes only differ in *where the root secret
comes from*; everything after that (per-message keys, forward secrecy,
anti-replay) is identical shared code.

**Visual idea:** a layered pyramid/stack where the four mode boxes (L2) funnel
into one ratchet box (L1) — literally four pipes merging into one machine.

---

## 4. Connection lifecycle (sequence)

```
 Alice                        Relay                         Bob
   │  join(room) ─────────────▶ │ ◀───────────── join(room)  │
   │                            │                             │
   │  PHASE 1 — hello: fresh 32-byte random nonce, plaintext  │
   │  hello{n=Na} ─────────────▶│──────────────────────────▶  │
   │  ◀─────────────────────────│◀───────────── hello{n=Nb}   │
   │        (first-write-wins; own nonce reflected back ⇒ rejected)
   │                            │                             │
   │  PHASE 2 — signed handshake (DHKE / PQKEM):              │
   │  { ephemeral pub, identity bundle,                       │
   │    dual-sig over  DOMAIN‖room‖fold(Na,Nb)‖pub }  ───────▶│
   │  ◀───────  same, signed by Bob  ──────────────────────── │
   │        (bad signature ⇒ REFUSE + disconnect, loudly)     │
   │                            │                             │
   │  PHASE 3 — human gate: both screens show the same        │
   │  SAFETY NUMBER → users compare in person → unlock chat   │
   │                            │                             │
   │  PHASE 4 — messages: ratchet-encrypted one-time-key      │
   │  AES-GCM frames, sequence-numbered, both directions      │
```

Why each phase exists:
- **Hello nonces (freshness):** the signed transcript covers both fresh
  per-connection nonces, so a validly-signed handshake *recorded in an earlier
  session* can never verify in this one → cross-session handshake replay dead.
  The nonces travel in plaintext but are authenticated *retroactively* by the
  signature that covers them — tampering just makes the handshake fail loudly.
- **Dual signature (authenticity):** a relay that swaps in its own ephemeral
  key cannot forge Ed25519 **and** ML-DSA-65 over the transcript → MITM key
  substitution is detected, connection refused.
- **Safety number (the last gap):** a relay could still present an *entirely
  fake identity* and sign consistently. Then the two honest endpoints compute
  **different** safety numbers — the in-person comparison catches exactly
  this. Until the user clicks "verified", the app refuses to send **and drops
  incoming messages undecrypted** (receiving is gated too).
- **AES256 mode skips phase 2/3:** no key material crosses the wire; the
  shared passphrase *is* the out-of-band trust. The hello nonces still matter
  there (they key the session — see §6).

**Visual idea:** a classic sequence diagram with the relay drawn as a
suspicious middle actor; phases color-banded; a big red "✗ REFUSED" branch off
the signature check; a padlock that only opens at phase 3.

---

## 5. The ratchet — one-time keys from a one-way chain

The heart of message security. Two independent HMAC-SHA-256 chains per
session, **one per direction** (Alice→Bob and Bob→Alice), both derived from
the mode's root secret via HKDF (chain info binds each chain to its sender).

```
 chain_0 ──HMAC(·,0x02)──▶ chain_1 ──HMAC(·,0x02)──▶ chain_2 ──▶ …   (one-way!)
    │                         │                         │
    └HMAC(·,0x01)             └HMAC(·,0x01)             └HMAC(·,0x01)
    ▼                         ▼                         ▼
 msgKey_1  ──use once──▶🔥  msgKey_2  ──use once──▶🔥  msgKey_3 …
 (AES-256-GCM, erased)     (erased)                  (erased)
```

Properties (all enforced in `RatchetChannel`, crypto.js):
- **Forward secrecy in-session:** HMAC is one-way and consumed keys are
  zeroed, so ratchet state stolen at time T cannot decrypt anything sent
  before T.
- **Forgery fails:** the relay never learns the chain root → any forged frame
  fails AES-GCM authentication.
- **Reflection fails:** a frame bounced back at its sender was keyed with the
  *other direction's* chain → AEAD fails.
- **Replay fails:** each frame carries a sequence number `n` bound into the
  AEAD additional data (`modeDomain | roomId | n`); `n` must be strictly
  increasing, and the old key no longer exists anyway.
- **Skips are bounded:** if `n` jumps ahead (frames dropped in flight), the
  chain fast-forwards and *discards* the skipped keys — capped at 1024 steps
  so a hostile relay can't force unbounded work.
- **No interleaving bugs:** every encrypt/decrypt goes through a per-channel
  FIFO queue (`CallQueue`), and the receive chain only commits *after* the
  AEAD authenticates — a garbage frame can't burn keys or wedge the channel.
  (This closed two real pentest findings: a replay-counter rollback race and
  a double-consumed one-time key.)

**Visual idea:** a conveyor-belt / sprocket-chain graphic stepping left→right,
each step minting a key that burns after one use; a "no reverse gear" label;
two parallel belts labeled with the two directions.

---

## 6. The session-key modes (what differs, what's shared)

RSA key transport was a fifth mode until 2026-08-21; it was REMOVED (pentest
F-CRYPTO-009 — a counterparty-chosen modulus of the form small-factor x
large-prime hands the session to a passive observer, and no cheap validation
can detect it). `makeCipher` now refuses `"RSA"` by name and the UI does not
offer it. See the tombstone comment in `client/crypto.js`.

| | **AES256** | **DHKE** | **PQKEM** |
|---|---|---|---|
| Root secret from | shared passphrase: PBKDF2-SHA256, **600k iters**, salt = room id | ephemeral **ECDH P-256** exchange | hybrid: **ECDH P-256 + ML-KEM-768** secrets combined |
| Key material on the wire | **none** (only the plaintext hello nonces) | signed ephemeral pubkey | signed ECDH pub + KEM key/ciphertext |
| Identity + safety number | not used (passphrase = the out-of-band trust) | required | required |
| Cross-session forward secrecy | ✗ — passphrase is a long-term secret: whoever learns it + recorded traffic can re-derive **every** session (inherent to passphrase-only; stated honestly in the code) | ✓ (ephemeral keypair per session) | ✓ (all key material per-session) |
| In-session forward secrecy (ratchet) | ✓ | ✓ | ✓ |
| Secret-erasure moment | passphrase dropped at derive; HKDF base erased once chains exist | ECDH private key dropped the moment chains exist | **"seal"** on first real message: ECDH priv, KEM secret key, raw secrets all erased |
| Quantum resistance | n/a (symmetric) | ✗ | ✓ — attacker must break **both** ECDH *and* ML-KEM ("harvest-now-decrypt-later" resistant) |

Shared subtleties worth showing:
- **AES256 replay fix:** chains are keyed by passphrase **plus both fresh
  session nonces**, so a ciphertext captured in an earlier session of the same
  room+passphrase can never authenticate in this one.
- **Join-order race (PQKEM):** both peers may "offer" simultaneously.
  Solution: fold *all* established root secrets into HKDF, sorted by a hash
  tag — both sides feed HKDF identical input whether one or two secrets were
  exchanged, no role negotiation needed. Derivation is idempotent (replayed
  handshake frames can't rotate keys).
- **Reflection checks everywhere:** your own pubkey/nonce echoed back is
  always rejected — honest peers never share keypairs.

**Visual idea:** a 4-lane comparison — four differently-colored pipes (one per
mode) each producing a "root secret" token that drops into the same ratchet
machine; badges for ✓/✗ forward secrecy and a small quantum icon on PQKEM;
AES256's lane visibly marked with the honest limitation.

---

## 7. Identity, fingerprints, safety numbers, and the directory

```
                     Identity (long-term, per device)
        ┌───────────────────────────────────────────────┐
        │  Ed25519 (classical)  +  ML-DSA-65 (post-Q)   │  ← BOTH must verify;
        │  private keys: never leave device;            │    attacker must break
        │  at rest: passphrase → PBKDF2 600k → AES-GCM  │    two schemes at once
        └───────────────────────────────────────────────┘
              │ hash of both public keys
              ▼
   fingerprint (one identity)        safety number (a PAIR, order-independent
   "3F 9A C2 …" read aloud           — both people see the SAME number)
```

- **Dual signatures**: every handshake is signed with both keys and only
  verifies if **both** signatures pass — hedges against either scheme
  breaking (including future quantum attacks on Ed25519).
- **Pinning (TOFU + change alarm):** after the first in-person verification,
  the peer bundle is pinned (per contact or per room). Later sessions
  auto-accept a matching pin, and scream loudly if the key **changed**
  ("could be a device reset — could be an interceptor").
- **Account directory (optional, convenience only):** passwordless server
  directory — register proves control of *both* private keys by signature;
  login signs a fresh server challenge; lookups need the shareable handle
  `username#token`, so the namespace is not enumerable. Crucially the
  directory is **not a trust root** (it shares the relay's origin) — a
  directory-fetched key is treated as "expected", but the in-person safety
  number still governs, and a directory/live mismatch triggers a strong
  warning.
- The server stores **only public keys**; a full DB leak discloses nothing
  private.

**Visual idea:** two ID-card graphics (classical + PQ stamp) fused into one
badge; two phones showing the *same* safety number side by side with a
handshake between the humans; the directory drawn as a phone book with a
"helpful, but NOT the boss of trust" caption.

---

## 8. Threat model recap — attack vs. defense (great as a matrix)

| Relay tries to… | Stopped by |
|---|---|
| read messages | E2EE — only ciphertext ever reaches it |
| forge a message | AEAD with one-time keys derived from a root it never sees |
| replay a message (same session) | strictly-increasing sequence no. bound into AEAD AD + burned keys |
| replay across sessions | fresh per-connection nonces folded into handshake sig (all modes) and into the AES256 chains |
| reflect your own frames/keys/nonces back | direction-separated chains + explicit reflection rejects |
| swap the ephemeral key (MITM) | dual identity signature over the transcript |
| present a whole fake identity (full MITM) | in-person **safety number** mismatch; messaging (send *and* receive) locked until verified |
| move a signed key to another room | room id inside the signed transcript |
| desync/wedge the ratchet with garbage | decrypt commits only after AEAD passes; skip cap 1024 |
| decrypt the past after stealing device state | ratchet erasure + per-session keys ("seal"); *except* AES256-passphrase (documented limit) |
| harvest now, decrypt after quantum computers | PQKEM mode (ML-KEM-768 + ECDH hybrid), ML-DSA-65 signatures |
| enumerate users / squat identities | token-gated lookups, dual-sig registration proof, rate limits |

**Visual idea:** this table is the money shot — an attack/defense matrix with
red attacker icons on the left and green shields on the right works as the
closing summary graphic.

---

## 9. Facts checklist for the designer (do not contradict these)

- 1-to-1 chat only, printable-ASCII messages only. No group chat, no history
  (nothing is stored anywhere, by design).
- Primitives: WebCrypto (`crypto.subtle`) + audited @noble/post-quantum lib;
  **no hand-rolled primitives** — the project only composes them.
- Numbers that matter: PBKDF2 = 600,000 iterations (OWASP 2023); nonces =
  32 bytes; GCM IV = 96-bit random; ratchet skip cap = 1024;
  curves = P-256; PQ = ML-KEM-768 (FIPS 203) & ML-DSA-65 (Dilithium).
- Message frame versions: `aes-msg/v2`, `dhke-msg/v2`, `pqkem-msg/v2`; handshake transcript `secure-chat/handshake/v2`.
- OTP mode is deferred (would require in-person pad exchange).
- The Android app is a thin WebView shell bundling this exact web client
  (do not present it as a separate implementation).
- Status: crypto reviewed (no High/Medium open on the crypto itself), 56
  backend tests + client suites + real-browser E2E green. (An unrelated
  Android WebView injection bug is open — out of scope for this summary.)

## 10. Suggested visual set (if you want a menu)

1. Hero: "who sees what" endpoints-vs-relay panel (§2)
2. The 4-layer stack with four pipes → one ratchet (§3) ← best single explainer
3. Handshake sequence diagram with the refusal branch (§4)
4. Ratchet conveyor belt with burning one-time keys (§5)
5. 4-mode comparison lanes (§6)
6. Safety-number "two phones, same number" moment (§7)
7. Attack/defense matrix as the closing card (§8)

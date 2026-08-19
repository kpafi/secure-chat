# Security history — external pentest (2026-07-18), findings & fixes

Moved here from the README on 2026-08-19 so the README describes the system as
it is; this file keeps the fix-by-fix narrative. The reports themselves live in
`docs/pentests/`, and the per-commit detail is in `PROGRESS.md`.

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

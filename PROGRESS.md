# secure-chat — progress log

Working file so any session can pick up where the last left off. Newest notes
at the top of each section. Dates are absolute (YYYY-MM-DD).

## ⮕ RESUME HERE (snapshot as of 2026-07-25, in-depth pentest: 2 of 8 fixed)
**Full-stack pentest run against `4b9f270`; report in
`secure-chat-pentest-2026-07-25.md`. The crypto core held — nothing broke in
the handshake, ratchet, OTP, sealed envelope or web-of-trust. Every finding is
in the layer ABOVE the crypto: the async mailbox treats AUTHENTICATED data (the
sender really signed it) as TRUSTED (they are who they claim, and their values
are well-formed).** Deps clean (`npm audit` 0, `pip-audit` 0); starlette 1.3.1 /
fastapi 0.139.2 / cryptography 49.0.0 close the 2026-07-18 M-01/M-02/L-03.

**FIXED + committed this session (both re-verified against their own PoCs):**
- **F-02 (Medium) — chat mode string was unvalidated.** A peer could propose an
  arbitrary `mode`; on accept the header rendered `🔒 AES256 + verified by
  secure-chat` while `hasSecret:false` and NO inner layer was applied (every
  check is an exact `=== "AES256"`). Fix: `chats.MODES`/`isValidMode`
  allow-list, enforced in `setMode`/`setPending`/`ensure` AND dropped at the
  boundary in `app.js handleControl`; `chats.unlock()` sanitises an
  already-poisoned store (bogus mode → SEALED, phantom secret/salt dropped) so
  a victim heals on next unlock. New `client/chats.test.mjs`.
- **F-04 (Low) — `?t=ü` → HTTP 500 + traceback** on `/api/users/{u}`,
  `/api/users/{u}/vouches` and `/api/mailbox/{u}`: `hmac.compare_digest` raises
  TypeError on non-ASCII `str`. Not an existence oracle (both branches raised
  identically), but it broke fail-closed on the token gate and let anyone write
  tracebacks to the journal on demand (vs. I2). Fix: `accounts.token_matches()`
  compares UTF-8 **bytes** — constant-time preserved, decoy preserved. New
  `backend/tests/test_token_gate.py` (22 parametrised cases).

**STILL OPEN (highest first):**
- **F-01 (Medium) — contact injection.** `app.js:1142` derives a new contact's
  USERNAME from the attacker-chosen sealed `name`. PoC put contacts called
  `bank-support` and `alice` (attacker's keys) into the victim's Users+Chats
  lists, needing only the victim's public handle and no registered account. ⚪
  is shown correctly and is the real mitigation. Fix: use the neutral
  key-derived `fallback` name and show the claimed handle as an explicitly
  untrusted "claims to be …" field.
- **F-03 (Medium, deployment-gated) — rate-limit bypass off the proxy.**
  Rotating `X-Forwarded-For` gives a fresh bucket per request (16/16 allowed vs
  10-then-429). **Production is safe** (Caddy appends the real IP; uvicorn 0.51
  resolves rightmost-untrusted). The exposure is the planned `.onion` deploy,
  which forwards onion→127.0.0.1:8000 with no Caddy. Fix BEFORE that ships:
  `--forwarded-allow-ips=` when not behind a trusted proxy.
- **F-05/F-06 (Low)** — uncapped auto-created contacts (~5.9 KB each, ~880 to
  5 MB) and delete-on-read mail vs. unguarded batch processing. NOTE: I tried
  and **failed** to demonstrate the terminal failure for both — treat as
  resilience hardening, not confirmed defects.
- **F-07/F-08 (Info)** — `_bundleBytes` lacks per-field length checks (safe
  today because sizes are fixed); the phone runs the DEBUG APK so WebView
  debugging is live, and the Android passphrase masking is a `contains
  ("passphrase")` string match.

**Verified after the fixes:** backend **99 passed** (was 77; +22 new), client
`npm test` all green incl. the new chats suite, F-02 PoC no longer produces a
proposal, F-04 endpoints return 404 with no traceback, and the LEGITIMATE
AES256 negotiation (propose → accept → inner-layer round trip between two
honest peers) still works. Live-room + async-chat browser harnesses green.

## ⮕ RESUME HERE (snapshot as of 2026-07-25, redesign stage 2: hierarchy pass)
**User asked to continue the redesign; chose "go deeper on the visual design"
over shipping first. Stage 2 is BUILT and VERIFIED locally — deploy + APK
rebuild still PENDING (same rsync as every snapshot below; one rsync covers
all of them).** Presentation-only again: no crypto, no protocol, no new deps,
importmap untouched (`test_csp_hash.py` green).

Where stage 1 (2026-07-19) refreshed *tokens* — colors, radii, shadows — this
pass fixes *hierarchy*, which is what still read as cheap:

- **Dual type stack (the big one).** `--font-ui` (system-ui — NOT a web font,
  so `font-src` stays untouched and the CSP is unchanged) now carries labels,
  prose, buttons and nav; `--font-mono` is reserved for material read or
  compared character-by-character: fingerprints, safety numbers, room ids,
  handles, usernames, cipher specs (`.alg-desc`, `.badge.pq`), `.kv dd`.
  **User explicitly approved this** even though the stage-1 spec said "keep
  monospace" — it's the single biggest reason the UI looked like a terminal
  dump. Opt-in via a `.mono` selector list at the top of `style.css`.
- **Button tiers.** The DEFAULT `button` is now the quiet secondary; a screen
  earns at most ONE `.primary` (gradient blue) — Continue / Connect / Send /
  Add / Open / "It matches — unlock messaging" / Generate pad / Accept. Before,
  every "Copy handle" shouted as loud as "Connect". `.ghost` is now truly
  fill-less; `.danger` is a tinted red OUTLINE instead of a solid red block
  (every danger button is already confirm-gated in app.js). This DELETED the
  per-id overrides (`button#gen`, `#idCreate`, `#idUnlock`, `#otpImport/Export`)
  that existed only to undo the old loud default.
- **Profile view restructured** — `.idhead` (initial avatar + name + handle)
  replaces the flat "Name" row; Keys is a `<dl class="kv">` label/value grid;
  Status is a row of `.chip`s (on/off) instead of a `·`-joined sentence.
- **Drawer** gained a `.drawer-head` (wordmark) and a pinned `.drawer-foot`
  ("Keys never leave this device. The relay sees ciphertext only.").
- **Empty states**: new `emptyRow()` renders a dashed "No users yet" /
  "No chats yet" block in the list well (Users no longer just sets a hint).
- **Trust legend** is a 3-item `.legend` row, not a run-on paragraph.
- **Latent bug fixed:** added a global `[hidden] { display: none !important }`.
  `display:flex/grid` beats the `hidden` attribute's UA `display:none`, so any
  flex container toggled via `.hidden` stayed visible — the drawer had a
  one-off patch for this; the Profile copy-handle actions hit it the moment
  they became `.inline`. Now enforced once, globally.
- `renderHandleInto` switched from `className =` to `classList.toggle("ok")`
  so both call sites keep their own base classes.

**Verified** (harnesses in `scratchpad/verify/`, system Chromium via
puppeteer-core — `shots.mjs`, `flow.mjs`, `live.mjs`):
- Backend **77 passed** (unchanged), client offline `npm test` all green.
- `flow.mjs`: two real peers register + log in against the local relay, add
  each other by handle, verify (🟢), open an async SEALED chat — **bob received
  alice's message**; screenshots of the populated user rows / chat list /
  conversation, desktop + 390×844.
- `live.mjs`: two contexts join one room on AES-256, **both directions
  delivered**, disconnect clean. NOTE: the safety-number gate does NOT appear
  for two fresh unpinned identities (it needs a pinned contact) — that's
  by design; the harness treats it as optional.
- **Zero horizontal overflow** in every view at both widths; no pageerrors.
  Only console error is the known `/favicon.ico` 404.

**DEPLOYED + SHIPPED 2026-07-25.** Pushed to GitHub (`3e20702`), deployed to
Hetzner, and installed on the user's physical phone (Nothing A063 over USB;
`org.securechat.app`, launches clean, screenshot confirms the new type stack
and button tiers on-device). This ALSO finally made the long-pending
**vouch-v2 + mailbox-race backend fix (`a548f56`, pending since 2026-07-19)
live** — verified `vouch/v2` present in the deployed `accounts.py` and
`account.js`. The box had been serving Jul-18 code until now.

### ⚠️ THE OLD DEPLOY RECIPE WAS DESTRUCTIVE — DO NOT USE IT
Every earlier snapshot in this file records this rsync:
`rsync -az --exclude node_modules --exclude 'package*.json' --exclude
'*.test.mjs' --exclude __pycache__ backend client root@…:/opt/secure-chat/`
A `--dry-run` on 2026-07-25 showed it transfers **`backend/accounts.db`**
(plus `.venv/` and `.pytest_cache/`) — i.e. it **overwrites the live account
database with the local dev one**. Local was 327 KB (full of throwaway test
accounts); live was 176 KB. Always `--dry-run --itemize-changes` first.
**Use this instead:**
```
cd ~/secure-chat && rsync -az --itemize-changes \
  --exclude node_modules --exclude 'package*.json' --exclude '*.test.mjs' \
  --exclude __pycache__ --exclude '.venv' --exclude '.pytest_cache' \
  --exclude 'accounts.db*' --exclude '*.db' --exclude '*.db-shm' --exclude '*.db-wal' \
  --exclude 'tests' \
  backend client root@138.199.144.35:/opt/secure-chat/ \
&& ssh root@138.199.144.35 'chown -R securechat:securechat /opt/secure-chat/backend \
   && systemctl restart secure-chat'
```
A pre-deploy backup now exists at `/root/accounts.db.bak-2026-07-25-1333` on
the box. NOTE: `curl` to `https://138.199.144.35` fails from some networks
(direct-IP TLS); SSH works fine — verify over loopback on the box instead
(`ssh … 'curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/'`).

**APK rebuild (worked as documented):**
`cd ~/secure-chat/android && ANDROID_HOME=$HOME/android-sdk ./gradlew
assembleDebug -Dorg.gradle.java.home=$HOME/jdk-21.0.4+7 && adb install -r
app/build/outputs/apk/debug/app-debug.apk`

**Open UI nit found on-device (not yet fixed):** on the Step-1 screen with a
LOCKED stored identity, `#toRoom` ("Skip — no identity (AES-256 / OTP only)")
is the `.primary` while **Unlock** is a quiet secondary — backwards, since
Unlock is what the user wants there. The primary should move to `#idUnlock`
when a locked identity exists. Separately, the Android shell shows a native
ActionBar titled "secure-chat" ABOVE the web header's own wordmark — a
duplicated title bar; consider hiding the native one (pre-existing, not from
the redesign).

## ⮕ RESUME HERE (snapshot as of 2026-07-23, Android polish: icon + release signing)
**Deploy is STILL PENDING** (blocked again this session by the Claude Code
auto-mode permission classifier on SSH/rsync to the Hetzner box — same class of
block noted in earlier sessions, not a new problem). The 2026-07-19 vouch-v2 +
mailbox-race fix (commit `a548f56`, see snapshot below) is confirmed **still
not live** — diffed the deployed `app.js` against local and it's missing the
`ecdh`/`mlkem` binding in the vouch call sites. Run by hand:
`cd ~/secure-chat && rsync -az --exclude node_modules --exclude 'package*.json'
--exclude '*.test.mjs' --exclude __pycache__ backend client
root@138.199.144.35:/opt/secure-chat/ && ssh root@138.199.144.35 'chown -R
securechat:securechat /opt/secure-chat/backend && systemctl restart
secure-chat'`. Then rebuild/reinstall the APK (client changed).

**Android polish, two of three items done this session:**
- **App icon — DONE.** Adaptive icon (API 26+; no legacy PNG mipmaps needed
  since `minSdk = 26` is the same level adaptive icons were introduced at): a
  monochrome padlock reusing the same path language as the drawer's "Live
  room" nav SVG icon, `--bg` dark background (`#0D1117`) with `--accent` blue
  foreground (`#2F81F7`), plus a `<monochrome>` variant for Android 13+ themed
  icons. New files: `android/app/src/main/res/mipmap-anydpi-v26/ic_launcher.xml`
  (+ `_round`), `res/drawable/ic_launcher_{foreground,monochrome}.xml`,
  `res/values/colors.xml`. Manifest wired (`android:icon`/`android:roundIcon`).
- **Release signing config — DONE.** `signingConfigs { release { ... } }` in
  `app/build.gradle.kts` reads `android/keystore.properties` (gitignored) if
  present; falls back to an **unsigned** release build if absent (documented
  in new `android/keystore.properties.example`, committed). Generated a real
  local release keystore this session — `android/release.keystore` (PKCS12,
  RSA-4096, 10000-day validity, alias `secure-chat-release`, pseudonymous DN,
  no real name/org in the cert). **Gotcha:** PKCS12 keystores ignore a
  distinct `-keypass` — store and key password must be identical or the build
  breaks; documented in the `.example` file. Verified: `assembleDebug` +
  `assembleRelease` both build clean, and `apksigner verify --print-certs`
  confirms the release APK is actually signed (cert DN + SHA-256 fingerprint
  printed). **Both `release.keystore` and `keystore.properties` are gitignored
  + chmod 600, never committed. Back them up somewhere durable (password
  manager / offline storage) before ever shipping a signed build — losing
  them breaks the ability to publish updates under the same signature.**
- Side-effect fix: `assembleRelease` runs `lintVitalAnalyzeRelease`, which
  pulled lint/kotlin-compiler/groovy jars not covered by the existing
  `gradle/verification-metadata.xml` checksum allowlist (first time anyone
  ran a release build here — only `assembleDebug` had ever been exercised).
  Fixed the TOFU way this project already uses for dependency verification:
  ran once with `--write-verification-metadata sha256`, then confirmed a
  clean rebuild (`rm -rf app/build && assembleRelease`) passes verification
  normally — not a permanent bypass.
- **On-device verification-gate pass (DHKE/RSA/PQKEM) — STARTED, NOT
  FINISHED, session interrupted.** State left behind: emulator `sc_test` was
  running headless with the new-icon debug APK installed and launched
  (confirmed it resolves/launches); next step is attaching CDP per the
  on-device verify recipe and driving each of the three untested modes
  end-to-end (only AES256 has ever been verified on-device). Check
  `adb devices` first — may need reboot via the recipe further down this file
  / `memory/secure-chat-project.md`.

## ⮕ RESUME HERE (snapshot as of 2026-07-19, pentest: vouch enc-key gap fixed)
**A fresh in-depth pentest found ONE real issue (MEDIUM) plus one LOW; BOTH are
now fixed, tested, and committed — deploy PENDING (permission-blocked, commands
below).** The rest of the stack (relay, C-01 handshake binding, ratchet, OTP,
identity/contacts/chats at-rest, anti-enumeration, CSP/headers) was attacked and
held up.

- **MEDIUM — web-of-trust vouch (🟡) did not authenticate encryption keys
  (the H-01 gap, still open in the WoT path).** `vouchMessageBytes` /
  `_vouch_message` signed only the target's SIGNING keys (ed+mldsa), so a
  malicious directory could serve a genuinely-vouched contact's REAL signing
  keys + its OWN ecdh/mlkem and read every sealed message the victim sent, while
  the 🟡 "vouched by X" mark still displayed. Proven with a live module-level
  PoC (`scratchpad/verify-sc/pentest-vouch-enckey.mjs`): attacker decrypted the
  plaintext; real recipient could not. **Fix (v2 vouch, mirrors the H-01
  fingerprint fix):** the vouch now signs all four keys under a new
  `secure-chat/vouch/v2` domain when the target has encryption keys (legacy
  no-enc targets stay v1). Server (`accounts._vouch_message` + the `/api/vouch`
  handler now selects+binds ecdh/mlkem), client (`account.vouchMessageBytes`
  v2), publish path (`app.js` vouches over the full in-person bundle) and the
  🟡 award check (`refreshVouchMarks` verifies over the full bundle it holds —
  so swapped enc keys fail the signature and no 🟡 is given). Old v1 vouches
  stop lighting 🟡 for enc-key contacts until re-published (correct, safe
  migration). **Verified:** new `client/vouch.test.mjs` (in `npm test`) +
  `backend/tests/test_vouches.py::test_vouch_v2_binds_encryption_keys`; the
  fixed-code PoC (`scratchpad/verify-sc/pentest-vouch-fixed.mjs`) shows the
  poisoned bundle now earns NO 🟡 while the honest bundle still does.
- **LOW — mailbox fetch was a SELECT-then-DELETE race.** `fetch_mail` deleted
  the whole inbox (`WHERE recipient = ?`) after selecting, so an envelope that
  arrived between the two statements (two overlapping fetches, or a POST racing
  the GET; sync endpoints run in a threadpool) was silently lost. **Fix:** delete
  only the specific ids that were read (`mailbox.py`).

**Verified:** backend **77 passed** (was 76; +1 vouch-v2 test), client offline
suites all green (+ `vouch.test.mjs`), CSP-hash test still green (importmap
untouched), and a two-context Chromium smoke run (all views + live AES-256
round-trip + disconnect) green — no regression from the app.js edits.
**PENDING (permission-blocked — run by hand):** deploy backend+client and
restart (backend changed, so the full recipe incl. the `chown securechat` step):
`rsync -az --exclude node_modules --exclude 'package*.json' --exclude
'*.test.mjs' --exclude __pycache__ backend client
root@138.199.144.35:/opt/secure-chat/ && ssh root@138.199.144.35
'chown -R securechat:securechat /opt/secure-chat/backend && systemctl restart
secure-chat'`. Then rebuild+install the APK (client changed). NOTE: this is on
top of the still-pending cosmetic-pass deploy below — one rsync covers both.

## ⮕ RESUME HERE (snapshot as of 2026-07-19, cosmetic polish pass)
**The user-requested cosmetic polish pass ("make it look less cheap") is BUILT
and VERIFIED locally — deploy + APK rebuild still PENDING (this session's
permission system blocked the rsync and the gradle build; run them by hand,
commands below).** Presentation-only, zero logic/crypto changes, importmap
untouched (`test_csp_hash.py` green — no CSP-hash churn):

- **Drawer emojis removed** (`client/index.html`): the four `👤🔒👥💬` labels
  are now **monochrome inline SVG icons** (16×16 `stroke="currentColor"`,
  CSP-safe) + plain-text labels in `<span>`s. The `☰` menu button and the
  functional 🟢🟡⚪ trust glyphs are KEPT (documented security UX).
- **Design-token refresh** (`client/style.css`, full-file pass, same var
  names + hue language): new tokens `--panel-2` (raised/hover surface),
  `--inset` (input/log wells), `--accent-soft`, `--ring`, `--warn`,
  `--border-soft`, radii `--r-s/m/l`, spacing `--sp-1..5`, shadows
  `--shadow-1/2`. Refined: soft elevation on `.panel`/drawer, gradient
  primary buttons with hover/active/focus-visible states, input focus rings
  (`box-shadow` ring instead of outline), flex nav items with accent-tinted
  active state, uppercase `.step`, pill badges with tinted backgrounds
  (`color-mix`), gradient chat bubbles, polished `.safety`/`.myhandle`/
  `.profile-qr`, surface-layered `#log`/`.alg-cards`/`.userlist`. Mobile
  `@media (max-width:600px)` behavior preserved verbatim.
- **Verified:** new harness `scratchpad/verify-sc/cosmetic-pass.mjs`
  (system Chromium via puppeteer-core): all 4 views render on desktop AND
  390×844 phone, drawer labels pure-ASCII (no emoji) with SVG icons, trust
  glyphs still present, **zero horizontal overflow** in every view/viewport,
  and a full two-context AES-256 flow (generate room → connect ×2 → unlock →
  message both ways → disconnect) green. Client offline `npm test` green;
  backend `test_csp_hash.py` 2/2 green. Screenshots eyeballed (drawer, room
  cards, live chat, phone views).
- **PENDING (blocked remote/exec permissions — run by hand):**
  1. Deploy (client only, no restart/chown needed):
     `cd ~/secure-chat && rsync -az --exclude node_modules --exclude
     'package*.json' --exclude '*.test.mjs' --exclude __pycache__ client
     root@138.199.144.35:/opt/secure-chat/`
  2. APK: `cd ~/secure-chat/android && ANDROID_HOME=$HOME/android-sdk
     ./gradlew assembleDebug -Dorg.gradle.java.home=$HOME/jdk-21.0.4+7`,
     then `adb install -r app/build/outputs/apk/debug/app-debug.apk`.

## ⮕ RESUME HERE (snapshot as of 2026-07-18, Profile tab shipped)
**The 👤 Profile tab (drawer TODO below) is BUILT, VERIFIED, DEPLOYED, and in
the APK.** New drawer entry (first, before Live room) → a presentation-only
view that reads existing unlocked-identity state: **Name** (registered
username or "not registered yet"), **Handle** with **Copy handle** / **Copy
invite link** (the Users-view helpers were factored into a shared
`renderHandleInto()` + the copy wiring reused), an **invite QR** (new vendored
`lean-qr`, `client/vendor/lean-qr/index.mjs`, added to the importmap — no CDN,
CSP-safe), the four-key **fingerprint** (`identity.fingerprint()`), **key
details** (Ed25519 + ML-DSA-65 / ECDH P-256 + ML-KEM-768), a **status line**
(unlocked · registered? · logged in? · N saved users), and the **Copy backup /
Forget identity** actions surfaced here too. Locked state shows the same
"unlock in Live room first" hint as Users/Chats. All `textContent`, no new
network calls or trust surface.

**Importmap changed → CSP hash regenerated** to
`sha256-6Sm2nhNvoa7gr7uuY2hbAbpdWhIlL15/wXLm4dhO9UQ=` in BOTH `backend/main.py`
and `android/.../MainActivity.kt` (guarded by `test_csp_hash.py`, which passes).

**Verified:** new `scratchpad/verify-sc/profile-flow.mjs` (two-context
Chromium) — locked-before-unlock, pre/post-registration fields, key details,
status line, copy buttons present, and the rendered **invite QR decodes back to
the exact invite link** (jsQR). Green LOCAL and LIVE. Offline suites +
backend 76/76 + H-01 flow still green (no nav regression from adding the tab).
**DEPLOYED to Hetzner** (rsync + the `chown securechat` step + restart;
confirmed live: Profile nav, vendored lean-qr 200, served CSP hash matches,
profile flow green against production). **APK rebuilt** (5.8 MB, bundles the
Profile view + lean-qr; unit tests green) — `adb install -r
android/app/build/outputs/apk/debug/app-debug.apk` when the phone is back.

## ⮕ RESUME HERE (snapshot as of 2026-07-18, Codex-Terra audit fixes)
**A second external audit ("Codex Terra", pushed to GitHub as
`secure-chat-security-audit-2026-07-18.md`, auditing commit 70bbfcc) found
1 High + 3 Medium + 3 Low. ALL 7 ARE FIXED, TESTED, AND DEPLOYED TO THE
HETZNER BOX** (deploy commands were run by hand because the session's
permission system blocked remote writes; ownership gotcha below).

- **H-01 (async keys not fully bound into verification):** contact-list
  fingerprint now covers all four keys (`app.js` renderUserList);
  `sameBundle` compares all four normalized (`?? null`); pins store all four
  keys (`contacts.savePin`); `contacts.upsert` treats missing→present as a
  real key change; store blob v2→v3 migration downgrades 🟢 contacts that
  have enc keys (verified against the old signing-only fingerprint) to ⚪
  with a `reverify` UI hint; handshake distinguishes "pin predates
  encryption-key coverage" (specific re-verify prompt) from a real key
  change. Regression tests in `contacts.test.mjs` (5 new) +
  `identity.test.mjs` (per-key fingerprint/SN change) — all green. Full
  two-context Chromium flow green (handshake → verify → pin → reconnect
  silently accepted → messaging), harness
  `scratchpad/verify-sc/h01-flow.mjs`.
- **M-01 (Starlette host-header bypass of the dev-file gate):** middleware
  now gates on `request.scope["path"]`; Starlette upgraded (see M-02); new
  `backend/tests/test_static_hardening.py` (malicious-Host 404s, version
  floor, cheap pathological Range) — verified live on a running local server
  with curl.
- **M-02 (Starlette Range CPU DoS, CVE-2025-62727):** FastAPI 0.139.2 +
  Starlette 1.3.1 (also covers M-01's GHSA-86qp-5c8j-p5mr), cryptography
  49.0.0, uvicorn 0.51.0 etc. — exact pins in `requirements.txt`, hashed
  lockfile `requirements.lock` (pip-compile --generate-hashes). Backend
  suite 76/76 green on the new stack, installed `--require-hashes`.
- **M-03 (WS 16 MiB buffered before the 64 KiB app check):** uvicorn now
  runs with `--ws-max-size 66560` (run.sh; MUST also be added to the
  systemd unit ExecStart on deploy). Live-tested: 1 MiB frame → hard close
  1009, no buffering.
- **L-01 (unbounded PBKDF2 iters):** all four `deriveKey`s
  (identity/contacts/chats/otp) enforce integer iters ∈ [100k, 5M] and salt
  8–64 bytes BEFORE WebCrypto; identity backup capped 256 KiB, pad file
  capped 4 MiB before JSON.parse. Tests in identity/contacts suites.
- **L-02 (Android prompt shows passphrases):** `onJsPrompt` masks input
  (TYPE_TEXT_VARIATION_PASSWORD) when the app-local message asks for a
  passphrase. APK rebuilt (5.8 MB, bundles the new client) — `adb install
  -r android/app/build/outputs/apk/debug/app-debug.apk` when the phone is
  back.
- **L-03 (dependency hardening):** Python exact pins + hashed lock (above);
  gradle wrapper pinned via `distributionSha256Sum`; Gradle dependency
  verification enabled (`android/gradle/verification-metadata.xml`, 631
  sha256 entries — builds fail on any unpinned/tampered artifact).

**DEPLOYED + LIVE-VERIFIED (2026-07-18):** rsync of backend+client (now also
excluding `.venv`/`package*.json`/`*.test.mjs`), venv upgraded with
`pip install --require-hashes -r requirements.lock` (starlette 1.3.1 /
fastapi 0.139.2 / cryptography 49.0.0 confirmed on the box), ExecStart now
carries `--ws-max-size 66560`. **Deploy gotcha for next time:** the rsync
runs as root and re-owns `/opt/secure-chat/backend`, which crash-loops the
service (`sqlite3 … readonly database`, 502s) — always finish with
`chown -R securechat:securechat /opt/secure-chat/backend` before the
restart. Live checks all green: app.js on the site carries the H-01 fix;
`package.json`/`*.test.mjs` 404 (a hostile Host header hits Caddy's
catch-all — empty 200, never reaches the backend); HSTS present; 1 MiB WS
frame → hard close 1009; all 3 live integration suites green; full
two-context Chromium H-01 flow (handshake → verify → pin → reconnect
silently accepted) green AGAINST PRODUCTION. The audit-fix backport to
`~/secure-chat-live` is also DONE and pushed (cdc3ba8). Still pending:
`adb install -r` of the rebuilt APK when the phone is reconnected.

## ⮕ RESUME HERE (snapshot as of 2026-07-18, later)
**Repos split + published to GitHub.** The project now has TWO git repos:
this full one (`~/secure-chat` → `github.com/kpafi/secure-chat`) and a
**live-chat-only** split (`~/secure-chat-live` →
`github.com/kpafi/secure-chat-live`) that keeps only the live-room flow (4 modes,
no OTP, no async/contacts layer) plus an encrypted `pins.js` and a consolidated
`PENTEST-FINDINGS.md`. Both pushed on `master` over SSH (key `kpafi@…-deploy`).

**NEW feature (Users view share UX):** the Users view now shows **"Your handle"**
with **Copy handle** + **Copy invite link** buttons, and an inbound invite link
(`<origin>/#add=<url-encoded handle>`) opens the Users view and **pre-fills** the
add field for review. Security note: the link carries the handle in the URL
FRAGMENT (never sent to the server) and only PRE-FILLS — it never auto-adds and
never conveys trust (verification is still the in-person safety-number check), so
it grants nothing a pasted handle wouldn't. Changed files: `client/index.html`
(handle block in `#usersUnlocked`), `client/app.js` (`renderMyHandle`,
`inviteLink`, `applyPendingInvite`, `handleInviteLink`, copy wiring),
`client/style.css` (`.myhandle`). Web-verified in a two-context Chromium run
(`/tmp/verify-sclive/invite-flow.mjs`): handle shown, both buttons pass the
correct strings, invite pre-fills the peer's add field, contact lands ⚪
unverified. **DEPLOYED to Hetzner** (rsync of `client/` to
`/opt/secure-chat/client/`, no restart needed for static files; confirmed the
live `app.js`/`index.html`/`style.css` carry the change via curl). Phone app
inherits it via the gradle `syncWebClient` copy — APK rebuilt (5.8 MB);
`adb install -r android/app/build/outputs/apk/debug/app-debug.apk` when the phone
is reconnected. Committed + pushed to `github.com/kpafi/secure-chat` (643fc7f).
NOTE for future deploys: this is a SEPARATE step from the git push — the live
site serves `/opt/secure-chat/client/` on the box, so a frontend change is only
live after the rsync.

## ⮕ RESUME HERE (snapshot as of 2026-07-18)
**Status:** live on Hetzner `https://138-199-144-35.sslip.io`. **An external
black-box pentest (2026-07-18) found 9 issues incl. a CRITICAL handshake bug
(C-01); ALL are now fixed, tested, and deployed** — see the 2026-07-18 DONE
entry. Highlights: C-01 (session key ↔ identity now atomically bound: identity
pinned on first handshake, serialized message handling, hard-close on a second
identity — regression-tested); H-01 (fingerprint + safety number now cover the
ecdh/mlkem encryption keys; a change resets verified); M-02 (trust pins moved
into the identity-encrypted store, plaintext pins migrated + deleted); M-01
(OTP rollback tripwire); M-03/L-01/L-02 (challenge rate bucket, HSTS, dev-file
404 + removed from server). Backend **71 pytest passed**; client offline suites
green (crypto/identity/contacts/sealed/otp-rollback); C-01 regression + P6
pentest + full UI flow green local AND live; 3 live integration suites still
green. APK rebuilt (phone unplugged — reconnect + `adb install -r
android/app/build/outputs/apk/debug/app-debug.apk`). Verification harness in
`/tmp/verify-sc/`: `c01-regression.mjs`, `pentest-p6.mjs`, `ui-flow.mjs`.

## ⮕ (previous snapshot 2026-07-17, evening)
**Status:** backend relay + web client working locally **and LIVE on a Hetzner
test server: `https://138-199-144-35.sslip.io`** (all 3 live integration suites
green over the public internet — see the first 2026-07-17 DONE entry for the
server layout, hardening, and the rsync deploy recipe); git repo on `master`.
**BIG feature set landed today (P1–P6, all deployed): a left-drawer menu with a
Users view (contacts + 🟢/🟡/⚪ web-of-trust marks, dual-signed vouches) and a
Chats view (WhatsApp-style async 1:1 over a sealed store-and-forward mailbox;
hybrid ECDH P-256 + ML-KEM-768 sealed envelope with sealed sender; per-chat
mode lock SEALED/AES256 with a signed accept/decline mode change). Identity is
now bundle v2 (adds ECDH + ML-KEM encryption keys; pre-today identities
auto-upgrade + re-publish on first unlock). Contacts + chat history are
encrypted at rest under the identity passphrase.** Backend **70 pytest passed**;
client offline suites (crypto/identity/contacts/sealed) green; full puppeteer
flow (identity→room→chat, users, vouches, async chat both ways, mode
negotiation) green; P6 adversarial pentest green local + live. Tests to run
live: sed-swap `127.0.0.1:8000`→`138-199-144-35.sslip.io` in the three
`*.integration.test.mjs`. NEW client modules: `contacts.js`, `chats.js`,
`sealed.js`; NEW backend: `mailbox.py` (+ vouch endpoints in `accounts.py`).
**Phone:** APK rebuilt (5.8 MB) but the last two installs were skipped (phone
unplugged) — reconnect USB + `adb install -r
android/app/build/outputs/apk/debug/app-debug.apk` to update it.
Backend `pytest` = **57 passed**; client offline suite (`npm test`) green; all
3 live integration suites green; real-browser (puppeteer/Chromium) checks green
(v2 handshake, token-gated directory, RSA ratchet, the double-click send
regression, and the new OTP generate→export/import→two-way→persist flow).
**FIVE working encryption modes now: AES256, DHKE, RSA, PQKEM, and OTP (true
one-time pad, in-person pad exchange — added 2026-07-16, see dated entry).**
**OTP was self-pentested the same day; all 4 findings (concurrent-use lock,
encrypt-at-rest, export single-use, import entropy check) are FIXED + verified.**
**All four 2026-06-19-review accepted-risk items (L1, I1, L2, I2) are CLOSED.**
`pip install -r requirements.txt` also pulls `dilithium-py`. Logging is
minimized (no request/connection metadata at rest); `run.sh` must keep
`--no-access-log --log-level warning`.
**2026-07-16 — all four 2026-07-08 Android pentest findings FIXED** (+ the
informational should-fixes): `RelayUrls.parse` now whitelists the host charset
(Critical Finding 1), the injected config is built with `JSONObject`, the
`shouldOverrideUrlLoading` origin check compares parsed scheme+host (Finding 2),
the app serves from a unique `https://secure-chat.internal` origin via
`WebViewAssetLoader.setDomain` (Finding 4, `APP_WEBVIEW_ORIGIN` updated to
match), WebView remote debugging is `BuildConfig.DEBUG`-gated, cleartext is
scoped to loopback/.onion, and `importMapHash` drift is guarded in
`test_csp_hash.py`. New Robolectric `RelayUrlsTest` (11 tests) rejects the live
PoC payloads; debug APK builds clean. See the 2026-07-16 DONE entry. **Remaining
Android work:** on-device re-run against the new origin + the DHKE/RSA/PQKEM
safety-number gate (needs the emulator), app icon, and release-signing.
**2026-07-07 (four entries, newest first):**
0. **Android app (new `android/` module):** thin Kotlin/WebView shell that
   BUNDLES the audited web client in the APK (closes web-only trust gap H1) and
   points at a remote relay. Debug APK builds clean; verified in a real browser
   AND **on-device** (Android 14 emulator — AES256 end-to-end through the relay,
   both directions). Found + fixed a Mixed-Content constraint: the relay must be
   wss/loopback/.onion (a plain-http LAN relay is browser-blocked); app.js now
   reports it clearly. Backend gained a single allow-listed app origin (WS +
   CORS) and `SECURE_CHAT_EXTRA_ORIGINS`. See the two dated entries.
1. **Ratchet unification:** DHKE + PQKEM ported onto `RatchetChannel`
   (in-session forward secrecy for every mode; `AuthChannel` deleted); DHKE
   drops its private key at derivation, PQKEM seals like RSA on first
   traffic; reflected handshake keys + reflected hellos now refused in all
   modes. DHKE/PQKEM `msg` frames are `dhke-msg/v2`/`pqkem-msg/v2`.
2. **Final crypto review** of the whole stack: no High/Medium findings; full
   verification matrix green incl. a 4-mode real-browser end-to-end run.
3. **Both 2026-07-03 pentest concurrency bugs FIXED** (High: racing decrypts
   could roll the replay counter back; Medium: overlapping encrypts consumed
   the same one-time key and killed the ratchet): all channel encrypt/decrypt
   calls are serialized through a per-instance FIFO `CallQueue`, plus a
   Send-in-flight guard in app.js as defense in depth. See dated entries.
**2026-07-03:** TODO item (d) fully closed — ratcheting for RSA **and** AES256.
1. RSA mode is now **forward-secret** — RSA key transport + a one-way HMAC
   ratchet with one-time AES-GCM message keys; root secret and RSA private key
   are erased once traffic starts (see dated entry). RSA `msg` frames are
   `rsa-msg/v2`; handshake format unchanged.
2. AES256 mode now runs the same ratchet (shared `RatchetChannel`), rooted in
   the passphrase **plus both peers' fresh session nonces** (new plaintext
   hello exchange for AES256, reusing the app's existing hello phase) — this
   **CLOSES the AES256 cross-session-replay residual**. AES256 frames are
   `aes-msg/v2`; `AuthChannel` now serves only DHKE/PQKEM. FS for AES256 is
   honestly limited (passphrase = master secret; see dated entry).
Both committed together in a single commit on top of d5e2f68.
**2026-07-02 (second session), in order:**
1. CLOSED Medium finding **cross-session handshake replay in a reused room** —
   handshake transcript bumped to v2, covers a fresh per-connection nonce from
   BOTH peers (plaintext `hello` before the signed offer/answer, folded
   order-independently). Committed as c756cf9.
2. CLOSED accepted-risk **L1** (server-side ML-DSA-65 dual ownership proof at
   registration, via `dilithium-py`) and **I1** (username namespace made
   non-enumerable: token-gated `username#token` lookup + removed the
   challenge/verify existence oracles + dedicated lookup rate limit). See the
   "accepted-risk closeout" dated entry. NEW backend dep: `dilithium-py`.

Both were committed this session (c756cf9 = handshake replay; 1703a19 = L1/I1).

**Done & verified end-to-end (incl. real-browser checks via puppeteer):**
- Dumb-relay backend (strict validation, rate limit, connection cap, join +
  idle timeouts) + passwordless account directory (`/api`, rate-limited + capped).
- Web client: 5 working encryption modes — **AES256, DHKE, RSA, PQKEM, OTP**
  (PQKEM = hybrid ECDH P-256 + ML-KEM-768; OTP = true XOR one-time pad with an
  in-person pad exchange, added 2026-07-16). Identity = Ed25519 + ML-DSA-65,
  passphrase-encrypted at rest (PBKDF2 600k).
- **Authenticated handshake** (dual-sig) + in-person safety-number gate closes
  the relay-MITM gap. Account register/login + fetch-by-username pinning.
- Security review done; M1/M2/L3 fixed, H1 documented (see 2026-06-19 entry).

**Next options (pick one):** (a) on-device smoke test of the new Android app
(build + cross-origin browser verification DONE 2026-07-07; needs a real
device/emulator to exercise the WebView glue); (b) Tor `.onion` deployment
(pairs naturally with the app — set the relay to the `.onion` and add its
origin via `SECURE_CHAT_EXTRA_ORIGINS`); (c) OTP mode. Full open list in TODO
at the bottom.

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
### 2026-07-18 — External pentest response: C-01 (critical) + 8 more, all fixed ✅
An independent black-box audit of the live web instance reported 9 findings.
All addressed, tested, deployed. Full write-up in README ("External pentest").

**C-01 — CRITICAL — session key not atomically bound to peer identity.**
Confirmed by reading the code: `handleMessage` set `peerBundle = idb` then
`cipher.onPeerKey(pub)`, and the ciphers are first-key-wins. A relay could send
its OWN validly-signed offer first (cipher locks attacker key) then relay the
peer's real signed offer (peerBundle → real peer, cipher IGNORES the real key),
so the safety number / pin verified against the honest peer while the live
channel used the attacker's key — decoupling exactly what the safety-number
gate protects. **Fix (app.js):** (1) message handling serialized through a FIFO
`msgChain` (closes the TOCTOU where two frames pass verification before either
pins); (2) the peer identity is PINNED to the first accepted handshake —
`peerBundle` is write-once, and a later frame whose `idb` differs hard-closes
the connection with a MITM notice; (3) `enterVerification(room, verifiedBundle)`
takes the pinned bundle explicitly instead of re-reading a mutable global.
**Regression:** `/tmp/verify-sc/c01-regression.mjs` — a mock relay feeds two
validly-signed DHKE offers from DIFFERENT identities with identical nonces; the
first is accepted, the second hard-closes, messaging never unlocks, a MITM line
is logged.

**H-01 — HIGH — relay could swap the async (ecdh/mlkem) encryption keys.**
Fingerprint/safety-number covered only ed+mldsa, and a contacts enc-key change
did NOT reset verified — so a relay could pair the real signing keys with its
own encryption keys and silently redirect sealed messages. **Fix:**
`identity.js` `_bundleBytes` folds ecdh+mlkem into `fingerprintOf` +
`safetyNumber` (pre-v2 bundles hash unchanged); `contacts.upsert` treats ANY of
the four keys changing as a key change (resets verified, drops stale vouches);
the live-room verify gate mirrors the FULL bundle (incl. enc keys) into
contacts; adding a contact by handle no longer auto-verifies from an
ed/mldsa-only pin.

**M-02 — MEDIUM — trust pins were plaintext localStorage.** A forged
`sc.pins.v1` entry could auto-unlock. **Fix:** pins live inside the
identity-encrypted, GCM-authenticated contact store (`contacts.getPin/savePin`),
blob bumped to v2 `{contacts, pins}`; a one-time migration imports the old
plaintext pins then deletes the key.

**M-01 — MEDIUM — OTP rollback.** A wholesale restore of an old encrypted pad
blob rewound `sendOffset` to reuse keystream (GCM stops edits, not rollback).
**Fix (otp.js):** a SEPARATE monotonic high-water key `sc.otp.hw.v1.<id>`;
unlock refuses a pad whose offset regressed below it. `otp-rollback.test.mjs`
proves an old-blob restore is refused. *Residual (documented):* a full-storage
rollback that also reverts the tripwire needs OS-level trusted storage — out of
scope for browser localStorage.

**M-03 / L-01 / L-02.** Dedicated stricter rate bucket on `/api/auth/challenge`
(`CHALLENGE_RATE_CAPACITY=10`, 0.5/s) + test; `Strict-Transport-Security` sent
when `X-Forwarded-Proto: https` (not on loopback/.onion); middleware 404s
`package.json`/`package-lock.json`/`*.test.mjs` and they were removed from the
deployed client dir. **H-02 / L-03 / PQ-assurance:** documented as accepted /
architectural (web client = honest-but-curious; Android app = malicious-relay
answer; SSH key-only on a disposable box; noble-PQ self-audited).

**Verification:** backend **71 passed**; client offline suites green incl. new
`otp-rollback.test.mjs`; `c01-regression.mjs`, `pentest-p6.mjs`, full
`ui-flow.mjs` green LOCAL and the pentest + 3 integration suites green LIVE
against Hetzner. Deployed; HSTS + dev-file-404 confirmed on the live box; APK
rebuilt.

### 2026-07-17 — P6: hardening pass over the contacts/chats surface + live E2E ✅
Adversarial pass following the project method (attack the running code, prove
it with a live PoC): `/tmp/verify-sc/pentest-p6.mjs`, run against BOTH the
local relay and the live Hetzner box. Every attack refused:

- **Vouch forgery:** zero-signature vouch → 400; a vouch signed by a
  non-owner key but submitted under the attacker's session → 400 (server
  checks the sig against the AUTHENTICATED user's keys). **Client 🟡
  forge-resistance:** proved `Identity.verify` rejects a genuine vouch when
  the voucher keys are swapped to the attacker's, and when the target key is
  rotated — so a lying directory cannot manufacture a 🟡 (the award rule
  re-verifies against the client's OWN pinned voucher keys).
- **Mailbox:** wrong-token-for-real-user and unknown-user POST return
  byte-identical 404 (not an existence oracle); fetch without / with a bogus
  bearer token → 401; a logged-in eve never sees bob's queue (per-recipient);
  an envelope captured off the wire won't `open()` without the recipient's
  keys.
- **Chat sender spoofing:** eve seals a message to bob with alice's
  self-claimed handle — `open()` still binds the sender to EVE's real bundle,
  and since chats are keyed by bundle (never the claimed name), she cannot
  inject into bob's alice-chat.
- **Regression:** the 3 live integration suites (relay 4-mode, account
  directory, authenticated handshake) still pass against Hetzner after all the
  backend changes — the dumb relay + directory are untouched in behaviour.
- Docs: README gained a "Contacts, web of trust, and async chats" section
  (trust marks, sealed envelope, mailbox, mode lock, the FS trade-off). APK
  rebuilt (5.8 MB, ready for the next phone connect).
- NOTE: the pentests + browser runs left a handful of `pt-*`/`bob-*` test
  accounts in the LIVE directory (public keys only, harmless) — restart/redeploy
  starts fresh if you want a clean box for real testing.

### 2026-07-17 — P5: per-chat mode lock + negotiated mode change ✅
- **Modes (async):** SEALED (default, transport only) and AES256 (an inner
  AES-256-GCM layer under a per-chat passphrase, applied to the plaintext
  BEFORE sealing — so even a break of the recipient's long-term TRANSPORT keys
  leaks nothing without the chat passphrase). OTP-over-mailbox deliberately NOT
  offered (async pad sync = two-time-pad risk); it stays live-room only.
- **Negotiation:** the sealed envelope core now carries a `kind`
  (msg / mode-propose / mode-accept / mode-decline) — control messages are
  signed and authenticated exactly like text (`sealed.js` generalised from
  `text` to a `content` object; open() returns the whole signed body). One
  side proposes via the chat's mode picker (AES256 → prompts for a shared
  passphrase, mints a PBKDF2 salt sent in the proposal); the peer sees an
  accept/decline banner; the switch happens only after a signed accept, on
  both sides. Decline/lost-response leave the locked mode untouched.
- **Store:** `chats.js` gained `setMode`/`setPending`/`clearPending`, the
  AES256 fields (`secret`,`salt`), and inner-layer `innerEncrypt/innerDecrypt`
  (+ `newInnerSalt`). Mismatch cases render a clear system line rather than
  garbage. All negotiation state is inside the identity-encrypted chat store.
- **Verified:** `sealed.test.mjs` gains a control-message case (kind/mode/salt
  survive sign+seal); browser flow drives alice→propose AES256, bob→accept
  (both prompts auto-answered with the same passphrase), both lock to AES256,
  then a message round-trips through the inner layer. Offline suites + backend
  70 green; deployed to Hetzner. Screenshot eyeballed; tightened the convo
  header to wrap on narrow screens.

### 2026-07-17 — P4: store-and-forward mailbox + Chats view (WhatsApp-style async DMs) ✅
- **Backend `mailbox.py` (new):** rows are (recipient, opaque envelope,
  arrival time) — the sender is sealed INSIDE the envelope, invisible to the
  server. `POST /api/mailbox/{recipient}?t=<lookup token>` (token gate = same
  anti-enumeration boundary as the bundle lookup: wrong token / unknown user
  are an identical 404; printable-ASCII + 64 KiB envelope cap; dedicated
  per-host rate bucket 30 burst / 1 rps; per-inbox cap 200; global cap 100k;
  14-day TTL pruned on access). `GET /api/mailbox` requires the session token
  and DELETES what it returns — no server-side read history. New
  `tests/test_mailbox.py` (roundtrip+delete-on-fetch, token-gate oracle check,
  auth, size/ASCII/inbox-cap, TTL prune) → backend **70 passed**.
- **Client:** `chats.js` — encrypted chat store (same PBKDF2→AES-GCM posture,
  unlocked with the identity, wiped on forget; 500-msg cap per chat; inbound
  dedup by envelope id). `sealed.js` core gained a signed, self-claimed
  sender handle (display/reply-token only — chats are KEYED by the sender's
  signature-verified bundle, never by the claimed name). `account.js`:
  `sendMail`/`fetchMail`. Chats view: start-a-chat picker (saved users),
  chat list with safety marks + last-message preview, bubble conversation
  (textContent-only rendering), mode line "🔒 SEALED …". Sending needs only
  the contact's handle token; RECEIVING needs login (mailbox auth) — 6s
  polling after login + on view entry. Unknown senders are auto-added as ⚪
  contacts (sealed handle preferred, fingerprint-derived name fallback); a
  known bundle without a reply token adopts the sealed handle's token.
- **Verified:** browser suite extended — alice→bob sealed send, bob logs in,
  chat auto-appears filed under alice's handle, bob replies using the sealed
  token, alice's open conversation updates, chat blob at rest is ciphertext
  (no plaintext leak). Screenshots eyeballed (bubble UI). Deployed to the
  Hetzner box; APK rebuilt (phone was unplugged — install pending reconnect).
- **Known limitation (documented):** sealed envelopes have per-envelope
  ephemerals but NO live ratchet — long-term-key compromise exposes captured
  past envelopes. P5 adds the mode lock/negotiation; the hardening pass (P6)
  revisits mailbox abuse surface end-to-end.

### 2026-07-17 — P3: bundle v2 (encryption keys) + sealed async envelope ✅
Foundation for chats-without-a-live-room:

- **Identity (client):** now also holds ENCRYPTION keypairs — ECDH P-256 +
  ML-KEM-768 (`identity.js`). Blob format v3 (v2 blobs auto-upgrade on
  unlock: enc keys generated, blob re-exported once, bundle re-published to
  the directory opportunistically for registered users). Fingerprint / safety
  number / pins still cover ONLY the signing keys (identity continuity); the
  enc keys are bound to the identity by the registration signature.
- **Directory (backend):** registration v2 under `secure-chat/register/v2`
  (dual sig covers ecdh+mlkem; both-or-neither, strict sizes 65/1184 B).
  `accounts` table gained `ecdh_pub`/`mlkem_pub` (empty for v1 rows; those
  can't receive sealed messages until re-registered). **Same-identity
  re-registration is now a bundle refresh** (verifies the dual sig, matches
  stored ed+mldsa exactly, updates enc keys, returns the EXISTING lookup
  token) — foreign identities still get 409. Lookup returns enc keys when
  present; v1 registration still accepted. `tests/test_bundle_v2.py` (5
  tests): roundtrip, sig-must-cover-enc-keys (v1-sig + keys, post-sign key
  swap), both-or-neither + size validation, refresh-vs-409, v1 compat —
  backend **65 passed**.
- **`sealed.js` (client, new):** async E2EE to a contact's public bundle.
  Hybrid: ephemeral ECDH + ML-KEM-768 encaps → HKDF-SHA256(salt=domain,
  info=recipient-ed) → AES-256-GCM. **Sealed sender:** sender bundle + DUAL
  signature live inside the ciphertext; sig covers domain + RECIPIENT identity
  key + eph + KEM ct + core, so envelopes can't be re-targeted and the mailbox
  never learns the sender. FS trade-off documented (per-envelope ephemerals;
  no live ratchet in store-and-forward). `sealed.test.mjs`: roundtrip, opaque
  envelope (no plaintext/sender leak), wrong-recipient, tamper,
  eve-signs-as-alice forgery, legacy-blob upgrade — all green.
- Contacts store now carries contacts' enc keys (updated on add/lookup; an
  enc-key change alone does NOT reset `verified` — trust anchors stay
  ed/mldsa). Client suites + full browser flow green; deployed to Hetzner +
  phone. NOTE: identities created before today must unlock once (auto-upgrade
  + re-publish) before they can RECEIVE sealed messages.

### 2026-07-17 — P2: web-of-trust vouches (🟡 mark) ✅
- **Backend:** `vouches` table (voucher→target, dual sigs, created_at; PK
  dedups re-vouches). `POST /api/vouch` (session-token auth) verifies BOTH
  signatures against the voucher's registered keys over the TARGET's currently
  registered bundle before storing — the table can only hold statements the
  voucher really signed about the real directory entry. `DELETE /api/vouch/
  {target}` revokes. `GET /api/users/{u}/vouches` is gated by the target's
  lookup token (no graph enumeration) + the strict lookup rate bucket, returns
  ≤50 vouches incl. voucher public keys. Bounds in config: 200/voucher, 200k
  total. Domain-separated message: `secure-chat/vouch/v1\ntarget\ned\nmldsa`.
  Self-vouch 422. New `tests/test_vouches.py` (publish/fetch/revoke; wrong-key,
  cross-target, single-scheme-forgery, auth rejections; token-gated 404
  indistinguishability) — backend now **60 passed**.
- **Client:** `account.js` vouch/unvouch/fetchVouches (+ exported
  `vouchMessageBytes`); login now retains the session token in memory.
  Users view: turning a contact 🟢 offers (confirm, opt-in — it reveals the
  social edge publicly) publishing a vouch signed over MY pinned copy of their
  bundle; Unverify retracts. 🟡 computation is strictly local: a vouch counts
  ONLY if the voucher is a contact I verified in person AND the
  server-returned voucher keys equal my pinned copy AND the dual signature
  verifies over MY stored target bundle — a lying directory cannot invent a 🟡.
  Results cached in the encrypted store (10-min recheck TTL).
- **Verified:** full puppeteer flow incl. new WoT scenario (alice registers,
  logs in, re-verifies bob → publishes vouch; carol verifies alice in person,
  adds bob → 🟡 "vouched by alice"), screenshots eyeballed; all offline suites
  green. Deployed to Hetzner (backend restarted) + phone APK. Found+fixed in
  passing: renderUserList() wiped the just-set vouch status line (order swap).

### 2026-07-17 — P1 of the contacts/chats overhaul: drawer menu + encrypted contact store + Users view ✅
First phase of the planned contacts + web-of-trust + async-chats feature set
(full plan in TODO). Shipped:

- **Drawer menu** (☰ top-left): Live room (the untouched 3-step flow) / Users
  (new) / Chats (placeholder until P4). Pure presentation; switching views
  never touches an active connection. CSS gotcha fixed along the way:
  `.drawer { display:flex }` silently overrode the `hidden` attribute
  (author display beats the UA's `display:none`), leaving an invisible
  click-eating overlay — caught by the browser suite, fixed with an explicit
  `.drawer[hidden] { display:none }`.
- **`contacts.js` — encrypted contact store.** Records
  `{username, token, ed, mldsa, verified, verifiedAt, addedAt, keyChangedAt}`;
  at rest PBKDF2-600k → AES-256-GCM under the IDENTITY passphrase (same
  posture as identity + pads; GCM doubles as tamper protection — flipping
  `verified` in the blob just breaks decryption). Unlocked wherever the
  identity is created/unlocked (before the passphrase field is cleared);
  locked state renders a hint; wiped on identity-forget; a changed key for a
  known username RESETS `verified` (same rule as the pin store). Foreign/
  tampered blob → clear error, resettable via identity-forget.
- **Users view:** add contact by `username#token` (directory lookup),
  fingerprint per contact, marks 🟢 "verified by you" / ⚪ unverified (🟡
  vouched comes with P2), confirm-gated "Verified in person ✓" / Unverify /
  Remove, loud key-changed warning. Auto-🟢: adding a handle whose bundle
  matches an existing in-person pin, and the live-room safety-number confirm
  (`onVerifyOk`) mirrors into the store when the contact-handle field named
  the peer.
- **Tests:** new `contacts.test.mjs` (npm test now runs it): encrypted
  round-trip, wrong-passphrase refusal, GCM tamper refusal, key-change trust
  reset, wipe, opaque-at-rest. Browser suite extended: register→handle→add→
  ⚪→verify→🟢→reload-unlock→persisted→blob-is-ciphertext. All green
  (client offline, backend 57/57, full puppeteer flow); deployed to the
  Hetzner box + phone APK reinstalled.

### 2026-07-17 — UI rework: 3-screen flow + disconnect + copy-room-id (deployed live + on phone)
User feedback from live testing: no way to disconnect once connected, and the
single-page UI felt raw. Reworked the client into a guided **3-screen flow** —
UI structure only, **zero crypto/handshake/connection-logic changes** (all
element ids kept, so the test suites run unmodified):

1. **Identity screen** (identity panel + optional username register/login);
   Continue button (labelled "Skip — no identity (AES-256 / OTP only) →" until
   an identity is unlocked).
2. **Room screen** (room id + Generate, encryption picker, passphrase/OTP
   panel, contact handle, Connect) with Back navigation.
3. **Chat screen** with a sticky **top bar**: shortened room id, **Copy room
   id** button (clipboard), mirrored status, and the new **Disconnect** button
   (`ws.close()` → the existing onclose cleanup now returns to the room
   screen). Verify (safety-number) panel lives inside this screen.

Implementation: `index.html` regrouped into `#scrIdentity/#scrRoom/#scrChat`
wrappers + `showScreen()` in app.js; `joined`/`onclose` swap screens instead of
toggling `#setup`/`#chat`; the inline importmap kept **byte-identical** (CSP
hash — `test_csp_hash.py` still green). style.css: step indicator, topbar,
ghost buttons, `#log` height now `min(55vh, 480px)` for phones.
**Verified:** client `npm test` green, backend 57/57 green, and a new
puppeteer/Chromium two-peer UI-flow check (`/tmp/verify-sc/ui-flow.mjs` —
screen navigation, DHKE session, safety-number match, message delivery,
topbar copy → clipboard content asserted, disconnect → room screen). Deployed
to the Hetzner box and reinstalled on the phone (`adb install -r`) same day.
**Follow-up 2 (same day) — mobile polish + encryption picker cards.** The
`<select>` encryption picker is now a **radio-card group** (`#algCards`, one
`<input type="radio" name="alg">` per mode with name/badge/description —
`els.alg.value` reads became the `algValue()` helper; `syncAlgUI` listens on
the container). Phone-sized screens (`@media max-width: 600px`): tighter
padding, 16px inputs (no focus-zoom), bigger touch targets, `#log` sized via
`100dvh`, and the chat top bar becomes a 2×2 grid (room id | copy // status |
disconnect). Verified: npm test + 57/57 pytest green; ui-flow.mjs (extended
with a card-toggling check) green at a 390×844 viewport; screenshots
eyeballed. Deployed to the Hetzner box + phone same day.
**Follow-up (same day):** the browser kept showing the OLD client after the
deploy — StaticFiles sends only ETag/Last-Modified, no `Cache-Control`, so
browsers cache heuristically without revalidating. Fixed: the security-headers
middleware now also sets `Cache-Control: no-cache` (always revalidate; ETag
makes unchanged loads a 304). One manual hard reload (Ctrl+F5) is needed on
clients that cached before this fix; after that, deploys show up on plain
reload. 57/57 backend tests still green; live-verified on the Hetzner box.

### 2026-07-17 — FIRST LIVE DEPLOYMENT: Hetzner test server, all live suites green 🚀
The relay + web client are live on a Hetzner Cloud box (Debian 13, x86_64,
4 GB) for real-network testing:

- **URL: `https://138-199-144-35.sslip.io`** (sslip.io wildcard DNS → the
  server IP `138.199.144.35`; free Let's Encrypt cert via Caddy — swap in a
  real domain or the `.onion` later without touching the backend).
- Layout on the server: `/opt/secure-chat/{backend,client,venv}`, runs as the
  no-login system user `securechat` under systemd (`secure-chat.service`) with
  sandboxing (`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
  `NoNewPrivileges`). Uvicorn binds **loopback only** and keeps the mandatory
  `--no-access-log --log-level warning`; Caddy terminates TLS on 443 and its
  access log is set to `output discard` (metadata-minimization carried over,
  I2). Public origin allow-listed via
  `Environment=SECURE_CHAT_EXTRA_ORIGINS=https://138-199-144-35.sslip.io` in
  the unit (WS origin check + CORS).
- Host hardening: SSH is key-only (password auth disabled via
  `sshd_config.d/90-no-password.conf`), Hetzner cloud firewall allows only
  22/80/443 TCP inbound, unattended security upgrades enabled. Local test
  `accounts.db` was NOT deployed — the live directory starts empty.
- **Verified from the laptop against the live server:** all 3 live integration
  suites green over the public internet — relay (DHKE/AES256/RSA/PQKEM
  end-to-end via `wss://`), account directory (register→lookup→login→me,
  dup-username 409, wrong-key rejected), authenticated handshake
  (DHKE/RSA/PQKEM safety numbers + cross-session replay REJECTED). Run them
  live by sed-swapping `127.0.0.1:8000` → `138-199-144-35.sslip.io` (ws→wss,
  http→https) in the three `*.integration.test.mjs` files.
- Deploy/update recipe: `rsync -az --delete --exclude '.git' --exclude
  '__pycache__' --exclude 'node_modules' --exclude 'accounts.db*'
  backend client root@138.199.144.35:/opt/secure-chat/ && ssh
  root@138.199.144.35 systemctl restart secure-chat`.
- NOTE: test box is disposable (hourly billing); nothing on it is
  irreplaceable — everything above is reproducible from this repo.

### 2026-07-16 — OTP pentest: 2 Medium + 2 Low found (NOT yet fixed) 🔴
Adversarial review of the just-shipped OTP mode (crypto.js `OtpPad`, otp.js, the
app.js wiring), following this project's "attack the running code, prove it with
a live PoC" method. PoCs run against the actual shipping modules
(`/tmp/verify-sc/pentest-otp.mjs`). **The OTP core crypto held up** — replay,
cross-room replay, cross-session replay, ciphertext tamper, offset-relabeling,
reflection, and forward-secrecy zeroing are all correctly rejected/enforced
(re-proven). Four weaknesses found, all in pad *lifecycle/state management*, not
the cipher:

**Finding 1 — MEDIUM — concurrent pad use = two-time pad (catastrophic reuse).**
Nothing locks a pad to one active session. Two OtpPad instances built from the
same persisted record — exactly what two browser TABS get from `loadPad` (they
share localStorage but each holds its own in-memory offset) — both start at the
same offset and reuse the same keystream. **Live-proven:** `C1^C2 == P1^P2`, the
classic two-time-pad break (an eavesdropping relay recovers plaintext
relationships, and any one known/guessable message reveals the other outright).
`MAX_ROOM_MEMBERS=2` blocks the naïve "two tabs + peer in ONE room" variant, but
NOT (a) two concurrent conversations (two rooms) sharing one pad, nor (b) two
tabs alone in a room unlocking each other. Single-tab sequential use is safe
(offset persisted after every message). Fix: a same-origin lock (BroadcastChannel
lease / a localStorage "pad in use" epoch checked before each send) so a pad can
be live in only one session at a time; refuse or hard-warn on concurrent use.

**Finding 2 — MEDIUM — pad stored UNENCRYPTED at rest.** `otp.savePad` writes
`bytes: b64(record.bytes)` straight to localStorage in the clear, unlike the
identity private keys (which are PBKDF2→AES-GCM encrypted at rest). A device /
browser-profile compromise reads the entire REMAINING pad → decrypts all FUTURE
traffic until a new pad is exchanged. Consumed bytes are zeroed, so past traffic
stays protected (the FS property holds), but the long-term secret sitting in
plaintext is inconsistent with the rest of the app's at-rest posture and
undercuts exactly the high-assurance users who pick OTP. Fix: encrypt the pad at
rest under a passphrase (reuse the identity export machinery), unlocked per
session like the identity is.

**Finding 3 — LOW — export file has no single-use / role binding.** `importPad`
always returns `recipientRole` (= 1), so importing the same export file on more
than one device gives EVERY importer role 1 → two role-1 senders reuse region 1
(two-time pad again). Same if the generator forgets its role-0 copy and
re-imports its own file. **Live-proven** (two imports → identical role → keystream
reuse). Only the otp.js header doc ("import on one device per side") prevents it.
Fix direction: bind the pad to the exchanging identities if available, or at
least track "this file already imported / this pad already has a role-1 peer" and
warn hard; there is no fully-robust cross-device enforcement without identities.

**Finding 4 — LOW/informational — a malicious pad generator can downgrade the
importer's outbound confidentiality.** The generator produces ALL pad bytes,
including the importer's send region. A hostile (or corrupted) pad with an
all-zero / low-entropy send region makes the importer's outbound `ct = pt XOR 0
= pt` — plaintext on the wire, readable by the RELAY, not just the generator.
Bounded: the generator is your trusted in-person contact who receives your
plaintext anyway; the only *new* exposure is to third parties. Fix: a cheap
entropy sanity check on import (reject an all-zero / obviously non-random pad),
and/or document that the pad's randomness is only as trustworthy as whoever
generated it.

**Verified negatives (no finding):** the AD binds domain|room|role|offset|len so
moving a frame across rooms/offsets/regions fails the MAC; the one-time HMAC key
is full 32-byte SHA-256 (untruncated); `crypto.subtle.verify` is constant-time;
auth-failed frames consume no pad (a hostile relay can't burn the pad with
forgeries); the entropy mixer (CSPRNG XOR AES-CTR(H(finger))) is never weaker
than the CSPRNG; the export file is GCM-authenticated (wrong passphrase → clean
reject). `offset | 0` would truncate for >2 GiB pads but max pad is 1 MiB
(unreachable, latent-only). The non-OTP stack (relay, accounts, other four
ciphers) was not changed this session and its previously-closed findings remain
closed; a quick re-confirm left backend `pytest` 57 and all live suites green.

**Not yet fixed** — all four are on the TODO list below. **(All four FIXED later
the same day — see the entry above this one.)**

### 2026-07-16 — OTP pentest findings 1–4 FIXED ✅
Fixed all four findings from the OTP pentest (entry below). The OTP cipher core
was already sound; these harden pad lifecycle/state.
- **F1 (MEDIUM) — concurrent-use two-time pad.** New exclusive same-origin lock
  in app.js: `acquirePadLock(padId)` uses the **Web Locks API**
  (`navigator.locks`, auto-released if the tab dies) with a localStorage-
  heartbeat lease fallback. Taken on connect, released on disconnect; a pad live
  in one tab makes connect in any other tab refuse ("already in use"). Single-tab
  sequential use is unaffected.
- **F2 (MEDIUM) — pad unencrypted at rest.** `otp.js` persistence rewritten: the
  pad bytes AND consumption offsets are stored **encrypted** (PBKDF2-600k →
  AES-256-GCM) under a per-pad passphrase, never in the clear — same at-rest
  posture as the identity blob. `saveNewPad` derives the key once (PBKDF2);
  `unlockPad` decrypts on connect; `savePadProgress` re-encrypts each message
  with the cached key (no per-message PBKDF2). Offsets live INSIDE the GCM blob,
  so a local attacker can't roll `sendOffset` back to force pad reuse. A new
  "pad passphrase" field (distinct from the file "transfer passphrase") unlocks
  the pad per session.
- **F3 (LOW) — export single-use.** Re-exporting an already-shared pad warns and
  requires a confirming second click (`markExported` / `padMeta.exported`);
  import dedups by padId and the UI carries a strong "one device per side"
  warning. Cross-device double-import of a manually-copied file is inherent
  without identities (documented).
- **F4 (LOW) — low-entropy imported pad.** `importPad` now runs `looksRandom`
  (Shannon entropy over a byte histogram) and refuses a pad below 7.0 bits/byte
  (all-zero / grossly low-entropy), so a corrupt/sabotaged pad can't silently
  make outbound `ct == pt`.
- **UI:** two OTP passphrases now — a top-level **pad passphrase** (at-rest,
  per-session unlock) and the export/import **transfer passphrase** (`otpXferPass`).
- **Verified.** `node crypto.test.mjs` + `npm test` green (cipher unchanged);
  module-level checks (localStorage shim): at-rest blob carries only kdf/iv/ct
  (no plaintext bytes), unlock round-trips bytes+offsets, wrong passphrase
  rejected, all-zero pad import rejected, `looksRandom` correct. **Real-browser
  E2E (Chromium/puppeteer, two contexts + extra tabs):** generate (encrypted at
  rest) → export → re-export warns → import (encrypted, both passphrases) →
  connect → two-way messaging, zero undecryptable frames; a second tab is refused
  the in-use pad (F1); a wrong pad passphrase refuses unlock (F2). Backend
  `pytest` 57 + all 3 live integration suites still green.

### 2026-07-16 — OTP mode: true one-time pad, in-person pad exchange ✅
Implemented the deferred OTP mode as a genuine XOR one-time pad. Design forks
were decided with the user: true XOR OTP (not a pad-as-keypool shortcut),
file-based in-person pad transport (not Web Bluetooth), and CSPRNG hardened with
optional draw-to-generate entropy.
- **`OtpPad` cipher (`client/crypto.js`).** Confidentiality is a real one-time
  pad: `ct = plaintext XOR keystream`, keystream = fresh pad bytes never reused.
  The pad is split in half by ROLE (generator = role 0, importer = role 1); each
  side sends from its own region and receives from the other, so no byte is ever
  used to encrypt twice. Integrity: each message carries an HMAC-SHA-256 tag
  under a one-time 32-byte key also drawn from the pad, binding
  domain|room|role|offset|len|ct (stops XOR malleability; honest computational
  limit, since an info-theoretic one-time MAC would be hand-rolled crypto we
  forbid). A strictly increasing receive offset rejects replays AND cross-session
  replays (offsets persist per pad, never rewind). Consumed pad bytes are ZEROED
  on both send and receive (forward secrecy: capture at time T can't decrypt
  earlier traffic). Auth-failed frames consume nothing (a hostile relay can't
  burn pad with forgeries). Serialized through the shared `CallQueue`.
  `needsHandshake=false`, `usesNonces=false`; removed from `UNAVAILABLE`.
- **Pad lifecycle (`client/otp.js`, new).** `generatePad` = OS CSPRNG XOR an
  AES-CTR keystream keyed by SHA-256 of the user's drawn-motion samples (never
  weaker than the CSPRNG alone). `exportPad`/`importPad` = a passphrase-encrypted
  file (PBKDF2-600k → AES-256-GCM) carrying padId + region size + recipient role
  + pad bytes; export refuses a already-used pad (would hand the peer zeroed
  regions that XOR back to plaintext). localStorage persistence of bytes +
  offsets + role, pad index/list/forget. Size presets 64 KiB / 256 KiB / 1 MiB
  with honest per-side message estimates.
- **UI (`index.html`, `style.css`, `app.js`).** OTP panel: pad selector,
  generate (with a draw-to-generate entropy canvas), encrypted export (file
  download) / import (file upload), forget, and a live remaining-budget display.
  OTP unlocks messaging on peer PRESENCE (the pad is the out-of-band secret, like
  AES256's passphrase — no identity/safety-number gate). Offsets persisted after
  every send/receive so consumption survives reload (reuse would be
  catastrophic). `syncAlgUI` shows the panel; `connect()` loads the selected pad.
- **Docs.** README encryption-modes table + a new OTP paragraph state the two
  honest caveats plainly (computational MAC; CSPRNG-not-TRNG pad, so "at least as
  strong as the CSPRNG"). Backend needed no change — the `Algorithm` enum already
  allowed `OTP` (advisory tag; relay never acts on it).
- **Tests / verification.** New `otpChecks` in `crypto.test.mjs` (round-trip both
  directions, replay/tamper/reflection/forgery rejected, exhaustion refused, and
  FS zeroing asserted on sender + receiver) — `node crypto.test.mjs` green.
  Offline `npm test` green; all 3 live integration suites green (no regression to
  the other modes). **Real-browser check (Chromium/puppeteer, two isolated
  contexts):** Alice generated a pad with drawn entropy and exported the
  encrypted file; Bob imported it (wrong transfer passphrase rejected); both
  connected to one room, unlocked on presence, exchanged messages BOTH directions
  with zero undecryptable frames; the budget decremented; and localStorage showed
  the offsets persisted AND the consumed pad bytes zeroed at rest.
- **Known limits (documented):** a pad is a shared secret for exactly two
  devices (never import on more than one per side); pad size = total text budget
  (XOR consumes 1 byte/char + 32/msg); no post-compromise recovery beyond the
  zeroing already described. Cross-tab concurrent use of one pad on the same
  device is not locked — the offset is persisted before/after each send, but two
  tabs are a footgun; documented, IndexedDB/BroadcastChannel hardening is a
  future option if larger pads or multi-tab use are wanted.

### 2026-07-16 — Android pentest findings 1–4 (+ informational) FIXED ✅
Closed all four 2026-07-08 Android pentest findings and the informational
should-fix items. Root cause of Findings 1 & 3 was one permissive value flowing
into two sinks; fixed at the source plus defense in depth at each sink.
- **Finding 1 (CRITICAL) — relay-address → JS execution.** `RelayUrls.parse`
  (`RelayUrls.kt`) now rejects any host with a character outside
  `^[A-Za-z0-9.-]+$` (a `SAFE_HOST` regex) and rejects `user:pass@` authorities,
  BEFORE returning — so `android.net.Uri`'s permissive/percent-decoded `.host`
  can no longer smuggle `"`, `;`, `{`, `}`, spaces, or decoded delimiters
  downstream. Defense in depth: `MainActivity.loadWithRelay()` builds the
  injected `window.__SECURE_CHAT_RELAY__` config with `org.json.JSONObject`
  (proper escaping) instead of hand-interpolating a JS string literal.
- **Finding 2 (Medium) — prefix-confusable origin check.**
  `shouldOverrideUrlLoading` now compares the parsed `request.url.scheme`/`host`
  to the app origin (`https` + `appHost`), not `startsWith(appOrigin)`, so
  `https://secure-chat.internal.evil.com/…` is correctly treated as off-origin.
- **Finding 3 (Low) — CSP corruption.** Covered by the Finding 1 host whitelist:
  the value interpolated into `csp()` can no longer contain `;`/quotes/braces.
- **Finding 4 (Low/docs) — non-unique origin.** The asset loader now calls
  `.setDomain("secure-chat.internal")`, so the app serves from
  `https://secure-chat.internal` — an origin unique to this app, not
  androidx.webkit's shared `DEFAULT_DOMAIN`. `appOrigin`/`indexUrl`/`appHost`
  in `MainActivity.kt`, `APP_WEBVIEW_ORIGIN` in `backend/config.py` (WS + CORS
  allow-lists), and the `android/README.md` doc all updated in lockstep; the
  stale config.py comment claiming the default domain uniquely identifies the
  app is corrected.
- **Informational should-fixes.** `WebView.setWebContentsDebuggingEnabled` is now
  `if (BuildConfig.DEBUG)` (added `buildConfig = true` to `build.gradle.kts`);
  `network_security_config.xml` sets `base-config cleartextTrafficPermitted=
  "false"` and scopes cleartext to a `domain-config` of `127.0.0.1`/`localhost`/
  `onion` only; `importMapHash` drift is now guarded by
  `test_android_importmap_hash_matches` in `backend/tests/test_csp_hash.py`
  (recomputes the hash from index.html, asserts the Kotlin constant matches,
  skips when android/ isn't present so the backend stays standalone-testable).
- **Tests / verification:** new `android/app/src/test/.../RelayUrlsTest.kt`
  (Robolectric, so a REAL `android.net.Uri`) — 11 tests: legit https/loopback/
  onion/trailing-slash parse correctly; the exact Finding 1 PoC payloads
  (`http://y"};window.__pwn=1;%2f%2f`, percent-encoded `%2f%2f`/`%22`, and
  literal quote/brace/semicolon/space hosts) are all rejected; plus
  scheme/credentials/path-query-fragment/empty-host rejections.
  `./gradlew testDebugUnitTest` → 11 passed, 0 failures. Debug APK still builds
  clean (`./gradlew assembleDebug` BUILD SUCCESSFUL). Backend `pytest` = **57
  passed** (was 56 + the new drift guard). Web client untouched.
- **Remaining (unchanged):** on-device re-run of the app against the new origin
  + the identity/safety-number gate for DHKE/RSA/PQKEM (needs the emulator);
  app icon + release-signing config; OTP mode; Tor `.onion` deployment.

### 2026-07-08 — Android app pentest: 1 Critical + 3 Medium/Low found (NOT yet fixed) 🔴
Live pentest of the Android app on the same emulator used for on-device
verification, following this project's usual "attack the running system, prove
it with a live PoC" methodology. All four findings below are reproduced against
the actual installed APK; none require jailbreak/root — `run-as` on a **debug**
build stood in for "an attacker gets a value into `Prefs`", which for finding 1
is realistic via the app's own Settings dialog (see reachability note).

**Finding 1 — CRITICAL — relay-address string → arbitrary JS execution,
pre-page-script, CSP-bypassing (full app compromise).**
`RelayUrls.parse()` (`RelayUrls.kt`) validates a user-supplied "relay address"
using only `android.net.Uri.parse(text)` — scheme must be http/https, host must
be non-empty, and path/query/fragment must be absent. **`android.net.Uri` does
NOT validate hostname characters.** Empirically confirmed on-device: `"`, `;`,
`{`, `}`, and space all survive verbatim in `.host`; percent-encoding decodes
into `.host` too (`%22`→`"`, `%3a`→`:`, `%2f`→`/`) *without* tripping the
path/query rejection (the raw `%XX` bytes don't look like the real delimiter
chars to the top-level splitter, so a percent-encoded `%2f%2f` becomes a
literal `//` in the decoded host that the path check never saw coming).
`MainActivity.loadWithRelay()` then string-interpolates the PARSED value,
unescaped, into a JS snippet:
```kotlin
val js = "window.__SECURE_CHAT_RELAY__ = {api:\"${relay.httpOrigin}\", ws:\"${relay.wsOrigin}/ws\"};"
```
injected via `WebViewCompat.addDocumentStartJavaScript` — a mechanism that
(by design, so it can run before any page script) is **not subject to the
page's CSP**. The same unescaped value is also interpolated into the CSP
header itself (`csp()`), but that's a secondary effect (see Finding 3) — the
PRIMARY bypass is that `addDocumentStartJavaScript` doesn't consult CSP at all.
- **PoC 1 (marker):** relay address
  `http://y"};window.__pwn=1;%2f%2f` → after Uri decoding, httpOrigin becomes
  `http://y"};window.__pwn=1;//`. Substituted into the template, `//` becomes
  a JS line-comment eating the rest of the (single-line) injected script:
  `window.__SECURE_CHAT_RELAY__ = {api:"http://y"};window.__pwn=1;//", ws:...`
  parses as three clean statements (assign the object, `;`, `window.__pwn=1;`)
  followed by a comment. **Confirmed live via CDP: `window.__pwn === 1`.**
- **PoC 2 (real impact):** same technique, payload hooks
  `crypto.subtle.importKey` before any page script runs, then the "Create
  identity" / AES256-connect flow was driven for real. **Captured the actual
  first 8 bytes of the user's typed secret**: `[115,117,112,101,114,32,115,101]`
  = ASCII `"super se"` (from the passphrase "super secret victim passphrase"),
  proving the injected code can intercept identity/passphrase key material as
  the app derives it — a full break of the app's core security property
  (client-side key custody) via its one user-configurable value.
- **Reachability:** the ONLY way `Prefs` gets a relay value is the Settings
  dialog's `RelayUrls.parse(input.text.toString())` (confirmed by reading
  `MainActivity.kt` — no other write path exists). The realistic attack is
  social engineering: an attacker hands the victim a "relay address" to paste
  (a natural ask in this app — relays are meant to be shared), and the
  malicious JS executes the moment they hit Save (`loadWithRelay(parsed)`
  fires immediately with the freshly single-pass-parsed value, no restart
  needed). Note: writing the value to `Prefs` via `run-as` (used for the PoCs,
  since driving the native dialog's EditText through `adb shell input text`
  with these characters fights two layers of shell escaping) exactly reproduces
  what a successful dialog Save persists.
- **Fix direction:** `RelayUrls.parse` must reject any host containing
  characters outside a safe hostname charset (`[A-Za-z0-9.-]`, plus `[...]` for
  literal IPv6 — or just reject IPv6 literals too, unneeded here) BEFORE
  accepting it — don't rely on `Uri` alone. Independently, stop string-building
  JSON/JS by hand: `JSONObject` (or a proper JS-string-escape helper) for the
  injected config, and construct the CSP header via a list of validated tokens
  rather than raw interpolation.

**Finding 2 — Medium — `shouldOverrideUrlLoading` origin check is
prefix-confusable (chainable off Finding 1).**
```kotlin
override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean =
    request.url.toString().startsWith(appOrigin).not()
```
`"https://appassets.androidplatform.net.evil.com/x".startsWith("https://appassets.androidplatform.net")`
is `true` — `startsWith` doesn't check for a following `/` or end-of-string.
**Live-confirmed:** ran `location.href = "https://appassets.androidplatform.net.evil.com/probe"`
via CDP inside the loaded page; `window.location.href` afterward was
`chrome-error://chromewebdata/` — a real failed-navigation page, proving the
WebView actually attempted to load the attacker-suffixed host (only failing
because that specific fake domain doesn't resolve in DNS; a real
attacker-owned domain would succeed). On its own this needs a script already
running to trigger `location.href` — but Finding 1 supplies exactly that,
so the two chain into "malicious relay string → JS execution → silent
top-level navigation to an attacker page" as a single attack. Fix: compare
`Uri.parse(request.url.toString()).host == "appassets.androidplatform.net"`
(and scheme), not string-prefix matching.

**Finding 3 — Low/robustness — the same unescaped relay value corrupts the CSP
header.** `csp()` also interpolates `relay.httpOrigin`/`wsOrigin` unescaped
into the `Content-Security-Policy` header value. A payload containing `;`
splits it into bogus extra "directives" (confirmed via WebView console:
`"The Content-Security-Policy directive name 'window.__pwn=1' contains one or
more invalid characters"` etc.) — Chromium safely rejects the malformed
directives, so this isn't itself an escape (script-src, set BEFORE
connect-src in the string, is unaffected), but it can silently swallow the
directives that come AFTER connect-src in the source (`img-src`, `base-uri`,
`form-action`, `frame-ancestors`) if enough injected `;` shift the boundary,
and/or break the app's OWN legitimate relay connection (connect-src ends up
with no valid entries but `'self'`). Same fix as Finding 1 covers this too.

**Finding 4 — Low/docs — `https://appassets.androidplatform.net` is
`androidx.webkit`'s shared default domain, not unique to this app.**
Verified directly from the library bytecode (`WebViewAssetLoader.class`):
`public static final String DEFAULT_DOMAIN = "appassets.androidplatform.net"`,
and `MainActivity.kt` never calls `.setDomain(...)`, so it uses this literal
default. **Any other Android app** using `WebViewAssetLoader` with default
settings presents an identical `Origin` header. `backend/config.py`'s comment
on `APP_WEBVIEW_ORIGIN` — *"a single fixed value, not a wildcard, so
allow-listing it does not open the relay to arbitrary web pages"* — is
therefore not accurate: it doesn't uniquely gate "our app". **Impact is
bounded, not ignored:** CORS only restricts browser/WebView-enforced
`fetch()`; any native Android code could already hit `/api` with a raw HTTP
client with no CORS involved at all, and `/api` is designed to expose nothing
sensitive to an unauthenticated caller (token-gated lookup, signature-verified
registration, no existence oracles — see the I1 closeout). So this doesn't
grant a new capability, but the code comment's claim is false and should be
corrected; fix by calling `.setDomain("secure-chat.internal")` (or similar) to
make the origin genuinely unique, which closes the gap outright.

**Verified negative (no finding):** `WebViewAssetLoader`'s `AssetsPathHandler`
correctly rejects path traversal — tried literal `../`, `%2e%2e/`, `..%2f`,
and `....//` variants against `/assets/web/...`; all either hard-failed
("Failed to fetch") or cleanly 404'd, no content outside `assets/web/` leaked,
while the legitimate `index.html` fetch succeeded normally. Also noted but not
separately itemized (pre-existing, informational): `setWebContentsDebuggingEnabled(true)`
is unconditional (not gated to debug builds — should be `if (BuildConfig.DEBUG)`
before a release build ships); `network_security_config.xml`'s
`cleartextTrafficPermitted="true"` is unscoped (any domain, not just
loopback/.onion) though the Mixed-Content browser check is the actual gate in
practice; `importMapHash` in `MainActivity.kt` is a hardcoded duplicate of the
backend's value with no automated drift guard analogous to
`backend/tests/test_csp_hash.py` (fails closed if it drifts — app breaks
loudly rather than a security hole, but worth a guard).

**Not yet fixed** — all four are on the TODO list below. Diagnostic code used
to characterize `Uri.parse` behavior was added temporarily to
`MainActivity.onCreate` during testing and fully reverted (`git diff` clean
afterward); the device's `Prefs` was reset to a benign
`http://127.0.0.1:8000` relay before finishing.

### 2026-07-08 — Android app verified ON-DEVICE + Mixed-Content fix ✅
Installed the emulator (Android 14 `google_apis;x86_64`, KVM-accelerated) and
ran the app on a real WebView. Findings + fixes:
- **Works on-device.** App installs, renders the full UI in the WebView, and the
  relay config is injected before page scripts (`addDocumentStartJavaScript`
  works on WebView 113). Drove the real app via Chrome DevTools Protocol (over
  the adb-forwarded devtools socket) against a host-side AES256 peer through the
  relay: the on-device WebSocket reached the relay, the AES256 nonce exchange
  completed, and messages decrypted BOTH directions on the device.
- **Real bug found: Mixed-Content transport constraint.** The client page is a
  secure origin (https asset loader — required for `crypto.subtle`), so the
  browser blocks opening an INSECURE `ws://` from it. `ws://10.0.2.2:8000` was
  refused with a SecurityError; the relay must be a *potentially-trustworthy*
  origin — **wss://** (TLS), **loopback** (`127.0.0.1`/`localhost`), or a
  **.onion**. This corrected a wrong doc claim (a plain `http://192.168.x.x`
  LAN relay does NOT work). Emulator test uses `adb reverse tcp:8000 tcp:8000`
  + relay `http://127.0.0.1:8000` (loopback is Mixed-Content-exempt).
- **Fix (`client/app.js`):** `new WebSocket()` throws synchronously on the
  Mixed-Content block, which previously left the UI stuck on "connecting…"
  forever. Now wrapped in try/catch → status "connection blocked" + an
  actionable hint (needs wss/loopback/.onion) + Connect re-enabled. Verified
  on-device: pointing at `http://192.168.50.50:8000` shows the clear error
  instead of hanging. (Web client unaffected — it is same-origin, never
  Mixed-Content.)
- **Docs corrected:** relay-settings dialog text, `network_security_config`
  comment, and `android/README.md` now state the trusted-transport requirement.
- **Regression:** offline `npm test`, all 3 live suites, backend `pytest` 56 —
  all green after the app.js change. APK rebuilt + reinstalled; on-device happy
  path re-passed.
- Remaining app polish: icon, release-signing config, and an on-device pass of
  the identity + safety-number gate (only AES256 driven on-device; DHKE/RSA/
  PQKEM handshakes are covered in-browser).

### 2026-07-07 — Android app: WebView shell bundling the audited client ✅
New `android/` Gradle module. Rationale: the web deployment's one honest trust
gap (H1) is that a browser re-fetches the JS from the server each load, so a
compromised server could serve malicious crypto. The app removes that by
shipping the exact reviewed client INSIDE the APK and using the relay only as a
dumb ciphertext carrier.
- **Design (thin shell, one codebase):** `MainActivity` serves bundled
  `assets/web/` to a WebView from the local secure origin
  `https://appassets.androidplatform.net` (WebViewAssetLoader — secure context,
  so `crypto.subtle` works). The relay is remote, so the app supplies what the
  same-origin web build got for free: (1) the relay location, injected as
  `window.__SECURE_CHAT_RELAY__ = {api, ws}` via `addDocumentStartJavaScript`
  BEFORE any page script; (2) the CSP, stamped as a response header on
  index.html with `connect-src` pinned to exactly the configured relay origin.
  The relay address is entered once (menu → Relay settings), stored in
  SharedPreferences, validated to an http(s) origin (`RelayUrls`). Identity/pins
  stay in the WebView localStorage as on the web.
- **Client change (backward-compatible, keeps ONE codebase):** `app.js` reads
  `window.__SECURE_CHAT_RELAY__` for the ws URL + API base if present, else the
  original same-origin behavior (RELAY null path). Web behavior byte-identical;
  verified by re-running the same-origin 4-mode browser matrix + all 3 live
  suites green.
- **Backend change (deliberate, documented):** the app's origin differs from
  the relay's, so `APP_WEBVIEW_ORIGIN` (`https://appassets.androidplatform.net`)
  is added to `ALLOWED_WS_ORIGINS` (else the relay 1008-rejects the WS) and to a
  new `/api` CORS allow-list (`ALLOWED_HTTP_ORIGINS`, methods GET/POST, no
  credentials — endpoints carry no cookies, only explicit Bearer tokens). It is
  one fixed origin, not a wildcard. New `SECURE_CHAT_EXTRA_ORIGINS` env var adds
  more origins (e.g. the prod `.onion`) at deploy time without editing code.
  Backend `pytest` still 56 passed.
- **Bundle = single source of truth:** the `syncWebClient` Gradle task copies
  `../client` into `assets/web` at build time (excludes tests/manifests), so the
  APK can never drift from the reviewed client; the copy is gitignored.
- **Build:** needs a full JDK 21 *with jlink* (the distro's openjdk-21 here was
  JRE-only — used a self-contained Temurin 21) + Android SDK platform-34 /
  build-tools-34. `./gradlew assembleDebug` → 5.7 MB debug APK,
  `org.securechat.app`, minSdk 26 / target 34. Clean build from source verified
  (assets auto-synced, 21 web files packaged).
- **Verified (real browser, Chromium/puppeteer — the WebView IS Chromium):**
  reproduced the app's exact cross-origin setup (bundled client on origin A,
  relay on origin B, relay config injected before scripts, app CSP applied):
  relay config visible to the page; cross-origin `/api` register succeeded
  (CORS); cross-origin WS DHKE handshake with MATCHING safety numbers; two-way
  messages delivered. This exercises the whole app code path except the Kotlin
  glue (asset loader / document-start injection / menu), which compiles +
  packages but is **NOT yet run on a device/emulator** (none in the build env).
  On-device smoke test is the remaining step.

### 2026-07-07 — DHKE/PQKEM in-session FS + reflection guards (ratchet unification) ✅
Closed the main informational finding from the same-day review (below): DHKE
and PQKEM kept one static AES-GCM session key (`AuthChannel`), so state
compromise mid-session decrypted that entire session. Now ALL FOUR modes run
the same forward-secret `RatchetChannel`; `AuthChannel` is DELETED.
- **DHKE (`crypto.js`):** the ECDH secret is HKDF'd into two direction-
  separated chain heads (info binds each chain to its sender's raw pub, salt =
  room id, domain `secure-chat/dhke-fs/v1`); frames are `dhke-msg/v2`. Exactly
  one derivation ever happens (first key wins), so the ECDH private key is
  dropped the moment the chains exist — in-session FS from the first message.
  `myPub` is cached at init so a (replayed-offer) `handshakePayload()` still
  answers after the keypair is gone.
- **PQKEM (`crypto.js`):** same chains rooted in the hybrid ECDH+ML-KEM ikm
  (info binds the sender's ECDH pub, domain `secure-chat/pqkem-fs/v1`); frames
  are `pqkem-msg/v2`. Seals like RSA on first real traffic (`_seal` zeroes the
  KEM secret key + raw shared secrets, drops the ECDH keypair; post-seal
  handshake frames ignored) — the race path may deliver a second root secret
  until then, and messaging sits behind the safety-number gate so the race has
  settled by first traffic. `ecdhBits`/`ikm` intermediates are zeroed right
  after HKDF import (they weren't before; DHKE's too).
- **Reflection guards (all handshake modes + hello):** an offer/answer carrying
  OUR OWN public key (DHKE pub / RSA pub / PQKEM ECDH or KEM pub) is refused
  outright — never legitimate, and identical pubs would collapse the direction
  separation of the chains. Previously only the human safety-number comparison
  caught a relay echoing someone's own identity back. Likewise app.js now
  refuses a hello carrying OUR OWN nonce (a reflected hello used to wedge the
  handshake via first-write-wins; now the slot stays open for the real peer).
- **Wire format:** DHKE/PQKEM `msg` frames changed (`{iv,ct,n}` ratchet frames
  under new domains; the old `secure-chat/msg/v1` AuthChannel framing is gone).
  Handshake payloads unchanged. Both ends always run the same served code, so
  no compatibility shim.
- **Tests:** new `handshakeRatchetChecks` in `crypto.test.mjs` — DHKE keypair
  dropped at derivation; PQKEM material held until traffic then sealed on
  first encrypt AND first decrypt; skipped-frame keys unrecoverable (both);
  replayed offers ignored post-establishment/post-seal; reflected handshakes
  rejected (DHKE/PQKEM/RSA). Existing reflection/replay/tamper + concurrency
  checks now exercise `RatchetChannel` in all 4 modes.
- **Verified:** client offline `npm test` green; backend pytest 56 passed; all
  3 live integration suites green; real-browser matrix (Chromium/puppeteer,
  two isolated contexts per mode) green for ALL 4 MODES — identities, matching
  safety numbers, two-way traffic, zero undecryptable/dropped frames — plus
  the double-click regression; server log still 0 bytes after all traffic.
- Deliberately NOT fixed (still informational): backend token-lookup timing
  (256-bit random tokens), relay per-peer send stall, verify-panel replay
  cosmetics. Post-compromise recovery (DH ratchet) remains out of scope.

### 2026-07-07 — final crypto review + full verification matrix ✅
White-box review of the whole client crypto stack (crypto.js, auth.js,
identity.js, account.js, app.js flow) + backend front door (validation.py,
relay.py, accounts.py, main.py). **No new High/Medium findings.** Verified
green across the board: client offline `npm test` (32 OK), backend `pytest`
56 passed, all 3 live integration suites, real-browser matrix
(Chromium/puppeteer, two isolated contexts per mode): ALL 4 MODES end-to-end —
identity creation, staggered join, matching safety numbers (handshake modes),
4 two-way messages, zero undecryptable/dropped frames — plus the double-click
regression check; server log EMPTY after all traffic (I2 holds).
Informational notes (as found; the first three were FIXED the same day — see
the ratchet-unification entry above):
- **DHKE/PQKEM have no in-session FS** — CLOSED same day (all modes now run
  `RatchetChannel`; `AuthChannel` deleted).
- Key-material hygiene (`ecdhBits`/`ikm` not zeroed) — CLOSED same day.
- A relay reflecting a peer's OWN hello back wedged the handshake until
  reconnect — CLOSED same day (reflected hello + reflected handshake keys now
  refused in all modes).
- A relay replaying a signed offer FROM THE CURRENT session verifies (same
  nonces) and can re-trigger `enterVerification` — ciphers are idempotent so
  no desync; worst case a duplicate sys line / re-shown verify panel (pin
  short-circuits it after first confirm). Cosmetic; left as is.
- Backend nits (left as is): bearer-token dict lookup isn't constant-time
  (256-bit random tokens — negligible); relay fan-out send has no per-peer
  timeout (a stalled peer only stalls its own room's sender).

### 2026-07-07 — cipher-call serialization: both 2026-07-03 pentest races CLOSED ✅
Fixed the two open concurrency findings (High + Medium) in one change; shared
root cause was that `AuthChannel`/`RatchetChannel` update their anti-replay
state (sequence counters, chain heads) across awaited WebCrypto calls while
their callers don't serialize (`ws.onmessage` fires handlers back-to-back; the
UI could fire overlapping sends).
- **Fix (`client/crypto.js`):** new `CallQueue` — a per-channel FIFO promise
  queue; both channel classes now route the public `encrypt()`/`decrypt()`
  through it into the (renamed) `_encrypt`/`_decrypt`. One call runs at a time,
  in arrival order; a rejected call propagates to its caller but never blocks
  the queue. Covers all 4 modes (AES256/RSA via `RatchetChannel`, DHKE/PQKEM
  via `AuthChannel`) with no wire-format or interface change.
  - Kills the **High** (racing decrypts of already-observed frames could
    commit out of order, roll the replay counter back, and re-accept a message
    the user already saw) and the **Medium** (two overlapping encrypts read the
    same chain head, consumed the same one-time key, and permanently desynced
    the ratchet — the peer saw an undecryptable frame and all later messages
    silently vanished).
- **Defense in depth (`client/app.js`):** `sendText` now has a `sending`
  in-flight flag and disables the Send button while an encrypt is pending
  (re-enabled only if the gate still allows messaging), so a double-click /
  Enter-repeat can't even queue a duplicate send. A disabled default submit
  button also blocks implicit (Enter) form submission per spec.
- **Tests (`crypto.test.mjs`, new `concurrencyChecks`, run for all 4 modes):**
  overlapping unawaited encrypts → both frames decrypt + channel intact after;
  3 concurrent decrypts of the SAME frame → accepted exactly once; the exact
  pentest rollback scenario (two different frames delivered concurrently, then
  both replayed) → both replays rejected. Confirmed the suite CATCHES the bug:
  against the pre-fix `crypto.js` (git stash) it fails at the overlapping-
  encrypt check with the ratchet-desync AEAD failure.
- **Verified:** client offline `npm test` green; backend `pytest` 56 passed;
  all 3 live integration suites green; **real-browser regression check**
  (Chromium/puppeteer, two isolated contexts, AES256): Alice double-clicks
  Send in the same tick → message delivered exactly once, zero undecryptable
  frames, ordinary follow-up messages flow both directions afterwards (the
  pre-fix behavior was a corrupted second frame and a permanently dead channel).

### 2026-07-03 — AES256 ratchet: cross-session replay CLOSED + honest FS ✅
Second half of TODO item (d), building directly on the RSA ratchet (below).
- **Refactor first:** RSA's ratchet framing was extracted into a shared
  `RatchetChannel` (`client/crypto.js`): direction-separated one-way
  HMAC-SHA-256 chains, one-time AES-256-GCM message keys, strictly increasing
  `n`, skip-with-discard bounded by `RATCHET_MAX_SKIP=1024`, scratch-head
  stepping committed only after AEAD success. `Rsa` now delegates to it
  (unchanged wire format/behavior, all RSA FS tests still green); `AuthChannel`
  now serves only DHKE/PQKEM.
- **AES256 redesign.** The mode still puts NO key material on the wire, but the
  ratchet chains are no longer derived from the passphrase alone: on join both
  peers exchange fresh random 32-byte session nonces via the app's existing
  plaintext `hello` phase (previously handshake-modes-only; AES256 has no
  identity requirement, so its hello is unauthenticated — tampering only
  desyncs keys, a loud DoS the relay could always cause). Chains =
  HKDF(PBKDF2-600k(passphrase), salt = room|sorted-nonces, info =
  `secure-chat/aes-fs/v1|` + sender's nonce); frames are `aes-msg/v2`.
  **Your own nonce is fresh and never attacker-controlled, so a frame captured
  in an earlier session (same room + passphrase) can never authenticate in a
  new one — the documented AES256 cross-session-replay residual is CLOSED**
  (relay-forced replay of an old peer nonce just desyncs loudly; it cannot make
  the victim re-derive an old key). Erasure: the cipher's passphrase copy is
  dropped at `init()`, the derived HKDF base right after chain derivation.
- **Honest FS limit (documented in README + KNOWN LIMITATIONS):** captured
  ratchet STATE can't decrypt earlier traffic, but the passphrase is a
  long-term secret outside the code and the nonces are public — passphrase
  compromise + recorded ciphertext still re-derives every session. Inherent to
  passphrase-only; real FS = DHKE/PQKEM/RSA.
- **app.js:** the hello phase now runs for every mode (`joined` sends it
  unconditionally); on hello, AES256 (`cipher.usesNonces`) derives via
  `cipher.setNonces(myNonce, peerNonce)` and unlocks (the passphrase is the
  out-of-band verification — no identity gate, as before, but send/receive now
  unlock only after the peer joins). A phase-2 signed-handshake frame arriving
  in AES256 mode is refused (`!cipher.needsHandshake` guard) — it could only be
  relay-injected.
- **Tests:** `crypto.test.mjs` — AES256 paths now exchange nonces; new
  `aesRatchetChecks`: **cross-session replay REJECTED** (fresh-receiver variant
  too, so it's the key, not the counter, doing the rejecting), passphrase/base
  erasure, skipped-frame-unrecoverable. `integration.test.mjs` harness speaks
  the AES256 hello. All offline suites green; all 3 live integration suites
  green; backend pytest 56 passed. **Verified in a real browser**
  (Chromium/puppeteer, two contexts): send locked before the peer joins,
  unlocks after the nonce exchange, 5 messages both directions, zero
  dropped/undecryptable frames; RSA browser check re-run green (regression, since
  the joined/hello path changed for all modes).

### 2026-07-03 — RSA mode: forward secrecy (key transport + one-way ratchet) ✅
Closed TODO item (d) for RSA. Previously every RSA message's AES key was
RSA-OAEP-wrapped to the peer's session-long RSA key, and the HMAC root secret +
RSA private key lived for the whole session — so state compromise at any point
(or later, with a recorded transcript) decrypted the ENTIRE session. That
per-message wrapping was inherently incompatible with forward secrecy and was
removed.
- **New design (`client/crypto.js`, Rsa class).** The handshake is unchanged on
  the wire (offer `{pub}`, answer `{pub, ws}` with the OAEP-wrapped 32-byte
  root secret; race-tolerant sorted-tag folding; first-write-wins). From the
  root, HKDF derives two direction-separated **HMAC-SHA-256 chain keys** (info
  binds the sender's pub, salt = room id, domain `secure-chat/rsa-fs/v1`). Each
  message uses a **one-time AES-256-GCM key**: `msgKey = HMAC(chain, 0x01)`,
  then `chain = HMAC(chain, 0x02)` — one-way, consumed keys erased (raw bytes
  zeroed after import, keys non-extractable). Frames are `{iv, ct, n}` with AD
  `secure-chat/rsa-msg/v2|room|n` (v1 frames are thus invalid). A gap in `n`
  fast-forwards the chain and DISCARDS the skipped keys (bounded by
  `RSA_MAX_SKIP=1024` against hostile-relay CPU burn); the receive step is
  committed only after the AEAD authenticates, so a garbage frame can't wedge
  the channel or burn keys.
- **Sealing.** On the first real message (either direction) `_seal()` erases
  the root secrets AND drops the RSA private key (+ peer wrap key) — the two
  things that could replay the whole key schedule from a recorded transcript.
  Post-seal handshake frames are ignored (a replayed offer can't desync or
  resurrect state). Sealing at first traffic is safe because messaging sits
  behind the safety-number gate, seconds after the handshake settles; a relay
  withholding a race answer past that point could only cause a loud decrypt
  failure (= DoS it could do anyway). Same documented race window as PQKEM.
- **Properties:** forgery still fails (relay never learns the root → no valid
  AEAD); reflection fails (direction chains); replay fails (strictly increasing
  `n` + one-time keys); **in-session forward secrecy** (state at time T can't
  decrypt before T); cross-session FS was already given by per-session RSA keys.
  NOT provided (out of scope): post-compromise/break-in recovery — that needs a
  DH-style ratchet, pointless to fake with RSA.
- **Tests:** `crypto.test.mjs` — `rsaAttackChecks` updated (forgery/reflection/
  replay/tamper still rejected; + channel survives a rejected frame). New
  `rsaForwardSecrecyChecks`: seal erases kp/secrets on first send AND first
  receive; skipped frame's key unrecoverable while later frames decrypt;
  post-seal replayed offer ignored; far-future `n` rejected. All offline suites
  green; all 3 live integration suites green; backend pytest 56 passed.
  **Verified in a real browser** (Chromium/puppeteer, two isolated contexts):
  RSA staggered join, matching safety numbers, 5 messages both directions
  (ratchet advancing), zero dropped/undecryptable frames.
- app.js unchanged except a comment (generic cipher interface held); README
  encryption-modes table + RSA paragraph rewritten.

### 2026-07-02 — L2/I2 closeout: metadata-at-rest disabled + room-id guarantee ✅
Closed the last two accepted-risk items from the 2026-06-19 review.
- **I2 — no request/connection metadata at rest (code fix).** Uvicorn's access
  log wrote every request line (method/path/status/timing) and its error logger
  emitted INFO connection-lifecycle lines ("connection open/closed") — a
  who-connected-when trail if a `.onion` host is seized. `main.py` now disables
  the access logger and lifts `uvicorn.error` to WARNING at import
  (`_minimize_log_metadata`), the `__main__`/`uvicorn.run` path passes
  `access_log=False, log_level="warning"`, and `run.sh` carries
  `--no-access-log --log-level warning`. Verified live: after healthz + `/api`
  + a full WebSocket relay round-trip, the server log is EMPTY. Only genuine
  error tracebacks (never payloads/room ids) are ever logged. Guard test
  `tests/test_logging.py` (access logger disabled, error logger ≥ WARNING,
  run.sh keeps the flags) fails loudly on regression.
- **I2 does NOT change behavior** — purely removes logging; all suites still green.
- **L2 — room-id bearer-capability risk: closed as a documented bounded
  guarantee (no code change).** A room is joined by knowing its 256-bit id; the
  relay is deliberately anonymous (no joiner auth) to keep who-talks-to-whom off
  the server. A mechanism "fix" (relay-side admission control) would require
  binding identities to the relay and recording exactly that metadata — a net
  loss for the primary threat model. The impact of a leaked room id is already
  bounded to **availability + coarse metadata, never confidentiality or
  impersonation**: the relay forwards only opaque ciphertext, and the
  authenticated + safety-number-gated handshake stops a squatter posing as the
  real contact (AES256's unsent passphrase is its gate). Structural mitigations
  already in place: room ids are high-entropy (256-bit) and single-use/rotatable
  — treat one like a one-time secret. Documented precisely in README
  ("Metadata & residual risks") and the relay/threat notes.
- Backend `pytest` = **56 passed** (+3 logging guards).

### 2026-07-02 — accepted-risk closeout: L1 (PQ ownership proof) + I1 (enumeration) ✅
Closed the two accepted-risk items from the 2026-06-19 security review.
- **L1 — server-side ML-DSA-65 ownership proof at registration.** Registration
  now requires a dual signature over the bundle: the server verifies BOTH the
  Ed25519 proof (as before, via `cryptography`) AND an ML-DSA-65 proof (new,
  via `dilithium-py` — a pure-Python verifier, cross-checked against the
  client's `@noble/post-quantum` signer). A registrant can no longer bind a PQ
  public key they don't control. `RegisterReq` gains `mldsa_sig`; `account.js`
  now signs the register message with `identity.sign()` (dual) instead of
  `signEd()`. New dep: `dilithium-py==1.4.*` (verify only; the server is still
  not the authenticity root — the in-person safety number is).
- **I1 — username namespace made non-enumerable (token-gated lookup + oracle
  removal).** Registration mints a random per-account lookup token
  (`config.LOOKUP_TOKEN_BYTES=18`, ~144 bits); the shareable identifier is now
  the HANDLE `username#token`. `GET /api/users/{name}?t=<token>` returns an
  IDENTICAL 404 for a missing user OR a wrong token (constant-time compare
  against a decoy for missing users), so a bare/guessed username reveals
  nothing. `POST /api/auth/challenge` now issues a challenge for ANY well-formed
  username (no existence 404) and `POST /api/auth/verify` returns 401 for
  unknown-user and bad-sig alike — neither is an existence oracle anymore. A
  dedicated stricter per-host rate limit (`_lookup_limiter`) bounds the lookup
  path. Client: `account.parseHandle`, handle-based `fetchBundle`, register
  stores + displays the handle, the contact field takes a handle. Residual
  (documented, inherent): registering a taken name still 409s — but each probe
  costs a full dual-signed proof and is rate-limited, and enumeration of the
  bundle-fetch path is closed.
- **DB:** `accounts` table gains `lookup_token` (with an ALTER-based migration
  for pre-token DBs).
- **Tests:** `test_accounts.py` rewritten to sign with real ML-DSA (dilithium)
  and cover the new behavior: bad-PQ-sig rejection, missing `mldsa_sig`,
  token-gated lookup (no/wrong token → 404), challenge-doesn't-reveal-existence,
  verify-unknown-user-is-401, and a dedicated lookup rate-limit test. Backend
  `pytest` = **53 passed**. `accounts.integration.test.mjs` updated for the
  handle flow (incl. wrong-token → null). Verified in a real browser
  (Chromium/puppeteer): Alice registers → handle shown; Bob's WRONG token fails
  to resolve; Bob's correct handle → directory lookup, matching safety number,
  message delivered. All offline + live suites green.

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
- Message payloads never logged; no stack traces leaked to clients. Access log
  + connection-lifecycle logging disabled (I2) — no request/timing metadata at
  rest; only content-free error tracebacks are recorded.
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
- **AES256 forward secrecy is honest-but-limited (2026-07-03).** AES256 now
  ratchets too (one-time message keys; passphrase copy + derived base erased
  after chain derivation), and its session chains bind BOTH peers' fresh
  session nonces — so captured ratchet STATE can't decrypt earlier traffic and
  cross-session replay is closed. But the passphrase itself is a long-term
  secret outside the code (user's head, input field) and the nonces cross the
  relay in the clear: passphrase compromise + recorded ciphertext still
  decrypts every session, past and future. Inherent to a passphrase-only mode;
  real FS = DHKE/PQKEM/RSA — all three ratchet per message AND erase their
  handshake material (RSA/PQKEM seal on first traffic, DHKE drops its private
  key at derivation; since 2026-07-03/2026-07-07), on top of per-session
  ephemeral keys.
- **AES256 passphrase is offline-attackable by the relay.** The room id (which
  the relay routes on, so it always knows it) is the PBKDF2 salt, and the relay
  sees the ciphertext — so a malicious/compromised relay can mount an offline
  dictionary attack on the passphrase. 600k PBKDF2 iterations slow this, but a
  low-entropy passphrase will fall: AES256 security rests entirely on passphrase
  strength. Prefer a generated high-entropy passphrase, or use DHKE/PQKEM.
- **Reflection/replay — CLOSED for all modes, incl. cross-session
  (2026-07-02, completed 2026-07-03; unified 2026-07-07).** ALL FOUR modes now
  use the same `RatchetChannel`: direction-separated one-way chains + one-time
  message keys + strictly increasing sequence numbers. Reflected handshake
  keys and reflected hellos are additionally refused outright (2026-07-07).
  The old AES256 residual — cross-session replay of a frame captured under the
  same passphrase + room id — is CLOSED since 2026-07-03: the session chains
  bind a fresh random nonce from BOTH peers, so an old frame can never
  authenticate in a new session. DHKE/PQKEM are ephemeral per session and
  never had the residual.
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
  **UPDATE 2026-07-02 (second session): ALL FOUR now CLOSED** — L1/I1 in the
  "accepted-risk closeout" entry; L2 (documented bounded guarantee) and I2
  (access/connection logging disabled) in the "L2/I2 closeout" entry below.

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

### 2026-07-02 — cross-session handshake replay CLOSED (session nonces, transcript v2) ✅
- **Finding (2026-07-02 pentest, Medium):** the signed handshake transcript
  (`DOMAIN || roomId || ephemeralPayload`) had no per-connection freshness, so
  a relay could replay a peer's validly-signed handshake from an OLD session
  into a NEW session reusing the same room id → silent key desync with a
  misleading "verified" UI (integrity/availability, not confidentiality).
- **Fix (`client/auth.js` + `client/app.js`):** transcript bumped to
  `secure-chat/handshake/v2` and now covers a fresh random 32-byte nonce from
  BOTH peers' current connections. New plaintext `hello` phase inside the `key`
  message (`{hello:true, n, reply}`): each peer announces its nonce on join;
  the receiver of a reply:false hello answers once (reply:true) and then sends
  the signed offer; the signed answer flows as before. Nonces are folded
  order-independently (sort b64, concat bytes) so both sides sign/verify the
  same transcript regardless of direction; peer nonce is first-write-wins.
  Hellos are unauthenticated in flight but authenticated retroactively by the
  signature that covers them — tampering only makes the handshake fail loudly
  (a relay could always DoS). A stale signed handshake can never cover the
  nonce the victim generated THIS connection → signature verification fails
  instead of desyncing. The domain bump alone also invalidates all pre-v2
  captured handshakes. Note the offer direction reversed in the staggered-join
  case (the EARLY joiner now sends the first signed offer, since it learns both
  nonces first); the ciphers' symmetric/race-tolerant design is direction-
  agnostic, and the simultaneous-join race path is unchanged (dual offer +
  dual answer, idempotent onPeerKey).
- **Tests:** `identity.test.mjs` — new cross-session-replay rejection suite
  (stale sig vs fresh nonce REJECTED, fresh-pair REJECTED, genuine ACCEPTED,
  nonce-order independence). `auth.integration.test.mjs` — peers speak the new
  hello+offer/answer protocol, PLUS a live PoC regression: session 1 captured
  through the real relay, its validly-signed handshake replayed by a Mallory
  client into session 2 (same room) → REJECTED. Verified in a real browser
  (Chromium/puppeteer): two isolated contexts, DHKE staggered join, identical
  safety numbers, two-way messages. All suites green: client `npm test`, all 3
  live integration suites, backend `pytest` 48 passed.

## TODO / NEXT (suggested order)

### ✅ DONE (2026-07-25): redesign stage 2 — hierarchy pass
**SHIPPED (built + verified; deploy/APK pending) — see the top snapshot.**
Dual type stack, button tiers, restructured Profile, drawer head/foot, empty
states, trust legend, global `[hidden]` fix. Stage 1 fixed tokens; this fixed
hierarchy. If a stage 3 is ever wanted, the remaining candidates are: the
Live-room 3-step flow as a real progress affordance (it's still a text line),
a mobile bottom-nav instead of the drawer, and the OTP panel (still the
densest, least-designed surface in the app).

### ✅ DONE (2026-07-19): cosmetic polish pass ("make it look less cheap")
**SHIPPED — see the 2026-07-19 snapshot at the top** (built + verified;
deploy/APK were run by hand due to session permissions). Original spec below.

### (original spec, 2026-07-18, user-requested): cosmetic polish pass
User wants the web client + app to look **more polished while KEEPING the
existing design language** (dark GitHub-ish palette, monospace, panel cards).
Explicit ask: **remove the emojis from the drawer menu** — they make it look
cheap. This is presentation-only: no crypto, no logic changes, no new runtime
deps.

**Hard constraints (these rule out the usual redesign tools — do NOT fight them):**
- **Strict CSP:** `style-src 'self'` + no `unsafe-inline`, `default-src 'none'`.
  No inline styles, no CDN, no external stylesheets. **Web fonts are blocked**
  (font-src falls back to `'none'`) unless you add `font-src 'self'` to the CSP
  in BOTH `backend/main.py` and `android/.../MainActivity.kt` AND vendor a
  woff2 — treat a custom typeface as a *separate, security-relevant* change, not
  part of this pass. Default to a refined system stack instead.
- **No build step / vanilla JS, security-audited:** do it as a **hand-written
  CSS token refresh in `client/style.css`** (it already uses CSS custom
  properties — `--bg/--panel/--fg/--muted/--accent/--ok/--err/--border`). NO
  framework, NO Tailwind/CDN. Keep JS `textContent`-only.
- **Bundled into the Android WebView** via gradle `syncWebClient` — whatever you
  ship in `client/` must stay self-contained.
- **Do NOT touch the `<script type="importmap">` line in index.html** — its text
  is pinned by the CSP hash (`test_csp_hash.py`); changing it means regenerating
  the hash in two files. A pure style pass shouldn't need to.

**Do:**
1. **Remove drawer emojis** — `client/index.html:18–21` (`👤 Profile / 🔒 Live
   room / 👥 Users / 💬 Chats`). Prefer **subtle monochrome inline SVG icons**
   (inline SVG is CSP-safe; `img-src 'self' data:` also allows data-URIs) for a
   polished look; plain text labels are the safe fallback. **KEEP** the `☰`
   menu button (standard) and the **functional trust-mark glyphs 🟢🟡⚪** in the
   Users/Chats views (they're documented security UX, not decoration).
2. **Token refresh in `style.css`:** introduce a small design-token layer on top
   of the existing vars — a spacing scale, consistent radii, a real type scale
   (sizes/weights/letter-spacing on labels + `.step`), soft elevation/shadow for
   `.panel` and the drawer, and refined **hover/active/focus-visible** states on
   `.navitem`, `button`, `input/select`, `.alg-card`. Tighten the palette
   (subtle surface layering panel-vs-bg, gentler borders) WITHOUT changing the
   hue language. Polish the chat bubbles, `.safety` block, `.myhandle`,
   `.profile-qr`, badges. Keep the mobile `@media (max-width:600px)` behavior.
3. Keep everything responsive + theme-consistent; no horizontal overflow.

**Optional first step:** prototype 1–2 directions in a **Claude Artifact**
(self-contained, already CSP-shaped) so the user can eyeball before porting into
`style.css`.

**Verify + ship:** puppeteer harness in `scratchpad/verify-sc` (reuse
`profile-flow.mjs` / `h01-flow.mjs`) — confirm every view renders, the menu has
NO emoji, nothing overflows, all flows still work; screenshot a couple of views.
Then **deploy: rsync ONLY `client/`** to the box (backend untouched → no
`chown`/restart needed, static files serve immediately; importmap untouched → no
CSP-hash change). Rebuild the APK (`JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
./gradlew assembleDebug`, `syncWebClient` copies the client) and `adb install
-r`. Backend `test_csp_hash.py` must still pass. Commit + push; update this file.


### ✅ DONE (2026-07-18): Profile tab in the left drawer
**SHIPPED — see the "Profile tab shipped" snapshot at the top.** Built with ALL
the suggested additions (QR, key details, status line, identity actions,
saved-users count). What follows is the original spec, kept for reference.

Add a **👤 Profile** view to the drawer menu (alongside Live room / Users /
Chats — probably first) that shows the user's OWN data in one place. Read-only
display of what's already in memory when the identity is unlocked; no new crypto.

**Must show (user-specified):**
- **Name** — the registered username (`sc.username.v1`), or "not registered yet".
- **Handle** — `username#token` with the **Copy handle** + **Copy invite link**
  buttons (reuse `myHandle()` / `inviteLink()` / the copy wiring already built
  for the Users view — factor them out so both views share one implementation).
- **Fingerprint** — the identity fingerprint (`identity.fingerprint()`), the same
  string contacts verify in person. Show it prominently.

**Suggested additions (my picks — confirm before building):**
- **QR code of the invite link** — the natural in-person exchange (a contact
  scans it to add you). Needs a tiny self-contained QR generator; keep it inline
  (no CDN — CSP forbids external scripts).
- **Key details** — the algorithms (Ed25519 + ML-DSA-65 signing; ECDH P-256 +
  ML-KEM-768 encryption) and maybe the short public-key fingerprints, so a
  curious/technical user can see what's protecting them.
- **Status line** — identity unlocked? registered? logged in (mailbox reachable)?
- **Identity actions** — surface the existing **Copy backup** (export) and
  **Forget identity** here too (currently only on the Live-room identity screen),
  since a "Profile" page is where users will look for them.
- **Counts** — e.g. "N saved users" (from `contacts.list()`), for a quick sense
  of state. Optional.

**Locked/unlocked:** when the identity is locked, show a "unlock in the Live room
first" hint (same pattern as Users/Chats). No data is available before unlock.

**Security note:** this is presentation-only — it displays existing local state,
adds no network calls and no new trust surface. The fingerprint/handle shown are
already public-shareable. Keep everything `textContent` (no innerHTML), matching
the rest of app.js. Do it in `client/` (the single source of truth) so the phone
app inherits it via the gradle `syncWebClient` copy; then deploy to Hetzner
(rsync — separate from git push) and rebuild the APK.

### ⮕ PLAN (2026-07-17): contacts + web-of-trust + async 1:1 chats ("WhatsApp mode")
User-requested feature set: a left drawer menu with two new views next to the
existing live room — a **Users** list (known users + public keys + 3-level
safety marks, securely stored on-device) and a **Chats** list (persistent 1:1
chats, WhatsApp-style, no shared live room needed). Big change incl. backend
(store-and-forward). Locked design decisions:

- **Safety marks (trust levels):** 🟢 *verified by you* (you compared the
  fingerprint/safety number in person — the existing verify gate or an explicit
  action in the Users view); 🟡 *vouched* (a user YOU verified has published a
  signed vouch for them; UI names the voucher); ⚪ *unverified*. Vouches are
  dual-signed (Ed25519 + ML-DSA-65) statements over the target bundle,
  published to / fetched from the directory. The server is never the trust
  root — marks are computed client-side from signatures it can't forge.
- **Contacts & chats at rest:** encrypted client-side under a key derived from
  the identity passphrase (PBKDF2-600k → AES-256-GCM, own salt; key lives only
  in memory while the identity is unlocked) — same posture as the identity
  blob and OTP pads. Never plaintext in localStorage.
- **Async E2EE (chats without a live room)** needs public ENCRYPTION keys in
  the directory → **bundle v2**: identity adds P-256 ECDH + ML-KEM-768 public
  keys, dual-signed at registration. Async chat modes: **SEALED** (default:
  per-message ephemeral hybrid ECDH+ML-KEM → AES-256-GCM; sender identity +
  dual signature INSIDE the ciphertext), **AES256** (shared passphrase),
  **OTP** (pad). DHKE/RSA stay live-room-only (inherently interactive).
- **Mode lock + negotiated change:** each chat is locked to one mode; a mode
  change is an encrypted in-chat control message the peer must accept (both
  directions signed); the chat renders it as system lines.
- **Mailbox backend (store-and-forward):** server stores ONLY
  (recipient, opaque ciphertext, arrival time) — sender is inside the sealed
  envelope, invisible to the server. Hard caps: per-recipient message + byte
  quota, global cap, TTL (~14 d), delete-on-fetch (auth: session token), own
  rate bucket. No content, no sender metadata, no read receipts server-side.

**Phases** (each ends verified: unit + live-browser + deploy; check off here):
- [x] **P1 — client shell + contacts** — DONE 2026-07-17 (see dated entry):
      drawer menu (Live room / Users / Chats placeholder), `contacts.js`
      encrypted store (PBKDF2-600k → AES-GCM under the identity passphrase,
      unlocked alongside the identity, wiped on identity-forget, key-change
      resets `verified`), Users view (add by handle, fingerprint, 🟢/⚪ marks,
      confirm-gated verify/unverify/remove, auto-🟢 from the live-room verify
      gate + from a matching pin on add). Unit + live-browser verified;
      deployed to Hetzner + phone.
- [x] **P2 — web of trust** — DONE 2026-07-17 (see dated entry): vouch
      endpoints (POST/DELETE `/api/vouch`, GET `/api/users/{u}/vouches`
      token-gated), dual-sig verified server-side over the target's registered
      bundle, caps (200/voucher, 200k total, 50/response); client publishes on
      🟢 (opt-in confirm, requires login), retracts on Unverify, and computes
      🟡 STRICTLY locally (voucher must be a contact I verified, server keys
      must equal my pinned copy, dual sig over MY stored target bundle).
      3 new backend tests; browser flow: alice vouches bob → carol (verified
      alice) sees 🟡 "vouched by alice". Deployed to Hetzner + phone.
- [x] **P3 — bundle v2 + sealed envelope** — DONE 2026-07-17 (see dated
      entry): identity carries ECDH P-256 + ML-KEM-768 keypairs (blob v3;
      pre-v3 blobs auto-upgrade on unlock and re-publish), registration v2
      (own domain, dual sig covers enc keys; same-identity re-registration =
      bundle refresh keeping the lookup token), new `sealed.js`
      (hybrid HKDF→AES-GCM envelope, sealed sender + dual sig inside,
      re-target/forgery/tamper refused). 5 new backend tests (65 total),
      new `sealed.test.mjs`. Deployed.
- [x] **P4 — mailbox + Chats view** — DONE 2026-07-17 (see dated entry):
      `mailbox.py` store-and-forward (token-gated POST, login-gated
      delete-on-fetch GET, size/inbox/global caps + 14d TTL + own rate
      bucket; 5 tests, backend 70 passed); `chats.js` encrypted chat store;
      Chats view (start-chat picker, chat list w/ marks + preview,
      bubble conversation, 6s polling incl. auto-add of unknown senders from
      the sealed handle). Browser-verified both directions; deployed.
- [x] **P5 — mode lock + negotiated mode change** — DONE 2026-07-17 (see
      dated entry): each chat is locked to SEALED or AES256; a change is a
      signed control message the peer must accept/decline; AES256 adds an
      inner AES-256-GCM layer under a per-chat passphrase inside the sealed
      envelope. Browser-verified propose→accept→double-encrypted message;
      deployed (APK rebuilt, phone reconnect pending).
- [x] **P6 — hardening pass over the new surface** — DONE 2026-07-17 (see
      dated entry): adversarial `pentest-p6.mjs` (vouch forgery, client 🟡
      forge-resistance, mailbox enumeration/auth/cross-user isolation,
      captured-envelope, chat sender spoofing) — all attacks refused, local
      AND live. 3 live integration suites still green (no relay regression).
      README documents contacts/WoT/chats. APK rebuilt. Live E2E on Hetzner.
- [x] **MEDIUM — OTP concurrent pad use = two-time pad (2026-07-16 OTP pentest,
      Finding 1)** — FIXED 2026-07-16 (see dated entry): a same-origin exclusive
      lock (Web Locks API, localStorage-heartbeat fallback) is taken on connect;
      a pad live in one tab refuses connect in any other. Live-verified (second
      tab refused).
- [x] **MEDIUM — OTP pad stored unencrypted at rest (2026-07-16 OTP pentest,
      Finding 2)** — FIXED 2026-07-16: the pad bytes AND offsets are now stored
      encrypted (PBKDF2-600k → AES-256-GCM) under a per-pad passphrase, unlocked
      per session (PBKDF2 once; cached key for cheap per-message re-saves).
      Offsets inside the GCM blob, so an attacker can't roll `sendOffset` back to
      force reuse. Live-verified (blob has kdf/iv/ct only; wrong passphrase
      refused).
- [x] **LOW — OTP export file has no single-use/role binding (2026-07-16 OTP
      pentest, Finding 3)** — FIXED 2026-07-16: re-export of an already-shared pad
      warns and requires a confirming second click; import still dedups by padId
      and shows a strong one-device-per-side warning. (Cross-device double-import
      of a manually-copied file remains inherent without identities — documented.)
- [x] **LOW/info — malicious/low-entropy imported pad downgrades the importer's
      outbound confidentiality (2026-07-16 OTP pentest, Finding 4)** — FIXED
      2026-07-16: `importPad` rejects a pad whose Shannon entropy is < 7.0
      bits/byte (all-zero / grossly low-entropy). Live-verified.
- [x] **CRITICAL — relay-address JS injection (2026-07-08 Android pentest,
      Finding 1)** — FIXED 2026-07-16 (see dated entry): `RelayUrls.parse` now
      whitelist-validates the host charset (`^[A-Za-z0-9.-]+$`) and rejects
      credentials in the authority, before accepting; `MainActivity` builds the
      injected relay config with `JSONObject` instead of hand-interpolation.
      Regression tests (`RelayUrlsTest`, Robolectric) reject the live PoC
      payloads against the real `android.net.Uri`.
- [x] **Medium — `shouldOverrideUrlLoading` origin check is prefix-confusable
      (2026-07-08 Android pentest, Finding 2)** — FIXED 2026-07-16: the check now
      compares the PARSED `request.url` scheme+host to the app origin instead of
      `startsWith`, so `…internal.evil.com` no longer matches.
- [x] **Low — relay value also corrupts the CSP header (2026-07-08 Android
      pentest, Finding 3)** — FIXED 2026-07-16 by the Finding 1 host whitelist
      (the CSP interpolation can no longer receive `;`/quote/brace characters).
- [x] **Low/docs — CORS/WS-origin allow-list entry for the app isn't unique
      (2026-07-08 Android pentest, Finding 4)** — FIXED 2026-07-16: the app now
      pins a unique virtual origin via `WebViewAssetLoader.setDomain(
      "secure-chat.internal")`; `APP_WEBVIEW_ORIGIN` + `backend/config.py`'s
      comment updated to match (comment no longer claims the shared default
      domain uniquely identifies the app).
- [x] **Should-fix (informational, same pentest)** — FIXED 2026-07-16:
      `setWebContentsDebuggingEnabled` is now gated behind `BuildConfig.DEBUG`
      (enabled `buildConfig` in build.gradle.kts); `network_security_config.xml`
      scopes cleartext to loopback + `.onion` only (base-config now
      `cleartextTrafficPermitted="false"`); `importMapHash` drift is guarded by
      a new assertion in the backend's `test_csp_hash.py`
      (`test_android_importmap_hash_matches`, skips if android/ absent).
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
- [x] **Forward secrecy for RSA mode** — DONE (2026-07-03, see dated entry):
      RSA key transport + one-way HMAC ratchet with one-time AES-GCM message
      keys; root secret + RSA private key erased once traffic starts.
- [x] **AES256 ratchet** — DONE (2026-07-03, see dated entry): shared
      `RatchetChannel`, chains rooted in passphrase + both peers' fresh session
      nonces (new AES256 hello exchange). Closes the cross-session-replay
      residual; FS honestly limited by the passphrase being a long-term secret.
- [x] **Concurrent decrypt() reopens replay acceptance (High, found 2026-07-03
      pentest, all 4 modes)** — FIXED 2026-07-07 (see dated entry): per-channel
      `CallQueue` serializes all encrypt/decrypt calls, so the replay counter
      can no longer be read before a prior call commits it. Regression tests
      (`concurrencyChecks` in `crypto.test.mjs`, all 4 modes) cover concurrent
      duplicates and the counter-rollback replay scenario.
- [x] **Concurrent encrypt() permanently kills the ratchet channel (Medium,
      found 2026-07-03 pentest, AES256/RSA)** — FIXED 2026-07-07 (see dated
      entry): same `CallQueue` serialization (overlapping encrypts now step the
      chain sequentially), plus app.js disables Send while a send is in flight.
      Verified live in a real browser: double-click Send delivers exactly once
      and the channel keeps working.
- [~] **Android app** — IN PROGRESS (2026-07-07/08, see dated entries; icon +
      signing done 2026-07-23, see top snapshot): `android/` WebView shell
      bundling the audited client; debug APK builds clean; verified in a real
      browser AND ON-DEVICE (Android 14 emulator — AES256 end-to-end through
      the relay, both directions). Surfaced + fixed the Mixed-Content
      transport constraint (relay must be wss/loopback/.onion). Adaptive app
      icon and a real release-signing config (local keystore, gitignored) are
      now in place. REMAINING: an on-device pass of the identity +
      safety-number gate (DHKE/RSA/PQKEM; only AES256 driven on-device so far
      — started 2026-07-23, interrupted mid-session).
- [x] **OTP mode** — DONE (2026-07-16, see dated entry): true XOR one-time pad
      (`OtpPad` in crypto.js) with two-region split (no reuse across senders),
      strictly-increasing offsets (replay + cross-session replay rejected),
      per-message one-time HMAC-SHA-256 authenticator, and forward-secrecy
      zeroing of consumed bytes. Pad lifecycle in `otp.js`: CSPRNG + draw-to-
      generate entropy, passphrase-encrypted export/import file for the in-person
      exchange, localStorage persistence of bytes + offsets. UI + budget display
      in app.js/index.html. Verified end-to-end in a real browser (generate →
      export/import → two-way messaging → offsets persist → consumed bytes zeroed
      at rest).
- [ ] **Tor deployment** — hardened reverse setup, `.onion` service config,
      bind notes; never expose uvicorn directly to a public interface. Pairs
      with the app: point the relay at the `.onion`, add its origin via
      `SECURE_CHAT_EXTRA_ORIGINS`.
- [x] **Handshake replay across sessions in a reused room (Medium, found
      2026-07-02 pentest)** — DONE (2026-07-02 second session, see dated
      entry): transcript v2 folds a fresh per-connection nonce from both peers
      (hello phase) into the signed handshake; live relay replay PoC now
      REJECTED (regression test in `auth.integration.test.mjs`).
- [x] **AES256 cross-session replay (Low, re-confirmed 2026-07-02)** — CLOSED
      2026-07-03 by the AES256 ratchet: session chains bind both peers' fresh
      session nonces, so a captured session-1 frame can no longer authenticate
      in session-2 (regression test `aesRatchetChecks` in `crypto.test.mjs`,
      incl. a fresh-receiver variant proving the key — not the replay counter —
      rejects it).

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

# secure-chat — iOS app

The iOS twin of `../android`: a thin native shell around the **exact same**
web client in `../client`, bundled into the app so the relay never serves the
code (README "Trust boundary of the web client"). Read `android/README.md`
first — the security model is the same; this file only says where iOS differs.

## How it works
- `AppSchemeHandler` serves the bundled `web/` folder under the custom origin
  **`secure-chat://app`**. WKWebView will not let an app handle `https://`
  itself, so this is the iOS counterpart of Android's
  `https://secure-chat.internal`. WebKit treats a registered custom scheme as a
  secure context (so `crypto.subtle` exists); the simulator tests assert that
  rather than assume it. Paths are whitelisted (no `.`/`..`, no percent
  encoding, no hidden files) and re-checked to stay inside `web/`.
- **Relay location + pad floor** are injected by a document-start
  `WKUserScript` before any page script runs (`WebShell.documentStartScript`),
  exactly like Android's `addDocumentStartJavaScript`, and checked after load
  (`WebShell.verifyScript`); if either half is missing the app refuses to run
  and says why.
- **CSP** is stamped on `index.html` by the scheme handler, with `connect-src`
  pinned to the configured relay. The import-map hash is pinned in
  `WebShell.swift`; `backend/tests/test_csp_hash.py` fails if it drifts.
- **Relay-side requirement:** the relay must allow-list `secure-chat://app`
  (WS origin + CORS). That is in `backend/config.py` (`IOS_WEBVIEW_ORIGIN`) —
  **the relay must be redeployed with this change before the iOS app can
  connect to it.**
- **Transport:** the relay must be **https/wss**. `http://` is accepted only for
  `127.0.0.1`/`localhost` (testing), because the page is a secure context
  (mixed-content blocks `ws://`) and App Transport Security blocks cleartext.
  There is no Tor in this app, so a `.onion` relay does not work on iOS.

## The pad floor on iOS
Android keeps the OTP / contact-store / chat-store rollback floors behind a
synchronous `@JavascriptInterface` backed by an AndroidKeyStore HMAC key.
iOS differs in two ways, both deliberate:

1. **Channel.** WKWebView has no synchronous JS → native call except
   `window.prompt()`. The document-start script captures `prompt` before the
   page can touch it and republishes a frozen `{read, bump}`; `ShellUIDelegate`
   answers messages carrying the floor prefix silently (main frame of our own
   origin only) and never shows them. Page JS can call the channel directly —
   as it can call the Android bridge — and gets the same two operations: no
   lowering, no deletion.
2. **Key.** Same record format and MAC message as `PadFloor.kt`, but the HMAC
   key is 32 random bytes in the Keychain
   (`AfterFirstUnlockThisDeviceOnly`), which the app *process* can read; the
   Secure Enclave has no HMAC. The page cannot reach it. The records file is
   excluded from backup, so a restore cannot bring an old floor back. If the
   records exist but the key is gone (e.g. a re-signed sideload with another
   Keychain access group), no new key is minted: floors read TAMPERED until the
   key is back, rather than being orphaned for good.

## Backups (Android: allowBackup=false)
The web view keeps the client's storage — the passphrase-encrypted identity,
one-time pads, contact and chat stores — under `Library/WebKit`, which iOS
would put into iCloud / Finder backups and a Quick Start transfer. The app
marks that directory excluded from backup at every launch
(`WebDataBackup.exclude()`), matching Android's "nothing leaves the device"
(L-6): no second copy of a pad, no offline brute-force copy of the identity.
Consequence, same as Android: a new phone starts empty; move an identity with
its backup export, and exchange new pads.

## Screen protection (no FLAG_SECURE on iOS)
- App switcher: a cover goes up on `sceneWillResignActive`, so the snapshot is
  blank.
- Screen recording, mirroring, AirPlay: the cover stays up while
  `UIScreen.isCaptured`.
- **Screenshots cannot be blocked on iOS** (the OS only reports them after the
  fact). Not covered — accepted, stated here so nobody assumes otherwise.

## Build and test (GitHub Actions)
Everything runs in `.github/workflows/ios.yml` (no Mac needed locally):
1. Linux gate: relay pytest + client unit tests.
2. macOS: `xcodegen generate` (the `.xcodeproj` is generated from
   `project.yml` and gitignored), a local relay on 127.0.0.1:8000, then the
   simulator tests — unit (relay parsing, floor, scheme handler), in-page
   (secure context + WebCrypto, floor bridge, CSP enforcement, relay
   reachability, native dialogs, navigation policy) and a two-user end-to-end
   chat through two web views — followed by a cold relaunch that proves the
   client's localStorage survives a restart.
3. An **unsigned** Release `SecureChat-unsigned.ipa`, uploaded as a build
   artifact (the Release binary is checked for leftover debug hooks).

Cost: the repository is private, so macOS minutes are billed 10×; one run is
about 100–150 billed minutes. The workflow therefore runs only when `ios/**` or
the workflow changes (or by hand).

## Installing on an iPhone
The CI build is **unsigned**; iOS will not install it as is. Options:
- **Sideload** (AltStore / Sideloadly with a free Apple ID): re-signs the IPA
  for 7 days at a time.
- **Apple Developer Program** (99 USD/year): add a signing certificate and
  provisioning profile as repository secrets and the workflow can produce a
  signed ad-hoc or TestFlight build. Not wired up yet — needs the owner's
  account.

Compare the IPA's SHA-256 (next to it in the artifact) before sideloading.

## Known limits
- Invite links (`#add=` in `location`) point at `secure-chat://app/...`; the
  app registers no URL scheme on purpose (no deep-link attack surface), so
  such a link cannot open the app. Paste the handle instead.
- Lock-on-background is not done, as on Android (it would end live sessions).
- Design debt, deliberately deferred (hot review, rounds 1–2): the native
  bar stays visible with the keyboard up (hiding it risks the web review's
  lost-first-tap bug; needs its own test); in a conversation the bar is
  `--bg` over the `--panel` conversation head, and a 34 pt strip sits under
  the composer — the one remaining "page in a frame" seam; the page reflows
  behind native alerts while the keyboard guide moves.
- The pad floor holds at most 4096 records (about 1365 pads); past that a new
  pad's floor reads TAMPERED (fail closed). Raise the cap if anyone gets near.
- Pinch zoom is off; text size follows Dynamic Type, capped so the page stays
  at least 320 CSS px wide. System Zoom (Accessibility) still works.
- Screenshots of the app are possible (iOS offers no FLAG_SECURE).

## CI notes
- The iOS gate runs only the relay tests the app depends on, to stay fast;
  the full relay and client suites run in `.github/workflows/backend.yml`
  (Linux). The intermittent `tests/test_ws.py` hang that once motivated the
  split was a test-harness bug, fixed (see that file's header).
- Screenshots and a test summary go to the `ci/ios-shots` branch from a
  separate job; the macOS job itself holds a read-only token. The publish
  job treats the artifact as hostile (allow-listed PNGs + SUMMARY.txt copied
  into a fresh tree, git dir outside it, hooks and fsmonitor off).


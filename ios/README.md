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

## Getting it onto an iPhone

There is no "download the APK and install it" on iOS: the system installs and
starts only apps signed with a certificate Apple trusts. Without a paid Apple
Developer account (99 USD/year, not used here) there are two ways, and they
make **different security promises**. Pick per person, and tell them which one
they have.

| | **iOS app via SideStore** | **Home Screen web app** |
| --- | --- | --- |
| Where the client code comes from | inside the app, fixed at install | the relay, **on every start** |
| A compromised relay can… | only offer a malicious *update*; you must accept it — but an accepted update gets the app's data and keys | ship different code the next time you open it |
| One-time-pad rollback protection | native floor (Keychain + HMAC) | browser residual (see the main README) |
| Setup | ~20 min, a computer once, a free Apple ID | ~30 s, nothing to install |
| Upkeep | re-sign every 7 days (SideStore can do it in the background, when its helper VPN is on and iOS lets it run) | none |
| Fits | people who want the app's guarantee and can handle sideloading | everyone else, who trusts the relay operator |

### Option A — the iOS app via SideStore

What the user does (the tools change; **docs.sidestore.io** is authoritative):

1. **Once, on a computer:** install SideStore on the iPhone with the installer
   the SideStore guide recommends; it signs SideStore with the user's own
   Apple ID and creates a *pairing file*.
2. **iPhone:** Settings → General → VPN & Device Management → trust the Apple
   ID; Settings → Privacy & Security → **Developer Mode** on (restart).
3. Install the small helper "VPN" the guide names (it only lets SideStore
   talk to the phone itself, for signing without a computer).
4. Open SideStore, sign in, import the pairing file.
5. **Verify, then install that exact file.** Download
   `https://<your relay host>/ios/SecureChat-<version>.ipa`, compute its
   SHA-256 yourself (on a computer: `shasum -a 256 SecureChat-*.ipa`, or an iOS
   Shortcut), compare it with the value the operator sent you through a
   **different channel** (not this server), then in SideStore tap **+** and
   pick that file.
6. Optional, for update notices: SideStore → Sources → **+** →
   `https://<your relay host>/ios/apps.json`. **Do not treat a source install
   as verified**: SideStore checks the download against a hash that comes from
   the same server, so a hostile server can serve a matching pair. Any hash in
   the description text is informational only. Repeat step 5 for every update.
7. Open secure-chat, enter the relay address (`https://…`).

Problems, stated plainly:
- **Every 7 days** SideStore must refresh the signature (helper VPN on,
  "Refresh All"; an iOS Shortcut can automate it). Missed it → the app will
  not start until refreshed. Chats and keys stay.
- A free Apple ID signs at most **3 apps** at a time; SideStore is one of them.
- SideStore logs in to Apple with that Apple ID through a helper service —
  use a **separate Apple ID**, not the main one.
- Developer Mode, a trusted developer profile and a helper VPN are real
  hurdles; non-technical users give up here.
- The download server (the relay host, `deploy/README.md`) can replace the
  IPA *and* `apps.json` together. The app's guarantee starts after install;
  **hashing the downloaded file yourself and comparing with a second
  channel** is what protects the install — and every update, because an
  accepted update replaces the app in place with full access to its data and
  Keychain (identity, contacts, pad floor).
- There is no Apple review: SideStore re-signs the IPA with the development
  certificate of the user's own Apple ID, and the user runs what the operator
  built. That is the point — and the responsibility. SideStore's app
  permission check is off by default; it would not stop a changed app anyway.
- The IPA is built on a GitHub-hosted runner that also runs third-party tools
  (Homebrew, pip); the build is not reproducible yet. The guarantee is "the
  code the operator's CI built", not "code you could rebuild bit for bit".

### Option B — the Home Screen web app

What the user does: open `https://<your relay host>/` in **Safari** →
Share → **Add to Home Screen**. It gets the secure-chat icon, opens full
screen, no Safari bars.

Problems, stated plainly:
- **It is the web client with an icon.** Its code is fetched from the relay on
  every start, so the web client's trust boundary applies unchanged (main
  README, "Trust boundary of the web client"): whoever controls the relay
  controls the code. For a self-hosted relay run by someone you trust, that
  may be fine; it is not the app's guarantee.
- **No native rollback floor** for one-time pads and the at-rest stores; the
  browser residual documented in the main README applies.
- **Separate storage.** The Home Screen web app does not share storage with
  Safari: an identity created in Safari is not there. Move it with the
  identity backup (Copy backup → restore) or create it in the web app.
- **iOS may drop website data** under storage pressure; Home Screen web apps
  are exempt from Safari's 7-day deletion of unused sites, but a device-wide
  cleanup or deleting the icon wipes the identity. Keep the backup.
- Needs **https** (a clearnet relay with TLS); the `.onion` does not work in
  Safari.
- **Invite links open in Safari**, not in the Home Screen web app, and
  Safari's storage is separate — so an invite lands where the identity is not.
  Paste the handle into the web app instead.
- No service workers, deliberately and enforced (`worker-src 'none'` in the
  relay's CSP): a worker would outlive a cleaned-up relay and keep serving
  its code.
- No offline mode: without the relay there is no client.

### With an Apple Developer account (not set up)

TestFlight (a public link, builds expire after 90 days) or ad-hoc installs
from the relay (≤ 100 registered devices) would remove the 7-day refresh and
the sideloading steps. Needs the account's signing certificate, profile or
App Store Connect API key as repository secrets; the CI can then upload or
build signed installs.

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


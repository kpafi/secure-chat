# secure-chat — Android app

A thin native shell around the **exact same** web client in `../client`. The
point of the app (versus opening the site in a browser) is to close the web
deployment's one honest trust gap (README "H1"): a browser trusts the server to
serve honest JavaScript on every load, so a compromised server could ship
malicious crypto. The app instead **bundles the audited client inside the APK**
and treats the relay as nothing but a dumb WebSocket/HTTP endpoint for opaque
ciphertext.

## How it works
- `MainActivity` serves the bundled `assets/web/` to a `WebView` from a local
  **secure** origin (`https://secure-chat.internal`, pinned via
  `WebViewAssetLoader.setDomain()` so the origin is unique to this app rather
  than androidx.webkit's shared default domain). A secure origin is required for
  `window.crypto.subtle`.
- The relay is remote, so the app supplies the two things the same-origin web
  build got for free:
  1. **Relay location** — injected as `window.__SECURE_CHAT_RELAY__ = {api, ws}`
     *before any page script runs* (`addDocumentStartJavaScript`). The client
     (`app.js`) uses it when present and falls back to same-origin when absent,
     so the web and app share one unmodified codebase.
  2. **CSP** — set as a response header on the bundled `index.html`, with
     `connect-src` pinned to exactly the configured relay origin (http + ws),
     `script-src` still pinning the import-map hash. Nothing else is reachable.
- The relay address is entered once (menu → **Relay settings**), stored in
  `SharedPreferences`, and validated to an http(s) **origin** (no path).
- **Transport constraint (important):** the client page is a *secure* origin
  (https, required for `crypto.subtle`), so the browser's Mixed-Content rule
  forbids opening an insecure `ws://` from it. The relay must therefore be a
  *potentially-trustworthy* origin: **wss://** (TLS), a **loopback** address
  (`127.0.0.1`/`localhost`), or a **.onion** (Tor treats it as trustworthy). A
  plain `http://192.168.x.x` LAN relay will NOT connect — the app shows a clear
  error. For local testing against a host relay, use `adb reverse tcp:8000
  tcp:8000` and set the relay to `http://127.0.0.1:8000`.
- Identity keys and pins live in the WebView's `localStorage` (managed by the
  bundled client), exactly as on the web. The app persists only the relay URL.

## Screen capture is blocked (FLAG_SECURE)
Pentest 2026-08-07 F-ANDROID-003: the activity window sets `FLAG_SECURE`
before its first frame, so the recents-switcher snapshot is blank and
screenshots / screen recording of the app (including the native secret and
passphrase prompts) are refused by the OS. The accepted cost is that a user
cannot screenshot the safety number or an invite QR from inside the app.
**Not done, deliberately:** lock-on-background. The unlocked identity, the
decrypted contact/chat stores and any live session keys are process memory;
a lock on `onStop` would end every live chat (session keys cannot be
re-derived from the passphrase) and needs a timed design and a `lockAll()`
in the client first. Verify on a device by backgrounding the app and opening
recents (blank card), and with `adb shell screencap` (refused or black).

## Relay-side requirement
Because the app's origin differs from the relay's, the relay must allow-list it
(it is a single fixed origin, not a wildcard). This is already wired:
`APP_WEBVIEW_ORIGIN` is in `ALLOWED_WS_ORIGINS` and in the `/api` CORS list
(`backend/config.py`). Add a production `.onion`/clearnet origin at deploy time
with `SECURE_CHAT_EXTRA_ORIGINS="https://…"` — no code edit needed.

## Build
```bash
# Needs a full JDK 21 (with jlink) and the Android SDK (platform 34, build-tools 34).
export ANDROID_HOME=$HOME/android-sdk
./gradlew assembleDebug        # -> app/build/outputs/apk/debug/app-debug.apk
```
The bundled web client is **generated at build time** from `../client` by the
`syncWebClient` Gradle task (so it can never drift from the reviewed source);
`assets/web/` is gitignored.

## Verification status (2026-07-08)
- Debug APK builds clean from source; all 21 client files packaged.
- Cross-origin mechanism verified in a real browser (Chromium): bundled client
  on one origin, relay on another, relay config injected before scripts, app CSP
  applied — full DHKE handshake (matching safety numbers), two-way messages, and
  a cross-origin `/api` register all succeed.
- **Verified ON-DEVICE** (Android 14 emulator, `google_apis;x86_64`, KVM): app
  installs and renders the full UI in the real WebView; the relay config is
  injected before page scripts (`addDocumentStartJavaScript` works on WebView
  113); driven via CDP against a host-side AES256 peer over the relay (through
  `adb reverse` loopback), the on-device WebSocket reached the relay, the AES256
  nonce exchange completed, and messages decrypted **both directions** on the
  device. This is what surfaced the Mixed-Content transport constraint above
  (a `ws://10.0.2.2` relay was blocked; `127.0.0.1` via `adb reverse` works).
- Remaining polish: app icon, a release-signing config, and an on-device pass of
  the identity + safety-number gate (DHKE/RSA/PQKEM) — only AES256 was driven
  end-to-end on-device so far (the handshake modes are covered in-browser).

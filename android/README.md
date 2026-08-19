# secure-chat — Android app

A thin native shell around the **exact same** web client in `../client`. The
point of the app (versus opening the site in a browser) is to close the web
deployment's one honest trust gap (README, "Trust boundary of the web client"): a browser trusts the server to
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
- **OTP pad floor** (`PadFloor.kt`): the monotone consumption watermark for
  one-time pads lives in app-private storage behind an AndroidKeyStore HMAC, not
  in `localStorage`, so a rolled-back pad is refused outright instead of
  prompting. This is why OTP's rollback guarantee is stronger in the app than in
  a browser (README, "OTP mode"; pentest 2026-07-28 F-1).

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

## Verification status
- 2026-07-08: debug APK builds clean from source; cross-origin mechanism verified
  in a real browser (bundled client on one origin, relay on another, relay config
  injected before scripts, app CSP applied — DHKE handshake with matching safety
  numbers, two-way messages, cross-origin `/api` register). On an Android 14
  emulator the on-device WebSocket reached the relay via `adb reverse` and AES256
  messages decrypted both ways — which is what surfaced the Mixed-Content
  transport constraint above.
- 2026-07-27/28: installed on a physical phone and used against the live
  relay; contact-store and OTP-pad at-rest migrations confirmed on-device
  (details in `PROGRESS.md`).
- Release signing is configured via a gitignored `keystore.properties` (copy
  `keystore.properties.example`); `assembleRelease` without it produces an
  unsigned APK. A launcher icon ships.
- Not recorded as driven end-to-end on a device: the identity + safety-number
  gate for DHKE/RSA/PQKEM (those modes are covered in-browser by `e2e/all-modes.mjs`).

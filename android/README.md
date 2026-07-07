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
  **secure** origin (`https://appassets.androidplatform.net`) via
  `WebViewAssetLoader`. A secure origin is required for `window.crypto.subtle`.
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
  `SharedPreferences`, and validated to an http(s) **origin** (no path). It can
  be a LAN dev relay, a clearnet TLS host, or an `.onion` via Orbot.
- Identity keys and pins live in the WebView's `localStorage` (managed by the
  bundled client), exactly as on the web. The app persists only the relay URL.

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

## Verification status (2026-07-07)
- Debug APK builds clean from source; all 21 client files packaged.
- The app's cross-origin mechanism is verified in a real browser (Chromium):
  bundled client on one origin, relay on another, relay config injected before
  scripts, the app CSP applied — a full DHKE handshake (matching safety
  numbers), two-way messages, and a cross-origin `/api` register all succeed.
- Not yet run **on a device/emulator** (none available in the build env). The
  WebView glue (asset loader, document-start injection, menu) compiles and
  packages but has not been exercised on-device. That is the next step.

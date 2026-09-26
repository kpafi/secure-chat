# secure-chat — Android app

A thin native shell around the **exact same** web client in `../client`. The
point of the app (versus opening the site in a browser) is to close the web
deployment's one honest trust gap (`../README.md`, "Trust boundary of the
web client"): a browser trusts the server to
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
screenshots / screen recording of the app are refused by the OS. A dialog is a
separate window that the activity's flag does NOT cover (this README used to
claim it did), so since Package 3 every native dialog — the `window.prompt()`
passphrase prompt, `alert`/`confirm` (contact names, consent text), the relay
prompt and the unsupported-WebView notice — sets `FLAG_SECURE` on its own
window before it is shown (`MainActivity.secureShow`). The accepted cost is
that a user cannot screenshot the safety number or an invite QR from inside
the app. **Not yet checked on a device:** a capture (`adb shell screencap`, or
a screen recording) taken while a passphrase prompt is open must be black.

**Known gap, needs a device check:** a `<select>` popup (`#chatNew` — contact
names, `#otpSelect` — pad labels, `#chatModeSel`) is drawn by the WebView
itself in its own native popup window, which `secureShow` never sees, so it
very likely does NOT carry `FLAG_SECURE`. Check with a screen recording while
each list is open. If it is capturable, the fix is to render those three lists
in-page (a listbox inside the WebView surface, which the activity flag covers)
instead of native `<select>`s — not done here because it is a UI change to
three screens, not a flag.

Also since Package 3: `WebChromeClient.onConsoleMessage` swallows the web
client's console output in release builds (it used to reach logcat), and
`MainActivity` has `android:taskAffinity=""` (F-ANDROID-001) with the default
launch mode — launching from the icon and returning via recents should behave
exactly as before; confirm on a device.
**Not done, deliberately:** lock-on-background. The unlocked identity, the
decrypted contact/chat stores and any live session keys are process memory;
a lock on `onStop` would end every live chat (session keys cannot be
re-derived from the passphrase) and needs a timed design and a `lockAll()`
in the client first. Verify on a device by backgrounding the app and opening
recents (blank card), and with `adb shell screencap` (refused or black).

## The pad-floor bridge and frames (F-ANDROID-002)
The native OTP/store floor is reached through ONE `addJavascriptInterface`
bridge, `SecureChatPadFloor`. Android exposes such a bridge to **every frame**
of the WebView, of any origin — so the bridge is only as narrow as the set of
frames the WebView can ever load. The app loads no framed content, and since
package 6 that is a pinned invariant rather than an accident: the CSP stamped
on `index.html` (`MainActivity.csp`) says `frame-src 'none'; child-src 'none'`
(and `worker-src 'none'`) explicitly (not only through the `default-src 'none'`
fallback, which a later edit could widen), the web relay's and the iOS shell's
CSPs say the same, and all three are pinned (`client/android-source.test.mjs`,
`backend/tests/test_static_hardening.py`, `backend/tests/test_csp_hash.py`).
Honest limit: `frame-src` cannot stop an `about:blank` or `srcdoc` frame (there
is no URL to fetch). Such a frame inherits the page's CSP, so no script runs in
it — the bridge is still visible there, but nothing can call it — and the
client creates none. What the bridge accepts is small
anyway (read/bump of integer floors under an app-private HMAC, see
`PadFloor.kt`).

Why not `WebViewCompat.addWebMessageListener` (which can be limited to an
origin allow-list)? It is asynchronous — messages, no return value — while the
client's floor check runs synchronously inside unlock/persist decisions
(`nativefloor.js`: "is this copy older than the floor?" must be answered
before the next statement runs). Moving to it means reworking every floor call
site into an async round trip with its own failure and ordering cases, a
larger change than the risk it removes while no framed content loads. Revisit if the
app ever needs a frame.

## SafeBrowsing is off (F-P7-24)
`AndroidManifest.xml` sets `android.webkit.WebView.EnableSafeBrowsing` to
`false`. SafeBrowsing checks every URL the WebView loads against Google's lists,
sending URL hash prefixes to Google; this WebView only ever loads the app's own
bundled files (`https://secure-chat.internal/…`) and the one relay the user
configured, so the check can protect nothing and would tell a third party
when, and to which relay host, the app connects. Pinned in
`client/android-source.test.mjs`. On a device this needs only the normal
smoke test (the app still loads and reaches its relay).

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
./gradlew assembleRelease      # -> app/build/outputs/apk/release/ (signed if keystore.properties exists)
adb install -r app/build/outputs/apk/debug/app-debug.apk
```
Release signing reads `keystore.properties` (gitignored; template in
`keystore.properties.example`). Without it `assembleRelease` produces an
unsigned APK. A debug build has WebView remote debugging on, so use a release
build on a phone you actually rely on.

The bundled web client is **generated at build time** from `../client` by the
`syncWebClient` Gradle task (so it can never drift from the reviewed source);
`assets/web/` is gitignored.

## Verification status
- **Emulator (2026-07-08):** Android 14, driven over CDP against a host relay
  through `adb reverse`: the relay config is injected before page scripts, and
  an AES256 session decrypted messages both directions. This run surfaced the
  Mixed-Content transport constraint above (`ws://10.0.2.2` blocked,
  `127.0.0.1` via `adb reverse` works).
- **Real phone (2026-09-21/22):** APK built and installed; the pad-floor
  harness passed 33/33 against the real AndroidKeyStore; `FLAG_SECURE`
  verified; unlock and login against the deployed relay observed.
- The handshake modes (DHKE / PQKEM) and every other mode are covered in
  real browsers by `e2e/all-modes.mjs`, which drives the same client code.
- **Owed on the phone (package 3b, durable storage):** (1) the v0.3.x → 0.4.0
  upgrade with data kept: contacts and chats open intact and have moved to
  IndexedDB (`localStorage` no longer holds `sc.contacts.v1` / `sc.chats.v1`;
  the `sc.*.idb.v1` markers are set), existing pads unlock where they were;
  (2) an OTP send followed within a second or two by a force-stop
  (`adb shell am force-stop`) reopens the pad past the sent message, with no
  "rolled back" refusal; (3) the same for a received message and for Export
  (the re-export warning appears). The node suite simulates all three
  (`client/durable.test.mjs`) and `e2e/durable-crash.mjs` proves (2) in desktop
  Chromium; neither runs the Android WebView.
- **Owed on the phone (package 4, owner decisions):** (1) upgrade with data
  kept: the existing identity unlocks WITHOUT the "no encryption keys"
  question (it has them), and the native floor gains an `identity:<hash>`
  record at generation 0; (2) the mode picker shows four modes, no RSA; (3) as
  the GUEST of a live room (DHKE), the owner's key appears on the admission
  sheet ("Is this who you are expecting?", Continue / Refuse) on the phone
  layout, above the tab bar, with the same 500 ms tap guard; Refuse returns to
  the room screen with the reason, Continue reaches the safety number; (4) with
  a contact verified in person on the phone (the pin written by "It matches"),
  joining their room shows no prompt and the transcript line "approved without
  asking"; (5) mixed versions: the 0.3.x APK as owner and the new client as
  guest, and the reverse, still connect (only the new guest is asked). The
  node suite and e2e cover all of it in desktop Chromium; none runs the
  Android WebView.

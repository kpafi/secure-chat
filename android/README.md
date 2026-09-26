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
The native OTP/store floor is reached through an `addJavascriptInterface`
bridge, `SecureChatPadFloor` (since the OTP transfer sheets there is a second
one, `SecureChatFiles`, below; everything in this section holds for both).
Android exposes such a bridge to **every frame**
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

## Pad files: Share, Save to device, Import (OTP transfer sheets)
Before this, Import did nothing on the phone (a WebView ignores
`<input type=file>` unless the `WebChromeClient` implements
`onShowFileChooser`) and Export handed out nothing (a WebView drops
`<a download>` on a `blob:` URL) — after the pad had been latched as exported.
Spec: `design/research/reviews/otp-transfer-brief.md` 5, 6, 9. Code:
`PadFiles.kt` (validation, the bridge) and `MainActivity` (the intents).

- **Export** goes through a second bridge, `SecureChatFiles`, captured in the
  same document-start script as the pad floor and republished frozen as
  `window.__SECURE_CHAT_FILES__ = {share, save}` (bound methods,
  non-writable, non-configurable; `verifyRelayConfig` refuses to run without
  it). `share(name, text)` / `save(name, text)` answer at once with a request
  id, `"busy"` or `"invalid"`; the outcome (`shared` / `saved` / `cancelled` /
  `error`) comes back through `window.__SECURE_CHAT_FILES_RESULT__(id,
  outcome)`, evaluated by the shell from our own hex id and a constant.
- **Validated natively**, whatever the page checked: the name must be exactly
  `secure-chat-pad-YYYY-MM-DD-HHMM.json` (ASCII digits — on Android `\d` is
  ICU's, which admits any Unicode digit), the text at most 4 MiB and exactly
  the envelope `exportPad()` writes: the same literals and key order,
  `iters` exactly otp.js's `KDF_ITERS` (600000), salt 16 and iv 12 bytes of
  btoa base64, `ct` canonical base64. Checked by a single-pass scanner, not a
  regex: on the device `java.util.regex` is ICU, whose backtracking stack is
  limited and is not the engine the JVM tests run (pentest r1). The two ends
  are tied through a committed fixture (real `exportPad()` output) that
  `PadFilesTest` accepts and whose skeleton `android-source.test.mjs` compares
  with a fresh `exportPad()`. One request at a time.
- **What page script can do with it** (any script in the page reaches it):
  ask for the system share sheet or save dialog for one timestamp-named,
  pad-envelope-shaped file. Nothing leaves app-private storage until the user
  picks a target in system UI. It cannot choose a path, a name, a type or an
  intent extra, and it cannot read any file. It can spam: one request at a
  time, and each needs the user to tap through a system screen. A page that
  passes a huge string can exhaust memory (the bridge copies arguments before
  any check) — denial of service by a party that already runs the page.
- **Share** writes the file to `cacheDir/pad-share/<requestId>/<name>` and
  hands it out via a non-exported `FileProvider` whose paths xml admits that
  directory only, `ACTION_SEND` `application/json`, a read grant to the chosen
  target only. The URI is unique per request (pentest r1 F1: a grant is keyed
  by URI, and the name alone is minute-resolution, so a same-name re-share
  used to be readable through the first target's grant); the target sees only
  the neutral name.
  *What "shared" means:* the chooser's activity result is `RESULT_CANCELED`
  whether or not a target was picked, so the shell passes the chooser an
  `IntentSender`, which the system sends when a target is picked: a target
  picked = `shared`; none by the time the chooser returns (+1.5 s, the two
  signals travel separately) = `cancelled`. The PendingIntent behind it is
  immutable (the chooser then drops its `EXTRA_CHOSEN_COMPONENT` fill-in,
  which we never read), one-shot, package-explicit and has its own
  requestCode per share, so two activity instances cannot swap results
  (pentest r1 F2, F5). Whether the file reached the other phone Android cannot
  tell an app; the UI says "File shared", not "handed over".
- **The share file's life** (pentest r1 F1, F2): every file is un-granted
  (`revokeUriPermission`) before it is deleted, and nothing deletes it any
  other way. On `cancelled`/`error` it goes at once. After `shared` it lives
  **10 minutes** (`SHARE_TTL_MS`: Bluetooth reads it from a background service
  after its screen has closed), then a timer revokes and deletes it; a new
  share supersedes every earlier one at once; every start of the activity
  removes files past their 10 minutes — and only those, so a second instance
  (another app can start ours into its own task) or a recreation (dark mode,
  locale, font scale, a fold) no longer deletes a file a target has yet to
  read. A file whose process died before its timer ran goes at the next start
  or share.
- **Save** is `ACTION_CREATE_DOCUMENT` (`application/json`, the name
  suggested); `saved` only after the bytes are written and the stream closed.
  The stream is opened `"wt"` (pentest r1 F3: an existing file the user chose
  to overwrite must be truncated, or its tail stays behind the envelope). The
  shell never deletes a document: from the URI it cannot tell a new file from
  one the user chose to overwrite, so a failed write is reported as `error`
  and left, and a save result that arrives after the process died (no request,
  no text) is ignored — at worst an empty file stays, never someone's file
  removed.
- **Document URIs** (pentest r1 F4): a picker or save-dialog result is used
  only if it is `content://` from another app's provider — never `file://`
  (which `ContentResolver` would open directly, app-private files included),
  never our own `FileProvider`. DocumentsUI only returns such URIs, so this
  refuses nothing real.
- **Import**: `onShowFileChooser` → `ACTION_OPEN_DOCUMENT`,
  `CATEGORY_OPENABLE`, `*/*` (Quick Share and Bluetooth often deliver a .json
  as `application/octet-stream`), one document, no persisted permission. The
  WebView's callback is answered exactly once (`null` on cancel). This works
  with `allowContentAccess = false`: that setting governs `content://` URLs the
  *page* loads; the chooser's pick reaches the page as an upload the WebView
  reads itself under the one-document grant (the Import check below confirms
  it on the device).
- **No cloud roots (design critic r2, N-M1):** Save and Import both put
  `EXTRA_LOCAL_ONLY`, so DocumentsUI lists local roots only, not Google Drive.
  A pad file on a server is protected only by the transfer passphrase,
  guessable offline for as long as the copy exists. **This is a hint**: an OEM
  picker may ignore it, which is why the UI says "File saved", never "saved to
  this device".
- No new permission; no new dialog of ours (the close confirm is the page's
  `confirm()`, through `secureShow`). The share sheet, save dialog and picker
  are other apps' windows, which `FLAG_SECURE` does not cover; they show only
  the neutral file name.

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
- **Owed on the phone (OTP transfer sheets, pad files):** the Robolectric
  tests drive the intents, not real system UI. (1) **Share…**: the chooser
  opens; Quick Share to the second phone delivers
  `secure-chat-pad-YYYY-MM-DD-HHMM.json` there and the sheet says "File
  shared"; backing out of the chooser without a pick says "Not shared." within
  ~2 s. **Check whether Bluetooth is offered at all** — AOSP Bluetooth's share
  filter lists specific MIME types and may not include `application/json`; if
  it is missing, that is a decision (share as `text/plain` or `*/*`), not a
  bug to paper over. Also check the Quick Share button of the Android 14
  sharesheet reports "File shared" (it must fire the chosen-target callback,
  which is an IMMUTABLE PendingIntent since pentest r1 F5 — the platform sends
  it with the fill-in dropped; if a real pick says "Not shared." on every
  target, this is the first suspect;
  if it says "Not shared." after a real send, note the device and build).
  (2) **Save to device**: the save dialog shows no Google Drive / cloud roots
  (`EXTRA_LOCAL_ONLY`; if the OEM picker lists them anyway, note it); saving
  into Downloads says "File saved" and the file in Files is the JSON envelope;
  cancelling says "Not saved."; saving OVER an existing, longer file leaves
  exactly the envelope (the `"wt"` truncation is up to the provider).
  (3) **Import**: "Choose pad file…" opens the
  system picker (no cloud roots), the file received by Quick Share (often
  `application/octet-stream`) is selectable and imports; cancelling changes
  nothing, and a second tap opens the picker again. (4) While the file is
  ready, the close confirm is black in a screen recording (`secureShow`).
  (5) Debug build: after a share, `adb shell run-as org.securechat.app ls -R
  cache/pad-share` lists one `<id>/secure-chat-pad-….json`; ten minutes after
  "File shared" (app left open) it is empty; after a force-stop and a restart
  more than ten minutes later it is empty. A 1 MiB pad exports (Share and
  Save) without "Could not share/save" — the native envelope check is a
  linear scan, but the largest file has only run on the JVM so far. A
  recreation right after "File shared" (switch dark mode: the activity is
  rebuilt) does not break a Bluetooth send still reading the file. (6) Android Back closes an open sheet (the client pushes a history
  entry; `onBackPressed` calls `webview.goBack()` while `canGoBack()`)
  instead of leaving the app, and does not dismiss a working sheet.

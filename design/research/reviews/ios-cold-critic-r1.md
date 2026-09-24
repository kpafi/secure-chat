# Cold critic, round 1: iOS shell (commit 021c2ed)

Scope: ios/project.yml, ios/SecureChat/*, ios/SecureChatTests/*, ios/scripts/*, .github/workflows/ios.yml.
I read the Swift as a compiler would for Xcode 16 / iOS 18 SDK / Swift 5 mode / iOS 17 target. Nothing here was compiled.
Confidence labels: **certain**, **likely**, **worth checking**.

Summary: I found no certain compile errors in the app target. The test target very probably compiles too. The run as written will go red on one test assertion (certain). Several CI choices put the 2000-minute budget at risk. I also found one real crash path in the WKUIDelegate and one iOS-specific backup interaction that Android avoids.

---

## BLOCKERS

### B1. `FloorBridgeTests.testDocumentStartScriptEscapesConfigAndCapturesPrompt` fails (certain)
- ios/SecureChatTests/FloorBridgeTests.swift:51 `XCTAssertFalse(s.contains("parseInt"))`
- The injected script contains the JS comment `// only as an int32 — no parseInt/Number/RegExp, …` (ios/SecureChat/WebShell.swift:85). That comment is inside the `"""` literal, so it ships in the document-start script, and the assertion is false.
- Effect: `** TEST FAILED **`, and the CI job is red on every run.
- Fix: reword the comment (for example "no global parse functions"), or strip `//…` lines before asserting. A better check is the behaviour itself, which test02 already covers in real WebKit.

### B2. The simulator picker can choose a runtime the selected Xcode cannot drive (likely, CI)
- ios/scripts/pick-simulator.py picks the newest `iOS-X-Y` runtime from `simctl list devices available`. The workflow never pins Xcode; it only prints `xcodebuild -version`.
- On `macos-15` images, CoreSimulator is system-wide. When a newer Xcode is also installed (GitHub has shipped Xcode 26 plus iOS 26 runtimes alongside a 16.x default on macos-15), `simctl` lists iOS 26 devices while `xcodebuild` is 16.x. The result is "Unable to find a destination matching … / runtime not supported". The reverse can also happen: the default Xcode changes under you and the app builds against a different SDK and Swift compiler than the one reviewed.
- Fix: pin Xcode (`sudo xcode-select -s /Applications/Xcode_16.4.app`, or whatever version you target). Then keep only runtimes whose major version is ≤ `xcrun --sdk iphonesimulator --show-sdk-version`. The script can take the SDK version as argv. This costs nothing and turns an image drift into an obvious error.

---

## MAJORS

### M1. WKUIDelegate: a failed `present` crashes the app (certain mechanism, rare trigger)
- ShellUIDelegate.swift:350-401. If `top.present(a, …)` does not happen, the alert and its actions are deallocated along with the WebKit `completionHandler`. That covers "already presenting", a presentation in progress, or a presenter that is being presented or dismissed. WebKit's `CompletionHandlerCallChecker` then raises `NSInternalInconsistencyException: Completion handler passed to -[… webView:runJavaScript…Panel…] was not called`. The app crashes.
- Trigger examples:
  - A JS `alert`/`confirm`/`prompt` arrives while the export share sheet is animating in (`downloadDidFinish`).
  - A JS dialog arrives while the Relay settings alert is being presented.
  - `top()` returns a VC that `isBeingPresented`. It skips only `isBeingDismissed` children, and it never checks the top VC itself.
- Fix: wrap each completion in a once-guard. After `present(…)`, check on the next runloop turn (or in the completion) that `a.presentingViewController != nil`, and answer the default (`()` / `false` / `nil`) if it is not. Alternatively, queue dialogs until any transition finishes.

### M2. Backup and restore leaves the stores fail-closed; Android avoids this with `allowBackup=false` (likely)
- PadFloor excludes the floor file from backup, and the HMAC key is `…ThisDeviceOnly`. The WKWebsiteDataStore `.default()` data under `Library/WebKit/WebsiteData` IS backed up by default. That data holds the encrypted identity plus contact and chat stores, whose AEAD records "native floor expected".
- After an iCloud or Finder restore, including a new-phone migration, the stores come back but every `contacts:`/`chats:`/pad floor reads ABSENT. The client treats ABSENT-where-expected as destruction and fails closed. The user gets an app that unlocks into rollback/tamper errors instead of a clean start or a clean restore.
- Android never reaches this state because nothing is backed up.
- Fix: mark the WebKit website-data directory excluded from backup at launch (after the first load creates it; re-apply each launch), or move to a custom `WKWebsiteDataStore(forIdentifier:)` (iOS 17) and exclude its directory. Document the behaviour either way.
- Related (worth checking): WebKit storage is best-effort. It can be evicted under storage pressure, and ITP applies to WKWebView apps. The only copy of the identity lives there. Consider `navigator.storage.persist()` from the page, and say so in ios/README.md.

### M3. CI can hang until the 35-minute job timeout, which costs about 350 billed minutes (likely under some failures)
- `Page.eval` uses `callAsyncJavaScript` inside a checked continuation with no timeout. If any native JS dialog is left on screen, the web process blocks in the synchronous dialog and every later `eval` never resumes. That can happen through a future client change that adds an `alert` to onboarding. It also happens in test05/test06: when `presentedAlert()` returns nil, `return`/`XCTFail` leaves a late-appearing prompt pending. Nothing bounds this: xcodebuild's test timeouts are off by default.
- Fix:
  - Pass `-test-timeouts-enabled YES -default-test-execution-time-allowance 120 -maximum-test-execution-time-allowance 300` to `xcodebuild test`.
  - Add `timeout-minutes: 20` on the test step and lower the job timeout to about 25.
  - Put a timeout race on `Page.eval`.
  - In `tearDown`, dismiss and answer any presented alert through the same handler trick.

### M4. Minute burn from trigger scope (certain, budget)
- `on: push: paths: ios/**` fires on every branch push that touches ios/, including ios/README.md-only commits. Each run is about 12-15 real minutes, which is 120-150 billed minutes, so 2000 minutes buys about 13 pushes. A review/fix loop like this one can use that up in days.
- The Release IPA step rebuilds everything in Release on every run. That is about 2-4 real minutes, or 20-40 billed.
- Fix:
  - Add `!ios/**/*.md` to `paths`.
  - Run the IPA step only on `workflow_dispatch`, tags or main (`if: github.event_name == 'workflow_dispatch' || github.ref == 'refs/heads/main'`).
  - Consider making push runs dispatch-only while iterating.

### M5. Web content ignores Dynamic Type; Android honours the system font scale (certain, a11y parity)
- Android WebView's default `textZoom` follows the system font scale. WKWebView ignores the iOS Larger Text setting unless the CSS uses `-apple-system-*` fonts. The native shell does nothing to bridge this.
- Fix: set `webView.pageZoom` (iOS 14+) from `UIFontMetrics.default.scaledValue(for: 1)` (clamp to about 1.0–2.0). Update it on `UIContentSizeCategory.didChangeNotification`. The client's responsive layout should absorb this, but it needs checking at AX sizes.

### M6. The keyboard can cover the page's fixed bottom tab bar and composer (worth checking on device)
- The web view is pinned to `safeAreaLayoutGuide.bottomAnchor` (MainViewController.swift:47). WKWebView does not resize for the keyboard; it only changes the visual viewport. The client's `.tabbar { position: fixed; bottom: 0 }` and `--vh: 100dvh` layout were built for Android's adjustResize behaviour.
- Fix: pin the bottom to `view.keyboardLayoutGuide.topAnchor` instead. That is iOS 15+ and matches the safe area when no keyboard is shown, so the web view really resizes as on Android. Check the chat composer on a device.

### M7. The two-user test does not check what its comment claims (certain)
- TwoUserE2ETests.swift:126-133 says "their generation floors exist and are positive". The JS computes `f` and `ids` and never uses them; only `marker === true` is asserted.
- Either read `f.read('contacts:'+idHash)` / `f.read('chats:'+idHash)` and assert > 0, or delete the comment. The idHash is available from the client modules.

---

## MINORS

### CI
1. **`! ls "$APP/web" | grep -q "\.test\.mjs$"` is a no-op (certain).** Under `bash -e`, a `!`-negated pipeline never triggers errexit. Use `if ls … | grep -q …; then echo …; exit 1; fi`.
2. **The `strings` check cannot see `SC_TEST_RELAY` (certain).** That literal is 13 bytes, and Swift stores literals of 15 bytes or fewer inline as instruction immediates, not in `__cstring`. `SC_PERSIST_PROBE` (16 bytes) is caught. Grep for `DebugHooks` as well (a type name in reflection metadata) or `persist-probe.txt`.
3. **The cold relaunch assumes the simulator is still booted after `xcodebuild test`.** It usually is, but `get_app_container` fails on a shut-down device. Add `xcrun simctl bootstatus "$UDID" -b` first; it costs about 1 second.
4. **The relay uses whatever `python3` the macOS image has; the gate pins 3.12.** Wheels for cryptography, pydantic-core and uvloop on a newer default could slow or break the install. Add `actions/setup-python@v5` with 3.12 in the ios job (cheap).
5. **Silent skips.** `TestApp.mainPage` throws `XCTSkip`, and xcodebuild still prints `** TEST SUCCEEDED **` when InPage and E2E are all skipped. In CI the relaunch probe happens to catch the no-relay case, because test07 never ran. Locally it passes silently. Use `XCTFail` plus throw, or fail CI on skipped > 0 via `xcresulttool`.
6. **`brew install xcodegen` takes about 20-60 seconds of 10x minutes.** The release zip from GitHub is faster and pins the version.

### Tests
7. **Ordering dependency.** The relaunch probe depends on `InPageTests.test07` having run. The e2e depends on Alice having no identity yet, so it fails on a second local run against the same simulator. Give Alice a fresh state: erase the website data store in `setUp`, or use `forget`.
8. **`TestApp.presentedAlert` returns an alert that `isBeingDismissed`.** After `dismiss(animated:false)` in test06 the stale prompt could in principle be returned; tapping its action again would call the WebKit completion twice, which raises. The timing makes this unlikely (a JS round trip happens in between), but add `!alert.isBeingDismissed`.
9. **The `UIAlertAction` `handler` KVC plus `unsafeBitCast` trick** works on iOS 17 and 18 and is widely used. If Apple renames the ivar, `value(forKey:)` raises `NSUnknownKeyException`, which Swift cannot catch and which kills the host. Acceptable for tests; just be aware of it.
10. **`(vc, page) = try await TestApp.mainPage()`** (InPageTests.swift:174) assigns a `(A, B)` value to `(A!, B!)` lvalues. Tuple element-wise optional conversion should compile in Swift 5.10/6. If it does not, use `let (v, p) = …; vc = v; page = p`. Worth checking only.
11. **test02 writes random floor ids into the real `PadFloor.shared` file.** Harmless, but it pollutes the app's store.

### Runtime / platform
12. **Keychain on the simulator with ad-hoc signing, no team and no entitlements (worth checking; the biggest unknown for the first CI run).** If `SecItemAdd` returns `-34018`, then `keychainKey()` returns nil and every floor op answers TAMPERED. That fails test02 and testKeychainKeyIsStable and fail-closes the e2e stores. More generally, `verifyScript` only proves that the bridge exists. A nil `PadFloor.shared` or an unavailable key gives a running app where every store fails closed, instead of the refusal screen. Probe `PadFloor.shared?.bump("probe", 0) != tampered` natively before loading, and send failure to `refuseToRun`.
13. **`keychainKey()` runs `SecItemCopyMatching` on every read, and twice per bump.** Each call happens on the main thread while the web process blocks in `prompt()`. Cache the key after the first successful fetch.
14. **Relay re-prompt on invalid input** is presented from the Save handler (MainViewController.swift:164). If UIKit still lists the old alert as `presentedViewController`, the new one is dropped, and a first-run user is left with an empty screen; only the ⋯ menu's Reload re-prompts. Present it in `DispatchQueue.main.async`, or from the dismissal completion.
15. **`onProcessTerminated` reloads unconditionally.** A page that crashes the content process on load (memory) will reload forever. Cap the retries.
16. **Deprecation warnings (no errors):**
    - `UIScreen.isCaptured` and `capturedDidChangeNotification` are deprecated on iOS 18; `traitCollection.sceneCaptureState` plus `registerForTraitChanges` is available on iOS 17.
    - `MainActor.assumeIsolated { self?.… }` returns `()?`, which may give an unused-result warning.
    - `String(contentsOf:)` without an encoding in PadFloorTests.
17. **No `PrivacyInfo.xcprivacy`.** `UserDefaults` is a required-reason API (CA92.1), and App Store Connect rejects uploads without the manifest. It does not matter for the unsigned IPA, but it will block submission. `ITSAppUsesNonExemptEncryption` is also absent.
18. **`NSAllowsLocalNetworking` ships in Release.** `RelayUrls` only allows loopback anyway, but the exemption could be Debug-only through a separate plist or `INFOPLIST_PREPROCESS`.

### Native a11y / platform fit
19. **Privacy shield (SceneDelegate.swift:198-221).**
    - While screen capture is active, sighted users see only a lock glyph and no visible text explaining why the app went blank. The explanation exists only as the VoiceOver label. Add a visible label, for example "Hidden while your screen is recorded or shared", with Dynamic Type.
    - The code does not post `UIAccessibility.post(notification: .screenChanged, argument: v)` on show or `.screenChanged, nil` on hide. VoiceOver focus can stay on, and re-read, the now-hidden element under the shield.
    - The label is chosen at show time and goes stale if capture starts while the shield is already up for inactivity.
    - Alerts presented after the shield sits above it; the keyboard window is never covered. Consider `window.endEditing(true)` when capture begins.
20. **Refusal screen (MainViewController.swift:88-122).**
    - The text is centred in a plain stack with no scroll view. At accessibility text sizes the body runs off-screen and cannot be reached. Put it in a `UIScrollView`.
    - It does not post `.screenChanged` with the title, so VoiceOver focus is left on the removed web view.
21. **Nav bar.** An opaque 44/32 pt bar exists only for the ⋯ button, above the page's own header. That costs a lot of height in landscape on iPhone. It is acceptable because recovery needs it natively (the same argument as on Android), but consider `hidesBarsWhenVerticallyCompact` or hiding the bar in landscape. The label "App menu" is fine; iOS convention for ⋯ is "More".
22. **Secret prompt field.** Consider `textContentType = .oneTimeCode` (or leaving it nil explicitly) so the Passwords AutoFill bar does not offer Keychain credentials for pad passphrases. Worth checking on device.
23. **Floor calls go through WebKit's modal-dialog path.** Every floor op runs `Chrome::runJavaScriptPrompt`, which defers loads and exits fullscreen, and on iOS it interacts with the focused-element and keyboard state. Check on a device that typing in the composer while messages arrive (which triggers floor bumps) does not drop focus, the keyboard, or an open `<select>` picker.

---

## Things I checked that are fine
- **Swift signatures:**
  - WKURLSchemeHandler `webView(_:start:)` / `webView(_:stop:)`.
  - WKNavigationDelegate policy methods (both), `navigationAction:didBecome:` and `navigationResponse:didBecome:`.
  - WKDownloadDelegate: all three.
  - WKUIDelegate: `createWebViewWith`, alert, confirm, prompt.
  - `UIBarButtonItem(image:menu:)`, `UIMenu(children:)`, `WKDownload.cancel(_:)`, `callAsyncJavaScript(_:arguments:in:in:completionHandler:)`.
  - CryptoKit `HMAC.isValidAuthenticationCode` (the ContiguousBytes overload, constant-time and length-safe), `Data(mac)`, `Data.WritingOptions.completeFileProtectionUntilFirstUserAuthentication`.
- **Concurrency.** Missing Sendable/isolation annotations on completion-handler parameters are warnings only in Swift 5 mode for Clang-imported WebKit/UIKit, and `SWIFT_STRICT_CONCURRENCY: minimal` is set.
- **Theme.** `0x0D / 255` is CGFloat division, not integer division.
- **XcodeGen spec.** Keys are valid (`postCompileScripts`, `basedOnDependencyAnalysis`, scheme `[test]`, `TEST_HOST`/`BUNDLE_LOADER`). sync-web.sh is committed as 755. `UNLOCALIZED_RESOURCES_FOLDER_PATH` puts the files in `SecureChat.app/web`. XcodeGen's debug preset supplies `DEBUG` and `ENABLE_TESTABILITY`.
- **Info.plist and assets.** The scene configuration comes from the AppDelegate. `UILaunchScreen` color is set. The 1024 px icon is RGB with no alpha.
- **Bundled file names.** Every name matches the scheme handler's whitelist (checked all of client/ except tests).
- **Test environment.** `TEST_RUNNER_` variables reach the app-hosted test process. `SIMCTL_CHILD_` plus `get_app_container … data` is the right mechanism for the relaunch probe.
- **XCTest ordering.** Classes and methods run alphabetically, so the `test01…test99` naming works.
- **Delegate lifetimes.** They are retained by the VC (lazy vars) and by the test instance for Bob. The scheme handler is retained by the configuration.

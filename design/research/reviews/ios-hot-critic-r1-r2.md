# Hot critic: iOS shell, round 1

Scope: the native layer only (ios/SecureChat/*, Assets, Info.plist) and how it meets the shared web client on an iPhone 16 (393x852 pt). All colours below were sampled from the shots5 PNGs, not eyeballed.

Measured facts used throughout:

| Region (portrait, iPhone 16) | pt (y) | Colour | Source |
|---|---|---|---|
| Status bar + native nav bar | 0 to 97.7 | `#11161d` (Theme.bgTop) | SceneDelegate appearance |
| Web wordmark bar (`.apphead`) | 97.7 to 145 | `#0d1117` (`--bg`) | style.css `.apphead { background: var(--bg) }` |
| Page body just under it | 146 onward | `#11161f` fading to `#0d1117` | body gradient `--bg-top` to `--bg` |
| Conversation head (`.convo-head`) | 97.7 to 206 | `#161c23` (`--panel`) | |
| Composer bar | 404 to 472 | `#161c23` (`--panel`) | |
| Tab bar | 753.7 to 818 (64 pt) | `#0d1117` | |
| Home-indicator strip | 818 to 852 (34 pt) | `#0d1117` (Theme.bg) | view background |
| App icon glyph bbox | 260..762 x 205..817 of 1024 | 49% w, 60% h, bbox-centred (cy 511), mass centre cy 580 | |
| Privacy-shield lock | 26 x 37 pt, centred at (196.5, 425.8) | `#2f81f7` | SF Symbol `lock.fill` |

---

## BLOCKERS

### B1. The native bar is a different colour from everything next to it
In every screenshot the top of the screen is three bands. First the bar at `#11161d`. Under it is the web wordmark bar, which is darker at `#0d1117`. Under that the page gradient starts again at `#11161f`. In a conversation the bar is `#11161d` and the header under it is `#161c23`. So the bar matches neither the header below it nor the launch screen (`LaunchBackground` = `#0D1117`). The top band changes colour at launch, and the 44 pt band reads as a separate strip of chrome.

`Theme.bgTop` was chosen on the theory that "the page gradient starts here". That theory is wrong: the first thing the page paints is `.apphead`, a solid `--bg`. This also breaks the design contract. design/README.md says "the native status/navigation bars use `bg` and `fg`". The Android shell does the same (`Widget.SecureChat.ActionBar` background = `@color/app_bg` = `#0D1117`).

**Change**
- `SceneDelegate.swift`: `appearance.backgroundColor = Theme.bg` (was `Theme.bgTop`).
- `Theme.swift`: delete `bgTop`. Nothing else uses it, and keeping it invites the same mistake again.
- Keep `shadowColor = .clear`. The web bar already draws its own `--border-soft` hairline underneath.

Result: on Live room, Users, Profile and Chats (list), the status bar, the native bar and the web wordmark bar become one `#0d1117` surface, the way Android looks. The launch frame to first frame is seamless too.

### B2. The shield does not cover alerts or the keyboard (and the recording note says it does)
`showShield()` adds a subview to the app window. A `UIAlertController` presented later goes into a new transition view added above it. While the screen is recorded or mirrored, the cover stays up and the app stays active. If the page then raises a `confirm()` or `prompt()`, or the relay alert opens, that alert draws on top of the shield and shows up in the recording. The keyboard's window (with QuickType suggestions of what is being typed) is also above it. The label on the shield says "Hidden while the screen is being recorded or shared", which is then untrue. This is a design-integrity issue as much as a security one.

**Change** (`SceneDelegate.swift`)
- Make the shield its own window: `let w = UIWindow(windowScene: windowScene); w.windowLevel = .alert + 1; w.backgroundColor = Theme.bg; w.rootViewController = ShieldViewController()`. Show it with `w.isHidden = false`, hide it with `w.isHidden = true`. Keep `accessibilityViewIsModal`.
- In `showShield()` call `window?.endEditing(true)` so the keyboard (and its suggestion bar) goes down with it.
- Give the new window `overrideUserInterfaceStyle = .dark`.

---

## MAJORS

### M1. Keep the native bar; do not float the menu over the web header. Make the bar cheaper instead.
The empty bar is justified for the reason Android gives. Relay settings has to be reachable when the page cannot load, and it has to be reachable in every view, scroll position and orientation. I checked the alternatives against the actual CSS. None of them is safe from the native side:

| Alternative | Why it fails |
|---|---|
| Float a 44 pt button at the web header's right edge, vertically centred on it (safe top + 24 pt) | **Wordmark views:** `.apphead` is `position: static` on phones and scrolls away, so the button would detach and sit over content. It would cover the step progress line, the right-edge "?" and Copy buttons, and the card edges. **Live room chat** (`#scrChat .topbar`): Copy and Leave are 44 pt buttons flush to the right edge with only `--sp-1` padding, so the overlap is certain. **Conversation** (`.convo-head`): the name wraps rather than truncates, so the trust pill ("unverified •••", right edge at 317 pt today) reaches the right edge for longer names. The free space is only about 64 pt today. **Landscape:** 734 pt is over 600 CSS px, so the page switches to the desktop header with the tabs right-aligned, and the button would land on Profile. |
| Status-bar row | Owned by the system: clock, Dynamic Island, battery. A tap there means scroll-to-top. Not allowed and not reachable. |
| Bar carries the wordmark | The web bar below already shows the wordmark, so you get two stacked "secure-chat" bars. This is exactly the bug Android removed (themes.xml comment). |
| `hidesBarsOnSwipe` | The web view resizes on every hide and show, so `100dvh` and the chat stage height reflow under the finger. Cold review r2 already failed a design for moving targets under a touch. |

The truly native fix would be for the shell to own the only bar (wordmark plus menu) and the page to drop its phone wordmark bar inside the app. That is a client change, so I only note it for the owner and do not recommend it here.

**What to do in the native layer, on top of B1:**
1. **Hide the bar while the keyboard is up.** That is when the 44 pt costs most: in shot 12 the visible log is only 197 pt, and 44 pt more is +22%. Nobody opens Reload or Relay settings mid-sentence. In `MainViewController`, observe `UIResponder.keyboardWillShowNotification` and `keyboardWillHideNotification`. Only when `presentedViewController == nil` (so an alert's own text field does not trigger it), call `navigationController?.setNavigationBarHidden(show, animated: true)` inside `UIView.animate(withDuration: info[duration], delay: 0, options: curve << 16)` so it rides the keyboard's curve. Re-run the cold-review r2 "first tap on Send/Connect lost" scenario before accepting. If it regresses, show the bar again on `keyboardDidHide` instead of `WillHide`.
2. **Hide the bar on the refusal screen** (see M5). There is nothing left in it once `rightBarButtonItem = nil`.
3. Keep `ellipsis.circle`, which is the iOS "more" idiom. Rename the item to **"Relay settings…"**: it opens a dialog, and iOS menus mark that with an ellipsis. Keep sentence case to match the web copy. See also m4.

### M2. Chat views have a two-tone seam at top and bottom; the chrome should follow the page's edge colour
With B1 fixed, the non-chat views are seamless. The two chat views are not. The conversation head and the live-room `.topbar` are `--panel` `#161c23` under a `#0d1117` bar. With the keyboard down, the composer bar (`#161c23`) sits on a 34 pt `#0d1117` home-indicator strip. Messages, Signal and WhatsApp all run the composer surface to the bottom edge. Here a dark strip is left under it, which is the most visible "web page in a frame" tell after B1.

**Change:** have the native layer read the page's top and bottom edge colours and paint the bar and the bottom strip with them.
- Add a `WKUserScript` in an isolated `WKContentWorld.world(name: "shell-chrome")`, `forMainFrameOnly: true`, `.atDocumentEnd`. The page's own scripts cannot see or forge an isolated world. The script:
  - finds the first opaque computed `backgroundColor`, walking up the ancestors of `document.elementFromPoint(innerWidth - 2, 1)`;
  - does the same for `document.elementFromPoint(innerWidth - 2, innerHeight - 1)`;
  - posts both `{top, bottom}` through `webkit.messageHandlers.chrome` (register the handler with `add(_:contentWorld:name:)` in that world only);
  - re-runs from a `MutationObserver` on `attributes: true, attributeFilter: ["hidden"], subtree: true` and on `resize`, throttled with `requestAnimationFrame`.
- Native side: parse only `rgb(r, g, b)` with alpha 1 and ignore anything else. Set `UINavigationBarAppearance.backgroundColor` for the top colour, re-assigning `standardAppearance` and `scrollEdgeAppearance`. Put a plain `UIView` pinned between `wv.bottomAnchor` and `view.bottomAnchor`, behind the web view, and give it the bottom colour.

It is read-only, cannot run anything, and the worst a hostile page can do is choose two colours. Worth a line in ios/README.md so the security reviewers see it. Expected result: conversation = `#161c23` bar, then the head, and the composer continues into the home-indicator strip. Wordmark views stay `#0d1117`.

If this is judged too much for v1, ship B1 alone. The seam is then limited to the two chat views.

### M3. Dynamic Type zoom breaks the web layout at accessibility sizes
`pageZoom` goes up to 2.0. On a 393 pt screen that leaves a 196 CSS px viewport, and on an iPhone SE (375 pt) 187 px. The web UI was designed and reviewed down to 320 px (style.css: "Below 360px Disconnect becomes an icon too"). At AX sizes the tab labels, the conversation head and the safety-number grid will overflow or clip. The native layer caused this, so the native layer should cap it.

**Change** (`MainViewController.applyTextSize`):
```swift
let wanted = Self.pageZoom(for: traitCollection.preferredContentSizeCategory)
let width = webView?.bounds.width ?? view.bounds.width
webView?.pageZoom = min(wanted, max(1.0, width / 320))
```
Call it again from `viewDidLayoutSubviews` when the width changes (rotation). On an iPhone 16 this caps at 1.23, which is about 18.4 pt body text. That is less than AX5 asks for, but it is legible and not broken. Verify with screenshots at XXXL and AX3. Note in ios/README.md that system Zoom covers the rest.

### M4. Landscape on iPhone is unreviewed and lands in the desktop layout
The plist allows landscape. In landscape the web view is 734 pt wide (852 minus 2 x 59 side insets), which is over 600, so the page switches to its desktop layout. That means a 56 px sticky top bar holding the tabs and `--control-h: 40px`, below the 44 pt touch minimum the contract requires on phones. The height is 393 - 32 (compact bar) - 21 (home indicator) = 340 pt. With the keyboard up, roughly 100 pt is left, minus the 56 px sticky bar. None of this appears in any screenshot. The side strips (Theme.bg) are fine.

**Change, pick one:**
- (a) Recommended for v1: portrait only on iPhone. In `Info.plist`, `UISupportedInterfaceOrientations` = `[UIInterfaceOrientationPortrait]`. Signal on iPhone is portrait-only outside media, which is precedent. This also removes the M1 landscape collision question.
- (b) Keep landscape and hide the native bar in compact height: `registerForTraitChanges([UITraitVerticalSizeClass.self])` then `setNavigationBarHidden(traitCollection.verticalSizeClass == .compact, animated: true)`. The menu is back as soon as the phone is upright. Then take screenshots of the landscape conversation with the keyboard up, and of Live room step 1, before release.

### M5. The refusal screen should be a native empty state, not a left-aligned paragraph
Shot 08-refused: a regular-weight `title2` and four lines of muted body, left-aligned, vertically centred in the window, with no symbol, under an empty bar. On iOS this pattern is `UIContentUnavailableConfiguration` (iOS 17, the deployment target is 17.0). It gives centred alignment, the system spacing, Dynamic Type, scrolling and the readable width for free, and replaces around 30 lines of hand-built constraints.

**Change** (`MainViewController.refuseToRun`):
```swift
navigationController?.setNavigationBarHidden(true, animated: false)
var c = UIContentUnavailableConfiguration.empty()
c.image = UIImage(systemName: "lock.trianglebadge.exclamationmark")
c.imageProperties.tintColor = Theme.muted          // not accent: nothing to act on here
c.text = "Cannot start securely"
c.textProperties.color = Theme.fg
c.secondaryText = "<same body copy>"
c.secondaryTextProperties.color = Theme.muted
c.background.backgroundColor = Theme.bg
contentUnavailableConfiguration = c
```
Keep the `.screenChanged` post (to the view). The copy is good, so keep it. Do not use `--err` red: nothing is on fire for the user, and red would read as "your data is gone".

---

## MINORS

### m1. Privacy shield: use the brand padlock, not SF `lock.fill`, and size it for the app switcher
The switcher already prints the app name and icon above the card, so the wordmark would be redundant. What the card should show is the same padlock as the icon. `lock.fill` has a narrower, taller shackle and a different body ratio, so shield and icon read as two locks. At 26 x 37 pt, the switcher's roughly 0.5x scale makes it tiny.
- Export the icon glyph (the Android `ic_launcher_foreground.xml` paths, already in icon.mjs) as a single-scale vector `BrandLock.pdf` (or `.svg`) imageset, with **Preserve Vector Data** on and **Render As: Template**.
- Shield: `UIImageView(image: UIImage(named: "BrandLock"))`, tint `Theme.accent`, 64 x 64 pt, centred with `centerYAnchor` offset by -16 pt (optical centre; the body is the heavy part). Keep the recording note 16 pt under it.
- Build it as a `ShieldViewController` (see B2) and use the same view for the refusal's background colour, so the three "not the app" screens (launch, shield, refusal) share one ground.

### m2. App icon: optically centre it, align it with Android, add iOS 18 variants
The glyph is bbox-centred (cy = 511/1024), but its mass centre is at cy = 580: the solid body pulls it down, so on the home screen it reads as sitting low. The size, 60% of the height, is fine for a single solid glyph on the iOS grid; keep it at 57 to 60%. Android is inconsistent in the other direction: bbox centre at 46.6/108, which is 7% high. Fix both to one rule: bbox centre about 2% above canvas centre.
- In `scratchpad/icon.mjs`, change `viewBox="10 2.6 88 88"` to `viewBox="8.6 2.95 90.8 90.8"`, with the rect to match. That gives a 594 px glyph (58%) with its bbox centre at y = 492, and mass centre about 560. Regenerate `icon-1024.png`.
- Android (a follow-up for its owner): translate the foreground paths by `+5.4` in y. Group them in `<group android:translateY="5.4">` so the bbox centre sits at 52 of 108.
- iOS 18: add a `dark` appearance (the glyph in accent on a **transparent** background; iOS supplies the dark ground) and a `tinted` appearance (the glyph in white or grey on transparent, the counterpart of Android's `ic_launcher_monochrome`). In `AppIcon.appiconset/Contents.json`, add two more `1024x1024` entries with `"appearances": [{"appearance":"luminosity","value":"dark"}]` / `"tinted"`. Without them, iOS 18's dark and tinted home screens auto-derive a muddy version.

### m3. Relay alert: too dense for what it is
Shot 08: 4 lines of footnote text, half of it about loopback testing, above one field. Most people see this once, on first run.
- Message: **"Where your encrypted messages are passed on. The relay only ever sees ciphertext."**
- Move the https / loopback rule into the error re-ask only, where it is the answer. Error text: **"Use an https:// address with no path. http:// works only for 127.0.0.1, when testing."**
- Title "Relay address", the placeholder and Save/Cancel are good. The alert tint already comes out as `#2f81f7` (sampled) through `AccentColor`, so no change there.

### m4. Secret prompt and confirms: small native touches
- Secret prompt (shot 05): the field is empty with no placeholder. Set `field.placeholder = secret ? "Passphrase" : nil`. The page text is the message, and without a title iOS sets it in the bold title style, which reads well. Keep that.
- Keep OK/Cancel. The shell cannot know the verb, and guessing from the text is fragile. Do not add keyword-based `.destructive` styling.

### m5. The page reflows behind alerts
Shot 08-relay-settings: the alert's text field brings up the keyboard. `wv.bottom = keyboardLayoutGuide.top` then shrinks the web view behind the dimming. The tab bar jumps up to mid-screen over "Continue without an identity", and snaps back on dismiss. The same happens behind every JS prompt.
- In `MainViewController`, keep two bottom constraints: `kb = wv.bottom == keyboardLayoutGuide.top` and `safe = wv.bottom == safeAreaLayoutGuide.bottom`.
- Before presenting any alert (`promptForRelay`, and `ShellUIDelegate.show` through a `presenter` hook), activate `safe` and deactivate `kb`. On the alert's action handlers, and in the `fallback`, swap back.
- This pairs with M1.1 (do not hide the bar for an alert's keyboard).

### m6. Tab bar and home indicator: fine as is (no change)
Measured: the tab bar is 64 pt (753.7 to 818), then the 34 pt home-indicator strip. Both are `#0d1117`, so the seam is invisible. The tab labels end about 11 pt above the safe-area line. `env(safe-area-inset-bottom)` is 0 inside the safe-area-pinned web view, so there is no double inset. The bottom chrome is 98 pt against a native tab bar's 83 pt; that is the reviewed 64 px web tab bar, so leave it.

### m7. Smaller "website in a box" tells that the shell can remove
- **Pinch and double-tap zoom** still work on the page, which makes it feel like a web page. Dynamic Type (M3) and system Zoom cover the accessibility need. Set `wv.scrollView.pinchGestureRecognizer?.isEnabled = false` after the first load (the recogniser is created lazily), or set `scrollView.minimumZoomScale = scrollView.maximumZoomScale = 1` in `webView(_:didFinish:)`.
- **Rubber-band overscroll at the top** shows `scrollView.backgroundColor` (already Theme.bg, good). With M2, set `wv.underPageBackgroundColor` to the same top colour so pulling down in a chat view does not flash a dark gap above the panel head.
- The WKWebView **form accessory bar** (‹ › Done above the keyboard) is the strongest remaining tell in the composer. It can only be removed by swizzling `WKContentView.inputAccessoryView`, which is private-class surgery. **Do not do it** in a security app; accept it. Recorded here so nobody re-raises it.
- **Edge-swipe back** in a conversation is expected on iOS but needs the client (its back is not history). Out of scope; noted for a client follow-up.

---

## Not changing (checked, fine)
- Dark-only (`UIUserInterfaceStyle = Dark` plus window override): correct for a single-palette design system.
- Alerts are dark, the tint is `#2f81f7` (sampled from shots 05 and 08), and system alerts are the right call for secrets (secure field, no page-side DOM).
- `navigationBar.tintColor = Theme.fg` for the ⋯: correct. The accent is reserved for "act here / you are here".
- The recording note copy and `callout` style.
- `isOpaque = false` + `backgroundColor = Theme.bg`: no white flash on load.

---

# Round 2 (HEAD 229626e; screenshots from CI run 6 in shots6/)

I checked every round-1 item against pixels sampled from shots6 (the same method as round 1) and against the code at HEAD.

## Round-1 items

| Item | Status | Evidence |
|---|---|---|
| B1 bar colour | **Fixed** | 10, 11: one `#0d1117` run from 0 to 144.7 pt (status bar, bar and web wordmark bar), then the web hairline. 06 (dimmed behind the alert): one uniform run. `Theme.bgTop` is deleted. |
| B2 shield over alerts/keyboard | **Fixed** | `shieldWindow` at `.alert + 1`, `endEditing` on show, `keyboardWillShow` dismissal while it is up. The comment now says what the window level does not cover. See R2-m2 for a side effect. |
| M1 hide bar with keyboard | Deferred, **accepted** | The lost-first-tap risk is real. In 12-keyboard the log is 206 to 403 pt (197 pt): tight but usable. |
| M2 per-view seams | Deferred, **accepted as known debt** | Still there, exactly as predicted. 12: `#0d1117` bar over the `#161c23` conversation head; the composer panel ends at 817.7 pt with a 34 pt `#0d1117` strip under it. This is the one remaining "web page in a frame" tell. |
| M3 zoom cap | **Fixed** | `appliedZoom = min(wanted, max(1, width/320))`, re-applied in `viewDidLayoutSubviews` only when it changes. The extraSmall 0.85 case gives 462 CSS px on an iPhone 16 and 517 on a Pro Max, both under 600, so no desktop layout. No regression. |
| M4 landscape | **Fixed** (portrait only) | Info.plist. The app is iPhone-only (`TARGETED_DEVICE_FAMILY 1`), so there is no iPad multitasking constraint. |
| M5 refusal | **Fixed** | 08-refused: centred symbol in muted colour, semibold title, centred body, bar hidden. Reads as a native iOS empty state. |
| m1 shield glyph | **Fixed** | 08-privacy-shield: the brand padlock, 50 x 61 pt, bbox centre at 408.8 pt, which is 17 pt above the screen centre as specified. Same shape as the icon. |
| m2 icon | **Fixed** | Light: glyph 487 x 593 px (58%), bbox centre y 491.5, mass centre 558 (was 511 / 580). Dark: accent glyph on a transparent background. Tinted: white glyph on a transparent background. Same bbox in all three. |
| m3 relay copy | **Fixed** | The short message is in place; the transport rule appears only on error. |
| m4 placeholder | **Fixed** | 05: the "Passphrase" placeholder renders; the accessibility label matches it. |
| m5 reflow behind alerts | Deferred, accepted | Still visible: in 05 the page's tab bar has gone behind the dim because the alert's keyboard shrank the web view. Cosmetic only. |
| m7 zoom/overscroll | **Partly verified** | `underPageBackgroundColor = Theme.bg` is good. The pinch disable is set in `viewDidLoad`, where `scrollView.pinchGestureRecognizer` is normally still nil. WebKit also resets `min/maxZoomScale` from the viewport on each load. So pinch and double-tap zoom may still work. See R2-m3. |

## New findings (regressions and gaps in the fixes)

### R2-M1 (major, small fix). The crash-loop screen's filled button uses the colour the design system rejected for white text
`showCrashLoop` uses `UIButton.Configuration.filled()` with no colour set, so it takes the global `AccentColor`, `#2f81f7`. White on `#2f81f7` is 3.8:1. The design contract replaced exactly that pair with `--accent-fill` `#1f6feb` (4.6:1) for every primary fill, and it is the only filled button in the whole native layer. It fails WCAG AA for the button label.
**Fix:** add `static let accentFill = UIColor(red: 0x1F/255, green: 0x6F/255, blue: 0xEB/255, alpha: 1)` to `Theme.swift`. Then set `button.baseBackgroundColor = Theme.accentFill` and `button.baseForegroundColor = .white`. Do not change `AccentColor`: it is right as text on dark (alert buttons, caret).

### R2-M2 (major, logic plus visual). Reload and Relay settings do not clear the crash-loop screen
The crash-loop view sits under the bar, so the ⋯ menu stays reachable, which is good. But `load()` does not remove `crashView`, un-hide the web view or reset `crashTimes`. If the user picks **Reload**, or saves a new relay via **Relay settings…** (the natural move when the page keeps dying), the page loads behind a hidden web view. The user keeps seeing "stopped responding" over a working app, until "Try again" happens to be tapped.
**Fix:** in `load(_:)`, before loading, add `if crashView != nil { crashView?.removeFromSuperview(); crashView = nil; webView?.isHidden = false; crashTimes = [] }`. Then `retryAfterCrashLoop()` reduces to `if let r = Prefs.relay() { load(r) }`.

### R2-m1. Crash-loop copy and layout
- The copy is good. In particular "Your identity and chats are still on this device" is right, and it is right to avoid "reinstall".
- The view is pinned `top = safeArea.top`, `bottom = view.bottom`, while the refusal view is pinned to `view.top`. Both are fine, because `UIContentUnavailableView` centres within its own margins. The crash screen's centre then sits about 22 pt lower than the refusal's. That is acceptable; they are never seen together.

### R2-m2. The shield now drops the keyboard on every resign-active
`showShield()` calls `window?.endEditing(true)` on every show, including plain `sceneWillResignActive`. That covers pulling down Notification Center or Control Center, an incoming-call banner, or Siri. The user loses focus in the composer and has to tap back into it on return; Messages and Signal keep it. The keyboard is not part of the app-switcher snapshot, so this protects nothing in the resign-active case. It is only needed while `isCaptured`.
**Fix:** `if isCaptured { window?.endEditing(true) }` in `showShield()`. In the `keyboardWillShow` observer, keep the dismissal but make it conditional on `isCaptured` too. In the `capturedDidChange` path, when capture starts with the shield already up, call `endEditing` there.

### R2-m3. The pinch-zoom disable is probably ineffective
`scrollView.pinchGestureRecognizer` is created lazily, and WebKit re-applies viewport zoom limits on every commit.
**Fix:** in `ShellNavigationDelegate.webView(_:didFinish:)`, set `webView.scrollView.pinchGestureRecognizer?.isEnabled = false`. Also add one XCUITest `pinch(withScale: 2, velocity: 1)` on the web view and assert that `scrollView.zoomScale == 1`.

### R2-m4. The prompt's default button is Cancel
05: "Cancel" is bold and "OK" regular. That is the system default when a `.cancel` action exists and no `preferredAction` is set. In the JS prompt (the passphrase), Return and the emphasis should go to OK. The relay alert already does this (`a.preferredAction = save`).
**Fix:** in `ShellUIDelegate` prompt, `let ok = UIAlertAction(...); a.addAction(ok); a.preferredAction = ok`. Leave `confirm()` as it is: 06 "Remove this identity from the device?" with Cancel emphasised is the right default for a destructive question.

### R2-m5. The tinted icon background (verify on device)
The tinted variant is a white glyph on a transparent background. Apple's tinted template expects a grayscale glyph; the system supplies the dark backdrop and tints by luminance, so this should work. Check it once on an iOS 18 device or simulator (Home Screen > Customize > Tinted) to confirm the glyph is not rendered at reduced contrast. There is nothing to change unless it looks washed out.

## Verdict
The native layer now **meets the bar**. Both blockers are fixed and hold up in the pixels. The bar, status bar and web head read as one surface on every non-chat view. The shield, refusal screen and icon are consistent with each other and native in feel. Portrait-only and the zoom cap remove the two layout risks.

Still open:
- **Before release (small, native-only):** R2-M1 (the button fill contrast; a contract violation) and R2-M2 (the crash screen survives Reload and Relay settings).
- **Known, accepted debt:** M2 (the chat-view seams, the most visible remaining tell), M1 and m5. Log them in ios/README.md as deliberate.
- **Minors:** R2-m2 to R2-m5, fine to batch.

There are no blockers.

# secure-chat rework — the fixed part of the direction (IA decisions + implementer contract)

Written by the orchestrator after reading client/app.js, client/index.html, client/style.css and the four e2e runs.
The polish rules (what "polished, Kali-like" means concretely) are in direction.md next to this file.

## Reconciliation of the v1 canvas with the owner's new input

Owner's input: keep the design language and colours; make the whole web client and the Android
WebView app feel *significantly* more polished, not "boxes stacked together"; orient on the Kali
website and on comparable secure messengers; everything pentested and reviewed.

v1 decisions that STAY: palette, mono-for-key-material, copy; persistent navigation (tabs) instead
of the drawer; trust marks as icon + word, no emoji; one message rendering; safety number as a
readable grid; primary fill #1f6feb (4.7:1) instead of the #2f81f7 gradient (3.8:1); admission and
verification as first-class moments.

v1 decisions that CHANGE:
- "One unlock screen instead of four" is dropped. e2e/two-user-flow.mjs pins that every locked view
  unlocks IN PLACE (an invite link opens a new tab that starts locked). Instead: ONE styled
  "locked" component reused by Profile / Users / Chats, and the identity panel in the Live room
  becomes the first-run welcome. Same behaviour, one visual language.
- "Chats is home" is dropped for now: identity creation lives in the Live room's step 1 and every
  e2e run starts there. Default view stays `live`; tab order Live room · Chats · Users · Profile.
- Desktop two-pane chat is a follow-up (chatListWrap/chatConvo are toggled by app.js with `hidden`;
  showing both needs behaviour changes that do not belong in a visual rework).

## Structural changes (index.html + app.js) — deliberately minimal

1. Navigation: remove the drawer (`#drawer`, `#menuBtn`, `#scrim`, `setDrawer`) and add a persistent
   `<nav id="tabbar">` holding the same four `.navitem` buttons with `data-view` and the existing
   inline SVG icons. Phone (≤600px): bottom tab bar, icon over label, 64px tall, safe-area aware.
   Wider: a top app bar — wordmark left, the four items as horizontal tabs, the active one marked.
   app.js: bind `document.querySelectorAll(".navitem")` instead of `els.drawer.querySelectorAll`,
   keep `aria-current="page"` on the active item, delete the drawer code paths and the three `els`
   entries. Nothing else in `showView` changes.
2. First-run welcome: inside `#scrIdentity`, above the identity panel, static markup (wordmark,
   one-sentence pitch, three short facts: keys stay on the device / the relay sees ciphertext only /
   you verify each other in person). Purely static copy in index.html; app.js untouched here.
3. Trust marks, chat mode, legend: drop the emoji characters from the strings in `contactMark()`,
   `renderUserList()`, `renderConversation()` ("🔒 " prefix) and the legend in index.html; draw the
   icon with CSS (`.u-mark::before`, `.chatmode::before`, `.legend-item::before` using
   `mask-image: url("data:image/svg+xml,…")` + `background: currentColor`; CSP allows `img-src data:`).
   The WORDS stay exactly: "verified by you", "vouched by …", "unverified", "not in your users
   list", " — key CHANGED since you last verified" (e2e reads `.u-mark` textContent).
4. Everything else is CSS. No new ids are required; new class names are fine on static markup.

## Hard constraints (fail the review if violated)

- CSP: `style-src 'self'`, `script-src 'self'` + ONE pinned sha256 for the import map. No inline
  `style=`, no `<style>`, no inline event handlers, no external fonts/images/scripts. The
  `<script type="importmap">` text must stay BYTE-IDENTICAL (its hash is in backend/main.py).
- `img-src 'self' data:` — data-URI SVG in CSS masks/backgrounds is allowed; nothing else.
- Every element id in index.html stays (app.js `els` map binds ~150 of them; e2e pins ~70).
- `[hidden] { display: none !important; }` stays and every new container that app.js toggles via
  the `hidden` attribute must not defeat it.
- Text app.js sets and e2e reads stays verbatim: "Copied ✓", "Copy room id", "Verified in person"
  (button), "Remove", "registered", "logged in", "identity unlocked", the `.chip` texts,
  "Open anyway (I understand the risk)", "Let them in", "Deny", "It matches — unlock messaging",
  "It differs — disconnect", "Continue →" / "Continue without an identity →".
- Android: `android/app/src/main/res/values/colors.xml` `app_bg`/`app_fg` must equal the page
  background and text colour; if the ground colour moves, move both.
- Phone: inputs/selects/buttons ≥16px font (no zoom on focus), touch targets ≥44px, chat log fills
  the viewport with `100dvh` minus chrome, bottom tab bar never covers the composer.
- Accessibility: every text ≥4.5:1 on its ground (3:1 at ≥24px), visible focus (2px accent ring),
  `aria-current` on the active tab, `aria-live` regions kept, `prefers-reduced-motion` respected.
- No AI tropes: no blue-purple gradients, no emoji decoration, no left-border cards, no glassmorphism.

## Tests that must be updated WITH the change (not skipped, not weakened)

- `view()` helper in e2e/two-user-flow.mjs, room-admission.mjs, no-dead-ends.mjs, hostile-relay.mjs:
  click `.navitem[data-view="…"]` directly (no `#menuBtn`).
- e2e/no-dead-ends.mjs lines ~130–150 and ~160–195: the "open drawer marks the current view" check
  becomes "the tab bar marks the current view" — assert `.navitem[aria-current="page"]` has the
  expected `data-view`, and that the tabs are reachable (visible, not `hidden`).
- Everything else in the four runs must pass unchanged. Client `npm test` and backend `pytest`
  must pass unchanged.

## Definition of done for the implementation

- `client/style.css` rewritten (may grow; keep the token names; document sections).
- `client/index.html` restructured as above; `client/app.js` touched only in the places named.
- e2e helpers updated; all four e2e runs green against the local relay; `npm test` green;
  `pytest` green (162).
- `e2e/screenshots.mjs` (already being written separately) produces the full set at phone and
  desktop size without a missed state.

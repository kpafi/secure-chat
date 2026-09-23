# Kali.org as a reference for secure-chat: design brief

## Sources and confidence

- **kali.org could not be fetched.** WebFetch got `EGRESS_BLOCKED`, the Wayback Machine was refused, and two web searches found nothing on the site's CSS. The theme is not in Kali's public GitLab.
- **[fetched]** Kali's public GitLab: the press-pack logo `kali-logo-dragon-blue.svg` fills with **#367bf0** and **#2777ff**. The Kali-Dark GTK theme (`kali-themes`) uses surfaces **#1f222a / #23252e / #272a34**, darkest edge **#0d0e11**, and **#2777ff** for selected and checked states.
- **[from memory]** Everything about the site's layout, type and components: structure and approximate treatments only, no hex values. Check details against the live site before quoting them.

The key fetched finding: Kali's blue (#367bf0, 4.7:1 on #0d1117) is almost the same hue as secure-chat's #2f81f7. The palette is already close to Kali's. What differs is **structure, type and rhythm**.

## What kali.org does [from memory]

- **Palette.** A near-black, slightly cool ground with one or two lifted surfaces. Blue is the only chromatic colour. Text has about three tiers: near-white, grey, dim.
- **Type.** A clean sans (family unverified): large, heavy, tightly tracked headings over calm grey body text. Mono only in terminal snippets, as brand texture.
- **Structure.** Sections are separated by generous space and a repeated header (heading, one muted line), not boxes. Strict centred grid.
- **Cards** ("Kali Everywhere", Get Kali, docs). Same anatomy everywhere: icon, title, short description, action. One radius, one padding, subtle border or tone lift, hover changes border or tint only.
- **Buttons, nav, footer.** Filled blue primary (Download) beside an outline secondary. Slim top bar with dropdowns, hamburger on mobile. Muted multi-column footer.
- **Icons, imagery, motion.** One icon family in blue. Hero screenshot plus dragon mark. Motion is hover colour only.

## The decisions that make it read as "designed"

1. **One accent with one job.** Blue means "act here" or "you are here". It never decorates.
2. **Few type sizes and strong contrast between them.** Big tight headings over quiet body text, instead of a dozen near-identical sizes.
3. **Space separates, borders only contain.** Sections are divided by whitespace, not by nested boxes.
4. **One rhythm.** All padding and gaps are multiples of one base unit.
5. **A tone ladder for surfaces.** Elevation comes from lighter surfaces plus hairlines. Kali-Dark's steps are about 4/255 per channel, which is very tight. Shadows are kept for things that float.
6. **Repeated component anatomy.** Every card and row is built the same way, so the screen reads as a system.
7. **Mono as deliberate texture,** used only where the content is technical.
8. **An explicit CTA hierarchy:** filled, then outline, then text.
9. **One icon family** with one stroke weight, size and colour rule.
10. **Restrained motion:** short colour and border transitions, nothing bouncy.

## Translation to secure-chat

**Diagnosis.** `style.css` has about 12 font sizes (0.64–0.92rem), off-grid spacing (0.35/0.45/0.6/0.85rem), borders *and* `--shadow-1` on flat panels, and a bordered card per list row. That is the "stacked boxes" feel.

- **Accent (1).** Keep `#2f81f7` for text, icons, focus and active states (5.05:1 on `--bg`). Primary fill becomes `#1f6feb`, which gives 4.63:1 with white (the design README already proposes this). Make it flat, with `box-shadow: inset 0 1px 0 rgba(255,255,255,.12)` and no gradient. Allow one blue element per screen besides the primary button.
- **Type scale (2).** Use the system stack with six sizes: 12, 13, 15, 17, 20 and 24px.
  - Titles: 20 to 24px, weight 650, `letter-spacing: -0.02em`, `line-height: 1.2`.
  - Body: 15px/1.5.
  - Overline labels: 11 to 12px, uppercase, weight 600, `letter-spacing: .08em`, in `--muted`.
  - Add `font-variant-numeric: tabular-nums` to timestamps and safety numbers.
  - Keep 16px on inputs on phones.
- **Text tiers.** `--fg` #d8dfe7, `--muted` #8b949e (5.58:1 on panel), and a new `--faint` #6e7681 (3.73:1 on panel) for timestamps and metadata only.
- **Space (3, 4).** Use a 4px base with an 8px rhythm: `--sp` 4/8/12/16/24/32/48. Screen gutter 16px, card padding 16, gap between sections 24 to 32. Set a screen header pattern (overline, title, one muted line, `max-width: 60ch`) and lay the content under it without wrapping it in a panel.
- **Surfaces (5).**
  - Ladder: `--inset` #0a0e13, then `--bg` #0d1117, then `--panel` #161c23, then `--panel-2` #1c232c.
  - Panels get `border: 1px solid rgba(240,246,252,.08)` and `box-shadow: inset 0 1px 0 rgba(255,255,255,.03)`. Drop `--shadow-1` from flat surfaces.
  - `--shadow-2` is only for the drawer, sheets and menus.
  - Lists (chats, users) become **one** container with hairline dividers (`border-top: 1px solid var(--border-soft)` between rows), not one card per row.
- **Background.** No assets are needed:
  `background: radial-gradient(120% 50% at 50% -10%, rgba(47,129,247,.10), transparent 60%), linear-gradient(180deg, #11161d 0, #0d1117 360px) no-repeat, #0d1117;`
  An optional faint grid can be drawn with `repeating-linear-gradient` at about 3% alpha and faded out with `mask-image: radial-gradient(...)` (add the `-webkit-` prefix for older WebViews). Avoid `background-attachment: fixed` because it janks in Android WebView.
- **Cards (6).** Radii are 6 (controls), 10 (cards) and 16 (sheets and bubbles). Inner radius = outer radius minus padding. Hover changes the border to `var(--muted)` and nothing else. Selected state: `border-color: rgba(47,129,247,.5)` over `linear-gradient(180deg, rgba(47,129,247,.08), rgba(47,129,247,.02))`. Reserve the glow `0 8px 24px -12px rgba(47,129,247,.45)` for one element, such as the "verified" state.
- **Mono (7).** Key material sits in wells: `--inset` background, hairline border, radius 8, 13px, `letter-spacing: .02em`, fingerprints in a 2-column grid of groups. This is secure-chat's version of Kali's terminal texture.
- **Buttons (8).** 40px tall (44px touch target), radius 8. Order: primary, then secondary (transparent with a hairline border), then ghost (text only). Danger stays a tinted outline.
- **Navigation.** The top bar is `position: sticky`, `background: rgba(13,17,23,.8)`, `backdrop-filter: blur(12px)` with a solid fallback, and a hairline bottom border. The bottom tab bar is 56px plus `env(safe-area-inset-bottom)`, with 20px icons and 11px labels. The active tab is accent-coloured with a 2px indicator.
- **Icons (9).** Inline `<svg>` in index.html (CSP-safe), 20px, `stroke-width: 1.5`, round caps, `stroke: currentColor`. These replace the emoji.
- **Motion (10).** Colour and border transitions run 120–160ms ease-out. The drawer and sheet `transform` runs 220ms `cubic-bezier(.2,.8,.2,1)`. Wrap all motion in `prefers-reduced-motion`.

## What does not transfer

- **Imagery:** hero screenshot, dragon mark, illustrations. The mono wordmark stays the mark.
- **Marketing layout:** feature rows, platform grids, partner logos, huge display type. A chat app needs density; 24px is the ceiling.
- **Mega-menus and footer columns.** At most a one-line muted meta row (version, cipher) in the drawer foot.
- **Web fonts,** if Kali uses any: CSP forbids them.
- **Blue-glow atmosphere everywhere.** In a security app, glow must signal state (verified, active), never decorate.

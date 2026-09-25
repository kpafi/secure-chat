// FROZEN COPY of the released v0.3.1 client module (`git show v0.3.1:client/<name>.js`),
// kept only so the package-3b tests can run the OLD code against the new
// storage layout (a tab left open across the upgrade; a downgrade). The only
// edit is the nativefloor import path. Never shipped (`*.test.mjs`). Do not fix
// or modernise it: it must stay what users actually ran.
// The device-native anti-rollback floor, shared by every at-rest store.
//
// Pentest 2026-08-07 (F-ATREST-001/002/003/005): this used to live inside
// otp.js, so only one-time pads had a floor the JS context cannot delete or
// lower. The contact store (identity pins), the chat store (envelope-replay
// ring, negotiated modes) and the OTP receive/exported state all sat in
// deletable localStorage with, at best, an AEAD witness that a coordinated
// snapshot restore defeats. The bridge itself is a generic string-keyed
// monotone counter (PadFloor.kt HMACs `id\0value`), so one module can serve all
// of them; each store uses its own id namespace:
//
//   <padId>            OTP send offset (the original F-1 floor)
//   recv:<padId>       OTP receive high-water mark (F-ATREST-001)
//   exported:<padId>   OTP "this pad was exported" flag, 0/1 (F-ATREST-002)
//   contacts:<idHash>  contact-store generation, per identity (F-ATREST-003/004)
//   chats:<idHash>     chat-store generation, per identity (F-ATREST-005)
//
// Pad ids are 32 hex characters (otp.js validates that at import and unlock),
// so no pad file can address another namespace through the `:`.
//
// Everything below is otp.js's F-1 / H-1 / H-A / round-2 H-1 code moved
// verbatim; the comments are kept because each one records an attack that
// worked against a previous version of these lines.
//
// F-1 (2026-07-27): where the app runs, a floor is kept in a store the JS
// context cannot write to — the Android Keystore-backed record in
// PadFloor.kt, published to the page as a bridge. Every write bumps it; it
// can only go up; and a value that exists is itself evidence.
//
// In a plain browser there is no such primitive, so `nativeFloor` is null and
// the residual stands — documented in README.

export const NATIVE_ABSENT = -1;
export const NATIVE_TAMPERED = -2;

// Pentest 2026-07-29 H-1. Feature-detecting the bridge alone was a silent
// downgrade: `SecureChatPadFloor` is an ordinary writable global, so
// `delete window.SecureChatPadFloor` at document-start made the code below
// return null, the floor went away, and NOTHING said so — on the platform whose
// whole point is that the floor is unreachable from JS.
//
// The app's document-start script now also defines `__SECURE_CHAT_NATIVE_FLOOR__`
// as a non-writable, NON-CONFIGURABLE property. That is the load-bearing part:
// a JS attacker can still delete the bridge, but `delete` on a non-configurable
// property does not remove it, so they cannot also erase the statement that a
// floor was supposed to be here. Marker present + bridge missing or unusable is
// therefore not "plain browser" — it is evidence of tampering, and it fails
// CLOSED on every pad rather than quietly dropping the control.
//
// A plain browser sets neither, so it still gets `null` and the documented
// residual (see README) — unchanged.
// Fix review 2026-07-30 (H-A). Hardening the marker alone was not enough: this
// code used to look the bridge up by the ordinary global `SecureChatPadFloor`
// and accept anything with `read`/`bump` functions. An attacker never needed to
// DELETE it — installing a lookalike that answers "no floor", or overwriting
// just the two methods on the real object, satisfied every check while the real
// Keystore-backed floor was never consulted. Two assignments, and F-1 was void.
//
// The app now captures the bridge at document-start, before any page script can
// run, and republishes it FROZEN under `__SECURE_CHAT_PAD_FLOOR__` as a
// non-configurable property, with the methods bound so a later
// `SecureChatPadFloor.read = fake` cannot reach them. That name is the only one
// read here. `__SECURE_CHAT_NATIVE_FLOOR__` is the separate, also
// non-configurable statement that a floor is SUPPOSED to exist, so
// "expected but not securable" is a distinguishable, fail-closed state rather
// than something that reads as a plain browser.
// Captured at each store module's load — not once here — so a test (or any
// second instance of a store module) sees the bridge exactly as the page did
// at ITS load. Safety does not depend on capture time: the protections are
// the frozen, non-configurable globals themselves, and a document-start
// attacker runs before any module regardless.
export function captureNativeFloor() {
  const nativeFloorMarker = globalThis.__SECURE_CHAT_NATIVE_FLOOR__;
  const nativeFloorExpected = nativeFloorMarker === true || nativeFloorMarker === "unavailable";
  const b = globalThis.__SECURE_CHAT_PAD_FLOOR__;
  if (!b || typeof b.read !== "function" || typeof b.bump !== "function") {
    if (!nativeFloorExpected) return null;   // genuine browser: no floor exists
    // Marker without a usable protected bridge. Refuse everything rather than
    // degrade — this is either the app failing to secure the interface, or
    // someone having set the marker to brick OTP (loud, and fail-closed).
    return { read: () => NATIVE_TAMPERED, bump: () => NATIVE_TAMPERED, broken: true };
  }
  // Fix review round 2 (H-1): validate WITHOUT poisonable globals.
  //
  // This used to be `parseInt(v, 10)` guarded by `Number.isFinite`. Freezing the
  // bridge stopped an attacker replacing the function that produces the answer,
  // but both of those are ordinary writable globals, so one assignment —
  // `globalThis.parseInt = () => 0` — made every floor read as 0 while the
  // frozen bridge, the non-configurable marker and verifyRelayConfig's probe
  // all stayed intact. The hardened part was bypassed by poisoning the step
  // AFTER it. Note that capturing primordials at module top would not help
  // either: a document-start attacker runs first.
  //
  // So: the bridge now returns a NUMBER (see PadFloorBridge), and the checks
  // below use only `typeof` and bitwise ops, which are language constructs with
  // no interceptable global behind them. `(n | 0) === n` is an integer test
  // that cannot be redefined, and pad offsets are far below 2^31.
  const num = (v) => {
    // An unreadable answer from the bridge is TAMPERED, never "no floor" — a
    // broken bridge must not read as a clean slate.
    if (typeof v !== "number") return NATIVE_TAMPERED;
    if ((v | 0) !== v) return NATIVE_TAMPERED;      // NaN, Infinity, fractions
    return v;
  };
  return {
    read: (id) => { try { return num(b.read(id)); } catch { return NATIVE_TAMPERED; } },
    bump: (id, v) => { try { return num(b.bump(id, v | 0)); } catch { return NATIVE_TAMPERED; } },
  };
}

// Max without `Math.max` (H-1). `Math.max` is writable, and the rollback verdict
// is a single call to it over the four floors — so one assignment overruled the
// native floor, the authenticated watermark, the in-AEAD `hwSend` and the legacy
// watermark simultaneously, silently. Comparison operators cannot be redefined.
export function maxOf(...values) {
  let best = 0;
  for (const v of values) {
    const n = typeof v === "number" && (v | 0) === v ? v : 0;
    if (n > best) best = n;
  }
  return best;
}

// Fix review 2026-07-30 (L-A). When the floor is EXPECTED but not usable, the
// pad is fine and the platform is not: every message that came out of this state
// blamed the pad ("damaged or forged", "already been used") and told the user to
// exchange a fresh one, which does not help and burns real pads. Say what is
// actually wrong instead. Still fail-closed — only the wording changes.
export function floorUnavailableError(what = "one-time pads") {
  return new Error(
    `this device says it has hardware rollback protection for ${what}, but the app cannot reach it. ` +
    (what === "one-time pads" ? "Your pad is probably fine — do NOT exchange a new one. " : "Your data is probably fine. ") +
    "On Android, reinstall or update the app; " +
    "in a browser, an extension or script has set this flag and this feature is disabled until it is removed.",
  );
}

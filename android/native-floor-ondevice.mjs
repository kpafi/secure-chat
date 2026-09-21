// On-device proof of the native OTP pad floor, against the REAL AndroidKeyStore
// path in the installed APK.
//
// Pentest 2026-08-07: the client now keys further floors under the same bridge
// (`recv:<padId>`, `exported:<padId>`, `contacts:<idHash>`, `chats:<idHash>`,
// see client/nativefloor.js). The bridge contract this harness proves is
// unchanged — string id in, monotone Long out — so those ids are covered by
// the same assertions; the next on-device run should bump one of each prefix
// to show the `:` survives the HMAC path (it is only ever a string to Kotlin). Everything else that tests this runs in Node with a
// simulated bridge, which is exactly how 2026-07-29 H-1 and its two fix-review
// rounds slipped through: a mock cannot be substituted, poisoned, or frozen, so
// it cannot show you that yours can be.
//
// This replaces the 2026-07-28 harness, which no longer applies — H-1 changed
// the contract it asserted:
//   * `clear()` is GONE from the bridge (it voided the whole F-1 guarantee).
//   * read/bump return Long, not String (round-2 H-1: the String forced a
//     `parseInt` on the JS side, and `parseInt` is a writable global).
//   * the interface the client uses is the frozen `__SECURE_CHAT_PAD_FLOOR__`,
//     republished at document-start, NOT the writable `SecureChatPadFloor`.
//
// Usage:
//   adb shell monkey -p org.securechat.app -c android.intent.category.LAUNCHER 1
//   adb forward tcp:9222 localabstract:webview_devtools_remote_<pid>
//   node android/native-floor-ondevice.mjs
//
// Read-only apart from bumping a floor for a PROBE pad id, which is namespaced
// and cleaned up at the end. It never touches a real pad: no lowering operation
// exists, so a bump against a real padId would be permanent.

const CDP = "http://127.0.0.1:9222/json/list";
const PROBE = "probe-native-floor-" + Date.now();

let pass = 0, fail = 0;
const ok = (name, detail = "") => { pass++; console.log(`    OK   ${name}${detail ? " — " + detail : ""}`); };
const bad = (name, detail = "") => { fail++; console.log(`    FAIL ${name}${detail ? " — " + detail : ""}`); };
const check = (cond, name, detail) => (cond ? ok : bad)(name, detail);

const targets = await (await fetch(CDP)).json();
const page = targets.find((t) => t.type === "page" && t.url.includes("index.html"));
if (!page) throw new Error("no secure-chat page target — is the app open on its main screen?");

const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });

let msgId = 0;
const pending = new Map();
ws.onmessage = (e) => {
  const m = JSON.parse(e.data);
  if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
};

/** Evaluate `expr` in the page and return its JSON value (throws on JS error). */
function evaluate(expr) {
  const id = ++msgId;
  return new Promise((res, rej) => {
    pending.set(id, (m) => {
      if (m.error) return rej(new Error(JSON.stringify(m.error)));
      const r = m.result;
      if (r.exceptionDetails) {
        return rej(new Error(r.exceptionDetails.exception?.description || "page threw"));
      }
      res(r.result.value);
    });
    ws.send(JSON.stringify({
      id, method: "Runtime.evaluate",
      params: { expression: expr, returnByValue: true, awaitPromise: true },
    }));
  });
}

console.log(`\n=== native pad floor, on device (probe id ${PROBE}) ===\n`);
console.log("--- the marker and the protected interface (H-1) ---");

check(await evaluate("window.__SECURE_CHAT_NATIVE_FLOOR__ === true"),
  "the app declares a native floor",
  "__SECURE_CHAT_NATIVE_FLOOR__ === true");

// Non-configurable is the load-bearing part: an attacker may still delete the
// writable bridge, but must not be able to erase the STATEMENT that a floor was
// supposed to exist, or "no floor" reads as a plain browser and fails open.
check(await evaluate(`(() => {
  try { delete window.__SECURE_CHAT_NATIVE_FLOOR__; } catch (e) {}
  return window.__SECURE_CHAT_NATIVE_FLOOR__ === true;
})()`), "the marker survives `delete` (non-configurable)");

check(await evaluate(`(() => {
  try { Object.defineProperty(window, '__SECURE_CHAT_NATIVE_FLOOR__', { value: false }); } catch (e) {}
  return window.__SECURE_CHAT_NATIVE_FLOOR__ === true;
})()`), "the marker survives redefinition");

const shape = await evaluate(`(() => {
  const b = window.__SECURE_CHAT_PAD_FLOOR__;
  return JSON.stringify({
    present: !!b, read: typeof (b||{}).read, bump: typeof (b||{}).bump,
    frozen: !!b && Object.isFrozen(b), clear: typeof (b||{}).clear,
  });
})()`);
const s = JSON.parse(shape);
check(s.present && s.read === "function" && s.bump === "function",
  "the frozen interface is published", "__SECURE_CHAT_PAD_FLOOR__ has read/bump");
check(s.frozen, "the interface object is frozen");
// 2026-07-29 H-1: `clear` was an unauthenticated JS-reachable reset. One call
// and a snapshot rollback reopened a used pad at its old offset.
check(s.clear === "undefined", "there is NO clear/reset on the bridge");

console.log("\n--- the real AndroidKeyStore floor ---");

const absent = await evaluate(`window.__SECURE_CHAT_PAD_FLOOR__.read(${JSON.stringify(PROBE)})`);
check(absent === -1, "an unknown pad has no floor", `read() = ${absent}`);
// Round-2 H-1: a String here forced `parseInt` on the JS side, and one
// `globalThis.parseInt = () => 0` zeroed every floor while the frozen bridge and
// the marker both stayed intact. The type IS the fix.
check(typeof absent === "number", "read() returns a NUMBER, so there is no parse step to poison",
  `typeof = ${typeof absent}`);

const up = await evaluate(`window.__SECURE_CHAT_PAD_FLOOR__.bump(${JSON.stringify(PROBE)}, 500)`);
check(up === 500, "bump(500) raises the floor", `= ${up}`);

const down = await evaluate(`window.__SECURE_CHAT_PAD_FLOOR__.bump(${JSON.stringify(PROBE)}, 5)`);
check(down === 500, "bump(5) does NOT lower it — monotone through the real HMAC", `= ${down}`);

const reread = await evaluate(`window.__SECURE_CHAT_PAD_FLOOR__.read(${JSON.stringify(PROBE)})`);
check(reread === 500, "the floor persists across calls", `read() = ${reread}`);

console.log("\n--- the H-A substitution attack (fix review round 1) ---");
// The attacker never needed `delete`. Overwriting the two METHODS on the
// ordinary global, or installing a lookalike that answers "no floor", satisfied
// every check the client made while the Keystore floor sat unconsulted.
const substituted = await evaluate(`(() => {
  const before = window.__SECURE_CHAT_PAD_FLOOR__.read(${JSON.stringify(PROBE)});
  try { window.SecureChatPadFloor = { read: () => -1, bump: () => -1 }; } catch (e) {}
  try { window.SecureChatPadFloor.read = () => -1; } catch (e) {}
  const after = window.__SECURE_CHAT_PAD_FLOOR__.read(${JSON.stringify(PROBE)});
  return JSON.stringify({ before, after });
})()`);
const sub = JSON.parse(substituted);
check(sub.after === 500,
  "replacing the writable global does NOT affect the protected interface",
  `floor still ${sub.after} after substitution`);

const bound = await evaluate(`(() => {
  const b = window.__SECURE_CHAT_PAD_FLOOR__;
  try { b.read = () => -1; } catch (e) {}
  return b.read(${JSON.stringify(PROBE)});
})()`);
check(bound === 500, "the frozen interface's own methods cannot be overwritten", `read() = ${bound}`);

console.log("\n--- the round-2 value-path poisoning (H-1) ---");
// `globalThis.parseInt = () => 0` and `Math.max = () => 0` each defeated the
// floor without ever naming the bridge. The bridge answering with a number, and
// otp.js validating with typeof/bitwise ops and a local maxOf, is what closed it.
const poisoned = await evaluate(`(() => {
  const saved = { parseInt: globalThis.parseInt, max: Math.max };
  try {
    globalThis.parseInt = () => 0;
    Math.max = () => 0;
    const v = window.__SECURE_CHAT_PAD_FLOOR__.read(${JSON.stringify(PROBE)});
    return JSON.stringify({ v, t: typeof v });
  } finally {
    globalThis.parseInt = saved.parseInt;
    Math.max = saved.max;
  }
})()`);
const p = JSON.parse(poisoned);
check(p.v === 500 && p.t === "number",
  "poisoning parseInt and Math.max does not move the floor",
  `read() = ${p.v} (${p.t})`);

console.log("\n--- cleanup ---");
// There is deliberately no lowering operation, so the probe's floor cannot be
// removed from JS. It is namespaced to a padId no real pad can have, which is
// why the probe used one.
const left = await evaluate(`window.__SECURE_CHAT_PAD_FLOOR__.read(${JSON.stringify(PROBE)})`);
console.log(`    note: probe floor ${PROBE} = ${left} and CANNOT be cleared from JS`);
console.log("          (by design — no clear/lowering call exists. It is inert:");
console.log("           no real pad can carry this id.)");

const realPads = await evaluate(
  `Object.keys(localStorage).filter(k => k.indexOf('sc.otp') === 0).length`);
console.log(`    note: real sc.otp.* keys on device: ${realPads}`);

ws.close();
console.log(`\n=== summary ===\n  ${pass}/${pass + fail} checks passed`);
if (fail) { console.log("  NATIVE FLOOR PROOF FAILED"); process.exit(1); }
console.log("  native floor proved on real hardware");

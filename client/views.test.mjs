// Phase-7 pentest 2026-09-16, F-P7-9 — hint() must land on the view that is
// on screen. Run: node views.test.mjs   (server not required)
//
// activeHintEl() chose among #roomHint / #idHint / #hint by each SCREEN's
// `hidden` attribute — and all three live inside #viewLive. On the Users,
// Chats or Profile view the "sealed messages will not arrive" warning
// (app.js pollMailbox/autoLogin) was written into a zero-size node, and the
// transcript line beside it is inside #viewLive too: silent, exactly where
// someone waiting for async mail sits. app.js cannot be imported here (it
// touches `document` at module scope), so this pins the routing at source.
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { stripComments, liftFunction } from "./test-source.mjs";

const src = stripComments(readFileSync(new URL("./app.js", import.meta.url), "utf8"));
const html = readFileSync(new URL("./index.html", import.meta.url), "utf8");
const fn = liftFunction(src, "activeHintEl", assert);

// The view check comes FIRST, and covers every non-Live view with that view's
// own status element.
const viewGate = fn.indexOf("if (els.viewLive.hidden) {");
assert.notStrictEqual(viewGate, -1, "F-P7-9: activeHintEl must first ask whether the Live view is on screen at all");
assert.ok(viewGate < fn.indexOf("els.scrRoom.hidden"), "...before it looks at the Live view's screens");
for (const [view, el] of [["viewUsers", "usersHint"], ["viewChats", "chatsHint"], ["viewProfile", "profileHint"]]) {
  assert.match(fn, new RegExp(`if \\(!els\\.${view}\\.hidden\\) return els\\.${el};`),
    `F-P7-9: with the ${view} view on screen, hint() must write to its own status line (#${el})`);
  assert.match(html, new RegExp(`id="${el}"`), `#${el} exists in index.html`);
}
// The three Live-view targets are indeed inside #viewLive (the premise), and
// the three view status lines are inside THEIR views.
const at = (id) => html.indexOf(`id="${id}"`);
assert.ok(at("viewLive") < at("idHint") && at("idHint") < at("viewUsers"), "#idHint is inside #viewLive");
assert.ok(at("viewLive") < at("roomHint") && at("roomHint") < at("viewUsers"), "#roomHint is inside #viewLive");
assert.ok(at("viewLive") < at("hint") && at("hint") < at("viewUsers"), "#hint is inside #viewLive");
assert.ok(at("viewUsers") < at("usersHint") && at("usersHint") < at("viewChats"), "#usersHint is inside #viewUsers");
assert.ok(at("viewChats") < at("chatsHint"), "#chatsHint is inside #viewChats");
assert.ok(at("viewLive") < at("viewProfile") && at("viewProfile") < at("profileHint") && at("profileHint") < at("viewUsers"), "#profileHint is inside #viewProfile");
// The hint targets are DEDICATED elements (review of the first fix, L-5): the
// views' status elements are rewritten by their renderers (usersStatus(""),
// chatsStatus(""), the profile chip container), so a warning there died on the
// next render. Nothing but hint()/clearHints() may write the hint elements.
for (const el of ["usersHint", "chatsHint", "profileHint"]) {
  const writers = src.split("\n").filter((l) => new RegExp(`els\\.${el}\\b`).test(l));
  assert.deepStrictEqual(writers.map((l) => l.trim()).filter((l) => !/^(usersHint|chatsHint|profileHint|profileStatus):/.test(l) && !/\$\("/.test(l) && !/^for \(const el of \[els\.idHint/.test(l)),
    [`if (!els.${{ usersHint: "viewUsers", chatsHint: "viewChats", profileHint: "viewProfile" }[el]}.hidden) return els.${el};`],
    `#${el} is referenced only by activeHintEl (and cleared by clearHints via the shared list) — found: ${writers.map((l) => l.trim()).join(" | ")}`);
}
const clear = liftFunction(src, "clearHints", assert);
for (const el of ["usersHint", "chatsHint", "profileHint"]) assert.ok(clear.includes(`els.${el}`), `clearHints() covers #${el}`);
// Every hint() caller goes through activeHintEl — no second router.
assert.strictEqual((src.match(/function activeHintEl\(/g) || []).length, 1);
const hintFn = liftFunction(src, "hint", assert);
assert.match(hintFn, /const el = activeHintEl\(\);/, "hint() resolves its target through activeHintEl()");
console.log("OK  F-P7-9: hint() lands on the view that is on screen");
console.log("All view-routing checks passed.");

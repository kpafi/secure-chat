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
for (const [view, el] of [["viewUsers", "usersStatus"], ["viewChats", "chatsStatus"], ["viewProfile", "profileStatus"]]) {
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
assert.ok(at("viewUsers") < at("usersStatus") && at("usersStatus") < at("viewChats"), "#usersStatus is inside #viewUsers");
assert.ok(at("viewChats") < at("chatsStatus"), "#chatsStatus is inside #viewChats");
assert.ok(at("viewLive") < at("viewProfile") && at("viewProfile") < at("profileStatus") && at("profileStatus") < at("viewUsers"), "#profileStatus is inside #viewProfile");
// Every hint() caller goes through activeHintEl — no second router.
assert.strictEqual((src.match(/function activeHintEl\(/g) || []).length, 1);
const hintFn = liftFunction(src, "hint", assert);
assert.match(hintFn, /const el = activeHintEl\(\);/, "hint() resolves its target through activeHintEl()");
console.log("OK  F-P7-9: hint() lands on the view that is on screen");
console.log("All view-routing checks passed.");

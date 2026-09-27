// The one-time pad SHEETS (New pad / Export / Import), executed — the
// decisions of design/research/reviews/otp-transfer-brief.md § Design
// decisions that a user's safety rests on:
//
//   - the transfer passphrase may not be the pad passphrase (both sheets),
//     and New pad carries its passphrase into #otpPass so the rule fires in
//     New pad → Export;
//   - a received pad offers no Export and a forced one is refused;
//   - Android: the file bridge is used only as the frozen capture; Share /
//     Save report back by request id only; closing before the file was shared
//     or saved asks first;
//   - Import holds the picked file so "Try again" needs no second pick, and
//     refuses a file over 4 MiB without reading it;
//   - a working sheet cannot be closed (×, Back); closing clears what the
//     sheet collected but never #otpPass; Back closes an idle sheet.
//
// The stub does not parse markup classes: `.primary` is asserted here only
// where app.js sets it; which buttons are visible is asserted everywhere, and
// e2e/otp-transfer.mjs counts the visible primaries in a real browser.
// Its own process (a module is evaluated once): here the Android shell's
// bridge exists, so app.js takes the Android export path. The browser path
// (download at once) is app-otp.test.mjs's. The stub is not a browser — what
// is proven is app.js's DECISIONS; the layout is e2e/otp-transfer.mjs's.
// Run: node app-otp-sheets.test.mjs
import assert from "node:assert";
import { fakeIdb } from "./fake-idb.test.mjs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { installDom, El } from "./dom-stub.test.mjs";

void fakeIdb;
const HERE = dirname(fileURLToPath(import.meta.url));
const ROOM = "c".repeat(64);
const NAME_RE = /^secure-chat-pad-\d{4}-\d{2}-\d{2}-\d{4}\.json$/;

const store = new Map();
globalThis.localStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => { store.set(k, String(v)); },
  removeItem: (k) => { store.delete(k); },
  key: (i) => [...store.keys()][i] ?? null,
  get length() { return store.size; },
  clear: () => store.clear(),
};
globalThis.setInterval = () => 0;
globalThis.clearInterval = () => {};
globalThis.fetch = async () => new Response("{}", { status: 404 });

// The window's own listeners (popstate), captured: installDom keeps an
// addEventListener that already exists.
const winListeners = new Map();
globalThis.addEventListener = (type, fn) => {
  if (!winListeners.has(type)) winListeners.set(type, []);
  winListeners.get(type).push(fn);
};
const popstate = () => Promise.all((winListeners.get("popstate") || []).map((f) => f({ type: "popstate" })));

const dom = installDom(join(HERE, "index.html"));
dom.body.appendChild(dom.el("tabbar"));
dom.seedAlgRadios(["DHKE", "AES256", "PQKEM", "OTP"], "DHKE");
dom.seedNavItems(["live", "chats", "users", "profile"]);
dom.seedChild("scrChat", "div", "topbar");
for (const id of ["usersLocked", "chatsLocked"]) dom.seedChild(id, "p", "hint");
{ const row = new El("div"); row.className = "row"; row.appendChild(dom.el("username")); }

// History, modelled faithfully (fix round 1: the first model fired popstate
// on every back(), even at the first entry — which is why pentest R2-2 was
// invisible): a list of entries and an index; pushState truncates forward
// entries; back() traverses LATER (a task), relative to the entry current
// THEN, and at the first entry does nothing (the Android WebView with no
// earlier page); `state` is the current entry's. `userBack()` is the Back
// button. `backs` counts app.js's own back() calls.
const hist = { pushes: 0, backs: 0, entries: [null], idx: 0 };
const traverseBack = async () => {
  if (hist.idx === 0) return false;
  hist.idx--;
  await popstate();
  return true;
};
const userBack = () => traverseBack();
Object.defineProperty(globalThis, "history", {
  value: {
    replaceState() {},
    get state() { return hist.entries[hist.idx]; },
    pushState(st) { hist.pushes++; hist.entries.splice(hist.idx + 1); hist.entries.push(st); hist.idx++; },
    back() { hist.backs++; setTimeout(traverseBack, 0); },
  },
  writable: true, configurable: true,
});

// Web Locks, exclusive per name: `ifAvailable` answers null while the name is
// held; otherwise the request waits for the release — or for its `signal`.
const held = new Map(); // name -> promise that resolves on release
// A gate holds any request for a name (even ifAvailable) until the test
// opens it — to keep a sheet "working" at a known point (fix round 5).
const lockGates = new Map(); // name -> { promise, open }
const gateLock = (name) => { let open; const promise = new Promise((r) => { open = r; }); lockGates.set(name, { promise, open }); return () => { lockGates.delete(name); open(); }; };
globalThis.navigator = { ...globalThis.navigator, locks: {
  request(name, opts, fn) {
    if (typeof opts === "function") { fn = opts; opts = {}; }
    const gate = lockGates.get(name);
    if (gate) return gate.promise.then(() => navigator.locks.request(name, opts, fn));
    const run = () => {
      let rel;
      held.set(name, new Promise((r) => { rel = r; }));
      return Promise.resolve(fn({ name })).finally(() => { held.delete(name); rel(); });
    };
    if (!held.has(name)) return run();
    if (opts.ifAvailable) return Promise.resolve(fn(null));
    return new Promise((resolve, reject) => {
      const sig = opts.signal;
      if (sig) {
        if (sig.aborted) { reject(sig.reason); return; }
        sig.addEventListener("abort", () => reject(sig.reason), { once: true });
      }
      const wait = () => {
        if (sig && sig.aborted) return;
        if (held.has(name)) held.get(name).then(wait);
        else run().then(resolve, reject);
      };
      wait();
    });
  },
} };

let downloads = 0;
const realObjectURL = URL.createObjectURL;
URL.createObjectURL = (b) => { downloads++; return realObjectURL.call(URL, b); };

// The Android shell's bridge, as the shell publishes it: frozen, on a
// non-writable, non-configurable property.
const calls = [];
let answer = null; // override what share()/save() return
let reqN = 0;
const bridge = Object.freeze({
  share: (name, text) => { calls.push({ kind: "share", name, text }); return answer ?? "req-" + (++reqN); },
  save: (name, text) => { calls.push({ kind: "save", name, text }); return answer ?? "req-" + (++reqN); },
});
Object.defineProperty(globalThis, "__SECURE_CHAT_FILES__", { value: bridge, writable: false, configurable: false });

// Fix round 4 (pentest r5 KH): record the 8-byte random draws made while
// app.js loads — the history token must be one of them (not a constant).
const draws8 = [];
{
  const real = crypto.getRandomValues.bind(crypto);
  crypto.getRandomValues = (a) => { const r = real(a); if (a && a.length === 8) draws8.push(Array.from(a, (b) => b.toString(16).padStart(2, "0")).join("")); return r; };
  await import("./app.js");
  crypto.getRandomValues = real;
}
const otp = await import("./otp.js");

const settle = async (n = 40) => { for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 5)); };
const until = async (cond, what) => {
  for (let i = 0; i < 2000 && !cond(); i++) await new Promise((r) => setTimeout(r, 5));
  assert.ok(cond(), "timed out waiting for " + what);
};
const el = (id) => dom.el(id);
const shown = (id) => !el(id).hidden;
const primary = (id) => el(id).classList.contains("primary");
const result = (id, outcome) => globalThis.__SECURE_CHAT_FILES_RESULT__(id, outcome);
const st = el("otpStatus");
const set = async (id, v) => { el(id).value = v; await el(id).dispatch("input"); };

// ---- the result callback is the page's own, fixed -------------------------
{
  const d = Object.getOwnPropertyDescriptor(globalThis, "__SECURE_CHAT_FILES_RESULT__");
  assert.ok(d && typeof d.value === "function" && !d.writable && !d.configurable,
    "the shell's result callback is defined by app.js as non-writable, non-configurable");
  console.log("OK  Android bridge: the result callback is non-writable and non-configurable");
}

// ---- empty panel: no primary, Connect aria-disabled and says why ----------
{
  await el("toRoom").click(); // the room screen, where the OTP panel lives (R4-1 checks it)
  el("room").value = ROOM;
  await el("room").dispatch("input");
  dom.selectAlg("OTP");
  await el("algCards").dispatch("change");
  assert.strictEqual(otp.listPads().length, 0, "fixture: no pad yet");
  assert.ok(shown("otpEmpty") && !shown("otpPadRow") && !shown("otpPassRow"), "empty: the card, not the pad rows");
  assert.strictEqual(el("otpActions").parentNode, el("otpEmpty"), "empty: the entry row sits inside the card");
  assert.ok(!primary("otpNewOpen") && !primary("otpImportOpen"),
    "round 2 minor 1: New pad and Import have equal weight (neither is the primary)");
  assert.strictEqual(el("connect").getAttribute("aria-disabled"), "true", "empty: Connect is aria-disabled");
  assert.ok(!primary("connect"), "…and not the blue primary");
  await el("connect").click();
  const said = ["hint", "roomHint", "idHint"].map((id) => el(id).textContent).find((t) => t) || "";
  assert.match(said, /^Choose a one-time pad first — New pad or Import, under Security options\.$/,
    "a tap on Connect says what to do: " + said);
  dom.selectAlg("DHKE");
  await el("algCards").dispatch("change");
  assert.ok(el("connect").getAttribute("aria-disabled") === null && primary("connect"),
    "another mode: Connect is enabled and the primary again");
  dom.selectAlg("OTP");
  await el("algCards").dispatch("change");
  await el("connect").click(); // the refusal again: New pad below must take it away (cold mi-1)
  console.log("OK  empty panel: New pad = Import, Connect aria-disabled (refusal on tap), restored in other modes");
}

// ---- New pad: carried passphrase; a working sheet cannot be closed; Export is the primary ----
const PADPASS = "pad passphrase for the sheet tests";
let madeId;
{
  const p0 = hist.pushes;
  await el("otpNewOpen").click();
  assert.ok(shown("otpNewSheet") && shown("otpScrim"), "New pad opens its sheet over the scrim");
  assert.ok(el("viewLive").inert, "…the Live room is inert (the tab bar too: e2e — the stub's #admit is never hidden)");
  assert.strictEqual(hist.pushes, p0 + 1, "N-M2: opening a sheet pushes one history entry");
  await el("otpGenerate").click();
  assert.match(st.textContent, /^Set a pad passphrase first/, "empty pad passphrase: refused");
  await set("otpNewPass", PADPASS);
  el("otpLabel").value = "sheet-pad";
  el("otpSize").value = "8192";
  const gen = el("otpGenerate").click();
  await until(() => el("otpNewSheet").getAttribute("data-state") === "working", "New pad working");
  assert.ok(!shown("otpNewClose") && !shown("otpGenerate"), "working: no ×, no Create");
  await el("otpNewClose").click();
  assert.ok(shown("otpNewSheet"), "working: × (even if reached) does not close");
  const p1 = hist.pushes;
  await userBack();
  assert.ok(shown("otpNewSheet"), "N-M2: Back while working does not close…");
  assert.strictEqual(hist.pushes, p1 + 1, "…it puts the history entry back");
  await gen;
  await until(() => el("otpNewSheet").getAttribute("data-state") === "done", "New pad done");
  madeId = el("otpSelect").value;
  assert.ok(["hint", "roomHint", "idHint"].every((id) => !/Choose a one-time pad first/.test(el(id).textContent)),
    "cold mi-1: once a pad exists the 'Choose a one-time pad first' refusal is gone");
  assert.ok(madeId && otp.padMeta(madeId).label === "sheet-pad", "the pad is made and selected");
  assert.strictEqual(el("otpPass").value, PADPASS, "§ 2: the pad passphrase is carried into #otpPass");
  assert.match(st.textContent, /^Generated \+ encrypted pad "sheet-pad"/, "#otpStatus keeps the sentence…");
  assert.match(st.className, /\bvh\b/, "…visually hidden (the done block said it)");
  assert.ok(shown("otpNewDoneBlock") && shown("otpNewToExport") && shown("otpNewLater") && !shown("otpGenerate"),
    "done: 'Export to your contact' is the primary, 'Later' beside it");
  assert.ok(shown("otpUnlocked") && el("otpPass").hidden, "the panel shows the unlocked row");
  assert.ok(primary("otpExportOpen") && !primary("connect"),
    "round 2 minor 6: a pad made here and never exported makes Export the primary, not Connect");
  console.log("OK  New pad: working sheet stays (× and Back), passphrase carried, Export is the primary until exported");
}

// ---- Export (Android): must-differ, ready, Share/Save by request id, close-confirm ----
{
  const p0 = hist.pushes;
  await el("otpNewToExport").click();
  assert.ok(!shown("otpNewSheet") && shown("otpExportSheet") && shown("otpScrim"), "New pad hands over to Export");
  assert.strictEqual(hist.pushes, p0, "…in the same history entry");
  assert.strictEqual(el("otpNewPass").value, "", "the New pad sheet was cleared when it closed");
  await set("otpXferPass", PADPASS);
  const c0 = calls.length, d0 = downloads;
  await el("otpExport").click();
  await settle(5);
  assert.strictEqual(el("otpExportStatus").textContent,
    "Use a different passphrase for the file — this one is your pad passphrase.",
    "must-differ: the carried pad passphrase is refused as the transfer passphrase");
  assert.strictEqual(el("otpXferPass").getAttribute("aria-invalid"), "true", "…and the field is marked");
  assert.strictEqual(otp.padMeta(madeId).exported, false, "…and nothing was exported");
  assert.ok(calls.length === c0 && downloads === d0, "…no file anywhere");
  await set("otpXferPass", "harbour mint cobalt fern");
  assert.strictEqual(el("otpXferPass").getAttribute("aria-invalid"), null, "the mark goes on the next input");
  const t0 = new Date();
  await el("otpExport").click();
  await until(() => el("otpExportSheet").getAttribute("data-state") === "ready", "Export ready");
  const t1 = new Date();
  assert.strictEqual(downloads, d0, "Android: nothing is downloaded (the WebView would drop it)");
  assert.ok(shown("otpShare") && shown("otpSave") && !shown("otpExport") && !shown("otpExportCancel"),
    "ready: Share… (primary) and Save to device");
  assert.ok(el("otpExportReadyWeak").hidden, "a strong transfer passphrase: no weak warning beside Share / Save");
  const name = el("otpExportStep2Caption").textContent;
  assert.match(name, NAME_RE, "§ 7: the file name is neutral — the native side's exact pattern: " + name);
  // …and it is the local date and minute of the export (24h, zero-padded).
  const z = (n, w = 2) => String(n).padStart(w, "0");
  const at = (d) => `secure-chat-pad-${z(d.getFullYear(), 4)}-${z(d.getMonth() + 1)}-${z(d.getDate())}-${z(d.getHours())}${z(d.getMinutes())}.json`;
  assert.ok(name === at(t0) || name === at(t1), `§ 7: the name is the export's local date and minute (${name}; ${at(t0)} / ${at(t1)})`);
  assert.match(st.textContent, /^Exported\. /, "#otpStatus has the Exported sentence");

  // Closing before any share/save asks first; Cancel keeps the sheet.
  const realConfirm = globalThis.confirm;
  let asked = 0;
  globalThis.confirm = (m) => { asked++; assert.match(m, /has not been shared or saved yet/); return false; };
  await el("otpExportClose").click();
  assert.ok(asked === 1 && shown("otpExportSheet"), "§ 5: closing an unshared Android file asks, and Cancel keeps it");
  const p1 = hist.pushes;
  await userBack();
  assert.ok(asked === 2 && shown("otpExportSheet") && hist.pushes === p1 + 1,
    "N-M2: Back in file-ready puts the entry back and asks the same question");

  await el("otpShare").click();
  const req = calls.at(-1);
  assert.ok(req.kind === "share" && req.name === name && JSON.parse(req.text).fmt === "secure-chat-otp-pad",
    "Share hands the bridge the neutral name and the pad-file envelope");
  assert.ok(el("otpShare").disabled && el("otpSave").disabled, "Share and Save are disabled while a request is open");
  result("req-999", "shared");
  assert.strictEqual(el("otpExportSheet").getAttribute("data-state"), "ready", "a result for another request id is ignored");
  result("req-" + reqN, "cancelled");
  assert.ok(el("otpExportStatus").textContent === "Not shared." && !el("otpShare").disabled, "cancelled: 'Not shared.', buttons back");
  answer = "busy";
  await el("otpShare").click();
  answer = null;
  assert.match(el("otpExportStatus").textContent, /^Could not share the file\. Another share or save is still open/, "busy: said");
  answer = "invalid";
  await el("otpSave").click();
  answer = null;
  assert.ok(el("otpExportStatus").textContent === "Could not save the file." && !el("otpSave").disabled &&
    el("otpExportSheet").getAttribute("data-state") === "ready", "invalid: said, and Share / Save stay available");
  await el("otpSave").click();
  result("req-" + reqN, "shared");
  assert.ok(el("otpExportSheet").getAttribute("data-state") === "ready" && el("otpExportStatus").textContent === "Could not save the file.",
    "a save request answered 'shared' is not a success");
  await el("otpSave").click();
  result("req-" + reqN, "error");
  assert.strictEqual(el("otpExportStatus").textContent, "Could not save the file.", "error: said");
  await el("otpSave").click();
  result("req-" + reqN, "saved");
  assert.strictEqual(el("otpExportSheet").getAttribute("data-state"), "done", "saved: done");
  assert.strictEqual(el("otpExportDoneTitle").textContent, "File saved", "round 2 N-M1: 'File saved' (not 'to this device')");
  assert.strictEqual(el("otpExportDelete").textContent, "Once they've imported it, delete the file on both devices.",
    "fix round 2: after a save the sender has a copy too — delete it on both devices");
  assert.ok(shown("otpExportDoneFile") && el("otpExportDoneFile").textContent === name, "…with the file name on its own line");
  assert.ok(shown("otpExportDone") && !shown("otpShare") && el("otpSendAgain").textContent === "Share or save the same file again",
    "done: Done is the primary; after a SAVE the link says share or save — the same file (design r3 minor 6, cold MA-3)");
  await el("otpSendAgain").click();
  assert.strictEqual(el("otpExportSheet").getAttribute("data-state"), "ready", "Send it again: back to Share / Save");
  const nBefore = calls.length;
  await el("otpShare").click();
  assert.strictEqual(calls.at(-1).text, req.text, "…with the SAME held file (no new export)");
  assert.strictEqual(calls.length, nBefore + 1);
  result("req-" + reqN, "shared");
  assert.strictEqual(el("otpExportDoneTitle").textContent, "File shared", "shared: 'File shared'");
  assert.strictEqual(el("otpExportDelete").textContent, "Once they've imported it, they delete the file.",
    "design r4 minor 1: after a share the sender has no copy to find — only they delete it");
  assert.strictEqual(el("otpSendAgain").textContent, "Didn't arrive? Send the same file again", "…and after a share: 'Didn't arrive?'");
  const b0 = hist.backs;
  await el("otpExportDone").click();
  assert.ok(!shown("otpExportSheet") && !shown("otpScrim"), "Done closes (no question once it was shared)");
  assert.strictEqual(asked, 2, "…without asking");
  assert.strictEqual(hist.backs, b0 + 1, "N-M2: closing drops the history entry (back once)");
  await settle(5);
  assert.ok(!shown("otpExportSheet"), "…and the popstate that causes is ignored");
  assert.strictEqual(el("otpXferPass").value, "", "closing cleared the transfer passphrase");
  assert.strictEqual(el("otpPass").value, PADPASS, "…but never #otpPass");
  assert.ok(!el("viewLive").inert, "the Live room is live again");
  assert.ok(primary("connect") && !primary("otpExportOpen"), "exported: Connect is the primary again");
  globalThis.confirm = realConfirm;
  console.log("OK  Export (Android): must-differ refused; Share/Save by request id only; unshared close asks; Done drops the history entry and clears the sheet");
}

// ---- Back closes an idle sheet ------------------------------------------------
{
  await el("otpImportOpen").click();
  assert.ok(shown("otpImportSheet"), "Import opens");
  await set("otpImportXfer", "typed");
  const b0 = hist.backs;
  await userBack();
  assert.ok(!shown("otpImportSheet") && !shown("otpScrim"), "N-M2: Back closes an idle sheet");
  assert.strictEqual(hist.backs, b0, "…without a second back()");
  assert.strictEqual(el("otpImportXfer").value, "", "…and clears it");
  console.log("OK  Back closes an idle sheet and clears it");
}

// ---- Import: must-differ, wrong passphrase → Try again without a re-pick, 4 MiB cap ----
let receivedId;
{
  const foreign = await otp.generatePad({ label: "received", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const file = await otp.exportPad(foreign, "the agreed words");
  receivedId = foreign.padId;
  await el("otpImportOpen").click();
  let picks = 0;
  el("otpFile").addEventListener("click", () => { picks++; });
  await set("otpImportXfer", "same words here");
  await set("otpImportPass", "same words here");
  await el("otpImport").click();
  assert.strictEqual(el("otpImportStatus").textContent,
    "Use a different passphrase on this device — the transfer passphrase is known to your contact.",
    "Import must-differ: refused");
  assert.strictEqual(picks, 0, "…before the file picker opens");
  assert.strictEqual(el("otpImportPass").getAttribute("aria-invalid"), "true", "…and the pad passphrase field is marked");

  // Over 4 MiB: refused without reading it.
  await set("otpImportPass", "my own pad words");
  let read = false;
  el("otpFile").files = [{ name: "big.json", size: 4 * 1024 * 1024 + 1, text: async () => { read = true; return "{}"; } }];
  await el("otpFile").dispatch("change");
  assert.ok(el("otpImportStatus").textContent === "Import failed: not a valid pad file" && !read,
    "a file over 4 MiB is refused without being read");

  // Wrong transfer passphrase: the field is marked, the file is held.
  await set("otpImportXfer", "the agreed wordz");
  el("otpFile").files = [{ name: "secure-chat-pad-2026-09-26-1432.json", size: file.length, text: async () => file }];
  await el("otpFile").dispatch("change");
  await until(() => el("otpImportSheet").getAttribute("data-state") === "form" && el("otpImportStatus").textContent, "import error");
  assert.strictEqual(el("otpImportStatus").textContent, "Import failed: wrong passphrase or corrupted pad file");
  assert.ok(el("otpImportXfer").getAttribute("aria-invalid") === "true" && shown("otpImportXferErr") &&
    el("otpImportXfer").getAttribute("aria-describedby") === "otpImportXferErr otpImportStatus",
    "the transfer passphrase is marked, with its line");
  assert.ok(shown("otpImportRetry") && !primary("otpImport") && el("otpImport").classList.contains("ghost") &&
    el("otpImport").textContent === "Choose another file", "'Try again' is the primary, 'Choose another file' the ghost");
  assert.strictEqual(el("otpImportStep3Caption").textContent, "secure-chat-pad-2026-09-26-1432.json — chosen");
  await set("otpImportXfer", "the agreed words");
  assert.ok(!shown("otpImportXferErr") && el("otpImportXfer").getAttribute("aria-invalid") === null, "the marks clear on input");
  el("otpFile").files = []; // a re-pick would find nothing
  await el("otpImportRetry").click();
  await until(() => el("otpImportSheet").getAttribute("data-state") === "done", "import done");
  assert.strictEqual(el("otpSelect").value, receivedId, "Try again imported the held file, without a second pick");
  assert.strictEqual(el("otpPass").value, "my own pad words", "§ 2: the import's pad passphrase is carried into #otpPass");
  assert.ok(shown("otpImportDone") && !shown("otpImport") && !shown("otpImportRetry"), "done: Done is the primary");
  await el("otpImportDone").click();
  assert.ok(!shown("otpImportSheet"), "Done closes");
  console.log("OK  Import: must-differ refused before the picker; >4 MiB not read; wrong passphrase marks the field and Try again reuses the held file");
}

// ---- A received pad: no Export, a note; a forced one is refused ----------
{
  assert.ok(!shown("otpExportOpen") && shown("otpExportNote"), "received pad: Export hidden, the note shown");
  assert.ok(el("otpActions").classList.contains("two"), "…the entry row has two cells");
  assert.ok(!primary("otpExportOpen") && primary("connect"), "…and Connect is the primary");
  await el("otpExportOpen").click(); // only reachable through a stale index; tried anyway
  assert.strictEqual(st.textContent, "You received this pad — only the person who made it can export it.",
    "the Export entry refuses a received pad");
  assert.ok(!shown("otpExportSheet"), "…and opens no sheet");
  const c0 = calls.length, d0 = downloads;
  el("otpXferPass").value = "some other words";
  await el("otpExport").click(); // the handler itself, driven directly
  await settle(5);
  assert.strictEqual(st.textContent, "Export failed: you received this pad — only the person who made it can export it",
    "otp.exportPad refuses it (M9)");
  assert.ok(calls.length === c0 && downloads === d0, "…no file anywhere");
  el("otpXferPass").value = "";
  console.log("OK  received pad: no Export entry, the note, and forced exports refused (M9)");
}

// ---- Choosing another pad empties the carried passphrase ----------------
{
  assert.strictEqual(el("otpPass").value, "my own pad words", "fixture: the received pad's passphrase is carried");
  el("otpSelect").value = madeId;
  await el("otpSelect").dispatch("change");
  assert.strictEqual(el("otpPass").value, "", "round 2 minor 5: another pad → the carried passphrase is emptied");
  assert.ok(!el("otpPass").hidden && !shown("otpUnlocked"), "…and the field shows (that pad is locked)");
  console.log("OK  choosing another pad empties #otpPass");
}

// ---- the Export entry unlocks first; its history entry is pushed in the click ----
{
  const p0 = hist.pushes, b0 = hist.backs;
  await el("otpExportOpen").click();
  assert.ok(st.textContent === "Enter this pad's passphrase to unlock it." && hist.pushes === p0 && !shown("otpExportSheet"),
    "locked, no passphrase: said, no sheet, no history entry");
  el("otpPass").value = "not the pad passphrase";
  el("otpPass")._focused = false; el("otpExportOpen").focus(); // (the stub keeps no single focus: reset the flag)
  await el("otpExportOpen").click();
  await settle(5);
  assert.ok(/^Could not unlock this pad: /.test(st.textContent) && !shown("otpExportSheet"),
    "a wrong passphrase: said as an unlock failure (nothing was exported), no sheet: " + st.textContent);
  assert.ok(el("otpPass")._focused, "…focus goes to the passphrase field (hot m3)");
  assert.ok(hist.pushes === p0 + 1 && hist.backs === b0 + 1, "…and the entry pushed for it is dropped again");
  el("otpPass").value = PADPASS;
  const opening = el("otpExportOpen").click();
  assert.strictEqual(hist.pushes, p0 + 2, "N-M2: the entry is pushed synchronously in the click, before the unlock's await");
  assert.strictEqual(el("otpExportOpen").getAttribute("aria-busy"), "true", "…while the button says it works");
  await opening;
  assert.ok(shown("otpExportSheet") && hist.pushes === p0 + 2, "unlocked: the sheet opens, no second entry");
  assert.ok(shown("otpUnlocked"), "…and the panel shows the unlocked row");
  assert.ok(shown("otpExportPadWarn"), "the pad card says '· exported before' (index hint at open)");
  await el("otpExportClose").click();
  assert.ok(!shown("otpExportSheet") && hist.backs === b0 + 2, "× closes and drops the entry");
  await settle(5);
  console.log("OK  Export entry: unlock first (said on failure), history entry pushed inside the click and dropped on failure");
}

// ======== fix round 1 (design/research/reviews/otp-fix-round-1.md) ========
const REEXPORT = /^This pad was already exported\. A pad must be imported on only ONE device/;
const PAD_BUSY_TEXT = "This pad is in use — open in a chat, or being exported or imported, in this or another tab or window. Close or finish it there first.";
const openExport = async () => {
  await el("otpExportOpen").click();
  assert.ok(shown("otpExportSheet"), "fixture: the Export sheet is open");
};
const stateOf = (id) => el(id).getAttribute("data-state");

// ---- J10 / M17: closing the re-export confirm disarms it; the panel keeps no sheet error ----
{
  assert.strictEqual(el("otpSelect").value, madeId, "fixture: our own (exported) pad is selected, unlocked");
  await openExport();
  await set("otpXferPass", "another transfer passphrase");
  await el("otpExport").click();
  assert.ok(stateOf("otpExportSheet") === "confirm" && REEXPORT.test(el("otpExportStatus").textContent),
    "fixture: an exported pad asks first (the re-export confirm)");
  assert.match(st.className, /\bvh\b/, "design R3-M1: while the sheet is up, the panel copy of its error is not shown");
  await el("otpExportCancel").click();
  assert.ok(!shown("otpExportSheet"), "'Don't export' closes");
  assert.strictEqual(st.textContent, "", "design R3-M1: …and the panel keeps nothing of the sheet's error");
  const c0 = calls.length;
  await openExport();
  await set("otpXferPass", "another transfer passphrase");
  await el("otpExport").click();
  assert.ok(stateOf("otpExportSheet") === "confirm" && REEXPORT.test(el("otpExportStatus").textContent) && calls.length === c0,
    "§ 5: closing disarmed the latch — the next Create asks again, no file");
  await el("otpExportCancel").click();
  console.log("OK  fix round: closing the re-export confirm disarms it (unit); the panel keeps no sheet error");
}

// ---- hot B1 / pentest R2-1: a busy pad returns the Export sheet to its form ----
{
  let release;
  const holding = navigator.locks.request("sc.otp.lock.v1." + madeId, () => new Promise((r) => { release = r; }));
  await openExport();
  await set("otpXferPass", "words while the pad is busy");
  const c0 = calls.length;
  await el("otpExport").click();
  assert.strictEqual(stateOf("otpExportSheet"), "form", "R2-1: a busy pad leaves 'working' — back to the form");
  assert.ok(shown("otpExportClose") && shown("otpExport"), "…× and Create are back");
  assert.strictEqual(el("otpExportStatus").textContent, PAD_BUSY_TEXT, "…and the sheet says why");
  assert.ok(!el("otpExport").disabled && calls.length === c0, "…Create is usable again, and nothing was handed out");
  await el("otpExportClose").click();
  assert.ok(!shown("otpExportSheet") && !el("viewLive").inert, "…and the sheet closes: the page is usable");
  release();
  await holding;
  console.log("OK  R2-1: PAD_BUSY in the Export sheet goes back to the form, closable");
}

// ---- pentest R2-3 / cold MA-2: must-differ cannot be skipped by switching pads ----
{
  el("otpSelect").value = receivedId;
  await el("otpSelect").dispatch("change");
  el("otpSelect").value = madeId;
  await el("otpSelect").dispatch("change");
  assert.ok(!shown("otpUnlocked") && !el("otpPass").hidden && el("otpPass").value === "",
    "R2-3: back on a pad after choosing another: it is locked again, its field empty");
  await el("otpExportOpen").click();
  assert.ok(st.textContent === "Enter this pad's passphrase to unlock it." && !shown("otpExportSheet"),
    "…so Export asks for the passphrase first");
  el("otpPass").value = PADPASS;
  await openExport();
  await set("otpXferPass", PADPASS);
  await el("otpExport").click();
  assert.strictEqual(el("otpExportStatus").textContent,
    "Use a different passphrase for the file — this one is your pad passphrase.",
    "R2-3: the pad passphrase is refused as the transfer passphrase after the round trip");
  await el("otpExportClose").click();
  // Fail closed: unlocked, but nothing in the field to compare against.
  el("otpPass").value = "";
  el("otpXferPass").value = PADPASS;
  const d0 = downloads, c0 = calls.length;
  await el("otpExport").click();
  assert.strictEqual(st.textContent, "Enter this pad's passphrase to unlock it.",
    "R2-3: with the pad unlocked but #otpPass empty, Export refuses instead of skipping the comparison");
  assert.ok(downloads === d0 && calls.length === c0, "…nothing handed out");
  el("otpXferPass").value = "";
  el("otpPass").value = PADPASS;
  console.log("OK  R2-3: switching pads locks the panel's pad; an export with nothing to compare fails closed");
}

// ---- hot M1 / cold MA-1 / pentest R2-2: Back during the Export entry's unlock ----
{
  const lockMade = async () => {
    el("otpSelect").value = receivedId; await el("otpSelect").dispatch("change");
    el("otpSelect").value = madeId; await el("otpSelect").dispatch("change");
    el("otpPass").value = PADPASS;
  };
  await lockMade();
  await settle(5); // the back() of the last close has run
  const idx0 = hist.idx, b0 = hist.backs;
  const opening = el("otpExportOpen").click();
  assert.strictEqual(hist.idx, idx0 + 1, "fixture: the entry is pushed in the click");
  await userBack(); // Back while the unlock's KDF runs
  await opening;
  await settle(5);
  assert.ok(!shown("otpExportSheet"), "R2-2: Back during the unlock means 'never mind' — no sheet opens after it");
  assert.ok(hist.backs === b0 && hist.idx === idx0, `…and app.js calls no back() of its own (it would leave the app): backs ${hist.backs - b0}, idx ${hist.idx} vs ${idx0}, status ${st.textContent}`);
  assert.ok(shown("otpUnlocked"), "…the pad stays unlocked (that was wanted)");
  // The bookkeeping is sound afterwards: a sheet opens, Back closes it.
  await el("otpImportOpen").click();
  assert.ok(shown("otpImportSheet") && hist.idx === idx0 + 1, "a later sheet pushes its own entry");
  await userBack();
  assert.ok(!shown("otpImportSheet") && hist.idx === idx0, "…and Back closes it (no ignore left over)");
  // With no earlier page (Android): a close whose entry is already gone calls no back().
  console.log("OK  R2-2: Back during the Export entry's unlock cancels it; history stays in step");
}

// ---- cold M2: another pad chosen during the Export entry's unlock ----------
{
  el("otpSelect").value = receivedId; await el("otpSelect").dispatch("change");
  el("otpSelect").value = madeId; await el("otpSelect").dispatch("change");
  el("otpPass").value = PADPASS;
  await settle(5);
  const idx0 = hist.idx;
  const opening = el("otpExportOpen").click();
  el("otpSelect").value = receivedId;
  await el("otpSelect").dispatch("change");
  await opening;
  await settle(5);
  assert.ok(!shown("otpExportSheet"), "cold M2: the pad was switched during the unlock — no Export sheet (for the wrong card)");
  assert.strictEqual(hist.idx, idx0, "…and its history entry is dropped");
  el("otpSelect").value = madeId; await el("otpSelect").dispatch("change");
  assert.ok(!shown("otpUnlocked"), "…the unlock of a pad no longer on screen is not cached");
  el("otpPass").value = PADPASS;
  console.log("OK  cold M2: a pad switch during the Export entry's unlock opens no sheet");
}

// ---- J20 / hot n2: a close and an open in one task keep the new sheet ------
{
  await settle(5);
  const idx0 = hist.idx;
  await el("otpImportOpen").click();
  await el("otpImportClose").click(); // drops its entry: back() is queued
  await el("otpNewOpen").click();     // …and a new sheet opens before that popstate arrives
  await settle(5);
  assert.ok(shown("otpNewSheet"), "J20: the popstate of the close is ignored — it does not close the NEW sheet");
  await el("otpNewLater").click();
  await settle(5);
  assert.ok(!shown("otpNewSheet") && hist.idx === idx0,
    "…and once it closes, history is back where it started (no entry left over, none taken from the page)");
  console.log("OK  J20: the ignore counter keeps a sheet opened in the same task; no stray back()");
}

// ---- M6: the 500 ms double-tap guard on bottom-row actions ------------------
{
  await el("otpNewOpen").click();
  const now = performance.now();
  await el("otpGenerate").dispatch("click", { timeStamp: now });
  assert.strictEqual(el("otpNewStatus").textContent, "", "M6: a tap within 500 ms of the sheet appearing is ignored");
  await el("otpGenerate").dispatch("click", { timeStamp: now + 600 });
  assert.match(el("otpNewStatus").textContent, /^Set a pad passphrase first/, "…a later one acts");
  console.log("OK  M6: bottom-row taps in a sheet's first 500 ms are ignored");
}

// ---- M10: New pad runs once for two taps ------------------------------------
{
  await set("otpNewPass", "a strong enough pad passphrase");
  el("otpLabel").value = "double-tap";
  const n0 = otp.listPads().length;
  const c1 = el("otpGenerate").click(), c2 = el("otpGenerate").click();
  await c1; await c2;
  await until(() => stateOf("otpNewSheet") === "done", "New pad done");
  assert.strictEqual(otp.listPads().length, n0 + 1, "M10: two taps on Create pad make ONE pad");
  await el("otpNewLater").click();
  console.log("OK  M10: New pad's re-entry guard");
}

// ---- M5 / J16 / hot m1 / design r3 minor 5: file-level import errors ---------
{
  const foreign = await otp.generatePad({ label: "for errors", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const good = await otp.exportPad(foreign, "agreed words");
  await el("otpImportOpen").click();
  await set("otpImportXfer", "agreed wordz");
  await set("otpImportPass", "my pad words here");
  el("otpFile").files = [{ name: "a.json", size: good.length, text: async () => good }];
  await el("otpFile").dispatch("change");
  await until(() => el("otpImportStatus").textContent !== "", "import error");
  assert.strictEqual(el("otpImportXfer").getAttribute("aria-invalid"), "true", "fixture: a wrong passphrase marks the field");
  el("otpFile").files = [{ name: "junk.json", size: 7, text: async () => "garbage" }];
  await el("otpFile").dispatch("change");
  await until(() => /not a valid pad file/.test(el("otpImportStatus").textContent), "file-level error");
  assert.ok(!shown("otpImportRetry") && el("otpImport").textContent === "Choose another file",
    "M5/J16: a file-level error drops the held file — no 'Try again' for a file that can never import");
  assert.strictEqual(el("otpImportXfer").getAttribute("aria-invalid"), null,
    "hot m1: …and the transfer passphrase is no longer blamed");
  const unreadable = new Error("The requested file could not be read, typically due to permission problems");
  unreadable.name = "NotReadableError";
  el("otpFile").files = [{ name: "gone.json", size: 10, text: async () => { throw unreadable; } }];
  await el("otpFile").dispatch("change");
  assert.strictEqual(el("otpImportStatus").textContent, "Import failed: could not read that file — choose it again.",
    "design r3 minor 5: an unreadable file is said in our words, with the next step");
  await el("otpImportClose").click();
  console.log("OK  file-level import errors: held file dropped, no stale passphrase mark, readable wording");
}

// ---- J11 / J13: a closed sheet leaves no request in flight; "again" only when done ----
{
  const realConfirm = globalThis.confirm;
  globalThis.confirm = () => true; // close an unshared Android file: OK
  el("otpSelect").value = madeId; await el("otpSelect").dispatch("change"); // our exported pad
  el("otpPass").value = PADPASS;
  try {
    const toReady = async () => {
      await openExport();
      await set("otpXferPass", "yet another transfer passphrase");
      await el("otpExport").click();
      assert.strictEqual(stateOf("otpExportSheet"), "confirm", "fixture: the re-export confirm");
      await el("otpExport").click(); // "Export again"
      await until(() => stateOf("otpExportSheet") === "ready", "ready");
    };
    await toReady();
    await el("otpShare").click(); // a request in flight…
    assert.ok(el("otpShare").disabled, "fixture: Share is disabled while its request is open");
    await el("otpExportClose").click(); // …and the sheet is closed under it
    assert.ok(!shown("otpExportSheet"), "fixture: closed");
    await toReady();
    assert.ok(!el("otpShare").disabled && !el("otpSave").disabled,
      "J11: a request left open by a closed sheet does not disable Share / Save in the next one");
    await el("otpShare").click();
    result("req-" + reqN, "cancelled");
    assert.strictEqual(el("otpExportStatus").textContent, "Not shared.", "fixture: cancelled");
    await el("otpSendAgain").click(); // hidden in this state; driven anyway
    assert.ok(stateOf("otpExportSheet") === "ready" && el("otpExportStatus").textContent === "Not shared.",
      "J13: 'Send the same file again' does nothing outside the done state");
    await el("otpExportClose").click();
  } finally {
    globalThis.confirm = realConfirm;
  }
  console.log("OK  J11/J13: no stale request after close; the 'again' link acts only when done");
}

// ---- the success sentences are quiet in the panel also with no sheet up ----
{
  // (Handlers do not depend on a sheet being open.) New pad driven directly:
  await set("otpNewPass", "a pad passphrase with no sheet");
  el("otpLabel").value = "no-sheet";
  await el("otpGenerate").click();
  await until(() => /^Generated \+ encrypted pad "no-sheet"/.test(st.textContent), "generated");
  assert.match(st.className, /\bvh\b/, "§ 1.5: 'Generated + encrypted…' is visually hidden in the panel, sheet or not");
  el("otpNewPass").value = "";
  console.log("OK  success sentences are .vh in the panel with no sheet open");
}

// ======== fix round 2 (otp-fix-round-1.md, "Round 2") ========
const lockPad = async (id, pass) => {
  await settle(5);
  const other = otp.listPads().find((p) => p.padId !== id).padId;
  el("otpSelect").value = other; await el("otpSelect").dispatch("change");
  el("otpSelect").value = id; await el("otpSelect").dispatch("change");
  el("otpPass").value = pass;
};
const ALREADY = "You already have this pad on this device — not importing again (a pad must live on exactly one device per side).";

// ---- cold r2 MA-1 + hot r2 N2: the same file twice / the maker's own file ----
{
  const foreign = await otp.generatePad({ label: "twice", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const file = await otp.exportPad(foreign, "agreed words twice");
  const importFile = async (text) => {
    await el("otpImportOpen").click();
    await set("otpImportXfer", "agreed words twice");
    await set("otpImportPass", "my own words for twice");
    el("otpFile").files = [{ name: "f.json", size: text.length, text: async () => text }];
    await el("otpFile").dispatch("change");
    await until(() => stateOf("otpImportSheet") !== "working" && (el("otpImportStatus").textContent || stateOf("otpImportSheet") === "done"), "import settled");
  };
  await importFile(file);
  assert.strictEqual(stateOf("otpImportSheet"), "done", "fixture: the first import works");
  await el("otpImportDone").click();
  await lockPad(madeId, PADPASS);
  await openExport(); await el("otpExportClose").click(); // unlock madeId in the panel
  assert.ok(shown("otpUnlocked") && el("otpPass").value === PADPASS, "fixture: our pad is unlocked, its passphrase in the field");
  await importFile(file);
  assert.strictEqual(el("otpImportStatus").textContent, ALREADY,
    "cold MA-1: the same file again says 'you already have this pad' — not 'already been used … generate a fresh pad'");
  assert.strictEqual(el("otpSelect").value, foreign.padId, "…and selects it");
  assert.ok(el("otpPass").value === "" && !shown("otpUnlocked"),
    "hot r2 N2: a selection made by the page locks the unlocked pad and empties #otpPass, as a user's change does");
  await el("otpImportClose").click();
  // The maker importing their own export.
  const own = await otp.unlockPad(madeId, PADPASS);
  const ownFile = await otp.exportPad(own.record, "agreed words twice");
  own.record.bytes.fill(0);
  await importFile(ownFile);
  assert.strictEqual(el("otpImportStatus").textContent, ALREADY, "cold MA-1: the maker's own file: 'you already have this pad'");
  await el("otpImportClose").click();
  console.log("OK  cold MA-1 / hot N2: a pad still here is 'already have', and the page's selection locks the panel");
}

// ---- cold r2 MA-3: Forget asks, naming the pad --------------------------------
{
  const doomed = await otp.generatePad({ label: "to forget", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  await otp.saveNewPad(doomed, "forget me passphrase");
  el("otpSelect").value = doomed.padId; await el("otpSelect").dispatch("change");
  const realConfirm = globalThis.confirm;
  let said = null;
  globalThis.confirm = (m) => { said = m; return false; };
  await el("otpForget").click();
  assert.ok(said && /"to forget"/.test(said) && /cannot be imported again/.test(said), "MA-3: Forget asks, naming the pad: " + said);
  assert.ok(otp.padMeta(doomed.padId), "…Cancel keeps the pad");
  el("otpPass").value = "typed for the doomed pad";
  globalThis.confirm = () => true;
  await el("otpForget").click();
  globalThis.confirm = realConfirm;
  assert.strictEqual(otp.padMeta(doomed.padId), null, "…OK deletes it");
  assert.strictEqual(el("otpPass").value, "", "cold r2 n-2 / hot N2: no passphrase is left in the field after Forget");
  console.log("OK  cold MA-3: Forget is confirm-gated and names the pad");
}

// ---- hot r2 N3: a view switch during the Export entry's unlock cancels it ----
{
  await lockPad(madeId, PADPASS);
  const idx0 = hist.idx;
  const opening = el("otpExportOpen").click();
  const nav = (v) => dom.body.querySelectorAll(".navitem").find((b) => b.dataset.view === v);
  const chats = nav("chats");
  await chats.click();
  await opening;
  await settle(5);
  assert.ok(!shown("otpExportSheet"), "N3: the user went to another view during the unlock — no Export sheet over it");
  assert.strictEqual(hist.idx, idx0, "…and its history entry is dropped");
  await nav("live").click();
  console.log("OK  hot N3: a view switch during the Export entry's unlock cancels it");
}

// ---- W1 / M19: #otpPass edited during the unlock's KDF ------------------------
{
  await lockPad(madeId, PADPASS);
  const opening = el("otpExportOpen").click();
  el("otpPass").value = "something typed during the unlock";
  await opening;
  assert.ok(shown("otpExportSheet"), "fixture: the Export sheet opened");
  assert.strictEqual(el("otpPass").value, PADPASS, "W1: the field holds the passphrase that unlocked the pad, not what was typed meanwhile");
  await set("otpXferPass", PADPASS);
  await el("otpExport").click();
  assert.strictEqual(el("otpExportStatus").textContent, "Use a different passphrase for the file — this one is your pad passphrase.",
    "W1: …so the pad passphrase is still refused as the transfer passphrase");
  await el("otpExportClose").click();
  console.log("OK  W1: the unlock writes back its passphrase; must-differ holds after an edit during the KDF");
}

// ---- W6: no other sheet opens while the Export entry unlocks ------------------
{
  await lockPad(madeId, PADPASS);
  const idx0 = hist.idx;
  const opening = el("otpExportOpen").click();
  await el("otpImportOpen").click();
  assert.ok(!shown("otpImportSheet") && hist.idx === idx0 + 1, "W6: Import tapped during the unlock opens nothing (its entry would sit on ours)");
  await opening;
  assert.ok(shown("otpExportSheet"), "…the Export sheet opens as asked");
  await el("otpExportClose").click();
  await settle(5);
  assert.strictEqual(hist.idx, idx0, "…and history is back where it was");
  console.log("OK  W6: no other sheet during the Export entry's unlock");
}

// ---- W3+W4: Back during a FAILED unlock, at the first history entry (Android) ----
{
  await lockPad(madeId, "not the pad passphrase");
  hist.entries = [null]; hist.idx = 0; // no earlier page: the app's first entry
  const b0 = hist.backs;
  const opening = el("otpExportOpen").click();
  await userBack();
  await opening;
  await settle(5);
  assert.ok(!shown("otpExportSheet") && /^Could not unlock this pad: /.test(st.textContent), "fixture: the unlock failed, no sheet");
  assert.strictEqual(hist.backs, b0, "W3+W4: Back took the entry — app.js calls no back() of its own");
  await el("otpImportOpen").click();
  assert.ok(shown("otpImportSheet"), "fixture: a later sheet opens");
  assert.strictEqual(st.textContent, "", "hot r2 N1-nit: the panel's earlier error is cleared when a sheet opens");
  await userBack();
  assert.ok(!shown("otpImportSheet"), "W3+W4: …and the next Back closes it (no ignore left stuck)");
  console.log("OK  W3+W4: Back during a failed unlock leaves history in step");
}

// ---- cold M4: the on-top check alone ---------------------------------------
{
  await settle(5);
  await el("otpImportOpen").click();
  // A traversal whose popstate never reached the page (e.g. a shell's own
  // goBack racing a reload): the entry is gone, the page still thinks it owns one.
  hist.idx--;
  const b0 = hist.backs;
  await el("otpImportClose").click();
  assert.strictEqual(hist.backs, b0, "cold M4: a close whose entry is no longer on top calls no back() (it would leave the app)");
  console.log("OK  cold M4: otpHistDrop only goes back from its own entry");
}

// ---- hot m4: a marked field is described by its sheet's status ----------------
{
  el("otpXferPass").setAttribute("aria-describedby", "otpXferWarn"); // as in index.html (the stub reads no attributes)
  await lockPad(madeId, PADPASS);
  await openExport();
  await set("otpXferPass", PADPASS);
  await el("otpExport").click();
  assert.strictEqual(el("otpXferPass").getAttribute("aria-describedby"), "otpXferWarn otpExportStatus",
    "hot m4: the refused field is described by the refusal: " + el("otpXferPass").getAttribute("aria-describedby") + " / " + el("otpExportStatus").textContent);
  await set("otpXferPass", "x");
  assert.strictEqual(el("otpXferPass").getAttribute("aria-describedby"), "otpXferWarn", "…and only by its warn line again after input");
  await el("otpExportClose").click();
  console.log("OK  hot m4: aria-describedby follows the mark");
}

// ---- owner (cold r2 MA-4): the weak transfer warning at the field and beside Share / Save ----
{
  await lockPad(madeId, PADPASS);
  const realConfirm = globalThis.confirm;
  globalThis.confirm = () => true;
  try {
    await openExport();
    await set("otpXferPass", "hunter2");
    assert.match(el("otpXferWarn").textContent, /^Weak: .*Anyone who gets a copy of the file can try to guess it/,
      "MA-4: the transfer field's warning says what is at stake");
    await el("otpExport").click();
    if (stateOf("otpExportSheet") === "confirm") await el("otpExport").click();
    await until(() => stateOf("otpExportSheet") === "ready", "ready");
    assert.ok(!el("otpExportReadyWeak").hidden, "MA-4: …and stands beside Share / Save when the file leaves");
    await el("otpExportClose").click();
  } finally {
    globalThis.confirm = realConfirm;
  }
  console.log("OK  MA-4: weak transfer passphrase warned at the field and at Share / Save (still accepted)");
}

// ---- cold r2 n-1: New pad forgets its name, size and drawing on close ------------
{
  await el("otpNewOpen").click();
  el("otpLabel").value = "left behind";
  el("otpSize").value = "8192";
  await el("otpNewClose").click();
  await el("otpNewOpen").click();
  assert.ok(el("otpLabel").value === "" && el("otpSize").value === String(otp.PAD_SIZES[1].bytes), "n-1: a reopened New pad starts clean");
  await el("otpNewClose").click();
  console.log("OK  cold n-1: New pad resets on close");
}

// ======== fix round 3 (otp-fix-round-1.md, "Round 3") ========
const TOKEN = (hist.entries.find((e) => e && e.otpSheet) || {}).otpSheet;
assert.ok(typeof TOKEN === "string" && TOKEN.length >= 16, "fixture: app.js pushes its per-page token (I-3)");

// ---- pentest r4 G3 / W23: Back during a failed unlock over a stale entry of our own ----
{
  await lockPad(madeId, "not the pad passphrase");
  hist.entries = [{ otpSheet: TOKEN }]; hist.idx = 0; // an entry of ours left below (hot n2 / J20)
  const b0 = hist.backs;
  const opening = el("otpExportOpen").click();
  await userBack();
  await opening;
  await settle(5);
  assert.ok(!shown("otpExportSheet"), "fixture: the unlock failed, no sheet");
  assert.strictEqual(hist.backs, b0,
    "W23: the Back during the unlock cleared the entry flag — no back() from the stale entry below (it would find nothing, or leave)");
  await el("otpImportOpen").click();
  await userBack();
  assert.ok(!shown("otpImportSheet"), "…and the next Back closes a later sheet");
  console.log("OK  W23: popstate clears the entry flag even with no sheet up");
}

// ---- pentest r4 I-3: an entry left by an EARLIER page is never ours ----------
{
  await settle(5);
  hist.entries = [null, { otpSheet: "entry-of-an-earlier-page" }]; hist.idx = 1; // a reload with a sheet up
  await el("otpImportOpen").click();
  hist.idx--; // a traversal whose popstate never reached the page (as in cold M4)
  const b0 = hist.backs;
  await el("otpImportClose").click();
  assert.strictEqual(hist.backs, b0, "I-3: the entry on top is another page's — no back() (the token tells them apart)");
  hist.entries = [null]; hist.idx = 0;
  console.log("OK  I-3: history entries carry this page's token");
}

// ---- pentest r4 R4-1: Connect pressed during the Export entry's unlock ------
{
  // (a) the relay has not answered (still the room screen): since round 5
  //     (pentest r6 R6-1) a pending connect locks nothing — the sheet opens;
  //     a chat coming up later closes it (the R5-1 blocks below).
  await lockPad(madeId, PADPASS);
  dom.selectAlg("OTP");
  const before0 = dom.socket();
  const openingA = el("otpExportOpen").click();
  const connectingA = el("connect").click();
  await openingA; await connectingA;
  await settle(5);
  assert.ok(shown("otpExportSheet"), "R6-1: a Connect the relay has not answered does not cancel the Export entry");
  await el("otpExportClose").click();
  if (dom.socket() !== before0) dom.socket().close();
  await settle(5);
}
{
  // (b) the pentester's PoC: the chat screen comes up (whichever KDF ends first).
  await lockPad(madeId, PADPASS);
  dom.selectAlg("OTP");
  const before = dom.socket();
  const idx0 = hist.idx;
  const opening = el("otpExportOpen").click();
  const connecting = el("connect").click();
  await until(() => dom.socket() !== before, "the socket");
  const ws = dom.socket();
  ws.open();
  await ws.deliver({ type: "joined", role: "owner" });
  await opening; await connecting;
  await settle(5);
  assert.ok(!el("scrChat").hidden, "fixture: the chat screen is up");
  assert.ok(!shown("otpExportSheet") && !el("viewLive").inert,
    "R4-1: the Export sheet does not open over the live chat (and the chat is not made inert): " + JSON.stringify({ sheet: shown("otpExportSheet"), inert: el("viewLive").inert, room: el("scrRoom").hidden, st: st.textContent, hint: el("hint").textContent }));
  assert.strictEqual(hist.idx, idx0, "…its history entry is dropped");
  await el("disconnect").click();
  await el("toRoom").click();
  console.log("OK  R4-1: Connect during the Export entry's unlock cancels the sheet");
}

// ---- pentest r4 G1 / W12: another security option during the unlock --------
{
  await lockPad(madeId, PADPASS);
  const idx0 = hist.idx;
  const opening = el("otpExportOpen").click();
  dom.selectAlg("DHKE");
  await el("algCards").dispatch("change");
  await opening;
  await settle(5);
  assert.ok(!shown("otpExportSheet"), "W12: the OTP card was left during the unlock — no Export sheet over another option");
  assert.strictEqual(hist.idx, idx0, "…and its history entry is dropped");
  dom.selectAlg("OTP");
  await el("algCards").dispatch("change");
  console.log("OK  W12: leaving the OTP option during the unlock cancels the sheet");
}

// ---- pentest r4 I-2: the Forget confirm shows a cleaned label ----------------
{
  const odd = await otp.generatePad({ label: "odd", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  await otp.saveNewPad(odd, "odd pad passphrase words");
  // The index is not authenticated (and older imports kept raw labels).
  const IDX = "sc.otp.index.v1";
  const idx = JSON.parse(localStorage.getItem(IDX));
  idx.find((e) => e.padId === odd.padId).label = "Chess\n\nOK only hides it‮evil\u0007";
  localStorage.setItem(IDX, JSON.stringify(idx));
  el("otpSelect").value = odd.padId; await el("otpSelect").dispatch("change");
  const realConfirm = globalThis.confirm;
  let said = null;
  globalThis.confirm = (m) => { said = m; return false; };
  await el("otpForget").click();
  globalThis.confirm = realConfirm;
  assert.ok(said && said.startsWith('Delete the pad "Chess OK only hides it evil" from this device?'),
    "I-2: the confirm names the pad without line breaks, bidi overrides or control characters: " + JSON.stringify(said));
  console.log("OK  I-2: the Forget confirm shows the label cleaned");
}

// ======== fix round 4 (otp-fix-round-1.md, "Round 4") ========
// ---- pentest r5 KH: the history token is this page's random draw ----------
assert.ok(draws8.includes(TOKEN), "KH: the history token is a fresh 64-bit random draw of this page load, not a constant");
console.log("OK  KH: the per-page history token comes from crypto.getRandomValues");

const startConnect = async () => {
  dom.selectAlg("OTP");
  el("room").value = ROOM; await el("room").dispatch("input");
  const before = dom.socket();
  const connecting = el("connect").click();
  await until(() => dom.socket() !== before, "the socket");
  const ws = dom.socket();
  ws.open();
  await settle(5);
  return { ws, connecting };
};
const endChat = async () => {
  if (!el("scrChat").hidden || dom.socket().readyState !== 3) await el("disconnect").click();
  await settle(5);
  if (el("scrRoom").hidden) await el("toRoom").click();
};

// ---- pentest r5 R5-1 (P1, P1b) as decided in round 5: Connect first, a sheet
//      before the relay answers — it opens (R6-1), and the chat closes it ----
{
  await lockPad(madeId, PADPASS);
  await openExport(); await el("otpExportClose").click(); // unlocked: Export opens at once
  await settle(5);
  for (const [entry, sheet] of [["otpExportOpen", "otpExportSheet"], ["otpNewOpen", "otpNewSheet"], ["otpImportOpen", "otpImportSheet"]]) {
    const { ws, connecting } = await startConnect();
    await el(entry).click();
    assert.ok(shown(sheet), `R6-1: ${entry} opens while a connect waits for the relay (pad management is not locked)`);
    await ws.deliver({ type: "joined", role: "owner" });
    await connecting; await settle(5);
    assert.ok(!shown(sheet) && !el("scrChat").hidden && !el("viewLive").inert,
      `R5-1 (P1): the chat screen closes the idle ${sheet}; the chat is usable`);
    await el(entry).click();
    assert.ok(!shown(sheet), "…and no sheet opens over the chat screen");
    await endChat();
  }
  console.log("OK  R5-1/R6-1: sheets open while a connect is pending; the chat screen closes them");
}

// ---- pentest r5 P2 / KJ: Connect on pad A, then Export on locked pad B; joined during B's unlock ----
{
  const B = await otp.generatePad({ label: "padB", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  await otp.saveNewPad(B, "pad b passphrase words");
  await lockPad(madeId, PADPASS);
  const { ws, connecting } = await startConnect();
  el("otpSelect").value = B.padId; await el("otpSelect").dispatch("change");
  el("otpPass").value = "pad b passphrase words";
  const idx0 = hist.idx;
  const opening = el("otpExportOpen").click();          // B's unlock (a KDF) starts
  await ws.deliver({ type: "joined", role: "owner" });  // the chat screen comes up meanwhile
  await opening; await connecting; await settle(5);
  assert.ok(!shown("otpExportSheet") && !el("scrChat").hidden && !el("viewLive").inert,
    "P2/KJ: the chat came up during B's unlock — no Export sheet over it (the room-screen term)");
  assert.strictEqual(hist.idx, idx0, "…its entry dropped");
  await endChat();
  console.log("OK  P2/KJ: the room-screen term keeps the Export sheet off a chat that came up during the unlock");
}

// ---- KJ / R4-1: the relay answers during the Export entry's unlock ----------
// Three layers stop the sheet here: the busy check at the end of the unlock,
// the room-screen term, and the chat screen closing an idle sheet; the test
// holds the outcome (no sheet over the chat), the mutants in the triage show
// which layer binds on its own.
{
  await lockPad(madeId, PADPASS);
  const idx0 = hist.idx;
  const opening = el("otpExportOpen").click();
  const { ws, connecting } = await startConnect();
  await ws.deliver({ type: "joined", role: "owner" });
  await opening; await connecting; await settle(5);
  assert.ok(!shown("otpExportSheet") && !el("scrChat").hidden && !el("viewLive").inert,
    "KJ/R4-1: joined during the entry's unlock — no sheet over the chat");
  assert.strictEqual(hist.idx, idx0, "…its entry dropped");
  await endChat();
  console.log("OK  KJ: no Export sheet over a chat that came up during the unlock");
}

// ---- pentest r5 I-5c: a Connect that refuses at once does not cancel Export ----
{
  await lockPad(madeId, PADPASS);
  el("room").value = "not-a-room"; await el("room").dispatch("input");
  dom.selectAlg("OTP");
  const opening = el("otpExportOpen").click();
  const connecting = el("connect").click(); // refused at once: bad chat code
  await opening; await connecting; await settle(5);
  assert.ok(shown("otpExportSheet"), "I-5c: Connect refused at once (bad code) — the Export sheet still opens");
  await el("otpExportClose").click();
  el("room").value = ROOM; await el("room").dispatch("input");
  console.log("OK  I-5c: an instant Connect refusal does not cancel the Export entry");
}

// ---- R5-1, second layer: showScreen closes an idle sheet; a working one finishes first ----
{
  // (The tab bar and the Live room are inert under a sheet in a browser; the
  // stub lets Connect be pressed anyway — the only way to raise the chat
  // screen under an open sheet, for this layer's sake.)
  await el("otpImportOpen").click();
  assert.ok(shown("otpImportSheet"), "fixture: an idle sheet");
  let { ws, connecting } = await startConnect();
  await ws.deliver({ type: "joined", role: "owner" });
  await connecting; await settle(5);
  assert.ok(!shown("otpImportSheet") && !el("viewLive").inert, "R5-1: the chat screen closes an idle sheet (as showView does)");
  await endChat();
  // Working: New pad's KDF runs when the chat screen comes up.
  await el("otpNewOpen").click();
  await set("otpNewPass", "a pad passphrase while connecting");
  const gen = el("otpGenerate").click();
  await until(() => stateOf("otpNewSheet") === "working", "working");
  ({ ws, connecting } = await startConnect());
  await ws.deliver({ type: "joined", role: "owner" });
  await connecting;
  assert.ok(shown("otpNewSheet") && stateOf("otpNewSheet") === "working", "R5-1: a WORKING sheet is not torn down mid-KDF");
  await gen; await settle(5);
  assert.ok(!shown("otpNewSheet") && !el("viewLive").inert, "…it closes itself once the work ends, the pad made");
  assert.ok(/^Pad “.*” created — Export it to your contact after this chat\.$/.test(st.textContent) && !/\bvh\b/.test(st.className) &&
    el("hint").textContent === st.textContent,
    "R7-2: what the done block would have said stays, visible, in the chat's hint and the panel: " + JSON.stringify([st.textContent, st.className, el("hint").textContent]));
  await endChat();
  console.log("OK  R5-1: showScreen closes an idle sheet; a working one finishes, then closes");
}

// ---- pentest r5 KG, I-5b: the pad list and the Export card show cleaned labels ----
{
  const IDX = "sc.otp.index.v1";
  const idx = JSON.parse(localStorage.getItem(IDX));
  idx.find((e) => e.padId === madeId).label = "Mine‮\n​x";
  localStorage.setItem(IDX, JSON.stringify(idx));
  await el("otpNewOpen").click(); // a New pad refreshes the list
  await set("otpNewPass", "another strong pad passphrase");
  await el("otpGenerate").click();
  await until(() => stateOf("otpNewSheet") === "done", "done");
  await el("otpNewLater").click();
  const opt = el("otpSelect").children.find((o) => o.value === madeId);
  assert.ok(opt && opt.textContent.startsWith("Mine x ("), "KG: the pad list shows the cleaned label: " + (opt && JSON.stringify(opt.textContent)));
  await lockPad(madeId, PADPASS);
  await openExport();
  assert.strictEqual(el("otpExportPadLabel").textContent, "Mine x", "I-5b: the Export card shows the cleaned label");
  await el("otpExportClose").click();
  console.log("OK  KG/I-5b: cleaned labels in the pad list and the Export card");
}

// ======== fix round 5 (otp-fix-round-1.md, "Round 5") ========
// ---- N7 / N10: an Export working when the chat comes up closes itself after ----
{
  await lockPad(madeId, PADPASS);
  await openExport();
  await set("otpXferPass", "a transfer passphrase for N7");
  const openGate = gateLock("sc.otp.export.v1." + madeId); // the export waits here, "working"
  const exporting = el("otpExport").click();
  await until(() => stateOf("otpExportSheet") === "working", "export working");
  // The chat screen comes up under it (the stub lets Connect be pressed; a
  // browser needs the save-wait window of R6-2). Connect on another pad.
  // Connect on M10's pad ("double-tap"); the export already read its own id.
  const other = otp.listPads().find((p) => p.label === "double-tap").padId;
  el("otpPass").value = "a strong enough pad passphrase";
  const conn = await (async () => {
    dom.selectAlg("OTP"); el("room").value = ROOM; await el("room").dispatch("input");
    el("otpSelect").value = other;
    const before = dom.socket();
    const c = el("connect").click();
    await until(() => dom.socket() !== before, "the socket");
    dom.socket().open();
    await dom.socket().deliver({ type: "joined", role: "owner" });
    return c;
  })();
  assert.ok(!el("scrChat").hidden && shown("otpExportSheet") && stateOf("otpExportSheet") === "working",
    "fixture: the chat is up and the Export sheet still works (never torn down mid-work)");
  openGate();
  await exporting; await conn; await settle(5);
  assert.ok(!shown("otpExportSheet") && !el("viewLive").inert,
    "N7/N10: when the Export's work ends (here: the re-export confirm), the sheet closes itself — the room screen is gone");
  assert.ok(st.textContent === "Export did not finish — open Export again after this chat." && el("hint").textContent === st.textContent,
    "R8-2/W9: an Export that did not finish says so — never 'downloaded': " + JSON.stringify(st.textContent));
  await endChat();
  console.log("OK  N7/N10: Export closes itself after its work when the chat came up");
}

// ---- N8: an Import working when the chat comes up closes itself after -------
{
  const f = await otp.generatePad({ label: "n8", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const file = await otp.exportPad(f, "agreed words n8");
  await el("otpImportOpen").click();
  await set("otpImportXfer", "agreed words n8");
  await set("otpImportPass", "my own words for n8");
  const openGate = gateLock("sc.otp.lock.v1." + f.padId); // the save waits here, "working"
  el("otpFile").files = [{ name: "n8.json", size: file.length, text: async () => file }];
  const importing = el("otpFile").dispatch("change");
  await until(() => stateOf("otpImportSheet") === "working", "import working");
  await lockPad(madeId, PADPASS);
  const { ws, connecting } = await startConnect();
  await ws.deliver({ type: "joined", role: "owner" });
  await connecting;
  assert.ok(!el("scrChat").hidden && shown("otpImportSheet"), "fixture: the chat is up, Import still working");
  openGate();
  await importing; await settle(20);
  assert.ok(otp.padMeta(f.padId), "fixture: the import completed");
  assert.ok(!shown("otpImportSheet") && !el("viewLive").inert, "N8: when the Import's work ends, the sheet closes itself");
  assert.strictEqual(st.textContent, "Pad “n8” imported. Delete the pad file now.", "R7-2: …and says it was imported, and to delete the file");
  await endChat();
  console.log("OK  N8: Import closes itself after its work when the chat came up");
}

// ---- N1: an Android file not yet shared or saved is never closed unasked ----
{
  const realConfirm = globalThis.confirm;
  let asked = 0;
  globalThis.confirm = () => { asked++; return true; };
  try {
    await lockPad(madeId, PADPASS);
    await openExport();
    await set("otpXferPass", "a transfer passphrase for N1");
    await el("otpExport").click();
    if (stateOf("otpExportSheet") === "confirm") await el("otpExport").click();
    await until(() => stateOf("otpExportSheet") === "ready", "ready");
    const other = otp.listPads().find((p) => p.label === "double-tap").padId;
    el("otpSelect").value = other; el("otpPass").value = "a strong enough pad passphrase";
    dom.selectAlg("OTP"); el("room").value = ROOM; await el("room").dispatch("input");
    const before = dom.socket();
    const c = el("connect").click();
    await until(() => dom.socket() !== before, "the socket");
    dom.socket().open();
    await dom.socket().deliver({ type: "joined", role: "owner" });
    await c; await settle(5);
    assert.ok(shown("otpExportSheet") && stateOf("otpExportSheet") === "ready" && asked === 0,
      "N1: the chat screen does not close — nor ask about — an Android file not yet shared or saved");
    await el("otpExportClose").click();
    assert.ok(asked === 1 && !shown("otpExportSheet"), "…× asks, and closes on OK");
    await endChat();
  } finally {
    globalThis.confirm = realConfirm;
  }
  console.log("OK  N1: an unshared Android file is never closed unasked");
}

// ---- N11: the Export card falls back to "pad" for an invisible-only label ----
{
  const IDX = "sc.otp.index.v1";
  const idx = JSON.parse(localStorage.getItem(IDX));
  idx.find((e) => e.padId === madeId).label = "​⁠";
  localStorage.setItem(IDX, JSON.stringify(idx));
  await lockPad(madeId, PADPASS);
  await openExport();
  assert.strictEqual(el("otpExportPadLabel").textContent, "pad", "N11: an invisible-only label shows as 'pad'");
  await el("otpExportClose").click();
  console.log("OK  N11: the card's fallback name");
}

// ======== fix round 6 (otp-fix-round-1.md, "Round 6") ========
// ---- pentest r7 R7-1: a knock revealed by an OTP sheet closing gets a fresh guard ----
{
  const realConfirm = globalThis.confirm;
  globalThis.confirm = () => true;
  try {
    await lockPad(madeId, PADPASS);
    await openExport();
    await set("otpXferPass", "a transfer passphrase for R7-1");
    await el("otpExport").click();
    if (stateOf("otpExportSheet") === "confirm") await el("otpExport").click();
    await until(() => stateOf("otpExportSheet") === "ready", "ready");
    // The chat comes up under the "ready" Android sheet (a slow `join`).
    const other = otp.listPads().find((p) => p.label === "double-tap").padId;
    el("otpSelect").value = other; el("otpPass").value = "a strong enough pad passphrase";
    dom.selectAlg("OTP"); el("room").value = ROOM; await el("room").dispatch("input");
    const before = dom.socket();
    const c = el("connect").click();
    await until(() => dom.socket() !== before, "the socket");
    const ws = dom.socket();
    ws.open();
    await ws.deliver({ type: "joined", role: "owner" });
    await c; await settle(5);
    assert.ok(shown("otpExportSheet") && el("viewLive").inert, "fixture: the unshared Export stands over the chat");
    // A knock arrives under the sheet; its own 500 ms pass while it is covered.
    const knock = Buffer.from(JSON.stringify({})).toString("base64");
    await ws.deliver({ type: "knock", room: ROOM, jid: "0123456789abcdef", payload: knock });
    await until(() => !el("admit").hidden, "the knock prompt");
    await new Promise((r) => setTimeout(r, 600));
    await el("otpExportClose").click(); // asks (unshared), OK
    assert.ok(!shown("otpExportSheet") && !el("viewLive").inert, "fixture: the sheet is gone, the prompt revealed");
    const sent0 = ws.sent.length;
    await el("admitOk").dispatch("click", { timeStamp: performance.now() }); // the second half of the tap that closed it
    assert.ok(!el("admit").hidden && !ws.sent.slice(sent0).some((f) => f.type === "admit"),
      "R7-1: a tap within 500 ms of the sheet closing does not let the knocker in");
    await el("admitOk").dispatch("click", { timeStamp: performance.now() + 600 });
    assert.ok(ws.sent.slice(sent0).some((f) => f.type === "admit"), "control: a deliberate tap after the guard admits");
    await endChat();
  } finally {
    globalThis.confirm = realConfirm;
  }
  console.log("OK  R7-1: an OTP sheet closing re-arms the knock prompt's 500 ms guard");
}

// ======== fix round 7 (otp-fix-round-1.md, "Round 7") ========
// ---- W9 / R8-2 / R8-1 / R8-3: what a self-closing Import leaves behind ------
{
  // A gate on the KDF keeps the import "working" while the chat comes up.
  const subtle = globalThis.crypto.subtle;
  const realDK = subtle.deriveKey;
  let gate = null;
  subtle.deriveKey = async function (...a) { if (gate) await gate.p; return realDK.apply(this, a); };
  const holdKdf = () => { let open; gate = { p: new Promise((r) => { open = r; }) }; return () => { gate = null; open(); }; };
  const selfClosingImport = async (file, xfer, pass) => {
    // Connect on our own pad, unlocked first (so the connect needs no KDF of its own).
    await lockPad(madeId, PADPASS);
    await openExport(); await el("otpExportClose").click();
    await settle(5);
    await el("otpImportOpen").click();
    await set("otpImportXfer", xfer);
    await set("otpImportPass", pass);
    const release = holdKdf();
    el("otpFile").files = [{ name: "r8.json", size: file.length, text: async () => file }];
    const importing = el("otpFile").dispatch("change");
    await until(() => stateOf("otpImportSheet") === "working", "import working");
    const { ws, connecting } = await startConnect();
    await ws.deliver({ type: "joined", role: "owner" });
    await connecting;
    release();
    await importing; await settle(20);
    assert.ok(!shown("otpImportSheet"), "fixture: the Import sheet closed itself");
    return [st.textContent, st.className, el("hint").textContent];
  };
  try {
    const f = await otp.generatePad({ label: "Café 🎉 \"x\"", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    const file = await otp.exportPad(f, "agreed words r8");
    // (1) a wrong transfer passphrase: the import fails while the chat is up.
    let [text, cls, hintText] = await selfClosingImport(file, "agreed wordz r8", "my own words for r8 import");
    assert.strictEqual(text, "Import did not finish — open Import again after this chat.",
      "R8-2: a self-closing Import that failed says so: " + JSON.stringify(text));
    assert.ok(!/imported|Delete the pad file/.test(text + hintText) && hintText === text && /\berr\b/.test(cls),
      "W9: …never in the success words ('imported', 'delete the file'), in the chat too, as a warning");
    assert.strictEqual(otp.padMeta(f.padId), null, "fixture: nothing was imported");
    await endChat();
    // (2) the right one, with a weak pad passphrase; the maker's label with an emoji and a quote.
    [text, cls, hintText] = await selfClosingImport(file, "agreed words r8", "password1");
    assert.strictEqual(text, "Pad “Café 🎉 \"x\"” imported. Delete the pad file now. Weak pad passphrase — accepted.",
      "R8-1/R8-3: the done line keeps the weak-passphrase line and the label as written (cleaned, not ASCII-mangled), in “…”: " + JSON.stringify(text));
    assert.ok(hintText === text && /\berr\b/.test(cls), "…in the chat too, as a warning");
    await endChat();
  } finally {
    subtle.deriveKey = realDK;
  }
  console.log("OK  W9/R8-1/R8-2/R8-3: a self-closed Import says what happened — failure, success with its weak line, the label intact");
}

// ======== fix round 8 (otp-fix-round-1.md, "Round 8") ========
// ---- M10 / M8 / Info-1: a self-closing New pad — failed, weak, and a chat error it must not hide ----
{
  const subtle = globalThis.crypto.subtle;
  const realDK = subtle.deriveKey;
  let gate = null;
  subtle.deriveKey = async function (...a) { if (gate) { const g = gate; await g.p; if (g.fail) throw new Error("the KDF failed (test)"); } return realDK.apply(this, a); };
  const selfClosingNew = async (pass, { fail = false, chatError = false } = {}) => {
    await lockPad(madeId, PADPASS);
    await openExport(); await el("otpExportClose").click(); // unlocked: the connect needs no KDF
    await settle(5);
    await el("otpNewOpen").click();
    await set("otpNewPass", pass);
    let open; gate = { p: new Promise((r) => { open = r; }), fail };
    const gen = el("otpGenerate").click();
    await until(() => stateOf("otpNewSheet") === "working", "new working");
    const { ws, connecting } = await startConnect();
    await ws.deliver({ type: "joined", role: "owner" });
    await connecting;
    if (chatError) { el("hint").textContent = "Key exchange failed: test"; el("hint").className = "hint err"; }
    const g = gate; gate = null; open(); void g;
    await gen; await settle(20);
    assert.ok(!shown("otpNewSheet"), "fixture: the New pad sheet closed itself");
    const r = { panel: st.textContent, cls: st.className, hint: el("hint").textContent, live: st.getAttribute("aria-live") };
    await endChat();
    return r;
  };
  try {
    let r = await selfClosingNew("a pad passphrase that is strong enough", { fail: true });
    assert.strictEqual(r.panel, "New pad did not finish — open New pad again after this chat.",
      "M10: a New pad that failed says so — never 'created': " + JSON.stringify(r.panel));
    assert.strictEqual(r.live, "assertive", "Info-2: the warning is announced assertively");
    r = await selfClosingNew("password1");
    assert.ok(/^Pad “.*” created — Export it to your contact after this chat\. Weak pad passphrase — accepted\.$/.test(r.panel) && /\berr\b/.test(r.cls),
      "M8: a weak pad passphrase keeps its line in the New pad notice: " + JSON.stringify(r.panel));
    r = await selfClosingNew("another strong pad passphrase words", { chatError: true });
    assert.ok(r.hint === "Key exchange failed: test" && /^Pad “.*” created/.test(r.panel),
      "Info-1: an error the chat's hint shows is not replaced; the panel still gets the notice: " + JSON.stringify(r));
  } finally {
    subtle.deriveKey = realDK;
  }
  console.log("OK  M10/M8/Info-1/Info-2: New pad self-close — failure, weak line, a chat error kept, announced");
}

console.log("\nAll OTP sheet checks passed.");

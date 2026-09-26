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

// History: pushState / back, counted; back() fires popstate like a browser.
const hist = { pushes: 0, backs: 0 };
Object.defineProperty(globalThis, "history", {
  value: {
    replaceState() {},
    pushState() { hist.pushes++; },
    back() { hist.backs++; setTimeout(popstate, 0); },
  },
  writable: true, configurable: true,
});

// Web Locks, exclusive per name: `ifAvailable` answers null while the name is
// held; otherwise the request waits for the release — or for its `signal`.
const held = new Map(); // name -> promise that resolves on release
globalThis.navigator = { ...globalThis.navigator, locks: {
  request(name, opts, fn) {
    if (typeof opts === "function") { fn = opts; opts = {}; }
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

await import("./app.js");
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
  await popstate();
  assert.ok(shown("otpNewSheet"), "N-M2: Back while working does not close…");
  assert.strictEqual(hist.pushes, p1 + 1, "…it puts the history entry back");
  await gen;
  await until(() => el("otpNewSheet").getAttribute("data-state") === "done", "New pad done");
  madeId = el("otpSelect").value;
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
  await popstate();
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
  assert.ok(shown("otpExportDoneFile") && el("otpExportDoneFile").textContent === name, "…with the file name on its own line");
  assert.ok(shown("otpExportDone") && !shown("otpShare") && el("otpSendAgain").textContent === "Didn't arrive? Send it again",
    "done: Done is the primary; the 'again' link");
  await el("otpSendAgain").click();
  assert.strictEqual(el("otpExportSheet").getAttribute("data-state"), "ready", "Send it again: back to Share / Save");
  const nBefore = calls.length;
  await el("otpShare").click();
  assert.strictEqual(calls.at(-1).text, req.text, "…with the SAME held file (no new export)");
  assert.strictEqual(calls.length, nBefore + 1);
  result("req-" + reqN, "shared");
  assert.strictEqual(el("otpExportDoneTitle").textContent, "File shared", "shared: 'File shared'");
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
  await popstate();
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
  await el("otpExportOpen").click();
  await settle(5);
  assert.ok(/^Export failed: /.test(st.textContent) && !shown("otpExportSheet"), "a wrong passphrase: said, no sheet");
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

// ---- a working Export sheet is not held forever by another tab's export ----
{
  const id = el("otpSelect").value;
  assert.strictEqual(id, madeId, "fixture: our own pad is selected (and unlocked)");
  let releaseOther;
  const other = navigator.locks.request("sc.otp.export.v1." + id, () => new Promise((r) => { releaseOther = r; }));
  const realTimeout = AbortSignal.timeout;
  let asked = null;
  AbortSignal.timeout = (ms) => { asked = ms; return realTimeout.call(AbortSignal, 50); }; // the bound, compressed
  try {
    await el("otpExportOpen").click();
    assert.ok(shown("otpExportSheet"), "fixture: the Export sheet is open");
    await set("otpXferPass", "words for a stuck export");
    const exporting = el("otpExport").click();
    const outcome = await Promise.race([exporting.then(() => "settled"), new Promise((r) => setTimeout(() => r("hung"), 4000))]);
    assert.strictEqual(outcome, "settled", "the wait for another tab's export lock ends");
    assert.strictEqual(asked, 30000, "…bounded at 30 s");
    assert.strictEqual(el("otpExportStatus").textContent,
      "Export failed: another tab or window is still exporting this pad — finish or close it there, then try again",
      "…and says why");
    assert.ok(el("otpExportSheet").getAttribute("data-state") === "form" && shown("otpExportClose"), "…the sheet is closable again");
  } finally {
    AbortSignal.timeout = realTimeout;
    releaseOther();
    await other;
  }
  await el("otpExportClose").click();
  await settle(5);
  console.log("OK  a working Export sheet waits at most 30 s for another tab's export lock, then says why");
}

console.log("\nAll OTP sheet checks passed.");

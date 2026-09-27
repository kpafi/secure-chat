// The page side of the Android file bridge (otp-transfer-brief.md § 9a):
// app.js accepts `window.__SECURE_CHAT_FILES__` ONLY as the shell publishes
// it — a frozen object on a non-writable, non-configurable data property —
// and treats anything else as "no bridge" (the browser path). Fix round 1
// (hot m6, cold M4, pentest J18): the suites only ever installed a correct
// bridge, so dropping either half of that check left them green.
//
// app.js is a module (evaluated once per process), so each shape runs in a
// child process of this file; the parent asserts what each child saw. The
// observable: the Export sheet's "again" link, which app.js words for the
// Android path ("Didn't arrive? …") or for the browser ("Download …").
// Run: node app-otp-bridge.test.mjs
import assert from "node:assert";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const SELF = fileURLToPath(import.meta.url);
const variant = process.argv[2];

if (!variant) {
  const expect = {
    frozen: "android",        // control: the shell's shape
    writable: "browser",      // a writable property: page script could swap it
    configurable: "browser",  // a configurable property: could be redefined
    unfrozen: "browser",      // methods could be replaced on the object
    accessor: "browser",      // a getter: could answer differently each time
    assigned: "browser",      // a plain global, as any page script can make
  };
  for (const [v, want] of Object.entries(expect)) {
    const r = spawnSync(process.execPath, [SELF, v], { cwd: HERE, encoding: "utf8", timeout: 120000 });
    const line = (r.stdout || "").split("\n").find((l) => l.startsWith("PATH ")) || "";
    assert.ok(line, `bridge shape "${v}": the child reported nothing (exit ${r.status}): ${(r.stderr || "").slice(-400)}`);
    assert.strictEqual(line.slice(5), want, `bridge shape "${v}": app.js took the ${line.slice(5)} path, expected ${want}`);
    console.log(`OK  bridge shape ${v}: ${want} path`);
  }
  console.log("\nAll bridge-shape checks passed.");
} else {
  await child(variant);
}

async function child(v) {
  await import("./fake-idb.test.mjs");
  const { installDom, El } = await import("./dom-stub.test.mjs");
  const store = new Map();
  globalThis.localStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, val) => { store.set(k, String(val)); },
    removeItem: (k) => { store.delete(k); },
    key: (i) => [...store.keys()][i] ?? null,
    get length() { return store.size; },
    clear: () => store.clear(),
  };
  globalThis.setInterval = () => 0;
  globalThis.clearInterval = () => {};
  globalThis.fetch = async () => new Response("{}", { status: 404 });
  const dom = installDom(join(HERE, "index.html"));
  dom.body.appendChild(dom.el("tabbar"));
  dom.seedAlgRadios(["DHKE", "AES256", "PQKEM", "OTP"], "OTP");
  dom.seedNavItems(["live", "chats", "users", "profile"]);
  dom.seedChild("scrChat", "div", "topbar");
  for (const id of ["usersLocked", "chatsLocked"]) dom.seedChild(id, "p", "hint");
  { const row = new El("div"); row.className = "row"; row.appendChild(dom.el("username")); }
  globalThis.navigator = { ...globalThis.navigator, locks: {
    request(name, opts, fn) { if (typeof opts === "function") fn = opts; return Promise.resolve(fn({ name })); },
  } };

  const methods = { share: () => "0000000000000001", save: () => "0000000000000002" };
  const frozen = Object.freeze({ ...methods });
  const K = "__SECURE_CHAT_FILES__";
  if (v === "frozen") Object.defineProperty(globalThis, K, { value: frozen, writable: false, configurable: false });
  else if (v === "writable") Object.defineProperty(globalThis, K, { value: frozen, writable: true, configurable: false });
  else if (v === "configurable") Object.defineProperty(globalThis, K, { value: frozen, writable: false, configurable: true });
  else if (v === "unfrozen") Object.defineProperty(globalThis, K, { value: { ...methods }, writable: false, configurable: false });
  else if (v === "accessor") Object.defineProperty(globalThis, K, { get: () => frozen, configurable: false });
  else if (v === "assigned") globalThis[K] = frozen;
  else throw new Error("unknown variant " + v);

  await import("./app.js");
  const otp = await import("./otp.js");
  const PASS = "a pad passphrase for the shape test";
  const pad = await otp.generatePad({ label: "shape", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  await otp.saveNewPad(pad, PASS);
  await dom.el("algCards").dispatch("change");
  // The select is filled at load; this pad came later, so refill it the way
  // the page does after a save (a change event re-renders the panel).
  const sel = dom.el("otpSelect");
  const o = new El("option"); o.value = pad.padId; sel.appendChild(o);
  sel.value = pad.padId;
  await sel.dispatch("change");
  dom.el("otpPass").value = PASS;
  await dom.el("otpExportOpen").click();
  if (dom.el("otpExportSheet").hidden) throw new Error("the Export sheet did not open: " + dom.el("otpStatus").textContent);
  const again = dom.el("otpSendAgain").textContent;
  console.log("PATH " + (/^Didn't arrive/.test(again) ? "android" : /^Download/.test(again) ? "browser" : "? " + again));
  process.exit(0);
}

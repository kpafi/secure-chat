// F-PROTO-001 regression test — two real browsers against a hostile relay.
//
//   POLICY=honest node e2e/hostile-relay/hostile.mjs &
//   SCENARIO=control node e2e/hostile-relay/proto001.mjs      # positive control
//
//   POLICY=demote node e2e/hostile-relay/hostile.mjs &
//   node e2e/hostile-relay/proto001.mjs                       # both peers shipped
//   SCENARIO=attacker node e2e/hostile-relay/proto001.mjs     # peer runs /evil/
//
// The relay puts both parties in the room as guests, so neither client is ever
// asked to approve anybody — the configuration the finding is about. The
// property under test is the one the rebuilt control actually provides:
//
//   a handshake from an identity no human on THIS device approved never
//   establishes a channel, whatever the relay says and whatever the peer's
//   client does.
//
// Two scenarios, because the interesting endpoint differs:
//
//   shipped  — both peers run the shipped client. The peer that ANSWERS the
//              hello sends the first handshake; its receiver is the one that
//              must prompt. (The sender then stalls at hello with an open
//              socket, which is not a second stopping point — it is this one
//              seen from the other end.)
//   attacker — the peer runs a client patched not to ask its own user
//              (EVIL_MODE=autoapprove), so it answers with a handshake of its
//              own. That puts the SHIPPED client in the receiving seat. This is
//              the direct regression for the 2026-08-07 admission proof, which
//              the attacker defeated by signing one for its victim: the victim
//              proceeded to the safety-number screen with nobody having
//              approved anything.
//
// Exit code is non-zero if any check fails.
import puppeteer from "../node_modules/puppeteer-core/lib/puppeteer/puppeteer-core.js";

const APP = process.env.APP || "http://127.0.0.1:8099";
const SCENARIO = process.env.SCENARIO || "shipped";
const PASS = "correct horse battery staple 42";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok });
  console.log(`  ${ok ? "OK  " : "FAIL"} ${name}${detail ? " — " + detail : ""}`);
}

const browser = await puppeteer.launch({
  executablePath: process.env.CHROMIUM || "/usr/bin/chromium",
  headless: "new",
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});

async function agent(label, path = "/") {
  const ctx = await browser.createBrowserContext();
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("console", (m) => {
    const t = m.text();
    if (m.type() === "error" && !/favicon|404/.test(t)) errors.push(t);
  });
  // Wrap the constructor before any app code runs, so the frame log is the
  // client's own view of the socket rather than the relay's account of it. The
  // old harness logged only join/knock, which is why "no key frames in the log"
  // was read as "the client never sent one".
  await page.evaluateOnNewDocument(() => {
    window.__wsLog = [];
    const Real = window.WebSocket;
    const t0 = Date.now();
    function Wrapped(url, protocols) {
      const s = protocols === undefined ? new Real(url) : new Real(url, protocols);
      window.__ws = s;
      const rec = (dir, data) => {
        let type = "?", kind = "";
        try {
          const m = JSON.parse(data);
          type = m.type;
          if (typeof m.payload === "string") {
            const p = JSON.parse(atob(m.payload));
            kind = p.hello ? (p.reply ? "hello-reply" : "hello")
              : p.pub ? "handshake"
              : p.confirm ? "confirm" : p.idb ? "knock-intro" : Object.keys(p).join("+");
          }
        } catch { /* not packed */ }
        window.__wsLog.push({ t: Date.now() - t0, dir, type, kind });
      };
      const send = s.send.bind(s);
      s.send = (d) => { rec("send", d); return send(d); };
      s.addEventListener("message", (e) => rec("recv", e.data));
      s.addEventListener("close", () => window.__wsLog.push({ t: Date.now() - t0, dir: "close", type: "-", kind: "" }));
      return s;
    }
    Wrapped.prototype = Real.prototype;
    for (const k of ["CONNECTING", "OPEN", "CLOSING", "CLOSED"]) Wrapped[k] = Real[k];
    window.WebSocket = Wrapped;
  });
  await page.goto(APP + path, { waitUntil: "networkidle0" });
  await page.type("#idPass", PASS);
  await page.click("#idCreate");
  await page.waitForFunction(() => !document.querySelector("#idExport").hidden, { timeout: 60000 });
  const fingerprint = await page.evaluate(() =>
    document.querySelector("#idFingerprint").textContent.replace(/^[^:]*:\s*/, "").trim());
  await page.click("#toRoom");
  await page.waitForFunction(() => !document.querySelector("#scrRoom").hidden, { timeout: 20000 });
  return { label, page, fingerprint, errors };
}

const snap = (a) => a.page.evaluate(() => {
  const t = (s) => { const el = document.querySelector(s); return el ? el.textContent.trim() : ""; };
  const vis = (s) => { const el = document.querySelector(s); return !!el && !el.hidden; };
  return {
    chatStatus: t("#chatStatus"),
    hint: t("#hint"),
    log: [...document.querySelectorAll("#log li")].map((li) => li.textContent.trim()),
    promptShown: vis("#admit"),
    // Item 20: WHICH prompt. `#admit` is shared by the owner's knock prompt and
    // the guest's peer-approval prompt, so `promptShown` alone cannot tell them
    // apart — and the check below used to go green against the owner's knock.
    // `promptMode` is app.js's own marker; `promptOk` is the button label the
    // human actually reads. Both are asserted, so a marker that drifts away from
    // the visible label fails instead of quietly passing.
    promptMode: (() => {
      const el = document.querySelector("#admit");
      return el && !el.hidden ? (el.dataset.mode || "") : "";
    })(),
    promptOk: t("#admitOk"),
    promptTitle: t("#admitTitle"),
    promptFingerprint: t("#admitFingerprint"),
    promptWho: t("#admitWho"),
    promptWarn: t("#admitWarn"),
    verifyShown: vis("#verify"),
    safetyNumber: t("#safetyNumber"),
    canSend: !document.querySelector("#text").disabled,
    readyState: window.__ws ? window.__ws.readyState : "none",
    frames: window.__wsLog,
  };
});

function dump(label, s) {
  console.log(`\n  ── ${label}: status=${JSON.stringify(s.chatStatus)} readyState=${s.readyState} ` +
    `prompt=${s.promptShown} verify=${s.verifyShown} canSend=${s.canSend}`);
  for (const l of s.log) console.log("     log: " + JSON.stringify(l));
  for (const f of s.frames) console.log(`     ${String(f.t).padStart(6)}ms ${f.dir.padEnd(4)} ${String(f.type).padEnd(7)} ${f.kind}`);
}

// What the relay actually served under /evil/. `none` means the shipped client
// was served unpatched, i.e. nothing is attacking in this run.
async function peerEvilMode() {
  return peer.page.evaluate(() => globalThis.__HARNESS_EVIL_MODE__ || "patched");
}

console.log(`\n=== F-PROTO-001: hostile relay, scenario=${SCENARIO} (${APP}) ===\n`);

// alice always runs the shipped client. In `attacker` she is the victim; in
// `shipped` she is the one that answers the hello and sends the first handshake.
const alice = await agent("alice", "/");
// `directory` uses the attacker client too: the victim is the side that TYPED a
// handle, and she only reaches her own decision once the other side stops
// waiting on its prompt. An honest peer would park on its own approval prompt
// and the victim's decision — the thing under test — would never be reached.
const peer = await agent("peer",
  SCENARIO === "attacker" || SCENARIO === "directory" ? "/evil/" : "/");

// Item 8, second half: `EVIL_MODE=none SCENARIO=attacker` used to serve the
// SHIPPED client under /evil/ and report a clean 9/9. Nothing attacked in that
// run, so the pass was worthless — and it is an easy invocation to mistype. The
// relay now stamps a marker into the bytes it serves; refuse to continue.
if (SCENARIO === "attacker") {
  const mode = await peerEvilMode();
  if (mode === "none") {
    console.log(
      "\n  !! SCENARIO=attacker but the relay is running EVIL_MODE=none, so /evil/\n" +
      "     served the UNPATCHED shipped client. There is no attacker in this run\n" +
      "     and a pass would prove nothing. Restart the relay without EVIL_MODE=none\n" +
      "     (the default is EVIL_MODE=autoapprove), or run SCENARIO=control.\n");
    process.exit(2);
  }
}

// --- SCENARIO=directory (pentest item 8 / item 14) --------------------------
// The gap this closes: this harness served no /api/* routes and nothing ever
// typed a handle, so `expectedPeerBundle` was null in every run and the whole
// directory-driven flow item 14 is ABOUT was invisible end to end.
//
// The attack, end to end: the victim asks for the handle of the person they mean
// to talk to. The directory is the attacker's, so it answers with the keys of
// whoever is actually going to connect. The bundle the victim was handed and the
// bundle that shows up therefore MATCH — which is exactly the condition item 14's
// deleted route used to treat as "no need to ask". The client must still ask.
if (SCENARIO === "directory") {
  // The peer registers under a name the victim is NOT looking for, so the
  // hostile directory has somebody else's keys to answer with.
  await peer.page.click("#toIdentity");
  await peer.page.waitForFunction(() => !document.querySelector("#scrIdentity").hidden, { timeout: 20000 });
  await peer.page.type("#username", "mallory");
  await peer.page.click("#register");
  await peer.page.waitForFunction(
    () => /registered|already/i.test(document.querySelector("#accountStatus").textContent),
    { timeout: 20000 });
  await peer.page.click("#toRoom");
  await peer.page.waitForFunction(() => !document.querySelector("#scrRoom").hidden, { timeout: 20000 });

  // The victim looks up "bob" — a handle the directory has never seen. Under
  // DIRECTORY=hostile it answers with mallory's bundle anyway.
  await alice.page.type("#contact", "bob#harnesstoken");
  console.log("  setup: peer registered as \"mallory\"; alice will look up \"bob#harnesstoken\"\n");
}

const code = await alice.page.evaluate(() => document.querySelector("#room").value.trim());
await alice.page.click("#connect");
await sleep(1500);
await peer.page.evaluate(() => { document.querySelector("#room").value = ""; });
await peer.page.type("#room", code);
await peer.page.click("#connect");
await sleep(10000);

// The positive control runs against POLICY=honest and asserts the harness can
// complete an ORDINARY session: owner approves the knock, guest approves the
// key, both reach the safety number. Without it, a bug in hostile.mjs that
// stalls the session reads as "the attack was blocked".
if (SCENARIO === "control") {
  // Item 20: wait for the RIGHT prompt on each side and assert which one it was,
  // rather than "#admit is un-hidden" plus an unconditional `check(..., true)`.
  // The owner gets the knock prompt, the guest gets the peer-approval prompt;
  // asserting only visibility could not tell them apart and the `true` literal
  // asserted nothing at all.
  const waitForMode = (page, mode) => page.waitForFunction(
    (m) => {
      const el = document.querySelector("#admit");
      return !!el && !el.hidden && el.dataset.mode === m;
    }, { timeout: 45000 }, mode);

  await waitForMode(alice.page, "knock");
  const knockSnap = await snap(alice);
  check("owner is asked to approve the knock",
    knockSnap.promptMode === "knock" && knockSnap.promptOk === "Let them in",
    `mode=${knockSnap.promptMode} ok=${JSON.stringify(knockSnap.promptOk)}`);
  await alice.page.click("#admitOk");

  await waitForMode(peer.page, "peer");
  const peerSnap = await snap(peer);
  check("guest is asked to approve the owner's key",
    peerSnap.promptMode === "peer" && peerSnap.promptOk === "Connect",
    `mode=${peerSnap.promptMode} ok=${JSON.stringify(peerSnap.promptOk)}`);
  await peer.page.click("#admitOk");
  for (const a of [alice, peer]) {
    await a.page.waitForFunction(() => !document.querySelector("#verify").hidden, { timeout: 45000 })
      .catch(() => { /* asserted below */ });
  }
  const [cA, cP] = [await snap(alice), await snap(peer)];
  check("both peers reach the safety-number gate", cA.verifyShown && cP.verifyShown,
    `verify=${cA.verifyShown}/${cP.verifyShown}`);
  check("both compute the SAME safety number",
    !!cA.safetyNumber && cA.safetyNumber === cP.safetyNumber, cA.safetyNumber.slice(0, 24) + "…");
  dump(alice.label, cA);
  dump(peer.label, cP);
  const ctlErrors = [...alice.errors, ...peer.errors];
  check("no page errors", ctlErrors.length === 0, ctlErrors.join(" | "));
  const ctlFailed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - ctlFailed.length}/${results.length} checks passed`);
  if (ctlFailed.length) process.exitCode = 1;
  await browser.close();
  process.exit();
}

let snapA = await snap(alice);
let snapP = await snap(peer);

// Whoever was handed a handshake is the endpoint whose control is under test.
//
// Item 20: selected on the PEER-APPROVAL prompt specifically, not on "#admit is
// visible". The owner's knock prompt uses the same panel, so the old heuristic
// picked the owner whenever their knock prompt happened to be open — and then
// asserted the control had fired, against a prompt that has nothing to do with
// it. Under POLICY=honest that is a green run of a test that checked nothing.
const isPeerPrompt = (s) => s.promptShown && s.promptMode === "peer";
const victim = isPeerPrompt(snapA) ? { a: alice, s: snapA, other: peer, os: snapP }
  : { a: peer, s: snapP, other: alice, os: snapA };

// Item 20: the failure this file is most likely to produce is an INVOCATION
// error, not a regression — and it used to be indistinguishable from one. If
// neither side has a peer-approval prompt but one has a knock prompt, the relay
// routed an ordinary session, which is what POLICY=honest does. Say so, loudly,
// before the failures scroll past.
if (!isPeerPrompt(snapA) && !isPeerPrompt(snapP) &&
    (snapA.promptMode === "knock" || snapP.promptMode === "knock")) {
  console.log(
    "\n  !! An owner's KNOCK prompt is open and neither side has a peer-approval\n" +
    "     prompt. That is an ORDINARY session, which means the relay is almost\n" +
    "     certainly POLICY=honest. The failures below are how this scenario\n" +
    "     reports a wrong invocation, not evidence that the fix is broken.\n" +
    "     For the positive control run:  SCENARIO=control node e2e/hostile-relay/proto001.mjs\n" +
    "     For the attack, restart the relay with POLICY=demote (it is read at startup).\n");
}

check("nobody was asked to approve anyone by the relay (the attack ran)",
  !snapA.log.some((l) => /you let someone in/.test(l)) &&
  !snapP.log.some((l) => /you let someone in/.test(l)));
check("the peer that received a handshake ASKS its user before proceeding",
  isPeerPrompt(victim.s),
  isPeerPrompt(victim.s)
    ? `${victim.a.label} (mode=${victim.s.promptMode})`
    : `no PEER-approval prompt on either side (alice=${snapA.promptMode || "none"}, ` +
      `peer=${snapP.promptMode || "none"})`);
// The marker must agree with what the user is shown, or the check above is
// asserting on a label nobody reads.
check("...and it is the peer-approval prompt the user actually sees",
  victim.s.promptOk === "Connect", JSON.stringify(victim.s.promptOk));
check("the prompt names it as an unapproved connection",
  /is it them\?|already in this chat/i.test(victim.s.promptTitle),
  JSON.stringify(victim.s.promptTitle));
check("the prompt shows the peer's REAL fingerprint",
  victim.s.promptFingerprint === victim.other.fingerprint,
  `${victim.s.promptFingerprint.slice(0, 20)}… vs ${victim.other.fingerprint.slice(0, 20)}…`);
check("no safety number and no messaging on either side while it is unanswered",
  !snapA.verifyShown && !snapP.verifyShown && !snapA.canSend && !snapP.canSend,
  `verify=${snapA.verifyShown}/${snapP.verifyShown} send=${snapA.canSend}/${snapP.canSend}`);

// --- item 14, end to end ----------------------------------------------------
if (SCENARIO === "directory") {
  // Vacuity guard FIRST. If the lookup had failed, alice would have refused to
  // connect at all and every check above would be measuring an empty session —
  // a green that proves nothing, which is the failure mode this whole scenario
  // exists to stop repeating.
  check("the victim's directory lookup was answered (the scenario is not vacuous)",
    !snapA.log.some((l) => /No one found for the handle/i.test(l)) &&
    snapA.frames.length > 0,
    `alice frames=${snapA.frames.length}`);

  // THE FINDING. The bundle the directory handed alice and the bundle that
  // connected are the same — the exact condition item 14's deleted route read as
  // "no need to ask". The prompt must appear anyway, on the victim's side.
  check("item 14: a MATCHING hostile-directory answer does NOT skip the prompt",
    isPeerPrompt(snapA),
    `alice prompt mode=${snapA.promptMode || "none"} — the directory named "bob" and handed ` +
    "over the keys of the peer that connected; pre-fix this skipped the human");
  check("item 14: and the client does not print a directory-sourced reassurance",
    !snapA.log.some((l) => /matches the directory key/i.test(l)),
    snapA.log.filter((l) => /directory/i.test(l)).join(" | ") || "(no directory line)");
  // The bundles match, so there is nothing to warn about — the point is that a
  // MATCH is not a reason to skip. A ⚠ here would mean the harness failed to
  // make the directory lie in the way this scenario intends.
  check("item 14: the prompt shows no mismatch warning (the lie was consistent)",
    !/NOT the user you selected/i.test(snapA.promptWarn),
    JSON.stringify(snapA.promptWarn));
}

// Refusing must end it, not merely postpone it.
//
// Item 20: gated on the PEER prompt, and a missing one FAILS rather than
// silently skipping two checks. The old `if (promptShown)` had both problems —
// it would have clicked "Deny" on an owner's knock prompt and called that a
// refusal of the peer, and when no prompt appeared at all the two checks below
// simply vanished from the run while the summary still read "all passed".
if (isPeerPrompt(victim.s)) {
  await victim.a.page.click("#admitNo");
  await sleep(1500);
  const after = await snap(victim.a);
  check("refusing disconnects and says so",
    after.readyState === 3 && after.log.some((l) => /you refused this peer/i.test(l)),
    `readyState=${after.readyState}`);
  check("nothing was established after a refusal",
    !after.verifyShown && !after.canSend && !after.safetyNumber);
  victim.s = after;
} else {
  check("refusing disconnects and says so", false,
    "NOT RUN — no peer-approval prompt appeared, so there was nothing to refuse");
  check("nothing was established after a refusal", false,
    "NOT RUN — no peer-approval prompt appeared");
}

dump(alice.label, snapA);
dump(peer.label, snapP);

const pageErrors = [...alice.errors, ...peer.errors];
check("no page errors", pageErrors.length === 0, pageErrors.join(" | "));

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) process.exitCode = 1;

await browser.close();

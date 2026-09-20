// Run every hostile-relay scenario end to end, unattended — PROGRESS item 7a,
// second half.
//
// `hostile.mjs` serves the real client AND speaks the relay protocol itself,
// so these scenarios need no backend and no database: one command runs them
// all. That matters because they are the ONLY control that catches several
// things the unit suite structurally cannot — the Phase-7 report's F-P7-A2
// showed two mutants that reintroduced the deleted item-14 directory route
// with `npm test` fully green, caught only by `SCENARIO=directory` — and until
// now every one of them had to be started by hand, in the right order, with
// the right environment, which is the same as not being run.
//
//   node e2e/hostile-relay/run-scenarios.mjs        # all four, exits non-zero on failure
//   ONLY=directory node e2e/hostile-relay/run-scenarios.mjs
//
// Needs system Chromium and puppeteer-core in e2e/ (see e2e/README.md). Each
// scenario gets its own relay on PORT (default 8099), started and stopped here.
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8099);
const ONLY = process.env.ONLY || null;

// Each scenario is the pair (relay policy, driver scenario) the README
// documents, with what it proves.
const SCENARIOS = [
  { name: "control", env: { POLICY: "honest" }, scenario: "control", expect: 5,
    why: "a normal session must complete, or nothing below counts" },
  { name: "demote", env: { POLICY: "demote" }, scenario: "shipped", expect: 9,
    why: "F-PROTO-001: both parties told they are guests, so nobody is ever asked" },
  { name: "attacker", env: { POLICY: "demote" }, scenario: "attacker", expect: 9,
    why: "...and the same against a peer running a patched client" },
  { name: "directory", env: { POLICY: "demote", DIRECTORY: "hostile" }, scenario: "directory", expect: 13,
    why: "item 14: the DIRECTORY lies about who owns a handle" },
];

function startRelay(env) {
  const child = spawn(process.execPath, [join(HERE, "hostile.mjs")], {
    env: { ...process.env, PORT: String(PORT), ...env },
    stdio: ["ignore", "pipe", "inherit"],
  });
  return new Promise((resolve, reject) => {
    // Review of 4b9d2c6..a88baa4 (L-2): a relay that never printed its banner
    // was rejected but never killed — it kept PORT, every later scenario
    // failed with EADDRINUSE, and a stray process outlived the run.
    const timer = setTimeout(() => { child.kill(); reject(new Error("the hostile relay did not start in 15s")); }, 15000);
    child.stdout.on("data", (d) => {
      if (/listening|hostile relay|http:\/\/127/i.test(String(d))) { clearTimeout(timer); resolve(child); }
    });
    child.on("exit", (code) => { clearTimeout(timer); reject(new Error(`the hostile relay exited early (${code})`)); });
  });
}

function drive(scenario) {
  return new Promise((resolve) => {
    let out = "";
    const child = spawn(process.execPath, [join(HERE, "proto001.mjs")], {
      env: { ...process.env, APP: `http://127.0.0.1:${PORT}`, SCENARIO: scenario },
      stdio: ["ignore", "pipe", "inherit"],
    });
    child.stdout.on("data", (d) => { out += String(d); process.stdout.write(d); });
    child.on("exit", (code) => resolve({ code, out }));
  });
}

// Review of 4b9d2c6..a88baa4 (L-1): `ONLY=nope` used to skip every scenario
// and print the success banner — the "passed with zero checks" shape this
// file exists to prevent, one level up.
if (ONLY && !SCENARIOS.some((s) => s.name === ONLY)) {
  console.log(`no such scenario "${ONLY}" — one of: ${SCENARIOS.map((s) => s.name).join(", ")}`);
  process.exit(2);
}
let failed = 0;
let ran = 0;
for (const s of SCENARIOS) {
  if (ONLY && ONLY !== s.name) continue;
  ran++;
  console.log(`\n=== ${s.name}: ${s.why}`);
  let relay;
  try {
    relay = await startRelay(s.env);
  } catch (e) {
    console.log(`  FAIL ${s.name}: ${e.message}`);
    failed++;
    continue;
  }
  try {
    const { code, out } = await drive(s.scenario);
    const m = /(\d+)\/(\d+) checks passed/.exec(out);
    if (code !== 0 || !m) {
      console.log(`  FAIL ${s.name}: driver exited ${code}`);
      failed++;
    } else if (Number(m[2]) !== s.expect) {
      // A scenario that silently stops asserting is the failure mode this
      // project has hit repeatedly: pin the COUNT, not just the exit code.
      console.log(`  FAIL ${s.name}: expected ${s.expect} checks, the run made ${m[2]} — update this file deliberately`);
      failed++;
    } else if (m[1] !== m[2]) {
      console.log(`  FAIL ${s.name}: ${m[1]}/${m[2]}`);
      failed++;
    } else {
      console.log(`  ok   ${s.name}: ${m[0]}`);
    }
  } finally {
    relay.kill();
    await new Promise((r) => setTimeout(r, 300));
  }
}
if (ran === 0) { console.log("\nno scenario ran"); process.exit(2); }
console.log(failed ? `\n${failed} scenario(s) FAILED` : `\nall ${ran} hostile-relay scenario(s) passed`);
process.exit(failed ? 1 : 0);

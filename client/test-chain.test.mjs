// Every runnable client test is in the `npm test` chain — review of
// 4b9d2c6..a88baa4, Info-4; tightened by the review of d98f220 (L-3).
//
// The chain in package.json is a hand-written `&&` list. A new test file that
// is not appended to it is a test that is never run — the same "silently
// stops asserting" shape the scenario runner pins with its check COUNT. Two
// kinds of file are legitimately absent and are named here BY FILE, with the
// reason, so that a new one has to be listed deliberately: the first cut
// exempted anything matching an integration PATTERN, which let a file named
// `*.integration.test.mjs` hide, and scanned one directory with one extension,
// which let `sub/x.test.mjs` and `x.test.js` hide.
import assert from "node:assert";
import { readdirSync, readFileSync, existsSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, relative } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(HERE, "package.json"), "utf8"));

// Libraries: imported by other tests, no assertions of their own at module scope.
const LIBRARIES = new Set(["dom-stub.test.mjs", "identity-store-helpers.test.mjs"]);
// Need a running relay on :8000 (see each file's header); run by hand.
const INTEGRATION = new Set(["accounts.integration.test.mjs", "auth.integration.test.mjs", "integration.test.mjs"]);
// Not test trees.
const SKIP_DIRS = new Set(["node_modules", "vendor", ".git"]);

function scan(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) { if (!SKIP_DIRS.has(name)) scan(p, out); continue; }
    if (/\.test\.m?js$/.test(name)) out.push(relative(HERE, p));
  }
  return out.sort();
}

const chained = pkg.scripts.test.split("&&").map((c) => c.trim()).map((c) => {
  const m = /^node ([\w.-]+\.test\.mjs)$/.exec(c);
  assert.ok(m, `the test chain is a plain list of \`node <file>.test.mjs\` commands, got: ${c}`);
  return m[1];
});
for (const f of chained) assert.ok(existsSync(join(HERE, f)), `the chain names a file that exists: ${f}`);

const onDisk = scan(HERE);
const runnable = onDisk.filter((f) => !LIBRARIES.has(f) && !INTEGRATION.has(f));
const missing = runnable.filter((f) => !chained.includes(f));
assert.deepStrictEqual(missing, [],
  `every test file under client/ is in the npm test chain — add these to package.json (or to LIBRARIES / INTEGRATION here, with a reason): ${missing.join(", ")}`);
for (const f of [...LIBRARIES, ...INTEGRATION]) assert.ok(onDisk.includes(f), `a listed exemption still exists: ${f}`);
assert.ok(runnable.length >= 23, `fixture: ${runnable.length} runnable tests found — the scan clearly saw the suite`);
console.log(`OK  every client test file is in the npm test chain (${chained.length} chained, ${LIBRARIES.size} libraries, ${INTEGRATION.size} integration, named)`);

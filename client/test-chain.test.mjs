// Every runnable client test is in the `npm test` chain — review of
// 4b9d2c6..a88baa4, Info-4.
//
// The chain in package.json is a hand-written `&&` list. A new *.test.mjs that
// is not appended to it is a test that is never run — the same "silently
// stops asserting" shape the scenario runner pins with its check COUNT. Two
// kinds of file are legitimately absent and are named here, with the reason,
// so that a new one has to be listed deliberately.
import assert from "node:assert";
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(HERE, "package.json"), "utf8"));

// Libraries: imported by other tests, no assertions of their own at module scope.
const LIBRARIES = new Set(["dom-stub.test.mjs", "identity-store-helpers.test.mjs"]);
// Need a running server (see each file's header); run by hand or by e2e.
const isIntegration = (f) => /(^|\.)integration\.test\.mjs$/.test(f);

const chained = pkg.scripts.test.split("&&").map((c) => c.trim()).map((c) => {
  const m = /^node ([\w.-]+\.test\.mjs)$/.exec(c);
  assert.ok(m, `the test chain is a plain list of \`node <file>.test.mjs\` commands, got: ${c}`);
  return m[1];
});
for (const f of chained) assert.ok(existsSync(join(HERE, f)), `the chain names a file that exists: ${f}`);

const onDisk = readdirSync(HERE).filter((f) => /\.test\.mjs$/.test(f)).sort();
const runnable = onDisk.filter((f) => !LIBRARIES.has(f) && !isIntegration(f));
const missing = runnable.filter((f) => !chained.includes(f));
assert.deepStrictEqual(missing, [],
  `every runnable *.test.mjs is in the npm test chain — add these to package.json (or to LIBRARIES here, with a reason): ${missing.join(", ")}`);
for (const f of LIBRARIES) assert.ok(onDisk.includes(f), `a listed library still exists: ${f}`);
assert.ok(runnable.length >= 22, `fixture: ${runnable.length} runnable tests found — the scan clearly saw the suite`);
console.log(`OK  every runnable client test is in the npm test chain (${chained.length} chained, ${LIBRARIES.size} libraries, ${onDisk.filter(isIntegration).length} integration)`);

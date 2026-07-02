// Integration test for the client account directory protocol (account.js)
// against the real backend. Proves the client builds the registration proof
// and login signature in exactly the form the server verifies, and that
// look-up-by-username returns the bundle a contact would pin.
//
// Requires the server running:  cd backend && ./run.sh
// Run:                          node client/accounts.integration.test.mjs
import assert from "node:assert";
import { Identity } from "./identity.js";
import * as account from "./account.js";

const BASE = "http://127.0.0.1:8000";

function uniqueName(prefix) {
  // valid charset [a-z0-9_.-], 3..32 chars; keep it unique per run.
  const rnd = Math.random().toString(36).slice(2, 8);
  return `${prefix}.${rnd}`;
}

async function testRegisterLookupLogin() {
  const id = await Identity.generate();
  const username = uniqueName("alice");

  const reg = await account.register(BASE, id, username);
  assert.strictEqual(reg.username, username, "register echoes the username");
  assert.ok(reg.lookup_token, "register returns a lookup token");
  const handle = `${username}#${reg.lookup_token}`;

  // Directory returns exactly the bundle a contact would pin (via the handle).
  const fetched = await account.fetchBundle(BASE, handle);
  assert.strictEqual(fetched.ed, id.publicBundle().ed, "fetched ed key matches");
  assert.strictEqual(fetched.mldsa, id.publicBundle().mldsa, "fetched mldsa key matches");

  // Anti-enumeration (I1): the right username with the WRONG token -> null,
  // and an unknown username -> null. The two are indistinguishable.
  assert.strictEqual(await account.fetchBundle(BASE, `${username}#wrongtoken`), null, "wrong token -> null");
  assert.strictEqual(await account.fetchBundle(BASE, `${uniqueName("ghost")}#faketoken`), null, "missing user -> null");

  // Login (challenge-signature) yields a usable bearer token.
  const { token, ttl } = await account.login(BASE, id, username);
  assert.ok(token && ttl > 0, "login returns a token + ttl");
  assert.strictEqual(await account.me(BASE, token), username, "token resolves to the username");

  console.log("OK  register -> lookup -> login -> me round-trip");
}

async function testDuplicateRejected() {
  const id = await Identity.generate();
  const username = uniqueName("bob");
  await account.register(BASE, id, username);

  // Same name, different identity -> 409 conflict.
  const other = await Identity.generate();
  await assert.rejects(
    () => account.register(BASE, other, username),
    (e) => e.status === 409,
    "duplicate username rejected with 409",
  );
  console.log("OK  duplicate username rejected (409)");
}

async function testWrongKeyLoginRejected() {
  const id = await Identity.generate();
  const username = uniqueName("carol");
  await account.register(BASE, id, username);

  // An impostor who knows the username but not the private key cannot log in:
  // sign the challenge with a DIFFERENT identity -> verify must fail.
  const impostor = await Identity.generate();
  await assert.rejects(
    async () => {
      const c = await fetch(BASE + "/api/auth/challenge", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username }),
      });
      const { challenge } = await c.json();
      const { unb64 } = await import("./identity.js");
      const sig = await impostor.signEd(unb64(challenge));
      const v = await fetch(BASE + "/api/auth/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username, challenge, sig }),
      });
      if (!v.ok) throw new Error("verify failed: " + v.status);
    },
    "login with the wrong key is rejected",
  );
  console.log("OK  login with wrong key rejected");
}

await testRegisterLookupLogin();
await testDuplicateRejected();
await testWrongKeyLoginRejected();
console.log("\nAll account-directory integration checks passed.");
process.exit(0);

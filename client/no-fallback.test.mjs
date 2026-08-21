// crypto.subtle is REQUIRED. There is no fallback, and there must never be one.
// Run: node no-fallback.test.mjs   (no server, no DOM)
//
// Pentest 2026-07-29, test-coverage gap 7. The 2026-07-29 sweep called this the
// highest-stakes question it asked, and the answer was the best result in the
// report: no polyfill, no fallback, no optional chaining, no `typeof` guard, no
// security-relevant Math.random, and no permissive `catch` in eight modules —
// every operation throws, `app.js` gates on `cipher.ready`, and on an encrypt
// throw it does NOT call `ws.send`, so no plaintext leaves. A hard dead-end.
//
// But NOTHING ASSERTED IT. That property is one well-meaning "let's be
// compatible with older browsers" commit away from silently inverting, and the
// failure mode is plaintext on the wire. So it is pinned here, two ways: by
// behaviour (the modules throw with crypto.subtle absent) and by source (the
// specific shapes a fallback would take are absent from the code).
import assert from "node:assert";
import { readFile, readdir } from "node:fs/promises";

const HERE = new URL("./", import.meta.url);

// --- 1. behaviour: with crypto.subtle gone, everything throws ----------------
// Node caches modules per specifier, so a query string gives a fresh instance
// that evaluates against the crippled global.
{
  const realSubtle = globalThis.crypto.subtle;
  const mem = new Map();
  globalThis.localStorage = {
    getItem: (k) => (mem.has(k) ? mem.get(k) : null),
    setItem: (k, v) => mem.set(k, String(v)),
    removeItem: (k) => mem.delete(k),
    clear: () => mem.clear(),
  };

  Object.defineProperty(globalThis.crypto, "subtle", {
    value: undefined, configurable: true, writable: true,
  });
  try {
    const crypto_ = await import("./crypto.js?nosubtle=1");
    const identity = await import("./identity.js?nosubtle=1");
    const contacts = await import("./contacts.js?nosubtle=1");

    // Identity creation must not half-succeed and must write nothing.
    await assert.rejects(() => identity.Identity.generate(),
      "Identity.generate must throw without crypto.subtle");
    assert.strictEqual(mem.size, 0, "no identity material may be written on failure");

    // The verifier must THROW, never return a value. A verifier that returns
    // false is survivable; one that returns true is catastrophic, and a
    // `catch { return false }` added here would be indistinguishable from a
    // fallback until the day it wasn't.
    await assert.rejects(
      () => identity.Identity.verify(
        { ed: "AAAA", mldsa: "AAAA" }, new Uint8Array(1), { ed: "AAAA", mldsa: "AAAA" },
      ),
      "Identity.verify must throw, not return a verdict, without crypto.subtle",
    );

    // Every negotiated cipher mode must fail to become ready, and must refuse
    // to encrypt. `ready` staying false is what app.js gates on.
    for (const alg of ["AES256", "DHKE", "PQKEM"]) {
      const c = crypto_.makeCipher(alg, "a".repeat(64), { passphrase: "x" });
      await assert.rejects(async () => {
        await c.init();
        if (c.usesNonces) await c.setNonces("n".repeat(44), "m".repeat(44));
        if (c.needsHandshake) await c.onPeerKey(await c.handshakePayload());
        await c.encrypt("plaintext that must never reach the wire");
      }, `${alg} must not produce ciphertext without crypto.subtle`);
      assert.ok(!c.ready, `${alg}.ready must stay false without crypto.subtle`);
    }

    // The at-rest store must not silently open unencrypted either.
    await assert.rejects(() => contacts.unlock("passphrase"),
      "the contact store must not unlock without crypto.subtle");
  } finally {
    Object.defineProperty(globalThis.crypto, "subtle", {
      value: realSubtle, configurable: true, writable: true,
    });
    delete globalThis.localStorage;
  }
}
console.log("OK  crypto.subtle absent: identity, every cipher mode, and the store all fail closed");

// --- 2. source: the shapes a fallback would take must not appear -------------
// Behavioural tests only cover the paths they walk. These patterns are how a
// fallback actually gets introduced, and they are cheap to forbid outright.
{
  const files = (await readdir(HERE))
    .filter((f) => f.endsWith(".js") && !f.endsWith(".test.mjs"));
  assert.ok(files.length >= 8, `expected the client modules, found ${files.length}`);

  const banned = [
    [/crypto\s*\.\s*subtle\s*\?\./, "optional chaining on crypto.subtle"],
    [/typeof\s+crypto\s*\.\s*subtle/, "a typeof guard on crypto.subtle"],
    [/crypto\s*\.\s*subtle\s*(\|\||\?\?)/, "a `crypto.subtle || fallback`"],
    [/\bwindow\s*\.\s*msCrypto\b/, "the msCrypto polyfill hook"],
    [/\brequire\(['"]crypto-js/, "a crypto-js polyfill"],
    [/\bsjcl\b/, "the SJCL polyfill"],
  ];

  for (const f of files) {
    const src = await readFile(new URL(f, HERE), "utf8");
    for (const [re, what] of banned) {
      assert.ok(!re.test(src), `${f} contains ${what} — that is a crypto.subtle fallback`);
    }
    // Math.random: banned outright in the client modules.
    //
    // Pentest 2026-08-07 F-CRYPTO-014. This used to allow Math.random on any
    // line whose text lacked key/nonce/iv/salt/secret/token/randomBytes — a
    // keyword grep of the same line. `const TAB_ID = Math.random()...` contains
    // none of those words, so this check reported green on the one Math.random
    // in the client that gated key material: TAB_ID was the sole discriminator
    // for the OTP pad lease, i.e. the value standing between the user and a
    // two-time pad. A rule that decides what is security-relevant by reading
    // the words on the line will keep missing exactly the cases where the
    // security relevance lives somewhere else, so it is now unconditional.
    // If UI jitter ever genuinely needs it, add a named allowlist here rather
    // than reopening the keyword heuristic.
    for (const [i, line] of src.split("\n").entries()) {
      // Skip comment lines only: `//`, a block-comment opener, or a
      // continuation `*`. (The `/*` case was missing in the first cut.)
      if (!/Math\.random/.test(line) || /^\s*(\/\/|\/\*|\*)/.test(line)) continue;
      assert.fail(`${f}:${i + 1}: Math.random in a client module: ${line.trim()}`);
    }
  }
}
console.log("OK  no polyfill, no optional-chaining guard, no Math.random key material");

console.log("\nAll no-fallback checks passed.");

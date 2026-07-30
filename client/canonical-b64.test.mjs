// Pentest 2026-07-27 H-1 / M-4: base64 encoding-equality mismatch.
//
// `atob` is WHATWG *forgiving* base64: it discards the trailing slack bits
// rather than rejecting them. Every fixed-size key in this project has a length
// ≡ 2 (mod 3), i.e. 2 slack bits, so FOUR distinct base64 strings decode to the
// identical key bytes. That split every key into two domains — byte checks
// (signatures, digests, safety numbers) were encoding-blind and PASSED on a
// mutated spelling, while string checks (the pinned bundle, the reflection
// guard) DIVERGED. A relay flipping a single character could therefore fire the
// "identity key CHANGED" alarm on a genuine peer, get a non-canonical string
// pinned, and permanently wedge async chats.
//
// These tests pin the fix: decoding is canonical, so a re-spelled key is
// malformed input that dies at the boundary rather than a value that verifies
// but compares unequal three checks later.
//
// Run: node canonical-b64.test.mjs   (server not required)
import assert from "node:assert";
import { Identity, b64, unb64 } from "./identity.js";
import { makeCipher, bufToB64, b64ToBuf } from "./crypto.js";

const ROOM = "a".repeat(64);

// The four spellings of the same bytes. For a value whose length ≡ 2 (mod 3)
// the last base64 character carries 2 bits that the decoder throws away, so the
// three alternatives to the canonical last character decode identically.
const B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
function respellings(canonical) {
  // One '=' -> the final sextet carries 2 slack bits (4 spellings); two '=' ->
  // 4 slack bits (16). A value with no padding has none and cannot be re-spelt.
  const pad = (canonical.match(/=*$/) || [""])[0].length;
  assert.ok(pad > 0, "expected a value with slack bits (length % 3 !== 0)");
  const slackBits = pad === 1 ? 2 : 4;
  const lastIdx = canonical.length - pad - 1;
  const idx = B64_ALPHABET.indexOf(canonical[lastIdx]);
  const mask = (1 << slackBits) - 1;
  const out = [];
  for (let v = 0; v <= mask; v++) {
    const alt = (idx & ~mask) | v;
    if (alt === idx) continue;
    out.push(canonical.slice(0, lastIdx) + B64_ALPHABET[alt] + canonical.slice(lastIdx + 1));
  }
  return out;
}

async function testForgivingDecodeIsGone() {
  const id = await Identity.generate();
  const bundle = id.publicBundle();

  // Ground truth: the premise of the finding still holds for raw atob — these
  // really are distinct strings for the same key. If this ever stops being true
  // the rest of the file is testing nothing.
  const alts = respellings(bundle.ed);
  assert.strictEqual(alts.length, 3, "a 32-byte key has exactly 4 spellings");
  for (const alt of alts) {
    assert.notStrictEqual(alt, bundle.ed, "re-spelling must differ as a STRING");
    assert.deepStrictEqual(
      Buffer.from(alt, "base64"), Buffer.from(bundle.ed, "base64"),
      "re-spelling must decode to the SAME bytes under forgiving base64",
    );
  }

  // The fix: our decoders refuse every non-canonical spelling.
  for (const alt of alts) {
    assert.throws(() => unb64(alt), /canonical/, "identity.unb64 rejects slack bits");
    assert.throws(() => b64ToBuf(alt), /canonical/, "crypto.b64ToBuf rejects slack bits");
  }
  // …and still accept the canonical one, round-tripping exactly.
  assert.strictEqual(b64(unb64(bundle.ed)), bundle.ed, "canonical value round-trips");
  assert.strictEqual(bufToB64(new Uint8Array(b64ToBuf(bundle.ed))), bundle.ed);

  // Other forgiving-base64 slack the decoders must also refuse: whitespace,
  // missing padding, and the base64url alphabet.
  for (const bad of [" " + bundle.ed, bundle.ed.replace(/=+$/, ""), bundle.ed.replace(/\+/g, "-")]) {
    if (bad === bundle.ed) continue; // key happened to contain no '+'
    assert.throws(() => unb64(bad), /canonical/, "non-canonical form rejected: " + bad.slice(-8));
  }
  console.log("OK  H-1: forgiving base64 is gone — only the canonical spelling decodes");
}

async function testMutatedBundleNoLongerVerifies() {
  const id = await Identity.generate();
  const bundle = id.publicBundle();
  const mutated = { ...bundle, ed: respellings(bundle.ed)[0] };
  const msg = new TextEncoder().encode("some signed message");
  const sig = await id.sign(msg);

  // BEFORE the fix all four of these agreed with the original — that agreement
  // was the vulnerability. Now the mutated bundle is malformed and every
  // byte-domain check refuses it outright, so it can never reach a string
  // comparison that would disagree.
  await assert.rejects(
    () => Identity.verify(mutated, msg, sig), /canonical/,
    "a re-spelled bundle no longer verifies",
  );
  await assert.rejects(
    () => Identity.fingerprintOf(mutated), /canonical/,
    "a re-spelled bundle has no fingerprint",
  );
  await assert.rejects(
    () => Identity.safetyNumber(bundle, mutated), /canonical/,
    "a re-spelled bundle has no safety number",
  );
  await assert.rejects(
    () => Identity.bundleDigest(mutated), /canonical/,
    "a re-spelled bundle has no digest",
  );
  console.log("OK  H-1: a re-spelled bundle is rejected, not silently equivalent");
}

async function testDhkeReflectionGuardOnBytes() {
  // M-4: the DHKE reflection guard was a bare string compare on `this.myPub`,
  // so a re-spelled copy of the guest's OWN signed offer walked past it. She
  // then derived a channel with herself and was prompted to verify her own
  // fingerprint; clicking through pinned her own bundle as the room's contact.
  const a = makeCipher("DHKE", ROOM);
  await a.init();
  const mine = await a.handshakePayload();

  await assert.rejects(() => a.onPeerKey(mine), /reflected/, "exact reflection rejected");
  for (const alt of respellings(mine)) {
    await assert.rejects(
      () => a.onPeerKey(alt), /reflected|canonical/,
      "re-spelled reflection rejected (M-4)",
    );
  }
  assert.strictEqual(a.chan, null, "no channel was derived from a reflection");

  // A genuine peer still completes normally.
  const bob = makeCipher("DHKE", ROOM);
  await bob.init();
  await a.onPeerKey(await bob.handshakePayload());
  await bob.onPeerKey(mine);
  assert.strictEqual(await bob.decrypt(await a.encrypt("hello")), "hello",
    "an honest DHKE handshake is unaffected");
  console.log("OK  M-4: DHKE reflection guard compares the point, not its spelling");
}

async function testWireFramesAreCanonical() {
  // The ratchet frame fields (iv, ct) decode through the same canonical path,
  // so a relay cannot re-spell them either. Nothing about an honest frame
  // changes; a re-spelled one is rejected like any other tampering.
  const a = makeCipher("AES256", ROOM, { passphrase: "correct horse battery staple" });
  const b = makeCipher("AES256", ROOM, { passphrase: "correct horse battery staple" });
  await a.init();
  await b.init();
  const [na, nb] = ["n".repeat(43) + "a", "n".repeat(43) + "b"];
  await a.setNonces(na, nb);
  await b.setNonces(nb, na);

  const wire = await a.encrypt("canonical frames only");
  const frame = JSON.parse(Buffer.from(wire, "base64").toString());
  const respelt = Buffer.from(
    JSON.stringify({ ...frame, ct: respellings(frame.ct)[0] }),
  ).toString("base64");
  await assert.rejects(() => b.decrypt(respelt), "a re-spelled frame is rejected");
  assert.strictEqual(await b.decrypt(wire), "canonical frames only",
    "the channel survives and the honest frame still opens");
  console.log("OK  H-1: wire frames decode canonically too (channel intact)");
}

// --- M-6 (2026-07-29): the DIRECTORY path was never put behind this gate -----
// account.fetchBundle copied the server's key strings verbatim, and
// contacts.upsert decides `keyChanged` by RAW STRING comparison. So a hostile
// directory could re-spell a key — byte-for-byte the same key — and truthfully
// fire "the fetched keys DIFFER from what you verified", stripping the verified
// mark and every vouch; permanently break sealed messaging to that contact,
// because the non-canonical string is persisted and seal() throws on it before
// sending; and push their inbound mail into a fresh `unknown-…` auto-contact.
async function testDirectoryAnswersAreCanonicalised() {
  const account = await import("./account.js");
  const id = await Identity.generate();
  const bundle = id.publicBundle();
  const TOKEN = "tok";
  const HANDLE = `dir-victim#${TOKEN}`;

  const realFetch = globalThis.fetch;
  const serve = (body) => {
    globalThis.fetch = async () => ({
      ok: true, status: 200, json: async () => body,
    });
  };
  try {
    // Honest answer: passes through unchanged.
    serve({ ed: bundle.ed, mldsa: bundle.mldsa });
    const good = await account.fetchBundle("http://relay.invalid", HANDLE);
    assert.strictEqual(good.ed, bundle.ed, "a canonical bundle is returned as-is");
    assert.strictEqual(good.mldsa, bundle.mldsa);

    // Hostile answer: same BYTES, different spelling. Must be refused at the
    // boundary rather than returned as a different-looking key.
    for (const field of ["ed", "mldsa"]) {
      const evil = { ed: bundle.ed, mldsa: bundle.mldsa };
      evil[field] = respellings(bundle[field])[0];
      assert.notStrictEqual(evil[field], bundle[field], "precondition: re-spelt");
      assert.deepStrictEqual(
        Buffer.from(unb64(bundle[field])), Buffer.from(atob(evil[field]), "binary"),
        "precondition: the re-spelling decodes to the SAME bytes",
      );
      serve(evil);
      await assert.rejects(
        () => account.fetchBundle("http://relay.invalid", HANDLE),
        /malformed/,
        `M-6: a re-spelled ${field} from the directory must be refused`,
      );
    }

    // The v2 encryption keys go through the same gate — they are what seal()
    // consumes, so a re-spelling there is the "permanently unmailable" half.
    const ecdh = b64(crypto.getRandomValues(new Uint8Array(65)));
    const mlkem = b64(crypto.getRandomValues(new Uint8Array(1184)));
    serve({ ed: bundle.ed, mldsa: bundle.mldsa, ecdh, mlkem });
    const v2 = await account.fetchBundle("http://relay.invalid", HANDLE);
    assert.strictEqual(v2.ecdh, ecdh, "canonical v2 keys pass through");
    for (const field of ["ecdh", "mlkem"]) {
      const evil = { ed: bundle.ed, mldsa: bundle.mldsa, ecdh, mlkem };
      evil[field] = respellings(evil[field])[0];
      serve(evil);
      await assert.rejects(
        () => account.fetchBundle("http://relay.invalid", HANDLE),
        /malformed/,
        `M-6: a re-spelled ${field} from the directory must be refused`,
      );
    }
    console.log("OK  M-6: directory answers go through the canonical-base64 gate");
  } finally {
    globalThis.fetch = realFetch;
  }
}

await testForgivingDecodeIsGone();
await testMutatedBundleNoLongerVerifies();
await testDhkeReflectionGuardOnBytes();
await testWireFramesAreCanonical();
await testDirectoryAnswersAreCanonicalised();
console.log("\nAll canonical-base64 checks passed.");

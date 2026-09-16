// Pentest 2026-08-07 F-CRYPTO-012: every advertised pad size must actually be
// generatable.
//
// Web Crypto hard-caps one getRandomValues() call at 65536 bytes and throws
// QuotaExceededError above it. `randomPad` asked for the whole pad in a single
// call, so of the three sizes PAD_SIZES offers the user, 256 KiB and 1 MiB
// threw before a single byte was written — two thirds of the advertised menu
// was dead. This walks the real PAD_SIZES list so a future size cannot be added
// without being provably generatable.
//
// Run: node otp-padgen.test.mjs   (server not required)
import assert from "node:assert";
import { PAD_SIZES, generatePad } from "./otp.js";

const CSPRNG_MAX_BYTES = 65536;

// The cap is a property of the platform, not of our code — pin it, so that if a
// future runtime lifts it this test still describes reality.
await assert.rejects(
  async () => crypto.getRandomValues(new Uint8Array(CSPRNG_MAX_BYTES + 1)),
  "platform no longer caps getRandomValues — the chunking premise needs a re-read",
);
console.log(`OK  platform caps getRandomValues at ${CSPRNG_MAX_BYTES} bytes`);

for (const size of PAD_SIZES) {
  const pad = await generatePad({ label: "test", totalBytes: size.bytes });
  assert.strictEqual(pad.bytes.length, size.bytes, `${size.label}: wrong length`);
  assert.strictEqual(pad.regionSize, size.bytes / 2);

  // Every chunk must be filled — an unwritten tail would be a pad of zeros,
  // i.e. plaintext on the wire, which is the worst possible way to fail here.
  for (let off = 0; off < pad.bytes.length; off += CSPRNG_MAX_BYTES) {
    const chunk = pad.bytes.subarray(off, Math.min(off + CSPRNG_MAX_BYTES, pad.bytes.length));
    assert.ok(chunk.some((b) => b !== 0), `all-zero chunk at offset ${off} in ${size.label}`);
  }

  // Chunks must not repeat one another: a naive fill that re-randomised one
  // buffer and copied it would pass the check above but produce a two-time pad.
  if (pad.bytes.length > CSPRNG_MAX_BYTES) {
    const first = Buffer.from(pad.bytes.subarray(0, 64));
    const second = Buffer.from(pad.bytes.subarray(CSPRNG_MAX_BYTES, CSPRNG_MAX_BYTES + 64));
    assert.ok(!first.equals(second), `${size.label}: chunk 1 repeats chunk 0`);
  }

  // Coarse spread check: a byte-frequency collapse would show here.
  const zeros = pad.bytes.reduce((n, b) => n + (b === 0 ? 1 : 0), 0);
  const expected = pad.bytes.length / 256;
  assert.ok(zeros > expected * 0.5 && zeros < expected * 1.5, `${size.label}: implausible zero-byte count ${zeros}`);

  console.log(`OK  ${size.label} generates (${size.bytes} bytes, ${zeros} zero bytes vs ~${expected.toFixed(0)} expected)`);
}

// Folding in drawn entropy must not regress either — that path XORs an AES-CTR
// keystream over the whole pad.
{
  const finger = new Uint8Array(4096).fill(7);
  const pad = await generatePad({ label: "test", totalBytes: 1024 * 1024, fingerBytes: finger });
  assert.strictEqual(pad.bytes.length, 1024 * 1024);
  assert.ok(pad.bytes.subarray(1024 * 1024 - 64).some((b) => b !== 0), "tail unwritten with drawn entropy");
  console.log("OK  1 MiB pad with drawn entropy folded in");
}

// --- the PARTIAL TAIL, which PAD_SIZES cannot reach -------------------------
// Test-debt item 7. Every entry in PAD_SIZES is an exact multiple of
// CSPRNG_MAX_BYTES (65536, 262144, 1048576), so the loop above only ever walks
// whole chunks: `fillRandom`'s final short chunk — the `Math.min(...)` end of the
// last `subarray` — has never been executed by this suite at all. A fill loop
// that stopped one chunk early (`off + CSPRNG_MAX_BYTES <= buf.length`) still
// passes all three advertised sizes and leaves the tail of any other size as
// ZEROS, which is not "a weaker pad": XOR against zeros is the identity, so those
// bytes are the user's plaintext on the wire.
//
// The sizes are a UI menu, not a law — `generatePad` accepts any even integer
// >= 128 — so this must be pinned independently of what the menu happens to
// offer today. 100000 = 65536 + 34464, i.e. one whole chunk plus a partial one.
{
  const ODD = 100_000;
  const TAIL_START = CSPRNG_MAX_BYTES;
  assert.ok(PAD_SIZES.every((s) => s.bytes % CSPRNG_MAX_BYTES === 0),
    "premise of this block: every advertised size is a whole number of chunks, which is exactly " +
    "why the loop above cannot reach the partial-tail branch — if a non-multiple size is ever " +
    "added to the menu, say so here rather than letting this block quietly become redundant");

  const tail = await generatePad({ label: "partial tail", totalBytes: ODD });
  assert.strictEqual(tail.bytes.length, ODD, "a non-multiple size must still generate in full");
  assert.ok(tail.bytes.subarray(TAIL_START).some((b) => b !== 0),
    "F-CRYPTO-012: the final SHORT chunk must be filled — an unwritten tail is a run of zeros, " +
    "and XOR-OTP against zeros transmits the plaintext verbatim");
  // The very end specifically: a loop that wrote the tail but computed its length
  // wrong would leave only the last handful of bytes untouched, which is still a
  // plaintext leak and is invisible to a whole-tail "some non-zero" check.
  assert.ok(tail.bytes.subarray(ODD - 64).some((b) => b !== 0),
    "F-CRYPTO-012: ...including the final bytes of the pad, not merely most of the tail");
  // ...and the tail must be its own randomness, not a copy of chunk 0 (the
  // two-time-pad shape the whole-chunk loop above also guards against).
  {
    const first = Buffer.from(tail.bytes.subarray(0, 64));
    const last = Buffer.from(tail.bytes.subarray(TAIL_START, TAIL_START + 64));
    assert.ok(!first.equals(last), "the partial tail must not repeat the first chunk");
  }
  console.log(`OK  item 7: a non-multiple size (${ODD}) fills its partial final chunk`);

  // The drawn-entropy path XORs a full-length AES-CTR keystream over the base,
  // so it can mask a zero tail with keystream and LOOK filled while the CSPRNG
  // contributed nothing there. Assert the size works at all; the base-fill claim
  // is carried by the plain case above, which is why both are kept.
  const drawn = await generatePad({
    label: "partial tail, drawn", totalBytes: ODD, fingerBytes: new Uint8Array(4096).fill(7),
  });
  assert.strictEqual(drawn.bytes.length, ODD);
  assert.ok(drawn.bytes.subarray(ODD - 64).some((b) => b !== 0),
    "tail unwritten with drawn entropy at a non-multiple size");
  console.log(`OK  item 7: ...and with drawn entropy folded in at ${ODD} bytes`);
}

console.log("\nAll OTP pad generation checks passed.");

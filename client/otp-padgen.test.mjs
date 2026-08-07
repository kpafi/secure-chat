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

console.log("\nAll OTP pad generation checks passed.");

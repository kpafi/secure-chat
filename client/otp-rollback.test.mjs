// M-01 regression: a full old encrypted-pad blob restore (rolling sendOffset
// back to reuse consumed keystream) is refused by the separate high-water
// tripwire. Run: node otp-rollback.test.mjs
import assert from "node:assert";

const mem = new Map();
globalThis.localStorage = {
  getItem: (k) => (mem.has(k) ? mem.get(k) : null),
  setItem: (k, v) => mem.set(k, String(v)),
  removeItem: (k) => mem.delete(k),
};

const otp = await import("./otp.js");

const PASS = "pad-pass";
const rec = await otp.generatePad({ label: "rollback", totalBytes: 64 * 1024, fingerBytes: new Uint8Array(0) });
const atRest = await otp.saveNewPad(rec, PASS);

// Snapshot the pristine (offset 0) blob — this is what an attacker would keep.
const padK = "sc.otp.pad.v1." + rec.padId;
const oldBlob = localStorage.getItem(padK);

// Consume some pad: advance sendOffset and persist (bumps the high-water).
rec.sendOffset = 500;
await otp.savePadProgress(rec, atRest);
assert.strictEqual(otp.padMeta(rec.padId).padId, rec.padId);
const unlockedOk = await otp.unlockPad(rec.padId, PASS);
assert.strictEqual(unlockedOk.record.sendOffset, 500, "current pad unlocks normally");
console.log("OK  pad unlocks at its true (advanced) offset");

// Attacker restores the OLD blob (offset 0) wholesale — valid GCM ciphertext.
localStorage.setItem(padK, oldBlob);
await assert.rejects(otp.unlockPad(rec.padId, PASS), /rolled back/, "rolled-back blob must be refused");
console.log("OK  M-01: a wholesale old-blob restore (offset rollback) is refused");

// Pentest 2026-07-26 P-05: forgetPad must KEEP the tripwire. It used to delete
// it, which made "Forget pad" the easiest route to a two-time pad: an export
// file is always pristine, and the duplicate-import guard is an index lookup
// that forgetPad clears — so forget + re-import the same file resurrected the
// pad at offset 0 with a clean watermark, and every later message reused
// keystream the peer had already seen.
otp.forgetPad(rec.padId);
assert.ok(
  localStorage.getItem("sc.otp.wm.v1." + rec.padId) !== null,
  "P-05: the authenticated watermark survives forgetPad so a re-import can be refused",
);
assert.ok(otp.padWasUsed(rec.padId), "P-05: pad is still known to have been used here");
console.log("OK  P-05: high-water tripwire SURVIVES forgetPad");

// ...and re-importing that same pad file is refused rather than rewinding it.
const freshPad = await otp.generatePad({ label: "reimport", totalBytes: 1024, fingerBytes: new Uint8Array(0) });
freshPad.padId = rec.padId; // same pad identity as the one already consumed here
const file = await otp.exportPad(freshPad, "transfer-pass");
await assert.rejects(
  otp.importPad(file, "transfer-pass"), /already been used/,
  "P-05: re-importing a pad already consumed on this device is refused",
);
console.log("OK  P-05: re-import of an already-consumed pad is refused");

// P-01 (and its own fix-review follow-up): the stored blob must authenticate its
// own metadata, and must not be downgradable to the legacy format. The first cut
// of the P-01 fix keyed "is this legacy?" on the OUTER `v` byte, so deleting `v`
// handed `role` back to an attacker — a full two-time pad. The discriminator is
// now the presence of `padId` INSIDE the ciphertext, which cannot be forged.
const p = await otp.generatePad({ label: "authmeta", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
p.role = 1;
const pAtRest = await otp.saveNewPad(p, PASS);
p.sendOffset = 4000;
await otp.savePadProgress(p, pAtRest);
const pKey = "sc.otp.pad.v1." + p.padId;

const outer = JSON.parse(localStorage.getItem(pKey));
assert.deepStrictEqual(
  Object.keys(outer).sort(), ["ct", "iv", "kdf", "v"],
  "P-01: only version + KDF params + ciphertext may sit outside the AEAD",
);

// Downgrade attempt: strip "v", re-attach attacker-chosen outer metadata.
delete outer.v;
outer.padId = p.padId; outer.label = "x"; outer.regionSize = p.regionSize; outer.role = 0;
localStorage.setItem(pKey, JSON.stringify(outer));
const afterDowngrade = await otp.unlockPad(p.padId, PASS);
assert.strictEqual(afterDowngrade.record.role, 1, "P-01: outer 'role' must be ignored even with 'v' stripped");
console.log("OK  P-01: a v2 blob cannot be downgraded to the legacy path");

// Re-keying that same blob under a fresh id must still be refused.
const copy = JSON.parse(localStorage.getItem(pKey));
delete copy.v; copy.padId = "forgedid"; copy.regionSize = p.regionSize; copy.role = 0;
localStorage.setItem("sc.otp.pad.v1.forgedid", JSON.stringify(copy));
await assert.rejects(
  otp.unlockPad("forgedid", PASS), /does not match its storage key/,
  "P-01: a blob re-keyed under a fresh padId must be refused",
);
console.log("OK  P-01: padId re-key (M-01 watermark bypass) is refused");

// --- Pentest 2026-07-27 H-3: the watermark is authenticated + fails closed ---
// The tripwire used to be one PLAINTEXT decimal string, and its reader returned
// 0 for a missing value. So the "restore just the pad blob" attack M-01 was
// built to catch cost one extra removeItem: two messages then encrypted at the
// same offset and C1 XOR C2 = P1 XOR P2 handed over a plaintext.
{
  const h = await otp.generatePad({ label: "h3", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const hAtRest = await otp.saveNewPad(h, PASS);
  const hKey = "sc.otp.pad.v1." + h.padId;
  const pristine = localStorage.getItem(hKey);
  h.sendOffset = 85;
  await otp.savePadProgress(h, hAtRest);

  // The watermark is opaque at rest: no offset readable or editable in the clear.
  //
  // This was `!wmRaw.includes("85")` — a substring search over random base64
  // ciphertext, so it failed ~1.4% of runs whenever "85" turned up by chance
  // (caught 2026-07-28 while re-running the suite; pre-existing, not from the
  // bf6bcd2 work). A flaky assertion on a security property is worse than none:
  // it trains you to re-run until green. The property it was reaching for is
  // structural and deterministic — the record carries ONLY iv+ct, so there is no
  // plaintext field to read or edit, whatever the ciphertext happens to spell.
  const wmRaw = localStorage.getItem("sc.otp.wm.v1." + h.padId);
  assert.ok(wmRaw, "the watermark exists after a save");
  assert.deepStrictEqual(Object.keys(JSON.parse(wmRaw)).sort(), ["ct", "iv"],
    "watermark stores only iv+ct — no plaintext offset field");

  // Restore the pristine blob AND delete the watermark — the reported PoC.
  localStorage.setItem(hKey, pristine);
  localStorage.removeItem("sc.otp.wm.v1." + h.padId);
  await assert.rejects(
    otp.unlockPad(h.padId, PASS), /rollback record for this pad is missing/,
    "H-3: deleting the watermark must FAIL CLOSED, not reset the tripwire to 0",
  );

  // Forging one is not an option either: it is AEAD under the pad's own key.
  localStorage.setItem("sc.otp.wm.v1." + h.padId, JSON.stringify({
    iv: "AAAAAAAAAAAAAAAA", ct: "AAAAAAAAAAAAAAAAAAAAAAA=",
  }));
  await assert.rejects(
    otp.unlockPad(h.padId, PASS), /damaged or forged/,
    "H-3: a forged watermark is refused",
  );
}
console.log("OK  H-3: deleting or forging the OTP watermark fails closed");

// --- Pentest 2026-07-27 M-7: the RECEIVE watermark rolls back too ------------
// bumpHW only ever advanced on sendOffset, and the tripwire only checked
// sendOffset. A restore taken after a stretch of RECEIVING ONLY therefore left
// sendOffset untouched — nothing fired — while recvHighWater fell back to zero
// and every already-delivered frame re-authenticated as fresh.
{
  const m = await otp.generatePad({ label: "m7", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const mAtRest = await otp.saveNewPad(m, PASS);
  const mKey = "sc.otp.pad.v1." + m.padId;

  m.sendOffset = 200;            // some sending, then…
  await otp.savePadProgress(m, mAtRest);
  const beforeReceiving = localStorage.getItem(mKey);

  m.recvHighWater = 119;         // …a stretch of receiving only
  await otp.savePadProgress(m, mAtRest);
  assert.strictEqual((await otp.unlockPad(m.padId, PASS)).record.recvHighWater, 119);

  // Restore the copy taken before the receiving: sendOffset is IDENTICAL, so
  // the old send-only tripwire saw nothing wrong.
  localStorage.setItem(mKey, beforeReceiving);
  await assert.rejects(
    otp.unlockPad(m.padId, PASS), /receive state was rolled back/,
    "M-7: a receive-side rollback is refused even when sendOffset is unchanged",
  );
}
console.log("OK  M-7: OTP recvHighWater rollback (replay across a reload) is refused");

// --- Pentest 2026-07-27 L-3: `exported` is authenticated ---------------------
// The double-export gate lived in the plaintext index, so clearing one field
// removed the only warning that stops one pristine pad going to two importers.
{
  const e = await otp.generatePad({ label: "l3", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const eAtRest = await otp.saveNewPad(e, PASS);
  const unlocked = await otp.unlockPad(e.padId, PASS);
  assert.strictEqual(unlocked.record.exported, false, "a fresh pad is not exported");

  await otp.markExported(unlocked.record, unlocked.atRest);
  assert.strictEqual((await otp.unlockPad(e.padId, PASS)).record.exported, true,
    "the flag round-trips through the AEAD");

  // Clear the plaintext index copy — the render cache, not the trust source.
  const idx = JSON.parse(localStorage.getItem("sc.otp.index.v1"));
  for (const entry of idx) {
    if (entry.padId === e.padId) entry.exported = false;
  }
  localStorage.setItem("sc.otp.index.v1", JSON.stringify(idx));
  assert.strictEqual(otp.padMeta(e.padId).exported, false, "the index copy really was cleared");
  assert.strictEqual((await otp.unlockPad(e.padId, PASS)).record.exported, true,
    "L-3: clearing the plaintext index does NOT disarm the double-export warning");
}
console.log("OK  L-3: the double-export gate is authenticated, not a plaintext flag");

// --- v2 -> v3 migration of a pad that was ALREADY USED before the fix -------
// Found on-device 2026-07-28: every check above builds its pad with the CURRENT
// generatePad(), so the blob is v3 with an authenticated watermark from birth.
// Nothing here ever saw a genuine pre-fix pad, and the shipped code refused one:
// `knownUsedHere` counted the legacy PLAINTEXT watermark as proof that a v3
// record must exist — but that watermark is written only by pre-fix code, so it
// is present on exactly the pads that legitimately have none yet. Result: a
// pre-fix pad that had sent even one message was permanently unusable.
//
// Reconstructs a real pre-fix pad rather than asserting on the guard directly:
// re-encrypt the inner record WITHOUT the v3-only fields under the same at-rest
// key, stamp `v:2`, drop both post-fix artifacts, and leave the legacy
// plaintext watermark the old code would have written.
const _enc = new TextEncoder();
const _dec = new TextDecoder();
const _b64 = (u8) => Buffer.from(u8).toString("base64");
const _unb64 = (s) => new Uint8Array(Buffer.from(s, "base64"));

// Rewrite a pad's stored blob into the genuine pre-fix (v2) shape: the same
// inner record minus the v3-only fields, re-encrypted under the same at-rest
// key. `mutate` may adjust the inner record first (e.g. to stage a rollback).
// Verified against `git show e86a60b:client/otp.js` — the pre-fix writePadBlob
// emits exactly padId,label,regionSize,role,createdAt,bytes,sendOffset,
// recvHighWater, in that order, which is what stripping the three v3 fields
// from the current inner record produces.
async function makeV2Blob(padId, key, mutate) {
  const k = "sc.otp.pad.v1." + padId;
  const cur = JSON.parse(localStorage.getItem(k));
  const inner = JSON.parse(_dec.decode(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: _unb64(cur.iv) }, key, _unb64(cur.ct),
  )));
  delete inner.hwSend;    // v3-only: the authenticated watermark mirror
  delete inner.hwRecv;
  delete inner.exported;  // v3-only: L-3 moved this inside the AEAD
  if (mutate) mutate(inner);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, key, _enc.encode(JSON.stringify(inner)),
  ));
  localStorage.setItem(k, JSON.stringify({ v: 2, kdf: cur.kdf, iv: _b64(iv), ct: _b64(ct) }));
}

{
  const enc = _enc;
  const dec = _dec;
  const b64 = _b64;
  const unb64 = _unb64;

  const m = await otp.generatePad({ label: "v2-used", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const mAtRest = await otp.saveNewPad(m, PASS);
  const mKey = "sc.otp.pad.v1." + m.padId;

  const USED = 1234;
  m.sendOffset = USED;
  await otp.savePadProgress(m, mAtRest);

  // Roll the stored blob back to the pre-fix shape.
  const cur = JSON.parse(localStorage.getItem(mKey));
  const innerPlain = JSON.parse(dec.decode(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(cur.iv) }, mAtRest.key, unb64(cur.ct),
  )));
  delete innerPlain.hwSend;      // v3-only: the authenticated watermark mirror
  delete innerPlain.hwRecv;
  delete innerPlain.exported;    // v3-only: L-3 moved this inside the AEAD
  const iv2 = crypto.getRandomValues(new Uint8Array(12));
  const ct2 = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv2 }, mAtRest.key, enc.encode(JSON.stringify(innerPlain)),
  ));
  localStorage.setItem(mKey, JSON.stringify({ v: 2, kdf: cur.kdf, iv: b64(iv2), ct: b64(ct2) }));
  localStorage.removeItem("sc.otp.wm.v1." + m.padId);    // never existed pre-fix
  localStorage.removeItem("sc.otp.used.v1." + m.padId);  // stamped only post-fix
  localStorage.setItem("sc.otp.hw.v1." + m.padId, String(USED)); // what old code wrote

  // F-1: adoption is no longer automatic. A pad with no authenticated floor is
  // refused until the caller has shown the user the warning and they accept it.
  // Silent adoption was the vulnerability, so this refusal is the fix.
  await assert.rejects(
    otp.unlockPad(m.padId, PASS),
    (e) => e.code === "LEGACY_PAD_ADOPTION" && e.suspicious === true,
    "F-1: a pre-fix pad must NOT be adopted silently, and this device has run OTP so it is flagged suspicious",
  );

  const migrated = await otp.unlockPad(m.padId, PASS, { adoptLegacy: true });
  assert.strictEqual(migrated.record.sendOffset, USED,
    "a USED pre-fix pad must migrate, not be refused");
  assert.strictEqual(JSON.parse(localStorage.getItem(mKey)).v, 3,
    "the migrated blob is rewritten as v3");
  assert.ok(localStorage.getItem("sc.otp.wm.v1." + m.padId),
    "migration writes the authenticated watermark");

  // The floor must SURVIVE the migration — adopting a pre-fix pad must not
  // reset its tripwire to zero, or the upgrade itself becomes the rollback.
  const rewound = JSON.parse(localStorage.getItem(mKey));
  const innerNow = JSON.parse(dec.decode(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(rewound.iv) }, mAtRest.key, unb64(rewound.ct),
  )));
  // NOTE: this assertion is necessary but NOT discriminating on its own — with
  // USED === sendOffset, writePadBlob's max(prev, record.sendOffset) satisfies it
  // even if readLegacyHW were dropped from the floor entirely. The case that
  // actually pins readLegacyHW is the separate block below.
  assert.strictEqual(innerNow.hwSend, USED, "the legacy watermark became the authenticated floor");

  // And the H-3 guard still bites once the pad IS post-fix: same PoC as above.
  const post = localStorage.getItem(mKey);
  m.sendOffset = USED + 500;
  await otp.savePadProgress(m, mAtRest);
  localStorage.setItem(mKey, post);
  localStorage.removeItem("sc.otp.wm.v1." + m.padId);
  await assert.rejects(
    otp.unlockPad(m.padId, PASS), /rollback record for this pad is missing/,
    "H-3 still fails closed for a v3 blob whose watermark was deleted",
  );
}
console.log("OK  v2→v3: a USED pre-fix pad migrates (and keeps its floor), H-3 still closed");

// --- the legacy watermark stays load-bearing AS A FLOOR ----------------------
// Review of bf6bcd2 (F-3): every existing assertion about the floor was
// satisfied by `record.sendOffset` alone, so deleting readLegacyHW() from the
// max() at otp.js survived the whole suite — while being a real break. The
// discriminating case is a pre-fix blob whose stored offset sits BELOW the
// legacy watermark: a partial restore, or a restore-from-backup that reverted
// the blob but not the plaintext tripwire. Only readLegacyHW() catches it.
//
// This is the one job bf6bcd2's rationale left for the legacy value after
// removing it from `knownUsedHere`, so it is the one that must be pinned.
{
  const f = await otp.generatePad({ label: "v2-floor", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const fAtRest = await otp.saveNewPad(f, PASS);
  const REACHED = 1234;
  f.sendOffset = REACHED;
  await otp.savePadProgress(f, fAtRest);

  // Pre-fix shape, blob rewound to 0, legacy tripwire still recording 1234.
  await makeV2Blob(f.padId, fAtRest.key, (inner) => { inner.sendOffset = 0; });
  localStorage.removeItem("sc.otp.wm.v1." + f.padId);
  localStorage.removeItem("sc.otp.used.v1." + f.padId);
  localStorage.setItem("sc.otp.hw.v1." + f.padId, String(REACHED));

  await assert.rejects(
    otp.unlockPad(f.padId, PASS), /rolled back/,
    "the legacy watermark must remain a FLOOR: a v2 blob below it is a rollback",
  );
}
console.log("OK  F-3: the legacy watermark is still load-bearing as a rollback floor");

// --- each knownUsedHere clause must be load-bearing ON ITS OWN ---------------
// Review of bf6bcd2 (F-4): the H-3 checks above delete sc.otp.wm.v1 but leave
// sc.otp.used.v1 on a v3 blob, so BOTH surviving clauses are true and neither is
// isolated — dropping either one survived the suite, and dropping the
// inner.hwSend clause is exploitable. bf6bcd2 deliberately narrowed this
// predicate to two clauses, so both need pinning separately.
{
  // (a) the AUTHENTICATED clause alone: v3 blob, every plaintext marker deleted.
  const a = await otp.generatePad({ label: "clause-inner", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const aAtRest = await otp.saveNewPad(a, PASS);
  a.sendOffset = 400;
  await otp.savePadProgress(a, aAtRest);
  localStorage.removeItem("sc.otp.wm.v1." + a.padId);
  localStorage.removeItem("sc.otp.used.v1." + a.padId);
  localStorage.removeItem("sc.otp.hw.v1." + a.padId);
  await assert.rejects(
    otp.unlockPad(a.padId, PASS), /rollback record for this pad is missing/,
    "inner.hwSend alone must trip H-3 once every plaintext marker is gone",
  );

  // (b) the usedKey clause alone: v2-shaped blob (no inner.hwSend), but this
  // device stamped sc.otp.used.v1 — so a missing watermark is DELETION, not a
  // pad that predates the scheme, and it must still fail closed.
  const b = await otp.generatePad({ label: "clause-used", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const bAtRest = await otp.saveNewPad(b, PASS);
  b.sendOffset = 300;
  await otp.savePadProgress(b, bAtRest);
  await makeV2Blob(b.padId, bAtRest.key);
  localStorage.removeItem("sc.otp.wm.v1." + b.padId);
  localStorage.removeItem("sc.otp.hw.v1." + b.padId);
  await assert.rejects(
    otp.unlockPad(b.padId, PASS), /rollback record for this pad is missing/,
    "usedKey alone must trip H-3 on a v2-shaped blob",
  );
}
console.log("OK  F-4: each knownUsedHere clause fails closed on its own");

// --- F-1: the reported two-time pad, and the native floor that closes it -----
// Review of bf6bcd2 found H-3 fully bypassable on a v2-shaped blob: with no
// `hwSend` inside the AEAD the whole defence was the plaintext `sc.otp.used.v1`,
// so restoring a v2 snapshot plus three removeItem()s reopened the pad at offset
// 0 and two messages encrypted under the same keystream.
//
// Two layers now stand in the way, and they are tested separately because they
// protect different platforms: the adoption gate (browser — user attention, the
// only control available where all storage is attacker-writable), and the native
// monotonic floor (Android — the pad ran, the floor says so, and no JS-side
// deletion can say otherwise).
{
  // -- browser: no native bridge. The attack must at minimum become LOUD. ----
  const v = await otp.generatePad({ label: "f1-browser", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const vAtRest = await otp.saveNewPad(v, PASS);
  v.sendOffset = 900;
  await otp.savePadProgress(v, vAtRest);

  await makeV2Blob(v.padId, vAtRest.key, (inner) => { inner.sendOffset = 0; });
  localStorage.removeItem("sc.otp.wm.v1." + v.padId);
  localStorage.removeItem("sc.otp.used.v1." + v.padId);
  localStorage.removeItem("sc.otp.hw.v1." + v.padId);   // the full 3-key PoC

  await assert.rejects(
    otp.unlockPad(v.padId, PASS),
    (e) => e.code === "LEGACY_PAD_ADOPTION" && e.suspicious === true,
    "F-1: the v2 two-time-pad PoC must not unlock silently",
  );

  // -- android: the native floor refuses it OUTRIGHT, adoption or not. -------
  // Fresh module instance so the bridge is captured at load, exactly as on the
  // device (otp.js reads globalThis.SecureChatPadFloor once, at import).
  const floors = new Map();
  globalThis.SecureChatPadFloor = {
    read: (id) => String(floors.has(id) ? floors.get(id) : -1),
    bump: (id, val) => {
      const n = Math.max(floors.has(id) ? floors.get(id) : -1, parseInt(val, 10));
      floors.set(id, n);
      return String(n);
    },
  };
  const otpN = await import("./otp.js?native=1");

  const n = await otpN.generatePad({ label: "f1-native", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const nAtRest = await otpN.saveNewPad(n, PASS);
  n.sendOffset = 900;
  await otpN.savePadProgress(n, nAtRest);
  assert.strictEqual(floors.get(n.padId), 900, "the native floor tracks the send offset");

  // Same PoC, plus consent — the strongest form of the attack.
  await makeV2Blob(n.padId, nAtRest.key, (inner) => { inner.sendOffset = 0; });
  localStorage.removeItem("sc.otp.wm.v1." + n.padId);
  localStorage.removeItem("sc.otp.used.v1." + n.padId);
  localStorage.removeItem("sc.otp.hw.v1." + n.padId);

  await assert.rejects(
    otpN.unlockPad(n.padId, PASS, { adoptLegacy: true }),
    /rollback record for this pad is missing/,
    "F-1: the native floor refuses the PoC even when the user adopts",
  );

  // The floor is monotone: a bump downwards must not lower it.
  globalThis.SecureChatPadFloor.bump(n.padId, "5");
  assert.strictEqual(floors.get(n.padId), 900, "the native floor never goes down");

  // A bridge that cannot be read fails CLOSED, never as "no floor".
  const broken = await (async () => {
    globalThis.SecureChatPadFloor = { read: () => "not-a-number", bump: () => "0" };
    const mod = await import("./otp.js?native=broken");
    const p = await mod.generatePad({ label: "f1-broken", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
    await mod.saveNewPad(p, PASS);
    return mod.unlockPad(p.padId, PASS).then(() => null, (e) => e.message);
  })();
  assert.match(broken, /damaged or forged/, "an unreadable native floor fails closed");

  delete globalThis.SecureChatPadFloor;
}
console.log("OK  F-1: v2 two-time-pad PoC is loud in the browser, refused outright on device");

// --- F-2: `exported` cannot be laundered through the migrating unlock --------
// The plaintext index used to be taken at face value on the one unlock that
// upgrades a pad, and then baked into the AEAD forever. Flipping it to false
// beforehand disarmed the double-export warning permanently — the warning that
// is all that stands between one pristine pad and two importers.
{
  const x = await otp.generatePad({ label: "f2", totalBytes: 8192, fingerBytes: new Uint8Array(0) });
  const xAtRest = await otp.saveNewPad(x, PASS);
  const unlocked = await otp.unlockPad(x.padId, PASS);
  await otp.markExported(unlocked.record, unlocked.atRest);

  // Pre-fix shape (no authenticated `exported`), and the attacker clears the
  // only remaining source before the upgrading unlock.
  await makeV2Blob(x.padId, xAtRest.key);
  localStorage.removeItem("sc.otp.wm.v1." + x.padId);
  localStorage.removeItem("sc.otp.used.v1." + x.padId);
  localStorage.removeItem("sc.otp.hw.v1." + x.padId);
  const idx = JSON.parse(localStorage.getItem("sc.otp.index.v1"));
  for (const e of idx) if (e.padId === x.padId) e.exported = false;
  localStorage.setItem("sc.otp.index.v1", JSON.stringify(idx));

  const adopted = await otp.unlockPad(x.padId, PASS, { adoptLegacy: true });
  assert.strictEqual(adopted.record.exported, true,
    "F-2: an unverifiable `exported` must resolve to TRUE, not to the attacker's plaintext false");
  assert.strictEqual((await otp.unlockPad(x.padId, PASS)).record.exported, true,
    "and it is authenticated from then on");
}
console.log("OK  F-2: `exported` cannot be cleared through the legacy migration");

console.log("\nAll OTP rollback checks passed.");

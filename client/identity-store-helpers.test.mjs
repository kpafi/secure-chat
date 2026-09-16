// Shared fakes for identity-store.test.mjs and the fresh-process cases it
// spawns. Named `*.test.mjs` so the deploy globs (backend L-02 404 list, the
// Android Sync task) keep it out of the shipped client like every other test
// file; it is a library, not a runnable test, and `npm test` does not list it.
export const PASS = "correct horse battery staple";

export function fakeLocalStorage() {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
    clear: () => m.clear(),
    key: (i) => [...m.keys()][i] ?? null,
    get length() { return m.size; },
    _dump: () => new Map(m),
    _restore: (snap) => { m.clear(); for (const [k, v] of snap) m.set(k, v); },
  };
}

// PadFloor.kt semantics, including the ROUND-3 F-4 one: a failed commit() moves
// the in-memory map (which `read` is backed by) and returns COMMIT_FAILED.
export function fakeFloor(opts = {}) {
  const slots = new Map();
  return {
    slots,
    read: (id) => (opts.tampered ? -2 : (slots.has(id) ? slots.get(id) : -1)),
    bump: (id, v) => {
      if (opts.tampered) return -2;
      const cur = slots.has(id) ? slots.get(id) : -1;
      const next = cur === -1 ? v : Math.max(cur, v);
      if (next === cur) return cur;
      slots.set(id, next);
      return (opts.commitFails && opts.commitFails(id, next)) ? -3 : next;
    },
  };
}

// A stand-in for identity.js that carries exactly the at-rest fields the store
// logic reads, with no PBKDF2 (600k iterations per export would make the suite
// take minutes). testRealIdentityCarriesTheCounter pins the REAL Identity to
// the same reading rules, so the two cannot drift apart unnoticed.
export function fakeIdentity(flags = {}) {
  return {
    deviceFlags: flags,
    generation: 0,
    floorClaim: false,
    upgraded: false,
    async export(pass) {
      return JSON.stringify({ pass, flags: this.deviceFlags, gen: this.generation, floor: this.floorClaim });
    },
  };
}

export async function fakeImport(blob, pass) {
  const o = JSON.parse(blob);
  if (o.pass !== pass) throw new Error("wrong passphrase or corrupted identity");
  const id = fakeIdentity(o.flags && typeof o.flags === "object" ? o.flags : {});
  id.generation = (Number.isInteger(o.gen) && o.gen >= 0) ? o.gen : 0;
  id.floorClaim = (o.floor === true || o.floor === false) ? o.floor : "unconfirmed";
  return id;
}

// A blob as every device wrote it before this change: gen and floor absent.
// With `flags` set it is the dominant deployed population (an established v3
// identity); without, it is "today's blob IS the archived artifact".
export function preFixBlob(flags) {
  return JSON.stringify(flags ? { pass: PASS, flags } : { pass: PASS });
}

// A DOM stub just large enough to import and DRIVE `app.js` in node.
//
// PROGRESS item 7a, asked for by four consecutive pentest rounds. `app.js`
// holds every relay-message decision in the client — the approval gate, the
// role gates, the suspect-pin refusal, the deprecated-alg latch — and it
// cannot be imported (it touches `document` at module scope), so every control
// over it is a REGEX over its source. Each of the last four rounds found a
// spelling that walked past one: `/**/ statement;`, a decoy in a comment,
// `wasPending ||= true`, `els.admitOk.click()`, `resolvePeerApproval?.(true)`,
// a `getPin` wrapper that strips a flag. A regex cannot bind name resolution;
// only running the code can.
//
// So: a stub, deliberately small and honest about what it is. It is NOT a
// browser — no layout, no CSS, no real event ordering — and a test written
// against it proves that app.js's DECISIONS are what they claim, not that the
// page renders. The source anchors stay: they are cheap and they catch
// deletion. This catches what they structurally cannot.
//
// Named `*.test.mjs` so every ship list (the relay's 404 rule, the deploy
// rsync, the APK Sync task) already excludes it, like identity-store-helpers.
import { readFileSync } from "node:fs";

const assert_ = (cond, msg) => { if (!cond) throw new Error(msg); };

const TEXT = Symbol("text");

class Node {
  constructor(text = "") {
    this[TEXT] = String(text);
    this.parentNode = null;
  }
  get textContent() { return this[TEXT]; }
  set textContent(v) { this[TEXT] = String(v); }
}

class El {
  constructor(tag = "div", id = null) {
    this.tagName = String(tag).toUpperCase();
    this.id = id || "";
    this.children = [];
    this.parentNode = null;
    this._listeners = new Map();
    this._attrs = Object.create(null);
    this[TEXT] = "";
    this.value = "";
    this.hidden = false;
    this.disabled = false;
    this.selected = false;
    this.checked = false;
    this.className = "";
    this.dataset = Object.create(null);
    this.style = Object.create(null);
    this.files = [];
    this.width = 300;
    this.height = 150;
    this.scrollTop = 0;
    this.scrollHeight = 0;
  }
  // textContent: reading concatenates descendants (that is how a test reads a
  // transcript line built from a <span> plus a text node); writing REPLACES
  // every child, which is how app.js clears a list before refilling it.
  get textContent() {
    if (this.children.length === 0) return this[TEXT];
    return this.children.map((c) => c.textContent).join("");
  }
  set textContent(v) {
    this.children = [];
    this[TEXT] = String(v);
  }
  get childElementCount() { return this.children.filter((c) => c instanceof El).length; }
  get firstElementChild() { return this.children.find((c) => c instanceof El) || null; }
  get lastElementChild() { return [...this.children].reverse().find((c) => c instanceof El) || null; }
  appendChild(c) {
    // Like the DOM: appending a node that already has a parent MOVES it.
    if (c.parentNode) c.parentNode.removeChild(c);
    c.parentNode = this; this.children.push(c); return c;
  }
  removeChild(c) {
    const i = this.children.indexOf(c);
    if (i >= 0) this.children.splice(i, 1);
    c.parentNode = null;
    return c;
  }
  remove() { if (this.parentNode) this.parentNode.removeChild(this); }
  // `append` takes nodes or strings, like the DOM (strings become text nodes).
  append(...xs) { for (const x of xs) this.appendChild(x instanceof El || x instanceof Node ? x : new Node(x)); }
  replaceChildren(...xs) { this.children = []; this[TEXT] = ""; this.append(...xs); }
  contains(n) {
    for (let p = n; p; p = p.parentNode) if (p === this) return true;
    return false;
  }
  // Sibling moves (the contact sheet reorders its two buttons).
  insertBefore(n, ref) {
    if (n.parentNode) n.parentNode.removeChild(n);
    const i = ref ? this.children.indexOf(ref) : -1;
    n.parentNode = this;
    this.children.splice(i < 0 ? this.children.length : i, 0, n);
    return n;
  }
  after(n) {
    const p = this.parentNode;
    if (!p) return;
    if (n.parentNode) n.parentNode.removeChild(n);
    n.parentNode = p;
    p.children.splice(p.children.indexOf(this) + 1, 0, n);
  }
  get nextElementSibling() {
    const p = this.parentNode;
    if (!p) return null;
    return p.children.slice(p.children.indexOf(this) + 1).find((c) => c instanceof El) || null;
  }
  closest(sel) {
    const match = compileSelector(sel);
    for (let p = this; p; p = p.parentNode) if (p instanceof El && match(p)) return p;
    return null;
  }
  toggleAttribute(k, on) { if (on) this.setAttribute(k, ""); else this.removeAttribute(k); return !!on; }
  setAttribute(k, v) { this._attrs[k] = String(v); }
  getAttribute(k) { return k in this._attrs ? this._attrs[k] : null; }
  removeAttribute(k) { delete this._attrs[k]; }
  get classList() {
    const self = this;
    const list = () => self.className.split(/\s+/).filter(Boolean);
    return {
      add(...c) { self.className = [...new Set([...list(), ...c])].join(" "); },
      remove(...c) { self.className = list().filter((x) => !c.includes(x)).join(" "); },
      toggle(c, on) { if (on === undefined ? list().includes(c) : !on) this.remove(c); else this.add(c); },
      contains(c) { return list().includes(c); },
    };
  }
  addEventListener(type, fn) {
    if (!this._listeners.has(type)) this._listeners.set(type, []);
    this._listeners.get(type).push(fn);
  }
  removeEventListener(type, fn) {
    const l = this._listeners.get(type);
    if (l) this._listeners.set(type, l.filter((f) => f !== fn));
  }
  // Returns the listeners' promises so a test can await what a click started.
  dispatch(type, ev = {}) {
    const l = this._listeners.get(type) || [];
    return Promise.all(l.map((f) => f.call(this, { type, target: this, preventDefault() {}, stopPropagation() {}, ...ev })));
  }
  click() { return this.dispatch("click"); }
  focus() { this._focused = true; }
  blur() { this._focused = false; }
  getContext() {
    return {
      strokeStyle: "", lineWidth: 0, lineCap: "",
      beginPath() {}, moveTo() {}, lineTo() {}, stroke() {}, clearRect() {}, fillRect() {},
    };
  }
  getBoundingClientRect() { return { left: 0, top: 0, width: this.width, height: this.height }; }
  querySelector(sel) { return this._find(sel)[0] || null; }
  querySelectorAll(sel) { return this._find(sel); }
  _find(sel) {
    const match = compileSelector(sel);
    const out = [];
    const walk = (n) => {
      for (const c of n.children) {
        if (c instanceof El) {
          if (match(c)) out.push(c);
          walk(c);
        }
      }
    };
    walk(this);
    return out;
  }
}

// A selector subset: `tag`, `.class`, `#id`, `[attr="v"]`, and combinations of
// those on ONE element (no descendant combinators — app.js does not use them).
function compileSelector(sel) {
  const s = String(sel).trim();
  const tag = (s.match(/^[a-zA-Z]+/) || [null])[0];
  const classes = [...s.matchAll(/\.([\w-]+)/g)].map((m) => m[1]);
  const id = (s.match(/#([\w-]+)/) || [null, null])[1];
  const attrs = [...s.matchAll(/\[([\w-]+)="([^"]*)"\]/g)].map((m) => [m[1], m[2]]);
  const pseudo = [...s.matchAll(/:([a-z]+)/g)].map((m) => m[1]);
  return (el) => {
    if (tag && el.tagName !== tag.toUpperCase()) return false;
    if (id && el.id !== id) return false;
    for (const ps of pseudo) {
      if (ps === "checked" && el.checked !== true) return false;
      if (ps === "disabled" && el.disabled !== true) return false;
    }
    for (const c of classes) if (!el.classList.contains(c)) return false;
    for (const [k, v] of attrs) {
      const actual = k === "name" || k === "value" ? (el[k] !== undefined && el[k] !== "" ? el[k] : el.getAttribute(k)) : el.getAttribute(k);
      if (String(actual) !== v) return false;
    }
    return true;
  };
}

// The stub's WebSocket: never connects, records what was sent, and lets a test
// play the relay by calling `deliver()`.
class StubWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;
  constructor(url) {
    this.url = url;
    this.readyState = StubWebSocket.CONNECTING;
    this.sent = [];
    StubWebSocket.last = this;
    this.onopen = null; this.onmessage = null; this.onclose = null; this.onerror = null;
  }
  send(data) { this.sent.push(typeof data === "string" ? JSON.parse(data) : data); }
  close() {
    if (this.readyState === StubWebSocket.CLOSED) return;
    this.readyState = StubWebSocket.CLOSED;
    if (this.onclose) this.onclose({});
  }
  /** Pretend the relay accepted the socket. */
  open() {
    this.readyState = StubWebSocket.OPEN;
    if (this.onopen) this.onopen({});
  }
  /** Pretend the relay sent a frame; resolves once app.js has handled it. */
  async deliver(obj) {
    if (!this.onmessage) throw new Error("app.js has not wired ws.onmessage yet");
    this.onmessage({ data: JSON.stringify(obj) });
    // app.js serialises frames through a promise chain; two turns of the
    // microtask queue plus a macrotask is enough for the handlers under test.
    await new Promise((r) => setTimeout(r, 0));
    await Promise.resolve();
  }
}

/**
 * Install the stub as globals. `htmlPath` is index.html: every id in it may be
 * looked up, and any OTHER id returns null — so an app.js that asks for an id
 * the page does not have crashes here, loudly, instead of silently reading
 * `null` in a browser.
 */
export function installDom(htmlPath) {
  const html = readFileSync(htmlPath, "utf8");
  const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]));
  const tagOf = (id) => {
    const m = new RegExp(`<([a-zA-Z]+)[^>]*\\bid="${id}"`).exec(html);
    return m ? m[1] : "div";
  };
  const registry = new Map();
  const asked = new Set();
  const get = (id) => {
    asked.add(id);
    if (!ids.has(id)) return null;
    if (!registry.has(id)) registry.set(id, new El(tagOf(id), id));
    return registry.get(id);
  };
  const body = new El("body");
  const doc = {
    body,
    getElementById: get,
    createElement: (tag) => new El(tag),
    createTextNode: (t) => new Node(t),
    // `#id > selector` (app.js: `#scrChat > .topbar`) resolves against the
    // id'd element's direct children; everything else searches the body.
    querySelector: (sel) => {
      const m = /^#([\w-]+)\s*>\s*(.+)$/.exec(String(sel).trim());
      if (m) { const host = get(m[1]); const match = compileSelector(m[2]); return host ? host.children.find((c) => c instanceof El && match(c)) || null : null; }
      return body.querySelector(sel);
    },
    querySelectorAll: (sel) => body.querySelectorAll(sel),
    addEventListener() {},
    visibilityState: "visible",
    activeElement: null,
  };
  const locks = {
    _chain: Promise.resolve(),
    request(_name, optsOrFn, maybeFn) {
      const fn = typeof optsOrFn === "function" ? optsOrFn : maybeFn;
      const run = () => Promise.resolve(fn({ name: _name }));
      const next = locks._chain.then(run, run);
      locks._chain = next.then(() => {}, () => {});
      return next;
    },
  };
  // `navigator` (and `performance`) are getter-only accessors on modern node's
  // globalThis, so a plain assignment throws — define them instead.
  const prev = new Map();
  const set = (k, v) => {
    prev.set(k, Object.getOwnPropertyDescriptor(globalThis, k));
    Object.defineProperty(globalThis, k, { value: v, writable: true, configurable: true, enumerable: false });
  };
  set("document", doc);
  set("location", { hash: "", search: "", pathname: "/", host: "127.0.0.1:8000", protocol: "http:", origin: "http://127.0.0.1:8000" });
  set("navigator", { clipboard: { writeText: async () => {} }, locks });
  set("performance", { now: () => Date.now() });
  set("WebSocket", StubWebSocket);
  set("confirm", () => true);
  set("prompt", () => "pw");
  set("alert", () => {});
  set("history", { replaceState() {} });
  // app.js listens for the window's own focus (the admission guard re-arm);
  // node's globalThis is not an EventTarget.
  if (typeof globalThis.addEventListener !== "function") set("addEventListener", () => {});
  globalThis.window = globalThis;

  return {
    ids, asked, registry, body,
    el: get,
    /**
     * Seed structure the stub cannot infer from an id. Everything app.js
     * touches is id-addressed EXCEPT three things, each seeded explicitly by
     * the test so it is obvious what is modelled and what is not: the
     * encryption radios (read with `input[name="alg"]:checked`), the tab bar's
     * nav items (`.navitem`), the chat top bar (`#scrChat > .topbar`), and the one `<p>` inside each locked pane
     * (rewritten with `querySelector("p")`).
     */
    seedAlgRadios(values, checked) {
      const host = get("algCards");
      for (const v of values) {
        const input = new El("input");
        input.setAttribute("name", "alg");
        input.value = v;
        input.checked = v === checked;
        host.appendChild(input);
      }
    },
    selectAlg(value) {
      for (const i of get("algCards").querySelectorAll('input[name="alg"]')) i.checked = i.value === value;
    },
    seedNavItems(views, hostId = "tabbar") {
      const host = get(hostId);
      for (const v of views) {
        const b = new El("button");
        b.className = "navitem";
        b.dataset.view = v;
        host.appendChild(b);
      }
    },
    seedChild(parentId, tag, className = "") {
      const host = get(parentId);
      assert_(host, `seedChild: index.html has no #${parentId}`);
      const c = new El(tag);
      c.className = className;
      host.appendChild(c);
      return c;
    },
    /** Every id app.js asked for that index.html does not define. */
    missingIds: () => [...asked].filter((id) => !ids.has(id)),
    /** The most recently constructed socket. */
    socket: () => StubWebSocket.last,
    lines: () => (registry.get("log") ? registry.get("log").children.map((c) => c.textContent) : []),
    restore() {
      for (const [k, d] of prev) {
        if (d) Object.defineProperty(globalThis, k, d);
        else delete globalThis[k];
      }
    },
  };
}

export { El, Node, StubWebSocket };

// secure-chat web client controller.
//
// Wires the UI to the relay WebSocket and to the client-side ciphers. The
// server only ever sees ciphertext; all encryption happens here. Rendering uses
// textContent exclusively (never innerHTML), so message contents can never be
// interpreted as markup.
//
// SECURITY — authenticated key exchange (closes the MITM gap):
//   For the handshake modes (DHKE / RSA) the ephemeral/public key is signed by
//   a long-term IDENTITY (Ed25519 + ML-DSA-65, see identity.js). The peer
//   verifies that dual signature against the identity bundle that arrived, then
//   the user confirms a SAFETY NUMBER in person. A relay that swaps the
//   ephemeral key cannot forge the signature; a relay that swaps the whole
//   identity is caught because the two endpoints then compute different safety
//   numbers. AES256-passphrase mode exchanges no keys and needs no identity.
//
//   The optional account directory (account.js / /api) lets you look a contact
//   up by username and pre-pin their bundle. It is a convenience, not a trust
//   root (it shares the relay's origin), so the in-person check still governs.

import { makeCipher, isAscii, bufToB64, b64ToBuf } from "./crypto.js";
import { Identity } from "./identity.js";
import { signHandshake, verifyHandshake, freshNonce, isValidNonce } from "./auth.js";
import * as account from "./account.js";

const $ = (id) => document.getElementById(id);
const els = {
  // identity
  idStatus: $("idStatus"), idPass: $("idPass"), idPassRow: $("idPassRow"),
  idCreate: $("idCreate"), idUnlock: $("idUnlock"), idExport: $("idExport"),
  idForget: $("idForget"), idFingerprint: $("idFingerprint"),
  // account directory
  account: $("account"), username: $("username"), register: $("register"),
  login: $("login"), accountStatus: $("accountStatus"),
  // setup
  room: $("room"), gen: $("gen"), alg: $("alg"), pass: $("pass"),
  passRow: $("passRow"), contactRow: $("contactRow"), contact: $("contact"),
  connect: $("connect"), status: $("status"), setup: $("setup"),
  // verification gate
  verify: $("verify"), verifyTitle: $("verifyTitle"), verifyHint: $("verifyHint"),
  safetyNumber: $("safetyNumber"), peerFingerprint: $("peerFingerprint"),
  verifyOk: $("verifyOk"), verifyNo: $("verifyNo"),
  // chat
  chat: $("chat"), log: $("log"),
  form: $("sendForm"), text: $("text"), send: $("send"), hint: $("hint"),
};

const enc = new TextEncoder();
const dec = new TextDecoder();
const ROOM_RE = /^[0-9a-f]{64}$/;

// Relay location. The web client is served BY the relay, so it talks to it
// same-origin (empty API base, ws:// to location.host). The Android app has no
// server origin — it serves this exact code from bundled assets and points at a
// REMOTE relay — so it sets `window.__SECURE_CHAT_RELAY__ = {api, ws}` before
// this module loads. When that global is absent, behaviour is byte-identical to
// the original same-origin web client.
const RELAY = (typeof window !== "undefined" && window.__SECURE_CHAT_RELAY__) || null;
const API_BASE = RELAY ? RELAY.api : ""; // same-origin unless the host app overrides

// localStorage keys. Private keys live only inside the passphrase-encrypted
// identity blob; pins hold peers' PUBLIC bundles only.
const LS_IDENTITY = "sc.identity.v1";
const LS_PINS = "sc.pins.v1";
const LS_USERNAME = "sc.username.v1";
const LS_LOOKUP_TOKEN = "sc.lookuptoken.v1"; // our directory lookup token

let ws = null;
let cipher = null;
let joined = false;
let verified = false; // in-person gate passed; gates RECEIVING as well as sending

let identity = null;       // unlocked Identity, or null
let myBundle = null;       // identity.publicBundle(), or null
let peerBundle = null;     // the peer identity bundle we received this session

let expectedPeerName = null;   // contact username we looked up (or null)
let expectedPeerBundle = null; // bundle fetched from the directory (or null)
let currentPinKey = null;      // pin key for the active session

// Per-connection handshake freshness (see auth.js). Each peer contributes a
// fresh random nonce; the signed transcript covers BOTH, so a validly-signed
// handshake from an earlier session of the same room cannot verify here.
let myNonce = null;       // our fresh nonce for this connection
let peerNonce = null;     // the peer's nonce (first-write-wins)
let helloAnswered = false; // answered the peer's hello (and sent our offer) once

// ---- handshake payload framing -------------------------------------------
// `key` messages carry base64(JSON(...)) of one of two payload kinds:
//   hello:     {hello: true, n, reply} — plaintext nonce exchange that seeds
//              handshake freshness. Sent on join (reply=false); the receiver
//              answers once (reply=true) and then sends its signed offer.
//   handshake: {pub, reply, idb, sig} — `pub` is the sender's ephemeral/public
//              key; `idb`+`sig` authenticate it over room + both nonces.
// The `reply` flags prevent infinite ping-pong in both phases: the later
// joiner initiates, the early joiner answers exactly once.

function packKey(obj) {
  return bufToB64(enc.encode(JSON.stringify(obj)));
}
function unpackKey(b64) {
  return JSON.parse(dec.decode(b64ToBuf(b64)));
}

// ---- pin store (TOFU + change detection) ----------------------------------
// Pins are keyed by `user:<name>` when a contact username is in play, else by
// `room:<id>`. A later session whose key differs from the pin warns loudly.

function loadPins() {
  try {
    return JSON.parse(localStorage.getItem(LS_PINS) || "{}");
  } catch {
    return {};
  }
}
function getPin(key) {
  return loadPins()[key] || null;
}
function savePin(key, bundle) {
  const pins = loadPins();
  pins[key] = { ed: bundle.ed, mldsa: bundle.mldsa };
  localStorage.setItem(LS_PINS, JSON.stringify(pins));
}
function sameBundle(a, b) {
  return !!a && !!b && a.ed === b.ed && a.mldsa === b.mldsa;
}

// ---- UI helpers -----------------------------------------------------------

function setStatus(text, cls = "") {
  els.status.textContent = text;
  els.status.className = "status" + (cls ? " " + cls : "");
}

function hint(text, isErr = false) {
  els.hint.textContent = text;
  els.hint.className = "hint" + (isErr ? " err" : "");
}

function accountStatus(text, cls = "") {
  els.accountStatus.textContent = text;
  els.accountStatus.className = "hint" + (cls ? " " + cls : "");
}

function addLine(kind, who, text) {
  const li = document.createElement("li");
  li.className = kind;
  if (who) {
    const w = document.createElement("span");
    w.className = "who";
    w.textContent = who;
    li.appendChild(w);
  }
  li.appendChild(document.createTextNode(text)); // textContent path: no markup
  els.log.appendChild(li);
  els.log.scrollTop = els.log.scrollHeight;
}

function enableSend(on) {
  els.text.disabled = !on;
  els.send.disabled = !on;
  if (on) els.text.focus();
}

function wsUrl() {
  if (RELAY) return RELAY.ws;
  const scheme = location.protocol === "https:" ? "wss" : "ws";
  return `${scheme}://${location.host}/ws`;
}

function algNeedsIdentity(alg) {
  return alg === "DHKE" || alg === "RSA" || alg === "PQKEM";
}

// ---- identity management --------------------------------------------------

function setIdentityStatus(text, cls = "") {
  els.idStatus.textContent = text;
  els.idStatus.className = "hint" + (cls ? " " + cls : "");
}

async function showIdentityUnlocked() {
  myBundle = identity.publicBundle();
  const fp = await identity.fingerprint();
  setIdentityStatus("Identity unlocked. Your contact verifies this in person.", "ok");
  els.idFingerprint.hidden = false;
  els.idFingerprint.textContent = "Your fingerprint: " + fp;
  els.idPassRow.hidden = true;
  els.idCreate.hidden = true;
  els.idUnlock.hidden = true;
  els.idExport.hidden = false;
  els.idForget.hidden = false;
  // The account directory is only meaningful once we hold an identity to bind.
  els.account.hidden = false;
  const savedName = localStorage.getItem(LS_USERNAME);
  const savedToken = localStorage.getItem(LS_LOOKUP_TOKEN);
  if (savedName && savedToken) {
    els.username.value = savedName;
    accountStatus(`Your contact handle: ${savedName}#${savedToken} — share it so contacts can look you up. Log in to prove control.`);
  } else if (savedName) {
    els.username.value = savedName;
    accountStatus(`Saved username: ${savedName}. Register (once) to get your shareable handle, or log in to prove control.`);
  } else {
    accountStatus("Optional: claim a username so contacts can look up this identity.");
  }
}

function refreshIdentityUI() {
  const stored = localStorage.getItem(LS_IDENTITY);
  if (identity) {
    showIdentityUnlocked();
    return;
  }
  els.idFingerprint.hidden = true;
  els.idExport.hidden = true;
  els.account.hidden = true;
  els.idPassRow.hidden = false;
  els.idCreate.hidden = !!stored;   // hide "Create" if one already exists
  els.idUnlock.hidden = !stored;
  els.idForget.hidden = !stored;
  if (stored) {
    setIdentityStatus("A locked identity is stored on this device. Enter its passphrase to unlock.");
  } else {
    setIdentityStatus("No identity on this device yet. Create one (needed for DHKE / RSA).");
  }
}

async function createIdentity() {
  const pass = els.idPass.value;
  if (!pass) {
    setIdentityStatus("Choose a passphrase first — it encrypts your private keys on this device.", "err");
    return;
  }
  if (localStorage.getItem(LS_IDENTITY)) {
    setIdentityStatus("An identity already exists here. Unlock it, or Forget it first.", "err");
    return;
  }
  setIdentityStatus("Generating identity keys (Ed25519 + ML-DSA-65)…");
  try {
    identity = await Identity.generate();
    const blob = await identity.export(pass);
    localStorage.setItem(LS_IDENTITY, blob);
    els.idPass.value = "";
    await showIdentityUnlocked();
  } catch (e) {
    identity = null;
    setIdentityStatus("Could not create identity: " + e.message, "err");
  }
}

async function unlockIdentity() {
  const pass = els.idPass.value;
  const blob = localStorage.getItem(LS_IDENTITY);
  if (!blob) {
    setIdentityStatus("Nothing to unlock — create an identity first.", "err");
    return;
  }
  if (!pass) {
    setIdentityStatus("Enter your identity passphrase to unlock.", "err");
    return;
  }
  setIdentityStatus("Unlocking…");
  try {
    identity = await Identity.import(blob, pass);
    els.idPass.value = "";
    await showIdentityUnlocked();
  } catch (e) {
    identity = null;
    setIdentityStatus("Wrong passphrase or corrupted identity.", "err");
  }
}

async function exportIdentity() {
  const blob = localStorage.getItem(LS_IDENTITY);
  if (!blob) return;
  try {
    await navigator.clipboard.writeText(blob);
    setIdentityStatus("Encrypted backup copied to clipboard. Keep it safe — it is useless without your passphrase.", "ok");
  } catch {
    setIdentityStatus("Could not access the clipboard. Backup not copied.", "err");
  }
}

function forgetIdentity() {
  if (!confirm("Remove this identity from the device? Without a backup you cannot recover it, and contacts will need to re-verify you.")) {
    return;
  }
  localStorage.removeItem(LS_IDENTITY);
  identity = null;
  myBundle = null;
  refreshIdentityUI();
}

// ---- account directory ----------------------------------------------------

async function registerAccount() {
  if (!identity) return;
  const username = els.username.value.trim();
  if (!account.isValidUsername(username)) {
    accountStatus("Username must be 3–32 chars from a-z 0-9 _ . -", "err");
    return;
  }
  accountStatus("Registering…");
  try {
    const { lookup_token } = await account.register(API_BASE, identity, username);
    localStorage.setItem(LS_USERNAME, username);
    localStorage.setItem(LS_LOOKUP_TOKEN, lookup_token);
    accountStatus(`Registered. Your contact handle is ${username}#${lookup_token} — share it (username alone will not resolve).`, "ok");
  } catch (e) {
    if (e.status === 409) {
      accountStatus(`"${username}" is already taken. Pick another (or log in if it is yours).`, "err");
    } else {
      accountStatus("Registration failed: " + e.message, "err");
    }
  }
}

async function loginAccount() {
  if (!identity) return;
  const username = els.username.value.trim();
  if (!account.isValidUsername(username)) {
    accountStatus("Username must be 3–32 chars from a-z 0-9 _ . -", "err");
    return;
  }
  accountStatus("Proving account control…");
  try {
    const { ttl } = await account.login(API_BASE, identity, username);
    localStorage.setItem(LS_USERNAME, username);
    accountStatus(`Logged in as "${username}" (session valid ~${Math.round(ttl / 60)} min). You control this account.`, "ok");
  } catch (e) {
    accountStatus("Login failed: " + e.message + " (is the username registered to this identity?)", "err");
  }
}

// ---- connection lifecycle -------------------------------------------------

async function connect() {
  const room = els.room.value.trim();
  const alg = els.alg.value;
  if (!ROOM_RE.test(room)) {
    hint("Room id must be exactly 64 hex characters. Use Generate.", true);
    return;
  }
  if (algNeedsIdentity(alg) && !identity) {
    hint("Create or unlock your identity above — it authenticates the " + alg + " key exchange.", true);
    return;
  }

  // Optional directory pre-fetch of the contact's identity bundle, keyed by
  // their `username#token` handle (a bare username no longer resolves).
  expectedPeerName = null;
  expectedPeerBundle = null;
  const contact = els.contact.value.trim();
  if (algNeedsIdentity(alg) && contact) {
    const parsed = account.parseHandle(contact);
    if (!parsed) {
      hint("Contact handle must look like username#token (as your contact shared it), or leave it blank to verify by safety number.", true);
      return;
    }
    setStatus("looking up contact…");
    try {
      expectedPeerBundle = await account.fetchBundle(API_BASE, contact);
    } catch (e) {
      hint("Directory lookup failed: " + e.message, true);
      setStatus("disconnected", "err");
      return;
    }
    if (!expectedPeerBundle) {
      hint(`No directory entry for "${parsed.username}" with that token. Check the handle, or leave it blank to verify by safety number.`, true);
      setStatus("disconnected", "err");
      return;
    }
    expectedPeerName = parsed.username;
  }

  try {
    cipher = makeCipher(alg, room, { passphrase: els.pass.value });
    await cipher.init();
  } catch (e) {
    hint("Setup failed: " + e.message, true);
    return;
  }

  peerBundle = null;
  verified = false;
  myNonce = freshNonce();
  peerNonce = null;
  helloAnswered = false;
  setStatus("connecting…");
  els.connect.disabled = true;
  try {
    // Constructing a WebSocket can throw synchronously — most importantly a
    // SecurityError when a secure page (the Android app's https asset origin)
    // tries to open an insecure ws:// relay (browser Mixed-Content rule). Catch
    // it so the UI reports the cause instead of hanging on "connecting…".
    ws = new WebSocket(wsUrl());
  } catch (e) {
    setStatus("connection blocked", "err");
    hint(
      "Could not open the relay connection: " + e.message +
      " — from the app's secure page the relay must be reachable over a trusted " +
      "transport: wss:// (TLS), a loopback address (127.0.0.1/localhost), or an " +
      ".onion. A plain ws:// host is blocked by the browser.",
      true,
    );
    els.connect.disabled = false;
    return;
  }

  ws.onopen = () => {
    ws.send(JSON.stringify({ type: "join", room }));
  };

  ws.onmessage = (ev) => handleMessage(room, ev.data);

  ws.onclose = () => {
    setStatus("disconnected", "err");
    joined = false;
    verified = false;
    enableSend(false);
    els.verify.hidden = true;
    els.setup.hidden = false;
    els.connect.disabled = false;
  };

  ws.onerror = () => setStatus("connection error", "err");
}

// Produce + sign the next handshake payload. Computed fresh each call (not
// cached): for PQKEM and RSA the initial "offer" and the "answer" are different
// payloads (RSA's answer transports the wrapped root secret), and each must
// carry its own signature. For DHKE the payload is idempotent, so re-signing
// the reply is just a negligible extra signature. The signature covers both
// per-connection nonces, so it is only meaningful once the hello exchange
// fixed them.
async function signedHandshake(room) {
  const pub = await cipher.handshakePayload();
  const sig = await signHandshake(identity, room, [myNonce, peerNonce], pub);
  return { pub, sig };
}

function sendSignedKey(room, reply) {
  return signedHandshake(room).then(({ pub, sig }) => {
    ws.send(JSON.stringify({
      type: "key", room, alg: els.alg.value,
      payload: packKey({ pub, reply, idb: myBundle, sig }),
    }));
  });
}

async function handleMessage(room, raw) {
  let m;
  try {
    m = JSON.parse(raw);
  } catch {
    return;
  }

  switch (m.type) {
    case "joined": {
      joined = true;
      els.setup.hidden = true;
      els.chat.hidden = false;
      setStatus("connected", "ok");
      addLine("sys", "", `joined room — encryption: ${els.alg.value}`);
      // Phase 1: announce our fresh session nonce. For handshake modes the
      // signed handshake follows once we also know the peer's nonce; for
      // AES256 (usesNonces, no key material on the wire) the nonces alone fix
      // the session's ratchet chains, closing cross-session frame replay.
      ws.send(JSON.stringify({
        type: "key", room, alg: els.alg.value,
        payload: packKey({ hello: true, n: myNonce, reply: false }),
      }));
      hint("Waiting for the other party to join / exchange keys…");
      break;
    }

    case "key": {
      try {
        const p = unpackKey(m.payload);

        // Phase 1 — hello: record the peer's session nonce (first-write-wins,
        // so a relay injecting extra hellos can't rotate it mid-handshake),
        // answer the initiator's hello once, then send our signed offer.
        if (p.hello) {
          if (!isValidNonce(p.n)) {
            throw new Error("peer sent a malformed session nonce");
          }
          // Our own 256-bit nonce coming back can only be a relay reflecting
          // our hello. Accepting it as the "peer" nonce would wedge the
          // handshake (first-write-wins would hold the bogus value); refusing
          // it keeps the slot open for the real peer's hello.
          if (p.n === myNonce) {
            throw new Error("reflected hello rejected");
          }
          if (peerNonce === null) peerNonce = p.n;
          if (!p.reply && !helloAnswered) {
            helloAnswered = true;
            ws.send(JSON.stringify({
              type: "key", room, alg: els.alg.value,
              payload: packKey({ hello: true, n: myNonce, reply: true }),
            }));
            if (cipher.needsHandshake) await sendSignedKey(room, false);
          }
          // AES256: both nonces known — derive the session's ratchet chains
          // and unlock. No identity gate here: the shared passphrase IS the
          // out-of-band verification, so receiving unlocks with sending.
          if (cipher.usesNonces && !cipher.ready) {
            await cipher.setNonces(myNonce, peerNonce);
            verified = true;
            enableSend(true);
            hint("Ready. Messages are end-to-end encrypted.");
          }
          break;
        }

        // Phase 2 — signed handshake. AES256 exchanges no key material, so a
        // handshake frame in that mode can only be relay-injected: refuse. For
        // the rest it is meaningless before the nonce exchange (no freshness).
        if (!cipher.needsHandshake) {
          throw new Error("unexpected key-exchange message for this mode");
        }
        const { pub, reply, idb, sig } = p;
        if (peerNonce === null) {
          throw new Error("peer sent a handshake before the nonce exchange");
        }

        // Authenticated modes: the signed identity bundle is mandatory and must
        // verify over THIS room + both session nonces + ephemeral key, or we
        // refuse outright. A replayed handshake from an earlier session fails
        // here: it cannot cover the nonce we generated for THIS connection.
        if (!idb || !sig) {
          throw new Error("peer sent an unauthenticated handshake");
        }
        const ok = await verifyHandshake(idb, room, [myNonce, peerNonce], pub, sig);
        if (!ok) {
          addLine("sys", "", "[handshake signature INVALID — refusing to connect; a relay may be tampering with the key exchange]");
          hint("Authentication failed — disconnecting. This is what a MITM attempt looks like.", true);
          if (ws) ws.close();
          return;
        }

        peerBundle = idb;
        await cipher.onPeerKey(pub);

        // Answer the initiator exactly once with our own signed key.
        if (!reply) {
          await sendSignedKey(room, true);
        }

        if (cipher.ready) {
          await enterVerification(room);
        }
      } catch (e) {
        hint("Key exchange failed: " + e.message, true);
      }
      break;
    }

    case "msg": {
      // The in-person gate covers RECEIVING too: a relay running a MITM session
      // passes signature verification (with its own identity), so anything it
      // sends before the user confirms the safety number would render as a
      // trusted "peer" line. Drop such frames — never decrypt or display them.
      if (!verified) {
        addLine("sys", "", "[message arrived before you verified the safety number — dropped]");
        break;
      }
      try {
        const text = await cipher.decrypt(m.payload);
        addLine("peer", "peer", text);
      } catch {
        addLine("sys", "", "[undecryptable message — wrong key or tampered]");
      }
      break;
    }

    case "error":
      hint("Server: " + (m.reason || "error"), true);
      break;
  }
}

// The in-person verification gate. The dual signature is already verified at
// this point; this step defeats a relay that swaps the WHOLE identity (the two
// honest endpoints would then see different safety numbers).
async function enterVerification(room) {
  const sn = await Identity.safetyNumber(myBundle, peerBundle);
  const peerFp = await Identity.fingerprintOf(peerBundle);
  els.safetyNumber.textContent = sn;
  els.peerFingerprint.textContent = "Contact fingerprint: " + peerFp;
  currentPinKey = expectedPeerName ? "user:" + expectedPeerName : "room:" + room;

  // If we looked the contact up by username, the live key must match what the
  // directory published. A mismatch is a strong red flag (though note the
  // directory is not a trust root — see account.js).
  if (expectedPeerBundle && !sameBundle(expectedPeerBundle, peerBundle)) {
    els.verify.hidden = false;
    els.verify.classList.add("changed");
    els.verifyTitle.textContent = `⚠ Key does NOT match the directory entry for "${expectedPeerName}"`;
    els.verifyHint.textContent =
      `The key presented in this room is different from the one the directory publishes for "${expectedPeerName}". ` +
      "Do NOT proceed unless you confirm this safety number with them in person.";
    addLine("sys", "", `[directory mismatch for "${expectedPeerName}" — verification required]`);
    hint("Directory mismatch — confirm the safety number in person before proceeding.", true);
    return;
  }

  const pin = getPin(currentPinKey);
  if (sameBundle(pin, peerBundle)) {
    // Seen and verified before — accept without re-prompting.
    addLine("sys", "", expectedPeerName
      ? `contact "${expectedPeerName}" matches your saved pin`
      : "contact identity matches your saved pin");
    unlockMessaging();
    return;
  }

  els.verify.hidden = false;
  if (pin) {
    // A pin exists but the key changed: loud warning, require re-verification.
    els.verify.classList.add("changed");
    els.verifyTitle.textContent = "⚠ Contact identity key CHANGED — re-verify in person";
    els.verifyHint.textContent =
      "The identity key you pinned before is different now. This happens if your contact reset their " +
      "device — but it is also what an interceptor looks like. Do NOT proceed until you have confirmed " +
      "this safety number with them over a trusted channel.";
    addLine("sys", "", "[pinned identity CHANGED — verification required]");
  } else {
    els.verify.classList.remove("changed");
    els.verifyTitle.textContent = "Verify your contact — in person";
    if (expectedPeerBundle) {
      addLine("sys", "", `key matches the directory entry for "${expectedPeerName}" — still verify in person`);
    }
  }
  hint("Confirm the safety number with your contact before messaging unlocks.");
}

function unlockMessaging() {
  verified = true;
  els.verify.hidden = true;
  enableSend(true);
  addLine("sys", "", "secure channel established");
  hint("Verified. Messages are end-to-end encrypted.", false);
  els.hint.className = "hint ok";
}

function onVerifyOk() {
  if (!peerBundle || !currentPinKey) return;
  savePin(currentPinKey, peerBundle);
  addLine("sys", "", "contact verified and pinned");
  unlockMessaging();
}

function onVerifyNo() {
  addLine("sys", "", "disconnected — contact not verified");
  if (ws) ws.close();
}

// One send at a time. The ciphers serialize concurrent encrypt/decrypt calls
// internally (see crypto.js CallQueue), so an overlapping send could no longer
// desync a ratchet — but a double-click/Enter-repeat should still not queue the
// same message twice, so the Send path is guarded here as defense in depth.
let sending = false;

async function sendText(e) {
  e.preventDefault();
  if (sending) return;
  const text = els.text.value;
  if (!text) return;
  if (!isAscii(text)) {
    hint("Only printable ASCII characters are allowed.", true);
    return;
  }
  if (!cipher || !cipher.ready) {
    hint("Secure channel not ready yet.", true);
    return;
  }
  sending = true;
  els.send.disabled = true;
  try {
    const payload = await cipher.encrypt(text);
    ws.send(JSON.stringify({ type: "msg", room: els.room.value.trim(), payload, alg: els.alg.value }));
    addLine("me", "me", text);
    els.text.value = "";
    hint("");
  } catch (err) {
    hint("Encryption failed: " + err.message, true);
  } finally {
    sending = false;
    // Re-enable only if the gate still allows messaging (the socket may have
    // closed while the encrypt was in flight, which disables the form).
    if (verified) els.send.disabled = false;
  }
}

// ---- wiring ---------------------------------------------------------------

els.idCreate.addEventListener("click", createIdentity);
els.idUnlock.addEventListener("click", unlockIdentity);
els.idExport.addEventListener("click", exportIdentity);
els.idForget.addEventListener("click", forgetIdentity);
els.register.addEventListener("click", registerAccount);
els.login.addEventListener("click", loginAccount);

els.gen.addEventListener("click", () => {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  els.room.value = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  hint("New 256-bit room id generated. Share it with exactly one person.");
});

function syncAlgUI() {
  const alg = els.alg.value;
  els.passRow.hidden = alg !== "AES256";
  els.contactRow.hidden = !algNeedsIdentity(alg); // lookup only aids DHKE/RSA
}
els.alg.addEventListener("change", syncAlgUI);

els.connect.addEventListener("click", connect);
els.form.addEventListener("submit", sendText);
els.verifyOk.addEventListener("click", onVerifyOk);
els.verifyNo.addEventListener("click", onVerifyNo);

syncAlgUI();
refreshIdentityUI();

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
import * as otp from "./otp.js";
import * as contacts from "./contacts.js";
import * as chats from "./chats.js";
import * as sealed from "./sealed.js";
import { generate as qrGenerate } from "lean-qr";

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
  room: $("room"), gen: $("gen"), algCards: $("algCards"), pass: $("pass"),
  passRow: $("passRow"), contactRow: $("contactRow"), contact: $("contact"),
  connect: $("connect"), status: $("status"), setup: $("setup"),
  // one-time pad
  otpPanel: $("otpPanel"), otpSelect: $("otpSelect"), otpForget: $("otpForget"),
  otpStatus: $("otpStatus"), otpSize: $("otpSize"), otpLabel: $("otpLabel"),
  otpEntropy: $("otpEntropy"), otpEntropyStatus: $("otpEntropyStatus"),
  otpGenerate: $("otpGenerate"), otpPass: $("otpPass"), otpXferPass: $("otpXferPass"),
  otpExport: $("otpExport"), otpImport: $("otpImport"), otpFile: $("otpFile"),
  // verification gate
  verify: $("verify"), verifyTitle: $("verifyTitle"), verifyHint: $("verifyHint"),
  safetyNumber: $("safetyNumber"), peerFingerprint: $("peerFingerprint"),
  verifyOk: $("verifyOk"), verifyNo: $("verifyNo"),
  // chat
  chat: $("chat"), log: $("log"),
  form: $("sendForm"), text: $("text"), send: $("send"), hint: $("hint"),
  // screens + chat top bar
  scrIdentity: $("scrIdentity"), scrRoom: $("scrRoom"), scrChat: $("scrChat"),
  toRoom: $("toRoom"), toIdentity: $("toIdentity"),
  roomShort: $("roomShort"), copyRoom: $("copyRoom"),
  chatStatus: $("chatStatus"), disconnect: $("disconnect"),
  // drawer menu + views
  menuBtn: $("menuBtn"), drawer: $("drawer"), scrim: $("scrim"),
  viewLive: $("viewLive"), viewUsers: $("viewUsers"), viewChats: $("viewChats"),
  viewProfile: $("viewProfile"),
  // profile view
  profileLocked: $("profileLocked"), profileUnlocked: $("profileUnlocked"),
  profileUnlockPass: $("profileUnlockPass"), profileUnlock: $("profileUnlock"),
  profileUnlockStatus: $("profileUnlockStatus"),
  usersUnlockPass: $("usersUnlockPass"), usersUnlock: $("usersUnlock"),
  usersUnlockStatus: $("usersUnlockStatus"),
  chatsUnlockPass: $("chatsUnlockPass"), chatsUnlock: $("chatsUnlock"),
  chatsUnlockStatus: $("chatsUnlockStatus"),
  profileName: $("profileName"), profileAvatar: $("profileAvatar"),
  profileHandleText: $("profileHandleText"),
  profileHandleActions: $("profileHandleActions"),
  profileCopyHandle: $("profileCopyHandle"), profileCopyInvite: $("profileCopyInvite"),
  profileQrRow: $("profileQrRow"), profileQr: $("profileQr"),
  profileFingerprint: $("profileFingerprint"), profileKeys: $("profileKeys"),
  profileStatus: $("profileStatus"),
  profileExport: $("profileExport"), profileForget: $("profileForget"),
  // users view
  usersLocked: $("usersLocked"), usersUnlocked: $("usersUnlocked"),
  addHandle: $("addHandle"), addContact: $("addContact"),
  usersStatus: $("usersStatus"), userList: $("userList"),
  myHandleText: $("myHandleText"), myHandleActions: $("myHandleActions"),
  copyHandle: $("copyHandle"), copyInvite: $("copyInvite"),
  // chats view
  chatsLocked: $("chatsLocked"), chatsUnlocked: $("chatsUnlocked"),
  chatsStatus: $("chatsStatus"), chatListWrap: $("chatListWrap"),
  chatNew: $("chatNew"), chatStart: $("chatStart"), chatList: $("chatList"),
  chatConvo: $("chatConvo"), chatBack: $("chatBack"), chatPeer: $("chatPeer"),
  chatPeerMark: $("chatPeerMark"), chatLog: $("chatLog"),
  chatForm: $("chatForm"), chatText: $("chatText"), chatSend: $("chatSend"),
  chatHint: $("chatHint"), chatMode: $("chatMode"), chatModeSel: $("chatModeSel"),
  chatPending: $("chatPending"),
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

// Pentest 2026-07-25 F-08: the Android shell has to decide whether a
// window.prompt() is asking for a secret so it can mask the input. It used to
// guess by looking for the word "passphrase" in the message, which silently
// un-masks a secret the moment a prompt is reworded. Secret prompts now carry
// an explicit marker the shell recognises and strips. It is added ONLY when
// running inside the app (RELAY is injected by MainActivity), so the browser
// still shows the plain message.
const SECRET_PROMPT_MARK = "[secure-chat:secret] ";
function promptSecret(message) {
  return prompt(RELAY ? SECRET_PROMPT_MARK + message : message);
}

// localStorage keys. Private keys live only inside the passphrase-encrypted
// identity blob; pins hold peers' PUBLIC bundles only.
const LS_IDENTITY = "sc.identity.v1";
const LS_PINS = "sc.pins.v1";
const LS_USERNAME = "sc.username.v1";
const LS_LOOKUP_TOKEN = "sc.lookuptoken.v1"; // our directory lookup token

let ws = null;
let cipher = null;
let otpRecord = null;      // the OTP pad in use this session (bytes + offsets), or null
let otpAtRest = null;      // cached at-rest key {key,salt,iters} for cheap re-saves
let otpLockRelease = null; // releases this pad's exclusive same-origin lock
const TAB_ID = Math.random().toString(36).slice(2) + Date.now().toString(36);
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
let msgChain = Promise.resolve(); // serializes async message handling (C-01)

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
// M-02: pins now live INSIDE the identity-encrypted, GCM-authenticated contact
// store (contacts.js), not plaintext localStorage — a forged pin can no longer
// be planted to auto-unlock a MITM. These require the store to be unlocked,
// which is guaranteed in the handshake modes (they need the identity anyway).

function getPin(key) {
  return contacts.isUnlocked() ? contacts.getPin(key) : null;
}
function savePin(key, bundle) {
  if (contacts.isUnlocked()) return contacts.savePin(key, bundle);
  return Promise.resolve();
}
// Audit 2026-07-18 H-01: bundle equality covers ALL FOUR public keys,
// normalized so missing and present never compare equal — a swapped or newly
// appeared ecdh/mlkem pair must never ride under an existing match.
function sameBundle(a, b) {
  return !!a && !!b && a.ed === b.ed && a.mldsa === b.mldsa &&
    (a.ecdh ?? null) === (b.ecdh ?? null) &&
    (a.mlkem ?? null) === (b.mlkem ?? null);
}
// Signing-only equality, used ONLY to tell "same identity, pin predates
// encryption-key coverage" apart from a full identity change in the pin flow.
function sameSigning(a, b) {
  return !!a && !!b && a.ed === b.ed && a.mldsa === b.mldsa;
}

// ---- UI helpers -----------------------------------------------------------

function setStatus(text, cls = "") {
  els.status.textContent = text;
  els.status.className = "status" + (cls ? " " + cls : "");
  // Mirror onto the chat top bar (only one of the two is visible at a time).
  els.chatStatus.textContent = text;
  els.chatStatus.className = els.status.className;
}

// The UI is a three-step flow; exactly one screen is visible at a time.
// Screens only group existing panels — no crypto or connection logic lives here.
function showScreen(name) {
  els.scrIdentity.hidden = name !== "identity";
  els.scrRoom.hidden = name !== "room";
  els.scrChat.hidden = name !== "chat";
}

// ---- drawer menu + top-level views ----------------------------------------
// Three views: live (the 3-step room flow), users (contact list + trust),
// chats (async DMs, later phase). Pure presentation — switching views never
// touches an active connection.

function setDrawer(open) {
  els.drawer.hidden = !open;
  els.scrim.hidden = !open;
}

function showView(name) {
  els.viewProfile.hidden = name !== "profile";
  els.viewLive.hidden = name !== "live";
  els.viewUsers.hidden = name !== "users";
  els.viewChats.hidden = name !== "chats";
  for (const b of els.drawer.querySelectorAll(".navitem")) {
    b.classList.toggle("active", b.dataset.view === name);
  }
  setDrawer(false);
  if (name === "profile") renderProfile();
  if (name === "users") refreshUsers();
  if (name === "chats") {
    refreshChats();
    pollMailbox(); // opportunistic fetch on entering the view
  }
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

// The encryption picker is a radio-card group (one input per mode); exactly one
// is always checked (DHKE by default in the markup).
function algValue() {
  return els.algCards.querySelector('input[name="alg"]:checked').value;
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
  els.toRoom.textContent = "Continue →";
  const savedName = localStorage.getItem(LS_USERNAME);
  const savedToken = localStorage.getItem(LS_LOOKUP_TOKEN);
  // Opportunistically (re-)publish the bundle for registered users so the
  // directory learns the encryption keys of an upgraded identity. The server
  // treats a same-identity re-registration as a bundle refresh; failures
  // (offline, foreign name) are non-fatal.
  if (savedName && savedToken && myBundle.ecdh) {
    account.register(API_BASE, identity, savedName).catch(() => {});
  }
  if (savedName && savedToken) {
    els.username.value = savedName;
    accountStatus(`Your contact handle: ${savedName}#${savedToken} — share it so contacts can look you up.`);
    // Async chats only DELIVER once we hold a directory session: pollMailbox
    // needs it, and it is the only way mail is ever fetched. Requiring a
    // separate "Log in" click meant a registered user could send messages that
    // their contact silently never received — log in automatically instead.
    autoLogin(savedName);
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
  els.toRoom.textContent = "Skip — no identity (AES-256 / OTP only) →";
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
    await unlockContacts(pass); // contact store shares the identity passphrase
    els.idPass.value = "";
    await showIdentityUnlocked();
  } catch (e) {
    identity = null;
    setIdentityStatus("Could not create identity: " + e.message, "err");
  }
}

// Unlock the stored identity with `pass`. Shared by the Live-room control and
// the per-view unlock rows (Profile / Users / Chats), so a new tab opened from
// an invite link can unlock where the user actually is instead of sending them
// back to the Live room. Returns null on success, or an error message.
async function unlockWithPassphrase(pass) {
  const blob = localStorage.getItem(LS_IDENTITY);
  if (!blob) return "Nothing to unlock — create an identity in the Live room first.";
  if (!pass) return "Enter your identity passphrase to unlock.";
  try {
    identity = await Identity.import(blob, pass);
    if (identity.upgraded) {
      // Pre-v3 blob: encryption keys were just added — persist them so the
      // upgrade happens exactly once, then re-publish the bundle below.
      localStorage.setItem(LS_IDENTITY, await identity.export(pass));
    }
    await unlockContacts(pass); // contact store shares the identity passphrase
    await showIdentityUnlocked();
    return null;
  } catch (e) {
    identity = null;
    return "Wrong passphrase or corrupted identity.";
  }
}

async function unlockIdentity() {
  const pass = els.idPass.value;
  if (!localStorage.getItem(LS_IDENTITY)) {
    setIdentityStatus("Nothing to unlock — create an identity first.", "err");
    return;
  }
  if (!pass) {
    setIdentityStatus("Enter your identity passphrase to unlock.", "err");
    return;
  }
  setIdentityStatus("Unlocking…");
  const err = await unlockWithPassphrase(pass);
  if (err) {
    setIdentityStatus(err, "err");
    return;
  }
  els.idPass.value = "";
}

// Wire an in-view unlock row. `render` re-draws that view once unlocked.
function wireViewUnlock(passEl, btnEl, statusFn, render) {
  const go = async () => {
    const pass = passEl.value;
    statusFn("Unlocking…");
    const err = await unlockWithPassphrase(pass);
    if (err) {
      statusFn(err, true);
      return;
    }
    passEl.value = "";
    statusFn("");
    // An invite link may have been waiting on the identity (Users view).
    applyPendingInvite();
    render();
  };
  btnEl.addEventListener("click", go);
  // Enter in the passphrase field should submit, like every other password box.
  passEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); go(); }
  });
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
  contacts.wipe(); // bound to the identity passphrase; unusable without it
  chats.wipe();
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
    // Registering is when a first-time user gets their handle, and it is the
    // moment they expect chats to work. Take the directory session now, or they
    // would send messages fine while silently receiving nothing until they
    // happened to press "Log in".
    await autoLogin(username);
  } catch (e) {
    if (e.status === 409) {
      accountStatus(`"${username}" is already taken. Pick another (or log in if it is yours).`, "err");
    } else {
      accountStatus("Registration failed: " + e.message, "err");
    }
  }
}

// Silent directory login for an already-registered identity. Never shouts on
// failure (offline, or the name belongs to another identity) — the explicit
// "Log in" button is still there and reports properly.
let autoLoginRunning = false;
async function autoLogin(username) {
  if (!identity || apiToken || autoLoginRunning) return false;
  if (!account.isValidUsername(username)) return false;
  autoLoginRunning = true;
  try {
    const { token } = await account.login(API_BASE, identity, username);
    apiToken = token;
    startMailboxPolling();
    renderProfile();
    if (!els.viewChats.hidden) refreshChats();
    return true;
  } catch {
    return false;
  } finally {
    autoLoginRunning = false;
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
    const { token, ttl } = await account.login(API_BASE, identity, username);
    apiToken = token; // kept in memory only — enables vouches + mailbox fetch
    startMailboxPolling();
    localStorage.setItem(LS_USERNAME, username);
    accountStatus(`Logged in as "${username}" (session valid ~${Math.round(ttl / 60)} min). You control this account.`, "ok");
  } catch (e) {
    accountStatus("Login failed: " + e.message + " (is the username registered to this identity?)", "err");
  }
}

// ---- users view (contact list + safety marks) -----------------------------

let contactsError = null; // unlock failure message, shown in the Users view
let apiToken = null;      // directory session token (from Log in), memory only

// Unlock the contact store with the identity passphrase. Called wherever the
// identity itself is created/unlocked, BEFORE the passphrase field is cleared.
async function unlockContacts(pass) {
  try {
    await contacts.unlock(pass);
    contactsError = null;
  } catch (e) {
    contactsError = e.message;
  }
  try {
    await chats.unlock(pass); // chat history shares the at-rest posture
  } catch (e) {
    contactsError = contactsError || e.message;
  }
}

function usersStatus(text, isErr = false) {
  els.usersStatus.textContent = text;
  els.usersStatus.className = "hint" + (isErr ? " err" : "");
}

function refreshUsers() {
  const unlocked = contacts.isUnlocked();
  els.usersLocked.hidden = unlocked;
  els.usersUnlocked.hidden = !unlocked;
  if (!unlocked) {
    els.usersLocked.querySelector("p").textContent = contactsError
      ? "Contact store error: " + contactsError +
        " (Forget + recreate the identity resets it — contacts are bound to the identity passphrase.)"
      : "Contacts are stored encrypted under your identity passphrase. " +
        "Enter it to unlock them here.";
    return;
  }
  renderMyHandle();
  applyPendingInvite();
  renderUserList();
}

// My shareable handle (username#token) — only exists after registering, since
// the token is minted at registration (anti-enumeration; a bare username never
// resolves).
function myHandle() {
  const n = localStorage.getItem(LS_USERNAME);
  const t = localStorage.getItem(LS_LOOKUP_TOKEN);
  return n && t ? n + "#" + t : null;
}

// An invite link carries the handle in the URL FRAGMENT (`#add=...`), so it
// stays client-side and never reaches the server. It is a convenience only:
// opening it PRE-FILLS the add field — it never auto-adds and never verifies,
// so it grants no trust a pasted handle wouldn't (trust still needs the
// in-person safety-number check).
function inviteLink(handle) {
  return location.origin + location.pathname + "#add=" + encodeURIComponent(handle);
}

// Render "your handle" into a text element + toggle its copy actions. Shared by
// the Users view and the Profile view so both stay identical (one source).
// Toggles `ok` rather than assigning className, so each call site keeps its own
// base classes (the Users view is a `.hint`, the Profile view an `.idhead-sub`).
function renderHandleInto(textEl, actionsEl) {
  const h = myHandle();
  if (h) {
    textEl.textContent = h;
    textEl.classList.add("ok");
    if (actionsEl) actionsEl.hidden = false;
  } else {
    textEl.textContent =
      "Register a username in the Live room (Step 1) to get a shareable handle.";
    textEl.classList.remove("ok");
    if (actionsEl) actionsEl.hidden = true;
  }
  return h;
}

function renderMyHandle() {
  renderHandleInto(els.myHandleText, els.myHandleActions);
}

// ---- profile view (presentation-only: shows existing local state) ---------
// Adds no network calls and no new trust surface; the handle/fingerprint shown
// are already public-shareable. textContent only, matching the rest of app.js.
function renderProfile() {
  const unlocked = !!identity;
  els.profileLocked.hidden = unlocked;
  els.profileUnlocked.hidden = !unlocked;
  if (!unlocked) return;

  // Identity head: initial + name (registered username, or not-yet-registered).
  const name = localStorage.getItem(LS_USERNAME);
  els.profileName.textContent = name || "not registered yet";
  els.profileName.classList.toggle("none", !name);
  els.profileAvatar.textContent = name ? name[0] : "·";

  // Handle + copy/invite (shared with the Users view) and the invite QR.
  const h = renderHandleInto(els.profileHandleText, els.profileHandleActions);
  if (h) {
    els.profileQrRow.hidden = false;
    drawInviteQr(inviteLink(h));
  } else {
    els.profileQrRow.hidden = true;
  }

  // Fingerprint — the string contacts compare in person (all four keys, H-01).
  els.profileFingerprint.textContent = "…";
  identity.fingerprint().then((fp) => { els.profileFingerprint.textContent = fp; });

  // Key details, as a label/value grid.
  els.profileKeys.textContent = "";
  for (const [term, value] of [
    ["Signing", "Ed25519 · ML-DSA-65"],
    ["Encryption", "ECDH P-256 · ML-KEM-768"],
  ]) {
    const dt = document.createElement("dt");
    dt.textContent = term;
    const dd = document.createElement("dd");
    dd.textContent = value;
    els.profileKeys.append(dt, dd);
  }

  // Status, as chips — each one on/off at a glance.
  let n = 0;
  try { if (contacts.isUnlocked()) n = contacts.list().length; } catch { /* locked */ }
  els.profileStatus.textContent = "";
  for (const [label, on] of [
    ["identity unlocked", true],
    [name ? "registered" : "not registered", !!name],
    [apiToken ? "logged in" : "not logged in", !!apiToken],
    [`${n} saved ${n === 1 ? "user" : "users"}`, n > 0],
  ]) {
    const chip = document.createElement("span");
    chip.className = "chip " + (on ? "on" : "off");
    chip.textContent = label;
    els.profileStatus.appendChild(chip);
  }
}

// Render the invite link as a QR into the profile canvas (lean-qr, vendored —
// no network, CSP-safe). Wrapped so a QR failure never blocks the rest of the
// view.
function drawInviteQr(link) {
  try {
    const code = qrGenerate(link);
    code.toCanvas(els.profileQr, {
      on: [0, 0, 0, 255],
      off: [0, 0, 0, 0],
    });
  } catch {
    els.profileQrRow.hidden = true;
  }
}

// If the app was opened from an invite link, drop the target handle into the
// add field for the user to review and Add. Runs once (cleared after use).
let pendingInviteHandle = null;
function applyPendingInvite() {
  if (!pendingInviteHandle) return;
  const handle = pendingInviteHandle;
  pendingInviteHandle = null;
  if (contacts.get(account.parseHandle(handle).username)) {
    usersStatus(`"${account.parseHandle(handle).username}" is already in your users list.`);
    return;
  }
  els.addHandle.value = handle;
  usersStatus("Someone shared this handle with you — review it and click Add (you still verify them in person to trust the key).");
}

// A deliberate empty state in the well the list will occupy, instead of the
// list silently collapsing to nothing.
function emptyRow(title, detail) {
  const li = document.createElement("li");
  li.className = "empty";
  const t = document.createElement("span");
  t.className = "empty-title";
  t.textContent = title;
  li.append(t, document.createTextNode(detail));
  return li;
}

function renderUserList() {
  els.userList.textContent = "";
  const all = contacts.list().sort((a, b) => a.username.localeCompare(b.username));
  if (all.length === 0) {
    els.userList.appendChild(emptyRow(
      "No users yet",
      "Add someone with their username#token handle above — then compare fingerprints in person to verify them.",
    ));
    return;
  }
  for (const c of all) {
    const li = document.createElement("li");

    const head = document.createElement("div");
    head.className = "u-head";
    const name = document.createElement("span");
    name.className = "u-name";
    name.textContent = c.username;
    const mark = document.createElement("span");
    let markText = "⚪ unverified", markCls = "";
    if (c.verified) {
      markText = "🟢 verified by you";
      markCls = " ok";
    } else if (c.vouchedBy && c.vouchedBy.length) {
      // Middle trust level: someone YOU verified has published a vouch whose
      // signature checked out against YOUR pinned copy of their keys.
      markText = "🟡 vouched by " + c.vouchedBy.join(", ");
      markCls = " mid";
    }
    mark.className = "u-mark" + markCls;
    mark.textContent = markText;
    head.append(name, mark);
    li.appendChild(head);

    // F-01: an auto-created contact's self-claimed handle is displayed as a
    // claim, clearly separated from the neutral local label, so a stranger
    // cannot make themselves LOOK like a name you recognise.
    if (c.claimedName) {
      const claim = document.createElement("div");
      claim.className = "u-claim";
      claim.textContent = `claims to be "${c.claimedName}" — unverified, they chose this name themselves`;
      li.appendChild(claim);
    }

    if (c.keyChangedAt && !c.verified) {
      const warn = document.createElement("div");
      warn.className = "hint err";
      warn.textContent = "⚠ this user's key CHANGED since you saved them — re-verify in person before trusting";
      li.appendChild(warn);
    } else if (c.reverify && !c.verified) {
      // Set by the H-01 store migration: the old 🟢 was compared against a
      // fingerprint that did not cover the encryption keys.
      const warn = document.createElement("div");
      warn.className = "hint err";
      warn.textContent = "⚠ verification reset — the fingerprint format now also covers this user's encryption keys; compare it again in person";
      li.appendChild(warn);
    }

    const fp = document.createElement("div");
    fp.className = "u-fp";
    fp.textContent = "fingerprint: …";
    // Full four-key fingerprint (audit 2026-07-18 H-01): the value the user
    // compares in person must also cover the keys that seal async messages.
    Identity.fingerprintOf({
      ed: c.ed, mldsa: c.mldsa, ecdh: c.ecdh ?? null, mlkem: c.mlkem ?? null,
    }).then((f) => {
      fp.textContent = "fingerprint: " + f;
    }).catch(() => {
      // F-07: _bundleBytes now rejects wrong-length keys. Say so instead of
      // leaving the row showing "…" forever — a contact whose stored keys are
      // malformed cannot be verified and must not look like it is loading.
      fp.textContent = "fingerprint unavailable — stored keys are malformed";
      fp.className = "u-fp err";
    });
    li.appendChild(fp);

    const row = document.createElement("div");
    row.className = "inline u-actions";
    const vbtn = document.createElement("button");
    vbtn.type = "button";
    vbtn.className = c.verified ? "ghost" : "";
    vbtn.textContent = c.verified ? "Unverify" : "Verified in person ✓";
    vbtn.addEventListener("click", async () => {
      if (!c.verified && !confirm(
        `Mark "${c.username}" as verified ONLY if you compared this fingerprint with them in person ` +
        "(or over a call where you recognise their voice). Continue?",
      )) return;
      await contacts.setVerified(c.username, !c.verified);
      let statusMsg = null, statusErr = false;
      if (!c.verified) {
        // Just turned 🟢 — offer to publish a signed vouch so users who
        // verified YOU can see this contact as 🟡 "vouched by you". Opt-in.
        if (apiToken && identity && confirm(
          `Also publish a signed vouch for "${c.username}"? Anyone who has verified YOU ` +
          "will then see them as 🟡 vouched-by-you. (This reveals publicly that you know them.)",
        )) {
          try {
            // Vouch over the FULL in-person-verified bundle incl. encryption
            // keys (H-01) so the 🟡 mark attests the keys used to seal async
            // messages, not just the signing identity.
            await account.vouch(API_BASE, identity, apiToken, dirName(c), {
              ed: c.ed, mldsa: c.mldsa, ecdh: c.ecdh ?? null, mlkem: c.mlkem ?? null,
            });
            statusMsg = `Vouch for "${c.username}" published.`;
          } catch (e) {
            statusMsg = "Could not publish the vouch: " + e.message;
            statusErr = true;
          }
        } else if (!apiToken) {
          statusMsg = "Tip: Log in (Live room → step 1) to also publish a signed vouch for people you verify.";
        }
      } else if (apiToken) {
        // Turned back to unverified — retract a published vouch if any.
        account.unvouch(API_BASE, apiToken, dirName(c)).catch(() => { /* none published */ });
      }
      renderUserList(); // clears the status line…
      if (statusMsg) usersStatus(statusMsg, statusErr); // …so report after
    });
    const rbtn = document.createElement("button");
    rbtn.type = "button";
    rbtn.className = "danger";
    rbtn.textContent = "Remove";
    rbtn.addEventListener("click", async () => {
      if (!confirm(`Remove "${c.username}" (and your verification of them) from this device?`)) return;
      await contacts.remove(c.username);
      renderUserList();
    });
    row.append(vbtn, rbtn);
    li.appendChild(row);

    els.userList.appendChild(li);
  }
  usersStatus("");
  refreshVouchMarks(); // opportunistic 🟡 refresh; re-renders only on change
}

// Refresh the 🟡 marks: fetch vouches for unverified contacts and validate
// them LOCALLY — a vouch counts only if (a) the voucher is a contact YOU
// verified in person, (b) the server-returned voucher keys equal your pinned
// copy, and (c) the dual signature verifies over the target bundle YOU hold.
// A lying directory therefore cannot invent a 🟡 mark.
const VOUCH_RECHECK_MS = 10 * 60 * 1000;
let vouchRefreshRunning = false;

async function refreshVouchMarks() {
  if (vouchRefreshRunning || !contacts.isUnlocked()) return;
  vouchRefreshRunning = true;
  let changed = false;
  try {
    for (const c of contacts.list()) {
      if (c.verified || !c.token) continue;
      if (c.vouchCheckedAt && Date.now() - c.vouchCheckedAt < VOUCH_RECHECK_MS) continue;
      let raw;
      try {
        raw = await account.fetchVouches(API_BASE, mailHandle(c));
      } catch {
        continue; // offline / rate-limited: leave the cache, retry next render
      }
      const names = [];
      for (const v of raw || []) {
        const voucher = contacts.get(v.voucher);
        if (!voucher || !voucher.verified) continue;
        if (voucher.ed !== v.voucher_ed || voucher.mldsa !== v.voucher_mldsa) continue;
        // H-01: verify the vouch over the FULL bundle WE hold for this contact,
        // including the encryption keys. If a malicious directory swapped the
        // ecdh/mlkem it served us, the v2 vouch signature (which the in-person
        // voucher made over the REAL enc keys) no longer matches, so no 🟡 is
        // awarded — the mark can never vouch for keys the directory forged.
        const ok = await Identity.verify(
          { ed: voucher.ed, mldsa: voucher.mldsa },
          account.vouchMessageBytes(dirName(c), {
            ed: c.ed, mldsa: c.mldsa, ecdh: c.ecdh ?? null, mlkem: c.mlkem ?? null,
          }),
          { ed: v.sig, mldsa: v.mldsa_sig },
        ).catch(() => false);
        if (ok) names.push(v.voucher);
      }
      await contacts.setVouches(c.username, names);
      changed = true;
    }
  } finally {
    vouchRefreshRunning = false;
  }
  if (changed && !els.viewUsers.hidden) renderUserList();
}

async function addContactFromHandle() {
  const handle = els.addHandle.value.trim();
  const parsed = account.parseHandle(handle);
  if (!parsed) {
    usersStatus("A handle looks like username#token — exactly as the user shared it.", true);
    return;
  }
  usersStatus("Looking up…");
  let bundle;
  try {
    bundle = await account.fetchBundle(API_BASE, handle);
  } catch (e) {
    usersStatus("Directory lookup failed: " + e.message, true);
    return;
  }
  if (!bundle) {
    usersStatus(`No directory entry for "${parsed.username}" with that token.`, true);
    return;
  }
  // Never auto-verify from the fetched bundle: the directory is not a trust
  // root, and a pin only attests the SIGNING identity, not the encryption keys
  // (H-01). upsert() keeps an existing 🟢 only when EVERY key (incl. ecdh/mlkem)
  // still matches what was verified in person; any change drops it to ⚪.
  const before = contacts.get(parsed.username);
  await contacts.upsert({
    username: parsed.username, token: parsed.token,
    ed: bundle.ed, mldsa: bundle.mldsa,
    ecdh: bundle.ecdh || null, mlkem: bundle.mlkem || null,
  });
  const after = contacts.get(parsed.username);
  els.addHandle.value = "";
  usersStatus(after.verified
    ? `Updated "${parsed.username}" — keys match what you verified in person (🟢).`
    : (before && before.verified
      ? `⚠ "${parsed.username}" — the fetched keys DIFFER from what you verified; reset to ⚪. Re-verify in person.`
      : `Added "${parsed.username}" (⚪ unverified — compare fingerprints in person to trust this key).`));
  renderUserList();
}

// ---- chats view (async 1:1 via the sealed mailbox) ------------------------

let activeChat = null;    // username of the open conversation, or null
let mailboxTimer = null;  // polling interval handle

function chatsStatus(text, isErr = false) {
  els.chatsStatus.textContent = text;
  els.chatsStatus.className = "hint" + (isErr ? " err" : "");
}

function chatHint(text, isErr = false) {
  els.chatHint.textContent = text;
  els.chatHint.className = "hint" + (isErr ? " err" : "");
}

function contactMark(c) {
  if (!c) return "⚪ not in your users list";
  if (c.verified) return "🟢 verified by you";
  if (c.vouchedBy && c.vouchedBy.length) return "🟡 vouched by " + c.vouchedBy.join(", ");
  return "⚪ unverified";
}

function refreshChats() {
  const unlocked = chats.isUnlocked() && contacts.isUnlocked();
  els.chatsLocked.hidden = unlocked;
  els.chatsUnlocked.hidden = !unlocked;
  if (!unlocked) return;
  if (!apiToken) {
    chatsStatus("You can send now; to RECEIVE messages, log in (Live room → step 1) so the mailbox can be fetched.");
  } else {
    chatsStatus("");
  }
  // "Start a chat" picker: saved users not already in the chat list.
  els.chatNew.textContent = "";
  const have = new Set(chats.list().map((c) => c.username));
  const candidates = contacts.list().filter((c) => !have.has(c.username));
  const none = document.createElement("option");
  none.value = "";
  none.textContent = candidates.length ? "— pick a user —" : "— add users in the Users view first —";
  els.chatNew.appendChild(none);
  for (const c of candidates) {
    const o = document.createElement("option");
    o.value = c.username;
    o.textContent = c.username;
    els.chatNew.appendChild(o);
  }
  if (activeChat) {
    renderConversation();
  } else {
    renderChatList();
  }
}

function renderChatList() {
  els.chatConvo.hidden = true;
  els.chatListWrap.hidden = false;
  els.chatList.textContent = "";
  const open = chats.list();
  if (open.length === 0) {
    els.chatList.appendChild(emptyRow(
      "No chats yet",
      "Pick a saved user above and open a chat — messages are sealed end-to-end and wait on the relay until they fetch them.",
    ));
  }
  for (const chat of open) {
    const c = contacts.get(chat.username);
    const li = document.createElement("li");
    li.className = "chatrow";
    const head = document.createElement("div");
    head.className = "u-head";
    const name = document.createElement("span");
    name.className = "u-name";
    name.textContent = chat.username;
    const mark = document.createElement("span");
    mark.className = "u-mark" + (c && c.verified ? " ok" : c && c.vouchedBy && c.vouchedBy.length ? " mid" : "");
    mark.textContent = contactMark(c);
    head.append(name, mark);
    const last = chat.messages[chat.messages.length - 1];
    const preview = document.createElement("div");
    preview.className = "u-fp";
    preview.textContent = last ? (last.dir === "out" ? "you: " : "") + last.text.slice(0, 60) : "no messages yet";
    li.append(head, preview);
    li.addEventListener("click", () => openChat(chat.username));
    els.chatList.appendChild(li);
  }
}

async function openChat(username) {
  await chats.ensure(username);
  activeChat = username;
  renderConversation();
}

function renderConversation() {
  const chat = chats.get(activeChat);
  if (!chat) return;
  els.chatListWrap.hidden = true;
  els.chatConvo.hidden = false;
  const c = contacts.get(activeChat);
  els.chatPeer.textContent = activeChat;
  els.chatPeerMark.className = "u-mark" + (c && c.verified ? " ok" : c && c.vouchedBy && c.vouchedBy.length ? " mid" : "");
  els.chatPeerMark.textContent = contactMark(c);
  els.chatLog.textContent = "";
  for (const m of chat.messages) {
    const li = document.createElement("li");
    li.className = m.dir === "out" ? "me" : "peer";
    li.textContent = m.text; // textContent path: no markup, ever
    els.chatLog.appendChild(li);
  }
  els.chatLog.scrollTop = els.chatLog.scrollHeight;

  // Mode indicator + picker (picker shows the CURRENT mode; changing it
  // proposes a switch).
  els.chatMode.textContent = "🔒 " + chat.mode;
  els.chatModeSel.value = chat.mode;

  // Pending mode negotiation banner.
  renderPending(chat);

  if (!c) {
    chatHint("This sender is not in your Users list — you cannot reply until they share their handle.", true);
  } else if (!c.token) {
    chatHint("No handle token saved for this user — re-add them by their full username#token handle to reply.", true);
  } else if (!c.ecdh || !c.mlkem) {
    chatHint("This user has not published encryption keys yet (older app) — they must unlock once with the updated app; then re-add them.", true);
  } else if (chat.mode === "AES256") {
    chatHint("🔒 AES256 — extra AES-256-GCM under your shared chat passphrase, inside the sealed PQ envelope.");
  } else {
    chatHint("🔒 SEALED — hybrid ECDH P-256 + ML-KEM-768, sender sealed inside. " + (c.verified ? "" : "Verify this contact in person for the strongest trust."));
  }
}

function renderPending(chat) {
  els.chatPending.textContent = "";
  const p = chat.pending;
  if (!p) { els.chatPending.hidden = true; return; }
  els.chatPending.hidden = false;
  if (p.dir === "out") {
    els.chatPending.textContent = `Waiting for ${chat.username} to accept the switch to ${p.mode}…`;
    return;
  }
  // Inbound proposal: accept / decline.
  const msg = document.createElement("span");
  msg.textContent = `${chat.username} wants to switch this chat to ${p.mode}. `;
  const accept = document.createElement("button");
  accept.type = "button";
  accept.className = "primary";
  accept.textContent = "Accept";
  accept.addEventListener("click", () => acceptModeChange(chat.username));
  const decline = document.createElement("button");
  decline.type = "button";
  decline.className = "danger";
  decline.textContent = "Decline";
  decline.addEventListener("click", () => declineModeChange(chat.username));
  els.chatPending.append(msg, accept, decline);
}

async function proposeModeChange(username, mode) {
  const chat = chats.get(username);
  const c = contacts.get(username);
  if (!chat || chat.mode === mode || !c || !c.token || !c.ecdh) return;
  const control = { kind: "mode-propose", mode };
  let salt = null, secret = null;
  if (mode === "AES256") {
    secret = promptSecret(
      `Choose a shared passphrase for the ${username} chat. Tell it to them out of band — ` +
      "they must enter the SAME one to accept. It adds AES-256 on top of the sealed envelope.",
    );
    if (!secret) return;
    salt = chats.newInnerSalt();
    control.salt = salt;
  }
  try {
    await sendControl(username, c, control);
  } catch (e) {
    chatHint("Could not propose mode change: " + e.message, true);
    els.chatModeSel.value = chat.mode; // revert the picker
    return;
  }
  await chats.setPending(username, { mode, dir: "out", salt, secret });
  renderConversation();
}

async function acceptModeChange(username) {
  const chat = chats.get(username);
  const c = contacts.get(username);
  if (!chat || !chat.pending || chat.pending.dir !== "in" || !c) return;
  const { mode, salt } = chat.pending;
  let secret = null;
  if (mode === "AES256") {
    secret = promptSecret(`Enter the shared passphrase ${username} gave you for this chat (must match exactly).`);
    if (!secret) return;
  }
  try {
    await sendControl(username, c, { kind: "mode-accept", mode, salt });
  } catch (e) {
    chatHint("Could not accept: " + e.message, true);
    return;
  }
  await chats.setMode(username, mode, { secret, salt });
  chatHint(`Switched to ${mode}.`);
  renderConversation();
}

async function declineModeChange(username) {
  const c = contacts.get(username);
  if (c) { try { await sendControl(username, c, { kind: "mode-decline" }); } catch { /* best effort */ } }
  await chats.clearPending(username);
  renderConversation();
}

async function sendControl(username, contact, control) {
  const myName = localStorage.getItem(LS_USERNAME);
  const myToken = localStorage.getItem(LS_LOOKUP_TOKEN);
  const senderHandle = myName && myToken ? myName + "#" + myToken : null;
  const envelope = await sealed.seal(
    identity, { ed: contact.ed, mldsa: contact.mldsa, ecdh: contact.ecdh, mlkem: contact.mlkem }, control, senderHandle,
  );
  await account.sendMail(API_BASE, mailHandle(contact), envelope);
}

async function sendChatMessage(e) {
  e.preventDefault();
  const text = els.chatText.value;
  if (!text || !activeChat) return;
  if (!isAscii(text)) {
    chatHint("Only printable ASCII characters are allowed.", true);
    return;
  }
  const c = contacts.get(activeChat);
  if (!c || !c.token || !c.ecdh || !c.mlkem) {
    chatHint("Cannot send — see the note above.", true);
    return;
  }
  const chat = chats.get(activeChat);
  if (chat.mode === "AES256" && (!chat.secret || !chat.salt)) {
    chatHint("This chat is set to AES256 but the shared passphrase isn't set here — re-negotiate the mode.", true);
    return;
  }
  els.chatSend.disabled = true;
  try {
    // Include our handle (if registered) sealed inside, so the receiver can
    // reply even if they never saved us. Self-claimed; keyed by bundle.
    const myName = localStorage.getItem(LS_USERNAME);
    const myToken = localStorage.getItem(LS_LOOKUP_TOKEN);
    const senderHandle = myName && myToken ? myName + "#" + myToken : null;
    // AES256 mode: wrap the text in the inner layer first; the sealed core
    // then carries {enc} instead of {msg} so the transport still hides it.
    let content;
    if (chat.mode === "AES256") {
      content = { kind: "msg", enc: await chats.innerEncrypt(chat.secret, chat.salt, text) };
    } else {
      content = text;
    }
    const envelope = await sealed.seal(identity, { ed: c.ed, mldsa: c.mldsa, ecdh: c.ecdh, mlkem: c.mlkem }, content, senderHandle);
    await account.sendMail(API_BASE, mailHandle(c), envelope);
    await chats.append(activeChat, { dir: "out", text, ts: Date.now() });
    els.chatText.value = "";
    renderConversation();
  } catch (err) {
    chatHint("Send failed: " + err.message, true);
  } finally {
    els.chatSend.disabled = false;
  }
}

// Fetch queued envelopes, open them, and file them into chats. Sender identity
// = the SEALED bundle (signature-verified in sealed.open). The self-claimed
// handle inside is used only to (a) name a brand-new contact and (b) store the
// reply token; an existing contact keyed by the same bundle always wins.
async function pollMailbox() {
  if (!apiToken || !identity || !chats.isUnlocked() || !contacts.isUnlocked()) return;
  let batch;
  try {
    batch = await account.fetchMail(API_BASE, apiToken);
  } catch (e) {
    // A directory session lasts TOKEN_TTL_SEC. When it expires the fetch 401s
    // forever and mail stops arriving with no visible sign, so re-authenticate
    // and let the next tick collect. Anything else: offline, just retry later.
    if (e && e.status === 401) {
      apiToken = null;
      const savedName = localStorage.getItem(LS_USERNAME);
      if (savedName) await autoLogin(savedName);
    }
    return;
  }
  let changed = false;
  for (const m of batch) {
    // Pentest 2026-07-25 F-06: GET /api/mailbox is delete-on-read, so the server
    // has ALREADY discarded everything in `batch`. Anything that throws while
    // filing one envelope must not take the rest of the batch with it — the
    // remainder would be unrecoverable. Each envelope is therefore processed in
    // full isolation, and the loop continues past a failure.
    try {
      changed = (await processEnvelope(m)) || changed;
    } catch (err) {
      // Keep going: the other envelopes in this batch are still deliverable.
      console.error("[mailbox] dropping one envelope:", err && err.message);
    }
  }
  if (changed && !els.viewChats.hidden) refreshChats();
}

// Cap on contacts created automatically from inbound mail (F-05). Anyone who
// knows our handle — which the app publishes as an invite link / QR — can send
// sealed mail, and each unknown sender used to add a record to the encrypted
// contact store with no ceiling. Past this many, unknown senders are refused
// until the user clears some; known contacts are never affected.
const MAX_AUTO_CONTACTS = 50;

// The DIRECTORY name for a contact: what the server knows them as, which is
// NOT necessarily the local label (F-01 — an auto-created contact is labelled
// neutrally and keeps the claimed directory name in `addrUsername`).
function dirName(c) {
  return c.addrUsername || c.username;
}
// The `username#token` handle used to address mail / directory lookups.
function mailHandle(c) {
  return dirName(c) + "#" + c.token;
}

// A local label derived from the sender's OWN key material, so an unknown
// sender can never choose how they are listed (F-01). Deterministic, so the
// same sender always lands on the same record.
function neutralName(edB64) {
  return "unknown-" + edB64.replace(/[^a-zA-Z0-9]/g, "").slice(0, 12).toLowerCase();
}

// File one fetched envelope. Returns true if it changed anything on screen.
async function processEnvelope(m) {
  let opened;
  try {
    opened = await sealed.open(identity, m.envelope);
  } catch {
    return false; // undecryptable/forged envelope: drop silently
  }
  const senderBundle = opened.from;
  // Match the sender to a saved user by their SIGNING keys — never by any
  // string they supplied.
  let sender = contacts.list().find((c) => c.ed === senderBundle.ed && c.mldsa === senderBundle.mldsa) || null;
  // The handle sealed inside is SELF-CLAIMED. It is signed, which proves the
  // sender wrote it — not that it is theirs.
  const claimed = opened.name ? account.parseHandle(opened.name) : null;

  if (!sender) {
    // Pentest 2026-07-25 F-01: this used to take the local username straight
    // from the claim, so any stranger could seat a contact called "alice" or
    // "bank-support" (bound to THEIR keys) in the Users and Chats lists. The
    // local label is now always derived from the sender's own key material;
    // the claim is kept separately, shown as unverified, and used only to
    // address replies.
    if (contacts.list().filter((c) => c.auto).length >= MAX_AUTO_CONTACTS) {
      chatsStatus(
        `Ignoring mail from unknown senders — the automatic contact limit (${MAX_AUTO_CONTACTS}) is reached. ` +
        "Remove some unknown contacts in Users to accept new ones.", true,
      );
      return false;
    }
    sender = await contacts.upsert({
      username: neutralName(senderBundle.ed),
      addrUsername: claimed ? claimed.username : null,
      claimedName: opened.name || null,
      auto: true,
      token: claimed ? claimed.token : null,
      ed: senderBundle.ed, mldsa: senderBundle.mldsa,
      ecdh: senderBundle.ecdh || null, mlkem: senderBundle.mlkem || null,
    });
  } else if (sender.token === null && claimed) {
    // Known bundle, no reply address yet: adopt the claimed one. Safe because
    // the bundle already matched a contact WE hold — the claim only decides
    // where a reply is posted, and a wrong one simply fails to deliver.
    sender = await contacts.upsert({
      username: sender.username,
      addrUsername: sender.addrUsername || claimed.username,
      claimedName: sender.claimedName || opened.name || null,
      token: claimed.token,
      ed: sender.ed, mldsa: sender.mldsa, ecdh: sender.ecdh, mlkem: sender.mlkem,
    });
  }

  // Control traffic (mode negotiation) vs a regular message.
  if (opened.kind && opened.kind !== "msg") {
    return await handleControl(sender, opened);
  }

  // Regular message. Decrypt the inner AES256 layer if this chat is in that
  // mode; a mode mismatch (peer still on the old mode) shows a system note.
  let text = opened.msg;
  if (opened.enc !== undefined) {
    const chat = chats.get(sender.username);
    if (chat && chat.mode === "AES256" && chat.secret && chat.salt) {
      try {
        text = await chats.innerDecrypt(chat.secret, chat.salt, opened.enc);
      } catch {
        text = "[AES256 message that did not decrypt — shared passphrase mismatch]";
      }
    } else {
      text = "[AES256 message but this chat isn't in AES256 mode here]";
    }
  }
  return await chats.append(sender.username, {
    dir: "in", text, ts: opened.ts, id: opened.id,
  });
}

// Apply an inbound mode-negotiation control message. Returns true if anything
// changed. The sender is already bundle-authenticated (sealed.open); only a
// verified-enough contact can drive our chat state.
async function handleControl(sender, opened) {
  const u = sender.username;
  // Pentest 2026-07-25 F-02: `opened.mode` is peer-supplied. The sealed envelope
  // proves they signed it, NOT that it is a mode we support — and every mode
  // check downstream is an exact string compare, so an unrecognised value would
  // silently take the plain-SEALED send path while the padlocked indicator
  // rendered the attacker's string. Refuse it at the boundary.
  if (opened.kind === "mode-propose" || opened.kind === "mode-accept") {
    if (!chats.isValidMode(opened.mode)) return false;
  }
  if (opened.kind === "mode-propose") {
    await chats.setPending(u, { mode: opened.mode, dir: "in", salt: opened.salt || null });
    if (activeChat === u) renderConversation();
    return true;
  }
  if (opened.kind === "mode-accept") {
    // Our proposal was accepted — lock in the mode we staged.
    const chat = chats.get(u);
    if (chat && chat.pending && chat.pending.dir === "out" && chat.pending.mode === opened.mode) {
      await chats.setMode(u, opened.mode, { secret: chat.pending.secret || null, salt: chat.pending.salt || null });
      if (activeChat === u) { chatHint(`${u} accepted — switched to ${opened.mode}.`); renderConversation(); }
    }
    return true;
  }
  if (opened.kind === "mode-decline") {
    await chats.clearPending(u);
    if (activeChat === u) { chatHint(`${u} declined the mode change.`, true); renderConversation(); }
    return true;
  }
  return false;
}

function startMailboxPolling() {
  if (mailboxTimer) return;
  mailboxTimer = setInterval(pollMailbox, 6000);
  pollMailbox();
}

// ---- connection lifecycle -------------------------------------------------

async function connect() {
  const room = els.room.value.trim();
  const alg = algValue();
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

  releaseOtpLock();
  otpRecord = null;
  otpAtRest = null;
  const opts = { passphrase: els.pass.value };
  if (alg === "OTP") {
    const padId = els.otpSelect.value;
    if (!padId) {
      hint("Select or generate a one-time pad first (Generate / share a pad).", true);
      return;
    }
    // Exclusive same-origin lock: a pad must be live in only ONE tab/window at a
    // time, or two sessions would draw the same keystream (two-time pad).
    otpLockRelease = await acquirePadLock(padId);
    if (!otpLockRelease) {
      hint("This pad is already in use in another tab or window. Close it there before using the pad here.", true);
      return;
    }
    try {
      const unlocked = await ensureUnlocked(padId); // decrypts the pad at rest
      otpRecord = unlocked.record;
      otpAtRest = unlocked.atRest;
    } catch (e) {
      releaseOtpLock();
      hint(e.message, true);
      return;
    }
    if (otpRecord.regionSize - otpRecord.sendOffset < 64) {
      releaseOtpLock();
      hint("This pad is exhausted for sending — exchange a fresh pad in person.", true);
      return;
    }
    opts.pad = otpRecord;
  }

  try {
    cipher = makeCipher(alg, room, opts);
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

  // Serialize message handling. handleMessage is async and awaits (signature
  // verification, key derivation); without serialization two handshake frames
  // could both pass verification before either pins the peer identity — the
  // TOCTOU half of C-01. A single FIFO chain makes the pin check atomic.
  msgChain = Promise.resolve();
  ws.onmessage = (ev) => {
    msgChain = msgChain.then(() => handleMessage(room, ev.data)).catch(() => {});
  };

  ws.onclose = () => {
    setStatus("disconnected", "err");
    if (joined) addLine("sys", "", "disconnected");
    joined = false;
    verified = false;
    enableSend(false);
    els.verify.hidden = true;
    showScreen("room");
    els.connect.disabled = false;
    releaseOtpLock();
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
      type: "key", room, alg: algValue(),
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
      els.roomShort.textContent = room.slice(0, 8) + "…" + room.slice(-8);
      showScreen("chat");
      setStatus("connected", "ok");
      addLine("sys", "", `joined room — encryption: ${algValue()}`);
      // Phase 1: announce our fresh session nonce. For handshake modes the
      // signed handshake follows once we also know the peer's nonce; for
      // AES256 (usesNonces, no key material on the wire) the nonces alone fix
      // the session's ratchet chains, closing cross-session frame replay.
      ws.send(JSON.stringify({
        type: "key", room, alg: algValue(),
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
              type: "key", room, alg: algValue(),
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
          } else if (!cipher.needsHandshake && !cipher.usesNonces && !verified) {
            // OTP: no key material and no nonces — the pre-shared pad IS the
            // out-of-band secret (like AES256's passphrase), so seeing the peer
            // join is enough to unlock messaging.
            verified = true;
            enableSend(true);
            updateOtpBudget();
            hint("Ready. Messages are one-time-pad encrypted.");
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

        // C-01: atomically bind the peer IDENTITY to the FIRST accepted
        // handshake. The ciphers are first-key-wins (a later ephemeral key is
        // ignored), so if we let a second, differently-signed handshake through
        // it could set peerBundle (and thus the safety number / pin check) to a
        // DIFFERENT identity than the one whose key the cipher actually locked
        // in — decoupling the verified identity from the live channel key. So:
        // pin the identity on first accept; hard-refuse any later frame whose
        // identity differs, and close the connection (that is a MITM attempt).
        if (peerBundle === null) {
          peerBundle = idb; // write-once for this connection
        } else if (!sameBundle(peerBundle, idb)) {
          addLine("sys", "", "[a SECOND identity tried to complete the key exchange — refusing; this is a relay MITM attempt]");
          hint("Two different identities attempted this handshake — disconnecting to protect you.", true);
          if (ws) ws.close();
          return;
        }
        // Feed the key material (same identity guaranteed above). The cipher
        // keeps its first key; repeat/answer frames from this identity are
        // folded idempotently.
        await cipher.onPeerKey(pub);

        // Answer the initiator exactly once with our own signed key.
        if (!reply) {
          await sendSignedKey(room, true);
        }

        if (cipher.ready) {
          await enterVerification(room, peerBundle);
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
        persistOtpProgress();
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
async function enterVerification(room, verifiedBundle) {
  // Use the bundle passed from the pinned first handshake — never re-read a
  // mutable global that a later frame might have changed (C-01).
  const bundle = verifiedBundle || peerBundle;
  const sn = await Identity.safetyNumber(myBundle, bundle);
  const peerFp = await Identity.fingerprintOf(bundle);
  els.safetyNumber.textContent = sn;
  els.peerFingerprint.textContent = "Contact fingerprint: " + peerFp;
  currentPinKey = expectedPeerName ? "user:" + expectedPeerName : "room:" + room;

  // If we looked the contact up by username, the live key must match what the
  // directory published. A mismatch is a strong red flag (though note the
  // directory is not a trust root — see account.js).
  if (expectedPeerBundle && !sameBundle(expectedPeerBundle, bundle)) {
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

  const pin = await getPin(currentPinKey);
  if (sameBundle(pin, bundle)) {
    // Seen and verified before — accept without re-prompting.
    addLine("sys", "", expectedPeerName
      ? `contact "${expectedPeerName}" matches your saved pin`
      : "contact identity matches your saved pin");
    unlockMessaging();
    return;
  }

  els.verify.hidden = false;
  if (pin && sameSigning(pin, bundle) && pin.ecdh == null && pin.mlkem == null &&
      (bundle.ecdh || bundle.mlkem)) {
    // Audit 2026-07-18 H-01: a pre-fix pin covered only the signing keys. The
    // signing identity matches, but the encryption keys now presented were
    // never part of what was verified — treat the pin as NOT sufficient and
    // require a fresh in-person check (the safety number now covers all keys).
    els.verify.classList.add("changed");
    els.verifyTitle.textContent = "Re-verify this contact — your saved pin predates encryption-key checks";
    els.verifyHint.textContent =
      "Your earlier verification did not cover the keys now used to encrypt messages to this contact. " +
      "Compare the safety number with them in person (or over a call where you recognise their voice) " +
      "before proceeding.";
    addLine("sys", "", "[pin predates encryption-key coverage — re-verification required]");
  } else if (pin) {
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

async function onVerifyOk() {
  if (!peerBundle || !currentPinKey) return;
  await savePin(currentPinKey, peerBundle);
  // An in-person safety-number confirmation is the strongest trust signal we
  // have — mirror it into the Users list (🟢) when the peer is known by name.
  // Store the FULL bundle incl. the encryption keys the safety number covered
  // (H-01), so async chats trust exactly the keys just verified in person.
  if (expectedPeerName && contacts.isUnlocked()) {
    const parsed = account.parseHandle(els.contact.value.trim());
    await contacts.upsert({
      username: expectedPeerName, token: parsed ? parsed.token : null,
      ed: peerBundle.ed, mldsa: peerBundle.mldsa,
      ecdh: peerBundle.ecdh || null, mlkem: peerBundle.mlkem || null,
      verified: true,
    }).catch(() => { /* contact mirroring must never block messaging */ });
  }
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
    ws.send(JSON.stringify({ type: "msg", room: els.room.value.trim(), payload, alg: algValue() }));
    addLine("me", "me", text);
    els.text.value = "";
    hint("");
    persistOtpProgress();
  } catch (err) {
    hint("Encryption failed: " + err.message, true);
  } finally {
    sending = false;
    // Re-enable only if the gate still allows messaging (the socket may have
    // closed while the encrypt was in flight, which disables the form).
    if (verified) els.send.disabled = false;
  }
}

// ---- one-time pad UI ------------------------------------------------------

function otpStatusMsg(text, isErr = false) {
  els.otpStatus.textContent = text;
  els.otpStatus.className = "hint" + (isErr ? " err" : "");
}

function fmtBytes(n) {
  if (n >= 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + " MiB";
  if (n >= 1024) return Math.round(n / 1024) + " KiB";
  return n + " B";
}

// Sync the cipher's advanced offsets back onto the pad record (its bytes array
// is the same reference the cipher zeroes in place) and persist (encrypted at
// rest, with the cached key so there is no per-message PBKDF2). Called after
// every send/receive so consumption survives a reload — reuse would be
// catastrophic for a one-time pad.
function persistOtpProgress() {
  if (!otpRecord || !otpAtRest || !cipher || algValue() !== "OTP") return;
  otpRecord.sendOffset = cipher.sendOffset;
  otpRecord.recvHighWater = cipher.recvHighWater;
  otp.savePadProgress(otpRecord, otpAtRest).catch((e) => hint("Could not save pad progress: " + e.message, true));
  updateOtpBudget();
}

// ---- pad exclusive lock (one live session per pad) ------------------------
// Prevents the concurrent-use two-time-pad break: two tabs each loading the same
// pad at the same offset. Uses the Web Locks API (auto-released if the tab dies)
// where available, with a localStorage-heartbeat lease as a fallback.
function acquirePadLock(padId) {
  const name = "sc.otp.lock.v1." + padId;
  if (navigator.locks && navigator.locks.request) {
    return new Promise((resolveGot) => {
      let releaseHeld;
      navigator.locks.request(name, { ifAvailable: true }, (lock) => {
        if (!lock) { resolveGot(null); return; } // held elsewhere
        resolveGot(() => { if (releaseHeld) releaseHeld(); });
        return new Promise((r) => { releaseHeld = r; }); // hold until released
      }).catch(() => resolveGot(null));
    });
  }
  return Promise.resolve(acquireLeaseFallback(name));
}
function acquireLeaseFallback(name) {
  const STALE = 12000;
  try {
    const cur = JSON.parse(localStorage.getItem(name) || "null");
    if (cur && Date.now() - cur.ts < STALE && cur.owner !== TAB_ID) return null;
  } catch { /* fall through */ }
  const write = () => localStorage.setItem(name, JSON.stringify({ owner: TAB_ID, ts: Date.now() }));
  write();
  try { if (JSON.parse(localStorage.getItem(name)).owner !== TAB_ID) return null; } catch { return null; }
  const hb = setInterval(write, 4000);
  return () => {
    clearInterval(hb);
    try { if (JSON.parse(localStorage.getItem(name)).owner === TAB_ID) localStorage.removeItem(name); } catch { /* ignore */ }
  };
}
function releaseOtpLock() {
  if (otpLockRelease) { try { otpLockRelease(); } catch { /* ignore */ } otpLockRelease = null; }
}

// Decrypt the selected pad at rest using the pad passphrase, caching the result
// for the session. Returns { record, atRest }.
let otpUnlockedId = null;
async function ensureUnlocked(padId) {
  if (otpUnlockedId === padId && otpRecord && otpAtRest) {
    return { record: otpRecord, atRest: otpAtRest };
  }
  if (!els.otpPass.value) throw new Error("Enter this pad's passphrase to unlock it.");
  const unlocked = await otp.unlockPad(padId, els.otpPass.value);
  otpUnlockedId = padId;
  otpRecord = unlocked.record;
  otpAtRest = unlocked.atRest;
  return unlocked;
}

function updateOtpBudget() {
  if (!otpRecord) return;
  const remain = otpRecord.regionSize - otpRecord.sendOffset;
  const est = Math.max(0, Math.floor(remain / (32 + 60))); // ~60-byte messages
  otpStatusMsg(`Pad "${otpRecord.label}": ${fmtBytes(remain)} left to send (~${est} more short messages).`);
}

function syncOtpSelection() {
  els.otpForget.hidden = !els.otpSelect.value;
}

function refreshOtpPads(selectId) {
  const pads = otp.listPads();
  els.otpSelect.textContent = "";
  const none = document.createElement("option");
  none.value = "";
  none.textContent = pads.length ? "— select a pad —" : "— no pad on this device —";
  els.otpSelect.appendChild(none);
  for (const p of pads) {
    const o = document.createElement("option");
    o.value = p.padId;
    o.textContent = `${p.label} (${p.role === 0 ? "you generated" : "imported"}, ${fmtBytes(p.regionSize)}/side)`;
    els.otpSelect.appendChild(o);
  }
  if (selectId) els.otpSelect.value = selectId;
  syncOtpSelection();
}

function populateOtpSizes() {
  els.otpSize.textContent = "";
  otp.PAD_SIZES.forEach((s, i) => {
    const o = document.createElement("option");
    o.value = String(s.bytes);
    o.textContent = s.label;
    if (i === 1) o.selected = true; // default to the middle size
    els.otpSize.appendChild(o);
  });
}

// Draw-to-generate entropy: capture pointer motion samples to fold into the pad.
let otpDrawing = false;
let otpEntropySamples = [];

function updateEntropyStatus() {
  const n = otpEntropySamples.length / 3;
  els.otpEntropyStatus.textContent = n === 0
    ? "Entropy from drawing: none yet (the OS random generator is used regardless)."
    : `Entropy from drawing: ${n} motion samples captured.`;
}
function entropyBytes() {
  if (otpEntropySamples.length === 0) return new Uint8Array(0);
  return new Uint8Array(new Float64Array(otpEntropySamples).buffer);
}
function clearEntropy() {
  otpEntropySamples = [];
  const c = els.otpEntropy;
  if (c) c.getContext("2d").clearRect(0, 0, c.width, c.height);
  updateEntropyStatus();
}
function setupEntropyCanvas() {
  const c = els.otpEntropy;
  if (!c) return;
  const ctx = c.getContext("2d");
  ctx.strokeStyle = "#2f81f7";
  ctx.lineWidth = 1.5;
  ctx.lineCap = "round";
  let last = null;
  const sample = (e) => {
    const r = c.getBoundingClientRect();
    const x = (e.clientX - r.left) * (c.width / r.width);
    const y = (e.clientY - r.top) * (c.height / r.height);
    otpEntropySamples.push(x, y, performance.now());
    if (last) {
      ctx.beginPath();
      ctx.moveTo(last[0], last[1]);
      ctx.lineTo(x, y);
      ctx.stroke();
    }
    last = [x, y];
    updateEntropyStatus();
  };
  c.addEventListener("pointerdown", (e) => { otpDrawing = true; last = null; c.setPointerCapture(e.pointerId); sample(e); });
  c.addEventListener("pointermove", (e) => { if (otpDrawing) sample(e); });
  const end = () => { otpDrawing = false; last = null; };
  c.addEventListener("pointerup", end);
  c.addEventListener("pointercancel", end);
}

async function otpGenerate() {
  if (!els.otpPass.value) {
    otpStatusMsg("Set a pad passphrase first — it encrypts the pad on this device.", true);
    return;
  }
  try {
    otpStatusMsg("Generating pad… (deriving the at-rest key, this takes a moment)");
    const totalBytes = parseInt(els.otpSize.value, 10);
    const rec = await otp.generatePad({ label: els.otpLabel.value.trim(), totalBytes, fingerBytes: entropyBytes() });
    otpAtRest = await otp.saveNewPad(rec, els.otpPass.value); // encrypted at rest
    otpRecord = rec;
    otpUnlockedId = rec.padId; // keep unlocked so Export works immediately
    clearEntropy();
    els.otpLabel.value = "";
    refreshOtpPads(rec.padId);
    otpStatusMsg(`Generated + encrypted pad "${rec.label}". Now Export it and give the file to your contact in person.`);
  } catch (e) {
    otpStatusMsg("Generation failed: " + e.message, true);
  }
}

function downloadText(name, text) {
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name.replace(/[^\w.\-]+/g, "_");
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

let pendingReexportId = null;
async function otpExport() {
  const id = els.otpSelect.value;
  if (!id) { otpStatusMsg("Select a pad to export.", true); return; }
  if (!els.otpXferPass.value) { otpStatusMsg("Enter a transfer passphrase first (agree on it with your contact in person).", true); return; }
  // Re-export guard (Finding 3): sharing one pad with more than one importer
  // causes key reuse. Warn once and require a second click to confirm.
  const meta = otp.padMeta(id);
  if (meta && meta.exported && pendingReexportId !== id) {
    pendingReexportId = id;
    otpStatusMsg("⚠ This pad was already exported. A pad must be imported on only ONE device — re-exporting risks catastrophic key reuse. Click Export again to confirm you know what you are doing.", true);
    return;
  }
  pendingReexportId = null;
  try {
    const { record } = await ensureUnlocked(id); // decrypt at rest first
    const text = await otp.exportPad(record, els.otpXferPass.value);
    downloadText(`secure-chat-pad-${record.label || record.padId}.json`, text);
    otp.markExported(id);
    otpStatusMsg("Exported. Give the file to your contact in person; they Import it with the same TRANSFER passphrase.");
  } catch (e) {
    otpStatusMsg("Export failed: " + e.message, true);
  }
}

function otpImportClick() {
  if (!els.otpXferPass.value) {
    otpStatusMsg("Enter the TRANSFER passphrase your contact agreed on, then choose their file.", true);
    return;
  }
  if (!els.otpPass.value) {
    otpStatusMsg("Also set a pad passphrase (top of this panel) — it encrypts the imported pad on this device.", true);
    return;
  }
  els.otpFile.click();
}

async function otpFileChosen() {
  const file = els.otpFile.files[0];
  els.otpFile.value = "";
  if (!file) return;
  try {
    const text = await file.text();
    const rec = await otp.importPad(text, els.otpXferPass.value); // transfer passphrase + entropy check
    if (otp.padMeta(rec.padId)) {
      refreshOtpPads(rec.padId);
      otpStatusMsg("You already have this pad on this device — not importing again (a pad must live on exactly one device per side).", true);
      return;
    }
    otpAtRest = await otp.saveNewPad(rec, els.otpPass.value); // encrypt at rest with the pad passphrase
    otpRecord = rec;
    otpUnlockedId = rec.padId;
    refreshOtpPads(rec.padId);
    otpStatusMsg(`Imported + encrypted pad "${rec.label}". Select it, use the same room id as your contact, and Connect.`);
  } catch (e) {
    otpStatusMsg("Import failed: " + e.message, true);
  }
}

function otpForgetSelected() {
  const id = els.otpSelect.value;
  if (!id) return;
  otp.forgetPad(id);
  refreshOtpPads();
  otpStatusMsg("Pad forgotten (deleted from this device).");
}

// ---- wiring ---------------------------------------------------------------

els.idCreate.addEventListener("click", createIdentity);
els.idUnlock.addEventListener("click", unlockIdentity);
els.idExport.addEventListener("click", exportIdentity);
els.idForget.addEventListener("click", forgetIdentity);
els.register.addEventListener("click", registerAccount);
els.login.addEventListener("click", loginAccount);

// Per-view unlock (Profile / Users / Chats). Opening an invite link spawns a
// NEW tab, and an unlocked identity lives in memory per tab — so that tab
// always started locked with no way to unlock without navigating to the Live
// room. Each locked view now unlocks in place.
const setUnlockStatus = (el) => (text, isErr = false) => {
  el.textContent = text;
  el.className = "hint" + (isErr ? " err" : "");
};
wireViewUnlock(els.profileUnlockPass, els.profileUnlock,
  setUnlockStatus(els.profileUnlockStatus), renderProfile);
wireViewUnlock(els.usersUnlockPass, els.usersUnlock,
  setUnlockStatus(els.usersUnlockStatus), refreshUsers);
wireViewUnlock(els.chatsUnlockPass, els.chatsUnlock,
  setUnlockStatus(els.chatsUnlockStatus), refreshChats);

els.gen.addEventListener("click", () => {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  els.room.value = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  hint("New 256-bit room id generated. Share it with exactly one person.");
});

function syncAlgUI() {
  const alg = algValue();
  els.passRow.hidden = alg !== "AES256";
  els.contactRow.hidden = !algNeedsIdentity(alg); // lookup only aids DHKE/RSA
  els.otpPanel.hidden = alg !== "OTP";
}
els.algCards.addEventListener("change", syncAlgUI); // radio changes bubble here

els.connect.addEventListener("click", connect);
els.form.addEventListener("submit", sendText);
els.verifyOk.addEventListener("click", onVerifyOk);
els.verifyNo.addEventListener("click", onVerifyNo);

// drawer menu + views
els.menuBtn.addEventListener("click", () => setDrawer(els.drawer.hidden));
els.scrim.addEventListener("click", () => setDrawer(false));
for (const b of els.drawer.querySelectorAll(".navitem")) {
  b.addEventListener("click", () => showView(b.dataset.view));
}
els.addContact.addEventListener("click", addContactFromHandle);

// "Your handle" share controls (Users view). Copy the raw handle, or an invite
// link that pre-fills the add field for the recipient. Both are convenience
// only — neither conveys trust (the recipient still verifies in person).
async function copyToClipboard(btn, text, okLabel = "Copied ✓") {
  const orig = btn.textContent;
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = okLabel;
  } catch {
    btn.textContent = "Copy failed";
  }
  setTimeout(() => { btn.textContent = orig; }, 1500);
}
els.copyHandle.addEventListener("click", () => {
  const h = myHandle();
  if (h) copyToClipboard(els.copyHandle, h);
});
els.copyInvite.addEventListener("click", () => {
  const h = myHandle();
  if (h) copyToClipboard(els.copyInvite, inviteLink(h));
});

// Profile view: same share controls + the identity actions surfaced here too.
els.profileCopyHandle.addEventListener("click", () => {
  const h = myHandle();
  if (h) copyToClipboard(els.profileCopyHandle, h);
});
els.profileCopyInvite.addEventListener("click", () => {
  const h = myHandle();
  if (h) copyToClipboard(els.profileCopyInvite, inviteLink(h));
});
els.profileExport.addEventListener("click", exportIdentity);
els.profileForget.addEventListener("click", async () => {
  await forgetIdentity();
  renderProfile(); // reflect the now-locked state without leaving the view
});

// chats view
els.chatStart.addEventListener("click", () => {
  if (els.chatNew.value) openChat(els.chatNew.value);
});
els.chatBack.addEventListener("click", () => {
  activeChat = null;
  refreshChats();
});
els.chatForm.addEventListener("submit", sendChatMessage);
els.chatModeSel.addEventListener("change", () => {
  if (activeChat) proposeModeChange(activeChat, els.chatModeSel.value);
});

// screen navigation + chat top bar
els.toRoom.addEventListener("click", () => showScreen("room"));
els.toIdentity.addEventListener("click", () => showScreen("identity"));
els.disconnect.addEventListener("click", () => {
  if (ws) ws.close(); // onclose does the cleanup and returns to the room screen
});
els.copyRoom.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(els.room.value.trim());
    els.copyRoom.textContent = "Copied ✓";
  } catch {
    els.copyRoom.textContent = "Copy failed";
  }
  setTimeout(() => { els.copyRoom.textContent = "Copy room id"; }, 1500);
});

// one-time pad controls
els.otpSelect.addEventListener("change", syncOtpSelection);
els.otpGenerate.addEventListener("click", otpGenerate);
els.otpExport.addEventListener("click", otpExport);
els.otpImport.addEventListener("click", otpImportClick);
els.otpFile.addEventListener("change", otpFileChosen);
els.otpForget.addEventListener("click", otpForgetSelected);
populateOtpSizes();
setupEntropyCanvas();
refreshOtpPads();

showScreen("identity");
syncAlgUI();
refreshIdentityUI();

// Invite-link handling: an inbound `#add=<handle>` opens the Users view and
// stages the handle for review (never auto-adds). The fragment is cleared from
// the URL immediately so it isn't re-triggered or left in history/bookmarks.
(function handleInviteLink() {
  const m = /^#add=(.+)$/.exec(location.hash || "");
  if (!m) return;
  let handle;
  try {
    handle = decodeURIComponent(m[1]);
  } catch {
    return;
  }
  history.replaceState(null, "", location.pathname + location.search);
  if (!account.parseHandle(handle)) return; // ignore anything not username#token
  pendingInviteHandle = handle;
  showView("users"); // refreshUsers() applies the pending invite once unlocked
})();

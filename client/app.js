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
import {
  signHandshake, verifyHandshake, freshNonce, isValidNonce, signKnock, verifyKnock,
  unb64,
} from "./auth.js";
import * as account from "./account.js";
import * as otp from "./otp.js";
import * as contacts from "./contacts.js";
import * as chats from "./chats.js";
import * as sealed from "./sealed.js";
import { makeKeyConfirmation } from "./keyconfirm.js";
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
  safetyNumber: $("safetyNumber"),
  // room admission (owner approves who may join)
  admit: $("admit"), admitFingerprint: $("admitFingerprint"), admitWho: $("admitWho"),
  admitWarn: $("admitWarn"), admitOk: $("admitOk"), admitNo: $("admitNo"), admitLeave: $("admitLeave"),
  idHint: $("idHint"), roomHint: $("roomHint"), roomHelp: $("roomHelp"),
  stepIdentity: $("stepIdentity"), stepRoom: $("stepRoom"),
  copyCode: $("copyCode"), algDetails: $("algDetails"), algSummary: $("algSummary"), peerFingerprint: $("peerFingerprint"),
  verifyOk: $("verifyOk"), verifyNo: $("verifyNo"),
  // chat
  chat: $("chat"), log: $("log"),
  form: $("sendForm"), text: $("text"), send: $("send"), hint: $("hint"),
  // screens + chat top bar
  scrIdentity: $("scrIdentity"), scrRoom: $("scrRoom"), scrChat: $("scrChat"),
  toRoom: $("toRoom"), toIdentity: $("toIdentity"),
  roomShort: $("roomShort"), copyRoom: $("copyRoom"),
  chatStatus: $("chatStatus"), disconnect: $("disconnect"), chatVerified: $("chatVerified"),
  chatTop: document.querySelector("#scrChat > .topbar"), tabbar: $("tabbar"),
  // views
  viewLive: $("viewLive"), viewUsers: $("viewUsers"), viewChats: $("viewChats"),
  viewProfile: $("viewProfile"),
  // profile view
  profileLocked: $("profileLocked"), profileUnlocked: $("profileUnlocked"),
  profileUnlockPass: $("profileUnlockPass"), profileUnlock: $("profileUnlock"),
  profileUnlockStatus: $("profileUnlockStatus"),
  usersUnlockPass: $("usersUnlockPass"), usersUnlock: $("usersUnlock"),
  usersUnlockStatus: $("usersUnlockStatus"),
  usersAdopt: $("usersAdopt"), usersAdoptHint: $("usersAdoptHint"),
  chatsUnlockPass: $("chatsUnlockPass"), chatsUnlock: $("chatsUnlock"),
  chatsUnlockStatus: $("chatsUnlockStatus"),
  chatsAdopt: $("chatsAdopt"), chatsAdoptHint: $("chatsAdoptHint"),
  profileName: $("profileName"), profileAvatar: $("profileAvatar"),
  profileHandleText: $("profileHandleText"),
  profileHandleActions: $("profileHandleActions"),
  profileCopyHandle: $("profileCopyHandle"), profileCopyInvite: $("profileCopyInvite"),
  profileQrRow: $("profileQrRow"), profileQr: $("profileQr"),
  profileFingerprint: $("profileFingerprint"), profileKeys: $("profileKeys"),
  profileStatus: $("profileStatus"),
  profileExport: $("profileExport"), profileForget: $("profileForget"),
  profileLogout: $("profileLogout"), profileSessionHint: $("profileSessionHint"),
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
  chatPending: $("chatPending"), chatModeWhy: $("chatModeWhy"), expectRow: $("expectRow"),
  // contact profile sheet
  contactSheet: $("contactSheet"), contactScrim: $("contactScrim"),
  contactAvatar: $("contactAvatar"), contactName: $("contactName"), contactMark: $("contactMark"),
  contactClose: $("contactClose"), contactWarn: $("contactWarn"),
  contactHandleLabel: $("contactHandleLabel"), contactHandle: $("contactHandle"),
  contactCopyHandle: $("contactCopyHandle"), contactFingerprint: $("contactFingerprint"),
  contactFacts: $("contactFacts"), contactStatus: $("contactStatus"),
  contactMessage: $("contactMessage"), contactVerify: $("contactVerify"), contactRemove: $("contactRemove"),
};

const enc = new TextEncoder();
const dec = new TextDecoder();
const ROOM_RE = /^[0-9a-f]{64}$/;

// A chat code is copied and pasted between people, so it arrives with stray
// spaces, line breaks or capitals far more often than it arrives pristine.
// Normalise on read rather than rejecting the user over whitespace.
function roomCode() {
  return els.room.value.replace(/\s+/g, "").toLowerCase();
}
function newRoomCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

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
// Pentest 2026-07-26 P-19: the room id and algorithm this session actually
// negotiated, captured once at connect(). The send path used to re-read
// roomCode()/algValue() from the live DOM, so any later UI change would have
// been described on the wire as though it had always been the session's mode.
let sessionRoom = null;
let sessionAlg = null;

// ---- room admission (pentest 2026-07-26 P-08) ------------------------------
// Knowing a room id used to be enough to TAKE a slot, which let anyone lock the
// invited peer out. Now the first party in owns the room and everyone else
// waits; the owner sees who is knocking (key fingerprint + trust mark) and
// decides. The relay enforces the slots, but the decision — and the check that
// the peer who then completes the handshake is the one that was let in — is
// entirely client-side, because the relay is not trusted with either.
let roomRole = null;       // "owner" | "guest" for this connection
let admittedBundle = null; // the identity WE let in (owner side), or null
let admittedAnon = false;  // we let in someone with no identity at all
let wasPending = false;    // we sat in the approval queue (M-2, guest side)
// Pentest 2026-08-07 F-PROTO-001: the one fact about room ownership the relay
// does NOT get to supply. `roomRole` above is whatever the relay answers to
// `join`, and a hostile relay can answer the room's CREATOR with `pending` —
// then `joined:guest` — which the M-2 guest-half check accepts, because it
// only proves we passed through the queue, not that an owner existed. The
// creator then never sees a knock, approves nobody, and whoever the relay
// routes in completes the handshake with no admission binding. So the client
// remembers whether THIS page minted the code in the box, and a creator
// refuses to be seated as a guest at all.
let roomCodeMine = false;   // the code in #room came from newRoomCode() here
let sessionRoomMine = false; // frozen copy for the live connection (like sessionRoom)
// Fix review 2026-09-21: page-instance state alone failed open on the most
// likely recovery path — after a reload the box is empty (autocomplete=off),
// the creator pastes the code she already sent, and `input` cleared the flag.
// Minted codes are therefore also remembered in localStorage (last few). That
// key is attacker-writable, but the failure directions are asymmetric: a
// removed entry only restores the pre-fix behaviour for that code, an added
// one only makes THIS page refuse a room (loud, local). Never a trust source
// for anything else.
const LS_MINTED_CODES = "sc.room.mine.v1";
function rememberMinted(code) {
  try {
    const cur = JSON.parse(localStorage.getItem(LS_MINTED_CODES) || "[]");
    const next = [code, ...(Array.isArray(cur) ? cur.filter((c) => c !== code) : [])].slice(0, 8);
    localStorage.setItem(LS_MINTED_CODES, JSON.stringify(next));
  } catch { /* storage unavailable: the in-memory flag still covers this page */ }
}
function isMinted(code) {
  try {
    const cur = JSON.parse(localStorage.getItem(LS_MINTED_CODES) || "[]");
    return Array.isArray(cur) && cur.includes(code);
  } catch {
    return false;
  }
}
// Why a client-side refusal closed the socket. `ws.onclose` returns to the room
// screen, and changing screens clears every hint — so a refusal's explanation
// vanished with the chat screen and the user was left on the room screen with
// no idea why. The refusal parks its message here and onclose re-shows it.
let closeHint = null;
// Phase 2a fix round (pentest P2): every close the APP starts goes through
// closeWs(). onclose re-shows a relay-parked reason (A3) only for a close the
// app did NOT start — the relay's or the network's — so a parked "room closed"
// can never relabel the user's own Disconnect or "It differs", or a client
// refusal. `refusal`, when given, is what onclose shows (it wins over anything
// the relay said). `sock` is the socket the refusal belongs to (a frame's own).
let clientClosing = false;
function closeWs(refusal = null, sock = ws) {
  if (!sock) return;
  // Round 3 (pentest L2): a frame handled after its socket's onclose ran (the
  // room screen is up) — show the refusal now instead of dropping it.
  if (sock.readyState === WebSocket.CLOSED) { if (refusal !== null && sock === ws) hint(refusal, true); return; }
  if (refusal !== null) closeHint = refusal;
  clientClosing = true;
  sock.close();
}
let knockQueue = [];       // [{jid, bundle, anon}] waiting for our verdict
let currentRoom = null;    // the room this connection is in (keyconfirm effects)
// L-1: a backstop on the approval queue, NOT the control.
//
// The relay holds at most MAX_ROOM_PENDING (4) waiters at a time, so with the
// `withdrawn` pruning below this queue cannot legitimately exceed that. The cap
// exists for the case where pruning does not happen — an older relay that does
// not send `withdrawn`, or a hostile one that withholds it — and it is set well
// above the relay's own limit so it never drops a knock the relay considers
// live. The first cut of this fix set it to 8 with no pruning at all, which the
// fix review (M-A) showed made things WORSE than no cap: cheap
// connect/knock/disconnect cycles filled the queue with ghosts that nothing
// removed, and because the client sends its knock exactly once and the relay
// refuses a second one on the same socket, a dropped knocker could never try
// again. That is a permanent, silent denial of admission — a direct hit on the
// P-08 property this was supposed to protect.
const MAX_KNOCK_QUEUE = 16;

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

// Pentest 2026-07-26 P-02: "no pin recorded" and "pins UNREADABLE" must not look
// alike. unlockContacts() swallows a decrypt failure (corrupt/tampered/foreign
// blob) into a string and returns normally, so the identity stayed fully usable
// with the pin store locked — getPin() then returned null and the verification
// gate showed the benign first-contact prompt instead of the loud
// "identity key CHANGED" alarm. Overwriting sc.contacts.v1 with garbage was
// therefore enough to strip TOFU change detection for every contact.
function pinsReadable() {
  return contacts.isUnlocked() || !contacts.hasStore();
}
function getPin(key) {
  return contacts.isUnlocked() ? contacts.getPin(key) : null;
}
function savePin(key, bundle) {
  if (contacts.isUnlocked()) return contacts.savePin(key, bundle);
  // Rejecting (was: silently resolving) so the caller can tell the user their
  // confirmation was NOT durably recorded — otherwise the next session shows
  // "first contact" again and the change alarm never arms.
  return Promise.reject(new Error("contact store is locked — the identity pin could not be saved"));
}
// Audit 2026-07-18 H-01: bundle equality covers ALL FOUR public keys,
// normalized so missing and present never compare equal — a swapped or newly
// appeared ecdh/mlkem pair must never ride under an existing match.
//
// Pentest 2026-07-27 H-1: compare the KEYS, not their spelling. `atob` used to
// accept several base64 strings per key, so a relay flipping one character
// produced a bundle that verified, digested and safety-numbered identically yet
// compared UNEQUAL here — a free "identity key CHANGED" alarm on a genuine
// peer, and a route to getting a non-canonical string pinned. Decoding is
// canonical now, so `field` also rejects a re-spelled key outright; comparing
// decoded bytes makes that independent of where the value came from.
function sameKey(x, y) {
  if (x == null || y == null) return x == null && y == null;
  let a, b;
  try {
    a = unb64(x);
    b = unb64(y);
  } catch {
    return false; // a non-canonical spelling is not equal to anything
  }
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
function sameBundle(a, b) {
  return !!a && !!b && sameKey(a.ed, b.ed) && sameKey(a.mldsa, b.mldsa) &&
    sameKey(a.ecdh ?? null, b.ecdh ?? null) &&
    sameKey(a.mlkem ?? null, b.mlkem ?? null);
}
// Signing-only equality, used ONLY to tell "same identity, pin predates
// encryption-key coverage" apart from a full identity change in the pin flow.
function sameSigning(a, b) {
  return !!a && !!b && sameKey(a.ed, b.ed) && sameKey(a.mldsa, b.mldsa);
}
// Re-spell every key of a received bundle in canonical base64 — i.e. reject any
// that is not already canonical. Anything PERSISTED (a pin, a contact record) or
// re-signed (sealed.js signs the stored string) must go through this, so the
// stored form is the one spelling of the bytes the user actually verified.
function canonicalBundle(b) {
  if (!b || typeof b !== "object") throw new Error("malformed identity bundle");
  const out = {};
  for (const f of ["ed", "mldsa", "ecdh", "mlkem"]) {
    if (b[f] == null) continue;
    out[f] = bufToB64(unb64(b[f])); // unb64 throws on a non-canonical spelling
  }
  if (!out.ed || !out.mldsa) throw new Error("malformed identity bundle");
  return out;
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
  clearHints();
  // Move focus to the new screen's heading so a keyboard or screen-reader user
  // lands where the content changed instead of staying on the button they left.
  // NOT on the first paint: nobody navigated there, and focusing on load just
  // paints a focus ring the user did not ask for.
  if (screenShown) {
    const head = { identity: els.stepIdentity, room: els.stepRoom, chat: els.roomShort }[name];
    if (head && typeof head.focus === "function") head.focus();
  }
  screenShown = true;
}
let screenShown = false;

// ---- top-level views (tab bar) ---------------------------------------------
// Four views: live (the 3-step room flow), chats (async DMs), users (contact
// list + trust), profile. Pure presentation — switching views never touches
// an active connection.

function showView(name) {
  closeContact(false); // the profile belongs to the view it was opened over
  const liveWasHidden = els.viewLive.hidden;
  els.viewProfile.hidden = name !== "profile";
  els.viewLive.hidden = name !== "live";
  els.viewUsers.hidden = name !== "users";
  els.viewChats.hidden = name !== "chats";
  for (const b of document.querySelectorAll(".navitem")) {
    const on = b.dataset.view === name;
    b.classList.toggle("active", on);
    // Which view is current was conveyed by colour alone; say it out loud too.
    if (on) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  }
  // An admission prompt that came in behind another view is revealed only now:
  // it gets the same 500 ms guard and focus as a prompt that just appeared.
  if (name === "live" && liveWasHidden && !els.admit.hidden) armAdmitGuard(admitShownFor);
  setAdmitModal(!els.admit.hidden); // B3: modal only while the sheet is on screen
  if (name === "profile") renderProfile();
  if (name === "users") refreshUsers();
  if (name === "chats") {
    refreshChats();
    pollMailbox(); // opportunistic fetch on entering the view
  }
}

// Feedback goes to whichever screen the user is actually LOOKING at.
//
// `#hint` lives inside screen 3 (chat), so every validation failure raised on
// screen 2 — empty chat code, missing identity, bad contact handle, no OTP pad,
// pad exhausted — wrote its message into a hidden element. Connect simply did
// nothing, with no explanation. Routing by visible screen fixes all of those at
// once, instead of leaving ten call sites to each remember the right target.
function activeHintEl() {
  if (!els.scrRoom.hidden) return els.roomHint;
  if (!els.scrIdentity.hidden) return els.idHint;
  return els.hint;
}

function hint(text, isErr = false) {
  const el = activeHintEl();
  el.textContent = text;
  el.className = "hint" + (isErr ? " err" : "");
  // Errors are announced immediately; ordinary progress waits for a pause.
  el.setAttribute("aria-live", isErr ? "assertive" : "polite");
}

// Clear stale feedback when moving between screens, so an old error can never
// look like it belongs to the screen you just arrived at.
function clearHints() {
  for (const el of [els.idHint, els.roomHint, els.hint]) {
    if (el) { el.textContent = ""; el.className = "hint"; }
  }
}

// Relay `error` frames (phase 2a, pentest pre-existing). They used to render as
// "Server: " + reason — words the RELAY chose, shown as the app's own sentence,
// so a hostile relay had a line in our voice ("Server: tap It matches"). The
// honest relay only ever sends the fixed reasons in backend/main.py; each maps
// to a sentence the client owns. Anything else gets a generic sentence, and the
// raw reason appears only as a quoted, clipped aside on its own line — never
// joined into our words. A Map, not an object literal: a reason such as
// "constructor" must not find Object.prototype.
const RELAY_REASONS = new Map([
  ["binary frames not accepted", "The relay could not read what this app sent and closed the connection. Connect again."],
  ["frame too large", "A message was larger than the relay accepts, so it closed the connection."],
  ["non-ascii", "The relay only carries plain ASCII text, so it closed the connection."],
  ["rate limited", "The relay is rate-limiting this connection — wait a moment and try again."],
  ["bad envelope", "The relay could not read a message from this app and dropped it."],
  ["already joined", "The relay says this connection is already in a chat."],
  ["join timeout", "Joining took too long, so the relay closed the connection. Connect again."],
  ["approval timeout", "The person who created this chat did not let you in within the time limit."],
  ["idle timeout", "Nothing was sent for a long time, so the relay closed the connection. Connect again to continue."],
  ["room full", "That chat already has two people in it."],
  ["room closed", "The person who created this chat left, so the chat was closed."],
  ["not waiting", "The relay says you are not waiting to be let into this chat."],
  ["already knocked", "Your request to join was already passed on — wait for the person who created this chat."],
  ["not in room", "The relay says you are not in this chat, so it did not pass that on."],
  ["not the room owner", "Only the person who created this chat can let people in or turn them away."],
  ["no such waiting peer", "That person is no longer waiting to be let in."],
]);
// The relay closes the socket right after these (main.py), and onclose returns
// to the room screen, which clears every hint — the trap the refusals escape
// through `closeHint`. These sentences are parked the same way.
const RELAY_FATAL = new Set([
  "binary frames not accepted", "frame too large", "non-ascii",
  "join timeout", "approval timeout", "idle timeout", "room closed",
]);
let closeRelayReason = null;

function relayErrorHint(reason) {
  const known = typeof reason === "string" ? RELAY_REASONS.get(reason) : undefined;
  hint(known || "The relay refused the request.", true);
  if (known || typeof reason !== "string" || !reason) return;
  // Printable ASCII only (no bidi override or line break can rearrange the
  // line), at most 80 characters, in quotes, in an element of its own.
  let said = reason.replace(/[^\x20-\x7e]+/g, "?");
  if (said.length > 80) said = said.slice(0, 79) + "…";
  const aside = document.createElement("span");
  aside.className = "relay-said";
  aside.textContent = `relay says: "${said}"`;
  activeHintEl().append(aside);
}

function accountStatus(text, cls = "") {
  els.accountStatus.textContent = text;
  els.accountStatus.className = "hint" + (cls ? " " + cls : "");
}

// Phase 2b fix round, D3: once registered, the username field with Register
// and Log in steps aside (it competed with Continue); the status line keeps
// the handle. It comes back whenever it is the way forward again: not
// registered, signed out, or the automatic directory login failing (Log in is
// then the manual retry).
function showUsernameRow(show) {
  els.username.closest(".row").hidden = !show;
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
  setIdentityStatus("Unlocked.", "ok");
  els.idFingerprint.hidden = false;
  els.idFingerprint.textContent = fp; // its label is static markup (with a "?")
  els.idPassRow.hidden = true;
  els.idCreate.hidden = true;
  els.idUnlock.hidden = true;
  els.idExport.hidden = false;
  els.idForget.hidden = false;
  // The account directory is only meaningful once we hold an identity to bind.
  els.account.hidden = false;
  els.toRoom.textContent = "Continue →";
  els.toRoom.classList.add("primary");
  els.idCreate.classList.remove("primary");
  els.idUnlock.classList.remove("primary");
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
    accountStatus(`Registered as ${savedName}#${savedToken} — share this handle.`);
    showUsernameRow(false);
    // Async chats only DELIVER once we hold a directory session: pollMailbox
    // needs it, and it is the only way mail is ever fetched. Requiring a
    // separate "Log in" click meant a registered user could send messages that
    // their contact silently never received — log in automatically instead.
    autoLogin(savedName);
  } else if (savedName) {
    els.username.value = savedName;
    accountStatus(`Saved username: ${savedName}. Register (once) to get your shareable handle, or log in to prove control.`);
    showUsernameRow(true);
  } else {
    accountStatus(""); // the "?" beside the username label explains it
    showUsernameRow(true);
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
  // Without an identity the forward action is a fallback, not the thing to do:
  // make Create/Unlock the primary and let "continue anyway" recede.
  els.toRoom.textContent = "Continue without an identity →";
  els.toRoom.classList.remove("primary");
  els.idCreate.classList.toggle("primary", !stored);
  els.idUnlock.classList.toggle("primary", !!stored);
  els.idPassRow.hidden = false;
  els.idCreate.hidden = !!stored;   // hide "Create" if one already exists
  els.idUnlock.hidden = !stored;
  els.idForget.hidden = !stored;
  if (stored) {
    setIdentityStatus("Locked — enter your passphrase.");
  } else {
    setIdentityStatus("No identity on this device yet.");
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
  setIdentityStatus("Generating keys…");
  try {
    identity = await Identity.generate();
    const blob = await identity.export(pass);
    localStorage.setItem(LS_IDENTITY, blob);
    await unlockContacts(pass, { expectStore: false }); // contact store shares the identity passphrase
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
    await unlockContacts(pass, { expectStore: true }); // contact store shares the identity passphrase
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
    // The identity opened; a store may still have refused (fix review
    // 2026-09-21: this used to print an empty, success-looking status).
    statusFn(contactsError ? "Unlocked, but: " + contactsError : "", !!contactsError);
    // An invite link waiting on the identity is applied by refreshUsers(), the
    // Users view's render (phase 2a, pentest pre-existing): applied here first,
    // its line was cleared by that render and the invite already consumed.
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
    setIdentityStatus("Backup copied. It is useless without your passphrase.", "ok");
  } catch {
    setIdentityStatus("Could not access the clipboard. Backup not copied.", "err");
  }
}

async function forgetIdentity() {
  if (!confirm("Remove this identity from the device? Without a backup you cannot recover it, and contacts will need to re-verify you.")) {
    return;
  }
  // Fix review round 2 (L-3): revoke the directory session too.
  //
  // This dropped `apiToken` locally and left the bearer valid on the relay for
  // the rest of TOKEN_TTL_SEC — a live capability surviving the exact control a
  // user reaches for when handing the device on, which is the same reasoning
  // that made the L-4 fix below remove the handle and lookup token. Once M-C
  // stopped re-login from being a revocation, this was the last silent gap.
  // Best-effort and non-blocking on failure: the local wipe must happen either
  // way, and the token expires on its own.
  stopMailboxPolling();
  const staleToken = apiToken;
  apiToken = null;
  if (staleToken) await account.logout(API_BASE, staleToken);

  localStorage.removeItem(LS_IDENTITY);
  closeContact(false); // it shows a record that is about to be gone
  vouchUnsure.clear();   // they belonged to this identity's account
  vouchGen.clear();
  retractPending.clear();
  contactsStale = false; // nothing of this identity is left to reload (cold r5 MINOR-B)
  contactsError = null;
  contacts.wipe(); // bound to the identity passphrase; unusable without it
  chats.wipe();
  // Pentest 2026-07-27 L-4: the handle and the lookup token are PLAINTEXT and
  // used to survive this. "Forget identity" is the control a user reaches for
  // when handing the device on or when they think they are compromised, and it
  // left behind both the directory name that says who used this device and a
  // live capability: the lookup token gates fetching that account's bundle and
  // posting mail to it, and it stays valid until the account is re-registered.
  // They belong to the identity, so they go with it.
  localStorage.removeItem(LS_USERNAME);
  localStorage.removeItem(LS_LOOKUP_TOKEN);
  apiToken = null;
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
    accountStatus(`Registered as ${username}#${lookup_token} — share this handle.`, "ok");
    showUsernameRow(false);
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
// Pentest fix review 2026-07-30 (M-C). This used to retry on every 6 s mailbox
// tick and swallow every failure silently, so a re-login that kept failing —
// most easily because the relay's global challenge bucket was rate-limiting it —
// left the tab permanently offline for sealed mail with NO visible sign: the
// "not logged in" chip is only redrawn when the user happens to open the profile
// view. That is the failure the 401 handler exists to prevent, reached by a
// different road. So: back off, and say something.
let autoLoginBackoffUntil = 0;
let autoLoginFailures = 0;

async function autoLogin(username) {
  if (!identity || apiToken || autoLoginRunning) return false;
  if (!account.isValidUsername(username)) return false;
  if (Date.now() < autoLoginBackoffUntil) return false;
  autoLoginRunning = true;
  try {
    const { token } = await account.login(API_BASE, identity, username);
    apiToken = token;
    autoLoginFailures = 0;
    autoLoginBackoffUntil = 0;
    startMailboxPolling();
    renderProfile();
    if (!els.viewChats.hidden) refreshChats();
    return true;
  } catch (e) {
    // Exponential-ish backoff, capped: 12s, 24s, 48s, 96s, then 2 minutes. Keeps
    // a retry loop from being indistinguishable from an attack on the shared
    // challenge bucket, which is what two tabs doing this became.
    autoLoginFailures += 1;
    const wait = Math.min(120000, 6000 * 2 ** Math.min(autoLoginFailures, 5));
    autoLoginBackoffUntil = Date.now() + wait;
    renderProfile();
    showUsernameRow(true); // D3: the manual Log in is the fallback
    // Visible, once per failure streak, so the user is not silently offline.
    // Routed through hint(), which writes to whichever screen is actually in
    // front of the user — addLine() alone put this in the CHAT TRANSCRIPT, a
    // screen you are usually not on when a background re-login fails, which is
    // the same "only redrawn if you happen to look" complaint that made M-C
    // silent in the first place.
    if (autoLoginFailures === 1 || autoLoginFailures === 4) {
      const why = e && e.message ? e.message : "login failed";
      hint(`Not signed in to the directory — sealed messages will not arrive (${why}). Retrying.`, true);
      addLine("sys", "", `[not signed in to the directory — sealed messages will not arrive (${why})]`);
    }
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
// The store locked itself because another tab wrote first (the profile's
// Verify/Remove): benign — unlocking again loads that version. Said as such,
// never with the Forget advice meant for a store that cannot be opened.
let contactsStale = false;
const STALE_LINE = "Your contacts were changed in another tab — enter your passphrase to load that version.";
// Pentest 2026-08-07 F-ATREST-003/004/005: set when the store refused to open
// for a reason the USER may legitimately override (an unverifiable legacy
// store, or a store this device says existed and is now gone). The Users view
// then offers "Open anyway"; nothing opens the store silently.
let contactsAdoptable = false;
const adoptCodes = new Set(); // which store raised which code, for the override
// A notice about the stores that must outlive the room transcript (fix review
// 2026-09-21: the browser both-deleted warning was one line in the Live room,
// and the Users view rendered a normal empty list with nothing at all).
let storeNotice = null;

// The per-identity id under which the native floor (Android) keeps the contact
// and chat store generations: the hash of the identity's public signing key.
// Only the signing key, deliberately — the bundle grows encryption keys on the
// one-time legacy upgrade, and a floor id that changed then would read as
// "floor deleted" on the store written before it.
async function storeFloorId() {
  if (!identity) return null;
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", identity.edPubRaw));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
}
let apiToken = null;      // directory session token (from Log in), memory only

// Unlock the contact store with the identity passphrase. Called wherever the
// identity itself is created/unlocked, BEFORE the passphrase field is cleared.
// P-02: a failure here leaves the identity usable but the PIN STORE LOCKED,
// which silently disables key-change detection. It is still not fatal (the user
// may legitimately have a foreign blob and want to wipe it), but it must be
// visible wherever it matters — so besides `contactsError` for the Users view,
// the room screen warns and the verification gate refuses to auto-accept.
//
// `opts.expectStore` — an EXISTING identity is being unlocked (not created), so
// a store that has to be created from nothing is worth a warning: in a browser
// there is no floor, and "store + witness both deleted" is indistinguishable
// from a first run (F-ATREST-003). The identity restored onto a new device gets
// the same line; the wording covers both. `opts.adoptLegacy` / `adoptDeleted`
// come from the Users view's explicit "Open anyway".
const ADOPTABLE = new Set([
  "LEGACY_CONTACTS_ADOPTION", "DELETED_CONTACTS_ADOPTION",
  "LEGACY_CHATS_ADOPTION", "DELETED_CHATS_ADOPTION",
]);
// `opts.adopt` — true when the user pressed "Open anyway": each store gets
// exactly the override for the code IT raised last time (fix review
// 2026-09-21: one click used to adopt both stores with both flags, so a user
// who read the contacts warning also adopted an unverifiable chat store).
async function unlockContacts(pass, opts = {}) {
  const floorId = await storeFloorId();
  const flags = (legacy, deleted) => ({
    floorId,
    adoptLegacy: !!opts.adopt && adoptCodes.has(legacy),
    adoptDeleted: !!opts.adopt && adoptCodes.has(deleted),
  });
  const contactOpts = flags("LEGACY_CONTACTS_ADOPTION", "DELETED_CONTACTS_ADOPTION");
  const chatOpts = flags("LEGACY_CHATS_ADOPTION", "DELETED_CHATS_ADOPTION");
  contactsAdoptable = false;
  adoptCodes.clear();
  storeNotice = null;
  contactsStale = false; // an unlock attempt says its own result
  closeContact(false);
  if (contacts.isUnlocked()) contacts.lock(); // re-run from scratch (the override path)
  try {
    const r = await contacts.unlock(pass, contactOpts);
    contactsError = null;
    if (contactOpts.adoptLegacy || contactOpts.adoptDeleted) {
      storeNotice = "Contacts opened WITHOUT a verifiable history — treat every contact as unverified until you re-check the safety number.";
    } else if (r && r.created && opts.expectStore) {
      storeNotice = "No saved contacts were found for this identity. If you have used this device before, " +
        "they were deleted and key-change warnings for earlier contacts are gone — treat every contact as unverified.";
    }
    if (storeNotice) addLine("sys", "", "[" + storeNotice + "]");
  } catch (e) {
    contactsError = e.message;
    if (ADOPTABLE.has(e.code)) { contactsAdoptable = true; adoptCodes.add(e.code); }
    addLine("sys", "", "[contact store did not unlock — key-change warnings are OFF until it does]");
  }
  if (chats.isUnlocked()) chats.lock();
  try {
    const r = await chats.unlock(pass, chatOpts); // chat history shares the at-rest posture
    if (r && r.created && opts.expectStore && !contactsError) {
      addLine("sys", "", "[no chat history was found for this identity on this device]");
    }
  } catch (e) {
    contactsError = contactsError || e.message;
    if (ADOPTABLE.has(e.code)) { contactsAdoptable = true; adoptCodes.add(e.code); }
    addLine("sys", "", "[chat store did not unlock — " + e.message + "]");
  }
}

function usersStatus(text, isErr = false) {
  els.usersStatus.textContent = text;
  els.usersStatus.className = "hint" + (isErr ? " err" : "");
}

function refreshUsers() {
  // Phase 2a, pentest pre-existing: the one place the status line is cleared.
  // renderUserList() used to clear it, which erased addContactFromHandle()'s
  // result ("…keys DIFFER…") and the invite line below in their own render.
  usersStatus("");
  const unlocked = contacts.isUnlocked();
  els.usersLocked.hidden = unlocked;
  els.usersUnlocked.hidden = !unlocked;
  if (!unlocked) {
    els.usersLocked.querySelector("p").textContent = contactsStale ? STALE_LINE : contactsError
      ? "Contact store error: " + contactsError +
        (contactsAdoptable ? "" :
          " (Forget + recreate the identity resets it — contacts are bound to the identity passphrase.)")
      : "Locked. Enter your passphrase.";
    // F-ATREST-003/004/005: the override is offered, never taken for the user.
    els.usersAdopt.hidden = !contactsAdoptable;
    els.usersAdoptHint.hidden = !contactsAdoptable;
    return;
  }
  renderMyHandle();
  applyPendingInvite();
  renderUserList();
  if (storeNotice) usersStatus(storeNotice, true);
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

  // L-4: sign-out is only meaningful while a session exists. This is the ONLY
  // revocation a user can trigger — "log in again" is deliberately no longer a
  // revocation, because making it one made two tabs fight (M-C).
  els.profileLogout.hidden = !apiToken;
  els.profileSessionHint.hidden = !apiToken;
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
  usersStatus("Handle received — review it and press Add.");
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
  // Cold M3: a re-render (mail, a vouch refresh) replaces the rows; the row
  // that had keyboard focus gets it back, as the Chats list does (C2).
  const focused = els.userList.contains(document.activeElement)
    ? document.activeElement.closest("li")?.dataset.user : null;
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
    li.dataset.user = c.username; // find the row again (focus return from the profile)

    // The row's head is ONE button — avatar, name, trust mark — that opens
    // the contact's short profile. The fingerprint and the Verify / Remove
    // actions live there now, next to each other: the value you compare
    // sits directly above the button that says you compared it.
    const open = document.createElement("button");
    open.type = "button";
    open.className = "u-open";
    open.dataset.initial = c.username.charAt(0); // the avatar disc (CSS attr())
    open.setAttribute("aria-haspopup", "dialog");
    const head = document.createElement("span");
    head.className = "u-head";
    const name = document.createElement("span");
    name.className = "u-name";
    name.textContent = c.username;
    const mark = document.createElement("span");
    // No key-changed caption here: this row says it in a sentence of its own.
    renderMark(mark, c, false);
    head.append(name, mark);
    open.appendChild(head);
    open.addEventListener("click", () => openContact(c.username, "users"));
    li.appendChild(open);

    // The claim and the warnings stay IN the list: a security signal is never
    // behind a tap. The profile repeats them.
    for (const line of contactWarnings(c)) li.appendChild(line);
    // F-07: a contact whose stored keys are malformed cannot be verified —
    // said in the list too, not only behind the tap (the fingerprint is
    // computed here for that alone).
    Identity.fingerprintOf(keysOf(c)).catch(() => {
      const warn = document.createElement("div");
      warn.className = "hint err";
      warn.textContent = "fingerprint unavailable — stored keys are malformed";
      li.appendChild(warn);
    });
    // Hot M6: the pointer opens the profile from anywhere on the row — the
    // claim and warning lines too; the keyboard has the one button.
    // A drag or double click that selects text (the claimed name is what
    // someone would copy) is a selection, not a tap (cold r2 m2).
    li.addEventListener("click", (e) => {
      if (e.target.closest("button") || String(getSelection()).trim()) return;
      open.click();
    });

    els.userList.appendChild(li);
  }
  if (focused) [...els.userList.children].find((li) => li.dataset.user === focused)?.querySelector(".u-open")?.focus();
  refreshVouchMarks(); // opportunistic vouched-mark refresh; re-renders only on change
  renderContact(); // the profile over the list follows the store
}

// The lines a contact carries beside its name, in the Users row and in its
// profile alike: the self-claimed name (F-01) and the key-changed / H-01 reset
// warnings. Same words in both places.
function contactWarnings(c, inSheet = false) {
  const out = [];
  // F-01: an auto-created contact's self-claimed handle is displayed as a
  // claim, clearly separated from the neutral local label, so a stranger
  // cannot make themselves LOOK like a name you recognise. In the profile,
  // when the claim IS the handle printed under it, the sentence points there
  // instead of quoting the attacker's string a second time (hot M8, M-B).
  if (c.claimedName) {
    const claim = document.createElement("div");
    claim.className = "u-claim";
    claim.textContent = inSheet && c.token && c.claimedName === mailHandle(c)
      ? "claims the handle below — unverified, they chose this name themselves"
      : `claims to be "${c.claimedName}" — unverified, they chose this name themselves`;
    out.push(claim);
  }
  if (c.keyChangedAt && !c.verified) {
    const warn = document.createElement("div");
    warn.className = "hint err";
    warn.textContent = "this user's key CHANGED since you saved them — re-verify in person before trusting";
    out.push(warn);
  } else if (c.reverify && !c.verified) {
    // Set by the H-01 store migration: the old verified mark was compared against a
    // fingerprint that did not cover the encryption keys.
    const warn = document.createElement("div");
    warn.className = "hint err";
    warn.textContent = "verification reset — the fingerprint format now also covers this user's encryption keys; compare it again in person";
    out.push(warn);
  }
  return out;
}

// ---- contact profile ---------------------------------------------------------
// A saved user's short profile, as a sheet over Users or Chats. Opened only by
// the user's own tap (a Users row, a Chats row's avatar, the conversation's
// name). It is rendered from the store on every open and again whenever the
// store may have changed under it, and closes itself when the contact goes,
// the store locks, or the view changes.

let contactShown = null;   // username of the contact on screen, or null
let contactFrom = null;    // "users" | "chats" | "convo": where focus goes back to
let contactKeys = null;    // the keys the fingerprint on screen is (being) computed from;
                           // a computation for any other keys never writes
let contactFpReady = false;
let contactBusy = false;   // a Verify/Unverify (and its vouch) is running: further clicks are refused (pentest L-1)
const VOUCH_TIMEOUT_MS = 15000; // a relay that never answers must not hold contactBusy (pentest pass 2)
// Vouches the relay may hold although we never heard it say so (a vouch POST
// that got no answer: pentest p3 L-1), and retractions the user asked for
// that could not be sent yet (not logged in, or the DELETE failed: pentest
// p5 L-3). Keyed like the relay keys a vouch — by the DIRECTORY name, for
// this identity — not by our local label (pentest p5 L-2). In memory only.
//
// Nothing retracts on its own from what the relay LISTS: that let a
// stranger's claimed handle delete our real vouches (pentest p4 M-1). Every
// retraction here starts from the user's own Unverify or Remove.
const vouchUnsure = new Set();   // dirNames
const vouchGen = new Map();      // dirName -> vouch POSTs sent this session
const retractPending = new Set(); // dirNames the user un-trusted; DELETE not yet delivered
// Another saved record we still trust under the same directory name (an
// automatic contact claims a real user's name): its vouch is the wanted one.
const trustedUnder = (name) => contacts.isUnlocked() &&
  contacts.list().some((o) => o.verified && dirName(o) === name);
function sendRetract(name) {
  if (trustedUnder(name)) { retractPending.delete(name); return true; }
  if (!apiToken) return false; // stays pending: the next logged-in tick sends it
  const token = apiToken, gen = vouchGen.get(name) || 0;
  retractPending.add(name);
  account.unvouch(API_BASE, token, name).then(() => {
    if ((vouchGen.get(name) || 0) === gen) retractPending.delete(name);
  }).catch(() => { /* stays pending; retried on the next mailbox tick */ });
  return true;
}
// Returns false when the retraction could not be sent now (not logged in).
function retractVouch(c) {
  const name = dirName(c);
  if (trustedUnder(name)) return true;
  retractPending.add(name);
  const sent = sendRetract(name);
  if (vouchUnsure.delete(name)) {
    const gen = vouchGen.get(name) || 0;
    setTimeout(() => {
      if ((vouchGen.get(name) || 0) !== gen) return; // vouched again since: that one is wanted
      if (trustedUnder(name)) return;
      sendRetract(name);
    }, VOUCH_TIMEOUT_MS + 5000);
  }
  return sent;
}
// The mailbox tick (every few seconds while logged in) delivers what is
// pending; a newer vouch for the name cancels it.
function flushRetractions() {
  if (!apiToken) return;
  for (const name of [...retractPending]) {
    if (trustedUnder(name)) { retractPending.delete(name); continue; }
    sendRetract(name);
  }
}
let contactShownAt = 0;    // when the sheet appeared (the 500 ms rule below)

// The sheet appears under the user's own tap, so a double tap's second half
// lands on it — on a phone right where Unverify or Message now sit (pentest
// L-3). Same rule as the admission prompt: an activation within 500 ms of the
// sheet appearing is not a decision about what it shows. The event's own
// timestamp, so a queued event cannot pass as a late one.
const CONTACT_GUARD_MS = 500;
const contactTooSoon = (e) => !e || e.timeStamp < contactShownAt + CONTACT_GUARD_MS;

const keysOf = (c) => ({ ed: c.ed, mldsa: c.mldsa, ecdh: c.ecdh ?? null, mlkem: c.mlkem ?? null });
const sameKeys = (a, b) => !!a && !!b &&
  a.ed === b.ed && a.mldsa === b.mldsa && a.ecdh === b.ecdh && a.mlkem === b.mlkem;

function openContact(username, from) {
  if (!contacts.isUnlocked() || !contacts.get(username)) return;
  contactShown = username;
  contactFrom = from;
  contactKeys = null; // a fresh open always recomputes the fingerprint
  els.contactStatus.textContent = "";
  els.contactStatus.className = "hint";
  // Pentest L-4: one Copy button serves every contact; a "Copied ✓" left over
  // from the last one must not stand beside this one's handle.
  resetCopyLabel(els.contactCopyHandle);
  // Each profile opens as itself: a "?" opened on the last one stays shut.
  for (const d of els.contactSheet.querySelectorAll("details")) d.open = false;
  renderContact();
  if (contactShown === null) return; // the render found nothing to show
  els.contactSheet.hidden = false;
  els.contactScrim.hidden = false;
  contactShownAt = performance.now();
  applyModal();
  els.contactClose.focus();
}

function closeContact(restoreFocus = true) {
  if (contactShown === null) return;
  const hadFocus = els.contactSheet.contains(document.activeElement);
  const user = contactShown, from = contactFrom;
  contactShown = null;
  contactFrom = null;
  contactKeys = null; // a fingerprint still being computed must not land
  els.contactSheet.hidden = true;
  els.contactScrim.hidden = true;
  applyModal();
  if (restoreFocus && hadFocus) contactReturnFocus(user, from);
}

// Focus goes back to the control that opened the sheet; the rows are
// re-rendered freely, so it is found again by the contact's name.
function contactReturnFocus(user, from) {
  const inList = (list, sel) =>
    [...list.querySelectorAll("li")].find((li) => li.dataset.user === user)?.querySelector(sel);
  // Cold M2: after a Remove the Chats avatar is a picture (a span) and the
  // conversation's name is disabled — fall back to what is still a control.
  const target = from === "users" ? inList(els.userList, ".u-open") || els.addHandle
    : from === "chats" ? inList(els.chatList, "button.u-avatar") || inList(els.chatList, ".chatrow-open") || els.chatNew
      : from === "convo" && !els.chatConvo.hidden ? (els.chatPeer.disabled ? els.chatBack : els.chatPeer) : null;
  if (target && !target.disabled) target.focus();
}

function renderContact() {
  if (contactShown === null) return;
  const c = contacts.isUnlocked() ? contacts.get(contactShown) : null;
  if (!c) { closeContact(); return; }

  els.contactAvatar.textContent = c.username.charAt(0);
  els.contactName.textContent = c.username;
  renderMark(els.contactMark, c, false); // hot M5: the box under the head says it
  els.contactWarn.textContent = "";
  els.contactWarn.append(...contactWarnings(c, true));

  // The handle is what addresses them. For a contact made from an unknown
  // sender's mail it is the name THEY put in the envelope: labelled a claim.
  els.contactHandleLabel.textContent = c.auto || c.claimedName ? "Handle they claim" : "Handle";
  if (c.token) {
    // Two spans, so the line breaks at the "#" before it cuts the token.
    const user = document.createElement("span");
    user.textContent = dirName(c);
    const tok = document.createElement("span");
    tok.className = "tok";
    tok.textContent = "#" + c.token;
    els.contactHandle.replaceChildren(user, tok);
    els.contactHandle.className = "hint contact-handle ok";
    els.contactCopyHandle.hidden = false;
  } else {
    els.contactHandle.textContent = "No handle saved — re-add them by their username#token handle to reply.";
    els.contactHandle.className = "hint contact-handle";
    els.contactCopyHandle.hidden = true;
  }

  // The fingerprint is computed from the keys in the store NOW. Until it is on
  // screen there is nothing to compare, so Verify waits for it; and a
  // computation for keys that have since moved never writes.
  const keys = keysOf(c);
  if (!sameKeys(keys, contactKeys)) {
    contactKeys = keys;
    contactFpReady = false;
    els.contactFingerprint.textContent = "…";
    els.contactFingerprint.className = "safety";
    Identity.fingerprintOf(keys).then((f) => {
      if (!sameKeys(keys, contactKeys)) return; // closed, or the keys moved meanwhile
      els.contactFingerprint.textContent = f;
      contactFpReady = true;
      renderContactActions(contacts.get(contactShown));
    }).catch(() => {
      if (!sameKeys(keys, contactKeys)) return;
      // F-07: a contact whose stored keys are malformed cannot be verified.
      els.contactFingerprint.textContent = "fingerprint unavailable — stored keys are malformed";
      els.contactFingerprint.className = "safety err";
    });
  }

  // What else the app knows, quietly: when, whether, by whom, and whether a
  // sealed message can reach them. Day precision only.
  // Hot M3: only what the pill does not already say — two dates, and the one
  // reason a sealed message cannot reach them (no token says so above).
  const day = (t) => new Date(t).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
  els.contactFacts.textContent = "";
  const facts = [];
  if (c.addedAt) facts.push(["Saved", day(c.addedAt)]);
  if (c.verified && c.verifiedAt) facts.push(["Verified", day(c.verifiedAt)]);
  if (c.token && !(c.ecdh && c.mlkem)) facts.push(["Sealed mail", "no encryption keys published yet"]);
  for (const [term, value] of facts) {
    // Each pair in a <div> (valid in a <dl>): a term never wraps away from
    // its value (hot r2 m-a).
    const pair = document.createElement("div");
    const dt = document.createElement("dt");
    dt.textContent = term;
    const dd = document.createElement("dd");
    dd.textContent = value;
    pair.append(dt, dd);
    els.contactFacts.append(pair);
  }
  renderContactActions(c);
}

function renderContactActions(c) {
  if (!c) return;
  // Message: not from the conversation it would reopen, and not while the
  // chat store is closed.
  els.contactMessage.hidden = contactFrom === "convo" || !chats.isUnlocked();
  // One next step. A changed key (or the H-01 reset) makes verifying it the
  // step (hot B1 — Signal's pattern); otherwise Message, but only when a
  // sealed message can actually reach them (hot M1).
  const changed = !c.verified && !!(c.keyChangedAt || c.reverify);
  const canSend = !!(c.token && c.ecdh && c.mlkem);
  els.contactMessage.className = changed || !canSend ? "" : "primary";
  els.contactVerify.className = c.verified ? "ghost" : changed ? "primary" : "";
  // The primary comes first — in the DOM, so Tab and reading order match
  // what is on screen (hot M-C, cold m1).
  // Moving a focused node blurs it (cold r3 MAJOR-A, pentest L-3): move the
  // one that is not focused. A reorder under the pointer also restarts the
  // 500 ms rule, so a tap aimed at one button never lands on the other.
  const focused = document.activeElement;
  const [first, second] = changed ? [els.contactVerify, els.contactMessage] : [els.contactMessage, els.contactVerify];
  if (first.nextElementSibling !== second) {
    if (focused === first) first.after(second); else first.parentNode.insertBefore(first, second);
    contactShownAt = performance.now();
  }
  els.contactVerify.textContent = c.verified ? "Unverify" : "Verified in person\u00a0✓";
  // Pentest L-1: the click acts as it was rendered, never as a fresh read
  // of the store says — a second click must not undo the first.
  els.contactVerify.dataset.action = c.verified ? "unverify" : "verify";
  // Disabling the focused button would drop focus to <body>: keep it in the
  // sheet. (A running action is refused by contactBusy, not by disabling.)
  els.contactVerify.disabled = !c.verified && !contactFpReady;
  if (focused === els.contactVerify && els.contactVerify.disabled) els.contactSheet.focus();
}

// "One moment" on whichever sheet is up; the running action clears it when it
// ends, also from another contact's sheet (pentest p4 I-3).
const BUSY_LINE = "Still saving the last change — one moment.";
function busyNotice() { contactStatus(BUSY_LINE); }
function contactStatus(text, isErr = false) {
  els.contactStatus.textContent = text;
  els.contactStatus.className = "hint" + (isErr ? " err" : "");
}

// Every place that may have changed the store re-renders the lists; the sheet
// follows whichever list is under it.
function contactsChanged() {
  if (!els.viewUsers.hidden) renderUserList();
  // Pentest L-2 / cold M1: the Chats row marks and the conversation header
  // show the same trust state — they follow too (each re-renders the sheet).
  else if (!els.viewChats.hidden && chats.isUnlocked() && contacts.isUnlocked()) refreshChats();
  else renderContact();
}

els.contactClose.addEventListener("click", () => closeContact());
// Cold m1: a press on the scrim must not blur the sheet first, or the close
// cannot tell focus was in it and does not give it back to the opener. Cold
// m2: the second half of the double tap that opened the sheet lands here
// while it slides in — not a request to close it.
els.contactScrim.addEventListener("mousedown", (e) => e.preventDefault());
els.contactScrim.addEventListener("click", (e) => { if (!contactTooSoon(e)) closeContact(); });
// Cold m3: Escape closes from wherever focus is while the sheet is up (a
// click on its text focuses the sheet itself; the rest of the page is inert).
document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape" || contactShown === null) return;
  e.preventDefault();
  closeContact();
});
els.contactSheet.addEventListener("keydown", (e) => {
  if (e.key !== "Tab") return;
  const stops = [...els.contactSheet.querySelectorAll("button, summary, [tabindex]")]
    .filter((el) => !el.disabled && el.tabIndex >= 0 && el.offsetParent !== null);
  if (!stops.length) return;
  const first = stops[0], last = stops[stops.length - 1];
  const at = document.activeElement;
  if (e.shiftKey ? at === first || at === els.contactSheet : at === last) {
    e.preventDefault();
    (e.shiftKey ? last : first).focus();
  }
});

els.contactCopyHandle.addEventListener("click", (e) => {
  if (contactTooSoon(e)) return;
  const c = contactShown !== null ? contacts.get(contactShown) : null;
  if (c && c.token) copyToClipboard(els.contactCopyHandle, mailHandle(c));
});

els.contactMessage.addEventListener("click", async (e) => {
  if (contactTooSoon(e)) return;
  const user = contactShown;
  if (user === null || !contacts.get(user) || !chats.isUnlocked()) return;
  closeContact(false);
  showView("chats");
  await openChat(user);
});

els.contactVerify.addEventListener("click", async (e) => {
  if (contactTooSoon(e)) return;
  if (contactBusy) { busyNotice(); return; }
  const user = contactShown;
  const c = user !== null ? contacts.get(user) : null;
  if (!c) return;
  // Pentest L-1: act as the button was rendered. If the store no longer
  // agrees (another tab, or a click that raced the last one), redraw.
  const wantVerified = els.contactVerify.dataset.action === "verify";
  if (wantVerified === !!c.verified) { renderContact(); return; }
  if (wantVerified ? !confirm(
    `Mark "${c.username}" as verified ONLY if you compared this fingerprint with them in person ` +
    "(or over a call where you recognise their voice). Continue?",
  ) : !confirm(
    // Unverify revokes the pin: as destructive as Remove, and gated the same.
    `Unverify "${c.username}"? You will need to compare the fingerprint with them in person again.`,
  )) return;
  // What the user compared is the fingerprint on screen. If the record's keys
  // moved while the sheet was open (a mail re-keyed them), that is not the
  // key this click would mark: refuse and show the new one instead.
  const now = contacts.get(user);
  if (!now || contactShown !== user || !!now.verified !== !!c.verified ||
      (wantVerified && (!contactFpReady || !sameKeys(keysOf(now), contactKeys)))) {
    renderContact();
    contactStatus("This user's keys changed while their profile was open — compare the new fingerprint.", true);
    return;
  }
  // Busy from the store write to the end of the vouch round trip, so a vouch
  // and an unvouch for the same contact can never race each other at the
  // relay; the round trip is bounded, so busy always ends.
  contactBusy = true;
  let statusMsg = null, statusErr = false, lostErr = null;
  try {
    try {
      await contacts.setVerified(c.username, wantVerified);
    } catch (err) {
      // Pentest pass 2: e.g. the store refused a stale write (another tab)
      // and locked itself — say so instead of failing silently; a locked
      // store says it on its locked panel (the lists are hidden then).
      statusMsg = "Could not save: " + err.message;
      statusErr = true;
      if (!contacts.isUnlocked()) { contactsError = err.message; lostErr = err; }
      return;
    }
    // The store has changed: show it now, not after the vouch round trip.
    // The button now says the opposite, so the 500 ms rule starts again (a
    // double click's second half must not take it at its new word).
    contactShownAt = performance.now();
    contactsChanged();
    if (wantVerified) {
      // Just turned verified — offer to publish a signed vouch so users who
      // verified YOU can see this contact as "vouched by you". Opt-in.
      if (apiToken && identity && confirm(
        `Also publish a signed vouch for "${c.username}"? Anyone who has verified YOU ` +
        "will then see them as vouched-by-you. (This reveals publicly that you know them.)",
      )) {
        contactStatus("Publishing the vouch…");
        const name = dirName(c), who = identity;
        vouchGen.set(name, (vouchGen.get(name) || 0) + 1);
        retractPending.delete(name); // this vouch is the wanted state now
        try {
          // Vouch over the FULL in-person-verified bundle incl. encryption
          // keys (H-01) so the vouched mark attests the keys used to seal async
          // messages, not just the signing identity — the keys compared (`c`).
          await account.vouch(API_BASE, identity, apiToken, dirName(c), keysOf(c), AbortSignal.timeout(VOUCH_TIMEOUT_MS));
          statusMsg = `Vouch for "${c.username}" published.`;
        } catch (err) {
          statusErr = true;
          // No answer at all (timeout, abort, network) is not "not published":
          // the relay may have acted (pentest p3 L-1, p4 L-4). Only an HTTP
          // error response means it refused.
          if (err && (err.name === "TimeoutError" || err.name === "AbortError" || err instanceof TypeError)) {
            // Only for the identity that sent it: a Forget during the round
            // trip must not hand the next identity a retraction (p5 L-1).
            if (identity === who) vouchUnsure.add(name);
            statusMsg = `No answer from the relay about the vouch for "${c.username}" — it may still have been ` +
              "published. Unverify retracts it.";
          } else {
            statusMsg = `Could not publish the vouch for "${c.username}": ` + err.message;
          }
        }
      } else if (!apiToken) {
        statusMsg = "Tip: Log in (Live room → step 1) to also publish a signed vouch for people you verify.";
      }
    } else {
      // Turned back to unverified — retract a published vouch if any. Not
      // logged in: say it will happen, instead of silently not (p5 L-3).
      if (!retractVouch(c)) {
        statusMsg = `Not logged in — any vouch you published for "${c.username}" will be retracted once you are.`;
      }
    }
  } finally {
    contactBusy = false;
    // Whatever happened, the sheet and the lists show the store. A store that
    // locked itself (the refusal above) has nothing to show: the sheet closes
    // and the view underneath shows its locked state, with the reason.
    if (!contacts.isUnlocked()) {
      contactStoreLost(lostErr);
    } else {
      contactsChanged();
      // The result belongs to this contact: another one's sheet opened
      // meanwhile never shows it (pentest p3 I-1); the list's line names it.
      if (contactShown === user) contactStatus(statusMsg || "", statusErr);
      else if (els.contactStatus.textContent === BUSY_LINE) contactStatus("");
      if (!els.viewUsers.hidden) usersStatus(statusMsg || "", statusErr); // this action's result replaces the last one's
      else if (!els.viewChats.hidden && statusErr) chatsStatus(statusMsg, true);
    }
  }
});

// The store locked itself under the sheet (it refused a write another tab
// made stale): close the sheet, show the view's locked panel — which carries
// the reason (contactsError) — and put focus in its passphrase field.
function contactStoreLost(err = null) {
  contactsStale = !err || err.code === "STALE";
  closeContact(false);
  if (!els.viewUsers.hidden) { refreshUsers(); els.usersUnlockPass.focus(); }
  else if (!els.viewChats.hidden) { refreshChats(); els.chatsUnlockPass.focus(); }
}

els.contactRemove.addEventListener("click", async (e) => {
  if (contactTooSoon(e)) return;
  const user = contactShown;
  const c = user !== null ? contacts.get(user) : null;
  if (!c) return;
  if (contactBusy) { busyNotice(); return; }
  if (!confirm(`Remove "${c.username}" (and your verification of them) from this device?`)) return;
  try {
    await contacts.remove(c.username);
  } catch (err) {
    if (!contacts.isUnlocked()) { contactsError = err.message; contactStoreLost(err); return; }
    contactStatus("Could not remove: " + err.message, true);
    return;
  }
  // A vouch of ours for them would outlive the contact (pentest p3 I-2).
  // Only where one can exist (verified, or a vouch we are unsure about): a
  // DELETE for anyone else would tell the relay who we had saved.
  if (c.verified || vouchUnsure.has(dirName(c))) retractVouch(c);
  // Re-render first: the render finds the contact gone and closes the sheet,
  // and focus then goes where the removed row's neighbours are, not into a
  // row that is about to be replaced.
  if (!els.viewUsers.hidden) {
    usersStatus(""); // a line about the removed row would now be stale
    renderUserList();
  } else if (!els.viewChats.hidden) {
    refreshChats();
  }
  closeContact();
});

// Refresh the vouched marks: fetch vouches for unverified contacts and validate
// them LOCALLY — a vouch counts only if (a) the voucher is a contact YOU
// verified in person, (b) the server-returned voucher keys equal your pinned
// copy, and (c) the dual signature verifies over the target bundle YOU hold.
// A lying directory therefore cannot invent a vouched mark.
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
        // voucher made over the REAL enc keys) no longer matches, so no vouched mark is
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
      // F-PROTO-005: `c` is the snapshot the signatures were checked against;
      // the store refuses the write if the record's keys moved meanwhile.
      try {
        if (await contacts.setVouches(c.username, names, {
          ed: c.ed, mldsa: c.mldsa, ecdh: c.ecdh ?? null, mlkem: c.mlkem ?? null,
        })) changed = true;
      } catch (err) {
        // The usual first write in an old tab: another tab wrote meanwhile,
        // the store locked itself (pentest p5 L-4) — show that, not a dead list.
        if (!contacts.isUnlocked()) { contactsError = err.message; contactStoreLost(err); return; }
        throw err;
      }
    }
  } finally {
    vouchRefreshRunning = false;
  }
  if (changed) contactsChanged();
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
  // (H-01). upsert() keeps an existing verified mark only when EVERY key (incl. ecdh/mlkem)
  // still matches what was verified in person; any change drops it to unverified.
  const before = contacts.get(parsed.username);
  await contacts.upsert({
    username: parsed.username, token: parsed.token,
    ed: bundle.ed, mldsa: bundle.mldsa,
    ecdh: bundle.ecdh || null, mlkem: bundle.mlkem || null,
  });
  const after = contacts.get(parsed.username);
  els.addHandle.value = "";
  usersStatus(after.verified
    ? `Updated "${parsed.username}" — keys match what you verified in person.`
    : (before && before.verified
      ? `"${parsed.username}" — the fetched keys DIFFER from what you verified; reset to unverified. Re-verify in person.`
      : `Added "${parsed.username}" (unverified — compare fingerprints in person to trust this key).`));
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

// The trust mark, drawn into `el` (a11y/design review B5). The pill holds the
// words and the level class: ok = verified by you; mid = vouched — someone YOU
// verified published a vouch whose signature checked out against YOUR pinned
// copy of their keys; none = unverified / not a contact.
// F-PROTO-005 (adjacent): a record whose keys changed since it was last
// verified says so wherever the mark is shown. That used to be a suffix run
// into the pill's words; it is now a caption span on its own line inside the
// box-shaped `.changed` mark. Its " — " stays in the text, visually hidden, so
// the mark's textContent reads exactly as it did.
function renderMark(el, c, note = true) {
  const vouched = !!(c && !c.verified && c.vouchedBy && c.vouchedBy.length);
  const changed = !!(c && !c.verified && c.keyChangedAt);
  el.className = "u-mark" + (c && c.verified ? " ok" : vouched ? " mid" : "") + (changed ? " changed" : "");
  el.textContent = !c ? "not in your users list"
    : c.verified ? "verified by you"
      : vouched ? "vouched by " + c.vouchedBy.join(", ") : "unverified";
  if (changed && note) {
    const cap = document.createElement("span");
    cap.className = "u-mark-note";
    const sep = document.createElement("span");
    sep.className = "vh";
    sep.textContent = " — ";
    cap.append(sep, "key CHANGED since you last verified");
    el.append(cap);
  }
}

function refreshChats() {
  const unlocked = chats.isUnlocked() && contacts.isUnlocked();
  els.chatsLocked.hidden = unlocked;
  els.chatsUnlocked.hidden = !unlocked;
  if (!unlocked) {
    // Fix review 2026-09-21: a chat store that refused while contacts opened
    // had no visible error and no override anywhere — a dead end whose only
    // exit was Forget identity. The Chats view now carries both.
    els.chatsLocked.querySelector("p").textContent = contactsStale && identity ? STALE_LINE : contactsError && identity
      ? "Chat store error: " + contactsError
      : "Locked. Enter your passphrase.";
    els.chatsAdopt.hidden = !contactsAdoptable;
    els.chatsAdoptHint.hidden = !contactsAdoptable;
    return;
  }
  if (!apiToken) {
    chatsStatus("Not logged in — messages cannot arrive. Log in on step 1 of the Live room.");
  } else {
    chatsStatus("");
  }
  // "Start a chat" picker: saved users not already in the chat list.
  const picked = els.chatNew.value; // a rebuild keeps the user's pick (cold r2 m5)
  els.chatNew.textContent = "";
  const have = new Set(chats.list().map((c) => c.username));
  const saved = contacts.list();
  const candidates = saved.filter((c) => !have.has(c.username));
  const none = document.createElement("option");
  none.value = "";
  // Phase 2a, pentest pre-existing: "add users first" was also shown when
  // every saved user already had a chat open.
  none.textContent = candidates.length ? "— pick a user —"
    : saved.length ? "— every saved user already has a chat —"
      : "— add users in the Users view first —";
  els.chatNew.appendChild(none);
  for (const c of candidates) {
    const o = document.createElement("option");
    o.value = c.username;
    o.textContent = c.username;
    els.chatNew.appendChild(o);
  }
  if (picked && candidates.some((c) => c.username === picked)) els.chatNew.value = picked;
  if (activeChat) {
    renderConversation();
  } else {
    renderChatList();
  }
}

function renderChatList() {
  // C2 (a11y review): a re-render (mail arriving) replaces the rows; a row
  // that had keyboard focus gets it back instead of dropping it to <body>.
  const focused = els.chatList.contains(document.activeElement)
    ? document.activeElement.closest("li")?.dataset.user : null;
  els.chatConvo.hidden = true;
  els.chatListWrap.hidden = false;
  els.chatList.textContent = "";
  const open = chats.list();
  if (open.length === 0) {
    els.chatList.appendChild(contacts.list().length
      ? emptyRow("No chats yet", "Pick a user above.")
      : emptyRow("No users yet", "Add someone in Users."));
  }
  for (const chat of open) {
    const c = contacts.get(chat.username);
    const li = document.createElement("li");
    li.className = "chatrow";
    li.dataset.user = chat.username; // C2: find the row again
    // Two controls per row: the avatar opens the contact's profile, the rest
    // of the row opens the conversation (B4, a11y review: real buttons, so the
    // keyboard reaches and operates both; a button inside a role="button" row
    // would be invalid). A sender who is not a saved user has no profile: the
    // disc is then only a picture.
    const av = document.createElement(c ? "button" : "span");
    av.className = "u-avatar";
    av.dataset.initial = chat.username.charAt(0); // the avatar disc (CSS attr())
    if (c) {
      av.type = "button";
      av.setAttribute("aria-label", "Profile of " + chat.username);
      av.setAttribute("aria-haspopup", "dialog");
      av.addEventListener("click", () => openContact(chat.username, "chats"));
    } else {
      av.setAttribute("aria-hidden", "true");
    }
    const open = document.createElement("button");
    open.type = "button";
    open.className = "chatrow-open";
    const head = document.createElement("span");
    head.className = "u-head";
    const name = document.createElement("span");
    name.className = "u-name";
    name.textContent = chat.username;
    const mark = document.createElement("span");
    renderMark(mark, c);
    head.append(name, mark);
    const last = chat.messages[chat.messages.length - 1];
    const preview = document.createElement("span");
    preview.className = "u-fp";
    preview.textContent = last ? (last.dir === "out" ? "you: " : "") + last.text.slice(0, 60) : "no messages yet";
    open.append(head, preview);
    open.addEventListener("click", () => openChat(chat.username));
    li.append(av, open);
    els.chatList.appendChild(li);
  }
  if (focused) focusChatRow(focused);
  renderContact(); // the profile over the list follows the store
}

// C2: focus the row for `username`, else the first row.
function focusChatRow(username) {
  const rows = [...els.chatList.querySelectorAll("li.chatrow")];
  const row = rows.find((r) => r.dataset.user === username) || rows[0];
  if (row) row.querySelector(".chatrow-open").focus();
}

async function openChat(username) {
  await chats.ensure(username);
  activeChat = username;
  renderConversation();
  // C2: the row that had focus is hidden now; continue in the conversation.
  els.chatBack.focus();
}

function renderConversation() {
  const chat = chats.get(activeChat);
  if (!chat) return;
  els.chatListWrap.hidden = true;
  els.chatConvo.hidden = false;
  const c = contacts.get(activeChat);
  els.chatPeer.textContent = activeChat;
  els.chatPeer.disabled = !c; // no saved user, no profile
  els.chatPeer.toggleAttribute("aria-haspopup", !!c); // cold m4: and it opens nothing
  if (c) els.chatPeer.setAttribute("aria-haspopup", "dialog");
  renderMark(els.chatPeerMark, c);
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
  els.chatMode.textContent = chat.mode;
  els.chatModeSel.value = chat.mode;

  // Pending mode negotiation banner.
  renderPending(chat);

  // What the mode means sits behind the "?" beside the mode picker; the
  // composer's hint line keeps only what the user must act on.
  els.chatModeWhy.textContent = chat.mode === "AES256"
    ? "AES256 — extra AES-256-GCM under your shared chat passphrase, inside the sealed PQ envelope."
    : "SEALED — hybrid ECDH P-256 + ML-KEM-768, sender sealed inside. " + (c && c.verified ? "" : "Verify this contact in person for the strongest trust.");
  renderContact(); // the profile over the conversation follows the store
  if (!c) {
    chatHint("This sender is not in your Users list — you cannot reply until they share their handle.", true);
  } else if (!c.token) {
    chatHint("No handle token saved for this user — re-add them by their full username#token handle to reply.", true);
  } else if (!c.ecdh || !c.mlkem) {
    chatHint("This user has not published encryption keys yet (older app) — they must unlock once with the updated app; then re-add them.", true);
  } else {
    chatHint("");
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
  if (!identity || !chats.isUnlocked() || !contacts.isUnlocked()) return;
  // Fix review round 2 (M-1): re-authenticate from HERE, not only from the 401
  // branch below.
  //
  // The 401 branch cleared `apiToken` and called `autoLogin` once. If that call
  // failed — a 429 from the global challenge bucket, a blip, or the new
  // deliberate sign-out — `apiToken` stayed null and every later tick returned
  // at this very line, before ever reaching the 401 branch again. So there was
  // no second attempt, the backoff ladder added for M-C was unreachable from
  // the only periodic caller, and the tab sat permanently offline for sealed
  // mail: exactly the state M-C was supposed to remove, arrived at by a
  // different road. autoLogin's own backoff is what keeps this from becoming a
  // 6 s retry loop against a shared bucket.
  if (!apiToken) {
    const savedName = localStorage.getItem(LS_USERNAME);
    if (savedName) await autoLogin(savedName);
    return; // let the next tick collect, with a token or with a longer backoff
  }
  flushRetractions(); // retractions the user asked for while logged out
  let batch;
  try {
    batch = await account.fetchMail(API_BASE, apiToken);
  } catch (e) {
    // A directory session lasts TOKEN_TTL_SEC. When it expires the fetch 401s
    // forever and mail stops arriving with no visible sign, so drop the token
    // and let the block above re-authenticate on the next tick.
    if (e && e.status === 401) apiToken = null;
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
  // Filing a mail writes the store; a write refused because another tab wrote
  // first locks it — say so instead of leaving a dead list (pentest p5 L-4).
  if (!contacts.isUnlocked()) { contactStoreLost(); return; }
  if (changed && !els.viewChats.hidden) refreshChats();
  if (changed) contactsChanged(); // a mail can re-key or re-address a saved user
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

  // P-13: de-duplicate EVERY envelope kind here, before it can act. The old
  // dedup lived in chats.append (regular messages only) and scanned the trimmed
  // display history, so control envelopes could be replayed by a hostile mailbox
  // without limit and old messages could reappear once the 500-message window
  // scrolled past. markSeen is backed by a ring kept independently of history.
  if (opened.id && !(await chats.markSeen(sender.username, opened.id))) {
    return false; // already processed this envelope
  }

  // Control traffic (mode negotiation) vs a regular message.
  if (opened.kind && opened.kind !== "msg") {
    return await handleControl(sender, opened);
  }

  // Regular message. Decrypt the inner AES256 layer if this chat is in that
  // mode; a mode mismatch (peer still on the old mode) shows a system note.
  let text = opened.msg;
  const chat = chats.get(sender.username);
  if (opened.enc !== undefined) {
    if (chat && chat.mode === "AES256" && chat.secret && chat.salt) {
      try {
        text = await chats.innerDecrypt(chat.secret, chat.salt, opened.enc);
      } catch {
        text = "[AES256 message that did not decrypt — shared passphrase mismatch]";
      }
    } else {
      text = "[AES256 message but this chat isn't in AES256 mode here]";
    }
  } else if (chat && chat.mode === "AES256") {
    // Pentest 2026-07-27 L-2: the OTHER direction of the same mismatch was
    // silent. This chat is agreed to carry a second, passphrase-derived layer
    // inside the sealed envelope, and this message arrived without it — either
    // the peer's chat store was rolled back to before the mode change (there is
    // no generation marker to stop that) or someone is stripping the layer. The
    // envelope is still authenticated end-to-end, so nothing is forged; what is
    // lost is the extra layer the two of you agreed on, and saying so is the
    // difference between a downgrade you notice and one you do not.
    text = "[arrived WITHOUT the agreed AES256 layer — the other side may have lost the shared passphrase] " + text;
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
    // P-06: the proposer chooses this PBKDF2 salt. Reject anything that is not
    // the 16 random bytes newInnerSalt() mints, at the boundary, so a degenerate
    // or shared salt never reaches storage or the KDF. AES256 needs one; SEALED
    // carries none.
    if (opened.mode === "AES256" && !chats.isValidInnerSalt(opened.salt)) return false;
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

// Stop polling on a deliberate sign-out (L-4). Without this the interval keeps
// firing, 401s on the revoked token, and re-authenticates — turning sign-out
// into a 6 s round trip that undoes itself.
function stopMailboxPolling() {
  if (mailboxTimer) {
    clearInterval(mailboxTimer);
    mailboxTimer = null;
  }
}

// ---- connection lifecycle -------------------------------------------------

// Pentest 2026-07-26 P-19: connect() awaits a directory fetch, a pad unlock
// (600k PBKDF2) and RSA keygen before it disabled the button, so a double-click
// ran two overlapping connects that fought over ws/cipher/otpRecord/
// otpLockRelease — the second call's releaseOtpLock() dropped the lock the first
// had just taken, and both opened sockets into a room capped at two members,
// locking the real peer out. Claimed synchronously, before the first await.
let connecting = false;

async function connect() {
  if (connecting) return;
  connecting = true;
  els.connect.disabled = true;
  try {
    await connectInner();
  } finally {
    connecting = false;
    // connectInner keeps the button disabled for the life of a live socket (the
    // onclose handler re-enables it). Re-enable here only when we never got that
    // far — note `ws` may still hold a CLOSED socket from a previous session, so
    // test the state rather than mere presence.
    const live = ws && (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN);
    if (!live) els.connect.disabled = false;
  }
}

async function connectInner() {
  const room = roomCode();
  const alg = algValue();
  if (!ROOM_RE.test(room)) {
    hint("That chat code does not look right — it should be 64 letters/numbers. Press \u201cNew code\u201d to create a valid one, or paste the code your contact sent you.", true);
    return;
  }
  if (algNeedsIdentity(alg) && !identity) {
    hint("This security option needs your identity. Go back to step 1 and create or unlock it \u2014 that is what proves to your contact it is really you.", true);
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
      hint("That handle does not look right \u2014 it should look like alice#a1b2c3. Paste it exactly as they sent it, or leave the field blank.", true);
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
      hint(`No one found for the handle "${parsed.username}#\u2026". Check you pasted it exactly, or leave the field blank and compare a safety number instead.`, true);
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
      hint("Choose a one-time pad first, under Security options \u2192 Generate / share a pad.", true);
      return;
    }
    // Exclusive same-origin lock: a pad must be live in only ONE tab/window at a
    // time, or two sessions would draw the same keystream (two-time pad).
    otpLockRelease = await acquirePadLock(padId);
    if (!otpLockRelease) {
      hint("This one-time pad is open in another tab or window. Close it there first \u2014 using a pad twice at once would break its security.", true);
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
      hint("This one-time pad is used up. You and your contact need to exchange a fresh one in person.", true);
      return;
    }
    opts.pad = otpRecord;
  }

  try {
    cipher = makeCipher(alg, room, opts);
    await cipher.init();
  } catch (e) {
    hint("Could not set up encryption: " + e.message, true);
    return;
  }

  peerBundle = null;
  verified = false;
  els.chatVerified.hidden = true; // B2: nobody is verified on a new connection
  myNonce = freshNonce();
  peerNonce = null;
  helloAnswered = false;
  roomRole = null;
  admittedBundle = null;
  admittedAnon = false;
  wasPending = false;
  keyConfirm.reset();
  knockQueue = [];
  hideAdmitPrompt();
  // P-19: freeze the session's room/alg now; the send path uses these, never the
  // live DOM.
  sessionRoom = room;
  sessionAlg = alg;
  sessionRoomMine = roomCodeMine;
  clientClosing = false;
  closeRelayReason = null; closeHint = null; // L2: nothing parked carries over
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
  const sock = ws; // L2: every frame is handled against the socket it came on
  ws.onmessage = (ev) => {
    msgChain = msgChain.then(() => handleMessage(room, ev.data, sock)).catch(() => {});
  };

  ws.onclose = () => {
    setStatus("disconnected", "err");
    if (joined) addLine("sys", "", "disconnected");
    joined = false;
    verified = false;
    els.chatVerified.hidden = true; // B2
    roomRole = null;
    admittedBundle = null;
    admittedAnon = false;
    wasPending = false;
    keyConfirm.reset();
    knockQueue = [];
    hideAdmitPrompt(); // also lifts the B3 modal: nothing stays inert after a drop
    enableSend(false);
    els.verify.hidden = true;
    showScreen("room");
    if (closeHint) { hint(closeHint, true); closeHint = null; }
    else if (closeRelayReason && !clientClosing) relayErrorHint(closeRelayReason); // A3; P2: not ours
    closeRelayReason = null;
    clientClosing = false;
    els.connect.disabled = false;
    releaseOtpLock();
  };

  ws.onerror = () => setStatus("connection error", "err");
}

// ---- room admission, client side (P-08) ------------------------------------

// Our introduction to the room owner. Anonymous sessions (AES256/OTP without an
// identity) have nothing to prove, and say so plainly rather than omitting the
// field and looking like a stripped bundle.
async function knockIntro(room) {
  if (!identity || !myBundle) return { anon: true };
  return { idb: myBundle, sig: await signKnock(identity, room) };
}

// Owner side: file an inbound knock for a human decision. Everything here is
// UNTRUSTED input from the relay — validate it, never render it as markup, and
// never let it decide anything by itself.
async function queueKnock(m) {
  if (roomRole !== "owner") return; // only the owner is asked; ignore the rest
  if (typeof m.jid !== "string" || !/^[0-9a-f]{16}$/.test(m.jid)) return;
  if (knockQueue.some((k) => k.jid === m.jid)) return;
  // Pentest 2026-07-29 L-1: cap the queue.
  //
  // It used to grow without bound. Dedup is per-`jid` and every fresh socket
  // brings a new one, the relay never tells the owner that a waiter left, and
  // main.py creates the WS token bucket PER CONNECTION — so
  // connect->join->knock->disconnect gets a fresh budget each cycle. Measured
  // at 60 knocks in 1.6s (~37/s), each one forcing an Ed25519 AND an ML-DSA-65
  // verify on the owner's tab. Availability only, and the owner can see it
  // happening, but it dents P-08's "waiting costs the room nothing".
  //
  // Dropping the EXCESS rather than the oldest is deliberate: the queue is
  // handled oldest-first, so the entries already in it are the ones the owner
  // is being asked about right now, and letting a flood evict them would let an
  // attacker push a genuine contact's knock off the list — turning a nuisance
  // into a targeted denial of admission. A dropped knocker simply has to knock
  // again once the queue drains, which is what an honest one does anyway.
  //
  // Note the cap sits BEFORE the two signature verifies below, so a flood costs
  // the owner a regex and an array scan, not the expensive part.
  if (knockQueue.length >= MAX_KNOCK_QUEUE) return;
  let p;
  try {
    p = unpackKey(m.payload);
  } catch {
    return;
  }
  let entry = { jid: m.jid, bundle: null, anon: true };
  if (p && p.idb && p.sig) {
    // A bundle that does not verify is worse than no bundle: it is someone
    // claiming keys they cannot use. Show it as unproven rather than dropping
    // the knock silently, so the owner sees the attempt.
    // H-1: the introduction is what `admittedBundle` is compared against later,
    // so canonicalize its spelling here — a re-spelled key would otherwise show
    // the right fingerprint at the prompt and then fail the identity binding
    // when the very same peer completes the handshake.
    let idb = null;
    try {
      idb = canonicalBundle(p.idb);
    } catch {
      idb = null;
    }
    const ok = idb ? await verifyKnock(idb, sessionRoom, p.sig).catch(() => false) : false;
    entry = { jid: m.jid, bundle: ok ? idb : null, anon: false, unproven: !ok };
  }
  knockQueue.push(entry);
  await showNextKnock();
}

// Fix review round 2 (L-2). `showNextKnock` awaits a digest before it writes
// any DOM, and it now has two concurrent triggers that are NOT serialised
// against each other: the click path (decideKnock) and the message path (the
// new `withdrawn` case, plus `queueKnock`). `handleMessage` serialises
// message-vs-message via msgChain, but nothing serialises click-vs-message. Two
// interleavings matter: a synchronous render for an ANON entry finishing while a
// bundled render is still inside fingerprintOf, leaving the DOM describing a
// verified contact while knockQueue[0] is the anon one; and `withdrawn`
// emptying the queue and hiding the prompt while an in-flight render then
// un-hides it for an entry that no longer exists — an undismissable prompt,
// which is what no-dead-ends.mjs exists to catch.
//
// A generation counter fixes both: only the most recently STARTED render may
// write, and it re-reads the queue head after every await.
let knockRenderGen = 0;
// 2026-09-22 rework pentest, tap-through under the tab bar: a tap aimed at what
// sat under the prompt must not decide it. Clicks (and keys, same handler) that
// HAPPENED (event timeStamp, not dispatch time) in the first 500 ms after the
// prompt became visible — shown, a new knock at its head, or revealed by a
// switch back to the Live view — are ignored, and so is any click while the
// queue head is not the knock the prompt shows (a render still in flight).
let admitShownAt = 0, admitShownFor = null;
function armAdmitGuard(k) {
  admitShownAt = performance.now();
  admitShownFor = k;
  els.admitNo.focus();
}
// 2026-09-23 final pentest (Low): a prompt armed while the page was hidden;
// the window-activating click must not decide it. Coming back to the page (the
// tab shown again, or the window focused) re-arms the guard for the prompt on
// screen. Only the window's OWN focus event reaches this listener (element
// focus does not bubble), so the click that brings the window forward is
// dropped and the next one, 500 ms on, decides as usual.
const rearmAdmitGuard = () => {
  if (document.visibilityState === "visible" && !els.viewLive.hidden && !els.admit.hidden) armAdmitGuard(admitShownFor);
};
document.addEventListener("visibilitychange", rearmAdmitGuard);
window.addEventListener("focus", rearmAdmitGuard);

// B3 (a11y review): the sheet is modal for the keyboard and assistive tech as
// well, not only under the pointer (the scrim): everything else a Tab could
// reach — the tab bar, the chat bar, the gate, the log and composer — is inert
// while it is up. Only while it is ON SCREEN: a knock that arrives behind
// another view un-hides #admit inside the hidden Live view, and an inert tab
// bar then would leave no way back to it. showView re-applies it on a switch.
let admitModalOn = false;
function setAdmitModal(on) {
  admitModalOn = on;
  applyModal();
}
// The one place `inert` is decided, for both sheets, so closing one never
// un-inerts what the other still needs. The contact profile opens only over
// Users or Chats (showView closes it), so the two are never up together; the
// tab bar is inert while either is.
function applyModal() {
  const admit = admitModalOn && !els.viewLive.hidden;
  const contact = contactShown !== null;
  for (const el of [els.chatTop, els.verify, els.chat]) el.inert = admit;
  els.tabbar.inert = admit || contact;
  for (const el of [els.viewUsers, els.viewChats, els.viewProfile]) el.inert = contact;
}
// With the rest inert, Tab would walk off the sheet into the browser chrome:
// wrap it between the sheet's first and last focusable instead. Escape does
// nothing on purpose — a knock is decided, never dismissed.
els.admit.addEventListener("keydown", (e) => {
  if (e.key !== "Tab") return;
  const stops = [...els.admit.querySelectorAll("button, [tabindex]")]
    .filter((el) => !el.disabled && !el.hidden && el.tabIndex >= 0);
  if (!stops.length) return;
  const first = stops[0], last = stops[stops.length - 1];
  if (e.shiftKey ? document.activeElement === first : document.activeElement === last) {
    e.preventDefault();
    (e.shiftKey ? last : first).focus();
  }
});

async function showNextKnock() {
  const gen = ++knockRenderGen;
  if (!knockQueue.length) {
    hideAdmitPrompt();
    return;
  }
  const k = knockQueue[0];
  els.admitWarn.textContent = "";
  els.admitWarn.className = "hint";
  if (k.bundle) {
    const fp = await Identity.fingerprintOf(k.bundle);
    // Someone else started a render, or this entry left the queue, while we were
    // hashing. Whatever they decided is newer than this; do not write over it.
    if (gen !== knockRenderGen || knockQueue[0] !== k) return;
    els.admitFingerprint.textContent = fp;
    els.admitFingerprint.hidden = false;
    // Who is this, in OUR terms? Matched on the keys themselves — never on a
    // name the other side chose (F-01).
    const known = contacts.isUnlocked()
      ? contacts.list().find((c) => c.ed === k.bundle.ed && c.mldsa === k.bundle.mldsa)
      : null;
    if (known) {
      // B1 (design review): our name for them, then the same trust pill the
      // lists draw.
      const name = document.createElement("span");
      name.className = "u-name"; // H1 (design review): a handle, set like every other one
      name.textContent = dirName(known);
      const mark = document.createElement("span");
      renderMark(mark, known);
      els.admitWho.textContent = "";
      els.admitWho.append(name, " ", mark);
    } else {
      els.admitWho.textContent = pinsReadable()
        ? "Not in your users list — you have never verified this key"
        : "Unknown — your saved users could not be read, so trust cannot be checked";
    }
    // If this session was aimed at a specific contact, say whether it is them.
    if (expectedPeerBundle && !sameBundle(expectedPeerBundle, k.bundle)) {
      els.admitWarn.textContent =
        "This is NOT the user you selected for this session. Deny unless you know why.";
      els.admitWarn.className = "hint err";
    }
  } else if (k.unproven) {
    // B6 (design review): no key, no fingerprint well (was an empty "—" box).
    els.admitFingerprint.textContent = "";
    els.admitFingerprint.hidden = true;
    els.admitWho.textContent = "Presented an identity it could not prove.";
    els.admitWarn.textContent =
      "The signature over their claimed keys is invalid. Deny: this is what an impersonation attempt looks like.";
    els.admitWarn.className = "hint err";
  } else {
    els.admitFingerprint.textContent = "";
    els.admitFingerprint.hidden = true; // B6
    els.admitWho.textContent =
      "No identity — they are connecting without one (passphrase or one-time-pad modes only).";
    els.admitWarn.textContent =
      "There is no key to compare here. Only let them in if the shared secret you agreed on is what protects this chat.";
  }
  // One admit per session. A chat holds two people, so a second admit is
  // refused by the relay anyway — but the pin would already have moved to a
  // knocker that never arrives, and the peer in the room would then fail our
  // own identity check. Note we cannot say "the room is full": a peer that quit
  // frees its slot without the relay telling us, so the honest statement is
  // about what WE did, not about the room's current occupancy.
  els.admitOk.disabled = admittedSomeone();
  if (els.admitOk.disabled) {
    els.admitWarn.textContent =
      "You have already let someone into this chat. You can turn this one away; " +
      "to talk to a different person, disconnect and start a new chat.";
    els.admitWarn.className = "hint";
  }
  const fresh = els.admit.hidden || admitShownFor !== k;
  els.admit.hidden = false;
  setAdmitModal(true); // B3; before the guard, so its focus lands on Deny
  if (fresh) armAdmitGuard(k);
  if (knockQueue.length > 1) {
    els.admitWarn.textContent +=
      (els.admitWarn.textContent ? " " : "") +
      `(${knockQueue.length - 1} more waiting — decide one at a time.)`;
  }
}

function hideAdmitPrompt() {
  // C1 (a11y review): hiding the sheet hides the button that had focus. Put
  // focus where the next decision is — the gate's safety number when it is up,
  // else the chat bar — instead of dropping it to <body>.
  const hadFocus = els.admit.contains(document.activeElement);
  els.admit.hidden = true;
  setAdmitModal(false); // B3
  if (hadFocus) (els.verify.hidden ? els.copyRoom : els.safetyNumber).focus();
  els.admitOk.disabled = false;
  els.admitFingerprint.textContent = "";
  els.admitFingerprint.hidden = false; // B6
  els.admitWho.textContent = "";
  els.admitWarn.textContent = "";
}

// The verdict. Admitting PINS the identity we let in: the handshake below
// refuses anyone else, so a relay that admits one peer and routes another fails
// closed instead of quietly connecting us to a stranger.
//
// Post-fix review: this used to overwrite the pin on EVERY admit click. A chat
// holds two people, so a second admit is refused by the relay ("room full") —
// but the pin had already moved to the second knocker, and the peer already in
// the room then failed the identity check and was disconnected by its own
// owner. One admit per session; the button is disabled once someone is in.
async function decideKnock(allow) {
  if (!knockQueue.length || !ws) return;
  if (allow && admittedSomeone()) return; // guarded in the UI too; belt and braces
  const k = knockQueue.shift();
  if (allow) {
    admittedBundle = k.bundle;
    admittedAnon = !k.bundle;
    addLine("sys", "", k.bundle
      ? "you let someone in — their key is now pinned for this session"
      : "you let someone in — they have no identity to pin");
  }
  ws.send(JSON.stringify({
    type: allow ? "admit" : "deny", room: sessionRoom, jid: k.jid,
  }));
  if (!allow) addLine("sys", "", "you denied someone who asked to join");
  return showNextKnock();   // awaited by callers; unawaited it races the message path
}

// True once this session has let someone in. The chat holds two people, so from
// here on the only meaningful verdict is "deny".
function admittedSomeone() {
  return admittedBundle !== null || admittedAnon;
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
      type: "key", room, alg: sessionAlg,
      payload: packKey({ pub, reply, idb: myBundle, sig }),
    }));
  });
}

// ---- key confirmation (pentest 2026-07-27 M-5) ------------------------------
// `cipher.ready` only ever meant "I derived chains" — never "my peer derived the
// SAME chains". Two peers could reach that state holding different key material,
// show IDENTICAL safety numbers (those cover long-term identities, not the
// session key), pass the in-person gate, and unlock a chat in which one
// direction is permanently undeliverable. The finding named two routes there,
// both driven by a hostile relay: a DHKE chain derived from an encoding rather
// than a key (closed separately by H-1), and a PQKEM exchange whose `reply=true`
// answers were both dropped, leaving each side with a different single KEM
// secret. Neither is detectable from inside one endpoint — the sides have to
// compare something derived from the chains.
//
// So they do, before verification is offered: each peer sends HMAC(its own SEND
// chain, domain-separated context) and requires exactly HMAC(its RECV chain,
// same context) back. Deriving the same tag is proof of the same material. A
// mismatch is a loud disconnect instead of a chat that silently goes nowhere.
//
// This gates only the UNLOCK step. It is not a substitute for the safety-number
// comparison: confirmation proves you share a key with whoever is at the other
// end, and the in-person check is what proves who that is.
// Pentest 2026-07-29 M-5. The exchange above was right, but it assumed the
// chains it confirms never change afterwards. They can: `_derive` REPLACES
// `this.chan` (and so both confirmation tags) whenever its input signature
// changes, in PQKEM and RSA alike. Two consequences, both of which this block
// now handles explicitly:
//
//  1. THE ATTACK. A relay replays one genuine hello and delays one genuine
//     signed offer until after confirmation has completed. `case "key"` had no
//     `confirmDone` gate and `tryFinishConfirmation` returned early once done,
//     so the late frame re-derived new chains that nobody re-confirmed: both
//     peers displayed "secure channel established", compared safety numbers
//     successfully, and then nothing worked — precisely the silent dead chat
//     the comment above promises cannot happen. Chains are now FROZEN once
//     confirmed; a frame that would change them is a loud refusal.
//
//  2. THE RACE, which the fix must not break. In a genuine simultaneous
//     connect each side derives twice (its own offer secret, then the answer),
//     so a tag sent after the first derivation is stale by the time the peer
//     sees it. Comparing only the latest tag made confirmation ALWAYS mismatch
//     in that case and disconnected BOTH honest peers — the race tolerance
//     documented at crypto.js:645 stopped being real the moment confirmation
//     was put in front of it. So we keep every tag the peer has sent and match
//     our current `theirs` against the set: each tag is a signed, identity-
//     pinned claim "I derived this material", and one of them matching is the
//     proof we want, whichever order the frames arrived in.
//
// A mismatch therefore no longer disconnects on the spot — a stale tag is
// expected in the race — so the loudness comes from a deadline instead. This
// also covers a case the old code hung on: a relay that never delivers the
// peer's confirm frame at all.
// The state machine itself lives in keyconfirm.js so it can be unit-tested
// without a DOM — see that file's header for why. app.js supplies the effects.
const keyConfirm = makeKeyConfirmation({
  send: (tag) => ws.send(JSON.stringify({
    type: "key", room: currentRoom, alg: sessionAlg, payload: packKey({ confirm: tag }),
  })),
  hint: (msg) => hint(msg),
  fail: (why) => {
    addLine("sys", "", `[${why} — refusing to continue]`);
    // Phase 2a fix round (pentest P1): shown after the close, like the A2 refusals.
    closeWs(
      "Key confirmation failed: you and your contact do not hold the same session key. " +
      "Messages would silently fail to arrive. Disconnecting.",
    );
  },
  finish: () => finishSession(currentRoom),
});

async function onChannelReady(room) {
  currentRoom = room;
  await keyConfirm.onChains(cipher.confirmation);
}

// Everything that used to happen the moment the chains existed.
async function finishSession(room) {
  if (cipher.needsHandshake) {
    await enterVerification(room, peerBundle);
    // C1: the gate is the decision on screen now. Focus its safety number (a
    // read-only stop, never "It matches") unless the user is somewhere else.
    if (!els.verify.hidden && (document.activeElement === document.body ||
        els.scrChat.contains(document.activeElement))) els.safetyNumber.focus();
    return;
  }
  verified = true;
  enableSend(true);
  if (cipher.usesNonces) {
    hint("Ready. Messages are end-to-end encrypted.");
  } else {
    updateOtpBudget();
    hint("Ready. Messages are one-time-pad encrypted.");
  }
}

async function handleMessage(room, raw, sock) {
  let m;
  try {
    m = JSON.parse(raw);
  } catch {
    return;
  }
  // A3: a fatal relay error is followed by the close, never by more traffic;
  // any later frame means the socket lived on and the parked sentence is stale.
  if (!m || m.type !== "error") closeRelayReason = null;

  switch (m.type) {
    // We are waiting for the room owner to let us in (P-08). Nothing of ours
    // reaches the room until they do — not even the session nonce — so the
    // only thing to send now is the introduction they will judge us by.
    case "pending": {
      // Write-once, like the peer identity pin: a relay must not be able to
      // re-cast us mid-session (an owner told "you are a guest" would stop
      // being asked to approve anyone).
      if (roomRole !== null) break;
      if (sessionRoomMine) {
        // F-PROTO-001: we minted this code, so nobody can legitimately own the
        // room before us — "wait for the owner" from the relay means either a
        // hostile relay demoting the creator, or an invitee who connected
        // first. Both end the same way: refuse, and let the creator start over
        // in the order the design promises (creator connects, then approves).
        addLine("sys", "", "[we created this chat code but the relay says someone else owns the room — refusing]");
        closeWs("You created this code, so you should be the one approving people. " +
          "Connect first, then send the code — or press New code and connect before sharing it.", sock);
        return;
      }
      roomRole = "guest";
      wasPending = true; // M-2: proof we went through the approval queue
      els.roomShort.textContent = room.slice(0, 8) + "…" + room.slice(-8);
      showScreen("chat");
      setStatus("waiting for approval");
      addLine("sys", "", "waiting — the person who created this chat has to let you in");
      hint("Waiting for the other person to approve you. They see the fingerprint of your key and decide.");
      ws.send(JSON.stringify({
        type: "knock", room, payload: packKey(await knockIntro(room)),
      }));
      break;
    }

    // Pentest 2026-07-27 M-1: someone tried to join and was refused because the
    // approval queue is full. Only the owner is told. This is a warning, not an
    // action: the person being turned away may well be the peer you are waiting
    // for, and a queue held by knocked squatters cannot be cleared from here —
    // agreeing a fresh chat code out of band is the way out.
    case "turned-away": {
      const n = Number.isInteger(m.count) && m.count > 1 ? m.count : 1;
      addLine("sys", "", n > 1
        ? `[${n} people were turned away — the waiting queue is full]`
        : "[someone was turned away — the waiting queue is full]");
      hint(
        "Someone could not even reach the approval queue because it is full. If the person you invited " +
        "is stuck on \"room full\", agree a NEW chat code with them out of band.",
        true,
      );
      break;
    }

    // The owner declined us (or the relay says so). Either way we are not in.
    case "denied": {
      addLine("sys", "", "[the other person did not let you in]");
      hint("They declined. If you expected to be let in, check with them out of band that you are both using the same chat code.", true);
      break;
    }

    // Owner side: someone is asking to be let in. NEVER auto-admit — the whole
    // point is that a human looks at the key.
    case "knock": {
      await queueKnock(m);
      break;
    }

    // A waiter gave up or was cut off (fix review 2026-07-30, M-A). Prune it, so
    // the queue reflects who is actually still waiting. Without this the entry
    // is immortal — nothing else reports a departed waiter — and the L-1 cap
    // then turns a flood of cheap connect/knock/disconnect cycles into a
    // permanent denial of admission for the peer you are actually expecting.
    //
    // Untrusted, like every relay frame, but it can only ever REMOVE an entry
    // from our own queue. The worst a hostile relay does with it is drop a
    // knock it could have declined to deliver in the first place.
    case "withdrawn": {
      if (roomRole !== "owner") break;
      if (typeof m.jid !== "string") break;
      const before = knockQueue.length;
      knockQueue = knockQueue.filter((k) => k.jid !== m.jid);
      // Re-render only if the prompt could be showing the entry we just removed.
      if (knockQueue.length !== before) await showNextKnock();
      break;
    }

    case "joined": {
      joined = true;
      // An older relay answers `join` with a bare {"joined"} — no role, no
      // admission control. Refusing beats silently running the protocol this
      // fix removed: the room would again be first-come-first-served and the
      // approval prompt would never appear, with nothing on screen to say so.
      if (m.role !== "owner" && m.role !== "guest") {
        addLine("sys", "", "[this relay does not support join approval — refusing]");
        // Phase 2a, pentest pre-existing (this and the five refusals in `key`):
        // a hint() here was erased by onclose's return to the room screen.
        closeWs("This relay is running an older protocol without the join-approval step. Update the relay (or your app) before using it.", sock);
        return;
      }
      // Write-once (see `pending`). The only legitimate sequence for a guest is
      // pending -> joined:guest, so a role that CHANGES is the relay re-casting
      // us: a guest told it is the owner would start approving people into a
      // room it does not control, an owner told it is a guest would stop being
      // asked. Neither is recoverable, so fail closed.
      if (roomRole === null) {
        roomRole = m.role;
      } else if (roomRole !== m.role) {
        addLine("sys", "", "[the relay changed our role mid-session — refusing]");
        closeWs("The relay tried to change your role in this room. Disconnected.", sock);
        return;
      }
      // Pentest 2026-07-27 M-2, guest half. The owner half (below, in the
      // handshake) refuses a peer nobody approved; that alone still leaves the
      // relay the option of telling BOTH parties they are guests, so neither
      // one is ever asked to approve anybody. But the only legitimate way to
      // become a guest is pending -> knock -> joined:guest, so a seat handed to
      // us without ever passing through the queue means no owner approved it.
      if (roomRole === "guest" && sessionRoomMine) {
        // F-PROTO-001, belt and braces: a relay that skips `pending` and seats
        // the creator straight in as a guest (already refused below via
        // `wasPending`, kept explicit so the invariant survives a refactor).
        addLine("sys", "", "[we created this chat code but the relay seated us as a guest — refusing]");
        closeWs("You created this code, so you should be the one approving people. " +
          "The relay tried to seat you as a guest. Connect first, then send the code.", sock);
        return;
      }
      if (roomRole === "guest" && !wasPending) {
        addLine("sys", "", "[we were seated in this room without ever asking to be let in — refusing]");
        closeWs("This relay put you in the room without the owner approving you. Disconnected.", sock);
        return;
      }
      els.roomShort.textContent = room.slice(0, 8) + "…" + room.slice(-8);
      showScreen("chat");
      setStatus("connected", "ok");
      addLine("sys", "", `joined room — encryption: ${sessionAlg}`);
      if (roomRole === "owner") {
        addLine("sys", "", "you created this chat — you decide who is let in");
      }
      // Phase 1: announce our fresh session nonce. For handshake modes the
      // signed handshake follows once we also know the peer's nonce; for
      // AES256 (usesNonces, no key material on the wire) the nonces alone fix
      // the session's ratchet chains, closing cross-session frame replay.
      ws.send(JSON.stringify({
        type: "key", room, alg: sessionAlg,
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
              type: "key", room, alg: sessionAlg,
              payload: packKey({ hello: true, n: myNonce, reply: true }),
            }));
            if (cipher.needsHandshake) await sendSignedKey(room, false);
          }
          // AES256: both nonces known — derive the session's ratchet chains
          // and unlock. No identity gate here: the shared passphrase IS the
          // out-of-band verification, so receiving unlocks with sending.
          if (cipher.usesNonces && !cipher.ready) {
            await cipher.setNonces(myNonce, peerNonce);
            await onChannelReady(room);
          } else if (!cipher.needsHandshake && !cipher.usesNonces && !verified) {
            // OTP: no key material and no nonces — the pre-shared pad IS the
            // out-of-band secret (like AES256's passphrase), so seeing the peer
            // join is enough to unlock messaging.
            await onChannelReady(room);
          }
          break;
        }

        // Phase 3 — key confirmation (pentest 2026-07-27 M-5). Carried as a
        // `key` frame like the rest of the exchange, and handled before the
        // handshake branch because it is not one: it arrives after the chains
        // exist and carries no key material.
        if (typeof p.confirm === "string") {
          // M-5: a bounded set rather than first-write-wins, because the race
          // legitimately produces two tags per side and the second is the one
          // that counts. The cap is what keeps this from becoming an oracle a
          // relay can hammer — see MAX_PEER_CONFIRMS.
          currentRoom = room;
          await keyConfirm.onPeerTag(p.confirm, cipher.confirmation);
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
        // Pentest 2026-07-27 H-1: pin the SPELLING before anything looks at the
        // bundle. Every check downstream — the admitted-identity binding, the
        // write-once peerBundle, the pin comparison, what sealed.js later signs
        // over — has to agree about what "this key" is, and forgiving base64
        // gave a relay four spellings per key to play them off each other. A
        // non-canonical bundle is malformed input and dies here, not three
        // checks later as a phantom "identity key CHANGED".
        const idbCanon = canonicalBundle(idb);
        const ok = await verifyHandshake(idbCanon, room, [myNonce, peerNonce], pub, sig);
        if (!ok) {
          addLine("sys", "", "[handshake signature INVALID — refusing to connect; a relay may be tampering with the key exchange]");
          closeWs("Authentication failed — disconnecting. This is what a MITM attempt looks like.", sock);
          return;
        }

        // P-08: if WE admitted this peer, the handshake must come from the
        // identity we were shown and approved. This is the binding that makes
        // the approval prompt more than decoration: the relay picks who is
        // routed to us, so without it a relay could show the owner a knock from
        // a trusted contact and then hand the seat to someone else. (The guest
        // side has no such check — it approved nobody — and keeps relying on
        // the safety number and the pin, exactly as before.)
        // Keyed on admittedBundle ALONE, never on roomRole: the role comes from
        // the relay, so gating the check on it would let a relay switch the
        // check off by re-sending `joined` with role "guest".
        //
        // Pentest 2026-07-27 M-2: keying on `admittedBundle` alone closes the
        // role-flip door but leaves the check OFF BY DEFAULT — a relay that
        // answers `join` with role "owner" to both parties and never delivers a
        // `pending`/`knock` leaves admittedBundle null and admittedAnon false,
        // so both gates below are skipped and P-08's approval control is fully
        // negated. Refuse first, unconditionally: as the owner of a room, the
        // only legitimate way a second member exists is that WE admitted it
        // (relay.py `admit` is the sole seat-granting path), so a handshake
        // with nobody admitted means the relay seated someone behind our back.
        if (roomRole === "owner" && !admittedSomeone()) {
          addLine("sys", "", "[a peer completed the key exchange without ever being approved — refusing]");
          closeWs("Someone was connected to this room without your approval. The relay is not behaving. Disconnecting.", sock);
          return;
        }
        if (admittedBundle && !sameBundle(admittedBundle, idbCanon)) {
          addLine("sys", "", "[the peer that connected is NOT the one you let in — refusing]");
          closeWs("The identity that completed the key exchange differs from the one you approved. Disconnecting.", sock);
          return;
        }
        // Admitting someone who showed no identity, then receiving a signed
        // handshake, means the socket changed its story between the two steps.
        if (admittedAnon) {
          addLine("sys", "", "[the peer you let in had no identity but now sends one — refusing]");
          closeWs("This peer introduced itself without an identity and then produced one. Disconnecting.", sock);
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
          peerBundle = idbCanon; // write-once for this connection, canonical (H-1)
        } else if (!sameBundle(peerBundle, idbCanon)) {
          addLine("sys", "", "[a SECOND identity tried to complete the key exchange — refusing; this is a relay MITM attempt]");
          closeWs("Two different identities attempted this handshake — disconnecting to protect you.", sock);
          return;
        }
        // M-5: refuse handshake material once confirmation has completed.
        // `_derive` rebuilds the chains whenever its input signature changes,
        // so folding in a withheld-then-delivered offer here would silently
        // replace the very material both sides just proved they shared — the
        // safety numbers stay green and the chat goes quietly dead. onChannelReady
        // catches the same condition afterwards; this refuses it up front so
        // the cipher state is never disturbed in the first place.
        if (keyConfirm.done) {
          keyConfirm.failNow("a handshake frame arrived AFTER both sides had confirmed the key");
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
          await onChannelReady(room);
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
        // P-04: recvHighWater must reach disk too — an unpersisted receive
        // watermark lets an already-delivered frame be replayed after a reload.
        try {
          await persistOtpProgress();
        } catch (err) {
          otpPersistFailed(err);
        }
      } catch {
        addLine("sys", "", "[undecryptable message — wrong key or tampered]");
      }
      break;
    }

    case "error":
      // Phase 2a, pentest pre-existing: our sentence for a known reason, never
      // the relay's words as ours (see RELAY_REASONS).
      if (sock.readyState === WebSocket.CLOSED) break; // L2: its onclose already ran
      relayErrorHint(m.reason);
      closeRelayReason = RELAY_FATAL.has(m.reason) ? m.reason : null;
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
  currentPinKey = expectedPeerName ? contacts.pinKeyFor(expectedPeerName) : "room:" + room;

  // If we looked the contact up by username, the live key must match what the
  // directory published. A mismatch is a strong red flag (though note the
  // directory is not a trust root — see account.js).
  if (expectedPeerBundle && !sameBundle(expectedPeerBundle, bundle)) {
    els.verify.hidden = false;
    els.verify.classList.add("changed");
    els.verifyTitle.textContent = `Key does NOT match the directory entry for "${expectedPeerName}"`;
    els.verifyHint.textContent =
      `The key presented in this room is different from the one the directory publishes for "${expectedPeerName}". ` +
      "Do NOT proceed unless you confirm this safety number with them in person.";
    addLine("sys", "", `[directory mismatch for "${expectedPeerName}" — verification required]`);
    hint("Directory mismatch — confirm the safety number in person before proceeding.", true);
    return;
  }

  // P-02: if a contact store EXISTS but will not open, we cannot tell a first
  // contact from a changed key — so say exactly that, loudly, instead of
  // rendering the reassuring first-contact prompt. Fail closed: no auto-accept
  // path may run while pins are unreadable.
  if (!pinsReadable()) {
    els.verify.hidden = false;
    els.verify.classList.add("changed");
    els.verifyTitle.textContent = "Your saved contacts could not be opened — key changes cannot be detected";
    els.verifyHint.textContent =
      "Your contact store is locked or damaged" +
      (contactsError ? ` (${contactsError})` : "") +
      ", so this app cannot check whether this contact's key changed since last time. " +
      "Treat this as an UNVERIFIED first contact: confirm the safety number below in person " +
      "before you continue. Unlock your contacts on the Profile screen to restore key-change warnings.";
    addLine("sys", "", "[contact store unreadable — pinned-key change detection is OFF]");
    hint("Key-change detection is off — your saved contacts could not be opened.", true);
    return;
  }

  const pin = await getPin(currentPinKey);
  if (sameBundle(pin, bundle) && !pin.revoked) {
    // Seen and verified before — accept without re-prompting.
    addLine("sys", "", expectedPeerName
      ? `contact "${expectedPeerName}" matches your saved pin`
      : "contact identity matches your saved pin");
    unlockMessaging();
    return;
  }
  if (sameBundle(pin, bundle) && pin.revoked) {
    // Pentest 2026-08-07 F-ATREST-007: the keys match a pin the user has since
    // WITHDRAWN (Unverify / Remove). Not a key change — no CHANGED alarm — but
    // no auto-accept either: the revocation has to mean something here, which
    // is the one place it did not.
    els.verify.hidden = false;
    els.verify.classList.remove("changed");
    els.verifyTitle.textContent = "You withdrew your verification of this contact — confirm the safety number again";
    els.verifyHint.textContent =
      "This key matches what you verified before, but you later removed or unverified this contact. " +
      "Compare the safety number with them in person (or over a call where you recognise their voice) " +
      "before proceeding.";
    addLine("sys", "", "[pin matches, but your verification of this contact was withdrawn — re-verify]");
    hint("You unverified this contact earlier — confirm the safety number again.", true);
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
    els.verifyTitle.textContent = "Contact identity key CHANGED — re-verify in person";
    els.verifyHint.textContent =
      "The identity key you pinned before is different now. This happens if your contact reset their " +
      "device — but it is also what an interceptor looks like. Do NOT proceed until you have confirmed " +
      "this safety number with them over a trusted channel.";
    addLine("sys", "", "[pinned identity CHANGED — verification required]");
  } else {
    els.verify.classList.remove("changed");
    els.verifyTitle.textContent = "Verify your contact — in person";
    // Phase 2b fix round, pentest S1: a warning variant above rewrote the
    // hint; a clean first contact must not inherit it (same words as index.html).
    els.verifyHint.textContent = "Read it aloud to your contact. It must match exactly.";
    if (expectedPeerBundle) {
      addLine("sys", "", `key matches the directory entry for "${expectedPeerName}" — still verify in person`);
    }
  }
  hint("Confirm the safety number with your contact before messaging unlocks.");
}

function unlockMessaging() {
  verified = true;
  els.verify.hidden = true;
  // B2 (design review): the header keeps saying so for this connection. Only
  // the in-person paths get here — onVerifyOk, and a saved pin, which only
  // onVerifyOk writes — never AES256/OTP (finishSession). Hidden again by
  // connect() and onclose.
  els.chatVerified.hidden = false;
  enableSend(true);
  addLine("sys", "", "secure channel established");
  hint("Verified. Messages are end-to-end encrypted.", false);
  els.hint.className = "hint ok";
}

async function onVerifyOk() {
  if (!peerBundle || !currentPinKey) return;
  // P-02: savePin now rejects when the store is locked. The user's in-person
  // check still holds for THIS session, so messaging is allowed — but say
  // plainly that it was not remembered, or they would expect a change warning
  // next time that can never come.
  try {
    await savePin(currentPinKey, peerBundle);
  } catch (e) {
    addLine("sys", "", "[verified for this session only — the pin could NOT be saved: " + e.message + "]");
  }
  // An in-person safety-number confirmation is the strongest trust signal we
  // have — mirror it into the Users list (verified) when the peer is known by name.
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
  // Fix round (pentest P2/P4): the room screen says why the user is back there,
  // in the app's words — never a reason the relay parked before the click.
  closeWs("You disconnected because the safety numbers did not match — someone may be intercepting " +
    "this chat. Check with your contact over another channel before you try again.");
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
    // Pentest 2026-07-26 P-04: a one-time pad must record consumption DURABLY
    // BEFORE the ciphertext is transmitted. This used to run after ws.send(),
    // un-awaited, with failures downgraded to a hint — so a tab kill or a
    // QuotaExceededError left the peer holding a frame at offset o while disk
    // still said `sendOffset < o`, and the next message re-encrypted new
    // plaintext under keystream the relay had already captured. Persisting first
    // makes the failure mode OVER-consumption (wasted pad bytes), which is
    // harmless; under-consumption is the one that breaks the pad.
    try {
      await persistOtpProgress();
    } catch (err) {
      // The pad bytes are already spent in memory; refusing to transmit means
      // we merely waste them, which is the safe direction.
      otpPersistFailed(err);
      return;
    }
    // Session-captured room/alg (P-19): never re-read live UI state at send
    // time — the envelope must describe the session we actually negotiated.
    ws.send(JSON.stringify({ type: "msg", room: sessionRoom, payload, alg: sessionAlg }));
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
// Pentest 2026-07-26 P-04: this is now awaited and it THROWS. A pad session that
// cannot durably record what it has spent must stop, not carry on — so callers
// treat a failure as fatal to the session (see otpPersistFailed). It no longer
// gates on `algValue()` either (P-19): that read live UI state, so a mode change
// mid-session would have silently stopped recording consumption — the one thing
// that must never stop. `otpRecord`/`otpAtRest` are set only by an OTP connect()
// and cleared on every connect, so they are the reliable signal.
async function persistOtpProgress() {
  if (!otpRecord || !otpAtRest || !cipher) return;
  if (typeof cipher.sendOffset !== "number" || typeof cipher.recvHighWater !== "number") return;
  otpRecord.sendOffset = cipher.sendOffset;
  otpRecord.recvHighWater = cipher.recvHighWater;
  await otp.savePadProgress(otpRecord, otpAtRest);
  updateOtpBudget();
}

// A pad whose consumption cannot be written to disk is unsafe to keep using:
// every further message would risk reusing keystream after a reload. Stop the
// session loudly instead of continuing with a hint.
function otpPersistFailed(err) {
  // Clear the gate BEFORE disabling the form: sendText's `finally` re-enables
  // the Send button whenever `verified` is still true, so without this the stop
  // was undone the moment this function returned (and ws.close() is async, so
  // the onclose handler that also clears it has not run yet). Dropping the gate
  // additionally makes the `case "msg"` receive path refuse further frames.
  verified = false;
  enableSend(false);
  addLine("sys", "", "[could not save one-time-pad progress — stopping to prevent key reuse]");
  // Phase 2a fix round (pentest P1): shown after the close, like the A2 refusals.
  closeWs(
    "Could not save pad progress: " + err.message +
    " — disconnecting so the pad cannot be reused. Free up storage, then reconnect.",
  );
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
  let unlocked;
  try {
    unlocked = await otp.unlockPad(padId, els.otpPass.value);
  } catch (e) {
    // Pentest 2026-07-28 F-1. A pad predating the authenticated rollback record
    // carries consumption state nothing can verify, so adopting it is now a
    // decision the USER makes, not something that happens because they unlocked.
    // The wording names the danger rather than asking to "continue": in the
    // attack the victim is looking at a pad they have used for months, and
    // "no usage record" is the sentence that should stop them.
    if (e.code !== "LEGACY_PAD_ADOPTION") throw e;
    const warn = e.suspicious
      ? "WARNING: this device HAS used one-time pads under the current version, " +
        "so this pad having no usage record is a strong sign its rollback " +
        "protection was tampered with.\n\n"
      : "";
    if (!confirm(
      warn + e.message +
      "\n\nAdopt it anyway? Only do this if you are certain the pad has never " +
      "been used to send a message from this device.",
    )) {
      throw new Error("Pad not adopted. Exchange a fresh pad in person.");
    }
    unlocked = await otp.unlockPad(padId, els.otpPass.value, { adoptLegacy: true });
  }
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
    ? "Entropy from drawing: none yet." // the "?" says the OS generator is used regardless
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
  try {
    // Pentest 2026-07-27 L-3: the re-export guard now consults the AUTHENTICATED
    // `exported` flag inside the pad blob, so it has to unlock first. Clearing
    // the plaintext index entry no longer disarms the one warning that stands
    // between a user and handing one pristine pad to two importers.
    const { record, atRest } = await ensureUnlocked(id); // decrypt at rest first
    // Re-export guard (Finding 3): sharing one pad with more than one importer
    // causes key reuse. Warn once and require a second click to confirm.
    if (record.exported && pendingReexportId !== id) {
      pendingReexportId = id;
      otpStatusMsg("This pad was already exported. A pad must be imported on only ONE device — re-exporting risks catastrophic key reuse. Click Export again to confirm you know what you are doing.", true);
      return;
    }
    pendingReexportId = null;
    const text = await otp.exportPad(record, els.otpXferPass.value);
    downloadText(`secure-chat-pad-${record.label || record.padId}.json`, text);
    await otp.markExported(record, atRest);
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
    // Pentest 2026-07-29 H-3: this path takes the record straight from
    // saveNewPad and never calls unlockPad, so none of unlockPad's rollback or
    // native-floor checks run on an import. That was half the finding — the
    // other half being that importPad's own guard read only deletable
    // localStorage keys.
    //
    // Both guards now live INSIDE the two functions this line calls
    // (importPad above and saveNewPad here), and both consult the native floor,
    // which the JS context cannot delete. Deliberately not "fixed" by adding an
    // unlockPad round trip: that would put the check beside the path instead of
    // on it, and cost a third 600k-iteration KDF for no property this does not
    // already have.
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
els.idForget.addEventListener("click", () => { forgetIdentity(); });
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
// F-ATREST-003/004/005 "Open anyway": the explicit adoption the stores refuse
// to perform on their own. Needs the passphrase again (the unlock row clears
// it), and the identity must already be unlocked (it is — only the stores
// refused).
function wireAdopt(btnEl, passEl, statusEl, render) {
  btnEl.addEventListener("click", async () => {
    const pass = passEl.value;
    const status = setUnlockStatus(statusEl);
    if (!identity) { status("Unlock your identity first.", true); return; }
    if (!pass) { status("Enter your identity passphrase, then press Open anyway.", true); return; }
    status("Opening…");
    await unlockContacts(pass, { expectStore: true, adopt: true });
    passEl.value = "";
    status(contactsError ? contactsError : "", !!contactsError);
    refreshUsers();
    refreshChats();
    render();
  });
}
wireAdopt(els.usersAdopt, els.usersUnlockPass, els.usersUnlockStatus, refreshUsers);
wireAdopt(els.chatsAdopt, els.chatsUnlockPass, els.chatsUnlockStatus, refreshChats);
wireViewUnlock(els.chatsUnlockPass, els.chatsUnlock,
  setUnlockStatus(els.chatsUnlockStatus), refreshChats);

els.gen.addEventListener("click", () => {
  els.room.value = newRoomCode();
  roomCodeMine = true; // F-PROTO-001
  rememberMinted(els.room.value);
  hint("New chat code created. Send it to the one person you want to talk to.");
});

els.copyCode.addEventListener("click", async () => {
  const code = roomCode();
  if (!code) { hint("There is no code to copy yet — press New code.", true); return; }
  try {
    await navigator.clipboard.writeText(code);
    hint("Chat code copied. Send it to your contact, then press Connect.");
  } catch {
    els.room.select();
    hint("Could not reach the clipboard — the code is selected, copy it manually.", true);
  }
});

// Keep the collapsed summary honest about what is actually selected, so
// choosing a non-default mode and then collapsing the panel cannot hide it.
const ALG_LABELS = {
  DHKE: "DHKE (recommended)",
  AES256: "AES-256 with a shared passphrase",
  RSA: "RSA",
  PQKEM: "post-quantum (ML-KEM-768)",
  OTP: "one-time pad",
};
function syncAlgUI() {
  const alg = algValue();
  els.passRow.hidden = alg !== "AES256";
  els.contactRow.hidden = !algNeedsIdentity(alg); // lookup only aids DHKE/RSA
  els.otpPanel.hidden = alg !== "OTP";
  els.algSummary.textContent = "Security options — currently: " + (ALG_LABELS[alg] || alg);
  // A non-default choice needs the panel to stay open, or the setting becomes
  // invisible the moment the user looks away.
  if (alg !== "DHKE") els.algDetails.open = true;
}
els.algCards.addEventListener("change", syncAlgUI); // radio changes bubble here
// Phase 2b fix round: a filled "Expecting…" value never hides in the collapsed
// row. Opened when it holds a value; never closed under the user's typing.
if (els.contact.value) els.expectRow.open = true;
els.contact.addEventListener("input", () => { if (els.contact.value) els.expectRow.open = true; });

els.connect.addEventListener("click", connect);
els.form.addEventListener("submit", sendText);
els.verifyOk.addEventListener("click", onVerifyOk);
els.verifyNo.addEventListener("click", onVerifyNo);
for (const [btn, allow] of [[els.admitOk, true], [els.admitNo, false]]) {
  btn.addEventListener("click", (e) => {
    if (knockQueue[0] !== admitShownFor || e.timeStamp - admitShownAt < 500) return;
    decideKnock(allow);
  });
}

// tab bar
for (const b of document.querySelectorAll(".navitem")) {
  b.addEventListener("click", () => showView(b.dataset.view));
}
els.addContact.addEventListener("click", addContactFromHandle);

// "Your handle" share controls (Users view). Copy the raw handle, or an invite
// link that pre-fills the add field for the recipient. Both are convenience
// only — neither conveys trust (the recipient still verifies in person).
// The result is also a class, so a button drawn as an icon alone (Users:
// Copy handle) can show it: its words are clipped there.
// A button's resting label is kept once (pentest L-4): read live, a second
// click inside the 1.5 s window took "Copied ✓" for the label and kept it.
// A reset (or a newer copy) bumps the button's generation: a write or a
// timer that belongs to an older one must not relabel it (pentest pass 2).
function resetCopyLabel(btn) {
  btn.dataset.gen = String((+btn.dataset.gen || 0) + 1);
  if (btn.dataset.label) btn.textContent = btn.dataset.label;
  btn.classList.remove("copied", "copy-failed");
}
async function copyToClipboard(btn, text, okLabel = "Copied ✓") {
  const orig = btn.dataset.label || (btn.dataset.label = btn.textContent);
  resetCopyLabel(btn);
  const gen = btn.dataset.gen;
  let ok = true;
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    ok = false;
  }
  if (btn.dataset.gen !== gen) return; // reset meanwhile: another contact is on screen
  btn.textContent = ok ? okLabel : "Copy failed";
  btn.classList.add(ok ? "copied" : "copy-failed");
  setTimeout(() => { if (btn.dataset.gen === gen) resetCopyLabel(btn); }, 1500);
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
// L-4: the user-facing half of session revocation. Drop the token locally
// FIRST, so the session is gone from this device even if the relay is
// unreachable, and stop the poller before it can re-authenticate — otherwise
// the next 6 s tick would 401 and sign straight back in, which is exactly the
// loop the M-C fix removed from re-login.
els.profileLogout.addEventListener("click", async () => {
  const token = apiToken;
  apiToken = null;
  stopMailboxPolling();
  // Suppress the automatic re-login for a moment, so this is a deliberate
  // sign-out rather than a blip the poller undoes.
  autoLoginBackoffUntil = Date.now() + 60000;
  renderProfile();
  await account.logout(API_BASE, token);
  // Say WHERE to sign back in: this button is in Profile, the login field is on
  // the identity screen, and "sign in again" on its own sends people looking.
  accountStatus("Signed out of the directory. Sealed messages will not arrive until you log in again on the identity screen.", "ok");
  showUsernameRow(true); // D3: Log in is on that screen again
  addLine("sys", "", "[signed out of the directory — sealed messages will not arrive until you log in again]");
});
els.profileForget.addEventListener("click", async () => {
  await forgetIdentity();
  renderProfile(); // reflect the now-locked state without leaving the view
});

// chats view
els.chatStart.addEventListener("click", () => {
  if (els.chatNew.value) openChat(els.chatNew.value);
});
els.chatPeer.addEventListener("click", () => {
  if (activeChat && contacts.get(activeChat)) openContact(activeChat, "convo");
});
els.chatBack.addEventListener("click", () => {
  const was = activeChat;
  activeChat = null;
  refreshChats();
  focusChatRow(was); // C2: back to the row that was open
});
els.chatForm.addEventListener("submit", sendChatMessage);
els.chatModeSel.addEventListener("change", () => {
  if (activeChat) proposeModeChange(activeChat, els.chatModeSel.value);
});

// screen navigation + chat top bar
els.toRoom.addEventListener("click", () => showScreen("room"));
els.toIdentity.addEventListener("click", () => showScreen("identity"));
els.disconnect.addEventListener("click", () => {
  closeWs(); // onclose does the cleanup and returns to the room screen
});
// Fix round (pentest P3): the modal sheet's own way out, for an owner facing an
// endless supply of knocks. Round 3 (pentest L1): on a phone the sheet docks
// over the composer, so a tap meant for it could leave — same 500 ms rule.
els.admitLeave.addEventListener("click", (e) => {
  if (e.timeStamp - admitShownAt < 500) return;
  closeWs();
});
els.copyRoom.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(roomCode());
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
showView("live"); // establishes aria-current / active state on first paint
syncAlgUI();
refreshIdentityUI();

// Start with a chat code already in the box. Pressing Connect on an empty field
// used to fail a validation check whose message was written to a hidden element,
// so the button appeared to do nothing at all. A code costs nothing until you
// connect, and someone JOINING simply pastes over it — so the failure mode is
// removed rather than merely explained.
if (!els.room.value) { els.room.value = newRoomCode(); roomCodeMine = true; rememberMinted(els.room.value); }
else roomCodeMine = isMinted(els.room.value.trim());
// F-PROTO-001: anything typed or pasted over the box is somebody else's code —
// unless it is one this device minted earlier (a reload, then re-paste).
els.room.addEventListener("input", () => { roomCodeMine = isMinted(els.room.value.trim()); });

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

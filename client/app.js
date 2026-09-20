// secure-chat web client controller.
//
// Wires the UI to the relay WebSocket and to the client-side ciphers. The
// server only ever sees ciphertext; all encryption happens here. Rendering uses
// textContent exclusively (never innerHTML), so message contents can never be
// interpreted as markup.
//
// SECURITY — authenticated key exchange (closes the MITM gap):
//   For the handshake modes (DHKE / PQKEM) the ephemeral/public key is signed by
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

import { makeCipher, isAscii, bufToB64, b64ToBuf, DEPRECATED_ALGS } from "./crypto.js";
import { Identity } from "./identity.js";
import {
  signHandshake, verifyHandshake, freshNonce, isValidNonce, signKnock, verifyKnock,
  unb64,
} from "./auth.js";
import * as account from "./account.js";
import * as otp from "./otp.js";
import * as idstore from "./identity-store.js";
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
  admitWarn: $("admitWarn"), admitOk: $("admitOk"), admitNo: $("admitNo"),
  admitTitle: $("admitTitle"), admitHint: $("admitHint"),
  idHint: $("idHint"), roomHint: $("roomHint"), roomHelp: $("roomHelp"),
  atRestWarning: $("atRestWarning"),
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
  usersStartFresh: $("usersStartFresh"), chatsStartFresh: $("chatsStartFresh"),
  chatsUnlockPass: $("chatsUnlockPass"), chatsUnlock: $("chatsUnlock"),
  chatsUnlockStatus: $("chatsUnlockStatus"),
  profileName: $("profileName"), profileAvatar: $("profileAvatar"),
  profileHandleText: $("profileHandleText"),
  profileHandleActions: $("profileHandleActions"),
  profileCopyHandle: $("profileCopyHandle"), profileCopyInvite: $("profileCopyInvite"),
  profileQrRow: $("profileQrRow"), profileQr: $("profileQr"),
  profileFingerprint: $("profileFingerprint"), profileKeys: $("profileKeys"),
  profileStatus: $("profileStatus"), profileHint: $("profileHint"),
  usersHint: $("usersHint"), chatsHint: $("chatsHint"),
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
  chatPending: $("chatPending"),
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
// F-ATREST-008: every WRITE of this key goes through identity-store.js, which
// stamps the blob with a monotone generation and mirrors it into the native
// floor (captured there at load, from otp.js — nothing to wire up here);
// identity-store.test.mjs pins this file to zero direct writes of the key.
const LS_IDENTITY = idstore.LS_IDENTITY;
const LS_PINS = "sc.pins.v1";
const LS_USERNAME = "sc.username.v1";
const LS_LOOKUP_TOKEN = "sc.lookuptoken.v1"; // our directory lookup token

let ws = null;
let cipher = null;
let otpRecord = null;      // the OTP pad in use this session (bytes + offsets), or null
let otpAtRest = null;      // cached at-rest key {key,salt,iters} for cheap re-saves
let otpLockRelease = null; // releases this pad's exclusive same-origin lock
// Pentest 2026-08-07 F-CRYPTO-014: there was a `TAB_ID` here, seeded from
// `Math.random()`. It was the sole discriminator between "my pad lease" and
// "someone else's" — the one value standing between the user and a two-time
// pad, and the only Math.random in the client on a path that gated key
// material. The lease it served is gone (see acquirePadLock), and with it the
// id: nothing else ever read it. Deleted rather than kept "for bookkeeping",
// which is what the first version of this fix wrongly claimed it was for. The
// blanket Math.random ban in no-fallback.test.mjs now covers the original
// concern without needing a value to point at.
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
//
// Pentest 2026-08-07 F-PROTO-001, and the 2026-08-08 review of its own fix.
//
// The guest half of that promise was missing: a guest's only evidence of having
// been approved was that the relay sent it `pending` and then `joined`, both of
// which the relay writes for free. The first repair had the owner SIGN the
// admission and the guest verify it — which is forgeable, because the signature
// is checked against the peer's own bundle and nothing in it requires the signer
// to be trusted or a human to have been asked. An attacker signs one for the
// victim with a keypair it generates on the spot; verified end to end by
// `SCENARIO=attacker node e2e/hostile-relay/proto001.mjs`, where the shipped
// client plus ONE assignment walked an unapproved identity to the safety-number
// screen.
//
// That approach cannot be repaired. The room id travels to the relay in
// cleartext (it IS the `join` frame), so a hostile relay can always be a
// legitimate code-knowing participant; any evidence such a peer offers about
// itself is evidence the attacker chose. The only unforgeable, relay-independent
// fact available here is what a human ON THIS DEVICE approved.
//
// So approval is symmetric now. Both sides refuse a handshake from an identity
// this device's user did not approve — the owner through the knock prompt it
// already had, the guest through the same prompt shown when the peer's signed
// handshake arrives. Trust that is already established skips it — but ONLY the
// kind that is genuinely local: a 🟢 key verified in person (see
// `peerAlreadyTrusted`). Nothing the relay or the directory sends can switch it
// off, because no relay frame and no server answer is consulted.
//
// The cost, stated honestly (it was understated here until 2026-08-08 item 14):
// a repeat chat with a contact you have verified in person gains no click, and
// EVERY other first handshake — including the first chat with a contact you
// picked by handle — costs one approve/deny prompt before the safety-number
// step. The earlier claim that the named-contact flow was free depended on
// trusting an unsigned directory answer, which is the thing the relay can write.
let roomRole = null;       // "owner" | "guest" for this connection
let admittedBundle = null; // the identity WE let in (owner side), or null
let admittedAnon = false;  // we let in someone with no identity at all
let wasPending = false;    // we sat in the approval queue (M-2, guest side)
// Phase-7 pentest 2026-09-16, F-P7-7: the deprecated-alg refusal is said ONCE
// per connection. It runs before the type dispatch, so a 14-byte {"alg":"RSA"}
// needed no room state to reach addLine + hint — and 10 000 of them (~140 KB)
// wedged the renderer for minutes while burying every real transcript line.
let saidDeprecatedAlg = false;
let saidTurnedAway = false;   // M-1 (review of 4b9d2c6..a88baa4): the queue-full line is said once per connection
let saidDenied = false;       // M-1, third review: the denial is said once per connection
let knockQueue = [];       // [{jid, bundle, anon}] waiting for our verdict
// The identity a human on THIS device approved for this session, by either
// route. This is the whole admission control: it is written only by a click.
let approvedBundle = null;
// Set while the peer-approval prompt is open: {bundle, resolve}. The message
// pump is parked on this promise, so nothing else is processed until the user
// decides or the socket closes.
let approvalPending = null;
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
//              (A short-lived `adm` admission proof used to ride along here;
//              it was removed as unsound — see the note at `approvedBundle`.)
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
// Pentest 2026-08-07 F-ATREST-003 (confirmed), second half. `hasStore()` reads
// a deletable localStorage key, so `!contacts.hasStore()` asserted "pins are
// readable" precisely when an attacker had just deleted the store: this
// returned TRUE while the store was locked, the loud branch below was skipped,
// getPin() returned null, and every peer rendered as a benign first contact.
// The alarm was inverted by the very act it was built to catch. "No store" is
// only benign when this device never had one — which is what the identity-
// anchored flag answers (and it answers `false` when it cannot know, so an
// identity-less flow behaves exactly as before).
function pinsReadable() {
  if (contacts.isUnlocked()) return true;
  return !contacts.hasStore() && !contacts.storeExpected();
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
// compared UNEQUAL here — a free "⚠ identity key CHANGED" alarm on a genuine
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

// ---- drawer menu + top-level views ----------------------------------------
// Three views: live (the 3-step room flow), users (contact list + trust),
// chats (async DMs, later phase). Pure presentation — switching views never
// touches an active connection.

function setDrawer(open) {
  els.drawer.hidden = !open;
  els.scrim.hidden = !open;
  els.menuBtn.setAttribute("aria-expanded", open ? "true" : "false");
  if (open) {
    const active = els.drawer.querySelector(".navitem.active");
    if (active) active.focus();
  }
}

function showView(name) {
  els.viewProfile.hidden = name !== "profile";
  els.viewLive.hidden = name !== "live";
  els.viewUsers.hidden = name !== "users";
  els.viewChats.hidden = name !== "chats";
  for (const b of els.drawer.querySelectorAll(".navitem")) {
    const on = b.dataset.view === name;
    b.classList.toggle("active", on);
    // Which view is current was conveyed by colour alone; say it out loud too.
    if (on) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  }
  setDrawer(false);
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
  // Phase-7 pentest 2026-09-16, F-P7-9: the three targets below all live inside
  // #viewLive, and this used to test only the SCREENS' `hidden` — so with the
  // Users or Chats view on screen (where someone waiting for mail sits) the
  // "sealed messages will not arrive" warning was written into a zero-size
  // node. Pick the visible VIEW first; each has its own status line.
  // Each view gets a hint line of its OWN (review of the first fix, L-5): the
  // views' status elements are written and cleared by their renderers, so a
  // warning written there was destroyed on the next render — and on Profile
  // the "status" is a chip container that hint() would have wiped.
  if (els.viewLive.hidden) {
    if (!els.viewUsers.hidden) return els.usersHint;
    if (!els.viewChats.hidden) return els.chatsHint;
    if (!els.viewProfile.hidden) return els.profileHint;
  }
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
  for (const el of [els.idHint, els.roomHint, els.hint, els.usersHint, els.chatsHint, els.profileHint]) {
    if (el) { el.textContent = ""; el.className = "hint"; }
  }
}

function accountStatus(text, cls = "") {
  els.accountStatus.textContent = text;
  els.accountStatus.className = "hint" + (cls ? " " + cls : "");
}

const LOG_MAX_LINES = 500; // F-P7-7
function addLine(kind, who, text, keep = false) {
  // Review of the F-P7-7 fix (M-5): a relay that floods junk `msg` frames makes
  // us narrate "[undecryptable message …]" once per frame, and oldest-first
  // eviction then pushed the SECURITY lines ("you approved this peer",
  // "handshake signature INVALID") out of the transcript entirely — the
  // F-PROTO-002 note says those must not survive only as a scrolled-past line,
  // and they no longer survived at all. Two rules: a system line identical to
  // the previous one is COUNTED onto it rather than appended, so a flood of one
  // message is one line; and eviction takes the oldest NON-system line first,
  // touching system lines only when they alone exceed the cap.
  const last = els.log.lastElementChild;
  if (kind === "sys" && !who && last && last.className === "sys" && last.dataset.text === text) {
    const n = (Number(last.dataset.repeat) || 1) + 1;
    last.dataset.repeat = String(n);
    last.textContent = `${text} (×${n})`;
    els.log.scrollTop = els.log.scrollHeight;
    return;
  }
  // Third review of the M-1 fix: the consecutive rule folds only NEIGHBOURS,
  // so any TWO alternating narrations defeat it — `denied` × junk `msg` reached
  // the cap in 800 frames after two rounds of enumerating arms. So the rule for
  // a narration (a system line that is NOT part of the record) is membership,
  // not adjacency: if the transcript already holds that exact line, it is
  // counted onto and MOVED to the end, never appended again. The number of
  // narration lines is therefore bounded by the number of distinct narration
  // strings in this file, whatever order a relay sends them in. Record lines
  // (`keep`) keep the consecutive rule only: each is once per connection by
  // construction, and folding "joined room" across reconnects would hide the
  // order of sessions.
  if (kind === "sys" && !who && !keep) {
    for (const c of els.log.children) {
      if (c.className === "sys" && !c.dataset.keep && c.dataset.text === text) {
        const n = (Number(c.dataset.repeat) || 1) + 1;
        c.dataset.repeat = String(n);
        c.textContent = `${text} (×${n})`;
        els.log.appendChild(c); // moves it: the latest occurrence is where it is read
        els.log.scrollTop = els.log.scrollHeight;
        return;
      }
    }
  }
  const li = document.createElement("li");
  li.className = kind;
  if (kind === "sys" && !who) li.dataset.text = text;
  if (keep) li.dataset.keep = "1"; // the session's record: evicted last (see below)
  if (who) {
    const w = document.createElement("span");
    w.className = "who";
    w.textContent = who;
    li.appendChild(w);
  }
  li.appendChild(document.createTextNode(text)); // textContent path: no markup
  els.log.appendChild(li);
  // F-P7-7: the transcript is bounded. Every frame the relay can make us
  // narrate costs a node plus a synchronous layout (scrollTop below), so an
  // unbounded list is O(n^2) work an attacker controls.
  // Eviction order, in three tiers. Review of 4b9d2c6..a88baa4 (M-1) found
  // that once only system lines remained the fallback evicted the OLDEST —
  // the session's record ("joined room", the approval prompt) went first.
  // The first fix flipped it to the NEWEST, and its own review (M-1 again)
  // showed that freezes the transcript: every later line, including a
  // genuine refusal, is appended and destroyed. So instead the lines that ARE
  // the record are marked `keep` where they are written (each is once per
  // connection by construction: write-once role, a closed socket, a decided
  // approval) and go last:
  //   1. the oldest NON-system line (a conversation is the cheapest thing to lose);
  //   2. the oldest system line that is not part of the record;
  //   3. the oldest record line — reachable only through the user's own
  //      reconnects, never through relay frames.
  while (els.log.childElementCount > LOG_MAX_LINES) {
    let victim = null;
    for (const c of els.log.children) { if (c.className !== "sys") { victim = c; break; } }
    if (!victim) for (const c of els.log.children) { if (!c.dataset.keep) { victim = c; break; } }
    if (!victim) victim = els.log.firstElementChild;
    els.log.removeChild(victim);
  }
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
  // RSA was here until 2026-08-21 (F-CRYPTO-009, see the tombstone in
  // crypto.js). It is not merely unlisted: index.html no longer offers it and
  // makeCipher refuses it outright.
  return alg === "DHKE" || alg === "PQKEM";
}

// The encryption picker is a radio-card group (one input per mode); exactly one
// is always checked (DHKE by default in the markup).
//
// The `.value` read used to be unguarded, so a markup change that dropped the
// `checked` attribute (e.g. while removing a mode card) would surface as a bare
// TypeError on null deep inside connect(). Name the failure instead: connect()
// turns a throw here into a red hint, which is the loud refusal this project
// wants in place of an unexplained crash.
function algValue() {
  const picked = els.algCards.querySelector('input[name="alg"]:checked');
  if (!picked) throw new Error("no encryption mode is selected");
  return picked.value;
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
    account.register(API_BASE, identity, savedName).catch((e) => {
      // Benign failures — offline, or a name now owned by a different identity —
      // stay quiet: this is a background refresh, not an action the user asked for.
      // But a keys_locked, or a stale_counter that survived the resync retry, means
      // the directory still holds a SUPERSEDED encryption bundle: contacts sealing
      // mail will encrypt to a key this identity may no longer control. That is not
      // benign and must be visible, though it stays non-fatal.
      if (e && (e.code === "keys_locked" || e.code === "stale_counter")) {
        accountStatus("Your published encryption keys could not be updated — a contact's sealed mail may be going to a superseded key. " + e.message, "err");
      }
    });
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
    setIdentityStatus("Your identity is locked. Enter your passphrase to unlock it.");
  } else {
    setIdentityStatus("No identity on this device yet. Create one so contacts can confirm it is really you.");
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
    const saved = await idstore.persistIdentity(identity, pass);
    if (saved.warning) addLine("sys", "", "[identity: " + saved.warning + "]", true);
    installStoreAnchor(pass);
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
  let verdict;
  try {
    ({ identity, verdict } = await idstore.openIdentity(pass, Identity.import));
  } catch (e) {
    identity = null;
    return "Wrong passphrase or corrupted identity.";
  }
  // F-ATREST-008. A bad verdict is not a lock-out: the keys are the user's own
  // in every version of the blob. It is reported, and identity-store.js reads
  // every anchor as established from here on (fail closed), which
  // installStoreAnchor below also commits into the in-memory flags.
  // F-ATREST-008 (pentest of the change, F-7): the verdict has to reach the
  // user on whichever view they unlocked from, and the per-view unlock rows
  // hide themselves on success — so it goes into the one banner every view
  // shows, plus the transcript.
  els.atRestWarning.textContent = verdict.ok ? "" : "Identity unlocked, but " + verdict.message + ".";
  els.atRestWarning.hidden = verdict.ok;
  if (!verdict.ok) {
    addLine("sys", "", "[identity at rest: " + verdict.message + "]", true);
  }
  installStoreAnchor(pass);
  if (identity.upgraded || !verdict.ok || verdict.arm) {
    // Three reasons to write, one write. Pre-v3 blob: encryption keys were
    // just added — persist them so the upgrade happens exactly once, then
    // re-publish the bundle below. Bad verdict: the write re-converges the
    // counter with the floor and carries the fail-closed flags into the blob,
    // so the warning shows once. `arm`: this device has no record of this
    // identity yet (every existing install, on its first unlock after the
    // F-ATREST-008 update) — the write is what creates the record, and without
    // it the guard never arms (pentest of the change, F-1). The identity is
    // usable either way; a refused write (a full localStorage) is reported,
    // not fatal.
    try {
      const saved = await idstore.persistIdentity(identity, pass);
      if (saved.warning) addLine("sys", "", "[identity: " + saved.warning + "]", true);
    } catch (e) {
      addLine("sys", "", "[identity could not be re-saved: " + e.message + "]", true);
    }
  }
  await unlockContacts(pass); // contact store shares the identity passphrase
  await showIdentityUnlocked();
  if (!verdict.ok) {
    // showIdentityUnlocked wrote the routine "unlocked" line; the at-rest
    // verdict is the more important one, so it gets the status row too.
    setIdentityStatus("Identity unlocked, but " + verdict.message + ".", "err");
  }
  return null;
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
  return go;
}

// F-ATREST-008 fix review (F-2): the consent gate for starting a store over
// EMPTY. Reachable only while the store's deletion alarm is showing (the button
// is hidden otherwise), confirms with the cost spelled out, and arms the
// consent for exactly one unlock attempt — the `finally` disarms it whether the
// passphrase was right or not, so a typo cannot leave consent lying around for
// a later unlock the user did not mean this way.
function wireStartFresh(btnEl, store, what, cost, go) {
  btnEl.addEventListener("click", async () => {
    if (!confirm(
      `Start over with an EMPTY ${what}? This device says one existed and it is gone. ` +
      "If someone deleted it to switch off key-change warnings, starting over is exactly what they want — " +
      `only continue if YOU know why it is missing. ${cost}`,
    )) return;
    try {
      freshStoreConsent[store] = true;
      await go();
    } finally {
      freshStoreConsent[store] = false;
    }
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
  els.atRestWarning.hidden = true;
  contactsErrorCode = null;
  chatsErrorCode = null;
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
    accountStatus(`Registered. Your contact handle is ${username}#${lookup_token} — share it (username alone will not resolve).`, "ok");
    // Registering is when a first-time user gets their handle, and it is the
    // moment they expect chats to work. Take the directory session now, or they
    // would send messages fine while silently receiving nothing until they
    // happened to press "Log in".
    await autoLogin(username);
  } catch (e) {
    // Branch on the machine-readable code (account.js surfaces err.code), not on
    // the 409 status alone. A counter/keys 409 is an EXISTING owner re-registering,
    // not a name collision — telling them to "pick another" would throw away their
    // handle and every contact's pin. The three 409s mean three different things.
    if (e.code === "username_taken") {
      // ROUND-4 M-3. `e.code` is a string the RELAY chose, and the advice it drives
      // — rename — is the one action that loses the handle and every contact's pin.
      // A hostile relay answering "taken" for a name this device provably holds was
      // reproduced end to end. We cannot authenticate the relay here, but we do not
      // have to: if this identity already registered THIS name successfully, we hold
      // the ground truth locally, and "taken by someone else" is then simply false.
      // Degrade to the conservative wording rather than repeating the relay's claim.
      const ownsIt = localStorage.getItem(LS_USERNAME) === username
        && localStorage.getItem(LS_LOOKUP_TOKEN);
      accountStatus(ownsIt
        ? `The directory says "${username}" is taken, but this device already registered that name — so this is your own account, not a collision. Do NOT pick another name (that would lose your handle and every contact's saved pin). Try again; if it persists, the directory you are talking to may not be the one you registered with.`
        : `"${username}" is already taken. Pick another (or log in if it is yours).`, "err");
    } else if (e.code === "stale_counter") {
      // Survived the one-shot resync retry: the directory holds a counter this
      // device cannot overtake (most often a wrong wall clock). Renaming does NOT
      // help and loses the handle, so do not suggest it.
      accountStatus("Your registration counter is behind the directory's and could not be resynced — check this device's clock (it may be set into the future), then try again. Do not rename; this is your account.", "err");
    } else if (e.code === "keys_locked") {
      accountStatus("The directory has your encryption keys locked and will not accept this update. A fresh counter-bearing registration from the device that owns them is required.", "err");
    } else if (e.status === 409) {
      // A 409 whose code we do not recognise: stay conservative and do not claim
      // the name is taken (that was the old M-3 misfire).
      accountStatus("Registration was refused by the directory: " + e.message, "err");
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
    // Visible, once per failure streak, so the user is not silently offline.
    // Routed through hint(), which writes to whichever screen is actually in
    // front of the user — addLine() alone put this in the CHAT TRANSCRIPT, a
    // screen you are usually not on when a background re-login fails, which is
    // the same "only redrawn if you happen to look" complaint that made M-C
    // silent in the first place.
    if (autoLoginFailures === 1 || autoLoginFailures === 4) {
      const why = e && e.message ? e.message : "login failed";
      hint(`Not signed in to the directory — sealed messages will not arrive (${why}). Retrying.`, true);
      addLine("sys", "", `[not signed in to the directory — sealed messages will not arrive (${why})]`, true);
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
let chatsError = null;    // chat-store unlock failure, kept separate (F3)
let contactsErrorCode = null; // "STORE_DELETED" when the contact store is gone but was expected
let chatsErrorCode = null;
// F-ATREST-008 fix review (F-2): consent to start a store over, EMPTY, when the
// device says one was established and none is there. Armed only by the two
// "Start over" buttons, each behind a confirm() that names what is lost, and
// only for the duration of that one unlock attempt (see the click handlers).
// Never set anywhere else: identity-store.test.mjs pins the writers.
const freshStoreConsent = { contacts: false, chats: false };
let apiToken = null;      // directory session token (from Log in), memory only

// Unlock the contact store with the identity passphrase. Called wherever the
// identity itself is created/unlocked, BEFORE the passphrase field is cleared.
// P-02: a failure here leaves the identity usable but the PIN STORE LOCKED,
// which silently disables key-change detection. It is still not fatal (the user
// may legitimately have a foreign blob and want to wipe it), but it must be
// visible wherever it matters — so besides `contactsError` for the Users view,
// the room screen warns and the verification gate refuses to auto-accept.
// F-ATREST-003/004: give the contact store its anti-deletion anchor before it
// opens. The flag lives inside the identity's AEAD, so it cannot be forged or
// stripped without the passphrase; F-ATREST-008 (identity-store.js) is what
// stops it being ROLLED BACK with the whole blob — under any at-rest verdict
// short of clean, `anchorEstablished` answers true. `markEstablished`
// re-exports the identity, i.e. one PBKDF2; it runs once in the life of the
// device, not once per save.
function installStoreAnchor(pass) {
  const anchorFor = (flag) => ({
    established: idstore.anchorEstablished(identity, flag),
    markEstablished: async () => {
      identity.deviceFlags[flag] = true;
      await idstore.persistIdentity(identity, pass);
    },
  });
  contacts.setStoreAnchor(anchorFor("contactsEstablished"));
  chats.setStoreAnchor(anchorFor("chatsEstablished")); // F-ATREST-005
}

async function unlockContacts(pass) {
  const storeWarnings = [];
  try {
    const warning = await contacts.unlock(pass, { startFresh: freshStoreConsent.contacts });
    if (freshStoreConsent.contacts) addLine("sys", "", "[contact store started over EMPTY at your request — every contact must be re-verified]", true);
    // F-P7-6: a bad floor verdict opens the store with its trust reset; say so.
    // All store warnings are collected and shown as ONE hint (second review,
    // M-2: four back-to-back hint() calls left only the last one visible).
    for (const w of [warning, contacts.lastFloorWarning()]) {
      if (w) { addLine("sys", "", "[contacts: " + w + "]", true); storeWarnings.push("Contacts: " + w); }
    }
    contactsError = null;
    contactsErrorCode = null;
  } catch (e) {
    contactsError = e.message;
    contactsErrorCode = e.code || null;
    addLine("sys", "", "[contact store did not unlock — key-change warnings are OFF until it does]", true);
  }
  try {
    const warning = await chats.unlock(pass, { startFresh: freshStoreConsent.chats }); // chat history shares the at-rest posture
    if (freshStoreConsent.chats) addLine("sys", "", "[chat history started over EMPTY at your request]", true);
    for (const w of [warning, chats.lastFloorWarning()]) {
      if (w) { addLine("sys", "", "[chats: " + w + "]", true); storeWarnings.push("Chats: " + w); }
    }
    chatsError = null;
    chatsErrorCode = null;
  } catch (e) {
    // Fix review 2026-08-07 (F3): this used to fold into `contactsError` with no
    // line of its own, so a chat store that refuses to open — which the new
    // F-ATREST-005 rollback control can now do, loudly and on purpose — showed
    // the user nothing but a locked Chats pane, and re-entering the passphrase
    // failed identically with no explanation. Say what happened and why.
    chatsError = e.message;
    chatsErrorCode = e.code || null;
    contactsError = contactsError || e.message;
    addLine("sys", "", `[chat history did not unlock — ${e.message}]`, true);
  }
  if (storeWarnings.length) hint(storeWarnings.join(" — "), true);
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
        (contactsErrorCode === "STORE_DELETED"
          ? " (If you know why — a fresh install, a cleared browser — you can start over with an empty store below; every contact must then be re-verified in person.)"
          : " (Forget + recreate the identity resets it — contacts are bound to the identity passphrase.)")
      : "Contacts are stored encrypted under your identity passphrase. " +
        "Enter it to unlock them here.";
    els.usersStartFresh.hidden = contactsErrorCode !== "STORE_DELETED";
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
      // Second review of F-P7-6 (L-1): a rollback reset used to be described
      // as the routine H-01 format migration — an alarm that names something
      // benign. Say which it was.
      warn.textContent = c.reverifyReason === "rollback"
        ? "⚠ verification reset — your saved contacts were ROLLED BACK on this device (or their rollback guard was deleted); compare the fingerprint again in person"
        : "⚠ verification reset — the fingerprint format now also covers this user's encryption keys; compare it again in person";
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
      // F-PROTO-005: `c` is a snapshot taken before the awaited fetch above.
      // Bind the write to the bundle the signatures were actually checked
      // against, so a directory that stalls /vouches while the user re-adds the
      // contact cannot land this mark on keys the voucher never signed.
      const written = await contacts.setVouches(c.username, names, {
        ed: c.ed, mldsa: c.mldsa, ecdh: c.ecdh ?? null, mlkem: c.mlkem ?? null,
      });
      if (written) changed = true;
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
  if (!unlocked) {
    // Fix review round 3 (F-3): `chatsError` was write-only, so the pane showed
    // a red "Start over" button under a routine "enter your passphrase" line.
    // The alarm is rendered here exactly as the Users pane renders its own.
    els.chatsLocked.querySelector("p").textContent = chatsError
      ? "Chat store error: " + chatsError +
        (chatsErrorCode === "STORE_DELETED"
          ? " (If you know why — a fresh install, a cleared browser — you can start over with an empty chat history below; replay protection for sealed messages is reset and every negotiated chat mode returns to the default.)"
          : " (Forget + recreate the identity resets it — chats are bound to the identity passphrase.)")
      : "Chats are stored encrypted under your identity passphrase. " +
        "Enter it to unlock them here.";
    els.chatsStartFresh.hidden = chatsErrorCode !== "STORE_DELETED";
    return;
  }
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
  } else if (chat.rollback) {
    // F-P7-6 (second review, M-1): durable evidence. The chat store was rolled
    // back on this device; a passphrase or mode changed since may have been
    // reverted to the old one. Cleared by the next deliberate mode change.
    chatHint(`⚠ ${chat.mode} — your chat history was ROLLED BACK on this device: if you changed this chat's passphrase or mode since, it may have reverted to the OLD one. Re-agree it in person, then set the mode again.`, true);
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
let mailThrottled = false; // F-P7-2: the 429 warning is said once per outage
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
  let batch;
  try {
    batch = await account.fetchMail(API_BASE, apiToken);
    mailThrottled = false;
  } catch (e) {
    // A directory session lasts TOKEN_TTL_SEC. When it expires the fetch 401s
    // forever and mail stops arriving with no visible sign, so drop the token
    // and let the block above re-authenticate on the next tick.
    if (e && e.status === 401) apiToken = null;
    // Phase-7 pentest 2026-09-16 F-P7-2: a 429 used to be a bare return — mail
    // silently stopped while the client kept polling. Say so, once per outage.
    if (e && e.status === 429 && !mailThrottled) {
      mailThrottled = true;
      hint("The directory is rate-limiting mail fetches — sealed messages are delayed. Retrying.", true);
      addLine("sys", "", "[the directory is rate-limiting mail fetches — sealed messages are delayed]");
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
  // Phase-7 pentest 2026-09-16 F-P7-22: sealed.open verifies `from` but
  // canonically decodes only ed/mldsa; ecdh/mlkem reached the contact store
  // verbatim — the one surviving second encoding domain of the H-1 shape in a
  // value contacts.js string-compares. Every bundle that reaches storage goes
  // through canonicalBundle; a non-canonical spelling is a malformed envelope.
  let senderBundle;
  try {
    senderBundle = canonicalBundle(opened.from);
  } catch {
    return false;
  }
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
// (600k PBKDF2) and a keypair generation before it disabled the button, so a double-click
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
  } catch (e) {
    // ROUND-4 (pentest of the RSA removal): `connectInner` can throw before it
    // reaches its own try — `algValue()` is called on its first line, outside it.
    // The click handler discards this promise and the client installs no
    // `unhandledrejection` handler, so without this catch a named error reaches
    // the console and the user sees an unexplained dead button. A refusal the
    // user cannot see is not a refusal; that is the property this codebase keeps
    // insisting on, so it has to be true here too.
    hint(e.message, true);
    setStatus("disconnected", "err");
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
    const padLock = await acquirePadLock(padId);
    if (padLock === PAD_LOCK_UNSUPPORTED) {
      // F-CRYPTO-014: no Web Locks means no way to prove the pad is not already
      // open elsewhere, and guessing is how a two-time pad happens. Name the
      // real limitation rather than blaming another tab.
      hint("This browser is too old to guarantee a one-time pad is open only once (it has no Web Locks API), and using a pad twice would destroy its security. Use a current browser for one-time-pad mode, or pick another encryption mode.", true);
      return;
    }
    if (!padLock) {
      hint("This one-time pad is open in another tab or window. Close it there first \u2014 using a pad twice at once would break its security.", true);
      return;
    }
    otpLockRelease = padLock;
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
  myNonce = freshNonce();
  peerNonce = null;
  helloAnswered = false;
  joined = false;   // a repeated `joined` is dropped (see the arm); the flag must not leak across connections
  roomRole = null;
  admittedBundle = null;
  admittedAnon = false;
  approvedBundle = null;
  resolvePeerApproval(false);
  wasPending = false;
  saidDeprecatedAlg = false;
  saidTurnedAway = false;
  saidDenied = false;
  keyConfirm.reset();
  knockQueue = [];
  hideAdmitPrompt();
  // P-19: freeze the session's room/alg now; the send path uses these, never the
  // live DOM.
  sessionRoom = room;
  sessionAlg = alg;
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
    if (joined) addLine("sys", "", "disconnected", true);
    joined = false;
    verified = false;
    roomRole = null;
    admittedBundle = null;
    admittedAnon = false;
    approvedBundle = null;
    // Unpark handleMessage: without this the promise never settles and the
    // FIFO chain for this connection is wedged for as long as the page lives.
    resolvePeerApproval(false);
    wasPending = false;
  saidDeprecatedAlg = false;
  saidTurnedAway = false;
  saidDenied = false;
    keyConfirm.reset();
    knockQueue = [];
    hideAdmitPrompt();
    enableSend(false);
    els.verify.hidden = true;
    showScreen("room");
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

async function showNextKnock() {
  // The peer-approval prompt owns the panel while it is open, and the message
  // pump is parked on it. Rendering a knock over it would swap the buttons out
  // from under a decision the user is in the middle of making — and worse,
  // `hideAdmitPrompt()` below would dismiss a prompt that nothing then settles.
  // Knocks are not lost: the queue is re-rendered once the approval resolves.
  if (approvalPending) return;
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
    describeIdentity(k.bundle, els.admitWho, els.admitWarn,
      "⚠ This is NOT the user you selected for this session. Deny unless you know why.");
  } else if (k.unproven) {
    els.admitFingerprint.textContent = "—";
    els.admitWho.textContent = "Presented an identity it could not prove.";
    els.admitWarn.textContent =
      "⚠ The signature over their claimed keys is invalid. Deny: this is what an impersonation attempt looks like.";
    els.admitWarn.className = "hint err";
  } else {
    els.admitFingerprint.textContent = "—";
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
  // Pentest 2026-08-08 item 20: which of the two prompts this is, as machine-
  // readable state. `#admit` is shared by the owner's knock prompt and the
  // guest's peer-approval prompt, so "is `#admit` visible" cannot tell them
  // apart — and a harness check that the RECEIVING peer asks its user went green
  // against the OWNER's knock prompt because of exactly that. The labels below
  // already differ, but asserting on prose makes every test a hostage to
  // copy-editing. Tests assert this AND the visible label, so the marker cannot
  // silently drift away from what the human is actually being shown.
  els.admit.dataset.mode = "knock";
  els.admit.hidden = false;
  if (knockQueue.length > 1) {
    els.admitWarn.textContent +=
      (els.admitWarn.textContent ? " " : "") +
      `(${knockQueue.length - 1} more waiting — decide one at a time.)`;
  }
}

function hideAdmitPrompt() {
  els.admit.hidden = true;
  // Cleared, not left at its last value: a stale "peer" on a hidden panel is
  // exactly the kind of residue a visibility-only check would misread (item 20).
  delete els.admit.dataset.mode;
  els.admitOk.disabled = false;
  els.admitFingerprint.textContent = "";
  els.admitWho.textContent = "";
  els.admitWarn.textContent = "";
  els.admitTitle.textContent = KNOCK_LABELS.title;
  els.admitHint.textContent = KNOCK_LABELS.hint;
  els.admitOk.textContent = KNOCK_LABELS.ok;
  els.admitNo.textContent = KNOCK_LABELS.no;
}

// Who is this, in OUR terms? Matched on the keys themselves — never on a name
// the other side chose (F-01). Shared by both prompts so the two can never
// describe the same key differently.
//
// Pentest 2026-08-15 (ROUND-2 F-3): this used to RETURN a `mismatch` boolean.
// That boolean was the whole item-14 attack surface in a new disguise — a
// decision-grade verdict on a plain object that a single added line
// (`if (!describeIdentity(idb).mismatch) approvedBundle = idbCanon;`) could read
// to wave a hostile-directory peer straight past the approval gate, with the
// forbidden identifiers appearing nowhere. So there is no boolean to read: this
// function is display-only. It WRITES the "who" and the mismatch warning into
// the elements it is handed and returns nothing. The gate's own mismatch check
// lives independently in `peerAlreadyTrusted`, which recomputes it from bytes.
function describeIdentity(bundle, whoEl, warnEl, mismatchMsg) {
  const known = contacts.isUnlocked()
    ? contacts.list().find((c) => c.ed === bundle.ed && c.mldsa === bundle.mldsa)
    : null;
  whoEl.textContent = known
    ? `${dirName(known)} — ${contactMark(known)}`
    : (pinsReadable()
      ? "Not in your users list — ⚪ you have never verified this key"
      : "Unknown — your saved users could not be read, so trust cannot be checked");
  // If this session was aimed at a specific contact, say whether it is them.
  if (expectedPeerBundle && !sameBundle(expectedPeerBundle, bundle)) {
    warnEl.textContent = mismatchMsg;
    warnEl.className = "hint err";
  } else {
    warnEl.textContent = "";
    warnEl.className = "hint";
  }
}

// ---- peer approval, guest side (F-PROTO-001, 2026-08-08) -------------------
//
// When this device did not run the knock prompt, the peer's signed handshake is
// held here until a human looks at it. Exactly ONE way past without asking: the
// peer is a key this user already verified in person (🟢 in the contacts store,
// which is behind the at-rest passphrase). Anything else — every first contact,
// and every hostile-relay configuration — is a prompt. That is the point: the
// attack's whole effect was that nobody was ever asked.
//
// Pentest 2026-08-08 item 14. There used to be a second route: "the peer matches
// `expectedPeerBundle`, the directory bundle for the contact the user picked".
// It is deleted, because it was not a local fact at all. `expectedPeerBundle`
// comes from `account.fetchBundle`, which canonicalises the base64 and
// length-checks the keys and verifies NO SIGNATURE — nothing binds a handle to
// its key material, and the handle's token is a random server-issued lookup
// token. So a hostile directory answered with its own bundle, the prompt was
// skipped, and the client printed an attacker-chosen reassurance naming the
// victim's contact. The comment that both routes were "facts we hold locally and
// the relay cannot write" was false of this one, and the route it guarded was
// precisely the flow the rewrite advertised as costing no click.
//
// Not only a same-origin concern: `RELAY.api` exists so the Android app can
// serve trusted client bytes locally while pointing at a remote directory —
// honest client, attacker-controlled directory, one identical `fetch`.
//
// Restoring this route needs the directory answer to be SIGNED by the identity
// it names, verified here against something the user already trusts. Until that
// exists, first contact by handle costs one click — which is the same question
// the safety-number step asks immediately afterwards anyway.
function peerAlreadyTrusted(bundle) {
  // Item 21: if the user picked a specific contact and this is not them, ASK —
  // never fall through to the contacts route. Without this, a 🟢 contact who is
  // not the contact you selected skipped the prompt: `describeIdentity` computes
  // exactly that verdict (`mismatch`) and this gate never consulted it. The
  // directory answer is untrusted (item 14 above), so a mismatch is not by
  // itself proof of an attack — but it is always a reason to show the human the
  // fingerprint rather than to wave it through.
  if (expectedPeerBundle && !sameBundle(expectedPeerBundle, bundle)) return null;
  if (contacts.isUnlocked()) {
    // Item 24: compare decoded bytes, as every other bundle comparison here
    // does, rather than base64 strings. Both sides are canonical today so this
    // changes no verdict; it removes the standing trap that a spelling
    // difference would silently read as a different identity.
    const known = contacts.list().find((c) => sameSigning(c, bundle) && c.verified);
    if (known) return `is the key you verified in person for "${dirName(known)}"`;
  }
  return null;
}

const KNOCK_LABELS = {
  title: "Someone wants to join this chat",
  hint: "They know your chat code. Let them in only if you are expecting them — " +
    "check the key fingerprint below against the person you invited.",
  ok: "Let them in",
  no: "Deny",
};

const PEER_LABELS = {
  title: "Someone is already in this chat — is it them?",
  hint: "You were put into this chat without being asked to approve anyone. " +
    "Check this key fingerprint against the person you meant to talk to BEFORE " +
    "any keys are exchanged. If you cannot, refuse.",
  ok: "Connect",
  no: "Refuse",
};

// Registers the promise SYNCHRONOUSLY, then renders. The other order would let a
// close arriving mid-render find no pending approval to cancel, and the message
// pump would stay parked on a promise nothing could ever settle.
function requestPeerApproval(bundle) {
  const decided = new Promise((resolve) => { approvalPending = { bundle, resolve }; });
  renderPeerApproval(bundle);
  return decided;
}

async function renderPeerApproval(bundle) {
  const fp = await Identity.fingerprintOf(bundle);
  if (!approvalPending || approvalPending.bundle !== bundle) return; // decided already
  els.admitTitle.textContent = PEER_LABELS.title;
  els.admitHint.textContent = PEER_LABELS.hint;
  els.admitOk.textContent = PEER_LABELS.ok;
  els.admitNo.textContent = PEER_LABELS.no;
  els.admitFingerprint.textContent = fp;
  describeIdentity(bundle, els.admitWho, els.admitWarn,
    "⚠ This is NOT the user you selected for this session. Refuse unless you know why.");
  els.admitOk.disabled = false;
  els.admit.dataset.mode = "peer";   // item 20 — see the note in showAdmitPrompt
  els.admit.hidden = false;
}

// Settles the parked handshake. Safe to call when nothing is pending, which is
// what makes it usable straight from `ws.onclose`.
function resolvePeerApproval(ok) {
  if (!approvalPending) return;
  const { resolve } = approvalPending;
  approvalPending = null;
  hideAdmitPrompt();
  resolve(ok);
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
    approvedBundle = k.bundle;  // the same local-approval fact, owner route
    addLine("sys", "", k.bundle
      ? "you let someone in — their key is now pinned for this session"
      : "you let someone in — they have no identity to pin", true);
  }
  ws.send(JSON.stringify({
    type: allow ? "admit" : "deny", room: sessionRoom, jid: k.jid,
  }));
  if (!allow) addLine("sys", "", "you denied someone who asked to join", true);
  return showNextKnock();   // awaited by callers; unawaited it races the message path
}

// True once this session has let someone in. The chat holds two people, so from
// here on the only meaningful verdict is "deny".
function admittedSomeone() {
  return admittedBundle !== null || admittedAnon;
}

// Produce + sign the next handshake payload. Computed fresh each call (not
// cached): for PQKEM the initial "offer" and the "answer" are different
// payloads (the answer carries the encapsulation to the peer's key), and each must
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
  return signedHandshake(room).then(async ({ pub, sig }) => {
    // No admission proof travels with this any more (F-PROTO-001, 2026-08-08):
    // a signature the PEER makes about its own authority is worth nothing when
    // the peer is the attacker, and sending one invited exactly the false
    // confidence the review found. Approval is now decided locally on the
    // receiving side. This also un-breaks the wire: the frame is `handshake/v3`
    // again, with no field a client of either vintage must send.
    const frame = { pub, reply, idb: myBundle, sig };
    ws.send(JSON.stringify({
      type: "key", room, alg: sessionAlg,
      payload: packKey(frame),
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
// changes (PQKEM). Two consequences, both of which this block
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
    addLine("sys", "", `[${why} — refusing to continue]`, true);
    hint(
      "Key confirmation failed: you and your contact do not hold the same session key. " +
      "Messages would silently fail to arrive. Disconnecting.",
      true,
    );
    if (ws) ws.close();
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

async function handleMessage(room, raw) {
  // Pentest 2026-08-07 F-PROTO-002. Every authentication refusal in this file
  // ends in a bare `ws.close()`, which stops nothing that is already in flight:
  // `msgChain` is a FIFO promise chain, so frames the relay batched with the
  // refused one were already queued and kept driving this state machine after
  // the decision to refuse. Demonstrated end state, after the client printed
  // "[a SECOND identity tried to complete the key exchange — refusing]": the
  // channel was still derived, the receive gate still opened, relayed
  // ciphertext was still decrypted and rendered as trusted peer content, the
  // Send box was re-enabled on a socket that was going away, and the user was
  // left reading "Verified. Messages are end-to-end encrypted." The loud
  // warning survived only as a scrolled-past log line.
  //
  // `close()` moves readyState to CLOSING synchronously, so testing it here —
  // at dispatch, not at queue time — drops every frame queued behind a refusal,
  // whichever of the ~10 refusal sites fired. Nothing else in the session
  // closes the socket while frames are still worth processing: a user
  // disconnect and a relay-side close both want exactly this behaviour too.
  if (!ws || ws.readyState !== WebSocket.OPEN) return;

  let m;
  try {
    m = JSON.parse(raw);
  } catch {
    return;
  }

  // Deprecation backstop (F-CRYPTO-009, 2026-08-21). The live-room mode is
  // chosen ENTIRELY LOCALLY — from this page's own radio, frozen into
  // `sessionAlg` at connect time — and no inbound frame has ever selected a
  // cipher: `alg` on the wire is an advisory tag that neither this dispatch nor
  // the relay reads. So a peer or relay claiming alg:"RSA" cannot downgrade us.
  // What it CAN mean is that the other end is an old build still running the
  // removed mode, in which case nothing it sends is decryptable here. Say that
  // out loud rather than letting it arrive as a generic "undecryptable message":
  // an unexplained mismatch is exactly what a downgrade would look like if the
  // local-only property ever broke, and this codebase treats a quiet mode
  // discrepancy as a finding. Drop the frame only — never throw (an unhandled
  // throw here would stall every later frame in the pump) and never adopt the
  // peer's mode.
  if (typeof m.alg === "string" && Object.prototype.hasOwnProperty.call(DEPRECATED_ALGS, m.alg)) {
    if (!saidDeprecatedAlg) { // F-P7-7: once per connection, or the refusal is a DOM flood
      saidDeprecatedAlg = true;
      addLine("sys", "", `[frame refused — the other end is using ${m.alg}, which this version has removed]`);
      hint(`${m.alg} is no longer supported — ${DEPRECATED_ALGS[m.alg]}`, true);
    }
    return;
  }

  switch (m.type) {
    // We are waiting for the room owner to let us in (P-08). Nothing of ours
    // reaches the room until they do — not even the session nonce — so the
    // only thing to send now is the introduction they will judge us by.
    case "pending": {
      // Write-once, like the peer identity pin: a relay must not be able to
      // re-cast us mid-session (an owner told "you are a guest" would stop
      // being asked to approve anyone).
      if (roomRole !== null) break;
      roomRole = "guest";
      wasPending = true; // M-2: proof we went through the approval queue
      els.roomShort.textContent = room.slice(0, 8) + "…" + room.slice(-8);
      showScreen("chat");
      setStatus("waiting for approval");
      addLine("sys", "", "waiting — the person who created this chat has to let you in", true);
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
      // Review of 4b9d2c6..a88baa4 (M-1): this used to interpolate the relay's
      // `count` into the line and run hint() per frame — the only line a relay
      // could make us narrate unprompted that was NOT a constant string, so the
      // collapse rule never fired and 1 200 thirty-byte frames pushed every
      // security line out of the transcript (the fallback below evicted the
      // OLDEST system line once only system lines remained). The count was
      // relay-controlled and told the owner nothing they can act on; say it
      // once per connection, like the deprecated-alg refusal.
      if (roomRole !== "owner") break; // only the owner is asked to admit anyone (second review, Info-2)
      if (!saidTurnedAway) {
        saidTurnedAway = true;
        addLine("sys", "", "[someone was turned away — the waiting queue is full]", true);
        hint(
          "Someone could not even reach the approval queue because it is full. If the person you invited " +
          "is stuck on \"room full\", agree a NEW chat code with them out of band.",
          true,
        );
      }
      break;
    }

    // The owner declined us (or the relay says so). Either way we are not in.
    case "denied": {
      // Third review of the M-1 fix: only a guest can be denied, and the honest
      // relay sends this once and closes the socket — a hostile one sent it
      // forever, alternated with junk, to reach the transcript cap. Owner-only
      // and once per connection, like the queue-full line.
      if (roomRole === "owner") break;
      if (!saidDenied) {
        saidDenied = true;
        addLine("sys", "", "[the other person did not let you in]", true);
        hint("They declined. If you expected to be let in, check with them out of band that you are both using the same chat code.", true);
      }
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
      // Second review of the M-1 fix: a repeated `joined` re-narrated the
      // session start — two distinct lines per 32-byte frame, which the
      // consecutive-collapse rule cannot fold, so 300 frames reached the cap
      // with no peer and no user. The seat is write-once; a second `joined`
      // carries nothing new and is dropped (a CHANGED role is still refused
      // below, because that one is evidence).
      if (joined && m.role === roomRole) break;
      joined = true;
      // An older relay answers `join` with a bare {"joined"} — no role, no
      // admission control. Refusing beats silently running the protocol this
      // fix removed: the room would again be first-come-first-served and the
      // approval prompt would never appear, with nothing on screen to say so.
      if (m.role !== "owner" && m.role !== "guest") {
        addLine("sys", "", "[this relay does not support join approval — refusing]", true);
        hint("This relay is running an older protocol without the join-approval step. Update the relay (or your app) before using it.", true);
        if (ws) ws.close();
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
        addLine("sys", "", "[the relay changed our role mid-session — refusing]", true);
        hint("The relay tried to change your role in this room. Disconnecting.", true);
        if (ws) ws.close();
        return;
      }
      // Pentest 2026-07-27 M-2, guest half. The owner half (below, in the
      // handshake) refuses a peer nobody approved; that alone still leaves the
      // relay the option of telling BOTH parties they are guests, so neither
      // one is ever asked to approve anybody. But the only legitimate way to
      // become a guest is pending -> knock -> joined:guest, so a seat handed to
      // us without ever passing through the queue means no owner approved it.
      if (roomRole === "guest" && !wasPending) {
        addLine("sys", "", "[we were seated in this room without ever asking to be let in — refusing]", true);
        hint("This relay put you in the room without the owner approving you. Disconnecting.", true);
        if (ws) ws.close();
        return;
      }
      els.roomShort.textContent = room.slice(0, 8) + "…" + room.slice(-8);
      showScreen("chat");
      setStatus("connected", "ok");
      addLine("sys", "", `joined room — encryption: ${sessionAlg}`, true);
      if (roomRole === "owner") {
        addLine("sys", "", "you created this chat — you decide who is let in", true);
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
          addLine("sys", "", "[handshake signature INVALID — refusing to connect; a relay may be tampering with the key exchange]", true);
          hint("Authentication failed — disconnecting. This is what a MITM attempt looks like.", true);
          if (ws) ws.close();
          return;
        }

        // P-08: if WE admitted this peer, the handshake must come from the
        // identity we were shown and approved. This is the binding that makes
        // the approval prompt more than decoration: the relay picks who is
        // routed to us, so without it a relay could show the owner a knock from
        // a trusted contact and then hand the seat to someone else.
        //
        // Keyed on admittedBundle ALONE, never on roomRole: the role comes from
        // the relay, so gating the check on it would let a relay switch the
        // check off by re-sending `joined` with role "guest" (M-2, F-PROTO-001).
        if (admittedBundle && !sameBundle(admittedBundle, idbCanon)) {
          addLine("sys", "", "[the peer that connected is NOT the one you let in — refusing]", true);
          hint("The identity that completed the key exchange differs from the one you approved. Disconnecting.", true);
          if (ws) ws.close();
          return;
        }
        // Admitting someone who showed no identity, then receiving a signed
        // handshake, means the socket changed its story between the two steps.
        if (admittedAnon) {
          addLine("sys", "", "[the peer you let in had no identity but now sends one — refusing]", true);
          hint("This peer introduced itself without an identity and then produced one. Disconnecting.", true);
          if (ws) ws.close();
          return;
        }
        // The relay told us we own this room, and we admitted nobody — so it
        // seated a second member behind our back. `relay.py admit` is the only
        // seat-granting path, so an honest relay cannot produce this. Consulting
        // a relay frame here is safe in the one direction it runs: it can only
        // ever ADD a refusal, never skip the approval below (M-2's owner half,
        // kept because it costs nothing).
        if (roomRole === "owner" && !admittedSomeone()) {
          addLine("sys", "", "[the relay seated someone in your room without asking you — refusing]", true);
          hint("You own this chat and approved nobody, yet someone completed the key exchange. The relay is not behaving. Disconnecting.", true);
          if (ws) ws.close();
          return;
        }

        // F-PROTO-001, rebuilt 2026-08-08. See the note at `approvedBundle`.
        //
        // Everything above is the OWNER's half. This is the other one: if no
        // human on this device has approved this identity, ask now — before any
        // key material is touched — and refuse if they say no.
        //
        // The previous repair asked the PEER to prove it had admitted us, which
        // is unsound in a way no binding fixes: the proof is verified against
        // the peer's own bundle, so the attacker signs one with a keypair it
        // generates on the spot. The relay already knows the room id (it is the
        // `join` frame), so it can always be a code-knowing participant, and
        // every claim such a participant makes about itself is the attacker's to
        // choose. Local approval is the only input it cannot write.
        if (!approvedBundle) {
          const trusted = peerAlreadyTrusted(idbCanon);
          if (trusted) {
            // Not a click, but not the relay's word either: the one remaining
            // route compares against a 🟢 key this user verified in person,
            // held in the passphrase-backed contacts store. Item 14 deleted the
            // route that compared against an unsigned directory answer.
            approvedBundle = idbCanon;
            addLine("sys", "", `peer key ${trusted} — no approval needed`, true);
          } else {
            addLine("sys", "", "[nobody has approved this connection — asking you before any keys are exchanged]", true);
            const allowed = await requestPeerApproval(idbCanon);
            // The socket can close under us while the prompt is open; the pump
            // check at the top of handleMessage does not re-run after an await.
            if (!ws || ws.readyState !== WebSocket.OPEN) return;
            if (!allowed) {
              addLine("sys", "", "[you refused this peer — disconnecting]", true);
              hint("You refused the key that was offered. Nothing was exchanged.", true);
              ws.close();
              return;
            }
            approvedBundle = idbCanon;
            addLine("sys", "", "you approved this peer — their key is now pinned for this session", true);
            // A knock may have queued behind the prompt (an owner who was told
            // it is a guest still receives them).
            await showNextKnock();
          }
        }
        // A second, different identity after an approval is a relay swapping the
        // seat. C-01 below catches it too, but say the specific thing here.
        if (!sameBundle(approvedBundle, idbCanon)) {
          addLine("sys", "", "[a different identity than the one approved completed the key exchange — refusing]", true);
          hint("The identity that completed the key exchange is not the one that was approved. Disconnecting.", true);
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
          peerBundle = idbCanon; // write-once for this connection, canonical (H-1)
        } else if (!sameBundle(peerBundle, idbCanon)) {
          addLine("sys", "", "[a SECOND identity tried to complete the key exchange — refusing; this is a relay MITM attempt]", true);
          hint("Two different identities attempted this handshake — disconnecting to protect you.", true);
          if (ws) ws.close();
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
        // P-04: recvHighWater must reach disk too — an unpersisted receive
        // watermark lets an already-delivered frame be replayed after a reload.
        //
        // ROUND-3 F-2 (pentest 2026-08-21): persist BEFORE displaying, mirroring
        // the send path, which persists before it transmits. The old order left a
        // window where a frame had been accepted and shown while nothing durable
        // recorded that its keystream was consumed — and on the FIRST frame a pad
        // ever receives that window has the floors still at the probe-only
        // (0,0,0), which since F-A1-R1 is deliberately not evidence of use. A
        // crash there plus H-3's marker deletion made the pad re-importable, which
        // rewinds recvHighWater and re-authenticates every already-delivered frame
        // as fresh (the M-7 class). Persisting first makes "shown to the user"
        // imply "durably recorded as spent".
        //
        // A failure still SHOWS the message rather than dropping it: the keystream
        // is already spent in memory, so dropping would lose content the pad paid
        // for while making nothing safer. `otpPersistFailed` is the loud part.
        try {
          await persistOtpProgress();
        } catch (err) {
          otpPersistFailed(err);
        }
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
    addLine("sys", "", `[directory mismatch for "${expectedPeerName}" — verification required]`, true);
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
    els.verifyTitle.textContent = "⚠ Your saved contacts could not be opened — key changes cannot be detected";
    els.verifyHint.textContent =
      "Your contact store is locked or damaged" +
      (contactsError ? ` (${contactsError})` : "") +
      ", so this app cannot check whether this contact's key changed since last time. " +
      "Treat this as an UNVERIFIED first contact: confirm the safety number below in person " +
      "before you continue. Unlock your contacts on the Profile screen to restore key-change warnings.";
    addLine("sys", "", "[contact store unreadable — pinned-key change detection is OFF]", true);
    hint("Key-change detection is off — your saved contacts could not be opened.", true);
    return;
  }

  const pin = await getPin(currentPinKey);
  if (pin && pin.suspect === true) {
    // F-P7-6: the contact store was rolled back (or its rollback guard
    // deleted/forged) on this device, so this pin may be one the user had
    // already replaced. It is kept — so this is NOT a first contact — but it
    // may not unlock anything until the safety number is confirmed in person
    // again, which writes a fresh pin and clears the mark.
    els.verify.hidden = false;
    els.verify.classList.add("changed");
    els.verifyTitle.textContent = "⚠ Re-verify this contact — your saved contacts were rolled back on this device";
    els.verifyHint.textContent =
      "This device's protected record says your saved contacts are older than they should be, so the " +
      "pin for this contact may be one you had already replaced. Compare the safety number with them " +
      "in person (or over a call where you recognise their voice) before you continue.";
    addLine("sys", "", "[pin marked suspect after a rollback of your saved contacts — re-verification required]", true);
    hint("Confirm the safety number with your contact before messaging unlocks.");
    return;
  }
  if (sameBundle(pin, bundle)) {
    // Seen and verified before — accept without re-prompting.
    addLine("sys", "", expectedPeerName
      ? `contact "${expectedPeerName}" matches your saved pin`
      : "contact identity matches your saved pin", true);
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
    addLine("sys", "", "[pin predates encryption-key coverage — re-verification required]", true);
  } else if (pin) {
    // A pin exists but the key changed: loud warning, require re-verification.
    els.verify.classList.add("changed");
    els.verifyTitle.textContent = "⚠ Contact identity key CHANGED — re-verify in person";
    els.verifyHint.textContent =
      "The identity key you pinned before is different now. This happens if your contact reset their " +
      "device — but it is also what an interceptor looks like. Do NOT proceed until you have confirmed " +
      "this safety number with them over a trusted channel.";
    addLine("sys", "", "[pinned identity CHANGED — verification required]", true);
    // `pinsReadable()` above is also true when this device has NO contact store
    // at all, and `pinWasSwept()` throws in that state — so the unlock check is
    // not redundant with it.
  } else if (contacts.isUnlocked() && contacts.pinWasSwept(currentPinKey, bundle)) {
    // Pentest 2026-08-10-night F-A2. There is a third way to arrive here with no
    // pin, besides "never seen" and "pin deleted by an attacker": this pin was
    // swept as COLLATERAL when the user revoked somebody else who had these same
    // keys recorded in their history (see contacts.js dropPinsFor).
    //
    // Revocation deletes that pin unconditionally, because letting a second
    // record decide what revocation may delete is what made F-A2 fail open. The
    // cost of that is exactly this state — and rendering it as a benign first
    // contact is M-2's alarm inversion, the failure the whole item is about. So
    // the tombstone the sweep left behind is read here and said out loud.
    //
    // Keyed on the PIN KEY, not on a contact record (F-A2-R1): a `room:<id>` pin
    // whose owner has no record — the default for Live-room use — and a bystander
    // who has since rotated both used to be swept with no marker at all, and
    // still rendered benign.
    els.verify.classList.add("changed");
    els.verifyTitle.textContent = "Re-verify this contact — their saved pin was cleared";
    // Wording note: the tombstone covers every pin the sweep deleted, which
    // includes the revoked contact's own — so this must not claim the revocation
    // was of "another contact". It says what is true of every case: a pin existed
    // here and a revocation removed it.
    els.verifyHint.textContent =
      "There was a verified pin for this key, and it was removed when you revoked or removed a " +
      "contact that used these keys. This is NOT a first contact: compare the safety number " +
      "with them in person before you continue, exactly as you did the first time.";
    addLine("sys", "", "[pin cleared by an earlier revocation — re-verification required]", true);
  } else {
    els.verify.classList.remove("changed");
    els.verifyTitle.textContent = "Verify your contact — in person";
    if (expectedPeerBundle) {
      addLine("sys", "", `key matches the directory entry for "${expectedPeerName}" — still verify in person`, true);
    }
  }
  hint("Confirm the safety number with your contact before messaging unlocks.");
}

function unlockMessaging() {
  verified = true;
  els.verify.hidden = true;
  enableSend(true);
  addLine("sys", "", "secure channel established", true);
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
    addLine("sys", "", "[verified for this session only — the pin could NOT be saved: " + e.message + "]", true);
  }
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
  addLine("sys", "", "contact verified and pinned", true);
  unlockMessaging();
}

function onVerifyNo() {
  addLine("sys", "", "disconnected — contact not verified", true);
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
  addLine("sys", "", "[could not save one-time-pad progress — stopping to prevent key reuse]", true);
  hint(
    "Could not save pad progress: " + err.message +
    " — disconnecting so the pad cannot be reused. Free up storage, then reconnect.",
    true,
  );
  if (ws) ws.close();
}

// ---- pad exclusive lock (one live session per pad) ------------------------
// Prevents the concurrent-use two-time-pad break: two tabs each loading the same
// pad at the same offset. Uses the Web Locks API (auto-released if the tab dies)
// where available, with a localStorage-heartbeat lease as a fallback.
// Returned instead of a release function when this engine has no Web Locks API.
// Distinct from `null` ("someone else holds the pad") because the two need very
// different sentences in front of the user.
const PAD_LOCK_UNSUPPORTED = "unsupported";

// Exclusive same-origin lock on a pad. OTP's entire information-theoretic claim
// (P9) rests on no pad byte ever encrypting twice; within a tab that is
// `sendOffset` monotonicity plus the P-01 zeroization guard, and ACROSS tabs it
// is this and nothing else.
//
// Pentest 2026-08-07 F-CRYPTO-014: when Web Locks was absent this fell back to a
// hand-rolled localStorage lease, which is not an exclusion primitive. `getItem`
// and `setItem` are separate operations with no cross-tab atomicity, so two tabs
// that both read "free" both acquired; and because nothing re-read the lease
// after acquisition, a backgrounded tab whose 4 s heartbeat was throttled lost
// its 12 s lease to a second tab and kept sending regardless. Both tabs then
// held the same decrypted pad at the same `sendOffset`; the P-01 spent-keystream
// guard reads each tab's own copy, so it passes in the stale one — a genuine
// two-time pad on the wire plus a reused one-time MAC key, recoverable by
// crib-dragging.
//
// A lease that cannot be made atomic in localStorage must not be presented as an
// exclusion lock for that hazard, so the fallback is gone: no Web Locks, no OTP
// mode. This is the same fail-closed stance the project takes on a missing
// `crypto.subtle` (see no-fallback.test.mjs) — the affected engines are Chrome /
// Android System WebView < 69, Firefox < 96 and Safari 15.0-15.3, and on those
// the honest answer is that we cannot guarantee the pad is open only once.
//
// The Web Locks path itself needs no re-validation: the lock is held inside an
// unresolved callback promise for the life of the session, and a rejected
// request resolves `null`, which fails closed.
function acquirePadLock(padId) {
  const name = "sc.otp.lock.v1." + padId;
  if (!(navigator.locks && navigator.locks.request)) {
    return Promise.resolve(PAD_LOCK_UNSUPPORTED);
  }
  return new Promise((resolveGot) => {
    let releaseHeld;
    navigator.locks.request(name, { ifAvailable: true }, (lock) => {
      if (!lock) { resolveGot(null); return; } // held elsewhere
      resolveGot(() => { if (releaseHeld) releaseHeld(); });
      return new Promise((r) => { releaseHeld = r; }); // hold until released
    }).catch(() => resolveGot(null));
  });
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
    // A4/F-A3: two different unverifiable states reach this gate, and the
    // escalation has to say something TRUE of the one at hand. "No usage record"
    // is the sentence that should stop a user looking at a pad they have used for
    // months; it is simply wrong about a pad whose floor could not be WRITTEN.
    const warn = !e.suspicious ? ""
      : e.reason === "unarmable-floor"
        ? "WARNING: this device HAS used one-time pads under the current version, " +
          "so its protected storage failing on this pad specifically is a strong " +
          "sign its rollback protection was interfered with.\n\n"
        : "WARNING: this device HAS used one-time pads under the current version, " +
          "so this pad having no usage record is a strong sign its rollback " +
          "protection was tampered with.\n\n";
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
      otpStatusMsg("⚠ This pad was already exported. A pad must be imported on only ONE device — re-exporting risks catastrophic key reuse. Click Export again to confirm you know what you are doing.", true);
      return;
    }
    pendingReexportId = null;
    const text = await otp.exportPad(record, els.otpXferPass.value);
    // Pentest 2026-08-10-night F-A1: LATCH BEFORE HANDING THE FILE OVER.
    //
    // This used to download first and latch second. `markExported` is the only
    // thing that records "this pad has left the device", and it can fail (a full
    // disk, a broken floor bridge) — so the old order could put a pristine pad
    // file in the user's hands with nothing on the device remembering it. The
    // re-export warning is then silent on the SECOND export, and one pad in two
    // importers is a two-time pad, the one failure OTP cannot survive.
    //
    // Latching first inverts the failure: the export fails loudly and no file is
    // produced. The cost of the bad case is one extra confirm click on the
    // retry; the cost of the other one is unbounded.
    await otp.markExported(record, atRest);
    downloadText(`secure-chat-pad-${record.label || record.padId}.json`, text);
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
const usersGo = wireViewUnlock(els.usersUnlockPass, els.usersUnlock,
  setUnlockStatus(els.usersUnlockStatus), refreshUsers);
const chatsGo = wireViewUnlock(els.chatsUnlockPass, els.chatsUnlock,
  setUnlockStatus(els.chatsUnlockStatus), refreshChats);
wireStartFresh(els.usersStartFresh, "contacts", "contact store",
  "Every contact must then be re-verified in person.", usersGo);
wireStartFresh(els.chatsStartFresh, "chats", "chat history",
  "Replay protection for sealed messages is reset and every negotiated chat mode returns to the default.", chatsGo);

els.gen.addEventListener("click", () => {
  els.room.value = newRoomCode();
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
  PQKEM: "post-quantum (ML-KEM-768)",
  OTP: "one-time pad",
};
function syncAlgUI() {
  // ROUND-4: this runs at module scope during init, so an `algValue()` throw here
  // would abort the REST of app.js's setup (identity UI, the default room code,
  // invite-link handling) with nothing shown — a blank, half-built page. Report it
  // and leave the rest of init to run; `connect()` still refuses loudly, which is
  // where the refusal actually has to bite.
  let alg;
  try {
    alg = algValue();
  } catch (e) {
    els.algSummary.textContent = "Security options — " + e.message;
    return;
  }
  els.passRow.hidden = alg !== "AES256";
  els.contactRow.hidden = !algNeedsIdentity(alg); // lookup only aids DHKE/PQKEM
  els.otpPanel.hidden = alg !== "OTP";
  els.algSummary.textContent = "Security options — currently: " + (ALG_LABELS[alg] || alg);
  // A non-default choice needs the panel to stay open, or the setting becomes
  // invisible the moment the user looks away.
  if (alg !== "DHKE") els.algDetails.open = true;
}
els.algCards.addEventListener("change", syncAlgUI); // radio changes bubble here

els.connect.addEventListener("click", connect);
els.form.addEventListener("submit", sendText);
els.verifyOk.addEventListener("click", onVerifyOk);
els.verifyNo.addEventListener("click", onVerifyNo);
// One pair of buttons, two prompts. The peer-approval prompt owns them while it
// is open (showNextKnock defers to it), so the dispatch cannot cross wires.
els.admitOk.addEventListener("click", () => {
  if (approvalPending) resolvePeerApproval(true); else decideKnock(true);
});
els.admitNo.addEventListener("click", () => {
  if (approvalPending) resolvePeerApproval(false); else decideKnock(false);
});

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
  addLine("sys", "", "[signed out of the directory — sealed messages will not arrive until you log in again]", true);
});
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
if (!els.room.value) els.room.value = newRoomCode();

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

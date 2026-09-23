# Messenger patterns for secure-chat

**Sources.** WebFetch was blocked by the proxy, but WebSearch worked (Sept 2026). **[fetched]** means confirmed from search results. **[from memory]** means my recollection; re-check before citing it.

**Constraints kept throughout:** 1:1 only; three trust levels; the in-person safety-number check gates sending and receiving; the relay is hostile and stores nothing; mono type for key material only; the dark blue palette with `#1f6feb` as primary.

## 1. Identity create / unlock

**Borrow.** Session and SimpleX start without a phone number or email **[fetched]**. Signal's lock screen is a plain screen with one action **[from memory]**. The passphrase is the only secret, so it gets the whole screen.

**Layout.** *First run:* the wordmark in mono and one line, "Your keys are made on this device. Nobody else holds them." Below it, a passphrase field with a strength hint, **Create identity**, and a text link for "Restore from backup". The directory username moves to Profile as an optional step. Next, a prompt like Session's recovery-password nag **[from memory]**: "Copy your backup now. There is no account recovery." (**Copy backup** / "Later"). A Profile banner stays until the backup is done. *Returning:* the passphrase field and **Unlock**. Forget does not appear on this screen.

**Don't copy.** Phone or email sign-up, Signal's PIN cloud recovery, Session's seed words, or biometric-only unlock (the passphrase derives the keys).

## 2. Live room (code, mode picker, "who are you expecting", Connect)

**Borrow.** SimpleX has one-time invitation links and QR codes **[fetched]**. Briar splits adding a contact "nearby" from "at a distance" and shows a pending state **[fetched]**. The chat code already works as a one-time invitation, so presenting it that way removes the "room id" jargon.

**Layout.** A segmented control at the top: **Start** | **Join**. *Start:*
- The code is shown large in mono across two rows, with Copy and Share. "New code" is a ghost icon.
- "Expecting (optional)" picks from Users or takes a pasted handle, and shows that contact's trust pill.
- The encryption choice collapses to one row, "Encryption: DHKE (recommended) ›". It opens a sheet of five cards. The AES-256 and OTP fields appear only once that card is selected.
- **Connect** is pinned at the bottom.

Waiting state, like Briar's: "Waiting for them. You both need this screen open. The relay keeps nothing." A Cancel button sits below.

**Don't copy.** SimpleX's long-term address with auto-accept (it bypasses admission), or Briar's 48-hour pending queue. The live room is live-only.

## 3. Admission prompt

**Borrow.** SimpleX shows a connection request with accept/reject, and Session holds message requests apart until you accept **[fetched]**. The risk is named at the moment the user decides, and Deny is as easy to reach as Accept.

**Layout.** A bottom sheet titled "Someone wants to join".
- *Expected handle matched:* the name and a "verified by you" pill.
- *No match:* the warning "Not the person you were expecting". Neither button is primary, and focus starts on **Deny**.
- *Always:* the fingerprint as a mono grid of 2 rows × 4 groups. The buttons are **Let them in** and **Deny** (outline in the danger colour). The explanation sits behind "What am I checking?".

**Don't copy.** Auto-accept, or a requests inbox. Admission happens live, once.

## 4. Safety-number verify gate

**Borrow.** Signal shows 60 digits in 12 groups of 5, a QR code to scan, and "Mark as verified" **[fetched]**. Element's emoji check offers **They match** and **They don't match** as equal buttons **[from memory]**. Grouping aids reading aloud; equal buttons keep "no" visible.

**Layout.** A full screen with no chat behind it.
- The header reads "Compare with alice", with her pill.
- The 40-hex safety number is 10 mono groups at about 22px, in 5 rows × 2 columns. Each row has a small muted number (1–5), so people can say "row three: 7F2A 91C0".
- One line below: "Read it aloud in person. It must match exactly." A "Why?" link holds the man-in-the-middle explanation.
- Full-width stacked buttons: **It matches — unlock messaging** and **It differs — disconnect** (danger outline).
- "Show their fingerprint" is a secondary link.

**Don't copy.** Signal's "Verify automatically", which trusts a key-transparency log run by the server **[fetched, Aug 2026]**. secure-chat's relay is hostile, so it can't play that role. Also skip Element's cross-signing (for multiple devices) and any option to chat unverified.

## 5. Live chat

**Borrow.** Signal's composer placeholder has doubled as the encryption indicator **[from memory]**, and it shows a check next to a verified name in the header **[fetched]**. The security state appears where the user is already looking.

**Layout.**
- *Header:* back, the name with a pill, and a small mono chip `DHKE · ratchet`. The overflow menu holds Copy room id and **Disconnect**.
- *Composer:* the placeholder reads "Encrypted to alice". Before verification it is disabled and gives the reason inline.
- *Messages:* the same bubbles as async chats. System lines are centred and muted ("Verified in person · 14:02").

**Don't copy.** Typing indicators, read receipts, or disappearing timers. They add metadata or repeat what is already true.

## 6. Users view

**Borrow.** Threema marks every contact with three dots: red when the key came from the server, orange when it matched the address book, and green after an in-person QR scan **[fetched]**. Element turns the shield red when a verified user's identity changes, and Element X blocks sending until you pick "Withdraw verification and send" **[fetched]**. The number of filled dots carries the meaning without colour.

**Layout.**
- *Rows:* avatar, name, handle in muted mono, and the pill aligned right (icon, word, and 1, 2 or 3 filled dots).
- *Key changed:* those rows sort to the top with a red "Key changed" pill.
- *Adding:* a "+" in the header opens "Paste handle" and "Scan QR". The legend sits behind an ⓘ.
- *Detail screen (Threema-like, [from memory]):* a large avatar, the name and handle, and the pill with a sentence ("Compared in person on 12 Sep"). Then the fingerprint grid and "Vouched by: bob". Actions: **Open chat**, Start live room, Re-verify, Remove (danger).

**Don't copy.** Threema's orange level, which means an address-book match. secure-chat's middle level means vouched, so a directory lookup must never show as trust. Also skip Element's grey "trusted by default" state.

## 7. Async Chats (sealed mailbox, mode negotiation)

**Borrow.** Signal's chat-list row: avatar, name, preview, time and unread badge **[from memory]**. Signal also shows setting changes inline to both sides **[from memory]**. A change that needs consent belongs in the conversation, not in a hidden `<select>`.

**Layout.**
- *Rows:* name with trust mark, preview and time.
- *Empty state:* "No chats yet — chats go to people saved in Users", with **Add someone**.
- *Header:* a `SEALED` chip. Tapping it opens a sheet with two cards and **Propose**. The proposer then sees "You proposed AES-256 · waiting for alice".
- *Recipient:* a sticky bar above the composer, "alice wants to switch to AES-256 (extra passphrase)", with **Accept**, Decline and "What changes?". Either answer is logged inline.
- *Key changed:* Signal requires manual approval before sending in this case **[fetched]**. Here, sending opens a sheet, "alice's key changed. Re-verify before sending", with **Re-verify** and a secondary "Send anyway".

**Don't copy.** Cloud history, "delete for everyone" (a relay that stores nothing can't guarantee it), or notification previews.

## 8. Profile

**Borrow.** Threema's "My ID" screen leads with the ID and QR code and keeps key detail behind a tap **[from memory]**. What you show other people should be the biggest thing on the screen.

**Layout.**
- *Top:* avatar, name, and the handle in mono with Copy.
- *QR:* large and centred; tapping it enlarges it. Under it: "Scanning only fills in your handle. You still compare fingerprints in person."
- *Fingerprint:* a grid of 2 × 4 groups.
- *Keys:* collapsed under "Technical details". Status chips follow.
- *Danger zone at the bottom:* Copy backup, Sign out of directory, and **Forget identity**. Forget requires typing your handle to confirm.

**Don't copy.** Seed words, uploading profile photos, or cloud backup.

## Cross-cutting

- **Short explanations:** one sentence, then "Why?" or "Learn more", like Signal's link under the safety number **[from memory]**.
- **Destructive actions:** the confirmation states the consequence. Typed confirmation is reserved for Forget identity.
- **Encryption indicator:** one per screen (the header chip).

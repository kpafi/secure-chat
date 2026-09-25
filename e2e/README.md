# End-to-end runs

Reproducible two-agent runs of the flows a real pair of users actually go
through. These exist because a live test with a second person surfaced two bugs
that every unit test and single-user harness missed — both about the *second*
user's experience.

## Run it

```bash
cd backend && ./run.sh          # terminal 1
node e2e/two-user-flow.mjs      # terminal 2 — async chat + web of trust
node e2e/room-admission.mjs     #            — live room join approval
node e2e/no-dead-ends.mjs       #            — every failure path says something
node e2e/hostile-relay.mjs      #            — a relay cannot demote the room creator
node e2e/contact-profile.mjs    #            — a saved user's short profile (sheet)
node e2e/all-modes.mjs          #            — all four encryption modes, both directions
node e2e/screenshots.mjs <dir>  #            — every screen at phone + desktop size, for design review
node e2e/durable-crash.mjs      #            — SIGKILL after an OTP send; the pad must not reopen at a spent offset (~2 min)
```

`durable-crash.mjs` (package 3b) is the real-browser half of
`client/durable.test.mjs`: it saves a pad, lets it settle on disk, spends two
messages' worth of pad (each save awaited, as before a send), SIGKILLs the
browser process as soon as the second save returned and unlocks the pad in a new browser on the same
profile. It reports which save `localStorage` actually kept (three runs on
Chromium: the offset-500 blob — the second save never reached disk). Against the
pre-3b client it fails (`{"open":500}` — the pad reopened inside a spent
message); with 3b the IndexedDB record reopens it at 1000.

Needs Node 20+, system Chromium (`/usr/bin/chromium`, override with `$CHROMIUM`)
and `puppeteer-core` resolvable from `e2e/` (`cd e2e && npm install --no-save
puppeteer-core` — it is gitignored, and the tree has shipped with the symlink
pointing at a deleted temp dir before). Point the runs elsewhere with
`SECURE_CHAT_E2E_URL=https://…`.

## Credentials

`test-users.json` holds fixed passphrases so a failing step can be re-driven by
hand in a browser with the same accounts. **They are throwaway test values —
never use them for a real identity.** Usernames get a per-run suffix because the
directory refuses a name already registered to a different identity.

## What `room-admission.mjs` asserts (pentest P-08)

Three real browser peers: the owner, the peer she invited, and a squatter that
knows the code and knocks **first**. It pins the property that fixes P-08 —
waiting costs the room nothing — and the one that makes the approval mean
something: the owner is shown the knocker's **actual key fingerprint** (compared
against that agent's own identity) plus its trust mark, a waiting peer receives
no key exchange and cannot send, the squatter is denied, and the invited peer
still completes the handshake and messages both ways.

## What `hostile-relay.mjs` asserts (pentest 2026-08-07 F-PROTO-001)

The relay is real; the hostility is a document-start `WebSocket` wrapper that
answers the room creator's `join` with `pending`, swallows her knock and seats
her as a guest — the frame sequence that used to pass the M-2 guest-half check
and leave a room with no owner to approve anyone. The creator (whose page
minted the code) must refuse and be told why on the screen she lands on; a
peer who *pasted* the code and gets the identical `pending` must still go
through the honest queue, so the refusal keys on "we minted this code", not
on `pending`; and a fresh code still seats the creator as the owner.

`no-dead-ends.mjs` also drives the one dead end the 2026-09-21 fix review
found: a chat store that refuses to open (one `removeItem`) must show its
error in the Chats view and offer a working *Open anyway* there, while the
Users view, which did not refuse, offers none.

## What `contact-profile.mjs` asserts

Three agents (alice, bob, and carol as a stranger whose mail makes an
automatic contact). The profile sheet opens from a Users row, a Chats row's
avatar and the conversation's name, by pointer and keyboard; it shows bob's
real handle and the fingerprint bob's OWN device shows; it is a real modal
(focus in, Tab wraps, the rest inert, Escape / × / scrim close and give focus
back). The trust actions are pinned hardest: Verify waits for the fingerprint,
refuses when the keys moved under the open sheet, acts once on a double click,
is the primary for a changed key; Unverify is confirm-gated; a vouch the relay
never answers times out instead of blocking every later Verify; a slow
fingerprint never lands on another contact's sheet; a double tap's second half
(reduced motion) neither acts nor closes. Seeded records cover an adopted
claim and malformed stored keys. Dialogs are counted and answered per check
(`page.answers`), so a gate that stops asking fails the run.

## What `two-user-flow.mjs` asserts

1. **Registering is enough to receive.** Async chat only delivers while the
   client holds a directory session, and that used to require finding a "Log in"
   button — so a user could send messages that their contact silently never
   received. The run never clicks that button.
2. **An invite link is usable in the tab it opens.** A new tab shares
   `localStorage` but *not* the in-memory unlocked identity, so it starts locked;
   every locked view now unlocks in place, and the invited handle is prefilled.
3. **Mail from a stranger is delivered**, filed under a key-derived name and
   marked unverified (never a name the sender chose — see pentest F-01).
4. **Replies work in both directions** once the contact is added.
5. **Web of trust**: verifying a contact in person marks them 🟢.

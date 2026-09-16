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
node e2e/all-modes.mjs          #            — a live room in each of the five modes, both ways
```

`all-modes.mjs` also runs against a deployed relay (`SECURE_CHAT_E2E_URL=…`) or
over Tor (`SECURE_CHAT_E2E_PROXY=socks5://127.0.0.1:9050`); see its header.
`hostile-relay/` is the F-PROTO-001 regression test against a relay that lies —
it has its own README.

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

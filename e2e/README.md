# End-to-end runs

Reproducible two-agent runs of the flows a real pair of users actually go
through. These exist because a live test with a second person surfaced two bugs
that every unit test and single-user harness missed — both about the *second*
user's experience.

## Run it

```bash
cd backend && ./run.sh          # terminal 1
node e2e/two-user-flow.mjs      # terminal 2
```

Needs Node 20+, system Chromium (`/usr/bin/chromium`, override with `$CHROMIUM`)
and `puppeteer-core` resolvable from `e2e/`. Point it elsewhere with
`SECURE_CHAT_E2E_URL=https://…`.

## Credentials

`test-users.json` holds fixed passphrases so a failing step can be re-driven by
hand in a browser with the same accounts. **They are throwaway test values —
never use them for a real identity.** Usernames get a per-run suffix because the
directory refuses a name already registered to a different identity.

## What it asserts

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

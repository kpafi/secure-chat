// Key confirmation state machine (pentest 2026-07-27 M-5, hardened 2026-07-29 M-5).
//
// WHY THIS IS ITS OWN MODULE. It used to be a handful of `let`s and two
// functions in app.js, reset from two places and read from a third. That made
// it untestable — app.js needs a DOM — so the 2026-07-29 pentest could only
// model it "line for line" in a harness and note that a real reproduction
// would make the finding airtight. A control nothing can test is a control
// nobody can check, so the logic moved here: pure state, effects injected.
//
// WHAT IT IS FOR. Neither peer can tell a healthy handshake from a wedged one
// on its own: the honest staggered order and a relay that drops both answers
// leave a peer holding indistinguishable local state. The difference is only
// visible when the two sides compare something derived from the chains. So each
// sends HMAC(its own SEND chain, domain-separated context) and requires exactly
// HMAC(its RECV chain, same context) back. Deriving the same tag is proof of
// the same material.
//
// This gates only the UNLOCK step. It is not a substitute for the safety-number
// comparison: confirmation proves you share a key with whoever is at the other
// end, and the in-person check is what proves WHO that is.

// The confirm frame is NOT signature-covered — it is handled before the
// handshake branch precisely because it carries no key material — so the
// original code took the FIRST tag only, to stop a relay trying tag after tag
// until one stuck. Keeping a set for the race (below) must not throw that away,
// so the set is hard-capped at the maximum a legitimate peer can produce: each
// side derives once in the staggered case and twice in the simultaneous-connect
// race (its own offer secret, then the answer), never more — PQKEM is the mode
// that can do it (RSA could too, until it was removed on 2026-08-21,
// F-CRYPTO-009). A third distinct tag is not a peer with bad luck; it is someone
// guessing.
export const MAX_PEER_CONFIRMS = 2;

// Generous: the worst case is a slow phone doing ML-KEM + ML-DSA over Tor, and
// this only has to be shorter than a user's patience. Honest sessions confirm
// in well under a second, the race in one extra round trip.
export const CONFIRM_TIMEOUT_MS = 15000;

/**
 * @param {object} io
 * @param {(tag: string) => void} io.send      put our confirmation tag on the wire
 * @param {(why: string) => void} io.fail      loud teardown; the session is over
 * @param {() => Promise<void>|void} io.finish confirmation succeeded; unlock
 * @param {(msg: string) => void} [io.hint]    progress text for the user
 * @param {typeof setTimeout} [io.setTimer]
 * @param {typeof clearTimeout} [io.clearTimer]
 */
export function makeKeyConfirmation(io) {
  const setTimer = io.setTimer || setTimeout;
  const clearTimer = io.clearTimer || clearTimeout;

  let sentTag = null;        // the `mine` tag we last put on the wire
  let peerTags = new Set();  // every distinct tag this peer has sent
  let done = false;
  let confirmedTag = null;   // our `mine` tag at the moment we confirmed
  let deadline = null;

  function clearDeadline() {
    if (deadline !== null) {
      clearTimer(deadline);
      deadline = null;
    }
  }

  function armDeadline() {
    if (deadline !== null || done) return;
    deadline = setTimer(() => {
      deadline = null;
      if (done) return;
      // A mismatch is no longer an instant teardown — in the race a stale tag
      // is expected and the matching one is still in flight — so the loudness
      // lives here instead. This also covers a case the original code hung on
      // forever: a relay that simply never delivers the peer's confirm frame.
      fail("the other side never proved it derived the same key");
    }, CONFIRM_TIMEOUT_MS);
  }

  function fail(why) {
    clearDeadline();
    io.fail(why);
  }

  return {
    get done() { return done; },
    /** Test/inspection only. */
    get state() {
      return { sentTag, peerTags: [...peerTags], done, confirmedTag, armed: deadline !== null };
    },

    /**
     * Tear the session down for a reason the CALLER detected — currently the
     * app-level gate that refuses handshake material once confirmation is
     * complete. Routed through here so every confirmation failure clears the
     * deadline and reads the same way to the user.
     */
    failNow(why) {
      fail(why);
    },

    reset() {
      clearDeadline();
      sentTag = null;
      peerTags = new Set();
      done = false;
      confirmedTag = null;
    },

    /**
     * The cipher's chains exist (or have just been rebuilt).
     * @param {{mine: string, theirs: string}|null} confirmation
     * @returns {Promise<boolean>} true if the session may proceed to unlock
     */
    async onChains(confirmation) {
      // OTP: nothing was negotiated, so there is nothing to confirm. Finish it
      // here rather than returning "you finish it" — a caller that has to know
      // which of two truthy answers means "already done" is a bug waiting to
      // happen, and double-finishing would unlock the session twice.
      if (!confirmation) {
        await io.finish();
        return true;
      }

      // 2026-07-29 M-5, the attack. `_derive` REPLACES the channel — and so both
      // tags — whenever its input signature changes. A relay that withholds one
      // genuine signed offer and delivers it AFTER confirmation completes
      // therefore swapped the material both sides had just proved they shared:
      // "secure channel established", safety numbers compared, and then nothing
      // works. The chains are final once confirmed.
      if (done) {
        if (confirmation.mine !== confirmedTag) {
          fail("the key exchange changed AFTER both sides had confirmed it");
        }
        return false;
      }

      // (Re)send whenever the chains change, so what the peer checks is always
      // a tag for the material we currently hold.
      if (confirmation.mine !== sentTag) {
        sentTag = confirmation.mine;
        io.send(confirmation.mine);
        if (io.hint) io.hint("Confirming that both sides derived the same key…");
      }
      armDeadline();
      return this._tryFinish(confirmation);
    },

    /**
     * A confirmation tag arrived from the peer.
     * @returns {Promise<boolean>} true if the session may proceed to unlock
     */
    async onPeerTag(tag, confirmation) {
      if (done) {
        // Nothing left to confirm. A tag arriving now is either noise or setup
        // for the post-confirmation re-derivation above; it changes nothing.
        return false;
      }
      // Phase-7 pentest 2026-09-16, F-P7-19. The confirm frame is the one key
      // payload that is NOT signature-covered, and it used to be counted toward
      // the cap even before our chains existed — i.e. before any tag could
      // possibly be checked. A relay that injected two tags ahead of the honest
      // one made the honest peer's tag the third, and BOTH sides then printed
      // that the other side had sent too many confirmations and disconnected.
      // A tag that cannot be matched yet is not evidence of anything; it is
      // ignored. In the shipped flow an honest tag always follows the key frame
      // it belongs to through the same serial pump, so the chains exist by the
      // time it arrives (M-5's derive-twice race sends its stale tag AFTER the
      // first derivation, which is also post-chain on the receiving side).
      if (!confirmation) return false;
      if (!peerTags.has(tag)) {
        if (peerTags.size >= MAX_PEER_CONFIRMS) {
          // Not "the other side": the honest peer sends at most two, so a third
          // distinct tag came from whoever sits between us — the relay.
          fail("more key confirmations arrived than any honest peer can send — the relay is injecting them");
          return false;
        }
        peerTags.add(tag);
      }
      return this._tryFinish(confirmation);
    },

    async _tryFinish(confirmation) {
      if (done || !confirmation || peerTags.size === 0) return false;
      // 2026-07-29 M-5, the race the fix must not break. In a genuine
      // simultaneous connect each side derives twice, so a tag sent after the
      // first derivation is stale by the time the peer sees it. Comparing only
      // the LATEST tag made confirmation always mismatch there and disconnected
      // both honest peers — the race tolerance documented at crypto.js:645
      // stopped being real the moment confirmation was put in front of it.
      //
      // So match against every tag the peer has sent. Each is a signed,
      // identity-pinned claim "I derived this material"; one of them equalling
      // our current recv chain is the proof we want, in any arrival order. Not
      // matching YET is not a failure — that is what the deadline is for.
      if (!peerTags.has(confirmation.theirs)) return false;
      clearDeadline();
      done = true;
      confirmedTag = confirmation.mine;
      await io.finish();
      return true;
    },
  };
}

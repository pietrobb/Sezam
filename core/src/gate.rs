//! May a pull reply be applied, where does the cursor go, and does the state
//! at an unchanged checkpoint still match.
//!
//! Ported from the desktop (`sync_pull.PullMixin.pull`,
//! `sync_state._check_rollback`); the web (`pullWebDelta`) and the phone
//! (`SyncService._pull`) make the same checks.

use serde::{Deserialize, Serialize};

/// What the client stored at its last applied pull (S2: the only pull state).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    /// Cursor: the commit_seq the next delta pull starts after.
    pub seq: i64,
    /// Token of the commit this client saw at its anchor seq, sent as
    /// check_token; the server answers the token it holds for that seq now.
    #[serde(default)]
    pub anchor_token: Option<String>,
    /// State hash of the server-confirmed objects at `seq`.
    #[serde(default)]
    pub state_hash: Option<String>,
    /// State hash of the live objects at `seq` (see [`Candidate`]).
    #[serde(default)]
    pub live_state_hash: Option<String>,
}

/// The parts of a pull reply the gate reads.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyHead {
    /// HTTP 410: the server compacted (tombstone GC) past the cursor. Always
    /// named (review c78fd19): a client that left it out passed the gate.
    pub gone: bool,
    #[serde(default)]
    pub head_commit_seq: Option<i64>,
    #[serde(default)]
    pub check_token: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "gate", rename_all = "snake_case")]
pub enum Gate {
    /// Apply the reply.
    Apply,
    /// Below the GC floor: only an explicitly confirmed full resync goes on.
    FullResyncRequired,
    /// The server's head is behind the checkpoint: restored from a backup.
    HeadBehind { head: i64, checkpoint: i64 },
    /// The server holds another commit under the anchor seq: restored from a
    /// backup and pushed past the checkpoint again (desktop SM7, web SM71).
    Reissued,
    /// A rollback was seen before and not yet accepted: a delta pull would
    /// skip what the server committed again under numbers already passed.
    RollbackPending,
}

/// The gate before a delta pull is applied. A full resync is not gated: the
/// user confirmed taking the server as it is.
pub fn gate(checkpoint: &Checkpoint, reply: &ReplyHead, rollback_pending: bool) -> Gate {
    if reply.gone {
        return Gate::FullResyncRequired;
    }
    if rollback_pending {
        return Gate::RollbackPending;
    }
    if let Some(head) = reply.head_commit_seq {
        if head < checkpoint.seq {
            return Gate::HeadBehind {
                head,
                checkpoint: checkpoint.seq,
            };
        }
    }
    if let Some(anchor) = &checkpoint.anchor_token {
        if !anchor.is_empty() && reply.check_token.as_deref() != Some(anchor.as_str()) {
            return Gate::Reissued;
        }
    }
    Gate::Apply
}

/// The cursor after an applied pull. A first pull (or a full resync) whose
/// newest commits were collected tombstones ends below the GC floor; stored
/// as the cursor, every later pull asked from below the floor and got 410
/// (review a159e97). It continues from the floor: nothing exists between.
/// The cursor never moves back, and the floor never passes the server's head.
pub fn next_cursor(
    last_seq: i64,
    max_commit_seq: i64,
    gc_floor_seq: i64,
    head_commit_seq: Option<i64>,
) -> i64 {
    let floor = head_commit_seq.map_or(gc_floor_seq, |head| gc_floor_seq.min(head));
    let known = if last_seq == 0 {
        max_commit_seq.max(floor)
    } else {
        max_commit_seq
    };
    known.max(last_seq)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum StateCheck {
    Ok,
    /// The reply ends below the stored checkpoint.
    Rollback {
        seq: i64,
        stored: i64,
    },
    /// Same seq, other server-confirmed state: the server changed history.
    Mismatch {
        seq: i64,
    },
}

/// The state a pull reply leads to, as the client computed it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub max_commit_seq: i64,
    /// Hash over every object the client holds (tombstones, keys, audit).
    pub state_hash: String,
    /// Hash over the live objects only. A client that rebuilds its state
    /// from a full pull (the web) sends it: tombstone GC removes rows its
    /// checkpoint covered (review d150605 #4).
    #[serde(default)]
    pub live_state_hash: Option<String>,
    #[serde(default)]
    pub gc_floor_seq: i64,
    /// The reply brought objects the server sent now, not only writes this
    /// client held back and applies again (which change the state here
    /// without a new commit there).
    pub served: bool,
}

/// Compare the state after applying a reply with the stored checkpoint.
pub fn check_state(stored: Option<&Checkpoint>, candidate: &Candidate) -> StateCheck {
    let Some(stored) = stored else {
        return StateCheck::Ok;
    };
    let seq = candidate.max_commit_seq;
    // Writes applied again alone change the state at an unchanged seq here,
    // not there; a lower seq is a rollback whatever the reply brought (the
    // phone's rule, kept).
    if seq > stored.seq || (seq == stored.seq && !candidate.served) {
        return StateCheck::Ok;
    }
    let same = seq == stored.seq
        && stored
            .state_hash
            .as_deref()
            .is_none_or(|hash| hash.is_empty() || hash == candidate.state_hash);
    if same {
        return StateCheck::Ok;
    }
    // Collected tombstones explain a lower seq or another full hash only
    // when every live object is still exactly the one the checkpoint saw:
    // a hidden tombstone cannot bring anything back.
    let gc_explains = candidate.gc_floor_seq > 0
        && (seq == stored.seq || candidate.gc_floor_seq >= stored.seq)
        && stored.live_state_hash.as_deref().is_some_and(|hash| {
            !hash.is_empty() && Some(hash) == candidate.live_state_hash.as_deref()
        });
    if gc_explains {
        StateCheck::Ok
    } else if seq < stored.seq {
        StateCheck::Rollback {
            seq,
            stored: stored.seq,
        }
    } else {
        StateCheck::Mismatch { seq }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cp(seq: i64, token: Option<&str>) -> Checkpoint {
        Checkpoint {
            seq,
            anchor_token: token.map(str::to_string),
            state_hash: Some("h".into()),
            live_state_hash: None,
        }
    }

    fn reply(head: Option<i64>, token: Option<&str>) -> ReplyHead {
        ReplyHead {
            gone: false,
            head_commit_seq: head,
            check_token: token.map(str::to_string),
        }
    }

    #[test]
    fn a_compacted_cursor_needs_a_confirmed_full_resync() {
        let gone = ReplyHead {
            gone: true,
            ..ReplyHead::default()
        };
        assert_eq!(gate(&cp(5, None), &gone, false), Gate::FullResyncRequired);
        // Even with a rollback pending: 410 says more.
        assert_eq!(gate(&cp(5, None), &gone, true), Gate::FullResyncRequired);
    }

    #[test]
    fn a_head_behind_the_checkpoint_is_a_restore() {
        assert_eq!(
            gate(&cp(9, Some("t9")), &reply(Some(4), Some("t9")), false),
            Gate::HeadBehind {
                head: 4,
                checkpoint: 9
            }
        );
    }

    #[test]
    fn another_commit_under_the_anchor_seq_is_a_restore() {
        // SM7 / SM71: the head moved past the checkpoint again.
        assert_eq!(
            gate(&cp(9, Some("t9")), &reply(Some(12), Some("other")), false),
            Gate::Reissued
        );
        assert_eq!(
            gate(&cp(9, Some("t9")), &reply(Some(12), None), false),
            Gate::Reissued
        );
    }

    #[test]
    fn an_unaccepted_rollback_keeps_blocking_delta_pulls() {
        assert_eq!(
            gate(&cp(9, Some("t9")), &reply(Some(12), Some("t9")), true),
            Gate::RollbackPending
        );
    }

    #[test]
    fn a_matching_reply_is_applied() {
        assert_eq!(
            gate(&cp(9, Some("t9")), &reply(Some(12), Some("t9")), false),
            Gate::Apply
        );
        // No anchor yet (first pull): nothing to compare.
        assert_eq!(
            gate(&cp(0, None), &reply(Some(3), None), false),
            Gate::Apply
        );
    }

    #[test]
    fn the_cursor_continues_from_the_gc_floor_on_a_first_pull() {
        assert_eq!(next_cursor(0, 7, 10, None), 10);
        assert_eq!(next_cursor(0, 12, 10, None), 12);
        // A delta pull stays at what it saw.
        assert_eq!(next_cursor(5, 7, 10, None), 7);
        // Never back.
        assert_eq!(next_cursor(9, 7, 0, None), 9);
        // The floor never passes the head.
        assert_eq!(next_cursor(0, 7, 10, Some(8)), 8);
    }

    fn candidate(seq: i64, hash: &str, served: bool) -> Candidate {
        Candidate {
            max_commit_seq: seq,
            state_hash: hash.into(),
            served,
            ..Candidate::default()
        }
    }

    #[test]
    fn the_state_at_an_unchanged_seq_must_match() {
        let stored = cp(9, None);
        let check = |c: Candidate| check_state(Some(&stored), &c);
        assert_eq!(check(candidate(9, "h", true)), StateCheck::Ok);
        assert_eq!(
            check(candidate(9, "x", true)),
            StateCheck::Mismatch { seq: 9 }
        );
        assert_eq!(
            check(candidate(7, "h", true)),
            StateCheck::Rollback { seq: 7, stored: 9 }
        );
        assert_eq!(check(candidate(10, "x", false)), StateCheck::Ok);
        assert_eq!(check(candidate(10, "x", true)), StateCheck::Ok);
        assert_eq!(
            check(candidate(7, "h", false)),
            StateCheck::Rollback { seq: 7, stored: 9 }
        );
    }

    #[test]
    fn writes_applied_again_alone_are_not_a_mismatch() {
        // Only held-back writes re-judged: the state changed here, not there.
        assert_eq!(
            check_state(Some(&cp(9, None)), &candidate(9, "x", false)),
            StateCheck::Ok
        );
        assert_eq!(check_state(None, &candidate(9, "x", true)), StateCheck::Ok);
    }

    #[test]
    fn collected_tombstones_are_excused_only_by_the_same_live_objects() {
        // Review d150605 #4: only a delete happened, then GC took its row.
        let stored = Checkpoint {
            live_state_hash: Some("live".into()),
            ..cp(9, None)
        };
        let after_gc = |seq: i64, live: &str, floor: i64| Candidate {
            live_state_hash: Some(live.into()),
            gc_floor_seq: floor,
            ..candidate(seq, "other", true)
        };
        assert_eq!(
            check_state(Some(&stored), &after_gc(9, "live", 9)),
            StateCheck::Ok
        );
        // The tombstone held the highest seq: the full pull ends lower.
        assert_eq!(
            check_state(Some(&stored), &after_gc(7, "live", 9)),
            StateCheck::Ok
        );
        // Something live differs: a hidden tombstone cannot explain it.
        assert_eq!(
            check_state(Some(&stored), &after_gc(9, "changed", 9)),
            StateCheck::Mismatch { seq: 9 }
        );
        // A floor below the checkpoint explains no lower seq.
        assert_eq!(
            check_state(Some(&stored), &after_gc(7, "live", 8)),
            StateCheck::Rollback { seq: 7, stored: 9 }
        );
        // No floor, no excuse.
        assert_eq!(
            check_state(Some(&stored), &after_gc(9, "live", 0)),
            StateCheck::Mismatch { seq: 9 }
        );
    }
}

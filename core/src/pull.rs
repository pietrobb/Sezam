//! What a pulled object does to a folder or entry with an unsent change, and
//! whether a pull batch is complete enough to apply.
//!
//! The three clients each had a rule of their own: the desktop
//! (`SyncApplyMixin._apply_pulled_object`) kept the change when the server
//! sent its base or an older copy and adopted its own earlier push whose
//! reply was lost; the web (`reconcileWebDirtyState`) dropped a change the
//! server held exactly and kept one on its base; the phone
//! (`applyPullAndCommitCheckpoint`) kept only one on its exact base. This is
//! the one rule, the union of what each got right.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::Version;

/// A folder or entry row with a queued write.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unsent {
    /// The row as it would be sent.
    pub version: i64,
    pub hash: String,
    #[serde(default)]
    pub parent_ref: Option<String>,
    pub is_deleted: bool,
    /// The server version the change was made on (none: never on the server).
    #[serde(default)]
    pub base: Option<Version>,
}

/// A verified object of a pull reply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pulled {
    pub version: i64,
    pub hash: String,
    #[serde(default)]
    pub parent_ref: Option<String>,
    pub is_deleted: bool,
    /// The client checked the object's signature: this account signed this
    /// very version earlier (a push whose reply was lost). Crypto stays with
    /// the client; only the answer comes here. Always named (review c78fd19).
    pub own_earlier_push: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// No unsent change: store the server copy.
    Apply,
    /// The server holds exactly the unsent change (its push landed): store
    /// the copy and drop the queued write.
    Sent,
    /// The copy is the change's base or older: the change builds on it.
    KeepUnsent,
    /// This account's earlier push of the object, whose reply was lost: it
    /// becomes the change's base, the change stays queued.
    AdoptAsBase,
    /// Another write: hold the server copy aside, the user decides.
    Conflict,
}

pub fn decide(unsent: Option<&Unsent>, pulled: &Pulled) -> Decision {
    let Some(unsent) = unsent else {
        return Decision::Apply;
    };
    // A row still at its base is queued for another reason (a re-key batch
    // sends it sealed again at push time): the copy is its base, not its
    // landed push, and dropping it left the batch short ("missing").
    let at_base = unsent
        .base
        .as_ref()
        .is_some_and(|base| base.version == unsent.version && base.hash == unsent.hash);
    if !at_base
        && unsent.version == pulled.version
        && unsent.hash == pulled.hash
        && unsent.parent_ref == pulled.parent_ref
        && unsent.is_deleted == pulled.is_deleted
    {
        return Decision::Sent;
    }
    if let Some(base) = &unsent.base {
        // Stateful test SM56: tombstone GC let another device write the
        // collected version's number again; the same number with another
        // hash is another version, not the base.
        if pulled.version < base.version
            || (pulled.version == base.version && pulled.hash == base.hash)
        {
            return Decision::KeepUnsent;
        }
    }
    if pulled.own_earlier_push && unsent.version >= pulled.version {
        return Decision::AdoptAsBase;
    }
    Decision::Conflict
}

/// The server's copy of an object this client holds (no unsent change: a
/// queued write meets every copy in [`decide`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Held {
    pub version: i64,
    /// What identifies the copy held, compared with the pulled one's (empty:
    /// not known). R17-N1: the whole signed message (type, parent, target,
    /// tombstone flag, payload hash), not the payload alone, so the version
    /// held served with other signed fields is an equivocation.
    pub hash: String,
    pub is_deleted: bool,
    /// The row has a queued write.
    pub queued: bool,
    /// The commit the held copy came with, when known.
    #[serde(default)]
    pub commit_seq: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeldDecision {
    /// Store the pulled copy.
    Apply,
    /// The very copy held: nothing changes (storing it again is harmless).
    Same,
    /// An older version than held: the held copy stays.
    KeepHeld,
    /// Another copy of the version held: the held copy stays, and the client
    /// reports the server for it.
    Equivocation,
}

/// What a pulled copy does to the copy held (review c78fd19: the web and the
/// phone took a folder or entry back to an older version, so a server could
/// serve an old, validly signed password again; the desktop kept its copy).
/// A newer version is stored; so is another copy of the version of a
/// tombstone the server collected below its GC floor (stateful tests SM8,
/// SM21: that version number may then come back), unless a write of it waits
/// here. An older version never is: the floor is unsigned, and a server
/// serving an old, validly signed copy again over a tombstone brought a
/// deleted password back (INV-3, tests/test_inv3_replay_over_tombstone.py).
pub fn against_held(held: Option<&Held>, pulled: &Version, gc_floor_seq: i64) -> HeldDecision {
    let Some(held) = held else {
        return HeldDecision::Apply;
    };
    if pulled.version > held.version {
        return HeldDecision::Apply;
    }
    if pulled.version < held.version {
        return HeldDecision::KeepHeld;
    }
    let collected = held.is_deleted
        && !held.queued
        && held
            .commit_seq
            .is_some_and(|seq| seq > 0 && seq <= gc_floor_seq);
    if collected && pulled.hash != held.hash {
        return HeldDecision::Apply;
    }
    if !pulled.hash.is_empty() && !held.hash.is_empty() && pulled.hash != held.hash {
        return HeldDecision::Equivocation;
    }
    HeldDecision::Same
}

/// A key archive of the batch and the key that replaces it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Archive {
    pub id: String,
    pub replaced_by: String,
}

/// The first archive whose successor key neither the batch nor the client
/// holds. A server that left a re-key's new folder key out of a pull sent
/// its archive and the items sealed under it (review 7c10379): the batch is
/// refused, nothing applied, and the next complete pull brings the key.
pub fn missing_successor<'a>(
    archives: &'a [Archive],
    keys: &HashSet<String>,
) -> Option<&'a Archive> {
    archives.iter().find(|a| !keys.contains(&a.replaced_by))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(version: i64, hash: &str) -> Version {
        Version {
            version,
            hash: hash.into(),
        }
    }

    fn unsent(version: i64, hash: &str, base: Option<Version>) -> Unsent {
        Unsent {
            version,
            hash: hash.into(),
            parent_ref: Some("F".into()),
            is_deleted: false,
            base,
        }
    }

    fn pulled(version: i64, hash: &str) -> Pulled {
        Pulled {
            version,
            hash: hash.into(),
            parent_ref: Some("F".into()),
            is_deleted: false,
            own_earlier_push: false,
        }
    }

    #[test]
    fn without_an_unsent_change_the_copy_is_stored() {
        assert_eq!(decide(None, &pulled(3, "a")), Decision::Apply);
    }

    #[test]
    fn the_unsent_change_itself_is_sent() {
        assert_eq!(
            decide(Some(&unsent(4, "b", Some(v(3, "a")))), &pulled(4, "b")),
            Decision::Sent
        );
        // Moved or deleted differently: not the same object.
        let moved = Pulled {
            parent_ref: Some("G".into()),
            ..pulled(4, "b")
        };
        assert_eq!(
            decide(Some(&unsent(4, "b", Some(v(3, "a")))), &moved),
            Decision::Conflict
        );
    }

    #[test]
    fn the_base_or_an_older_copy_keeps_the_change() {
        let change = unsent(4, "b", Some(v(3, "a")));
        assert_eq!(decide(Some(&change), &pulled(3, "a")), Decision::KeepUnsent);
        // A full pull of a restored server sent an older copy.
        assert_eq!(decide(Some(&change), &pulled(2, "z")), Decision::KeepUnsent);
        // A row queued unchanged on its base (re-key batch, review 8): kept.
        let at_base = unsent(3, "a", Some(v(3, "a")));
        assert_eq!(
            decide(Some(&at_base), &pulled(3, "a")),
            Decision::KeepUnsent
        );
    }

    #[test]
    fn the_same_number_with_other_content_is_a_conflict() {
        // SM56 and stateful seed run 44260509986.
        assert_eq!(
            decide(Some(&unsent(4, "b", Some(v(3, "a")))), &pulled(3, "other")),
            Decision::Conflict
        );
    }

    #[test]
    fn a_newer_copy_is_a_conflict() {
        assert_eq!(
            decide(Some(&unsent(4, "b", Some(v(3, "a")))), &pulled(4, "c")),
            Decision::Conflict
        );
        assert_eq!(
            decide(Some(&unsent(5, "b", Some(v(3, "a")))), &pulled(4, "c")),
            Decision::Conflict
        );
    }

    #[test]
    fn a_change_never_on_the_server_conflicts_with_any_copy() {
        assert_eq!(
            decide(Some(&unsent(1, "b", None)), &pulled(1, "c")),
            Decision::Conflict
        );
    }

    #[test]
    fn an_own_earlier_push_becomes_the_base() {
        // The push landed, its reply was lost, the user edited again.
        let own = Pulled {
            own_earlier_push: true,
            ..pulled(4, "b")
        };
        assert_eq!(
            decide(Some(&unsent(5, "c", Some(v(3, "a")))), &own),
            Decision::AdoptAsBase
        );
        // Not when the server is ahead of this row.
        let ahead = Pulled {
            own_earlier_push: true,
            ..pulled(6, "d")
        };
        assert_eq!(
            decide(Some(&unsent(5, "c", Some(v(3, "a")))), &ahead),
            Decision::Conflict
        );
    }

    fn held(version: i64, hash: &str, is_deleted: bool, commit_seq: Option<i64>) -> Held {
        Held {
            version,
            hash: hash.into(),
            is_deleted,
            queued: false,
            commit_seq,
        }
    }

    #[test]
    fn a_pull_never_takes_a_held_copy_back() {
        let h = held(3, "c", false, Some(9));
        assert_eq!(against_held(None, &v(1, "a"), 0), HeldDecision::Apply);
        assert_eq!(against_held(Some(&h), &v(4, "d"), 0), HeldDecision::Apply);
        assert_eq!(against_held(Some(&h), &v(3, "c"), 0), HeldDecision::Same);
        // An older, validly signed copy served again (review c78fd19).
        assert_eq!(
            against_held(Some(&h), &v(2, "b"), 0),
            HeldDecision::KeepHeld
        );
        assert_eq!(
            against_held(Some(&h), &v(3, "x"), 0),
            HeldDecision::Equivocation
        );
    }

    #[test]
    fn a_collected_tombstone_may_come_back_unless_a_write_waits() {
        // SM8: the server collected the tombstone at seq 5, floor 7.
        let tomb = held(4, "t", true, Some(5));
        assert_eq!(
            against_held(Some(&tomb), &v(4, "x"), 7),
            HeldDecision::Apply
        );
        assert_eq!(against_held(Some(&tomb), &v(4, "t"), 7), HeldDecision::Same);
        // INV-3: an older version is a replay whatever the unsigned floor says.
        assert_eq!(
            against_held(Some(&tomb), &v(2, "b"), 7),
            HeldDecision::KeepHeld
        );
        // Above the floor, or a write of it waits, or the seq is not known.
        assert_eq!(
            against_held(Some(&tomb), &v(4, "x"), 4),
            HeldDecision::Equivocation
        );
        let queued = Held {
            queued: true,
            ..tomb.clone()
        };
        assert_eq!(
            against_held(Some(&queued), &v(4, "x"), 7),
            HeldDecision::Equivocation
        );
        let unknown = held(4, "t", true, None);
        assert_eq!(
            against_held(Some(&unknown), &v(4, "x"), 7),
            HeldDecision::Equivocation
        );
    }

    #[test]
    fn an_archive_without_its_successor_refuses_the_batch() {
        let archives = [
            Archive {
                id: "A1".into(),
                replaced_by: "K1".into(),
            },
            Archive {
                id: "A2".into(),
                replaced_by: "K2".into(),
            },
        ];
        let keys: HashSet<String> = ["K1".to_string()].into();
        assert_eq!(
            missing_successor(&archives, &keys).map(|a| a.id.as_str()),
            Some("A2")
        );
        let all: HashSet<String> = ["K1".to_string(), "K2".to_string()].into();
        assert_eq!(missing_successor(&archives, &all), None);
    }
}

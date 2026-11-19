//! The send side after a re-key: which key an unsent write goes out under,
//! when a folder key the log has replaced may still be opened, and whether a
//! member revoked elsewhere still needs a re-key here (capability review
//! run 365; conformance scenarios client_revokes_member,
//! member_revoked_under_an_unsent_write).
//!
//! A replaced key is opened for one thing only: to seal this account's own
//! unsent ciphertext again under the folder's current key. The log must let
//! the account hold that current key; a revoked account opens nothing.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};

/// The parts of the verified team log these decisions read.
///
/// Ordered maps (review 782dde8): with a hash map, a key a malformed log
/// names in two folders was answered by whichever folder came first in this
/// process, `g2` in one run and `h2` in the next.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Team {
    /// Each folder's keys, oldest generation first; the last is current.
    pub folders: BTreeMap<String, Vec<String>>,
    /// The keys the log lets this account hold.
    #[serde(default)]
    pub may_hold: BTreeSet<String>,
}

/// The log's keys looked up once (review c78fd19: each question walked every
/// folder, so a re-key batch over many folders was quadratic).
pub struct TeamIndex<'a> {
    team: &'a Team,
    /// A replaced key and its folder's current key (the first folder, in
    /// order, that names it replaced).
    replaced: HashMap<&'a str, &'a str>,
    known: HashSet<&'a str>,
    current: HashSet<&'a str>,
}

impl Team {
    pub fn index(&self) -> TeamIndex<'_> {
        let mut index = TeamIndex {
            team: self,
            replaced: HashMap::new(),
            known: HashSet::new(),
            current: HashSet::new(),
        };
        for gens in self.folders.values() {
            let Some(last) = gens.last() else {
                continue;
            };
            index.current.insert(last);
            for (at, key) in gens.iter().enumerate() {
                index.known.insert(key);
                if at + 1 < gens.len() {
                    index.replaced.entry(key).or_insert(last);
                }
            }
        }
        index
    }
}

impl TeamIndex<'_> {
    /// May this account open `key`, a folder key the log has replaced, to
    /// seal its own unsent writes again: only while the log lets it hold the
    /// folder's current key.
    pub fn may_open_superseded(&self, key: &str) -> bool {
        self.replaced
            .get(key)
            .is_some_and(|current| self.team.may_hold.contains(*current))
    }

    /// Whether a member revoked on another device of this account still
    /// holds, by its envelopes here (`keys`), a key that needs a re-key: one
    /// the log does not know, or one that is still some folder's current
    /// key. A key the log has replaced was re-keyed by the other device.
    pub fn rekey_due(&self, keys: &[String]) -> bool {
        keys.iter()
            .any(|key| !self.known.contains(key.as_str()) || self.current.contains(key.as_str()))
    }
}

pub fn may_open_superseded(team: &Team, key: &str) -> bool {
    team.index().may_open_superseded(key)
}

pub fn rekey_due(team: Option<&Team>, keys: &[String]) -> bool {
    match team {
        None => !keys.is_empty(),
        Some(team) => team.index().rekey_due(keys),
    }
}

/// How an unsent write sealed under some key goes out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "send", rename_all = "snake_case")]
pub enum Reseal {
    /// The key is current (or not one anything replaced): send as it is.
    AsIs,
    /// The key was replaced and this device holds the replacement: seal the
    /// write again under `key` first.
    Reseal { key: String },
    /// The key was replaced by `key`, which this device does not hold (or
    /// the log does not let this account hold): the write waits. Review
    /// c78fd19: this answered as "as it is", and the write left under the
    /// retired key a removed member still reads.
    Wait { key: String },
}

/// The key an unsent write sealed under `sealed` goes out under.
///
/// A team folder's replaced key: the folder's current key, if the log lets
/// the account hold it and this device holds it open. Any other key: the end
/// of the chain of signed archives (`successors`, old key to new key), if
/// this device holds it.
pub fn reseal_target(
    team: Option<&TeamIndex>,
    successors: &BTreeMap<String, String>,
    held: &HashSet<String>,
    sealed: &str,
) -> Reseal {
    if let Some(team) = team {
        if let Some(&current) = team.replaced.get(sealed) {
            return if team.team.may_hold.contains(current) && held.contains(current) {
                Reseal::Reseal {
                    key: current.to_string(),
                }
            } else {
                Reseal::Wait {
                    key: current.to_string(),
                }
            };
        }
    }
    let mut seen = HashSet::from([sealed]);
    let mut at = sealed;
    while let Some(next) = successors.get(at) {
        if !seen.insert(next.as_str()) {
            break;
        }
        at = next;
    }
    if at == sealed {
        Reseal::AsIs
    } else if held.contains(at) {
        Reseal::Reseal {
            key: at.to_string(),
        }
    } else {
        Reseal::Wait {
            key: at.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn team(may_hold: &[&str]) -> Team {
        Team {
            folders: BTreeMap::from([
                ("F".into(), vec!["g1".into(), "g2".into(), "g3".into()]),
                ("G".into(), vec!["h1".into()]),
            ]),
            may_hold: may_hold.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn set(keys: &[&str]) -> HashSet<String> {
        keys.iter().map(|s| s.to_string()).collect()
    }

    fn target(
        t: Option<&Team>,
        chain: &BTreeMap<String, String>,
        held: &[&str],
        sealed: &str,
    ) -> Reseal {
        let index = t.map(Team::index);
        reseal_target(index.as_ref(), chain, &set(held), sealed)
    }

    fn reseal(key: &str) -> Reseal {
        Reseal::Reseal { key: key.into() }
    }

    fn wait(key: &str) -> Reseal {
        Reseal::Wait { key: key.into() }
    }

    #[test]
    fn a_member_of_the_current_generation_opens_an_earlier_one() {
        let t = team(&["g3"]);
        assert!(may_open_superseded(&t, "g1"));
        assert!(may_open_superseded(&t, "g2"));
    }

    #[test]
    fn a_revoked_account_opens_no_replaced_key() {
        let t = team(&["g1"]);
        assert!(!may_open_superseded(&t, "g1"));
    }

    #[test]
    fn a_current_or_unknown_key_is_not_superseded() {
        let t = team(&["g3", "h1"]);
        assert!(!may_open_superseded(&t, "g3"));
        assert!(!may_open_superseded(&t, "h1"));
        assert!(!may_open_superseded(&t, "x"));
    }

    #[test]
    fn an_unsent_write_under_a_replaced_key_goes_to_the_current_one() {
        let t = team(&["g3"]);
        let none = BTreeMap::new();
        assert_eq!(target(Some(&t), &none, &["g3"], "g1"), reseal("g3"));
    }

    #[test]
    fn it_waits_when_the_log_refuses_the_current_key() {
        let t = team(&["g1"]);
        let none = BTreeMap::new();
        assert_eq!(target(Some(&t), &none, &["g3"], "g1"), wait("g3"));
    }

    #[test]
    fn it_waits_while_the_current_key_is_not_held() {
        // Review c78fd19: this was the answer of a current key, and the write
        // left under the retired one.
        let t = team(&["g3"]);
        let none = BTreeMap::new();
        assert_eq!(target(Some(&t), &none, &[], "g1"), wait("g3"));
    }

    #[test]
    fn a_write_under_the_current_key_is_sent_as_it_is() {
        let t = team(&["g3"]);
        let none = BTreeMap::new();
        assert_eq!(target(Some(&t), &none, &["g3"], "g3"), Reseal::AsIs);
        assert_eq!(target(Some(&t), &none, &["g3"], "unknown"), Reseal::AsIs);
    }

    #[test]
    fn outside_the_log_the_archive_chain_ends_at_a_held_key() {
        let chain = BTreeMap::from([("a".into(), "b".into()), ("b".into(), "c".into())]);
        assert_eq!(target(None, &chain, &["c"], "a"), reseal("c"));
        assert_eq!(target(None, &chain, &["b"], "a"), wait("c"));
        assert_eq!(target(None, &chain, &["c"], "c"), Reseal::AsIs);
    }

    #[test]
    fn a_looping_archive_chain_ends() {
        let chain = BTreeMap::from([("a".into(), "b".into()), ("b".into(), "a".into())]);
        assert_eq!(target(None, &chain, &["b"], "a"), reseal("b"));
    }

    #[test]
    fn a_key_named_in_two_folders_has_one_answer() {
        // Review 782dde8: g2 in one process, h2 in the next.
        let t = Team {
            folders: BTreeMap::from([
                ("B".into(), vec!["k".into(), "h2".into()]),
                ("A".into(), vec!["k".into(), "g2".into()]),
            ]),
            may_hold: ["g2".to_string(), "h2".to_string()].into(),
        };
        for _ in 0..50 {
            assert_eq!(
                target(Some(&t), &BTreeMap::new(), &["g2", "h2"], "k"),
                reseal("g2")
            );
        }
    }

    #[test]
    fn many_folders_are_indexed_once() {
        let folders: BTreeMap<String, Vec<String>> = (0..40_000)
            .map(|i| (format!("F{i}"), vec![format!("old{i}"), format!("new{i}")]))
            .collect();
        let t = Team {
            may_hold: folders.values().map(|g| g[1].clone()).collect(),
            folders,
        };
        let held: HashSet<String> = t.may_hold.iter().cloned().collect();
        let started = std::time::Instant::now();
        let index = t.index();
        let none = BTreeMap::new();
        for i in 0..40_000 {
            let to = reseal_target(Some(&index), &none, &held, &format!("old{i}"));
            assert_eq!(to, reseal(&format!("new{i}")));
        }
        assert!(
            started.elapsed().as_millis() < 2_000,
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_member_key_replaced_by_the_other_device_needs_no_rekey() {
        let t = team(&["g3"]);
        assert!(!rekey_due(Some(&t), &["g1".into(), "g2".into()]));
        assert!(rekey_due(Some(&t), &["g1".into(), "g3".into()]));
        assert!(rekey_due(Some(&t), &["x".into()]));
        assert!(rekey_due(None, &["g1".into()]));
        assert!(!rekey_due(Some(&t), &[]));
    }
}

//! What a full resync does with the unsent changes it set aside (lockout
//! review M4): created again, written on the version they were made on, or
//! kept as a copy. Ported from the phone (`planUnsentReapply`), with the
//! S1 identity the S4a conformance run brought it to.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::Version;

/// A row of the set-aside changes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetAside {
    pub id: String,
    pub object_type: String,
    #[serde(default)]
    pub parent_ref: Option<String>,
    /// Always named (review c78fd19): left out, a delete was replayed.
    pub is_deleted: bool,
    /// The server version the change was made on (none: never synced, or an
    /// export from before S1).
    #[serde(default)]
    pub base: Option<Version>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    CreateNode,
    CreateEntry,
    /// The live entry is still the version the change was made on.
    UpdateEntry,
    /// The server holds another version since: the change stays on its own
    /// base and the server copy is held aside as a conflict (the state a
    /// pull leaves when it meets one); the user decides.
    UpdateOnItsBase,
    /// The live entry has unsent edits of its own, or the change has no
    /// base: a separate copy, so neither is lost.
    CopyEntry,
    Skip,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    /// Index into the set-aside rows.
    pub index: usize,
    pub action: Action,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The live vault after the resync, as far as the plan goes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Live {
    #[serde(default)]
    pub nodes: HashSet<String>,
    /// Each live entry's server version; null while it has unsent edits of
    /// its own (its content is no longer that version).
    #[serde(default)]
    pub entries: HashMap<String, Option<Version>>,
}

/// Skipped rows as met, then folders parent before child, then entries.
/// Deletes and key or share changes are never replayed: a delete from an old
/// export could remove what other devices added since, and sharing must be
/// redone knowingly.
pub fn plan(rows: &[SetAside], live: &Live) -> Vec<Step> {
    let skip = |index: usize, reason: &str| Step {
        index,
        action: Action::Skip,
        reason: Some(reason.into()),
    };
    let mut steps = Vec::new();
    let mut pending: Vec<usize> = Vec::new();
    let mut entries = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        if row.is_deleted {
            steps.push(skip(index, "delete is not replayed"));
        } else if row.object_type == "node" {
            if live.nodes.contains(&row.id) {
                steps.push(skip(index, "folder already exists"));
            } else {
                pending.push(index);
            }
        } else if row.object_type == "entry" {
            let action = match live.entries.get(&row.id) {
                None => Action::CreateEntry,
                Some(None) => Action::CopyEntry,
                Some(Some(current)) => match &row.base {
                    None => Action::CopyEntry,
                    Some(base) if base == current => Action::UpdateEntry,
                    Some(_) => Action::UpdateOnItsBase,
                },
            };
            entries.push(Step {
                index,
                action,
                reason: None,
            });
        } else {
            steps.push(skip(
                index,
                &format!("{} change is not replayed", row.object_type),
            ));
        }
    }

    // Level by level: the folders whose parent is no pending folder, then
    // their children, each level in row order. One pass per row (review
    // c78fd19: a round over every pending row per level was quadratic).
    let pending_ids: HashSet<&str> = pending.iter().map(|&i| rows[i].id.as_str()).collect();
    let mut children: HashMap<&str, Vec<usize>> = HashMap::new();
    let mut level: Vec<usize> = Vec::new();
    for &i in &pending {
        match rows[i].parent_ref.as_deref() {
            Some(parent) if pending_ids.contains(parent) => {
                children.entry(parent).or_default().push(i)
            }
            _ => level.push(i),
        }
    }
    let mut placed = vec![false; rows.len()];
    while !level.is_empty() {
        let mut next = Vec::new();
        for &i in &level {
            steps.push(Step {
                index: i,
                action: Action::CreateNode,
                reason: None,
            });
            placed[i] = true;
            // Taken out: two rows of one id release their children once.
            next.extend(children.remove(rows[i].id.as_str()).unwrap_or_default());
        }
        next.sort_unstable();
        level = next;
    }
    steps.extend(
        pending
            .into_iter()
            .filter(|&i| !placed[i])
            .map(|i| skip(i, "folder cycle")),
    );
    steps.extend(entries);
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    const V3: fn() -> Version = || Version {
        version: 3,
        hash: "h3".into(),
    };
    const V4: fn() -> Version = || Version {
        version: 4,
        hash: "h4".into(),
    };

    fn row(id: &str, object_type: &str, parent: Option<&str>, base: Option<Version>) -> SetAside {
        SetAside {
            id: id.into(),
            object_type: object_type.into(),
            parent_ref: parent.map(str::to_string),
            is_deleted: false,
            base,
        }
    }

    fn live(entries: &[(&str, Option<Version>)]) -> Live {
        Live {
            nodes: HashSet::new(),
            entries: entries
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        }
    }

    fn actions(steps: &[Step]) -> Vec<Action> {
        steps.iter().map(|s| s.action).collect()
    }

    #[test]
    fn folders_come_before_what_is_inside_them_entries_last() {
        let rows = [
            row("E1", "entry", Some("N2"), None),
            row("N2", "node", Some("N1"), None),
            row("N1", "node", Some("ROOT"), None),
        ];
        let steps = plan(
            &rows,
            &Live {
                nodes: ["ROOT".to_string()].into(),
                ..Live::default()
            },
        );
        let order: Vec<&str> = steps.iter().map(|s| rows[s.index].id.as_str()).collect();
        assert_eq!(order, ["N1", "N2", "E1"]);
        assert_eq!(
            actions(&steps),
            [Action::CreateNode, Action::CreateNode, Action::CreateEntry]
        );
    }

    #[test]
    fn an_edit_overwrites_only_the_version_it_was_made_on() {
        let rows = [
            row("E1", "entry", None, Some(V3())),
            row("E2", "entry", None, Some(V3())),
        ];
        let steps = plan(&rows, &live(&[("E1", Some(V3())), ("E2", Some(V4()))]));
        assert_eq!(
            actions(&steps),
            [Action::UpdateEntry, Action::UpdateOnItsBase]
        );
    }

    #[test]
    fn the_same_number_with_other_content_is_another_version() {
        // Stateful seed run 44260509986.
        let rows = [row("E1", "entry", None, Some(V4()))];
        let other = Version {
            version: 4,
            hash: "other".into(),
        };
        assert_eq!(
            actions(&plan(&rows, &live(&[("E1", Some(other))]))),
            [Action::UpdateOnItsBase]
        );
    }

    #[test]
    fn no_base_or_a_live_unsent_edit_makes_a_copy() {
        let rows = [
            row("E1", "entry", None, Some(V3())),
            row("E2", "entry", None, None),
        ];
        let steps = plan(&rows, &live(&[("E1", None), ("E2", Some(V3()))]));
        assert_eq!(actions(&steps), [Action::CopyEntry, Action::CopyEntry]);
    }

    #[test]
    fn deletes_keys_shares_and_folder_cycles_are_not_replayed() {
        let mut deleted = row("E1", "entry", None, None);
        deleted.is_deleted = true;
        let rows = [
            deleted,
            row("D1", "dek", None, None),
            row("S1", "share", None, None),
            row("N1", "node", Some("N2"), None),
            row("N2", "node", Some("N1"), None),
            row("N3", "node", None, None),
        ];
        let steps = plan(
            &rows,
            &Live {
                nodes: ["N3".to_string()].into(),
                ..Live::default()
            },
        );
        assert_eq!(steps.len(), 6);
        assert!(steps.iter().all(|s| s.action == Action::Skip));
    }

    #[test]
    fn a_deep_chain_is_planned_in_linear_time() {
        // Review c78fd19: one round per level over every pending folder.
        let n = 40_000;
        let rows: Vec<SetAside> = (0..n)
            .map(|i| {
                let parent = format!("N{}", i + 1);
                row(
                    &format!("N{i}"),
                    "node",
                    (i + 1 < n).then_some(parent.as_str()),
                    None,
                )
            })
            .collect();
        let started = std::time::Instant::now();
        let steps = plan(&rows, &Live::default());
        assert!(
            started.elapsed().as_millis() < 500,
            "{:?}",
            started.elapsed()
        );
        assert_eq!(steps.first().map(|s| s.index), Some(n - 1));
        assert_eq!(steps.last().map(|s| s.index), Some(0));
        assert!(steps.iter().all(|s| s.action == Action::CreateNode));
    }
}

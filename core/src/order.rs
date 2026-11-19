//! The order a pull batch is applied in and the order queued audit records
//! are sent in. Both return indices into the input, so a client keeps its
//! own row type.
//!
//! Ported from the desktop (`PullMixin._order_pulled_objects`,
//! `outbox.parents_first`).

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

/// An object of a pull batch, as far as its order goes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PulledRef {
    pub id: String,
    pub object_type: String,
    #[serde(default)]
    pub parent_ref: Option<String>,
}

fn rank(object_type: &str) -> u8 {
    match object_type {
        "dek" => 0,
        "node" => 1,
        "dek_archive" => 2,
        "envelope" => 3,
        "entry" => 4,
        _ => 5,
    }
}

/// Keys first, then folders parent before child, then archives, envelopes,
/// entries and the rest; within a kind, as the server sent them. A delta page
/// may carry a key after its folder or a subfolder before its parent.
pub fn order_pulled(objects: &[PulledRef]) -> Vec<usize> {
    let nodes: HashMap<&str, Option<&str>> = objects
        .iter()
        .filter(|o| o.object_type == "node")
        .map(|o| (o.id.as_str(), o.parent_ref.as_deref()))
        .collect();
    let mut depths: HashMap<&str, usize> = HashMap::new();
    let mut depth = |id: &str| -> usize {
        // Up the batch's own folders; a cycle stops where it closes.
        // A set beside the chain (review c78fd19): `chain.contains` made a
        // chain of 40 000 folders quadratic, 4 s with the GUI frozen.
        let mut chain: Vec<&str> = Vec::new();
        let mut on_chain: HashSet<&str> = HashSet::new();
        let mut current = Some(id);
        while let Some(node) = current {
            let Some((&key, parent)) = nodes.get_key_value(node) else {
                break;
            };
            if depths.contains_key(key) || !on_chain.insert(key) {
                break;
            }
            chain.push(key);
            current = *parent;
        }
        let base = current.and_then(|c| depths.get(c).copied()).unwrap_or(0);
        for (offset, node) in chain.iter().rev().enumerate() {
            depths.insert(node, base + offset + 1);
        }
        depths.get(id).copied().unwrap_or(0)
    };
    let mut keyed: Vec<(u8, usize, usize)> = objects
        .iter()
        .enumerate()
        .map(|(index, o)| {
            let d = if o.object_type == "node" {
                depth(&o.id)
            } else {
                0
            };
            (rank(&o.object_type), d, index)
        })
        .collect();
    keyed.sort();
    keyed.into_iter().map(|(_, _, index)| index).collect()
}

/// A queued audit record, as far as its order goes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRef {
    pub id: String,
    #[serde(default)]
    pub parent_ids: Vec<String>,
}

/// Audit records in queue order, but never one before a queued parent. A
/// clock jump or a record the server lost and that was queued again can put
/// a child ahead of its parent; sent over two requests, a pull between them
/// saw the child without its parent (CI 44293105454). A cycle stays as
/// queued, after the rest.
pub fn parents_first(rows: &[AuditRef]) -> Vec<usize> {
    let position: HashMap<&str, usize> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| (r.id.as_str(), i))
        .collect();
    let mut waiting: Vec<HashSet<usize>> = rows
        .iter()
        .map(|r| {
            r.parent_ids
                .iter()
                .filter_map(|p| position.get(p.as_str()).copied())
                .collect()
        })
        .collect();
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); rows.len()];
    for (child, parents) in waiting.iter().enumerate() {
        for &parent in parents {
            children[parent].push(child);
        }
    }
    let mut ready: BinaryHeap<Reverse<usize>> = (0..rows.len())
        .filter(|&i| waiting[i].is_empty())
        .map(Reverse)
        .collect();
    let mut ordered = Vec::with_capacity(rows.len());
    let mut placed = vec![false; rows.len()];
    while let Some(Reverse(i)) = ready.pop() {
        ordered.push(i);
        placed[i] = true;
        for &child in &children[i] {
            waiting[child].remove(&i);
            if waiting[child].is_empty() {
                ready.push(Reverse(child));
            }
        }
    }
    ordered.extend((0..rows.len()).filter(|&i| !placed[i]));
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(id: &str, object_type: &str, parent: Option<&str>) -> PulledRef {
        PulledRef {
            id: id.into(),
            object_type: object_type.into(),
            parent_ref: parent.map(str::to_string),
        }
    }

    fn ids(objects: &[PulledRef], order: Vec<usize>) -> Vec<String> {
        order.into_iter().map(|i| objects[i].id.clone()).collect()
    }

    #[test]
    fn keys_then_folders_parent_first_then_the_rest() {
        let batch = [
            obj("E1", "entry", Some("N2")),
            obj("N2", "node", Some("N1")),
            obj("A1", "audit", None),
            obj("V1", "envelope", Some("D1")),
            obj("N1", "node", Some("ROOT")),
            obj("X1", "dek_archive", None),
            obj("D1", "dek", Some("N1")),
        ];
        assert_eq!(
            ids(&batch, order_pulled(&batch)),
            ["D1", "N1", "N2", "X1", "V1", "E1", "A1"]
        );
    }

    #[test]
    fn a_folder_cycle_does_not_loop() {
        let batch = [obj("N1", "node", Some("N2")), obj("N2", "node", Some("N1"))];
        assert_eq!(order_pulled(&batch).len(), 2);
    }

    #[test]
    fn same_kind_and_depth_keep_the_server_order() {
        let batch = [
            obj("B", "entry", None),
            obj("A", "entry", None),
            obj("C", "entry", None),
        ];
        assert_eq!(ids(&batch, order_pulled(&batch)), ["B", "A", "C"]);
    }

    /// A chain of `n` folders, deepest first: each one's parent comes later.
    fn deep_chain(n: usize) -> Vec<PulledRef> {
        (0..n)
            .map(|i| {
                let parent = format!("N{}", i + 1);
                obj(
                    &format!("N{i}"),
                    "node",
                    (i + 1 < n).then_some(parent.as_str()),
                )
            })
            .collect()
    }

    #[test]
    fn a_deep_chain_is_ordered_in_linear_time() {
        // Review c78fd19: 40 000 folders took 4.1 s.
        let batch = deep_chain(40_000);
        let started = std::time::Instant::now();
        let order = order_pulled(&batch);
        assert!(
            started.elapsed().as_millis() < 500,
            "{:?}",
            started.elapsed()
        );
        assert_eq!(order.first(), Some(&39_999));
        assert_eq!(order.last(), Some(&0));
    }

    fn rec(id: &str, parents: &[&str]) -> AuditRef {
        AuditRef {
            id: id.into(),
            parent_ids: parents.iter().map(|p| p.to_string()).collect(),
        }
    }

    #[test]
    fn a_record_never_goes_before_a_queued_parent() {
        // CI 44293105454: the child was queued first.
        let rows = [rec("C", &["P"]), rec("X", &[]), rec("P", &["SENT"])];
        let order: Vec<&str> = parents_first(&rows)
            .into_iter()
            .map(|i| rows[i].id.as_str())
            .collect();
        assert_eq!(order, ["X", "P", "C"]);
    }

    #[test]
    fn queue_order_holds_otherwise_and_a_cycle_comes_last() {
        let rows = [
            rec("A", &[]),
            rec("B", &["A"]),
            rec("Y", &["Z"]),
            rec("Z", &["Y"]),
            rec("C", &[]),
        ];
        let order: Vec<&str> = parents_first(&rows)
            .into_iter()
            .map(|i| rows[i].id.as_str())
            .collect();
        assert_eq!(order, ["A", "B", "C", "Y", "Z"]);
    }
}

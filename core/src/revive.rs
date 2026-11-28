//! A folder another device deleted while this device queued work in it
//! comes back (docs/CORE_UNIFICATION.md step U7e; capability review 100,
//! conformance scenario offline_write_under_deleted_folder). Once for the
//! desktop (`_revive_folders_of_unsent`), the page
//! (`reviveFoldersOfUnsentWork`) and the phone (`reviveFoldersOfUnsent`);
//! they open the tombstone, seal the folder again and queue it.
//!
//! One level of folders per call: a folder brought back is queued work in
//! its parent, so the client calls again until none is due (it stops at 64).

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deleted {
    pub id: String,
    /// the tombstone's version
    pub version: i64,
    /// the highest version this device sent of the folder, if it knows one
    #[serde(default)]
    pub sent: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviveIn {
    /// deleted folders as this device holds them, less those it could not
    /// bring back this run
    pub deleted: Vec<Deleted>,
    /// the parent of each queued folder or entry that is not deleted
    pub work_in: Vec<String>,
}

/// The folders due: `[{id, version}]`, by id. A folder comes back above
/// every version this device sent of it too (R16-Z SM18): a revive at a
/// version already on the server (its reply lost) was a second content of
/// it, no longer read as this device's own write, refused on every push.
pub fn revive(i: ReviveIn) -> Value {
    let work: BTreeSet<&str> = i.work_in.iter().map(String::as_str).collect();
    let mut due: BTreeMap<&str, i64> = BTreeMap::new();
    for d in i.deleted.iter().filter(|d| work.contains(d.id.as_str())) {
        let version = d.version.max(d.sent.unwrap_or(0)) + 1;
        let at = due.entry(d.id.as_str()).or_insert(version);
        *at = (*at).max(version);
    }
    json!(due
        .into_iter()
        .map(|(id, version)| json!({"id": id, "version": version}))
        .collect::<Vec<_>>())
}

pub fn run(op: &str, input: &str) -> Option<Result<Value, String>> {
    if op != "revive_folders" {
        return None;
    }
    Some(
        serde_json::from_str(input)
            .map(revive)
            .map_err(|e| format!("bad input: {e}")),
    )
}

//! The one entry point of the bindings: `call(op, input)` with a JSON
//! document in and `{"ok": ...}` or `{"error": "..."}` out. PyO3,
//! wasm-bindgen and flutter_rust_bridge each wrap this single function, so
//! the three clients see the same operations with the same shapes.

use std::collections::{BTreeMap, HashSet};

use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::gate::{self, Candidate, Checkpoint, ReplyHead};
use crate::order::{self, AuditRef, PulledRef};
use crate::pull::{self, Archive, Held, Pulled, Unsent};
use crate::reapply::{self, Live, SetAside};
use crate::reseal::{self, Team};
use crate::Version;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SupersededIn {
    team: Team,
    key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResealIn {
    #[serde(default)]
    team: Option<Team>,
    #[serde(default)]
    successors: BTreeMap<String, String>,
    #[serde(default)]
    held: HashSet<String>,
    keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RekeyDueIn {
    #[serde(default)]
    team: Option<Team>,
    keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GateIn {
    checkpoint: Checkpoint,
    reply: ReplyHead,
    /// Always named (review c78fd19): left out, a pending rollback passed.
    rollback_pending: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorIn {
    last_seq: i64,
    max_commit_seq: i64,
    #[serde(default)]
    gc_floor_seq: i64,
    #[serde(default)]
    head_commit_seq: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateIn {
    #[serde(default)]
    stored: Option<Checkpoint>,
    candidate: Candidate,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PulledIn {
    #[serde(default)]
    unsent: Option<Unsent>,
    pulled: Pulled,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchIn {
    items: Vec<PulledIn>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeldItem {
    held: Option<Held>,
    pulled: Version,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeldIn {
    items: Vec<HeldItem>,
    gc_floor_seq: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuccessorIn {
    archives: Vec<Archive>,
    keys: HashSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OrderIn {
    objects: Vec<PulledRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParentsIn {
    rows: Vec<AuditRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReapplyIn {
    rows: Vec<SetAside>,
    #[serde(default)]
    live: Live,
}

fn run(op: &str, input: &str) -> Result<Value, String> {
    fn parse<T: DeserializeOwned>(input: &str) -> Result<T, String> {
        serde_json::from_str(input).map_err(|e| format!("bad input: {e}"))
    }
    let out = match op {
        "version" => json!(crate::VERSION),
        "gate" => {
            let i: GateIn = parse(input)?;
            json!(gate::gate(&i.checkpoint, &i.reply, i.rollback_pending))
        }
        "next_cursor" => {
            let i: CursorIn = parse(input)?;
            json!(gate::next_cursor(
                i.last_seq,
                i.max_commit_seq,
                i.gc_floor_seq,
                i.head_commit_seq
            ))
        }
        "check_state" => {
            let i: StateIn = parse(input)?;
            json!(gate::check_state(i.stored.as_ref(), &i.candidate))
        }
        "decide_pulled" => {
            let i: PulledIn = parse(input)?;
            json!(pull::decide(i.unsent.as_ref(), &i.pulled))
        }
        "decide_pulled_batch" => {
            let i: BatchIn = parse(input)?;
            json!(i
                .items
                .iter()
                .map(|x| pull::decide(x.unsent.as_ref(), &x.pulled))
                .collect::<Vec<_>>())
        }
        "against_held" => {
            let i: HeldIn = parse(input)?;
            json!(i
                .items
                .iter()
                .map(|x| pull::against_held(x.held.as_ref(), &x.pulled, i.gc_floor_seq))
                .collect::<Vec<_>>())
        }
        "missing_successor" => {
            let i: SuccessorIn = parse(input)?;
            json!(pull::missing_successor(&i.archives, &i.keys))
        }
        "order_pulled" => {
            let i: OrderIn = parse(input)?;
            json!(order::order_pulled(&i.objects))
        }
        "parents_first" => {
            let i: ParentsIn = parse(input)?;
            json!(order::parents_first(&i.rows))
        }
        "plan_reapply" => {
            let i: ReapplyIn = parse(input)?;
            json!(reapply::plan(&i.rows, &i.live))
        }
        "may_open_superseded" => {
            let i: SupersededIn = parse(input)?;
            json!(reseal::may_open_superseded(&i.team, &i.key))
        }
        "reseal_targets" => {
            let i: ResealIn = parse(input)?;
            let index = i.team.as_ref().map(Team::index);
            json!(i
                .keys
                .iter()
                .map(|k| reseal::reseal_target(index.as_ref(), &i.successors, &i.held, k))
                .collect::<Vec<_>>())
        }
        "rekey_due" => {
            let i: RekeyDueIn = parse(input)?;
            json!(reseal::rekey_due(i.team.as_ref(), &i.keys))
        }
        _ => {
            match crate::teamlog::ops::run(op, input)
                .or_else(|| crate::vouchers::run(op, input))
                .or_else(|| crate::authority::run(op, input))
                .or_else(|| crate::formats::run(op, input))
                .or_else(|| crate::messages::run(op, input))
                .or_else(|| crate::audit::run(op, input))
            {
                Some(out) => out?,
                None => return Err(format!("unknown operation {op:?}")),
            }
        }
    };
    Ok(out)
}

/// Run one operation: `{"ok": <result>}` or `{"error": "<why>"}`.
pub fn call(op: &str, input: &str) -> String {
    match run(op, input) {
        Ok(value) => json!({ "ok": value }),
        Err(error) => json!({ "error": error }),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(op: &str, input: Value) -> Value {
        let out: Value = serde_json::from_str(&call(op, &input.to_string())).unwrap();
        assert!(out.get("error").is_none(), "{op}: {out}");
        out["ok"].clone()
    }

    #[test]
    fn every_operation_answers_in_json() {
        assert_eq!(ok("version", json!({})), json!(crate::VERSION));
        assert_eq!(
            ok(
                "gate",
                json!({"checkpoint": {"seq": 9, "anchor_token": "t"}, "reply": {"gone": false, "head_commit_seq": 4, "check_token": "t"}, "rollback_pending": false})
            ),
            json!({"gate": "head_behind", "head": 4, "checkpoint": 9})
        );
        assert_eq!(
            ok(
                "gate",
                json!({"checkpoint": {"seq": 1}, "reply": {"gone": true}, "rollback_pending": false})
            ),
            json!({"gate": "full_resync_required"})
        );
        assert_eq!(
            ok(
                "next_cursor",
                json!({"last_seq": 0, "max_commit_seq": 7, "gc_floor_seq": 10})
            ),
            json!(10)
        );
        assert_eq!(
            ok(
                "check_state",
                json!({"stored": {"seq": 9, "state_hash": "h"}, "candidate": {"max_commit_seq": 9, "state_hash": "x", "served": true}})
            ),
            json!({"state": "mismatch", "seq": 9})
        );
        let unsent = json!({"version": 4, "hash": "b", "is_deleted": false, "base": {"version": 3, "hash": "a"}});
        let pulled = |version: i64, hash: &str| json!({"version": version, "hash": hash, "is_deleted": false, "own_earlier_push": false});
        assert_eq!(
            ok(
                "decide_pulled",
                json!({"unsent": unsent, "pulled": pulled(3, "x")})
            ),
            json!("conflict")
        );
        assert_eq!(
            ok(
                "decide_pulled_batch",
                json!({"items": [{"pulled": pulled(1, "a")}, {"unsent": unsent, "pulled": pulled(3, "a")}]})
            ),
            json!(["apply", "keep_unsent"])
        );
        assert_eq!(
            ok(
                "against_held",
                json!({"gc_floor_seq": 0, "items": [
                    {"held": null, "pulled": {"version": 1, "hash": "a"}},
                    {"held": {"version": 3, "hash": "c", "is_deleted": false, "queued": false}, "pulled": {"version": 2, "hash": "b"}},
                    {"held": {"version": 3, "hash": "c", "is_deleted": false, "queued": false}, "pulled": {"version": 3, "hash": "x"}},
                ]})
            ),
            json!(["apply", "keep_held", "equivocation"])
        );
        assert_eq!(
            ok(
                "missing_successor",
                json!({"archives": [{"id": "A", "replaced_by": "K"}], "keys": []})
            ),
            json!({"id": "A", "replaced_by": "K"})
        );
        assert_eq!(
            ok(
                "order_pulled",
                json!({"objects": [{"id": "E", "object_type": "entry"}, {"id": "D", "object_type": "dek"}]})
            ),
            json!([1, 0])
        );
        assert_eq!(
            ok(
                "parents_first",
                json!({"rows": [{"id": "C", "parent_ids": ["P"]}, {"id": "P"}]})
            ),
            json!([1, 0])
        );
        assert_eq!(
            ok(
                "plan_reapply",
                json!({"rows": [{"id": "E", "object_type": "entry", "is_deleted": false, "base": {"version": 3, "hash": "a"}}],
                                      "live": {"entries": {"E": {"version": 3, "hash": "b"}}}})
            ),
            json!([{"index": 0, "action": "update_on_its_base"}])
        );
        assert_eq!(
            ok(
                "reseal_targets",
                json!({"team": {"folders": {"F": ["g1", "g2"]}, "may_hold": ["g2"]}, "held": [], "keys": ["g1", "g2"]})
            ),
            json!([{"send": "wait", "key": "g2"}, {"send": "as_is"}])
        );
    }

    #[test]
    fn bad_input_and_unknown_operations_are_errors_not_panics() {
        let out: Value = serde_json::from_str(&call("gate", "{")).unwrap();
        assert!(out["error"].as_str().unwrap().starts_with("bad input"));
        let out: Value = serde_json::from_str(&call("nope", "{}")).unwrap();
        assert!(out["error"].as_str().unwrap().contains("unknown operation"));
    }

    fn refused(op: &str, input: Value) -> String {
        let out: Value = serde_json::from_str(&call(op, &input.to_string())).unwrap();
        out["error"]
            .as_str()
            .unwrap_or_else(|| panic!("{op} took {input}"))
            .to_string()
    }

    #[test]
    fn an_unknown_field_is_refused_not_ignored() {
        // Review 782dde8 [REPRO]: a misspelt field was dropped, the safe
        // default stood in, and the answer was "apply".
        let error = refused(
            "decide_pulled",
            json!({"pulled": {"version": 1, "hash": "a", "is_deleted": false, "own_earlier_push": false, "own_erlier_push": true}}),
        );
        assert!(error.contains("unknown field"), "{error}");
        let error = refused(
            "gate",
            json!({"checkpoint": {"seq": 1}, "reply": {"gone": false}, "rollback_pending": false, "rollback": true}),
        );
        assert!(error.contains("unknown field"), "{error}");
    }

    #[test]
    fn a_security_field_left_out_is_refused() {
        // Review c78fd19: each defaulted to false, the permissive answer.
        for (op, input) in [
            (
                "gate",
                json!({"checkpoint": {"seq": 1}, "reply": {}, "rollback_pending": false}),
            ),
            (
                "gate",
                json!({"checkpoint": {"seq": 1}, "reply": {"gone": true}}),
            ),
            (
                "decide_pulled",
                json!({"pulled": {"version": 1, "hash": "a", "is_deleted": false}}),
            ),
            (
                "decide_pulled",
                json!({"pulled": {"version": 1, "hash": "a", "own_earlier_push": false}}),
            ),
            (
                "plan_reapply",
                json!({"rows": [{"id": "E", "object_type": "entry"}]}),
            ),
            ("against_held", json!({"items": []})),
        ] {
            let error = refused(op, input);
            assert!(error.contains("missing field"), "{op}: {error}");
        }
    }
}

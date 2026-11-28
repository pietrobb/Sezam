//! The push rule (design §4.3.4-6) in the core: the log's verdict on one
//! folder or item about to be sent (web, phone, desktop) or taken (server),
//! before it was composed four times (assertTeamLogAllowsWrite, teamLogVerdict,
//! sync.py _team_log_refusal; docs/CORE_UNIFICATION.md U5). Team 1 of
//! tests/vectors/authority.json: folder F1 under key D1, W may write there, R
//! only read (team 0: F1 waits for a re-key).

use serde_json::{json, Value};

const W: &str = "01JM0000000000000000000002";
const R: &str = "01JM0000000000000000000003";
const F1: &str = "01JF0000000000000000000001";
const D1: &str = "01JD0000000000000000000001";
const SUB: &str = "01JNODE0000000000000000001";
const TOP: &str = "01JNODE0000000000000000002";
const ITEM: &str = "01JENTRY000000000000000001";
const OWN_KEY: &str = "01JPDEK0000000000000000001";

fn team_at(i: usize) -> Value {
    let v: Value =
        serde_json::from_str(include_str!("../../tests/vectors/authority.json")).unwrap();
    v["teams"][i].clone()
}

fn team() -> Value {
    team_at(1)
}

fn call(op: &str, input: Value) -> Value {
    let out: Value =
        serde_json::from_str(&sezam_sync_core::json::call(op, &input.to_string())).unwrap();
    assert!(out.get("error").is_none(), "{out}");
    out["ok"].clone()
}

fn item(parent: &str, signer: &str, dek_id: Option<&str>, deleted: bool) -> Value {
    json!({"id": ITEM, "object_type": "entry", "parent_ref": parent, "signer": signer,
           "dek_id": dek_id, "is_deleted": deleted})
}

fn key(id: &str, signer: &str) -> Value {
    json!({"id": id, "object_type": "dek", "parent_ref": null, "signer": signer})
}

/// The tree: SUB below team folder F1, TOP outside every team folder.
fn tree() -> Vec<Value> {
    vec![
        json!({"id": F1, "object_type": "node", "parent_ref": null}),
        json!({"id": SUB, "object_type": "node", "parent_ref": F1}),
        json!({"id": TOP, "object_type": "node", "parent_ref": null}),
    ]
}

fn verdict(object: Value, more: Vec<Value>) -> (bool, Value) {
    let mut objects = tree();
    objects.extend(more);
    let out = call(
        "authority_write_refusal",
        json!({"writes": [object], "objects": objects, "team": team()}),
    )[0]
    .clone();
    (out["decided"].as_bool().unwrap(), out["refusal"].clone())
}

const NO_WRITE: &str = "team log gives no write access here";
const UNKNOWN_KEY: &str = "sealed with a key the team log does not know";

#[test]
fn below_a_team_folder_its_key_and_write_access_decide() {
    assert_eq!(
        verdict(item(SUB, W, Some(D1), false), vec![]),
        (true, Value::Null)
    );
    assert_eq!(
        verdict(item(SUB, R, Some(D1), false), vec![]),
        (true, json!(NO_WRITE))
    );
}

#[test]
fn a_push_into_a_folder_that_waits_for_a_re_key_is_refused() {
    let out = call(
        "authority_write_refusal",
        json!({"writes": [item(SUB, W, Some(D1), false)], "objects": tree(), "team": team_at(0)}),
    )[0]
    .clone();
    assert_eq!(out["refusal"], json!("folder waits for a re-key"));
}

#[test]
fn a_key_outside_the_log_is_only_the_authors_own_one() {
    let own = vec![key(OWN_KEY, W)];
    assert_eq!(
        verdict(item(SUB, W, Some(OWN_KEY), false), own.clone()),
        (true, Value::Null)
    );
    assert_eq!(
        verdict(item(SUB, R, Some(OWN_KEY), false), own),
        (true, json!(UNKNOWN_KEY))
    );
    // Not among the keys at all.
    assert_eq!(
        verdict(item(SUB, W, Some(OWN_KEY), false), vec![]),
        (true, json!(UNKNOWN_KEY))
    );
}

#[test]
fn outside_every_team_folder_under_a_key_it_does_not_know_the_log_has_no_say() {
    assert_eq!(
        verdict(item(TOP, R, Some(OWN_KEY), false), vec![]),
        (false, Value::Null)
    );
    // A team key decides even there.
    assert!(verdict(item(TOP, R, Some(D1), false), vec![]).0);
}

#[test]
fn a_removal_needs_write_access_where_it_was() {
    let held = vec![item(SUB, W, Some(D1), false)];
    assert_eq!(
        verdict(item(SUB, R, None, true), held.clone()),
        (true, json!(NO_WRITE))
    );
    assert_eq!(verdict(item(SUB, W, None, true), held), (true, Value::Null));
}

#[test]
fn moving_out_of_a_team_folder_needs_write_there_unless_it_is_ones_own() {
    let held = vec![item(SUB, R, Some(D1), false)];
    assert_eq!(
        verdict(item(TOP, R, Some(D1), false), held),
        (true, json!(NO_WRITE))
    );
    // TL7: one's own personal object (its own key, before and now) may leave.
    let own = vec![item(SUB, R, Some(OWN_KEY), false), key(OWN_KEY, R)];
    assert_eq!(
        verdict(item(TOP, R, Some(OWN_KEY), false), own),
        (false, Value::Null)
    );
}

#[test]
fn moving_out_someone_elses_personal_object_is_refused_on_push() {
    // The server's rule (review c78fd19): the key must be the author's.
    let theirs = vec![item(SUB, W, Some(OWN_KEY), false), key(OWN_KEY, W)];
    assert_eq!(
        verdict(item(TOP, R, Some(OWN_KEY), false), theirs),
        (true, json!(NO_WRITE))
    );
}

#[test]
fn a_tombstone_that_moves_out_moves_as_a_live_write_on_push() {
    // Review c78fd19 (#1): sealed with W's own key, R still may not take it out.
    let theirs = vec![item(SUB, W, Some(OWN_KEY), false), key(OWN_KEY, W)];
    assert_eq!(
        verdict(item(TOP, R, None, true), theirs),
        (true, json!(NO_WRITE))
    );
    let own = vec![item(SUB, R, Some(OWN_KEY), false), key(OWN_KEY, R)];
    assert_eq!(verdict(item(TOP, R, None, true), own), (true, Value::Null));
}

#[test]
fn a_pulled_copy_is_judged_as_unauthorized_writes_judges_it() {
    let pulled = |object: Value, more: Vec<Value>, team: Value| {
        let mut objects = tree();
        objects.extend(more);
        call(
            "authority_write_refusal",
            json!({"writes": [object], "objects": objects, "team": team, "sealing": false}),
        )[0]["refusal"]
            .clone()
    };
    // Written before the folder waited for a re-key.
    assert_eq!(
        pulled(item(SUB, W, Some(D1), false), vec![], team_at(0)),
        Value::Null
    );
    let theirs = vec![item(SUB, W, Some(OWN_KEY), false), key(OWN_KEY, W)];
    assert_eq!(
        pulled(item(TOP, R, Some(OWN_KEY), false), theirs, team()),
        Value::Null
    );
}

#[test]
fn the_team_folder_above_a_node() {
    let parents = json!({SUB: F1, F1: null, TOP: null});
    let above = |node: Value| {
        call(
            "authority_team_folder_above",
            json!({"node_id": node, "parents": parents, "team": team()}),
        )
    };
    assert_eq!(above(json!(SUB)), json!(F1));
    assert_eq!(above(json!(F1)), json!(F1));
    assert_eq!(above(json!(TOP)), Value::Null);
    assert_eq!(above(Value::Null), Value::Null);
}

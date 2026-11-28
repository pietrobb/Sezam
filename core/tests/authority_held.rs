//! Review a159e97 H2 in the core: a pulled folder or item below a folder this
//! device does not know is held back unless this account or one it vouches
//! for wrote it. The answers are the desktop's `held_back` before the switch
//! (src/sezam/vault/sync_writers.py at fa0c02f, docs/CORE_UNIFICATION.md U5).

use serde_json::{json, Value};

const OWN: &str = "01JM0000000000000000000001";
const FRIEND: &str = "01JM0000000000000000000002";
const STRANGER: &str = "01JM0000000000000000000003";
const MISSING: &str = "01JMISSING0000000000000001";
const SUB: &str = "01JNODE0000000000000000001";
const ITEM: &str = "01JENTRY000000000000000001";
const KNOWN: &str = "01JNODE0000000000000000009";

fn node(id: &str, parent: &str, signer: &str) -> Value {
    json!({"id": id, "object_type": "node", "parent_ref": parent, "signer": signer})
}

fn entry(id: &str, parent: &str, signer: &str) -> Value {
    json!({"id": id, "object_type": "entry", "parent_ref": parent, "signer": signer})
}

fn writes(objects: Value, context: Value) -> Value {
    let input = json!({"objects": objects, "own_user_id": OWN, "context": context});
    let out: Value = serde_json::from_str(&sezam_sync_core::json::call(
        "authority_unauthorized_writes",
        &input.to_string(),
    ))
    .unwrap();
    assert!(out.get("error").is_none(), "{out}");
    out["ok"].clone()
}

fn held(objects: Value, context: Value) -> Value {
    writes(objects, context)["held"].clone()
}

#[test]
fn a_stranger_below_an_unknown_folder_is_held_and_what_is_below_it() {
    let out = writes(
        json!([node(SUB, MISSING, STRANGER), entry(ITEM, SUB, STRANGER)]),
        json!({"vouched": []}),
    );
    assert_eq!(out["held"], json!([SUB, ITEM]));
    assert_eq!(out["blocked"], json!([]));
}

#[test]
fn the_order_of_the_batch_does_not_matter() {
    let objects = json!([entry(ITEM, SUB, OWN), node(SUB, MISSING, STRANGER)]);
    assert_eq!(held(objects, json!({"vouched": []})), json!([ITEM, SUB]));
}

#[test]
fn this_account_and_one_vouched_for_are_not_held() {
    let objects = json!([node(SUB, MISSING, OWN)]);
    assert_eq!(held(objects, json!({"vouched": []})), json!([]));
    let objects = json!([node(SUB, MISSING, FRIEND)]);
    assert_eq!(held(objects, json!({"vouched": [FRIEND]})), json!([]));
}

#[test]
fn a_folder_known_here_holds_nothing() {
    let known = json!([{"id": KNOWN, "object_type": "node", "parent_ref": null}]);
    let objects = json!([node(SUB, KNOWN, STRANGER)]);
    assert_eq!(
        held(objects, json!({"vouched": [], "known_nodes": known})),
        json!([])
    );
}

#[test]
fn below_a_held_folder_even_a_vouched_write_is_held() {
    let objects = json!([node(SUB, MISSING, STRANGER), entry(ITEM, SUB, FRIEND)]);
    assert_eq!(
        held(objects, json!({"vouched": [FRIEND]})),
        json!([SUB, ITEM])
    );
}

#[test]
fn below_one_refused_before_it_is_blocked_not_held() {
    let out = writes(
        json!([node(SUB, MISSING, STRANGER)]),
        json!({"vouched": [], "refused": [MISSING]}),
    );
    assert_eq!(out["held"], json!([]));
    assert_eq!(out["blocked"], json!([SUB]));
}

#[test]
fn without_a_vouched_list_web_and_phone_hold_nothing() {
    let objects = json!([node(SUB, MISSING, STRANGER), entry(ITEM, SUB, STRANGER)]);
    assert_eq!(held(objects, json!({})), json!([]));
}

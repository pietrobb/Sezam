//! tests/vectors/audit.json in the core: the audit record's signed bytes, its
//! sync payload, the pull-side parse and the DAG check
//! (docs/CORE_UNIFICATION.md U6d).

use serde_json::{json, Value};

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/vectors/audit.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn call(op: &str, input: &Value) -> Value {
    serde_json::from_str(&sezam_sync_core::json::call(op, &input.to_string())).unwrap()
}

fn hex(text: &str) -> String {
    text.bytes().map(|b| format!("{b:02x}")).collect()
}

fn parse_input(case: &Value) -> Value {
    json!({
        "id": case["id"],
        "version": case["version"],
        "is_deleted": case.get("is_deleted").cloned().unwrap_or(json!(false)),
        "payload": hex(case["payload"].as_str().unwrap()),
    })
}

#[test]
fn the_signed_bytes_match() {
    let v = vectors();
    for case in v["message"].as_array().unwrap() {
        assert_eq!(call("audit_message", case)["ok"], case["message"], "{case}");
    }
    let cross: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/vectors/cross_client.json"
        ))
        .unwrap(),
    )
    .unwrap();
    for c in cross["audit_canonical"].as_array().unwrap() {
        let input = json!({
            "id": c["id"], "actor_id": c["actor_id"], "parent_ids": c["parent_ids"],
            "action": c["action"], "timestamp": c["timestamp"],
            "encrypted_details": c["encrypted_details_hex"],
        });
        assert_eq!(call("audit_message", &input)["ok"], c["message_hex"], "{c}");
    }
}

#[test]
fn the_payload_matches() {
    for case in vectors()["payload"].as_array().unwrap() {
        assert_eq!(call("audit_payload", case)["ok"], case["payload"], "{case}");
    }
}

#[test]
fn a_pulled_record_parses_as_the_desktop_parsed_it() {
    for case in vectors()["parse"].as_array().unwrap() {
        let out = &call("audit_parse", &parse_input(case))["ok"];
        for field in [
            "actor_id",
            "action",
            "timestamp",
            "parent_ids",
            "parent_ids_json",
            "encrypted_details",
            "signature",
            "message",
        ] {
            assert_eq!(out[field], case[field], "{field} {case}");
        }
    }
}

#[test]
fn a_bad_record_is_refused() {
    let cases = vectors()["parse_refused"].as_array().unwrap().clone();
    assert_eq!(cases.len(), 30);
    for case in &cases {
        let out = call("audit_parse", &parse_input(case));
        assert!(out.get("error").is_some(), "{} {out}", case["why"]);
    }
}

#[test]
fn the_dag_check_matches() {
    for case in vectors()["dag"].as_array().unwrap() {
        let out = call("audit_dag", case);
        assert_eq!(
            out.get("error").is_none(),
            case["ok"] == true,
            "{case} {out}"
        );
    }
}

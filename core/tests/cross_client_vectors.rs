//! tests/vectors/cross_client.json in the core: the signed messages and
//! formats every client builds through it (docs/CORE_UNIFICATION.md U6).

use serde_json::{json, Value};

fn vectors() -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/vectors/cross_client.json"
        ))
        .unwrap(),
    )
    .unwrap()
}

fn call(op: &str, input: &Value) -> Value {
    serde_json::from_str(&sezam_sync_core::json::call(op, &input.to_string())).unwrap()
}

#[test]
fn sync_signature_messages() {
    let cases = vectors()["sync_signature"].as_array().unwrap().clone();
    assert!(!cases.is_empty());
    for case in cases {
        let object = json!({
            "id": case["id"], "object_type": case["object_type"],
            "parent_ref": case["parent_ref"], "target_user_id": case["target_user_id"],
            "is_deleted": case["is_deleted"], "version": case["version"],
            "payload_hash": case["payload_hash"],
        });
        let out = call("key_voucher_signed_message", &json!({"object": object}));
        assert_eq!(out["ok"], case["message_hex"], "{}", case["id"]);
    }
}

#[test]
fn a_field_the_message_cannot_hold_is_refused() {
    let base = json!({"id": "01JOBJ0000000000000000000B", "object_type": "entry",
        "is_deleted": 0, "version": 1, "payload_hash": "00".repeat(32)});
    for (field, value) in [
        ("id", json!("01JOBJ0000000000000000000BX")),
        ("parent_ref", json!("a\u{10d}")),
        ("is_deleted", json!(2)),
        ("version", json!(4_294_967_296u64)),
        ("version", Value::Null),
        ("payload_hash", json!("00")),
    ] {
        let mut object = base.clone();
        object[field] = value;
        assert!(
            call("key_voucher_signed_message", &json!({"object": object}))
                .get("error")
                .is_some(),
            "{field}"
        );
    }
}

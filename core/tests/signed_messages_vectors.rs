//! tests/vectors/signed_messages.json in the core: the login, key rotation,
//! reseed/rejoin and org-recovery rewrap messages every side signs or
//! verifies through it (docs/CORE_UNIFICATION.md U6c).

use serde_json::{json, Value};

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/vectors/signed_messages.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn call(op: &str, input: &Value) -> Value {
    serde_json::from_str(&sezam_sync_core::json::call(op, &input.to_string())).unwrap()
}

fn without_message(case: &Value) -> Value {
    let mut input = case.clone();
    input.as_object_mut().unwrap().remove("message");
    input
}

fn check(op: &str, section: &str) -> usize {
    let cases = vectors()[section].as_array().unwrap().clone();
    for case in &cases {
        let out = call(op, &without_message(case));
        assert_eq!(out["ok"], case["message"], "{op} {case}");
    }
    cases.len()
}

#[test]
fn every_message_matches_the_vectors() {
    assert_eq!(check("auth_challenge_message", "auth_challenge"), 8);
    assert_eq!(check("key_rotation_message", "key_rotation"), 5);
    assert_eq!(check("reseed_message", "reseed"), 15);
    assert_eq!(
        check("org_recovery_rewrap_message", "org_recovery_rewrap"),
        15
    );
}

#[test]
fn the_cross_client_key_rotation_vector_holds() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/vectors/cross_client.json"
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let r = &v["key_rotation"];
    let out = call(
        "key_rotation_message",
        &json!({
            "user_id": r["user_id"],
            "old_signing_pk": r["old_signing_pk_hex"],
            "old_encryption_pk": r["old_encryption_pk_hex"],
            "new_signing_pk": r["new_signing_pk_hex"],
            "new_encryption_pk": r["new_encryption_pk_hex"],
        }),
    );
    assert_eq!(out["ok"], r["message_hex"], "{r}");
}

#[test]
fn what_a_message_cannot_hold_is_refused() {
    let v = vectors();
    for case in v["auth_challenge_refused"].as_array().unwrap() {
        assert!(
            call("auth_challenge_message", case).get("error").is_some(),
            "{case}"
        );
    }
    let base = without_message(&v["key_rotation"][0]);
    for case in v["key_rotation_refused"].as_array().unwrap() {
        let mut input = base.clone();
        if case.get("short_key").is_some() {
            input["old_signing_pk"] = json!("00".repeat(31));
        } else {
            input["user_id"] = case["user_id"].clone();
        }
        assert!(
            call("key_rotation_message", &input).get("error").is_some(),
            "{case}"
        );
    }
    let base = without_message(&v["org_recovery_rewrap"][1]);
    for case in v["org_recovery_rewrap_refused"].as_array().unwrap() {
        let mut input = base.clone();
        for (k, val) in case.as_object().unwrap() {
            input[k] = val.clone();
        }
        assert!(
            call("org_recovery_rewrap_message", &input)
                .get("error")
                .is_some(),
            "{case}"
        );
    }
    let mut long = without_message(&v["reseed"][0]);
    long["username"] = json!("x".repeat(65_536));
    assert!(call("reseed_message", &long).get("error").is_some());
    long["username"] = json!("alice");
    long["user_id"] = json!("A".repeat(27));
    assert!(call("reseed_message", &long).get("error").is_some());
}

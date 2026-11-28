//! The shared key ring vectors (tests/vectors/key_ring.json, capability
//! review 716) through the core's one entry point.
//!
//! Signatures are the clients' (libsodium): here a refused response must be
//! refused before any check, and with no check verified only the current key
//! is trusted. tests/test_key_ring_vectors.py (desktop and web) and
//! mobile/test/key_ring_vectors_test.dart run every case with real
//! verification.

use std::path::PathBuf;

use serde_json::{json, Value};

fn vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/vectors/key_ring.json");
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn call(op: &str, input: Value) -> Result<Value, String> {
    let out: Value =
        serde_json::from_str(&sezam_sync_core::json::call(op, &input.to_string())).unwrap();
    match out.get("error") {
        Some(e) => Err(e.as_str().unwrap().to_string()),
        None => Ok(out["ok"].clone()),
    }
}

fn args(v: &Value, c: &Value) -> Value {
    let mut out = json!({
        "user_id": v["user_id"],
        "current_signing_pk": v["current"]["signing_pk"],
        "current_encryption_pk": v["current"]["encryption_pk"],
    });
    if let Some(served) = c.get("archived_keys") {
        out["archived_keys"] = served.clone();
    }
    out
}

#[test]
fn a_malformed_response_is_refused_whole_and_the_rest_name_their_checks() {
    let v = vectors();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 30);
    for c in cases {
        let checks = call("key_ring_checks", args(&v, c));
        if c["trusted"] == "error" {
            assert!(checks.is_err(), "{}", c["name"]);
            assert!(call("key_ring", json!({"verified": []})).is_err());
            continue;
        }
        let checks = checks.unwrap_or_else(|e| panic!("{}: {e}", c["name"]));
        let n = checks.as_array().unwrap().len();
        let mut input = args(&v, c);
        input["verified"] = json!(vec![false; n]);
        assert_eq!(
            call("key_ring", input).unwrap(),
            json!([v["current"]]),
            "{}",
            c["name"]
        );
    }
}

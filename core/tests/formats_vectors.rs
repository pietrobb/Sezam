//! Formats without secrets in the core (docs/CORE_UNIFICATION.md U6): AAD
//! (cross_client.json), padded_size (padding.json), normalize_username and
//! split_for_push (formats.json, the desktop's answers before they moved).

use serde_json::{json, Value};

fn vectors(name: &str) -> Value {
    let path = format!("{}/../tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn call(op: &str, input: &Value) -> Value {
    serde_json::from_str(&sezam_sync_core::json::call(op, &input.to_string())).unwrap()
}

#[test]
fn aad() {
    let cases = vectors("cross_client.json")["aad"]
        .as_array()
        .unwrap()
        .clone();
    assert!(!cases.is_empty());
    for case in cases {
        let out = call("aad", &case);
        assert_eq!(out["ok"], case["aad_hex"], "{case}");
    }
    for case in vectors("formats.json")["aad_refused"].as_array().unwrap() {
        assert!(call("aad", case).get("error").is_some(), "{case}");
    }
    // A receiver binds the header it read, an unsupported alg too.
    let out = call(
        "aad",
        &json!({"alg": 2, "schema_version": 3, "blob_kind": 4, "dek_id": "D", "object_id": "O", "version": 5}),
    );
    let hex = out["ok"].as_str().unwrap();
    assert_eq!(&hex[..6], "020304");
    assert_eq!(&hex[hex.len() - 8..], "00000005");
}

#[test]
fn padded_size() {
    let cases = vectors("padding.json")["padded_size"]
        .as_array()
        .unwrap()
        .clone();
    assert!(cases.len() > 10);
    for case in cases {
        assert_eq!(
            call("padded_size", &json!({"n": case[0]}))["ok"],
            case[1],
            "{case}"
        );
    }
}

#[test]
fn normalize_username() {
    let cases = vectors("formats.json")["normalize_username"]
        .as_array()
        .unwrap()
        .clone();
    assert!(cases.len() > 100);
    for case in cases {
        let out = call("normalize_username", &json!({"value": case[0]}));
        assert_eq!(out["ok"], case[1], "{case}");
    }
}

#[test]
fn split_for_push() {
    let cases = vectors("formats.json")["split_for_push"]
        .as_array()
        .unwrap()
        .clone();
    assert!(cases.len() > 10);
    for case in cases {
        let out = call("split_for_push", &json!({"sizes": case[0]}));
        assert_eq!(out["ok"], case[1], "{}", case[0].as_array().unwrap().len());
    }
}

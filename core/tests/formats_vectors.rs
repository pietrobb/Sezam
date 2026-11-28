//! Formats without secrets in the core (docs/CORE_UNIFICATION.md U6): AAD
//! (cross_client.json), padded_size (padding.json), normalize_username and
//! split_for_push (formats.json, the desktop's answers before they moved), the
//! state hash (cross_client.json and formats.json).

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

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

fn b64(text: &str) -> Vec<u8> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let (mut bits, mut n, mut out) = (0u32, 0, Vec::new());
    for c in text.bytes().filter(|c| *c != b'=') {
        bits = bits << 6 | A.iter().position(|a| *a == c).unwrap() as u32;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// cross_client.json's server objects in the core's shape.
fn served(objects: &Value) -> Vec<Value> {
    objects
        .as_array()
        .unwrap()
        .iter()
        .map(|o| {
            json!({
                "id": o["id"],
                "version": o["version"],
                "payload_hash": hex(&Sha256::digest(b64(o["payload"].as_str().unwrap()))),
                "parent_ref": o.get("parent_ref").cloned().unwrap_or(Value::Null),
                "is_deleted": o.get("is_deleted").and_then(Value::as_i64).unwrap_or(0) != 0,
            })
        })
        .collect()
}

#[test]
fn state_hash() {
    let cc = vectors("cross_client.json");
    let legacy = served(&cc["state_hash"]["objects"]);
    let mut reversed = legacy.clone();
    reversed.reverse();
    for objects in [&legacy, &reversed] {
        let out = call("state_hash", &json!({"objects": objects, "legacy": true}));
        assert_eq!(out["ok"], cc["state_hash"]["state_hash"]);
    }
    let v2 = &cc["state_hash_v2"];
    let mut signed = served(&v2["objects"]);
    signed.reverse();
    assert_eq!(
        call("state_hash", &json!({"objects": signed}))["ok"],
        v2["state_hash"]
    );
    let first = signed.len() - 1;
    let mut moved = signed.clone();
    moved[first]["parent_ref"] = Value::Null;
    assert_eq!(
        call("state_hash", &json!({"objects": moved}))["ok"],
        v2["moved"]
    );
    let mut deleted = signed.clone();
    deleted[first]["is_deleted"] = json!(true);
    assert_eq!(
        call("state_hash", &json!({"objects": deleted}))["ok"],
        v2["deleted"]
    );

    let f = vectors("formats.json");
    let cases = f["state_hash"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let out = call("state_hash", &json!({"objects": case["objects"]}));
        assert_eq!(out["ok"], case["state_hash"], "{case}");
        let out = call(
            "state_hash",
            &json!({"objects": case["objects"], "legacy": true}),
        );
        assert_eq!(out["ok"], case["legacy"], "{case}");
    }
    for case in f["state_hash_refused"].as_array().unwrap() {
        assert!(call("state_hash", case).get("error").is_some(), "{case}");
    }
}

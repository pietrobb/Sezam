//! The shared key voucher vectors (tests/vectors/key_vouchers.json,
//! signed_fields.json) through the core's one entry point.
//!
//! Signatures are the clients' (libsodium): here every list counts as
//! verified, so a case only shows that what the core vouches for includes what
//! it should; tests/test_key_vouchers_vectors.py (desktop, through the core)
//! and the web and phone vector tests run every case with real verification.

use std::path::PathBuf;

use serde_json::{json, Value};

fn vectors(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/vectors")
        .join(name);
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

#[test]
fn every_voucher_message_is_byte_for_byte_the_reference() {
    let v = vectors("key_vouchers.json");
    for m in v["messages"].as_array().unwrap() {
        let out = call("key_voucher_message", m.clone()).unwrap();
        assert_eq!(out["message"], m["message_hex"], "{m}");
    }
}

#[test]
fn every_object_entry_and_signed_message_is_the_reference() {
    let v = vectors("key_vouchers.json");
    for e in v["object_entries"].as_array().unwrap() {
        let message = call("key_voucher_signed_message", json!({"object": e["object"]})).unwrap();
        assert_eq!(message, e["signed_message_hex"], "{e}");
        let entry = call("key_voucher_object_entry", e.clone()).unwrap();
        assert_eq!(entry, e["entry"], "{e}");
    }
}

#[test]
fn every_malformed_entry_is_refused() {
    let v = vectors("key_vouchers.json");
    for bad in v["malformed_entries"].as_array().unwrap() {
        assert!(
            call("key_voucher_canonical", json!({"entries": [bad]})).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn every_vouched_case_is_vouched_once_its_signature_verified() {
    let v = vectors("key_vouchers.json");
    for c in v["cases"].as_array().unwrap() {
        let lists = c.get("lists").cloned().unwrap_or(Value::Null);
        let n = lists.as_array().map_or(0, Vec::len);
        let out = call(
            "key_voucher_vouched",
            json!({
                "user_id": v["user_id"], "current_signing_pk": v["current_signing_pk"],
                "lists": lists, "verified": vec![true; n],
            }),
        )
        .unwrap();
        let found = out.as_array().unwrap().contains(&c["entry"]);
        if c["vouched"] == true {
            assert!(found, "{}", c["name"]);
        }
    }
}

#[test]
fn a_list_by_another_key_is_not_even_offered_for_verification() {
    let v = vectors("key_vouchers.json");
    let c = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "listed only by a retired key")
        .unwrap();
    let out = call(
        "key_voucher_lists",
        json!({"user_id": v["user_id"], "current_signing_pk": v["current_signing_pk"], "lists": c["lists"]}),
    )
    .unwrap();
    assert!(out.as_array().unwrap().iter().all(Value::is_null), "{out}");
}

#[test]
fn every_signed_field_changes_the_message_and_the_entry() {
    let v = vectors("signed_fields.json");
    let entry = |obj: &Value, signer: &Value, pk: &Value| {
        call(
            "key_voucher_object_entry",
            json!({"object": obj, "signer_id": signer, "signing_pk": pk}),
        )
        .unwrap()
    };
    let base = entry(&v["object"], &v["signer_id"], &v["signing_pk"]);
    assert!(!base.is_null());
    for field in v["fields"].as_array().unwrap() {
        let f = field.as_str().unwrap();
        let mut other = v["object"].clone();
        other[f] = v["other"][f].clone();
        let changed = entry(&other, &v["signer_id"], &v["signing_pk"]);
        assert_ne!(changed[2], base[2], "{f}");
    }
    for f in v["none"].as_array().unwrap() {
        let mut other = v["object"].clone();
        other[f.as_str().unwrap()] = Value::Null;
        assert_ne!(
            entry(&other, &v["signer_id"], &v["signing_pk"])[2],
            base[2],
            "{f}"
        );
    }
    assert_ne!(
        entry(&v["object"], &v["other_signer_id"], &v["signing_pk"])[2],
        base[2]
    );
    assert_ne!(
        entry(&v["object"], &v["signer_id"], &v["other_signing_pk"])[2],
        base[2]
    );
}

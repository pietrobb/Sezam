//! U7e (docs/CORE_UNIFICATION.md): tests/vectors/rotated_seals.json and
//! tests/vectors/revive_folders.json, from the desktop before the move.

use std::path::PathBuf;

use serde_json::{json, Value};

fn vectors(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/vectors")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn call(op: &str, input: Value) -> Value {
    let out: Value =
        serde_json::from_str(&sezam_sync_core::json::call(op, &input.to_string())).unwrap();
    assert!(out.get("error").is_none(), "{op}: {out}");
    out["ok"].clone()
}

#[test]
fn rotated_seals_as_the_desktop_decided() {
    let v = vectors("rotated_seals.json");
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 15);
    for case in cases {
        let mut input = case.clone();
        let input = input.as_object_mut().unwrap();
        input.remove("name");
        input.remove("expect");
        assert_eq!(
            call("team_log_rotated_seals", Value::Object(input.clone())),
            case["expect"],
            "{}",
            case["name"]
        );
    }
}

#[test]
fn revive_folders_as_the_desktop_decided() {
    let v = vectors("revive_folders.json");
    for case in v["cases"].as_array().unwrap() {
        assert_eq!(
            call(
                "revive_folders",
                json!({"deleted": case["deleted"], "work_in": case["work_in"]})
            ),
            case["expect"],
            "{}",
            case["name"]
        );
    }
}

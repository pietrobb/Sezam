//! U7f (docs/CORE_UNIFICATION.md): tests/vectors/team_log_local_refusal.json,
//! from the desktop's rule before the move (capability run 707).

use std::path::PathBuf;

use serde_json::Value;

fn call(op: &str, input: Value) -> Value {
    let out: Value =
        serde_json::from_str(&sezam_sync_core::json::call(op, &input.to_string())).unwrap();
    assert!(out.get("error").is_none(), "{op}: {out}");
    out["ok"].clone()
}

#[test]
fn local_refusals_as_the_desktop_decided() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/vectors/team_log_local_refusal.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 200);
    let mut seen = std::collections::BTreeSet::new();
    for case in cases {
        let mut input = case.clone();
        let input = input.as_object_mut().unwrap();
        input.remove("name");
        input.remove("expect");
        let got = call("team_log_local_refusal", Value::Object(input.clone()));
        assert_eq!(got, case["expect"], "{}", case["name"]);
        seen.insert(got["cause"].as_str().unwrap_or("none").to_string());
    }
    // every outcome is in the file
    assert_eq!(
        seen.into_iter().collect::<Vec<_>>(),
        ["anchor_conflict", "local_damaged", "none"]
    );
}

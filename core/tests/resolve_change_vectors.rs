//! A queued team change made again (docs/CORE_UNIFICATION.md U7a):
//! tests/vectors/resolve_change.json, the desktop's answers before it moved.

use serde_json::{json, Value};

#[test]
fn every_queued_change_resolves_as_the_vectors_say() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/vectors/resolve_change.json"
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 82);
    for c in cases {
        let state = &v["states"][c["state"].as_str().unwrap()];
        let input = json!({"state": state, "questions": [
            {"fn": "resolve_change", "args": [c["kind"], c["data"]]}
        ]});
        let out: Value = serde_json::from_str(&sezam_sync_core::json::call(
            "team_log_ask",
            &input.to_string(),
        ))
        .unwrap();
        let got = &out["ok"][0];
        let expect = &c["expect"];
        if expect.get("refused").is_some() {
            assert_eq!(got["refused"]["code"], expect["refused"], "{c}: {out}");
            assert_eq!(got["refused"]["seq"], expect["seq"], "{c}: {out}");
        } else {
            assert_eq!(got, &json!({"data": expect["data"]}), "{c}");
        }
    }
}

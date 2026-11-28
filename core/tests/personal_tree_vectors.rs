//! tests/vectors/personal_tree.json: this account's personal trees (TL7,
//! INV-7 rule 3) and the keys a team log names (docs/CORE_UNIFICATION.md U5).

use serde_json::{json, Value};

fn call(op: &str, input: &Value) -> Value {
    let out: Value =
        serde_json::from_str(&sezam_sync_core::json::call(op, &input.to_string())).unwrap();
    assert!(out.get("error").is_none(), "{out}");
    out["ok"].clone()
}

#[test]
fn personal_tree_vectors() {
    let doc: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/vectors/personal_tree.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let cases = doc["cases"].as_array().unwrap();
    assert!(cases.len() >= 15);
    for case in cases {
        let input = json!({
            "objects": case["objects"],
            "own_user_id": case["own_user_id"],
            "team_keys": case["team_keys"],
        });
        assert_eq!(
            call("authority_personal_tree", &input),
            case["expect"],
            "{}",
            case["name"]
        );
    }
}

#[test]
fn team_key_ids_read_every_record_that_parses() {
    let bodies = json!([
        r#"{"author":"A","data":{"dek_id":"K1","folder":"F","gen":0,"prev_dek_id":null},"prev":"0","seq":1,"type":"folder.key","v":2}"#,
        r#"{"data":{"prev_dek_id":"K0","dek_id":"K2"},"type":"folder.key"}"#,
        "not json",
        r#"{"data":"no object"}"#,
        r#"{"data":{"user_id":"U"},"type":"member.add"}"#,
    ]);
    assert_eq!(
        call("authority_team_key_ids", &json!({"bodies": bodies})),
        json!(["K0", "K1", "K2"])
    );
}

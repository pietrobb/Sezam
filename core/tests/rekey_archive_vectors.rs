//! The removal re-key archive id in the core (docs/CORE_UNIFICATION.md U6):
//! tests/vectors/rekey_archive.json, the desktop's answers before it moved.

use serde_json::{json, Value};

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/vectors/rekey_archive.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn call(op: &str, input: &Value) -> Value {
    serde_json::from_str(&sezam_sync_core::json::call(op, &input.to_string())).unwrap()
}

#[test]
fn messages_ids_and_checks() {
    let v = vectors();
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 20);
    let mut checks = 0;
    for c in cases {
        let input = json!({"new_dek_id": c["new_dek_id"], "user_id": c["user_id"]});
        assert_eq!(
            call("removal_archive_messages", &input)["ok"],
            c["messages"],
            "{c}"
        );
        let input = json!({"prefix": c["prefix"], "mark": c["mark"], "member": c["member"]});
        assert_eq!(
            call("removal_archive_id", &input)["ok"],
            c["archive_id"],
            "{c}"
        );
        for k in c["checks"].as_array().unwrap() {
            let input =
                json!({"archive_id": k["archive_id"], "mark": k["mark"], "member": k["member"]});
            assert_eq!(
                call("removal_archive_check", &input)["ok"],
                k["removed"],
                "{k}"
            );
            checks += 1;
        }
    }
    assert_eq!(checks, 160);
}

#[test]
fn refused() {
    let v = vectors();
    let refused = v["refused"].as_array().unwrap();
    assert_eq!(refused.len(), 10);
    for r in refused {
        let out = call(r["op"].as_str().unwrap(), &r["input"]);
        assert!(out["error"].is_string(), "{r}: {out}");
    }
}

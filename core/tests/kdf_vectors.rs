//! tests/vectors/kdf.json in the core: which Argon2id params a client derives
//! an account KEK or a .sezam-key backup with (docs/CORE_UNIFICATION.md U6).

use serde_json::{json, Value};

fn vectors() -> Value {
    let path = format!("{}/../tests/vectors/kdf.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn call(op: &str, input: &Value) -> Value {
    serde_json::from_str(&sezam_sync_core::json::call(op, &input.to_string())).unwrap()
}

#[test]
fn account_params() {
    let v = vectors();
    let cases = v["account"].as_array().unwrap();
    assert!(cases.len() > 1000);
    for case in cases {
        let mut input = case["params"].clone();
        input["local"] = case["local"].clone();
        input["stored"] = case["stored"].clone();
        let out = call("account_kdf_refusal", &input);
        assert!(out.get("error").is_none(), "{case}: {out}");
        assert_eq!(
            !out["ok"].is_null(),
            case["refused"].as_bool().unwrap(),
            "{case}"
        );
    }
    let base = json!({"time_cost": 3, "memory_cost": 131072, "parallelism": 4});
    assert_eq!(call("account_kdf_refusal", &base)["ok"], Value::Null);
    let mut extra = base.clone();
    extra["salt_len"] = json!(16);
    assert!(call("account_kdf_refusal", &extra).get("error").is_some());
}

#[test]
fn sezam_key_params() {
    let v = vectors();
    let cases = v["sezam_key"].as_array().unwrap();
    assert!(cases.len() > 1000);
    for case in cases {
        let mut input = case.clone();
        input.as_object_mut().unwrap().remove("refused");
        let out = call("sezam_key_kdf_refusal", &input);
        assert!(out.get("error").is_none(), "{case}: {out}");
        assert_eq!(
            !out["ok"].is_null(),
            case["refused"].as_bool().unwrap(),
            "{case}"
        );
    }
}

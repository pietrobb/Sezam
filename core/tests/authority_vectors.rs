//! The shared authority vectors (tests/vectors/authority.json, written by
//! tests/authority_vectors.py) through the core's one entry point: the key a
//! header names, the log's admins and which pulled writes are not applied.

use std::path::PathBuf;

use serde_json::{json, Value};

fn vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/vectors/authority.json");
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn call(op: &str, input: Value) -> Value {
    let out: Value =
        serde_json::from_str(&sezam_sync_core::json::call(op, &input.to_string())).unwrap();
    assert!(out.get("error").is_none(), "{op}: {out}");
    out["ok"].clone()
}

/// The objects as a client hands them over: the key its header names.
fn objects(list: &Value) -> Value {
    let list = list.as_array().unwrap();
    Value::Array(
        list.iter()
            .map(|o| {
                let mut o = o.as_object().unwrap().clone();
                let head = o.remove("head").unwrap();
                let dek_id = call(
                    "authority_sealing_dek_id",
                    json!({"object_type": o["object_type"], "head": head}),
                );
                o.insert("dek_id".into(), dek_id);
                Value::Object(o)
            })
            .collect(),
    )
}

#[test]
fn every_header_names_the_reference_key() {
    for c in vectors()["cases"].as_array().unwrap() {
        for o in c["objects"].as_array().unwrap() {
            let got = call(
                "authority_sealing_dek_id",
                json!({"object_type": o["object_type"], "head": o["head"]}),
            );
            let key = format!(
                "{}/{}",
                o["id"].as_str().unwrap(),
                o["object_type"].as_str().unwrap()
            );
            assert_eq!(got, c["dek_ids"][&key], "{} {key}", c["name"]);
        }
    }
}

#[test]
fn every_case_blocks_what_the_reference_blocks() {
    let v = vectors();
    for c in v["cases"].as_array().unwrap() {
        let team = c["team"].as_u64().map(|i| v["teams"][i as usize].clone());
        let mut input = json!({
            "objects": objects(&c["objects"]),
            "own_user_id": c["own_user_id"],
            "team": team,
            "team_admins": c["team_admins"],
        });
        if !c["previous"].is_null() {
            input["previous"] = objects(&c["previous"]);
        }
        let out = call("authority_unauthorized_writes", input);
        assert_eq!(out["blocked"], c["blocked"], "{}", c["name"]);
        assert_eq!(out["by_team_log"], c["by_team_log"], "{}", c["name"]);
    }
}

#[test]
fn the_log_admins_are_the_reference() {
    let v = vectors();
    let log: Value = serde_json::from_str(
        &std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/vectors/team_log.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let scenarios = [
        "second_admin_removes_founder",
        "org_recovery_wrap",
        "handover_on_ends_the_role_keys",
    ];
    let mut checked = 0;
    for c in v["cases"].as_array().unwrap() {
        let (Some(i), Some(admins)) = (c["team"].as_u64(), c["team_admins"].as_array()) else {
            continue;
        };
        let scenario = log["scenarios"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == scenarios[i as usize])
            .unwrap();
        let bodies: Vec<Value> = scenario["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["body"].clone())
            .collect();
        let got = call(
            "authority_log_admins",
            json!({"bodies": bodies, "team": v["teams"][i as usize]}),
        );
        assert_eq!(got.as_array().unwrap(), admins, "{}", c["name"]);
        checked += 1;
    }
    assert!(checked > 0);
}

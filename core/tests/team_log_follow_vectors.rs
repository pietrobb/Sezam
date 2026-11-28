//! Following the server's team log in the core (docs/CORE_UNIFICATION.md
//! U7b): tests/vectors/team_log_mismatch.json, written by an oracle that
//! knows no client code, through the three follow steps the clients run.
//!
//! Signatures are the clients' (libsodium): here every check passes but the
//! forged record's, the one the vectors' "forged" server serves.

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

/// The state after `records` on `state`, or the refusal's detail.
fn replay(records: &[Value], state: &Value, forged: bool) -> Result<Value, String> {
    let checks = call(
        "team_log_replay",
        json!({"records": records, "state": state}),
    )["checks"]
        .as_array()
        .unwrap()
        .len();
    let verified = if forged { checks - 1 } else { checks };
    let out = call(
        "team_log_replay",
        json!({"records": records, "state": state, "verified": verified}),
    );
    match out.get("refused") {
        Some(r) => Err(r["detail"].as_str().unwrap().to_string()),
        None => Ok(out["state"].clone()),
    }
}

fn seq(record: &Value) -> i64 {
    let body: Value = serde_json::from_str(record["body"].as_str().unwrap()).unwrap();
    body["seq"].as_i64().unwrap()
}

fn tip(state: &Value) -> Value {
    json!({"seq": state["head_seq"], "hash": state["head_hash"], "genesis_hash": state["genesis_hash"]})
}

fn outcome(refused: &Value) -> Value {
    json!({"refused": refused["cause"], "forget": refused["forget"]})
}

/// One case as a client runs it: plan, check what is served, fetch, judge.
fn follow(case: &Value) -> Value {
    let device = &case["device"];
    let served: Vec<Value> = case["server"]["records"].as_array().unwrap().clone();
    let head = &case["server"]["head"];
    let forged = case["name"].as_str().unwrap().ends_with("/forged");
    let local = device["records"]
        .as_array()
        .map(|records| replay(records, &Value::Null, false).unwrap());
    let forgotten = !device["forgotten_genesis"].as_array().unwrap().is_empty();
    let plan = call(
        "team_log_follow_plan",
        json!({
            "head": head,
            "local": local.as_ref().map(tip),
            "pinned_genesis": local.as_ref().map(|s| s["genesis_hash"].clone()),
            "confirmed_genesis": device["confirmed_genesis"],
            "left_earlier_log": forgotten,
        }),
    );
    if let Some(check) = plan.get("check_served") {
        let first =
            served.first().map(
                |r| match replay(std::slice::from_ref(r), &Value::Null, false) {
                    Ok(s) => json!({"genesis": s["genesis_hash"]}),
                    Err(e) => json!({"error": e}),
                },
            );
        let out = call(
            "team_log_follow_served",
            json!({"check": check, "head_shown": !head.is_null(), "first": first}),
        );
        return outcome(&out["refused"]);
    }
    if let Some(r) = plan.get("refused") {
        return outcome(r);
    }
    if plan.get("none").is_some() {
        return json!({"follows": null});
    }
    let local = local.unwrap_or(Value::Null);
    if plan.get("same").is_some() {
        return json!({"follows": local["head_seq"]});
    }
    let since = plan["fetch"]["since"].as_i64().unwrap();
    let upto = plan["fetch"]["upto"].as_i64().unwrap();
    let batch: Vec<Value> = served
        .iter()
        .filter(|r| seq(r) > since)
        .take(usize::try_from(upto - since).unwrap())
        .cloned()
        .collect();
    let (state, fetched, error) = match replay(&batch, &local, forged) {
        Ok(state) => {
            let hashes: Vec<Value> = batch
                .iter()
                .map(|r| {
                    call(
                        "team_log_record_hash",
                        json!({"body": r["body"], "sig": r["sig"]}),
                    )
                })
                .collect();
            (state, hashes, None)
        }
        Err(e) => (local.clone(), vec![], Some(e)),
    };
    let state = if state.is_null() {
        call("team_log_empty_state", json!({}))
    } else {
        state
    };
    let refusal = call(
        "team_log_ask",
        json!({"state": state, "questions": [{"fn": "admin_policy_refusal", "args": []}]}),
    )[0]
    .clone();
    let out = call(
        "team_log_follow_caught_up",
        json!({
            "head": head, "since": since, "fetched": fetched, "replay_error": error,
            "state": tip(&state), "admin_refusal": refusal,
        }),
    );
    match out.get("refused") {
        Some(r) => outcome(r),
        None => json!({"follows": state["head_seq"]}),
    }
}

#[test]
fn every_mismatch_case_gives_the_oracles_answer() {
    let file = vectors("team_log_mismatch.json");
    let cases = file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 65);
    for case in cases {
        let mut want = case["expect"].clone();
        want.as_object_mut().unwrap().remove("risk");
        assert_eq!(follow(case), want, "{}", case["name"]);
    }
}

#[test]
fn the_causes_are_the_vectors() {
    let file = vectors("team_log_mismatch.json");
    assert_eq!(call("team_log_mismatch_causes", json!({})), file["causes"]);
}

#[test]
fn pins_and_withdrawn_records_are_held_to() {
    let head = json!({"genesis_hash": "g", "seq": 3, "hash": "h3"});
    let plan = call(
        "team_log_follow_plan",
        json!({"head": head, "local": null, "pins": [{"seq": 3, "hashes": ["other"]}],
               "pinned_genesis": "g", "confirmed_genesis": null, "who": "this phone"}),
    );
    assert_eq!(plan["refused"]["cause"], "differs", "{plan}");
    let plan = call(
        "team_log_follow_plan",
        json!({"head": {"genesis_hash": "g", "seq": 1.5, "hash": "h"}, "local": null,
               "pinned_genesis": "g", "confirmed_genesis": null}),
    );
    assert_eq!(plan["refused"]["cause"], "went_back", "{plan}");
    let state = json!({"seq": 3, "hash": "h3", "genesis_hash": "g"});
    let judged = |pins: Value, withdrawn: Value| {
        call(
            "team_log_follow_caught_up",
            json!({"head": head, "since": 0, "pins": pins, "fetched": ["h1", "h2", "h3"],
                   "replay_error": null, "state": state, "withdrawn": withdrawn,
                   "admin_refusal": null, "who": "this browser"}),
        )
    };
    let out = judged(json!([{"seq": 2, "hashes": ["x"]}]), json!([]));
    assert_eq!(out["refused"]["detail"], "differs at record 2", "{out}");
    let out = judged(json!([{"seq": 2, "hashes": ["x", "h2"]}]), json!(["h2"]));
    assert_eq!(
        out["refused"]["detail"],
        "holds record 2, which this browser withdrew (the server refused it, or this browser went on without it)",
        "{out}"
    );
    assert_eq!(judged(json!([]), json!([]))["accept"], true);
}

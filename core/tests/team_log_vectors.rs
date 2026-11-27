//! The shared team log vectors (tests/vectors/team_log*.json, written from
//! the Python reference and by hand) through the core's one entry point.
//!
//! Signatures are the clients' (libsodium), so here every check passes but
//! the one a vector names as `bad_signature` / `bad_new_key_signature`; the
//! Python differential test (tests/test_core_team_log.py) runs them with
//! real verification.

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

/// How many checks pass from the start when the vector expects `error`.
fn passing(checks: &[Value], error: Option<&Value>) -> usize {
    let Some(error) = error else {
        return checks.len();
    };
    let seq = error["seq"].as_i64().unwrap();
    let before = checks
        .iter()
        .filter(|c| c["seq"].as_i64() < Some(seq))
        .count();
    match error["code"].as_str().unwrap() {
        "bad_signature" => before,
        // the record's own signature passed, its new key's proof did not
        "bad_new_key_signature" => before + 1,
        _ => checks.len(),
    }
}

#[test]
fn every_team_log_scenario_gives_the_reference_state_answers_and_errors() {
    let file = vectors("team_log.json");
    let scenarios = file["scenarios"].as_array().unwrap();
    assert!(scenarios.len() > 100);
    for s in scenarios {
        let name = s["name"].as_str().unwrap();
        let records = &s["records"];
        let checks = call(
            "team_log_replay",
            json!({"records": records, "state": null}),
        )["checks"]
            .as_array()
            .unwrap()
            .clone();
        let verified = passing(&checks, s.get("error"));
        let out = call(
            "team_log_replay",
            json!({"records": records, "state": null, "verified": verified}),
        );
        if let Some(error) = s.get("error") {
            let refused = &out["refused"];
            assert_eq!(
                (&refused["code"], &refused["seq"]),
                (&error["code"], &error["seq"]),
                "{name}: {out}"
            );
            continue;
        }
        let state = out["state"].clone();
        assert!(!state.is_null(), "{name}: {out}");
        let questions: Vec<Value> = std::iter::once(json!({"fn": "state_json", "args": []}))
            .chain(
                s["questions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|q| json!({"fn": q["fn"], "args": q["args"]})),
            )
            .collect();
        let answers = call(
            "team_log_ask",
            json!({"state": state, "questions": questions}),
        );
        assert_eq!(answers[0], s["state"], "{name}: state");
        for (q, a) in s["questions"]
            .as_array()
            .unwrap()
            .iter()
            .zip(&answers.as_array().unwrap()[1..])
        {
            assert_eq!(a, &q["answer"], "{name}: {} {}", q["fn"], q["args"]);
        }
    }
}

#[test]
fn a_signature_the_client_did_not_verify_stops_the_replay_there() {
    let file = vectors("team_log.json");
    let s = file["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s.get("error").is_none() && s["records"].as_array().unwrap().len() > 2)
        .unwrap();
    let out = call(
        "team_log_replay",
        json!({"records": s["records"], "state": null, "verified": 1}),
    );
    assert_eq!(out["refused"]["code"], "bad_signature");
    assert_eq!(out["refused"]["seq"], 1);
}

#[test]
fn every_fork_case_gives_its_hand_written_answer() {
    let file = vectors("team_log_fork.json");
    for case in file["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let out = call(
            "team_log_fork",
            json!({
                "lost": case["lost"], "theirs": case["theirs"], "user_id": case["user_id"],
                "held_keys": case["held_keys"], "withdrawn": case["withdrawn"],
            }),
        );
        let fork = &out["fork"];
        let expect = &case["expect"];
        assert_eq!(fork["refusal"], expect["refusal"], "{name}: {out}");
        if let Some(missing) = expect.get("missing") {
            assert_eq!(&fork["missing"], missing, "{name}");
        }
        if let Some(abandoned) = expect.get("abandoned") {
            let hashes = call(
                "team_log_abandoned",
                json!({"lost": case["lost"], "user_id": case["user_id"]}),
            )["hashes"]
                .clone();
            let expected: Vec<Value> = case["lost"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|r| {
                    let body: Value = serde_json::from_str(r["body"].as_str().unwrap()).unwrap();
                    abandoned.as_array().unwrap().contains(&body["seq"])
                })
                .map(|r| {
                    call(
                        "team_log_record_hash",
                        json!({"body": r["body"], "sig": r["sig"]}),
                    )
                })
                .collect();
            assert_eq!(hashes, json!(expected), "{name}: abandoned");
        }
    }
}

#[test]
fn every_restore_part_ends_where_the_vector_says() {
    let file = vectors("team_log_restore_parts.json");
    for case in file["cases"].as_array().unwrap() {
        let bodies: Vec<Value> = case["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| json!({"type": r[0], "author": r[1], "data": {"user_id": r[2]}}))
            .collect();
        let end = call(
            "team_log_restore_part_end",
            json!({"bodies": bodies, "start": case["start"], "limit": case["limit"]}),
        );
        assert_eq!(end, case["end"], "{}", case["name"]);
    }
}

#[test]
fn a_truncated_state_is_bad_input_not_an_empty_log() {
    let out: Value = serde_json::from_str(&sezam_sync_core::json::call(
        "team_log_ask",
        &json!({"state": {"org": "x"}, "questions": []}).to_string(),
    ))
    .unwrap();
    assert!(
        out["error"].as_str().unwrap().contains("missing field"),
        "{out}"
    );
}

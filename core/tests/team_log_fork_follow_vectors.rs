//! Following a fork in the core (docs/CORE_UNIFICATION.md U7d):
//! tests/vectors/team_log_fork_follow.json, from the desktop's follow_fork
//! before the move, through the steps every client runs: split, replay what
//! is served, take.
//!
//! Signatures are the clients' (libsodium): here every check passes but the
//! last one of the case whose served log does not replay (a forged record).

use std::path::PathBuf;

use serde_json::{json, Value};

fn vectors() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/vectors/team_log_fork_follow.json");
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn call(op: &str, input: Value) -> Value {
    let out: Value =
        serde_json::from_str(&sezam_sync_core::json::call(op, &input.to_string())).unwrap();
    assert!(out.get("error").is_none(), "{op}: {out}");
    out["ok"].clone()
}

fn replay(records: &[Value], forged: bool) -> Option<Value> {
    let checks = call("team_log_replay", json!({"records": records}))["checks"]
        .as_array()
        .unwrap()
        .len();
    let verified = if forged { checks - 1 } else { checks };
    let out = call(
        "team_log_replay",
        json!({"records": records, "verified": verified}),
    );
    out.get("refused").is_none().then(|| out["state"].clone())
}

fn follow(case: &Value) -> Value {
    let split = call(
        "team_log_fork_split",
        json!({
            "local": case["local"], "served": case["served"], "pins": case["pins"],
            "user_id": case["user_id"], "held_keys": case["held_keys"], "withdrawn": case["withdrawn"],
        }),
    );
    let Some(fork) = split.get("fork").and_then(Value::as_u64) else {
        return split;
    };
    let served = case["served"].as_array().unwrap();
    let forged = case["name"] == "served_does_not_replay";
    let Some(state) = replay(served, forged) else {
        return json!({"stand": true});
    };
    let lost = &case["local"].as_array().unwrap()[fork as usize..];
    let mut take = call(
        "team_log_fork_take",
        json!({
            "state": state, "head": case["head"], "lost": lost, "missing": split["missing"],
            "user_id": case["user_id"], "held_keys": case["held_keys"],
            "old_signing_pk": case["old_signing_pk"],
        }),
    );
    if let Some(follow) = take.get_mut("follow") {
        follow["fork"] = json!(fork);
    }
    take
}

#[test]
fn every_case_as_the_desktop_decided() {
    let v = vectors();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 20);
    for case in cases {
        assert_eq!(follow(case), case["expect"], "{}", case["name"]);
    }
}

#[test]
fn which_refusals_look_for_a_fork() {
    for (cause, follows) in [
        ("went_back", true),
        ("differs", true),
        ("does_not_replay", true),
        ("short_of_head", false),
        ("log_gone", false),
        ("other_genesis", false),
    ] {
        assert_eq!(
            call("team_log_fork_follows", json!({"cause": cause})),
            json!(follows),
            "{cause}"
        );
    }
}

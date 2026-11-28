//! tests/vectors/account_bundle.json in the core: pre-anchor password states
//! and the SZACCT account bundle as the desktop's aead.py answered before they
//! moved (docs/CORE_UNIFICATION.md U6). The KEK's check and a legacy bundle's
//! public key stay with each platform's libsodium.

use serde_json::{json, Value};

fn vectors() -> Value {
    let path = format!(
        "{}/../tests/vectors/account_bundle.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn call(op: &str, input: &Value) -> Value {
    serde_json::from_str(&sezam_sync_core::json::call(op, &input.to_string())).unwrap()
}

fn cases(name: &str) -> Vec<Value> {
    let cases = vectors()[name].as_array().unwrap().clone();
    assert!(cases.len() > 5, "{name}");
    cases
}

/// The core answers what the desktop answered: the same result, or a refusal
/// (with the desktop's message where the rule is the core's).
fn same(out: &Value, case: &Value) {
    match case.get("ok") {
        Some(ok) => assert_eq!(out.get("ok"), Some(ok), "{case}"),
        None => assert!(out.get("error").is_some(), "{case} -> {out}"),
    }
}

#[test]
fn parse() {
    for case in cases("pre_anchor_parse") {
        let out = call("pre_anchor_parse", &json!({"blob": case["blob"]}));
        match case.get("ok") {
            Some(ok) => {
                let got = out["ok"].as_array().unwrap();
                assert_eq!(got.len(), ok.as_array().unwrap().len(), "{case}");
                for (g, want) in got.iter().zip(ok.as_array().unwrap()) {
                    for key in ["salt", "time_cost", "memory_cost", "parallelism", "check"] {
                        assert_eq!(g[key], want[key], "{case}");
                    }
                    let raw = g["raw"].as_str().unwrap();
                    assert!(raw.starts_with(want["salt"].as_str().unwrap()));
                    assert!(raw.ends_with(want["check"].as_str().unwrap()));
                }
            }
            None => assert_eq!(out["error"], case["error"], "{case}"),
        }
    }
}

#[test]
fn merge() {
    for case in cases("pre_anchor_merge") {
        let out = call(
            "pre_anchor_merge",
            &json!({"kept": case["kept"], "other": case["other"]}),
        );
        same(&out, &case);
    }
}

#[test]
fn add() {
    for case in cases("pre_anchor_add") {
        let out = call("pre_anchor_add", &case);
        same(&out, &case);
    }
}

#[test]
fn bundle_decode() {
    for case in cases("bundle_decode") {
        let payload = case["payload"].as_str().unwrap();
        let length = payload.len() / 2;
        let input = if length >= 104 {
            json!({"length": length, "version": &payload[..16], "tail": &payload[144..]})
        } else {
            json!({"length": length})
        };
        let out = call("account_bundle_decode", &input);
        if case["error"] == "Invalid account keypair public key" {
            // The legacy pk is the platform's check.
            assert_eq!(out["ok"]["kind"], "legacy96", "{case}");
            continue;
        }
        let Some(want) = case.get("ok") else {
            assert_eq!(out["error"], case["error"], "{case}");
            continue;
        };
        let got = &out["ok"];
        assert_eq!(
            got["confirmed_genesis"], want["confirmed_genesis"],
            "{case}"
        );
        assert_eq!(got["pre_anchor"], want["pre_anchor"], "{case}");
        let keys = match got["kind"].as_str().unwrap() {
            "anchored" | "v1" => payload[16..144].to_string(),
            "legacy64" => payload.to_string(),
            "legacy96" => format!("{}{}", &payload[..64], &payload[128..]),
            other => panic!("{other}"),
        };
        assert_eq!(json!(keys), want["keys"], "{case}");
    }
}

#[test]
fn bundle_encode() {
    for case in cases("bundle_encode") {
        let keys = case["keys"].as_str().unwrap();
        let out = call(
            "account_bundle_encode",
            &json!({"confirmed_genesis": case["confirmed_genesis"], "pre_anchor": case["pre_anchor"]}),
        );
        if ![128, 192].contains(&keys.len()) {
            // The key lengths are the platform's check.
            assert!(case.get("error").is_some());
            continue;
        }
        let Some(want) = case.get("ok") else {
            assert_eq!(out["error"], case["error"], "{case}");
            continue;
        };
        let keys64 = if keys.len() == 192 {
            format!("{}{}", &keys[..64], &keys[128..])
        } else {
            keys.to_string()
        };
        let got = format!(
            "{}{}{}",
            out["ok"]["version"].as_str().unwrap(),
            keys64,
            out["ok"]["tail"].as_str().unwrap()
        );
        assert_eq!(json!(got), *want, "{case}");
    }
}

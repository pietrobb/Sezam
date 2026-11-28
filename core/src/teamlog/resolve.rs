//! A queued team change made again on the log as it is now (docs/CORE_UNIFICATION.md
//! step U7a): the desktop's `resolve_change`, the page's and the phone's
//! `resolveChange`, once.

use serde_json::{Map, Value};

use super::{rules, LogError, LogResult, State};

fn text<'a>(data: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    data.get(key).and_then(Value::as_str)
}

fn refused(state: &State, code: &str, detail: String) -> LogError {
    LogError::new(code, Some(state.head_seq + 1), &detail)
}

/// The record data a queued `kind` change goes out with on `state`, or None
/// when the log has it already (its reply was lost, or another device made
/// it). Keys starting with `_` are the queue's own and never sent; `_seen` is
/// the member's state when the change was queued.
///
/// Refused (the change can never land): `founded_elsewhere` (another device
/// founded the log), `removed_meanwhile` (a member.add queued before another
/// device removed the member would bring them back), `folder_key_moved` (the
/// folder went on to another key), `not_remade` (no such kind).
pub fn resolve_change(state: &State, kind: &str, data: &Value) -> LogResult<Option<Value>> {
    let Some(queued) = data.as_object() else {
        return Err(refused(
            state,
            "not_remade",
            format!("a lost {kind} has no data"),
        ));
    };
    let seen = queued.get("_seen");
    let data: Map<String, Value> = queued
        .iter()
        .filter(|(k, _)| !k.starts_with('_'))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let member = state.members.get(text(&data, "user_id").unwrap_or(""));
    let keys_match = |m: &super::Member| {
        Some(m.signing_pk.as_str()) == text(&data, "signing_pk")
            && Some(m.encryption_pk.as_str()) == text(&data, "encryption_pk")
    };
    let has = |done: bool| (!done).then(|| Value::Object(data.clone()));
    Ok(match kind {
        "genesis" => {
            if state.head_seq < 0 {
                Some(Value::Object(data))
            } else if Some(state.org.as_str()) == text(&data, "org") {
                None
            } else {
                return Err(refused(
                    state,
                    "founded_elsewhere",
                    "another device founded the team log first".into(),
                ));
            }
        }
        "member.add" => {
            let done = member.is_some_and(|m| m.active && keys_match(m));
            let removed_since = member.is_some_and(|m| !m.active)
                && !matches!(seen, None | Some(Value::Null))
                && seen.and_then(Value::as_str) != Some("removed");
            if !done && removed_since {
                return Err(refused(
                    state,
                    "removed_meanwhile",
                    format!(
                        "member {} was removed meanwhile",
                        text(&data, "user_id").unwrap_or("")
                    ),
                ));
            }
            has(done)
        }
        "member.role" => has(member.is_some_and(|m| Some(m.role.as_str()) == text(&data, "role"))),
        "member.remove" => has(member.is_none_or(|m| !m.active)),
        "member.keys" => has(member.is_some_and(keys_match)),
        "access.set" => {
            // R17-N8: a member's removal takes every access they had, also a
            // queued one; sent after it, the access.set was refused for good.
            let level = data.get("level").and_then(Value::as_str);
            let removed = member.is_some_and(|m| !m.active) && level.is_some();
            let current = text(&data, "folder")
                .and_then(|f| state.access.get(f))
                .and_then(|a| a.get(text(&data, "user_id").unwrap_or("")))
                .map(String::as_str);
            has(removed || current == level)
        }
        "folder.key" => {
            if text(&data, "dek_id").is_some_and(|d| state.dek_index.contains_key(d)) {
                return Ok(None);
            }
            let folder = text(&data, "folder").unwrap_or("");
            let current = rules::current_key(state, folder);
            let prev = text(&data, "prev_dek_id");
            if current != prev {
                return Err(refused(
                    state,
                    "folder_key_moved",
                    format!(
                        "folder {folder} is at key {}, not {}",
                        current.unwrap_or("None"),
                        prev.unwrap_or("None")
                    ),
                ));
            }
            let gen = state.folders.get(folder).map_or(0, Vec::len);
            let mut out = data;
            out.insert("gen".into(), Value::from(gen));
            Some(Value::Object(out))
        }
        "org.recovery" => {
            let pk = data.get("recovery_pk");
            has(state
                .org_recovery
                .values()
                .any(|v| pk.and_then(Value::as_str) == Some(v)))
        }
        "org.recovery.wrap" => has(state.org_recovery_wrap.values().any(|w| *w == data)),
        _ => {
            return Err(refused(
                state,
                "not_remade",
                format!("a lost {kind} is not made again"),
            ))
        }
    })
}

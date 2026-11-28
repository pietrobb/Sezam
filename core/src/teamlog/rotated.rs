//! Sealing the current team keys again to a member who rotated its identity
//! (docs/CORE_UNIFICATION.md step U7e; review 1141a20 H1, goal #369). Once
//! for the desktop (`_seal_to_rotated_members`) and the page
//! (`sealToRotatedMembers`); the phone seals no team keys. They open their
//! own earlier envelopes, seal, push and move the marker.

use std::collections::BTreeSet;

use serde::Deserialize;
use serde_json::{json, Value};

use super::canonical::parse_body;
use super::rules::{current_key, is_admin, key_recipients, may_seal};
use super::State;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealsIn {
    /// the log as this device trusts it
    pub state: State,
    /// the last seq whose member.keys records this device saw to (-1: none)
    pub done: i64,
    /// the bodies of the log's records after `done`
    pub bodies: Vec<String>,
    pub user_id: String,
    /// the founder is confirmed (an admin seals nothing before)
    pub trusted: bool,
    /// a pending re-key or revocation seals to the log's recipients itself
    #[serde(default)]
    pub blocked: bool,
    /// members a queued removal of this device takes out
    #[serde(default)]
    pub withheld: BTreeSet<String>,
    /// the log with this device's queued changes on it; none: nothing queued
    pub projected: Option<State>,
}

fn nothing(advance: bool) -> Value {
    json!({"seal": [], "advance": advance})
}

/// `{seal: [{folder, dek_id, user_id, encryption_pk, level}], advance}`: the
/// envelopes due (the client skips a key it does not hold, and one its own
/// envelope at that level already seals to that key), and whether the
/// marker moves to the head once they are out.
pub fn seals(i: SealsIn) -> Result<Value, String> {
    if i.blocked || i.done >= i.state.head_seq {
        return Ok(nothing(false));
    }
    let mut rotated = BTreeSet::new();
    for text in &i.bodies {
        let body = parse_body(text, None).map_err(|e| e.to_json().to_string())?;
        let seq = body.get("seq").and_then(Value::as_i64).unwrap_or(-1);
        let kind = body.get("type").and_then(Value::as_str);
        let member = body
            .get("data")
            .and_then(|d| d.get("user_id"))
            .and_then(Value::as_str);
        if let (Some("member.keys"), Some(uid)) = (kind, member) {
            if seq > i.done && seq <= i.state.head_seq && uid != i.user_id {
                rotated.insert(uid.to_string());
            }
        }
    }
    if rotated.is_empty() {
        return Ok(nothing(true));
    }
    let admin = is_admin(&i.state, &i.user_id);
    if admin && !i.trusted {
        return Ok(nothing(false)); // retried once the founder is confirmed
    }
    let mut seal = Vec::new();
    let mut waiting = false;
    for folder in i.state.folders.keys().filter(|_| admin) {
        // docs/SYNC_SINGLE_SOURCE.md 3.5: a folder a queued removal leaves
        // stale gets no envelope under the key that removal retires.
        if may_seal(&i.state, folder) && i.projected.as_ref().is_some_and(|p| !may_seal(p, folder))
        {
            waiting = true;
            continue;
        }
        let Some(dek_id) = current_key(&i.state, folder).filter(|_| may_seal(&i.state, folder))
        else {
            continue; // a re-key seals to the current keys
        };
        for (uid, encryption_pk, level) in key_recipients(&i.state, folder) {
            if rotated.contains(&uid) && !i.withheld.contains(&uid) {
                seal.push(json!({
                    "folder": folder, "dek_id": dek_id, "user_id": uid,
                    "encryption_pk": encryption_pk, "level": level,
                }));
            }
        }
    }
    Ok(json!({"seal": seal, "advance": !waiting}))
}

//! Decisions from a replayed state (design §4.3). Unknown is always "no".

use serde_json::{json, Map, Value};

use super::{State, FORMAT_VERSION};

pub fn is_team_folder(state: &State, folder: &str) -> bool {
    state.folders.contains_key(folder)
}

pub fn current_key<'a>(state: &'a State, folder: &str) -> Option<&'a str> {
    state
        .folders
        .get(folder)
        .and_then(|gens| gens.last())
        .map(|g| g.dek_id.as_str())
}

/// ("current", gen) / ("old", gen) / ("unknown", None) for a key of `folder`.
pub fn key_generation(state: &State, folder: &str, dek_id: &str) -> (&'static str, Option<i64>) {
    match state.dek_index.get(dek_id) {
        Some((f, gen)) if f == folder => {
            let last = state.folders.get(folder).map_or(0, |g| g.len() as i64) - 1;
            (if *gen == last { "current" } else { "old" }, Some(*gen))
        }
        _ => ("unknown", None),
    }
}

pub fn is_stale(state: &State, folder: &str) -> bool {
    state.stale.get(folder).is_some_and(|s| !s.is_empty())
}

/// New content or keys may be sealed under the folder's current key.
pub fn may_seal(state: &State, folder: &str) -> bool {
    is_team_folder(state, folder) && !is_stale(state, folder)
}

pub fn is_admin(state: &State, user_id: &str) -> bool {
    state
        .members
        .get(user_id)
        .is_some_and(|m| m.active && m.role == "admin")
}

/// The org recovery key the log names for `user_id`, an active admin.
pub fn recovery_key<'a>(state: &'a State, user_id: &str) -> Option<&'a str> {
    if !is_admin(state, user_id) {
        return None;
    }
    state.org_recovery.get(user_id).map(String::as_str)
}

/// The KEK wrap the log holds for that admin's named recovery key.
pub fn recovery_wrap<'a>(state: &'a State, user_id: &str) -> Option<&'a Map<String, Value>> {
    recovery_key(state, user_id)?;
    state.org_recovery_wrap.get(user_id)
}

fn level_of<'a>(state: &'a State, folder: &str, user_id: &str) -> Option<&'a str> {
    state
        .access
        .get(folder)
        .and_then(|a| a.get(user_id))
        .map(String::as_str)
}

pub fn may_write(state: &State, folder: &str, user_id: &str) -> bool {
    match state.members.get(user_id) {
        Some(m) if m.active && is_team_folder(state, folder) => {
            m.role == "admin" || level_of(state, folder, user_id) == Some("write")
        }
        _ => false,
    }
}

/// Exactly the members a new key of `folder` is sealed to: (user_id,
/// encryption_pk, level).
pub fn key_recipients(state: &State, folder: &str) -> Vec<(String, String, String)> {
    if !is_team_folder(state, folder) {
        return Vec::new();
    }
    state
        .access
        .get(folder)
        .into_iter()
        .flatten()
        .filter_map(|(uid, level)| {
            let m = state.members.get(uid).filter(|m| m.active)?;
            Some((uid.clone(), m.encryption_pk.clone(), level.clone()))
        })
        .collect()
}

pub fn may_hold_key(state: &State, user_id: &str, dek_id: &str) -> bool {
    let (Some((folder, gen)), Some(member)) =
        (state.dek_index.get(dek_id), state.members.get(user_id))
    else {
        return false;
    };
    if !member.active {
        return false;
    }
    let Some(gens) = state.folders.get(folder) else {
        return false;
    };
    if *gen != gens.len() as i64 - 1 {
        return false;
    }
    // Review 8bc70f7 M1: the admin holds every current key by the role, not
    // by an access.set a handover granted.
    level_of(state, folder, user_id).is_some()
        || gens.last().is_some_and(|g| g.author == user_id)
        || member.role == "admin"
}

fn former_admin(state: &State, folder: &str, user_id: &str) -> bool {
    state
        .former_admins
        .get(folder)
        .is_some_and(|s| s.contains(user_id))
}

/// Why a live folder/item by `user_id` sealed with `dek_id` is not valid,
/// or None. `sealing`: a new write (push); a pulled copy is not refused only
/// because the folder waits for a re-key. `folder`: the team folder at or
/// above the object's parent (None: no team rules). A key the log does not
/// know is only the author's own personal key (`own_dek`), and below a team
/// folder even that needs write access there.
pub fn item_refusal(
    state: &State,
    user_id: &str,
    obj_id: &str,
    folder: Option<&str>,
    dek_id: Option<&str>,
    own_dek: bool,
    sealing: bool,
) -> Option<&'static str> {
    let wrote = |where_: &str| {
        // A pulled copy by an admin who handed the role over while the
        // folder's current key was current was written while admin.
        may_write(state, where_, user_id)
            || (!sealing
                && state.members.get(user_id).is_some_and(|m| m.active)
                && former_admin(state, where_, user_id))
    };
    let found = dek_id.and_then(|d| state.dek_index.get(d));
    let Some((key_folder, _)) = found else {
        let folder = folder?;
        if !own_dek {
            return Some("sealed with a key the team log does not know");
        }
        if !wrote(folder) {
            return Some("team log gives no write access here");
        }
        return None;
    };
    if Some(key_folder.as_str()) != folder && key_folder != obj_id {
        return Some("sealed with another folder's team key");
    }
    if key_generation(state, key_folder, dek_id.unwrap_or_default()).0 != "current" {
        return Some("sealed with an old key generation");
    }
    if sealing && !may_seal(state, key_folder) {
        return Some("folder waits for a re-key");
    }
    if !wrote(key_folder) {
        return Some("team log gives no write access here");
    }
    None
}

/// TL7: one active admin per organisation.
pub fn admin_policy_refusal(state: &State) -> Option<&'static str> {
    let admins = state
        .members
        .keys()
        .filter(|uid| is_admin(state, uid))
        .count();
    (admins > 1).then_some("more than one admin")
}

/// The log rotated `user_id` away from signing key `pk`.
pub fn signing_key_retired(state: &State, user_id: &str, pk: &str) -> bool {
    state.members.get(user_id).is_some_and(|m| {
        m.signing_pk != pk && state.seen_keys.get(pk).is_some_and(|o| o == user_id)
    })
}

/// What today's rules refuse in `body`, a record its own older rules take
/// on top of `state` (review e443cbc H3).
pub fn todays_rules_refusal(state: &State, body: &Map<String, Value>) -> Option<String> {
    let v = body
        .get("v")
        .and_then(Value::as_u64)
        .unwrap_or(FORMAT_VERSION);
    let kind = body.get("type").and_then(Value::as_str).unwrap_or("");
    if v >= FORMAT_VERSION || !["genesis", "member.add", "member.keys"].contains(&kind) {
        return None;
    }
    let data = body.get("data")?.as_object()?;
    let user_id = data.get("user_id")?.as_str()?;
    let current = state.members.get(user_id);
    for name in ["signing_pk", "encryption_pk"] {
        let pk = data.get(name)?.as_str()?;
        let held = current.is_some_and(|m| pk == m.signing_pk || pk == m.encryption_pk);
        if state.seen_keys.get(pk).is_some_and(|o| o == user_id) && !held {
            let seq = body.get("seq").map(Value::to_string).unwrap_or_default();
            return Some(format!(
                "record {seq} gives {user_id} back a key the log retired (rules {FORMAT_VERSION})"
            ));
        }
    }
    None
}

/// A deletion of an object sealed with a team key needs write access there.
pub fn tombstone_refusal(
    state: &State,
    user_id: &str,
    stored_dek_id: Option<&str>,
) -> Option<&'static str> {
    let (folder, _) = stored_dek_id.and_then(|d| state.dek_index.get(d))?;
    (!may_write(state, folder, user_id)).then_some("team log gives no write access here")
}

/// A folder/item leaving the team folder `old_folder` is a removal from it;
/// leaving needs write access in the folder left. `own_personal` (TL7): the
/// account's own object under a key the log does not know may leave for
/// outside every team folder.
pub fn move_refusal(
    state: &State,
    user_id: &str,
    old_folder: Option<&str>,
    new_folder: Option<&str>,
    own_personal: bool,
) -> Option<&'static str> {
    if own_personal && new_folder.is_none() {
        return None;
    }
    match old_folder {
        Some(old) if Some(old) != new_folder && !may_write(state, old, user_id) => {
            Some("team log gives no write access here")
        }
        _ => None,
    }
}

/// An envelope giving `target_id` the key `dek_id` (design §4.3.5), sealed
/// by the admin or by an admin who handed the role over while that key was
/// current (review c78fd19 R13-8).
pub fn envelope_valid(
    state: &State,
    signer_id: &str,
    target_id: &str,
    dek_id: &str,
    level: Option<&str>,
    target_encryption_pk: &str,
) -> bool {
    if !may_hold_key(state, target_id, dek_id) {
        return false;
    }
    let Some((folder, _)) = state.dek_index.get(dek_id) else {
        return false;
    };
    let signer_ok = is_admin(state, signer_id)
        || (state.members.get(signer_id).is_some_and(|m| m.active)
            && former_admin(state, folder, signer_id));
    if !signer_ok {
        return false;
    }
    if state
        .members
        .get(target_id)
        .is_none_or(|m| m.encryption_pk != target_encryption_pk)
    {
        return false;
    }
    let by_role = is_admin(state, target_id).then_some("write");
    level_of(state, folder, target_id).or(by_role) == level
}

/// An envelope giving `target_id` a key the log replaced, which the caller
/// found `target_id` may still open (review c02cc47 R17-L). Sealed to the
/// member's current key by the generation's author, the admin or a former
/// admin of the folder.
pub fn superseded_envelope_valid(
    state: &State,
    signer_id: &str,
    target_id: &str,
    dek_id: &str,
    target_encryption_pk: &str,
) -> bool {
    let (Some((folder, gen)), Some(target), Some(signer)) = (
        state.dek_index.get(dek_id),
        state.members.get(target_id),
        state.members.get(signer_id),
    ) else {
        return false;
    };
    if !target.active || !signer.active {
        return false;
    }
    let Some(gens) = state.folders.get(folder) else {
        return false;
    };
    if *gen == gens.len() as i64 - 1 || target.encryption_pk != target_encryption_pk {
        return false;
    }
    gens.get(*gen as usize)
        .is_some_and(|g| g.author == signer_id)
        || is_admin(state, signer_id)
        || former_admin(state, folder, signer_id)
}

/// The body of the record that would follow `state` (to be signed).
pub fn next_body(state: &State, kind: &str, author: &str, data: &Value) -> Value {
    json!({
        "v": FORMAT_VERSION,
        "seq": state.head_seq + 1,
        "prev": state.head_hash,
        "type": kind,
        "author": author,
        "data": data,
    })
}

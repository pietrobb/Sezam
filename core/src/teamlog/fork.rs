//! A server log that forks from the device's copy (review 18c300f R16-H1,
//! tests/vectors/team_log_fork.json) and the parts a restore is uploaded in
//! (tests/vectors/team_log_restore_parts.json).

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use super::canonical::{canonical, parse_body};
use super::replay::record_hash;
use super::{LogError, LogResult};

fn field<'a>(body: &'a Map<String, Value>, name: &str) -> &'a str {
    body.get(name).and_then(Value::as_str).unwrap_or("")
}

fn data_field<'a>(body: &'a Map<String, Value>, name: &str) -> &'a str {
    body.get("data")
        .and_then(|d| d.get(name))
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// The change a record made, as a device makes it again on another head: a
/// folder.key's generation and a member.keys' proof are bound to the head.
pub fn change_key(body: &Map<String, Value>) -> LogResult<String> {
    let data: Map<String, Value> = body
        .get("data")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(k, _)| *k != "gen" && *k != "new_key_sig")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    canonical(&json!({"type": body.get("type"), "data": data}), None)
}

struct Rec {
    hash: String,
    body: Map<String, Value>,
    key: String,
}

fn parse(records: &[Value]) -> LogResult<Vec<Rec>> {
    records
        .iter()
        .map(|r| {
            let text = r
                .get("body")
                .and_then(Value::as_str)
                .ok_or_else(|| LogError::new("bad_encoding", None, "body is not a string"))?;
            let sig = r.get("sig").and_then(Value::as_str).unwrap_or("");
            let body = parse_body(text, None)?;
            Ok(Rec {
                hash: record_hash(text, sig),
                key: change_key(&body)?,
                body,
            })
        })
        .collect()
}

/// Whether a device follows a server log that forks from its copy. `lost`:
/// the device's records from the fork on; `theirs`: the server's. Refused
/// (Some reason) when the server's side holds a record of this account the
/// device withdrew, a role change or member added by this account that was
/// not lost here, or a key change of this account not lost here that names
/// keys this device does not hold. Else the seqs of this account's lost
/// changes that are not on the server's side, for the device to make again.
pub fn fork_refusal(
    lost: &[Value],
    theirs: &[Value],
    user_id: Option<&str>,
    held_keys: Option<(&str, &str)>,
    withdrawn: &BTreeSet<String>,
) -> LogResult<(Option<String>, Vec<i64>)> {
    let lost = parse(lost)?;
    let theirs = parse(theirs)?;
    let refuse = |why: String| Ok((Some(why), Vec::new()));
    let was: BTreeSet<&str> = lost.iter().map(|r| r.key.as_str()).collect();
    let mine = |body: &Map<String, Value>| user_id.is_some_and(|u| field(body, "author") == u);
    let seq_of = |body: &Map<String, Value>| body.get("seq").and_then(Value::as_i64).unwrap_or(-1);

    for rec in &theirs {
        if !mine(&rec.body) {
            continue;
        }
        let seq = seq_of(&rec.body);
        if withdrawn.contains(&rec.hash) {
            return refuse(format!("its record {seq} is one this device withdrew"));
        }
        let kind = field(&rec.body, "type");
        let new_here = !was.contains(rec.key.as_str());
        if kind == "member.role" && new_here {
            return refuse(format!(
                "its record {seq} changes a role this device did not lose"
            ));
        }
        if kind == "member.add" && new_here {
            return refuse(format!(
                "its record {seq} adds a member this device did not lose"
            ));
        }
        if kind == "member.keys"
            && new_here
            && held_keys
                != Some((
                    data_field(&rec.body, "signing_pk"),
                    data_field(&rec.body, "encryption_pk"),
                ))
        {
            return refuse(format!(
                "its record {seq} names keys this device does not hold"
            ));
        }
    }
    let made: BTreeSet<&str> = theirs.iter().map(|r| r.key.as_str()).collect();
    for pair in lost.windows(2) {
        // A readmit (member.remove + member.add of one member, one append)
        // is on the server's side whole or not at all.
        let (first, second) = (&pair[0], &pair[1]);
        if field(&first.body, "type") == "member.remove"
            && field(&second.body, "type") == "member.add"
            && data_field(&first.body, "user_id") == data_field(&second.body, "user_id")
            && made.contains(first.key.as_str()) != made.contains(second.key.as_str())
        {
            return refuse(format!(
                "it holds one half of the readmit at record {}",
                seq_of(&first.body)
            ));
        }
    }
    // R16-Z SM21: a stale device of this account put the lost log back with
    // one link onto the keys this device holds; the rotations lost here in
    // between are moot.
    let own_rotation = |body: &Map<String, Value>| {
        field(body, "type") == "member.keys"
            && mine(body)
            && user_id.is_some_and(|u| data_field(body, "user_id") == u)
    };
    let on_held = theirs
        .iter()
        .rev()
        .find(|r| own_rotation(&r.body))
        .is_some_and(|r| {
            held_keys
                == Some((
                    data_field(&r.body, "signing_pk"),
                    data_field(&r.body, "encryption_pk"),
                ))
        });
    let mut missing = Vec::new();
    for rec in &lost {
        if made.contains(rec.key.as_str()) || (on_held && own_rotation(&rec.body)) {
            continue;
        }
        if !mine(&rec.body) {
            return refuse(format!(
                "record {} this device saw is not on the server's side (it follows once its author makes that change again)",
                seq_of(&rec.body)
            ));
        }
        missing.push(seq_of(&rec.body));
    }
    Ok((None, missing))
}

/// The hashes of this account's records in `lost` a device goes on without
/// when it follows a fork: it withdraws them (review 18c300f finding 505).
pub fn fork_abandoned(lost: &[Value], user_id: Option<&str>) -> LogResult<Vec<String>> {
    let Some(user_id) = user_id else {
        return Ok(Vec::new());
    };
    Ok(parse(lost)?
        .into_iter()
        .filter(|r| field(&r.body, "author") == user_id)
        .map(|r| r.hash)
        .collect())
}

/// Where the member.remove `bodies[index]` is undone by its author's
/// member.add of the same account in the same run of that author's records.
pub fn readmitted(bodies: &[Map<String, Value>], index: usize) -> Option<usize> {
    let body = bodies.get(index)?;
    if field(body, "type") != "member.remove" {
        return None;
    }
    for (later, other) in bodies.iter().enumerate().skip(index + 1) {
        if field(other, "author") != field(body, "author") {
            return None;
        }
        if field(other, "type") == "member.add"
            && data_field(other, "user_id") == data_field(body, "user_id")
        {
            return Some(later);
        }
    }
    None
}

/// Review c02cc47 R17-L: the end (exclusive) of a restore upload part from
/// `start`, at most `limit` records, not inside a readmit (split, the
/// server took the removal alone). A readmit longer than `limit` is split
/// anyway.
pub fn restore_part_end(bodies: &[Map<String, Value>], start: usize, limit: usize) -> usize {
    let end = (start + limit).min(bodies.len());
    if end == bodies.len() {
        return end;
    }
    for index in start..end {
        if readmitted(bodies, index).is_some_and(|undone| undone >= end) {
            return if index > start { index } else { end };
        }
    }
    end
}

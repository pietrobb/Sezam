//! Following a server log that forks from the device's copy
//! (docs/CORE_UNIFICATION.md step U7d, goal #442, review 18c300f R16-H1).
//! Once for the desktop (`team_log_fork.follow_fork`), the page
//! (`followWebTeamLogFork`) and the phone (`_followFork`); they only fetch
//! the served records, verify signatures, make the lost changes again and
//! store.
//!
//! * [`follows`]: whether a refusal with this cause looks for a fork at all;
//! * [`split`]: with the served records up to the head: where the server's
//!   log forks from the copy, and whether the device follows it that far
//!   ([`super::fork::fork_refusal`]): `stand`, `refusal` or `fork` (with
//!   `relink`: a lost rotation the device links again from its old keys);
//! * [`take`]: once the served records replayed: `stand`, or `follow` with
//!   the changes to make again, the rotation to link again, and the hashes
//!   to withdraw ([`super::fork::fork_abandoned`]).

use std::collections::BTreeSet;

use serde::Deserialize;
use serde_json::{json, Map, Value};

use super::canonical::parse_body;
use super::follow::Pin;
use super::fork::{fork_abandoned, fork_refusal};
use super::replay::record_hash;
use super::rules::{admin_policy_refusal, signing_key_retired};
use super::State;

fn kind(body: &Map<String, Value>) -> &str {
    body.get("type").and_then(Value::as_str).unwrap_or("")
}

/// The refusals a fork may be behind: the log went back, differs at a seq
/// the device saw, or does not replay on its copy.
pub const FOLLOWS: &[&str] = &["went_back", "differs", "does_not_replay"];

/// A lost record of these kinds is made again as the change it made; a
/// genesis or a member.keys is bound to the head it was signed on (R16-M5).
pub const REMADE_KINDS: &[&str] = &[
    "member.add",
    "member.role",
    "member.remove",
    "access.set",
    "folder.key",
    "org.recovery",
    "org.recovery.wrap",
];

fn stand() -> Value {
    json!({"stand": true})
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FollowsIn {
    /// none: an error that is no refusal of the log
    #[serde(default)]
    pub cause: Option<String>,
}

pub fn follows(i: FollowsIn) -> Value {
    json!(i.cause.is_some_and(|c| FOLLOWS.contains(&c.as_str())))
}

fn hash_of(record: &Value) -> Option<String> {
    let body = record.get("body")?.as_str()?;
    let sig = record.get("sig")?.as_str()?;
    Some(record_hash(body, sig))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitIn {
    /// the device's copy, from genesis
    pub local: Vec<Value>,
    /// the server's records, from genesis up to the head it announces
    pub served: Vec<Value>,
    /// heads the device saw before: its copy must still hold them
    #[serde(default)]
    pub pins: Vec<Pin>,
    pub user_id: Option<String>,
    /// the identity keys the device holds (signing, encryption; hex)
    pub held_keys: Option<(String, String)>,
    /// what the device withdrew: never followed back onto
    #[serde(default)]
    pub withdrawn: BTreeSet<String>,
}

pub fn split(i: SplitIn) -> Value {
    for pin in &i.pins {
        let held = usize::try_from(pin.seq)
            .ok()
            .and_then(|seq| i.local.get(seq))
            .and_then(hash_of);
        if !held.is_some_and(|h| pin.hashes.contains(&h)) {
            return stand();
        }
    }
    let differs = i.local.iter().zip(&i.served).position(|(mine, theirs)| {
        match (hash_of(mine), hash_of(theirs)) {
            (Some(a), Some(b)) => a != b,
            _ => true,
        }
    });
    // None: one is a prefix of the other; 0: another genesis.
    let Some(fork) = differs.filter(|&f| f > 0) else {
        return stand();
    };
    let held = i.held_keys.as_ref().map(|(a, b)| (a.as_str(), b.as_str()));
    match fork_refusal(
        &i.local[fork..],
        &i.served[fork..],
        i.user_id.as_deref(),
        held,
        &i.withdrawn,
    ) {
        Err(_) => stand(),
        Ok((Some(refusal), _)) => json!({"refusal": refusal}),
        Ok((None, missing)) => {
            // A lost rotation to link again: only then does the device read
            // the old keys of its unpushed rotation for `take`.
            let relink = i.local[fork..].iter().any(|r| {
                r.get("body")
                    .and_then(Value::as_str)
                    .and_then(|t| parse_body(t, None).ok())
                    .is_some_and(|b| {
                        let seq = b.get("seq").and_then(Value::as_i64);
                        kind(&b) == "member.keys" && seq.is_some_and(|s| missing.contains(&s))
                    })
            });
            json!({"fork": fork, "missing": missing, "relink": relink})
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TakeIn {
    /// the served records, replayed with their signatures checked
    pub state: State,
    /// the head the pull announced
    pub head: Value,
    /// the device's records from the fork on
    pub lost: Vec<Value>,
    /// `split`'s seqs of this account's lost changes to make again
    pub missing: Vec<i64>,
    pub user_id: Option<String>,
    pub held_keys: Option<(String, String)>,
    /// the signing key (hex) of this device's identity rotation the server
    /// has not taken yet; none: a lost member.keys is not linked again
    pub old_signing_pk: Option<String>,
}

/// The lost member.keys `body` links the held keys from the old ones of the
/// device's unpushed rotation, which `state` still names: the device signs
/// it again on that head, so nothing is lost by following (goal #442).
fn linked_again(i: &TakeIn, body: &Map<String, Value>) -> bool {
    let (Some(user_id), Some((signing, encryption)), Some(old)) =
        (&i.user_id, &i.held_keys, &i.old_signing_pk)
    else {
        return false;
    };
    let data = body.get("data").and_then(Value::as_object);
    let named = |k: &str| data.and_then(|d| d.get(k)).and_then(Value::as_str);
    let Some(member) = i.state.members.get(user_id) else {
        return false;
    };
    named("user_id") == Some(user_id)
        && member.active
        && named("signing_pk") == Some(signing)
        && named("encryption_pk") == Some(encryption)
        && member.signing_pk == *old
        && !signing_key_retired(&i.state, user_id, old)
}

pub fn take(i: TakeIn) -> Value {
    let head_seq = i.head.get("seq").and_then(Value::as_i64);
    let head_hash = i.head.get("hash").and_then(Value::as_str);
    if head_seq != Some(i.state.head_seq)
        || head_hash != Some(i.state.head_hash.as_str())
        || admin_policy_refusal(&i.state).is_some()
    {
        return stand();
    }
    let mut bodies = Vec::new();
    for record in &i.lost {
        let Some(text) = record.get("body").and_then(Value::as_str) else {
            return stand();
        };
        let Ok(body) = parse_body(text, None) else {
            return stand();
        };
        let seq = body.get("seq").and_then(Value::as_i64).unwrap_or(-1);
        if i.missing.contains(&seq) {
            bodies.push(body);
        }
    }
    let (links, remake): (Vec<_>, Vec<_>) =
        bodies.into_iter().partition(|b| kind(b) == "member.keys");
    if remake.iter().any(|b| !REMADE_KINDS.contains(&kind(b)))
        || links.len() > 1
        || (!remake.is_empty() && i.user_id.is_none())
        || links.first().is_some_and(|b| !linked_again(&i, b))
    {
        return stand();
    }
    let Ok(abandoned) = fork_abandoned(&i.lost, i.user_id.as_deref()) else {
        return stand();
    };
    json!({"follow": {
        "remake": remake,
        "link": links.into_iter().next(),
        "abandoned": abandoned,
    }})
}

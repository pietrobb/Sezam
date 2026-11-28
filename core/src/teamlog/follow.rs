//! Following the server's team log (docs/CORE_UNIFICATION.md step U7b): when
//! a device takes the log a pull announces, and when it refuses it with which
//! cause (INV-7, tests/vectors/team_log_mismatch.json). Once for the desktop
//! (`TeamLogMixin._sync_team_log`), the page (`syncWebTeamLog`) and the phone
//! (`syncTeamLog`); they only fetch, verify signatures and store.
//!
//! Three steps, each an answer the client acts on:
//! * [`plan`]: from what the device holds and the head the pull announces:
//!   `none` (no log, none expected), `same` (the head this device holds),
//!   `fetch` (records after `since`, up to `upto`), `check_served` (a cause
//!   that offers to forget the pin, borne out only by the records served,
//!   goal #440), or `refused`;
//! * [`served`]: the `check_served` answer once the first served record is known;
//! * [`caught_up`]: after the records were fetched and replayed: `accept` or `refused`.
//!
//! The head is unsigned: every answer that names a loss is checked against
//! the records, never taken from the head alone.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// INV-7: why a device refuses the server's team log, and for which causes
/// "forget the pinned team log" is offered: only where the log is missing or
/// a new one starts (another server, a reseed). A fork, a log going back or
/// one that does not replay is a server that lies, never forgotten. INV-8:
/// every offer is a risk (a hostile server drops its log just as easily).
pub const CAUSES: &[(&str, bool)] = &[
    ("confirmed_genesis", true), // not the genesis confirmed out of band
    ("log_gone", true),          // no log, while the device holds or pins one
    ("other_genesis", true),     // the log starts with another genesis
    ("left_earlier_log", false), // no log, and the device left one: it waits for the new one
    ("went_back", false),        // the head is behind what the device saw
    ("differs", false),          // another record at a seq the device saw (a fork)
    ("does_not_replay", false),
    ("short_of_head", false), // the records do not reach the announced head
    ("head_genesis", false),  // the records start with another genesis than the head names
    ("refused_at_head", false), // TL7: a head the server must refuse
    ("local_damaged", false), // the device's own copy does not replay or fails its pins
    ("anchor_conflict", true), // the account keys name another log than the device holds or pins
];

pub fn causes() -> Value {
    Value::Object(
        CAUSES
            .iter()
            .map(|(c, f)| ((*c).to_string(), Value::Bool(*f)))
            .collect(),
    )
}

fn refused(cause: &str, detail: String) -> Value {
    let forget = CAUSES.iter().any(|(c, f)| *c == cause && *f);
    json!({"refused": {"cause": cause, "detail": detail, "forget": forget}})
}

/// A head the device holds: its own copy's (seq, hash, genesis).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tip {
    pub seq: i64,
    pub hash: Option<String>,
    pub genesis_hash: Option<String>,
}

/// A head the device saw before (the page's and the phone's checkpoint pin,
/// the desktop's damaged copy): the record at `seq` is one of `hashes`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub seq: i64,
    pub hashes: Vec<String>,
}

/// A cause that offers to forget, still to be borne out by the records served.
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub genesis: Option<String>,
    pub cause: String,
    pub detail: String,
    pub who: String,
}

fn head_field<'a>(head: &'a Value, key: &str) -> Option<&'a str> {
    head.get(key).and_then(Value::as_str)
}

fn who_or_default(who: Option<String>) -> String {
    who.unwrap_or_else(|| "this device".into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanIn {
    /// the pull's team_log_head; null: the server names no log
    pub head: Value,
    /// the copy this device holds and trusts
    pub local: Option<Tip>,
    #[serde(default)]
    pub pins: Vec<Pin>,
    /// the genesis pinned without a copy (or with one)
    pub pinned_genesis: Option<String>,
    pub confirmed_genesis: Option<String>,
    /// the device left a log, and no founding of a new one is under way
    #[serde(default)]
    pub left_earlier_log: bool,
    /// how the messages name the device ("this browser", "this phone")
    pub who: Option<String>,
}

pub fn plan(i: PlanIn) -> Value {
    let who = who_or_default(i.who);
    let check = |genesis: Option<&str>, cause: &str, detail: String| {
        json!({"check_served": Check {
            genesis: genesis.map(str::to_string),
            cause: cause.into(),
            detail,
            who: who.clone(),
        }})
    };
    let head = (!i.head.is_null()).then_some(&i.head);
    let head_genesis = head.and_then(|h| head_field(h, "genesis_hash"));
    if let Some(confirmed) = i.confirmed_genesis.as_deref() {
        if head_genesis != Some(confirmed) {
            return check(
                Some(confirmed),
                "confirmed_genesis",
                "does not match the independently confirmed genesis".into(),
            );
        }
    }
    let named = i
        .local
        .as_ref()
        .and_then(|l| l.genesis_hash.as_deref())
        .or(i.pinned_genesis.as_deref());
    let Some(head) = head else {
        if i.local.is_some() || !i.pins.is_empty() || named.is_some() {
            return check(
                named,
                "log_gone",
                "is gone (a server restored from a backup, or another server)".into(),
            );
        }
        if i.left_earlier_log {
            // Review 8bc70f7 M2: a device that left a log does not fall back
            // to the rules from before any log because a server sends none.
            return refused(
                "left_earlier_log",
                format!(
                    "is missing, and {who} left an earlier team log: it waits for the team's \
                     new log (the admin founds it) and its confirmed founder"
                ),
            );
        }
        return json!({"none": true});
    };
    if let Some(named) = named {
        if head_genesis != Some(named) {
            return check(
                Some(named),
                "other_genesis",
                format!("starts with another genesis than {who} saw"),
            );
        }
    }
    let local_seq = i.local.as_ref().map_or(-1, |l| l.seq);
    let seen = i.pins.iter().map(|p| p.seq).fold(local_seq, i64::max);
    let raw_seq = head.get("seq").cloned().unwrap_or(Value::Null);
    let seq = match raw_seq.as_i64() {
        Some(seq) if seq >= seen => seq,
        _ => return refused("went_back", format!("went back (head {raw_seq} < {seen})")),
    };
    let hash = head_field(head, "hash");
    for pin in i.pins.iter().filter(|p| p.seq == seq) {
        if !hash.is_some_and(|h| pin.hashes.iter().any(|p| p == h)) {
            return refused("differs", format!("differs at record {seq}"));
        }
    }
    if let Some(local) = i.local.as_ref().filter(|l| l.seq == seq) {
        if hash != local.hash.as_deref() {
            return refused("differs", format!("differs at record {seq}"));
        }
        return json!({"same": true});
    }
    json!({"fetch": {"since": local_seq, "upto": seq}})
}

/// What the first record served says (None: the server serves no record).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct First {
    pub genesis: Option<String>,
    pub error: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServedIn {
    pub check: Check,
    /// the pull announced a head
    pub head_shown: bool,
    pub first: Option<First>,
}

/// A cause that offers to forget, only as far as the records served bear it
/// out: no record while the head says none is the log gone; a first record
/// that is the device's genesis makes the head a lie (head_genesis); another
/// genesis is the loss named, or other_genesis for a log called gone.
pub fn served(i: ServedIn) -> Value {
    let c = i.check;
    let Some(first) = i.first else {
        if !i.head_shown {
            return refused(&c.cause, c.detail);
        }
        return refused(
            "short_of_head",
            "does not reach the head it announced".into(),
        );
    };
    if let Some(e) = first.error {
        return refused("does_not_replay", format!("does not replay: {e}"));
    }
    if first.genesis.is_some() && first.genesis == c.genesis {
        return refused(
            "head_genesis",
            "head names another genesis than the records it serves".into(),
        );
    }
    if c.cause == "log_gone" {
        return refused(
            "other_genesis",
            format!("starts with another genesis than {} saw", c.who),
        );
    }
    refused(&c.cause, c.detail)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaughtUpIn {
    pub head: Value,
    /// the seq the fetch started after (the plan's `since`)
    pub since: i64,
    #[serde(default)]
    pub pins: Vec<Pin>,
    /// the hashes of the records fetched and replayed, from seq since + 1
    pub fetched: Vec<String>,
    /// the replay of the next page failed with this
    pub replay_error: Option<String>,
    /// the state after the fetched records
    pub state: Tip,
    /// record hashes this device withdrew (R16-H1)
    #[serde(default)]
    pub withdrawn: Vec<String>,
    /// TL7 on the state reached (`admin_policy_refusal`)
    pub admin_refusal: Option<String>,
    pub who: Option<String>,
}

pub fn caught_up(i: CaughtUpIn) -> Value {
    let who = who_or_default(i.who);
    let at = |seq: i64| {
        usize::try_from(seq - i.since - 1)
            .ok()
            .and_then(|k| i.fetched.get(k))
    };
    for pin in &i.pins {
        if at(pin.seq).is_some_and(|h| !pin.hashes.contains(h)) {
            return refused("differs", format!("differs at record {}", pin.seq));
        }
    }
    if let Some(e) = i.replay_error {
        return refused("does_not_replay", format!("does not replay: {e}"));
    }
    let head_seq = i.head.get("seq").and_then(Value::as_i64);
    if head_seq != Some(i.state.seq) || head_field(&i.head, "hash") != i.state.hash.as_deref() {
        return refused(
            "short_of_head",
            "does not reach the head it announced".into(),
        );
    }
    if head_field(&i.head, "genesis_hash") != i.state.genesis_hash.as_deref() {
        return refused(
            "head_genesis",
            "genesis differs from the head it announced".into(),
        );
    }
    if let Some(k) = i.fetched.iter().position(|h| i.withdrawn.contains(h)) {
        // R16-H1: the server kept a record it refused, or one this device went on without.
        return refused(
            "differs",
            format!(
                "holds record {}, which {who} withdrew (the server refused it, or {who} went on without it)",
                i.since + 1 + k as i64
            ),
        );
    }
    if let Some(r) = i.admin_refusal {
        // TL7: the server refuses such an append; a head with it is not followed.
        return refused("refused_at_head", format!("is refused at its head: {r}"));
    }
    json!({"accept": true})
}

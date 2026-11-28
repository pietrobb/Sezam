//! Why a device refuses its own team log before asking the server
//! (docs/CORE_UNIFICATION.md step U7f, INV-7, capability run 707): a trust
//! record it cannot open or a copy that is damaged (`local_damaged`), or
//! account keys that name another log than the device holds or pins
//! (`anchor_conflict`). Once for the desktop (`_local_team_state`,
//! `record_account_anchor`, `import_account_anchor`), the page
//! (`webLocalTeamLogRefusal`) and the phone (`_loadTeamLog`); they read and
//! unseal what they hold and replay it with libsodium, never compare.

use serde::Deserialize;
use serde_json::{json, Value};

use super::follow::CAUSES;

/// The first record of the device's copy.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Held {
    /// its genesis hash, replayed alone with its signature checked; none
    /// when it does not replay
    pub genesis: Option<String>,
    /// the hash the device stored with it, if it stores one
    #[serde(default)]
    pub stored: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalIn {
    /// a trust record (pin, list of logs left, anchor, ledger) that does not
    /// open here: the client's reason
    #[serde(default)]
    pub unreadable: Option<String>,
    /// the genesis the account keys name
    pub anchor: Option<String>,
    /// the logs this device left
    #[serde(default)]
    pub forgotten: Vec<String>,
    /// the genesis confirmed out of band
    pub confirmed: Option<String>,
    /// the genesis other pins name (a checkpoint, the copy seen before)
    #[serde(default)]
    pub pins: Vec<Option<String>>,
    pub held: Option<Held>,
    /// the client's replay or storage check of its whole copy failed: why
    #[serde(default)]
    pub copy_error: Option<String>,
}

/// The genesis the copy holds: its first record once it replays as one and
/// matches the hash stored with it. Capability run 418: a damaged first
/// record named its own hash as another genesis, so local damage (repaired
/// by the next pull, under the pins) was refused as anchor_conflict.
pub fn held_genesis(held: &Held) -> Option<&str> {
    let genesis = held.genesis.as_deref()?;
    match held.stored.as_deref() {
        Some(stored) if stored != genesis => None,
        _ => Some(genesis),
    }
}

/// Does `anchor` conflict with what the device pins or holds? An anchor in
/// the logs this device left names nothing.
pub fn anchor_conflicts(i: &LocalIn) -> bool {
    let Some(anchor) = i.anchor.as_deref() else {
        return false;
    };
    if i.forgotten.iter().any(|g| g == anchor) {
        return false;
    }
    std::iter::once(i.confirmed.as_deref())
        .chain(i.pins.iter().map(Option::as_deref))
        .chain(std::iter::once(i.held.as_ref().and_then(held_genesis)))
        .flatten()
        .any(|g| g != anchor)
}

fn refusal(cause: &str, what: &str, detail: Option<&str>) -> Value {
    let forget = CAUSES.iter().any(|(c, f)| *c == cause && *f);
    json!({"cause": cause, "what": what, "detail": detail, "forget": forget})
}

/// Null, or `{cause, what, detail, forget}`: `what` is `trust` (a record does
/// not open), `anchor` or `copy`; in that order.
pub fn refusal_of(i: LocalIn) -> Value {
    if let Some(why) = i.unreadable.as_deref() {
        return refusal("local_damaged", "trust", Some(why));
    }
    if anchor_conflicts(&i) {
        return refusal("anchor_conflict", "anchor", None);
    }
    if let Some(why) = i.copy_error.as_deref() {
        return refusal("local_damaged", "copy", Some(why));
    }
    Value::Null
}

//! The signed team log (docs/DESIGN_TEAM_LOG.md) once, for the desktop, the
//! server, the web page and the phone (docs/CORE_UNIFICATION.md step U1).
//!
//! The log is an append-only, hash-chained list of signed records that says
//! who is a member, who may access which shared folder and which key is the
//! current key of a folder. Every side replays it here and asks the replayed
//! state; anything the log does not say is a "no".
//!
//! Signatures are not checked here: each side keeps checking them with its
//! own libsodium (an Ed25519 port differs at the edges: small-order points,
//! non-canonical encodings). A replay therefore runs twice. The first run
//! ([`replay::checks`]) takes every signature as good and names the checks
//! in order; the side runs them and the second run ([`replay::replay`]) is
//! told how many passed from the start. The first one that did not is the
//! record's `bad_signature` (or `bad_new_key_signature`), as before.

pub mod canonical;
pub mod follow;
pub mod fork;
pub mod fork_follow;
pub mod ops;
pub mod replay;
pub mod resolve;
pub mod rotated;
pub mod rules;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

/// A body's "v" names the rules its record is judged by: 1 = before review
/// 1141a20 (a member could get a retired key back); 2 = retired keys stay
/// retired. New records are written with the newest.
pub const RULES_VERSIONS: [u64; 2] = [1, 2];
pub const FORMAT_VERSION: u64 = 2;
pub const SIG_DOMAIN: &str = "sezam-team-log-v1\0";
pub const HASH_DOMAIN: &str = "sezam-team-log-hash-v1\0";
pub const NEW_KEY_DOMAIN: &str = "sezam-team-log-newkey-v1\0";
pub const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub const MAX_INT: u64 = (1 << 53) - 1;

/// A record breaks a rule. Replay stops; nothing may be decided from it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LogError {
    pub code: String,
    pub seq: Option<i64>,
    pub detail: String,
}

impl LogError {
    pub fn new(code: &str, seq: Option<i64>, detail: &str) -> Self {
        LogError {
            code: code.to_string(),
            seq,
            detail: detail.to_string(),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({"code": self.code, "seq": self.seq, "detail": self.detail})
    }
}

pub type LogResult<T> = Result<T, LogError>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub signing_pk: String,
    pub encryption_pk: String,
    pub role: String,
    pub active: bool,
}

/// One generation of a folder's key and the admin who made it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Generation {
    pub dek_id: String,
    pub author: String,
}

/// The replayed state, whole: a side keeps it between calls as it is. No
/// field has a default (review c02cc47: a permissive `#[serde(default)]`
/// let a truncated state pass as an empty one).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub org: String,
    pub genesis_hash: String,
    pub head_seq: i64,
    pub head_hash: String,
    pub members: BTreeMap<String, Member>,
    /// folder -> its keys by generation
    pub folders: BTreeMap<String, Vec<Generation>>,
    pub access: BTreeMap<String, BTreeMap<String, String>>,
    /// folder -> members who lost access but may still know the current key
    pub stale: BTreeMap<String, BTreeSet<String>>,
    /// public key (hex) -> the account the log gave it to
    pub seen_keys: BTreeMap<String, String>,
    /// dek_id -> (folder, generation)
    pub dek_index: BTreeMap<String, (String, i64)>,
    /// folder -> admins handed over while its current key was current: what
    /// they sealed with it then is still theirs (review 1141a20).
    pub former_admins: BTreeMap<String, BTreeSet<String>>,
    /// the rules version of the last record (0: no log yet)
    pub rules: u64,
    /// admin -> org recovery signing key (hex)
    pub org_recovery: BTreeMap<String, String>,
    /// admin -> the KEK wrap of that key (org.recovery.wrap data)
    pub org_recovery_wrap: BTreeMap<String, Map<String, Value>>,
}

impl Default for State {
    fn default() -> Self {
        State {
            org: String::new(),
            genesis_hash: String::new(),
            head_seq: -1,
            head_hash: ZERO_HASH.to_string(),
            members: BTreeMap::new(),
            folders: BTreeMap::new(),
            access: BTreeMap::new(),
            stale: BTreeMap::new(),
            seen_keys: BTreeMap::new(),
            dek_index: BTreeMap::new(),
            former_admins: BTreeMap::new(),
            rules: 0,
            org_recovery: BTreeMap::new(),
            org_recovery_wrap: BTreeMap::new(),
        }
    }
}

impl State {
    /// The comparable form the decision vectors (tests/vectors/team_log.json)
    /// hold.
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        if !self.org_recovery.is_empty() {
            out.insert("org_recovery".into(), json!(self.org_recovery));
        }
        if !self.org_recovery_wrap.is_empty() {
            out.insert("org_recovery_wrap".into(), json!(self.org_recovery_wrap));
        }
        out.insert("rules".into(), json!(self.rules));
        out.insert("org".into(), json!(self.org));
        out.insert("genesis_hash".into(), json!(self.genesis_hash));
        out.insert("head_seq".into(), json!(self.head_seq));
        out.insert("head_hash".into(), json!(self.head_hash));
        let members: Map<String, Value> = self
            .members
            .iter()
            .map(|(uid, m)| {
                (
                    uid.clone(),
                    json!({
                        "signing_pk": m.signing_pk,
                        "encryption_pk": m.encryption_pk,
                        "role": m.role,
                        "active": if m.active { 1 } else { 0 },
                    }),
                )
            })
            .collect();
        out.insert("members".into(), Value::Object(members));
        let folders: Map<String, Value> = self
            .folders
            .iter()
            .map(|(f, gens)| {
                (
                    f.clone(),
                    json!(gens.iter().map(|g| g.dek_id.clone()).collect::<Vec<_>>()),
                )
            })
            .collect();
        out.insert("folders".into(), Value::Object(folders));
        let access: Map<String, Value> = self
            .access
            .iter()
            .filter(|(_, a)| !a.is_empty())
            .map(|(f, a)| (f.clone(), json!(a)))
            .collect();
        out.insert("access".into(), Value::Object(access));
        let stale: Map<String, Value> = self
            .stale
            .iter()
            .filter(|(_, s)| !s.is_empty())
            .map(|(f, s)| (f.clone(), json!(s)))
            .collect();
        out.insert("stale".into(), Value::Object(stale));
        Value::Object(out)
    }
}

/// A string field of record data (validated bodies always have it).
pub(crate) fn text<'a>(data: &'a Map<String, Value>, name: &str, seq: i64) -> LogResult<&'a str> {
    data.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| LogError::new("bad_schema", Some(seq), name))
}

/// A nullable string field of record data.
pub(crate) fn opt_text<'a>(
    data: &'a Map<String, Value>,
    name: &str,
    seq: i64,
) -> LogResult<Option<&'a str>> {
    match data.get(name) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        _ => Err(LogError::new("bad_schema", Some(seq), name)),
    }
}

pub(crate) fn int(data: &Map<String, Value>, name: &str, seq: i64) -> LogResult<i64> {
    data.get(name)
        .and_then(Value::as_u64)
        .map(|n| n as i64)
        .ok_or_else(|| LogError::new("bad_schema", Some(seq), name))
}

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}

/// Lowercase hex only (the schema allows no other).
pub(crate) fn from_hex(text: &str) -> Option<Vec<u8>> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .chunks(2)
        .map(|pair| Some(nibble(pair[0])? << 4 | nibble(pair[1])?))
        .collect()
}

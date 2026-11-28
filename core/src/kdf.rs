//! Argon2id parameter bounds (docs/CORE_UNIFICATION.md U6, domain E): which
//! parameters a client derives a password with. One copy; it replaced the
//! server's AccountKdfParams bounds, the desktop's server_account_kdf floor
//! and _validate_sezam_key_kdf, the web's normalizeKdfParams clamp and
//! validateSezamKeyKdf, and the phone's accountKdfParams and
//! _validateSezamKeyMetadata ranges. The derivation stays with each
//! platform's Argon2.

use serde_json::{json, Map, Value};

/// time_cost, memory_cost (KiB), parallelism.
#[derive(Clone, Copy)]
pub struct Params {
    pub time: u64,
    pub memory: u64,
    pub lanes: u64,
}

/// Account params (spec 7.2 hard floor, lockout review #6 cap): what the
/// server stores and every client derives the account KEK with.
const ACCOUNT_TIME: (u64, u64) = (2, 20);
const ACCOUNT_MEMORY: (u64, u64) = (65_536, 262_144);
const ACCOUNT_LANES: (u64, u64) = (1, 8);
/// Params written before the 256 MiB cap, kept as they are (any other value
/// derives a KEK that opens nothing): a stored account, a pending migration.
pub const STORED_MAX_MEMORY: u64 = 1_048_576;
/// A file or a pre-anchor state records what its vault was made with, also
/// below the account floor.
pub const RECORDED_TIME: (u64, u64) = (1, 20);
pub const RECORDED_MEMORY_MIN: u64 = 8_192;
pub const RECORDED_LANES: (u64, u64) = (1, 16);

fn within(value: u64, (low, high): (u64, u64)) -> bool {
    (low..=high).contains(&value)
}

/// Why the account params are not derived with, or None. `local`: the
/// params this vault itself was made with, which lower the floor (review
/// d615826: a server's cheaper params for a password change elsewhere made
/// the auth proof crackable offline). `stored`: params from before the cap.
pub fn account_refusal(p: Params, local: Option<Params>, stored: bool) -> Option<&'static str> {
    let (time_min, memory_min) = match local {
        Some(l) => (ACCOUNT_TIME.0.min(l.time), ACCOUNT_MEMORY.0.min(l.memory)),
        None => (ACCOUNT_TIME.0, ACCOUNT_MEMORY.0),
    };
    let memory_max = if stored {
        STORED_MAX_MEMORY
    } else {
        ACCOUNT_MEMORY.1
    };
    if p.time < time_min || p.memory < memory_min {
        Some("below the minimum")
    } else if !within(p.time, (time_min, ACCOUNT_TIME.1))
        || !within(p.memory, (memory_min, memory_max))
        || !within(p.lanes, ACCOUNT_LANES)
    {
        Some("outside the account bounds")
    } else {
        None
    }
}

/// Why a .sezam-key backup's params are refused, or None (the message names
/// the field). `stored`: a pending migration of params from before the cap.
pub fn sezam_key_refusal(salt_len: u64, p: Params, stored: bool) -> Option<&'static str> {
    let memory_max = if stored {
        STORED_MAX_MEMORY
    } else {
        ACCOUNT_MEMORY.1
    };
    if !within(salt_len, (16, 64)) {
        Some("Invalid .sezam-key Argon2 salt length")
    } else if !within(p.time, RECORDED_TIME) {
        Some("Invalid .sezam-key Argon2 time cost")
    } else if !within(p.memory, (RECORDED_MEMORY_MIN, memory_max)) {
        Some("Invalid .sezam-key Argon2 memory cost")
    } else if !within(p.lanes, RECORDED_LANES) {
        Some("Invalid .sezam-key Argon2 parallelism")
    } else {
        None
    }
}

fn fields(input: &Value, allowed: &[&str]) -> Result<Map<String, Value>, String> {
    let map = input.as_object().ok_or("input is a JSON object")?;
    if let Some(k) = map.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(format!("unknown field {k:?}"));
    }
    Ok(map.clone())
}

/// A field that is not a non-negative integer is a refusal, not an error:
/// the params come from the server or a file.
fn number(map: &Map<String, Value>, name: &str) -> Option<u64> {
    map.get(name).and_then(Value::as_u64)
}

fn params(map: &Map<String, Value>) -> Option<Params> {
    Some(Params {
        time: number(map, "time_cost")?,
        memory: number(map, "memory_cost")?,
        lanes: number(map, "parallelism")?,
    })
}

fn flag(map: &Map<String, Value>, name: &str) -> Result<bool, String> {
    match map.get(name) {
        None => Ok(false),
        Some(v) => v.as_bool().ok_or(format!("{name} must be true or false")),
    }
}

/// hash_len, where given, is 64 (32-byte KEK + 32-byte auth proof).
fn hash_len_ok(map: &Map<String, Value>) -> bool {
    map.get("hash_len").is_none_or(|h| h.as_u64() == Some(64))
}

pub fn run(op: &str, input: &str) -> Option<Result<Value, String>> {
    if !matches!(op, "account_kdf_refusal" | "sezam_key_kdf_refusal") {
        return None;
    }
    let out = (|| -> Result<Value, String> {
        let input: Value = serde_json::from_str(input).map_err(|e| format!("bad input: {e}"))?;
        let common = [
            "time_cost",
            "memory_cost",
            "parallelism",
            "hash_len",
            "stored",
        ];
        Ok(match op {
            "account_kdf_refusal" => {
                let map = fields(&input, &[&common[..], &["local"]].concat())?;
                let local = match map.get("local") {
                    None | Some(Value::Null) => None,
                    Some(l) => Some(
                        params(&fields(l, &["time_cost", "memory_cost", "parallelism"])?)
                            .ok_or("local params must be non-negative integers")?,
                    ),
                };
                let stored = flag(&map, "stored")?;
                let refusal = match params(&map) {
                    None => Some("missing or not integers"),
                    Some(_) if !hash_len_ok(&map) => Some("hash_len must be 64"),
                    Some(p) => account_refusal(p, local, stored),
                };
                json!(refusal)
            }
            "sezam_key_kdf_refusal" => {
                let map = fields(&input, &[&common[..], &["salt_len"]].concat())?;
                let stored = flag(&map, "stored")?;
                let refusal = match (number(&map, "salt_len"), params(&map)) {
                    (Some(salt_len), Some(p)) if hash_len_ok(&map) => {
                        sezam_key_refusal(salt_len, p, stored)
                    }
                    _ => Some("Invalid .sezam-key Argon2 parameters"),
                };
                json!(refusal)
            }
            _ => unreachable!(),
        })
    })();
    Some(out)
}

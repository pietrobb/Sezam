//! Data formats without secrets (docs/CORE_UNIFICATION.md U6, domain E): the
//! bytes and sizes every client and the server must agree on. One copy; it
//! replaced aead.build_aad, padding.padded_size, sync_limits.split_for_push and
//! normalize_username in Python (desktop and server), app.js and the phone.
//! Encryption itself stays with each platform's libsodium.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::teamlog::{from_hex, to_hex};

/// XChaCha20-Poly1305 envelope (spec 2.6).
pub const ENVELOPE_ALG: u8 = 0x01;
pub const SCHEMA_VERSION: u8 = 0x01;
pub const AAD_LEN: usize = 59;
const MAX_PADDING: u64 = 0xFFFF;
const BUCKET: u64 = 0x10000;
/// What one POST /api/sync may carry (review 526419e #1; server
/// models/schemas.py MAX_SYNC_OBJECTS, MAX_REQUEST_BODY_BYTES minus room for
/// the request's own fields).
pub const MAX_PUSH_OBJECTS: usize = 1_000;
pub const MAX_PUSH_REQUEST_BYTES: u64 = 15 * 1024 * 1024;

/// An id as 26 bytes: at most 26 ASCII characters without NUL, padded with NUL.
pub fn id_bytes(id: &str) -> Result<[u8; 26], String> {
    let raw = id.as_bytes();
    if raw.len() > 26 || !id.is_ascii() || raw.contains(&0) {
        return Err(format!(
            "an id is at most 26 ASCII characters without NUL, not {id:?}"
        ));
    }
    let mut out = [0u8; 26];
    out[..raw.len()].copy_from_slice(raw);
    Ok(out)
}

/// The envelope's associated data (spec 2.6): alg || schema || blob kind ||
/// dek id (26) || object id (26) || u32be(version). A version the u32 does
/// not hold exactly is refused (INV-3), never cut into another one. `head` is
/// (alg, schema version, blob kind): a receiver binds the header it read, so a
/// header it does not support still fails authentication.
pub fn aad(
    head: [u8; 3],
    dek_id: &str,
    object_id: &str,
    version: u64,
) -> Result<[u8; AAD_LEN], String> {
    let version = u32::try_from(version).map_err(|_| "version must fit a u32".to_string())?;
    let mut out = [0u8; AAD_LEN];
    out[..3].copy_from_slice(&head);
    out[3..29].copy_from_slice(&id_bytes(dek_id)?);
    out[29..55].copy_from_slice(&id_bytes(object_id)?);
    out[55..].copy_from_slice(&version.to_be_bytes());
    Ok(out)
}

/// The size a padded blob of `n` bytes takes (spec 2.6, review 18c300f
/// R16-L3): the next power of two, at least 32; where that needs more padding
/// than the u16 prefix holds, the next multiple of 64 KiB.
pub fn padded_size(n: u64) -> u64 {
    let target = n.max(32).next_power_of_two();
    if target - n > MAX_PADDING {
        n.div_ceil(BUCKET) * BUCKET
    } else {
        target
    }
}

/// Consecutive push chunks within the per-request limits, order kept: the
/// number of objects in each. `sizes` are the bytes each object takes in the
/// request as the client sends it (its own JSON encoder).
pub fn split_for_push(sizes: &[u64]) -> Vec<usize> {
    let mut chunks = Vec::new();
    let (mut count, mut size) = (0usize, 0u64);
    for &obj in sizes {
        if count > 0 && (count >= MAX_PUSH_OBJECTS || size + obj > MAX_PUSH_REQUEST_BYTES) {
            chunks.push(count);
            (count, size) = (0, 0);
        }
        count += 1;
        size += obj;
    }
    if count > 0 {
        chunks.push(count);
    }
    chunks
}

/// What every client trims from an account name (review 688edcb N3): the
/// union of Python's str.isspace, JS and Dart trim (NBSP, BOM, NEL,
/// \x1c-\x1f, zero-width space).
fn username_edge(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{feff}' | '\u{200b}' | '\u{1c}'..='\u{1f}')
}

/// The account name as every client sends it (review 688edcb N3): NFC, then
/// trimmed, so one visible name is one account on every device. The reseed
/// signature covers these bytes.
pub fn normalize_username(value: &str) -> String {
    let nfc: String = value.nfc().collect();
    nfc.trim_matches(username_edge).to_string()
}

const STATE_HASH_V2: &[u8] = b"sezam-state-v2";

/// One sync object as the state hash sees it. `payload_hash` is SHA-256 of
/// the payload, which each platform takes from its own bytes.
pub struct StateObject {
    pub id: [u8; 26],
    pub version: u32,
    pub payload_hash: [u8; 32],
    pub parent_ref: Option<String>,
    pub is_deleted: bool,
}

/// Spec 8.3 state_hash (R17-N1: the signed parent and deleted flag count):
/// SHA-256("sezam-state-v2" || concat(sorted: id(26) || u32be(version) ||
/// SHA-256(payload) || u8(is_deleted) || (SHA-256(parent_ref) or 32 zero
/// bytes when it has none))). `legacy`: the formula of a checkpoint without
/// state_v, no prefix and the first three fields only.
pub fn state_hash(objects: &[StateObject], legacy: bool) -> [u8; 32] {
    let mut elements: Vec<Vec<u8>> = objects
        .iter()
        .map(|o| {
            let mut e = Vec::with_capacity(95);
            e.extend_from_slice(&o.id);
            e.extend_from_slice(&o.version.to_be_bytes());
            e.extend_from_slice(&o.payload_hash);
            if !legacy {
                e.push(u8::from(o.is_deleted));
                match o.parent_ref.as_deref() {
                    Some(p) if !p.is_empty() => e.extend_from_slice(&Sha256::digest(p.as_bytes())),
                    _ => e.extend_from_slice(&[0u8; 32]),
                }
            }
            e
        })
        .collect();
    elements.sort();
    let mut hasher = Sha256::new();
    if !legacy {
        hasher.update(STATE_HASH_V2);
    }
    for e in &elements {
        hasher.update(e);
    }
    hasher.finalize().into()
}

fn state_object(obj: &Value, legacy: bool) -> Result<StateObject, String> {
    let map = obj.as_object().ok_or("an object is a JSON object")?;
    let signed = ["parent_ref", "is_deleted"];
    if let Some(k) = map.keys().find(|k| {
        !matches!(k.as_str(), "id" | "version" | "payload_hash") && !signed.contains(&k.as_str())
    }) {
        return Err(format!("unknown field {k:?}"));
    }
    if !legacy {
        if let Some(k) = signed.iter().find(|k| !map.contains_key(**k)) {
            return Err(format!("{k} is missing"));
        }
    }
    let payload_hash = str_arg(obj, "payload_hash")
        .ok()
        .and_then(from_hex)
        .and_then(|h| <[u8; 32]>::try_from(h).ok())
        .ok_or("payload_hash must be a hex SHA-256 digest")?;
    let parent_ref = match obj.get("parent_ref") {
        None | Some(Value::Null) => None,
        Some(Value::String(p)) => Some(p.clone()),
        Some(_) => return Err("parent_ref must be a string or null".into()),
    };
    let is_deleted = match obj.get("is_deleted") {
        None => false,
        Some(v) => v.as_bool().ok_or("is_deleted must be true or false")?,
    };
    Ok(StateObject {
        id: id_bytes(str_arg(obj, "id")?)?,
        version: u32::try_from(u64_arg(obj, "version")?)
            .map_err(|_| "version must fit a u32".to_string())?,
        payload_hash,
        parent_ref,
        is_deleted,
    })
}

fn u64_arg(input: &Value, name: &str) -> Result<u64, String> {
    input
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{name} must be a non-negative integer"))
}

fn str_arg<'a>(input: &'a Value, name: &str) -> Result<&'a str, String> {
    input
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{name} must be a string"))
}

pub fn run(op: &str, input: &str) -> Option<Result<Value, String>> {
    if !matches!(
        op,
        "aad" | "padded_size" | "split_for_push" | "normalize_username" | "state_hash"
    ) {
        return None;
    }
    let out = (|| -> Result<Value, String> {
        let input: Value = serde_json::from_str(input).map_err(|e| format!("bad input: {e}"))?;
        Ok(match op {
            "aad" => {
                let byte = |name: &str, default: Option<u8>| match (input.get(name), default) {
                    (None, Some(d)) => Ok(d),
                    _ => u8::try_from(u64_arg(&input, name)?)
                        .map_err(|_| format!("{name} must fit a u8")),
                };
                let head = [
                    byte("alg", Some(ENVELOPE_ALG))?,
                    byte("schema_version", Some(SCHEMA_VERSION))?,
                    byte("blob_kind", None)?,
                ];
                json!(to_hex(&aad(
                    head,
                    str_arg(&input, "dek_id")?,
                    str_arg(&input, "object_id")?,
                    u64_arg(&input, "version")?,
                )?))
            }
            "padded_size" => json!(padded_size(u64_arg(&input, "n")?)),
            "split_for_push" => {
                let sizes = input
                    .get("sizes")
                    .and_then(Value::as_array)
                    .ok_or("sizes must be a list")?
                    .iter()
                    .map(|s| s.as_u64().ok_or("a size is a non-negative integer"))
                    .collect::<Result<Vec<_>, _>>()?;
                json!(split_for_push(&sizes))
            }
            "normalize_username" => json!(normalize_username(str_arg(&input, "value")?)),
            "state_hash" => {
                let legacy = match input.get("legacy") {
                    None => false,
                    Some(v) => v.as_bool().ok_or("legacy must be true or false")?,
                };
                let objects = input
                    .get("objects")
                    .and_then(Value::as_array)
                    .ok_or("objects must be a list")?
                    .iter()
                    .map(|o| state_object(o, legacy))
                    .collect::<Result<Vec<_>, _>>()?;
                json!(to_hex(&state_hash(&objects, legacy)))
            }
            _ => unreachable!(),
        })
    })();
    Some(out)
}

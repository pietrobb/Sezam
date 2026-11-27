//! Key vouchers (review e443cbc R15, INV-3; R17-N1): which object versions a
//! retired identity key still vouches for. One copy for the desktop, the
//! server, the web and the phone (docs/CORE_UNIFICATION.md U5); it replaced
//! src/sezam/key_vouchers.py, the web's and the phone's ports.
//!
//! A voucher list names object versions as (id, version, digest), signed by
//! the account's CURRENT key. The digest covers the whole signed message of
//! the version and its signer's account and key, so a leaked retired key
//! cannot sign a vouched version again with another parent, tombstone flag or
//! signer. The core builds and checks every byte; the client only verifies the
//! Ed25519 signatures with its libsodium (`key_voucher_lists` → verify →
//! `key_voucher_vouched`), the same split as the team log.

use std::collections::BTreeSet;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::teamlog::{from_hex, to_hex};

const DOMAIN: &[u8] = b"sezam-key-vouchers-v2\x00";
const ENTRY_DOMAIN: &[u8] = b"sezam-key-voucher-entry-v2\x00";
pub const MAX_ENTRIES: usize = 200_000;
/// The largest integer every client reads exactly (JavaScript's
/// Number.MAX_SAFE_INTEGER).
pub const MAX_VERSION: u64 = (1 << 53) - 1;

/// (object id, version, digest).
pub type Entry = (String, u64, String);

/// An id as 26 bytes: at most 26 ASCII characters without NUL, padded with NUL.
fn id_bytes(id: &str) -> Result<[u8; 26], String> {
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

fn hex_of_len(text: &str, len: usize) -> Option<Vec<u8>> {
    if text.len() != len * 2 {
        return None;
    }
    from_hex(&text.to_ascii_lowercase())
}

fn is_object_id(id: &str) -> bool {
    id.len() == 26 && id.bytes().all(|c| c.is_ascii_alphanumeric())
}

fn is_digest(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// The bytes a sync object's signature covers (spec 8.2).
pub fn signed_message(obj: &Value) -> Result<Vec<u8>, String> {
    let field = |name: &str| obj.get(name).filter(|v| !v.is_null());
    let id = obj.get("id").and_then(Value::as_str).ok_or("id")?;
    let object_type = obj
        .get("object_type")
        .and_then(Value::as_str)
        .ok_or("object_type")?;
    let optional_id = |name: &str| -> Result<[u8; 26], String> {
        match field(name) {
            None => Ok([0u8; 26]),
            Some(Value::String(s)) if s.is_empty() => Ok([0u8; 26]),
            Some(Value::String(s)) => id_bytes(s),
            Some(_) => Err(format!("{name} must be an id")),
        }
    };
    let is_deleted = match obj.get("is_deleted") {
        None => 0,
        Some(Value::Bool(b)) => u8::from(*b),
        Some(v) => match v.as_u64() {
            Some(n @ (0 | 1)) => n as u8,
            _ => return Err("is_deleted must be 0 or 1".into()),
        },
    };
    let version = match obj.get("version") {
        None => 1,
        Some(v) => v
            .as_u64()
            .filter(|n| *n <= u64::from(u32::MAX))
            .ok_or("version must fit a u32")?,
    };
    let payload_hash = obj
        .get("payload_hash")
        .and_then(Value::as_str)
        .and_then(|h| hex_of_len(h, 32))
        .ok_or("payload_hash must be a hex SHA-256 digest")?;
    let ot = object_type.as_bytes();
    if ot.len() > 255 {
        return Err("object_type is at most 255 bytes".into());
    }
    let mut out = Vec::with_capacity(26 + 1 + ot.len() + 52 + 5 + 32);
    out.extend_from_slice(&id_bytes(id)?);
    out.push(ot.len() as u8);
    out.extend_from_slice(ot);
    out.extend_from_slice(&optional_id("parent_ref")?);
    out.extend_from_slice(&optional_id("target_user_id")?);
    out.push(is_deleted);
    out.extend_from_slice(&(version as u32).to_be_bytes());
    out.extend_from_slice(&payload_hash);
    Ok(out)
}

/// The entry a voucher names for `obj` as `signing_pk` of `signer_id` signed
/// it; None when its fields are malformed.
pub fn object_entry(obj: &Value, signer_id: &str, signing_pk: &[u8]) -> Option<Entry> {
    if signing_pk.len() != 32 {
        return None;
    }
    let message = signed_message(obj).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(ENTRY_DOMAIN);
    hasher.update(id_bytes(signer_id).ok()?);
    hasher.update(signing_pk);
    hasher.update(&message);
    let id = obj.get("id")?.as_str()?.to_string();
    let version = obj.get("version").map_or(Some(1), Value::as_u64)?;
    Some((id, version, to_hex(&hasher.finalize())))
}

/// Sorted, de-duplicated entries; Err on any malformed one.
pub fn canonical_entries(entries: &Value) -> Result<Vec<Entry>, String> {
    let list = match entries {
        Value::Null => return Ok(Vec::new()),
        Value::Array(list) => list,
        _ => return Err("voucher entries must be a list".into()),
    };
    if list.len() > MAX_ENTRIES {
        return Err("too many voucher entries".into());
    }
    let mut out = BTreeSet::new();
    for entry in list {
        let parts = entry
            .as_array()
            .filter(|p| p.len() == 3)
            .ok_or("a voucher entry is [id, version, digest]")?;
        let id = parts[0]
            .as_str()
            .filter(|id| is_object_id(id))
            .ok_or("a voucher entry needs a 26-character object id")?;
        let version = match &parts[1] {
            Value::Number(n) => n.as_u64().or_else(|| {
                n.as_f64()
                    .filter(|f| *f >= 0.0 && f.fract() == 0.0 && *f <= MAX_VERSION as f64)
                    .map(|f| f as u64)
            }),
            _ => None,
        }
        .filter(|v| *v <= MAX_VERSION)
        .ok_or("a voucher entry needs an unsigned version of at most 2^53 - 1")?;
        let digest = parts[2]
            .as_str()
            .filter(|d| is_digest(d))
            .ok_or("a voucher entry needs a lowercase hex SHA-256 digest")?;
        out.insert((id.to_string(), version, digest.to_string()));
    }
    Ok(out.into_iter().collect())
}

/// Bytes the account's current key signs for a voucher list, and its entries.
pub fn voucher_message(
    user_id: &str,
    signing_pk: &[u8],
    entries: &Value,
) -> Result<(Vec<u8>, Vec<Entry>), String> {
    if signing_pk.len() != 32 {
        return Err("a voucher signing key is 32 bytes".into());
    }
    let items = canonical_entries(entries)?;
    let mut out = Vec::with_capacity(DOMAIN.len() + 62 + items.len() * 66);
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&id_bytes(user_id)?);
    out.extend_from_slice(signing_pk);
    out.extend_from_slice(&(items.len() as u32).to_be_bytes());
    for (id, version, digest) in &items {
        out.extend_from_slice(id.as_bytes());
        out.extend_from_slice(&version.to_be_bytes());
        out.extend_from_slice(&from_hex(digest).expect("checked digest"));
    }
    Ok((out, items))
}

/// What the client must verify for one served list: (message, signature),
/// or None when the list counts for nothing before any signature check
/// (another key, another shape, a malformed entry).
fn list_to_verify(
    user_id: &str,
    current_pk: &[u8],
    list: &Value,
) -> Option<(Vec<u8>, Vec<u8>, Vec<Entry>)> {
    let obj = list.as_object()?;
    let pk = hex_of_len(obj.get("signing_pk")?.as_str()?, 32)?;
    let signature = hex_of_len(obj.get("signature")?.as_str()?, 64)?;
    let entries = obj.get("entries").unwrap_or(&Value::Null);
    if pk != current_pk {
        return None;
    }
    let (message, items) = voucher_message(user_id, current_pk, entries).ok()?;
    Some((message, signature, items))
}

fn lists_of(lists: &Value) -> &[Value] {
    lists.as_array().map_or(&[], Vec::as_slice)
}

/// Per served list: {"message", "signature"} (hex) to verify with the current
/// key, or null for a list that vouches for nothing anyway.
pub fn lists_to_verify(user_id: &str, current_pk: &[u8], lists: &Value) -> Vec<Value> {
    lists_of(lists)
        .iter()
        .map(|list| match list_to_verify(user_id, current_pk, list) {
            Some((message, signature, _)) => {
                json!({ "message": to_hex(&message), "signature": to_hex(&signature) })
            }
            None => Value::Null,
        })
        .collect()
}

/// Every entry a list named, among those whose signature the client verified.
pub fn vouched(user_id: &str, current_pk: &[u8], lists: &Value, verified: &[bool]) -> Vec<Entry> {
    let mut out = BTreeSet::new();
    for (i, list) in lists_of(lists).iter().enumerate() {
        if !verified.get(i).copied().unwrap_or(false) {
            continue;
        }
        if let Some((_, _, items)) = list_to_verify(user_id, current_pk, list) {
            out.extend(items);
        }
    }
    out.into_iter().collect()
}

fn str_arg<'a>(input: &'a Value, name: &str) -> Result<&'a str, String> {
    input
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{name} is required"))
}

fn key_arg(input: &Value, name: &str) -> Result<Vec<u8>, String> {
    hex_of_len(str_arg(input, name)?, 32).ok_or_else(|| format!("{name} must be 32 bytes of hex"))
}

fn entry_json(entry: &Entry) -> Value {
    json!([entry.0, entry.1, entry.2])
}

/// The `key_voucher_*` operations; None: not one of them.
pub fn run(op: &str, input: &str) -> Option<Result<Value, String>> {
    if !op.starts_with("key_voucher_") {
        return None;
    }
    let out = (|| -> Result<Value, String> {
        let input: Value = serde_json::from_str(input).map_err(|e| format!("bad input: {e}"))?;
        let none = Value::Null;
        Ok(match op {
            "key_voucher_object_entry" => {
                let obj = input.get("object").ok_or("object is required")?;
                let pk = key_arg(&input, "signing_pk")?;
                object_entry(obj, str_arg(&input, "signer_id")?, &pk)
                    .as_ref()
                    .map_or(Value::Null, entry_json)
            }
            "key_voucher_signed_message" => {
                let obj = input.get("object").ok_or("object is required")?;
                json!(to_hex(&signed_message(obj)?))
            }
            "key_voucher_canonical" => {
                let entries = canonical_entries(input.get("entries").unwrap_or(&none))?;
                json!(entries.iter().map(entry_json).collect::<Vec<_>>())
            }
            "key_voucher_message" => {
                let pk = key_arg(&input, "signing_pk")?;
                let (message, items) = voucher_message(
                    str_arg(&input, "user_id")?,
                    &pk,
                    input.get("entries").unwrap_or(&none),
                )?;
                json!({
                    "message": to_hex(&message),
                    "entries": items.iter().map(entry_json).collect::<Vec<_>>(),
                })
            }
            "key_voucher_lists" => {
                let pk = key_arg(&input, "current_signing_pk")?;
                json!(lists_to_verify(
                    str_arg(&input, "user_id")?,
                    &pk,
                    input.get("lists").unwrap_or(&none)
                ))
            }
            "key_voucher_vouched" => {
                let pk = key_arg(&input, "current_signing_pk")?;
                let verified: Vec<bool> = input
                    .get("verified")
                    .and_then(Value::as_array)
                    .ok_or("verified is required")?
                    .iter()
                    .map(|v| v.as_bool() == Some(true))
                    .collect();
                let entries = vouched(
                    str_arg(&input, "user_id")?,
                    &pk,
                    input.get("lists").unwrap_or(&none),
                    &verified,
                );
                json!(entries.iter().map(entry_json).collect::<Vec<_>>())
            }
            _ => return Err(format!("unknown operation {op:?}")),
        })
    })();
    Some(out)
}

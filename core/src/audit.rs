//! Audit records (docs/CORE_UNIFICATION.md U6, spec 7): the sync payload of a
//! record, the bytes its Ed25519 signature covers and the DAG check. One
//! copy; it replaced AuditLog._build_canonical, serialize_audit_row,
//! _parse_audit_payload and _validate_audit_dag on the desktop and
//! parseCanonicalAuditRecord, buildAuditCanonical and the DAG checks of
//! app.js and the phone. The signature itself is verified by each platform's
//! libsodium with the actor's keys.
//!
//! The payload is the desktop's, which writes every record: keys sorted, no
//! spaces, every non-ASCII character escaped as \uXXXX (Python json.dumps).
//! The web and phone compared against their own JSON encoders, which leave
//! non-ASCII as is, and refused desktop records with such an action.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::formats::id_bytes;
use crate::teamlog::{from_hex, to_hex};

pub const FORMAT: &str = "sezam-audit-v1";
const FIELDS: [&str; 8] = [
    "action",
    "actor_id",
    "encrypted_details",
    "format",
    "id",
    "parent_ids",
    "signature",
    "timestamp",
];

/// One parsed record (`id` is the sync object's).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub id: String,
    pub actor_id: String,
    pub parent_ids: Vec<String>,
    pub action: String,
    pub timestamp: u64,
    pub encrypted_details: Vec<u8>,
    pub signature: Vec<u8>,
}

/// A JSON string as Python's json.dumps writes it (ensure_ascii).
fn push_json_string(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Any JSON value in the canonical form: keys sorted, no spaces, ASCII only.
fn push_canonical(out: &mut String, value: &Value) {
    match value {
        Value::String(s) => push_json_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                push_canonical(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            for (i, (key, item)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                push_json_string(out, key);
                out.push(':');
                push_canonical(out, item);
            }
            out.push('}');
        }
        other => out.push_str(&other.to_string()),
    }
}

fn parents_json(parent_ids: &[String]) -> String {
    let mut out = String::new();
    push_canonical(&mut out, &json!(parent_ids));
    out
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Standard base64 with padding, in its one canonical spelling only.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(4) {
        return None;
    }
    let body = text.trim_end_matches('=');
    if text.len() - body.len() > 2 {
        return None;
    }
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for c in body.bytes() {
        let v = B64.iter().position(|&b| b == c)? as u32;
        bits = bits << 6 | v;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    (base64_encode(&out) == text).then_some(out)
}

/// The bytes the actor's key signs: id (26) || actor id (26) ||
/// u16be(len) || parent ids JSON || u16be(len) || action || u64be(timestamp)
/// || SHA-256(encrypted details), 32 zero bytes when there are none.
pub fn message(
    id: &str,
    actor_id: &str,
    parent_ids: &[String],
    action: &str,
    timestamp: u64,
    encrypted_details: &[u8],
) -> Result<Vec<u8>, String> {
    let parents = parents_json(parent_ids);
    let parents_len =
        u16::try_from(parents.len()).map_err(|_| "audit parent list is too long".to_string())?;
    let action_len =
        u16::try_from(action.len()).map_err(|_| "audit action is too long".to_string())?;
    let details_hash: [u8; 32] = if encrypted_details.is_empty() {
        [0; 32]
    } else {
        Sha256::digest(encrypted_details).into()
    };
    Ok([
        &id_bytes(id)?[..],
        &id_bytes(actor_id)?,
        &parents_len.to_be_bytes(),
        parents.as_bytes(),
        &action_len.to_be_bytes(),
        action.as_bytes(),
        &timestamp.to_be_bytes(),
        &details_hash,
    ]
    .concat())
}

/// The record's sync payload (parent ids sorted).
pub fn payload(record: &Record) -> String {
    let mut parents = record.parent_ids.clone();
    parents.sort();
    let mut out = String::new();
    push_canonical(
        &mut out,
        &json!({
            "action": record.action,
            "actor_id": record.actor_id,
            "encrypted_details": base64_encode(&record.encrypted_details),
            "format": FORMAT,
            "id": record.id,
            "parent_ids": parents,
            "signature": to_hex(&record.signature),
            "timestamp": record.timestamp,
        }),
    );
    out
}

fn is_id(value: &str) -> bool {
    value.len() == 26 && id_bytes(value).is_ok()
}

/// The record a pulled audit sync object carries: complete, canonical,
/// append-only (version 2, never deleted) and naming its own id.
pub fn parse(id: &str, version: u64, is_deleted: bool, payload: &[u8]) -> Result<Record, String> {
    if version != 2 || is_deleted {
        return Err("audit records are append-only version 2".into());
    }
    let text = std::str::from_utf8(payload).map_err(|_| "invalid audit payload")?;
    let value: Value = serde_json::from_str(text).map_err(|_| "invalid audit payload")?;
    let map = value.as_object().ok_or("invalid audit payload")?;
    let keys: BTreeSet<&str> = map.keys().map(String::as_str).collect();
    if keys != FIELDS.into_iter().collect::<BTreeSet<_>>() {
        return Err("incomplete audit payload".into());
    }
    let mut canonical = String::new();
    push_canonical(&mut canonical, &value);
    if canonical != text || map["format"] != FORMAT || map["id"] != id {
        return Err("non-canonical or mismatched payload".into());
    }
    let (actor_id, action, timestamp) = match (
        map["actor_id"].as_str(),
        map["action"].as_str(),
        map["timestamp"].as_u64(),
    ) {
        (Some(a), Some(act), Some(t)) if is_id(a) && !act.is_empty() && act.len() <= 0xFFFF => {
            (a, act, t)
        }
        _ => return Err("invalid audit fields".into()),
    };
    let parent_ids: Vec<String> = map["parent_ids"]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .map(|p| p.as_str().filter(|p| is_id(p)).map(str::to_string))
                .collect()
        })
        .ok_or("invalid audit parents")?;
    if parent_ids.windows(2).any(|w| w[0] >= w[1]) || parent_ids.iter().any(|p| p == id) {
        return Err("invalid audit parents".into());
    }
    let encrypted_details = map["encrypted_details"]
        .as_str()
        .and_then(base64_decode)
        .ok_or("invalid audit encoding")?;
    let signature = map["signature"]
        .as_str()
        .filter(|s| s.len() == 128 && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')))
        .and_then(from_hex)
        .ok_or("invalid audit encoding")?;
    Ok(Record {
        id: id.to_string(),
        actor_id: actor_id.to_string(),
        parent_ids,
        action: action.to_string(),
        timestamp,
        encrypted_details,
        signature,
    })
}

/// The whole audit graph: every parent present and no cycle.
pub fn check_dag(records: &[(String, Vec<String>)]) -> Result<(), String> {
    let parents: BTreeMap<&str, BTreeSet<&str>> = records
        .iter()
        .map(|(id, p)| (id.as_str(), p.iter().map(String::as_str).collect()))
        .collect();
    let mut children: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut indegree: BTreeMap<&str, usize> = BTreeMap::new();
    for (&id, ps) in &parents {
        if ps.iter().any(|p| !parents.contains_key(p)) {
            return Err(format!(
                "audit DAG record {id} references missing parent(s)"
            ));
        }
        indegree.insert(id, ps.len());
        for &p in ps {
            children.entry(p).or_default().push(id);
        }
    }
    let mut ready: Vec<&str> = indegree
        .iter()
        .filter(|(_, &d)| d == 0)
        .map(|(&id, _)| id)
        .collect();
    let mut visited = 0;
    while let Some(id) = ready.pop() {
        visited += 1;
        for child in children.get(id).into_iter().flatten() {
            let d = indegree.get_mut(child).expect("every child is a record");
            *d -= 1;
            if *d == 0 {
                ready.push(child);
            }
        }
    }
    if visited != parents.len() {
        return Err("audit DAG cycle detected".into());
    }
    Ok(())
}

fn str_arg<'a>(input: &'a Value, name: &str) -> Result<&'a str, String> {
    input
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{name} must be a string"))
}

fn u64_arg(input: &Value, name: &str) -> Result<u64, String> {
    input
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{name} must be a non-negative integer"))
}

fn hex_arg(input: &Value, name: &str) -> Result<Vec<u8>, String> {
    let text = str_arg(input, name)?;
    if text.len() % 2 != 0 {
        return Err(format!("{name} must be hex"));
    }
    from_hex(&text.to_ascii_lowercase()).ok_or_else(|| format!("{name} must be hex"))
}

fn ids_arg(input: &Value, name: &str) -> Result<Vec<String>, String> {
    input
        .get(name)
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .map(|p| p.as_str().map(str::to_string))
                .collect()
        })
        .ok_or_else(|| format!("{name} must be a list of strings"))
}

fn record_arg(input: &Value) -> Result<Record, String> {
    Ok(Record {
        id: str_arg(input, "id")?.to_string(),
        actor_id: str_arg(input, "actor_id")?.to_string(),
        parent_ids: ids_arg(input, "parent_ids")?,
        action: str_arg(input, "action")?.to_string(),
        timestamp: u64_arg(input, "timestamp")?,
        encrypted_details: hex_arg(input, "encrypted_details")?,
        signature: match input.get("signature") {
            None => Vec::new(),
            Some(_) => hex_arg(input, "signature")?,
        },
    })
}

/// The JSON ops.
pub fn run(op: &str, input: &str) -> Option<Result<Value, String>> {
    if !matches!(
        op,
        "audit_message" | "audit_payload" | "audit_parse" | "audit_dag"
    ) {
        return None;
    }
    Some((|| {
        let input: Value = serde_json::from_str(input).map_err(|e| e.to_string())?;
        Ok(match op {
            "audit_message" => {
                let r = record_arg(&input)?;
                json!(to_hex(&message(
                    &r.id,
                    &r.actor_id,
                    &r.parent_ids,
                    &r.action,
                    r.timestamp,
                    &r.encrypted_details
                )?))
            }
            "audit_payload" => {
                let r = record_arg(&input)?;
                if r.signature.len() != 64 {
                    return Err("signature must be 64 bytes".into());
                }
                message(
                    &r.id,
                    &r.actor_id,
                    &r.parent_ids,
                    &r.action,
                    r.timestamp,
                    &[],
                )?;
                json!(payload(&r))
            }
            "audit_parse" => {
                let id = str_arg(&input, "id")?;
                let is_deleted = match input.get("is_deleted") {
                    None | Some(Value::Null) => false,
                    Some(Value::Bool(b)) => *b,
                    Some(v) => v.as_u64().ok_or("is_deleted must be a boolean")? != 0,
                };
                let r = parse(
                    id,
                    u64_arg(&input, "version")?,
                    is_deleted,
                    &hex_arg(&input, "payload")?,
                )?;
                let m = message(
                    &r.id,
                    &r.actor_id,
                    &r.parent_ids,
                    &r.action,
                    r.timestamp,
                    &r.encrypted_details,
                )?;
                json!({
                    "actor_id": r.actor_id,
                    "action": r.action,
                    "timestamp": r.timestamp,
                    "parent_ids": r.parent_ids,
                    "parent_ids_json": parents_json(&r.parent_ids),
                    "encrypted_details": to_hex(&r.encrypted_details),
                    "signature": to_hex(&r.signature),
                    "message": to_hex(&m),
                })
            }
            "audit_dag" => {
                let records = input
                    .get("records")
                    .and_then(Value::as_array)
                    .ok_or("records must be a list")?
                    .iter()
                    .map(|r| Ok((str_arg(r, "id")?.to_string(), ids_arg(r, "parent_ids")?)))
                    .collect::<Result<Vec<_>, String>>()?;
                check_dag(&records)?;
                Value::Null
            }
            _ => unreachable!(),
        })
    })())
}

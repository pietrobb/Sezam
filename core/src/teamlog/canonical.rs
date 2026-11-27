//! The restricted canonical JSON of a record body (design §3.3) and the
//! schema of a parsed body.

use serde_json::{Map, Value};

use super::{LogError, LogResult, MAX_INT, RULES_VERSIONS};

const BODY_FIELDS: [&str; 6] = ["author", "data", "prev", "seq", "type", "v"];

/// type -> [(field, kind)]; a kind ending in `?` may be null.
fn data_schema(kind: &str) -> Option<&'static [(&'static str, &'static str)]> {
    Some(match kind {
        "genesis" => &[
            ("org", "ulid"),
            ("user_id", "ulid"),
            ("signing_pk", "hex64"),
            ("encryption_pk", "hex64"),
        ],
        "member.add" => &[
            ("user_id", "ulid"),
            ("signing_pk", "hex64"),
            ("encryption_pk", "hex64"),
            ("role", "role"),
        ],
        "member.role" => &[("user_id", "ulid"), ("role", "role")],
        "member.remove" => &[("user_id", "ulid")],
        "member.keys" => &[
            ("user_id", "ulid"),
            ("signing_pk", "hex64"),
            ("encryption_pk", "hex64"),
            ("new_key_sig", "hex128"),
        ],
        "folder.key" => &[
            ("folder", "ulid"),
            ("gen", "int"),
            ("dek_id", "ulid"),
            ("prev_dek_id", "ulid?"),
        ],
        "access.set" => &[("folder", "ulid"), ("user_id", "ulid"), ("level", "level?")],
        // Review 8595ec1 (R10-D): the admin's org recovery key, from rules 2.
        "org.recovery" => &[("recovery_pk", "hex64?")],
        "org.recovery.wrap" => &[
            ("wrapped_kek", "hex144"),
            ("key_epoch", "int"),
            ("threshold", "int"),
            ("total_shares", "int"),
        ],
        _ => return None,
    })
}

pub const RECOVERY_TYPES: [&str; 2] = ["org.recovery", "org.recovery.wrap"];

fn safe(text: &str) -> bool {
    text.bytes()
        .all(|b| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\')
}

fn check_value(value: &Value, seq: Option<i64>) -> LogResult<()> {
    let bad = |detail: &str| Err(LogError::new("bad_encoding", seq, detail));
    match value {
        Value::Null => Ok(()),
        Value::Bool(_) => bad("boolean"),
        Value::Number(n) => match n.as_u64() {
            Some(n) if n <= MAX_INT => Ok(()),
            _ if n.is_f64() => bad("float"),
            _ => bad("integer out of range"),
        },
        Value::String(s) if safe(s) => Ok(()),
        Value::String(_) => bad("string"),
        Value::Object(map) => {
            for (key, item) in map {
                if !safe(key) {
                    return bad("key");
                }
                check_value(item, seq)?;
            }
            Ok(())
        }
        Value::Array(_) => bad("list"),
    }
}

fn encode(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => {
            out.push('"');
            out.push_str(s);
            out.push('"');
        }
        Value::Object(map) => {
            // serde_json's map is ordered by key bytes, as the design wants.
            out.push('{');
            for (i, (key, item)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('"');
                out.push_str(key);
                out.push_str("\":");
                encode(item, out);
            }
            out.push('}');
        }
        Value::Bool(_) | Value::Array(_) => unreachable!("check_value refuses it"),
    }
}

/// The canonical text of `value`.
pub fn canonical(value: &Value, seq: Option<i64>) -> LogResult<String> {
    check_value(value, seq)?;
    let mut out = String::new();
    encode(value, &mut out);
    Ok(out)
}

/// Parse a transmitted body; it must already be in canonical form.
pub fn parse_body(body: &str, seq: Option<i64>) -> LogResult<Map<String, Value>> {
    let parsed: Value =
        serde_json::from_str(body).map_err(|_| LogError::new("bad_encoding", seq, "json"))?;
    // A duplicate key, an escape, white space or a float all come back
    // different from what was sent.
    if !parsed.is_object() || canonical(&parsed, seq)? != body {
        return Err(LogError::new("bad_encoding", seq, "not canonical"));
    }
    match parsed {
        Value::Object(map) => Ok(map),
        _ => unreachable!(),
    }
}

fn pattern(text: &str, kind: &str) -> bool {
    let hex =
        |n: usize| text.len() == n && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    match kind {
        "ulid" => {
            let b = text.as_bytes();
            b.len() == 26
                && (b'0'..=b'7').contains(&b[0])
                && b[1..].iter().all(|c| {
                    c.is_ascii_digit()
                        || (c.is_ascii_uppercase() && !matches!(c, b'I' | b'L' | b'O' | b'U'))
                })
        }
        "hex64" => hex(64),
        "hex128" => hex(128),
        "hex144" => hex(144),
        _ => false,
    }
}

/// Whether `value` is of the schema kind `kind` (without the `?`).
pub fn is_kind(kind: &str, value: &Value) -> bool {
    match kind {
        "ulid" | "hex64" | "hex128" | "hex144" => value.as_str().is_some_and(|s| pattern(s, kind)),
        "role" => matches!(value.as_str(), Some("admin" | "member")),
        "level" => matches!(value.as_str(), Some("read" | "write")),
        // "int": canonical() lets only integers 0..=MAX_INT through
        _ => value.is_u64(),
    }
}

/// The schema of a parsed body, checked in this exact order. Errors carry
/// the record's position `seq`.
pub fn validate_body(body: &Map<String, Value>, seq: i64) -> LogResult<()> {
    let bad = |detail: &str| Err(LogError::new("bad_schema", Some(seq), detail));
    if body.len() != BODY_FIELDS.len() || !BODY_FIELDS.iter().all(|f| body.contains_key(*f)) {
        return bad("body fields");
    }
    let v = body["v"].as_u64();
    if !v.is_some_and(|v| RULES_VERSIONS.contains(&v)) {
        return bad("version");
    }
    if !body["seq"].is_u64() {
        return bad("seq");
    }
    if !is_kind("hex64", &body["prev"]) {
        return bad("prev");
    }
    if !is_kind("ulid", &body["author"]) {
        return bad("author");
    }
    let kind = body["type"].as_str();
    let schema = kind.and_then(data_schema);
    let schema = match schema {
        Some(s) if !(RECOVERY_TYPES.contains(&kind.unwrap_or("")) && v < Some(2)) => s,
        _ => return bad("type"),
    };
    let data = match &body["data"] {
        Value::Object(d)
            if d.len() == schema.len() && schema.iter().all(|(n, _)| d.contains_key(*n)) =>
        {
            d
        }
        _ => return bad("data fields"),
    };
    for (name, kind) in schema {
        let value = &data[*name];
        if value.is_null() && kind.ends_with('?') {
            continue;
        }
        if !is_kind(kind.trim_end_matches('?'), value) {
            return bad(name);
        }
    }
    Ok(())
}

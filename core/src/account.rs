//! The portable account bundle and its pre-anchor password states
//! (docs/CORE_UNIFICATION.md U6, domain E; capability run 269). One copy; it
//! replaced parse/merge/add_pre_anchor and encode/decode_account_bundle in
//! aead.py, app.js and crypto_service.dart.
//!
//! No key material comes here (plan rule 3). The check of a state is
//! SHA-256("sezam-pre-anchor-kek-v1" || KEK), computed by the platform's own
//! libsodium; a bundle's private keys (bytes 8..72, or a legacy bundle whole)
//! stay with the platform, which hands over only the version and the bytes
//! from 72 on (the confirmed genesis and the states).

use serde_json::{json, Value};

use crate::teamlog::{from_hex, to_hex};

/// salt(16) || time u32be || memory u32be || lanes u32be || check(32)
pub const PRE_ANCHOR_ENTRY_LEN: usize = 60;
pub const PRE_ANCHOR_MAX: usize = 8;
const BUNDLE_V1: &[u8; 8] = b"SZACCT01";
const BUNDLE_ANCHORED: &[u8; 8] = b"SZACCT02";
const BUNDLE_LEN: usize = 104;

/// The entries of `count u8 || entries`; an empty blob has none. Stored
/// params outside what any client ever derived with are refused.
pub fn pre_anchor_entries(blob: &[u8]) -> Result<Vec<&[u8]>, String> {
    let Some(&count) = blob.first() else {
        return Ok(Vec::new());
    };
    let count = usize::from(count);
    if !(1..=PRE_ANCHOR_MAX).contains(&count) || blob.len() != 1 + count * PRE_ANCHOR_ENTRY_LEN {
        return Err("Invalid account keypair pre-anchor states".into());
    }
    let entries: Vec<&[u8]> = blob[1..].chunks(PRE_ANCHOR_ENTRY_LEN).collect();
    for entry in &entries {
        let (time, memory, lanes) = params_of(entry);
        if !((1..=20).contains(&time)
            && (8192..=1_048_576).contains(&memory)
            && (1..=16).contains(&lanes))
        {
            return Err("Invalid account keypair pre-anchor KDF params".into());
        }
    }
    Ok(entries)
}

fn params_of(entry: &[u8]) -> (u32, u32, u32) {
    let u32_at = |at: usize| u32::from_be_bytes(entry[at..at + 4].try_into().unwrap());
    (u32_at(16), u32_at(20), u32_at(24))
}

/// `kept` plus the states only `other` records, newest last, at most
/// PRE_ANCHOR_MAX (a rebind never forgets one). None when there are none.
pub fn pre_anchor_merge(kept: &[u8], other: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let mut entries = pre_anchor_entries(kept)?;
    for entry in pre_anchor_entries(other)? {
        if !entries.contains(&entry) {
            entries.push(entry);
        }
    }
    let last = &entries[entries.len().saturating_sub(PRE_ANCHOR_MAX)..];
    if last.is_empty() {
        return Ok(None);
    }
    let mut out = vec![last.len() as u8];
    for entry in last {
        out.extend_from_slice(entry);
    }
    Ok(Some(out))
}

/// `blob` plus one password state.
pub fn pre_anchor_add(
    blob: &[u8],
    salt: &[u8],
    params: [u64; 3],
    check: &[u8],
) -> Result<Option<Vec<u8>>, String> {
    if salt.len() != 16 {
        return Err("Invalid pre-anchor salt".into());
    }
    if check.len() != 32 {
        return Err("Invalid pre-anchor check".into());
    }
    let mut one = vec![1u8];
    one.extend_from_slice(salt);
    for value in params {
        let value = u32::try_from(value)
            .map_err(|_| "Invalid account keypair pre-anchor KDF params".to_string())?;
        one.extend_from_slice(&value.to_be_bytes());
    }
    one.extend_from_slice(check);
    pre_anchor_merge(blob, &one)
}

/// The bundle's version and tail around the platform's keys:
/// version || keys(64) || tail, where tail = confirmed genesis(32) || states.
pub fn bundle_encode(confirmed_genesis: &str, pre_anchor: &[u8]) -> Result<Value, String> {
    let genesis = (confirmed_genesis.len() == 64)
        .then(|| from_hex(confirmed_genesis))
        .flatten()
        .ok_or("Invalid account keypair confirmed genesis")?;
    pre_anchor_entries(pre_anchor)?;
    let version = if pre_anchor.is_empty() {
        BUNDLE_V1
    } else {
        BUNDLE_ANCHORED
    };
    let mut tail = genesis;
    tail.extend_from_slice(pre_anchor);
    Ok(json!({"version": to_hex(version), "tail": to_hex(&tail)}))
}

/// What a bundle of `length` bytes is. `version` (its first 8 bytes) and
/// `tail` (its bytes from 72 on) are given only for a bundle of at least 104
/// bytes; a shorter one is a legacy key pair, whose bytes are all key.
/// kind: "anchored" | "v1" (keys at 8..72), "legacy64" (the 64 bytes),
/// "legacy96" (seed || signing pk || encryption sk: the platform checks the
/// pk). Legacy keys are explicitly unanchored; unknown bundles never downgrade.
pub fn bundle_decode(length: usize, version: &[u8], tail: &[u8]) -> Result<Value, String> {
    if length >= BUNDLE_LEN && (version.len() != 8 || tail.len() != length - 72) {
        return Err("Invalid account keypair payload".into());
    }
    if length > BUNDLE_LEN && version == BUNDLE_ANCHORED {
        let states = &tail[32..];
        pre_anchor_entries(states)?;
        return Ok(json!({
            "kind": "anchored",
            "confirmed_genesis": to_hex(&tail[..32]),
            "pre_anchor": to_hex(states),
        }));
    }
    Ok(match length {
        BUNDLE_LEN if version == BUNDLE_V1 => json!({
            "kind": "v1", "confirmed_genesis": to_hex(tail), "pre_anchor": null,
        }),
        BUNDLE_LEN => return Err("Invalid account keypair bundle version".into()),
        64 => json!({"kind": "legacy64", "confirmed_genesis": null, "pre_anchor": null}),
        96 => json!({"kind": "legacy96", "confirmed_genesis": null, "pre_anchor": null}),
        _ => return Err("Invalid account keypair payload length".into()),
    })
}

fn hex_arg(input: &Value, name: &str) -> Result<Vec<u8>, String> {
    match input.get(name) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(text)) => from_hex(text).ok_or_else(|| format!("{name} must be hex")),
        _ => Err(format!("{name} must be hex")),
    }
}

fn u64_arg(input: &Value, name: &str) -> Result<u64, String> {
    input
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{name} must be a non-negative integer"))
}

fn blob_out(blob: Option<Vec<u8>>) -> Value {
    blob.map_or(Value::Null, |b| json!(to_hex(&b)))
}

pub fn run(op: &str, input: &str) -> Option<Result<Value, String>> {
    if !matches!(
        op,
        "pre_anchor_parse"
            | "pre_anchor_merge"
            | "pre_anchor_add"
            | "account_bundle_encode"
            | "account_bundle_decode"
    ) {
        return None;
    }
    let out = (|| -> Result<Value, String> {
        let input: Value = serde_json::from_str(input).map_err(|e| format!("bad input: {e}"))?;
        Ok(match op {
            "pre_anchor_parse" => Value::Array(
                pre_anchor_entries(&hex_arg(&input, "blob")?)?
                    .into_iter()
                    .map(|e| {
                        let (time, memory, lanes) = params_of(e);
                        json!({
                            "raw": to_hex(e), "salt": to_hex(&e[..16]), "check": to_hex(&e[28..]),
                            "time_cost": time, "memory_cost": memory, "parallelism": lanes,
                        })
                    })
                    .collect(),
            ),
            "pre_anchor_merge" => blob_out(pre_anchor_merge(
                &hex_arg(&input, "kept")?,
                &hex_arg(&input, "other")?,
            )?),
            "pre_anchor_add" => blob_out(pre_anchor_add(
                &hex_arg(&input, "blob")?,
                &hex_arg(&input, "salt")?,
                [
                    u64_arg(&input, "time_cost")?,
                    u64_arg(&input, "memory_cost")?,
                    u64_arg(&input, "parallelism")?,
                ],
                &hex_arg(&input, "check")?,
            )?),
            "account_bundle_encode" => bundle_encode(
                input
                    .get("confirmed_genesis")
                    .and_then(Value::as_str)
                    .ok_or("Invalid account keypair confirmed genesis")?,
                &hex_arg(&input, "pre_anchor")?,
            )?,
            "account_bundle_decode" => bundle_decode(
                usize::try_from(u64_arg(&input, "length")?).map_err(|e| e.to_string())?,
                &hex_arg(&input, "version")?,
                &hex_arg(&input, "tail")?,
            )?,
            _ => unreachable!(),
        })
    })();
    Some(out)
}

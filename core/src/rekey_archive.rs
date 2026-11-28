//! The archive id of a re-key that removed a member (capability review run
//! 140, docs/CORE_UNIFICATION.md U6): the 16 random characters of the ULID
//! carry two tags keyed by the new DEK, "a removal re-key" and "it removed
//! this member". The keyed BLAKE2b (16 bytes, key = the new DEK) stays with
//! the platform (rule 3); the core builds its inputs, encodes the digests and
//! compares them. It replaced the desktop's dek.removal_archive_id /
//! archive_removed and the web's removalArchiveId / rekeyArchiveChars.

use serde_json::{json, Value};

use crate::teamlog::from_hex;

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const REMOVAL_MARK: &[u8] = b"sezam-rekey-archive-v1\x00";
const REMOVAL_MEMBER: &[u8] = b"sezam-rekey-removed-v1\x00";
pub const DIGEST_LEN: usize = 16;
const PREFIX_LEN: usize = 10;

/// The keyed-hash input: label || new_dek_id (ASCII) || NUL || user id (UTF-8).
fn message(label: &[u8], new_dek_id: &str, user_id: &str) -> Vec<u8> {
    [label, new_dek_id.as_bytes(), b"\x00", user_id.as_bytes()].concat()
}

/// (mark, member): what the platform hashes under the new DEK.
pub fn messages(new_dek_id: &str, user_id: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    if !new_dek_id.is_ascii() {
        return Err("new_dek_id must be ASCII".into());
    }
    Ok((
        message(REMOVAL_MARK, new_dek_id, ""),
        message(REMOVAL_MEMBER, new_dek_id, user_id),
    ))
}

/// 8 Crockford characters from the first 8 digest bytes (low 5 bits each).
fn chars(digest: &[u8]) -> String {
    digest[..8]
        .iter()
        .map(|b| CROCKFORD[usize::from(b & 0x1f)] as char)
        .collect()
}

pub fn archive_id(prefix: &str, mark: &[u8], member: &[u8]) -> Result<String, String> {
    if prefix.len() != PREFIX_LEN || !prefix.bytes().all(|b| CROCKFORD.contains(&b)) {
        return Err("prefix must be the 10 Crockford characters of a ULID's time".into());
    }
    Ok(format!("{prefix}{}{}", chars(mark), chars(member)))
}

fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// Whether the re-key behind `archive_id` removed the member whose digest is
/// `member`; None when the id carries no removal tag (older or other re-keys).
pub fn removed(archive_id: &str, mark: &[u8], member: &[u8]) -> Option<bool> {
    let tail: String = archive_id.chars().skip(PREFIX_LEN).take(16).collect();
    let (tag, rest) = tail.split_at(tail.char_indices().nth(8).map_or(tail.len(), |(i, _)| i));
    if !same(tag, &chars(mark)) {
        return None;
    }
    Some(same(rest, &chars(member)))
}

fn str_arg<'a>(input: &'a Value, name: &str) -> Result<&'a str, String> {
    input
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{name} must be a string"))
}

fn digest_arg(input: &Value, name: &str) -> Result<Vec<u8>, String> {
    str_arg(input, name)
        .ok()
        .and_then(from_hex)
        .filter(|d| d.len() == DIGEST_LEN)
        .ok_or_else(|| format!("{name} must be a hex 16-byte digest"))
}

pub fn run(op: &str, input: &str) -> Option<Result<Value, String>> {
    if !matches!(
        op,
        "removal_archive_messages" | "removal_archive_id" | "removal_archive_check"
    ) {
        return None;
    }
    let out = (|| -> Result<Value, String> {
        let input: Value = serde_json::from_str(input).map_err(|e| format!("bad input: {e}"))?;
        Ok(match op {
            "removal_archive_messages" => {
                let (mark, member) =
                    messages(str_arg(&input, "new_dek_id")?, str_arg(&input, "user_id")?)?;
                json!({"mark": crate::teamlog::to_hex(&mark), "member": crate::teamlog::to_hex(&member)})
            }
            "removal_archive_id" => json!(archive_id(
                str_arg(&input, "prefix")?,
                &digest_arg(&input, "mark")?,
                &digest_arg(&input, "member")?,
            )?),
            "removal_archive_check" => json!(removed(
                str_arg(&input, "archive_id")?,
                &digest_arg(&input, "mark")?,
                &digest_arg(&input, "member")?,
            )),
            _ => unreachable!(),
        })
    })();
    Some(out)
}

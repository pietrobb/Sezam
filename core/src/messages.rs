//! Signed messages (docs/CORE_UNIFICATION.md U6, domain D): the bytes an
//! identity or recovery key signs for a login, a key rotation, a reseed or
//! rejoin and an org-recovery rewrap. One copy; it replaced the builders in
//! server/app/auth.py, routers/recovery.py, the desktop (sync_common,
//! reseed, key_rotation), app.js and the phone. Signing and verifying stay
//! with each platform's libsodium.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::formats::id_bytes;
use crate::teamlog::{from_hex, to_hex};

pub const AUTH_SIGNATURE_CONTEXT: &[u8] = b"sezam-auth-challenge-signature-v1";
pub const CURRENT_KEY_PROOF_CONTEXT: &[u8] = b"sezam-current-key-proof-v1";
pub const AUTH_CHALLENGE_LENGTH: usize = 40;
pub const KEY_ROTATION_CONTEXT: &[u8] = b"sezam-key-rotation-v1";
pub const RESEED_CONTEXT: &[u8] = b"sezam-reseed-v1";
pub const REJOIN_CONTEXT: &[u8] = b"sezam-rejoin-v1";
pub const ORG_RECOVERY_REWRAP_CONTEXT: &[u8] = b"sezam-org-recovery-rewrap-v1\x00";

/// What a key signs to answer a login challenge: context || challenge, and
/// only a challenge of the server's fixed layout, so a server cannot have it
/// sign bytes of its choosing under the guise of a login. `current_key` is
/// the proof of the team log's current key next to a retired one
/// (capability run 300).
pub fn auth_challenge_message(challenge: &[u8], current_key: bool) -> Result<Vec<u8>, String> {
    if challenge.len() != AUTH_CHALLENGE_LENGTH {
        return Err(format!(
            "a login challenge is {AUTH_CHALLENGE_LENGTH} bytes, not {}",
            challenge.len()
        ));
    }
    let context = if current_key {
        CURRENT_KEY_PROOF_CONTEXT
    } else {
        AUTH_SIGNATURE_CONTEXT
    };
    Ok([context, challenge].concat())
}

/// What the new signing key signs to vouch for the old one.
pub fn key_rotation_message(user_id: &str, keys: [&[u8; 32]; 4]) -> Result<Vec<u8>, String> {
    let mut out = [KEY_ROTATION_CONTEXT, &id_bytes(user_id)?].concat();
    for key in keys {
        out.extend_from_slice(key);
    }
    Ok(out)
}

/// What the identity key signs to seed an empty server with an existing
/// account (`rejoin` false) or to bring back a member account a restore lost.
/// Domain-separated from the login message, so neither stands in for the other.
pub fn reseed_message(
    rejoin: bool,
    challenge: &[u8],
    user_id: &str,
    username: &str,
    signing_pk: &[u8; 32],
    encryption_pk: &[u8; 32],
    key_epoch: u64,
) -> Result<Vec<u8>, String> {
    let name = username.as_bytes();
    let len = u16::try_from(name.len()).map_err(|_| "username is too long".to_string())?;
    let context = if rejoin {
        REJOIN_CONTEXT
    } else {
        RESEED_CONTEXT
    };
    Ok([
        context,
        challenge,
        &id_bytes(user_id)?,
        &len.to_be_bytes(),
        name,
        signing_pk,
        encryption_pk,
        &key_epoch.to_be_bytes(),
    ]
    .concat())
}

/// What the recovery key signs to re-store its server blob without the
/// password (review d615826): the user id as it is, not padded.
pub fn org_recovery_rewrap_message(
    user_id: &str,
    key_epoch: u64,
    threshold: u8,
    total_shares: u8,
    wrapped_kek: &[u8],
) -> Result<Vec<u8>, String> {
    if !user_id.is_ascii() {
        return Err(format!("a user id is ASCII, not {user_id:?}"));
    }
    Ok([
        ORG_RECOVERY_REWRAP_CONTEXT,
        user_id.as_bytes(),
        &key_epoch.to_be_bytes(),
        &[threshold, total_shares],
        &Sha256::digest(wrapped_kek),
    ]
    .concat())
}

fn arg<'a>(input: &'a Value, name: &str) -> Result<&'a Value, String> {
    input.get(name).ok_or_else(|| format!("{name} is missing"))
}

fn str_arg<'a>(input: &'a Value, name: &str) -> Result<&'a str, String> {
    arg(input, name)?
        .as_str()
        .ok_or_else(|| format!("{name} must be a string"))
}

fn u64_arg(input: &Value, name: &str) -> Result<u64, String> {
    arg(input, name)?
        .as_u64()
        .ok_or_else(|| format!("{name} must be a non-negative integer"))
}

fn u8_arg(input: &Value, name: &str) -> Result<u8, String> {
    u8::try_from(u64_arg(input, name)?).map_err(|_| format!("{name} must fit a byte"))
}

fn bytes_arg(input: &Value, name: &str) -> Result<Vec<u8>, String> {
    let text = str_arg(input, name)?;
    if text.len() % 2 != 0 {
        return Err(format!("{name} must be hex"));
    }
    from_hex(&text.to_ascii_lowercase()).ok_or_else(|| format!("{name} must be hex"))
}

fn key_arg(input: &Value, name: &str) -> Result<[u8; 32], String> {
    bytes_arg(input, name)?
        .try_into()
        .map_err(|_| format!("{name} must be 32 bytes"))
}

fn bool_arg(input: &Value, name: &str) -> Result<bool, String> {
    match input.get(name) {
        None => Ok(false),
        Some(v) => v
            .as_bool()
            .ok_or_else(|| format!("{name} must be a boolean")),
    }
}

/// The JSON ops: every message comes back as hex.
pub fn run(op: &str, input: &str) -> Option<Result<Value, String>> {
    if !matches!(
        op,
        "auth_challenge_message"
            | "key_rotation_message"
            | "reseed_message"
            | "org_recovery_rewrap_message"
    ) {
        return None;
    }
    let message = (|| {
        let input: Value = serde_json::from_str(input).map_err(|e| e.to_string())?;
        match op {
            "auth_challenge_message" => auth_challenge_message(
                &bytes_arg(&input, "challenge")?,
                bool_arg(&input, "current_key")?,
            ),
            "key_rotation_message" => key_rotation_message(
                str_arg(&input, "user_id")?,
                [
                    &key_arg(&input, "old_signing_pk")?,
                    &key_arg(&input, "old_encryption_pk")?,
                    &key_arg(&input, "new_signing_pk")?,
                    &key_arg(&input, "new_encryption_pk")?,
                ],
            ),
            "reseed_message" => reseed_message(
                bool_arg(&input, "rejoin")?,
                &bytes_arg(&input, "challenge")?,
                str_arg(&input, "user_id")?,
                str_arg(&input, "username")?,
                &key_arg(&input, "signing_pk")?,
                &key_arg(&input, "encryption_pk")?,
                u64_arg(&input, "key_epoch")?,
            ),
            "org_recovery_rewrap_message" => org_recovery_rewrap_message(
                str_arg(&input, "user_id")?,
                u64_arg(&input, "key_epoch")?,
                u8_arg(&input, "threshold")?,
                u8_arg(&input, "total_shares")?,
                &bytes_arg(&input, "wrapped_kek")?,
            ),
            _ => unreachable!(),
        }
    })();
    Some(message.map(|m| json!(to_hex(&m))))
}

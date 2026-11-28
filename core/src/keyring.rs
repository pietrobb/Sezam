//! The key ring of an account (capability review 716): which retired signing
//! keys of `GET /api/users/{id}/keys` a client trusts. One copy for the
//! desktop, the web and the phone; it replaced sync_common.key_ring_from_response,
//! the web's verifyArchivedKeyChain and the phone's loop in sync_service.dart.
//!
//! An archived key is trusted only if its successor (the current key or an
//! archive already trusted) signed `key_rotation_message` for it, and, when the
//! server kept it, the old key's own authorization of that rotation verifies
//! too (review 688edcb V4). The core parses the response and names every
//! signature to check (`key_ring_checks`); the client verifies them with its
//! libsodium and the core walks the chain (`key_ring`), the split of the key
//! vouchers.
//!
//! One answer for what the three copies read differently:
//! - an archive without `successor_signing_pk` or `rotation_signature` (absent,
//!   null or empty) is an uncertified legacy archive: never trusted, skipped;
//! - any other malformed field of an archive (no `key_fingerprint`, one that
//!   does not match, keys not 32 bytes, bad hex) refuses the whole response;
//! - at most [`MAX_ARCHIVES`] archives, as the server serves.

use std::collections::BTreeMap;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::messages::key_rotation_message;
use crate::teamlog::{from_hex, to_hex};

/// The server serves at most this many archived keys (server/app/routers/users.py).
pub const MAX_ARCHIVES: usize = 64;

struct Archive {
    signing_pk: [u8; 32],
    encryption_pk: [u8; 32],
    successor: [u8; 32],
    certificate: Vec<u8>,
    authorization: Option<Vec<u8>>,
}

/// One signature for the client to verify.
struct Check {
    message: Vec<u8>,
    signature: Vec<u8>,
    public_key: [u8; 32],
}

fn hex_bytes(text: &str, name: &str) -> Result<Vec<u8>, String> {
    from_hex(&text.to_ascii_lowercase()).ok_or_else(|| format!("{name} is not hex"))
}

fn key(value: Option<&Value>, name: &str) -> Result<[u8; 32], String> {
    let text = value
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{name} is required"))?;
    hex_bytes(text, name)?
        .try_into()
        .map_err(|_| format!("{name} must be 32 bytes"))
}

/// A present, non-empty string field; None when absent, null or empty.
fn optional_str<'a>(archive: &'a Value, name: &str) -> Result<Option<&'a str>, String> {
    match archive.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(format!("archived key {name} must be a string")),
    }
}

fn fingerprint(signing_pk: &[u8; 32], encryption_pk: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(signing_pk);
    hasher.update(encryption_pk);
    to_hex(&hasher.finalize())
}

/// The certified archives of a served `archived_keys`, in served order.
fn archives(served: Option<&Value>) -> Result<Vec<Archive>, String> {
    let list = match served {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(list)) => list,
        Some(_) => return Err("malformed archived key list".into()),
    };
    if list.len() > MAX_ARCHIVES {
        return Err(format!("more than {MAX_ARCHIVES} archived keys"));
    }
    let mut out = Vec::new();
    for archive in list {
        if !archive.is_object() {
            return Err("malformed archived key".into());
        }
        let successor = optional_str(archive, "successor_signing_pk")?;
        let certificate = optional_str(archive, "rotation_signature")?;
        let (Some(successor), Some(certificate)) = (successor, certificate) else {
            continue; // uncertified legacy archive: never trusted
        };
        let signing_pk = key(archive.get("signing_pk"), "archived signing_pk")?;
        let encryption_pk = key(archive.get("encryption_pk"), "archived encryption_pk")?;
        if archive.get("key_fingerprint").and_then(Value::as_str)
            != Some(fingerprint(&signing_pk, &encryption_pk).as_str())
        {
            return Err("archived key fingerprint mismatch".into());
        }
        let authorization = optional_str(archive, "authorization_signature")?
            .map(|a| hex_bytes(a, "authorization_signature"))
            .transpose()?;
        out.push(Archive {
            signing_pk,
            encryption_pk,
            successor: hex_bytes(successor, "successor_signing_pk")?
                .try_into()
                .map_err(|_| "successor_signing_pk must be 32 bytes".to_string())?,
            certificate: hex_bytes(certificate, "rotation_signature")?,
            authorization,
        });
    }
    Ok(out)
}

/// (signing key, encryption key).
type KeyPair = ([u8; 32], [u8; 32]);
/// (archive, successor's encryption key) → (certificate check, authorization check).
type CheckIndex = BTreeMap<(usize, [u8; 32]), (usize, Option<usize>)>;

struct Ring {
    user_id: String,
    current: KeyPair,
    archives: Vec<Archive>,
}

impl Ring {
    fn parse(input: &Value) -> Result<Self, String> {
        Ok(Ring {
            user_id: input
                .get("user_id")
                .and_then(Value::as_str)
                .ok_or("user_id is required")?
                .to_string(),
            current: (
                key(input.get("current_signing_pk"), "current_signing_pk")?,
                key(input.get("current_encryption_pk"), "current_encryption_pk")?,
            ),
            archives: archives(input.get("archived_keys"))?,
        })
    }

    /// Every check, and per (archive, successor's encryption key) the indexes
    /// of its certificate check and of its authorization check.
    fn checks(&self) -> Result<(Vec<Check>, CheckIndex), String> {
        let mut checks = Vec::new();
        let mut index = BTreeMap::new();
        for (i, a) in self.archives.iter().enumerate() {
            if a.certificate.len() != 64
                || a.authorization.as_ref().is_some_and(|s| s.len() != 64)
                || a.signing_pk == self.current.0
            {
                continue; // can never be trusted
            }
            // The successor's encryption key is that of whichever entry with
            // its signing key the chain trusts first: name each one.
            let mut successors = Vec::new();
            if a.successor == self.current.0 {
                successors.push(self.current.1);
            }
            for b in &self.archives {
                if b.signing_pk == a.successor && !successors.contains(&b.encryption_pk) {
                    successors.push(b.encryption_pk);
                }
            }
            for successor_encryption in successors {
                let message = key_rotation_message(
                    &self.user_id,
                    [
                        &a.signing_pk,
                        &a.encryption_pk,
                        &a.successor,
                        &successor_encryption,
                    ],
                )?;
                let cert = checks.len();
                checks.push(Check {
                    message: message.clone(),
                    signature: a.certificate.clone(),
                    public_key: a.successor,
                });
                let auth = a.authorization.as_ref().map(|signature| {
                    checks.push(Check {
                        message,
                        signature: signature.clone(),
                        public_key: a.signing_pk,
                    });
                    checks.len() - 1
                });
                index.insert((i, successor_encryption), (cert, auth));
            }
        }
        Ok((checks, index))
    }

    /// The trusted (signing, encryption) keys, current first, in chain order.
    fn trusted(&self, verified: &[bool]) -> Result<Vec<KeyPair>, String> {
        let (_, index) = self.checks()?;
        let ok = |i: usize| verified.get(i).copied().unwrap_or(false);
        let mut trusted = vec![self.current];
        let mut progress = true;
        while progress {
            progress = false;
            for (i, a) in self.archives.iter().enumerate() {
                if trusted.iter().any(|t| t.0 == a.signing_pk) {
                    continue;
                }
                let Some(successor) = trusted.iter().find(|t| t.0 == a.successor) else {
                    continue;
                };
                let Some(&(cert, auth)) = index.get(&(i, successor.1)) else {
                    continue;
                };
                if ok(cert) && auth.is_none_or(ok) {
                    trusted.push((a.signing_pk, a.encryption_pk));
                    progress = true;
                }
            }
        }
        Ok(trusted)
    }
}

/// The `key_ring*` operations; None: not one of them.
pub fn run(op: &str, input: &str) -> Option<Result<Value, String>> {
    if op != "key_ring_checks" && op != "key_ring" {
        return None;
    }
    let out = (|| -> Result<Value, String> {
        let input: Value = serde_json::from_str(input).map_err(|e| format!("bad input: {e}"))?;
        let ring = Ring::parse(&input)?;
        Ok(match op {
            "key_ring_checks" => {
                let (checks, _) = ring.checks()?;
                json!(checks
                    .iter()
                    .map(|c| json!({
                        "message": to_hex(&c.message),
                        "signature": to_hex(&c.signature),
                        "public_key": to_hex(&c.public_key),
                    }))
                    .collect::<Vec<_>>())
            }
            "key_ring" => {
                let verified: Vec<bool> = input
                    .get("verified")
                    .and_then(Value::as_array)
                    .ok_or("verified is required")?
                    .iter()
                    .map(|v| v.as_bool() == Some(true))
                    .collect();
                json!(ring
                    .trusted(&verified)?
                    .iter()
                    .map(|(s, e)| json!({"signing_pk": to_hex(s), "encryption_pk": to_hex(e)}))
                    .collect::<Vec<_>>())
            }
            _ => unreachable!(),
        })
    })();
    Some(out)
}

//! Replaying records onto a state, and a side's own change projected onto
//! it for local decisions.

use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::canonical::{is_kind, parse_body, validate_body};
use super::{
    from_hex, int, opt_text, text, to_hex, Generation, LogError, LogResult, Member, State,
    HASH_DOMAIN, NEW_KEY_DOMAIN, SIG_DOMAIN,
};

/// One signature the side checks with its own libsodium.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Check {
    /// the record's position
    pub seq: i64,
    /// Ed25519 public key, hex
    pub pk: String,
    /// the signed message, hex
    pub message: String,
    /// the signature, hex
    pub sig: String,
}

/// Where a replay's signature checks come from.
trait Verifier {
    fn verify(&mut self, seq: i64, pk: &str, message: &[u8], sig: &str) -> bool;
}

/// First run: every check passes and is written down.
struct Collect(Vec<Check>);

impl Verifier for Collect {
    fn verify(&mut self, seq: i64, pk: &str, message: &[u8], sig: &str) -> bool {
        self.0.push(Check {
            seq,
            pk: pk.to_string(),
            message: to_hex(message),
            sig: sig.to_string(),
        });
        true
    }
}

/// Second run: the first `passed` checks passed, the next one did not.
struct Counted {
    passed: usize,
    seen: usize,
}

impl Verifier for Counted {
    fn verify(&mut self, _: i64, _: &str, _: &[u8], _: &str) -> bool {
        self.seen += 1;
        self.seen <= self.passed
    }
}

fn sig_message(body: &str) -> Vec<u8> {
    [SIG_DOMAIN.as_bytes(), body.as_bytes()].concat()
}

/// The record's hash: what the next record names as `prev`.
pub fn record_hash(body: &str, sig: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(HASH_DOMAIN.as_bytes());
    hasher.update(body.as_bytes());
    hasher.update(from_hex(sig).unwrap_or_default());
    to_hex(&hasher.finalize())
}

/// What a member.keys' new signing key signs: the head it builds on, the
/// account and both new keys.
pub fn new_key_message(
    prev: &str,
    user_id: &str,
    signing_pk: &str,
    encryption_pk: &str,
) -> Vec<u8> {
    [
        NEW_KEY_DOMAIN.as_bytes(),
        &from_hex(prev).unwrap_or_default(),
        user_id.as_bytes(),
        &from_hex(signing_pk).unwrap_or_default(),
        &from_hex(encryption_pk).unwrap_or_default(),
    ]
    .concat()
}

fn verify(
    v: &mut dyn Verifier,
    pk: &str,
    message: &[u8],
    sig: &str,
    seq: i64,
    code: &str,
) -> LogResult<()> {
    if v.verify(seq, pk, message, sig) {
        Ok(())
    } else {
        Err(LogError::new(code, Some(seq), ""))
    }
}

fn claim_keys(state: &mut State, user_id: &str, seq: i64, pks: &[&str]) -> LogResult<()> {
    let current = state.members.get(user_id);
    for pk in pks {
        if let Some(owner) = state.seen_keys.get(*pk) {
            // Rules 2: a key the log retired stays retired, also for its owner.
            let retired = state.rules >= 2
                && current.is_none_or(|m| *pk != m.signing_pk && *pk != m.encryption_pk);
            if owner != user_id || retired {
                return Err(LogError::new("key_reused", Some(seq), ""));
            }
        }
    }
    if pks.len() == 2 && pks[0] == pks[1] {
        return Err(LogError::new("key_reused", Some(seq), ""));
    }
    for pk in pks {
        state.seen_keys.insert(pk.to_string(), user_id.to_string());
    }
    Ok(())
}

fn active_admins(state: &State) -> usize {
    state
        .members
        .values()
        .filter(|m| m.active && m.role == "admin")
        .count()
}

fn lose_access(state: &mut State, folder: &str, user_id: &str) {
    if let Some(a) = state.access.get_mut(folder) {
        a.remove(user_id);
    }
    state
        .stale
        .entry(folder.to_string())
        .or_default()
        .insert(user_id.to_string());
}

fn apply(state: &mut State, record: &Value, v: &mut dyn Verifier) -> LogResult<()> {
    let expected = state.head_seq + 1;
    let fields = match record {
        Value::Object(r) if r.len() == 2 && r.contains_key("body") && r.contains_key("sig") => r,
        _ => return Err(LogError::new("bad_schema", Some(expected), "record fields")),
    };
    if !is_kind("hex128", &fields["sig"]) {
        return Err(LogError::new("bad_schema", Some(expected), "sig"));
    }
    let sig = fields["sig"].as_str().unwrap_or_default();
    let text_body = fields["body"]
        .as_str()
        .ok_or_else(|| LogError::new("bad_encoding", Some(expected), "body is not a string"))?;
    let body = parse_body(text_body, Some(expected))?;
    validate_body(&body, expected)?;
    let seq = body["seq"].as_u64().unwrap_or_default() as i64;
    if seq != expected {
        return Err(LogError::new("bad_seq", Some(expected), ""));
    }
    let prev = body["prev"].as_str().unwrap_or_default();
    if prev != state.head_hash {
        return Err(LogError::new("bad_prev", Some(seq), ""));
    }
    let rules = body["v"].as_u64().unwrap_or_default();
    if rules < state.rules {
        return Err(LogError::new("rules_downgrade", Some(seq), ""));
    }
    state.rules = rules;

    let kind = body["type"].as_str().unwrap_or_default();
    let author = body["author"].as_str().unwrap_or_default();
    let data = body["data"].as_object().cloned().unwrap_or_default();
    let message = sig_message(text_body);

    if kind == "genesis" {
        if seq != 0 {
            return Err(LogError::new("bad_genesis", Some(seq), "not first"));
        }
        if author != text(&data, "user_id", seq)? {
            return Err(LogError::new("bad_genesis", Some(seq), "author"));
        }
        let signing = text(&data, "signing_pk", seq)?;
        let encryption = text(&data, "encryption_pk", seq)?;
        verify(v, signing, &message, sig, seq, "bad_signature")?;
        claim_keys(state, author, seq, &[signing, encryption])?;
        state.org = text(&data, "org", seq)?.to_string();
        state.members.insert(
            author.to_string(),
            Member {
                signing_pk: signing.to_string(),
                encryption_pk: encryption.to_string(),
                role: "admin".into(),
                active: true,
            },
        );
    } else {
        if seq == 0 {
            return Err(LogError::new(
                "bad_genesis",
                Some(seq),
                "first record is not genesis",
            ));
        }
        let signer = match state.members.get(author) {
            Some(m) if m.active => m.clone(),
            _ => return Err(LogError::new("not_member", Some(seq), "")),
        };
        verify(v, &signer.signing_pk, &message, sig, seq, "bad_signature")?;
        if kind != "member.keys" && signer.role != "admin" {
            return Err(LogError::new("not_admin", Some(seq), ""));
        }
        apply_change_in(state, seq, kind, author, &data, prev, v)?;
    }

    state.head_seq = seq;
    state.head_hash = record_hash(text_body, sig);
    if seq == 0 {
        state.genesis_hash = state.head_hash.clone();
    }
    Ok(())
}

fn apply_change_in(
    new: &mut State,
    seq: i64,
    kind: &str,
    author: &str,
    data: &Map<String, Value>,
    prev: &str,
    v: &mut dyn Verifier,
) -> LogResult<()> {
    let err = |code: &str| Err(LogError::new(code, Some(seq), ""));
    let user_id = data.get("user_id").and_then(Value::as_str).unwrap_or("");
    let member = new.members.get(user_id).cloned();
    let active = member.as_ref().is_some_and(|m| m.active);

    match kind {
        "member.add" => {
            if active {
                return err("member_exists");
            }
            let signing = text(data, "signing_pk", seq)?;
            let encryption = text(data, "encryption_pk", seq)?;
            let role = text(data, "role", seq)?;
            claim_keys(new, user_id, seq, &[signing, encryption])?;
            new.members.insert(
                user_id.to_string(),
                Member {
                    signing_pk: signing.to_string(),
                    encryption_pk: encryption.to_string(),
                    role: role.to_string(),
                    active: true,
                },
            );
        }
        "member.role" => {
            let role = text(data, "role", seq)?;
            let member = match member {
                Some(m) if m.active => m,
                _ => return err("not_active"),
            };
            if member.role == role {
                return err("unchanged");
            }
            if member.role == "admin" && active_admins(new) == 1 {
                return err("last_admin");
            }
            if member.role == "admin" {
                let folders: Vec<String> = new.folders.keys().cloned().collect();
                for folder in folders {
                    new.former_admins
                        .entry(folder)
                        .or_default()
                        .insert(user_id.to_string());
                }
                new.org_recovery.remove(user_id);
                new.org_recovery_wrap.remove(user_id);
            }
            if let Some(m) = new.members.get_mut(user_id) {
                m.role = role.to_string();
            }
        }
        "member.remove" => {
            let member = match member {
                Some(m) if m.active => m,
                _ => return err("not_active"),
            };
            if member.role == "admin" && active_admins(new) == 1 {
                return err("last_admin");
            }
            if let Some(m) = new.members.get_mut(user_id) {
                m.active = false;
            }
            new.org_recovery.remove(user_id);
            new.org_recovery_wrap.remove(user_id);
            let losing: Vec<String> = new
                .folders
                .iter()
                .filter(|(folder, gens)| {
                    new.access
                        .get(*folder)
                        .is_some_and(|a| a.contains_key(user_id))
                        || gens.last().is_some_and(|g| g.author == user_id)
                })
                .map(|(folder, _)| folder.clone())
                .collect();
            for folder in losing {
                lose_access(new, &folder, user_id);
            }
        }
        "member.keys" => {
            if author != user_id {
                return err("not_self");
            }
            let signing = text(data, "signing_pk", seq)?;
            let encryption = text(data, "encryption_pk", seq)?;
            let proof = text(data, "new_key_sig", seq)?;
            verify(
                v,
                signing,
                &new_key_message(prev, user_id, signing, encryption),
                proof,
                seq,
                "bad_new_key_signature",
            )?;
            // Review e443cbc H1: two keys the member does not hold in either
            // role (a swap X -> Y -> X looped the server's rotation walk).
            let member = member.ok_or_else(|| LogError::new("not_active", Some(seq), ""))?;
            let held = [member.signing_pk.as_str(), member.encryption_pk.as_str()];
            if held.contains(&signing) || held.contains(&encryption) {
                return err("key_reused");
            }
            claim_keys(new, user_id, seq, &[signing, encryption])?;
            if let Some(m) = new.members.get_mut(user_id) {
                m.signing_pk = signing.to_string();
                m.encryption_pk = encryption.to_string();
            }
        }
        "folder.key" => {
            let folder = text(data, "folder", seq)?;
            let dek_id = text(data, "dek_id", seq)?;
            let gen = int(data, "gen", seq)?;
            let prev_dek = opt_text(data, "prev_dek_id", seq)?;
            if new.dek_index.contains_key(dek_id) {
                return err("dek_reused");
            }
            match new.folders.get(folder) {
                None if gen != 0 || prev_dek.is_some() => return err("bad_generation"),
                Some(gens)
                    if gen != gens.len() as i64
                        || prev_dek != gens.last().map(|g| g.dek_id.as_str()) =>
                {
                    return err("bad_generation")
                }
                _ => {}
            }
            new.folders
                .entry(folder.to_string())
                .or_default()
                .push(Generation {
                    dek_id: dek_id.to_string(),
                    author: author.to_string(),
                });
            new.dek_index
                .insert(dek_id.to_string(), (folder.to_string(), gen));
            new.stale.remove(folder);
            new.former_admins.remove(folder);
        }
        "access.set" => {
            let folder = text(data, "folder", seq)?;
            let level = opt_text(data, "level", seq)?;
            if !new.folders.contains_key(folder) {
                return err("folder_unknown");
            }
            let current = new.access.get(folder).and_then(|a| a.get(user_id)).cloned();
            let Some(level) = level else {
                if current.is_none() {
                    return err("unchanged");
                }
                lose_access(new, folder, user_id);
                return Ok(());
            };
            if !active {
                return err("not_active");
            }
            if current.as_deref() == Some(level) {
                return err("unchanged");
            }
            if current.as_deref() == Some("write") && level == "read" {
                new.stale
                    .entry(folder.to_string())
                    .or_default()
                    .insert(user_id.to_string());
            }
            new.access
                .entry(folder.to_string())
                .or_default()
                .insert(user_id.to_string(), level.to_string());
        }
        "org.recovery" => {
            let pk = opt_text(data, "recovery_pk", seq)?;
            if new.org_recovery.get(author).map(String::as_str) == pk {
                return err("unchanged");
            }
            if pk.is_some_and(|pk| new.seen_keys.contains_key(pk)) {
                // a member's key is no recovery key
                return err("key_reused");
            }
            new.org_recovery_wrap.remove(author); // it wraps for the old key
            match pk {
                None => {
                    new.org_recovery.remove(author);
                }
                Some(pk) => {
                    new.org_recovery.insert(author.to_string(), pk.to_string());
                }
            }
        }
        "org.recovery.wrap" => {
            if !new.org_recovery.contains_key(author) {
                return err("no_recovery_key");
            }
            let threshold = int(data, "threshold", seq)?;
            let total = int(data, "total_shares", seq)?;
            if !(1 <= threshold && threshold <= total && total <= 255) {
                return err("bad_shares");
            }
            if new.org_recovery_wrap.get(author) == Some(data) {
                return err("unchanged");
            }
            new.org_recovery_wrap
                .insert(author.to_string(), data.clone());
        }
        _ => return Err(LogError::new("bad_schema", Some(seq), "type")),
    }
    Ok(())
}

fn run(
    records: &[Value],
    state: Option<&State>,
    v: &mut dyn Verifier,
    steps: Option<&mut Vec<State>>,
) -> LogResult<State> {
    let mut current = state.cloned().unwrap_or_default();
    let mut steps = steps;
    for record in records {
        apply(&mut current, record, v)?;
        if let Some(out) = steps.as_deref_mut() {
            out.push(current.clone());
        }
    }
    Ok(current)
}

/// First run: the signature checks a replay of `records` onto `state` (a
/// fresh log when None) needs, in order, as far as the records get when
/// every check passes.
pub fn checks(records: &[Value], state: Option<&State>) -> Vec<Check> {
    let mut collect = Collect(Vec::new());
    let _ = run(records, state, &mut collect, None);
    collect.0
}

/// Second run: replay `records` onto a copy of `state`, the first
/// `verified` checks of [`checks`] having passed and the next one not. The
/// whole call fails on the first bad record.
pub fn replay(records: &[Value], state: Option<&State>, verified: usize) -> LogResult<State> {
    run(
        records,
        state,
        &mut Counted {
            passed: verified,
            seen: 0,
        },
        None,
    )
}

/// Like [`replay`], with the state after each record.
pub fn replay_steps(
    records: &[Value],
    state: Option<&State>,
    verified: usize,
) -> LogResult<Vec<State>> {
    let mut steps = Vec::new();
    run(
        records,
        state,
        &mut Counted {
            passed: verified,
            seen: 0,
        },
        Some(&mut steps),
    )?;
    Ok(steps)
}

/// The state after `author`'s own unsigned change, for local decisions
/// only: the head does not move, the result is never a log to build on.
pub fn apply_change(
    state: &State,
    kind: &str,
    author: &str,
    data: &Map<String, Value>,
) -> LogResult<State> {
    let seq = state.head_seq + 1;
    if kind == "genesis" || kind == "member.keys" {
        return Err(LogError::new(
            "bad_schema",
            Some(seq),
            &format!("{kind} is not projected"),
        ));
    }
    let mut new = state.clone();
    let mut none = Counted { passed: 0, seen: 0 };
    let head = state.head_hash.clone();
    apply_change_in(&mut new, seq, kind, author, data, &head, &mut none)?;
    Ok(new)
}

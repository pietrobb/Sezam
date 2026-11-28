//! Authority over folders and items: which pulled writes a client does not
//! apply or show (review 7c10379 H4, a159e97 H4, 1141a20 H5/H6, TL5, TL7).
//! One copy for the clients (docs/CORE_UNIFICATION.md U5); it replaced
//! unauthorizedWrites/webTeamFolderAbove/sealingDekId/webLogAdmins of
//! web/static/js/app.js and their ports in mobile/lib/services/
//! write_authority.dart, which had drifted apart (the phone had no own-grant
//! rule below this account's own root and no held copy for a move).
//!
//! Judged by signatures (the account whose signature verified, not the
//! unsigned owner_id): directly below a top-level folder writes this account,
//! an account that signed what only an admin may push (a top-level folder,
//! envelope, key archive, folder key, audit record), a member with a write
//! grant on a key of that folder, and - a folder only - its author under a key
//! of the author's own (a personal folder). Inside a member's personal folder
//! everything is sealed with that member's keys. With a team log a folder or
//! item in a team folder is the log's alone (rules::item_refusal, sealing
//! false), a removal needs write access where it was (in `previous`), and
//! outside team folders only the log's admins count; no unsigned access_level
//! grants write, a top-level folder is an admin's or its signer's own tree,
//! and below the first level of the organisation's tree only an admin writes.

use std::collections::{BTreeSet, HashMap};

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::teamlog::{rules, State};

/// Depth bound of every walk up a tree (as each client had it).
const MAX_DEPTH: usize = 64;

/// One sync object as the client holds it (the fields authority reads).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Obj {
    pub id: String,
    pub object_type: String,
    #[serde(default)]
    pub parent_ref: Option<String>,
    #[serde(default, deserialize_with = "flag")]
    pub is_deleted: bool,
    /// The account whose signature verified (the client's fallback included).
    #[serde(default)]
    pub signer: Option<String>,
    #[serde(default)]
    pub access_level: Option<String>,
    #[serde(default)]
    pub target_user_id: Option<String>,
    /// The key the sealed meta's header names (`sealing_dek_id`).
    #[serde(default)]
    pub dek_id: Option<String>,
}

fn flag<'de, D: serde::Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    Ok(match Value::deserialize(d)? {
        Value::Bool(b) => b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::Null => false,
        _ => return Err(serde::de::Error::custom("is_deleted must be a flag")),
    })
}

impl Obj {
    fn parent(&self) -> Option<&str> {
        self.parent_ref.as_deref().filter(|p| !p.is_empty())
    }
}

/// The DEK id a sealed folder meta or item meta names in its header. `head`
/// is the payload's start (an item: u32be meta length, then its meta
/// envelope; 57 bytes suffice). None when no envelope header is there.
pub fn sealing_dek_id(object_type: &str, head: &[u8]) -> Option<String> {
    let is_envelope = |b: &[u8]| b.len() >= 53 && b[0] == 1 && b[1] == 1;
    let mut bytes = head;
    if object_type == "entry" && !is_envelope(bytes) {
        bytes = bytes.get(4..)?;
    }
    if !is_envelope(bytes) {
        return None;
    }
    let id: String = bytes[3..29]
        .iter()
        .filter(|&&c| c != 0)
        .map(|&c| c as char)
        .collect();
    (!id.is_empty() && bytes[3..29].is_ascii()).then_some(id)
}

/// Objects by id in their first order, the last copy of an id winning.
struct Snapshot<'a> {
    order: Vec<&'a str>,
    by_id: HashMap<&'a str, &'a Obj>,
}

impl<'a> Snapshot<'a> {
    fn new(objects: &'a [Obj]) -> Self {
        let mut order = Vec::new();
        let mut by_id = HashMap::new();
        for obj in objects {
            if by_id.insert(obj.id.as_str(), obj).is_none() {
                order.push(obj.id.as_str());
            }
        }
        Snapshot { order, by_id }
    }

    fn get(&self, id: &str) -> Option<&'a Obj> {
        self.by_id.get(id).copied()
    }

    fn node(&self, id: &str) -> Option<&'a Obj> {
        self.get(id).filter(|o| o.object_type == "node")
    }

    /// The team folder at or above node `node_id`, or None.
    fn team_folder_above(&self, team: &State, node_id: Option<&str>) -> Option<String> {
        let mut current = node_id.filter(|n| !n.is_empty());
        for _ in 0..MAX_DEPTH {
            let id = current?;
            if rules::is_team_folder(team, id) {
                return Some(id.to_string());
            }
            current = self.node(id)?.parent();
        }
        None
    }
}

/// What not to apply: `blocked` (and all below), and among them
/// `by_team_log`, the ones the team log refused (the caller keeps what it
/// showed before).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Verdict {
    pub blocked: Vec<String>,
    pub by_team_log: BTreeSet<String>,
}

type Signer = Option<String>;

struct Ctx<'a> {
    snap: Snapshot<'a>,
    prev: Option<Snapshot<'a>>,
    own_user_id: Signer,
    team: Option<&'a State>,
    admins: BTreeSet<Signer>,
    personal_dek_signers: HashMap<&'a str, Signer>,
    write_grants: BTreeSet<(Signer, &'a str)>,
    own_write_grants: BTreeSet<(Signer, &'a str)>,
}

#[derive(Default)]
struct Judged {
    verdicts: HashMap<String, bool>,
    personal_owner: HashMap<String, String>,
    by_team_log: BTreeSet<String>,
}

impl<'a> Ctx<'a> {
    fn is_own(&self, signer: &Signer) -> bool {
        *signer == self.own_user_id
    }

    /// The signer of the account's own key `rec` is sealed with; None: no such key.
    fn sealed_by(&self, rec: &Obj) -> Option<&Signer> {
        self.personal_dek_signers.get(rec.dek_id.as_deref()?)
    }

    fn known(team: &State, dek_id: Option<&str>) -> bool {
        dek_id.is_some_and(|d| team.dek_index.contains_key(d))
    }

    /// None: the log does not decide; Some(None): valid; Some(Some(why)).
    fn team_refusal(&self, team: &State, rec: &Obj) -> Option<Option<&'static str>> {
        let author = rec.signer.clone().unwrap_or_default();
        let folder = self.snap.team_folder_above(team, rec.parent());
        let held = self
            .prev
            .as_ref()
            .and_then(|p| p.get(&rec.id))
            .filter(|h| !h.is_deleted);
        let stored = held.and_then(|h| h.dek_id.as_deref());
        if rec.is_deleted {
            if folder.is_none() && !Self::known(team, stored) {
                return None;
            }
            return Some(rules::tombstone_refusal(team, &author, stored));
        }
        let dek_id = rec.dek_id.as_deref();
        // TL7: one's own personal object may leave for the personal root
        // (only its author holds that key to seal the next version).
        let own_personal = stored.is_some() && stored == dek_id && !Self::known(team, stored);
        let left = held.and_then(|h| self.prev.as_ref()?.team_folder_above(team, h.parent()));
        if let Some(why) = rules::move_refusal(
            team,
            &author,
            left.as_deref(),
            folder.as_deref(),
            own_personal,
        ) {
            return Some(Some(why));
        }
        if folder.is_none() && !Self::known(team, dek_id) {
            return None;
        }
        let own_dek = dek_id.is_some() && self.sealed_by(rec) == Some(&rec.signer);
        Some(rules::item_refusal(
            team,
            &author,
            &rec.id,
            folder.as_deref(),
            dek_id,
            own_dek,
            false,
        ))
    }

    /// true: `rec` is blocked.
    fn judge(&self, j: &mut Judged, rec: &Obj, depth: usize) -> bool {
        if let Some(v) = j.verdicts.get(&rec.id) {
            return *v;
        }
        let v = self.decide(j, rec, depth);
        j.verdicts.insert(rec.id.clone(), v);
        v
    }

    fn decide(&self, j: &mut Judged, rec: &Obj, depth: usize) -> bool {
        let parent = rec
            .parent()
            .and_then(|p| self.snap.node(p))
            .filter(|_| depth < MAX_DEPTH);
        let decided = self.team.and_then(|t| self.team_refusal(t, rec));
        let author = &rec.signer;
        if let Some(parent) = parent {
            if self.judge(j, parent, depth + 1) {
                if j.by_team_log.contains(&parent.id) {
                    j.by_team_log.insert(rec.id.clone());
                }
                return true;
            }
        }
        if self.team.is_some()
            && rec.parent().is_none()
            && rec.object_type == "node"
            && !rec.is_deleted
        {
            // A top-level folder is an admin's (the organisation's root) or
            // its signer's own tree under a key of their own; not one the
            // server re-signed under another account (review 1141a20 H5).
            return !self.is_own(author)
                && !self.admins.contains(author)
                && self.sealed_by(rec) != Some(author);
        }
        if let Some(refusal) = decided {
            if refusal.is_some() {
                j.by_team_log.insert(rec.id.clone());
            }
            return refusal.is_some();
        }
        let Some(parent) = parent else {
            return false;
        };
        let sealed: Signer = self.sealed_by(rec).cloned().flatten();
        if parent.parent().is_some() {
            let owner = j.personal_owner.get(&parent.id).cloned();
            let mut blocked = false;
            if let Some(owner) = &owner {
                if self.own_user_id.as_deref() != Some(owner.as_str())
                    && !rec.is_deleted
                    && sealed.as_deref() != Some(owner.as_str())
                {
                    blocked = true;
                }
                if rec.object_type == "node" {
                    j.personal_owner.insert(rec.id.clone(), owner.clone());
                }
            }
            if self.team.is_some()
                && owner.is_none()
                && !rec.is_deleted
                && !self.is_own(author)
                && !self.admins.contains(author)
            {
                // Review 1141a20 H6: below the first level of the
                // organisation's own tree (no team folder, no personal tree)
                // only its admin writes.
                blocked = true;
            }
            return blocked;
        }
        if self.is_own(author) {
            return false;
        }
        let key = (author.clone(), parent.id.as_str());
        let granted = if self.team.is_some() {
            self.admins.contains(author)
        } else if self.is_own(&parent.signer) {
            // Review a159e97 H4 / capability run 196: directly below this
            // account's own top-level folder an 'admin' is the server's word;
            // only a write grant this account made counts there.
            self.own_write_grants.contains(&key)
        } else {
            self.admins.contains(author) || self.write_grants.contains(&key)
        };
        if granted {
            return false;
        }
        if rec.object_type == "node" && sealed == *author {
            if let Some(a) = author {
                j.personal_owner.insert(rec.id.clone(), a.clone());
            }
            return false;
        }
        !rec.is_deleted
    }
}

/// The ids of folders and items in `objects` not to apply or show.
/// `previous`: the snapshot before this pull (where a removal was);
/// `team_admins`: the admins outside team folders with a log (default: the
/// log's current admins; clients pass `log_admins`).
pub fn unauthorized_writes(
    objects: &[Obj],
    own_user_id: Option<&str>,
    team: Option<&State>,
    previous: Option<&[Obj]>,
    team_admins: Option<&BTreeSet<String>>,
) -> Verdict {
    let snap = Snapshot::new(objects);
    let records: Vec<&Obj> = snap.order.iter().map(|id| snap.by_id[id]).collect();
    let mut admins: BTreeSet<Signer> = BTreeSet::new();
    let mut personal_dek_signers = HashMap::new();
    let mut dek_folders: HashMap<&str, &str> = HashMap::new();
    for rec in &records {
        match rec.object_type.as_str() {
            "envelope" | "dek_archive" | "audit" => {
                admins.insert(rec.signer.clone());
            }
            "dek" => match rec.parent() {
                Some(parent) => {
                    admins.insert(rec.signer.clone());
                    dek_folders.insert(rec.id.as_str(), parent);
                }
                None => {
                    personal_dek_signers.insert(rec.id.as_str(), rec.signer.clone());
                }
            },
            _ => {}
        }
    }
    for rec in &records {
        if rec.object_type != "node" || rec.parent().is_some() {
            continue;
        }
        // Only an admin writes a top-level node sealed with a folder's key.
        // TL7: one sealed with a key of its signer's own that names no folder
        // is that account's own tree (a member's personal root); no admin.
        let sealed = rec
            .dek_id
            .as_deref()
            .and_then(|d| personal_dek_signers.get(d));
        if rec.dek_id.is_none() || sealed != Some(&rec.signer) {
            admins.insert(rec.signer.clone());
        }
    }
    let own = own_user_id.map(str::to_string);
    let mut write_grants = BTreeSet::new();
    let mut own_write_grants = BTreeSet::new();
    if team.is_none() {
        for rec in &records {
            if rec.object_type != "envelope"
                || rec.is_deleted
                || rec.access_level.as_deref() != Some("write")
            {
                continue;
            }
            let Some(folder) = rec.parent().and_then(|p| dek_folders.get(p).copied()) else {
                continue; // names no folder: grants nothing
            };
            write_grants.insert((rec.target_user_id.clone(), folder));
            if rec.signer == own {
                own_write_grants.insert((rec.target_user_id.clone(), folder));
            }
        }
    }
    if let Some(team) = team {
        admins = match team_admins {
            Some(list) => list.iter().cloned().map(Some).collect(),
            None => team
                .members
                .keys()
                .filter(|id| rules::is_admin(team, id))
                .cloned()
                .map(Some)
                .collect(),
        };
    }
    let ctx = Ctx {
        snap,
        prev: previous.map(Snapshot::new),
        own_user_id: own,
        team,
        admins,
        personal_dek_signers,
        write_grants,
        own_write_grants,
    };
    let mut judged = Judged::default();
    let mut blocked = Vec::new();
    for rec in &records {
        if (rec.object_type == "node" || rec.object_type == "entry")
            && ctx.judge(&mut judged, rec, 0)
        {
            blocked.push(rec.id.clone());
        }
    }
    Verdict {
        blocked,
        by_team_log: judged.by_team_log,
    }
}

/// Accounts the log ever made admin that are still active members: what they
/// wrote outside team folders while admin stays valid after a handover
/// (review 1141a20). `bodies`: the records' parsed bodies.
pub fn log_admins(bodies: &[Map<String, Value>], team: &State) -> BTreeSet<String> {
    let mut ever = BTreeSet::new();
    for body in bodies {
        let kind = body.get("type").and_then(Value::as_str).unwrap_or("");
        let data = body.get("data").and_then(Value::as_object);
        let named = if kind == "genesis" {
            body.get("author")
        } else if matches!(kind, "member.add" | "member.role")
            && data.and_then(|d| d.get("role")).and_then(Value::as_str) == Some("admin")
        {
            data.and_then(|d| d.get("user_id"))
        } else {
            None
        };
        if let Some(id) = named.and_then(Value::as_str) {
            ever.insert(id.to_string());
        }
    }
    ever.into_iter()
        .filter(|id| team.members.get(id).is_some_and(|m| m.active))
        .collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WritesIn {
    objects: Vec<Obj>,
    own_user_id: Option<String>,
    #[serde(default)]
    team: Option<State>,
    #[serde(default)]
    team_handle: Option<u64>,
    #[serde(default)]
    previous: Option<Vec<Obj>>,
    #[serde(default)]
    team_admins: Option<BTreeSet<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminsIn {
    /// The log's record bodies (canonical JSON strings), in order.
    bodies: Vec<String>,
    #[serde(default)]
    team: Option<State>,
    #[serde(default)]
    team_handle: Option<u64>,
}

/// `team` or the state loaded under `team_handle`.
fn team_of(
    team: Option<State>,
    handle: Option<u64>,
) -> Result<Option<std::sync::Arc<State>>, String> {
    match (team, handle) {
        (Some(_), Some(_)) => Err("team or team_handle, not both".into()),
        (Some(t), None) => Ok(Some(std::sync::Arc::new(t))),
        (None, Some(h)) => crate::teamlog::ops::loaded_state(h).map(Some),
        (None, None) => Ok(None),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadIn {
    object_type: String,
    head: String,
}

/// The `authority_*` operations; None: not one of them.
pub fn run(op: &str, input: &str) -> Option<Result<Value, String>> {
    if !op.starts_with("authority_") {
        return None;
    }
    let bad = |e: serde_json::Error| format!("bad input: {e}");
    let out = (|| -> Result<Value, String> {
        Ok(match op {
            "authority_unauthorized_writes" => {
                let i: WritesIn = serde_json::from_str(input).map_err(bad)?;
                let team = team_of(i.team, i.team_handle)?;
                let v = unauthorized_writes(
                    &i.objects,
                    i.own_user_id.as_deref(),
                    team.as_deref(),
                    i.previous.as_deref(),
                    i.team_admins.as_ref(),
                );
                json!({"blocked": v.blocked, "by_team_log": v.by_team_log})
            }
            "authority_log_admins" => {
                let i: AdminsIn = serde_json::from_str(input).map_err(bad)?;
                let team = team_of(i.team, i.team_handle)?.ok_or("team or team_handle needed")?;
                let bodies = i
                    .bodies
                    .iter()
                    .map(|b| {
                        crate::teamlog::canonical::parse_body(b, None)
                            .map_err(|e| e.to_json().to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                json!(log_admins(&bodies, &team))
            }
            "authority_sealing_dek_id" => {
                let i: HeadIn = serde_json::from_str(input).map_err(bad)?;
                let head = crate::teamlog::from_hex(&i.head.to_ascii_lowercase())
                    .ok_or("head must be hex")?;
                json!(sealing_dek_id(&i.object_type, &head))
            }
            _ => return Err(format!("unknown operation {op:?}")),
        })
    })();
    Some(out)
}

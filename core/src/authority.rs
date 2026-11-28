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

use std::collections::{BTreeMap, BTreeSet, HashMap};

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
    /// Or the payload's start (hex): the core reads `dek_id` from it.
    #[serde(default)]
    pub head: Option<String>,
}

impl Obj {
    fn read_head(&mut self) -> Result<(), String> {
        if let Some(head) = self.head.take() {
            let bytes =
                crate::teamlog::from_hex(&head.to_ascii_lowercase()).ok_or("head must be hex")?;
            self.dek_id = sealing_dek_id(&self.object_type, &bytes);
        }
        Ok(())
    }
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

/// A client's own record of what it judged before (the desktop judges each
/// pull's batch against its database; web and phone send their whole state
/// and no context).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    /// Folders applied here and not judged again: walked only (their
    /// signer is not known).
    #[serde(default)]
    pub known_nodes: Vec<Obj>,
    /// Ids not applied before: everything below them is not applied either.
    #[serde(default)]
    pub refused: BTreeSet<String>,
    #[serde(default)]
    pub personal_dek_signers: HashMap<String, String>,
    /// A member's personal folder directly below a top-level folder -> member.
    #[serde(default)]
    pub personal_trees: HashMap<String, String>,
    /// Without a log: accounts seen signing what only an admin may push.
    #[serde(default)]
    pub admin_signers: BTreeSet<String>,
    /// Without a log: write grants held here (envelope id, grantee, folder, granter).
    #[serde(default)]
    pub write_grants: Vec<Grant>,
    /// The folder each key named by a pulled envelope belongs to here.
    #[serde(default)]
    pub dek_folders: HashMap<String, String>,
    /// This account's top-level folders among `known_nodes`.
    #[serde(default)]
    pub own_tops: BTreeSet<String>,
    /// Review a159e97 H2 (the desktop): the accounts this device has its own
    /// evidence for. Given, a folder or item below a folder neither this call
    /// nor `known_nodes` has is held back (not judged) unless this account or
    /// one of them wrote it. The caller passes what it held back before again
    /// with the batch. Web and phone send none and hold nothing.
    #[serde(default)]
    pub vouched: Option<BTreeSet<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub id: String,
    pub user_id: String,
    pub folder: String,
    pub by: String,
}

/// Objects by id in their first order, the last copy of an id winning;
/// a folder not among them may be one of the context's walk-only ones.
struct Snapshot<'a> {
    order: Vec<&'a str>,
    by_id: HashMap<&'a str, &'a Obj>,
    known: HashMap<&'a str, &'a Obj>,
}

impl<'a> Snapshot<'a> {
    fn new(objects: &'a [Obj], known: impl IntoIterator<Item = &'a Obj>) -> Self {
        let mut order = Vec::new();
        let mut by_id = HashMap::new();
        for obj in objects {
            if by_id.insert(obj.id.as_str(), obj).is_none() {
                order.push(obj.id.as_str());
            }
        }
        let known = known.into_iter().map(|o| (o.id.as_str(), o)).collect();
        Snapshot {
            order,
            by_id,
            known,
        }
    }

    fn get(&self, id: &str) -> Option<&'a Obj> {
        self.by_id.get(id).copied()
    }

    /// Judged in this call (not a walk-only folder).
    fn judged_here(&self, id: &str) -> bool {
        self.by_id.contains_key(id)
    }

    fn node(&self, id: &str) -> Option<&'a Obj> {
        match self.get(id) {
            Some(o) => Some(o).filter(|o| o.object_type == "node"),
            None => self.known.get(id).copied(),
        }
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
    /// Why the log refused each of `by_team_log` it decided itself.
    pub refusals: BTreeMap<String, String>,
    /// Blocked because the folder above was (in this call or before).
    pub below_refused: BTreeSet<String>,
    /// The context's personal trees after this call.
    pub personal_trees: BTreeMap<String, String>,
    /// Without a log: the accounts seen signing what only an admin may push.
    pub admin_signers: BTreeSet<String>,
    /// The signer of each key that names no folder (the context's and this call's).
    pub personal_dek_signers: BTreeMap<String, String>,
    /// Held back below a folder not known here (H2): neither applied nor
    /// judged; the caller judges them again once that folder arrives.
    pub held: Vec<String>,
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
    refused: &'a BTreeSet<String>,
    own_tops: &'a BTreeSet<String>,
}

#[derive(Default)]
struct Judged {
    verdicts: HashMap<String, bool>,
    /// Personal folders directly below a top-level folder -> member.
    personal_trees: BTreeMap<String, String>,
    by_team_log: BTreeSet<String>,
    refusals: BTreeMap<String, String>,
    below_refused: BTreeSet<String>,
}

impl<'a> Ctx<'a> {
    fn is_own(&self, signer: &Signer) -> bool {
        *signer == self.own_user_id
    }

    /// The signer of the account's own key `rec` is sealed with; None: no such key.
    fn sealed_by(&self, rec: &Obj) -> Option<&Signer> {
        self.personal_dek_signers.get(rec.dek_id.as_deref()?)
    }

    /// The member whose personal tree folder `node_id` is in, or None.
    fn personal_owner(&self, j: &Judged, node_id: &str) -> Option<String> {
        let mut current = Some(node_id);
        for _ in 0..MAX_DEPTH {
            let id = current?;
            if let Some(owner) = j.personal_trees.get(id) {
                return Some(owner.clone());
            }
            current = self.snap.node(id)?.parent();
        }
        None
    }

    /// None: the log does not decide; Some(None): valid; Some(Some(why)).
    fn team_refusal(&self, team: &State, rec: &Obj) -> Option<Option<&'static str>> {
        let held = self
            .prev
            .as_ref()
            .and_then(|p| p.get(&rec.id))
            .filter(|h| !h.is_deleted);
        let left = held.and_then(|h| self.prev.as_ref()?.team_folder_above(team, h.parent()));
        let own_dek = rec.dek_id.is_some() && self.sealed_by(rec) == Some(&rec.signer);
        team_write_verdict(
            team,
            rec,
            self.snap.team_folder_above(team, rec.parent()).as_deref(),
            held,
            left.as_deref(),
            own_dek,
            None,
        )
    }
}

fn known(team: &State, dek_id: Option<&str>) -> bool {
    dek_id.is_some_and(|d| team.dek_index.contains_key(d))
}

/// The log's verdict on one folder/item write `rec`, by its signer: None
/// when the log has no say (outside every team folder, sealed with a key it
/// does not know); Some(None) valid; Some(Some(why)). `folder`: the team
/// folder at or above its parent; `held`: the live copy before it and `left`
/// the team folder that copy was in; `own_dek`: its key names no folder and
/// its author signed it. `push`: None for a pulled copy; for a write about to
/// be sent or taken (sealing), the signer of the held copy's key.
fn team_write_verdict(
    team: &State,
    rec: &Obj,
    folder: Option<&str>,
    held: Option<&Obj>,
    left: Option<&str>,
    own_dek: bool,
    push: Option<Option<&str>>,
) -> Option<Option<&'static str>> {
    let author = rec.signer.as_deref().unwrap_or_default();
    let stored = held.and_then(|h| h.dek_id.as_deref());
    let authors_key = push.is_none_or(|signer| signer == Some(author));
    if rec.is_deleted {
        if folder.is_none() && !known(team, stored) && (push.is_none() || left.is_none()) {
            return None;
        }
        let refusal = rules::tombstone_refusal(team, author, stored);
        if refusal.is_some() || push.is_none() || held.and_then(Obj::parent) == rec.parent() {
            return Some(refusal);
        }
        // Review c78fd19 (#1), the server's push rule: a tombstone that also
        // moves the object moves it as a live write would.
        let own_personal = stored.is_some() && !known(team, stored) && authors_key;
        return Some(rules::move_refusal(
            team,
            author,
            left,
            folder,
            own_personal,
        ));
    }
    let dek_id = rec.dek_id.as_deref();
    // TL7: one's own personal object may leave for the personal root (only
    // its author holds that key to seal the next version). A push also
    // needs the author's own key (the server's rule, review c78fd19).
    let own_personal = stored.is_some() && stored == dek_id && !known(team, stored) && authors_key;
    if let Some(why) = rules::move_refusal(team, author, left, folder, own_personal) {
        return Some(Some(why));
    }
    if folder.is_none() && !known(team, dek_id) {
        return None;
    }
    Some(rules::item_refusal(
        team,
        author,
        &rec.id,
        folder,
        dek_id,
        own_dek,
        push.is_some(),
    ))
}

/// The log's verdict on each folder/item of `writes`, by its signer.
/// `objects`: the state before them (each one's copy there, the folders it
/// left); `after`: the state they land in (folders to walk, keys and their
/// signers; default `objects` with `writes`). `sealing`: the push rule
/// (design §4.3.4-6) on writes about to be sent (a client) or taken (the
/// server); else a pulled copy's rule, as `unauthorized_writes` judges it.
/// Some(None) valid, None the log has no say.
pub fn write_refusals(
    team: &State,
    writes: &[Obj],
    objects: &[Obj],
    after: Option<&[Obj]>,
    sealing: bool,
) -> Vec<Option<Option<&'static str>>> {
    let before = Snapshot::new(objects, []);
    let landed: Vec<Obj>;
    let after = match after {
        Some(a) => Snapshot::new(a, []),
        None => {
            landed = objects.iter().chain(writes).cloned().collect();
            Snapshot::new(&landed, [])
        }
    };
    let key = |dek_id: Option<&str>| {
        let id = dek_id?;
        after
            .get(id)
            .or_else(|| before.get(id))
            .filter(|k| k.object_type == "dek" && !(sealing && k.is_deleted))
    };
    writes
        .iter()
        .map(|rec| {
            let held = before
                .get(&rec.id)
                .filter(|h| !h.is_deleted && h.object_type == rec.object_type);
            let left = held.and_then(|h| before.team_folder_above(team, h.parent()));
            let own_dek = key(rec.dek_id.as_deref()).is_some_and(|k| {
                k.parent().is_none() && k.signer.is_some() && k.signer == rec.signer
            });
            let stored_signer =
                key(held.and_then(|h| h.dek_id.as_deref())).and_then(|k| k.signer.as_deref());
            team_write_verdict(
                team,
                rec,
                after.team_folder_above(team, rec.parent()).as_deref(),
                held,
                left.as_deref(),
                own_dek,
                sealing.then_some(stored_signer),
            )
        })
        .collect()
}

/// The team folder at or above node `node_id`; `parents`: each folder's parent.
pub fn team_folder_above(
    team: &State,
    parents: &HashMap<String, Option<String>>,
    node_id: Option<&str>,
) -> Option<String> {
    let mut current = node_id.filter(|n| !n.is_empty());
    for _ in 0..MAX_DEPTH {
        let id = current?;
        if rules::is_team_folder(team, id) {
            return Some(id.to_string());
        }
        current = parents.get(id)?.as_deref().filter(|p| !p.is_empty());
    }
    None
}

impl<'a> Ctx<'a> {
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
        if let Some(p) = rec.parent() {
            let parent_blocked = if self.snap.judged_here(p) {
                parent.is_some_and(|parent| self.judge(j, parent, depth + 1))
            } else {
                self.refused.contains(p)
            };
            if parent_blocked {
                if j.by_team_log.contains(p) {
                    j.by_team_log.insert(rec.id.clone());
                }
                j.below_refused.insert(rec.id.clone());
                return true;
            }
        }
        // The log decides first, a top-level folder too (a team folder's
        // own meta, one sealed with a team folder's key; the desktop's rule).
        if let Some(refusal) = decided {
            if let Some(why) = refusal {
                j.by_team_log.insert(rec.id.clone());
                j.refusals.insert(rec.id.clone(), why.to_string());
            }
            return refusal.is_some();
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
        let Some(parent) = parent else {
            return false;
        };
        let sealed: Signer = self.sealed_by(rec).cloned().flatten();
        if parent.parent().is_some() {
            let owner = self.personal_owner(j, &parent.id);
            let mut blocked = false;
            if let Some(owner) = &owner {
                // With a log only the owner removes from a personal tree.
                let removal_allowed =
                    rec.is_deleted && (self.team.is_none() || author.as_deref() == Some(owner));
                if self.own_user_id.as_deref() != Some(owner.as_str())
                    && !removal_allowed
                    && sealed.as_deref() != Some(owner.as_str())
                {
                    blocked = true;
                }
            }
            if self.team.is_some()
                && owner.is_none()
                && !self.is_own(author)
                && !self.admins.contains(author)
            {
                // Review 1141a20 H6: below the first level of the
                // organisation's own tree (no team folder, no personal tree)
                // only its admin writes or removes.
                blocked = true;
            }
            return blocked;
        }
        // Directly below a top-level folder: decided again here.
        j.personal_trees.remove(&rec.id);
        if self.is_own(author) {
            return false;
        }
        let key = (author.clone(), parent.id.as_str());
        let granted = if self.team.is_some() {
            self.admins.contains(author)
        } else if self.is_own(&parent.signer) || self.own_tops.contains(&parent.id) {
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
                j.personal_trees.insert(rec.id.clone(), a.clone());
            }
            return false;
        }
        // A removal needs what a write needs: a personal folder's tombstone
        // is sealed with its owner's key (the desktop's rule).
        true
    }
}

/// Review a159e97 H2: is `rec` held back (see `Context::vouched`)? Below a
/// folder of this call it is held when that folder is; the first folder up
/// that this call lacks decides: not known here and written by an account
/// this device does not vouch for (an 'admin' is the server's word). Not
/// held below a folder refused before (that blocks it).
fn held_back(snap: &Snapshot, own: Option<&str>, context: &Context, rec: &Obj) -> bool {
    let Some(vouched) = context.vouched.as_ref() else {
        return false;
    };
    let mut cur = rec;
    for _ in 0..MAX_DEPTH {
        let Some(p) = cur.parent() else {
            return false;
        };
        if context.refused.contains(p) {
            return false;
        }
        match snap.get(p).filter(|o| o.object_type == "node") {
            Some(parent) => cur = parent,
            None => {
                let author = cur.signer.as_deref();
                let vouched_for = author.is_some_and(|a| own == Some(a) || vouched.contains(a));
                return !snap.known.contains_key(p) && !vouched_for;
            }
        }
    }
    false // a cycle within this call: every folder of it is here
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
    context: &Context,
) -> Verdict {
    let snap = Snapshot::new(objects, &context.known_nodes);
    let records: Vec<&Obj> = snap.order.iter().map(|id| snap.by_id[id]).collect();
    let mut admins: BTreeSet<Signer> = context.admin_signers.iter().cloned().map(Some).collect();
    let mut personal_dek_signers: HashMap<&str, Signer> = context
        .personal_dek_signers
        .iter()
        .map(|(k, v)| (k.as_str(), Some(v.clone())))
        .collect();
    let mut dek_folders: HashMap<&str, &str> = context
        .dek_folders
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
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
        // The grants held here, but for one this pull withdraws.
        let withdrawn: BTreeSet<&str> = records
            .iter()
            .filter(|r| r.object_type == "envelope" && r.is_deleted)
            .map(|r| r.id.as_str())
            .collect();
        for g in &context.write_grants {
            if withdrawn.contains(g.id.as_str()) {
                continue;
            }
            write_grants.insert((Some(g.user_id.clone()), g.folder.as_str()));
            if own.as_deref() == Some(g.by.as_str()) {
                own_write_grants.insert((Some(g.user_id.clone()), g.folder.as_str()));
            }
        }
    }
    let admin_signers: BTreeSet<String> = admins.iter().flatten().cloned().collect();
    let dek_signers_out: BTreeMap<String, String> = personal_dek_signers
        .iter()
        .filter_map(|(k, v)| Some((k.to_string(), v.clone()?)))
        .collect();
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
    let held: Vec<&Obj> = records
        .iter()
        .copied()
        .filter(|r| {
            matches!(r.object_type.as_str(), "node" | "entry")
                && held_back(&snap, own.as_deref(), context, r)
        })
        .collect();
    // A held folder is walked only, where things were too.
    let prev_known = context
        .known_nodes
        .iter()
        .chain(held.iter().copied().filter(|r| r.object_type == "node"));
    let ctx = Ctx {
        snap,
        prev: previous.map(|p| Snapshot::new(p, prev_known)),
        own_user_id: own,
        team,
        admins,
        personal_dek_signers,
        write_grants,
        own_write_grants,
        refused: &context.refused,
        own_tops: &context.own_tops,
    };
    let mut judged = Judged {
        personal_trees: context
            .personal_trees
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        // Not judged: what is below a held folder is held too.
        verdicts: held.iter().map(|r| (r.id.clone(), false)).collect(),
        ..Judged::default()
    };
    let held_ids: BTreeSet<&str> = held.iter().map(|r| r.id.as_str()).collect();
    let mut blocked = Vec::new();
    for rec in &records {
        if (rec.object_type == "node" || rec.object_type == "entry")
            && !held_ids.contains(rec.id.as_str())
            && ctx.judge(&mut judged, rec, 0)
        {
            blocked.push(rec.id.clone());
        }
    }
    Verdict {
        blocked,
        by_team_log: judged.by_team_log,
        refusals: judged.refusals,
        below_refused: judged.below_refused,
        personal_trees: judged.personal_trees,
        admin_signers,
        personal_dek_signers: dek_signers_out,
        held: held.iter().map(|r| r.id.clone()).collect(),
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
    #[serde(default)]
    context: Option<Context>,
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

fn yes() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteIn {
    /// The folders and items to judge.
    writes: Vec<Obj>,
    /// The state before them: folders, keys, each one's own copy.
    objects: Vec<Obj>,
    /// The state it lands in (default: `objects` with it).
    #[serde(default)]
    after: Option<Vec<Obj>>,
    /// false: a pulled copy (default: the push rule).
    #[serde(default = "yes")]
    sealing: bool,
    #[serde(default)]
    team: Option<State>,
    #[serde(default)]
    team_handle: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FolderIn {
    node_id: Option<String>,
    /// Each folder's parent (None: top level).
    parents: HashMap<String, Option<String>>,
    #[serde(default)]
    team: Option<State>,
    #[serde(default)]
    team_handle: Option<u64>,
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
                let mut i: WritesIn = serde_json::from_str(input).map_err(bad)?;
                let context = i.context.get_or_insert_with(Context::default);
                for o in i
                    .objects
                    .iter_mut()
                    .chain(i.previous.iter_mut().flatten())
                    .chain(context.known_nodes.iter_mut())
                {
                    o.read_head()?;
                }
                let team = team_of(i.team, i.team_handle)?;
                let v = unauthorized_writes(
                    &i.objects,
                    i.own_user_id.as_deref(),
                    team.as_deref(),
                    i.previous.as_deref(),
                    i.team_admins.as_ref(),
                    i.context.as_ref().unwrap_or(&Context::default()),
                );
                json!({
                    "blocked": v.blocked,
                    "by_team_log": v.by_team_log,
                    "refusals": v.refusals,
                    "below_refused": v.below_refused,
                    "personal_trees": v.personal_trees,
                    "admin_signers": v.admin_signers,
                    "personal_dek_signers": v.personal_dek_signers,
                    "held": v.held,
                })
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
            "authority_write_refusal" => {
                let mut i: WriteIn = serde_json::from_str(input).map_err(bad)?;
                for o in i
                    .writes
                    .iter_mut()
                    .chain(i.objects.iter_mut())
                    .chain(i.after.iter_mut().flatten())
                {
                    o.read_head()?;
                }
                let team = team_of(i.team, i.team_handle)?.ok_or("team or team_handle needed")?;
                let verdicts =
                    write_refusals(&team, &i.writes, &i.objects, i.after.as_deref(), i.sealing);
                let out: Vec<Value> = verdicts
                    .into_iter()
                    .map(|v| json!({"decided": v.is_some(), "refusal": v.flatten()}))
                    .collect();
                json!(out)
            }
            "authority_team_folder_above" => {
                let i: FolderIn = serde_json::from_str(input).map_err(bad)?;
                let team = team_of(i.team, i.team_handle)?.ok_or("team or team_handle needed")?;
                json!(team_folder_above(&team, &i.parents, i.node_id.as_deref()))
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

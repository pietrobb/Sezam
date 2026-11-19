# Sync redesign: one source of truth

Status: design, agreed 2026-11-18. Work branch #380 (S0–S4).

## Why

The last rounds of the deep stateful test (`tests/test_sync_state_machine.py`)
kept finding bugs with the same shape: **one fact was stored in two places,
the two drifted apart, and the code decided from the wrong one** — silently.

| Bug (2026-11-18) | The two copies |
|---|---|
| Full resync lost another device's edit | version number vs. the content of that version |
| Device stopped seeing new folders | `ETag` vs. the pull checkpoint |
| Push blocked with "unknown DEK" | current key in the DB vs. a revocation still queued |
| Envelopes never sent (earlier review) | envelope "unsent" derived from its folder's `is_dirty` |

Each fix patched one place. This document lists **every** place with that
shape in the server and the three clients (desktop = Python, web = JS,
phone = Dart) and the target model that removes the class, not the instances.

Nobody uses Sezam yet, so the local database formats and the protocol change
**without migration or backward compatibility**.

## The four points

1. **A version is (number, content hash), everywhere.** A version number
   alone never identifies a version.
2. **One source of truth for pull state.** No separately stored `ETag`; the
   authenticated checkpoint is the only record of how far a device pulled.
3. **An explicit outbox instead of dirty flags.** Everything waiting for the
   server is an operation with an order and a state. What gets re-sealed or
   re-keyed is decided from the state *after* the queued operations.
4. **One sync core for the three clients.** First one conformance test run
   against all three; then one implementation (Rust) with bindings.

---

## Inventory

Each row: where, what is duplicated, which point removes it.

### Point 1 — version identity

| # | Where | Two copies / gap | Point |
|---|---|---|---|
| 1.1 | `server/app/routers/sync.py:1052-1054` (push) | `base_version` and `base_payload_hash` are optional. With `base_version=None` the server takes **any** higher version — a blind overwrite. Web and phone never send a base. | 1 |
| 1.2 | `server/app/main.py:163` `_cleanup_tombstones` | Tombstone GC deletes the row: the server forgets the object's last version and hash, so the same `(id, version)` can later name different content (SM8, SM20, SM21). | 1 |
| 1.3 | `src/sezam/vault/schema.py:42-121` | `object_base_version` and `object_base_hash` are separate tables kept in step with `nodes`/`entries` by triggers; a new base deletes the hash (`base_hash_reset`), so the hash is often unknown and not sent. | 1 |
| 1.4 | `src/sezam/vault/sync_state.py:221-410` | `_set_base_version`, `_sent_from`, `_written_without_my_write`, `_lost_same_version`, `_own_sent_version`, `_stamp_base_versions`, `_revives_collected_tombstone`, `_record_base_hash`, `_holds_server_copy`: number-based identity repaired case by case. | 1 |
| 1.5 | `src/sezam/vault/sync_resync.py` (full resync) | Matched local and server copies by number; patched in `ab815d0` to compare the hash. | 1 |
| 1.6 | `web/static/js/app.js` push builders (≈3470, 6615, 8591, 9357), conflict check ≈5630 | Push carries no base; conflict detection compares `server_payload_hash` only after the fact. | 1 |
| 1.7 | `mobile/lib/services/vault_service.dart:1119-1136`, `mobile/lib/screens/entry_detail_screen.dart:122,250`, `mobile/lib/services/sync_service.dart:1331` | Local `version + 1`, no base sent; same as web. | 1 |
| 1.8 | `sync_conflicts` (`schema.py:9`, `database_service.dart:82`) | Already stores `server_version` + `server_payload_hash` — becomes the conflict's base `(number, hash)`. Keep. | 1 |

### Point 2 — pull state

| # | Where | Two copies | Point |
|---|---|---|---|
| 2.1 | `server/app/routers/sync.py:1568-1587, 1672-1674` | 304 compares `If-None-Match` with the global head; the response `ETag` is the page's `max_seq`. A response that left objects out still makes later pulls 304. | 2 |
| 2.2 | `src/sezam/vault/sync_client.py:111,548,585,1274-1277`, `sync_pull.py:41-44,259,334,426-429`, `sync_resync.py:793` | `_pull_etag` held next to the checkpoint (patched in `9cef788`). | 2 |
| 2.3 | `_verify_since_seq`: `sync_client.py:125,931`, `sync_pull.py:348`, `sync_resync.py:420`, `sync_writers.py:428` | A third in-memory copy of "pulled up to". | 2 |
| 2.4 | `sync_state.py:102-219`, `sync_common.py` (`COMMIT_ANCHOR_META`, `SERVER_ROLLBACK_META`) | `sync_checkpoint.last_sync_seq`, `commit_anchor.seq`, `server_rollback_head`: three seq records. | 2 |
| 2.5 | `web/static/js/app.js` `state.lastETag` (2400, 2677, 2700, 2894, 3094, 5215, 6962, 7041), `state.lastResponseETag` (2738, 6142, 6175), `state.lastCommitSeq` vs `state.syncCheckpoint.last_sync_seq` (2672, 2686) | Four copies; the web still has the frozen-ETag bug fixed on the desktop in `9cef788`. | 2 |
| 2.6 | `mobile/lib/services/database_service.dart:502-612` (`sync_state.last_commit_seq`) vs `sync_service.dart:1134-1160, 1641-1650` (`checkpoint.last_sync_seq`, `commit_token_seq`) | Two seqs cross-checked at 1643 ("does not match the authenticated checkpoint") — a mismatch is a hard stop the user cannot fix. | 2 |

### Point 3 — what waits for the server

| # | Where | Two copies | Point |
|---|---|---|---|
| 3.1 | `nodes.is_dirty`, `entries.is_dirty` (`schema.py:134,147`); ≈140 uses in `crud.py`, `sync_*.py`, `personal_root.py`, `rekey_abandon.py`, `reseed.py`, `trash.py` | "Must be sent" is a flag on the data row; the row's content and "what was queued" are one copy. | 3 |
| 3.2 | `audit_sync_state`, `envelope_sync_state`, `withdrawn_envelopes`, `pulled_envelopes` (`schema.py:21-37`) | Sent/unsent of audit records and envelopes, each its own table. | 3 |
| 3.3 | `object_sent_version`, `object_sent_base` (`schema.py:51-67`) | "What was sent" kept apart from "what is queued". | 3 (with 1) |
| 3.4 | `src/sezam/vault/pending_states.py` (`pending_key_rotation` + `last_pushed_key_epoch`, `pending_rekey_batch` with `held_edits`, `queued_revocations`, `org_recovery_*`, `pending_server_reseed`, `pending_bootstrap_keypair_upload`), `sync_common.py` (`STALE_OWN_WRAPS_META`, `LOST_WITHDRAWALS_META`, `DETACHED_DEKS_META`, `REFUSED_DEKS_META`, `REATTACHED_META`, `REVIVED_FOLDERS_META`), `sync_rekey.py:28` (`ROTATION_SEALED_META`), `team_log_local.py:29` (`PENDING_META`) | Pending operations as JSON in `vault_meta`, each with its own ordering rules. | 3 |
| 3.5 | `src/sezam/vault/crud.py` re-seal on identity rotation (patched in `ab815d0`) | Re-seals from the current `deks`/`access_envelopes`, not from the state after the queued revocation. | 3 |
| 3.6 | `mobile/lib/services/database_service.dart:216` `vault_objects.is_dirty`; `sync_service.dart:248,274,2136,2146`; `vault_service.dart` (14 uses); `key_rotation.dart`; `unsent_changes.dart` | Same flag model; key rotations are dirty rows too. | 3 |
| 3.7 | `web/static/js/app.js` `state.dirtyObjects` + `state.syncConflicts` (`saveWebDirtyState` 4909), `state.sentWrites` (`loadWebSentWrites` 5010) | Dirty map in IndexedDB, sent writes in another. | 3 |
| 3.8 | Web and phone equivalents of 3.4 (added after capability run 359): `web/static/js/app.js` `pending_rekey:<uid>:<revoked>` re-key journals (`listPendingWebRekeyIds`, `retryAllWebDirtyObjects` sent them before `state.outbox` and removed re-key objects queued in both), `pending_kek_rotation:<username>` (`saveKekRotationJournal`); phone `settings.pending_server_rejoin` (`auth_service.dart` `rejoinServer`), secure-storage `sezam_pending_keypair_migration` | Operations waiting for the server outside the outbox, their order against it written into code. | 3 |

### Point 4 — three implementations

| # | Where | Problem | Point |
|---|---|---|---|
| 4.1 | `src/sezam/vault/sync_*.py` (≈7 100 lines), sync part of `web/static/js/app.js` (file ≈8 900 lines), `mobile/lib/services/sync_service.dart` (≈2 600 lines) + `vault_service.dart` | Every rule written three times; every fix needed three times (2.5 shows one that reached only the desktop). | 4 |
| 4.2 | `tests/test_sync_state_machine.py` (≈2 900 lines) | The deep stateful test drives only the desktop client. | 4 |
| 4.3 | `tests/test_team_log_differential.py` | Existing pattern: the same inputs through Python, Node and `flutter test`, results compared. Template for 4(a). | 4 |

---

## Target model

### 1. Version = (number, hash)

**Server**
- Every update of an existing object **must** carry `base_version` and
  `base_payload_hash`; a missing base on an existing object is a conflict,
  not an overwrite. A create carries no base and is a conflict when the id
  exists or was collected.
- Tombstone GC keeps a ledger `collected_objects(id, version, payload_hash,
  commit_seq)` instead of forgetting. A write to a collected id is an update
  of that ledger row (base must match it). Version numbers of an id are never
  reused, so `(id, version)` names exactly one content forever.
- Conflict replies carry `server_version` + `server_payload_hash` (already
  so).

**Clients** — the base lives **on the object row**, not in side tables:
- Desktop: `nodes`/`entries` get `base_version`, `base_hash` columns (NULL =
  never on the server). `object_base_version`, `object_base_hash` and their
  triggers are deleted; `object_sent_version`/`object_sent_base` move into
  the outbox (point 3).
- Phone: `vault_objects` gets `base_version`, `base_hash`.
- Web: every pending write records the base `(version, hash)` of the
  `state.syncObjects` copy it was made on.
- An accepted push sets base = (pushed version, pushed hash); a pull of a
  copy the device took sets base = (server version, server hash). Nothing
  else writes the base.
- Identity checks ("is this my write?", "is this the copy I built on?") always
  compare the pair.

### 2. Pull state = the checkpoint

- `ETag` / `If-None-Match` is removed from the server and all clients. An
  empty delta is already a few hundred bytes; the optimisation is not worth a
  second source of truth.
- Each client keeps exactly one record: the authenticated checkpoint
  `{last_sync_seq, commit_token, state_hash, team_log_seq}`. The next pull's
  `since_commit_seq` is read from it, nothing else.
- Desktop: `_pull_etag` and `_verify_since_seq` go; `commit_anchor` and
  `server_rollback_head` fold into the checkpoint.
- Phone: `sync_state.last_commit_seq` and `commit_token_seq` go.
- Web: `lastETag`, `lastResponseETag` go; `lastCommitSeq` is read from
  `syncCheckpoint`.

Done in S2: the server sets no `ETag` and ignores `If-None-Match`; desktop
`_pull_etag`, web `lastETag` / `lastResponseETag` / `lastCommitSeq` and the
phone's 304 path are gone (a 304 is now an error, not "nothing new"). The
desktop `commit_anchor` / `last_known_commit_seq` and phone
`commit_token_seq` fold is left to S4's shared core, where the checkpoint
gets one definition for all three clients.

A push whose base is older than a delete that tombstone GC collected is
refused with code `collected_object` (server keeps only that copy's
version and hash). There is no copy left to choose, so the desktop rebuilds
the change on the collected (version, hash) and sends it again above it.

### 3. Outbox

One table (desktop and phone SQLite, web IndexedDB store):

```
outbox(
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,  -- send order
  kind       TEXT,      -- write | withdraw | key_change | revoke | rekey | org_recovery | reseed | bootstrap
  object_id  TEXT,      -- NULL for account-level operations
  body       BLOB,      -- the signed request part (ciphertext only)
  base_version INTEGER, base_hash TEXT,   -- for writes (point 1)
  after_seq  INTEGER,   -- must land before this one may be sent
  state      TEXT       -- queued | sent | conflict
)
```

- "Has unsent changes" = there is an outbox row for it. `is_dirty`,
  `audit_sync_state`, `envelope_sync_state` and the pending `vault_meta`
  keys of 3.4 are removed; `pending_states.py` reads the outbox.
- A local edit appends (or replaces the queued, not yet sent) row for that
  object in the same transaction as the data change.
- A push sends rows in `seq` order, an atomic batch for rows that must land
  together (re-key). Accepted → row deleted and base updated in one
  transaction. Conflict → row `conflict`, `sync_conflicts` holds the server
  copy.
- **Projected state**: decisions about sealing and re-keying (who gets a new
  envelope, which DEK is current) read the local state *with queued
  operations applied* — a member queued for removal gets no new envelope; the
  DEK of a queued rotation is the current one.
- A full resync exports the outbox (phone already exports unsent changes,
  `unsent_changes.dart`) and replays it on the fresh server copy.

**S3 part 1 (done):** folder and entry writes. Desktop (`vault/outbox.py`,
`outbox` table in `schema.py`) and phone (`outbox` table, DB v9 moves rows
with `is_dirty = 1` into it) queue a `write` row; the `is_dirty` column is no
longer read or written. Web's pending map is `state.outbox`. A tombstone
identical to the one tombstone GC collected (two devices deleted the same
object) is confirmed at the collected version, not resent (SM51).
**S3 part 2a (done):** desktop `audit_sync_state` and `envelope_sync_state`
are gone: an audit record or access envelope waiting for the server is an
`audit`/`envelope` row in the outbox (state `queued`, or `refused` for one the
server never takes); a vault from before is moved over on open. The phone
and web already queue these as ordinary writes. `withdrawn_envelopes` and
`pulled_envelopes` stay: they record what the server did (withdrew, brought
by a pull), not something waiting to be sent. A re-key batch item whose
tombstone GC collected (`collected_object`) builds on the collected
(version, hash) as outside a batch, instead of sinking the batch on every
push (seed 171717).
**S3 part 2b (done):** the pending operations of 3.4 are outbox rows with
their request in `body`: `key_change`, `rekey`, `reseed`, `bootstrap`,
`org_recovery` (`registration`/`rewrap`), a `revoke` per member, a
`team_change` per queued team-log change (`refused`: set aside), a
`team_grant` per envelope, a `withdrawal` (state `held` until its member is
revoked) per tombstone a restored server lost; a folder kept because it holds
unsent work is its queued `write` with body `{"revived": true}`. A vault from
before is moved over on open. The web's `state.sentWrites` is gone: its own
writes are the server copies it signed. Left in `vault_meta`, because none is
an operation waiting for the server: `last_pushed_key_epoch` (the key epoch
the server acknowledged), `team_rotation_sealed_seq` (how far this device
sealed envelopes for rotated members), and what pulls and refusals showed —
`stale_own_dek_wraps`, `detached_dek_folders`, `refused_folder_deks`,
`reattached_parents`.
**S3 projected state (done):** the desktop decides on
`team_log_local.projected_team_state` — the local log with the queued re-key
batch, team changes (a set-aside removal too) and grants applied. A grant to a
team folder that a queued removal leaves stale is refused before anything is
sealed (before: sealed under the key the removal retires, reported as "goes
with the next push", never reached the member); a queued re-key's key is the
folder's current one. `queued_for_removal` also names the member of a built,
unlanded re-key batch, and `grant_folder_access` seals nothing to a member
queued for removal. Sealing to rotated members skips a folder the queue leaves
stale and keeps its mark (`team_rotation_sealed_seq`) until the re-key landed.
The web already waits: no rotation seal while a re-key journal is pending, and
its re-key seals to the log after its own `member.remove`. The phone grants,
removes and seals to nobody else; it re-seals only its own unsent items to the
log's current key.
**S3 part 2c (done, 3.8):** the web's re-key of a revocation is an operation
of its outbox: `state.outboxOps` (`{kind: 'rekey', revoked_user_id, phase,
objects, team_log}`) sealed in the same `dirty_state:` record as the queued
writes, in queue order. Retry sends the queue in order — each re-key as its
one atomic batch, then the writes, resealed under the keys it made — and no
longer cleans up copies: a `pending_rekey:` record of an older version moves
into the queue when the queue loads (dropping the copies of its objects an
even older version queued as single writes). A queue set aside by a password
change elsewhere names its waiting removals in public (`revocations`, the ids
the old record ids held) so they are finished from the server's state without
the old password; `has_changes` says whether there is more for it. A password
change is refused while a re-key waits, as while writes wait. The phone's
rejoin stage is an outbox row (`kind = 'rejoin'`, body = stage; DB v10 moves
`settings.pending_server_rejoin` over). Two records stay outside on purpose,
neither a second copy of anything: the web's `pending_kek_rotation:` is the
account's key change itself — the outbox is sealed under the KEK that change
replaces, so the journal (ciphertext under the new KEK) is resumed at login
before the outbox can be opened (a password change in a session starts only
with an empty outbox; an outbox org recovery leaves under the old KEK is set
aside as above); the phone's `sezam_pending_keypair_migration` sends nothing (it
finishes a local secure-storage move). Measure: pending operations outside the
outbox — desktop 3.4, web and phone 3.8 — are 0 apart from these two.

### 4. One core

- **(a) Conformance first.** A scenario format (JSON: steps such as create,
  edit, delete, share, revoke, rotate identity, pull, push, and server faults
  — withhold objects, restore a backup, collect tombstones) and three drivers
  run against one real server: Python in-process, JS under Node (as
  `test_team_log_differential.py`), Dart under `flutter test`. All three must
  end in the same converged state. The seeds the stateful test found
  (`tests/test_public_ci_stateful_seeds.py`, `test_review10_stateful_seeds.py`)
  become scenarios.

  **S4(a) part 1 (done):** `tests/conformance/*.json` (steps for the client
  under test, a desktop device of the same account and the server; the vault
  every device must end with) and `tests/test_sync_conformance.py`, which runs
  each scenario with the desktop, the web page (`tests/web_tab.py`) and the
  phone (`mobile/test/sync_conformance_test.dart` under `flutter test`) on one
  uvicorn, settles, and compares the client, the desktop and a new device with
  `expect`. Client steps are what all three have: create folder/entry, edit
  and delete an entry, sync (a write stays local until sync; the web's send
  fails as offline and its periodic pull shows the queue). First finding,
  `offline_write_under_deleted_folder`: an item saved in a folder another
  device deleted stayed queued for good on the web and the phone (the server
  refuses an item below a deleted folder; the web made it a conflict Retry
  could never clear). Only the desktop brought the folder back. Both now do
  it the desktop's way (`reviveFoldersOfUnsentWork` in `app.js`,
  `VaultService.reviveFoldersOfUnsent` after the pull): the folder is queued
  one version above its tombstone, ahead of the item. `conflict_use_server`:
  the one conflict decision all three offer.

  **S4(a) part 2 (in progress):** client step `accept_restore` (the user
  accepts a server restored from a backup: `sezam pull --full-resync`, the
  page's rollback question answered yes, the phone's `fullResync`); until
  then a sync only reports the rollback, and the page answers the question
  no. Second finding, `own_write_only_the_client_had`: what only the web had
  sent after the backup (a new item, a new folder with its key and an item,
  an edit) was gone after the restore was accepted — the page took the
  server's data as it was, and its question said so. The desktop and the
  phone send it again. The page now does too (`requeueWritesTheServerLost`):
  the server copies it held before the full pull that this account signed
  and the restored server lacks above its GC floor (each kept copy records
  its `commit_seq`), or holds at an older version, are queued again as they
  were signed. `server_withholds_folders` / `server_withholds_keys`: a
  server that leaves a folder or a re-key's new folder key out of a pull. The
  desktop crashed on the key's archive (foreign key, `sqlite3.IntegrityError`);
  it now refuses the pull (`_refuse_archives_without_their_key`), as the web
  and the phone do, and the next complete pull applies it.
  Stateful seeds as scenarios: `withheld_folders_after_a_sync` (run
  44281542877) and `resync_older_edit_at_same_version` (run 44260509986, with
  a third device `ref2`). The second found the phone apart: its full resync
  re-applied an unsent edit by comparing `commit_seq`, and when another
  write had landed under the same version number it made an "(unsent copy)"
  item; the desktop and the web keep the edit on the version it was made on
  and the user gets the conflict. The phone now compares the S1 identity
  (`base_version`, `base_hash`; `planUnsentReapply`), keeps the edit on its
  base and holds the server copy aside as the conflict shadow
  (`holdServerCopyAside`) — the state a pull leaves when it meets one. A copy
  is made only for a live entry with unsent edits of its own or an export
  without a base.

  **Team steps (capability run 361).** The scenarios could not share,
  revoke or rotate on the client, so what S3 moved into the outbox had no
  three-client test. Client steps now also `grant` (share folder T with a
  member), `revoke` (with the re-key) and `rotate_identity`; ref steps
  `invite`, `grant`, `revoke`, `rotate_identity`; a member device (`bob`, a
  desktop) `reads` and `sync`s, and `"revoked"` names members who must hold
  no key to anything live (checked on the server's envelopes and the
  member's device). **Exceptions, by name, not by intersection**
  (`CLIENT_LACKS`): the web has no grant (no folder sharing UI) and no
  identity rotation (it changes the password only); the phone has none of
  the three (it only receives them). A client lacking a step skips that
  scenario; every such step is also taken by the ref in a scenario all three
  run (`ref_rotates_identity_with_a_member`,
  `member_revoked_under_an_unsent_write`). Found:
  - desktop, `client_revokes_member`: a device of the account that had not
    pulled another device's revocation queued the re-key again, the log
    refused it (folder key moved) and every sync failed, telling the user to
    `sezam abandon-rekey`. It now asks the log first (`_rekey_due`). The
    pull of that re-key then failed on the device's own write, sealed under
    the old key the log no longer lets it read: such a key now opens only to
    seal again under its successor, for an account the log lets hold the
    successor (`unlock_dek(superseded=True)`).
  - web, `member_revoked_under_an_unsent_write`: a write queued under T's key
    before another device re-keyed T went out under the old key on every
    Retry (the old key was refused with the rest, so nothing resealed it);
    such a key is now kept apart (`state.supersededDeks`) only to reseal, and
    the server's refusal of the first try is cleared once a copy is
    accepted, instead of staying an open conflict.
  - web, `ref_rotates_identity_with_a_member`: after the new login, a queued
    change restored from the set-aside banner kept the old identity's
    signature and the server refused it for good; it is signed again.
- **(b) Core.** `core/` Rust crate `sezam-sync-core`: a pure state machine
  without I/O and without crypto — input: local operations, verified pull
  pages, push replies; output: outbox rows to send, apply plan, conflicts,
  next checkpoint. Bindings: PyO3 (desktop), `wasm-bindgen` (web), 
  `dart:ffi` with a build hook (phone). Crypto stays on each platform's libsodium,
  which already passes the shared vectors. Clients keep storage and UI and
  call the core for every sync decision; their own copies of that logic are
  deleted.

  **S4(b) part 1 (crate):** `core/` holds `sezam-sync-core` with one entry
  point for the bindings, `json::call(op, input)` (JSON in, `{"ok"}` or
  `{"error"}` out). Operations: `gate` (410, head behind the checkpoint,
  another commit under the anchor seq, an unaccepted rollback), `next_cursor`
  (GC floor on a first pull), `check_state` (same seq, other state),
  `decide_pulled` / `decide_pulled_batch` (a pulled copy against a row with
  an unsent change), `missing_successor` (an archive without its new key),
  `order_pulled`, `parents_first`, `plan_reapply`. `decide_pulled` is the one
  rule where the clients still differed: the desktop kept a change when the
  server sent its base *or an older copy* and adopted its own earlier push
  whose reply was lost; the web dropped a change the server held exactly;
  the phone kept only one on its exact base. The core takes the union
  (`Sent`, `KeepUnsent`, `AdoptAsBase`, else `Conflict`); the switch of each
  client is checked by the conformance scenarios and the suites. CI job
  `core`: fmt, clippy, `cargo test`.

  **S4(b) part 2a (desktop binding):** `core/py` is the PyO3 wheel
  `sezam-sync-core` (module `sezam_sync_core`, one function `call`), a
  dependency of the desktop package (`pip install ./core/py` first; the CI
  jobs do so, the `host` container installs Rust for it).
  `sezam.vault.sync_core.call` is the desktop's door. Switched: the pull
  batch order (`_order_pulled_objects`) and the audit send order
  (`outbox.parents_first`); their Python bodies are gone.

  **S4(b) part 2b (desktop, the rest):** the pull gate (`pull`: a restored
  server by its head or commit token, an unaccepted rollback) and the full
  resync's "was the server restored" (`gate`), the state check
  (`_check_rollback` → `check_state`), the cursor after a pull and a full
  resync (`next_cursor`), a pulled copy against a queued write
  (`_apply_pulled_object` → `decide_pulled`; `_holds_server_copy` is gone)
  and the archive without its new key (`missing_successor`). The desktop
  does not replay set-aside changes (it exports them), so `plan_reapply` is
  the phone's. Left on the desktop: the full resync's handling of what this
  device holds *newer* than a restored server (`_local_objects_ahead_of`
  and the base/conflict choice after it), which no other client has.

  **S4(b) part 2c (web binding):** `core/wasm` is the `wasm-bindgen` crate;
  `python core/build_web.py` builds it into
  `web/static/js/vendor/sezam-sync-core.js` (glue + module inlined,
  `SezamSyncCore.ready` / `SezamSyncCore.call(op, args)`) and pins its
  Subresource Integrity hash in `index.html`. The file is committed like the
  other vendored scripts and names the digest of the core sources it was
  built from; `tests/test_sync_core_web.py` fails on a file older than
  `core/` and checks that the web and desktop bindings answer every
  operation alike. To rebuild: `rustup target add wasm32-unknown-unknown`,
  `cargo install wasm-bindgen-cli` at the version `core/wasm/Cargo.toml`
  pins, then `python core/build_web.py`. Switched in `app.js`: the pull gate
  (`gate`; a head behind the checkpoint now takes the same early path as a
  reissued commit, before the audit check), the state check
  (`checkPulledStateAgainstCheckpoint` → `check_state`, with the web's
  live-state rule for collected tombstones now in the core), the cursor
  (`syncPositionAfter` → `next_cursor`, never back) and a pulled copy against
  a queued write (`reconcileWebDirtyState` → `decide_pulled_batch`;
  `sameSignedSyncObject` is gone).

  Two rules settled while switching, both in the crate with tests: a row
  queued unchanged on its base (a re-key batch item) is kept, not taken as
  its own landed push (the desktop's order; the core had `Sent` first and a
  re-key rebase stopped as "missing"); and a seq below the checkpoint is a
  rollback even when the reply brought only writes applied again (the
  phone's rule; desktop and web skipped the check then).

  **S4(b) part 2d (phone binding):** `core/ffi` is a `cdylib` with the same
  entry point as a C function (`sezam_sync_core_call` / `_free`).
  `mobile/hook/build.dart` (a Dart build hook, `hooks` + `code_assets`)
  builds it with cargo for the target (Android linked by the NDK clang that
  Flutter passes, iOS, and the host for `flutter test`) and bundles it as a
  code asset; `lib/services/sync_core.dart` binds it with `@Native`. No
  generated bridge: one JSON function needs none. Switched: the pull gate
  and the full resync's "was the server restored" (`gate`), the state check
  (`check_state`), the cursor (`next_cursor`), a pulled copy against a
  queued write (`applyPullAndCommitCheckpoint` → `decide_pulled`: the phone
  now also drops a write the server holds exactly and keeps one on an older
  copy) and the full resync's reapply plan (`planUnsentReapply` →
  `plan_reapply`).

  **S4(b) part 2e (send side after a re-key; capability review run 365):**
  all three findings of conformance run 361 were on the send side, which
  each client still decided in its own copy. `core/src/reseal.rs` now owns
  it; a client passes the verified team log (each folder's keys oldest
  first, the keys the log lets the account hold), the signed archive chain
  and the keys it holds open, and does only the decrypt and seal itself.
  - `may_open_superseded`: a folder key the log has replaced is opened, only
    to seal the account's own unsent writes again, while the log lets the
    account hold the folder's current key. Replaces desktop
    `dek._may_hold_successor` and web `supersededOk`.
  - `reseal_targets`: the key an unsent write goes out under: a replaced
    team key's current one (log allows it, held), otherwise the end of the
    archive chain if held, otherwise as it is. Replaces the decision in
    desktop `_successor_dek` (also used for kept conflict copies), web
    `resealUnderFolderSuccessor` and phone `_resealUnsent`. The phone used
    to open a replaced key from its own wrap without the log rule; it now
    opens it only when the core names a target.
  - `rekey_due`: whether a member revoked on another device still needs a
    re-key here. Replaces desktop `revocation._rekey_due` (only the desktop
    revokes).
  `tests/test_sync_core_web.py` and `mobile/test/sync_core_test.dart` hold
  the three bindings to the same answers for the g1 → g2 → g3 case (member of
  g3: sealed again under g3; revoked: nothing opened, nothing resealed).

---

## Order of work

| Step | Goal | Contents | Done when |
|---|---|---|---|
| S1 | #382 | Point 1: server base mandatory + `collected_objects`; base columns on rows in three clients; delete side tables 1.3/1.4 | Regression tests "same number, different content" for the three clients; full suites green; pushed |
| S2 | #383 | Point 2: drop ETag in server + three clients; one checkpoint per client | Test "server leaves objects out, pull state must not freeze" for the three clients; suites green; pushed |
| S3 | #384 | Point 3: outbox in three clients; projected state for sealing/re-key | `is_dirty` gone as source of truth; stateful test and seeds green; suites green; pushed |
| S4 | #385 | Point 4: (a) conformance scenarios + three drivers; (b) Rust core + bindings, clients switched | Conformance green for all three; duplicated sync logic deleted; suites and CI green |

S1 before S3: the outbox stores the base, so the base must already be a
pair. S2 is independent and small. S4(a) is written against the S1–S3
protocol so it does not test behaviour that is about to be removed.

Each step: a reproduction or regression test first, full Python suite (with
MariaDB) and Flutter suite before the push, commit in the private repo and
`git am` into the public one with the noreply author.

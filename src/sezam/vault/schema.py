"""SQLite schema for local vault (sezam.db).

Spec 4.1: All content columns are ciphertext envelopes.
"""

import hashlib
import struct
from typing import Optional

# 2: the outbox replaced is_dirty and the object_base_* side tables
# (docs/SYNC_SINGLE_SOURCE.md). Review 18c300f R16-L7: that change kept 1, so
# d14d368 (knows 1) opened an upgraded vault and died on its is_dirty
# triggers with a raw sqlite error; now it refuses with its own message.
SCHEMA_VERSION = 2


def row_payload(meta: bytes, data: Optional[bytes]) -> bytes:
    """The sync payload of a folder (meta only) or an entry (u32be len(meta) || meta || data)."""
    meta = bytes(meta)
    if data is None:
        return meta
    return struct.pack(">I", len(meta)) + meta + bytes(data)


def row_payload_hash(meta: bytes, data: Optional[bytes]) -> str:
    """payload_hash of a folder or entry row (SQLite function sezam_payload_hash)."""
    return hashlib.sha256(row_payload(meta, data)).hexdigest()

SYNC_CONFLICTS_SQL = """
CREATE TABLE IF NOT EXISTS sync_conflicts (
    object_id          TEXT PRIMARY KEY,
    object_type        TEXT NOT NULL,
    local_version      INTEGER NOT NULL,
    server_version     INTEGER NOT NULL,
    server_payload     BLOB NOT NULL,
    server_parent_ref  TEXT,
    server_is_deleted  INTEGER NOT NULL,
    server_payload_hash TEXT,
    server_commit_seq  INTEGER,
    detected_at        INTEGER NOT NULL
);
-- What waits for the server, in send order (docs/SYNC_SINGLE_SOURCE.md
-- point 3; vault/outbox.py). kind 'write': the folder or entry object_id;
-- 'envelope': an access envelope; 'audit': an audit record; account-level
-- operations (key change, re-key, revocations, team changes...) carry their
-- request in body. state 'refused': never sent (an unverifiable legacy audit
-- record, a team change set aside).
CREATE TABLE IF NOT EXISTS outbox (
    seq                INTEGER PRIMARY KEY AUTOINCREMENT,
    kind               TEXT NOT NULL,
    object_id          TEXT,
    body               TEXT,
    state              TEXT NOT NULL DEFAULT 'queued',
    UNIQUE (kind, object_id)
);
-- Envelopes whose signed tombstone this device applied: a replay of the
-- live envelope is not taken back (review d615826 H2).
CREATE TABLE IF NOT EXISTS withdrawn_envelopes (
    envelope_id        TEXT PRIMARY KEY
);
-- Envelopes this device first got from the server, not made itself: only
-- its own grants are sealed again on a re-keyed folder's new key.
CREATE TABLE IF NOT EXISTS pulled_envelopes (
    envelope_id        TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS object_server_seq (
    object_id          TEXT PRIMARY KEY,  -- folder or entry the server confirmed
    commit_seq         INTEGER NOT NULL   -- at this commit_seq (review d150605 #5)
);
-- The server's modified_at (its clock) of the copy a pull confirmed: after a
-- restore, a lower version committed later was written without this copy.
CREATE TABLE IF NOT EXISTS object_server_time (
    object_id          TEXT PRIMARY KEY,
    modified_at        INTEGER NOT NULL
);
-- Versions this device sent. A reply that never arrived leaves the server
-- holding one of them; it is this device's own write, not a conflict.
CREATE TABLE IF NOT EXISTS object_sent_version (
    object_id          TEXT NOT NULL,
    version            INTEGER NOT NULL,
    payload_hash       TEXT NOT NULL,
    PRIMARY KEY (object_id, version)
);
-- The server version each sent write was made on. After a server restore lost
-- the write, a server copy above that version was written without knowing it:
-- a conflict, not an older copy to overwrite (stateful test SM17).
CREATE TABLE IF NOT EXISTS object_sent_base (
    object_id          TEXT NOT NULL,
    version            INTEGER NOT NULL,
    base_version       INTEGER NOT NULL,
    PRIMARY KEY (object_id, version)
);
-- The signed team log as this device accepted it (docs/DESIGN_TEAM_LOG.md).
CREATE TABLE IF NOT EXISTS team_log (
    seq                INTEGER PRIMARY KEY,
    body               TEXT NOT NULL,
    sig                TEXT NOT NULL,
    hash               TEXT NOT NULL
);
"""

# Run once the nodes and entries tables exist (new vault or on every open).
# docs/SYNC_SINGLE_SOURCE.md point 1: a row without a queued write is the
# server copy, so its base is (version, payload hash of its own blobs) and is
# not stored. When a write is queued, that pair is kept on the row: the copy
# the edit is made on (the write is queued before the row changes).
# sezam_payload_hash is registered by VaultDB.open.
BASE_VERSION_TRIGGERS_SQL = """
CREATE TRIGGER IF NOT EXISTS outbox_base_capture AFTER INSERT ON outbox
WHEN NEW.kind = 'write' BEGIN
    UPDATE nodes SET base_version = version, base_parent = COALESCE(parent_id, ''),
        base_hash = sezam_payload_hash(encrypted_meta, NULL) WHERE id = NEW.object_id;
    UPDATE entries SET base_version = version, base_parent = node_id,
        base_hash = sezam_payload_hash(encrypted_meta, encrypted_data) WHERE id = NEW.object_id;
END;
CREATE TRIGGER IF NOT EXISTS nodes_base_delete AFTER DELETE ON nodes BEGIN
    DELETE FROM object_sent_version WHERE object_id = OLD.id;
    DELETE FROM outbox WHERE kind = 'write' AND object_id = OLD.id;
END;
CREATE TRIGGER IF NOT EXISTS entries_base_delete AFTER DELETE ON entries BEGIN
    DELETE FROM object_sent_version WHERE object_id = OLD.id;
    DELETE FROM outbox WHERE kind = 'write' AND object_id = OLD.id;
END;
-- An envelope or audit record is unsent until the server is known to hold it
-- (a push accepted it or a pull brought it, vault/outbox.py).
CREATE TRIGGER IF NOT EXISTS envelope_queue AFTER INSERT ON access_envelopes BEGIN
    INSERT OR IGNORE INTO outbox (kind, object_id) VALUES ('envelope', NEW.id);
END;
CREATE TRIGGER IF NOT EXISTS envelope_unqueue AFTER DELETE ON access_envelopes BEGIN
    DELETE FROM outbox WHERE kind = 'envelope' AND object_id = OLD.id;
END;
CREATE TRIGGER IF NOT EXISTS audit_queue AFTER INSERT ON audit_log BEGIN
    INSERT OR IGNORE INTO outbox (kind, object_id) VALUES ('audit', NEW.id);
END;
CREATE TRIGGER IF NOT EXISTS audit_unqueue AFTER DELETE ON audit_log BEGIN
    DELETE FROM outbox WHERE kind = 'audit' AND object_id = OLD.id;
END;
"""

SCHEMA_SQL = """
-- ============================================================
-- STROM A ZÁZNAMY (všetky obsahové stĺpce sú ciphertext envelope)
-- ============================================================

CREATE TABLE IF NOT EXISTS nodes (
    id              TEXT PRIMARY KEY,   -- ULID
    parent_id       TEXT REFERENCES nodes(id),
    encrypted_meta  BLOB NOT NULL,      -- envelope: {name, tier, sync_flag, created_at, modified_at}
    dek_id          TEXT NOT NULL REFERENCES deks(id),
    version         INTEGER NOT NULL DEFAULT 1,
    is_deleted      INTEGER NOT NULL DEFAULT 0,
    -- Row with a queued write (outbox): the server copy (version, payload_hash)
    -- the edit was made on; NULL = never on the server. Otherwise unused.
    base_version    INTEGER,
    base_hash       TEXT,
    -- R16-N2: that copy's parent ('' = none, NULL = not known: the row's own).
    base_parent     TEXT
);
CREATE INDEX IF NOT EXISTS idx_nodes_parent ON nodes(parent_id);
CREATE INDEX IF NOT EXISTS idx_nodes_dek ON nodes(dek_id);

CREATE TABLE IF NOT EXISTS entries (
    id              TEXT PRIMARY KEY,   -- ULID
    node_id         TEXT NOT NULL REFERENCES nodes(id),
    encrypted_meta  BLOB NOT NULL,      -- envelope: {name, tier, created_at, modified_at}
    encrypted_data  BLOB NOT NULL,      -- envelope: {fields: [{key, value, sensitive, sort_order}]}
    dek_id          TEXT REFERENCES deks(id),  -- NULL = inherits node.dek_id
    version         INTEGER NOT NULL DEFAULT 1,
    is_deleted      INTEGER NOT NULL DEFAULT 0,
    base_version    INTEGER,            -- as nodes.base_version
    base_hash       TEXT,
    base_parent     TEXT
);
CREATE INDEX IF NOT EXISTS idx_entries_node ON entries(node_id);

-- ============================================================
-- KĽÚČE
-- ============================================================

CREATE TABLE IF NOT EXISTS deks (
    id              TEXT PRIMARY KEY,   -- ULID
    node_id         TEXT REFERENCES nodes(id),
    scope           TEXT NOT NULL CHECK(scope IN ('root', 'folder', 'tier2', 'share', 'audit', 'personal')),
    encrypted_dek   BLOB NOT NULL,     -- DEK wrapped by KEK (AEAD blob_kind=6)
    version         INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_deks_node ON deks(node_id);

CREATE TABLE IF NOT EXISTS dek_archive (
    id              TEXT PRIMARY KEY,
    replaced_by     TEXT NOT NULL REFERENCES deks(id),
    encrypted_dek   BLOB NOT NULL,      -- old DEK wrapped by new DEK (AEAD, blob_kind=6)
    archived_at     INTEGER NOT NULL,   -- Unix ms
    version         INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS access_envelopes (
    id              TEXT PRIMARY KEY,
    dek_id          TEXT NOT NULL REFERENCES deks(id),
    user_id         TEXT NOT NULL,
    created_by      TEXT NOT NULL,
    access_level    TEXT NOT NULL DEFAULT 'write' CHECK(access_level IN ('read', 'write')),
    encrypted_dek   BLOB NOT NULL       -- DEK wrapped by NaCl crypto_box
);
CREATE INDEX IF NOT EXISTS idx_envelopes_dek ON access_envelopes(dek_id);
CREATE INDEX IF NOT EXISTS idx_envelopes_user ON access_envelopes(user_id);

-- ============================================================
-- HISTÓRIA
-- ============================================================

CREATE TABLE IF NOT EXISTS entry_history (
    id              TEXT PRIMARY KEY,
    entry_id        TEXT NOT NULL REFERENCES entries(id),
    encrypted_snapshot BLOB NOT NULL,
    dek_id          TEXT NOT NULL,
    changed_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_history_entry ON entry_history(entry_id);

-- ============================================================
-- AUDIT LOG (Merkle DAG + Ed25519 podpisy)
-- ============================================================

CREATE TABLE IF NOT EXISTS audit_log (
    id              TEXT PRIMARY KEY,       -- ULID
    parent_ids      TEXT NOT NULL,          -- JSON array of ULIDs
    actor_id        TEXT NOT NULL,
    action          TEXT NOT NULL,
    encrypted_details BLOB,
    timestamp       INTEGER NOT NULL,       -- Unix ms
    signature       BLOB NOT NULL           -- Ed25519
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id);

CREATE TABLE IF NOT EXISTS audit_dag_edges (
    child_id        TEXT NOT NULL REFERENCES audit_log(id),
    parent_id       TEXT NOT NULL REFERENCES audit_log(id),
    PRIMARY KEY (child_id, parent_id)
);
CREATE INDEX IF NOT EXISTS idx_dag_parent ON audit_dag_edges(parent_id);

-- ============================================================
-- LOKÁLNY KEY CACHE (TOFU)
-- ============================================================

CREATE TABLE IF NOT EXISTS known_keys (
    user_id         TEXT PRIMARY KEY,
    signing_pk      BLOB NOT NULL,
    encryption_pk   BLOB NOT NULL,
    fingerprint     TEXT NOT NULL,
    first_seen      INTEGER NOT NULL,
    last_verified   INTEGER NOT NULL
);

-- ============================================================
-- METADÁTA
-- ============================================================

CREATE TABLE IF NOT EXISTS vault_meta (
    key             TEXT PRIMARY KEY,
    value           TEXT
);
"""

SCHEMA_SQL += SYNC_CONFLICTS_SQL + BASE_VERSION_TRIGGERS_SQL

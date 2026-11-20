"""MariaDB database management — async via aiomysql.

Content-blind blob store (spec 4.2).
"""

from __future__ import annotations

import asyncio
import logging
import random
import secrets
import aiomysql
import pymysql
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Awaitable, Callable, Optional, TypeVar

from .config import ServerConfig
from .models.schemas import normalize_username

logger = logging.getLogger(__name__)

T = TypeVar("T")


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id              VARCHAR(26) PRIMARY KEY,
    username        VARCHAR(255) UNIQUE NOT NULL,
    signing_pk      BLOB NOT NULL,
    encryption_pk   BLOB NOT NULL,
    key_fingerprint VARCHAR(64) NOT NULL,
    status          VARCHAR(10) NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending', 'active', 'revoked')),
    is_admin        TINYINT(1) NOT NULL DEFAULT 0,
    encrypted_keypair BLOB,
    argon2_salt     BLOB,
    auth_salt       BLOB,
    verify_salt     BLOB,
    auth_proof_hash VARCHAR(255),
    argon2_params   VARCHAR(255),
    token_epoch     INTEGER NOT NULL DEFAULT 0,
    recovery_locked TINYINT(1) NOT NULL DEFAULT 0,
    recovery_attempts INTEGER NOT NULL DEFAULT 0,
    recovery_attempts_hour INTEGER NOT NULL DEFAULT 0,
    last_recovery_attempt BIGINT,
    key_reset_until BIGINT NULL,
    key_reset_by    VARCHAR(26) NULL,
    recovery_trusted_nets TEXT NULL,
    recovery_unlock_hash VARCHAR(64) NULL,
    recovery_unlock_until BIGINT NULL,
    renamed_from    VARCHAR(255) NULL,
    created_at      BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

CREATE TABLE IF NOT EXISTS user_key_archives (
    id              VARCHAR(26) PRIMARY KEY,
    user_id         VARCHAR(26) NOT NULL,
    signing_pk      BINARY(32) NOT NULL,
    encryption_pk   BINARY(32) NOT NULL,
    key_fingerprint VARCHAR(64) NOT NULL,
    archived_at     BIGINT NOT NULL,
    successor_signing_pk BINARY(32) NULL,
    rotation_signature BINARY(64) NULL,
    authorization_signature BINARY(64) NULL,
    retired_seq     BIGINT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_uka_user_time (user_id, archived_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

CREATE TABLE IF NOT EXISTS user_key_material_archive (
    id                VARCHAR(26) PRIMARY KEY,
    user_id           VARCHAR(26) NOT NULL,
    key_epoch         INTEGER NOT NULL,
    encrypted_keypair BLOB NOT NULL,
    argon2_salt       BINARY(16),
    argon2_params     TEXT,
    auth_salt         BINARY(16),
    archived_at       BIGINT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_ukma_user_time (user_id, archived_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

CREATE TABLE IF NOT EXISTS vault_objects (
    id              VARCHAR(26) PRIMARY KEY,
    object_type     VARCHAR(20) NOT NULL,
    payload         LONGBLOB NOT NULL,
    owner_id        VARCHAR(26) NOT NULL,
    write_policy    VARCHAR(16) NOT NULL DEFAULT 'owner_only',
    access_level    VARCHAR(5),
    dek_scope       VARCHAR(8) NULL,
    target_user_id  VARCHAR(26),
    FOREIGN KEY (owner_id) REFERENCES users(id),
    FOREIGN KEY (target_user_id) REFERENCES users(id) ON DELETE CASCADE,
    parent_ref      VARCHAR(26),
    version         INTEGER NOT NULL DEFAULT 1,
    commit_seq      BIGINT,
    is_deleted      TINYINT(1) NOT NULL DEFAULT 0,
    payload_hash    VARCHAR(64) NOT NULL,
    client_signature BLOB,
    signature_user_id VARCHAR(26),
    FOREIGN KEY (signature_user_id) REFERENCES users(id),
    modified_at     BIGINT NOT NULL,
    INDEX idx_vo_type (object_type),
    INDEX idx_vo_owner (owner_id),
    INDEX idx_vo_target (target_user_id),
    INDEX idx_vo_parent (parent_ref),
    INDEX idx_vo_modified (modified_at),
    INDEX idx_vo_commit_seq (commit_seq)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

CREATE TABLE IF NOT EXISTS shared_links (
    id              VARCHAR(43) PRIMARY KEY,
    encrypted_blob  LONGBLOB NOT NULL,
    created_by      VARCHAR(26) NOT NULL,
    FOREIGN KEY (created_by) REFERENCES users(id),
    created_at      BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL,
    max_views       INTEGER NOT NULL DEFAULT 1,
    view_count      INTEGER NOT NULL DEFAULT 0,
    pin_hash        VARCHAR(255),
    pin_attempts    INTEGER NOT NULL DEFAULT 0,
    is_locked       TINYINT(1) NOT NULL DEFAULT 0,
    notify_on_view  TINYINT(1) NOT NULL DEFAULT 1,
    INDEX idx_shares_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

CREATE TABLE IF NOT EXISTS share_views (
    id              VARCHAR(26) PRIMARY KEY,
    share_id        VARCHAR(43) NOT NULL,
    viewed_at       BIGINT NOT NULL,
    viewer_ip_hmac  VARCHAR(64),
    user_agent_hmac VARCHAR(64),
    owner_id        VARCHAR(26),
    notification_pending TINYINT(1) NOT NULL DEFAULT 0,
    FOREIGN KEY (share_id) REFERENCES shared_links(id) ON DELETE CASCADE,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_share_notifications (owner_id, notification_pending)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

CREATE TABLE IF NOT EXISTS share_pin_rate_limits (
    ip_hmac           VARCHAR(64) PRIMARY KEY,
    window_started_at BIGINT NOT NULL,
    failure_count     INTEGER NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

CREATE TABLE IF NOT EXISTS server_audit (
    id              VARCHAR(26) PRIMARY KEY,
    user_id         VARCHAR(26) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id),
    action          VARCHAR(50) NOT NULL,
    timestamp       BIGINT NOT NULL,
    request_hash    VARCHAR(64),
    commit_seq_range TEXT,
    client_signature BLOB NOT NULL,
    client_ip       VARCHAR(45),
    INDEX idx_sa_time (timestamp),
    INDEX idx_sa_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

CREATE TABLE IF NOT EXISTS provisioning_tokens (
    token_hash      VARCHAR(64) PRIMARY KEY,
    user_id         VARCHAR(26) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id),
    created_at      BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL,
    is_used         TINYINT(1) NOT NULL DEFAULT 0,
    INDEX idx_prov_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

CREATE TABLE IF NOT EXISTS invitation_tokens (
    token_hash      VARCHAR(64) PRIMARY KEY,
    created_by      VARCHAR(26) NOT NULL,
    FOREIGN KEY (created_by) REFERENCES users(id),
    created_at      BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL,
    is_used         TINYINT(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

CREATE TABLE IF NOT EXISTS spent_challenges (
    challenge_hash  VARCHAR(64) PRIMARY KEY,
    used_at         BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

CREATE TABLE IF NOT EXISTS auth_challenge_limits (
    user_id         VARCHAR(26) PRIMARY KEY,
    window_started_at BIGINT NOT NULL,
    issue_count     INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

CREATE TABLE IF NOT EXISTS org_recovery_rate_limits (
    ip_hmac           VARCHAR(64) PRIMARY KEY,
    window_started_at BIGINT NOT NULL,
    attempt_count     INTEGER NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

CREATE TABLE IF NOT EXISTS recovery_name_limits (
    name_hmac               VARCHAR(64) PRIMARY KEY,
    recovery_attempts       INTEGER NOT NULL DEFAULT 0,
    recovery_attempts_hour  INTEGER NOT NULL DEFAULT 0,
    last_recovery_attempt   BIGINT NULL,
    recovery_locked         TINYINT NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

-- A locked name verifies one proof per window from each network (auth.py).
CREATE TABLE IF NOT EXISTS recovery_probe_slots (
    slot_key VARCHAR(64) PRIMARY KEY,
    probe_at BIGINT NOT NULL,
    INDEX idx_probe_at (probe_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

-- ... and at most recovery_locked_probes_per_window from all networks
-- together (capability run 85), keyed by the name's limit id.
CREATE TABLE IF NOT EXISTS recovery_name_rations (
    limit_id          VARCHAR(64) PRIMARY KEY,
    window_started_at BIGINT NOT NULL,
    checked_count     INTEGER NOT NULL DEFAULT 0,
    INDEX idx_window_started_at (window_started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

CREATE TABLE IF NOT EXISTS recovery_ip_limits (
    ip_hmac           VARCHAR(64) PRIMARY KEY,
    window_started_at BIGINT NOT NULL,
    failure_count     INTEGER NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

CREATE TABLE IF NOT EXISTS revoked_tokens (
    token_hash      VARCHAR(64) PRIMARY KEY,
    revoked_at      BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

CREATE TABLE IF NOT EXISTS write_acl (
    user_id         VARCHAR(26) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    node_id         VARCHAR(26) NOT NULL,
    granted_at      BIGINT NOT NULL,
    PRIMARY KEY (user_id, node_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

CREATE TABLE IF NOT EXISTS commit_counter (
    id              INTEGER PRIMARY KEY DEFAULT 1,
    next_seq        BIGINT NOT NULL DEFAULT 1,
    gc_floor_seq    BIGINT NOT NULL DEFAULT 0,
    gc_clock_ms     BIGINT NOT NULL DEFAULT 0,
    gc_clock_wall_ms BIGINT NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

-- A random token per push transaction (stateful test SM7). A server restored
-- from a backup hands out the same commit_seq again, under a new token: a
-- device whose checkpoint names the old token knows the server went back
-- even when other devices have since pushed the head past its checkpoint.
-- Tombstone GC keeps these rows (one per push): a device anchored below the
-- GC floor must still be told apart from one the server lost commits for.
CREATE TABLE IF NOT EXISTS commit_log (
    last_seq        BIGINT PRIMARY KEY,
    first_seq       BIGINT NOT NULL,
    token           CHAR(32) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

-- Folders and entries tombstone GC removed: their last version and payload
-- hash stay, so the same (id, version) never names other content. A write
-- to a collected id builds on this row (docs/SYNC_SINGLE_SOURCE.md point 1).
CREATE TABLE IF NOT EXISTS collected_objects (
    id              VARCHAR(26) PRIMARY KEY,
    version         INTEGER NOT NULL,
    payload_hash    VARCHAR(64) NOT NULL,
    commit_seq      BIGINT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

CREATE TABLE IF NOT EXISTS sync_state (
    user_id         VARCHAR(26) PRIMARY KEY,
    FOREIGN KEY (user_id) REFERENCES users(id),
    last_push_seq   BIGINT NOT NULL DEFAULT 0,
    last_pull_seq   BIGINT NOT NULL DEFAULT 0,
    last_activity   BIGINT NOT NULL DEFAULT 0,
    key_epoch       INTEGER NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

-- Remote AI kill switch: the owner's latest signed {enabled, epoch}. The
-- server only relays it, brokers verify it against their local key.
-- (No semicolons in comments: SCHEMA_SQL is split on them.)
CREATE TABLE IF NOT EXISTS ai_policies (
    user_id         VARCHAR(26) PRIMARY KEY,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    enabled         TINYINT(1) NOT NULL,
    epoch           BIGINT NOT NULL,
    signature       BINARY(64) NOT NULL,
    updated_at      BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

-- Review c78fd19 R13-11: the highest 'off' epoch a vault's broker saw, so a
-- saved 'on' written back into the vault file does not count after a
-- restart. Opaque here: anchor_key and mac are keyed by the vault's KEK.
CREATE TABLE IF NOT EXISTS ai_anchors (
    anchor_key      CHAR(64) PRIMARY KEY,
    user_id         VARCHAR(26) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    epoch           BIGINT NOT NULL,
    mac             CHAR(64) NOT NULL,
    updated_at      BIGINT NOT NULL,
    INDEX idx_ai_anchors_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

-- Parts of an all-or-nothing push too big for one request (review d150605
-- #3). The push that names the batch applies them and deletes them.
CREATE TABLE IF NOT EXISTS sync_staged_objects (
    user_id         VARCHAR(26) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    batch_id        VARCHAR(26) NOT NULL,
    idx             INTEGER NOT NULL,
    object_json     LONGTEXT NOT NULL,
    size_bytes      INTEGER NOT NULL,
    created_at      BIGINT NOT NULL,
    PRIMARY KEY (user_id, batch_id, idx)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

-- One staged push or stage request per account at a time, across workers
-- (review 7c10379 H7). A claim older than its TTL is taken over.
CREATE TABLE IF NOT EXISTS sync_push_claims (
    user_id         VARCHAR(26) PRIMARY KEY,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    claim_id        CHAR(32) NOT NULL,
    claimed_at      BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

-- One staged push held in memory server-wide at a time (review a159e97).
CREATE TABLE IF NOT EXISTS sync_staged_gate (
    id              INTEGER PRIMARY KEY,
    claim_id        CHAR(32) NOT NULL,
    claimed_at      BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

-- Accounts waiting for the staged gate, served in order of arrival (review
-- 1141a20 R9-F). A waiter refreshes seen_at while it polls, and one that
-- stopped (its worker died) is dropped.
CREATE TABLE IF NOT EXISTS sync_staged_queue (
    user_id         VARCHAR(26) PRIMARY KEY,
    claim_id        CHAR(32) NOT NULL,
    queued_at       BIGINT NOT NULL,
    seen_at         BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

CREATE TABLE IF NOT EXISTS org_recovery_blobs (
    id              INTEGER PRIMARY KEY DEFAULT 1,
    wrapped_kek     LONGBLOB NOT NULL,
    recovery_signing_pk BINARY(32) NOT NULL,
    threshold       INTEGER NOT NULL DEFAULT 3,
    total_shares    INTEGER NOT NULL DEFAULT 5,
    created_by      VARCHAR(26) NOT NULL,
    created_at      BIGINT NOT NULL,
    key_epoch       BIGINT NULL,
    log_seq         BIGINT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

-- A random id per database: the JWT key is derived from it (review 7c10379).
CREATE TABLE IF NOT EXISTS server_instance (
    id              INTEGER PRIMARY KEY DEFAULT 1,
    instance_id     BINARY(32) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;

-- Signed team log (docs/DESIGN_TEAM_LOG.md): appended only onto the head.
CREATE TABLE IF NOT EXISTS team_log (
    seq             BIGINT PRIMARY KEY,
    prev            CHAR(64) NOT NULL,
    hash            CHAR(64) NOT NULL UNIQUE,
    body            TEXT NOT NULL,
    sig             CHAR(128) NOT NULL,
    author          VARCHAR(26) NOT NULL,
    created_at      BIGINT NOT NULL,
    INDEX idx_team_log_author (author)
) ENGINE=InnoDB DEFAULT CHARSET=ascii;
"""

SCHEMA_TABLE_OPTIONS = "DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci"
SCHEMA_COLLATION = "utf8mb4_uca1400_ai_ci"


def schema_sql_for(charset: str, collation: str) -> str:
    """SCHEMA_SQL with the new utf8mb4 tables in ``charset``/``collation``.

    Review 4acfdde (R11 #1): a database an older version created holds users
    (and shared_links) in the server's default collation of that time, e.g.
    utf8mb4_general_ci on 10.x. A foreign key needs the same collation on both
    columns, so a new table in utf8mb4_uca1400_ai_ci referencing users failed
    with errno 150 and the server never started. New tables take the
    collation of the existing users table instead."""
    if not (charset.isidentifier() and collation.isidentifier()):
        raise ValueError(f"unexpected charset/collation {charset!r}/{collation!r}")
    return SCHEMA_SQL.replace(SCHEMA_TABLE_OPTIONS, f"DEFAULT CHARSET={charset} COLLATE={collation}")


async def _schema_sql(cur) -> str:
    await cur.execute(
        "SELECT CHARACTER_SET_NAME, COLLATION_NAME FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'id'"
    )
    row = await cur.fetchone()
    if row and row[1] and row[1] != SCHEMA_COLLATION:
        logger.warning(
            "users.id uses %s/%s (created by an older version): new tables "
            "use the same collation so their foreign keys to users hold",
            row[0], row[1],
        )
        return schema_sql_for(row[0], row[1])
    if not row:
        await cur.execute("SHOW COLLATION LIKE %s", (SCHEMA_COLLATION,))
        if not await cur.fetchall():
            raise RuntimeError(
                f"The database server has no {SCHEMA_COLLATION} collation: "
                "a new Sezam database needs MariaDB 10.10 or later"
            )
    return SCHEMA_SQL


INIT_SQL = """
INSERT IGNORE INTO commit_counter (id, next_seq, gc_floor_seq) VALUES (1, 1, 0);
"""

# Migrations for existing databases
MIGRATIONS_SQL = [
    # Add client_ip column to server_audit if not present
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'server_audit' AND COLUMN_NAME = 'client_ip'",
        "ALTER TABLE server_audit ADD COLUMN client_ip VARCHAR(45)",
    ),
    # Widen commit_seq_range from VARCHAR(100) to TEXT for existing databases
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'server_audit' "
        "AND COLUMN_NAME = 'commit_seq_range' AND DATA_TYPE = 'text'",
        "ALTER TABLE server_audit MODIFY COLUMN commit_seq_range TEXT",
    ),
    # Add write_policy column to vault_objects (ownership ACL)
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'vault_objects' AND COLUMN_NAME = 'write_policy'",
        "ALTER TABLE vault_objects ADD COLUMN write_policy VARCHAR(16) NOT NULL DEFAULT 'owner_only'",
    ),
    # Server-visible envelope permission. NULL is fail-closed for legacy rows.
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'vault_objects' AND COLUMN_NAME = 'access_level'",
        "ALTER TABLE vault_objects ADD COLUMN access_level VARCHAR(5) NULL",
    ),
    # DEK type label (root/audit/tier2/...) so a full resync keeps DEK roles.
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'vault_objects' AND COLUMN_NAME = 'dek_scope'",
        "ALTER TABLE vault_objects ADD COLUMN dek_scope VARCHAR(8) NULL",
    ),
    # Public key used for one-time proof of org recovery key reconstruction.
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'org_recovery_blobs' "
        "AND COLUMN_NAME = 'recovery_signing_pk'",
        "ALTER TABLE org_recovery_blobs ADD COLUMN recovery_signing_pk BINARY(32) NULL",
    ),
    # Owner key epoch the recovery blob wraps; a later rotation makes it stale.
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'org_recovery_blobs' "
        "AND COLUMN_NAME = 'key_epoch'",
        "ALTER TABLE org_recovery_blobs ADD COLUMN key_epoch BIGINT NULL",
    ),
    # Preserve object ownership while authenticating the user who signed its latest version.
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'vault_objects' "
        "AND COLUMN_NAME = 'signature_user_id'",
        "ALTER TABLE vault_objects ADD COLUMN signature_user_id VARCHAR(26) NULL",
    ),
    # Existing deployments predate password/key epoch enforcement.
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'sync_state' "
        "AND COLUMN_NAME = 'key_epoch'",
        "ALTER TABLE sync_state ADD COLUMN key_epoch INTEGER NOT NULL DEFAULT 0",
    ),
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'shared_links' "
        "AND COLUMN_NAME = 'notify_on_view'",
        "ALTER TABLE shared_links ADD COLUMN notify_on_view TINYINT(1) NOT NULL DEFAULT 1",
    ),
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'share_views' "
        "AND COLUMN_NAME = 'owner_id'",
        "ALTER TABLE share_views ADD COLUMN owner_id VARCHAR(26) NULL",
    ),
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'share_views' "
        "AND COLUMN_NAME = 'notification_pending'",
        "ALTER TABLE share_views ADD COLUMN notification_pending TINYINT(1) NOT NULL DEFAULT 0",
    ),
    # Per-account Argon2id params so every client derives the same KEK.
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' "
        "AND COLUMN_NAME = 'argon2_params'",
        "ALTER TABLE users ADD COLUMN argon2_params VARCHAR(255) NULL",
    ),
    # Bumped on key rotation / keypair replacement to revoke older JWTs.
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' "
        "AND COLUMN_NAME = 'token_epoch'",
        "ALTER TABLE users ADD COLUMN token_epoch INTEGER NOT NULL DEFAULT 0",
    ),
    # Rotation certificate: the successor key vouches for the archived key, so
    # a server cannot invent "historical" keys clients would trust.
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user_key_archives' "
        "AND COLUMN_NAME = 'successor_signing_pk'",
        "ALTER TABLE user_key_archives ADD COLUMN successor_signing_pk BINARY(32) NULL",
    ),
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user_key_archives' "
        "AND COLUMN_NAME = 'rotation_signature'",
        "ALTER TABLE user_key_archives ADD COLUMN rotation_signature BINARY(64) NULL",
    ),
    # Review 688edcb K1: an admin lets a user without the old password
    # (org recovery on the desktop) replace the key material once.
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' "
        "AND COLUMN_NAME = 'key_reset_until'",
        "ALTER TABLE users ADD COLUMN key_reset_until BIGINT NULL",
    ),
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' "
        "AND COLUMN_NAME = 'key_reset_by'",
        "ALTER TABLE users ADD COLUMN key_reset_by VARCHAR(26) NULL",
    ),
    # Review 688edcb V2: a locked name verifies one proof per window
    # (recovery_probe_slots), except from the networks its owner last
    # recovered from.
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' "
        "AND COLUMN_NAME = 'recovery_trusted_nets'",
        "ALTER TABLE users ADD COLUMN recovery_trusted_nets TEXT NULL",
    ),
    # Review e4cd15a: an admin unlock hands the owner a one-time code that
    # gets one /recover past the locked-name rations from any network.
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' "
        "AND COLUMN_NAME = 'recovery_unlock_hash'",
        "ALTER TABLE users ADD COLUMN recovery_unlock_hash VARCHAR(64) NULL",
    ),
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' "
        "AND COLUMN_NAME = 'recovery_unlock_until'",
        "ALTER TABLE users ADD COLUMN recovery_unlock_until BIGINT NULL",
    ),
    # Review 688edcb V4: the old key's consent to the rotation, and the last
    # commit_seq the archived key could have signed (clients trust it no later).
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user_key_archives' "
        "AND COLUMN_NAME = 'authorization_signature'",
        "ALTER TABLE user_key_archives ADD COLUMN authorization_signature BINARY(64) NULL",
    ),
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'user_key_archives' "
        "AND COLUMN_NAME = 'retired_seq'",
        "ALTER TABLE user_key_archives ADD COLUMN retired_seq BIGINT NULL",
    ),
    # Review e4cd15a (low): the name a migration-renamed account's devices
    # still sign in with (trim_stored_usernames).
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' "
        "AND COLUMN_NAME = 'renamed_from'",
        "ALTER TABLE users ADD COLUMN renamed_from VARCHAR(255) NULL",
    ),
    # Review d150605 N7: the clock tombstone GC ages tombstones by.
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'commit_counter' "
        "AND COLUMN_NAME = 'gc_clock_ms'",
        "ALTER TABLE commit_counter ADD COLUMN gc_clock_ms BIGINT NOT NULL DEFAULT 0",
    ),
    # Review 8595ec1: the wall clock at the last GC run, which bounds how far
    # a worker's first run may move the GC clock.
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'commit_counter' "
        "AND COLUMN_NAME = 'gc_clock_wall_ms'",
        "ALTER TABLE commit_counter ADD COLUMN gc_clock_wall_ms BIGINT NOT NULL DEFAULT 0",
    ),
    # Review 4acfdde R11 #2: the team-log head when the blob was stored, so
    # the newer of the blob and a key the log names is the current recovery.
    (
        "SELECT COUNT(*) FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'org_recovery_blobs' "
        "AND COLUMN_NAME = 'log_seq'",
        "ALTER TABLE org_recovery_blobs ADD COLUMN log_seq BIGINT NULL",
    ),
    # Review c78fd19 (medium): a member's own records (personal_tree) were
    # found by reading the whole log.
    (
        "SELECT COUNT(*) FROM information_schema.STATISTICS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'team_log' "
        "AND INDEX_NAME = 'idx_team_log_author'",
        "ALTER TABLE team_log ADD INDEX idx_team_log_author (author)",
    ),
]

# A blob from before log_seq was the server's current recovery at upgrade
# time: it ranks with the log head then.
BACKFILL_RECOVERY_LOG_SEQ_SQL = (
    "UPDATE org_recovery_blobs SET log_seq = "
    "(SELECT COALESCE(MAX(seq), -1) FROM team_log) WHERE log_seq IS NULL"
)

# Archives from before V4 never recorded when their key was retired: bound
# them by the head at upgrade time (nothing later can be theirs).
BACKFILL_RETIRED_SEQ_SQL = (
    "UPDATE user_key_archives SET retired_seq = "
    "(SELECT next_seq - 1 FROM commit_counter WHERE id = 1) "
    "WHERE retired_seq IS NULL"
)


async def _username_taken(cur, username: str, user_id: str) -> bool:
    await cur.execute(
        "SELECT COUNT(*) FROM users WHERE username = %s AND id <> %s",
        (username, user_id),
    )
    row = await cur.fetchone()
    return bool(row and row[0])


async def trim_stored_usernames(cur) -> None:
    """Lockout review N3: requests normalize the username (schemas.
    normalize_username: trimmed, NFC), so an account stored as " alice",
    "alice\\u00a0" or an NFD "Šimon" before that would no longer be reachable.
    Rename it to the normalized name. The filter runs here, not as a SQL
    REGEXP: MariaDB's [[:space:]] misses NBSP and the other Unicode spaces.

    Review 688edcb N3: if another account already holds the normalized name
    (every login reaches that one), the older account gets "<name>-2" (-3, ...)
    instead of staying under a name no request can reach any more; the log
    says which name its user now logs in with.

    Review e4cd15a (low): its devices still held the old name, and their
    logins reached the other account. The account records it in
    renamed_from; /auth/verify signs a login under that name in when the
    renamed account's key signed it and answers the current name, which
    the devices store."""
    await cur.execute("SELECT id, username FROM users")
    for user_id, username in await cur.fetchall():
        normalized = normalize_username(username)
        if not normalized or normalized == username:
            continue
        target = normalized
        suffix = 1
        while await _username_taken(cur, target, user_id):
            suffix += 1
            target = f"{normalized}-{suffix}"
        if target != normalized:
            logger.warning(
                "Account %s renamed to %r: its normalized name %r belongs to "
                "another account; its user now logs in as %r",
                user_id, target, normalized, target,
            )
            await cur.execute(
                "UPDATE users SET username = %s, renamed_from = %s WHERE id = %s",
                (target, normalized, user_id),
            )
            continue
        await cur.execute("UPDATE users SET username = %s WHERE id = %s", (target, user_id))


SCHEMA_LOCK_NAME = "sezam_schema_migration"
MAINTENANCE_LOCK_NAME = "sezam_periodic_maintenance"


class Database:
    """Async MariaDB connection pool."""

    def __init__(self, config: ServerConfig):
        self._config = config
        self._pool: Optional[aiomysql.Pool] = None
        self._maintenance_conn: Optional[aiomysql.Connection] = None
        self.instance_id: Optional[bytes] = None  # set by create_schema

    async def connect(self) -> None:
        self._pool = await aiomysql.create_pool(
            host=self._config.db_host,
            port=self._config.db_port,
            user=self._config.db_user,
            password=self._config.db_password,
            db=self._config.db_name,
            charset="utf8mb4",
            autocommit=True,
            # Out-of-range or too-long values must fail, never be truncated,
            # whatever sql_mode the server was configured with.
            init_command="SET SESSION sql_mode = CONCAT(@@sql_mode, ',STRICT_ALL_TABLES')",
            minsize=2,
            maxsize=10,
        )

    async def close(self) -> None:
        self._drop_maintenance_conn()
        if self._pool:
            self._pool.close()
            await self._pool.wait_closed()

    async def create_schema(self) -> None:
        async with self.acquire() as conn:
            async with conn.cursor() as cur:
                # Every worker calls this at startup; serialize them so two
                # workers never run the same ALTER TABLE concurrently.
                await cur.execute("SELECT GET_LOCK(%s, 120)", (SCHEMA_LOCK_NAME,))
                row = await cur.fetchone()
                if not row or row[0] != 1:
                    raise RuntimeError("Timed out waiting for the schema migration lock")
                try:
                    for statement in (await _schema_sql(cur)).split(";"):
                        stmt = statement.strip()
                        if stmt:
                            await cur.execute(stmt)
                    await cur.execute(INIT_SQL)
                    await cur.execute(
                        "INSERT IGNORE INTO server_instance (id, instance_id) VALUES (1, %s)",
                        (secrets.token_bytes(32),),
                    )
                    await cur.execute("SELECT instance_id FROM server_instance WHERE id = 1")
                    self.instance_id = bytes((await cur.fetchone())[0])
                    # Run migrations for existing databases
                    for check_sql, migrate_sql in MIGRATIONS_SQL:
                        await cur.execute(check_sql)
                        row = await cur.fetchone()
                        if row and row[0] == 0:
                            await cur.execute(migrate_sql)
                    await cur.execute(BACKFILL_RETIRED_SEQ_SQL)
                    await cur.execute(BACKFILL_RECOVERY_LOG_SEQ_SQL)
                    await trim_stored_usernames(cur)
                    await conn.commit()
                finally:
                    await cur.execute("SELECT RELEASE_LOCK(%s)", (SCHEMA_LOCK_NAME,))

    async def hold_maintenance_lock(self) -> bool:
        """Return True while this worker is the single maintenance runner.

        The MariaDB named lock lives as long as the dedicated connection that
        took it, so if the leading worker dies another one takes over on its
        next attempt.
        """
        assert self._pool is not None, "Database not connected"
        if self._maintenance_conn is not None:
            try:
                async with self._maintenance_conn.cursor() as cur:
                    await cur.execute(
                        "SELECT IS_USED_LOCK(%s) = CONNECTION_ID()",
                        (MAINTENANCE_LOCK_NAME,),
                    )
                    row = await cur.fetchone()
                if row and row[0] == 1:
                    return True
            except Exception:
                logger.warning("Maintenance lock connection lost; reacquiring", exc_info=True)
            self._drop_maintenance_conn()
        conn = await self._pool.acquire()
        try:
            async with conn.cursor() as cur:
                await cur.execute("SELECT GET_LOCK(%s, 0)", (MAINTENANCE_LOCK_NAME,))
                row = await cur.fetchone()
        except Exception:
            self._pool.release(conn)
            raise
        if row and row[0] == 1:
            self._maintenance_conn = conn
            return True
        self._pool.release(conn)
        return False

    def _drop_maintenance_conn(self) -> None:
        conn, self._maintenance_conn = self._maintenance_conn, None
        if conn is not None and self._pool is not None:
            conn.close()  # closing the session releases the named lock
            self._pool.release(conn)

    def pool_exhausted(self) -> bool:
        """Every connection of the pool is in use (busy, or wedged)."""
        pool = self._pool
        return pool is not None and pool.freesize == 0 and pool.size >= pool.maxsize

    async def ping_outside_pool(self, timeout: float) -> None:
        """SELECT 1 over a connection of its own: does the database answer?"""
        conn = await aiomysql.connect(
            host=self._config.db_host,
            port=self._config.db_port,
            user=self._config.db_user,
            password=self._config.db_password,
            db=self._config.db_name,
            connect_timeout=timeout,
        )
        try:
            async with conn.cursor() as cur:
                await cur.execute("SELECT 1")
                await cur.fetchone()
        finally:
            conn.close()

    @asynccontextmanager
    async def acquire(self) -> AsyncGenerator[aiomysql.Connection, None]:
        assert self._pool is not None, "Database not connected"
        conn = await self._pool.acquire()
        try:
            yield conn
        finally:
            self._pool.release(conn)

    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[aiomysql.Connection, None]:
        """Acquire connection with explicit transaction (BEGIN/COMMIT/ROLLBACK)."""
        async with self.acquire() as conn:
            await conn.begin()
            try:
                yield conn
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise


# InnoDB rolled the whole transaction back; running it again is safe.
# 1020 (record changed since last read): MariaDB 11.6+ with the default
# innodb_snapshot_isolation=ON, when a locking read meets a row another
# transaction committed after this one's snapshot (review 8595ec1: compose
# runs 11.8, CI ran 10.11 which never raises it).
RETRYABLE_LOCK_ERRORS = frozenset({1213, 1205, 1020})  # deadlock, lock wait timeout, snapshot
TRANSACTION_ATTEMPTS = 4


async def run_transaction(db, body: Callable[[aiomysql.Connection], Awaitable[T]]) -> T:
    """Run ``body(conn)`` in one transaction, retrying it from scratch when
    InnoDB aborts it with a deadlock or a lock wait timeout.

    ``body`` must keep all of its state local, because a retry starts over.
    """
    for attempt in range(1, TRANSACTION_ATTEMPTS + 1):
        try:
            async with db.transaction() as conn:
                return await body(conn)
        except pymysql.err.OperationalError as exc:
            code = exc.args[0] if exc.args else None
            if code not in RETRYABLE_LOCK_ERRORS or attempt == TRANSACTION_ATTEMPTS:
                raise
            logger.info("Transaction aborted by InnoDB (%s); retry %d", code, attempt)
            await asyncio.sleep(random.uniform(0.005, 0.02) * attempt)
    raise AssertionError("unreachable")

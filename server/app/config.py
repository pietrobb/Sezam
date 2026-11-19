"""Server configuration.

JWT signing key: Ed25519, generated at first start, stored in config file or env var.
Never in DB. Algorithm: EdDSA, crv=Ed25519. Manual rotation (admin restart).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from nacl.signing import SigningKey

# Shortest tombstone retention the server starts with (SEZAM_TOMBSTONE_GC_DAYS).
MIN_TOMBSTONE_GC_DAYS = 7


@dataclass
class ServerConfig:
    """Server configuration loaded from env vars or config file."""

    # Database
    db_host: str = "localhost"
    db_port: int = 3306
    db_user: str = "sezam"
    db_password: str = ""
    db_name: str = "sezam"

    # JWT
    jwt_expiry_seconds: int = 3600  # 1 hour
    jwt_onboarding_expiry_seconds: int = 900  # 15 min
    jwt_signing_key_path: str = ""  # Path to Ed25519 private key file

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    base_url: str = "http://localhost:8000"

    # Security
    hmac_server_secret: str = ""  # For HMAC(server_secret, IP), user enumeration fake salts
    cors_origins: list[str] = field(default_factory=list)

    # Tombstone GC
    tombstone_gc_days: int = 90

    # Share
    share_expiry_cron_hours: int = 1

    # Recovery rate limiting
    # Wrong proofs per client address per hour (any name): beyond it they are
    # answered 429; a correct proof is never refused for its address.
    recovery_ip_max_failures_per_hour: int = 10
    recovery_max_total: int = 10
    recovery_lock_seconds: int = 86_400  # total-failure lock auto-expires
    # A locked name verifies at most one proof per window from each network
    # and at most recovery_locked_probes_per_window from all networks together
    # (guessing from many addresses stays bounded). Fewer attacking networks
    # than that cannot refuse the owner; that many or more can, and then only
    # the owner's own networks (registration, signed device logins, past
    # recoveries) or an admin unlock get through - they are not rationed
    # (review 688edcb V2, capability runs 83, 85 and 88).
    recovery_locked_probe_seconds: int = 300
    recovery_locked_probes_per_window: int = 3

    # A bootstrap admin that never got key material (and left nothing else)
    # can be replaced by a new bootstrap after this long (lockout review #10).
    abandoned_bootstrap_seconds: int = 3600
    # Review 688edcb #10: by default only from the network the first bootstrap
    # came from; the operator sets this to allow it from anywhere.
    bootstrap_reset_any_network: bool = False
    # Review a159e97 H6: the operator turns POST /api/bootstrap off for good
    # once the first admin is set up (SEZAM_BOOTSTRAP_DISABLED=1).
    bootstrap_disabled: bool = False

    # Review a159e97 H7: how many objects one push of a non-admin may carry,
    # staged part included (a password change carries every DEK of theirs).
    member_push_max_objects: int = 20_000

    # Review 688edcb: key material replaced by a rotation or password change
    # (wrapped under the OLD password) is kept this long, then deleted - a
    # leaked database is an offline-guessing target for every kept generation.
    key_material_archive_days: int = 30

    # Cleanup intervals (seconds)
    spent_challenge_ttl_seconds: int = 300  # 5 min
    challenge_max_per_ttl: int = 10
    cleanup_interval_seconds: int = 300
    revoked_token_cleanup_seconds: int = 3600  # 1 hour

    @staticmethod
    def cors_origins_from_env() -> list[str]:
        cors_raw = os.getenv("SEZAM_CORS_ORIGINS", "")
        return [origin.strip() for origin in cors_raw.split(",") if origin.strip()]

    @classmethod
    def from_env(cls) -> ServerConfig:
        """Load config from environment variables."""
        hmac_server_secret = os.getenv("SEZAM_HMAC_SECRET", "").strip()
        if not hmac_server_secret:
            raise ValueError("SEZAM_HMAC_SECRET must be set and non-empty")
        from .auth import legacy_bare_signature_until

        legacy_bare_signature_until()  # a malformed date fails at startup
        # Review 8595ec1: 0 (or less) collected every tombstone on the next
        # run, and every device that had not pulled it needed a full resync.
        tombstone_gc_days = int(os.getenv("SEZAM_TOMBSTONE_GC_DAYS", "90"))
        if tombstone_gc_days < MIN_TOMBSTONE_GC_DAYS:
            raise ValueError(
                f"SEZAM_TOMBSTONE_GC_DAYS must be at least {MIN_TOMBSTONE_GC_DAYS} "
                f"(got {tombstone_gc_days})"
            )
        return cls(
            db_host=os.getenv("SEZAM_DB_HOST", "localhost"),
            db_port=int(os.getenv("SEZAM_DB_PORT", "3306")),
            db_user=os.getenv("SEZAM_DB_USER", "sezam"),
            db_password=os.getenv("SEZAM_DB_PASSWORD", ""),
            db_name=os.getenv("SEZAM_DB_NAME", "sezam"),
            jwt_signing_key_path=os.getenv("SEZAM_JWT_KEY_PATH", "jwt_key.bin"),
            host=os.getenv("SEZAM_HOST", "0.0.0.0"),
            port=int(os.getenv("SEZAM_PORT", "8000")),
            base_url=os.getenv("SEZAM_BASE_URL", "http://localhost:8000"),
            hmac_server_secret=hmac_server_secret,
            cors_origins=cls.cors_origins_from_env(),
            tombstone_gc_days=tombstone_gc_days,
            share_expiry_cron_hours=int(os.getenv("SEZAM_SHARE_EXPIRY_CRON_HOURS", "1")),
            recovery_ip_max_failures_per_hour=int(
                os.getenv("SEZAM_RECOVERY_IP_MAX_FAILURES_PER_HOUR", "10")
            ),
            recovery_max_total=int(os.getenv("SEZAM_RECOVERY_MAX_TOTAL", "10")),
            recovery_locked_probe_seconds=int(
                os.getenv("SEZAM_RECOVERY_LOCKED_PROBE_SECONDS", "300")
            ),
            recovery_locked_probes_per_window=int(
                os.getenv("SEZAM_RECOVERY_LOCKED_PROBES_PER_WINDOW", "3")
            ),
            abandoned_bootstrap_seconds=int(
                os.getenv("SEZAM_ABANDONED_BOOTSTRAP_SECONDS", "3600")
            ),
            bootstrap_reset_any_network=os.getenv(
                "SEZAM_BOOTSTRAP_RESET_ANY_NETWORK", ""
            ).strip().lower() in ("1", "true", "yes"),
            bootstrap_disabled=os.getenv(
                "SEZAM_BOOTSTRAP_DISABLED", ""
            ).strip().lower() in ("1", "true", "yes"),
            member_push_max_objects=int(
                os.getenv("SEZAM_MEMBER_PUSH_MAX_OBJECTS", "20000")
            ),
            key_material_archive_days=int(
                os.getenv("SEZAM_KEY_MATERIAL_ARCHIVE_DAYS", "30")
            ),
        )


class JWTKeyManager:
    """Manages Ed25519 key pair for JWT signing.

    Generated at first start, stored in file. Never in DB.
    """

    def __init__(self, key_path: str):
        self._key_path = Path(key_path)
        self._signing_key: SigningKey | None = None
        self._database_id: bytes | None = None

    def bind_database(self, database_id: bytes) -> None:
        """Sign with a key of this database only (review 7c10379).

        The revoked tokens and token epochs live in the database, the key in
        a file: a wiped database with the file kept took every unexpired
        token it had revoked again. The key is now derived from the file's
        key and the database's random id, so a new database refuses them all.
        """
        self._database_id = bytes(database_id)
        self._signing_key = None

    @property
    def signing_key(self) -> SigningKey:
        if self._signing_key is None:
            key = self._load_or_generate()
            if self._database_id is not None:
                key = SigningKey(hmac.new(
                    bytes(key), b"sezam jwt key of database\x00" + self._database_id,
                    hashlib.sha256,
                ).digest())
            self._signing_key = key
        return self._signing_key

    @property
    def verify_key_bytes(self) -> bytes:
        return bytes(self.signing_key.verify_key)

    def _load_or_generate(self) -> SigningKey:
        if self._key_path.exists():
            return SigningKey(self._key_path.read_bytes())
        # Several workers may start at once: write a complete key to a private
        # temp file and publish it with link(), which fails if another worker
        # won the race. The loser then loads the winner's key, so every worker
        # signs with the same key.
        key = SigningKey.generate()
        self._key_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self._key_path.parent, prefix=".jwt-key-")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(bytes(key))
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            try:
                os.link(tmp, self._key_path)
            except FileExistsError:
                return SigningKey(self._key_path.read_bytes())
            return key
        finally:
            os.unlink(tmp)

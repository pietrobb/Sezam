"""The sync client's org recovery: the server blob, its registration and the log's org.recovery.

Split from sync_client.py and team_log_local.py (review d615826 R6-H, MAX_LINES)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from nacl.signing import VerifyKey

from .. import teamlog
from . import oplock, pending_states
from .key_rotation import (
    open_recovery_secret,
    org_recovery_rewrap_message,
    org_recovery_server_wrap,
    org_recovery_signing_key,
    org_recovery_version,
)
from .sync_common import logger, server_error
from .team_log_state import SERVER_WRAP_META, _refusal_from_server

if TYPE_CHECKING:
    from .crud import Vault


class OrgRecoveryMixin:
    """The sync client's org recovery: the server blob, its registration and the log's org.recovery."""

    def _recovery_proof(self, journal: dict, user_id: str) -> dict:
        """Org recovery's reset proof (review e4cd15a #1): a fresh server
        challenge signed by the key derived from the rebuilt recovery secret.
        It authorizes the change without the old password or another admin;
        empty when the journal has no secret or the server has no recovery."""
        secret = open_recovery_secret(journal, self._dek_mgr._kek, user_id)
        if secret is None:
            return {}
        try:
            try:
                challenge = self._request("POST", "/api/org-recovery/challenge", {})["challenge"]
            except RuntimeError as exc:
                logger.warning("No org recovery proof for the password change: %s", exc)
                return {}
            signing_key = org_recovery_signing_key(secret, self._org_recovery_version(secret))
            signature = signing_key.sign(bytes.fromhex(challenge)).signature
            return {"recovery_challenge": challenge, "recovery_signature": signature.hex()}
        finally:
            secret[:] = b"\x00" * len(secret)

    def _org_recovery_version(self, secret: bytes) -> int:
        """R16-L4: the key version of this vault's recovery (the one its Ed25519
        key is); a recovery with no such key here is version 1."""
        return org_recovery_version(secret, self._db.get_meta("org_recovery_signing_pk")) or 1

    def _restore_org_recovery_blob(self, journal: dict, key_epoch: int) -> None:
        """After an org recovery's change landed, wrap the new KEK into the
        server blob under the same recovery key, so the shares keep working
        (web too) and the server does not report the recovery stale."""
        user_id = self._db.get_meta("user_id")
        secret = open_recovery_secret(journal, self._dek_mgr._kek, user_id)
        if secret is None:
            return
        try:
            version = self._org_recovery_version(secret)
            wrapped = org_recovery_server_wrap(self._dek_mgr._kek, secret, version)
            signing_key = org_recovery_signing_key(secret, version)
            threshold = int(self._db.get_meta("org_recovery_threshold") or "2")
            total = int(self._db.get_meta("org_recovery_shares") or "2")
            body = {
                "wrapped_kek": wrapped.hex(),
                "recovery_signing_pk": bytes(signing_key.verify_key).hex(),
                "threshold": threshold,
                "total_shares": total,
                "key_epoch": key_epoch,
                # Review d615826: without the password the server takes the
                # same recovery key's blob only signed by that key.
                "recovery_signature": signing_key.sign(org_recovery_rewrap_message(
                    user_id, key_epoch, threshold, total, wrapped,
                )).signature.hex(),
            }
        finally:
            secret[:] = b"\x00" * len(secret)
        # Capability run 316: the team log carries it too (next push).
        self._db.set_meta_json("org_recovery_server_wrap", {k: v for k, v in body.items() if k != "recovery_signature"})
        # Review 526419e N5: a failed re-wrap left the old KEK's blob on the server for
        # good once the journal was gone, so the body is kept and every push retries it.
        pending_states.set_org_recovery_rewrap(self._db, body)
        self.retry_org_recovery_rewrap()

    def retry_org_recovery_rewrap(self) -> bool:
        """Send a server blob re-wrap that failed before. True when none waits."""
        body = pending_states.org_recovery_rewrap(self._db)
        if body is None:
            return True
        try:
            self._request("POST", "/api/org-recovery/store", body, auth=True)
        except RuntimeError as exc:
            if server_error(exc, 409) or server_error(exc, 403):
                # The account moved on (another password change or another
                # admin's recovery): this wrap is void; unlock reports that the
                # server lacks this vault's recovery key (review 526419e V5).
                # 403: a body saved before review d615826 carries no recovery
                # signature, and the server never takes it without one.
                pending_states.clear_org_recovery_rewrap(self._db)
            logger.warning("Could not re-wrap the server org recovery blob: %s", exc)
            return False
        pending_states.clear_org_recovery_rewrap(self._db)
        return True

    @classmethod
    def register_org_recovery(
        cls, vault: "Vault", password: str, *, replace_other_admin: bool = False,
    ) -> bool:
        """Register the recovery key the vault just set up on its server
        (review e4cd15a #1). False when the vault is not connected; raises
        ValueError for a wrong password, RuntimeError when the server refuses.
        ``replace_other_admin`` replaces another admin's recovery (review 526419e S3)."""
        with oplock.exclusive(vault.db.path):  # INV-6: the body sent is the one cleared
            server_url = vault.db.get_meta("server_url")
            user_id = vault.db.get_meta("user_id")
            body = pending_states.org_recovery_registration(vault.db)
            if not server_url or not user_id or body is None:
                return False
            if replace_other_admin:
                body = {**body, "replace_other_admin": True}
            proof = vault.current_auth_proof(password)
            try:
                client = cls(vault.db, server_url, vault.keypair, user_id)
                client.set_dek_manager(vault.dek_mgr)
                client.store_org_recovery(body, proof)
            finally:
                proof[:] = b"\x00" * len(proof)
            pending_states.clear_org_recovery_registration(vault.db)
            return True

    @classmethod
    def org_recovery_after_connect(cls, vault: "Vault", password: str) -> Optional[str]:
        """Capability review run 91: an org recovery set up before 'connect'
        is registered now. Returns what to tell the user, or None when org
        recovery is not set up on this vault."""
        if not vault.org_recovery_configured() or not vault.db.get_meta("server_url"):
            return None
        from .org_recovery_server import LOG_ADMIN_NOTE, OTHER_ADMIN_NOTE, _log_admin, server_status, superseded_note

        status = server_status(vault)
        owner = status.get("created_by") if status.get("configured") else None
        if owner and owner != vault.db.get_meta("user_id"):
            # Review 526419e S3: a registration (or '--replace') only gets a 409.
            return LOG_ADMIN_NOTE if _log_admin(vault) else OTHER_ADMIN_NOTE
        if note := superseded_note(vault.db, status):  # review c78fd19 R13-10
            return note
        try:
            if cls.register_org_recovery(vault, password):
                return ("The server knows this vault's org recovery: after 'sezam "
                        "org-recovery' it accepts the new password without the old one.")
        except (RuntimeError, ValueError) as exc:
            if note := superseded_note(vault.db, exc=exc):
                return note
            return (f"Warning: the server did not take this vault's org recovery ({exc}). "
                    "Run 'sezam org-recovery-setup --replace' and hand out the new shares.")
        if owner and not status.get("stale"):
            return None
        return ("Warning: the server does not know this vault's org recovery (it was set "
                "up before the vault took the server's account key). The shares would "
                "reset this vault, but the server would refuse the new password. Run "
                "'sezam org-recovery-setup --replace' and hand out the new shares.")

    def store_org_recovery(self, body: dict, current_auth_proof: bytes) -> None:
        """Register this vault's org recovery key on the server (review e4cd15a #1)."""
        if not self._token:
            self.authenticate()
        self._request(
            "POST", "/api/org-recovery/store",
            {**body, "current_auth_proof": bytes(current_auth_proof).hex()}, auth=True,
        )

    def server_org_recovery_stale(self) -> bool:
        """True when this account's org recovery on the server wraps an old KEK.

        The blob is sealed under a recovery key only the share holders can
        rebuild, so no client can re-wrap it after a password change: an
        admin has to set org recovery up again.
        """
        try:
            status = self._request("GET", "/api/org-recovery/status", auth=True) or {}
        except RuntimeError:
            return False
        return bool(status.get("stale")) and status.get("created_by") == self._user_id

    def drop_superseded_org_recovery(self) -> bool:
        """Review c78fd19 R13-10: a setup saved here (offline, or before the
        unlock registered it) and replaced by a newer one on the web is
        forgotten before the push names its key in the log again. True when
        it was (org_recovery_server.SUPERSEDED_NOTE)."""
        from .org_recovery_server import withhold_superseded_setup, superseded_by, waiting_setup

        if waiting_setup(self._db) is None:  # registration or log record (capability run 378)
            return False
        try:
            status = self._request("GET", "/api/org-recovery/status", auth=True) or {}
        except RuntimeError as exc:
            logger.warning("Org recovery status not known: %s", exc)
            return False
        if not superseded_by(self._db, status):
            return False
        withhold_superseded_setup(self._db)
        return True

    def _drop_refused_org_recovery(self, exc: BaseException) -> bool:
        """The server refused this device's org.recovery record: a newer setup
        (web) replaced it after drop_superseded_org_recovery looked. The setup
        is forgotten the same way; True when its records left the queue."""
        from .org_recovery_server import withhold_superseded_setup

        detail = _refusal_from_server(exc)
        if detail is None or detail.get("team_log_code") != "org_recovery_superseded":
            return False
        before = len(self.pending_team_changes())
        withhold_superseded_setup(self._db)
        self._org_recovery_superseded = True
        return len(self.pending_team_changes()) < before

    def adopt_logged_org_recovery(self) -> None:
        """Admin: keep a local KEK wrap of a recovery set up on another client.

        Review 8595ec1 #4 (capability run 314): a recovery set up on the web
        lived only in the server's blob, so a server restored from before it
        lost the KEK wrap and the shares opened nothing. When the log names a
        recovery key of this admin that this vault does not hold and the
        server's blob is of that key, the KEK is wrapped here too (to the
        X25519 form of the Ed25519 recovery key): 'sezam org-recovery' then
        works with those shares and puts the blob back. Only a key the log
        names (signed by this admin) is taken, never one the server reports.
        """
        from nacl.public import SealedBox

        state = self.team_state()
        if state is None or self._dek_mgr is None or not teamlog.is_admin(state, self._user_id):
            return
        logged = teamlog.recovery_key(state, self._user_id)
        if logged is None or logged == self._db.get_meta("org_recovery_signing_pk"):
            return
        if any(kind == "org.recovery" for kind, _ in self.pending_team_changes()):
            return  # a setup here waits to replace it
        from . import pending_states

        if pending_states.org_recovery_registration(self._db) is not None:
            return  # so does one the server has yet to take (anchored after it)
        try:
            status = self._request("GET", "/api/org-recovery/status", auth=True) or {}
        except RuntimeError as exc:
            logger.warning("Org recovery status not known: %s", exc)
            return
        if (
            not status.get("configured") or status.get("stale")
            or status.get("created_by") != self._user_id
            or status.get("recovery_signing_pk") != logged
        ):
            return
        recovery_pk = VerifyKey(bytes.fromhex(logged)).to_curve25519_public_key()
        wrapped = SealedBox(recovery_pk).encrypt(bytes(self._dek_mgr._kek))
        with self._db.transaction(immediate=True):
            self._db.set_meta("org_recovery_pk", bytes(recovery_pk).hex())
            self._db.set_meta("org_recovery_signing_pk", logged)
            self._db.set_meta("org_recovery_wrapped_kek", wrapped.hex())
            self._db.set_meta("org_recovery_stale", "0")
            self._db.set_meta("org_recovery_threshold", str(int(status.get("threshold") or 0)))
            self._db.set_meta("org_recovery_shares", str(int(status.get("total_shares") or 0)))
            logged_wrap = teamlog.recovery_wrap(state, self._user_id)
            if logged_wrap is not None:
                self._db.set_meta_json(SERVER_WRAP_META, {**logged_wrap, "recovery_signing_pk": logged})
            # A setup of this vault the server never took is replaced too.
            pending_states.clear_org_recovery_registration(self._db)
            pending_states.clear_org_recovery_rewrap(self._db)

    def anchor_org_recovery(self, *, replace: bool = False) -> None:
        """Admin: queue an org.recovery record naming this vault's recovery key.

        Review 8595ec1 #4: a server restored from before the registration no
        longer knew the key, and a lone admin's reset after a forgotten
        password was refused for good. The log the devices put back names it.
        Only a key set up here is named, never one a server reports. A push
        names it only while the log names none for this admin: a newer key
        set up on another client (web) stays; ``replace`` is for a setup here.

        Capability run 316: the server-format KEK wrap of that key goes with
        it (org.recovery.wrap), so a restored server serves the shares' blob
        to any client; a newer wrap in the log (a later recovery) stays.
        """
        pk = self._db.get_meta("org_recovery_signing_pk")
        state = self.team_state()
        if not pk or state is None or not teamlog.is_admin(state, self._user_id):
            return
        from . import pending_states

        if pending_states.org_recovery_registration(self._db) is not None:
            return  # the server refuses a key its blob does not hold yet (R13-10)
        from .org_recovery_server import WITHHELD_META

        if self._db.get_meta(WITHHELD_META) == pk:
            return  # reported replaced: kept here, never named again (INV-3)
        logged = teamlog.recovery_key(state, self._user_id)
        replaces = self._db.get_meta_json("org_recovery_replaces") or {}
        # Registered later (offline setup): it still replaces the key it was set up over.
        meant = replaces.get("recovery_signing_pk") == pk and replaces.get("expected_signing_pk") == logged
        if logged is not None and logged != pk and not (replace or meant):
            return
        changes = [] if logged == pk else [["org.recovery", {"recovery_pk": pk}]]
        wrap = dict(self._db.get_meta_json(SERVER_WRAP_META) or {})
        if wrap.pop("recovery_signing_pk", None) == pk:
            current = None if changes else teamlog.recovery_wrap(state, self._user_id)
            if current is None or (current != wrap and wrap["key_epoch"] > current["key_epoch"]):
                changes.append(["org.recovery.wrap", wrap])
        waiting = self.pending_team_changes() + [item.get("change") for item in self.set_aside_team_changes()]
        changes = [change for change in changes if change not in waiting]
        if not changes:
            return
        try:
            self.queue_team_changes(changes)
        except teamlog.TeamLogError as exc:
            logger.warning("The team log does not take this vault's org recovery key: %s", exc)

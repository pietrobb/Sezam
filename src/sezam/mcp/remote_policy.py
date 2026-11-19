"""Remote AI kill switch (AI broker TODO, section 1 phase 2).

Another device of the account owner (the phone) publishes a signed
``ai_policy`` ``{enabled, epoch}`` through the sync server. Every running
``mcp-serve`` fetches it about every 30 s and pulls the brake (the same
``ai_off`` as ``sezam ai off``) when it sees an epoch newer than the last one
it applied. Rules:

- The signature is checked against the owner's signing key held in the
  local vault, never against keys the server hands out, so the server cannot
  forge a policy. A policy that does not verify is ignored and logged.
- A policy can only turn AI access off: ``enabled`` is never used to turn it
  on (that needs the master password on this machine). A new epoch with
  ``enabled=true`` is a brake too.
- An epoch already applied is not applied again, so ``sezam ai on`` after a
  remote brake sticks; a replayed old policy changes nothing.

Signed message (Ed25519, shared with the server and the mobile client,
pinned in tests/vectors/cross_client.json)::

    b"sezam-ai-policy-v1" || user_id (26 B ASCII) || u8(enabled) || u64be(epoch)
"""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Optional

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from ..vault import ai_access

if TYPE_CHECKING:
    from ..vault.crud import Vault
    from .broker import MCPBroker

logger = logging.getLogger(__name__)

POLICY_CONTEXT = b"sezam-ai-policy-v1"
APPLIED_KEY = ai_access.REMOTE_APPLIED_KEY
POLL_SECONDS = 30.0
MAX_EPOCH = 2**63 - 1
_SIGNATURE = re.compile(r"[0-9a-fA-F]{128}")


class PolicyError(ValueError):
    """A remote policy that is malformed or not signed by the owner."""


@dataclass(frozen=True)
class RemotePolicy:
    enabled: bool
    epoch: int


def policy_message(user_id: str, enabled: bool, epoch: int) -> bytes:
    user = user_id.encode("ascii")
    if len(user) != 26:
        raise ValueError("user_id must be a 26-character ULID")
    if not 1 <= epoch <= MAX_EPOCH:
        raise ValueError("epoch out of range")
    return POLICY_CONTEXT + user + bytes([1 if enabled else 0]) + epoch.to_bytes(8, "big")


def sign_policy(signing_key: SigningKey, user_id: str, enabled: bool, epoch: int) -> str:
    return signing_key.sign(policy_message(user_id, enabled, epoch)).signature.hex()


def verify_policy(raw: object, user_id: str, signing_pk: bytes) -> RemotePolicy:
    """Parse a policy from the server and check it against the local key."""
    if not isinstance(raw, dict):
        raise PolicyError("policy is not an object")
    enabled, epoch, signature = raw.get("enabled"), raw.get("epoch"), raw.get("signature")
    if raw.get("user_id", user_id) != user_id:
        raise PolicyError("policy belongs to another account")
    if not isinstance(enabled, bool):
        raise PolicyError("enabled must be a boolean")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or not 1 <= epoch <= MAX_EPOCH:
        raise PolicyError("epoch must be a positive integer")
    if not isinstance(signature, str) or not _SIGNATURE.fullmatch(signature):
        raise PolicyError("signature must be 64 bytes of hex")
    try:
        VerifyKey(bytes(signing_pk)).verify(
            policy_message(user_id, enabled, epoch), bytes.fromhex(signature)
        )
    except (BadSignatureError, ValueError) as exc:
        raise PolicyError("signature does not verify against the owner's key") from exc
    return RemotePolicy(enabled, epoch)


def applied_epoch(vault: "Vault") -> int:
    """Epoch of the last remote policy applied here (unreadable or not
    sealed under the KEK = 0, so any valid policy brakes again)."""
    return ai_access.remote_applied_epoch(vault)


def apply_policy(vault: "Vault", broker: "MCPBroker", policy: RemotePolicy) -> bool:
    """Pull the brake for a policy newer than the last applied one.

    The epoch is recorded only once the off state is persisted; if that
    fails the broker stays off in memory and the next poll tries again.
    """
    if policy.epoch <= applied_epoch(vault):
        return False
    state = broker.disable_ai(
        "remote_policy",
        {"remote_epoch": policy.epoch, "remote_enabled": policy.enabled},
    )
    if state is not None:
        ai_access.record_remote_applied(vault, policy.epoch)
    return True


def fetch_policy(vault: "Vault", token_box: dict) -> Optional[dict]:
    """GET the account's policy; None when the vault is not on a server."""
    from ..vault.sync_client import SyncClient

    server_url = vault.db.get_meta("server_url")
    user_id = vault.db.get_meta("user_id")
    if not server_url or not user_id:
        return None
    client = SyncClient(vault.db, server_url, vault.keypair, user_id)
    client.token = token_box.get("token")
    try:
        return client.get_ai_policy()
    finally:
        token_box["token"] = client.token


class RemotePolicyPoller:
    """Background poll of the remote policy while the vault is unlocked."""

    def __init__(
        self,
        vault: "Vault",
        broker: "MCPBroker",
        interval: float = POLL_SECONDS,
        fetch: Optional[Callable[[], Optional[dict]]] = None,
    ):
        self._vault = vault
        self._broker = broker
        self._interval = interval
        self._token: dict = {}
        self._fetch = fetch or (lambda: fetch_policy(self._vault, self._token))
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.last_result = "not polled"

    def poll_once(self) -> str:
        """One poll; returns what happened (also kept in ``last_result``)."""
        self.last_result = self._poll()
        return self.last_result

    def _poll(self) -> str:
        vault = self._vault
        if not vault.is_unlocked:
            return "locked"
        try:
            # The pinned key: the owner's key from this vault, read before
            # anything comes from the server.
            signing_pk = bytes(vault.keypair.signing_pk)
            user_id = vault.db.get_meta("user_id")
            raw = self._fetch()
        except Exception:
            logger.warning("Remote AI policy poll failed", exc_info=True)
            return "error"
        if raw is None or not user_id:
            return "none"
        try:
            policy = verify_policy(raw, user_id, signing_pk)
        except PolicyError as exc:
            logger.warning("Ignoring remote AI policy: %s", exc)
            return "invalid"
        try:
            applied = apply_policy(vault, self._broker, policy)
        except Exception:
            logger.exception("Applying the remote AI policy failed")
            return "error"
        if applied:
            logger.warning("Remote AI policy (epoch %d): AI access turned off", policy.epoch)
            return "applied"
        return "unchanged"

    def start(self) -> None:
        def run() -> None:
            while True:
                try:
                    self.poll_once()
                except Exception:
                    logger.exception("Remote AI policy poller failed")
                if self._stop.wait(self._interval):
                    return

        self._thread = threading.Thread(target=run, name="sezam-ai-policy", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

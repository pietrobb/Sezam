"""Stateful sync test: random combinations of operations on several devices.

Five review rounds kept finding bugs that only show up when two mechanisms
meet (a pending re-key and a delete, a rollback and a full resync, ...). A
test per reported scenario cannot keep up with the number of combinations,
so this one lets Hypothesis combine the operations itself and checks, after
every settle, the properties that must hold whatever happened before:

* every device ends up with the same vault, and so does a brand-new device
  connected to the account;
* every change any device made is either in the final state's history or
  was dropped by an explicit conflict decision — nothing disappears without
  a trace;
* sync settles: no unsent objects, open conflicts, pending key changes,
  pending re-keys or queued revocations are left behind, and no step raises
  an error the user has no way out of;
* every device unlocks with the account's current password;
* a team member: once revoked, holds the key of nothing live; while active,
  opens every envelope of theirs and keeps every folder shared with them.

The devices are the unmodified desktop code (Vault, SyncClient, the CLI
connect flow) against the real FastAPI app under uvicorn on loopback with
the in-memory database from test_server_spec.

Default run is derandomized and short so the suite stays fast and
deterministic. For a deep random run:

    set SEZAM_STATEFUL_EXAMPLES=300
    python -m pytest -q tests/test_sync_state_machine.py
"""

from __future__ import annotations

import asyncio
import contextlib
import copy
import hashlib
import itertools
import json
import os
import shutil
import sys
import tempfile
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import pytest
import uvicorn
from hypothesis import HealthCheck, settings
from hypothesis import event as coverage_event
from hypothesis import strategies as st
from hypothesis.stateful import (
    RuleBasedStateMachine,
    invariant,
    precondition,
    rule,
    run_state_machine_as_test,
)
from nacl.signing import SigningKey

from sezam.vault import pending_states as pending_store
from sezam import cli, teamlog
from sezam.crypto.aead import BlobKind, parse_envelope
from sezam.crypto.envelope_crypto import open_envelope
from sezam.crypto.keys import generate_keypair
from sezam.models import EntryMeta, NodeMeta, bytes_to_ulid, new_ulid
from sezam.vault import org_recovery_server, outbox, revocation, trash
from sezam.crypto.shamir import reconstruct_secret
from sezam.vault.crud import Vault
from sezam.vault.db import VaultChangedElsewhere
from sezam.vault.key_rotation import org_recovery_signing_key
from sezam.vault.pending_states import pending_states, rekey_batch
from sezam.vault.rekey_abandon import abandon_pending_rekey
from sezam.vault.sealed import open_sealed
from sezam.vault.sync_client import KeyEpochStale, SyncClient, TofuKeyChangeError
from sezam.vault.sync_common import STALE_OWN_WRAPS_META, ServerError
from tests.test_integration_client_server import PARAMS, PASSWORD
from tests.test_server_spec import MockDatabase
from tests import property_seeds
from tests import server_field_lies as field_lies
from tests.server_admin_lie import users_row_deciding
from tests.node_support import fetchable_socket, node_problem
from tests.web_tab import WebTab

NODE = node_problem() is None  # the web tab needs Node >= 24.7
WEB = "W"
DEEP = int(os.environ.get("SEZAM_STATEFUL_EXAMPLES", "0"))
MAX_DEVICES = 3
MAX_MEMBERS = 2
SETTLE_ROUNDS = 6


class _Server:
    """One uvicorn for the whole test; a fresh in-memory database per example."""

    def __init__(self, tmp: Path, wrap=None):
        """``wrap``: an ASGI wrapper around the server's app (the server
        faults of tests/test_sync_conformance.py)."""
        from server.app.config import JWTKeyManager, ServerConfig
        from server.app.main import app

        key_file = tmp / "jwt.key"
        key_file.write_bytes(bytes(SigningKey.generate()))
        self._jwt = JWTKeyManager(str(key_file))
        self._config = ServerConfig(
            jwt_expiry_seconds=3600,
            jwt_onboarding_expiry_seconds=900,
            hmac_server_secret="state-machine-server-secret",
            recovery_ip_max_failures_per_hour=10_000,
            recovery_max_total=10_000,
        )
        self._sock = fetchable_socket()  # the web client reaches it with Node's fetch
        self.url = f"http://127.0.0.1:{self._sock.getsockname()[1]}"
        asgi = wrap(app) if wrap else app
        self._uv = uvicorn.Server(uvicorn.Config(asgi, lifespan="off", ws="none", log_level="warning"))
        self._thread = threading.Thread(target=self._uv.run, kwargs={"sockets": [self._sock]}, daemon=True)
        self._thread.start()
        deadline = time.monotonic() + 10
        while not self._uv.started:
            assert time.monotonic() < deadline, "uvicorn did not start"
            time.sleep(0.02)

    def reset(self) -> MockDatabase:
        from server.app.dependencies import set_globals

        db = MockDatabase()
        asyncio.run(db.create_schema())
        set_globals(self._config, db, self._jwt)
        return db

    def close(self) -> None:
        self._uv.should_exit = True
        self._thread.join(timeout=10)
        self._sock.close()


# ── Reading a device's state ──
#
# A state is (alive, name, parent) for every folder and entry, deleted ones
# included. Every write uses a fresh name, so a name identifies the write.


def _open(vault, blob, object_id: str, version: int, kind: BlobKind, deleted: bool) -> bytes:
    blob = bytes(blob)
    dek = vault.dek_mgr.unlock_dek(bytes_to_ulid(parse_envelope(blob).dek_id))
    return open_sealed(blob, dek, object_id, version, kind, deleted=deleted)[0]


def _foreign_trees(vault, root: str | None) -> set[str]:
    """Another account's tree: the server sends every object, and a top-level
    node other than this account's root that this vault cannot open is
    someone else's (a second admin's). What of it this vault cannot open
    stays out; an unreadable item of our own is still a finding."""
    tops = set()
    for row in vault.db.fetchall(
        "SELECT id, encrypted_meta, version, is_deleted FROM nodes WHERE parent_id IS NULL AND id != ?",
        (root or "",),
    ):
        try:
            _open(vault, row["encrypted_meta"], row["id"], row["version"], BlobKind.NODE_META,
                  bool(row["is_deleted"]))
        except Exception:  # noqa: BLE001
            tops.add(row["id"])
    if not tops:
        return set()
    marks = ",".join("?" * len(tops))
    return {r["id"] for r in vault.db.fetchall(
        f"WITH RECURSIVE t(id) AS (SELECT id FROM nodes WHERE id IN ({marks}) UNION "
        "SELECT n.id FROM nodes n JOIN t ON n.parent_id = t.id) SELECT id FROM t "
        "UNION SELECT e.id FROM entries e JOIN t ON e.node_id = t.id", tuple(tops))}


def snapshot(vault) -> dict[str, tuple]:
    root = vault.db.get_meta("root_node_id")
    foreign = _foreign_trees(vault, root)
    out: dict[str, tuple] = {}
    for row in vault.db.fetchall(
        "SELECT id, parent_id, encrypted_meta, version, is_deleted FROM nodes"
    ):
        if row["id"] == root:
            continue
        try:
            name = NodeMeta.from_json(
                _open(vault, row["encrypted_meta"], row["id"], row["version"],
                      BlobKind.NODE_META, bool(row["is_deleted"]))
            ).name
        except Exception as exc:  # noqa: BLE001 — reported as a finding below
            if row["id"] in foreign:
                continue
            name = f"<unreadable: {type(exc).__name__}: {exc}>"
        parent = "ROOT" if row["parent_id"] == root else row["parent_id"]
        out[row["id"]] = (not row["is_deleted"], name, parent)
    for row in vault.db.fetchall(
        "SELECT id, node_id, encrypted_meta, version, is_deleted FROM entries"
    ):
        try:
            name = EntryMeta.from_json(
                _open(vault, row["encrypted_meta"], row["id"], row["version"],
                      BlobKind.ENTRY_META, bool(row["is_deleted"]))
            ).name
        except Exception as exc:  # noqa: BLE001
            if row["id"] in foreign:
                continue
            name = f"<unreadable: {type(exc).__name__}: {exc}>"
        parent = "ROOT" if row["node_id"] == root else row["node_id"]
        out[row["id"]] = (not row["is_deleted"], name, parent)
    return out


def _live(snap: dict[str, tuple]) -> dict[str, tuple]:
    return {obj: state for obj, state in snap.items() if state[0]}


def _as_bytes(value) -> bytes | None:
    if value is None:
        return None
    return bytes.fromhex(value) if isinstance(value, str) else bytes(value)


def _dirty_ids(vault) -> set[str]:
    rows = vault.db.fetchall(
        "SELECT id FROM nodes WHERE id IN (SELECT object_id FROM outbox WHERE kind = 'write') UNION SELECT id FROM entries WHERE id IN (SELECT object_id FROM outbox WHERE kind = 'write')"
    )
    return {row["id"] for row in rows}


@dataclass
class Event:
    id: int
    obj: str
    state: tuple
    device: str
    known: frozenset  # every event this write was made with knowledge of
    kind: str  # "write", "auto" (changed by sync itself), "genesis"


@dataclass
class Device:
    name: str
    vault: object
    client: object
    password: str  # what this device's vault unlocks with
    # Like the CLI: every command builds its own SyncClient, so nothing a
    # previous command kept in memory (pull etag, push cache, GC floor, the
    # audit verification point) carries over. A keeps one, like the GUI.
    per_command: bool = False


@dataclass
class Member:
    """A second user of the server: their keys (what they can open is checked
    from the server) and their own desktop vault, which syncs what is shared."""
    name: str
    user_id: str
    encryption_sk: bytes
    vault: object = None


class Injected(RuntimeError):
    pass


# revocation._push_grant: the envelope stays queued locally after a failed push.
_GRANT_DEFERRED = "it goes with the next push"


@contextlib.contextmanager
def _withholding_rekey_archives():
    """The server leaves re-key archives out of every pull while active. The
    override lives on SyncClient only for the duration; afterwards the method
    is again the one PullMixin defines (a leftover copy on SyncClient would
    shadow later fixes and break test_every_method_is_defined_once)."""
    order = SyncClient._order_pulled_objects
    SyncClient._order_pulled_objects = staticmethod(
        lambda objects: [o for o in order(objects) if o.get("object_type") != "dek_archive"])
    try:
        yield
    finally:
        del SyncClient._order_pulled_objects


def _fail_once(client, method: str, path_prefix: str, mode: str):
    """Make the next matching request fail before it is sent or after the
    server processed it (the reply is lost)."""
    real = client._request
    fired = {"done": False}

    def request(m, path, *args, **kwargs):
        if not fired["done"] and m == method and path.startswith(path_prefix):
            fired["done"] = True
            if mode == "before":
                raise Injected("network down (injected)")
            fired["reply"] = real(m, path, *args, **kwargs)
            raise Injected("reply lost (injected)")
        return real(m, path, *args, **kwargs)

    client._request = request
    undo = lambda: setattr(client, "_request", real)  # noqa: E731
    undo.fired = fired
    return undo


def _tamper_once(client, method: str, path_prefix: str, mutate, every: bool = False):
    """A malicious server: the next matching reply (or ``every`` one) is
    changed by ``mutate``."""
    real = client._request
    fired = {"done": False}

    def request(m, path, *args, **kwargs):
        reply = real(m, path, *args, **kwargs)
        if (every or not fired["done"]) and m == method and path.startswith(path_prefix) \
                and reply is not None:
            fired["done"] = True
            reply = mutate(copy.deepcopy(reply))
        return reply

    client._request = request
    undo = lambda: setattr(client, "_request", real)  # noqa: E731
    undo.fired = fired
    return undo


# What a lying server may make a client do: refuse. A crash type means the
# client was not ready for the lie.
LIES = ["replay", "replay_envelope", "epoch_up", "epoch_down", "scope", "dek_order", "weak_kdf", "access_up",
        "gc_floor"]
REFUSALS = (RuntimeError, ValueError, KeyEpochStale)


def _injected(exc: BaseException) -> bool:
    while exc is not None:
        if isinstance(exc, Injected):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


class SyncMachine(RuleBasedStateMachine):
    server: _Server  # set by the test
    # Pending states that warn but hold nothing back: a settle does not wait on them.
    ADVISORY: frozenset[str] = frozenset()

    def _waiting_members(self) -> set[str]:
        return set()

    def __init__(self):
        super().__init__()
        self.tmp = Path(tempfile.mkdtemp(prefix="sezam_sm_"))
        self.db = self.server.reset()
        self.url = self.server.url
        self.tokens = itertools.count(1)
        self.devices: dict[str, Device] = {}
        # The field the server lies in right now (server_lies_in_a_field).
        self.field_lie: str | None = None
        self.events: dict[int, Event] = {}
        self.producers: dict[tuple, set[int]] = defaultdict(set)
        self.names: dict[str, set[str]] = defaultdict(set)
        self.knowledge: dict[str, set[int]] = {}
        self.server_known: dict[str, set[int]] = {}
        # Writes no send of their device took yet (_closure(sent_only=True)).
        self.unsent: set[int] = set()
        self.traced: set[int] = set()
        # Objects tombstone GC removed from the server -> the events their
        # tombstone was written with knowledge of.
        self.collected: dict[str, set[int]] = {}
        # A server backup: (storage, server_known) at that moment.
        self.backup: tuple | None = None
        # Devices whose pull said only a full resync gets them going again.
        self.resync_due: set[str] = set()
        # Account salt -> the password it was made for (a password change
        # draws a new salt), so the server's current salt names the password
        # the user knows the account by now.
        self.salt_password: dict[str, str] = {}
        self.members: dict[str, Member] = {}
        # Accounts the malicious server activated itself -> the DEK they forged an envelope on.
        self.made_up: dict[str, str] = {}
        # Folders such an account wrote below the admin's root or an unknown parent.
        self.forged_by_made_up: set[str] = set()
        # member -> every DEK id the server ever held an envelope of theirs for.
        self.member_deks: dict[str, set[str]] = defaultdict(set)
        # member -> folders a grant to them succeeded for.
        self.granted: dict[str, set[str]] = defaultdict(set)
        self.write_granted: dict[str, set[str]] = defaultdict(set)
        self.revoked: set[str] = set()
        # Members the operator made admins.
        self.admins: set[str] = set()
        # Every encryption key the account ever had (envelopes are sealed by it).
        self.admin_pks: set[bytes] = set()
        # Org recovery (Shamir) set up on one device: (device, shares, the
        # signing key the server checks the recovery's reset proof against).
        self.org: tuple[str, list, str | None] | None = None
        # Signing keys an identity rotation retired: (user id, key) - what a
        # server holding one can sign (goal #443).
        self.leaked_signers: list[tuple[str, SigningKey]] = []
        # The web client: one open tab (or None), the browser profile it
        # leaves for the next tab, what the page shows, and whether its
        # session ended (a new tab must sign in again).
        self.web: WebTab | None = None
        self.web_idb: dict | None = None
        self.web_view: dict = {}
        self.web_ended = False
        self.web_password: str | None = None  # what the tab last signed in with
        self.log: list[str] = []
        # Every object a pull ever received: id -> version -> wire object,
        # what a malicious server can replay (validly signed, just old).
        self.wire: dict[str, dict[int, dict]] = defaultdict(dict)
        # device -> a second process unlocked on its vault (GUI / mcp-serve).
        self.second: dict[str, Vault] = {}
        for name in ("A", "B"):
            self._add_device(name)
        # A small shared tree, so that most steps touch objects both devices
        # hold (that is where the combinations are).
        top = self._token("F")
        self._local("A", f"create folder {top}", lambda v: v.create_node(top))
        top_id = self._folders("A")[0]
        sub = self._token("F")
        self._local("A", f"create folder {sub} under {top_id}", lambda v: v.create_node(sub, top_id))
        sub_id = next(f for f in self._folders("A") if f != top_id)
        for folder in (top_id, top_id, sub_id):
            name = self._token("E")
            self._local("A", f"create entry {name} in {folder}", lambda v, f=folder, n=name: v.create_entry(
                f, n, [{"key": "password", "value": n, "sensitive": True}]
            ))
        self._settle(lambda _obj: "server")
        self._invite_member("A")

    def teardown(self):
        try:
            if self.devices:
                self._settle(lambda _obj: "server")
                self._check_new_device_matches()
                self._withhold_archives_from_a_new_device()
        finally:
            if self.web is not None:
                self.web.kill()
            for vault in [d.vault for d in self.devices.values()] + list(self.second.values()) + [
                m.vault for m in self.members.values() if m.vault is not None
            ]:
                with contextlib.suppress(Exception):
                    vault.lock()
            shutil.rmtree(self.tmp, ignore_errors=True)

    # ── model bookkeeping ──

    def _token(self, prefix: str) -> str:
        return f"{prefix}{next(self.tokens)}"

    def _closure(self, obj: str, state: tuple | None, sent_only: bool = False) -> set[int]:
        """What a copy of ``obj`` in ``state`` was written knowing.

        ``sent_only``: the server's copy. Stateful test SM23a: A moved an
        entry away and on into the folder C had just moved it to, kept the
        server copy of the conflict, and C edited it on. A's unsent move had
        C's state, so the server copy counted A's first move as kept and C's
        edit looked like it lost that move without a conflict. A write no send
        took is not what the server's copy was made from (unless only such
        writes made that state: then it got there in a way not modelled).
        """
        known: set[int] = set()
        states = [state]
        if state and state[0]:
            # The sync code brings a folder back from its tombstone (unsent
            # work below it): the live copy is what the deleting device wrote.
            states.append((False, *state[1:]))
        for each in states:
            producers = self.producers.get((obj, each), set())
            if sent_only and producers - self.unsent:
                producers = producers - self.unsent
            for event_id in producers:
                known |= self.events[event_id].known
        return known

    def _sent(self, device: str, obj: str) -> None:
        """A send of ``device`` took its copy of ``obj``: its writes are out."""
        self.unsent -= {e for e in self.unsent if self.events[e].device == device and self.events[e].obj == obj}

    def _kept_server_copy(self, obj: str, state: tuple | None) -> set[int]:
        """What keeping the server copy of a conflict kept.

        Nightly second-admin run on c78fd19: a move away and back here
        equalled the server copy by state, not by history, and counted as
        kept; it was dropped with the conflict. The server copy carries what
        the server knew, not this device's writes it never got.
        """
        kept = self._closure(obj, state)
        if obj in self.server_known:
            kept &= self.server_known[obj]
        return kept

    def _event(self, device: str, obj: str, state: tuple, kind: str, extra=()) -> None:
        event_id = len(self.events) + 1
        known = frozenset(self.knowledge[device] | set(extra) | {event_id})
        self.events[event_id] = Event(event_id, obj, state, device, known, kind)
        self.producers[(obj, state)].add(event_id)
        self.names[obj].add(state[1])
        self.knowledge[device].add(event_id)
        if kind == "write":
            self.unsent.add(event_id)

    def _record_local_change(self, device: str, before: dict, after: dict) -> None:
        for obj, state in after.items():
            if before.get(obj) != state:
                self._event(device, obj, state, "write")

    def _observe(self, device: str) -> dict:
        """After a sync step: learn what the device now holds."""
        return self._learn(device, snapshot(self.devices[device].vault))

    def _learn(self, device: str, snap: dict) -> dict:
        known = self.knowledge[device]
        dev = self.devices.get(device)
        for obj, state in snap.items():
            if state[1].startswith("<unreadable") and dev is not None and \
                    dev.vault.db.get_meta_json(STALE_OWN_WRAPS_META):
                # Holds a key of its own in an older copy (a lying full
                # resync): it says so and pulls stop until a full resync.
                self.resync_due.add(device)
                continue
            assert not state[1].startswith("<unreadable"), (
                f"{device}: {obj} cannot be decrypted ({state[1]})\n" + self._trace()
            )
            if (obj, state) in self.producers:
                known |= self._closure(obj, state)
                continue
            # The sync code itself changed the object (e.g. brought a folder
            # back for an entry saved in it offline). Its content must still
            # be something a device wrote.
            assert state[1] in self.names[obj], (
                f"{device}: {obj} holds {state!r}, which no device ever wrote\n" + self._trace()
            )
            self._event(device, obj, state, "auto", self.server_known.get(obj, ()))
        return snap

    def _trace(self) -> str:
        return "steps:\n  " + "\n  ".join(self.log[-int(os.environ.get("SEZAM_SM_TRACE", "60")):])

    def _account_password(self) -> str:
        users = [u for u in self.db._storage.get("users", []) if u.get("username") == "admin"]
        if not users or not users[0].get("argon2_salt"):
            return PASSWORD
        return self.salt_password.get(bytes(users[0]["argon2_salt"]).hex(), PASSWORD)

    def _new_vault(self, path: Path) -> Vault:
        password = self._account_password()
        vault = Vault.create(path, password, PARAMS)
        vault.db.set_meta("username", "admin")
        cli._server_connect_flow(self.url, vault, password)
        assert vault.db.get_meta("server_url") == self.url, f"{path.name} did not connect"
        return vault

    def _new_client(self, vault) -> SyncClient:
        client = SyncClient(vault.db, self.url, vault.keypair, vault.db.get_meta("user_id"))
        client.set_dek_manager(vault.dek_mgr)
        real = client._request

        def recording(m, path, *args, **kwargs):
            reply = real(m, path, *args, **kwargs)
            if m == "GET" and path.startswith("/api/sync") and isinstance(reply, dict):
                for obj in reply.get("objects") or []:
                    if isinstance(obj.get("version"), int):
                        self.wire[obj["id"]].setdefault(obj["version"], copy.deepcopy(obj))
            return reply

        client._request = recording
        return client

    def _add_device(self, name: str) -> None:
        self.knowledge[name] = set()
        password = self._account_password()
        vault = Vault.create(self.tmp / name, password, PARAMS)
        vault.db.set_meta("username", "admin")
        for obj, state in snapshot(vault).items():
            self._event(name, obj, state, "genesis")
        cli._server_connect_flow(self.url, vault, password)
        assert vault.db.get_meta("server_url") == self.url, f"{name} did not connect"
        self.devices[name] = Device(name, vault, self._new_client(vault), password, per_command=name != "A")
        self.log.append(f"{name}: connect")
        self._observe(name)

    def _pick(self, data, items, label):
        items = sorted(items)
        if not items:
            return None
        return data.draw(st.sampled_from(items), label=label)

    def _folders(self, device: str) -> list[str]:
        # A second admin's tree reaches this vault too; no client offers it.
        vault = self.devices[device].vault
        foreign = _foreign_trees(vault, vault.db.get_meta("root_node_id"))
        return [row["id"] for row in vault.db.fetchall("SELECT id, parent_id FROM nodes WHERE is_deleted = 0")
                if row["parent_id"] is not None and row["id"] not in foreign]

    def _entries(self, device: str, deleted: bool = False) -> list[str]:
        vault = self.devices[device].vault
        foreign = _foreign_trees(vault, vault.db.get_meta("root_node_id"))
        return [row["id"] for row in vault.db.fetchall(
            "SELECT id FROM entries WHERE is_deleted = ?", (1 if deleted else 0,)
        ) if row["id"] not in foreign]

    def _device(self, data) -> str:
        return data.draw(st.sampled_from(sorted(self.devices)), label="device")

    def _local(self, device: str, label: str, action) -> None:
        vault = self.devices[device].vault
        before = snapshot(vault)
        try:
            action(vault)
        except RuntimeError as exc:
            # R16-Z SM23c: a team write on a device holding the log's pin but
            # not the log yet is refused (INV-5); the way out is a pull (INV-7).
            if "not downloaded yet; pull it first" not in str(exc) or snapshot(vault) != before:
                raise
            self.log.append(f"{device}: {label} -> refused until a pull")
            return
        self.log.append(f"{device}: {label}")
        self._record_local_change(device, before, snapshot(vault))

    # ── local edits ──

    @rule(data=st.data())
    def create_folder(self, data):
        device = self._device(data)
        parent = self._pick(data, self._folders(device) + ["ROOT"], "parent")
        name = self._token("F")
        self._local(device, f"create folder {name} under {parent}",
                    lambda v: v.create_node(name, None if parent == "ROOT" else parent))

    @rule(data=st.data())
    def create_entry(self, data):
        device = self._device(data)
        folder = self._pick(data, self._folders(device), "folder")
        if folder is None:
            return
        name = self._token("E")
        self._local(device, f"create entry {name} in {folder}", lambda v: v.create_entry(
            folder, name, [{"key": "password", "value": name, "sensitive": True}]
        ))

    @rule(data=st.data())
    def edit_entry(self, data):
        device = self._device(data)
        entry = self._pick(data, self._entries(device), "entry")
        if entry is None:
            return
        name = self._token("E")
        self._local(device, f"edit entry {entry} -> {name}", lambda v: v.update_entry(
            entry, name=name, fields=[{"key": "password", "value": name, "sensitive": True}]
        ))

    @rule(data=st.data())
    def rename_folder(self, data):
        device = self._device(data)
        folder = self._pick(data, self._folders(device), "folder")
        if folder is None:
            return
        name = self._token("F")
        self._local(device, f"rename folder {folder} -> {name}", lambda v: v.rename_node(folder, name))

    @rule(data=st.data())
    def move_entry(self, data):
        device = self._device(data)
        entry = self._pick(data, self._entries(device), "entry")
        if entry is None:
            return
        self._change(device, entry, "move", data)

    @rule(data=st.data())
    def delete_entry(self, data):
        device = self._device(data)
        entry = self._pick(data, self._entries(device), "entry")
        if entry is None:
            return
        self._local(device, f"delete entry {entry}", lambda v: v.delete_entry(entry))

    @rule(data=st.data())
    def delete_folder(self, data):
        device = self._device(data)
        folder = self._pick(data, self._folders(device), "folder")
        if folder is None:
            return
        self._local(device, f"delete folder {folder}", lambda v: v.delete_node(folder))

    @rule(data=st.data())
    def restore_from_trash(self, data):
        device = self._device(data)
        items = trash.list_trash(self.devices[device].vault)
        if not items:
            return
        item = data.draw(st.sampled_from(items), label="trash item")
        restore = trash.restore_node if item["type"] == "folder" else trash.restore_entry
        self._local(device, f"restore {item['type']} {item['id']}", lambda v: restore(v, item["id"]))

    ENTRY_OPS = ("edit", "delete", "move")
    FOLDER_OPS = ("rename", "delete", "add entry", "add folder", "move")

    def _change(self, device: str, obj: str, op: str, data) -> None:
        vault = self.devices[device].vault
        is_entry = vault.db.fetchone("SELECT 1 FROM entries WHERE id = ?", (obj,)) is not None
        if op == "edit":
            name = self._token("E")
            action = lambda v: v.update_entry(  # noqa: E731
                obj, name=name, fields=[{"key": "password", "value": name, "sensitive": True}]
            )
        elif op == "rename":
            name = self._token("F")
            action = lambda v: v.rename_node(obj, name)  # noqa: E731
        elif op == "delete":
            action = (lambda v: v.delete_entry(obj)) if is_entry else (lambda v: v.delete_node(obj))
        elif op == "add entry":
            name = self._token("E")
            action = lambda v: v.create_entry(  # noqa: E731
                obj, name, [{"key": "password", "value": name, "sensitive": True}]
            )
        elif op == "add folder":
            name = self._token("F")
            action = lambda v: v.create_node(name, obj)  # noqa: E731
        else:  # move
            current = snapshot(vault)[obj][2]
            if is_entry:
                target = self._pick(data, [f for f in self._folders(device) if f != current], "target")
                if target is None:
                    return
                action = lambda v: v.move_entry(obj, target)  # noqa: E731
            else:
                below = self._subtree(device, obj)
                targets = [f for f in self._folders(device) + ["ROOT"] if f not in below and f != current]
                target = self._pick(data, targets, "target")
                if target is None:
                    return
                root = vault.db.get_meta("root_node_id")
                action = lambda v: v.move_node(obj, root if target == "ROOT" else target)  # noqa: E731
        self._local(device, f"{op} {obj}", action)

    def _subtree(self, device: str, node_id: str) -> set[str]:
        rows = self.devices[device].vault.db.fetchall(
            "WITH RECURSIVE s(id) AS (SELECT ? UNION ALL "
            "SELECT nodes.id FROM nodes JOIN s ON nodes.parent_id = s.id) SELECT id FROM s",
            (node_id,),
        )
        return {row["id"] for row in rows}

    @precondition(lambda self: len(self.devices) >= 2)
    @rule(data=st.data(), push_first=st.booleans())
    def concurrent_change(self, data, push_first):
        """Two devices change the same object before either has seen the other."""
        first, second = data.draw(
            st.lists(st.sampled_from(sorted(self.devices)), min_size=2, max_size=2, unique=True),
            label="devices",
        )
        shared = sorted(
            obj for obj in set(self._folders(first) + self._entries(first))
            & set(self._folders(second) + self._entries(second))
        )
        if not shared:
            return
        obj = data.draw(st.sampled_from(shared), label="object")
        is_entry = obj in self._entries(first)
        ops = self.ENTRY_OPS if is_entry else self.FOLDER_OPS
        for device in (first, second):
            if obj not in (self._entries(device) if is_entry else self._folders(device)):
                continue  # a folder delete on this device took it already
            self._change(device, obj, data.draw(st.sampled_from(ops), label=f"{device} op"), data)
            if push_first and device == first:
                self._push(first)

    # ── sync ──

    def _take_over_account_keys(self, device: str, abandon: bool) -> None:
        """The way out the device offers: the user types the account password."""
        dev = self.devices[device]
        password = self._account_password()
        journal = pending_store.key_change_journal(dev.vault.db)
        if abandon and "recovery_secret" in journal:
            raise AssertionError(
                f"{device}: an org recovery could only be abandoned with the password "
                "the user forgot\n" + self._trace()
            )
        try:
            if abandon:
                dev.client.abandon_pending_change(dev.vault, password)
            else:
                dev.client.adopt_rotated_key_material(dev.vault, password)
        except Exception as exc:
            what = "abandon its pending change" if abandon else "take the key change over"
            self.log.append(f"{device}: {what} raised {type(exc).__name__}: {exc}")
            if self.field_lie is not None and isinstance(exc, REFUSALS):
                # The server lies in a field the key change is read from (e.g. a
                # damaged RecoverResponse.encrypted_keypair): refusing is the
                # right answer; the next call without the lie takes it over.
                raise
            raise AssertionError(
                f"{device}: cannot {what} with the account password: {exc!r}\n" + self._trace()
            ) from exc
        dev.password = password
        self.log.append(f"{device}: {'abandoned own change, ' if abandon else ''}"
                        f"took the account keys over ({password})")

    def _command(self, device: str):
        """A new command on the device: the CLI-like ones start a new client."""
        dev = self.devices[device]
        if dev.per_command:
            dev.client = self._new_client(dev.vault)
        return dev

    def _call(self, device: str, method: str, **kwargs):
        """A sync call; a key change made elsewhere is taken over first."""
        for attempt in range(3):
            client = self.devices[device].client
            if method == "push":
                # What 'sezam push' does: it also finishes queued revocations.
                vault = self.devices[device].vault
                call = lambda: revocation.push_with_queued_revocations(vault, client)  # noqa: E731
            else:
                call = lambda: getattr(client, method)(**kwargs)  # noqa: E731
            try:
                return call()
            except KeyEpochStale:
                if attempt == 2:
                    raise
                self.log.append(f"{device}: {method} says the account keys changed")
                self._take_over_account_keys(device, abandon=False)
            except RuntimeError as exc:
                if attempt == 2 or "abandon-pending-change" not in str(exc):
                    raise
                self.log.append(f"{device}: {method} refused the pending change: {exc}")
                self._take_over_account_keys(device, abandon=True)

    def _push(self, device: str, failure: str | None = None) -> None:
        dev = self._command(device)
        before = _dirty_ids(dev.vault)
        undo = _fail_once(dev.client, "POST", "/api/sync", failure) if failure else None
        try:
            result = self._call(device, "push")
            errors = sorted({c.get("error") for c in result.get("conflicts") or [] if c.get("error")})
            self.log.append(f"{device}: push -> accepted {len(result.get('accepted') or [])}, "
                            f"conflicts {len(result.get('conflicts') or [])}"
                            + (f" {errors}" if errors else "")
                            + (" ROLLBACK WARNING" if result.get("rollback_warning") else ""))
            if result.get("rollback_warning"):
                self.resync_due.add(device)
            if result.get("rekey_waits"):
                # R16-Z SM26c: the log moved a folder of the batch on to a key
                # the server lost; it waits for the device holding that key.
                # Without one it is stuck for good.
                key = result["rekey_waits"]["dek_id"]
                holders = [name for name, other in self.devices.items() if name != device
                           and other.vault.db.fetchone("SELECT 1 FROM deks WHERE id = ?", (key,))]
                assert holders, f"{device}: the re-key waits for key {key}, which no device holds\n" + self._trace()
                coverage_event("a re-key waits for the folder key a sibling holds")
                self.log.append(f"{device}: the re-key waits for {holders[0]}'s folder key {key}")
        except Exception as exc:
            if not (failure and _injected(exc)):
                if "full resync" in str(exc) or "full-resync" in str(exc):
                    # A push that pulls first (a pending re-key rebases on
                    # what the server holds) meets the same 410 as a pull.
                    self.log.append(f"{device}: push wants a full resync: {exc}")
                    self.resync_due.add(device)
                    return
                if self._recovery_lost_by_restore(device, exc):
                    # The documented way out (pending_states): another admin's
                    # 'sezam allow-key-reset', then the push goes through.
                    coverage_event("org recovery lost by a restore: key reset")
                    if self._second_admins():
                        # 'sezam allow-key-reset' on the second admin's desktop.
                        coverage_event("second admin allows a key reset")
                        admin = self.members[self._second_admins()[0]]
                        self._new_client(admin.vault).allow_key_reset(self._admin_user_id())
                    else:  # an admin the machine does not model
                        for user in self.db._storage.get("users", []):
                            if user.get("username") == "admin":
                                user["key_reset_until"] = int(time.time() * 1000) + 600_000
                    self.log.append(f"{device}: the server lost its org recovery; "
                                    "another admin allowed a key reset")
                    return self._push(device)
                if self._waits_for_sibling_rotation(device, exc):
                    return
                if self._waits_for_lost_log(device, exc):
                    self._note_pushed(device, before)
                    return
                self.log.append(f"{device}: push raised {type(exc).__name__}: {exc}")
                raise AssertionError(f"{device}: push raised {exc!r}\n" + self._trace()) from exc
            self.log.append(f"{device}: push failed ({failure})")
        else:
            # What 'sezam push' does next while it can ask for the password:
            # register a saved org recovery, or say the server lacks one.
            notice = org_recovery_server.register_while_password_known(dev.vault, dev.password)
            if notice:
                self.log.append(f"{device}: push says: {notice}")
        finally:
            if undo:
                undo()
        self._note_pushed(device, before, undo)

    def _recovery_lost_by_restore(self, device: str, exc: Exception) -> bool:
        """A password reset by org recovery the server can no longer check:
        it was restored from a backup taken before the recovery was set up.
        A lone admin cannot get out of this alone (review e4cd15a #1)."""
        journal = pending_store.key_change_journal(self.devices[device].vault.db)
        return (
            "Replacing the key material needs" in str(exc)
            and "recovery_secret" in journal
            and not self._org_recovery_usable()
        )

    def _rotation_the_log_waits_for(self, skip: str | None = None) -> str | None:
        """The admin device holding an identity rotation of the account that
        the server lost (restored from a backup), named by that device's copy
        of the log or still pending there, while the server signs the account
        in with another key (review e443cbc R15, #429: a backup from before
        two rotations came back). Until that device puts the log back and its
        rotation goes out again, the account's other devices are refused as
        retired and members cannot check the account's objects signed before
        it; they wait, fail-closed."""
        from sezam.vault.team_log_local import TeamLogMismatch

        user_id = self.devices["A"].vault.db.get_meta("user_id")
        account = next((u for u in self.db._storage.get("users", []) if u.get("id") == user_id), None)
        if account is None:
            return None
        server_key = bytes(account.get("signing_pk") or b"").hex()
        for name, dev in sorted(self.devices.items()):
            if name == skip:
                continue
            held = dev.vault.keypair.signing_pk.hex()
            if held == server_key:
                continue
            journal = dev.client._pending_identity()
            if journal is not None and journal["identity"].get("new_signing_pk") == held:
                return name
            try:
                state = dev.client.team_state()
            except TeamLogMismatch:
                continue
            member = state.members.get(user_id) if state is not None else None
            if member is not None and member.active and member.signing_pk == held:
                return name
        return None

    def _waits_for_sibling_rotation(self, device: str, exc: Exception) -> bool:
        """The server refuses this device's key as retired by the log while a
        sibling holds the rotation the log waits for. Without such a sibling
        the refusal is a lock-out."""
        if not isinstance(exc, ServerError) or "identity_key_retired" not in str(exc):
            return False
        sibling = self._rotation_the_log_waits_for(skip=device)
        if sibling is None:
            return False
        coverage_event("a device waits for a sibling's rotation the log names")
        self.log.append(f"{device}: waits for {sibling}'s identity rotation (key retired by the log)")
        return True

    def _waits_for_lost_log(self, device: str, exc: Exception) -> bool:
        """Only a machine with a team log has one the server can lose."""
        return False

    def _note_pushed(self, device: str, before: set[str], undo=None) -> None:
        """After a step that pushed: what the server holds now."""
        dev = self.devices[device]
        snap = self._observe(device)
        # A lost reply: the server took these, the device does not know it yet.
        landed = {a["id"] for a in ((undo.fired.get("reply") or {}).get("accepted") or [])} if undo else set()
        for obj in (before - _dirty_ids(dev.vault)) | (landed & before):
            if obj in snap:
                self._sent(device, obj)
                self.server_known[obj] = self._closure(obj, snap[obj], sent_only=True)

    def _pull(self, device: str, failure: str | None = None) -> None:
        dev = self._command(device)
        undo = _fail_once(dev.client, "GET", "/api/sync", failure) if failure else None
        try:
            result = self._call(device, "pull")
            self.log.append(f"{device}: pull -> {result.get('pulled')}"
                            + (" ROLLBACK WARNING" if result.get("rollback_warning") else ""))
        except Exception as exc:
            if not (failure and _injected(exc)):
                if "full resync" in str(exc) or "full-resync" in str(exc):
                    # 410 after GC or a server seen going back: the way out
                    # the user is told about is a full resync.
                    self.log.append(f"{device}: pull wants a full resync: {exc}")
                    self.resync_due.add(device)
                    return
                if self._waits_for_sibling_rotation(device, exc) or self._waits_for_lost_log(device, exc):
                    return
                self.log.append(f"{device}: pull raised {type(exc).__name__}: {exc}")
                raise AssertionError(f"{device}: pull raised {exc!r}\n" + self._trace()) from exc
            self.log.append(f"{device}: pull failed ({failure})")
            return
        finally:
            if undo:
                undo()
        snap = self._observe(device)
        if result.get("rollback_warning"):
            self.resync_due.add(device)
            return
        dirty = _dirty_ids(dev.vault)
        conflicts = {c["id"] for c in dev.client.get_pull_conflicts()}
        for obj, state in snap.items():
            if obj not in dirty and obj not in conflicts:
                self.server_known[obj] = self._closure(obj, state, sent_only=True)

    def _resolve(self, device: str, obj: str, keep: str) -> None:
        dev = self._command(device)
        known_before = set(self.knowledge[device])
        before = snapshot(dev.vault)
        pending = pending_store.rekey_batch(dev.vault.db)
        if obj in pending.get("object_ids", []):
            # Refused by design ("push it first, or drop the re-key"); settle
            # pushes first and checks the re-key ends and the conflict goes.
            with pytest.raises(RuntimeError, match="pending re-key"):
                dev.client.resolve_conflict(obj, keep)
            coverage_event("resolve refused during pending re-key")
            self.log.append(f"{device}: resolve {obj} refused (pending re-key)")
            return
        dev.client.resolve_conflict(obj, keep)
        self.log.append(f"{device}: resolve {obj} keep {keep}")
        if keep == "server":
            after = self._observe(device)
            lost = {e for e in known_before if self.events[e].obj == obj}
            self.traced |= lost - self._kept_server_copy(obj, after.get(obj))
        else:
            server = self.server_known.get(obj, set())
            self.traced |= {e for e in server if self.events[e].obj == obj} - known_before
            self.knowledge[device] |= server
            after = snapshot(dev.vault)
            self._event(device, obj, after[obj], "write")
            for other, state in after.items():
                if other != obj and before.get(other) != state:
                    self._event(device, other, state, "write")

    @rule(data=st.data(), failure=st.sampled_from([None, None, "before", "after"]))
    def push(self, data, failure):
        self._push(self._device(data), failure)

    @rule(data=st.data(), failure=st.sampled_from([None, None, "after"]))
    def pull(self, data, failure):
        self._pull(self._device(data), failure)

    @rule(data=st.data())
    def resolve_conflicts(self, data):
        device = self._device(data)
        for conflict in self.devices[device].client.get_pull_conflicts():
            keep = data.draw(st.sampled_from(["local", "server"]), label="keep")
            self._resolve(device, conflict["id"], keep)

    @rule(data=st.data())
    def full_resync(self, data):
        self._full_resync(self._device(data))

    def _full_resync(self, device: str, lie=None) -> bool | None:
        """``lie`` changes every page the server answers the resync with."""
        client = self._command(device).client
        blocker = client.full_resync_blocker()
        if blocker and device in self.resync_due and "abandon-rekey" in blocker:
            # The pending re-key cannot go out (its rebase needs the pull that
            # wants the full resync): the way out the message names.
            self.log.append(f"{device}: full resync refused: {blocker}")
            self.log.append(f"{device}: abandon re-key -> {abandon_pending_rekey(client)}")
            blocker = client.full_resync_blocker()
        if blocker:
            self.log.append(f"{device}: full resync refused: {blocker}")
            return
        # A full resync keeps unsent work, except an unsent delete of something
        # the server does not have (review d150605 #6): that delete is gone.
        on_server = {obj["id"] for obj in self.db._storage["vault_objects"]}
        vault = self.devices[device].vault
        for table in ("nodes", "entries"):
            for row in vault.db.fetchall(
                f"SELECT id FROM {table} WHERE is_deleted = 1 AND id IN (SELECT object_id FROM outbox WHERE kind = 'write')"
            ):
                if row["id"] not in on_server:
                    self.collected.setdefault(row["id"], set())
        undo = _tamper_once(client, "GET", "/api/sync", lie, every=True) if lie else None
        try:
            self._call(device, "full_resync", confirmed=True)
        except REFUSALS as exc:
            if lie is None and self._waits_for_lost_log(device, exc):
                return None
            if lie is None:
                self.log.append(f"{device}: full resync raised {type(exc).__name__}: {exc}")
                raise AssertionError(f"{device}: full resync raised {exc!r}\n" + self._trace()) from exc
            # A lying server may make the resync refuse; it is rolled back and
            # stays due (the caller checks the lie changed something).
            self.log.append(f"{device}: full resync refused the lie: {exc}")
            return False
        except Exception as exc:
            self.log.append(f"{device}: full resync raised {type(exc).__name__}: {exc}")
            raise AssertionError(f"{device}: full resync raised {exc!r}\n" + self._trace()) from exc
        finally:
            if undo:
                undo()
        self.log.append(f"{device}: full resync")
        self.resync_due.discard(device)
        self._observe(device)
        return True

    # ── keys: password change and identity rotation ──

    def _key_change(self, device: str, rotate: bool, failure: str | None) -> None:
        """What 'sezam change-password' / 'sezam rotate-identity' do."""
        dev = self._command(device)
        what = "rotate identity" if rotate else "change password"
        new = dev.password if rotate else self._token("pw-") + "-Sezam!"
        try:
            dev.client.prepare_key_change()
        except RuntimeError as exc:
            # The CLI stops here ("password was not changed"); the next sync
            # shows the user the way on.
            self.log.append(f"{device}: {what} not started, sync failed: {exc}")
            if "full-resync" in str(exc):
                self.resync_due.add(device)
            # Its pull may have run before the failure: what the device now
            # holds is known to its next writes.
            self._observe(device)
            return
        self._observe(device)
        old_signer = SigningKey(bytes(dev.vault.keypair.to_nacl_signing_key()))
        try:
            proof = dev.vault.change_password(dev.password, new, rotate_identity=rotate)
        except (ValueError, RuntimeError) as exc:
            self.log.append(f"{device}: {what} refused: {exc}")
            return
        if rotate:
            self.leaked_signers.append((dev.vault.db.get_meta("user_id"), old_signer))
        proof[:] = b"\x00" * len(proof)
        self.salt_password[dev.vault.db.get_meta("argon2_salt")] = new
        dev.password = new
        # The keypair may be new; the CLI builds its client after the change.
        dev.client = self._new_client(dev.vault)
        self.log.append(f"{device}: {what}" + ("" if rotate else f" -> {new}"))
        self._push(device, failure)

    @rule(data=st.data(), failure=st.sampled_from([None, None, "before", "after"]))
    def change_password(self, data, failure):
        self._key_change(self._device(data), False, failure)

    @rule(data=st.data(), failure=st.sampled_from([None, None, "before", "after"]))
    def rotate_identity(self, data, failure):
        self._key_change(self._device(data), True, failure)

    # ── teams: a second user, shared folders, revocation and its re-key ──

    def _invite_member(self, device: str) -> None:
        """'sezam invite' on an admin device, the member registers, the admin approves."""
        name = self._token("m")
        invitation = self._call(device, "create_invitation")
        vault = Vault.create(self.tmp / f"member_{name}", PASSWORD, PARAMS)
        vault.db.set_meta("username", name)
        poll = cli._poll_for_approval
        cli._poll_for_approval = lambda *a, **k: None
        try:
            cli._server_register_and_upload(
                self.url, vault, PASSWORD, is_bootstrap=False,
                invitation_token=invitation["invitation_token"],
            )
        finally:
            cli._poll_for_approval = poll
        user_id = vault.db.get_meta("user_id")
        self.members[user_id] = Member(name, user_id, bytes(vault.keypair.encryption_sk), vault)
        self.knowledge[name] = set()
        self._call(device, "approve_user", user_id=user_id)
        self.log.append(f"{device}: invite member {name} ({user_id}), approved")

    def _member_status(self, user_id: str) -> str | None:
        return next(
            (u.get("status") for u in self.db._storage.get("users", []) if u.get("id") == user_id), None
        )

    def _active_members(self) -> list[str]:
        return [u for u in sorted(self.members) if self._member_status(u) == "active"]

    @precondition(lambda self: len(self.members) < MAX_MEMBERS)
    @rule(data=st.data())
    def invite_member(self, data):
        self._invite_member(self._device(data))

    @rule(data=st.data(), access=st.sampled_from(["read", "write"]))
    def grant(self, data, access):
        """The admin shares a folder with a member (team dialog / 'sezam grant')."""
        device = self._device(data)
        member = self._pick(data, self._active_members(), "member")
        folder = self._pick(data, self._folders(device), "folder")
        if member is None or folder is None:
            return
        self._grant(device, member, folder, access)

    def _grant(self, device: str, member: str, folder: str, access: str) -> None:
        dev, name = self.devices[device], self.members[member].name
        before = _dirty_ids(dev.vault)
        try:
            revocation.grant_member(
                dev.vault, dev.client, member, folder, access, confirm_fingerprint=lambda _fp: True
            )
        except (ValueError, RuntimeError) as exc:
            self.log.append(f"{device}: grant {folder} to {name} not done: {exc}")
            if _GRANT_DEFERRED in str(exc):
                # Review 3662a06 (deep run): the push failed, but the envelope is
                # sealed locally and goes with the next push - the grant stands.
                self._note_granted(member, folder, access)
        else:
            self._note_granted(member, folder, access)
            self.log.append(f"{device}: grant {folder} ({access}) to {name}")
        self._note_pushed(device, before)

    def _note_granted(self, member: str, folder: str, access: str) -> None:
        self.granted[member].add(folder)
        if access == "write":
            self.write_granted[member].add(folder)

    @rule(data=st.data(), failure=st.sampled_from([None, "before", "after"]))
    def revoke(self, data, failure):
        """'sezam revoke-user': revoked on the server, then the folders re-keyed
        (an injected push failure leaves the re-key pending)."""
        device = self._device(data)
        member = self._pick(data, self._active_members(), "member")
        if member is None:
            return
        dev, name = self.devices[device], self.members[member].name
        before = _dirty_ids(dev.vault)
        undo = _fail_once(dev.client, "POST", "/api/sync", failure) if failure else None
        try:
            count = revocation.revoke_member(dev.vault, dev.client, member)
            self.log.append(f"{device}: revoke {name} -> re-keyed {count}")
        except RuntimeError as exc:  # RekeyPending, or the server call failed
            self.log.append(f"{device}: revoke {name}: {type(exc).__name__}: {exc}")
        finally:
            if undo:
                undo()
        if self._member_status(member) == "revoked":
            self.revoked.add(member)
        self.log.append(f"   {name} is {self._member_status(member)} on the server")
        self._note_pushed(device, before, undo)

    def _member_rekey_pending(self) -> list[str]:
        """Devices with a pending member re-key (an identity rotation waits the same
        way, but its way out is 'sezam abandon-pending-change')."""
        return sorted(
            name for name, dev in self.devices.items()
            if (pending := (pending_store.rekey_batch(dev.vault.db) or None))
            and not pending.get("identity_rotation")
        )

    @precondition(lambda self: self._member_rekey_pending())
    @rule(data=st.data())
    def delete_during_rekey(self, data):
        """An item of a re-keyed folder deleted while the re-key waits (review
        d150605 #2: a random delete seldom lands there before the next push)."""
        device = data.draw(st.sampled_from(self._member_rekey_pending()), label="device")
        pending = pending_store.rekey_batch(self.devices[device].vault.db)
        rekeyed = set(pending.get("object_ids") or [])
        item = self._pick(data, [("entry", e) for e in self._entries(device) if e in rekeyed]
                          + [("folder", f) for f in self._folders(device) if f in rekeyed], "item")
        if item is None:
            return
        kind, obj_id = item
        coverage_event(f"delete {kind} during pending re-key")
        self._local(device, f"delete {kind} {obj_id} (re-key pending)",
                    lambda v: v.delete_entry(obj_id) if kind == "entry" else v.delete_node(obj_id))

    @precondition(lambda self: self._member_rekey_pending())
    @rule(data=st.data())
    def abandon_rekey(self, data):
        """'sezam abandon-rekey', the way out 'sezam status' offers for a stuck re-key."""
        device = data.draw(st.sampled_from(self._member_rekey_pending()), label="device")
        db = self.devices[device].vault.db
        if self.made_up and db.fetchone(
            f"SELECT 1 FROM access_envelopes WHERE user_id IN ({','.join('?' * len(self.made_up))})",
            tuple(self.made_up),
        ):
            # Review a159e97 H1: her envelope must not be granted again.
            coverage_event("abandon re-key with a made-up member's envelope")
        try:
            result = abandon_pending_rekey(self.devices[device].client)
        except Exception as exc:
            self.log.append(f"{device}: abandon re-key raised {type(exc).__name__}: {exc}")
            raise AssertionError(f"{device}: abandon re-key raised {exc!r}\n" + self._trace()) from exc
        self.log.append(f"{device}: abandon re-key -> {result}")
        self._observe(device)

    # ── member desktops: what is shared with a member, synced on their vault ──

    def _member_snap(self, member: Member) -> dict[str, tuple]:
        """The member vault in the admins' terms (the admin root is 'ROOT').
        A copy it cannot open (a key it never got) is left out here; what it
        must open is checked by _check_member_desktops."""
        admin_root = self.devices[sorted(self.devices)[0]].vault.db.get_meta("root_node_id")
        return {
            obj: (alive, name, "ROOT" if parent == admin_root else parent)
            for obj, (alive, name, parent) in snapshot(member.vault).items()
            if not name.startswith("<unreadable")
        }

    def _member_sync(self, user_id: str) -> None:
        """'sezam sync' on the member's desktop; a conflict keeps the server copy."""
        member = self.members[user_id]
        client = self._new_client(member.vault)
        status = self._member_status(user_id)
        before = _dirty_ids(member.vault)
        # Every key the account really had: a rotation whose push failed leaves
        # the devices on a newer key than the one the server holds.
        admin_keys = {bytes(dev.vault.keypair.encryption_pk) for dev in self.devices.values()} | self.admin_pks
        resync = False
        try:
            for attempt in range(4):
                try:
                    if resync:
                        # Its signature checks can meet the admin's rotated key too.
                        client.full_resync(confirmed=True)
                        client = self._new_client(member.vault)
                        resync = False
                    if self._is_admin(user_id):
                        # 'sezam push' on an admin desktop: it also re-keys the
                        # folders of the members it revoked (their queue).
                        pushed = revocation.push_with_queued_revocations(member.vault, client)
                    else:
                        pushed = client.push()
                    pulled = client.pull()
                    if pulled.get("rollback_warning"):
                        raise RuntimeError(f"full resync: {pulled['rollback_warning']}")
                    break
                except TofuKeyChangeError as change:
                    # The admin rotated their identity: the member checks the new
                    # fingerprint with them (as 'sezam pull' asks) and accepts it -
                    # only if it is the admin's real key.
                    if attempt == 3 or bytes(change.encryption_pk) not in admin_keys:
                        raise
                    coverage_event("member accepts a rotated admin key")
                    client.confirm_tofu_key_change(change, change.new_fingerprint)
                    self.log.append(f"{member.name}: accepted the admin's new key {change.new_fingerprint}")
                except RuntimeError as exc:
                    # GC past its checkpoint or a restored server: the way out
                    # the member is told about ('sezam pull --full-resync').
                    if attempt == 3 or "full resync" not in str(exc) and "full-resync" not in str(exc):
                        raise
                    coverage_event("member full resync")
                    self.log.append(f"{member.name}: full resync ({exc})")
                    resync = True
        except Exception as exc:
            if status == "active":
                self.log.append(f"{member.name}: sync raised {type(exc).__name__}: {exc}")
                raise AssertionError(f"{member.name}: sync raised {exc!r}\n" + self._trace()) from exc
            coverage_event(f"member sync refused ({status})")
            self.log.append(f"{member.name}: sync refused ({status}): {exc}")
            return
        errors = sorted({f"{c.get('id')}: {c.get('error') or c.get('reason')}" for c in pushed.get("conflicts") or []})
        self.log.append(f"{member.name}: sync -> pushed {len(pushed.get('accepted') or [])}, "
                        f"conflicts {len(pushed.get('conflicts') or [])}, pulled {pulled.get('pulled')}"
                        + (f" {errors}" if errors else ""))
        snap = self._learn(member.name, self._member_snap(member))
        # Only what it sent: a copy moved out of the share stays here as it was.
        for obj in before - _dirty_ids(member.vault):
            if obj in snap:
                self._sent(member.name, obj)
                self.server_known[obj] = self._closure(obj, snap[obj], sent_only=True)
        for conflict in client.get_pull_conflicts():
            obj = conflict["id"]
            known_before = set(self.knowledge[member.name])
            client.resolve_conflict(obj, "server")
            self.log.append(f"{member.name}: resolve {obj} keep server")
            after = self._learn(member.name, self._member_snap(member))
            lost = {e for e in known_before if self.events[e].obj == obj}
            self.traced |= lost - self._kept_server_copy(obj, after.get(obj))

    def _member_desktops(self, active: bool = True) -> list[str]:
        return [u for u, m in sorted(self.members.items())
                if m.vault is not None and (not active or self._member_status(u) == "active")]

    @precondition(lambda self: self._member_desktops(active=False))
    @rule(data=st.data())
    def member_sync(self, data):
        self._member_sync(data.draw(st.sampled_from(self._member_desktops(active=False)), label="member"))

    @rule(data=st.data(), op=st.sampled_from(["add folder", "add entry", "edit"]))
    def member_write(self, data, op):
        """The member works in their own folders on their desktop (the desktop
        has no view of folders shared with them: those stay unreadable here)."""
        user_id = self._pick(data, self._member_desktops(), "member")
        if user_id is None:
            return
        member = self.members[user_id]
        snap = self._member_snap(member)
        own = [o for o, s in snap.items() if s[0] and member.vault.db.fetchone(
            "SELECT 1 FROM nodes WHERE id = ? AND is_deleted = 0", (o,))]
        name = self._token("E" if op != "add folder" else "F")
        fields = [{"key": "password", "value": name, "sensitive": True}]
        if op == "add folder":
            target = "ROOT"
            action = lambda v: v.create_node(name)  # noqa: E731
        elif op == "edit":
            target = self._pick(data, [o for o, s in snap.items() if s[0] and s[2] in own
                                       and member.vault.db.fetchone("SELECT 1 FROM entries WHERE id = ?", (o,))],
                                "entry")
            action = lambda v: v.update_entry(target, name=name, fields=fields)  # noqa: E731
        else:
            target = self._pick(data, own, "folder")
            action = lambda v: v.create_entry(target, name, fields)  # noqa: E731
        if target is None:
            return
        try:
            action(member.vault)
        except (ValueError, RuntimeError, PermissionError) as exc:
            self.log.append(f"{member.name}: {op} {target} refused: {exc}")
            return
        self.log.append(f"{member.name}: {op} {target} -> {name}")
        self._record_local_change(member.name, snap, self._member_snap(member))

    def _check_member_desktops(self) -> None:
        """An active member's desktop syncs, and what the member wrote there
        reached the server: nothing stays unsent once the sync settled."""
        for user_id in self._member_desktops():
            member = self.members[user_id]
            for _ in range(2):
                self._member_sync(user_id)
            # The member's own root and what is below it stay on this desktop:
            # the server lets no member make a top-level folder (write_acl
            # denied (top-level)), and without an envelope for the admins'
            # root the desktop does not adopt it (idea #24).
            root = member.vault.db.get_meta("root_node_id")
            on_server = {o["id"] for o in self.db._storage["vault_objects"]}
            local_only = set()
            # An admin may make top-level folders: their whole tree goes up.
            if root and root not in on_server and not self._is_admin(user_id):
                local_only = {r["id"] for r in member.vault.db.fetchall(
                    "WITH RECURSIVE t(id) AS (SELECT ? UNION SELECT n.id FROM nodes n JOIN t "
                    "ON n.parent_id = t.id) SELECT id FROM t UNION SELECT e.id FROM entries e "
                    "JOIN t ON e.node_id = t.id", (root,))}
                coverage_event("member desktop keeps its own root local")
            unsent = _dirty_ids(member.vault) - local_only
            if unsent:
                coverage_event("member desktop keeps unsent items")
            else:
                coverage_event("member desktop settled")
            assert not unsent, (
                f"member {member.name}'s desktop never sent {sorted(unsent)}\n" + self._trace()
            )
            # Review 7c10379 (state machine: the second admin gets stuck): a
            # revocation of a member whose folders another admin shared stayed
            # queued on this desktop for good. (Unsent changes are checked above,
            # with the member's own root that stays local.)
            # 'shared_before_team_log' only tells the member why a folder shared
            # in this log-less org does not open here (see member_write): it is
            # waiting on an admin's 'sezam team-log init', not a stuck sync.
            states = pending_states(member.vault)
            if any(s.key == "shared_before_team_log" for s in states):
                coverage_event("member desktop told a folder needs the team log")
            waiting = {s.key: s.summary for s in states
                       if s.key not in ("unpushed", "shared_before_team_log")}
            assert not waiting, f"member {member.name}'s desktop keeps waiting: {waiting}\n" + self._trace()

    # ── a second admin: a member the operator made an admin ──

    def _is_admin(self, user_id: str) -> bool:
        """On the server now (a restore from an older backup takes it back)."""
        return any(u.get("id") == user_id and u.get("is_admin") for u in self.db._storage.get("users", []))

    def _second_admins(self) -> list[str]:
        return [u for u in sorted(self.admins) if self._member_status(u) == "active" and self._is_admin(u)]

    def _admin_user_id(self) -> str:
        return self.devices[sorted(self.devices)[0]].vault.db.get_meta("user_id")

    @precondition(lambda self: not self._second_admins())
    @rule(data=st.data())
    def appoint_admin(self, data):
        """The operator makes a member an admin (there is no API for it: the
        flag is set on the server). Their desktop now syncs its own tree."""
        user_id = self._pick(data, self._member_desktops(), "member")
        if user_id is None:
            return
        self._appoint(user_id)

    def _appoint(self, user_id: str) -> None:
        next(u for u in self.db._storage["users"] if u["id"] == user_id)["is_admin"] = 1
        self.admins.add(user_id)
        coverage_event("second admin")
        self.log.append(f"operator: {self.members[user_id].name} is an admin")

    @precondition(lambda self: self._second_admins())
    @rule(data=st.data(), failure=st.sampled_from([None, "before", "after"]))
    def second_admin_revokes(self, data, failure):
        """The second admin revokes a member the first admin shared folders
        with: the first admin's devices hold the envelopes and must re-key."""
        admin = self.members[data.draw(st.sampled_from(self._second_admins()), label="admin")]
        target = self._pick(data, [u for u in self._active_members() if u not in self.admins], "member")
        if target is None:
            return
        name = self.members[target].name
        client = self._new_client(admin.vault)
        before = _dirty_ids(admin.vault)
        undo = _fail_once(client, "POST", "/api/sync", failure) if failure else None
        try:
            count = revocation.revoke_member(admin.vault, client, target)
            self.log.append(f"{admin.name} (admin): revoke {name} -> re-keyed {count}")
        except RuntimeError as exc:
            self.log.append(f"{admin.name} (admin): revoke {name}: {type(exc).__name__}: {exc}")
        finally:
            if undo:
                undo()
        if self._member_status(target) == "revoked":
            self.revoked.add(target)
            if self.granted[target]:
                coverage_event("second admin revokes a member the first admin shared with")
        self.log.append(f"   {name} is {self._member_status(target)} on the server")
        snap = self._learn(admin.name, self._member_snap(admin))
        for obj in before - _dirty_ids(admin.vault):
            if obj in snap:
                self._sent(admin.name, obj)
                self.server_known[obj] = self._closure(obj, snap[obj], sent_only=True)

    # ── org recovery (Shamir): the password is forgotten ──

    @precondition(lambda self: self.org is None)
    @rule(data=st.data())
    def setup_org_recovery(self, data):
        """'sezam org-recovery-setup -t 2 -n 3' on an admin device."""
        device = self._device(data)
        dev = self.devices[device]
        try:
            setup = org_recovery_server.setup_and_register(dev.vault, dev.password, 2, 3)
        except RuntimeError as exc:
            self.log.append(f"{device}: org recovery setup refused: {exc}")
            return
        secret = reconstruct_secret(setup.shares[:2])
        signing_pk = bytes(org_recovery_signing_key(secret).verify_key)
        self.org = (device, list(setup.shares), signing_pk)
        self.log.append(f"{device}: org recovery set up (registered: {setup.registered}"
                        + (f", {setup.error}" if setup.error else "") + ")")

    def _org_recovery_usable(self) -> bool:
        """The server checks the reset proof against the recovery key it holds:
        a restore from a backup taken before the setup forgot it."""
        if self.org is None or self.org[0] not in self.devices:
            return False
        # The server's current recovery: the stored blob or the key (and wrap)
        # the team log names. A stale one wraps the KEK of an older password.
        vault = self.devices[self.org[0]].vault
        status = org_recovery_server._client(vault)._request("GET", "/api/org-recovery/status") or {}
        return (
            bool(status.get("configured")) and not status.get("stale")
            and status.get("recovery_signing_pk") == self.org[2].hex()
        )

    def _check_org_recovery_told(self) -> None:
        """After settle the shares handed out work on the server, or the
        device tells the admin they do not (while the password is known)."""
        if self.org is None or self.org[0] not in self.devices or self._org_recovery_usable():
            return
        vault = self.devices[self.org[0]].vault
        issue = org_recovery_server.registration_issue(vault)
        stale = vault.db.get_meta("org_recovery_stale") == "1"
        coverage_event(f"org recovery not on the server: {issue or ('stale' if stale else 'silent')}")
        assert issue is not None or stale, (
            f"{self.org[0]}: the server lacks the org recovery the admin was given, "
            "and nothing says so\n" + self._trace()
        )

    def _org_recovery(self, failure: str | None) -> None:
        """'sezam org-recovery' with two of the three shares, then its push."""
        device, shares, _pk = self.org
        dev = self.devices[device]
        new = self._token("pw-") + "-Sezam!"
        rekey_pending = device in self._member_rekey_pending()
        if rekey_pending:
            coverage_event("org recovery with pending re-key")
        coverage_event("org recovery")
        self.log.append(f"{device}: org recovery -> {new}"
                        + (" (member re-key pending)" if rekey_pending else ""))
        dev.vault.lock()
        try:
            dev.vault.org_recovery(shares[:2], new)
        except Exception as exc:
            self.log.append(f"{device}: org recovery raised {type(exc).__name__}: {exc}")
            raise AssertionError(
                f"{device}: org recovery raised {exc!r}; the old password is forgotten\n" + self._trace()
            ) from exc
        self.salt_password[dev.vault.db.get_meta("argon2_salt")] = new
        dev.password = new
        dev.client = self._new_client(dev.vault)
        self._observe(device)
        self._push(device, failure)

    @precondition(lambda self: self._org_recovery_usable())
    @rule(failure=st.sampled_from([None, None, "before", "after"]))
    def org_recovery(self, failure):
        self._org_recovery(failure)

    @precondition(lambda self: self._org_recovery_usable() and self.org[0] in self._member_rekey_pending())
    @rule(failure=st.sampled_from([None, "before", "after"]))
    def org_recovery_during_rekey(self, failure):
        """The same while a member re-key waits on that device (review 526419e V4)."""
        self._org_recovery(failure)

    @precondition(lambda self: self.org is not None and self.org[0] in self.devices)
    @rule()
    def server_lies_about_org_recovery(self):
        """Review e443cbc #428 (INV-3): /api/org-recovery/status is unsigned.
        Through one push and unlock of the device that set org recovery up it
        names another recovery key of this admin. That may keep the device's
        setup from the server (withholding), never take its recovery key: the
        shares handed out still open the vault on it."""
        device = self.org[0]
        dev = self._command(device)
        user_id = dev.vault.db.get_meta("user_id")
        made_up = os.urandom(32).hex()
        real = SyncClient._request

        def lying(client, method, path, *args, **kwargs):
            resp = real(client, method, path, *args, **kwargs)
            if method == "GET" and path == "/api/org-recovery/status":
                coverage_event("server names another org recovery key of the admin")
                return {**(resp or {}), "configured": True, "created_by": user_id,
                        "recovery_signing_pk": made_up, "stale": False}
            return resp
        SyncClient._request = lying
        try:
            self.log.append(f"server: names another org recovery key to {device}")
            self._push(device)
            org_recovery_server.register_while_password_known(dev.vault, dev.password)
        finally:
            SyncClient._request = real
        assert dev.vault.db.get_meta("org_recovery_signing_pk") == self.org[2].hex(), (
            f"{device} dropped its org recovery key on the server's unsigned word\n" + self._trace())

    @rule(data=st.data(), kind=st.sampled_from(["dek", "envelope", "dek_archive", "node", "entry", "parent"]))
    def server_withholds(self, data, kind):
        """Review 7c10379: the server leaves every object of one kind out of a
        pull and sends the rest - a folder before its key, an entry before
        its folder, a re-key without its archive. The checkpoint it sends
        stops before the first object it held back, so the next (honest)
        pull brings it. The device may refuse; it must not crash, change its
        keys or relabel a DEK, and the next settle finds nothing lost."""
        device = self._device(data)
        dev = self._command(device)
        db = dev.vault.db
        withheld: list[dict] = []

        def held_back(obj: dict, objects: list) -> bool:
            if kind != "parent":
                return obj.get("object_type") == kind
            # Review a159e97 H2: only the folders something in the reply sits
            # in, so the writes below them arrive without their parent.
            return obj.get("object_type") == "node" and any(
                o.get("parent_ref") == obj.get("id") and o.get("object_type") in ("node", "entry")
                for o in objects
            )

        def withhold(reply):
            objects = reply.get("objects") or []
            held = [o for o in objects if held_back(o, objects)]
            withheld.extend(held)
            seqs = [o["commit_seq"] for o in withheld if isinstance(o.get("commit_seq"), int)]
            if not seqs or reply.get("has_more"):
                withheld.clear()
                return reply
            held_ids = {id(o) for o in held}
            reply["objects"] = [o for o in objects if id(o) not in held_ids]
            reply["max_commit_seq"] = max(min(seqs) - 1, int(db.get_meta("last_known_commit_seq") or 0))
            return reply
        keys = lambda: (db.get_meta("kek_dek_id"), db.get_meta("argon2_salt"))  # noqa: E731
        labels = lambda: {r["id"]: r["scope"] for r in db.fetchall("SELECT id, scope FROM deks")}  # noqa: E731
        keys_before, labels_before = keys(), labels()
        undo = _tamper_once(dev.client, "GET", "/api/sync", withhold)
        try:
            result = dev.client.pull()
            outcome = f"refused: {result['rollback_warning']}" if result.get("rollback_warning") \
                else "accepted"
        except KeyEpochStale:
            outcome = "asks for the account password"
        except REFUSALS as exc:
            outcome = f"refused: {exc}"
        except Exception as exc:
            self.log.append(f"server: withholds {kind} from {device}: crashed: {type(exc).__name__}: {exc}")
            raise AssertionError(f"{device}: the server withholding {kind} crashed it: {exc!r}\n"
                                 + self._trace()) from exc
        finally:
            undo()
        if not withheld:
            self.log.append(f"server: had no {kind} to withhold from {device}")
            # Nightly run on c78fd19: the pull still ran; unobserved, a later
            # edit of what it brought counted as losing that copy.
            self._observe(device)
            return
        self.log.append(f"server: withholds {len(withheld)} {kind} from {device} -> {outcome}")
        coverage_event(f"server withholds {kind}: {outcome.split(':')[0]}")
        assert keys() == keys_before, f"{device}: withheld {kind} changed its keys\n" + self._trace()
        after = labels()
        for dek_id, old in labels_before.items():
            new = after.get(dek_id, old)
            assert new == old or (old, new) in {("folder", "tier2"), ("folder", "root")}, (
                f"{device}: withheld {kind} relabelled DEK {dek_id} {old} -> {new}\n" + self._trace())
        self._observe(device)

    @precondition(lambda self: not self.made_up)
    @rule(data=st.data())
    def server_makes_up_a_member(self, data):
        """Review 7c10379 H2: the server activates an account 'Eve' no admin
        approved and stores an envelope she signed to herself on a folder's
        key. Eve is no member of anything: no client may give her a key
        (no_key_for_made_up_accounts), above all not a re-key of that folder
        after a revocation."""
        device = self._device(data)
        dev = self.devices[device]
        # The server takes an envelope only on a key it knows a folder of.
        on_server = {o["id"] for o in self.db._storage["vault_objects"]
                     if o["object_type"] == "dek" and o.get("parent_ref")}
        # Review a159e97 H1: her envelope on the new key of a re-key that waits
        # (its push landed, the device did not learn it), which 'sezam
        # abandon-rekey' grants again on the key the folder goes back to.
        batch = rekey_batch(dev.vault.db)
        pending = sorted(d for d in (batch.get("dek_map") or {}).values() if d in on_server)
        if pending and data.draw(st.booleans(), label="on the pending re-key's key"):
            dek_id, folder = data.draw(st.sampled_from(pending), label="pending dek"), "pending re-key"
            coverage_event("made-up member on a pending re-key's key")
        else:
            folder = self._pick(data, self._folders(device), "folder")
            if folder is None:
                return
            dek_id = dev.vault.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))["dek_id"]
            if dek_id not in on_server:
                return
        name = self._token("eve")
        # The server could mint the invitation itself; the admin's is the shortcut.
        invitation = self._call(device, "create_invitation")
        vault = Vault.create(self.tmp / f"made_up_{name}", PASSWORD, PARAMS)
        vault.db.set_meta("username", name)
        poll = cli._poll_for_approval
        cli._poll_for_approval = lambda *a, **k: None
        try:
            cli._server_register_and_upload(
                self.url, vault, PASSWORD, is_bootstrap=False,
                invitation_token=invitation["invitation_token"],
            )
        finally:
            cli._poll_for_approval = poll
        eve = vault.db.get_meta("user_id")
        user = next(u for u in self.db._storage["users"] if u["id"] == eve)
        user["status"] = "active"  # nobody approved her
        client = SyncClient(vault.db, self.url, vault.keypair, eve)
        client.authenticate()
        envelope = client._make_sync_object(
            id=new_ulid(), object_type="envelope", payload=os.urandom(88),
            parent_ref=dek_id, target_user_id=eve, access_level="read",
        )
        # Capability run 196: signing the envelope makes her an 'admin' to a
        # pull. She writes a folder directly below the account's root and one
        # in it; for 'unknown parent' the server then keeps the first back for
        # good (H2). No device may show either.
        where = data.draw(st.sampled_from([None, "root", "unknown parent"]), label="eve_writes")
        objects = [envelope]
        if where is not None:
            meta = bytes([1, 1, 2]) + dek_id.encode("ascii") + b"\x00" * 24 + os.urandom(48)
            top, sub = new_ulid(), new_ulid()
            for obj_id, parent in ((top, dev.vault.db.get_meta("root_node_id")), (sub, top)):
                objects.append(client._make_sync_object(
                    id=obj_id, object_type="node", payload=meta, parent_ref=parent,
                ))
        from server.app import team_log as server_team_log

        user["is_admin"] = 1  # the server takes from her what it takes from an admin
        # With a team log the server's own rules refuse her envelope (only an
        # admin the log names seals a team key) and her folders; a lying
        # server skips them.
        rules = {name: getattr(server_team_log, name) for name in ("envelope_refusal", "item_refusal")}
        for name in rules:
            setattr(server_team_log, name, lambda *_a, **_k: None)
        try:
            with users_row_deciding():  # and takes the users row, not the log, as the admin (INV-1)
                reply = client._request("POST", "/api/sync", {
                    "objects": objects, "atomic_batch": False,
                    "key_epoch": int(vault.db.get_meta("key_epoch") or 0),
                }, auth=True)
        finally:
            for name, rule_fn in rules.items():
                setattr(server_team_log, name, rule_fn)
            user["is_admin"] = 0
            vault.lock()
        assert reply.get("accepted"), f"the made-up envelope did not land: {reply}"
        self.made_up[eve] = dek_id
        self.log.append(f"server: made up account {name} ({eve}) with her own envelope on {dek_id} ({folder})")
        coverage_event("server makes up a member")
        if where is not None:
            landed = {a["id"] for a in reply.get("accepted") or []}
            assert {top, sub} <= landed, f"her folders did not land: {reply}"
            if where == "unknown parent":
                rows = self.db._storage["vault_objects"]
                rows[:] = [row for row in rows if row["id"] != top]
                self.forged_by_made_up.add(sub)
            else:
                self.forged_by_made_up |= {top, sub}
            self.log.append(f"server: {name} writes folders {top} (below the root) and {sub} in it;"
                            f" {where}")
            coverage_event(f"made-up member writes below {where}")

    @invariant()
    def no_folder_a_made_up_account_wrote(self):
        for device, dev in self.devices.items():
            leaked = self.forged_by_made_up & {
                row["id"] for row in dev.vault.db.fetchall("SELECT id FROM nodes")
            }
            assert not leaked, (f"{device} shows {sorted(leaked)}, written by an account the server"
                                " made up\n" + self._trace())

    @rule(data=st.data(), access=st.sampled_from(["read", "write"]))
    def server_swaps_a_member_key(self, data, access):
        """Review 7c10379: /api/users is the server's word too. During a grant
        it answers for the member with a keypair of its own. The admin
        compares the fingerprint with the member out of band, so it is
        confirmed only when it is the member's: the grant may be refused,
        but no envelope may be sealed to the server's key."""
        device = self._device(data)
        member = self._pick(data, self._active_members(), "member")
        folder = self._pick(data, self._folders(device), "folder")
        if member is None or folder is None:
            return
        dev, real = self.devices[device], self.members[member].vault.keypair
        fake = generate_keypair()
        real_fp = hashlib.sha256(bytes(real.signing_pk) + bytes(real.encryption_pk)).hexdigest()
        before = {o["id"] for o in self.db._storage["vault_objects"] if o["object_type"] == "envelope"}
        dirty = _dirty_ids(dev.vault)
        dev.client._signing_key_rings.pop(member, None)
        dev.client._tofu_checked_user_ids.discard(member)
        undo = _tamper_once(dev.client, "GET", f"/api/users/{member}/keys", lambda reply: {
            **reply, "signing_pk": bytes(fake.signing_pk).hex(), "encryption_pk": bytes(fake.encryption_pk).hex(),
        }, every=True)
        try:
            revocation.grant_member(
                dev.vault, dev.client, member, folder, access, confirm_fingerprint=lambda fp: fp == real_fp
            )
            outcome = "granted"
        except (ValueError, RuntimeError, TofuKeyChangeError) as exc:
            outcome = f"refused: {type(exc).__name__}: {exc}"
        finally:
            undo()
        self.log.append(f"server: swaps {self.members[member].name}'s key in {device}'s grant of {folder} -> {outcome}")
        coverage_event(f"server swaps a member key: {outcome.split(':')[0]}")
        if outcome == "granted" or _GRANT_DEFERRED in outcome:
            self._note_granted(member, folder, access)
        self._note_pushed(device, dirty)
        self.track_member_keys()  # the admin keys an envelope may be sealed with
        for obj in self.db._storage["vault_objects"]:
            if obj["object_type"] != "envelope" or obj["id"] in before or obj.get("is_deleted"):
                continue
            if obj.get("target_user_id") != member:
                continue
            opened = False
            for pk in self.admin_pks:
                with contextlib.suppress(Exception):
                    open_envelope(bytes(obj["payload"]), self.members[member].encryption_sk, pk)
                    opened = True
                    break
            assert opened, (f"{device} sealed {obj.get('parent_ref')} to the key the server swapped in"
                            f" for {self.members[member].name}\n" + self._trace())

    @rule(data=st.data(), lie=st.sampled_from(["revoked_active", "member_admin"]))
    def server_lies_about_users(self, data, lie):
        """Review a159e97: /api/users is the server's word. Through one push
        and pull of a device it calls every revoked member active, or every
        member an admin. A revoked member gets no key for it (settle checks
        their envelopes) and nobody's access level grows (no_write_level_nobody_granted)."""
        device = self._device(data)
        if not self.members:
            return

        def mutate(user: dict) -> dict:
            if user.get("id") not in self.members:
                return user
            if lie == "revoked_active" and user.get("status") == "revoked":
                coverage_event("server calls a revoked member active")
                return {**user, "status": "active"}
            if lie == "member_admin":
                coverage_event("server calls a member an admin")
                return {**user, "is_admin": True}
            return user
        real = SyncClient.list_users
        SyncClient.list_users = lambda client: [mutate(dict(u)) for u in real(client)]
        try:
            self.log.append(f"server: lies about users ({lie}) to {device}")
            self._push(device)
            self._pull(device)
        finally:
            SyncClient.list_users = real

    @rule(data=st.data(), key=st.sampled_from(field_lies.GENERIC), how=st.integers(0, 2))
    def server_lies_in_a_field(self, data, key, how):
        """Review e443cbc #428 (INV-3): the server lies in one field the
        register (server/app/unsigned_fields.py) calls a hint, through a login,
        a push and a pull of one device. The device may refuse (withholding);
        it must not crash, and the invariants and the settle find nothing
        forged or lost."""
        device = self._device(data)
        dev = self._command(device)
        db = dev.vault.db
        lied: list[str] = []
        real = SyncClient._request

        def lie(method, path, reply):
            if reply is not None:
                reply = copy.deepcopy(reply)
                if field_lies.tamper(key, method, path, reply, how):
                    lied.append(f"{method} {path.split('?')[0]}")
            return reply

        def lying(client, method, path, *args, **kwargs):
            reply = real(client, method, path, *args, **kwargs)
            return lie(method, path, reply) if client._db is db else reply
        # The device's client recorded its own request at creation (_new_client).
        first = dev.client
        own = first._request
        first._request = lambda method, path, *a, **kw: lie(method, path, own(method, path, *a, **kw))
        before = _dirty_ids(dev.vault)
        dev.client.token = None  # a login too
        outcomes = []
        SyncClient._request = lying
        self.field_lie = key
        try:
            for step in ("push", "pull"):
                try:
                    self._call(device, step)
                    outcomes.append(f"{step} ok")
                except REFUSALS as exc:
                    outcomes.append(f"{step} refused: {exc}")
                except Exception as exc:
                    self.log.append(f"server: lies in {key} to {device}: {step} crashed: {exc!r}")
                    raise AssertionError(f"{device}: a lie in {key} crashed its {step}: {exc!r}\n"
                                         + self._trace()) from exc
        finally:
            self.field_lie = None
            SyncClient._request = real
            first._request = own
        coverage_event(f"server lies in {key}" if lied else "server lies in a field it did not send")
        self.log.append(f"server: lies in {key} ({how}) to {device} at {sorted(set(lied)) or 'nothing'}"
                        f" -> {'; '.join(outcomes)}")
        self._note_pushed(device, before)

    @invariant()
    def no_key_for_made_up_accounts(self):
        for obj in self.db._storage.get("vault_objects", []):
            target = obj.get("target_user_id")
            if obj["object_type"] == "envelope" and target in self.made_up and not obj.get("is_deleted"):
                assert obj.get("owner_id") == target, (
                    f"{obj.get('owner_id')} sealed key {obj.get('parent_ref')} to {target},"
                    " an account the server made up\n" + self._trace())

    @invariant()
    def no_write_level_nobody_granted(self):
        """Review a159e97 H3: a member only ever granted 'read' gets no
        envelope saying 'write' from an admin, whatever a pull said."""
        admins = set(self.admins)
        for obj in self.db._storage.get("vault_objects", []):
            target = obj.get("target_user_id")
            if (obj["object_type"] != "envelope" or obj.get("is_deleted") or target not in self.members
                    or target in admins or obj.get("owner_id") == target or self.write_granted[target]):
                continue
            assert obj.get("access_level") != "write", (
                f"{obj.get('owner_id')} sealed key {obj.get('parent_ref')} to "
                f"{self.members[target].name} as 'write'; it was granted 'read' only\n" + self._trace())

    @invariant()
    def track_member_keys(self):
        """Remember every DEK a member was ever given and every account key."""
        for obj in self.db._storage.get("vault_objects", []):
            if obj["object_type"] == "envelope" and obj.get("target_user_id") in self.members:
                self.member_deks[obj["target_user_id"]].add(obj.get("parent_ref"))
        for dev in self.devices.values():
            with contextlib.suppress(Exception):
                self.admin_pks.add(bytes(dev.vault.keypair.encryption_pk))
        # R16-Z: a member who held the admin role sealed keys too (to itself).
        self.member_pks = getattr(self, "member_pks", set())
        for member in self.members.values():
            with contextlib.suppress(Exception):
                self.member_pks.add(bytes(member.vault.keypair.encryption_pk))

    # ── the web client (one browser tab, the unmodified app.js) ──
    #
    # The page pushes every save at once and pulls after it; what it could
    # not send stays queued in IndexedDB. Its view holds live objects only.

    WEB_ERRORS = (
        "Sync conflict",  # the save is queued, the banner offers Use server
        "(injected)",
        "error.key_epoch_changed",  # another device changed the keys: sign in again
        "error.session_ended",  # the server revoked the session: sign in again
        "entry.cross_scope_move",  # the page refuses to move across keys
        "sync.edit_blocked",  # no new edit on an item in conflict: resolve it first
    )

    def _web_snap(self, view: dict) -> dict[str, tuple]:
        root = view.get("rootNodeId")
        out: dict[str, tuple] = {}
        # Another account's tree the page shows locked ('tree.other_personal').
        foreign = {n["id"] for n in view.get("nodes", []) if n["undecryptable"]
                   and n.get("owner_id") and n["owner_id"] != view.get("userId")}
        while more := {n["id"] for n in view.get("nodes", []) if n["parent_ref"] in foreign} - foreign:
            foreign |= more
        for item in view.get("nodes", []) + view.get("entries", []):
            # INV-7: while the page refuses the team log only personal trees
            # open (the machine has none); the settle's equal views prove the
            # refusal ends once a device puts the log back.
            if item["id"] == root or item["undecryptable"] and (
                item["id"] in foreign or item["parent_ref"] in foreign or view.get("teamLogRefused")
            ):
                continue
            assert not item["undecryptable"], (
                f"W: {item['id']} cannot be decrypted in the page\n" + self._trace()
            )
            parent = "ROOT" if item["parent_ref"] == root else item["parent_ref"]
            out[item["id"]] = (True, item["name"], parent)
        return out

    def _web_accepted_restore(self, result: dict) -> None:
        """SM71: the page asked whether the server was restored and the user
        said yes. What it still queues goes out; what it had sent after the
        backup is queued again (S4a, requeueWritesTheServerLost), and its loss
        is still tolerated here (a copy the page held without its commit_seq)."""
        if not any("rollback_confirm" in c for c in result.get("confirms") or []):
            return
        unsent = set(result["view"]["dirty"]) | set(result["view"]["conflicts"])
        # Per object (SM89): a later write of the page that reached the
        # server carries this one in its history, not its content.
        held = [snapshot(dev.vault) for dev in self.devices.values()] + [
            self._member_snap(m) for m in self.members.values() if m.vault is not None]

        def kept(event_id: int) -> bool:
            obj = self.events[event_id].obj
            return event_id in self.server_known.get(obj, ()) or any(
                event_id in self._closure(obj, snap.get(obj)) for snap in held)

        lost = {e for e in self.knowledge[WEB] if self.events[e].obj not in unsent and not kept(e)}
        self.traced |= lost
        self.log.append(f"W: accepted the restored server (lost what only the page had: {sorted(lost)})")

    def _web_do(self, action: str, label: str, **step) -> dict:
        step.setdefault("confirm", True)  # the user answers yes to the page's questions
        refused_before = (self.web_view or {}).get("teamLogCause")
        result = self.web.do(action, **step)
        self.web_view = result["view"]
        self._web_accepted_restore(result)
        fired = result.get("failure") and result["failure"]["fired"]
        self.log.append(f"W: {label}" + (f" [{step['fail']['mode']} {step['fail']['method']}]" if fired else "")
                        + (f" -> {result['error']}" if result["error"] else ""))
        assert not result["rejections"], (
            f"W: {label} left unhandled rejections {result['rejections']}\n" + self._trace()
        )
        error = result["error"]
        if error and "retired by an identity rotation" in error and self._rotation_the_log_waits_for():
            coverage_event("the web page waits for a desktop's rotation the log names")
            self.log.append(f"W: waits for {self._rotation_the_log_waits_for()}'s identity rotation")
        elif (error and error.startswith("TEAM LOG MISMATCH") and action in ("save_object", "delete_entry")
              and refused_before and refused_before == self.web_view["teamLogCause"]):
            # INV-7 (full run on b20ece6): the page refuses the team log (the
            # server lost it and this browser holds no copy to put back), so a
            # write outside the personal tree (the machine has none) names the
            # refusal and its way out, and sends nothing; the settle proves the
            # refusal ends once a device puts the log back.
            coverage_event("the page refuses a team write while it refuses the team log")
            assert not [i for call in result["calls"] for i in call.get("objects") or []], (
                f"W: {label} sent objects while the page refuses the team log\n" + self._trace())
        elif error and not any(ok in error for ok in self.WEB_ERRORS):
            raise AssertionError(f"W: {label} failed: {error}\n" + self._trace())
        if not (self.web_view["token"] and self.web_view["unlocked"]):
            self.web_ended = True
        return result

    def _web_pulled(self, result: dict, skip: str | None = None) -> None:
        """What the page shows after it pulled: learnt; what it does not hold
        unsent is what the server has."""
        if self.web_ended:
            return
        snap = {o: s for o, s in self._web_snap(result["view"]).items() if o != skip}
        self._learn(WEB, snap)
        unsent = set(result["view"]["dirty"]) | set(result["view"]["conflicts"])
        # Only a pull shows the server; a retry that only posted shows the
        # page's old view (SM75: of a server restored since).
        calls = [c for c in result["calls"] if c.get("path") == "/api/sync"]
        pulled = any(c["method"] == "GET" and c.get("status") in (200, 304) for c in calls)
        posted = {i for c in calls if c["method"] == "POST" and c.get("status") == 200
                  for i in c.get("objects") or []}
        for obj, state in snap.items():
            if obj not in unsent and (pulled or obj in posted):
                if obj in posted:
                    self._sent(WEB, obj)
                self.server_known[obj] = self._closure(obj, state, sent_only=True)

    def _web_login(self) -> None:
        password = self._account_password()
        result = self.web.do("login", username="admin", password=password, confirm=True)
        self.web_view = result["view"]
        self._web_accepted_restore(result)
        self.log.append(f"W: sign in ({password})" + (f" -> {result['error']}" if result["error"] else ""))
        assert result["error"] is None and self.web_view["unlocked"], (
            f"W: cannot sign in with the account password {password!r}: {result['error']}\n" + self._trace()
        )
        assert not result["rejections"], f"W: sign in left {result['rejections']}\n" + self._trace()
        self.web_ended = False
        previous, self.web_password = self.web_password, password
        self._web_pulled(result)
        if self.web_view["set_aside"]:
            # Unsent changes of the session before a password change elsewhere:
            # the banner asks for the previous password.
            self._web_pulled(self._web_do(
                "restore_set_aside", f"restore set-aside changes ({previous})", password=previous, confirm=True,
            ))

    def _web_reload(self) -> None:
        """The user reloads the page (or opens a new tab) and signs in."""
        self.web_idb = self.web.close()
        self.web = WebTab(self.url, self.tmp / "web.log", self.web_idb)
        self.log.append("W: reload")
        self._web_login()

    def _web_folders(self) -> list[str]:
        return [o for o, s in self._web_snap(self.web_view).items()
                if any(n["id"] == o for n in self.web_view["nodes"])]

    def _web_entries(self) -> list[str]:
        shown = self._web_snap(self.web_view)
        return [e["id"] for e in self.web_view["entries"] if e["id"] in shown]

    def _web_write(self, obj: str | None, state: tuple, label: str, action: str, failure, **step) -> None:
        """A save or delete in the page: the write is W's (made with what W
        knew before), everything else the page pulled after it is learnt."""
        if self.web_ended:
            self._web_reload()
        before = self._web_snap(self.web_view)
        fail = {"method": "POST", "path": "/api/sync", "mode": failure} if failure else None
        result = self._web_do(action, label, **step, **({"fail": fail} if fail else {}))
        posted = [i for call in result["calls"] for i in call.get("objects") or []]
        if obj is None:  # a new object: the one the page sent
            known = set(before)
            obj = next((i for i in posted if i not in known and i not in self.events_objs()), None)
        if obj is not None and obj in posted and before.get(obj) != state:
            self._event(WEB, obj, state, "write")
            reply = (result.get("failure") or {}).get("reply") or {}
            landed = obj in {a["id"] for a in reply.get("accepted") or []}
            if landed or (not self.web_ended and obj not in result["view"]["dirty"]):
                self._sent(WEB, obj)
                self.server_known[obj] = self._closure(obj, state, sent_only=True)
        self._web_pulled(result, skip=obj)

    def events_objs(self) -> set[str]:
        return {event.obj for event in self.events.values()}

    @precondition(lambda self: NODE and self.web is None)
    @rule()
    def open_web_tab(self):
        self.knowledge[WEB] = set()
        self.web = WebTab(self.url, self.tmp / "web.log", self.web_idb)
        self.log.append("W: open the web client")
        self._web_login()

    @precondition(lambda self: self.web is not None)
    @rule()
    def web_reload(self):
        self._web_reload()

    @precondition(lambda self: self.web is not None and not self.web_ended and not any(
        self.web_view.get(k) for k in ("dirty", "conflicts", "set_aside")))
    @rule()
    def web_new_browser(self):
        """The user signs in from another browser: an empty IndexedDB, so none
        of the old page's own records (capability review run 134). Only with
        nothing unsent, which would stay in the old profile (and with the
        session alive: an ended one's view does not list its queue)."""
        self.web.close()
        self.web_idb = None
        self.knowledge[WEB] = set()
        self.web = WebTab(self.url, self.tmp / "web.log")
        self.log.append("W: sign in from another browser")
        self._web_login()

    WEB_FAILURES = st.sampled_from([None, None, "before", "after"])

    @precondition(lambda self: self.web is not None)
    @rule(data=st.data(), failure=WEB_FAILURES)
    def web_create_entry(self, data, failure):
        folder = self._pick(data, self._web_folders(), "folder")
        if folder is None:
            return
        name = self._token("E")
        self._web_write(None, (True, name, folder), f"create entry {name} in {folder}", "save_object", failure,
                        mode="entry", name=name, parent=folder,
                        fields=[{"key": "password", "value": name}])

    @precondition(lambda self: self.web is not None)
    @rule(data=st.data(), failure=WEB_FAILURES)
    def web_create_folder(self, data, failure):
        parent = self._pick(data, self._web_folders() + ["ROOT"], "parent")
        name = self._token("F")
        self._web_write(None, (True, name, parent), f"create folder {name} under {parent}", "save_object",
                        failure, mode="folder", name=name, parent=parent)

    @precondition(lambda self: self.web is not None)
    @rule(data=st.data(), failure=WEB_FAILURES)
    def web_edit_entry(self, data, failure):
        entry = self._pick(data, self._web_entries(), "entry")
        if entry is None:
            return
        parent = self._web_snap(self.web_view)[entry][2]
        name = self._token("E")
        self._web_write(entry, (True, name, parent), f"edit entry {entry} -> {name}", "save_object", failure,
                        mode="entry", id=entry, name=name, parent=parent,
                        fields=[{"key": "password", "value": name}])

    @precondition(lambda self: self.web is not None)
    @rule(data=st.data(), failure=WEB_FAILURES)
    def web_rename_folder(self, data, failure):
        folder = self._pick(data, self._web_folders(), "folder")
        if folder is None:
            return
        parent = self._web_snap(self.web_view)[folder][2]
        name = self._token("F")
        self._web_write(folder, (True, name, parent), f"rename folder {folder} -> {name}", "save_object",
                        failure, mode="folder", id=folder, name=name, parent=parent)

    @precondition(lambda self: self.web is not None)
    @rule(data=st.data(), failure=WEB_FAILURES)
    def web_move(self, data, failure):
        snap = self._web_snap(self.web_view)
        obj = self._pick(data, list(snap), "object")
        if obj is None:
            return
        is_entry = obj in self._web_entries()
        below = {obj} if is_entry else self._web_subtree(obj)
        targets = [f for f in self._web_folders() + ([] if is_entry else ["ROOT"])
                   if f not in below and f != snap[obj][2]]
        target = self._pick(data, targets, "target")
        if target is None:
            return
        _alive, name, _parent = snap[obj]
        step = {"mode": "entry" if is_entry else "folder", "id": obj, "name": name, "parent": target}
        if is_entry:
            password = next(e["password"] for e in self.web_view["entries"] if e["id"] == obj)
            step["fields"] = [{"key": "password", "value": password}]
        self._web_write(obj, (True, name, target), f"move {obj} -> {target}", "save_object", failure, **step)

    def _web_subtree(self, folder: str) -> set[str]:
        snap = self._web_snap(self.web_view)
        below = {folder}
        while True:
            more = {o for o, s in snap.items() if s[2] in below} - below
            if not more:
                return below
            below |= more

    @precondition(lambda self: self.web is not None)
    @rule(data=st.data(), failure=WEB_FAILURES)
    def web_delete_entry(self, data, failure):
        entry = self._pick(data, self._web_entries(), "entry")
        if entry is None:
            return
        _alive, name, parent = self._web_snap(self.web_view)[entry]
        self._web_write(entry, (False, name, parent), f"delete entry {entry}", "delete_entry", failure, id=entry)

    @precondition(lambda self: self.web is not None)
    @rule(failure=st.sampled_from([None, None, "after"]))
    def web_refresh(self, failure):
        if self.web_ended:
            self._web_reload()
        fail = {"method": "GET", "path": "/api/sync", "mode": failure} if failure else None
        self._web_pulled(self._web_do("refresh", "refresh", confirm=True, **({"fail": fail} if fail else {})))

    def _web_use_server(self) -> None:
        conflicts = list(self.web_view["conflicts"])
        known_before = set(self.knowledge[WEB])
        result = self._web_do("use_server", f"use the server's version of {conflicts}", confirm=True)
        after = self._web_snap(result["view"])
        for obj in conflicts:
            lost = {e for e in known_before if self.events[e].obj == obj}
            self.traced |= lost - self._kept_server_copy(obj, after.get(obj))
        self._web_pulled(result)

    @precondition(lambda self: self.web is not None)
    @rule()
    def web_resolve_conflicts(self):
        if self.web_view.get("conflicts"):
            self._web_use_server()

    def _web_settle(self) -> None:
        if self.web_ended:
            self._web_reload()
        self._web_pulled(self._web_do("retry", "retry", confirm=True))
        if self.web_view["conflicts"] and not self.web_ended:
            self._web_use_server()

    def _web_quiet(self) -> bool:
        return self.web is None or not (
            self.web_ended or self.web_view["dirty"] or self.web_view["conflicts"]
        )

    # ── a malicious server: one lying reply, then honest again ──

    def _lie(self, data, lie: str, epoch: int, db=None):
        """The reply change for ``lie``, or None when it has nothing to work on."""
        if lie == "gc_floor":
            # R15 #428 (INV-3): gc_floor_seq is unsigned. An older, validly
            # signed version of something the device deleted comes again in a
            # reply that brings a new commit, the floor above the tombstone.
            tombs = {
                row["id"]: row["version"] for table in ("nodes", "entries")
                for row in db.fetchall(f"SELECT id, version FROM {table} WHERE is_deleted = 1")  # noqa: S608
            }
            obj_id = self._pick(data, sorted(
                i for i, version in tombs.items() if (self.wire.get(i) and min(self.wire[i]) < version)
            ), "revived")
            if obj_id is None:
                return None
            old = copy.deepcopy(self.wire[obj_id][min(self.wire[obj_id])])
            self.log.append(f"server: serves {old.get('object_type')} {obj_id} v{old['version']} again "
                            f"over its tombstone v{tombs[obj_id]}, GC floor above it")
            self.revived = (obj_id, "nodes" if old.get("object_type") == "node" else "entries", tombs[obj_id])

            def revive(reply):
                seq = reply.get("max_commit_seq")
                if reply.get("has_more") or not isinstance(seq, int) \
                        or seq <= int(db.get_meta("last_known_commit_seq") or 0):
                    return reply
                coverage_event("server revives a tombstone with a GC floor lie")
                reply.setdefault("objects", []).append({**old, "commit_seq": seq})
                reply["gc_floor_seq"] = seq
                return reply
            return revive
        if lie in ("replay", "replay_envelope"):
            kinds = {"envelope"} if lie == "replay_envelope" else {"node", "entry", "dek", "envelope"}
            obj_id = self._pick(data, [
                i for i, versions in self.wire.items()
                if len(versions) > 1 and versions[min(versions)].get("object_type") in kinds
            ], "replayed")
            if obj_id is None:
                return None
            old = copy.deepcopy(self.wire[obj_id][min(self.wire[obj_id])])
            self.log.append(f"server: replays {old.get('object_type')} {obj_id} v{old['version']}")

            def replay(reply):
                reply.setdefault("objects", []).append(old)
                return reply
            return replay
        if lie == "access_up":
            # Review a159e97 H3: an envelope's access_level is not signed.
            def escalate(reply):
                for obj in reply.get("objects") or []:
                    if obj.get("object_type") == "envelope" and obj.get("access_level") != "write":
                        coverage_event("server turns a pulled envelope into write")
                        obj["access_level"] = "write"
                return reply
            return escalate
        if lie in ("epoch_up", "weak_kdf"):
            return lambda reply: {**reply, "key_epoch": int(reply.get("key_epoch") or 0) + 1}
        if lie == "epoch_down":
            if epoch <= 0:
                return None
            return lambda reply: {**reply, "key_epoch": epoch - 1}
        if lie == "dek_order":
            # Run 155: a folder's key and its tier-2 key both name the folder;
            # the order they come in is unsigned.
            def reorder(reply):
                objects = reply.get("objects") or []
                at = [i for i, obj in enumerate(objects) if obj.get("object_type") == "dek"]
                for i, obj in zip(at, [objects[i] for i in reversed(at)]):
                    self.honest_scopes[obj["id"]] = obj.get("scope")
                    objects[i] = obj
                if len(at) > 1:
                    coverage_event("server reverses the pulled DEKs")
                return reply
            return reorder
        label = data.draw(st.sampled_from(["root", "audit", "personal", "tier2", "bogus"]), label="scope")

        def relabel(reply):
            for obj in reply.get("objects") or []:
                if obj.get("object_type") == "dek":
                    coverage_event("server relabels a pulled DEK")
                    self.honest_scopes[obj["id"]] = obj.get("scope")
                    obj["scope"] = label
            return reply
        return relabel

    @rule(data=st.data(), lie=st.sampled_from(LIES))
    def server_lies(self, data, lie):
        """Replayed signed objects, a key_epoch or DEK scope the server made
        up, cheap KDF params with a made-up password change: the client may
        refuse, must not crash, and must not change its keys for it; the
        invariants after the next settle show nothing was lost."""
        device = self._device(data)
        others = sorted(set(self.devices) - {device})
        made = None
        if lie in ("scope", "dek_order", "gc_floor") and others:
            # The reply carries a key this device does not hold yet: a folder
            # another device of the account just made (with a tier-2 entry,
            # so a second key names it).
            other = self._pick(data, others, "maker")
            name = self._token("F")
            entries = [self._token("E"), self._token("E")] if lie == "dek_order" else []

            def make(vault):
                folder = vault.create_node(name)
                for tier, entry in enumerate(entries, start=1):
                    vault.create_entry(folder, entry, [{"key": "password", "value": entry, "sensitive": True}],
                                       tier=tier)
                return folder
            holder = {}
            self._local(other, f"create folder {name} under ROOT"
                        + (f" with entries {entries} (tiers 1, 2)" if entries else ""),
                        lambda v: holder.setdefault("id", make(v)))
            maker = self.devices[other].vault
            made = (holder["id"], maker.db.fetchone(
                "SELECT dek_id FROM nodes WHERE id = ?", (holder["id"],))["dek_id"])
            self._push(other)
        dev = self._command(device)
        meta = dev.vault.db
        keys = lambda: (meta.get_meta("kek_dek_id"), meta.get_meta("argon2_salt"),  # noqa: E731
                        meta.get_meta("argon2_params"))
        before = keys()
        epoch = int(meta.get_meta("key_epoch") or 0)
        self.honest_scopes: dict[str, str | None] = {}
        self.revived = None
        mutate = self._lie(data, lie, epoch, meta)
        if mutate is None:
            return
        scopes = lambda: {row["id"]: (row["scope"], row["node_id"]) for row in meta.fetchall(  # noqa: E731
            "SELECT id, scope, node_id FROM deks")}
        scopes_before = scopes()
        undos = [_tamper_once(dev.client, "GET", "/api/sync", mutate)]
        if lie == "weak_kdf":
            # The made-up change elsewhere comes with a new salt and params a
            # GPU guesses through; deriving with them hands out the password.
            fake_salt = os.urandom(16).hex()
            undos.append(_tamper_once(dev.client, "GET", "/api/meta", lambda reply: {
                **reply, "argon2_salt": fake_salt,
                "argon2_params": {"time_cost": 1, "memory_cost": 8, "parallelism": 1},
            }, every=True))
        took_over = False
        try:
            try:
                result = dev.client.pull()
                # Run on d994f32: after a restore the pull stops at the
                # rollback before it reads the key epoch (nothing derived).
                outcome = f"refused: {result['rollback_warning']}" if result.get("rollback_warning") \
                    else "accepted"
            except KeyEpochStale:
                outcome = "asks for the account password"
                try:
                    password = self._account_password()
                    dev.client.adopt_rotated_key_material(dev.vault, password)
                    took_over = True
                    dev.password = password
                    outcome += ", took the keys over"
                except REFUSALS as exc:
                    outcome += f", take-over refused: {exc}"
            except REFUSALS as exc:
                outcome = f"refused: {exc}"
        except Exception as exc:
            self.log.append(f"{device}: lie {lie} crashed: {type(exc).__name__}: {exc}")
            raise AssertionError(f"{device}: a lying server ({lie}) crashed it: {exc!r}\n"
                                 + self._trace()) from exc
        finally:
            for undo in reversed(undos):
                undo()
        self.log.append(f"{device}: lie {lie} -> {outcome}")
        coverage_event(f"lie {lie}: {outcome.split(':')[0]}")
        if lie == "weak_kdf":
            # A pull refused for another reason (compacted past the
            # checkpoint) never asks for the password: nothing is derived.
            assert not took_over and ("below the minimum" in outcome or outcome.startswith("refused")), (
                f"{device}: derived the password with the server's cheap params: {outcome}\n" + self._trace()
            )
        if not took_over:
            assert keys() == before, f"{device}: the lie {lie} changed its keys\n" + self._trace()
        if self.revived is not None:
            # R16-N5 (gate 26 on 7429bfc): the same reply may bring a newer,
            # honest write over the tombstone - another device's edit that
            # built on the collected copy (sync_push COLLECTED_OBJECT). Only
            # a copy at or below the tombstone's version is the lie's.
            obj_id, table, tomb_version = self.revived
            row = meta.fetchone(f"SELECT is_deleted, version FROM {table} WHERE id = ?", (obj_id,))  # noqa: S608
            assert row is None or row["is_deleted"] or row["version"] > tomb_version, (
                f"{device}: an old version over a GC floor lie brought deleted {obj_id} back\n" + self._trace())
        # A DEK's role is never the server's word: a key held keeps its label
        # but for what the device derives itself (tier 2 from the entry
        # binding, root from the adopted root node), and a key it did not hold
        # gets the label the honest server sent (run 151: a folder key taken
        # as tier2 lost its folder to the next tier-2 key). Another user's key
        # (a second admin's root) is no role here whatever either server says.
        foreign = set(meta.get_meta_json("foreign_dek_ids") or [])
        for dek_id, (scope, node_id) in scopes().items():
            old = scopes_before.get(dek_id, (None,))[0]
            if old is None:
                honest = "folder" if dek_id in foreign else self.honest_scopes.get(dek_id, scope)
                assert scope == honest, (
                    f"{device}: the lie {lie} made folder {node_id}'s key {dek_id} a {scope} key"
                    f" (honest: {honest})\n" + self._trace())
            else:
                # Seed 828282 (#438 (7)): a folder's old key taken for tier 2
                # while its archive was withheld is retired once the archive
                # comes (_retire_keys_taken_for_tier2): the archive opening to
                # it is the device's own proof, whatever order the keys came in.
                retired = (old, scope, node_id) == ("tier2", "folder", None) and (
                    dev.vault.dek_mgr.successor_of(dek_id) is not None)
                assert scope == old or retired or (old, scope) in {("folder", "tier2"), ("folder", "root")}, (
                    f"{device}: the lie {lie} relabelled its DEK {dek_id} {old} -> {scope}\n"
                    + self._trace())
        if made is not None and outcome == "accepted" and not took_over:
            folder, folder_dek = made
            bound = meta.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (folder,))
            assert bound is None or bound["dek_id"] == folder_dek, (
                f"{device}: the lie {lie} bound folder {folder} to {bound['dek_id']}, not its key {folder_dek}\n"
                + self._trace())
        self._observe(device)

    @rule(data=st.data(), trigger=st.sampled_from(["check_token", "gone"]), old_wraps=st.booleans())
    def server_lies_into_full_resync(self, data, trigger, old_wraps):
        """Review 7c10379 H1: the server makes a device full-resync (a head and
        commit token it made up, or 410 Gone) and answers the resync with the
        DEK wraps it kept from before a password change (the old KEK, a lower
        version, validly signed when current). The device may only refuse;
        every DEK its KEK opened still opens afterwards, at no lower version."""
        device = self._device(data)
        dev = self._command(device)
        db = dev.vault.db
        last_seq = int(db.get_meta("last_known_commit_seq") or 0)
        if last_seq == 0:
            return
        client = dev.client
        if trigger == "gone":
            real = client._request

            def gone(m, path, *args, **kwargs):
                if m == "GET" and path.startswith("/api/sync"):
                    raise ServerError(410, json.dumps({"detail": "compacted"}))
                return real(m, path, *args, **kwargs)
            client._request = gone
            undo = lambda: setattr(client, "_request", real)  # noqa: E731
        else:
            undo = _tamper_once(client, "GET", "/api/sync", lambda reply: {
                **reply, "head_commit_seq": last_seq - 1, "check_token": "made-up",
            })
        try:
            try:
                result = client.pull()
            except REFUSALS as exc:
                result = {"refused": str(exc)}
        finally:
            undo()
        self.log.append(f"server: made-up {trigger} -> {device}: {result}")
        wants = result.get("rollback_warning") or "full resync" in result.get("refused", "") \
            or "full-resync" in result.get("refused", "")
        if not wants:
            return
        self.resync_due.add(device)
        own = {
            row["id"]: row["version"] for row in db.fetchall("SELECT id, encrypted_dek, version FROM deks")
            if dev.vault.dek_mgr.can_unwrap(row["id"], bytes(row["encrypted_dek"]), row["version"])
        }
        replaced = []

        def old(reply):
            objects = reply.get("objects") or []
            for i, obj in enumerate(objects):
                versions = self.wire.get(obj.get("id")) or {}
                if obj.get("object_type") == "dek" and versions and min(versions) < obj.get("version", 0):
                    objects[i] = copy.deepcopy(versions[min(versions)])
                    replaced.append(f"{obj['id']} v{min(versions)}")
            return reply
        done = self._full_resync(device, old if old_wraps else None)
        # None: a blocker kept it from starting; False: it refused the answer.
        assert done is not False or replaced, (
            f"{device}: full resync refused though the server answered it honestly\n" + self._trace())
        if done is False:
            coverage_event("full resync refuses old DEK wraps under a pending key change")
        if replaced:
            self.log.append(f"server: answered {device}'s full resync with old DEK wraps {replaced}")
            coverage_event("server answers a full resync with old DEK wraps")
        for dek_id, version in own.items():
            row = db.fetchone("SELECT encrypted_dek, version FROM deks WHERE id = ?", (dek_id,))
            if row is None:
                continue
            assert row["version"] >= version and dev.vault.dek_mgr.can_unwrap(
                dek_id, bytes(row["encrypted_dek"]), row["version"]
            ), (f"{device}: after a made-up {trigger} its full resync took DEK {dek_id} v{row['version']}"
                f" (was v{version}) that its KEK no longer opens\n" + self._trace())

    def _retired_signers(self) -> list[tuple[str, SigningKey]]:
        """Leaked keys the server no longer serves as their account's current one."""
        def raw(value) -> bytes:
            return bytes.fromhex(value) if isinstance(value, str) else bytes(value or b"")
        current = {u.get("id"): raw(u.get("signing_pk")) for u in self.db._storage.get("users", [])}
        return [(uid, key) for uid, key in self.leaked_signers
                if uid in current and bytes(key.verify_key) != current[uid]]

    # Hypothesis picks a rule by its place in the rules sorted by name: a new
    # rule named to sort last keeps the saved counterexamples
    # (property_seeds.txt) fitting.
    @precondition(lambda self: self._retired_signers())
    @rule(data=st.data(), how=st.sampled_from(["new_device", "full_resync", "web"]))
    def with_a_leaked_retired_key_the_server_forges(self, data, how):
        """Goal #443 (review e443cbc R15, INV-3): the server holds a signing
        key an identity rotation retired. It serves the next version of a live
        object that key signed, signed with it, and stretches
        the archive's bound (retired_seq) over it. A device that never pinned a
        bound (a new device, a full resync, a web sign-in) may refuse or skip
        it, never take it: no voucher list names that version."""
        if how == "web" and not NODE:
            return
        retired = self._retired_signers()
        user_id, signer = retired[self._pick(data, range(len(retired)), "leaked key")]
        storage = self.db._storage
        signed = {o["id"]: o for o in storage["vault_objects"]
                  if o.get("object_type") == "entry" and not o.get("is_deleted")
                  and o.get("signature_user_id") == user_id}
        picked = self._pick(data, signed, "object")
        if picked is None:
            return
        target = signed[picked]
        original = copy.deepcopy(target)
        archives = [a for a in storage.get("user_key_archives", []) if a.get("user_id") == user_id]
        bounds = [a.get("retired_seq") for a in archives]
        # Well-formed content (the entry's own), so only the signature check
        # can refuse it.
        payload_hash = target["payload_hash"]
        version = target["version"] + 1
        counter = storage["commit_counter"][0]
        commit_seq = counter["next_seq"]
        counter["next_seq"] += 1
        canonical = SyncClient._build_signature_payload(
            id=target["id"], object_type="entry", parent_ref=target.get("parent_ref"),
            target_user_id=target.get("target_user_id"), is_deleted=0, version=version,
            payload_hash=payload_hash,
        )
        target.update(version=version, commit_seq=commit_seq,
                      client_signature=signer.sign(canonical).signature)
        for archive in archives:
            archive["retired_seq"] = 10**9
        obj = target["id"]
        self.log.append(f"server: signs {obj} v{version} with {user_id}'s retired key ({how})")
        try:
            if how == "new_device":
                name = self._token("fresh")
                try:
                    vault = self._new_vault(self.tmp / name)
                except REFUSALS as exc:
                    outcome, held = f"refused: {exc}", None
                else:
                    row = vault.db.fetchone("SELECT version FROM entries WHERE id = ?", (obj,))
                    outcome, held = "connected", row and row["version"]
                    vault.lock()
            elif how == "full_resync":
                device = self._device(data)
                client = self._command(device).client
                blocker = client.full_resync_blocker()
                if blocker:
                    self.log.append(f"{device}: full resync refused: {blocker}")
                    return
                row = self.devices[device].vault.db.fetchone("SELECT version FROM entries WHERE id = ?", (obj,))
                # Its own unsent change (a deleted folder's entry, say) can hold
                # that version number already: not the forgery.
                own = row and row["version"]
                try:
                    client.full_resync(confirmed=True)
                    outcome = "full resync done"
                except REFUSALS as exc:
                    outcome = f"refused: {exc}"
                row = self.devices[device].vault.db.fetchone("SELECT version FROM entries WHERE id = ?", (obj,))
                held = row and row["version"] if (row and row["version"]) != own else None
            else:
                tab = WebTab(self.url, self.tmp / "web-leaked.log")
                try:
                    result = tab.do("login", username="admin", password=self._account_password(), confirm=True)
                finally:
                    tab.kill()
                outcome = f"refused: {result['error']}" if result["error"] else "signed in"
                held = version if result["error"] is None or obj not in str(result["error"]) else None
        finally:
            # By id, not by the dicts above: a request that rolled back in
            # between put the memory database's deep copy from its start in
            # their place, the forgery with it (deep stateful run on c6d3dff).
            for row in storage["vault_objects"]:
                if row.get("id") == obj:
                    row.clear()
                    row.update(copy.deepcopy(original))
            restore = {a.get("id"): bound for a, bound in zip(archives, bounds)}
            for archive in storage.get("user_key_archives", []):
                if archive.get("id") in restore:
                    archive["retired_seq"] = restore[archive.get("id")]
        self.log.append(f"   -> {outcome}")
        coverage_event(f"leaked retired key ({how}): {outcome.split(':')[0]}")
        assert held != version, (
            f"{how}: took {obj} v{version}, signed by {user_id}'s retired key after its rotation\n"
            + self._trace())
        if how == "full_resync" and outcome == "full resync done":
            self._observe(device)

    def _withhold_archives_from_a_new_device(self) -> None:
        """Run 157: only the re-key archive ties a folder's new key to the one
        it retired, and both name the folder. A new device whose first pull
        lacks the archives must not take the retired key (the removed
        member's) for the folder's own."""
        archives = sorted(o["id"] for o in self.db._storage["vault_objects"]
                          if o.get("object_type") == "dek_archive" and not o.get("is_deleted"))
        if not archives:
            return
        name = self._token("fresh")
        try:
            with _withholding_rekey_archives():
                vault = self._new_vault(self.tmp / name)
        except REFUSALS as exc:
            self.log.append(f"server: withholds re-key archives from new device {name}: refused: {exc}")
            return
        coverage_event("server withholds re-key archives from a new device")
        # An archive names only the successor, so the honest new device's
        # binding is the reference (run 158).
        stale = [(row["id"], row["dek_id"], self.fresh_bindings[row["id"]])
                 for row in vault.db.fetchall("SELECT id, dek_id FROM nodes")
                 if row["id"] in self.fresh_bindings and row["dek_id"] != self.fresh_bindings[row["id"]]]
        self.log.append(f"server: withholds re-key archives {archives} from new device {name}")
        vault.lock()
        assert not stale, (
            f"new device {name}: with the re-key archives withheld, folders (id, key, honest key) "
            f"{stale} took another key than on an honest new device\n" + self._trace())

    # ── server: time and backups ──

    @rule()
    def gc_tombstones(self):
        """The GC window passed for every tombstone the server holds now."""
        from server.app.main import _cleanup_tombstones

        objects = self.db._storage["vault_objects"]
        for obj in objects:
            if obj.get("is_deleted"):
                obj["modified_at"] = 0
        before = {obj["id"] for obj in objects}
        asyncio.run(_cleanup_tombstones(self.db, 0))
        gone = before - {obj["id"] for obj in self.db._storage["vault_objects"]}
        for obj in gone:
            self.collected[obj] = set(self.server_known.pop(obj, ()))
        self.log.append(f"server: tombstone GC collected {sorted(gone)}")

    @rule()
    def server_backup(self):
        self.backup = (copy.deepcopy(self.db._storage), copy.deepcopy(self.server_known))
        self.log.append("server: backup")

    @precondition(lambda self: self.backup is not None)
    @rule()
    def server_restore(self):
        """The operator restores the server database from the last backup."""
        storage, server_known = copy.deepcopy(self.backup)
        # The team log records the restore takes from the server (goal #442).
        def hashes(rows):
            return {teamlog.record_hash({"body": r["body"], "sig": r["sig"]}) for r in rows}
        self.lost_by_restore = getattr(self, "lost_by_restore", set()) | (
            hashes(self.db._storage.get("team_log", [])) - hashes(storage.get("team_log", [])))
        self.db._storage.clear()
        self.db._storage.update(storage)
        self.server_known = server_known
        # What GC took stays taken from the devices that dropped it (a full
        # resync leaves out what the server no longer had), even if the
        # backup still holds the tombstone.
        self.log.append("server: restored from backup")

    @precondition(lambda self: len(self.devices) < MAX_DEVICES)
    @rule()
    def connect_another_device(self):
        self._add_device("C")

    # ── a second process on the same vault (the GUI or 'mcp-serve' left open) ──

    @rule(data=st.data())
    def open_second_process(self, data):
        """It unlocks with the password of the moment and keeps that KEK in
        memory while the CLI goes on changing keys (review d615826 H4)."""
        device = self._pick(data, [d for d in self.devices if d not in self.second], "device")
        if device is None:
            return
        process = Vault(self.tmp / device)
        process.unlock(self.devices[device].password)
        self.second[device] = process
        self.log.append(f"{device}: second process unlocked")

    @precondition(lambda self: self.second)
    @rule(data=st.data(), op=st.sampled_from(["add folder", "add entry", "edit"]))
    def second_process_write(self, data, op):
        """A write from the second process: done under the keys the vault has
        now, or refused - never a key wrapped under a KEK the vault left."""
        device = data.draw(st.sampled_from(sorted(self.second)), label="device")
        process = self.second[device]
        name = self._token("E" if op != "add folder" else "F")
        if op == "add folder":
            parent = self._pick(data, self._folders(device) + ["ROOT"], "parent")
            action = lambda v: v.create_node(name, None if parent == "ROOT" else parent)  # noqa: E731
        else:
            target = self._pick(data, self._folders(device) if op == "add entry" else self._entries(device), "target")
            if target is None:
                return
            fields = [{"key": "password", "value": name, "sensitive": True}]
            action = (  # noqa: E731
                (lambda v: v.create_entry(target, name, fields)) if op == "add entry"
                else (lambda v: v.update_entry(target, name=name, fields=fields))
            )
        vault = self.devices[device].vault
        before = snapshot(vault)
        try:
            action(process)
        except VaultChangedElsewhere as exc:
            coverage_event("second process refused: keys changed elsewhere")
            self.log.append(f"{device}: second process {op} refused ({exc}); it is closed")
            with contextlib.suppress(Exception):
                process.lock()
            del self.second[device]
            assert snapshot(vault) == before, f"{device}: a refused write changed the vault\n" + self._trace()
            return
        coverage_event(f"second process {op}")
        self.log.append(f"{device}: second process {op} {name}")
        self._record_local_change(device, before, snapshot(vault))

    @precondition(lambda self: self.second)
    @rule(data=st.data())
    def second_process_pull(self, data):
        """A pull from the second process (review 7c10379): with a KEK the
        vault left it judged our new DEKs foreign for good. Refused, or done
        with no DEK of this vault's KEK on the foreign list."""
        device = data.draw(st.sampled_from(sorted(self.second)), label="device")
        process = self.second[device]
        vault = self.devices[device].vault
        client = SyncClient(process.db, self.url, process.keypair, process.db.get_meta("user_id"))
        client.set_dek_manager(process.dek_mgr)
        before = snapshot(vault)
        try:
            client.pull()
        except VaultChangedElsewhere as exc:
            coverage_event("second process pull refused: keys changed elsewhere")
            self.log.append(f"{device}: second process pull refused ({exc}); it is closed")
            with contextlib.suppress(Exception):
                process.lock()
            del self.second[device]
            assert snapshot(vault) == before, f"{device}: a refused pull changed the vault\n" + self._trace()
        except Exception as exc:  # the CLI's own pulls surface what the server says
            coverage_event(f"second process pull raised {type(exc).__name__}")
            self.log.append(f"{device}: second process pull raised {type(exc).__name__}: {exc}")
        else:
            coverage_event("second process pull")
            self.log.append(f"{device}: second process pull")
        # The harm itself, whatever the pull did (review run 182).
        self._assert_no_own_dek_foreign(device, "by the second process")
        self._pull(device)
        self._assert_no_own_dek_foreign(device, "after the vault's own pull")

    def _assert_no_own_dek_foreign(self, device: str, when: str) -> None:
        """No DEK the vault's KEK opens may sit on its foreign list: every
        later key change, re-key and unlock skips what is there."""
        vault = self.devices[device].vault
        foreign = set(vault.db.get_meta_json("foreign_dek_ids") or [])
        ours = [
            row["id"] for row in vault.db.fetchall("SELECT id, encrypted_dek, version FROM deks")
            if row["id"] in foreign
            and vault.dek_mgr.can_unwrap(row["id"], row["encrypted_dek"], row["version"])
        ]
        assert not ours, f"{device}: own DEKs {ours} marked foreign {when}\n" + self._trace()

    @rule(data=st.data())
    def settle(self, data):
        # Nightly run on 782dde8 (second admin, FlakyStrategyDefinition): the
        # number of conflicts a settle meets can differ between two runs of the
        # same steps, and one draw per conflict made the draws differ too. The
        # choices are drawn up front, always the same number of them.
        keeps = data.draw(st.lists(st.sampled_from(["local", "server"]), min_size=8, max_size=8),
                          label="keep (n-th conflict)")
        order: dict[str, int] = {}
        self._settle(lambda obj: keeps[order.setdefault(obj, len(order)) % len(keeps)])

    # ── invariants ──

    def _discard_changes_for_departed_members(self, device: str) -> None:
        """The way out 'sezam team-log queue' shows for a change set aside as
        not_active: its member left the team (another admin device removed
        them) before this device's change went out (deep run, R16-Z SM15).
        'sezam team-log discard N' drops that change alone, 'sezam team-log
        retry' sends again the folder keys made with it. Any other refusal
        stays and keeps the settle red."""
        client = self.devices[device].client
        aside = client.set_aside_team_changes()
        moot = [n for n, item in enumerate(aside, 1)
                if item["reason"].endswith(": not_active") and not item["reason"].startswith("goes with")]
        if not moot:
            return
        client.discard_set_aside_team_changes(moot)
        self.log.append(f"{device}: team-log discard {moot} (their member left the team)")
        if any(item["reason"].startswith("goes with") for item in client.set_aside_team_changes()):
            client.retry_set_aside_team_changes()
            self.log.append(f"{device}: team-log retry")

    def _settle(self, choose) -> None:
        self.log.append("-- settle --")
        for _ in range(SETTLE_ROUNDS):
            for user_id in self._member_desktops():
                self._member_sync(user_id)
            for device in sorted(self.devices):
                self._push(device)
                self._pull(device)
                if device in self.resync_due:
                    self._full_resync(device)
                for conflict in self.devices[device].client.get_pull_conflicts():
                    self._resolve(device, conflict["id"], choose(conflict["id"]))
                self._discard_changes_for_departed_members(device)
            if self.web is not None:
                self._web_settle()
            for device in sorted(self.devices):
                self._pull(device)
            if self.web is not None and not self.web_ended:
                self._web_pulled(self._web_do("refresh", "refresh", confirm=True))
            # Quiet only when the one pending-state module lists nothing: the
            # machine knows every password, so each state has its way out here.
            quiet = not self.resync_due and not self._waiting_members() and self._web_quiet() and all(
                not _dirty_ids(dev.vault)
                and dev.client.dirty_object_count() == 0
                and not [s for s in pending_states(dev.vault) if s.key not in self.ADVISORY]
                and not rekey_batch(dev.vault.db)  # an identity rotation's too
                for dev in self.devices.values()
            )
            views = {name: _live(snapshot(dev.vault)) for name, dev in self.devices.items()}
            if self.web is not None and not self.web_ended:
                views[WEB] = self._web_snap(self.web_view)
            if quiet and len({repr(sorted(v.items())) for v in views.values()}) == 1:
                break
        else:
            details = {
                name: {
                    "dirty": sorted(_dirty_ids(dev.vault)),
                    "pending": {s.key: f"{s.summary} Way out: {s.resolve}" for s in pending_states(dev.vault)},
                }
                for name, dev in self.devices.items()
            }
            for user_id in self._waiting_members():
                details[self.members[user_id].name] = "waits for the team log records the server lost"
            if self.web is not None:
                details[WEB] = {"session ended": self.web_ended, "dirty": self.web_view.get("dirty"),
                                "conflicts": self.web_view.get("conflicts")}
            raise AssertionError(
                f"sync did not settle in {SETTLE_ROUNDS} rounds: {details}\n"
                + _diff_views(views) + "\n" + self._trace()
            )
        self._check_members()
        self._check_member_desktops()
        self._check_nothing_lost()
        self._check_devices_unlock()
        self._check_org_recovery_told()

    def _check_members(self) -> None:
        """A revoked member holds no key to anything live; an active one opens
        every envelope of theirs and still has every folder shared with them."""
        reference = self.devices[sorted(self.devices)[0]].vault
        objects = self.db._storage.get("vault_objects", [])
        live = [o for o in objects if not o.get("is_deleted")]
        content_dek: dict[str, str] = {}
        for obj in live:
            if obj["object_type"] in ("node", "entry") and obj.get("parent_ref") is not None:
                payload = bytes(obj["payload"])
                if obj["object_type"] == "entry":
                    payload = payload[4:4 + int.from_bytes(payload[:4], "big")]
                content_dek[obj["id"]] = bytes_to_ulid(parse_envelope(payload).dek_id)
        for user_id, member in sorted(self.members.items()):
            envelopes = [o for o in live if o["object_type"] == "envelope"
                         and o.get("target_user_id") == user_id]
            status = self._member_status(user_id)
            if user_id in self.revoked and status == "revoked":
                assert not envelopes, (
                    f"revoked member {member.name} still has live envelopes "
                    f"{[o['id'] for o in envelopes]}\n" + self._trace()
                )
                # Seed 626262: what an account the server made up wrote under
                # the folder's old key holds no secret of anybody's, and every
                # device refuses it (no_folder_a_made_up_account_wrote): no
                # re-key ever reseals it on the server.
                exposed = sorted(o for o, dek in content_dek.items()
                                 if dek in self.member_deks[user_id] and o not in self.forged_by_made_up)
                assert not exposed, (
                    f"revoked member {member.name} holds the key of live objects {exposed}\n" + self._trace()
                )
                continue
            if status != "active":
                continue
            member_keys: dict[str, bytes] = {}
            for envelope in envelopes:
                dek = None
                for pk in self.admin_pks | getattr(self, "member_pks", set()):
                    with contextlib.suppress(Exception):
                        dek = bytes(open_envelope(bytes(envelope["payload"]), member.encryption_sk, pk))
                        break
                assert dek is not None, (
                    f"member {member.name} cannot open envelope {envelope['id']} "
                    f"(DEK {envelope.get('parent_ref')})\n" + self._trace()
                )
                assert dek == bytes(reference.dek_mgr.unlock_dek(envelope["parent_ref"])), (
                    f"envelope {envelope['id']} of {member.name} holds another key than "
                    f"DEK {envelope.get('parent_ref')}\n" + self._trace()
                )
                member_keys[envelope["parent_ref"]] = dek
            if user_id in self.revoked:
                continue  # a server restore brought the member back: not a grant this run made
            shared = {o.get("parent_ref") for o in envelopes}
            for folder in sorted(self.granted[user_id]):
                row = reference.db.fetchone(
                    "SELECT dek_id FROM nodes WHERE id = ? AND is_deleted = 0", (folder,)
                )
                if row is None:
                    continue
                assert row["dek_id"] in shared, (
                    f"member {member.name} lost the shared folder {folder}: no live envelope for "
                    f"its DEK {row['dek_id']}\n" + self._trace()
                )
            self._check_member_reads(member, member_keys, reference, live, content_dek)

    def _check_member_reads(self, member, member_keys, reference, live, content_dek) -> None:
        """Every live item sealed under a granted folder's key (its entries, its
        subfolders' names, the content of subfolders sharing its DEK; not tier-2
        entries) opens on the server with a key from the member's envelopes."""
        folder_deks = {
            row["dek_id"]
            for folder in self.granted[member.user_id]
            for row in reference.db.fetchall(
                "SELECT n.dek_id FROM nodes n JOIN deks d ON d.id = n.dek_id "
                "WHERE n.id = ? AND n.is_deleted = 0 AND d.node_id = n.id", (folder,)
            )
        }
        for obj in live:
            if obj["id"] not in content_dek:
                continue
            parent = reference.db.fetchone(
                "SELECT dek_id FROM nodes WHERE id = ? AND is_deleted = 0", (obj["parent_ref"],)
            )
            if parent is None or parent["dek_id"] not in folder_deks:
                continue
            dek_id = content_dek[obj["id"]]
            scope = reference.db.fetchone("SELECT scope FROM deks WHERE id = ?", (dek_id,))
            if obj["object_type"] == "entry" and scope is not None and scope["scope"] == "tier2":
                continue
            assert dek_id in member_keys, (
                f"member {member.name} cannot decrypt {obj['object_type']} {obj['id']} in a "
                f"folder shared with them: it is under DEK {dek_id}, their envelopes hold "
                f"{sorted(member_keys)}\n" + self._trace()
            )
            payload = bytes(obj["payload"])
            kind = BlobKind.NODE_META
            if obj["object_type"] == "entry":
                payload = payload[4:4 + int.from_bytes(payload[:4], "big")]
                kind = BlobKind.ENTRY_META
            try:
                open_sealed(payload, member_keys[dek_id], obj["id"], obj["version"], kind, deleted=False)
            except Exception as exc:  # noqa: BLE001
                raise AssertionError(
                    f"member {member.name} holds DEK {dek_id} but {obj['object_type']} "
                    f"{obj['id']} v{obj['version']} does not open with it: {exc!r}\n" + self._trace()
                ) from exc

    def _check_devices_unlock(self) -> None:
        """Every device opens with the password the account has now."""
        account = self._account_password()
        for name, dev in sorted(self.devices.items()):
            assert dev.password == account, (
                f"{name} still unlocks with {dev.password!r}, the account's password is "
                f"{account!r}, and nothing asked to take the change over\n" + self._trace()
            )
            dev.vault.lock()
            try:
                dev.vault.unlock(dev.password)
            except Exception as exc:
                raise AssertionError(
                    f"{name} does not unlock with {dev.password!r}: {exc!r}\n" + self._trace()
                ) from exc
            dev.client = self._new_client(dev.vault)
        if self.web is not None:
            # A new tab on the same browser signs in with it and shows the same.
            shown = self._web_snap(self.web_view)
            self._web_reload()
            assert self._web_snap(self.web_view) == shown, (
                "W: a reload shows another vault\n"
                + _diff_views({"before": shown, "after reload": self._web_snap(self.web_view)})
                + "\n" + self._trace()
            )

    def _check_nothing_lost(self) -> None:
        admins = snapshot(self.devices[sorted(self.devices)[0]].vault)
        # What a member wrote on their desktop is theirs: the admins hold no
        # key for it, so it is checked on that desktop.
        members = {m.name: self._member_snap(m) for m in self.members.values() if m.vault is not None}
        for event in self.events.values():
            if event.kind == "genesis":
                continue
            reference = members.get(event.device, admins)
            final = reference.get(event.obj)
            if event.id in self.traced:
                continue  # discarded in a conflict the user resolved
            if event.obj in self.collected and (
                event.id in self.collected[event.obj]
                # Run on d994f32: or a full resync of a device that deleted it
                # too sent its own tombstone again (other content, still deleted).
                or ((final is None or not final[0]) and (not event.state[0] or self._deleted_later(event)))
            ):
                continue  # the delete it led to (or was) aged out of the server
            assert final is not None, (
                f"{event.obj} ({event.state}) written on {event.device} is gone everywhere\n"
                + self._trace()
            )
            closure = self._closure(event.obj, final)
            if event.id in self.traced or event.id in closure:
                continue
            if self.producers[(event.obj, event.state)] & closure:
                # Another device wrote the very same state (both deleted the
                # same entry) and the settled state builds on that: the same.
                continue
            if not event.state[0] and not final[0] and self.producers.get(
                (event.obj, (True,) + tuple(event.state[1:])), set()
            ) & closure:
                # Two deletes, one over a later edit: the trash keeps the
                # newer content and this delete carried nothing newer.
                continue
            if not final[0] and final[1] == event.state[1] and (
                not event.state[0] or self._deleted_later(event)
            ):
                # Deleted here and elsewhere with the same content (the other
                # device through a parent folder): only the place in the trash
                # differs, and a move this device deleted afterwards with it.
                continue
            if (
                event.kind == "auto"
                and event.state[2] == "ROOT"
                and final[2] in reference
                and (final[:2] == event.state[:2] or any(
                    self.events[e].kind == "write" and self.events[e].obj == event.obj
                    and self.events[e].state[:2] == event.state[:2] for e in closure
                ))
            ):
                # The sync hung an orphan below the root while its folder was
                # gone; the folder came back and holds it again, same content.
                # Seed 858585 on 4b961eb: or content another device edited
                # later, on top of the write the orphan showed (never sent).
                continue
            if not event.state[0] and final[0]:
                # A delete undone (e.g. a folder another device saved work in
                # meanwhile comes back): nothing is lost, the item is visible.
                continue
            raise AssertionError(
                f"{event.device}'s change of {event.obj} to {event.state} was lost without a "
                f"conflict: the settled state is {final}\n" + self._trace()
            )

    def _deleted_later(self, event: Event) -> bool:
        """A delete of the same object was made knowing this write."""
        return any(
            other.obj == event.obj and not other.state[0] and event.id in other.known
            for other in self.events.values()
            if other.id != event.id
        )

    def _check_new_device_matches(self) -> None:
        expected = _live(snapshot(self.devices[sorted(self.devices)[0]].vault))
        vault = self._new_vault(self.tmp / "fresh")
        try:
            self.fresh_bindings = {row["id"]: row["dek_id"]
                                   for row in vault.db.fetchall("SELECT id, dek_id FROM nodes")}
            got = _live(snapshot(vault))
            assert got == expected, (
                "a new device sees a different vault\n"
                + _diff_views({"settled": expected, "new device": got}) + "\n" + self._trace()
            )
        finally:
            vault.lock()


def _diff_views(views: dict[str, dict]) -> str:
    lines = []
    objects = sorted(set().union(*(v.keys() for v in views.values())))
    for obj in objects:
        states = {name: view.get(obj) for name, view in views.items()}
        if len(set(states.values())) > 1:
            lines.append(f"  {obj}: {states}")
    return "differences:\n" + ("\n".join(lines) or "  (none)")


@pytest.fixture(scope="module")
def loopback_server(tmp_path_factory):
    server = _Server(tmp_path_factory.mktemp("sm_server"))
    yield server
    server.close()


def test_sync_state_machine(loopback_server):
    SyncMachine.server = loopback_server
    run_state_machine_as_test(
        SyncMachine,
        settings=settings(
            max_examples=DEEP or 12,
            stateful_step_count=25,
            deadline=None,
            derandomize=not DEEP,
            database=None,
            suppress_health_check=list(HealthCheck),
            print_blob=True,
        ),
    )


class SecondAdminMachine(SyncMachine):
    """Starts with a second admin: random runs seldom get there (an invite, a
    member sync and the appointment first), and its revocation of a member
    the first admin shared with needs a second member on top."""

    def __init__(self):
        super().__init__()
        admin = self._active_members()[0]
        self._member_sync(admin)
        self._invite_member("A")
        member = next(u for u in self._active_members() if u != admin)
        self._grant("A", member, self._folders("A")[0], "write")
        self._appoint(admin)


class TeamLogMachine(SyncMachine):
    """The same steps in an organisation with a team log (review e443cbc R15,
    goal #429): the admin founds it right after the first member joined, every
    member confirms the founder's fingerprint, and from then on grants,
    revocations, rotations and appointments go through the log."""

    # Its way out ('sezam org-recovery-setup') is the setup_org_recovery step;
    # it sends nothing and holds nothing back.
    ADVISORY = frozenset({"lone_admin_without_recovery"})
    # The organisation shared its top folder before it had a log.
    GRANT_BEFORE_FOUNDING = False

    def __init__(self):
        from sezam.vault.team_migration import found_team_log

        # Members whose last sync stopped because the server's log went back
        # (a restored server): they wait, fail-closed, until an admin device
        # puts the lost records back; a settle does not end while one waits.
        self.waiting: set[str] = set()
        # Members whose confirm-founder was refused (the admin's shown key is
        # not in the log yet); they ask again before their next sync.
        self.unconfirmed: set[str] = set()
        super().__init__()
        if self.GRANT_BEFORE_FOUNDING:
            self._grant("A", self._active_members()[0], self._folders("A")[0], "read")
        admin = self.devices["A"]
        result = found_team_log(admin.vault, admin.client, lambda _uid, _fp: True)
        self.log.append(f"A: team-log init ({len(result.members)} member(s), {len(result.folders)} folder(s))")

    def _waits_for_lost_log(self, device: str, exc: Exception) -> bool:
        """INV-8 for the admin's own devices (deep run on 8914bac): one that
        pins the log without a copy of it (the account keys it took over carry
        the confirmed genesis) cannot put back a log the server lost, and
        forgets no pin on its own; it waits, fail-closed, for a device holding
        the log (INV-7). One holding a copy puts it back and does not wait."""
        from sezam.vault.team_log_local import TeamLogMismatch

        if self._server_log() or not isinstance(exc, TeamLogMismatch):
            return False
        if exc.cause not in ("log_gone", "confirmed_genesis"):
            return False
        if self.devices[device].vault.db.fetchall("SELECT seq FROM team_log LIMIT 1"):
            return False
        coverage_event("an admin device without the log waits for it to come back")
        self.log.append(f"{device}: waits for the lost team log, {exc.cause}")
        return True

    def _waiting_members(self) -> set[str]:
        return self.waiting & set(self._member_desktops())

    def _member_sync(self, user_id: str) -> None:
        from sezam.vault.team_log_local import TeamLogMismatch

        # A revoked member asks nothing: its sync is refused (super), and its
        # refused login made confirm-founder raise (randomized run).
        if user_id in self.unconfirmed and self._member_status(user_id) == "active":
            self._confirm_founder(user_id)
            if user_id in self.unconfirmed:
                # Fail-closed: no sync on a log whose founder it cannot check.
                self.log.append(f"{self.members[user_id].name}: waits for the founder's key in the log")
                self.waiting.add(user_id)
                return
        try:
            super()._member_sync(user_id)
        except AssertionError as exc:
            cause = exc.__cause__
            sibling = self._rotation_the_log_waits_for()
            if sibling is not None and "invalid signature" in str(cause):
                # The server signs the admin in with a key the log retired and
                # serves it without its bound: nothing signed with it checks.
                coverage_event("member waits for an admin rotation the log names")
                self.log.append(f"{self.members[user_id].name}: waits for {sibling}'s identity rotation, {cause}")
                self.waiting.add(user_id)
                return
            # R16-H1: a fork that left out a change it saw is followed once the
            # change's author makes it again (deep stateful run on c6d3dff):
            # it waits as for lost records; teardown checks it ends.
            author_remakes = "once its author makes that change again" in str(cause)
            # A copy from before the admin's identity rotation does not put a
            # lost log back (the server refuses the retired key, R15 #429): the
            # member keeps its pin until an admin device does (deep run on 0daf5f2).
            gone = getattr(cause, "cause", None) == "log_gone" and not self._server_log()
            if not (isinstance(cause, TeamLogMismatch) and (cause.cause == "went_back" or author_remakes or gone)):
                raise
            coverage_event("member waits for the lost team log records")
            self.log.append(f"{self.members[user_id].name}: waits, {cause}")
            self.waiting.add(user_id)
            return
        self.waiting.discard(user_id)

    def _confirm_founder(self, user_id: str) -> None:
        """'sezam team-log confirm-founder <fp>' on the member's desktop, with the
        fingerprint 'sezam fingerprint' shows on one of the admin's devices.

        As the CLI, it refreshes the log and trusts only a fingerprint linked to
        the founder's genesis identity: a key from a rotation whose push failed
        is not in the log yet, so the member waits and asks again later.
        """
        from sezam.crypto.keys import compute_fingerprint
        from sezam.vault.sync_common import CONFIRMED_MEMBER_KEYS_META
        from sezam.vault.team_log_state import founder_key_lineage

        vault = self.members[user_id].vault
        client = self._new_client(vault)
        client._refresh_team_log()
        shown = None
        if client.team_state() is not None:
            founder_id, known = founder_key_lineage(vault.db)
            linked = {compute_fingerprint(bytes.fromhex(spk), bytes.fromhex(epk)) for spk, epk in known}
            shown = next((dev.vault.keypair.fingerprint for dev in self.devices.values()
                          if dev.vault.keypair.fingerprint in linked), None)
        if shown is None:
            coverage_event("confirm-founder refused: the admin's key is not in the log yet")
            self.log.append(f"{self.members[user_id].name}: confirm-founder refused, the admin's key is not in the log yet")
            self.unconfirmed.add(user_id)
            return
        confirmed = vault.db.get_meta_json(CONFIRMED_MEMBER_KEYS_META) or {}
        confirmed[founder_id] = shown
        vault.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, confirmed)
        self.unconfirmed.discard(user_id)

    def _invite_member(self, device: str) -> None:
        from sezam.vault.team_log_local import TeamLogMismatch

        try:
            super()._invite_member(device)
        except TeamLogMismatch as exc:
            # INV-7: no invitation onto a log this device refuses (a pinned
            # log the server lost); a device holding it puts it back.
            self.log.append(f"{device}: invite refused, {exc.cause}")
            return
        self._confirm_founder(next(reversed(self.members)))

    def teardown(self):
        # Every example ends under attack, whatever its steps drew (capability
        # run 430 probe on cd6d473: no example of the derandomized run reached
        # a forgery only not_admin refuses).
        try:
            if hasattr(self, "db") and self.devices:
                self._attack_the_log()
        finally:
            super().teardown()

    def _attack_the_log(self) -> None:
        """Each forgery a member can sign, posted to append and to restore and
        served as a forged record to every device holding the log."""
        before = self._server_log()
        forgers = self._forgers(teamlog.replay(before)) if before else []
        if not forgers:
            return
        state = teamlog.replay(before)
        for kind in self.FORGERIES:
            for path in ("append", "restore"):
                self._post_forgery(state, before, forgers[0], kind, path)
            for name, vault in self._log_vaults():
                self._serve_a_lie(name, vault, "forged record", kind)
                self.every_device_holds_one_log()
        self.the_server_log_follows_the_rules()

    # ── The log itself under attack (capability run 430) ─────────────
    # A member signs records the rules refuse and sends them to append and to
    # restore; the server serves forks, gaps, reorders, forged records and
    # false heads. The invariants below hold after every step: a broken rule
    # on the server or in a client turns this machine red.

    FORGERIES = (
        "grant self", "appoint self", "add made-up admin", "sign as the admin",
        "take the admin's key", "rotate onto own key",
    )
    LOG_LIES = ("truncate", "drop a record", "reorder", "forged record", "old head", "other genesis")

    def _server_log(self) -> list[dict]:
        rows = sorted(self.db._storage.get("team_log", []), key=lambda r: r["seq"])
        return [{"body": r["body"], "sig": r["sig"]} for r in rows]

    def _forged_hashes(self) -> set[str]:
        return getattr(self, "forged", set())

    def _log_vaults(self) -> list[tuple[str, object]]:
        return [(name, dev.vault) for name, dev in sorted(self.devices.items())] + [
            (m.name, m.vault) for _, m in sorted(self.members.items()) if m.vault is not None
        ]

    def _log_holders(self) -> list[tuple[str, object]]:
        return [(n, v) for n, v in self._log_vaults() if v.db.fetchone("SELECT seq FROM team_log LIMIT 1")]

    def _forgers(self, state) -> list[str]:
        return [u for u in self._member_desktops()
                if u in state.members and state.members[u].active and not teamlog.is_admin(state, u)]

    def _forge(self, state, user_id: str, kind: str) -> dict:
        from nacl.public import PrivateKey

        own = self.members[user_id].vault.keypair.to_nacl_signing_key()
        admin = next(u for u in state.members if teamlog.is_admin(state, u))
        fresh = SigningKey.generate()
        fresh_pk = bytes(fresh.verify_key).hex()
        enc_pk = bytes(PrivateKey.generate().public_key).hex()
        folder = next(iter(sorted(state.folders)), None)
        author, signer = user_id, own
        if kind == "grant self" and folder is not None:
            level = "read" if state.access.get(folder, {}).get(user_id) == "write" else "write"
            change, data = "access.set", {"folder": folder, "user_id": user_id, "level": level}
        elif kind == "sign as the admin" and folder is not None:
            level = "read" if state.access.get(folder, {}).get(user_id) == "write" else "write"
            change, data = "access.set", {"folder": folder, "user_id": user_id, "level": level}
            author = admin
        elif kind == "add made-up admin":
            change, data = "member.add", {
                "user_id": new_ulid(), "signing_pk": fresh_pk, "encryption_pk": enc_pk, "role": "admin"}
        elif kind in ("take the admin's key", "rotate onto own key"):
            if kind == "take the admin's key":
                spk, epk, key = fresh_pk, state.members[admin].encryption_pk, fresh
            else:
                spk, epk, key = state.members[user_id].signing_pk, enc_pk, own
            proof = key.sign(teamlog.new_key_message(state.head_hash, user_id, spk, epk)).signature
            change, data = "member.keys", {
                "user_id": user_id, "signing_pk": spk, "encryption_pk": epk, "new_key_sig": proof.hex()}
        else:  # appoint self (also a grant while no folder is in the log yet)
            change, data = "member.role", {"user_id": user_id, "role": "admin"}
        return teamlog.sign_record(teamlog.next_body(state, change, author, data), signer)

    @precondition(lambda self: self._member_desktops())
    @rule(data=st.data())
    def member_forges_a_log_record(self, data):
        """A member signs every record the rules refuse and posts each to
        append and to restore (INV-1/INV-2: restore takes no more than append).
        A refused record changes nothing, so one step tries them all: drawn
        one at a time, the 8 derandomized examples reached one forgery and
        missed a broken not_admin rule (capability run 430 probe on cd6d473)."""
        before = self._server_log()
        state = teamlog.replay(before)
        user_id = self._pick(data, self._forgers(state), "forger")
        if user_id is None:
            return
        for kind in self.FORGERIES:
            for path in ("append", "restore"):
                self._post_forgery(state, before, user_id, kind, path)

    def _post_forgery(self, state, before: list[dict], user_id: str, kind: str, path: str) -> None:
        record = self._forge(state, user_id, kind)
        self.forged = self._forged_hashes() | {teamlog.record_hash(record)}
        client = self._new_client(self.members[user_id].vault)
        url = "/api/team-log" + ("/restore" if path == "restore" else "")
        try:
            client._request("POST", url, {"records": [record]}, auth=True)
        except Exception as exc:  # refused: what must happen
            outcome = f"refused ({type(exc).__name__})"
        else:
            raise AssertionError(
                f"the server took a {kind!r} record from {self.members[user_id].name} via {path}: "
                f"{record['body']}\n" + self._trace())
        coverage_event(f"member forges {kind} via {path}")
        self.log.append(f"{self.members[user_id].name}: forges {kind} -> {path} {outcome}")
        assert self._server_log() == before, f"a refused {path} changed the server's log\n" + self._trace()

    # Histories from genesis a member uploads onto a log the server lost
    # (capability run 433, review e443cbc H3): the restore's own checks
    # (founder, stolen keys, an admin on the way) are what refuses them.
    LOST_LOG_FORGERIES = (
        "own genesis", "made-up founder", "genesis under the admin's id", "second admin mid-history",
        "stolen admin key, second admin on the way",
    )

    def _key_the_log_names(self, state, user_id: str) -> SigningKey:
        """The signing key a copy of the log trusts for an account: current on
        one of its devices, or retired since by an identity rotation (a copy
        that has not seen the rotation still names the old key)."""
        keys = [v.keypair.to_nacl_signing_key() for _, v in self._log_vaults()
                if v.db.get_meta("user_id") == user_id]
        keys += [key for uid, key in self.leaked_signers if uid == user_id]
        return next(k for k in keys if bytes(k.verify_key).hex() == state.members[user_id].signing_pk)

    def _local_log(self, user_id: str) -> list[dict]:
        rows = self.members[user_id].vault.db.fetchall("SELECT body, sig FROM team_log ORDER BY seq")
        return [{"body": r["body"], "sig": r["sig"]} for r in rows]

    def _lost_log_forgers(self) -> dict[str, list[dict]]:
        """Members not admin in their own copy of the log, with that copy.

        Not a member the operator flagged admin on the server: with no log
        there, the flag is what lets an account found one (as 'team-log init'
        does), and every device pinned to the lost genesis refuses the new
        one (other_genesis, INV-8)."""
        forgers = {}
        for user_id in self._member_desktops():
            if self._is_admin(user_id):
                continue
            local = self._local_log(user_id)
            try:
                state = teamlog.replay(local)
            except teamlog.TeamLogError:
                continue
            member = state.members.get(user_id)
            if local and member is not None and member.active and not teamlog.is_admin(state, user_id):
                forgers[user_id] = local
        return forgers

    def _forge_history(self, local: list[dict], user_id: str, kind: str) -> list[dict]:
        from nacl.public import PrivateKey

        state = teamlog.replay(local)
        if kind in self.FORGERIES:  # the member's true copy, one forged record on top
            return local + [self._forge(state, user_id, kind)]
        own = self.members[user_id].vault.keypair.to_nacl_signing_key()
        me = state.members[user_id]
        admin = next(u for u in state.members if teamlog.is_admin(state, u))
        fresh = SigningKey.generate()
        fresh_pk = bytes(fresh.verify_key).hex()

        def genesis(founder, spk, epk, key):
            data = {"org": state.org, "user_id": founder, "signing_pk": spk, "encryption_pk": epk}
            return [teamlog.sign_record(teamlog.next_body(teamlog.TeamState(), "genesis", founder, data), key)]

        def then(records, change, author, data, key):
            body = teamlog.next_body(teamlog.replay(records), change, author, data)
            return records + [teamlog.sign_record(body, key)]

        if kind == "stolen admin key, second admin on the way":
            # The true copy, then the admin (its real key, stolen) appoints the
            # member and the member demotes the admin: one admin at the end,
            # two between the authors, which no append takes.
            stolen = self._key_the_log_names(state, admin)
            records = then(local, "member.role", admin, {"user_id": user_id, "role": "admin"}, stolen)
            return then(records, "member.role", user_id, {"user_id": admin, "role": "member"}, own)
        if kind == "own genesis":
            return genesis(user_id, me.signing_pk, me.encryption_pk, own)
        if kind == "made-up founder":
            return genesis(new_ulid(), fresh_pk, bytes(PrivateKey.generate().public_key).hex(), fresh)
        # The admin's id on a key the member holds, the member added under it.
        records = genesis(admin, fresh_pk, state.members[admin].encryption_pk, fresh)
        records = then(records, "member.add", admin, {
            "user_id": user_id, "signing_pk": me.signing_pk, "encryption_pk": me.encryption_pk, "role": "member"}, fresh)
        if kind == "second admin mid-history":  # two admins between two authors, one at the end
            records = then(records, "member.role", admin, {"user_id": user_id, "role": "admin"}, fresh)
            records = then(records, "member.role", user_id, {"user_id": admin, "role": "member"}, own)
        return records

    @precondition(lambda self: self._member_desktops() and not self._server_log())
    @rule(data=st.data(), kind=st.sampled_from(FORGERIES + LOST_LOG_FORGERIES),
          path=st.sampled_from(["restore", "append"]))
    def member_forges_a_restore_of_the_lost_log(self, data, kind, path):
        """The server lost its log; before an honest device puts it back, a
        member uploads a history of its own making (INV-2 on the restore path:
        refused, the server's log stays empty, no forged record stored)."""
        forgers = self._lost_log_forgers()
        user_id = self._pick(data, forgers, "forger")
        if user_id is None:
            return
        records = self._forge_history(forgers[user_id], user_id, kind)
        honest = {teamlog.record_hash(r) for r in forgers[user_id]}
        self.forged = self._forged_hashes() | ({teamlog.record_hash(r) for r in records} - honest)
        client = self._new_client(self.members[user_id].vault)
        url = "/api/team-log" + ("/restore" if path == "restore" else "")
        try:
            client._request("POST", url, {"records": records}, auth=True)
        except Exception as exc:  # refused: what must happen
            outcome = f"refused ({type(exc).__name__})"
        else:
            raise AssertionError(
                f"the server took {self.members[user_id].name}'s {kind!r} history onto the lost log via {path}\n"
                + self._trace())
        coverage_event(f"member forges {kind} onto the lost log via {path}")
        coverage_event(f"restore onto a lost log: forged via {path}")
        self.log.append(f"{self.members[user_id].name}: forges {kind} onto the lost log -> {path} {outcome}")
        assert not self._server_log(), f"a refused {path} onto the lost log changed it\n" + self._trace()

    @rule(data=st.data(), lie=st.sampled_from(LOG_LIES), kind=st.sampled_from(FORGERIES))
    def server_lies_about_the_log(self, data, lie, kind):
        """The server serves one device a log the true one is not; the device
        takes nothing from it and does no emergency action by itself (INV-8).
        A 'forged record' is one of the member forgeries (kind)."""
        if not self._server_log():
            return
        targets = self._log_vaults()
        name, vault = targets[data.draw(st.integers(0, len(targets) - 1), label="target")]
        self._serve_a_lie(name, vault, lie, kind)

    def _serve_a_lie(self, name: str, vault, lie: str, kind: str) -> None:
        from sezam.vault.team_log_local import (
            CONFIRMED_GENESIS_META, GENESIS_META, queued_changes, set_aside_changes,
        )

        true = self._server_log()
        state = teamlog.replay(true)
        forger = self._forgers(state)
        forged = self._forge(state, forger[0], kind) if forger else None
        if lie == "forged record" and forged is None:
            return

        def records(path: str) -> list:
            since = int(path.split("since=")[1]) if "since=" in path else -1
            # A device that is up to date gets the whole log again (a server
            # that ignores 'since'), so a gap or a reorder has records to hit.
            served = list(true[since + 1:])
            if lie == "forged record":  # on top of what the device holds
                return served + [forged]
            served = served or list(true)
            if lie == "truncate" and served:
                served.pop()
            elif lie == "drop a record" and len(served) > 1:
                served.pop(len(served) // 2)
            elif lie == "reorder" and len(served) > 1:
                served[-1], served[-2] = served[-2], served[-1]
            return served

        def head(served: dict) -> dict:
            served = dict(served)
            if lie == "forged record":
                served.update(seq=state.head_seq + 1, hash=teamlog.record_hash(forged))
            elif lie == "old head" and state.head_seq > 0:
                served.update(seq=state.head_seq - 1, hash=teamlog.record_hash(true[-2]))
            elif lie == "other genesis":
                served["genesis_hash"] = "1" * 64
            return served

        if forged is not None:
            self.forged = self._forged_hashes() | {teamlog.record_hash(forged)}
        client = self._new_client(vault)
        real = client._request
        lied = []  # R16-Z SM21: a device whose keys were rotated away is not signed in, nor lied to

        def lying(m, path, *args, **kwargs):
            reply = real(m, path, *args, **kwargs)
            if m != "GET" or not isinstance(reply, dict):
                return reply
            lied.append(path)
            reply = dict(reply)
            if path.startswith("/api/sync") and reply.get("team_log_head"):
                reply["team_log_head"] = head(reply["team_log_head"])
            elif path.startswith("/api/team-log"):
                reply["records"] = records(path)
                if reply.get("head"):
                    reply["head"] = head(reply["head"])
            return reply

        client._request = lying
        pins = (vault.db.get_meta(GENESIS_META), vault.db.get_meta(CONFIRMED_GENESIS_META))
        work = [json.dumps(c, sort_keys=True) for c in queued_changes(vault.db)] + [
            json.dumps(c, sort_keys=True) for c in set_aside_changes(vault.db)]
        refusal = None
        try:
            client._refresh_team_log()  # the log part of a pull, without its objects
            outcome = "followed"
        except Exception as exc:  # fail-closed is fine; what it kept is checked below
            outcome = f"refused ({type(exc).__name__})"
            refusal = exc
        true_genesis = teamlog.record_hash(true[0])
        if lie == "other genesis" and lied and pins[0] == true_genesis and pins[1] in (None, true_genesis):
            # Goal #440: the head alone is unsigned; over the device's own log
            # it is a lie, never the log lost (no forget offered).
            from sezam.vault.team_log_local import MISMATCH_CAUSES, TeamLogMismatch

            assert isinstance(refusal, TeamLogMismatch) and not MISMATCH_CAUSES[refusal.cause], (
                f"{name}: a head naming another genesis over its own log -> {refusal!r}\n" + self._trace())
        coverage_event(f"server lies about the log: {lie} -> {outcome.split(' ')[0]}")
        self.log.append(f"server: {lie} in the log served to {name} -> {outcome}")
        after = (vault.db.get_meta(GENESIS_META), vault.db.get_meta(CONFIRMED_GENESIS_META))
        # A device with no pin yet may take the true genesis from true records
        # (a prefix of the log); never another one, never a confirmation.
        first_pin = pins == (None, None) and after == (teamlog.record_hash(true[0]), None)
        assert after == pins or first_pin, (
            f"{name}: a lying server's {lie} changed the log pins {pins} -> {after}\n" + self._trace())
        kept = [json.dumps(c, sort_keys=True) for c in queued_changes(vault.db)] + [
            json.dumps(c, sort_keys=True) for c in set_aside_changes(vault.db)]
        lost = [c for c in work if c not in kept]
        assert not lost, f"{name}: a lying server's {lie} dropped queued team changes {lost}\n" + self._trace()

    @rule(data=st.data(), lie=st.sampled_from([None, "truncate", "drop a record", "reorder", "old head"]))
    def user_forgets_the_pin(self, data, lie):
        """'sezam team-log forget-pin GENESIS' while the log is not lost: the
        server follows it, or lies in a way that is no lost log (a fork, a log
        going back). INV-8: refused, and the pins and the log copy stay."""
        from sezam.vault.team_log_forget import forget_team_log_pin, pinned_genesis

        targets = self._log_holders()
        if not targets or not self._server_log():
            return
        name, vault = targets[data.draw(st.integers(0, len(targets) - 1), label="target")]
        pins = pinned_genesis(vault)
        rows = [tuple(r) for r in vault.db.fetchall("SELECT seq, hash FROM team_log ORDER BY seq")]
        client = self._new_client(vault)
        if lie is not None:
            true, real = self._server_log(), client._request

            def lying(m, path, *args, **kwargs):
                reply = real(m, path, *args, **kwargs)
                if m == "GET" and path.startswith("/api/team-log") and isinstance(reply, dict):
                    served = list(true)
                    if lie == "truncate" or (lie == "old head" and len(served) > 1):
                        served.pop()
                    elif lie == "drop a record" and len(served) > 2:
                        served.pop(len(served) // 2)
                    elif lie == "reorder" and len(served) > 1:
                        served[-1], served[-2] = served[-2], served[-1]
                    reply = {**reply, "records": served}
                return reply

            client._request = lying
        try:
            forget_team_log_pin(vault, " ".join(sorted(pins)), client)
        except (ValueError, RuntimeError) as exc:
            outcome = f"refused ({type(exc).__name__})"
        else:
            raise AssertionError(f"{name} forgot its team log pin with the log not lost ({lie})\n" + self._trace())
        coverage_event(f"forget-pin while the log is not lost: {lie}")
        self.log.append(f"{name}: forget-pin ({lie or 'honest server'}) -> {outcome}")
        assert pinned_genesis(vault) == pins, f"{name}: a refused forget-pin changed the pins\n" + self._trace()
        # The check before the forget may catch the copy up along the true log
        # (up to the head the server announces, goal #440), never anything else.
        after = [tuple(r) for r in vault.db.fetchall("SELECT seq, hash FROM team_log ORDER BY seq")]
        true_rows = [(seq, teamlog.record_hash(r)) for seq, r in enumerate(self._server_log())]
        assert after[:len(rows)] == rows and after == true_rows[:len(after)], (
            f"{name}: a refused forget-pin changed the log copy\n" + self._trace())

    @rule(data=st.data(), race=st.sampled_from([None, *FORGERIES, *LOST_LOG_FORGERIES]),
          path=st.sampled_from(["restore", "append"]))
    def operator_loses_the_log(self, data=None, race=None, path="restore"):
        """The server's team log is gone (a restore of the database without
        it). No device forgets its pin on its own (INV-8); an admin device that
        holds the log puts it back on its next sync (INV-7), and the settle
        ends with every device on that log. ``race``: a member uploads a
        history of its own first (capability run 433; random steps seldom
        find the log still empty)."""
        if not self._server_log():
            return
        # Taken from the server as by a restore: until it syncs, a device may
        # hold its own account's fork of them (deep stateful run on c6d3dff).
        self.lost_by_restore = getattr(self, "lost_by_restore", set()) | {
            teamlog.record_hash({"body": r["body"], "sig": r["sig"]}) for r in self.db._storage["team_log"]}
        self.db._storage["team_log"] = []
        self.log.append("server: team log lost")
        if race is not None and self._member_desktops():
            self.member_forges_a_restore_of_the_lost_log(data, race, path)

    @precondition(lambda self: self._server_log() and self._member_desktops())
    @rule(data=st.data(), chain=st.booleans(), unsent=st.booleans())
    def yield_the_admin_role_and_take_it_back(self, data, chain, unsent):
        """(Three arguments and this name sort it after every other rule,
        RuleStrategy orders by argument count, then name: the saved examples
        in property_seeds.txt keep their shape.)

        'sezam team-log hand-over' to a member desktop, whose push re-keys
        what the admin held only as admin, on to a third member if ``chain``,
        and back to the admin (review 8bc70f7 M1). The role is the admin's
        authority: after EVERY hop each member's access in the log is as it
        was (a handover grants none, only what the admin had queued for them
        goes out), and after the round trip no envelope of a current key the
        log does not give them (an_envelope_goes_with_its_access). With
        ``unsent`` the admin hands over with an edit not yet pushed: it goes
        out first, or the handover is refused."""
        from sezam.vault.team_migration import hand_over_admin

        start = teamlog.replay(self._server_log())
        user_id = self._pick(data, self._may_take_the_role(start), "member")
        if user_id is None:
            return
        device = self._device(data)
        dev = self._command(device)
        admin_id = dev.vault.db.get_meta("user_id")
        if not teamlog.is_admin(start, admin_id):
            return
        name = self.members[user_id].name
        edit = []
        folder = self._pick(data, self._folders(device), "folder") if unsent else None
        if folder is not None:
            title = self._token("E")
            self._local(device, f"create entry {title} in {folder}", lambda v: edit.append(v.create_entry(
                folder, title, [{"key": "password", "value": title, "sensitive": True}])))
        queued = dev.client.pending_team_changes() + [
            change for kept in dev.client.pending_team_grants().values() for change in kept]
        sent_for = {(c["user_id"], c["folder"]) for kind, c in queued if kind == "access.set"}
        dirty_before = _dirty_ids(dev.vault)
        try:
            hand_over_admin(dev.vault, dev.client, user_id, lambda _fp: True)
        except (RuntimeError, ValueError, teamlog.TeamLogError) as exc:
            coverage_event("handover refused")
            self.log.append(f"{device}: hand the admin role to {name} refused: {exc}")
            assert not teamlog.is_admin(teamlog.replay(self._server_log()), user_id), (
                f"a refused handover to {name} landed\n" + self._trace())
            return
        self.log.append(f"{device}: hands the admin role to {name}")
        # R16-Z SM24b: the handover pushes this device's writes first; the
        # server holds them now. Not credited, a later delete of them that
        # aged out of the server looked like the server never had them.
        self._note_pushed(device, dirty_before)
        if edit:
            coverage_event("handover with an unsent edit")
            assert not dev.vault.db.fetchone(
                "SELECT 1 FROM outbox WHERE object_id = ? AND state = 'queued'", (edit[0],)), (
                f"{device} handed the role over and left its unsent edit behind\n" + self._trace())
        holders = [user_id]
        self._the_handover_granted_nothing(start, holders, sent_for)
        third = self._pick(data, self._may_take_the_role(teamlog.replay(self._server_log())), "next admin") if chain else None
        if third is not None:
            self._member_hands_over(user_id, third)
            coverage_event("handover chain")
            holders.append(third)
            self._the_handover_granted_nothing(start, holders, sent_for)
        self._member_hands_over(holders[-1], admin_id)
        coverage_event("handover round trip")
        self._call(device, "pull")  # the members' re-keys, then 'sezam push' re-keys what it held as admin
        self._push(device)
        state = teamlog.replay(self._server_log())
        assert teamlog.is_admin(state, admin_id), f"the role went back to {device}, the log disagrees\n" + self._trace()
        self._the_handover_granted_nothing(start, holders, sent_for)
        for holder in holders:
            for folder in state.folders:
                if state.folders[folder][-1][1] == holder:
                    coverage_event("handover: a folder waits for the admin's re-key")
                    continue
                if holder not in state.access.get(folder, {}):
                    assert not teamlog.may_hold_key(state, holder, teamlog.current_key(state, folder)), (
                        f"{self.members[holder].name} holds {folder}'s current key after the role went back\n"
                        + self._trace())

    def _may_take_the_role(self, state) -> list[str]:
        return [
            u for u in self._member_desktops()
            if u in state.members and state.members[u].active and not teamlog.is_admin(state, u)
            and u not in self.waiting and u not in self.unconfirmed
        ]

    def _member_hands_over(self, from_id: str, to_id: str) -> None:
        """A member desktop that holds the admin role syncs, then hands it on."""
        from sezam.vault.team_migration import hand_over_admin

        name = self.members[from_id].name
        to = self.members[to_id].name if to_id in self.members else "the admin"
        for attempt in range(2):
            client = self._new_client(self.members[from_id].vault)
            try:
                client.pull()
                revocation.push_with_queued_revocations(self.members[from_id].vault, client)
                hand_over_admin(self.members[from_id].vault, client, to_id, lambda _fp: True)
                break
            except (RuntimeError, ValueError, teamlog.TeamLogError) as exc:
                self.log.append(f"{name}: hand the admin role to {to} refused: {exc}")
                if attempt == 1:
                    raise AssertionError(f"{name} cannot hand the admin role to {to}: {exc!r}\n" + self._trace()) from exc
                self._member_sync(from_id)  # settles its conflicts, as the refusal says
        self.log.append(f"{name}: hands the admin role " + ("back" if to_id not in self.members else f"to {to}"))

    def _the_handover_granted_nothing(self, start, holders: list[str], sent_for: set) -> None:
        """M1, checked after each hop: no access.set for a member the role went
        to, except what the admin had queued for them before the handover."""
        state = teamlog.replay(self._server_log())
        for user_id in holders:
            changed = {
                folder: (start.access.get(folder, {}).get(user_id), state.access.get(folder, {}).get(user_id))
                for folder in set(start.access) | set(state.access)
                if state.access.get(folder, {}).get(user_id) != start.access.get(folder, {}).get(user_id)
                and (user_id, folder) not in sent_for
            }
            assert not changed, (
                f"a handover changed {self.members[user_id].name}'s access: {changed}\n" + self._trace())

    @invariant()
    def the_server_log_follows_the_rules(self):
        """INV-1/INV-2: what the server stored replays under today's rules,
        holds no forged record and has one admin at its head."""
        if not hasattr(self, "db"):
            return
        records = self._server_log()
        state = teamlog.TeamState()
        for record in records:
            refusal = teamlog.todays_rules_refusal(state, teamlog.parse_body(record["body"]))
            assert refusal is None, f"the server stored a record today's rules refuse: {refusal}\n" + self._trace()
            try:
                state = teamlog.apply_record(state, record)
            except teamlog.TeamLogError as exc:
                raise AssertionError(f"the server stored a log the rules refuse: {exc}\n" + self._trace()) from exc
        stored = {teamlog.record_hash(r) for r in records}
        assert not stored & self._forged_hashes(), "the server stored a forged record\n" + self._trace()
        if records:
            assert teamlog.admin_policy_refusal(state) is None, "server log head: more than one admin\n" + self._trace()

    @invariant()
    def every_device_holds_one_log(self):
        self._holds_one_log(settled=False)

    def _check_new_device_matches(self):
        super()._check_new_device_matches()
        self._holds_one_log(settled=True)

    def _holds_one_log(self, settled: bool):
        """No device accepted a record the true log does not have (fork,
        forgery) or a log that does not replay; the server's and each device's
        copy are one the other's prefix (a restored server is the shorter).

        Until it syncs, a device may hold a fork of its own account (goal
        #442): its records after it are ones a restore took from the server,
        and every record on both sides is this account's. Once settled, none."""
        if not hasattr(self, "db"):
            return
        records = self._server_log()
        server = [teamlog.record_hash(r) for r in records]
        for name, vault in self._log_vaults():
            rows = vault.db.fetchall("SELECT body, sig FROM team_log ORDER BY seq")
            local = [teamlog.record_hash({"body": r["body"], "sig": r["sig"]}) for r in rows]
            assert not set(local) & self._forged_hashes(), f"{name} holds a forged log record\n" + self._trace()
            n = min(len(local), len(server))
            fork = next((i for i in range(n) if local[i] != server[i]), None)
            account = vault.db.get_meta("user_id")
            if (not settled and fork and set(local[fork:]) <= getattr(self, "lost_by_restore", set())
                    and all(teamlog.parse_body(r["body"])["author"] == account
                            for r in list(rows[fork:]) + records[fork:])):
                coverage_event("a device holds its own account's fork until it syncs")
                continue
            if not settled and fork and set(local[fork:]) <= getattr(self, "lost_by_restore", set()):
                # Records of the true log the server lost, pulled before the
                # loss: held until their author makes them again (R16-H1,
                # deep stateful run on c6d3dff); settled, none.
                coverage_event("a device holds records the server lost until their author remakes them")
                continue
            assert local[:n] == server[:n], (
                f"{name}'s team log forks from the server's at record "
                f"{next(i for i in range(n) if local[i] != server[i])}\n" + self._trace())

    @invariant()
    def an_envelope_goes_with_its_access(self):
        """INV-6: a grant's envelope and its access.set land in one request.
        A live envelope an admin sealed to a member for a key the log knows
        is there only while the log gives that member the folder.

        A server that lost its log and took back a shorter copy (another
        device's) lacks the grant until the device that made it puts its
        record back (R15 #441, default run on 4ee7d65): until then the
        grant is in that device's copy, which continues the server's."""
        if not hasattr(self, "db"):
            return
        records = self._server_log()
        if not records:
            return
        state = teamlog.replay(records)
        server = [teamlog.record_hash(r) for r in records]
        ahead = []
        for _name, vault in self._log_vaults():
            rows = [{"body": r["body"], "sig": r["sig"]}
                    for r in vault.db.fetchall("SELECT body, sig FROM team_log ORDER BY seq")]
            hashes = [teamlog.record_hash(r) for r in rows]
            if len(rows) > len(records) and hashes[:len(records)] == server:
                ahead.append(teamlog.replay(rows))
                continue
            # Or forks from it with records the server lost only (deep stateful
            # run on c6d3dff: the log lost, another device of the account
            # wrote on what it put back); that device makes them again.
            fork = next((i for i in range(min(len(hashes), len(server))) if hashes[i] != server[i]), None)
            if fork and set(hashes[fork:]) <= getattr(self, "lost_by_restore", set()):
                ahead.append(teamlog.replay(rows))
        for obj in self.db._storage.get("vault_objects", []):
            target = obj.get("target_user_id")
            if obj["object_type"] != "envelope" or obj.get("is_deleted") or target not in self.members:
                continue
            if obj.get("owner_id") == target or target not in state.members or teamlog.is_admin(state, target):
                continue
            if not state.members[target].active:
                # member.remove lands before the re-key (revoke_member); the
                # key it held is retired by that re-key, not by this envelope.
                continue
            folder, gen = state.dek_index.get(obj.get("parent_ref"), (None, None))
            if folder is None or gen != len(state.folders[folder]) - 1:
                continue  # not a log key, or an older generation (kept for history)
            if not state.access.get(folder, {}).get(target) and any(
                    copy.access.get(folder, {}).get(target) for copy in ahead):
                coverage_event("a grant waits in a device's copy the restored server lost")
                continue
            assert state.access.get(folder, {}).get(target), (
                f"{self.members[target].name} has an envelope of {folder}'s current key "
                f"({obj.get('parent_ref')}) the log gives them no access to\n" + self._trace())

    @invariant()
    def a_waiting_member_has_a_way_out(self):
        """INV-7: a member waiting for records a restored server lost waits
        for records some device of the admin still holds."""
        if not hasattr(self, "db"):
            return
        held = max([len(self._server_log())] + [
            len(dev.vault.db.fetchall("SELECT seq FROM team_log")) for dev in self.devices.values()])
        for user_id in self._waiting_members():
            mine = len(self.members[user_id].vault.db.fetchall("SELECT seq FROM team_log"))
            assert mine <= held, (
                f"{self.members[user_id].name} waits for team log records nobody holds\n" + self._trace())


class _Scripted:
    """A stand-in for st.data() that answers each draw from a script by label."""

    def __init__(self, **answers):
        self.answers = answers

    def draw(self, _strategy, label=None):
        return self.answers[label]


def test_sync_state_machine_stale_second_process_pull(loopback_server, monkeypatch):
    """Review 7c10379: random runs seldom line these steps up - a second
    process opened on A, a password change in A's CLI, a folder B makes under
    the new account KEK, then a pull of A's second process. Before the fix that
    pull put B's DEK on A's foreign list for good."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        machine.open_second_process(_Scripted(device="A"))
        machine.change_password(_Scripted(device="A"), None)
        machine.pull(_Scripted(device="B"), None)
        machine.create_folder(_Scripted(device="B", parent="ROOT"))
        machine.push(_Scripted(device="B"), None)
        # The rule asserts the harm (no own DEK of A foreign) after the stale
        # pull and after A's own pull; on 63ecc65~1 it fails there.
        machine.second_process_pull(_Scripted(device="A"))
        assert any(line.startswith("A: pull") for line in machine.log[-2:]), machine._trace()
    finally:
        machine.teardown()


@pytest.mark.parametrize("trigger", ["check_token", "gone"])
def test_sync_state_machine_full_resync_lies(loopback_server, monkeypatch, trigger):
    """Review 7c10379 H1: B sees the DEK wraps from before A's password change,
    takes the change over, then the server makes up a rollback (or 410) and
    answers B's full resync with those old wraps. Before the fix B's DEKs went
    back to them and its vault opened with neither password."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        machine.pull(_Scripted(device="B"), None)
        machine.change_password(_Scripted(device="A"), None)
        machine.push(_Scripted(device="A"), None)
        machine.pull(_Scripted(device="B"), None)
        machine.server_lies_into_full_resync(_Scripted(device="B"), trigger, True)
        assert any("old DEK wraps" in line for line in machine.log), (
            "the lie had no old wraps to send\n" + machine._trace())
    finally:
        machine.teardown()


@pytest.mark.parametrize("trigger", ["check_token", "gone"])
def test_sync_state_machine_full_resync_lies_about_a_new_key(loopback_server, monkeypatch, trigger):
    """Review 7c10379 R7-G (full suite run on d994f32): the old wrap is of a
    folder key B never held. A makes the folder, pushes, changes the password
    and pushes; the server makes B full-resync and answers with the key's copy
    from before the change. Before the fix B kept that copy, its checkpoint
    passed the current one, and the folder's entry never opened on B again."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        before = set(machine._folders("A"))
        machine.create_folder(_Scripted(device="A", parent="ROOT"))
        (folder,) = set(machine._folders("A")) - before
        machine.create_entry(_Scripted(device="A", folder=folder))
        machine.push(_Scripted(device="A"), None)
        machine.change_password(_Scripted(device="A"), None)
        machine.push(_Scripted(device="A"), None)
        machine.server_lies_into_full_resync(_Scripted(device="B"), trigger, True)
        assert any("old DEK wraps" in line for line in machine.log), (
            "the lie had no old wraps to send\n" + machine._trace())
        machine._settle(lambda _obj: "server")
        unreadable = {obj: state for obj, state in snapshot(machine.devices["B"].vault).items()
                      if state[1].startswith("<unreadable")}
        assert not unreadable, f"B: {unreadable} stay unreadable after the settle\n" + machine._trace()
    finally:
        machine.teardown()


def test_sync_state_machine_password_change_after_a_lying_full_resync(loopback_server, monkeypatch):
    """Review 7c10379 R7-G (found once the test above was fixed): B changes the
    password; the server makes A full-resync and answers with the DEK copies
    from before (A keeps its own, re-wrapped by the takeover, at the old
    version). A's own password change then re-wraps them at the version B's
    already has. Before the fix the push raised the server's raw 409 on every
    try: the pull it made first brings nothing past the checkpoint."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        machine.change_password(_Scripted(device="B"), None)
        machine.push(_Scripted(device="B"), None)
        machine.server_lies_into_full_resync(_Scripted(device="A"), "check_token", True)
        assert any("old DEK wraps" in line for line in machine.log), (
            "the lie had no old wraps to send\n" + machine._trace())
        machine.change_password(_Scripted(device="A"), None)
        assert "A" in machine.resync_due, "A's password change named no full resync\n" + machine._trace()
    finally:
        machine.teardown()


def test_sync_state_machine_gc_floor_lie_over_a_tombstone(loopback_server, monkeypatch):
    """R15 #428 (INV-3): random runs seldom line up a tombstone, an older
    version of it on the wire and another device's new commit. A deletes an
    entry B made; the server serves B's version 1 again with B's next folder
    and a GC floor above A's tombstone. Before the fix A had the entry back."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        machine.create_folder(_Scripted(device="B", parent="ROOT"))
        folder = machine._folders("B")[0]
        machine.create_entry(_Scripted(device="B", folder=folder))
        machine.push(_Scripted(device="B"), None)
        machine.pull(_Scripted(device="A"), None)
        entry = machine._entries("A")[0]
        machine.delete_entry(_Scripted(device="A", entry=entry))
        machine.push(_Scripted(device="A"), None)
        machine.pull(_Scripted(device="A"), None)
        machine.server_lies(_Scripted(device="A", maker="B", revived=entry), "gc_floor")
        assert any("over its tombstone" in line for line in machine.log), machine._trace()
        assert entry in machine._entries("A", deleted=True), machine._trace()
    finally:
        machine.teardown()


def test_sync_state_machine_lying_full_resync_under_a_pending_key_change(loopback_server, monkeypatch):
    """Review a159e97 (state machine, seed 949494): A's org recovery reached the
    server but A never heard back, so A still holds it as pending. The server
    makes up a rollback and answers A's full resync with the DEK wraps from
    before. A refuses (nothing opens them under the new KEK) and rolls back;
    the harness took that refusal for a crash. The settle then converges."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        machine.change_password(_Scripted(device="A"), None)
        machine.push(_Scripted(device="A"), None)
        machine.setup_org_recovery(_Scripted(device="A"))
        machine.push(_Scripted(device="A"), None)
        machine.org_recovery("after")
        assert machine.devices["A"].client.has_pending_key_change(), machine._trace()
        machine.server_lies_into_full_resync(_Scripted(device="A"), "check_token", True)
        assert any("refused the lie" in line for line in machine.log), machine._trace()
        machine._settle(lambda _obj: "server")
        unreadable = {obj: state for obj, state in snapshot(machine.devices["A"].vault).items()
                      if state[1].startswith("<unreadable")}
        assert not unreadable, f"A: {unreadable} stay unreadable after the settle\n" + machine._trace()
    finally:
        machine.teardown()


def test_sync_state_machine_server_lies_about_org_recovery(loopback_server, monkeypatch):
    """Review e443cbc #428 (INV-3): the status names another recovery key of
    the admin while A's setup still waits for the log. A stopped sending it and
    deleted its recovery key; the shares handed out opened nothing. A keeps the
    key now (the rule checks), and after the settle tells the admin the server
    lacks it."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        with monkeypatch.context() as lost:  # the registration's answer is lost: it waits
            lost.setattr(SyncClient, "store_org_recovery", lambda *_a: (_ for _ in ()).throw(
                ConnectionResetError("connection reset by peer")))
            machine.setup_org_recovery(_Scripted(device="A"))
        machine.server_lies_about_org_recovery()
        machine._settle(lambda _obj: "server")
        # Withheld: the server never took it, and A says so.
        assert org_recovery_server.registration_issue(machine.devices["A"].vault) == "withheld", machine._trace()
    finally:
        machine.teardown()


def test_sync_state_machine_rotation_reply_lost_then_pushed_again(loopback_server, monkeypatch):
    """Goal #443, default run on the #443 branch: B's identity rotation landed
    and its reply was lost. The next push carries the rotation again; its key
    vouchers needed the key the rotation retires, which the server no longer
    serves as the account's, and every push of B stopped there."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        machine.rotate_identity(_Scripted(device="B"), "after")
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


@pytest.mark.parametrize("how", ["new_device", "full_resync", "web"])
def test_sync_state_machine_server_holds_a_leaked_retired_key(loopback_server, monkeypatch, how):
    """Goal #443 (review e443cbc R15, INV-3): after A's identity rotation the
    server signs the next version of an entry with A's retired key and serves
    a bound over it. Before #443 a new device, a full resync and every web
    sign-in took it (the bound and the object's commit_seq were the server's
    word); a retired key now counts only for versions a voucher list names."""
    if how == "web" and not NODE:
        pytest.skip(node_problem())
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        machine.rotate_identity(_Scripted(device="A"), None)
        machine._settle(lambda _obj: "server")
        assert machine._retired_signers(), machine._trace()
        admin = machine.devices["A"].vault.db.get_meta("user_id")
        signed = sorted(o["id"] for o in machine.db._storage["vault_objects"]
                        if o.get("object_type") == "entry" and not o.get("is_deleted")
                        and o.get("signature_user_id") == admin)
        assert signed, machine._trace()
        machine.with_a_leaked_retired_key_the_server_forges(
            _Scripted(**{"leaked key": 0, "object": signed[0], "device": "B"}), how)
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


@pytest.mark.parametrize("key", field_lies.GENERIC)
def test_sync_state_machine_server_lies_in_a_field(loopback_server, monkeypatch, key):
    """Review e443cbc #428 (INV-3): each hint of the register without a rule
    of its own, lied about once in every way while A logs in, pushes an edit
    and pulls; the honest settle after converges."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        before = set(machine._folders("A"))
        machine.create_folder(_Scripted(device="A", parent="ROOT"))
        (folder,) = set(machine._folders("A")) - before
        machine.create_entry(_Scripted(device="A", folder=folder))
        machine.push(_Scripted(device="A"), None)
        machine.pull(_Scripted(device="B"), None)
        for how in range(3):
            machine.create_entry(_Scripted(device="A", folder=folder))
            machine.server_lies_in_a_field(_Scripted(device="A"), key, how)
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_sync_state_machine_restore_takes_back_a_second_admin(loopback_server, monkeypatch):
    """Review 7c10379 (state machine: a new device does not connect after a
    server restore, audit DAG): the server is restored from a backup taken
    before a member became an admin. A pulled his audit records; the server
    lost them and refuses them from him now ('admin only'). A's next record
    names one as a parent. Before the fix A's other device B failed every pull
    and full resync on 'references missing parent(s)', and so did a new device."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        member = machine._active_members()[0]
        machine._member_sync(member)
        machine.server_backup()
        machine._appoint(member)
        machine._member_sync(member)
        machine.member_write(_Scripted(member=member), "add folder")
        machine._member_sync(member)
        machine.pull(_Scripted(device="A"), None)
        machine.server_restore()
        assert not machine._is_admin(member), machine._trace()
        machine.create_folder(_Scripted(device="A", parent="ROOT"))
        machine._settle(lambda _obj: "server")
        machine._check_new_device_matches()
    finally:
        machine.teardown()


def test_sync_state_machine_restore_loses_another_accounts_rotation(loopback_server, monkeypatch):
    """Review a159e97 H11 (regression of 3d59ab3): the server is restored from
    a backup taken before the admin rotated their identity. The member's
    desktop had pulled the admin's records signed with the new key; its full
    resync kept them and sent them again, and checked against the key the
    server holds now each failed. Before the fix every sync of the member
    raised 'Invalid audit signature', full resync included."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        member = machine._active_members()[0]
        machine._member_sync(member)
        machine.server_backup()
        machine.rotate_identity(_Scripted(device="A"), None)
        machine._member_sync(member)
        machine.server_restore()
        machine._member_sync(member)
        machine._member_sync(member)
        machine._settle(lambda _obj: "server")
        machine._member_sync(member)
        machine._check_new_device_matches()
    finally:
        machine.teardown()


@pytest.mark.parametrize("failure", [None, "after"])
def test_sync_state_machine_second_admin_revokes_a_member_of_the_first(loopback_server, monkeypatch, failure):
    """Review 7c10379 (state machine: the second admin gets stuck): the second
    admin revokes a member the first admin shared a folder with. The second
    admin's desktop holds the envelope but not the folder's key. Before the fix
    its re-key opened that key, the member stayed queued and every later push
    of that desktop raised CryptoError ('Decryption failed.')."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SecondAdminMachine.server = loopback_server
    machine = SecondAdminMachine()
    try:
        (admin,) = machine._second_admins()
        machine._invite_member("A")
        target = next(u for u in machine._active_members() if u not in machine.admins)
        machine._grant("A", target, machine._folders("A")[0], "read")
        machine._member_sync(admin)
        machine.second_admin_revokes(_Scripted(admin=admin, member=target), failure)
        assert target in machine.revoked, machine._trace()
        machine._settle(lambda _obj: "server")  # the member desktops end with nothing waiting
    finally:
        machine.teardown()


def _restore_between_revoke_and_rekey(machine, who: str) -> str:
    """A shares a folder with a member and the member is revoked from ``who``
    (an admin device or the second admin); the backup is taken after the
    server revoked them and before the re-key landed; the re-key lands and
    every desktop pulls it; the server is restored. Returns the member."""
    machine._invite_member("A")
    member = next(u for u in machine._active_members() if u not in machine.admins)
    machine._grant("A", member, machine._folders("A")[0], "read")
    if who == "second":
        (admin,) = machine._second_admins()
        machine._member_sync(admin)
        machine.second_admin_revokes(_Scripted(admin=admin, member=member), "before")
    else:
        machine.pull(_Scripted(device=who), None)
        machine.revoke(_Scripted(device=who, member=member), "before")
    assert member in machine.revoked, machine._trace()
    machine.server_backup()
    machine._settle(lambda _obj: "server")
    machine.server_restore()
    return member


def test_sync_state_machine_restore_takes_back_a_member_rekey(loopback_server, monkeypatch):
    """Review 7c10379 R7-G (state machine, found probing the counterexample
    below): a member desktop pulled a folder of A's re-keyed after a
    revocation; the server is restored from a backup taken before the re-key.
    Before the fix its 'sezam pull --full-resync' kept the folder on the
    re-key's DEK the server lost, pruned that DEK and failed the commit on a
    foreign key (IntegrityError) every time."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        member = _restore_between_revoke_and_rekey(machine, "A")
        desktops = [u for u in machine._member_desktops() if u != member]
        assert desktops, machine._trace()
        for user_id in desktops:
            machine._member_sync(user_id)
        assert any("full resync" in line for line in machine.log[-4:]), machine._trace()
    finally:
        # Only the member desktops here; the settle of the admins' devices
        # after this restore is the next test's.
        machine.second.update({f"device {name}": dev.vault for name, dev in machine.devices.items()})
        machine.devices = {}
        machine.teardown()


@pytest.mark.parametrize("who", ["A", "B", "second"])
def test_sync_state_machine_restore_brings_back_a_revoked_envelope(loopback_server, monkeypatch, who):
    """Review 7c10379 (state machine: a revoked member keeps a live envelope):
    the backup was taken after the server revoked the member and before the
    re-key withdrew their envelope. Restored, the server holds it live again;
    A's devices had withdrawn it and ignored it as a replay, so its tombstone
    never went out again."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    machine_cls = SecondAdminMachine if who == "second" else SyncMachine
    machine_cls.server = loopback_server
    machine = machine_cls()
    try:
        _restore_between_revoke_and_rekey(machine, who)
        machine._settle(lambda _obj: "server")  # _check_members: no live envelope of a revoked member
    finally:
        machine.teardown()


def test_sync_state_machine_made_up_member(loopback_server, monkeypatch):
    """Review 7c10379 H2: a folder shared with a member, an account 'Eve' the
    server made up with an envelope she signed herself on that folder's key,
    then the member's revocation re-keys the folder. Before the fix the new
    key went to Eve too."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        folder = machine._folders("A")[0]
        machine.invite_member(_Scripted(device="A"))
        member = machine._active_members()[0]
        machine.grant(_Scripted(device="A", member=member, folder=folder), "read")
        machine.server_makes_up_a_member(_Scripted(device="A", folder=folder, eve_writes=None))
        assert machine.made_up, "no account was made up\n" + machine._trace()
        machine.pull(_Scripted(device="A"), None)
        machine.revoke(_Scripted(device="A", member=member), None)
        assert any("re-keyed 1" in line for line in machine.log), "no re-key\n" + machine._trace()
        machine.no_key_for_made_up_accounts()
    finally:
        machine.teardown()


def test_sync_state_machine_rekey_landed_with_its_reply_lost_is_not_abandoned(loopback_server, monkeypatch):
    """Nightly run 44891798136 on e443cbc (SecondAdmin, capability run 437):
    a member's re-key batch reached the server and its reply was lost; then
    the server made up a head, so the device full-resynced, and the way out
    of the pending re-key was 'abandon-rekey'. Nothing local said the batch
    had landed (no reply, no pull since), so abandon took the folders back
    under the old key and deleted the new one, which the server kept: the
    resync brought the folder back bound to a key this device no longer had
    and the subfolder could not be opened ('Decryption failed')."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        folder = machine._folders("A")[0]
        machine.create_folder(_Scripted(device="A", parent=folder))
        sub = next(f for f in machine._folders("A") if f != folder and machine.devices["A"].vault.db.fetchone(
            "SELECT 1 FROM nodes WHERE id = ? AND parent_id = ?", (f, folder)))
        machine.create_entry(_Scripted(device="A", folder=folder))
        machine.push(_Scripted(device="A"), None)
        machine.invite_member(_Scripted(device="A"))
        member = machine._active_members()[0]
        machine.grant(_Scripted(device="A", member=member, folder=folder), "write")
        machine.pull(_Scripted(device="A"), None)
        machine.revoke(_Scripted(device="A", member=member), "after")
        pending = pending_store.rekey_batch(machine.devices["A"].vault.db)
        new_deks = set(pending["dek_map"].values())
        assert new_deks, "no re-key pending\n" + machine._trace()
        assert {o["id"] for o in machine.db._storage["vault_objects"]} & new_deks, (
            "the batch did not reach the server\n" + machine._trace())
        machine.server_lies_into_full_resync(_Scripted(device="A"), "check_token", False)
        machine.full_resync(_Scripted(device="A"))
        machine.rename_folder(_Scripted(device="A", folder=sub))
        machine._settle(lambda _obj: "server")
        assert not any("requeued': True" in line for line in machine.log), (
            "a batch the server holds was undone here\n" + machine._trace())
    finally:
        machine.teardown()


def test_sync_state_machine_rekey_below_a_folder_deleted_elsewhere_survives_a_full_resync(
    loopback_server, monkeypatch,
):
    """Nightly run on e443cbc (goal #429 b): a member's re-key waited, another
    device deleted the folder above the re-keyed one, and the way out of the
    pending re-key before a full resync was 'abandon-rekey'. The resync kept
    the folder (it holds the re-keyed work) but queued it again without the
    mark that it brings the folder back, so the re-key batch went without it
    and the server refused the subfolder ('parent folder is deleted') on
    every sync."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        folder = machine._folders("A")[0]
        machine.create_folder(_Scripted(device="A", parent=folder))
        sub = next(f for f in machine._folders("A") if f != folder and machine.devices["A"].vault.db.fetchone(
            "SELECT 1 FROM nodes WHERE id = ? AND parent_id = ?", (f, folder)))
        machine.create_entry(_Scripted(device="A", folder=sub))
        machine.push(_Scripted(device="A"), None)
        machine.pull(_Scripted(device="B"), None)
        machine.invite_member(_Scripted(device="A"))
        member = machine._active_members()[0]
        machine.grant(_Scripted(device="A", member=member, folder=sub), "write")
        machine.pull(_Scripted(device="A"), None)
        machine.revoke(_Scripted(device="A", member=member), "before")
        assert pending_store.rekey_batch(machine.devices["A"].vault.db), "no re-key pending\n" + machine._trace()
        entry = machine.devices["A"].vault.db.fetchone("SELECT id FROM entries WHERE node_id = ?", (sub,))["id"]
        machine.edit_entry(_Scripted(device="A", entry=entry))
        machine.delete_folder(_Scripted(device="B", folder=folder))
        machine.push(_Scripted(device="B"), None)
        machine.pull(_Scripted(device="A"), None)
        machine.abandon_rekey(_Scripted(device="A"))
        machine.full_resync(_Scripted(device="A"))
        db = machine.devices["A"].vault.db
        assert db.fetchone("SELECT is_deleted FROM nodes WHERE id = ?", (folder,))["is_deleted"] == 0, machine._trace()
        assert folder in outbox.revived_folders(db), (  # what the re-key batch takes along (SM73)
            "the kept folder is queued as a plain edit\n" + machine._trace())
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


@pytest.mark.parametrize("where", ["root", "unknown parent"])
def test_sync_state_machine_made_up_admin_writes_below_the_root(loopback_server, monkeypatch, where):
    """Capability run 196 (review a159e97 H2, 7c10379 H4): 'Eve', an account
    the server made up, signs an envelope (only an admin may push one) and in
    the same push a folder directly below A's root or below a folder id that
    does not exist. A pull counted her an admin from that envelope and applied
    the folder below the root on A and B; on 8fbca52 the invariant fails."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        folder = machine._folders("A")[0]
        machine.server_makes_up_a_member(_Scripted(device="A", folder=folder, eve_writes=where))
        assert machine.forged_by_made_up, "her folder did not land\n" + machine._trace()
        for device in ("A", "B"):
            machine.pull(_Scripted(device=device), None)
        machine.full_resync(_Scripted(device="B"))
        machine.no_folder_a_made_up_account_wrote()
        machine._settle(lambda _obj: "server")
        machine.no_folder_a_made_up_account_wrote()
    finally:
        machine.teardown()


@pytest.mark.parametrize("pinned", [False, True])
def test_sync_state_machine_swapped_member_key(loopback_server, monkeypatch, pinned):
    """Review 7c10379: /api/users answers a grant with a key the server made;
    first grant to the member, or one whose key the admin already pinned."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        folders = machine._folders("A")
        machine.invite_member(_Scripted(device="A"))
        member = machine._active_members()[0]
        if pinned:
            machine.grant(_Scripted(device="A", member=member, folder=folders[0]), "read")
        machine.server_swaps_a_member_key(_Scripted(device="A", member=member, folder=folders[-1]), "write")
        assert "-> refused" in machine.log[-1], machine._trace()
    finally:
        machine.teardown()


@pytest.mark.parametrize("rekey_failure", [None, "after"])
def test_sync_state_machine_pending_rotation_meets_a_member_rekey(loopback_server, monkeypatch, rekey_failure):
    """Review 1141a20 (R9-E, state machine seed 737373, second admin): B's
    identity rotation does not reach the server; A revokes a member and
    re-keys the folder shared with them. B's rotation carried a re-sealed
    envelope on the folder's old key, now re-wrapped without its folder, and
    the server refused the whole batch ('envelope references unknown DEK')
    on every push of B's."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        machine._invite_member("A")
        member = next(u for u in machine._active_members() if u not in machine.admins)
        machine._grant("A", member, machine._folders("A")[0], "write")
        machine._member_sync(member)
        machine.rotate_identity(_Scripted(device="A"), "after")
        machine.track_member_keys()  # an invariant: Hypothesis runs it after every step
        machine._settle(lambda _obj: "server")
        machine.rotate_identity(_Scripted(device="B"), "before")
        machine.track_member_keys()
        assert machine.devices["B"].client.has_pending_key_change(), machine._trace()
        machine.pull(_Scripted(device="A"), None)
        machine.revoke(_Scripted(device="A", member=member), rekey_failure)
        machine.track_member_keys()
        assert member in machine.revoked, machine._trace()
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


@pytest.mark.parametrize("keep", ["local", "server"])
def test_sync_state_machine_unpulled_device_re_keys_what_another_re_keyed(loopback_server, monkeypatch, keep):
    """Review 4acfdde R11 #3 (reviewer's seed, second admin): the second admin
    revokes a member, B (not pulled) edits an entry in the member's folder and
    deletes the folder, A grants the folder to the second admin. A's push
    re-keys the folder; B's push re-keyed it again from its own copy and both
    batches landed. Once the folder came back, A and B each kept their own new
    key and the second admin held an envelope only on A's: they lost the
    folder."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SecondAdminMachine.server = loopback_server
    machine = SecondAdminMachine()
    try:
        machine.track_member_keys()
        machine._settle(lambda _obj: "server")
        machine.track_member_keys()
        (admin,) = machine._second_admins()
        member = next(u for u in machine._active_members() if u not in machine.admins)
        folder = sorted(machine.granted[member])[0]
        entry = next(
            row["id"] for row in machine.devices["B"].vault.db.fetchall(
                "SELECT id FROM entries WHERE node_id = ? AND is_deleted = 0 ORDER BY id", (folder,)
            )
        )
        machine.edit_entry(_Scripted(device="B", entry=entry))
        machine.second_admin_revokes(_Scripted(admin=admin, member=member), None)
        machine.track_member_keys()
        machine.delete_folder(_Scripted(device="B", folder=folder))
        machine._grant("A", admin, folder, "read")
        machine.track_member_keys()
        machine._settle(lambda obj: keep if obj == entry else "server")
    finally:
        machine.teardown()


@pytest.mark.parametrize("revoker", ["A", "second admin"])
def test_sync_state_machine_pending_rotation_meets_a_logged_member_remove(loopback_server, monkeypatch, revoker):
    """Review 4acfdde R11 #3 (reviewer's seed, second admin): B's identity
    rotation does not reach the server; a member is removed (a signed
    member.remove) and the folder shared with them re-keyed. B's push of the
    rotation was refused with 409 'envelope references unknown DEK'."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SecondAdminMachine.server = loopback_server
    machine = SecondAdminMachine()
    try:
        machine.track_member_keys()
        machine._settle(lambda _obj: "server")
        machine.track_member_keys()
        (admin,) = machine._second_admins()
        member = next(u for u in machine._active_members() if u not in machine.admins)
        assert machine.granted[member], machine._trace()
        machine.rotate_identity(_Scripted(device="B"), "before")
        machine.track_member_keys()
        assert machine.devices["B"].client.has_pending_key_change(), machine._trace()
        if revoker == "A":
            machine.revoke(_Scripted(device="A", member=member), None)
        else:
            machine.second_admin_revokes(_Scripted(admin=admin, member=member), None)
        machine.track_member_keys()
        assert member in machine.revoked, machine._trace()
        machine.push(_Scripted(device="B"), None)
        machine.track_member_keys()
        assert "409" not in machine.log[-1] and "unknown DEK" not in machine._trace(), machine._trace()
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_sync_state_machine_withheld_archive_then_a_stale_grant(loopback_server, monkeypatch):
    """Review 1141a20 (R9-E, state machine seed 626262, second admin): the
    second admin revokes a member, B re-keys the folder they shared, and C,
    not pulled, grants the folder to the second admin under its old key. The
    server withholds the re-key's archive from C's next pull: C took the old
    key, still naming the folder, for a tier-2 key and kept that label once
    the archive came, so it never sealed the current key to the member it had
    just granted, who lost the folder."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SecondAdminMachine.server = loopback_server
    machine = SecondAdminMachine()
    try:
        machine.track_member_keys()
        machine.connect_another_device()
        admin = next(iter(machine.admins))
        member = next(u for u in machine._active_members() if u not in machine.admins)
        folder = sorted(machine.granted[member])[0]
        machine.second_admin_revokes(_Scripted(admin=admin, member=member), None)
        machine.track_member_keys()
        machine.pull(_Scripted(device="B"), None)
        machine.push(_Scripted(device="B"), None)
        machine.track_member_keys()
        machine._grant("C", admin, folder, "read")
        assert folder in machine.granted[admin], machine._trace()
        machine.track_member_keys()
        machine.server_withholds(_Scripted(device="C"), "dek_archive")
        machine.track_member_keys()
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_sync_state_machine_rekey_of_a_folder_deleted_here(loopback_server, monkeypatch):
    """Review e443cbc #438 (7), seed 858585 (second admin): A deletes a folder
    shared with a member while B renames it; A's delete comes back a conflict.
    The second admin revokes the member, so A re-keys the folder. The rebase
    skipped the folder deleted here, so the batch went out at the old base and
    every push of A failed as 'Atomic re-key batch conflict'."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SecondAdminMachine.server = loopback_server
    machine = SecondAdminMachine()
    try:
        machine.track_member_keys()
        (admin,) = machine._second_admins()
        member = next(u for u in machine._active_members() if u not in machine.admins and machine.granted[u])
        folder = sorted(machine.granted[member])[0]
        machine.delete_folder(_Scripted(device="A", folder=folder))
        machine.rename_folder(_Scripted(device="B", folder=folder))
        machine.push(_Scripted(device="B"), None)
        machine.push(_Scripted(device="A"), None)
        assert "conflicts 1" in machine.log[-1], machine._trace()
        machine.second_admin_revokes(_Scripted(admin=admin, member=member), None)
        assert member in machine.revoked, machine._trace()
        machine.push(_Scripted(device="A"), None)
        assert "re-key batch conflict" not in machine._trace(), machine._trace()
        a = machine.devices["A"].client
        assert not rekey_batch(machine.devices["A"].vault.db), machine._trace()
        # The delete made here is not lost: it is a conflict with B's rename.
        assert folder in {c["id"] for c in a.get_pull_conflicts()}, machine._trace()
        machine.track_member_keys()
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_sync_state_machine_folder_back_on_the_key_of_a_withdrawn_grant(loopback_server, monkeypatch):
    """R16-Z SM24a (gate 21 on f963cb2, second admin): B deletes a folder
    shared with a member and tombstone GC collects it; A, not pulled, renames
    it, so its full resync keeps the folder and sends it back on its key. A
    new device C holds A's grant to the member but no folder: when the second
    admin revokes the member, C withdraws the envelope with nothing to re-key.
    A's pull applied the withdrawal and forgot the member knew the key, its
    re-key found nothing, and the revoked member could read the folder again."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SecondAdminMachine.server = loopback_server
    machine = SecondAdminMachine()
    try:
        machine.track_member_keys()
        (admin,) = machine._second_admins()
        member = next(u for u in machine._active_members() if u not in machine.admins and machine.granted[u])
        folder = sorted(machine.granted[member])[0]
        machine.delete_folder(_Scripted(device="B", folder=folder))
        machine.push(_Scripted(device="B"), None)
        machine.gc_tombstones()
        assert folder in machine.collected, machine._trace()
        machine.rename_folder(_Scripted(device="A", folder=folder))
        machine.connect_another_device()
        machine.track_member_keys()
        machine.second_admin_revokes(_Scripted(admin=admin, member=member), None)
        assert member in machine.revoked, machine._trace()
        machine.track_member_keys()
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_sync_state_machine_full_resync_keeps_a_name_the_rekey_moved_on(loopback_server, monkeypatch):
    """R16-Z SM25b (gate 22 on 8914bac, second admin): A renames a subfolder
    of a folder it shared, unsent; B revokes the member and re-keys the folder;
    A's full resync keeps the unsent name, sealed with the folder's old key,
    and takes the folder's new key. A pull seals such items again under the
    current key; the full resync did not, and A's next rename of the
    subfolder raised CryptoError (its name no longer opened)."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        db = machine.devices["A"].vault.db
        sub = db.fetchone(
            "SELECT id, parent_id FROM nodes WHERE is_deleted = 0 AND parent_id IN "
            "(SELECT id FROM nodes WHERE parent_id IS NOT NULL)"
        )
        machine.invite_member(_Scripted(device="A"))
        member = machine._active_members()[-1]
        machine._grant("A", member, sub["parent_id"], "write")
        machine.pull(_Scripted(device="B"), None)
        machine.rename_folder(_Scripted(device="A", folder=sub["id"]))
        machine.rename_folder(_Scripted(device="A", folder=sub["id"]))
        machine.revoke(_Scripted(device="B", member=member), None)
        assert member in machine.revoked, machine._trace()
        machine.full_resync(_Scripted(device="A"))
        assert machine.log[-1] == "A: full resync", machine._trace()
        machine.rename_folder(_Scripted(device="A", folder=sub["id"]))
        machine.track_member_keys()
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_sync_state_machine_withheld_keys_after_a_revocation(loopback_server, monkeypatch):
    """Run on S4a (reproduce_failure AXicY3BkcBR11HNUZHAEQxBicFQFsZlAhA5YFABcKASH):
    A grants a folder to a member, a new device C revokes the member (re-keys
    the folder), and the server leaves every key out of A's next pull. The
    pull crashed on commit with FOREIGN KEY constraint failed."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        member = machine._active_members()[0]
        folder = sorted(machine._folders("A"))[0]
        machine.grant(_Scripted(device="A", member=member, folder=folder), "read")
        machine.connect_another_device()
        machine.revoke(_Scripted(device="C", member=member), None)
        machine.server_withholds(_Scripted(device="A"), "dek")
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_sync_state_machine_withheld_keys_after_a_lost_rekey_reply(loopback_server, monkeypatch):
    """Nightly run on 782dde8 (seed 331791379353857271750628859435997544833):
    B's re-key after a revocation landed with its reply lost, and the server
    left the batch's new keys out of B's next pull while sending the copies
    sealed with them. Back clean, the copies were not collected again, and
    every push of B stopped as 'Atomic re-key batch is missing 2 local
    object(s)'."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        db = machine.devices["A"].vault.db
        top = db.fetchone(
            "SELECT id FROM nodes WHERE parent_id = (SELECT id FROM nodes WHERE parent_id IS NULL) "
            "AND id IN (SELECT parent_id FROM nodes) AND is_deleted = 0"
        )["id"]
        sub = db.fetchone("SELECT id FROM nodes WHERE parent_id = ?", (top,))["id"]
        entry = db.fetchone("SELECT id FROM entries WHERE node_id = ? ORDER BY id", (top,))["id"]
        member = machine._active_members()[0]
        machine.grant(_Scripted(device="A", member=member, folder=top), "read")
        machine.rotate_identity(_Scripted(device="B"), None)
        machine.server_lies_into_full_resync(_Scripted(device="B"), "check_token", False)
        machine.move_entry(_Scripted(device="A", entry=entry, target=sub))
        machine.server_makes_up_a_member(_Scripted(device="A", folder=top, eve_writes=None))
        machine.member_sync(_Scripted(member=member))
        machine.move_entry(_Scripted(device="B", entry=entry, target=sub))
        machine.revoke(_Scripted(device="B", member=member), "after")
        machine.invite_member(_Scripted(device="B"))
        machine.server_withholds(_Scripted(device="B"), "dek")
        assert "withholds" in machine.log[-1] and "accepted" in machine.log[-1], machine._trace()
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_sync_state_machine_pending_rekey_copy_moved_out_here(loopback_server, monkeypatch):
    """Nightly run on c78fd19: A's re-key after a revocation stayed pending, B
    deleted an entry of the re-keyed folder, and A moved its copy into a
    subfolder under another key. The rebase only looked inside the re-keyed
    folders, so the batch kept its stale copy of that entry and every push of
    A stopped as 'Atomic re-key batch conflict'."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SecondAdminMachine.server = loopback_server
    machine = SecondAdminMachine()
    try:
        db = machine.devices["A"].vault.db
        top = db.fetchone(
            "SELECT id FROM nodes WHERE parent_id = (SELECT id FROM nodes WHERE parent_id IS NULL) "
            "AND id IN (SELECT parent_id FROM nodes) AND is_deleted = 0"
        )["id"]
        sub = db.fetchone("SELECT id FROM nodes WHERE parent_id = ?", (top,))["id"]
        entry = db.fetchone("SELECT id FROM entries WHERE node_id = ? ORDER BY id", (top,))["id"]
        member = machine._active_members()[-1]
        machine.revoke(_Scripted(device="A", member=member), "before")
        assert "RekeyPending" in machine.log[-2], machine._trace()
        machine.concurrent_change(_Scripted(**{
            "devices": ["B", "A"], "object": entry, "B op": "delete", "A op": "move", "target": sub,
        }), True)
        machine.push(_Scripted(device="A"), None)
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_sync_state_machine_keep_server_after_a_move_away_and_back(loopback_server, monkeypatch):
    """Nightly second-admin run on c78fd19: B re-sealed an entry (there an
    identity rotation), A moved it into a subfolder and back, kept the server copy of
    the conflict, and B then deleted the folder. A's moves equalled the server
    copy by state and the model counted them as kept, so B's later delete
    looked like a change of A lost without a conflict."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        db = machine.devices["A"].vault.db
        top = db.fetchone(
            "SELECT id FROM nodes WHERE parent_id = (SELECT id FROM nodes WHERE parent_id IS NULL) "
            "AND id IN (SELECT parent_id FROM nodes) AND is_deleted = 0"
        )["id"]
        sub = db.fetchone("SELECT id FROM nodes WHERE parent_id = ?", (top,))["id"]
        entry = db.fetchone("SELECT id FROM entries WHERE node_id = ? ORDER BY id", (top,))["id"]
        # A newer server copy in the same state (name, folder): B re-seals it.
        machine._local("B", f"re-seal {entry}", lambda v: v.update_entry(
            entry, fields=[{"key": "password", "value": "re-sealed", "sensitive": True}]
        ))
        machine.push(_Scripted(device="B"), None)
        machine.move_entry(_Scripted(device="A", entry=entry, target=sub))
        machine.move_entry(_Scripted(device="A", entry=entry, target=top))
        machine.push(_Scripted(device="A"), None)
        machine.pull(_Scripted(device="A"), None)
        assert entry in {c["id"] for c in machine.devices["A"].client.get_pull_conflicts()}, (
            machine._trace()
        )
        machine.resolve_conflicts(_Scripted(device="A", keep="server"))
        machine.delete_folder(_Scripted(device="B", folder=top))
        machine.push(_Scripted(device="B"), None)
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_sync_state_machine_keep_server_after_moving_on_into_its_folder(loopback_server, monkeypatch):
    """R16-Z SM23a (gate 20 on c18a908): B moved an entry into a subfolder, A
    moved it elsewhere and on into that subfolder, unsent, and C's next pull
    credited the server copy with A's moves (the same state). A kept the server
    copy of the conflict and B edited the entry on: nothing of A's was lost,
    yet A's first move looked lost without a conflict."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        db = machine.devices["A"].vault.db
        top = db.fetchone(
            "SELECT id FROM nodes WHERE parent_id = (SELECT id FROM nodes WHERE parent_id IS NULL) "
            "AND id IN (SELECT parent_id FROM nodes) AND is_deleted = 0"
        )["id"]
        sub = db.fetchone("SELECT id FROM nodes WHERE parent_id = ?", (top,))["id"]
        entry = db.fetchone("SELECT id FROM entries WHERE node_id = ? ORDER BY id", (top,))["id"]
        machine.connect_another_device()
        machine.move_entry(_Scripted(device="B", entry=entry, target=sub))
        machine.push(_Scripted(device="B"), None)
        machine.create_folder(_Scripted(device="A", parent="ROOT"))
        away = next(f for f in machine._folders("A") if f not in (top, sub))
        machine.move_entry(_Scripted(device="A", entry=entry, target=away))
        machine.move_entry(_Scripted(device="A", entry=entry, target=sub))
        machine.pull(_Scripted(device="C"), None)  # B does not pull: it edits on its own move
        machine.push(_Scripted(device="A"), None)
        machine.pull(_Scripted(device="A"), None)
        assert entry in {c["id"] for c in machine.devices["A"].client.get_pull_conflicts()}, (
            machine._trace()
        )
        machine.resolve_conflicts(_Scripted(device="A", keep="server"))
        machine.edit_entry(_Scripted(device="B", entry=entry))
        machine.push(_Scripted(device="B"), None)
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_sync_state_machine_pulled_version_the_restore_lost(loopback_server, monkeypatch):
    """Nightly stateful-deep run on adc393a: A moved an entry twice, C pulled
    the second move, and the server was restored from a backup before both.
    B then changed the entry on top of the backup. C's full resync kept its
    higher version and took B's copy for its base, so C's push replaced B's
    change without a conflict: B's copy was committed after C's version."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        db = machine.devices["A"].vault.db
        top = db.fetchone(
            "SELECT id FROM nodes WHERE parent_id = (SELECT id FROM nodes WHERE parent_id IS NULL) "
            "AND id IN (SELECT parent_id FROM nodes) AND is_deleted = 0"
        )["id"]
        sub = db.fetchone("SELECT id FROM nodes WHERE parent_id = ?", (top,))["id"]
        entry = db.fetchone("SELECT id FROM entries WHERE node_id = ? ORDER BY id", (top,))["id"]
        machine.server_backup()
        machine.move_entry(_Scripted(device="A", entry=entry, target=sub))
        machine.push(_Scripted(device="A"), None)
        machine.move_entry(_Scripted(device="A", entry=entry, target=top))
        machine.push(_Scripted(device="A"), None)
        machine.connect_another_device()
        machine.server_restore()
        machine.edit_entry(_Scripted(device="B", entry=entry))
        machine.push(_Scripted(device="B"), None)
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


@pytest.mark.skipif(not NODE, reason="the web tab needs Node >= 24.7")
def test_sync_state_machine_edit_after_a_pull_with_nothing_withheld(loopback_server, monkeypatch):
    """Nightly run on c78fd19: the web client's edit landed with its reply lost,
    B pulled it in a 'withhold' step that found nothing to hold back, then
    edited it. The step returned without learning what B pulled, and the
    settle took B's edit for one that lost the web client's change."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    SyncMachine.server = loopback_server
    machine = SyncMachine()
    try:
        db = machine.devices["A"].vault.db
        top = db.fetchone(
            "SELECT id FROM nodes WHERE parent_id = (SELECT id FROM nodes WHERE parent_id IS NULL) "
            "AND id IN (SELECT parent_id FROM nodes) AND is_deleted = 0"
        )["id"]
        entry = db.fetchone("SELECT id FROM entries WHERE node_id = ? ORDER BY id", (top,))["id"]
        machine.open_web_tab()
        machine.web_edit_entry(_Scripted(entry=entry), "after")
        machine.web_refresh(None)
        machine.server_withholds(_Scripted(device="B"), "envelope")
        assert "had no envelope" in machine.log[-1], machine._trace()
        machine.edit_entry(_Scripted(device="B", entry=entry))
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_sync_state_machine_second_admin(loopback_server):
    SecondAdminMachine.server = loopback_server
    run_state_machine_as_test(
        SecondAdminMachine,
        settings=settings(
            max_examples=DEEP or 6,
            stateful_step_count=25,
            deadline=None,
            derandomize=not DEEP,
            database=None,
            suppress_health_check=list(HealthCheck),
            print_blob=True,
        ),
    )


class _FoundedAfterAGrant(TeamLogMachine):
    GRANT_BEFORE_FOUNDING = True


@pytest.mark.skipif(not NODE, reason="the web tab needs Node >= 24.7")
@pytest.mark.parametrize("how", ["granted", "founded", "created", "moved"])
def test_sync_state_machine_team_folder_with_a_folder_key_below(loopback_server, monkeypatch, how):
    """Review e443cbc R15, goal #429 (TeamLogMachine, first counterexample): a
    folder with a key of its own below a team folder, a key the log does not
    know. Every client refuses what it seals ('sealed with a key the team log
    does not know'), so the admin's own items there were gone on the web and a
    new device, and one written there later never left the desktop. It got
    there when a grant or the founding made the folder above a team folder
    ('granted', 'founded'), when the desktop gave a new folder in a team folder
    a key of its own ('created'), and when a folder with its own key moved into
    one ('moved')."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)  # outside a Hypothesis run
    klass = _FoundedAfterAGrant if how == "founded" else TeamLogMachine
    klass.server = loopback_server
    machine = klass()
    try:
        member = machine._active_members()[0]
        top = machine._folders("A")[0]
        if how != "founded":
            machine._grant("A", member, top, "read")
        machine.track_member_keys()  # an invariant: Hypothesis runs it between steps
        if how in ("created", "moved"):
            machine._settle(lambda _obj: "server")
            name, entry = machine._token("F"), machine._token("E")
            parent, before = (top if how == "created" else None), set(machine._folders("A"))
            machine._local("A", f"create folder {name} under {parent}", lambda v: v.create_node(name, parent))
            (folder,) = set(machine._folders("A")) - before
            machine._local("A", f"create entry {entry} in {folder}", lambda v: v.create_entry(
                folder, entry, [{"key": "password", "value": entry, "sensitive": True}]))
            if how == "moved":
                machine._settle(lambda _obj: "server")
                machine._local("A", f"move {folder} under {top}", lambda v: v.move_node(folder, top))
        machine.open_web_tab()
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


@pytest.mark.skipif(not NODE, reason="the web tab needs Node >= 24.7")
@pytest.mark.parametrize("who", ["desktop", "web"])
def test_sync_state_machine_team_trash_and_history_after_a_rekey(loopback_server, monkeypatch, who):
    """Review e443cbc R15, goal #429 (TeamLogMachine): an entry of a team
    folder deleted (on this desktop or on the web), and another edited, before
    a revocation re-keyed the folder. The trash and the entry history keep
    what was sealed under the folder's earlier key; the desktop opened it only
    for a key the log names current (may_hold_key), so the admin's own deleted
    entry read '(unreadable here)' and could not be restored, and the earlier
    version could not be read. Design §4.3.3: an old key reads history."""
    from sezam.vault import trash

    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        member = machine._active_members()[0]
        top = machine._folders("A")[0]
        snap = snapshot(machine.devices["A"].vault)
        gone, edited = [e for e in machine._entries("A") if snap[e][2] == top][:2]
        machine._grant("A", member, top, "read")
        machine._member_sync(member)
        machine.track_member_keys()
        machine.edit_entry(_Scripted(device="A", entry=edited))
        if who == "web":
            machine.open_web_tab()
            machine.web_delete_entry(_Scripted(entry=gone), None)
        else:
            machine.delete_entry(_Scripted(device="A", entry=gone))
        machine._settle(lambda _obj: "server")
        machine.revoke(_Scripted(device="A", member=member), None)
        machine._settle(lambda _obj: "server")

        vault = machine.devices["A"].vault
        listed = {item["id"]: item["name"] for item in trash.list_trash(vault)}
        assert listed.get(gone) == snap[gone][1], listed
        version = trash.list_history(vault, edited)[-1]
        assert trash.read_history(vault, edited, version["id"])
        machine._local("A", f"restore {gone} from the trash", lambda v: trash.restore_entry(v, gone))
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


@pytest.mark.skipif(not NODE, reason="the web tab needs Node >= 24.7")
def test_sync_state_machine_web_retry_after_a_rekey_elsewhere(loopback_server, monkeypatch):
    """R16-Z SM17 (deep run on 6e958f6, TeamLogMachine): a folder made on the
    web stayed queued in a team folder; the admin's desktop then lowered a
    member there from write to read and re-keyed the folder. Retry checked
    the queued folder against the log of the page's last pull, where the
    folder still waited for that re-key: it threw 'folder waits for a re-key'
    before its own pull, so no Retry ever sent it. The desktop's push reads
    the server's log again; the page's Retry does too."""
    from sezam.vault.team_log_local import local_team_state

    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        member = machine._active_members()[0]
        top = machine._folders("A")[0]
        machine._grant("A", member, top, "write")
        machine._member_sync(member)
        machine.track_member_keys()
        machine.open_web_tab()
        machine.web_create_folder(_Scripted(parent=top), "before")
        queued = set(machine.web_view["dirty"])
        assert queued, machine._trace()
        machine._grant("A", member, top, "read")  # write -> read: the folder waits for a re-key
        machine.web_refresh(None)  # the page's log: the folder waits
        machine.push(_Scripted(device="A"), None)  # 'sezam push' makes it
        assert not teamlog.is_stale(local_team_state(machine.devices["A"].vault.db), top), machine._trace()
        machine._web_settle()  # the banner's Retry, no pull since the re-key
        unsent = set(machine.web_view["dirty"]) | set(machine.web_view["conflicts"])
        assert not queued & unsent, f"{sorted(queued & unsent)} still queued\n" + machine._trace()
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


@pytest.mark.skipif(not NODE, reason="the web tab needs Node >= 24.7")
def test_sync_state_machine_web_retry_of_a_lost_tombstone_after_a_rekey(loopback_server, monkeypatch):
    """R16-N1 (nightly stateful-deep 45604036980 on d441587, SecondAdminMachine):
    A deleted a shared folder; the page pulled the tombstones; the server was
    restored from a backup taken before, so the page queued them again
    (requeueWritesTheServerLost). A tombstone keeps the blob of the version
    below it. B, which never saw the delete, removed the member and re-keyed
    the folder. Retry opened every queued item to seal it under the new key,
    tombstones too, at the tombstone's version: 'ciphertext cannot be
    decrypted using that key', and nothing in the queue left. The desktop and
    the phone send a tombstone as it is (the trash keeps the old key)."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    SecondAdminMachine.server = loopback_server
    machine = SecondAdminMachine()
    try:
        folder = machine._folders("A")[0]
        member = next(u for u in machine._active_members() if machine.write_granted[u] or machine.granted[u])
        machine.pull(_Scripted(device="B"), None)
        machine.server_backup()
        machine.delete_folder(_Scripted(device="A", folder=folder))
        machine.push(_Scripted(device="A"), None)
        machine.open_web_tab()
        machine.server_restore()
        machine.web_refresh(None)  # the restore accepted: the tombstones queued again
        assert machine.web_view["dirty"], machine._trace()
        machine.revoke(_Scripted(device="B", member=member), None)
        machine.web_refresh(None)  # the re-key pulled
        machine._web_settle()
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


@pytest.mark.parametrize("then", ["push", "invite"])
def test_sync_state_machine_team_log_pinned_by_the_account_keys(loopback_server, monkeypatch, then):
    """Review e443cbc R15, goal #429 (TeamLogMachine): the admin's second
    desktop B has not pulled since the log was founded when A rotates the
    identity. B takes the account keys over, and with them the log's anchor
    (import_account_anchor), but not the log: every push and invitation then
    stopped with 'not downloaded yet; pull it first'. The log is fetched."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        machine.rotate_identity(_Scripted(device="A"), None)
        machine._push("A")
        if then == "push":
            machine.rename_folder(_Scripted(device="B", folder=machine._folders("B")[0]))
            machine._push("B")
        else:
            machine._take_over_account_keys("B", abandon=False)
            machine._invite_member("B")
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_sync_state_machine_team_write_before_the_pinned_log_is_pulled(loopback_server, monkeypatch):
    """R16-Z SM23c (gate 20, team_log): the founder's device holds the log's
    pin (here 'team-log confirm-founder' before the first pull) but not the
    log. A delete in a team folder was refused (INV-5) telling the founder's
    own device to compare the founder's fingerprint and run 'team-log
    confirm-founder' - done already, no way out (INV-7). It says to pull;
    after the pull the write goes."""
    from sezam.vault.team_log_local import local_team_state
    from sezam.vault.team_log_state import CONFIRMED_GENESIS_META

    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        folder = machine._folders("A")[0]
        machine._take_over_account_keys("B", abandon=False)
        vault = machine.devices["B"].vault
        assert local_team_state(vault.db) is None
        vault.db.set_meta(CONFIRMED_GENESIS_META, local_team_state(machine.devices["A"].vault.db).genesis_hash)
        entry = vault.db.fetchone("SELECT id FROM entries WHERE node_id = ? AND is_deleted = 0", (folder,))["id"]
        with pytest.raises(RuntimeError, match="not downloaded yet; pull it first"):
            vault.delete_entry(entry)
        machine._pull("B")
        machine.delete_entry(_Scripted(device="B", entry=entry))
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_sync_state_machine_team_device_joins_while_the_pinned_log_is_lost(loopback_server, monkeypatch):
    """Review e443cbc R15, goal #429 (TeamLogMachine, randomized run): A's
    identity rotation published the log's anchor with the account keys, then
    the server lost the log. A new desktop C connects: its connect pull is
    refused (the pinned log is not there) and C pushed its own pristine root;
    the pull after it kept that second root, shown as a folder 'Root' no
    device wrote. Nothing goes out before the first pull took the tree."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        machine.rotate_identity(_Scripted(device="A"), None)
        machine._push("A")
        machine.operator_loses_the_log()
        machine._add_device("C")
        machine._settle(lambda _obj: "server")
        def roots(device):
            return sorted(tuple(r) for r in machine.devices[device].vault.db.fetchall(
                "SELECT id, is_deleted FROM nodes WHERE parent_id IS NULL"))

        assert roots("C") == roots("A"), (roots("C"), roots("A"), machine._trace())
    finally:
        machine.teardown()


def test_sync_state_machine_team_rekey_superseded_by_another_device(loopback_server, monkeypatch):
    """Review e443cbc R15, goal #429 (TeamLogMachine, randomized run): B
    revoked a member and its re-key push failed (the batch stays pending);
    A's next sync finished the queued revocation and re-keyed the folder in
    the log first. B's push then built its batch's folder.key onto the old
    key, the log refused it (folder_key_moved) before the server saw it, and
    every sync failed naming 'sezam abandon-rekey'. The superseded batch is
    dropped as for the server's batch conflict."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        member = machine._active_members()[0]
        machine._settle(lambda _obj: "server")
        machine.track_member_keys()
        folder = machine._folders("A")[0]
        machine._grant("A", member, folder, "read")
        assert machine.log[-1].startswith("A: grant "), machine._trace()
        machine._settle(lambda _obj: "server")
        machine.revoke(_Scripted(device="B", member=member), "before")
        assert rekey_batch(machine.devices["B"].vault.db), machine._trace()
        machine._push("A")
        machine._pull("A")
        machine._settle(lambda _obj: "server")
        assert not rekey_batch(machine.devices["B"].vault.db), machine._trace()
    finally:
        machine.teardown()


def test_sync_state_machine_team_admin_resends_a_rotation_the_server_lost(loopback_server, monkeypatch):
    """Review e443cbc R15, goal #442 (derandomized TeamLogMachine run): the
    admin's desktop A, which sealed a member's envelope, rotated the identity;
    the server went back to a backup from before it and got the log's
    member.keys back. Until A sends the rotation again its session may only
    pull and push that rotation, but 'sezam push' first listed the users for
    the revocation queue: 403 'Scoped JWT (key_rotation)' on every push, so
    the rotation never went out again. The queue waits for the key change."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        machine._settle(lambda _obj: "server")
        machine.track_member_keys()
        member = machine._active_members()[0]
        machine._grant("A", member, machine._folders("A")[0], "read")
        machine._settle(lambda _obj: "server")
        machine.server_backup()
        machine.rotate_identity(_Scripted(device="A"), None)
        machine._push("A")
        machine.track_member_keys()
        machine.server_restore()
        machine._push("A")
        machine.track_member_keys()
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_sync_state_machine_team_restore_from_before_two_rotations(loopback_server, monkeypatch):
    """Review e443cbc R15, goal #429 (TeamLogMachine, randomized run): the
    admin's desktop B rotated the account's identity, A took the keys over and
    rotated again, then the server went back to a backup from before both.
    Until A sends its rotation again, the server signs the account in with
    the backup's key, which the put-back log retired: B and the page are
    refused (identity_key_retired) and a member cannot check the admin's
    earlier objects ('invalid signature'). That is fail-closed, not a
    lock-out: the machine took it for a failure; they wait for A
    (_rotation_the_log_waits_for), and A's next push lets every device on."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        machine._settle(lambda _obj: "server")
        machine.track_member_keys()
        machine._appoint(machine._member_desktops()[0])
        machine.rotate_identity(_Scripted(device="B"), "before")
        machine.server_backup()
        machine._push("B")
        machine.track_member_keys()
        for user_id in machine._member_desktops():
            machine._member_sync(user_id)
        machine._push("A")
        machine._pull("A")
        machine.rotate_identity(_Scripted(device="A"), None)
        machine._push("A")
        machine.server_restore()
        machine._settle(lambda _obj: "server")
        admin = machine.devices["A"].vault
        account = next(u for u in machine.db._storage["users"] if u["id"] == admin.db.get_meta("user_id"))
        assert bytes(account["signing_pk"]) == admin.keypair.signing_pk, machine._trace()
        assert machine.devices["B"].vault.keypair.signing_pk == admin.keypair.signing_pk, machine._trace()
        assert not machine._waiting_members(), machine._trace()
    finally:
        machine.teardown()


def test_sync_state_machine_team_founder_takes_over_a_rotation_made_without_the_log(
    loopback_server, monkeypatch,
):
    """Review e443cbc R15, goal #429 (TeamLogMachine, randomized run): the
    server lost the log; the admin's second desktop B, which never held it,
    rotates the account's identity, so no member.keys links the new keys to
    the founder's. A, which holds the log, takes the keys over: its log names
    keys the account no longer has, and every pull and push stopped with
    'founder is not confirmed'. A held both keys at the take-over; it proves
    the link (member.keys) once the log is back."""
    from sezam.vault.team_log_local import local_team_state

    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        machine.operator_loses_the_log()
        machine.rotate_identity(_Scripted(device="B"), None)
        machine._push("B")
        machine._push("A")
        member = machine._active_members()[0]
        machine._settle(lambda _obj: "server")
        machine.track_member_keys()
        machine._grant("A", member, machine._folders("A")[0], "read")
        assert machine.log[-1].startswith("A: grant "), machine._trace()
        machine._settle(lambda _obj: "server")
        vault = machine.devices["A"].vault
        state = local_team_state(vault.db)
        admin = vault.db.get_meta("user_id")
        assert state.members[admin].signing_pk == vault.keypair.signing_pk.hex(), machine._trace()
        assert machine._server_log(), machine._trace()
    finally:
        machine.teardown()


def test_sync_state_machine_team_founder_takes_over_an_org_recovery_without_the_anchor(
    loopback_server, monkeypatch,
):
    """Review e443cbc R15, goal #429 (TeamLogMachine, randomized run): the
    founder's desktop A rotates its identity and the push fails before it is
    sent. The admin's second desktop B runs the org recovery with two shares;
    the account keys it sends carry no team anchor (the recovered password
    never had one). A took the change over and refused it ('missing this
    device's authenticated anchor'): every push of A wanted a full resync.
    A keeps the anchor it holds when the server's KEK is one this account
    left without it."""
    from sezam.vault.team_log_local import local_team_state

    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        machine.rotate_identity(_Scripted(device="A"), "before")
        machine.setup_org_recovery(_Scripted(device="B"))
        assert machine._org_recovery_usable(), machine._trace()
        machine._org_recovery(None)
        machine._push("A")
        assert not [line for line in machine.log if "authenticated anchor" in line], machine._trace()
        machine._settle(lambda _obj: "server")
        vault = machine.devices["A"].vault
        state = local_team_state(vault.db)
        admin = vault.db.get_meta("user_id")
        assert state.members[admin].signing_pk == vault.keypair.signing_pk.hex(), machine._trace()
    finally:
        machine.teardown()


def test_sync_state_machine_team_founder_takes_over_a_rotation_while_its_own_waits(
    loopback_server, monkeypatch,
):
    """R16-Z SM23d (gate 20, team_log): the founder's desktop A rotated its
    identity and the push failed before it was sent; B's rotation landed and
    its reply was lost; the server then lost the log. A took B's keys over
    holding the old ones only in its pending rotation, so it kept no link:
    the log it put back named keys the account no longer signs in with
    (refused), and every pull and full resync of A stopped with 'differs from
    the independently confirmed genesis', which offers to forget the pin."""
    from sezam.vault.team_log_local import local_team_state

    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        machine.rotate_identity(_Scripted(device="A"), "before")
        machine.rotate_identity(_Scripted(device="B"), "after")
        machine.operator_loses_the_log()
        machine.full_resync(_Scripted(device="A"))
        assert not [line for line in machine.log if "TeamLogMismatch" in line], machine._trace()
        assert machine._server_log(), machine._trace()
        machine._settle(lambda _obj: "server")
        vault = machine.devices["A"].vault
        state = local_team_state(vault.db)
        admin = vault.db.get_meta("user_id")
        assert state.members[admin].signing_pk == vault.keypair.signing_pk.hex(), machine._trace()
    finally:
        machine.teardown()


def test_sync_state_machine_team_grant_whose_reply_was_lost_before_a_revocation(
    loopback_server, monkeypatch,
):
    """Review e443cbc R15, goal #429 (TeamLogMachine, randomized run): A
    grants a folder to a member and the push reply is lost (the server has
    the envelope). B, which has not pulled it, revokes the member and
    re-keys the folder; its re-key withdraws only the envelopes B holds. A's
    pull ignored its own envelope as refused by the log, and A queued no
    withdrawal (the log had replaced the key): the revoked member kept a live
    envelope on the server for good."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        member = machine._active_members()[0]
        machine._pull("B")
        first, second = machine._folders("A")[:2]
        machine._grant("B", member, first, "write")
        machine._grant("A", member, second, "write")
        assert machine.log[-1].startswith("A: grant "), machine._trace()
        machine.revoke(_Scripted(device="B", member=member), None)
        assert machine.log[-2].endswith("re-keyed 2"), machine._trace()

        machine._settle(lambda _obj: "server")
        machine._check_members()
    finally:
        machine.teardown()


def test_sync_state_machine_team_write_lowered_to_read(loopback_server, monkeypatch):
    """Review e443cbc R15, goal #429 (TeamLogMachine, randomized run): A
    grants a member write, B lowers it to read. The log marks the folder's
    key stale (the member knew it with write) and refuses every new write
    there until a re-key, which no device made: A's new item waited for good
    and the sync never settled. An admin's push re-keys it; the member keeps
    read access."""
    from sezam.vault.team_log_local import local_team_state

    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        member = machine._active_members()[0]
        folder = machine._folders("A")[0]
        machine.track_member_keys()
        machine._grant("A", member, folder, "write")
        machine._pull("B")
        machine._grant("B", member, folder, "read")
        assert machine.log[-1].startswith("B: grant "), machine._trace()
        machine.create_entry(_Scripted(device="A", folder=folder))
        machine._settle(lambda _obj: "server")
        state = local_team_state(machine.devices["A"].vault.db)
        assert not state.stale.get(folder), machine._trace()
        assert state.access[folder][member] == "read", machine._trace()
    finally:
        machine.teardown()


def test_sync_state_machine_team_change_queued_before_a_rotation_taken_over(loopback_server, monkeypatch):
    """Review e443cbc R15, goal #429 (TeamLogMachine): the admin's desktop C,
    connected after the founding, revokes a member while A's identity
    rotation is on the server and C has neither the new keys nor the log
    records naming them: the removal stays queued (RekeyPending). C's push
    takes the keys over; the queued member.remove, checked against C's log
    (still naming the old key) and signed with the new one, failed as
    bad_signature and was set aside for good: the member stayed in the log."""
    from sezam.vault.team_log_local import local_team_state, set_aside_changes

    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        member = machine._active_members()[0]
        machine._add_device("C")
        machine.rotate_identity(_Scripted(device="A"), None)
        machine._push("A")
        machine.revoke(_Scripted(device="C", member=member), None)
        assert "RekeyPending" in machine.log[-2], machine._trace()
        machine._settle(lambda _obj: "server")
        vault = machine.devices["C"].vault
        assert not set_aside_changes(vault.db), set_aside_changes(vault.db)
        state = local_team_state(vault.db)
        assert not state.members[member].active, machine._trace()
    finally:
        machine.teardown()


def test_sync_state_machine_team_grant_while_own_rotation_waits(loopback_server, monkeypatch):
    """Review e443cbc R15, goal #429 (TeamLogMachine, randomized run): the
    admin's desktop B rotates its identity and the push fails before it is
    sent. A grant on B then signed its log record with the new key while the
    log still named the old one (member.keys goes last): B's own replay
    refused it (bad_signature) and the grant crashed. It is signed with the
    key the log names, and the rotation follows it."""
    from sezam.vault.team_log_local import local_team_state

    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        member = machine._active_members()[0]
        machine._member_sync(member)
        machine.rotate_identity(_Scripted(device="B"), "before")
        machine.track_member_keys()
        folder = machine._folders("B")[0]
        machine._grant("B", member, folder, "read")
        assert machine.log[-1].startswith("B: grant "), machine._trace()
        machine._settle(lambda _obj: "server")
        state = local_team_state(machine.devices["A"].vault.db)
        admin = machine.devices["B"].vault.db.get_meta("user_id")
        assert state.members[admin].signing_pk == machine.devices["B"].vault.keypair.signing_pk.hex()
        assert state.access.get(folder, {}).get(member) == "read", machine._trace()
    finally:
        machine.teardown()


@pytest.mark.parametrize("rotated", [("A",), ("A", "B")])
def test_sync_state_machine_team_log_member_confirms_a_rotating_founder(loopback_server, monkeypatch, rotated):
    """Deep run (goal #429): a member invited while the founder's rotation had
    not reached the server confirmed the founder's new key, which the log did
    not hold, and stayed 'founder is not confirmed' for good after the other
    device's rotation won. As 'sezam team-log confirm-founder' does, the member
    trusts only a fingerprint linked to the genesis identity and asks again."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        machine.rotate_identity(_Scripted(device="A"), "before")
        if rotated == ("A", "B"):
            machine.rotate_identity(_Scripted(device="B"), "before")
        machine.invite_member(_Scripted(device="A"))
        member = next(reversed(machine.members))
        if rotated == ("A",):
            machine.rotate_identity(_Scripted(device="B"), "before")
        else:
            # Neither device shows a key the log holds: refused, not trusted.
            assert member in machine.unconfirmed, machine._trace()
        machine._settle(lambda _obj: "server")
        assert member not in machine.unconfirmed and member not in machine.waiting, machine._trace()
        assert any(line.startswith(f"{machine.members[member].name}: sync ->") for line in machine.log), machine._trace()
    finally:
        machine.teardown()


def test_sync_state_machine_team_log_subfolder_made_before_the_grant_was_pulled(loopback_server, monkeypatch):
    """Stateful run on ab915bc (goal #429): B made a subfolder, with a key of
    its own, in a folder A had just shared and B had not pulled the grant of.
    The grant logged only the subfolders A knew, so the subfolder's key never
    reached the log and every item put there later was refused ('sealed with
    a key the team log does not know') and stayed unpushed for good."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        machine.create_folder(_Scripted(device="A", parent="ROOT"))
        machine.push(_Scripted(device="A"), None)
        machine.pull(_Scripted(device="B"), None)
        logged = machine.devices["A"].client.team_state().folders
        db = machine.devices["A"].vault.db
        folder = next(f for f in machine._folders("A") if f not in logged and db.fetchone(
            "SELECT 1 FROM nodes n JOIN deks d ON d.id = n.dek_id WHERE n.id = ? AND d.node_id = n.id", (f,)))
        machine._grant("A", machine._active_members()[0], folder, "write")
        assert folder in machine.devices["A"].client.team_state().folders, machine._trace()
        before = set(machine._folders("B"))
        machine.create_folder(_Scripted(device="B", parent=folder))
        sub = next(iter(set(machine._folders("B")) - before))
        assert machine.devices["B"].vault.db.fetchone(
            "SELECT 1 FROM deks WHERE node_id = ?", (sub,)), "the subfolder has no key of its own\n" + machine._trace()
        machine.push(_Scripted(device="B"), None)
        machine.pull(_Scripted(device="B"), None)
        machine.create_entry(_Scripted(device="B", folder=sub))
        machine.track_member_keys()  # the admin keys settle opens the member's envelopes with
        machine._settle(lambda _obj: "server")
        assert not any("sealed with a key the team log does not know" in line for line in machine.log), (
            machine._trace())
    finally:
        machine.teardown()


def test_sync_state_machine_team_log_under_attack(loopback_server, monkeypatch):
    """Capability run 430 (goal #429): every forgery a member can sign, sent
    to append and to restore, and every lie a server can tell about the log,
    with the log invariants after each step. Disabling one log rule on the
    server or in the clients (e.g. not_admin) turns this red."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()

    def check():
        machine.track_member_keys()
        machine.the_server_log_follows_the_rules()
        machine.every_device_holds_one_log()
        machine.an_envelope_goes_with_its_access()
        machine.a_waiting_member_has_a_way_out()

    try:
        member = machine._active_members()[0]
        machine._grant("A", member, machine._folders("A")[0], "read")
        machine._member_sync(member)
        check()
        for kind in TeamLogMachine.FORGERIES:
            for path in ("append", "restore"):
                before = machine._server_log()
                machine._post_forgery(teamlog.replay(before), before, member, kind, path)
                check()
        for lie in TeamLogMachine.LOG_LIES:
            for kind in TeamLogMachine.FORGERIES if lie == "forged record" else ("grant self",):
                for target in range(len(machine._log_vaults())):
                    machine.server_lies_about_the_log(_Scripted(target=target), lie, kind)
                    check()
        for lie in (None, "truncate", "drop a record", "reorder", "old head"):
            for target in range(len(machine._log_holders())):
                machine.user_forgets_the_pin(_Scripted(target=target), lie)
                check()
        machine.operator_loses_the_log()
        check()
        # Capability run 433: a member races the honest devices to the restore.
        for kind in TeamLogMachine.FORGERIES + TeamLogMachine.LOST_LOG_FORGERIES:
            for path in ("restore", "append"):
                machine.member_forges_a_restore_of_the_lost_log(_Scripted(forger=member), kind, path)
                check()
        lost = [line for line in machine.log if "onto the lost log -> " in line]
        assert len(lost) == 2 * len(TeamLogMachine.FORGERIES + TeamLogMachine.LOST_LOG_FORGERIES), machine._trace()
        machine._member_sync(member)
        check()
        machine._settle(lambda _obj: "server")
        check()
        assert machine._server_log(), "nobody put the lost team log back\n" + machine._trace()
    finally:
        machine.teardown()


def test_sync_state_machine_team_log_hands_the_role_over_and_back(loopback_server, monkeypatch):
    """Review 8bc70f7 M1 (goal #417): A -> member -> A with a folder shared
    with the member and one that is not. Before, the first handover granted
    the member write to the second folder (red on ba79e6b at the check after
    that hop, %TEMP%\\r14_m1_sm_mid_red.log); the end-of-trip check alone
    missed it, the folder's grant was not yet in the log at the start."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        member = machine._active_members()[0]
        machine.create_folder(_Scripted(device="A", parent="ROOT"))
        machine.create_folder(_Scripted(device="A", parent="ROOT"))
        machine.push(_Scripted(device="A"), None)
        db = machine.devices["A"].vault.db
        own_key = [f for f in machine._folders("A") if db.fetchone(
            "SELECT 1 FROM nodes n JOIN deks d ON d.id = n.dek_id WHERE n.id = ? AND d.node_id = n.id", (f,))]
        machine._grant("A", member, own_key[0], "read")
        if len(machine._active_members()) < 2:
            machine._invite_member("A")
        other = next(u for u in machine._active_members() if u != member)
        machine._grant("A", other, own_key[1], "read")  # a team folder not shared with the member
        machine._member_sync(member)
        machine.yield_the_admin_role_and_take_it_back(_Scripted(member=member, device="A"), False, False)
        assert any(line.endswith("hands the admin role back") for line in machine.log), machine._trace()
        machine.track_member_keys()
        machine.the_server_log_follows_the_rules()
        machine.an_envelope_goes_with_its_access()
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_sync_state_machine_team_log_handover_sends_a_delete_that_ages_out(loopback_server, monkeypatch):
    """R16-Z SM24b (gate 21 on f963cb2, team_log): A edits an entry and
    deletes it; the handover pushes both, tombstone GC collects the entry, and
    B, which edited it without seeing either, brings it back. The model did
    not credit the handover's push, so A's edit, gone with A's own delete,
    looked lost without a conflict."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        member = machine._active_members()[0]
        entry = sorted(machine._entries("A"))[0]
        machine.edit_entry(_Scripted(device="A", entry=entry))
        machine.delete_entry(_Scripted(device="A", entry=entry))
        machine.edit_entry(_Scripted(device="B", entry=entry))
        machine._member_sync(member)
        machine.yield_the_admin_role_and_take_it_back(_Scripted(member=member, device="A"), False, False)
        assert any(line.endswith("hands the admin role back") for line in machine.log), machine._trace()
        machine.gc_tombstones()
        assert entry in machine.collected, machine._trace()
        machine.track_member_keys()
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


@pytest.mark.parametrize("step", ["push", "full_resync"])
def test_sync_state_machine_team_log_lost_while_a_device_only_pins_it(loopback_server, monkeypatch, step):
    """R16-Z SM25a (gate 22 on 8914bac, team_log): B has not synced since the
    founding and holds no copy of the log. A changes the password and rotates
    its identity; the server loses the log; B takes the account keys over, and with them the confirmed
    genesis, so it refuses the empty log as its push or full resync. That is
    INV-8 (no pin forgotten on its own): B waits, and once A puts the log back
    (INV-7) B follows it. The model raised on the refusal."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        b = machine.devices["B"].vault
        assert not b.db.fetchall("SELECT seq FROM team_log LIMIT 1"), machine._trace()
        machine.change_password(_Scripted(device="A"), None)
        machine.rotate_identity(_Scripted(device="A"), None)
        machine.operator_loses_the_log()
        machine.create_folder(_Scripted(device="B", parent="ROOT"))
        if step == "push":
            machine.push(_Scripted(device="B"), None)
        else:
            machine.full_resync(_Scripted(device="B"))
        assert "B: waits for the lost team log, confirmed_genesis" in machine.log, machine._trace()
        machine._settle(lambda _obj: "server")
        assert machine._server_log(), machine._trace()
        assert b.db.fetchall("SELECT seq FROM team_log LIMIT 1"), machine._trace()
    finally:
        machine.teardown()


def test_sync_state_machine_team_log_key_comes_back_after_the_folder(loopback_server, monkeypatch):
    """R16-Z SM26a (gate 23 on 6858912, team_log): A revokes a member, which
    re-keys a team folder; the server then loses the log records from the
    revocation on (a restore) and keeps the re-sealed folder. B pulls it:
    sealed with a key the log does not know, what is in the folder is not
    applied (fail-closed). A puts the lost records back (INV-7), but B judged
    it once at its pull and never again: B kept the items on the old key, and
    the new ones never showed, for good."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        member = machine._active_members()[0]
        machine._settle(lambda _obj: "server")
        machine.track_member_keys()
        folder = machine._folders("A")[0]
        machine._grant("A", member, folder, "read")
        machine._settle(lambda _obj: "server")
        kept = len(machine._server_log())
        machine.revoke(_Scripted(device="A", member=member), None)
        assert len(machine._server_log()) > kept, machine._trace()
        machine.create_folder(_Scripted(device="A", parent=folder))
        machine._push("A")
        machine.db._storage["team_log"] = sorted(
            machine.db._storage["team_log"], key=lambda r: r["seq"])[:kept]
        machine.log.append("server: lost the team log records from the revocation on")
        machine.pull(_Scripted(device="B"), None)
        ignored = machine.devices["B"].vault.db.get_meta_json("ignored_unauthorized_writes") or {}
        assert folder in ignored.values(), machine._trace()
        machine.pull(_Scripted(device="A"), None)  # puts the lost records back
        assert len(machine._server_log()) > kept, machine._trace()
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_sync_state_machine_team_grant_not_sent_before_the_keys_are_taken_over(loopback_server, monkeypatch):
    """R16-Z SM26b (gate 23 on 6858912, team_log): B rotates the account's
    identity; A, not yet aware, shares a folder with a member. The grant is
    not sent (the key epoch is stale) and waits with its log records. A takes
    the new keys over; its push is lost and the server goes back to a backup
    from before the rotation, so A sends the rotation again and re-seals the
    envelopes it made: the new one went in the rotation's atomic batch, while
    the records stayed with the old one. The server refused it ('another
    account gets a key only with an access.set') and every push of A raised."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        member = machine._active_members()[0]
        machine._settle(lambda _obj: "server")
        machine.track_member_keys()
        machine.server_backup()
        machine.rotate_identity(_Scripted(device="B"), None)
        machine._push("B")
        folder = machine._folders("A")[0]
        machine._grant("A", member, folder, "write")
        assert _GRANT_DEFERRED in machine.log[-1], machine._trace()
        machine.push(_Scripted(device="A"), "after")
        machine.server_restore()
        machine._push("A")
        machine.track_member_keys()  # A sent its rotation again, onto a new key
        machine._settle(lambda _obj: "server")
        assert folder in machine.granted[member], machine._trace()
        state = teamlog.replay(machine._server_log())
        assert state.access.get(folder, {}).get(member) == "write", machine._trace()
    finally:
        machine.teardown()


def test_sync_state_machine_team_rekey_waits_for_the_key_a_restore_lost(loopback_server, monkeypatch):
    """R16-Z SM26c (gate 23 on 6858912, team_log): B revoked a member and its
    re-key push failed (the batch stays pending). A finished the revocation
    and re-keyed the folder first; then the server went back to a backup and
    lost A's re-key, while the log got its folder.key back (INV-7). B's batch
    is refused (folder_key_moved), and no pull binds the folder to A's key
    until A sends it again: every push of B raised 'Atomic re-key batch
    conflict' and named 'sezam abandon-rekey'. It waits for A instead."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        member = machine._active_members()[0]
        machine._settle(lambda _obj: "server")
        machine.track_member_keys()
        folder = machine._folders("A")[0]
        machine._grant("A", member, folder, "read")
        machine._settle(lambda _obj: "server")
        machine.revoke(_Scripted(device="B", member=member), "before")
        assert rekey_batch(machine.devices["B"].vault.db), machine._trace()
        machine.server_backup()
        machine._push("A")
        machine._pull("A")
        machine.server_restore()
        machine._pull("A")  # puts the lost records back
        machine._push("B")
        assert "B: push raised" not in machine._trace(), machine._trace()
        machine._settle(lambda _obj: "server")
        assert not rekey_batch(machine.devices["B"].vault.db), machine._trace()
    finally:
        machine.teardown()


def test_sync_state_machine_team_log_stolen_key_the_member_copy_names(loopback_server, monkeypatch):
    """Deep run on 0daf5f2 (R16-Z SM13, test harness): the member's copy of
    the log predates B's identity rotation. The 'stolen admin key' forgery on
    the lost log was signed with the admin's current key, which that copy does
    not hold, and building it failed (bad_signature) before anything reached
    the server. The thief signs with the key the member's copy trusts."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        member = machine._active_members()[0]
        machine._member_sync(member)
        machine.rotate_identity(_Scripted(device="B"), None)
        machine.pull(_Scripted(device="A"), None)  # A takes the new key too
        machine.operator_loses_the_log(
            _Scripted(forger=member), race="stolen admin key, second admin on the way", path="restore")
        assert any("forges stolen admin key, second admin on the way onto the lost log -> restore refused"
                   in line for line in machine.log), machine._trace()
        # m6 waits (its copy cannot put the log back); B, holding the rotation, does.
        machine._settle(lambda _obj: "server")
        assert machine._server_log() and not machine.waiting, machine._trace()
    finally:
        machine.teardown()


def test_sync_state_machine_team_log_lost_grant_to_a_removed_member(loopback_server, monkeypatch):
    """Deep run on 07487c3 (R16-Z SM15, test harness): the server lost B's
    grant to m6 (restored from a backup), A removed m6, and B sent its lost
    grant again: the log refuses it (not_active) and B sets it aside. The
    user's way out is 'sezam team-log discard N'; the settle takes it."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        member = machine._active_members()[0]
        machine.create_folder(_Scripted(device="B", parent="ROOT"))
        machine.push(_Scripted(device="B"), None)
        machine.pull(_Scripted(device="A"), None)
        machine.pull(_Scripted(device="B"), None)
        machine.server_backup()
        machine._grant("B", member, machine._folders("B")[-1], "read")
        machine.server_restore()
        machine.pull(_Scripted(device="A"), None)
        machine.revoke(_Scripted(device="A", member=member), None)
        machine._settle(lambda _obj: "server")
        assert any("team-log discard" in line for line in machine.log), machine._trace()
    finally:
        machine.teardown()


def test_sync_state_machine_team_handover_after_a_concurrent_move(loopback_server, monkeypatch):
    """R16-N2 (nightly stateful-deep 45604036980 on d441587, TeamLogMachine)."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        member = machine._active_members()[0]
        top = machine._folders("A")[0]
        snap = snapshot(machine.devices["A"].vault)
        below = next(f for f in machine._folders("A") if snap[f][2] == top)
        entry = next(e for e in machine._entries("A") if snap[e][2] == top)
        machine.member_sync(_Scripted(member=member))  # confirms the founder
        machine._settle(lambda _obj: "server")
        machine._grant("A", member, top, "read")
        machine.concurrent_change(_Scripted(devices=["A", "B"], object=entry, target=below,
                                            **{"A op": "move", "B op": "move"}), push_first=False)
        machine.yield_the_admin_role_and_take_it_back(
            _Scripted(member=member, device="A", folder=below), chain=True, unsent=True)
        machine.track_member_keys()  # an invariant: Hypothesis runs it, a script does not
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_sync_state_machine_team_grant_above_a_team_folder_on_a_stale_log(loopback_server, monkeypatch):
    """R16-N2 (nightly stateful-deep 45604036980 on d441587, TeamLogMachine,
    second failure after the first was fixed): B, whose copy of the log is
    older than A's grant of F2, makes a folder in F2 and shares F1 above it.
    The grant went by that copy: F2 looked unlogged and the folder B made
    there went into the log as a team folder of its own. Its key then reached
    m6 by a handover and the admin who took the role back did not hold the
    folder to re-key it (an_envelope_goes_with_its_access)."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        member = machine._active_members()[0]
        machine.member_sync(_Scripted(member=member))  # confirms the founder
        machine._settle(lambda _obj: "server")
        snap = snapshot(machine.devices["A"].vault)
        top = next(f for f in machine._folders("A") if snap[f][2] not in machine._folders("A"))
        below = next(f for f in machine._folders("A") if snap[f][2] == top)
        machine._grant("A", member, below, "read")  # B does not pull it
        before = set(machine._folders("B"))
        name = machine._token("F")
        machine._local("B", f"create folder {name} under {below}", lambda v: v.create_node(name, below))
        made = (set(machine._folders("B")) - before).pop()
        machine._grant("B", member, top, "write")
        logged = teamlog.replay(machine._server_log())
        assert top in logged.folders and below in logged.folders, machine._trace()
        assert made not in logged.folders, (
            f"the grant of {top} logged {made}, a folder below the team folder {below}\n" + machine._trace())
        machine.track_member_keys()
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_sync_state_machine_team_write_on_a_copy_moved_here_unsent(loopback_server, monkeypatch):
    """R16-N2 (nightly stateful-deep 45604036980 on d441587, TeamLogMachine,
    third failure): B moves an entry of F1 into F3 and has not pushed it. m6,
    who may write in F1 but only read F3, re-keys F1 as admin for a while: its
    copy of the entry stays in F1. B judged that copy as leaving F3 (its own
    unsent move) and refused it, so B's move conflicted on every push and the
    sync never settled. Web and phone judge it from the server copy."""
    monkeypatch.setattr(sys.modules[__name__], "coverage_event", lambda _name: None)
    TeamLogMachine.server = loopback_server
    machine = TeamLogMachine()
    try:
        member = machine._active_members()[0]
        machine.member_sync(_Scripted(member=member))  # confirms the founder
        snap = snapshot(machine.devices["A"].vault)
        top = next(f for f in machine._folders("A") if snap[f][2] not in machine._folders("A"))
        entry = next(e for e in machine._entries("A") if snap[e][2] == top)
        name = machine._token("F")
        machine._local("A", f"create folder {name}", lambda v: v.create_node(name))
        other = next(f for f in machine._folders("A") if f not in snap)
        machine._settle(lambda _obj: "server")
        machine._grant("A", member, top, "write")
        machine._grant("A", member, other, "read")
        machine.track_member_keys()
        machine._settle(lambda _obj: "server")
        machine._local("B", f"move entry {entry} to {other}", lambda v: v.move_entry(entry, other))
        machine.yield_the_admin_role_and_take_it_back(
            _Scripted(member=member, device="A", folder=top), chain=False, unsent=False)
        machine.track_member_keys()
        machine._settle(lambda _obj: "server")
    finally:
        machine.teardown()


def test_sync_state_machine_team_log(loopback_server):
    TeamLogMachine.server = loopback_server
    run_state_machine_as_test(
        TeamLogMachine,
        settings=settings(
            max_examples=DEEP or 8,
            stateful_step_count=25,
            deadline=None,
            derandomize=not DEEP,
            database=None,
            suppress_health_check=list(HealthCheck),
            print_blob=True,
        ),
    )


@pytest.mark.parametrize("seed", property_seeds.load("test_sync_state_machine.py"), ids=str)
def test_sync_state_machine_saved_counterexample(loopback_server, seed):
    """Review e443cbc P2: every counterexample in property_seeds.txt passes."""
    machine = {m.__name__: m for m in (SyncMachine, SecondAdminMachine, TeamLogMachine)}[seed.target]
    machine.server = loopback_server
    property_seeds.replay_machine(
        machine,
        seed,
        settings(stateful_step_count=25, deadline=None, database=None, suppress_health_check=list(HealthCheck)),
    )

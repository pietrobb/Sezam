"""Sync conformance (docs/SYNC_SINGLE_SOURCE.md point 4a): one scenario, three clients.

Each scenario in tests/conformance/*.json is a list of steps for the client
under test ("client"), a desktop device of the same account ("ref") and the
server ("server"), and the vault every device must end with ("expect": path
-> password, null for a folder). The client is the desktop (Vault +
SyncClient), the web page (app.js in node, tests/web_tab.py) or the phone
(mobile/test/sync_conformance_test.dart under flutter test), all against one
real server. The steps are the same for the three, so are the ends.

Client steps: create_folder, create_entry, edit_entry, delete_entry, sync,
resolve (keep "server": the one decision the web page offers too),
accept_restore (the user accepts that the server was restored from a backup:
sezam pull --full-resync, the page's rollback question answered yes, the
phone's full resync; until then a sync only reports the rollback), grant,
revoke (with the re-key) and rotate_identity, where the client has them
(CLIENT_LACKS). The ref also invites, grants, revokes and rotates; the member
"bob" (a desktop) syncs and "reads"; "revoked" members hold no key to
anything live.
A client write stays on the client until its next sync (the web page sends
on save; that send fails as if offline, then the page's periodic pull shows
what it queued). The ref device also renames,
moves and deletes folders; "ref2" is a third desktop of the account, made on
its first step. A pull below the GC floor (410) is reported as a restore is,
until accept_restore. Server steps: gc (tombstone GC), backup, restore
(with the rows of every account, as a restore of the server's database).
"""

from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path
from urllib.parse import parse_qs

import pytest

from sezam import cli
from sezam.crypto.aead import parse_envelope
from sezam.models import bytes_to_ulid
from sezam.vault import revocation
from sezam.vault.sync_common import CONFIRMED_MEMBER_KEYS_META, KeyEpochStale, TofuKeyChangeError
from sezam.vault.team_log_local import CONFIRMED_GENESIS_META
from sezam.vault.team_migration import add_member, found_team_log
from sezam.vault.crud import Vault
from sezam.vault.sync_client import SyncClient
from tests.node_support import node_problem
from tests.test_cross_client_password_change import _phone
from tests.test_integration_client_server import PARAMS, PASSWORD
from tests.test_sync_state_machine import _Server
from tests.web_tab import WebTab

SCENARIOS = sorted((Path(__file__).parent / "conformance").glob("*.json"))
PHONE_TEST = "test/sync_conformance_test.dart"
CLIENT_STEPS = {
    "create_folder", "create_entry", "edit_entry", "delete_entry", "sync", "resolve", "accept_restore",
    "grant", "revoke", "rotate_identity",
}
# What a client has no way to do (docs/SYNC_SINGLE_SOURCE.md 4a, exceptions):
# a scenario with such a client step is skipped for it, by name. Every one of
# these is also run by the ref desktop in a scenario all three clients take.
CLIENT_LACKS = {
    "web": {"grant", "rotate_identity"},
    "phone": {"grant", "revoke", "rotate_identity"},
}
OFFLINE = {"method": "POST", "path": "/api/sync", "mode": "before"}


def _load(path: Path) -> dict:
    scenario = json.loads(path.read_text(encoding="utf-8"))
    for step in scenario["steps"]:
        assert step["on"] != "client" or step["do"] in CLIENT_STEPS, f"{path.name}: {step}"
    return scenario


def _paths(folders: dict, entries: list, root: str) -> dict:
    """{id: (name, parent)} folders + [(name, parent, password)] -> {path: password|None}."""
    def path(folder: str) -> str | None:
        parts = []
        while folder != root:
            if folder not in folders:
                return None  # not under the account root (another account's tree)
            name, folder = folders[folder]
            parts.append(name)
        return "/".join(reversed(parts))

    view = {}
    for fid in folders:
        p = path(fid)
        if p:
            view[p] = None
    for name, parent, password in entries:
        p = path(parent)
        if p is not None:
            view[f"{p}/{name}" if p else name] = password
    return view


class Desktop:
    def __init__(self, path: Path, url: str):
        self.vault = Vault.create(path, PASSWORD, PARAMS)
        self.vault.db.set_meta("username", "admin")
        cli._server_connect_flow(url, self.vault, PASSWORD)
        assert self.vault.db.get_meta("server_url") == url
        self.url = url
        self.said: list = []
        self.users: dict = {}  # member name -> user id (Refs.members)

    def _tree(self, root: str | None = None):
        """The tree below ``root`` (a member passes the admin's root, a folder
        it does not hold: only what is shared with it hangs below)."""
        root = root or self.vault.db.get_meta("root_node_id")
        folders, entries, todo = {}, [], [root]
        while todo:
            parent = todo.pop()
            for node in self.vault.list_nodes(parent):
                folders[node["id"]] = (node["name"], parent)
                todo.append(node["id"])
            if parent == root and root != self.vault.db.get_meta("root_node_id"):
                continue
            for entry in self.vault.list_entries(parent):
                entries.append((entry["id"], entry["name"], parent))
        return root, folders, entries

    def _folder(self, name: str | None) -> str:
        root, folders, _ = self._tree()
        if name is None:
            return root
        return next(i for i, (n, _) in folders.items() if n == name)

    def _entry(self, name: str) -> str:
        return next(i for i, n, _ in self._tree()[2] if n == name)

    def step(self, step: dict) -> None:
        do, v = step["do"], self.vault
        if do == "create_folder":
            v.create_node(step["name"], self._folder(step.get("folder")))
        elif do == "create_entry":
            v.create_entry(self._folder(step["folder"]), step["name"], _fields(step["password"]))
        elif do == "edit_entry":
            v.update_entry(self._entry(step["name"]), fields=_fields(step["password"]))
        elif do == "delete_entry":
            v.delete_entry(self._entry(step["name"]))
        elif do == "delete_folder":
            v.delete_node(self._folder(step["name"]))
        elif do == "rename_folder":
            v.rename_node(self._folder(step["name"]), step["to"])
        elif do == "move_entry":
            v.move_entry(self._entry(step["name"]), self._folder(step["folder"]))
        elif do == "sync":
            self.sync()
        elif do == "resolve":
            client = self._client()
            conflicts = client.get_pull_conflicts()
            assert conflicts, "nothing to resolve"
            for conflict in conflicts:
                client.resolve_conflict(conflict["id"], step["keep"])
        elif do == "accept_restore":
            self._client().full_resync(confirmed=True)
        elif do == "grant":  # the team dialog / 'sezam grant'
            revocation.grant_member(
                v, self._client(), self.users[step["member"]], self._folder(step["folder"]),
                step.get("access", "read"), confirm_fingerprint=lambda _fp: True,
            )
        elif do == "revoke":  # 'sezam revoke-user': revoked, then the member's folders re-keyed
            revocation.revoke_member(v, self._client(), self.users[step["member"]])
        elif do == "rotate_identity":  # 'sezam rotate-identity'
            self._client().prepare_key_change()
            proof = v.change_password(PASSWORD, PASSWORD, rotate_identity=True)
            proof[:] = b"\x00" * len(proof)
        else:
            raise AssertionError(f"unknown step {step}")

    def _client(self) -> SyncClient:
        client = SyncClient(self.vault.db, self.url, self.vault.keypair, self.vault.db.get_meta("user_id"))
        client.set_dek_manager(self.vault.dek_mgr)
        return client

    def sync(self) -> bool:
        """Push, then pull ('sezam sync'). True when nothing is left: no
        queued operation, no open conflict."""
        client = self._client()
        try:
            pushed = revocation.push_with_queued_revocations(self.vault, client)
        except KeyEpochStale:
            # Another device rotated the account keys: the user types the
            # password and this one takes them over (as 'sezam sync' asks).
            client.adopt_rotated_key_material(self.vault, PASSWORD)
            client = self._client()
            pushed = revocation.push_with_queued_revocations(self.vault, client)
        self.said = [c.get("error") for c in pushed.get("conflicts") or []]
        try:
            pulled = client.pull()
        except RuntimeError as e:  # 410: below the GC floor, as the page and the phone report it
            if "explicit full resync" not in str(e):
                raise
            self.said.append(str(e))
            return False
        if pulled.get("rollback_warning"):
            self.said.append(pulled["rollback_warning"])
            return False
        queued = self.vault.db.fetchone("SELECT COUNT(*) AS n FROM outbox")["n"]
        return not queued and not client.get_pull_conflicts()

    def view(self, root: str | None = None) -> dict:
        root, folders, entries = self._tree(root)
        return _paths(folders, [
            (name, parent, self.vault.get_field_value(i, "password")) for i, name, parent in entries
        ], root)

    def close(self) -> None:
        self.vault.lock()


def _fields(password: str) -> list[dict]:
    return [{"key": "password", "value": password, "sensitive": True}]


class Web:
    def __init__(self, tmp: Path, url: str):
        self.tab = WebTab(url, tmp / "web.log")
        self.said: list = []
        self.users: dict = {}
        self.last = self._do("login", username="admin", password=PASSWORD)

    def _do(self, action: str, offline: bool = False, confirm: bool = True, **step) -> dict:
        result = self.tab.do(action, confirm=confirm, **({"fail": dict(OFFLINE)} if offline else {}), **step)
        assert not result["rejections"], result["rejections"]
        fired = offline and result["failure"] and result["failure"]["fired"]
        assert result["error"] is None or fired, f"{action}: {result['error']}"
        self.last = result
        if fired:
            # The page shows what it queued after its next periodic pull
            # (a pull only: the queue waits for the sync step's Retry).
            return self._do("refresh")
        return result

    def _id(self, kind: str, name: str) -> str:
        return next(o["id"] for o in self.last["view"][kind] if o["name"] == name)

    def step(self, step: dict) -> None:
        do = step["do"]
        if do == "create_folder":
            self._do("save", True, mode="folder", name=step["name"], parent=step.get("folder") or "ROOT")
        elif do == "create_entry":
            self._do("save", True, mode="entry", name=step["name"], parent=step["folder"],
                     fields=_fields(step["password"]))
        elif do == "edit_entry":
            self._do("save_object", True, mode="entry", id=self._id("entries", step["name"]),
                     fields=_fields(step["password"]))
        elif do == "delete_entry":
            self._do("delete_entry", True, id=self._id("entries", step["name"]))
        elif do == "sync":
            self.sync()
        elif do == "resolve":
            assert step["keep"] == "server", "the page offers only the server's version"
            assert self.last["view"]["conflicts"], "nothing to resolve"
            self._do("use_server")
        elif do == "accept_restore":
            self._do("refresh")
        elif do == "revoke":
            self._do("revoke", user_id=self.users[step["member"]])
        else:
            raise AssertionError(f"unknown step {step}")

    def sync(self) -> bool:
        """The conflict banner's Retry, then the periodic pull."""
        # A rollback question is answered no: only accept_restore says yes.
        self.said = [self.tab.do("retry", confirm=False)["error"]]
        result = self.tab.do("refresh", confirm=False)
        if not result["view"]["unlocked"]:
            # Another device rotated the account keys and the server ended
            # this session: the user logs in again (the desktop's
            # adopt_rotated_key_material), and the queue goes out after.
            self.said.append(f"session ended ({result['error']}): logged in again")
            if self._do("login", username="admin", password=PASSWORD)["view"]["set_aside"]:
                # What was queued under the previous keys: the set-aside
                # banner, the previous password, Restore.
                self._do("restore_set_aside", password=PASSWORD)
            return False
        if result["error"]:
            self.said.append(result["error"])
            return False
        self.last = result
        return not result["view"]["dirty"] and not result["view"]["conflicts"]

    def view(self) -> dict:
        page = self.last["view"]
        root = page["rootNodeId"]
        folders = {n["id"]: (n["name"], n["parent_ref"]) for n in page["nodes"]
                   if n["id"] != root and not n["undecryptable"]}
        return _paths(folders, [(e["name"], e["parent_ref"], e["password"]) for e in page["entries"]
                                if not e["undecryptable"]], root)

    def close(self) -> None:
        self.tab.kill()


class PullFault:
    """ASGI wrapper of the server: one GET /api/sync reply rewritten by
    ``hook(reply, since) -> bool`` (True: it changed the reply, and the fault
    is spent). The same for the three clients, as no client code is touched."""

    def __init__(self, app):
        self.app = app
        self.hook = None
        self.fired = 0

    async def __call__(self, scope, receive, send):
        hook = self.hook
        if hook is None or scope["type"] != "http" or scope["method"] != "GET" or scope["path"] != "/api/sync":
            return await self.app(scope, receive, send)
        start, body = {}, []

        async def rewrite(message):
            if message["type"] == "http.response.start":
                start.update(message)
                return
            body.append(message.get("body", b""))
            if message.get("more_body"):
                return
            data = b"".join(body)
            if start["status"] == 200 and self.hook is hook:
                reply = json.loads(data)
                since = int(parse_qs(scope["query_string"].decode()).get("since_commit_seq", ["0"])[0])
                if hook(reply, since):
                    self.hook = None
                    self.fired += 1
                    data = json.dumps(reply).encode()
            headers = [(k, v) for k, v in start["headers"] if k.lower() != b"content-length"]
            await send({**start, "headers": headers + [(b"content-length", str(len(data)).encode())]})
            await send({"type": "http.response.body", "body": data})

        await self.app(scope, receive, rewrite)


def _withhold(kind: str):
    """Review 7c10379 as a server fault (the stateful test's server_withholds):
    every object of one kind is left out of a pull and the rest sent; the
    checkpoint stops before the first one held back, so the next pull brings it."""
    def hook(reply: dict, since: int) -> bool:
        objects = reply.get("objects") or []
        held = [o for o in objects if o.get("object_type") == kind]
        seqs = [o["commit_seq"] for o in held if isinstance(o.get("commit_seq"), int)]
        if not seqs or reply.get("has_more"):
            return False
        reply["objects"] = [o for o in objects if o.get("object_type") != kind]
        reply["max_commit_seq"] = max(min(seqs) - 1, since)
        return True
    return hook


class Server:
    def __init__(self, server: _Server):
        self.db = server.reset()
        self.url = server.url
        self.backup = None
        self.faults: PullFault = server.faults
        self.faults.hook, self.faults.fired = None, 0

    def step(self, step: dict) -> None:
        do = step["do"]
        if do == "gc":
            from server.app.main import _cleanup_tombstones

            for obj in self.db._storage["vault_objects"]:
                if obj.get("is_deleted"):
                    obj["modified_at"] = 0
            asyncio.run(_cleanup_tombstones(self.db, 0))
        elif do == "backup":
            self.backup = copy.deepcopy(self.db._storage)
        elif do == "restore":
            self.db._storage.clear()
            self.db._storage.update(copy.deepcopy(self.backup))
        elif do == "withhold_next_pull":
            self.faults.hook = _withhold(step["kind"])
        else:
            raise AssertionError(f"unknown step {step}")


@pytest.fixture(scope="module")
def loopback(tmp_path_factory):
    faults = {}

    def wrap(app):
        faults["pull"] = PullFault(app)
        return faults["pull"]

    server = _Server(tmp_path_factory.mktemp("conformance"), wrap=wrap)
    server.faults = faults["pull"]
    yield server
    server.close()


def _live_envelopes(server: Server, user_id: str) -> set[str]:
    """The keys (DEK ids) the server holds a live envelope of for the user."""
    return {o["parent_ref"] for o in server.db._storage.get("vault_objects", [])
            if o["object_type"] == "envelope" and o.get("target_user_id") == user_id
            and not o.get("is_deleted")}


class Member(Desktop):
    """A team member's desktop (another account), invited and approved by the
    ref desktop ('sezam invite'). Its steps: sync, and reads (what it opens
    of the admin's tree must be "expect")."""

    def __init__(self, path: Path, url: str, admin: Desktop, server: Server):
        invitation = admin._client().create_invitation()
        self.vault = Vault.create(path, PASSWORD, PARAMS)
        self.vault.db.set_meta("username", path.name)
        poll = cli._poll_for_approval
        cli._poll_for_approval = lambda *a, **k: None
        try:
            cli._server_register_and_upload(
                url, self.vault, PASSWORD, is_bootstrap=False, invitation_token=invitation["invitation_token"],
            )
        finally:
            cli._poll_for_approval = poll
        self.user_id = self.vault.db.get_meta("user_id")
        admin._client().approve_user(user_id=self.user_id)
        self.url, self.server, self.admin = url, server, admin
        self.admin_root = admin.vault.db.get_meta("root_node_id")
        self.said, self.users, self.held = [], {}, set()

    def _tree(self, root: str | None = None):
        """What is shared with the member, below the admin's root. A shared
        folder's own name is sealed under its parent's key, which the member
        does not hold: it goes by the admin's name for it; all below must open."""
        admin_names = {i: n for i, (n, _) in self.admin._tree()[1].items()}
        folders, entries, todo = {}, [], [self.admin_root]
        while todo:
            parent = todo.pop()
            for row in self.vault.db.fetchall(
                "SELECT id FROM nodes WHERE parent_id = ? AND is_deleted = 0", (parent,)
            ):
                if parent == self.admin_root:
                    name = admin_names.get(row["id"], "<not the admin's>")
                else:
                    name = self.vault.read_node(row["id"])["name"]
                folders[row["id"]] = (name, parent)
                todo.append(row["id"])
            if parent != self.admin_root:
                for entry in self.vault.list_entries(parent):
                    entries.append((entry["id"], entry["name"], parent))
        return self.admin_root, folders, entries

    def step(self, step: dict) -> None:
        if step["do"] == "sync":
            self.sync()
        elif step["do"] == "reads":
            self.sync()
            view = self.view()
            assert view == step["expect"], f"{self.vault.db.get_meta('username')} reads {view}, expected {step['expect']} (its sync said {self.said})"
        else:
            raise AssertionError(f"unknown member step {step}")

    def sync(self) -> bool:
        # Every key it was given: after a revocation none of them may still
        # open anything live (checked at the end).
        self.held |= _live_envelopes(self.server, self.user_id)
        client = self._client()

        def pull():
            try:
                client.pull()
            except TofuKeyChangeError as change:
                # The admin rotated their identity: the member checks the new
                # fingerprint with them, as 'sezam pull' asks, and accepts it.
                client.confirm_tofu_key_change(change, change.new_fingerprint)
                client.pull()

        try:
            pull()  # the pinned team log comes first: a push waits for it
            client.push()
            pull()
        except RuntimeError as exc:  # revoked: the server refuses the account
            self.said = [str(exc)]
            return False
        self.held |= _live_envelopes(self.server, self.user_id)
        return True


class Refs:
    """The other desktops of the account: "ref" from the start, "ref2" made on
    its first step (a third device, e.g. one holding an old unsent edit).
    Team members are other accounts: {"on": "ref", "do": "invite", "member":
    "bob"} makes one, then "bob" takes the member steps."""

    def __init__(self, tmp: Path, server: Server):
        self.tmp, self.url, self.server = tmp, server.url, server
        self.devices = {"ref": Desktop(tmp / "ref", self.url)}  # registers the account
        self.members: dict[str, Member] = {}
        self.users: dict[str, str] = {}

    def step(self, step: dict) -> None:
        if step["on"] in self.members:
            self.members[step["on"]].step(step)
            return
        if step["do"] == "invite":
            self._invite(self.devices[step["on"]], step["member"])
            return
        if step["on"] not in self.devices:
            self.devices[step["on"]] = Desktop(self.tmp / step["on"], self.url)
        self.devices[step["on"]].users = self.users
        self.devices[step["on"]].step(step)

    def _invite(self, admin: Desktop, name: str) -> None:
        """'sezam invite', the member registers and is approved; the admin puts
        them in the team log ('sezam team-log init' the first time, else
        'team-log add-member', fingerprints confirmed) and the member pins the
        genesis the invitation link carries (#g=)."""
        member = Member(self.tmp / name, self.url, admin, self.server)
        client = admin._client()
        if client.team_state() is None:
            found_team_log(admin.vault, client, lambda _uid, _fp: True, confirm_plan=lambda _plan: True)
        else:
            add_member(admin.vault, client, member.user_id, lambda _fp: True)
        member.vault.db.set_meta(CONFIRMED_GENESIS_META, admin._client().team_state().genesis_hash)
        # 'sezam team-log confirm-founder': the fingerprint compared with the admin's.
        member.vault.db.set_meta_json(CONFIRMED_MEMBER_KEYS_META, {
            admin.vault.db.get_meta("user_id"): admin.vault.keypair.fingerprint,
        })
        self.members[name], self.users[name] = member, member.user_id

    def sync(self) -> bool:
        return all([device.sync() for device in self.devices.values()])

    def said(self) -> dict:
        return {name: device.said for name, device in self.devices.items()}

    def views(self) -> dict:
        return {name: device.view() for name, device in self.devices.items()}

    def close(self) -> None:
        for device in [*self.devices.values(), *self.members.values()]:
            device.close()


def _other(server: Server, refs: Refs, step: dict) -> None:
    (server if step["on"] == "server" else refs).step(step)


SETTLE_ROUNDS = 3


def _settle(under, refs: Refs) -> None:
    """Sync every device until none holds anything unsent or unresolved."""
    for _ in range(SETTLE_ROUNDS):
        if all([under.sync(), refs.sync(), under.sync()]):
            return
    raise AssertionError(f"sync does not settle: client said {under.said}, refs said {refs.said()}")


def _check(name: str, expect: dict, views: dict) -> None:
    for who, view in views.items():
        assert view == expect, f"{name}: {who} ended with {view}, expected {expect}"


def _content_dek(obj: dict) -> str:
    payload = bytes(obj["payload"])
    if obj["object_type"] == "entry":
        payload = payload[4:4 + int.from_bytes(payload[:4], "big")]
    return bytes_to_ulid(parse_envelope(payload).dek_id)


def _check_revoked(name: str, server: Server, member: Member) -> None:
    """A revoked member holds no key to anything live: no live envelope of
    theirs, and nothing live sealed under a key they were ever given."""
    assert member.held, f"{name}: the member never got a key, the revocation proves nothing"
    left = _live_envelopes(server, member.user_id)
    assert not left, f"{name}: the revoked member still has live envelopes for {sorted(left)}"
    exposed = sorted(
        o["id"] for o in server.db._storage.get("vault_objects", [])
        if not o.get("is_deleted") and o["object_type"] in ("node", "entry")
        and o.get("parent_ref") is not None and _content_dek(o) in member.held
    )
    assert not exposed, f"{name}: live objects {exposed} are still under a key the revoked member holds"


@pytest.mark.parametrize("client", ["desktop", "web", "phone"])
@pytest.mark.parametrize("path", SCENARIOS, ids=[p.stem for p in SCENARIOS])
def test_sync_conformance(loopback, tmp_path, path, client):
    scenario = _load(path)
    lacks = sorted({s["do"] for s in scenario["steps"] if s["on"] == "client"} & CLIENT_LACKS.get(client, set()))
    if lacks:
        pytest.skip(f"the {client} has no {', '.join(lacks)} (docs/SYNC_SINGLE_SOURCE.md 4a, exceptions)")
    if client == "web" and node_problem():
        pytest.skip(node_problem())
    server = Server(loopback)
    refs = Refs(tmp_path, server)
    views = {}
    try:
        if client == "phone":
            steps = {f"s{i}": (lambda s=step: _other(server, refs, s))
                     for i, step in enumerate(scenario["steps"]) if step["on"] != "client"}
            for round_ in range(SETTLE_ROUNDS):  # mobile/test/sync_conformance_test.dart
                steps[f"settle{round_}"] = refs.sync
            _phone(server.url, tmp_path, {
                "username": "admin", "password": PASSWORD, "steps": scenario["steps"],
            }, steps, PHONE_TEST)
            views["phone"] = json.loads((tmp_path / "phone" / "view.json").read_text(encoding="utf-8"))
        else:
            under = Desktop(tmp_path / "client", server.url) if client == "desktop" else Web(tmp_path, server.url)
            under.users = refs.users
            try:
                for step in scenario["steps"]:
                    (under if step["on"] == "client" else server if step["on"] == "server" else refs).step(step)
                _settle(under, refs)
                views[client] = under.view()
            finally:
                under.close()
        views.update(refs.views())
        fresh = Desktop(tmp_path / "fresh", server.url)
        try:
            fresh.sync()
            views["new device"] = fresh.view()
        finally:
            fresh.close()
        for name in scenario.get("revoked", []):
            _check_revoked(path.stem, server, refs.members[name])
    finally:
        refs.close()
    faults = sum(step["do"] == "withhold_next_pull" for step in scenario["steps"])
    assert server.faults.fired == faults, f"{path.stem}: a server fault found nothing to change"
    _check(path.stem, scenario["expect"], views)

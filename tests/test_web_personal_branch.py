"""Idea #5: on the web, everything under a personal folder is private.

A personal folder's DEK is wrapped only by its owner's KEK. Older web builds
used it only for records placed directly in the personal folder: a subfolder
got the account root DEK, and so did every record below it. Here the owner
builds a personal branch three levels deep with the real web modal handlers
(all of app.js in node against the real server). Every object of the branch
is sealed with the one personal DEK (the old behaviour fails right there),
that DEK is shared with nobody, and a team member who holds a shared folder
DEK through a real access envelope, then the same member as an admin, signs
in on the web: the shared record reads, nothing of the personal branch does.
"""

from __future__ import annotations

import base64
import struct

from sezam import cli
from sezam.crypto.aead import parse_envelope
from sezam.crypto.envelope_crypto import create_envelope
from sezam.models import bytes_to_ulid, new_ulid
from tests.test_cross_client_password_change import _web, _web_login
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    PASSWORD,
    _client,
    _entry_value,
    _vault,
    server,
)
from tests.test_review_web import pytestmark  # noqa: F401
from sezam.vault import outbox

PERSONAL_FOLDERS = ("Private", "Deep", "Deeper")
PERSONAL_ENTRIES = {"p-top": "Private", "p-deep": "Deep", "p-deeper": "Deeper"}


def _save(mode: str, name: str, parent: str | None = None, password: str | None = None) -> dict:
    step = {"action": "save", "mode": mode, "name": name, "parent": parent}
    if password is not None:
        step["fields"] = [{"key": "password", "value": password}]
    return step


def _user(db, user_id: str) -> dict:
    return next(u for u in db._storage["users"] if u["id"] == user_id)


def _encryption_pk(db, user_id: str) -> bytes:
    pk = _user(db, user_id)["encryption_pk"]
    return bytes.fromhex(pk) if isinstance(pk, str) else bytes(pk)


def _share_folder_with(admin, db, url: str, folder_id: str, member_id: str) -> str:
    """The admin's desktop gives the member the folder's DEK in a real
    crypto_box access envelope (no desktop UI makes one yet, idea #7)."""
    dek_id, dek = admin.dek_mgr.get_dek_for_node(folder_id)
    admin.db.execute(
        "INSERT INTO access_envelopes "
        "(id, dek_id, user_id, created_by, access_level, encrypted_dek) "
        "VALUES (?, ?, ?, ?, 'read', ?)",
        (
            new_ulid(), dek_id, member_id, admin.db.get_meta("user_id"),
            create_envelope(
                dek, admin.keypair.to_nacl_private_key().encode(), _encryption_pk(db, member_id)
            ),
        ),
    )
    outbox.queue_write(admin.db, folder_id)
    assert _client(admin, url).push()["conflicts"] == []
    assert any(
        o["object_type"] == "envelope" and o.get("target_user_id") == member_id
        and o["parent_ref"] == dek_id and not o["is_deleted"]
        for o in db._storage["vault_objects"]
    )
    return dek_id


def _readable(result: dict) -> tuple[set, dict]:
    folders = {n["name"] for n in result["nodes"] if not n["undecryptable"]}
    return folders, {e["name"]: e["password"] for e in result["entries"] if not e["undecryptable"]}


def test_personal_branch_on_web_stays_private_to_members_and_admins(
    server, tmp_path, monkeypatch  # noqa: F811
):
    url, db = server
    admin = _vault(tmp_path / "admin", "admin")
    team = admin.create_node("Team")
    cli._server_connect_flow(url, admin, PASSWORD)
    admin_id = admin.db.get_meta("user_id")
    admin_client = _client(admin, url)
    invitation = admin_client.create_invitation()
    monkeypatch.setattr(cli, "_poll_for_approval", lambda *a, **k: None)
    bob = _vault(tmp_path / "bob", "bob")
    cli._server_register_and_upload(
        url, bob, PASSWORD, is_bootstrap=False, invitation_token=invitation["invitation_token"]
    )
    bob_id = bob.db.get_meta("user_id")
    admin_client.approve_user(bob_id)
    bob.lock()
    team_dek_id = _share_folder_with(admin, db, url, team, bob_id)
    root_dek_id, _ = admin.dek_mgr.get_dek_for_node(admin.db.get_meta("root_node_id"))

    # The owner, in the browser: a record in the shared folder, and a
    # personal branch three folders deep with a record on every level.
    owner = _web(
        url, {},
        {"action": "login", "username": "admin", "password": PASSWORD},
        _save("entry", "team-vpn", "Team", "team-pw"),
        _save("personal", "Private"),
        _save("folder", "Deep", "Private"),
        _save("folder", "Deeper", "Deep"),
        *(_save("entry", name, folder, name + "-pw") for name, folder in PERSONAL_ENTRIES.items()),
    )
    assert owner["error"] is None, owner
    folders, passwords = _readable(owner)
    assert set(PERSONAL_FOLDERS) | {"Team"} <= folders
    assert passwords == {"team-vpn": "team-pw", **{n: n + "-pw" for n in PERSONAL_ENTRIES}}

    # Every object of the branch is sealed with the one personal DEK, which
    # is wrapped for the owner's KEK and shared with nobody.
    by_name = {o["name"]: o for o in owner["nodes"] + owner["entries"]}
    personal_dek_id = by_name["Private"]["dekId"]
    assert personal_dek_id not in (None, root_dek_id, team_dek_id)
    branch = [*PERSONAL_FOLDERS, *PERSONAL_ENTRIES]
    assert {n: by_name[n]["dekId"] for n in branch} == {n: personal_dek_id for n in branch}
    assert by_name["team-vpn"]["dekId"] == team_dek_id
    objects = db._storage["vault_objects"]
    personal_dek = next(o for o in objects if o["id"] == personal_dek_id)
    assert personal_dek["object_type"] == "dek"
    assert personal_dek["owner_id"] == admin_id
    assert not [o for o in objects if o["object_type"] == "envelope"
                and o["parent_ref"] == personal_dek_id]

    # The member holds the shared folder's DEK: its record reads, the
    # personal branch (names and records, on every level) does not.
    member = _web_login(url, "bob", PASSWORD, {})
    assert member["error"] is None, member
    # (The shared folder's own name is sealed with the admin's root DEK.)
    _, passwords = _readable(member)
    assert passwords == {"team-vpn": "team-pw"}
    hidden = {n["id"] for n in member["nodes"] if n["undecryptable"]}
    assert {by_name[n]["id"] for n in PERSONAL_FOLDERS} <= hidden
    assert {e["id"] for e in member["entries"] if e["undecryptable"]} == {
        by_name[n]["id"] for n in PERSONAL_ENTRIES
    }

    # An admin is no different: the flag grants no key.
    _user(db, bob_id)["is_admin"] = 1
    as_admin = _web_login(url, "bob", PASSWORD, {})
    assert as_admin["error"] is None, as_admin
    assert _readable(as_admin) == _readable(member)
    admin.lock()


def _header_dek_id(obj: dict) -> str:
    payload = base64.b64decode(obj["payload"]) if isinstance(obj["payload"], str) else bytes(obj["payload"])
    if obj["object_type"] == "entry":
        meta_len = struct.unpack(">I", payload[:4])[0]
        payload = payload[4:4 + meta_len]
    return bytes_to_ulid(parse_envelope(payload).dek_id)


def test_owner_desktop_reads_and_extends_a_personal_branch_made_on_the_web(
    server, tmp_path  # noqa: F811
):
    """The web binds a personal DEK to no node (the server allows a member's
    DEK no parent). The desktop bound such a personal root to the root DEK:
    the owner's own branch never decrypted there, and a record the desktop
    added below it would have been sealed with the root DEK."""
    url, db = server
    admin = _vault(tmp_path / "admin", "admin")
    cli._server_connect_flow(url, admin, PASSWORD)
    root_dek_id, _ = admin.dek_mgr.get_dek_for_node(admin.db.get_meta("root_node_id"))
    browser: dict = {}
    owner = _web(
        url, browser,
        {"action": "login", "username": "admin", "password": PASSWORD},
        _save("personal", "Private"),
        _save("folder", "Deep", "Private"),
        _save("entry", "p-top", "Private", "p-top-pw"),
        _save("entry", "p-deep", "Deep", "p-deep-pw"),
    )
    assert owner["error"] is None, owner
    personal_dek_id = next(n["dekId"] for n in owner["nodes"] if n["name"] == "Private")

    client = _client(admin, url)
    client.pull()
    assert [n["name"] for n in admin.list_nodes()] == ["Private"]
    assert _entry_value(admin, "Private", "p-top", "password") == "p-top-pw"
    private = admin.list_nodes()[0]["id"]
    assert [n["name"] for n in admin.list_nodes(private)] == ["Deep"]
    deep = admin.list_nodes(private)[0]["id"]
    [p_deep] = admin.list_entries(deep)
    assert p_deep["name"] == "p-deep"
    assert admin.get_field_value(p_deep["id"], "password") == "p-deep-pw"

    added = admin.create_entry(deep, "desk-deep", [{"key": "password", "value": "desk-pw"}])
    assert client.push()["conflicts"] == []
    stored = next(o for o in db._storage["vault_objects"] if o["id"] == added)
    assert _header_dek_id(stored) == personal_dek_id != root_dek_id

    again = _web_login(url, "admin", PASSWORD, browser)
    assert again["error"] is None, again
    assert _readable(again)[1] == {"p-top": "p-top-pw", "p-deep": "p-deep-pw", "desk-deep": "desk-pw"}
    admin.lock()

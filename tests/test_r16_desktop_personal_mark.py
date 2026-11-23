"""Review 18c300f R16-H2 on the desktop: the ``personal`` mark in a folder's
sealed meta makes it a personal root only when it is sealed with a key of
this account's own.

A member holding a team key (a team folder's, opened through an envelope;
or, for the admin, a key the team log names) could push a top-level folder
sealed with it that says ``personal``. On 18c300f the receiving desktop took
it for its own personal root, and what it saved there was sealed with a key
the member holds.
"""

from __future__ import annotations

from sezam.crypto.aead import BlobKind, encrypt
from sezam.models import NodeMeta, new_ulid, ulid_to_bytes
from sezam.vault.personal_root import is_personal_root, personal_root_ids
from sezam.vault.team_migration import found_team_log
from tests.test_integration_client_server import _client
from tests.test_integration_client_server import server  # noqa: F401  (fixture)
from tests.test_team_log_desktop import _confirm_founder, team  # noqa: F401  (fixture)
from tests.test_team_log_migration import org  # noqa: F401  (fixture)


def _pulled_top_level(vault, dek_id: str, name: str) -> str:
    """A top-level folder as a pull stores it: meta sealed with ``dek_id``."""
    node_id = new_ulid()
    blob = encrypt(
        plaintext=NodeMeta(name=name, personal=True).to_json(),
        dek=vault.dek_mgr.unlock_dek(dek_id),
        dek_id=ulid_to_bytes(dek_id),
        object_id=ulid_to_bytes(node_id),
        version=1,
        blob_kind=BlobKind.NODE_META,
    )
    vault.db.execute(
        "INSERT INTO nodes (id, parent_id, encrypted_meta, dek_id, version, is_deleted) "
        "VALUES (?, NULL, ?, ?, 1, 0)",
        (node_id, blob, dek_id),
    )
    return node_id


def test_a_team_key_folder_marked_personal_is_no_personal_root(org, server):  # noqa: F811
    _db, admin, admin_client, _bob, _bob_client, carol, _ids, ops, _dan = org
    found_team_log(admin, admin_client, lambda _uid, _fp: True)
    _confirm_founder(admin, carol)
    _client(carol, server[0]).pull()
    ops_key = carol.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (ops,))["dek_id"]

    mine = carol.create_personal_folder("Moje")
    assert is_personal_root(carol.db, carol.dek_mgr, mine)

    # Carol opens Ops through the admin's envelope.
    forged = _pulled_top_level(carol, ops_key, "Moje 2")
    assert not is_personal_root(carol.db, carol.dek_mgr, forged)
    assert forged not in personal_root_ids(carol.db, carol.dek_mgr)

    # The admin's KEK opens Ops, but the team log names it.
    forged_for_admin = _pulled_top_level(admin, ops_key, "Moje")
    assert not is_personal_root(admin.db, admin.dek_mgr, forged_for_admin)

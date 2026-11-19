"""Review main@d615826 (signed DEK role, desktop side of H3).

The DEK ``scope`` label is unsigned. On the web a folder key the server
labelled 'tier2' was skipped for the parent's key. The desktop binds a pulled
folder to the DEK whose signed parent_ref names it (_bind_pulled_deks), so a
relabel does not move what it adds there under the parent's key; this guards it.
"""

from __future__ import annotations

import pytest

from sezam.crypto.aead import parse_envelope
from sezam.models import bytes_to_ulid
from tests.test_integration_client_server import _client, server  # noqa: F401
from tests.test_rollback_commit_token_sm7 import _two_devices


@pytest.mark.parametrize("label", ["tier2", "personal"])
def test_a_relabelled_folder_key_stays_the_folders_key(server, tmp_path, label):  # noqa: F811
    """The parent's key relabelled 'personal' (a personal root's meta names
    its own key) must not become the subfolder's key either."""
    url, db = server
    laptop, phone = _two_devices(url, tmp_path)
    team = laptop.create_node("TEAM")
    sub = laptop.create_node("SUB", parent_id=team)
    sub_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (sub,))["dek_id"]
    team_dek = laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (team,))["dek_id"]
    assert sub_dek != team_dek
    _client(laptop, url).push()
    relabelled = sub_dek if label == "tier2" else team_dek
    next(o for o in db._storage["vault_objects"] if o["id"] == relabelled)["dek_scope"] = label

    _client(phone, url).pull()
    # Run 151: a new folder key no longer takes the server's label at all.
    assert phone.db.fetchone("SELECT scope FROM deks WHERE id = ?", (relabelled,))["scope"] == "folder"
    entry = phone.create_entry(sub, "db", [{"key": "password", "value": "x", "sensitive": True}])
    blob = bytes(phone.db.fetchone("SELECT encrypted_meta FROM entries WHERE id = ?", (entry,))[0])
    assert bytes_to_ulid(parse_envelope(blob).dek_id) == sub_dek
    laptop.lock()
    phone.lock()

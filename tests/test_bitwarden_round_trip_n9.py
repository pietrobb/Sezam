"""Review d150605 N9: a Bitwarden export did not come back whole.

The import dropped every item without fields, and an entry without fields
is exported as exactly such an item. '/' nests folders in Bitwarden, and
the export wrote folder names as they are, so a folder 'Work/Prod' came back
as 'Prod' inside 'Work'. The CSV export already escapes it (review 526419e N1).
"""

from __future__ import annotations

from sezam.cli import _export_bitwarden
from sezam.crypto.kdf import Argon2Params
from sezam.importers.bitwarden import import_bitwarden
from sezam.vault.crud import Vault

PARAMS = Argon2Params(time_cost=1, memory_cost=8_192, parallelism=1)


def _tree(vault: Vault, node_id=None) -> dict:
    node_id = node_id or vault.db.get_meta("root_node_id")
    tree = {e["name"]: len(vault.read_entry(e["id"])["fields"]) for e in vault.list_entries(node_id)}
    for node in vault.list_nodes(node_id):
        tree[node["name"] + "/"] = _tree(vault, node["id"])
    return tree


def test_bitwarden_export_imports_back_as_it_was(tmp_path):
    source = Vault.create(tmp_path / "a", "pw-123456789", PARAMS)
    try:
        slash = source.create_node("Work/Prod")
        source.create_entry(slash, "reminder", [])
        source.create_entry(slash, "db", [{"key": "password", "value": "x", "sensitive": True}])
        parent = source.create_node("Parent")
        child = source.create_node("Child", parent)
        source.create_entry(child, "nested", [{"key": "username", "value": "u"}])
        source.create_entry(source.create_node("C:\\tmp"), "path", [])
        before = _tree(source)
        dest = tmp_path / "bw.json"
        _export_bitwarden(source, str(dest))
    finally:
        source.lock()

    target = Vault.create(tmp_path / "b", "pw-123456789", PARAMS)
    try:
        assert import_bitwarden(target, dest) == 4
        assert _tree(target) == before
    finally:
        target.lock()

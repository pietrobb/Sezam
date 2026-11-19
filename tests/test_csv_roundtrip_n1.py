"""Review 526419e N1: what a CSV export + import lost.

An entry without fields wrote no row and vanished; a TOTP field came back
as a plain field (so no codes); an entry in a tier-2 folder came back
without a tier, i.e. readable by the AI; and a folder named 'Work/Prod'
came back as 'Prod' inside 'Work'.
"""

from sezam import cli
from sezam.crypto.kdf import Argon2Params
from sezam.importers.csv_import import import_csv
from sezam.vault.crud import Vault

PARAMS = Argon2Params(time_cost=1, memory_cost=8_192, parallelism=1)
PASSWORD = "pw-123456789"


def _roundtrip(tmp_path, build):
    source = Vault.create(tmp_path / "a", PASSWORD, PARAMS)
    build(source)
    dest = tmp_path / "out.csv"
    cli._export_csv(source, str(dest))
    target = Vault.create(tmp_path / "b", PASSWORD, PARAMS)
    import_csv(target, dest)
    return target


def _tree(vault, node_id=None, depth=0):
    out = []
    for child in vault.list_nodes(node_id):
        out.append((depth, child["name"]))
        out.extend(_tree(vault, child["id"], depth + 1))
    return out


def test_entry_without_fields_and_totp_survive(tmp_path):
    def build(vault):
        folder = vault.create_node("Web")
        vault.create_entry(folder, "placeholder", [])
        vault.create_entry(folder, "otp", [
            {"key": "otp", "value": "JBSWY3DPEHPK3PXP", "sensitive": True, "field_type": "totp"},
        ])

    target = _roundtrip(tmp_path, build)
    entries = {e["name"]: e for e in cli._collect_all_entries(target)}
    assert set(entries) == {"placeholder", "otp"}
    assert entries["placeholder"]["fields"] == []
    assert entries["otp"]["fields"][0]["field_type"] == "totp"


def test_tier2_folder_keeps_entries_hidden(tmp_path):
    def build(vault):
        folder = vault.create_node("Secret", tier=2)
        inner = vault.create_node("Inner", folder, tier=0)
        vault.create_entry(inner, "root-key", [{"key": "password", "value": "x", "sensitive": True}])
        approval = vault.create_node("Approval", tier=1)
        vault.create_entry(approval, "db", [{"key": "password", "value": "y", "sensitive": True}])

    target = _roundtrip(tmp_path, build)
    tiers = {e["name"]: e["tier"] for e in cli._collect_all_entries(target)}
    assert tiers == {"root-key": 2, "db": 1}


def test_slash_in_folder_name_is_not_nesting(tmp_path):
    def build(vault):
        folder = vault.create_node("Work/Prod")
        vault.create_entry(folder, "ssh", [{"key": "host", "value": "h"}])
        back = vault.create_node("C:\\keys")
        vault.create_entry(back, "k", [{"key": "host", "value": "h"}])

    target = _roundtrip(tmp_path, build)
    assert sorted(_tree(target)) == [(0, "C:\\keys"), (0, "Work/Prod")]


def test_plain_paths_from_other_tools_read_as_before():
    from sezam.importers.csv_import import split_folder_path

    assert split_folder_path("/servers/hetzner/") == ["servers", "hetzner"]
    assert split_folder_path("C:\\temp/x") == ["C:\\temp", "x"]

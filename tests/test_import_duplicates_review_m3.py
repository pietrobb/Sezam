"""Lockout review 2026-11-08, medium finding M3: import lost same-name entries.

import_entry matched an imported item to the first entry of that name in
the folder, including one the same import had just created. Two "Gmail"
accounts in one folder came out as one: in skip mode the second was
dropped, in overwrite mode it replaced the first. The Sezam CSV reader also
merged both into one entry. Each item is now matched only to an entry no
earlier item of the same run took, and the CSV export numbers its entries.
"""

from __future__ import annotations

import json

import pytest

from sezam import cli
from sezam.importers.bitwarden import import_bitwarden
from sezam.importers.csv_import import import_csv
from tests.test_integration_client_server import _vault


@pytest.fixture
def vault(tmp_path):
    v = _vault(tmp_path / "v", "admin")
    yield v
    v.lock()


def _passwords(vault, folder: str, name: str) -> list[str]:
    node_id, _ = vault.resolve_path(folder)
    values = []
    for entry in vault.list_entries(node_id):
        if entry["name"] == name:
            values.append(vault.get_field_value(entry["id"], "password"))
    return sorted(values)


def _bitwarden(tmp_path, *passwords: str):
    path = tmp_path / "bw.json"
    path.write_text(json.dumps({
        "encrypted": False,
        "folders": [{"id": "f1", "name": "Mail"}],
        "items": [
            {"type": 1, "name": "Gmail", "folderId": "f1",
             "login": {"username": f"user{i}", "password": pw}}
            for i, pw in enumerate(passwords)
        ],
    }), encoding="utf-8")
    return path


@pytest.mark.parametrize("mode", ["skip", "overwrite"])
def test_two_same_name_items_of_one_import_both_survive(vault, tmp_path, mode):
    source = _bitwarden(tmp_path, "work-pw", "home-pw")
    assert import_bitwarden(vault, source, conflict_mode=mode) == 2
    assert _passwords(vault, "Mail", "Gmail") == ["home-pw", "work-pw"]


def test_reimport_matches_each_existing_entry_once(vault, tmp_path):
    import_bitwarden(vault, _bitwarden(tmp_path, "work-pw", "home-pw"))

    assert import_bitwarden(vault, _bitwarden(tmp_path, "a", "b"), conflict_mode="skip") == 0
    assert _passwords(vault, "Mail", "Gmail") == ["home-pw", "work-pw"]

    assert import_bitwarden(
        vault, _bitwarden(tmp_path, "new-1", "new-2"), conflict_mode="overwrite"
    ) == 2
    assert _passwords(vault, "Mail", "Gmail") == ["new-1", "new-2"]


def test_csv_export_round_trip_keeps_same_name_entries_apart(vault, tmp_path):
    mail = vault.create_node("Mail")
    vault.create_entry(mail, "Gmail", [{"key": "password", "value": "work-pw"}])
    vault.create_entry(mail, "Gmail", [{"key": "password", "value": "home-pw"}])
    dest = tmp_path / "export.csv"
    cli._export_csv(vault, str(dest))

    target = _vault(tmp_path / "target", "admin")
    try:
        assert import_csv(target, dest, conflict_mode="skip") == 2
        assert _passwords(target, "Mail", "Gmail") == ["home-pw", "work-pw"]
    finally:
        target.lock()


def test_csv_without_entry_column_splits_on_a_repeated_field_key(vault, tmp_path):
    source = tmp_path / "old.csv"
    source.write_text(
        "folder,name,field_key,field_value,sensitive,tier\n"
        "Mail,Gmail,username,work,false,\n"
        "Mail,Gmail,password,work-pw,true,\n"
        "Mail,Gmail,username,home,false,\n"
        "Mail,Gmail,password,home-pw,true,\n",
        encoding="utf-8",
    )
    assert import_csv(vault, source) == 2
    assert _passwords(vault, "Mail", "Gmail") == ["home-pw", "work-pw"]

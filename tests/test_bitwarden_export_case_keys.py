"""Review 526419e S5: Bitwarden export with keys differing only in case.

An entry with 'password' and 'Password' (or 'notes' and 'Notes', common after
an import) filled the login slot from each in turn: the last one won and the
others were dropped, so the current password and the note could be lost. The
exactly named field now takes the slot; the others stay as custom fields.
"""

from __future__ import annotations

import json

import pytest

from sezam.cli import _export_bitwarden
from sezam.crypto.kdf import Argon2Params
from sezam.vault.crud import Vault

PARAMS = Argon2Params(time_cost=1, memory_cost=8_192, parallelism=1)


@pytest.mark.parametrize("order", ["exact_first", "exact_last"])
def test_case_variant_keys_keep_the_right_password_and_the_rest(tmp_path, order):
    vault = Vault.create(tmp_path / "v", "pw-123456789", PARAMS)
    try:
        folder = vault.create_node("Web")
        fields = [
            {"key": "password", "value": "current", "sensitive": True},
            {"key": "Password", "value": "old-imported", "sensitive": True},
            {"key": "notes", "value": "the note"},
            {"key": "Notes", "value": "imported note"},
        ]
        if order == "exact_last":
            fields.reverse()
        vault.create_entry(folder, "site", fields)
        dest = tmp_path / "bw.json"
        _export_bitwarden(vault, str(dest))
    finally:
        vault.lock()

    (item,) = json.loads(dest.read_text(encoding="utf-8"))["items"]
    assert item["login"]["password"] == "current"
    assert item["notes"] == "the note"
    custom = {f["name"]: f["value"] for f in item.get("fields", [])}
    assert custom == {"Password": "old-imported", "Notes": "imported note"}


def test_a_single_odd_case_key_still_fills_the_slot(tmp_path):
    vault = Vault.create(tmp_path / "v", "pw-123456789", PARAMS)
    try:
        folder = vault.create_node("Web")
        vault.create_entry(folder, "site", [{"key": "Password", "value": "only"}])
        dest = tmp_path / "bw.json"
        _export_bitwarden(vault, str(dest))
    finally:
        vault.lock()
    (item,) = json.loads(dest.read_text(encoding="utf-8"))["items"]
    assert item["login"]["password"] == "only"
    assert "fields" not in item

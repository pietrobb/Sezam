"""Stateful test finding SM15: a password change built on folder keys not yet pulled.

Another device rotated the identity key, which re-wraps every folder key on
the server at a new version. This device took the rotation over
(adopt_rotated_key_material keeps the local folder-key versions) and pushed,
but did not pull. 'sezam change-password' then built its re-wrap batch on the
old versions: the server refused it with 409 on every push and the change
never landed. A folder another device added since the last pull did the same
("Key epoch advance must include every active DEK"). The key-change commands
now pull before they change anything.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from sezam import cli
from sezam.vault.sync_client import KeyEpochStale
from tests.test_ai_r1_snapshots import _cli_env
from tests.test_integration_client_server import (
    NEW_PASSWORD,
    PASSWORD,
    _client,
    _vault,
    server,  # noqa: F401  (fixture)
)


def _change_password(vault_dir, monkeypatch):
    _cli_env(vault_dir, monkeypatch)
    return CliRunner().invoke(
        cli.main, ["change-password"], input=f"{PASSWORD}\n{NEW_PASSWORD}\n{NEW_PASSWORD}\n"
    )


def _laptop_and_phone(url, tmp_path):
    laptop = _vault(tmp_path / "laptop", "admin")
    laptop.create_node("F")
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    return laptop, phone


def _lands(url, tmp_path, laptop, phone, monkeypatch):
    phone.lock()
    result = _change_password(tmp_path / "phone", monkeypatch)
    assert result.exit_code == 0, result.output
    assert "server was not updated" not in result.output, result.output
    phone.unlock(NEW_PASSWORD)
    assert not _client(phone, url).has_pending_key_change()
    laptop_client = _client(laptop, url)
    with pytest.raises(KeyEpochStale):
        laptop_client.pull()
    laptop_client.adopt_rotated_key_material(laptop, NEW_PASSWORD)
    laptop_client.pull()
    phone.lock()
    laptop.lock()


def test_password_change_after_taking_a_rotation_over(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    laptop, phone = _laptop_and_phone(url, tmp_path)
    phone_client = _client(phone, url)
    _client(laptop, url).pull()
    laptop.change_password(PASSWORD, PASSWORD, rotate_identity=True)
    assert not _client(laptop, url).push()["conflicts"]

    phone_client._token = None  # a new login, as after the session ended
    with pytest.raises(KeyEpochStale):
        phone_client.push()
    phone_client.adopt_rotated_key_material(phone, PASSWORD)
    assert not phone_client.push()["conflicts"]
    _lands(url, tmp_path, laptop, phone, monkeypatch)


def test_password_change_after_another_device_added_a_folder(server, tmp_path, monkeypatch):  # noqa: F811
    url, db = server
    laptop, phone = _laptop_and_phone(url, tmp_path)
    laptop.create_node("new on the laptop")
    assert not _client(laptop, url).push()["conflicts"]
    _lands(url, tmp_path, laptop, phone, monkeypatch)

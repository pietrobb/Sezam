"""Review e4cd15a (low): an existing password with a control character.

The rule against control characters (688edcb) was applied to every
change_password call, including the ones that keep the current password: a
KDF upgrade and an identity rotation. A vault whose password predates the rule
(for example one ending in \\r from a piped Windows file) could do neither
until the password itself was changed. Only a new password is checked now.
"""

from __future__ import annotations

import pytest

from sezam.crypto.kdf import Argon2Params
from sezam.vault import crud
from sezam.vault.crud import Vault

FAST = Argon2Params(time_cost=1, memory_cost=8 * 1024, parallelism=1)
FASTER_UPGRADE = Argon2Params(time_cost=2, memory_cost=8 * 1024, parallelism=1)
OLD = "old password\r"  # set before the rule existed


@pytest.fixture
def old_vault(tmp_path, monkeypatch):
    with monkeypatch.context() as m:
        m.setattr(crud, "require_usable_password", lambda password: None)
        vault = Vault.create(tmp_path / "v", OLD, FAST)
    yield vault
    vault.lock()


def test_kdf_upgrade_keeps_the_existing_password(old_vault, tmp_path):
    old_vault.change_password(OLD, OLD, FASTER_UPGRADE)
    old_vault.lock()
    reopened = Vault(tmp_path / "v")
    reopened.unlock(OLD)
    reopened.lock()


def test_identity_rotation_keeps_the_existing_password(old_vault):
    before = bytes(old_vault.keypair.signing_pk)
    old_vault.change_password(OLD, OLD, rotate_identity=True)
    assert bytes(old_vault.keypair.signing_pk) != before


def test_a_new_password_with_one_is_still_refused(old_vault):
    with pytest.raises(ValueError, match="control character"):
        old_vault.change_password(OLD, "new password\r")

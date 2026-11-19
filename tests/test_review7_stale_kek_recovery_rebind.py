"""Review 7c10379 (desktop core, medium): stale KEK in org recovery and rebind.

The GUI stays unlocked with the KEK it derived at unlock while another
process changes the password. 'setup_org_recovery' then sealed that old KEK
for the Shamir shares, so a recovery with them restored a dead key. And
'rebind_server_identity' (GUI connect) re-wrapped the keypair under the old
KEK with the new kek_dek_id, so neither password unlocked the vault. Both now
check the vault's KEK like every other KEK wrap (KeyChangedElsewhere).
"""

from __future__ import annotations

import pytest

from sezam.models import new_ulid
from sezam.vault.crud import Vault
from sezam.vault.dek import KeyChangedElsewhere
from tests.test_review6_stale_kek_process import NEW, OLD, two_processes  # noqa: F401


def test_stale_process_cannot_seal_the_old_kek_for_org_recovery(two_processes):  # noqa: F811
    path, gui, _folder = two_processes
    with pytest.raises(KeyChangedElsewhere):
        gui.setup_org_recovery(threshold=2, shares=3)

    fresh = Vault(path)
    fresh.unlock(NEW)
    assert not fresh.org_recovery_configured()
    fresh.lock()


def test_stale_process_cannot_rebind_the_keypair_under_the_old_kek(two_processes):  # noqa: F811
    path, gui, _folder = two_processes
    user_id = gui.db.get_meta("user_id")
    with pytest.raises(KeyChangedElsewhere):
        gui.rebind_server_identity(new_ulid())

    fresh = Vault(path)
    fresh.unlock(NEW)  # the new password still opens the vault
    assert fresh.db.get_meta("user_id") == user_id
    fresh.lock()


def test_stale_process_says_key_changed_not_wrong_password(two_processes):  # noqa: F811
    _path, gui, _folder = two_processes
    with pytest.raises(KeyChangedElsewhere):
        gui.current_auth_proof(NEW)

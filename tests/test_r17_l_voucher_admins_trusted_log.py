"""Review c02cc47 R17-L (§7): a retired key's object counts as vouched by an
admin's list only when the admin comes from a team log this device trusts.

Before, the desktop, web and phone read the admins from any log they held: a
log whose founder this device never confirmed names whatever keys the server
chose, so a server holding a leaked retired key named its own key admin and
vouched for what it signed with the leaked one.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from sezam import teamlog
from sezam.vault.sync_vouchers import VoucherMixin

ROOT = Path(__file__).resolve().parent.parent
SERVER_ADMIN, SERVER_KEY = "01SERVERCHOSENADMIN0000000", bytes(range(32))


class _Client(VoucherMixin):
    def __init__(self, trusted: bool):
        self._trusted = trusted
        self._user_id = "01BOB0000000000000000000000"
        self._keypair = SimpleNamespace(signing_pk=b"\x02" * 32)
        self._voucher_keys = {}
        self._vouched_cache = {}
        self._held_cache = frozenset()
        self.asked: list[str] = []

    def team_state(self):
        member = SimpleNamespace(active=True, signing_pk=SERVER_KEY.hex())
        return SimpleNamespace(members={SERVER_ADMIN: member})

    def team_log_trusted(self, state) -> bool:
        return self._trusted

    def _lists_of(self, poster_id, key):
        self.asked.append(poster_id)
        return frozenset({("forged", poster_id)}) if poster_id == SERVER_ADMIN else frozenset()

    def _held(self):
        return frozenset()


@pytest.mark.parametrize("trusted", [False, True])
def test_desktop_counts_an_admin_s_list_only_from_a_trusted_log(monkeypatch, trusted):
    monkeypatch.setattr(teamlog, "is_admin", lambda state, uid: uid == SERVER_ADMIN)
    client = _Client(trusted)
    vouched = client._vouched("01ALICE00000000000000000000")
    assert (("forged", SERVER_ADMIN) in vouched) is trusted
    assert (SERVER_ADMIN in client.asked) is trusted


def test_web_and_phone_take_the_voucher_admins_from_a_trusted_log_only():
    web = (ROOT / "web/static/js/app.js").read_text(encoding="utf-8")
    assert "const voucherTeam = webTeamLogTrusted(_sodium, teamLog, teamLogRefusal) ? teamLog.team : null;" in web
    assert "const team = voucherTeam;" in web and "const team = teamLog?.team;" not in web
    phone = (ROOT / "mobile/lib/services/sync_service.dart").read_text(encoding="utf-8")
    assert "final team = voucherLogTrusted ? teamLog?.team : null;" in phone
    assert "localTeamLogTrusted(\n                teamLog," in phone

"""Review c02cc47 R17-L, phone: opening Settings and the start of the forget
judge the team log without a write to it (mobile/test/r17_l_settings_judge_no_write_test.dart)."""

from __future__ import annotations

from tests.test_cross_client_password_change import _phone


def test_phone_settings_judge_the_team_log_without_a_write(tmp_path):
    _phone("", tmp_path, {}, {}, test_file="test/r17_l_settings_judge_no_write_test.dart")

"""Review c02cc47 R17-L, phone: the unsigned name a 409 'Identity key rotated'
carries is no login name (mobile/test/r17_l_rotated_name_test.dart)."""

from __future__ import annotations

from tests.test_cross_client_password_change import _phone


def test_phone_keeps_its_login_name_on_the_409(tmp_path):
    _phone("", tmp_path, {}, {}, test_file="test/r17_l_rotated_name_test.dart")

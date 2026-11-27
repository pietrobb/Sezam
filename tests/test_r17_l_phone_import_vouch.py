"""Review c02cc47 R17-L, phone: the base an imported unsent-changes file names
is no held server copy and goes in no key voucher list
(mobile/test/r17_l_import_vouch_test.dart)."""

from __future__ import annotations

from tests.test_cross_client_password_change import _phone


def test_phone_vouches_for_no_base_an_imported_file_names(tmp_path):
    _phone("", tmp_path, {}, {}, test_file="test/r17_l_import_vouch_test.dart")

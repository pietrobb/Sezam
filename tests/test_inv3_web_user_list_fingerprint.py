"""docs/ROOT_CAUSE_PLAN.md S4 (INV-3), web: the admin user list showed the
fingerprint of the server's unsigned UserInfo.signing_pk/encryption_pk.
It shows the pinned key's, this device's own, or that none is pinned.
"""

from __future__ import annotations

from tests.test_review_web import APP, _function, _run_source, pytestmark  # noqa: F401


def test_user_list_fingerprint_is_the_pinned_keys_never_the_servers():
    helpers = "\n".join(_function(name) for name in ("escapeHtml", "hexToBytes", "adminUserFingerprintHtml"))
    script = """(async () => {
      t = key => key;
      console.warn = () => {};
      displayFingerprint = async (s, e) => ({ hex: `fp-${s[0]}-${e[0]}`, identicon: '', words: '' });
      ensureSodium = async () => ({ crypto_scalarmult_base: () => new Uint8Array([9]) });
      getKnownKey = async id => id === 'BOB' ? { signing_pk: '01', encryption_pk: '02' } : null;
      state.userId = 'ME';
      state.keypair = { signingPk: new Uint8Array([7]), encryptionSk: new Uint8Array([8]) };
      const lie = { signing_pk: 'ff', encryption_pk: 'ee', key_fingerprint: 'fp-255-238' };
      return {
        bob: await adminUserFingerprintHtml({ id: 'BOB', ...lie }),
        eve: await adminUserFingerprintHtml({ id: 'EVE', ...lie }),
        me: await adminUserFingerprintHtml({ id: 'ME', ...lie }),
      };
    })()"""
    result = _run_source(helpers, script)
    assert "fp-1-2" in result["bob"]
    assert "admin.not_pinned" in result["eve"] and "255" not in result["eve"]
    assert "fp-7-9" in result["me"]
    assert not any("255" in html for html in result.values())
    assert "user.signing_pk" not in _function("renderAdminUserList")

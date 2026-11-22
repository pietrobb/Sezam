"""docs/ROOT_CAUSE_PLAN.md S4 (INV-3), web: every sign-in took the browser's
identity from the server's unsigned VerifyResponse.user_id
(``state.userId = authResp.user_id``). A server naming another account made
this browser act as that account with its own keys. The phone refuses that
since review 8595ec1 (R10-F). The identity is the account the keys were
wrapped for (the KEYPAIR_WRAP AAD); a verify reply naming another one
refuses the sign-in.
"""

from __future__ import annotations

import re

from tests.test_review_web import APP, _function, _run_source, pytestmark  # noqa: F401


def test_a_verify_reply_naming_another_account_refuses_the_sign_in():
    script = """(() => {
      t = key => key;
      const outcome = (resp, id) => { try { return signedInUserId(resp, id); } catch (err) { return err.message; } };
      return {
        same: outcome({ user_id: 'ME' }, 'ME'),
        other: outcome({ user_id: 'ADMIN' }, 'ME'),
        missing: outcome({}, 'ME'),
        no_keys: outcome({ user_id: 'ME' }, undefined),
      };
    })()"""
    result = _run_source(_function("signedInUserId"), script)
    assert result == {
        "same": "ME", "other": "error.identity_mismatch",
        "missing": "error.identity_mismatch", "no_keys": "error.identity_mismatch",
    }


def test_every_sign_in_takes_the_identity_of_its_keys():
    assert not re.search(r"state\.userId\s*=\s*authResp\.user_id", APP)
    # Password login, bootstrap, approval wait, org recovery.
    assert len(re.findall(r"state\.userId = signedInUserId\(authResp, ", APP)) == 4
    # The password login knows which account its keypair opened for.
    returns = re.findall(r"return \{ authResp,[^}]*\}", _function("signInWithLoginKeypair"))
    assert returns and all("userId:" in r for r in returns), returns

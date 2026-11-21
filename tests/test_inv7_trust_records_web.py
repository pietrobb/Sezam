"""INV-7, the browser side of capability run 411 (mobile/test/inv7_trust_records_test.dart,
test_inv7_unlock_never_blocked.py): every team-log trust record this browser
keeps (its confirmed anchor, the genesis hashes it left), damaged in every
way, refuses the team (local_damaged) and never the sign-in; confirming the
founder again replaces what cannot be read.
"""

from __future__ import annotations

import pytest

from tests import test_team_log_web_rekey as web
from tests.team_log_vectors import B, Log
from tests.test_review_web import pytestmark  # noqa: F401
from tests.test_web_old_kek_records import FAKE_IDB

EXTRA = ["loadWebLocalStateLocked", "webLocalTeamLogRefusal", "teamLogMismatch"]


@pytest.mark.parametrize("record", ["confirmed", "forgotten"])
@pytest.mark.parametrize("damage", ["garbage", "other_user", "not_a_list"])
def test_a_damaged_trust_record_refuses_the_team_not_the_sign_in(monkeypatch, record, damage):
    monkeypatch.setattr(web, "FUNCTIONS", web.FUNCTIONS + EXTRA)
    result = web._run(FAKE_IDB + f"const record = '{record}', damage = '{damage}';" + """
        state.userId = ids.B;
        const want = state.teamLog.team.genesisHash;
        loadSyncCheckpoint = async () => null;
        const reload = async () => {
            state.syncCheckpointLoaded = false;
            await loadWebLocalStateLocked(state.sessionSerial, sodium);
            return webLocalTeamLogRefusal();
        };
        await saveConfirmedTeamGenesis(want, sodium);
        await saveForgottenTeamGenesis(['c'.repeat(64)], sodium);
        const clean = await reload();
        const id = record === 'confirmed' ? `confirmed_team_genesis:${ids.B}` : `forgotten_team_genesis:${ids.B}`;
        const field = record === 'confirmed' ? 'encrypted_genesis' : 'encrypted_list';
        const aad = record === 'confirmed' ? `sezam-team-genesis-v1:` : `sezam-team-genesis-forgotten-v1:`;
        const seal = async (text, userId) => {
            const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
            const sealed = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(new TextEncoder().encode(text),
                new TextEncoder().encode(aad + userId), null, nonce, await syncCheckpointKey('device-v2', sodium, true));
            return bytesToHex(new Uint8Array([...nonce, ...sealed]));
        };
        const value = damage === 'garbage' ? 'zz' : damage === 'other_user'
            ? await seal(record === 'confirmed' ? want : JSON.stringify([want]), 'OTHER')
            : await seal(record === 'confirmed' ? 'not-a-genesis' : '{"a":1}', ids.B);
        records.set(id, { id, [field]: value });
        const refused = await reload();  // the sign-in's local state: never throws
        state.keypair.confirmedGenesis = want;
        await importAccountTeamAnchor(sodium);  // the sign-in's anchor import: never throws
        const stillRefused = webLocalTeamLogRefusal();
        await saveConfirmedTeamGenesis(want, sodium);  // the way out: the founder confirmed again
        const after = await reload();
        return { clean: clean && clean.message, cause: refused && refused.teamLogCause,
                 lost: refused && refused.teamLogLost, message: refused && refused.message,
                 stillRefused: stillRefused && stillRefused.teamLogCause, after: after && after.message,
                 confirmed: state.confirmedTeamGenesis === want,
                 forgotten: await loadForgottenTeamGenesis(sodium) };
    """, Log().genesis().member(B), me=B)
    assert result["clean"] is None
    assert result["cause"] == "local_damaged" and result["lost"] is False, result
    assert "confirming the team's founder again" in result["message"]
    assert result["stillRefused"] == "local_damaged"
    assert result["after"] is None and result["confirmed"] is True, result
    assert result["forgotten"] == ([] if record == "forgotten" else ["c" * 64])

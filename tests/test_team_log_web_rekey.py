"""Removing a member from the web follows the team log (TL5; docs/DESIGN_TEAM_LOG.md §4.2, §4.3.1).

The re-key of a team folder seals the new key to exactly the log's
recipients, at the log's level, with the encryption key the log names, and
its member.remove and folder.key records go with the objects. Envelopes and
/api/users decide nothing there.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from nacl.public import PrivateKey

from tests.team_log_vectors import A, B, C, D, F1, ITEM, K, Actor, Log
from tests.test_review_web import _function, _run_source, pytestmark  # noqa: F401
from tests.test_web_old_kek_records import FAKE_IDB
from tests.test_integration_client_server import PASSWORD, server  # noqa: F401
from tests.test_team_log_desktop import _forget_server_cache, _found_with_bob, team  # noqa: F401
from tests.web_tab import WebTab

TEAMLOG_JS = (Path(__file__).parents[1] / "web" / "static" / "js" / "teamlog.js").read_text(encoding="utf-8")
FUNCTIONS = [
    "buildWebRekeyBatch", "webTeamRekeyPlan", "webTeamLogTrusted", "webFounderLineage", "webTeamFolderAbove", "teamLogRefusedError",
    "writesNotToSeal", "unauthorizedWrites", "sealingDekId", "isEncryptedEnvelope", "payloadDekId", "keyAuthors",
    "folderTreeOwner", "provenDekSuccessors", "ulidTimeMs", "generateULID", "rekeyArchiveChars",
    "webLogAdmins", "removalArchiveId", "hexToBytes", "bytesToHex", "pushWebRekeyBatch", "handleInviteUser",
    "handleOnboarding", "normalizeUsername", "syncCheckpointKey", "idbKeysRequest",
    "invitationTeamGenesis", "loadConfirmedTeamGenesis", "saveConfirmedTeamGenesis",
    "openTeamTrustModal", "closeTeamTrustModal", "handleConfirmTeamFounder",
    "syncWebTeamLog", "restoreWebTeamLog", "teamLogPin", "assertTeamLogAllowsWrite", "pushEncryptedVaultObjectLocked", "webBase", "withWebBase",
    "encryptAccountKeypair", "encodeAccountKeypair", "decodeAccountKeypair", "parsePreAnchor",
]
ROOT = "01JR0000000000000000000001"
OTHER = "01JR0000000000000000000002"  # a folder outside every team folder
LEGACY = "01JE0000000000000000000009"  # an item below F1 with a key of its own (tier 2)


def _secrets(actor) -> dict:
    seed = hashlib.sha256(b"sezam-team-log-vector:" + actor.name.encode()).digest()
    epk_sk = hashlib.sha256(seed + b"x25519").digest()
    return {"signingSk": (bytes(actor.sk) + bytes(actor.sk.verify_key)).hex(),
            "signingPk": actor.spk, "encryptionSk": epk_sk.hex()}


def _run(script: str, log: Log, me=A):
    prelude = f"""
      const TL = globalThis.SezamTeamLog;
      const RECORDS = {json.dumps(log.records)};
      const ids = {json.dumps({"A": A.uid, "B": B.uid, "C": C.uid, "D": D.uid, "F1": F1, "ITEM": ITEM,
                                "ROOT": ROOT, "OTHER": OTHER, "LEGACY": LEGACY,
                                "K1": K[1], "K8": K[8], "K9": K[9]})};
      const me = {json.dumps(_secrets(me))};
      const bobSk = hexToBytes({json.dumps(_secrets(B)["encryptionSk"])});
      const sealed = (dekId, kind = 'node') => {{
        const bytes = new Uint8Array(60); bytes[0] = 1; bytes[1] = 1; bytes[2] = 1;
        bytes.set(new TextEncoder().encode(dekId), 3);
        const out = kind === 'entry' ? new Uint8Array([0, 0, 0, 60, ...bytes]) : bytes;
        return Buffer.from(out).toString('base64');
      }};
      const rec = (id, object_type, parent_ref, signer, dek, extra = {{}}) => ({{
        id, object_type, parent_ref, signer, owner_id: signer, version: 1, is_deleted: 0,
        payload: dek ? sealed(dek, object_type) : '', ...extra }});
      const env = (id, dek, user, level) => rec(id, 'envelope', dek, ids.A, null,
                                                {{ target_user_id: user, access_level: level }});
      state.userId = {json.dumps(me.uid)};
      state.isAdmin = true;
      state.kek = new Uint8Array(32);
      state.keypair = {{ signingSk: hexToBytes(me.signingSk), signingPk: hexToBytes(me.signingPk),
                        encryptionSk: hexToBytes(me.encryptionSk) }};
      state.deks = {{ [ids.K1]: new Uint8Array(32).fill(1), [ids.K8]: new Uint8Array(32).fill(8),
                     [ids.K9]: new Uint8Array(32).fill(9) }};
      state.teamLog = {{ records: RECORDS, team: TL.replay(RECORDS, sodium) }};
      state.syncObjects = Object.fromEntries([
        rec(ids.ROOT, 'node', null, ids.A, ids.K8),
        rec(ids.K8, 'dek', ids.ROOT, ids.A, null, {{ scope: 'root' }}),
        rec(ids.F1, 'node', ids.ROOT, ids.A, ids.K1),
        rec(ids.K1, 'dek', ids.F1, ids.A, null, {{ scope: 'folder' }}),
        rec(ids.ITEM, 'entry', ids.F1, ids.B, ids.K1),
        rec(ids.OTHER, 'node', ids.ROOT, ids.A, ids.K8),
        rec(ids.LEGACY, 'entry', ids.F1, ids.A, ids.K9),
        rec(ids.K9, 'dek', ids.F1, ids.A, null, {{ scope: 'tier2' }}),
        // The server's envelopes: Carol and Dan have F1 by them, Dan even 'write'.
        env('E_B1', ids.K1, ids.B, 'read'), env('E_C1', ids.K1, ids.C, 'read'),
        env('E_D1', ids.K1, ids.D, 'write'),
        env('E_C9', ids.K9, ids.C, 'read'), env('E_C8', ids.K8, ids.C, 'read'),
        env('E_B8', ids.K8, ids.B, 'read'),
      ].map(o => [o.id, o]));
      apiFetch = async () => [ids.A, ids.B, ids.C, ids.D].map(id => ({{ id, status: 'active' }}));
      wrapDEK = () => new Uint8Array(72);
      wrapDEKWithKey = () => new Uint8Array(72);
      encryptedPayloadDekId = obj => payloadDekId(obj);
      decryptEnvelope = () => ({{ name: 'x' }});
      decryptEntryPayload = () => ({{ name: 'x' }});
      encryptEnvelope = () => new Uint8Array(60);
      encryptEntryPayload = () => new Uint8Array(60);
      const askedPk = [];
      getVerifiedEncryptionPkForRekey = async userId => {{
        askedPk.push(userId); return sodium.crypto_box_keypair().publicKey; }};
      buildSignedSyncObject = async (_s, meta, payload) => ({{ ...meta, payload }});
      loadWebWriteGrants = async () => new Set();
      saveWebWriteGrants = async () => {{}};
      const attempt = async () => {{
        try {{ return await buildWebRekeyBatch(ids.C, sodium); }} catch (err) {{ return err.message; }}
      }};
    """
    if script.lstrip().startswith("(async"):
        script = "return " + script.lstrip()
    return _run_source(TEAMLOG_JS + "\nvar ENVELOPE_ALG = 1, SCHEMA_VERSION = 1, TEAM_LOG_PAGES = 1000, BLOB_KIND = { NODE_META: 1 };\n" + "\n".join(_function(n) for n in FUNCTIONS),
                       "(async () => {" + prelude + script + "\n})()")


@pytest.mark.parametrize("fragment,valid", [("#g=" + "a" * 64, True), ("", True),
                                           ("#g=broken", False), ("#g=", False)])
def test_web_onboarding_saves_invitation_anchor_before_approval(fragment, valid):
    result = _run(FAKE_IDB + "const fragment = " + json.dumps(fragment) + ";" + """
        state.teamLog = null;
        window.location = { search: '?invite=abc', hash: fragment };
        const elements = {};
        document.getElementById = id => elements[id] ||= {
            value: id === 'onboard-username' ? 'bob' : 'a-long-password',
            classList: { add() {}, remove() {} }, textContent: '',
        };
        ensureSodium = async () => sodium;
        meetsNewPasswordPolicy = () => true;
        t = key => key;
        normalizeKdfParams = x => x;
        deriveKEK = async () => new Uint8Array(64).fill(4);
        const wrapped = [];
        encryptKeypairWrap = payload => { wrapped.push(Buffer.from(payload).toString('hex')); return new Uint8Array(72); };
        bytesToBase64 = b => Buffer.from(b).toString('base64');
        const calls = [];
        apiFetch = async (url, options) => {
            calls.push([url, options]);
            if (url === '/api/users/register') return { token: 't', user_id: ids.B };
            return { argon2_web_params: { t: 1, m: 1024, l: 1 } };
        };
        saveToIndexedDB = async () => {};
        buildSezamKeyBackup = () => new Uint8Array(1);
        offerSezamKeyDownload = () => {};
        let approved = false;
        pollForApproval = async () => { approved = true; };
        await handleOnboarding({ preventDefault() {} });
        return { approved, error: elements['onboard-error'].textContent,
                 stored: [...records.values()], calls, wrapped };
    """, Log().genesis())
    assert result["approved"] is valid, result["error"]
    if not valid:
        assert "Invalid team genesis" in result["error"]
        assert result["calls"] == []
        assert result["stored"] == []
        return
    # The uploaded account envelope carries the invitation anchor for new devices.
    [payload] = result["wrapped"]
    if fragment:
        assert payload == b"SZACCT01".hex() + payload[16:144] + "a" * 64
    else:
        assert len(payload) == 192
    assert any(row.get("encrypted_genesis") for row in result["stored"]) is bool(fragment)
    assert "a" * 64 not in json.dumps(result["stored"])
    assert "a" * 64 not in json.dumps(result["calls"])


def test_web_invitation_anchor_survives_reload_and_password_change_without_trusting_observed_pin():
    result = _run(FAKE_IDB + """
        state.userId = ids.B;
        const want = state.teamLog.team.genesisHash;
        const announced = teamLogPin(state.teamLog.team);
        state.syncCheckpoint = { team_log: announced };
        const observedOnly = webTeamLogTrusted(sodium);
        await saveConfirmedTeamGenesis(want, sodium);
        const trustedBefore = webTeamLogTrusted(sodium);
        // New login, a different KEK and no previous in-memory log/checkpoint.
        state.kek = newKek;
        state.confirmedTeamGenesis = null;
        state.teamLog = null;
        state.syncCheckpoint = null;
        state.confirmedTeamGenesis = await loadConfirmedTeamGenesis(sodium);
        apiFetch = async () => ({ records: RECORDS });
        state.teamLog = await syncWebTeamLog(announced, null, null, sodium);
        const trustedAfter = webTeamLogTrusted(sodium);
        const id = `confirmed_team_genesis:${state.userId}`;
        const before = JSON.stringify(records.get(id));
        let conflict = false;
        try { await saveConfirmedTeamGenesis('f'.repeat(64), sodium); }
        catch (err) { conflict = err.message.startsWith('TEAM LOG MISMATCH'); }
        return { observedOnly, trustedBefore, trustedAfter, conflict,
                 preserved: before === JSON.stringify(records.get(id)),
                 loaded: state.confirmedTeamGenesis, want };
    """, Log().genesis().member(B), me=B)
    assert result == {"observedOnly": False, "trustedBefore": True, "trustedAfter": True,
                      "conflict": True, "preserved": True, "loaded": result["want"], "want": result["want"]}


@pytest.mark.parametrize("fault", ["storage", "refresh", "session", "cancel", "foreign-pin", "corrupt-log", "forged-readd"])
def test_web_founder_confirmation_failures_preserve_trust_and_allow_retry(fault):
    log = Log().genesis().member(B)
    if fault == "forged-readd":
        attacker = Actor("fake-alice", 1)
        log = Log().genesis(attacker).member(B, "admin", by=attacker)
        log.add("member.role", attacker, {"user_id": attacker.uid, "role": "member"})
        log.remove(attacker, by=B).member(A, "admin", by=B)
    expected = hashlib.sha256(bytes.fromhex(A.spk + A.epk)).hexdigest()
    result = _run(FAKE_IDB + "const fault = " + json.dumps(fault) + "; const fingerprint = " + json.dumps(expected) + ";" + """
        state.userId = ids.B;
        state.confirmedTeamGenesis = null;
        const elements = {};
        document.getElementById = id => elements[id] ||= {
            value: '', textContent: '', disabled: false,
            classList: { hidden: true, add() { this.hidden = true; }, remove() { this.hidden = false; } },
        };
        t = key => key;
        ensureSodium = async () => sodium;
        let pulls = 0;
        pullAndBuildTreeLocked = async () => { pulls++; if (fault === 'refresh' && pulls === 1) throw Error('offline'); };
        const checkpoint = teamLogPin(state.teamLog.team);
        state.syncCheckpoint = { team_log: checkpoint, last_sync_seq: 99 };
        const before = JSON.stringify(state.syncCheckpoint);
        await syncCheckpointKey('device-v2', sodium, true);
        const original = idbKeysRequest;
        let failWrite = fault === 'storage';
        idbKeysRequest = async (mode, action) => {
            if (failWrite && mode === 'readwrite') { failWrite = false; throw Error('disk failure'); }
            return original(mode, action);
        };
        if (fault === 'foreign-pin') {
            const heldLog = state.teamLog;
            state.teamLog = null; state.syncCheckpoint = null;
            await saveConfirmedTeamGenesis('f'.repeat(64), sodium);
            state.teamLog = heldLog; state.syncCheckpoint = JSON.parse(before);
        }
        const packedBefore = JSON.stringify([...records.values()]);
        await openTeamTrustModal();
        const blank = elements['team-founder-fingerprint'].value === '';
        elements['team-founder-fingerprint'].value = fingerprint;
        if (fault === 'session') state.sessionSerial = 123;
        if (fault === 'cancel') closeTeamTrustModal();
        if (fault === 'corrupt-log') state.teamLog.records[1].sig = '0'.repeat(128);
        await handleConfirmTeamFounder({ preventDefault() {} });
        const first = {
            confirmed: state.confirmedTeamGenesis, pulls, error: elements['team-trust-error'].textContent,
            unchanged: packedBefore === JSON.stringify([...records.values()]),
        };
        if (fault === 'storage' || fault === 'refresh') {
            await handleConfirmTeamFounder({ preventDefault() {} });
        }
        return { first, blank, checkpointKept: before === JSON.stringify(state.syncCheckpoint),
            confirmed: state.confirmedTeamGenesis, want: state.teamLog.team.genesisHash,
            disabled: elements['team-trust-confirm'].disabled };
    """, log, me=B)
    assert result["blank"] and result["checkpointKept"] and not result["disabled"], result
    if fault == "refresh":
        assert result["first"]["confirmed"] == result["want"]
        assert result["first"]["error"] == "team.saved_refresh_failed"
    else:
        assert result["first"]["confirmed"] == ("f" * 64 if fault == "foreign-pin" else None), result
        assert result["first"]["pulls"] == 0 and result["first"]["unchanged"], result
    if fault in ("storage", "refresh"):
        assert result["confirmed"] == result["want"], result
    elif fault != "foreign-pin":
        assert result["confirmed"] is None, result


@pytest.mark.parametrize("rotated", [False, True])
def test_web_founder_confirmation_ui_reads_secret_and_survives_restart(team, server, tmp_path, rotated):
    from sezam.crypto.keys import compute_fingerprint
    from sezam.vault.revocation import grant_member
    from tests.test_review9_team_identity import _rotate
    from tests.test_team_log_desktop_changes import _ops

    url, _ = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    old_fingerprint = compute_fingerprint(admin.keypair.signing_pk, admin.keypair.encryption_pk)
    if rotated:
        client = _rotate(admin, client, url)
        client.push()
    fingerprint = compute_fingerprint(admin.keypair.signing_pk, admin.keypair.encryption_pk)
    ops = _ops(admin)
    admin.create_entry(ops, "confirmed-founder-secret", [{"key": "password", "value": "external-only"}])
    grant_member(admin, client, bob.db.get_meta("user_id"), ops, "write")
    tab = WebTab(url, tmp_path / "founder.log")
    try:
        login = tab.do("login", username="bob", password=PASSWORD)
        assert login["error"] is None, login
        assert not any(e["password"] == "external-only" for e in login["view"]["entries"])
        opened = tab.do("founder", open=True)
        assert opened["error"] is None, opened
        cancelled = tab.do("founder", cancel=True)
        assert cancelled["error"] is None, cancelled
        assert not any(e["password"] == "external-only" for e in cancelled["view"]["entries"])
        for invalid in ("", "f" * 64):
            refused = tab.do("founder", open=True, fingerprint=invalid)
            assert refused["error"], refused
            assert refused["calls"] == []
            assert not any(e["password"] == "external-only" for e in refused["view"]["entries"])
        confirmed = tab.do("founder", fingerprint=fingerprint.upper())
        assert confirmed["error"] is None, confirmed
        assert any(e["password"] == "external-only" for e in confirmed["view"]["entries"]), confirmed
        profile = tab.close()
    finally:
        tab.kill()
    tab = WebTab(url, tmp_path / "founder-restart.log", idb=profile)
    try:
        login = tab.do("login", username="bob", password=PASSWORD)
        assert login["error"] is None, login
        assert any(e["password"] == "external-only" for e in login["view"]["entries"]), login
        # A pre-rotation fingerprint still anchors the double-signed lineage.
        confirmed = tab.do("founder", open=True, fingerprint=old_fingerprint)
        assert confirmed["error"] is None, confirmed
    finally:
        tab.kill()


def test_web_anchor_session_change_cannot_publish_confirmation():
    result = _run(FAKE_IDB + """
        const want = state.teamLog.team.genesisHash;
        const inner = syncCheckpointKey;
        syncCheckpointKey = async (...args) => {
            const key = await inner(...args);
            state.sessionSerial = (state.sessionSerial || 0) + 1;
            state.userId = null;
            state.confirmedTeamGenesis = null;
            return key;
        };
        let refusal = null;
        try { await saveConfirmedTeamGenesis(want, sodium); }
        catch (err) { refusal = err.message; }
        return { refusal, confirmed: state.confirmedTeamGenesis,
                 saved: [...records.values()].some(row => row.encrypted_genesis) };
    """, Log().genesis())
    assert result == {"refusal": "The anchor session has ended", "confirmed": None, "saved": False}


def test_web_expected_but_missing_log_blocks_invitation_and_queue():
    result = _run("""
        state.confirmedTeamGenesis = state.teamLog.team.genesisHash;
        state.teamLog = null;
        let issued = false, invitationError = null, writeError = null;
        ensureSodium = async () => sodium;
        t = (_key, args) => args?.reason || args?.error;
        alert = message => { invitationError = message; };
        apiFetch = async () => { issued = true; };
        await handleInviteUser();
        try { assertTeamLogAllowsWrite({ object_type: 'entry' }); }
        catch (err) { writeError = err.message; }
        return { issued, invitationError, writeError };
    """, Log().genesis())
    assert not result["issued"]
    assert "not confirmed" in result["invitationError"]
    assert "not downloaded" in result["writeError"]


@pytest.mark.parametrize("operation", ["write", "delete", "move"])
@pytest.mark.parametrize("trust", ["none", "observed", "confirmed", "founder"])
def test_web_unconfirmed_log_cannot_authorize_queued_writes(operation, trust):
    log = Log().genesis().member(B).key(F1, 0, K[1], None).access(F1, B, "write")
    result = _run("const operation = " + json.dumps(operation) + "; const trust = " + json.dumps(trust) + ";" + """
        state.sodium = sodium;
        if (trust === 'confirmed') state.confirmedTeamGenesis = state.teamLog.team.genesisHash;
        if (trust === 'observed') state.syncCheckpoint = { team_log: teamLogPin(state.teamLog.team) };
        const obj = rec(ids.ITEM, 'entry', operation === 'move' ? ids.OTHER : ids.F1,
                        state.userId, operation === 'move' ? ids.K8 : ids.K1,
                        { is_deleted: operation === 'delete' ? 1 : 0 });
        const before = JSON.stringify(state.syncObjects);
        state.outbox = {}; state.syncConflicts = {};
        const calls = [];
        ensureSodium = async () => sodium;
        assertNotStackedOnConflict = () => {};
        assertSyncObjectFits = () => {};
        saveWebDirtyState = async () => { calls.push('saved'); };
        isSameSyncVersion = () => true;
        renderWebSyncConflicts = () => {};
        apiFetch = async () => { calls.push('sent'); return { accepted: [{ id: obj.id }] }; };
        let refusal = null;
        try { await pushEncryptedVaultObjectLocked(obj); }
        catch (err) { refusal = err.message; }
        return { refusal, calls, dirty: Object.keys(state.outbox),
                 preserved: before === JSON.stringify(state.syncObjects) };
    """, log, me=A if trust == "founder" else B)
    assert result["preserved"]
    assert result["dirty"] == []
    if trust in ("confirmed", "founder"):
        assert result["refusal"] is None, result
        assert "sent" in result["calls"]
    else:
        assert "not confirmed" in (result["refusal"] or ""), result
        assert result["calls"] == []


def test_web_unconfirmed_log_does_not_block_personal_or_legacy_writes():
    result = _run("""
        state.sodium = sodium;
        const own = '01JK0000000000000000000099';
        state.syncObjects[own] = rec(own, 'dek', null, state.userId, null);
        const object = rec('01JE0000000000000000000099', 'entry', ids.OTHER, state.userId, own);
        assertTeamLogAllowsWrite(object);
        state.teamLog = null;
        assertTeamLogAllowsWrite(object);
        return true;
    """, Log().genesis().member(B).key(F1, 0, K[1], None), me=B)
    assert result is True


def test_web_anchor_corruption_missing_key_and_cross_account_copy_fail_closed():
    result = _run(FAKE_IDB + """
        const want = state.teamLog.team.genesisHash;
        await saveConfirmedTeamGenesis(want, sodium);
        const id = `confirmed_team_genesis:${state.userId}`;
        const keyId = `sync_checkpoint_key:${state.userId}`;
        const original = JSON.parse(JSON.stringify(records.get(id)));
        const key = records.get(keyId);
        const errors = [];
        const refuses = async () => {
            try { await loadConfirmedTeamGenesis(sodium); errors.push('accepted'); }
            catch (err) { errors.push(err.message); }
        };
        records.set(id, { id, genesis: want });
        await refuses();
        const altered = hexToBytes(original.encrypted_genesis); altered[0] ^= 1;
        records.set(id, { ...original, encrypted_genesis: bytesToHex(altered) });
        await refuses();
        records.set(id, original);
        records.delete(keyId);
        await refuses();
        state.userId = 'OTHER';
        records.set('confirmed_team_genesis:OTHER', { ...original, id: 'confirmed_team_genesis:OTHER' });
        records.set('sync_checkpoint_key:OTHER', { ...key, id: 'sync_checkpoint_key:OTHER' });
        await refuses();
        return errors;
    """, Log().genesis())
    assert len(result) == 4
    assert all(message.startswith("Invalid encrypted team anchor:") for message in result)


def test_complete_web_login_uses_persisted_anchor_and_retries_after_server_lie(team, server, tmp_path):  # noqa: F811
    url, _ = server
    db, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    genesis = client.team_state().genesis_hash
    bob_id = bob.db.get_meta("user_id")
    # Use the same app storage path as onboarding, then open the whole app in a new process.
    stored = _run(FAKE_IDB + f"""
        state.userId = {json.dumps(bob_id)};
        state.teamLog = null;
        await saveConfirmedTeamGenesis({json.dumps(genesis)}, sodium);
        return [...records.values()];
    """, Log().genesis())
    profile = {"keys": [{"id": row["id"], "__json": json.dumps(row)} for row in stored]}
    honest = list(db._storage["team_log"])
    db._storage["team_log"] = []
    _forget_server_cache()
    tab = WebTab(url, tmp_path / "anchored-web.log", idb=profile)
    try:
        denied = tab.do("login", username="bob", password=PASSWORD)
        assert "TEAM LOG MISMATCH" in (denied["error"] or ""), denied
        assert not denied["view"]["unlocked"]
        assert not denied["view"]["entries"]
        profile = tab.close()
    finally:
        tab.kill()
        db._storage["team_log"] = honest
        _forget_server_cache()
    kept = {row["id"]: json.loads(row["__json"]) for row in profile["keys"]}
    anchor_id = f"confirmed_team_genesis:{bob_id}"
    assert kept[anchor_id] == next(row for row in stored if row["id"] == anchor_id)
    assert f"sync_checkpoint:{bob_id}" not in kept
    tab = WebTab(url, tmp_path / "anchored-web-retry.log", idb=profile)
    try:
        accepted = tab.do("login", username="bob", password=PASSWORD)
        assert accepted["error"] is None, accepted
        assert accepted["view"]["unlocked"]
        profile = tab.close()
    finally:
        tab.kill()
    from tests.test_review9_team_identity import _rotate
    client = _rotate(admin, client, url)
    client.push()
    tab = WebTab(url, tmp_path / "anchored-web-rotated.log", idb=profile)
    try:
        rotated = tab.do("login", username="bob", password=PASSWORD)
        assert rotated["error"] == "error.tofu_key_changed", rotated
    finally:
        tab.kill()
    # A separately provisioned anchor in a fresh browser still accepts the rotated chain.
    fresh = {"keys": [{"id": row["id"], "__json": json.dumps(row)} for row in stored]}
    tab = WebTab(url, tmp_path / "anchored-web-fresh-rotated.log", idb=fresh)
    try:
        rotated = tab.do("login", username="bob", password=PASSWORD)
        assert rotated["error"] is None, rotated
        assert rotated["view"]["unlocked"]
    finally:
        tab.kill()


def test_complete_web_unconfirmed_member_write_refused_then_anchored_retry(team, server, tmp_path):  # noqa: F811
    from sezam.vault import revocation
    from tests.test_team_log_desktop_changes import _ops

    url, db = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    ops = _ops(admin)
    bob_id = bob.db.get_meta("user_id")
    revocation.grant_member(admin, client, bob_id, ops, "write")
    before = json.dumps(db._storage["vault_objects"], sort_keys=True, default=str)
    tab = WebTab(url, tmp_path / "unconfirmed-write.log")
    try:
        login = tab.do("login", username="bob", password=PASSWORD)
        assert login["error"] is None, login
        denied = tab.do("save_object", mode="entry", name="must-not-leave-browser", parent=ops,
                        fields=[{"key": "password", "value": "secret"}])
        # Receipt is now refused too: sealing stops before the write gate, with no folder key.
        assert "does not hold the folder's current key" in (denied["error"] or ""), denied
        assert denied["view"]["dirty"] == []
        assert json.dumps(db._storage["vault_objects"], sort_keys=True, default=str) == before
        profile = tab.close()
    finally:
        tab.kill()
    stored = _run(FAKE_IDB + f"""
        state.userId = {json.dumps(bob_id)};
        state.teamLog = null;
        await saveConfirmedTeamGenesis({json.dumps(client.team_state().genesis_hash)}, sodium);
        return [...records.values()];
    """, Log().genesis())
    # Anchor storage shares the device key with the observed checkpoint: install it only
    # into a fresh browser, not by replacing that key underneath an existing ciphertext.
    profile = {"keys": [{"id": row["id"], "__json": json.dumps(row)} for row in stored]}
    tab = WebTab(url, tmp_path / "confirmed-write.log", idb=profile)
    try:
        login = tab.do("login", username="bob", password=PASSWORD)
        assert login["error"] is None, login
        accepted = tab.do("save_object", mode="entry", name="confirmed-write", parent=ops,
                          fields=[{"key": "password", "value": "secret"}])
        assert accepted["error"] is None, accepted
        assert accepted["view"]["dirty"] == []
        assert any(e["name"] == "confirmed-write" for e in accepted["view"]["entries"]), accepted
        queued = tab.do("save_object", mode="entry", name="queued-write", parent=ops,
                        fields=[{"key": "password", "value": "queued-secret"}],
                        fail={"method": "POST", "path": "/api/sync", "mode": "before"})
        assert queued["failure"]["fired"], queued
        assert len(queued["view"]["dirty"]) == 1, queued
        profile = tab.close()
    finally:
        tab.kill()
    assert json.dumps(db._storage["vault_objects"], sort_keys=True, default=str) != before
    before_retry = json.dumps(db._storage["vault_objects"], sort_keys=True, default=str)
    anchor = next(row for row in profile["keys"] if row["id"] == f"confirmed_team_genesis:{bob_id}")
    profile["keys"].remove(anchor)  # A profile holding observed history, not an external confirmation.
    tab = WebTab(url, tmp_path / "unconfirmed-queue.log", idb=profile)
    try:
        login = tab.do("login", username="bob", password=PASSWORD)
        assert login["error"] is None, login
        refused = tab.do("retry")
        assert "not confirmed" in (refused["error"] or ""), refused
        assert refused["view"]["dirty"] == queued["view"]["dirty"]
        assert not any(c["method"] == "POST" and c["path"] == "/api/sync" for c in refused["calls"])
        profile = tab.close()
    finally:
        tab.kill()
    assert json.dumps(db._storage["vault_objects"], sort_keys=True, default=str) == before_retry
    profile["keys"].append(anchor)
    tab = WebTab(url, tmp_path / "confirmed-queue-retry.log", idb=profile)
    try:
        login = tab.do("login", username="bob", password=PASSWORD)
        assert login["error"] is None, login
        retried = tab.do("retry")
        assert retried["error"] is None, retried
        assert retried["view"]["dirty"] == []
        assert any(e["name"] == "queued-write" and e["password"] == "queued-secret"
                   for e in retried["view"]["entries"]), retried
    finally:
        tab.kill()


@pytest.mark.parametrize("case", ["unconfirmed", "level", "withdrawn", "cached-withdrawn", "honest",
                                  "kek-unconfirmed", "kek-withdrawn", "kek-honest", "member-signed", "rotated-honest"])
def test_web_team_key_receipt_requires_confirmed_authority(team, server, tmp_path, case):  # noqa: F811
    from sezam import teamlog
    from sezam.vault import revocation
    from tests.test_team_log_desktop_changes import _ops

    url, db = server
    _, admin, client, bob, _ = team
    _found_with_bob(client, bob)
    ops = _ops(admin)
    admin.create_entry(ops, "anchor-secret", [{"key": "password", "value": "must-stay-sealed"}])
    assert client.push()["conflicts"] == []
    bob_id = bob.db.get_meta("user_id")
    revocation.grant_member(admin, client, bob_id, ops, "read")
    key = teamlog.current_key(client.team_state(), ops)
    envelope = next(o for o in db._storage["vault_objects"]
                    if o["object_type"] == "envelope" and o["parent_ref"] == key)
    if case == "member-signed":
        from sezam.crypto.envelope_crypto import create_envelope
        from tests.test_integration_client_server import _client

        payload = create_envelope(admin.dek_mgr.unlock_dek(key), bytes(bob.keypair.encryption_sk),
                                  bytes(bob.keypair.encryption_pk))
        signed = _client(bob, url)._make_sync_object(
            envelope["id"], "envelope", payload, parent_ref=key, target_user_id=bob_id,
            access_level="read", version=envelope["version"])
        envelope.update(payload=payload, payload_hash=signed["payload_hash"],
                        client_signature=bytes.fromhex(signed["signature"]), signature_user_id=bob_id)
    if case.startswith("kek-"):
        from sezam.crypto.aead import encrypt_dek_wrap
        from sezam.models import ulid_to_bytes

        # A validly signed wrap this member's KEK opens is not a grant from the log.
        row = next(o for o in db._storage["vault_objects"] if o["id"] == key)
        payload = encrypt_dek_wrap(admin.dek_mgr.unlock_dek(key), bob.dek_mgr._kek,
                                   ulid_to_bytes(bob.dek_mgr.kek_dek_id), ulid_to_bytes(key),
                                   version=row["version"])
        signed = client._make_sync_object(key, "dek", payload, parent_ref=ops, version=row["version"])
        row.update(payload=payload, payload_hash=signed["payload_hash"],
                   client_signature=bytes.fromhex(signed["signature"]))
        envelope["access_level"] = "write"  # Refuse the box path even in the positive KEK case.
    profile = None
    if not case.endswith("unconfirmed"):
        stored = _run(FAKE_IDB + f"""
            state.userId = {json.dumps(bob_id)};
            state.teamLog = null;
            await saveConfirmedTeamGenesis({json.dumps(client.team_state().genesis_hash)}, sodium);
            return [...records.values()];
        """, Log().genesis())
        profile = {"keys": [{"id": row["id"], "__json": json.dumps(row)} for row in stored]}
    if case == "rotated-honest":
        from tests.test_integration_client_server import _client
        client.prepare_key_change()
        admin.db.execute("DELETE FROM access_envelopes WHERE user_id = ?", (bob_id,))
        proof = admin.change_password(PASSWORD, PASSWORD, rotate_identity=True)
        proof[:] = bytes(len(proof))
        client = _client(admin, url)
        assert client.push()["conflicts"] == []
    if case == "level":
        envelope["access_level"] = "write"
    if case in ("withdrawn", "kek-withdrawn"):
        client.append_team_log([("access.set", {"folder": ops, "user_id": bob_id, "level": None})])
    tab = WebTab(url, tmp_path / f"key-receipt-{case}.log", idb=profile)
    try:
        result = tab.do("login", username="bob", password=PASSWORD)
        assert result["error"] is None, result
        if case == "cached-withdrawn":
            entry = next(e for e in result["view"]["entries"] if e["password"] == "must-stay-sealed")
            selected = tab.do("select_entry", id=entry["id"])
            assert selected["view"]["selectedPassword"] == "must-stay-sealed"
            assert "must-stay-sealed" in selected["view"]["detailFields"]
            client.append_team_log([("access.set", {"folder": ops, "user_id": bob_id, "level": None})])
            result = tab.do("refresh")
            assert result["error"] is None, result
        readable = any(e["password"] == "must-stay-sealed" for e in result["view"]["entries"])
        assert readable == case.endswith("honest"), result
        assert result["view"]["selectedPassword"] is None, result
        assert "must-stay-sealed" not in result["view"]["detailFields"], result
        if case == "cached-withdrawn":
            client.append_team_log([("access.set", {"folder": ops, "user_id": bob_id, "level": "read"})])
            retried = tab.do("refresh")
            assert retried["error"] is None, retried
            assert any(e["password"] == "must-stay-sealed" for e in retried["view"]["entries"]), retried
            client.append_team_log([("access.set", {"folder": ops, "user_id": bob_id, "level": None})])
            assert tab.do("refresh")["error"] is None
        profile = tab.close()
    finally:
        tab.kill()
    tab = WebTab(url, tmp_path / f"key-receipt-restart-{case}.log", idb=profile)
    try:
        restarted = tab.do("login", username="bob", password=PASSWORD)
        assert restarted["error"] is None, restarted
        assert any(e["password"] == "must-stay-sealed" for e in restarted["view"]["entries"]) == case.endswith("honest")
    finally:
        tab.kill()


def test_web_invitation_genesis_parser_rejects_malformed_and_duplicate_pins():
    result = _run("""
        const invalid = ['#g=', '#g=abc', '#g=' + 'a'.repeat(63), '#g=' + 'z'.repeat(64),
                         '#g=' + 'a'.repeat(64) + '&g=' + 'a'.repeat(64)];
        return { rejected: invalid.map(fragment => {
                    try { invitationTeamGenesis(fragment); return false; } catch { return true; }
                 }), absent: invitationTeamGenesis(''),
                 upper: invitationTeamGenesis('#g=' + 'AB'.repeat(32)) };
    """, Log().genesis())
    assert result == {"rejected": [True] * 5, "absent": None, "upper": "ab" * 32}


def test_web_invitation_uses_verified_local_genesis_not_server_response():
    result = _run("""(async () => {
        window.location = { origin: 'https://sync.invalid', pathname: '/' };
        ensureSodium = async () => sodium;
        let link = null;
        showInviteModal = (_token, value) => { link = value; };
        alert = message => { throw new Error(message); };
        apiFetch = async () => ({ invitation_token: 'a&b', genesis_hash: 'f'.repeat(64) });
        const want = state.teamLog.team.genesisHash;
        await handleInviteUser();
        const anchored = link;
        state.teamLog = null;
        await handleInviteUser();
        return { anchored, legacy: link, want };
    })()""", Log().genesis())
    assert result["anchored"] == f"https://sync.invalid/?invite=a%26b#g={result['want']}"
    assert result["legacy"] == "https://sync.invalid/?invite=a%26b"


def test_web_invitation_refuses_unconfirmed_log_before_issuing_token():
    result = _run("""(async () => {
        window.location = { origin: 'https://sync.invalid', pathname: '/' };
        ensureSodium = async () => sodium;
        let calls = 0, shown = false, refusal = null;
        showInviteModal = () => { shown = true; };
        t = (key, args) => args?.error || args?.reason || key;
        alert = message => { refusal = message; };
        apiFetch = async () => { calls++; return { invitation_token: 'abc' }; };
        await handleInviteUser();
        return { calls, shown, refusal };
    })()""", Log().genesis().member(B, "admin"), me=B)
    assert result["calls"] == 0
    assert result["shown"] is False
    assert "confirmed" in result["refusal"]


def test_readding_our_public_keys_does_not_make_an_attacker_genesis_trusted():
    attacker = Actor("fake-alice", 1)
    log = Log().genesis(attacker).member(B, "admin", by=attacker)
    log.add("member.role", attacker, {"user_id": attacker.uid, "role": "member"})
    log.remove(attacker, by=B).member(A, "admin", by=B)
    assert log.state is not None
    assert _run("return webTeamLogTrusted(sodium);", log, me=A) is False


def _team() -> Log:
    return Log().genesis().member(B).member(C).member(D).key(F1, 0, K[1], None) \
    .access(F1, B, "write").access(F1, C, "read")


def test_a_team_folder_is_re_keyed_to_the_logs_recipients_only():
    result = _run("""(async () => {
        const batch = await attempt();
        const after = TL.replay([...RECORDS, ...batch.team_log], sodium);
        const newDek = batch.objects.find(o => o.object_type === 'dek' && o.parent_ref === ids.F1);
        const sealedTo = batch.objects.filter(o => o.object_type === 'envelope' && !o.is_deleted &&
                                                   o.parent_ref === newDek.id);
        // Bob opens his new envelope with the key the log names for him.
        const env = sealedTo.find(o => o.target_user_id === ids.B);
        const nonce = env.payload.slice(0, sodium.crypto_box_NONCEBYTES);
        const opened = sodium.crypto_box_open_easy(env.payload.slice(nonce.length), nonce,
            sodium.crypto_scalarmult_base(state.keypair.encryptionSk), bobSk);
        return {
          types: batch.team_log.map(r => JSON.parse(r.body).type),
          current: TL.currentKey(after, ids.F1) === newDek.id,
          stale: TL.isStale(after, ids.F1),
          sealedTo: sealedTo.map(o => [o.target_user_id, o.access_level]),
          opened: opened.length,
          withdrawn: batch.objects.filter(o => o.object_type === 'envelope' && o.is_deleted).map(o => o.id).sort(),
          resealed: batch.objects.filter(o => ['node', 'entry'].includes(o.object_type)).map(o => o.id).sort(),
          legacy: batch.legacy_kept,
          askedPk,
        };
    })()""", _team())
    assert result["types"] == ["member.remove", "folder.key"]
    assert result["current"] is True and result["stale"] is False
    # Before: Dan too (his 'write' envelope) and Carol's level from the server.
    assert result["sealedTo"] == [[B.uid, "write"]]
    assert result["opened"] == 32
    # The old key's envelopes are withdrawn; the root key (outside the log) by the old rules.
    assert result["withdrawn"] == ["E_B1", "E_B8", "E_C1", "E_C8", "E_D1"]
    assert result["resealed"] == sorted([F1, ITEM, ROOT, OTHER])
    # Carol's tier-2 key below F1 is not in the log: kept and named.
    assert result["legacy"] == [K[9]]
    # Only the root key (outside the log) asks the server for a member's key.
    assert result["askedPk"] == [B.uid]


def test_a_member_without_team_folders_is_only_removed_from_the_log():
    log = Log().genesis().member(B).member(C).key(F1, 0, K[1], None).access(F1, B, "write")
    result = _run("""(async () => {
        delete state.syncObjects.E_C1; delete state.syncObjects.E_C9; delete state.syncObjects.E_C8;
        const batch = await attempt();
        return { types: batch.team_log.map(r => JSON.parse(r.body).type), objects: batch.objects.length };
    })()""", log)
    assert result == {"types": ["member.remove"], "objects": 0}


def test_a_member_already_removed_in_the_log_is_not_removed_again():
    log = _team().remove(C)
    result = _run("""(async () => {
        const batch = await attempt();
        return batch.team_log.map(r => JSON.parse(r.body).type);
    })()""", log)
    assert result == ["folder.key"]


def test_a_member_with_an_envelope_from_before_the_log_loses_the_current_key():
    """Review 1141a20 H5: Dan holds F1's current key by an envelope from
    before the log, which never gave him the folder: his member.remove marked
    nothing stale, the web left F1 out of the old path too (the log knows
    its key), and Dan kept the key new items in F1 are sealed with."""
    result = _run("""(async () => {
        const batch = await buildWebRekeyBatch(ids.D, sodium);
        const after = TL.replay([...RECORDS, ...batch.team_log], sodium);
        const newDek = batch.objects.find(o => o.object_type === 'dek' && o.parent_ref === ids.F1);
        return {
          types: batch.team_log.map(r => JSON.parse(r.body).type),
          rekeyed: TL.currentKey(after, ids.F1) !== ids.K1,
          withdrawn: batch.objects.filter(o => o.object_type === 'envelope' && o.is_deleted &&
                                                o.parent_ref === ids.K1).map(o => o.id).sort(),
          sealedTo: batch.objects.filter(o => o.object_type === 'envelope' && !o.is_deleted &&
                                              o.parent_ref === newDek?.id)
                                 .map(o => [o.target_user_id, o.access_level]).sort(),
        };
    })()""", _team())
    assert result["types"] == ["member.remove", "folder.key"]
    assert result["rekeyed"] is True
    assert result["withdrawn"] == ["E_B1", "E_C1", "E_D1"]
    assert result["sealedTo"] == sorted([[B.uid, "write"], [C.uid, "read"]])


def test_rotated_founder_can_remove_and_rekey_from_the_web():
    rotated = Actor("alice-rotated", 1)
    log = _team().rotate(A, rotated)
    result = _run("""(async () => {
        const batch = await attempt();
        const after = TL.replay([...RECORDS, ...batch.team_log], sodium);
        return { trusted: webTeamLogTrusted(sodium), active: after.members[ids.C].active,
                 keyChanged: TL.currentKey(after, ids.F1) !== ids.K1 };
    })()""", log, me=rotated)
    assert result == {"trusted": True, "active": False, "keyChanged": True}


def test_only_the_founder_with_its_current_keys_removes_members_from_the_web():
    with_admin = Log().genesis().member(B, role="admin").member(C).key(F1, 0, K[1], None).access(F1, C, "read")
    assert "only the admin who founded the team log" in _run("return await attempt();", with_admin, me=B)


def test_the_records_go_with_the_objects_or_alone():
    result = _run("""(async () => {
        const sent = [];
        apiFetch = async (url, opts) => { sent.push([url, Object.keys(opts.body).sort()]);
                                          return { accepted: (opts.body.objects || []).map(o => ({ id: o.id })) }; };
        postAtomicSyncBatch = async (objects, fields) => apiFetch('/api/sync', { body: { ...fields, objects } });
        state.keyEpoch = 3;
        const record = { body: '{}', sig: '00' };
        await pushWebRekeyBatch({ objects: [], team_log: [record] });
        await pushWebRekeyBatch({ objects: [{ id: 'X' }], team_log: [record] });
        await pushWebRekeyBatch({ objects: [{ id: 'Y' }] });  // a journal from before the log
        return sent;
    })()""", _team())
    assert result == [
        ["/api/team-log", ["records"]],
        ["/api/sync", ["key_epoch", "objects", "team_log"]],
        ["/api/sync", ["key_epoch", "objects"]],
    ]

"""Review 8bc70f7 H4 + M2, web: leaving a lost team log from the sign-in screen.

H4: a login failing on TEAM LOG MISMATCH reset the session, and "Forget the
pinned team log" was only in the vault that login never reached: a web-only
user was locked out for good. The sign-in screen now offers it after such a
failure; the next login's password authorizes it, and its queue (not loaded
by any pull yet) is checked, exported and dropped only on confirmation.

M2: offered only where the log is missing or starts anew (never for a fork or
a log that does not replay), and once a browser left a log, a server that
sends no log is a mismatch, not the rules from before any log.
"""

from __future__ import annotations

from pathlib import Path

from tests.test_review13_forget_pin_web import _run
from tests.test_review_web import _function, pytestmark  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]


def test_only_a_missing_or_new_log_offers_to_forget_it():
    result = _run("""
        // The records the server serves go with the head it announces: the
        // head alone is unsigned (goal #440).
        const attempt = async (head, local, pin, served = OLD) => {
            apiFetch = async () => ({ records: served });
            try { await syncWebTeamLog(head, local, pin, sodium); return null; }
            catch (err) { return { lost: err.teamLogLost === true, message: err.message }; }
        };
        const forked = { ...teamLogPin(old.team), hash: 'f'.repeat(64) };
        const behind = { ...teamLogPin(old.team), seq: old.team.headSeq - 1, hash: 'e'.repeat(64) };
        state.confirmedTeamGenesis = null;
        return {
            gone: await attempt(null, old, teamLogPin(old.team), []),
            reseeded: await attempt(teamLogPin(fresh), old, teamLogPin(old.team), NEW),
            forked: await attempt(forked, old, teamLogPin(old.team)),
            behind: await attempt(behind, null, teamLogPin(old.team)),
            no_head_over_the_log: await attempt(null, old, teamLogPin(old.team)),
            head_names_fresh_over_the_log: await attempt(teamLogPin(fresh), old, teamLogPin(old.team)),
        };
    """)
    assert result["gone"]["lost"] and result["reseeded"]["lost"], result
    assert "Forget the pinned team log" in result["reseeded"]["message"]
    for refused in ("forked", "behind", "no_head_over_the_log", "head_names_fresh_over_the_log"):
        assert result[refused]["message"].startswith("TEAM LOG MISMATCH"), result
        assert not result[refused]["lost"] and "Forget" not in result[refused]["message"], result


def test_after_forgetting_a_server_without_log_is_a_mismatch():
    result = _run("""
        state.confirmedTeamGenesis = null;  // only the log copy and the checkpoint pin it
        apiFetch = async () => ({ head: null, records: [] });  // the server lost the log
        const before = await syncWebTeamLog(null, null, null, sodium);
        await forgetWebTeamLogPinLocked(want.slice(0, 16), 'pw', 1, sodium);
        let after;
        try { after = await syncWebTeamLog(null, null, null, sodium); } catch (err) { after = err.message; }
        state.syncCheckpointLoaded = false;  // the next session reads it back
        state.forgottenTeamGenesis = [];
        await loadWebLocalStateLocked(1, sodium);
        return { before, after, reloaded: state.forgottenTeamGenesis };
    """)
    assert result["before"] is None
    assert result["after"].startswith("TEAM LOG MISMATCH") and "left an earlier team log" in result["after"]
    assert result["reloaded"]


def test_forgetting_at_sign_in_checks_the_queue_no_pull_loaded_yet():
    result = _run("""
        // A fresh login: the queue is only in IndexedDB. The server lost the log.
        apiFetch = async () => ({ head: null, records: [] });
        let stored = { objects: { E1: { id: 'E1', version: 2 } }, conflicts: {}, ops: [], sent: {} };
        loadWebDirtyState = async () => JSON.parse(JSON.stringify(stored));
        adoptLegacyWebRekeyJournals = async () => {};
        saveWebDirtyState = async (objects, conflicts, _s, ops) => { stored = { objects, conflicts, ops, sent: {} }; };
        state.outboxLoaded = false;
        state.outbox = {};
        // Review e443cbc H2: the forget itself asks to export and drop the
        // queue (every screen that forgets), and only for the right genesis.
        let answer = false, asked = 0, exported = [];
        window = { confirm: () => { asked++; return answer; } };
        exportWebDirtyObjects = objects => { exported.push(...objects.map(o => o.id)); };
        // Declined: nothing is dropped. A typo: the queue is never touched.
        let declined, typo;
        try { await forgetWebTeamLogPinLocked(want.slice(0, 16), 'pw', 1, sodium); } catch (err) { declined = err.message; }
        const keptPins = webPinnedTeamGenesis();
        try { await forgetWebTeamLogPinLocked('0'.repeat(16), 'pw', 1, sodium); } catch (err) { typo = err.message; }
        answer = true;
        const left = await forgetWebTeamLogPinLocked(want.slice(0, 16), 'pw', 1, sodium);
        return { keptPins, declined, typo, asked, exported, left, stored, pins: webPinnedTeamGenesis() };
    """)
    want = result["keptPins"]
    assert result["declined"] == "team.forget_unsent"
    assert result["typo"].startswith("team.forget_typed")
    assert result["asked"] == 2  # declined, then accepted; the typo never reached the question
    assert result["exported"] == ["E1"]
    assert result["left"] == want and result["pins"] == []
    assert result["stored"]["objects"] == {}


def test_the_sign_in_screen_offers_the_way_out():
    login = _function("handleLogin")
    assert login.index("getElementById('login-team-forget-genesis')") < login.index("resetSession();")
    anchor = login.index("await importAccountTeamAnchor(_sodium)")
    forget = login.index("await forgetTeamLogPinAtLogin(forgetTyped, password, loginSession, _sodium)")
    assert login.index("state.kek = kek;") < anchor < forget < login.index("await pullAndBuildTree();")
    catch = login[login.index("} catch (err) {"):]
    assert "getElementById('login-team-forget')" in catch and "err.teamLogLost" in catch
    # The field counts only after this page saw a login fail on a lost log.
    assert "state.loginTeamLogLost = !!(err.teamLogLost" in catch
    assert login.index("const forgetTyped = state.loginTeamLogLost") < login.index("resetSession();")
    at_login = _function("forgetTeamLogPinAtLogin")
    assert "window.confirm(t('team.forget_confirm'))" in at_login
    # Review e443cbc H2: the export and drop live in the forget itself, so the
    # vault's Team trust forget has them too.
    assert "forgetWebTeamLogPinLocked(typed, password, session, _sodium)" in at_login
    forget_locked = _function("forgetWebTeamLogPinLocked")
    assert forget_locked.index("exportWebDirtyObjects(objects)") < forget_locked.index("saveWebDirtyState(")
    index = (ROOT / "web/templates/index.html").read_text(encoding="utf-8")
    form = index[index.index('<form id="login-form"'):index.index("</form>", index.index('<form id="login-form"'))]
    assert 'id="login-team-forget"' in form and 'id="login-team-forget-genesis"' in form

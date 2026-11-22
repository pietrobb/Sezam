"""Review 1141a20 (R9-E, goal #361), web: a server restored from a backup lost
team-log records this browser accepted. The browser puts them back onto the
server's prefix of its copy; a fork, another genesis or a refused upload stays
TEAM LOG MISMATCH.
"""

from __future__ import annotations

from tests.team_log_vectors import B, C, D, F1, K, Log
from tests.test_review_web import pytestmark  # noqa: F401
from tests.test_team_log_web_pull import _run

SERVER = """
    const posted = [];
    let refuse = false;
    let serverRecords = SERVED.slice();
    apiFetch = async (url, opts) => {
        if (opts && opts.method === 'POST') {
            posted.push({ url, n: opts.body.records.length, first: opts.body.records[0] });
            if (refuse) { const err = new Error('400 refused'); err.status = 400; throw err; }
            serverRecords = serverRecords.concat(opts.body.records);
            return { records: [], head: head(serverRecords) };
        }
        const since = Number(/since=(-?\\d+)/.exec(url)[1]);
        return { records: serverRecords.slice(since + 1, since + 3) };
    };
    const local = { records: RECORDS, team: teamOf(RECORDS) };
    const announced = SERVED.length ? head(SERVED) : null;
    const attempt = async () => {
        try { const got = await syncWebTeamLog(announced, local, null, sodium); return { seq: got.team.headSeq }; }
        catch (err) { return { error: err.message }; }
    };
"""

LOG = Log().genesis().member(B).member(C).key(F1, 0, K[1], None).access(F1, B, "write")


def _restore(script: str, served: Log, log: Log = LOG):
    return _run("(async () => {" + SERVER + script + "})()", log, served=served)


def _prefix(n: int) -> Log:
    served = Log()
    served.records = LOG.records[:n]
    return served


def test_the_browser_puts_back_what_a_restored_server_lost():
    result = _restore("const got = await attempt(); return { ...got, posted };", _prefix(2))
    assert result["seq"] == 4, result
    assert [p["n"] for p in result["posted"]] == [3]
    assert result["posted"][0]["url"] == "/api/team-log/restore"
    assert result["posted"][0]["first"] == LOG.records[2]


def test_a_server_without_any_log_gets_the_whole_log_back():
    result = _restore("const got = await attempt(); return { ...got, posted };", Log())
    assert result["seq"] == 4, result
    assert [p["n"] for p in result["posted"]] == [5]


def test_a_forked_or_other_genesis_server_log_is_never_built_on():
    forked = Log().genesis().member(B).member(D)
    result = _restore("const got = await attempt(); return { ...got, posted };", forked)
    assert "went back (head 2 < 4)" in result["error"] and result["posted"] == []
    other = Log().genesis(D)
    result = _restore("const got = await attempt(); return { ...got, posted };", other)
    assert "another genesis" in result["error"] and result["posted"] == []


def test_a_fork_of_this_accounts_own_records_is_followed_once_nothing_is_lost():
    """Goal #442: another device of this account put back a shorter copy and
    then made the lost changes again. Before they are back the fork stays
    'went back'; once each is on the server's side it is followed; a fork
    with a record of another account never is."""
    own = "state.userId = ids.A; const got = await attempt(); return { ...got, posted };"
    shorter = Log().genesis().member(B).member(D)
    assert "went back (head 2 < 4)" in _restore(own, shorter)["error"]
    again = Log().genesis().member(B).member(D).member(C).key(F1, 0, K[1], None).access(F1, B, "write")
    result = _restore(own, again)
    assert result == {"seq": 5, "posted": []}, result
    other = Log().genesis().member(B).rotate(B, D).member(C).key(F1, 0, K[1], None).access(F1, B, "write")
    assert "does not replay" in _restore(own, other)["error"]


def test_a_refused_upload_stays_a_mismatch():
    result = _restore("refuse = true; const got = await attempt(); return { ...got, posted };", _prefix(2))
    assert result["error"].startswith("TEAM LOG MISMATCH") and "went back" in result["error"]
    assert len(result["posted"]) == 1

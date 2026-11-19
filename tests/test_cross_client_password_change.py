"""Lockout review L8: password changed on client A, then sign-in on client B.

X1: desktop A changes the password, web B logs in. X2: web A changes it (org
recovery with a new password, the web's only password change), desktop B
takes it over. X3: desktop or web A changes it, mobile B (the real Dart
AuthService/SyncService/VaultService under `flutter test`) takes it over;
the phone itself never changes the password. Then a new phone joins an
account another client made, by its password only.

The unmodified web client (all of web/static/js/app.js, its real handlers)
runs in node against the real server under uvicorn that the desktop client
(CLI connect flow, Vault, SyncClient) talks to. Only the browser around
app.js is simulated: an in-memory IndexedDB that persists between sessions
like a real browser profile, a DOM of plain elements, and the Argon2 Web
Worker (node's Argon2id with the same parameters).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from sezam import cli
from sezam.vault.crud import Vault
from sezam.vault.sync_client import KeyEpochStale
from tests.test_integration_client_server import (  # noqa: F401  (fixture)
    NEW_PASSWORD,
    PASSWORD,
    _client,
    _entry_value,
    _vault,
    server,
)
from tests.test_review_web import ROOT, VENDOR, pytestmark  # noqa: F401
from tests.web_browser import BROWSER_ACTIONS, BROWSER_PRELUDE
from tests.node_support import node_cmd

APP_JS = ROOT / "web" / "static" / "js" / "app.js"

BROWSER = BROWSER_PRELUDE + BROWSER_ACTIONS + r"""
let finished = false;
let currentStep = null;
process.on('beforeExit', () => {
  if (finished) return;
  console.error(`event loop drained during step ${currentStep}: a promise never settled`);
  process.exitCode = 1;
});

(async () => {
  await context.sodium.ready;
  let error = null;
  for (const step of input.steps) {
    currentStep = step.action;
    dropKeyRotation = !!step.drop_key_rotation;
    error = await actions[step.action](step);
    if (!error.classList.contains('hidden')) break;
  }
  const result = vm.runInContext(`({
    token: state.token, userId: state.userId, keyEpoch: state.keyEpoch,
    unlocked: !!state.kek,
    nodes: state.allNodes.map(n => ({
      id: n.id, name: n.name, parent_ref: n.parent_ref || null, dekId: n.dekId || null,
      personal: !!n.personal, undecryptable: !!n._undecryptable,
    })),
    entries: state.allEntries.map(e => ({
      id: e.id, parent_ref: e.parent_ref || null, dekId: e.dekId || null,
      name: e.name, undecryptable: !!e._undecryptable,
      password: ((e.fields || []).find(f => f.key === 'password') || {}).value ?? null,
    })),
  })`, context);
  result.error = error.classList.contains('hidden') ? null : error.textContent;
  result.shares = shares;
  result.alerts = alerts;
  result.calls = calls;
  result.idb = Object.fromEntries(Object.entries(stores).map(([name, rows]) => [
    name, [...rows.entries()].map(([key, value]) => ({ [keyPaths[name]]: key, __json: pack(value) })),
  ]));
  finished = true;
  console.log(JSON.stringify(result));
})().catch(err => { console.error(err); process.exit(1); });
"""


def _web(origin: str, browser: dict, *steps: dict) -> dict:
    """One browser session doing ``steps``; ``browser`` is its IndexedDB, updated in place."""
    payload = json.dumps({"origin": origin, "idb": browser.get("idb", {}), "steps": list(steps)})
    out = subprocess.run(
        [
            node_cmd(), "-e", BROWSER,
            str(VENDOR / "libsodium-sumo.min.js"),
            str(VENDOR / "libsodium-wrappers.min.js"),
            str(APP_JS),
            base64.b64encode(payload.encode()).decode(),
        ],
        capture_output=True, text=True, timeout=120,
    )
    assert out.returncode == 0, out.stderr
    result = json.loads(out.stdout.strip().splitlines()[-1])
    browser["idb"] = result.pop("idb")
    return result


def _web_login(origin: str, username: str, password: str, browser: dict) -> dict:
    return _web(origin, browser, {"action": "login", "username": username, "password": password})


def _cached_keypair(browser: dict) -> dict | None:
    for row in browser["idb"]["keys"]:
        if row["id"] == "keypair":
            return json.loads(row["__json"])
    return None


# The web asks a new password to meet its policy (length, cases, a symbol).
WEB_PASSWORD = "Recovered-On-Web-2026!"


def _passwords(result: dict) -> dict:
    return {e["name"]: e["password"] for e in result["entries"] if not e["undecryptable"]}


def _paths(result: dict) -> list[str]:
    return [c["path"] for c in result["calls"]]


def test_password_changed_on_desktop_then_web_login(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    user_id = laptop.db.get_meta("user_id")

    # Browser B signs in once before the change: its IndexedDB now caches
    # the keypair under the old KEK, plus a checkpoint sealed with it.
    browser: dict = {}
    before = _web_login(url, "admin", PASSWORD, browser)
    assert before["error"] is None, before
    assert before["userId"] == user_id
    assert _passwords(before)["db01"] == "s3cret"
    stale_cache = _cached_keypair(browser)
    assert stale_cache and stale_cache["user_id"] == user_id

    # Desktop A changes the password and keeps working under the new one.
    proof = laptop.change_password(PASSWORD, NEW_PASSWORD)
    proof[:] = b"\x00" * len(proof)
    laptop.unlock(NEW_PASSWORD)
    _client(laptop, url).push()
    folder = next(n["id"] for n in laptop.list_nodes() if n["name"] == "Servers")
    laptop.create_entry(folder, "web", [{"key": "password", "value": "after", "sensitive": True}])
    assert _client(laptop, url).push()["accepted"]
    server_wrap = bytes(next(u for u in db._storage["users"] if u["id"] == user_id)["encrypted_keypair"]).hex()
    assert server_wrap != stale_cache["encrypted_keypair"]

    # The old password is a wrong password (the desktop also changed the
    # salt, so it no longer opens B's stale cache): the server refuses its
    # proof, no session, nothing pulled, the cache stays as it was.
    old = _web_login(url, "admin", PASSWORD, browser)
    assert old["error"] == "error.wrong_password", old
    assert old["token"] is None and not old["unlocked"] and old["entries"] == []
    assert "/api/sync" not in _paths(old) and "/api/auth/verify" not in _paths(old)
    assert any(c["path"] == "/api/auth/recover" and c["status"] == 401 for c in old["calls"])
    assert _cached_keypair(browser) == stale_cache

    # The new password signs in, replaces the cache with the account's
    # current wrap and reads A's records, old and new.
    new = _web_login(url, "admin", NEW_PASSWORD, browser)
    assert new["error"] is None, new
    assert new["token"] and new["userId"] == user_id and new["keyEpoch"] == 1
    assert not any(e["undecryptable"] for e in new["entries"]), new["entries"]
    assert _passwords(new) == {"db01": "s3cret", "web": "after"}
    assert _cached_keypair(browser) == {"id": "keypair", "encrypted_keypair": server_wrap, "user_id": user_id}

    # From now on the old password fails against the replaced cache too,
    # and the new one keeps working from it.
    again_old = _web_login(url, "admin", PASSWORD, browser)
    assert again_old["error"] == "error.wrong_password", again_old
    assert again_old["token"] is None and "/api/sync" not in _paths(again_old)
    again_new = _web_login(url, "admin", NEW_PASSWORD, browser)
    assert again_new["error"] is None, again_new
    assert _passwords(again_new) == {"db01": "s3cret", "web": "after"}
    assert "/api/auth/recover" not in _paths(again_new)
    laptop.lock()


def test_password_changed_on_web_then_desktop_takes_it_over(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    user_id = laptop.db.get_meta("user_id")

    # Web A: the admin sets up org recovery, then (another session) recovers
    # the account with the shares and a new password.
    browser: dict = {}
    setup = _web(
        url, browser,
        {"action": "login", "username": "admin", "password": PASSWORD},
        {"action": "org_recovery_setup", "threshold": 2, "total_shares": 3, "password": PASSWORD},
    )
    assert setup["error"] is None, setup
    assert len(setup["shares"]) == 3
    recovered = _web(url, browser, {
        "action": "org_recovery", "shares": setup["shares"][:2], "total_shares": 3,
        "password": WEB_PASSWORD,
    })
    assert recovered["error"] is None, recovered
    assert recovered["alerts"] == ["recovery.success"]
    assert recovered["keyEpoch"] == 1
    assert _passwords(recovered) == {"db01": "s3cret"}
    epoch = next(s for s in db._storage["sync_state"] if s["user_id"] == user_id)["key_epoch"]
    assert epoch == 1

    # Desktop B, still on the old password: sync stops with "key epoch is
    # stale" until it takes the password changed elsewhere over.
    client = _client(laptop, url)
    with pytest.raises(KeyEpochStale):
        client.pull()
    with pytest.raises(RuntimeError, match="Wrong current account password"):
        client.adopt_rotated_key_material(laptop, PASSWORD)
    assert laptop.db.get_meta("key_epoch") == "0"
    assert client.adopt_rotated_key_material(laptop, WEB_PASSWORD) == 1
    client.pull()
    assert _entry_value(laptop, "Servers", "db01", "password") == "s3cret"
    folder = next(n["id"] for n in laptop.list_nodes() if n["name"] == "Servers")
    laptop.create_entry(folder, "desk", [{"key": "password", "value": "after", "sensitive": True}])
    pushed = client.push()
    assert pushed["accepted"] and not pushed["conflicts"]

    # The desktop vault opens with the new account password only.
    laptop.lock()
    reopened = Vault(tmp_path / "laptop")
    with pytest.raises(ValueError):
        reopened.unlock(PASSWORD)
    reopened.unlock(WEB_PASSWORD)
    assert _entry_value(reopened, "Servers", "desk", "password") == "after"
    reopened.lock()

    # A new desktop device: the old password is refused, the new one reads it all.
    with pytest.raises(Exception):
        cli._server_connect_flow(url, _vault(tmp_path / "old-pw", "admin"), PASSWORD)
    fresh = _vault(tmp_path / "fresh", "admin")
    cli._server_connect_flow(url, fresh, WEB_PASSWORD)
    assert fresh.db.get_meta("user_id") == user_id
    assert _entry_value(fresh, "Servers", "db01", "password") == "s3cret"
    assert _entry_value(fresh, "Servers", "desk", "password") == "after"
    fresh.lock()

    # And web A signs in with the new password and sees the desktop's record.
    web = _web_login(url, "admin", WEB_PASSWORD, browser)
    assert web["error"] is None, web
    assert _passwords(web) == {"db01": "s3cret", "desk": "after"}


def test_interrupted_web_org_recovery_finishes_at_the_next_login(server, tmp_path):  # noqa: F811
    """Review 688edcb K1, capability run 79.

    The org recovery's rotation push is lost after the journal was saved. The
    next login with the new password replays the journal; the server takes the
    new password only on proof of the recovery key (the first challenge is
    spent and the old password is forgotten). Before, the replay carried no
    proof: 403, the server kept the old password and the login failed.
    """
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    laptop.lock()
    user_id = next(u["id"] for u in db._storage["users"] if u["username"] == "admin")

    def epoch():
        return next(s for s in db._storage["sync_state"] if s["user_id"] == user_id)["key_epoch"]

    browser: dict = {}
    setup = _web(
        url, browser,
        {"action": "login", "username": "admin", "password": PASSWORD},
        {"action": "org_recovery_setup", "threshold": 2, "total_shares": 3, "password": PASSWORD},
    )
    assert setup["error"] is None, setup
    interrupted = _web(url, browser, {
        "action": "org_recovery", "shares": setup["shares"][:2], "total_shares": 3,
        "password": WEB_PASSWORD, "drop_key_rotation": True,
    })
    assert interrupted["error"] is not None
    assert epoch() == 0
    assert any(row["id"] == "pending_kek_rotation:admin" for row in browser["idb"]["keys"])

    web = _web_login(url, "admin", WEB_PASSWORD, browser)
    assert web["error"] is None, web
    assert epoch() == 1
    assert _passwords(web) == {"db01": "s3cret"}
    assert not any(row["id"] == "pending_kek_rotation:admin" for row in browser["idb"]["keys"])

    # The server took the new password: a new device gets in with it, not the old one.
    with pytest.raises(Exception):
        cli._server_connect_flow(url, _vault(tmp_path / "old-pw", "admin"), PASSWORD)
    fresh = _vault(tmp_path / "fresh", "admin")
    cli._server_connect_flow(url, fresh, WEB_PASSWORD)
    assert _entry_value(fresh, "Servers", "db01", "password") == "s3cret"
    fresh.lock()


MOBILE = ROOT / "mobile"
PHONE_TEST = "test/cross_client_password_change_test.dart"


@contextmanager
def _mobile_build_lock():
    """One 'flutter test' at a time in this mobile/ (pytest -n workers): two at
    once build into the same mobile/build and failed copying sqlite3.dll there
    (PathExistsException, errno 183)."""
    name = hashlib.sha256(str(MOBILE.resolve()).encode()).hexdigest()[:16]
    with open(Path(tempfile.gettempdir()) / f"sezam-flutter-{name}.lock", "a+b") as fh:
        if os.name == "nt":
            import msvcrt

            fh.seek(0)
            while True:
                try:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)  # gives up after 10 s
                    break
                except OSError:
                    continue
            try:
                yield
            finally:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)


def _phone(url: str, tmp_path, cfg: dict, steps: dict, test_file: str = PHONE_TEST) -> str:
    """Phone B: ``test_file`` (a test under mobile/) run by ``flutter test``
    against ``url``. When B reaches a step it waits until ``steps[name]()``
    (A's part) has run. Returns its output."""
    flutter = shutil.which("flutter")
    if flutter is None:
        if os.environ.get("SEZAM_REQUIRE_FLUTTER") == "1":  # CI: X3 must run
            pytest.fail("flutter is not installed but SEZAM_REQUIRE_FLUTTER=1")
        pytest.skip("flutter is not installed")
    work = tmp_path / "phone"
    (work / "app").mkdir(parents=True)
    (work / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    log = work / "flutter.log"
    env = {**os.environ, "SEZAM_X3_SERVER": url, "SEZAM_X3_DIR": str(work)}
    with _mobile_build_lock(), open(log, "w", encoding="utf-8") as out:
        proc = subprocess.Popen(
            # expanded: under GITHUB_ACTIONS flutter defaults to the github reporter
            [flutter, "test", "--reporter", "expanded", test_file], cwd=MOBILE, env=env,
            stdout=out, stderr=subprocess.STDOUT, start_new_session=os.name != "nt",
        )
        try:
            for name, step in steps.items():
                deadline = time.monotonic() + 300
                while not (work / f"{name}.ready").exists():
                    assert proc.poll() is None, log.read_text(encoding="utf-8", errors="replace")
                    assert time.monotonic() < deadline, f"the phone never reached {name}"
                    time.sleep(0.1)
                step()
                (work / f"{name}.done").write_text("", encoding="utf-8")
            proc.wait(timeout=300)
        finally:
            if proc.poll() is None:  # the flutter wrapper: end its dart children too
                if os.name == "nt":
                    subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
                else:
                    os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=30)
    output = log.read_text(encoding="utf-8", errors="replace")
    assert proc.returncode == 0, output
    assert "All tests passed" in output and "Skip" not in output, output
    return output


@pytest.mark.parametrize("changer", ["desktop", "web"])
def test_password_changed_on_desktop_or_web_then_phone_takes_it_over(
    server, tmp_path, changer,  # noqa: F811
):
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    browser: dict = {}
    setup: dict = {}

    def joined():
        # The phone set the server up; desktop A joins the same account
        # (password recovery of its keypair) and writes a record.
        cli._server_connect_flow(url, laptop, PASSWORD)
        folder = laptop.create_node("Servers")
        laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
        assert _client(laptop, url).push()["accepted"]
        if changer == "web":
            setup.update(_web(
                url, browser,
                {"action": "login", "username": "admin", "password": PASSWORD},
                {"action": "org_recovery_setup", "threshold": 2, "total_shares": 3, "password": PASSWORD},
            ))
            assert setup["error"] is None, setup

    if changer == "desktop":
        new_password = NEW_PASSWORD
        after = {"db01": "s3cret", "desk": "after"}

        def changed():
            proof = laptop.change_password(PASSWORD, NEW_PASSWORD)
            proof[:] = b"\x00" * len(proof)
            laptop.unlock(NEW_PASSWORD)
            _client(laptop, url).push()
            node = next(n["id"] for n in laptop.list_nodes() if n["name"] == "Servers")
            laptop.create_entry(node, "desk", [{"key": "password", "value": "after", "sensitive": True}])
            assert _client(laptop, url).push()["accepted"]
    else:
        new_password = WEB_PASSWORD
        after = {"db01": "s3cret"}

        def changed():
            recovered = _web(url, browser, {
                "action": "org_recovery", "shares": setup["shares"][:2], "total_shares": 3,
                "password": WEB_PASSWORD,
            })
            assert recovered["error"] is None, recovered
            assert recovered["keyEpoch"] == 1

    _phone(url, tmp_path, {
        "username": "admin", "old_password": PASSWORD, "new_password": new_password,
        "before": {"db01": "s3cret"}, "after": after,
    }, {"joined": joined, "changed": changed})

    user_id = laptop.db.get_meta("user_id")
    epoch = next(s for s in db._storage["sync_state"] if s["user_id"] == user_id)["key_epoch"]
    assert epoch == 1  # the phone took the change over, it did not make one
    # A sees the record the phone wrote under the new password.
    if changer == "desktop":
        _client(laptop, url).pull()
        assert _entry_value(laptop, "Servers", "phone", "password") == "from-phone"
    else:
        web = _web_login(url, "admin", WEB_PASSWORD, browser)
        assert web["error"] is None, web
        assert _passwords(web) == {"db01": "s3cret", "phone": "from-phone"}
    laptop.lock()


JOIN_TEST = "test/phone_joins_account_test.dart"


@pytest.mark.parametrize("scenario", ["empty", "local"])
def test_new_phone_joins_an_existing_account_by_password(server, tmp_path, scenario):  # noqa: F811
    """Desktop A made the account; phone B joins it with the password alone.
    "empty": a new phone without a vault. "local": a phone that already
    keeps entries offline; they move into the account (a failure halfway
    leaves the phone as it was). Before, B was sent to ask for an invitation
    (connectToServer) or failed on 'Local KEK id is missing' (recovery)."""
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    laptop.create_entry(folder, "db01", [{"key": "password", "value": "s3cret", "sensitive": True}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    user_id = laptop.db.get_meta("user_id")

    _phone(url, tmp_path, {
        "scenario": scenario, "username": "admin", "password": PASSWORD,
        "local_password": "phone-only-Pw-1234", "account": {"db01": "s3cret"},
    }, {}, test_file=JOIN_TEST)

    assert [u["id"] for u in db._storage["users"]] == [user_id]  # no second account
    _client(laptop, url).pull()
    if scenario == "local":
        assert _entry_value(laptop, "Mine", "offline", "password") == "o1"
        # Review 688edcb: the carried copy keeps what the phone's model does
        # not know - tier 2 (own DEK), creation time, AI policy.
        mine = next(n for n in laptop.list_nodes() if n["name"] == "Mine")
        tiered = next(e for e in laptop.list_entries(mine["id"]) if e["name"] == "tiered")
        tiered = laptop.read_entry(tiered["id"])
        assert tiered["tier"] == 2
        assert tiered["created_at"] == 1700000000000
        assert (tiered["ai_read_secret"], tiered["allowed_actions"]) == (False, ["connect"])
        assert tiered["max_session_minutes"] == 15
        assert tiered["fields"][0]["value"] == "t2"
        dek_id = laptop.db.fetchone("SELECT dek_id FROM entries WHERE id = ?", (tiered["id"],))[0]
        assert dek_id != laptop.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (mine["id"],))[0]
    laptop.lock()

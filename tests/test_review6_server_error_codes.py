"""Review d615826 R6-H: the client decides on the server's error code, not its wording.

The desktop client told "stale key epoch", "history changed", "token revoked"
and the other refusals apart by looking for words in the exception text
("409" in str(exc) and "Stale key epoch" in str(exc)). Rewording a server
message, or a message that merely mentions such words, changed what the client
did. The server now answers {"detail": ..., "code": ...} with a stable code
(server/app/errors.py) and the client reads ServerError.status / .code.
"""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.request

import pytest

from server.app import errors as server_errors
from sezam import cli
from sezam.vault import sync_common
from sezam.vault.sync_client import KeyEpochStale, ServerError
from sezam.vault.sync_common import server_error
from tests.test_integration_client_server import (
    PASSWORD,
    _client,
    _vault,
    server,  # noqa: F401  (fixture)
)
from tests.test_review2_rotation_server import _auth, _dek, _seeded
from tests.test_server_spec import app_client, mock_db  # noqa: F401  (fixtures)


def test_client_knows_every_server_code():
    client_codes = {
        value for name, value in vars(sync_common).items()
        if name.isupper() and isinstance(value, str) and value in server_errors.ERROR_CODES
    }
    assert client_codes == set(server_errors.ERROR_CODES)
    for name in vars(server_errors):
        if name.isupper() and name != "ERROR_CODES":
            assert getattr(sync_common, name) == getattr(server_errors, name)


def test_server_error_reads_status_and_code():
    body = json.dumps({"detail": "Stale key epoch, wording of the day", "code": "history_changed"})
    exc = ServerError(409, body)
    assert str(exc) == f"Server error 409: {body}"
    assert (exc.status, exc.code, exc.detail) == (409, "history_changed", exc.detail)
    # The words in the text do not decide; the code does.
    assert not server_error(exc, 409, sync_common.STALE_KEY_EPOCH)
    assert server_error(exc, 409, sync_common.HISTORY_CHANGED)
    # A wrapped refusal is still recognised through its cause.
    try:
        try:
            raise exc
        except ServerError as inner:
            raise RuntimeError(f"{inner}. hint") from inner
    except RuntimeError as outer:
        assert server_error(outer, 409, sync_common.HISTORY_CHANGED)
    assert not server_error(RuntimeError("Server error 409: Stale key epoch"), 409)
    # The CLI and the connect dialog show the detail, as before.
    shown = ServerError(403, json.dumps({"detail": "nope", "code": "x"}), show_detail=True)
    assert str(shown) == "Server error 403: nope"
    assert str(ServerError(502, "<html>", show_detail=True)) == "Server error 502: <html>"


@pytest.mark.asyncio
async def test_server_answers_carry_codes(app_client, mock_db):  # noqa: F811
    sk, token = await _seeded(app_client, mock_db)

    missing = await app_client.post("/api/sync", json={
        "objects": [], "atomic_batch": True, "key_epoch": 1,
    }, headers=_auth(token))
    assert missing.status_code == 409
    assert missing.json()["code"] == server_errors.KEY_CHANGE_MISSES_DEKS

    conflict = await app_client.post("/api/sync", json={
        "objects": [_dek(sk, 1, b"another payload at version 1")], "atomic_batch": True,
    }, headers=_auth(token))
    assert conflict.status_code == 409
    assert conflict.json()["code"] == server_errors.ATOMIC_BATCH_CONFLICT
    assert conflict.json()["detail"]["message"] == "Atomic batch conflict"

    bad = await app_client.get("/api/sync", headers=_auth("not-a-token"))
    assert bad.status_code == 401
    assert bad.json()["code"] == server_errors.TOKEN_INVALID


def _reword_server_errors(monkeypatch) -> list[str]:
    """Every refusal reaches the client with the same code but other words."""
    seen: list[str] = []
    real = urllib.request.urlopen

    def urlopen(req, *args, **kwargs):
        try:
            return real(req, *args, **kwargs)
        except urllib.error.HTTPError as exc:
            answer = json.loads(exc.read().decode("utf-8"))
            if answer.get("code"):
                seen.append(answer["code"])
            answer["detail"] = "refused (reworded)"
            raise urllib.error.HTTPError(
                exc.url, exc.code, exc.msg, exc.headers,
                io.BytesIO(json.dumps(answer).encode("utf-8")),
            ) from None

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    return seen


def test_desktop_follows_codes_when_the_wording_changes(server, tmp_path, monkeypatch):  # noqa: F811
    url, _db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    laptop.create_node("F")
    cli._server_connect_flow(url, laptop, PASSWORD)
    phone = _vault(tmp_path / "phone", "admin")
    cli._server_connect_flow(url, phone, PASSWORD)
    phone_client = _client(phone, url)
    phone.create_node("before")
    assert not phone_client.push()["conflicts"]  # the phone holds a session

    _client(laptop, url).pull()
    laptop.change_password(PASSWORD, PASSWORD)
    assert not _client(laptop, url).push()["conflicts"]

    seen = _reword_server_errors(monkeypatch)
    phone.create_node("after")
    # The password change ended the phone's session (token_revoked: log in
    # again) and its push is at the old key epoch (stale_key_epoch).
    with pytest.raises(KeyEpochStale):
        phone_client.push()
    assert server_errors.TOKEN_REVOKED in seen
    phone.lock()
    laptop.lock()

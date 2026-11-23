"""Review 18c300f R16-M2: an app that names its base by version only got
'conflict' on every push.

The public release d14d368 sends a folder or entry change with base_version
and, when it knows it, base_payload_hash. After "keep mine" it knows only the
version (resolve_conflict sets object_base_version; the hash of the server's
copy was never stored). The server takes a change of an existing folder or
entry only when it names both (docs/SYNC_SINGLE_SOURCE.md point 1), so it
answered 'conflict', the old app pulled the same copy, the user kept theirs
again, and the change never went through. The server now answers 426: that
app version must be updated. Current clients always send the pair (desktop
_stamp_base_versions, mobile base_version/base_hash, web webBase).

The request below is the d14d368 one (its sync_state._stamp_base_versions:
base_version without base_payload_hash); the red run with the real d14d368
client is in %TEMP%\\r16_M2_red.log.
"""

from __future__ import annotations

import copy

from sezam import cli
from sezam.vault.sync_common import ServerError
from tests.test_integration_client_server import PASSWORD, _client, _vault, server  # noqa: F401


def test_a_change_naming_its_base_by_version_only_gets_426(server, tmp_path):  # noqa: F811
    url, db = server
    laptop = _vault(tmp_path / "laptop", "admin")
    folder = laptop.create_node("Servers")
    entry_id = laptop.create_entry(folder, "db01", [{"key": "password", "value": "one"}])
    cli._server_connect_flow(url, laptop, PASSWORD)
    laptop.update_entry(entry_id, fields=[{"key": "password", "value": "two"}])

    client = _client(laptop, url)
    real = client._request
    old_answers = []

    def as_d14d368_too(method, path, body=None, **kw):
        if path == "/api/sync" and body and any(
            o.get("id") == entry_id for o in body.get("objects", [])
        ):
            old = copy.deepcopy(body)
            for obj in old["objects"]:
                if obj["object_type"] in ("node", "entry"):
                    obj.pop("base_payload_hash", None)
            try:
                old_answers.append(real(method, path, old, **kw))
            except ServerError as exc:
                old_answers.append(exc.status)
        return real(method, path, body, **kw)

    client._request = as_d14d368_too
    client.push()

    assert old_answers == [426]
    # The current client's change (base version and hash) went through.
    stored = next(o for o in db._storage["vault_objects"] if o["id"] == entry_id)
    assert stored["version"] == laptop.db.fetchone(
        "SELECT version FROM entries WHERE id = ?", (entry_id,)
    )["version"]

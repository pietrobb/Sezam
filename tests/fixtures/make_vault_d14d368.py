"""Make tests/fixtures/vault_d14d368/ with the code of d14d368 (the public release).

Not a test: run it from a checkout of d14d368, so the vault is written by that
version's own schema, triggers and sync code (review 782dde8 R12 #1: a vault
the test suite assembled by hand opened, a real one did not):

    git worktree add ../sz-d14 d14d368
    cd ../sz-d14
    set PYTHONPATH=%CD%\\src
    python <this repo>/tests/fixtures/make_vault_d14d368.py <this repo>/tests/fixtures/vault_d14d368

The vault holds a folder and an entry the server took, then unsent changes:
an edited entry and a renamed folder (each on a known server base), and a
folder never sent. expected.json names what the current version must see.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import sys
from pathlib import Path

from sezam import cli
from tests.test_integration_client_server import PASSWORD, _client, _vault, server


def main(out: Path) -> None:
    tmp = out.parent / "_make_tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    fixture = server.__wrapped__(tmp) if hasattr(server, "__wrapped__") else server(tmp)
    url, _db = next(fixture)
    try:
        vault = _vault(tmp / "laptop", "admin")
        cli._server_connect_flow(url, vault, PASSWORD)
        servers = vault.create_node("Servers")
        other = vault.create_node("Other")
        entry = vault.create_entry(servers, "db01", [{"key": "password", "value": "v1"}])
        _client(vault, url).push()

        vault.update_entry(entry, fields=[{"key": "password", "value": "v2 unsent"}])
        vault.rename_node(other, "Other, unsent")
        fresh = vault.create_node("Never sent")
        db = vault.db

        def base(object_id: str):
            version = db.fetchone(
                "SELECT version FROM object_base_version WHERE object_id = ?", (object_id,)
            )
            digest = db.fetchone(
                "SELECT version, payload_hash FROM object_base_hash WHERE object_id = ?",
                (object_id,),
            )
            v = None if version is None else version["version"]
            h = digest["payload_hash"] if digest is not None and digest["version"] == v else None
            return [v, h]

        expected = {
            "password": PASSWORD,
            "root": db.get_meta("root_node_id"),
            "servers": servers,
            "other": other,
            "entry": entry,
            "fresh": fresh,
            "base": {i: base(i) for i in (servers, other, entry, fresh)},
            "dirty": sorted(
                r["id"]
                for t in ("nodes", "entries")
                for r in db.fetchall(f"SELECT id FROM {t} WHERE is_dirty = 1")
            ),
        }
        vault.lock()
    finally:
        try:
            next(fixture)
        except StopIteration:
            pass

    path = tmp / "laptop" / "sezam.db"
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.close()
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    shutil.copy2(path, out / "sezam.db")
    (out / "expected.json").write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())

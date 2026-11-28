"""The shared authority vectors (tests/vectors/authority.json) on every side:
which pulled folders and items a client does not apply, the key a header
names and the log's admins (core/src/authority.rs, docs/CORE_UNIFICATION.md
U5). core/tests/authority_vectors.rs runs them in the core itself.
"""

from __future__ import annotations

import base64
import json
import sqlite3
from pathlib import Path

from tests.test_review_web import _function, _run_source, pytestmark  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads((ROOT / "tests" / "vectors" / "authority.json").read_text(encoding="utf-8"))
TEAM_LOG = json.loads((ROOT / "tests" / "vectors" / "team_log.json").read_text(encoding="utf-8"))
SCENARIOS = ("second_admin_removes_founder", "org_recovery_wrap", "handover_on_ends_the_role_keys")
TEAMLOG_JS = (ROOT / "web" / "static" / "js" / "teamlog.js").read_text(encoding="utf-8")


def _records() -> list[list[dict]]:
    scenarios = {s["name"]: s for s in TEAM_LOG["scenarios"]}
    return [scenarios[name]["records"] for name in SCENARIOS]


def _with_payloads(objects: list[dict] | None) -> list[dict] | None:
    if objects is None:
        return None
    return [{**o, "payload": base64.b64encode(bytes.fromhex(o["head"])).decode()} for o in objects]


def test_the_web_gives_the_vectors_answers():
    cases = [{**c, "objects": _with_payloads(c["objects"]), "previous": _with_payloads(c["previous"])}
             for c in VECTORS["cases"]]
    result = _run_source(
        TEAMLOG_JS + "\n" + "\n".join(_function(n) for n in (
            "sealingDekId", "authorityObjects", "unauthorizedWrites", "webLogAdmins")),
        f"""(() => {{
          const teams = {json.dumps(_records())}.map(records => ({{ records, team: SezamTeamLog.replay(records, sodium) }}));
          const map = list => list === null ? null : Object.fromEntries(list.map(o => [o.id, o]));
          return {json.dumps(cases)}.map(c => {{
            const log = c.team === null ? null : teams[c.team];
            const blocked = unauthorizedWrites(map(c.objects), c.own_user_id, log ? log.team : null,
              map(c.previous), c.team_admins ? new Set(c.team_admins) : null);
            return {{
              blocked: [...blocked], by_team_log: [...blocked.byTeamLog].sort(),
              dek_ids: Object.fromEntries(c.objects.map(o => [o.id + '/' + o.object_type, sealingDekId(o)])),
              team_admins: log && c.team_admins ? [...webLogAdmins(log)].sort() : null,
            }};
          }});
        }})()""",
    )
    for case, got in zip(VECTORS["cases"], result):
        assert got["dek_ids"] == case["dek_ids"], case["name"]
        assert got["blocked"] == case["blocked"], case["name"]
        assert got["by_team_log"] == case["by_team_log"], case["name"]
        assert got["team_admins"] == case["team_admins"], case["name"]
    assert len(result) == len(VECTORS["cases"])


class _LogRows:
    def __init__(self, records: list[dict]):
        self.rows = [{"body": r["body"]} for r in records]

    def fetchall(self, _sql, _params=()):
        return self.rows


def test_the_desktop_names_the_vectors_log_admins():
    from sezam import teamlog
    from sezam.vault.team_log_state import log_admins

    records = _records()
    checked = 0
    for case in VECTORS["cases"]:
        if case["team"] is None or case["team_admins"] is None:
            continue
        team = teamlog.TeamState.from_core(VECTORS["teams"][case["team"]])
        assert sorted(log_admins(_LogRows(records[case["team"]]), team)) == case["team_admins"], case["name"]
        checked += 1
    assert checked


class _Vault:
    """The tables and meta records the desktop's judge reads, in memory."""

    def __init__(self):
        from sezam.vault import schema

        self.c = sqlite3.connect(":memory:")
        self.c.row_factory = sqlite3.Row
        for sql in (schema.SYNC_CONFLICTS_SQL, schema.SCHEMA_SQL):
            self.c.executescript(sql)
        for sql in ("vault_meta (key TEXT PRIMARY KEY, value TEXT)", "team_log (seq INTEGER PRIMARY KEY, body TEXT)",
                    "known_keys (user_id TEXT, fingerprint TEXT)", "outbox (object_id TEXT, object_type TEXT)"):
            self.c.execute(f"CREATE TABLE IF NOT EXISTS {sql}")
        self.meta: dict = {}

    def fetchone(self, sql, params=()):
        return self.c.execute(sql, params).fetchone()

    def fetchall(self, sql, params=()):
        return self.c.execute(sql, params).fetchall()

    def get_meta_json(self, key):
        return self.meta.get(key)

    def set_meta_json(self, key, value):
        self.meta[key] = value

    get_meta, set_meta = get_meta_json, set_meta_json

    def hold(self, rows: list[dict]) -> None:
        """The previous snapshot as this device's applied rows."""
        for o in rows:
            meta = bytes.fromhex(o["head"])
            if o["object_type"] == "node":
                self.c.execute("INSERT INTO nodes (id, parent_id, encrypted_meta, dek_id, is_deleted) VALUES (?,?,?,?,?)",
                               (o["id"], o["parent_ref"], meta, "x", o["is_deleted"]))
            elif o["object_type"] == "entry":
                if meta[:2] != b"\x01\x01":
                    meta = meta[4:]
                self.c.execute("INSERT INTO entries (id, node_id, encrypted_meta, encrypted_data, is_deleted) "
                               "VALUES (?,?,?,?,?)", (o["id"], o["parent_ref"] or "", meta, b"", o["is_deleted"]))


def test_the_desktop_gives_the_vectors_answers(monkeypatch):
    """Its full resync's judge (sync_writers._unauthorized_writes) on every
    case, the previous snapshot in its tables; a write it holds back below a
    folder it does not know is not judged yet (review a159e97 H2). Cases with
    an unsigned object are the web's (the desktop takes no unsigned write)."""
    from sezam import teamlog
    from sezam.vault import sync_writers
    from sezam.vault.sync_client import SyncClient

    checked = 0
    for case in VECTORS["cases"]:
        if any(o["signer"] is None for o in case["objects"]):
            continue
        vault = _Vault()
        vault.hold(case["previous"] or [])
        team = teamlog.TeamState.from_core(VECTORS["teams"][case["team"]]) if case["team"] is not None else None
        if team is not None:
            if case["team_admins"] is None:
                # The case asked for the log's current admins.
                monkeypatch.setattr(sync_writers, "log_admins", lambda _db, t: {
                    u for u in t.members if teamlog.is_admin(t, u)})
            else:
                monkeypatch.setattr(sync_writers, "log_admins", lambda _db, t, a=case["team_admins"]: set(a))
        vault.meta[sync_writers.WRITER_ACCOUNTS_META] = []

        class Judge(sync_writers.WritersMixin):
            _db = vault
            _user_id = case["own_user_id"]
            _order_pulled_objects = staticmethod(SyncClient._order_pulled_objects)

            def _signer_id(self, obj):
                return obj["signer"]

            def team_state(self):
                return team

        objects = [{**o, "payload": base64.b64encode(bytes.fromhex(o["head"])).decode()} for o in case["objects"]]
        got = Judge()._unauthorized_writes(objects, full=True)
        held = set(vault.meta.get(sync_writers.DEFERRED_WRITES_META) or {})
        assert got - held == set(case["blocked"]) - held, case["name"]
        checked += 1
    assert checked > 100


def test_the_server_reads_the_vectors_header_key():
    from server.app.routers.sync import _sealing_dek_id

    checked = 0
    for case in VECTORS["cases"]:
        for o in case["objects"]:
            head = bytes.fromhex(o["head"])
            if o["object_type"] == "node":
                payload, entry = head + bytes(16), False
            elif o["object_type"] == "entry" and head[:2] != b"\x01\x01":
                # The server only takes an item as u32be(len(meta)) + meta.
                meta = head[4:] + bytes(16)
                payload, entry = len(meta).to_bytes(4, "big") + meta, True
            else:
                continue
            assert _sealing_dek_id(payload, entry) == case["dek_ids"][f"{o['id']}/{o['object_type']}"], case["name"]
            checked += 1
    assert checked


def test_the_desktop_walks_the_personal_tree_vectors():
    """tests/vectors/personal_tree.json: personal_root.in_personal_tree over
    the desktop's folders, given the vectors' roots. The desktop holds only
    folders it applied and opened, so cases with another signer or an
    unopened folder are not its."""
    from sezam.vault.personal_root import in_personal_tree

    cases = json.loads((ROOT / "tests" / "vectors" / "personal_tree.json").read_text(encoding="utf-8"))["cases"]
    checked = 0
    for case in cases:
        folders = [o for o in case["objects"] if o["object_type"] == "node"]
        own = case["own_user_id"]
        if case["team_keys"] or any(o.get("opened") is False or own not in (None, o["signer"]) for o in folders):
            continue
        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        db.execute("CREATE TABLE nodes (id TEXT, parent_id TEXT, dek_id TEXT)")
        db.executemany("INSERT INTO nodes VALUES (?, ?, ?)", [(o["id"], o["parent_ref"], o["dek_id"]) for o in folders])
        rows = type("Rows", (), {"fetchone": lambda self, sql, params: db.execute(sql, params).fetchone()})()
        roots = set(case["expect"]["roots"])
        tree = sorted(o["id"] for o in folders if in_personal_tree(rows, o["id"], roots))
        assert tree == case["expect"]["tree"], case["name"]
        checked += 1
    assert checked >= 9

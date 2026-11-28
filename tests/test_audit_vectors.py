"""tests/vectors/audit.json on the desktop and the web: an audit record's
signed bytes, sync payload, pull-side parse and DAG check are the core's
(docs/CORE_UNIFICATION.md U6d). core/tests/audit_vectors.rs checks the core
itself, mobile/test/audit_vectors_test.dart the phone."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sezam.vault.audit import AuditLog
from sezam.vault.sync_common import serialize_audit_row
from sezam.vault.sync_pull import PullMixin

V = json.loads((Path(__file__).parent / "vectors" / "audit.json").read_text(encoding="utf-8"))
PARSED = ("actor_id", "action", "timestamp", "parent_ids", "parent_ids_json")


@pytest.mark.parametrize("case", V["message"])
def test_signed_bytes(case):
    message = AuditLog._build_canonical(
        case["id"], case["actor_id"], json.dumps(case["parent_ids"], separators=(",", ":")),
        case["action"], case["timestamp"], bytes.fromhex(case["encrypted_details"]),
    )
    assert message.hex() == case["message"]


@pytest.mark.parametrize("case", V["payload"])
def test_sync_payload(case):
    row = dict(case, parent_ids=json.dumps(case["parent_ids"]),
               encrypted_details=bytes.fromhex(case["encrypted_details"]),
               signature=bytes.fromhex(case["signature"]))
    assert serialize_audit_row(row) == case["payload"].encode("ascii")


@pytest.mark.parametrize("case", V["parse"])
def test_a_pulled_record(case):
    record = PullMixin._parse_audit_payload(case["id"], case["payload"].encode("ascii"))
    assert {k: record[k] for k in PARSED} == {k: case[k] for k in PARSED}
    assert record["encrypted_details"].hex() == case["encrypted_details"]
    assert record["signature"].hex() == case["signature"]
    assert record["message"].hex() == case["message"]


@pytest.mark.parametrize("case", V["parse_refused"], ids=lambda c: c["why"])
def test_a_bad_record_is_refused(case):
    with pytest.raises(ValueError):
        PullMixin._parse_audit_payload(
            case["id"], case["payload"].encode("utf-8"), case["version"],
            case.get("is_deleted", False),
        )


class _Db:
    def __init__(self, records):
        self._rows = [{"id": r["id"], "parent_ids": json.dumps(r["parent_ids"])} for r in records]

    def fetchall(self, _sql):
        return self._rows


@pytest.mark.parametrize("case", V["dag"])
def test_the_dag_check(case):
    holder = type("Holder", (), {"_db": _Db(case["records"])})()
    if case["ok"]:
        PullMixin._validate_audit_dag(holder)
    else:
        with pytest.raises(ValueError):
            PullMixin._validate_audit_dag(holder)


def test_the_web_takes_a_desktop_record_with_a_non_ascii_action():
    """The web compared the payload with its own JSON.stringify, which keeps
    non-ASCII characters the desktop escapes, and refused such a record."""
    from tests.test_review_web import _run

    cases = [v for v in V["parse"] if not v["action"].isascii()]
    script = """(() => {
      btoa = value => Buffer.from(value, 'binary').toString('base64');
      return %s.map(v => { try { parseCanonicalAuditRecord({ id: v.id, version: 2,
        is_deleted: 0, payload: bytesToBase64(new TextEncoder().encode(v.payload)) });
        return 'ok'; } catch (e) { return e.message.replace(/[^ -~]/g, '?'); } });
    })()""" % json.dumps(cases)
    out = _run(["bytesToBase64", "parseCanonicalAuditRecord"], script)
    assert len(cases) == 3 and out == ["ok"] * 3


def test_the_web_parses_signs_and_checks_through_the_core():
    from tests.test_review_web import _run

    script = """(async () => {
      btoa = value => Buffer.from(value, 'binary').toString('base64');
      const V = %s;
      const obj = v => ({ id: v.id, object_type: 'audit', version: v.version,
        is_deleted: v.is_deleted ? 1 : 0, payload: bytesToBase64(new TextEncoder().encode(v.payload)) });
      const refused = (f) => { try { f(); return false; } catch (_) { return true; } };
      const graph = async (records) => {
        const objects = Object.fromEntries(records.map(r => [r.id, { id: r.id }]));
        parseCanonicalAuditRecord = so => records.find(r => r.id === so.id);
        state.userKeys = {};
        for (const r of records) { r.actor_id = 'a'; r.signature_bytes = new Uint8Array(64); }
        sodium.crypto_sign_verify_detached = () => true;
        getUserSigningPks = async () => [new Uint8Array(32)];
        for (const o of Object.values(objects)) o.object_type = 'audit';
        try { await verifyAuditGraph(objects, sodium); return true; } catch (_) { return false; }
      };
      const out = {
        messages: V.message.filter(v => Number.isSafeInteger(v.timestamp)).map(v => bytesToHex(buildAuditCanonical(Object.assign({}, v,
          { encrypted_details_bytes: hexToBytes(v.encrypted_details) })))),
        parsed: V.parse.map(v => { const r = parseCanonicalAuditRecord(obj(v));
          return [r.actor_id, bytesToHex(new TextEncoder().encode(r.action)), r.timestamp, r.parent_ids, bytesToHex(r.encrypted_details_bytes),
                  bytesToHex(r.signature_bytes), bytesToHex(r.message_bytes)]; }),
        refused: V.parse_refused.map(v => refused(() => parseCanonicalAuditRecord(obj(v)))),
      };
      out.dag = [];
      for (const c of V.dag) out.dag.push(await graph(c.records.map(r => ({ ...r }))));
      return out;
    })()""" % json.dumps(V)
    out = _run(["bytesToBase64", "parseCanonicalAuditRecord", "buildAuditCanonical", "verifyAuditGraph"], script)
    # A JS number holds a timestamp exactly up to 2**53 only; a pulled record's
    # signed bytes come from the core's parse (message_bytes), not from it.
    safe = [v["message"] for v in V["message"] if v["timestamp"] <= 2**53 - 1]
    assert len(safe) == 12 and out["messages"] == safe
    assert [p[:2] + p[3:] for p in out["parsed"]] == [
        [v["actor_id"], v["action"].encode().hex(), v["parent_ids"], v["encrypted_details"], v["signature"],
         v["message"]] for v in V["parse"]
    ]
    assert out["refused"] == [True] * len(V["parse_refused"])
    assert out["dag"] == [c["ok"] for c in V["dag"]]

"""tests/vectors/rekey_archive.json on the desktop and the web: the removal
re-key archive id is the core's (docs/CORE_UNIFICATION.md U6,
core/src/rekey_archive.rs); the keyed BLAKE2b under the new DEK stays with
the platform. core/tests/rekey_archive_vectors.rs checks the core itself; the
phone reads the id as an opaque ULID."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sezam.vault import dek
from tests.test_review_web import _run, pytestmark  # noqa: F401

V = json.loads((Path(__file__).parent / "vectors" / "rekey_archive.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", V["cases"])
def test_the_desktop_builds_and_reads_the_id(case, monkeypatch):
    monkeypatch.setattr(dek, "new_ulid", lambda: case["prefix"] + "0" * 16)
    key = bytes.fromhex(case["key"])
    assert dek.removal_archive_id(case["new_dek_id"], key, case["user_id"]) == case["archive_id"]
    for check in case["checks"]:
        # The probe's digests are under the key it was made with; the desktop
        # reads with a key, so only the probes under this case's key replay.
        if check["mark"] == case["mark"]:
            got = dek.archive_removed(check["archive_id"], case["new_dek_id"], key, check["user_id"])
            assert got == check["removed"], check


def test_the_desktop_refuses_a_non_ascii_key_id():
    for r in V["refused"]:
        if r["op"] == "removal_archive_messages":
            with pytest.raises(ValueError):
                dek.removal_archive_id(r["input"]["new_dek_id"], bytes(32), r["input"]["user_id"])


def test_the_web_builds_the_same_id():
    script = """(() => {
      const V = %s;
      return V.cases.map(c => {
        globalThis.generateULID = () => c.prefix + '0'.repeat(16);
        return removalArchiveId(c.new_dek_id, hex(c.key), c.user_id, sodium);
      });
    })()""" % json.dumps(V)
    assert _run(["removalArchiveId"], script) == [c["archive_id"] for c in V["cases"]]


def test_the_web_refuses_a_non_ascii_key_id_as_the_desktop():
    """The web's TextEncoder hashed any key id; the desktop's .encode("ascii") refused it."""
    ids = [r["input"]["new_dek_id"] for r in V["refused"] if r["op"] == "removal_archive_messages"]
    script = """(() => %s.map(id => {
      try { removalArchiveId(id, new Uint8Array(32), 'u', sodium); return 'built'; }
      catch (e) { return /ASCII/.test(e.message) ? 'refused' : e.message; }
    }))()""" % json.dumps(ids)
    # The old app.js built the tags in rekeyArchiveChars; cut it out too, so
    # this test replays the old code instead of failing to find a helper.
    app_js = (Path(__file__).parents[1] / "web" / "static" / "js" / "app.js").read_text(encoding="utf-8")
    helpers = ["rekeyArchiveChars"] if "function rekeyArchiveChars(" in app_js else []
    assert _run(["generateULID", *helpers, "removalArchiveId"], script) == ["refused"] * len(ids) == ["refused"] * 2

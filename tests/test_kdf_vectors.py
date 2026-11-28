"""tests/vectors/kdf.json on the server, the desktop and the web: the Argon2id
parameter bounds are the core's (docs/CORE_UNIFICATION.md U6,
core/src/kdf.rs). core/tests/kdf_vectors.rs checks the core itself,
mobile/test/kdf_vectors_test.dart the phone."""

from __future__ import annotations

import json
from pathlib import Path

from server.app.models.schemas import AccountKdfParams, StoredAccountKdfParams

from sezam.crypto.kdf import Argon2Params
from sezam.crypto.keys import _validate_sezam_key_kdf
from sezam.vault.crud import server_account_kdf

V = json.loads((Path(__file__).parent / "vectors" / "kdf.json").read_text(encoding="utf-8"))


def _refused(fn, *args) -> bool:
    try:
        fn(*args)
    except (ValueError, RuntimeError):
        return True
    return False


class _DB:
    def __init__(self, local):
        self.local = local

    def get_meta(self, key):
        return "ff" * 16 if key == "argon2_salt" else None

    def get_meta_json(self, key):
        return self.local


def test_the_server_takes_the_account_params_the_vectors_take():
    cases = [c for c in V["account"] if c["local"] is None]
    for c in cases:
        model = StoredAccountKdfParams if c["stored"] else AccountKdfParams
        params = {**c["params"], "hash_len": c["params"].get("hash_len", 64)}
        assert _refused(lambda: model.model_validate(params, strict=True)) == c["refused"], c


def test_the_desktop_takes_the_account_params_the_vectors_take():
    cases = [c for c in V["account"] if not c["stored"]]
    for c in cases:
        meta = {"argon2_salt": "00" * 16, "argon2_params": c["params"]}
        db = _DB(c["local"]) if c["local"] else None
        assert _refused(server_account_kdf, meta, db) == c["refused"], c
    assert sum(c["refused"] for c in cases) < len(cases)


def test_the_desktop_takes_the_sezam_key_params_the_vectors_take():
    cases = [c for c in V["sezam_key"] if not c["stored"] and isinstance(c["salt_len"], int)]
    for c in cases:
        params = Argon2Params(c["time_cost"], c["memory_cost"], c["parallelism"], c["salt_len"], c["hash_len"])
        assert _refused(_validate_sezam_key_kdf, bytes(c["salt_len"]), params) == c["refused"], c


def test_the_web_through_the_core():
    from tests.test_review_web import _run

    account = [c for c in V["account"] if c["local"] is None and not c["stored"]]
    sezam_key = [c for c in V["sezam_key"] if not c["stored"]]
    script = """(() => {
      const A = %s, K = %s;
      const refused = f => { try { f(); return false; } catch (e) { return true; } };
      return {
        account: A.map(c => refused(() => normalizeKdfParams(c.params))),
        sezam_key: K.map(c => refused(() => validateSezamKeyKdf(
          typeof c.salt_len === 'number' ? new Uint8Array(c.salt_len) : c.salt_len,
          { time_cost: c.time_cost, memory_cost: c.memory_cost, parallelism: c.parallelism, hash_len: c.hash_len }))),
      };
    })()""" % (json.dumps(account), json.dumps(sezam_key))
    out = _run(["normalizeKdfParams", "validateSezamKeyKdf"], script)
    assert out["account"] == [c["refused"] for c in account]
    assert out["sezam_key"] == [c["refused"] for c in sezam_key]

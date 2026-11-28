"""docs/ROOT_CAUSE_PLAN.md, precedence of INV-5 and INV-7 (rule 3: nothing
unknown is personal), web. Review e443cbc: while the team log was refused, the
web kept open every key sealing something below a personal root. A server
replaying a team folder's version from before the admin moved it out of the
personal tree (signed by the admin, sealed under the personal key) put the
team folder's items below the personal root: their team key stayed open, and
the admin's next edit resealed them under the personal key, out of the team's
reach. Only the personal roots' own keys stay open; a personal tree has one
key, its root's (TL7).
"""

from __future__ import annotations

import json
from pathlib import Path

from tests.test_review_web import APP, _run, pytestmark  # noqa: F401

ME = "01HMEMEMEMEMEMEMEMEMEMEMEM"
ME_VECTORS = "01JME00000000000000000000A"


def _keys(nodes: dict, signers: dict) -> list[str]:
    script = f"""(() => {{
      const nodes = {json.dumps(nodes)};
      const syncObjects = Object.fromEntries(Object.entries({json.dumps(signers)}).map(([id, s]) => [id, {{ signer: s }}]));
      return [...refusedLogPersonalKeys(nodes, syncObjects)].sort();
    }})()"""
    return _run(["webPersonalTree", "webInPersonalTree", "refusedLogPersonalKeys"], script, {"userId": ME})


def test_a_replayed_team_folder_below_the_personal_root_opens_no_team_key():
    nodes = {
        # The admin's personal root, its own key.
        "P": {"personal": True, "parent_ref": None, "dekId": "kP"},
        # The team folder, served at its version from inside P (sealed under kP).
        "F": {"personal": False, "parent_ref": "P", "dekId": "kP"},
        # A team item in it, at its current version under the team folder's key.
        "E": {"personal": False, "parent_ref": "F", "dekId": "kF"},
        # The team's root and an admin folder: never personal.
        "R": {"personal": False, "parent_ref": None, "dekId": "kR"},
    }
    assert _keys(nodes, {"P": ME, "F": ME, "E": ME, "R": ME}) == ["kP"]


def test_a_personal_root_counts_only_signed_by_this_account_and_top_level():
    nodes = {
        "P": {"personal": True, "parent_ref": None, "dekId": "kP"},
        "Q": {"personal": True, "parent_ref": None, "dekId": "kQ"},
        "N": {"personal": True, "parent_ref": "P", "dekId": "kN"},
        "U": {"personal": True, "parent_ref": None, "dekId": "kU", "_undecryptable": True},
    }
    assert _keys(nodes, {"P": ME, "Q": "01HOTHEROTHEROTHEROTHEROTH", "N": ME, "U": ME}) == ["kP"]


def test_the_web_gives_the_personal_tree_vectors_answers():
    """tests/vectors/personal_tree.json (folders only; the web passes this
    account and no team keys)."""
    vectors = json.loads((Path(__file__).parent / "vectors" / "personal_tree.json").read_text(encoding="utf-8"))
    cases = [c for c in vectors["cases"] if c["own_user_id"] == ME_VECTORS and not c["team_keys"]]
    assert len(cases) >= 12
    for case in cases:
        folders = [o for o in case["objects"] if o["object_type"] == "node"]
        nodes = {o["id"]: {"personal": o.get("personal", False), "parent_ref": o["parent_ref"], "dekId": o["dek_id"],
                           **({"_undecryptable": True} if o.get("opened") is False else {})} for o in folders}
        signers = {o["id"]: o["signer"] for o in folders}
        script = f"""(() => {{
          const nodes = {json.dumps(nodes)};
          const syncObjects = Object.fromEntries(Object.entries({json.dumps(signers)}).map(([id, s]) => [id, {{ signer: s }}]));
          return {{
            root_keys: [...refusedLogPersonalKeys(nodes, syncObjects)].sort(),
            tree: Object.keys(nodes).filter(id => webInPersonalTree(nodes, syncObjects, id)).sort(),
          }};
        }})()"""
        got = _run(["webPersonalTree", "webInPersonalTree", "refusedLogPersonalKeys"], script, {"userId": ME_VECTORS})
        assert got == {"root_keys": case["expect"]["root_keys"], "tree": case["expect"]["tree"]}, case["name"]


def test_the_refused_pull_opens_only_those_keys():
    assert "refusedLogPersonalKeys(candidateNodes, candidateSyncObjects)" in APP
    assert APP.count("refusedLogPersonalKeys(") == 2

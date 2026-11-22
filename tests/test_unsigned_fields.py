"""docs/ROOT_CAUSE_PLAN.md S4 (INV-3): every field the server answers is in
``server.app.unsigned_fields``, signed or classified, with the state-machine
rules that lie in it.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import pathlib
import re
import textwrap
import typing

import pydantic
import pytest
from fastapi.routing import APIRoute

from server.app.main import app
from server.app.unsigned_fields import CLIENT_FIELDS, DECIDES, FIELDS, HINT, SIGNED, UNREAD

ROOT = pathlib.Path(__file__).resolve().parent.parent
MACHINE = (ROOT / "tests" / "test_sync_state_machine.py").read_text(encoding="utf-8")
SOURCES = {
    "web": "\n".join(p.read_text(encoding="utf-8") for p in sorted((ROOT / "web/static/js").glob("*.js"))),
    "mobile": "\n".join(p.read_text(encoding="utf-8") for p in sorted((ROOT / "mobile/lib").rglob("*.dart"))),
}

# Open INV-3 findings in the web and mobile clients: access_level is the
# vault without a log (S6), commit_seq is #443, as on the desktop.
KNOWN_CLIENT_DECIDES = {
    ("web", "PullObject.commit_seq"),
    ("mobile", "PullObject.commit_seq"),
    ("web", "PullObject.access_level"),
    ("mobile", "PullObject.access_level"),
    # #443: the retired key's bound, as on the desktop (the web keeps it per session).
    ("web", "GET /api/users/{user_id}/keys .archived_keys"),
    ("mobile", "GET /api/users/{user_id}/keys .archived_keys"),
}

# Open INV-3 findings: a client decision rests on these unsigned fields.
# Remove a field here only when its entry stops being DECIDES.
# The first two are one finding, goal #443: a device pulling from below a
# retirement takes whatever a leaked retired key signs. access_level is the
# vault without a log (ROOT_CAUSE_PLAN S6, phase 3).
KNOWN_DECIDES = {
    "GET /api/users/{user_id}/keys .archived_keys",
    "PullObject.commit_seq",
    "PullObject.access_level",
}


def _models(annotation, found: dict) -> None:
    for arg in typing.get_args(annotation):
        _models(arg, found)
    if isinstance(annotation, type) and issubclass(annotation, pydantic.BaseModel) \
            and annotation.__name__ not in found:
        found[annotation.__name__] = annotation
        for field in annotation.model_fields.values():
            _models(field.annotation, found)


def _dict_keys(fn) -> set[str]:
    """String keys of the dicts ``fn`` returns (``return {...}`` or
    ``return SomeResponse({...})``)."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(inspect.unwrap(fn))))
    keys = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Return) and node.value is not None:
            value = node.value
            if isinstance(value, ast.Call) and value.args:
                value = value.args[0]
            if isinstance(value, ast.Dict):
                keys |= {k.value for k in value.keys if isinstance(k, ast.Constant)}
    return keys


def _answered() -> set[str]:
    models: dict = {}
    fields = set()
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        if route.response_model is None:
            methods = " ".join(sorted(route.methods - {"HEAD"}))
            fields |= {f"{methods} {route.path} .{key}" for key in _dict_keys(route.endpoint)}
        else:
            _models(route.response_model, models)
    for name, model in models.items():
        fields |= {f"{name}.{field}" for field in model.model_fields}
    return fields


def _resolve(dotted: str):
    module, _, name = dotted.partition(":")
    obj = importlib.import_module(f"sezam.{module}")
    for part in name.split("."):
        obj = getattr(obj, part)
    return obj


def test_every_answered_field_has_an_entry_and_every_entry_a_field():
    answered = _answered()
    listed = set(FIELDS)
    assert not answered - listed, f"fields without an entry in server/app/unsigned_fields.py: {sorted(answered - listed)}"
    assert not listed - answered, f"entries without a field: {sorted(listed - answered)}"


@pytest.mark.parametrize("key", sorted(FIELDS))
def test_entry_is_complete(key):
    entry = FIELDS[key]
    assert entry.trust in (SIGNED, HINT, UNREAD, DECIDES), key
    if entry.trust == SIGNED:
        assert entry.checks, f"{key}: signed, but no check named"
    if entry.trust in (HINT, DECIDES):
        assert entry.why, f"{key}: {entry.trust} needs the reason"
    for check in entry.checks:
        assert callable(_resolve(check)), f"{key}: {check}"
    for lie in entry.lies:
        rule, _, label = lie.partition(":")
        assert f"def {rule}(" in MACHINE, f"{key}: no state-machine rule {rule}"
        assert not label or f'"{label}"' in MACHINE, f"{key}: rule {rule} has no lie {label!r}"


def test_the_open_findings_are_the_known_ones():
    decides = {key for key, entry in FIELDS.items() if entry.trust == DECIDES}
    assert decides == KNOWN_DECIDES, (
        f"new: {sorted(decides - KNOWN_DECIDES)}; no longer deciding: {sorted(KNOWN_DECIDES - decides)}")


def _reads(client: str, key: str) -> bool:
    """The client's sources read a key of this name (``.name`` or ``['name']``)."""
    name = key.rsplit(".", 1)[-1].strip()
    return re.search(r"(?:\.|\[['\"])%s\b" % re.escape(name), SOURCES[client]) is not None


def _defined(client: str, name: str) -> bool:
    if client == "web":
        pattern = r"\bfunction\s+%s\s*\(|\b%s\s*=\s*(?:async\s*)?(?:function\b|\()" % (name, name)
    else:
        pattern = r"^\s*(?:static\s+)?[\w<>?,\[\] ]+\s+%s\s*\(" % name
    return re.search(pattern, SOURCES[client], re.M) is not None


def test_every_field_a_client_reads_is_classified_for_that_client():
    """Capability run 458: the desktop's classification says nothing about
    what web or mobile make of a field."""
    read = {(c, k) for c in SOURCES for k in FIELDS if _reads(c, k)}
    classified = {(c, k) for c, entries in CLIENT_FIELDS.items() for k in entries}
    missing = read - classified
    assert not missing, f"read by a client, not classified for it: {sorted(missing)}"


@pytest.mark.parametrize("client", sorted(CLIENT_FIELDS))
def test_client_entries_are_complete(client):
    for key, entry in CLIENT_FIELDS[client].items():
        assert key in FIELDS, f"{client}: {key} is no answered field"
        assert entry.trust in (SIGNED, HINT, UNREAD, DECIDES), key
        assert not entry.lies, f"{client}: {key}: the state machine drives the desktop only"
        if entry.trust == SIGNED:
            assert entry.checks, f"{client}: {key}: signed, but no check named"
        if entry.trust in (HINT, DECIDES):
            assert entry.why, f"{client}: {key}: {entry.trust} needs the reason"
        for check in entry.checks:
            assert _defined(client, check), f"{client}: {key}: no function {check}"


def test_the_open_client_findings_are_the_known_ones():
    decides = {(c, k) for c, entries in CLIENT_FIELDS.items() for k, e in entries.items() if e.trust == DECIDES}
    assert decides == KNOWN_CLIENT_DECIDES, (
        f"new: {sorted(decides - KNOWN_CLIENT_DECIDES)}; "
        f"no longer deciding: {sorted(KNOWN_CLIENT_DECIDES - decides)}")

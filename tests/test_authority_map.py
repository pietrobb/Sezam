"""docs/ROOT_CAUSE_PLAN.md S1 (INV-2): every operation that changes authority or
data is in the authority map, with who may, the checks and the tests.

Server: every route of the app has an entry in ``server.app.authority.ROUTES``.
Clients: every CLI command, MCP tool and public Vault / SyncClient method has
one in ``sezam.authority`` (the GUI only calls the Vault and SyncClient API:
a GUI module writing SQL or calling the server itself fails here).
"""

from __future__ import annotations

import ast
import importlib
import importlib.util
import inspect
import pathlib
import re
import textwrap

import click
import pytest
from fastapi.routing import APIRoute

from server.app import authority as server_authority
from server.app.main import app
from sezam import authority as client_authority
from sezam.cli import main as cli_main
from sezam.mcp.server import SezamMCPServer
from sezam.vault.crud import Vault
from sezam.vault.sync_client import SyncClient

ROOT = pathlib.Path(__file__).resolve().parent.parent
NOT_AUTH = {"get_db", "get_config", "get_jwt_manager"}
SQL_WRITE = re.compile(r"\b(INSERT\s+(IGNORE\s+)?INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|REPLACE\s+INTO)\b", re.I)


def _routes() -> dict[str, APIRoute]:
    found = {}
    for route in app.routes:
        if isinstance(route, APIRoute):
            for method in route.methods - {"HEAD"}:
                found[f"{method} {route.path}"] = route
    return found


def _resolve(dotted: str, package: str):
    module, _, name = dotted.partition(":")
    obj = importlib.import_module(f"{package}.{module}" if package else module)
    for part in name.split("."):
        obj = getattr(obj, part)
    return obj.callback if isinstance(obj, click.Command) else obj


def _referenced(fn, package: str) -> list:
    """``fn`` and every function of ``package`` it names, transitively."""
    seen, todo = [], [inspect.unwrap(fn)]
    while todo:
        f = todo.pop()
        if f in seen or not inspect.isfunction(f):
            continue
        seen.append(f)
        try:
            tree = ast.parse(textwrap.dedent(inspect.getsource(f)))
        except (OSError, TypeError):
            continue
        names = f.__globals__
        for node in ast.walk(tree):
            target = None
            if isinstance(node, ast.Name):
                target = names.get(node.id)
            elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                owner = names.get(node.value.id)
                if inspect.ismodule(owner) or inspect.isclass(owner):
                    target = getattr(owner, node.attr, None)
            if inspect.isfunction(target) and target.__module__.startswith(package):
                todo.append(target)
    return seen


def _writes_sql(fn, package: str) -> list[str]:
    hits = []
    for f in _referenced(fn, package):
        try:
            tree = ast.parse(textwrap.dedent(inspect.getsource(f)))
        except (OSError, TypeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and SQL_WRITE.search(node.value):
                hits.append(f"{f.__module__}.{f.__qualname__}")
                break
    return hits


def _mentions(test: str, *needles: str) -> bool:
    path = ROOT / test
    assert path.is_file(), f"{test} does not exist"
    text = path.read_text(encoding="utf-8")
    return any(n and n in text for n in needles)


# ── Server ──────────────────────────────────────────────────────────────────

def test_every_route_has_an_entry_and_every_entry_a_route():
    routes = set(_routes())
    registered = set(server_authority.ROUTES)
    assert not routes - registered, f"routes without an entry in server/app/authority.py: {sorted(routes - registered)}"
    assert not registered - routes, f"entries without a route: {sorted(registered - routes)}"


@pytest.mark.parametrize("key", sorted(server_authority.ROUTES))
def test_route_entry_matches_the_route(key):
    entry = server_authority.ROUTES[key]
    route = _routes()[key]
    assert entry.who, key
    for check in entry.checks:
        assert callable(_resolve(check, "server.app")), check
    used = {d.call.__name__ for d in route.dependant.dependencies if d.call} - NOT_AUTH
    listed = {c.split(":")[1] for c in entry.checks if c.startswith("dependencies:")}
    assert used == listed, f"{key}: auth dependencies {sorted(used)}, the map lists {sorted(listed)}"
    writes = _writes_sql(route.endpoint, "server.app")
    if not entry.changes:
        assert not writes, f"{key} is mapped as reading only, but writes in {writes}"
    else:
        assert entry.checks or entry.who == server_authority.PUBLIC, f"{key} writes with no check named"
    assert entry.tests, f"{key}: no test named"
    path = route.path
    static = [s for s in re.split(r"\{[^}]+\}", path) if s.strip("/")]
    needles = [route.endpoint.__name__, max(static, key=len) if static else f'"{path}"']
    for test in entry.tests:
        assert _mentions(test, *needles), f"{test} names neither {needles} ({key})"


# ── Clients ─────────────────────────────────────────────────────────────────

UI_FILES = [*sorted((ROOT / "src/sezam/gui").rglob("*.py")), ROOT / "src/sezam/cli.py",
            ROOT / "src/sezam/cli_team_log.py", *sorted((ROOT / "src/sezam/mcp").rglob("*.py"))]
API_PATH = re.compile(r"/api/[A-Za-z0-9\-/{}_]*")
_REACHED: dict = {}


def _module_of(path: pathlib.Path) -> str:
    return ".".join(path.relative_to(ROOT / "src").with_suffix("").parts)


def _owner(f):
    parts = f.__qualname__.split(".")
    if len(parts) < 2 or "<locals>" in parts:
        return None
    owner = importlib.import_module(f.__module__)
    for part in parts[:-1]:
        owner = getattr(owner, part, None)
    return SyncClient if inspect.isclass(owner) and owner in SyncClient.__mro__ else owner


def _scope(f, tree) -> dict:
    scope = dict(f.__globals__)
    package = f.__module__.rpartition(".")[0]
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            name = importlib.util.resolve_name("." * node.level + (node.module or ""), package) if node.level \
                else node.module
            if not name or not name.startswith("sezam"):
                continue
            module = importlib.import_module(name)
            for alias in node.names:
                value = getattr(module, alias.name, None)
                if value is None:
                    try:
                        value = importlib.import_module(f"{name}.{alias.name}")
                    except ImportError:
                        continue
                scope[alias.asname or alias.name] = value
    return scope


def _reach(fn):
    """Functions of sezam ``fn`` names (transitively), attribute names and strings in them."""
    fn = inspect.unwrap(fn)
    if fn not in _REACHED:
        funcs, attrs, strings, todo = set(), set(), set(), [fn]
        while todo:
            f = todo.pop()
            if not inspect.isfunction(f) or not f.__module__.startswith("sezam"):
                continue
            f = inspect.unwrap(f)
            if f in funcs:
                continue
            funcs.add(f)
            try:
                tree = ast.parse(textwrap.dedent(inspect.getsource(f)))
            except (OSError, TypeError, SyntaxError):
                continue
            scope, owner = _scope(f, tree), _owner(f)
            for node in ast.walk(tree):
                target = None
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    strings.add(node.value)
                elif isinstance(node, ast.Name):
                    target = scope.get(node.id)
                elif isinstance(node, ast.Attribute):
                    attrs.add(node.attr)
                    if isinstance(node.value, ast.Name):
                        base = owner if node.value.id in ("self", "cls") else scope.get(node.value.id)
                        if inspect.ismodule(base) or inspect.isclass(base):
                            target = getattr(base, node.attr, None)
                if inspect.isfunction(target):
                    todo.append(target)
        _REACHED[fn] = (funcs, attrs, strings)
    return _REACHED[fn]


def _cli_commands() -> dict:
    found = {}

    def walk(cmd, prefix):
        name = f"{prefix} {cmd.name}".strip()
        if isinstance(cmd, click.Group):
            for sub in cmd.commands.values():
                walk(sub, name)
        else:
            found[name] = cmd.callback

    for sub in cli_main.commands.values():
        walk(sub, "")
    return found


def _public(cls) -> set[str]:
    return {n for n, _ in inspect.getmembers(cls, inspect.isfunction) if not n.startswith("_")}


def _ui_vault_imports() -> tuple[set[str], set[str]]:
    """Functions and classes of sezam.vault the CLI, GUI and MCP import or call."""
    funcs, classes = set(), set()
    for path in UI_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        package = _module_of(path).rpartition(".")[0]
        modules = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            name = importlib.util.resolve_name("." * node.level + (node.module or ""), package) if node.level \
                else node.module
            if not name or not name.startswith("sezam.vault"):
                continue
            module = importlib.import_module(name)
            for alias in node.names:
                value = getattr(module, alias.name, None)
                if value is None or inspect.ismodule(value):
                    modules[alias.asname or alias.name] = importlib.import_module(f"{name}.{alias.name}")
                elif inspect.isfunction(value):
                    funcs.add(f"{value.__module__.removeprefix('sezam.vault.')}:{value.__name__}")
                elif inspect.isclass(value) and not issubclass(value, BaseException):
                    classes.add(f"{value.__module__.removeprefix('sezam.vault.')}:{value.__name__}")
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in modules:
                value = getattr(modules[node.value.id], node.attr, None)
                if inspect.isfunction(value):
                    funcs.add(f"{value.__module__.removeprefix('sezam.vault.')}:{value.__name__}")
    return funcs, classes - {"crud:Vault", "sync_client:SyncClient"}


def _ui_server_callers() -> set[str]:
    found = set()

    def visit(node, module, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                visit(child, module, f"{prefix}{child.name}.")
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if any(isinstance(n, ast.Constant) and isinstance(n.value, str) and API_PATH.search(n.value)
                       for n in ast.walk(child)):
                    found.add(f"{module}:{prefix}{child.name}")

    for path in UI_FILES:
        visit(ast.parse(path.read_text(encoding="utf-8")), _module_of(path).removeprefix("sezam."), "")
    return found


def _same(found: set, registered, what: str) -> None:
    registered = set(registered)
    assert not found - registered, f"{what} without an entry in src/sezam/authority.py: {sorted(found - registered)}"
    assert not registered - found, f"{what} entries that no longer exist: {sorted(registered - found)}"


def test_every_client_operation_has_an_entry():
    _same(set(_cli_commands()), client_authority.CLI, "CLI commands")
    tools = {t["name"] for t in SezamMCPServer.get_tools(SezamMCPServer.__new__(SezamMCPServer))}
    _same(tools, client_authority.MCP, "MCP tools")
    _same(_public(Vault), client_authority.VAULT, "Vault methods")
    _same(_public(SyncClient), client_authority.SYNC, "SyncClient methods")
    funcs, classes = _ui_vault_imports()
    _same(funcs, client_authority.FUNCTIONS, "sezam.vault functions the CLI, GUI or MCP call")
    _same(classes, client_authority.CLASSES, "sezam.vault classes the CLI, GUI or MCP use")
    _same(_ui_server_callers(), client_authority.DIRECT, "CLI, GUI or MCP functions that call the server")


def _client_object(section: str, key: str):
    if section == "VAULT":
        return getattr(Vault, key)
    if section == "SYNC":
        return getattr(SyncClient, key)
    if section in ("FUNCTIONS", "CLASSES"):
        return _resolve(key, "sezam.vault")
    if section == "DIRECT":
        return _resolve(key, "sezam")
    if section == "CLI":
        return _cli_commands()[key]
    return SezamMCPServer._handle_tool_call


def _named(target: str):
    if target.startswith(("Vault.", "SyncClient.")):
        cls, _, name = target.partition(".")
        return getattr(Vault if cls == "Vault" else SyncClient, name)
    if target.startswith("sezam."):
        return _resolve(target, "")
    return _resolve(target, "sezam.vault")


def _reaches(caller, section: str, key: str, obj) -> bool:
    funcs, attrs, _ = _reach(caller)
    if section in ("VAULT", "SYNC"):
        return key in attrs
    return inspect.unwrap(obj) in funcs or (inspect.isclass(obj) and obj.__name__ in attrs)


CLIENT_ENTRIES = [
    (section, key)
    for section in ("CLI", "MCP", "VAULT", "SYNC", "FUNCTIONS", "CLASSES", "DIRECT")
    for key in sorted(getattr(client_authority, section))
]


@pytest.mark.parametrize("section,key", CLIENT_ENTRIES, ids=[f"{s} {k}" for s, k in CLIENT_ENTRIES])
def test_client_entry_matches_the_code(section, key):
    entry = getattr(client_authority, section)[key]
    obj = _client_object(section, key)
    assert entry.who, key
    for route in entry.decided_by:
        assert route == client_authority.LOCAL or route in server_authority.ROUTES, f"{key}: no route {route}"
    if section == "MCP":
        assert not entry.changes, f"MCP tool {key} changes the vault: it needs a decision named"
    elif entry.changes:
        assert entry.decided_by or entry.via, f"{section} {key} changes something but names no decision"
    if entry.calls:
        strings = _reach(obj)[2] if not inspect.isclass(obj) else set()
        for path in entry.calls:
            assert any(path in s for s in strings), f"{section} {key} does not call {path}"
    short = key.split(":")[-1].split(".")[-1].split(" ")[-1]
    needles = (short, getattr(obj, "__name__", short))
    for test in entry.tests:
        assert _mentions(test, *needles), f"{test} names neither of {needles} ({section} {key})"
    for caller in entry.part_of:
        assert _reaches(_named(caller), section, short, obj), f"{caller} does not run {section} {key}"
    for target in entry.via:
        name = target.split(".")[-1] if target.startswith(("Vault.", "SyncClient.")) else None
        funcs, attrs, _ = _reach(obj)
        if name:
            assert name in attrs, f"CLI {key} does not run {target}"
        else:
            assert inspect.unwrap(_named(target)) in funcs, f"CLI {key} does not run {target}"
    untested = f"{section} {key}" in client_authority.UNTESTED
    if entry.changes and section != "CLI" and not entry.via:
        assert entry.tests or entry.part_of or untested, f"{section} {key} changes something and names no test"
    assert not (untested and (entry.tests or entry.part_of)), f"{section} {key} has tests now: drop it from UNTESTED"


def test_the_gui_writes_no_sql_of_its_own():
    for path in sorted((ROOT / "src/sezam/gui").rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert not SQL_WRITE.search(node.value), f"{path.name}: {node.value[:60]!r}"


def test_the_document_is_the_maps():
    from scripts.authority_map import render

    doc = ROOT / "docs/AUTHORITY_MAP.md"
    assert doc.read_text(encoding="utf-8") == render(), "docs/AUTHORITY_MAP.md is stale: python scripts/authority_map.py"


@pytest.mark.parametrize("key", ["POST /api/team-log", "POST /api/sync", "DELETE /api/users/{user_id}",
                                 "PUT /api/ai-anchor", "POST /api/auth/logout", "GET /api/share-notifications"])
def test_the_write_detector_sees_routes_that_write(key):
    """A route that writes, mapped as reading only, fails the entry test."""
    assert _writes_sql(_routes()[key].endpoint, "server.app"), key

"""Review 7c10379 H5: the HTTP broker did not read parameter names the way PHP does.

'?+_method=DELETE' is '_method' to PHP ('+' is a space and leading spaces are
dropped), '?rest_route%00=' is 'rest_route' (PHP cuts a name at NUL) and
'rest_route' in a form body is in $_POST, which WordPress routes by just as it
does $_GET. An entry allowing only GET /wp-json/wp/v2/posts could delete
posts or create an administrator. Names are now read as PHP reads them, in
the query and in form, multipart and JSON bodies; routing and override names
are refused, '_'-names unless the entry lists them, and an entry may list the
only parameters it allows (allowed_params).

The last test sends every accepted request to a real PHP (php -S) and checks
what PHP saw.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import time

import pytest

from sezam.mcp.http_api import HTTPManager, HTTPTarget
from sezam.mcp.ssh import SSHBrokerError


def _entry(base_url="https://api.example.test/wp-json", **extra) -> dict:
    fields = {
        "base_url": base_url,
        "auth_header": "Authorization: Bearer {token}",
        "token": "t0k3n",
        "allowed_methods": "GET, POST",
        "allowed_path_prefixes": "/wp/v2/posts",
        **extra,
    }
    return {"fields": [{"key": k, "value": v} for k, v in fields.items()]}


def _target(**extra) -> HTTPTarget:
    return HTTPTarget.from_entry(_entry(**extra))


@pytest.mark.parametrize(
    "query",
    [
        "+_method=DELETE",
        "%20%20_method=DELETE",
        "_method%00=DELETE",
        "_method%00x=DELETE",
        "rest_route%00=/wp/v2/users",
        "rest_route%00x=/wp/v2/users",
        "+rest_route=/wp/v2/users",
        "rest%2eroute=/wp/v2/users",
        "rest%5Broute=/wp/v2/users",
        "rest_route%5B%5D=/wp/v2/users",
    ],
)
def test_names_php_reads_as_routing_or_override_are_refused_in_the_query(query):
    with pytest.raises(SSHBrokerError) as err:
        _target().check("GET", "/wp/v2/posts?" + query)
    assert err.value.code in ("path_denied", "method_denied", "param_denied")


@pytest.mark.parametrize(
    ("body", "content_type"),
    [
        ("title=x&rest_route=/wp/v2/users", "application/x-www-form-urlencoded"),
        ("title=x&rest_route%00=/wp/v2/users", "application/x-www-form-urlencoded"),
        ("title=x&+_method=DELETE", "application/x-www-form-urlencoded"),
        ("rest_route=/wp/v2/users", None),
        (
            '--B\r\nContent-Disposition: form-data; name=" _method"\r\n\r\nDELETE\r\n--B--\r\n',
            "multipart/form-data; boundary=B",
        ),
        (
            '--B\r\nContent-Disposition: form-data; name="rest_route"\r\n\r\n/wp/v2/users\r\n--B--\r\n',
            "multipart/form-data; boundary=B",
        ),
        ('{"title": "x", "rest_route": "/wp/v2/users"}', "application/json"),
        ('{"title": "x", "\\u005fmethod": "DELETE"}', "application/json"),
    ],
)
def test_routing_and_override_names_are_refused_in_the_body(body, content_type):
    headers = {"Content-Type": content_type} if content_type else None
    with pytest.raises(SSHBrokerError) as err:
        _target().check_body(body, headers)
    assert err.value.code in ("path_denied", "method_denied", "param_denied")


def test_underscore_names_need_the_entry_to_list_them():
    with pytest.raises(SSHBrokerError) as err:
        _target().check("GET", "/wp/v2/posts?_fields=id,title")
    assert err.value.code == "param_denied"
    with pytest.raises(SSHBrokerError):
        _target().check_body("_wpnonce=1", {"Content-Type": "application/x-www-form-urlencoded"})
    listed = _target(allowed_params="_fields, per_page")
    assert listed.check("GET", "/wp/v2/posts?_fields=id&per_page=5")[1] == (
        "/wp-json/wp/v2/posts?_fields=id&per_page=5"
    )
    with pytest.raises(SSHBrokerError) as err:
        _target(allowed_params="_method, rest_route").check("GET", "/wp/v2/posts?_method=DELETE")
    assert err.value.code == "method_denied"


def test_allowed_params_limits_query_and_form_body():
    target = _target(allowed_params="per_page status title")
    assert target.check("GET", "/wp/v2/posts?per_page=5&status=publish")[0] == "GET"
    with pytest.raises(SSHBrokerError) as err:
        target.check("GET", "/wp/v2/posts?per_page=5&author=1")
    assert err.value.code == "param_denied"
    target.check_body("title=x", {"Content-Type": "application/x-www-form-urlencoded"})
    with pytest.raises(SSHBrokerError):
        target.check_body("title=x&author=1", {"Content-Type": "application/x-www-form-urlencoded"})
    # PHP reads the type up to the first ';', ',' or space: still a form.
    for content_type in ("application/x-www-form-urlencoded, application/json",
                         " Application/X-WWW-Form-Urlencoded charset=utf-8"):
        with pytest.raises(SSHBrokerError):
            target.check_body("title=x&author=1", {"Content-Type": content_type})
    with pytest.raises(SSHBrokerError) as err:
        target.check("GET", "/wp/v2/posts?per_page=5;author=1")
    assert err.value.code == "param_denied"
    # A JSON body is not parameters: only the refused names are checked.
    target.check_body('{"title": "x", "content": "y"}', {"Content-Type": "application/json"})


def test_ordinary_requests_still_pass():
    target = _target()
    assert target.check("GET", "/wp/v2/posts?per_page=5&status=publish") == (
        "GET", "/wp-json/wp/v2/posts?per_page=5&status=publish"
    )
    target.check_body("title=Hello&content=a+b", {"Content-Type": "application/x-www-form-urlencoded"})
    target.check_body('{"title": "x", "meta": {"payment_method": "card"}}', {"Content-Type": "application/json"})


# --- against a real PHP -----------------------------------------------------

_PHP = shutil.which("php")
_ROUTER = (
    "<?php header('Content-Type: application/json');"
    "echo json_encode(['get' => array_keys($_GET), 'post' => array_keys($_POST)]);"
)


def _variants(name: str) -> list[str]:
    """Spellings of ``name`` that some PHP version may read back as ``name``."""
    out = {name, name.upper(), "+" + name, "%20" + name, "+%20" + name, name + "%00", name + "%00x",
           name + "%5B%5D", name + "%5Bx", name + "%5Bx%5D"}
    for i, ch in enumerate(name):
        if ch == "_":
            for sub in ("+", "%20", ".", "%2e", "%2E", "%5B", "%5b", "%5F", "%5f", "%00"):
                out.add(name[:i] + sub + name[i + 1:])
    out.add("%5F" + name[1:] if name.startswith("_") else "%" + format(ord(name[0]), "02X") + name[1:])
    return sorted(out)


@pytest.fixture(scope="module")
def php_server(tmp_path_factory):
    if _PHP is None:
        pytest.skip("php is not installed")
    root = tmp_path_factory.mktemp("php")
    (root / "router.php").write_text(_ROUTER, encoding="ascii")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen(
        [_PHP, "-S", f"127.0.0.1:{port}", "router.php"], cwd=root,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        yield port
    finally:
        proc.kill()
        proc.wait()


@pytest.mark.parametrize("allowed", [None, "per_page, status, _fields"])
def test_what_php_receives_never_holds_a_refused_name(php_server, allowed):
    extra = {"allow_plain_http": "true", "allowed_path_prefixes": "/api"}
    if allowed:
        extra["allowed_params"] = allowed
    entry = _entry(base_url=f"http://127.0.0.1:{php_server}", **extra)
    permitted = {n.strip().lower() for n in (allowed or "").split(",")}
    manager = HTTPManager(timeout=5)
    names = [v for base in ("rest_route", "_method", "_fields", "per_page", "x_y") for v in _variants(base)]
    sent = refused = 0
    for name in names:
        for how in ("query", "form", "multipart", "odd type"):
            try:
                if how == "query":
                    result = manager.request(entry, "GET", f"/api?{name}=1")
                elif how == "multipart":
                    decoded = name.replace("+", " ").replace("%20", " ").replace("%00", "")
                    result = manager.request(
                        entry, "POST", "/api",
                        body=f'--B\r\nContent-Disposition: form-data; name="{decoded}"\r\n\r\n1\r\n--B--\r\n',
                        headers={"Content-Type": "multipart/form-data; boundary=B"},
                    )
                else:
                    content_type = "application/x-www-form-urlencoded"
                    if how == "odd type":
                        content_type += ", application/json"
                    result = manager.request(
                        entry, "POST", "/api", body=f"{name}=1", headers={"Content-Type": content_type},
                    )
            except SSHBrokerError:
                refused += 1
                continue
            sent += 1
            seen = json.loads(result["body"])
            keys = [k.lower() for k in seen["get"] + seen["post"]]
            for key in keys:
                assert key not in ("rest_route", "_method"), (how, name, seen)
                if key.startswith("_"):
                    assert key in permitted, (how, name, seen)
                if allowed:
                    assert key in permitted, (how, name, seen)
    assert sent and refused

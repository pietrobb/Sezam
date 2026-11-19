"""Review 1141a20 (AI broker, medium): M-AI1 non-ASCII reason phrase, M-AI2 routing names.

* M-AI1: http.client reads the status line and the headers as latin-1. The
  reason phrase and the returned headers were re-encoded as UTF-8 before
  redaction, so a credential with a non-ASCII character that the server
  echoed (as UTF-8 or as the latin-1 bytes http.client sent it in) no longer
  matched and reached the agent.
* M-AI2: the front-controller routing names were at once too broad ('q',
  's', 'action' are ordinary parameters of path-routed APIs, and the only
  way out was a complete allowed_params list) and incomplete ('p', 'url',
  'eID', ... route Craft, SilverStripe, TYPO3, ...). The list is longer now,
  and an entry for an API that routes by path only says so
  (path_routing_only) instead of listing every parameter it uses.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from sezam.mcp.http_api import HTTPManager
from sezam.mcp.ssh import SSHBrokerError
from tests.test_review7_http_php_params_h5 import _entry, _target

TOKEN = "pässwörd-t0k3n"


def _echo_server(encoding: str):
    class _Echo(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            raw = TOKEN.encode(encoding).decode("latin-1")  # the bytes, as http.server writes them
            self.send_response(403, f"Forbidden for {raw}")
            self.send_header("Location", f"/login?token={raw}")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), _Echo)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _leaks(text: str) -> bool:
    """The token, or the token as one wrong decoding shows it."""
    forms = {TOKEN}
    for encoding in ("utf-8", "latin-1"):
        for decoding in ("utf-8", "latin-1"):
            forms.add(TOKEN.encode(encoding).decode(decoding, "replace"))
    return any(form in text for form in forms) or "t0k3n" in text


@pytest.mark.parametrize("encoding", ["utf-8", "latin-1"])
def test_a_non_ascii_credential_echoed_in_the_status_line_or_a_header_is_redacted(encoding):
    server = _echo_server(encoding)
    try:
        entry = _entry(
            base_url=f"http://127.0.0.1:{server.server_address[1]}/wp-json",
            allow_plain_http="true",
            token=TOKEN,
        )
        result = HTTPManager(timeout=5).request(entry, "GET", "/wp/v2/posts")
    finally:
        server.shutdown()
        server.server_close()
    assert result["http_status"] == 403
    assert result["reason"].startswith("Forbidden for ")
    assert not _leaks(result["reason"]), result["reason"]
    assert not _leaks(result["headers"]["Location"]), result["headers"]


@pytest.mark.parametrize(
    "query",
    ["p=admin/settings", "page_id=2", "url=admin/security", "eID=dumpFile", "eid=x",
     "fc=module&module=x", "cl=admin_user", "fnc=delete", "d=admin", "do=admin",
     "ctl=user", "act=del", "view=users"],
)
def test_more_front_controller_names_are_refused_by_default(query):
    with pytest.raises(SSHBrokerError) as err:
        _target().check("GET", "/wp/v2/posts?" + query)
    assert err.value.code == "path_denied"
    with pytest.raises(SSHBrokerError):
        _target().check_body(query, {"Content-Type": "application/x-www-form-urlencoded"})


def test_an_api_that_routes_by_path_only_keeps_its_ordinary_parameters():
    target = _target(path_routing_only="true")
    query = "q=hello&s=draft&action=list&p=2&url=https%3A%2F%2Fexample.test&view=compact"
    assert target.check("GET", "/wp/v2/posts?" + query)[1] == "/wp-json/wp/v2/posts?" + query
    target.check_body("action=publish&q=x", {"Content-Type": "application/x-www-form-urlencoded"})
    # Not an allow-list: any other name still passes.
    assert target.check("GET", "/wp/v2/posts?per_page=5&author=1")[0] == "GET"


@pytest.mark.parametrize(
    ("query", "code"),
    [("rest_route=/wp/v2/users", "path_denied"), ("rest%2eroute=/x", "path_denied"),
     ("_method=DELETE", "method_denied"), ("+_method=DELETE", "method_denied"),
     ("_fields=id", "param_denied")],
)
def test_path_routing_only_never_lets_rest_route_overrides_or_underscore_names_through(query, code):
    with pytest.raises(SSHBrokerError) as err:
        _target(path_routing_only="true").check("GET", "/wp/v2/posts?" + query)
    assert err.value.code == code


def test_path_routing_only_takes_a_boolean():
    with pytest.raises(SSHBrokerError) as err:
        _target(path_routing_only="sometimes")
    assert err.value.code == "invalid_entry"
    with pytest.raises(SSHBrokerError):
        _target(path_routing_only="false").check("GET", "/wp/v2/posts?q=x")

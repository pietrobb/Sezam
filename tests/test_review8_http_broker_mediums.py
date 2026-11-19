"""Review a159e97 (AI broker, medium): reason phrase, routing names, double encoding.

* The server's HTTP reason phrase went to the agent unredacted: a server (or a
  proxy) that echoed the credential there leaked it.
* Only 'rest_route' was refused: front controllers that route by 'q', 'route',
  'r', 's', 'option', 'controller', ... let the agent leave
  allowed_path_prefixes. They are refused unless the entry lists them.
* '%252e' passed the path check and is '%2e' to a server that decodes twice.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from sezam.mcp.http_api import HTTPManager
from sezam.mcp.ssh import SSHBrokerError
from tests.test_review7_http_php_params_h5 import _entry, _target


class _EchoTokenReason(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        token = self.headers.get("Authorization", "").split()[-1]
        self.send_response(403, f"Forbidden for {token}")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


def test_the_reason_phrase_is_redacted():
    server = HTTPServer(("127.0.0.1", 0), _EchoTokenReason)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        entry = _entry(
            base_url=f"http://127.0.0.1:{server.server_address[1]}/wp-json",
            allow_plain_http="true",
        )
        result = HTTPManager(timeout=5).request(entry, "GET", "/wp/v2/posts")
    finally:
        server.shutdown()
        server.server_close()
    assert result["http_status"] == 403
    assert "t0k3n" not in result["reason"]
    assert result["reason"].startswith("Forbidden for ")


@pytest.mark.parametrize(
    "query",
    ["q=admin/people", "route=account/password", "r=user/admin", "s=/index/admin",
     "option=com_users", "controller=AdminEmployees", "c=admin&m=users", "action=delete",
     "Q=admin", "rou%74e=x", "+q=admin"],
)
def test_front_controller_routing_names_are_refused(query):
    with pytest.raises(SSHBrokerError) as err:
        _target().check("GET", "/wp/v2/posts?" + query)
    assert err.value.code == "path_denied"
    with pytest.raises(SSHBrokerError):
        _target().check_body(query, {"Content-Type": "application/x-www-form-urlencoded"})


def test_a_routing_name_the_entry_lists_passes():
    target = _target(allowed_params="q, per_page")
    assert target.check("GET", "/wp/v2/posts?q=hello&per_page=2")[1] == (
        "/wp-json/wp/v2/posts?q=hello&per_page=2"
    )
    with pytest.raises(SSHBrokerError):
        _target(allowed_params="rest_route").check("GET", "/wp/v2/posts?rest_route=/x")


@pytest.mark.parametrize(
    "path", ["/wp/v2/posts/%252e%252e/users", "/wp/v2/posts/%252E%252E/users",
             "/wp/v2/posts/%252fusers", "/wp/v2/posts/%25%32%65"],
)
def test_a_double_encoded_path_is_refused(path):
    with pytest.raises(SSHBrokerError) as err:
        _target().check("GET", path)
    assert err.value.code == "invalid_path"

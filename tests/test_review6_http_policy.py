"""Review main@d615826 (AI HTTP tool): method and path policy held only on the URL.

An entry allowing GET/POST under /wp/v2/posts let the agent reach any WordPress
endpoint with '?rest_route=/wp/v2/users' (PHP also reads 'rest.route' and
'rest[route' that way), turn POST into DELETE with '_method=DELETE' in the
query or body, and walk out of the prefix with '..;/' (Tomcat/Spring drop
';…' path parameters).
"""

from __future__ import annotations

import pytest

from sezam.mcp.http_api import HTTPTarget
from sezam.mcp.ssh import SSHBrokerError


def _target() -> HTTPTarget:
    fields = {
        "base_url": "https://api.example.test/wp-json",
        "auth_header": "Authorization: Bearer {token}",
        "token": "t0k3n",
        "allowed_methods": "GET, POST",
        "allowed_path_prefixes": "/wp/v2/posts",
    }
    return HTTPTarget.from_entry({"fields": [{"key": k, "value": v} for k, v in fields.items()]})


@pytest.mark.parametrize(
    "path",
    [
        "/wp/v2/posts?rest_route=/wp/v2/users",
        "/wp/v2/posts?REST_ROUTE=/wp/v2/users",
        "/wp/v2/posts?rest.route=/wp/v2/users",
        "/wp/v2/posts?rest%5Froute=/wp/v2/users",
        "/wp/v2/posts?rest[route=/wp/v2/users",
        "/wp/v2/posts?a=1&rest+route=/wp/v2/users",
    ],
)
def test_rest_route_in_the_query_is_refused(path):
    with pytest.raises(SSHBrokerError) as err:
        _target().check("GET", path)
    assert err.value.code in ("path_denied", "invalid_path")  # a raw '[' is not a query char


@pytest.mark.parametrize(
    "path",
    ["/wp/v2/posts/1?_method=DELETE", "/wp/v2/posts/1?_METHOD=delete", "/wp/v2/posts/1?%5Fmethod=DELETE"],
)
def test_method_override_in_the_query_is_refused(path):
    with pytest.raises(SSHBrokerError) as err:
        _target().check("POST", path)
    assert err.value.code == "method_denied"


@pytest.mark.parametrize(
    "body",
    [
        "_method=DELETE",
        "title=x&_method=DELETE",
        "title=x&%5Fmethod=DELETE",
        '{"title": "x", "_method": "DELETE"}',
        'Content-Disposition: form-data; name="_method"\r\n\r\nDELETE',
    ],
)
def test_method_override_in_the_body_is_refused(body):
    with pytest.raises(SSHBrokerError) as err:
        _target().check_body(body)
    assert err.value.code == "method_denied"


def test_a_field_merely_ending_in_method_is_allowed():
    _target().check_body('{"payment_method": "card", "shipping_method": "dhl"}')
    _target().check_body("payment_method=card")


@pytest.mark.parametrize("path", ["/wp/v2/posts/..;/users", "/wp/v2/posts;x=1", "/wp/v2/posts/%3B/users"])
def test_path_parameters_are_refused(path):
    with pytest.raises(SSHBrokerError) as err:
        _target().check("GET", path)
    assert err.value.code in ("invalid_path", "path_denied")


def test_a_reflected_secret_is_redacted_in_hex_and_reversed():
    from sezam.mcp.redact import Redactor

    secret = b"abcd EFGH 1234 ijkl"
    redactor = Redactor([secret])
    for leaked in (secret.hex(), secret.hex().upper(), secret[::-1].decode()):
        assert redactor.redact(f"<?php echo {leaked};".encode()) == b"<?php echo [REDACTED];"


def test_an_ordinary_request_still_passes():
    assert _target().check("GET", "/wp/v2/posts?per_page=5&status=publish") == (
        "GET", "/wp-json/wp/v2/posts?per_page=5&status=publish"
    )

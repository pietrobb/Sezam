"""Review 7c10379 (R7-H, AI table: the d615826 / H5 body override check, bypassed).

The HTTP broker decoded a body's JSON keys only for 'application/json' and
'*+json'. Laravel reads a body as JSON when its Content-Type merely contains
'/json' or '+json' ('text/json', 'text/plain; x=/json'), and the regex for
'_method' in a body misses '"_m\\u0065thod"'. Such a body was checked as a
form: an item allowed only POST could delete. The keys of any JSON-typed body,
and of any body that is a JSON object, are now decoded and checked.
"""

from __future__ import annotations

import pytest

from sezam.mcp.ssh import SSHBrokerError
from tests.test_review7_http_php_params_h5 import _target

OVERRIDE = '{"_m\\u0065thod": "DELETE", "title": "x"}'


@pytest.mark.parametrize(
    "content_type",
    [
        "text/json",
        "text/plain; x=/json",
        "application/x-json",
        "application/json-patch",
        "application/x-www-form-urlencoded",
        None,
    ],
)
def test_an_escaped_override_key_is_refused_whatever_the_type_says(content_type):
    headers = {"Content-Type": content_type} if content_type else {}
    with pytest.raises(SSHBrokerError) as err:
        _target().check_body(OVERRIDE, headers)
    assert err.value.code == "method_denied"


def test_an_escaped_routing_key_is_refused_in_a_json_typed_body():
    with pytest.raises(SSHBrokerError) as err:
        _target().check_body('{"rest_r\\u006fute": "/wp/v2/users"}', {"Content-Type": "text/json"})
    assert err.value.code == "path_denied"


def test_plain_json_and_form_bodies_still_pass():
    target = _target()
    target.check_body('{"title": "x", "status": "draft"}', {"Content-Type": "text/json"})
    target.check_body("title=x&status=draft", {"Content-Type": "application/x-www-form-urlencoded"})
    target.check_body("just text", {"Content-Type": "text/plain"})


def test_a_deeply_nested_body_is_no_crash():
    deep = "[" * 100_000 + "]" * 100_000
    for headers in ({"Content-Type": "application/json"}, {}):
        _target().check_body(deep, headers)

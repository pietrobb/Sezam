"""Review c78fd19 R13-11: a certificate renewal for one ssh client no
longer breaks another client that was just offered the previous one.

Two clients use the same AI SSH CA entry. Client A lists identities and
gets certificate 1; near its expiry client B lists and gets certificate 2,
which replaced 1 in the agent. A's sign request with 1 (still valid) then
failed, so A asked again and got yet another certificate.
"""

# ruff: noqa: F811  (pytest fixtures imported from the S3a tests)
from __future__ import annotations

import time

from sezam.mcp import ssh_agent
from sezam.mcp.ssh_agent import SSH_AGENT_FAILURE
from sezam.vault import ai_access
from tests.test_ai_s2a_ssh_agent import _sign_request
from tests.test_ai_s3a_ssh_ca import (  # noqa: F401  (fixtures)
    FAILURE,
    _cert_userauth,
    _certs,
    ca_pem,
    service,
    vault,
)


def _signs(service, blob) -> bool:
    return service.handle(_sign_request(blob, _cert_userauth(blob)))[0] != SSH_AGENT_FAILURE


def test_a_renewal_for_one_client_keeps_the_others_certificate_signable(service, monkeypatch):
    now = time.time()
    first = _certs(service)[0][0]  # client A lists
    monkeypatch.setattr(time, "time", lambda: now + 600 - ssh_agent.CERT_RENEW_SECONDS + 1)
    second = _certs(service)[0][0]  # client B lists: renewed
    assert second != first
    assert _signs(service, first)  # A finishes with the certificate it was offered
    assert _signs(service, second)
    assert _certs(service)[0][0] == second  # no third certificate for A
    monkeypatch.setattr(time, "time", lambda: now + 601)
    assert service.handle(_sign_request(first, _cert_userauth(first))) == FAILURE
    assert _signs(service, second)


def test_an_earlier_certificate_still_ends_with_the_kill_switch(vault, service, monkeypatch):
    now = time.time()
    first = _certs(service)[0][0]
    monkeypatch.setattr(time, "time", lambda: now + 600 - ssh_agent.CERT_RENEW_SECONDS + 1)
    second = _certs(service)[0][0]
    ai_access.disable(vault, "test")
    ai_access.enable(vault, "test")  # a new epoch
    for blob in (first, second):
        assert service.handle(_sign_request(blob, _cert_userauth(blob))) == FAILURE

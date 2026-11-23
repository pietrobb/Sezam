"""docs/ROOT_CAUSE_PLAN.md S4 (INV-3), review e443cbc goal #428: a pulled
object counts as signed only when the values the client keeps are exactly
the ones its signature covers.

Found by the state machine rule ``server_lies_in_a_field`` on the signed
fields: the desktop packed is_deleted and version with ``struct.pack``, so a
server sending is_deleted 1000 crashed the pull (``struct.error``) instead of
the object being refused. The web packed ``is_deleted ? 1 : 0`` and
``(version || 1) >>> 0`` and the phone a truncating Uint8List/ByteData, so a
version of 2**32 + 1 (or 0) verified as 1 and was kept as the server sent it.
"""

from __future__ import annotations

import hashlib

from nacl.signing import SigningKey

from sezam.vault.sync_client import SyncClient
from sezam.vault.sync_push import PushMixin
from tests.test_review_web import _function, _run_source, pytestmark  # noqa: F401

ID = "01HZZZZZZZZZZZZZZZZZZZZZZZ"
PAYLOAD_HASH = hashlib.sha256(b"x").hexdigest()


class _Device:
    """The parts of SyncClient _verify_object_signature asks."""

    _user_id = "01HUSERZZZZZZZZZZZZZZZZZZZ"
    _build_signature_payload = staticmethod(PushMixin._build_signature_payload)

    def __init__(self, pk):
        self._pk = pk

    def _signer_id(self, obj):
        return self._user_id

    def _get_signing_pks(self, _user):
        return [self._pk]

    def _is_retired(self, *_):
        return False

    def _log_retired_key(self, *_):
        return False


def _signed(sk, **values) -> dict:
    canonical = PushMixin._build_signature_payload(
        id=ID, object_type="node", parent_ref=None, target_user_id=None,
        is_deleted=values["is_deleted"], version=values["version"], payload_hash=PAYLOAD_HASH)
    return {"id": ID, "object_type": "node", "payload": "eA==", "payload_hash": PAYLOAD_HASH,
            "client_signature": sk.sign(canonical).signature.hex(), **values}


def test_the_desktop_refuses_a_value_its_signature_does_not_cover():
    sk = SigningKey.generate()
    device = _Device(bytes(sk.verify_key))
    honest = _signed(sk, is_deleted=1, version=1)
    assert SyncClient._verify_object_signature(device, honest)
    for lie in ({"is_deleted": 1000}, {"is_deleted": 257}, {"is_deleted": -1}, {"is_deleted": "1"},
                {"version": 2**32 + 1}, {"version": -1}, {"version": "1"}):
        assert SyncClient._verify_object_signature(device, {**honest, **lie}) is False, lie


def test_the_web_refuses_a_value_its_signature_does_not_cover():
    script = """(() => {
      const seen = [];
      const sodium = { crypto_sign_verify_detached: (_sig, canonical) => {
        seen.push(Array.from(canonical).join(','));
        return seen[seen.length - 1] === seen[0];
      } };
      const honest = { id: '%s', object_type: 'node', is_deleted: 1, version: 1,
                       payload_hash: '%s', client_signature: '00'.repeat(64) };
      const out = { honest: verifyObjectSignature(honest, new Uint8Array(32), sodium) };
      for (const [name, lie] of Object.entries({
          deleted_257: { is_deleted: 257 }, deleted_str: { is_deleted: '1' },
          version_wraps: { version: 2 ** 32 + 1 }, version_zero: { version: 0 },
          version_negative: { version: -1 }, version_str: { version: '1' } })) {
        out[name] = verifyObjectSignature({ ...honest, ...lie }, new Uint8Array(32), sodium);
      }
      return out;
    })()""" % (ID, PAYLOAD_HASH)
    result = _run_source(
        _function("hexToBytes") + _function("idBytes26") + _function("verifyObjectSignature"), script)
    assert result.pop("honest") is True
    assert result == dict.fromkeys(result, False), result

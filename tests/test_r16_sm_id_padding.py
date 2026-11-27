"""R16-Z SM3 (INV-3), deep state machine run on 736ade3: a 26-byte id field
of a signed or sealed value holds exactly one id.

Every client wrote an id as ``id.ljust(26, NUL)[:26]`` (web ``padEnd(26,
'\\0').slice(0, 26)``, phone ``padRight``/``_padToLength``): an id longer than
26 characters was cut to its first 26. A server appending one character to an
entry's parent_ref (``01M84...WDE`` -> ``01M84...WDEx``) kept the creator's
signature valid; the device kept the parent it was sent, found no such folder
and showed the entry below the root, while every other device had it in its
folder. The same holds for id and target_user_id (a second copy of an entry,
a key sealed "to" a made-up account) and for the AAD of a sealed blob.
"""

from __future__ import annotations

import hashlib

import pytest
from nacl.signing import SigningKey

from sezam.key_vouchers import voucher_message
from sezam.models import ulid_to_bytes
from sezam.vault.reseed import reseed_message
from sezam.vault.sync_client import SyncClient
from sezam.vault.sync_common import key_rotation_message
from sezam.vault.sync_push import PushMixin
from tests.test_inv3_signed_values_exact import _Device
from tests.test_review_web import _function, _run_source, pytestmark  # noqa: F401

ID = "01M84VW3C2YKNF1AHKTC84CS4C"
FOLDER = "01M84VVY89SQQ6B0MXD8SBQWDE"
USER = "01M84VVZ6FGBBBNETGYZRCY153"
PAYLOAD_HASH = hashlib.sha256(b"x").hexdigest()
LONGER = {"x": "x", "nul": "\x00", "two": "AB"}


def _entry(sk) -> dict:
    canonical = PushMixin._build_signature_payload(
        id=ID, object_type="entry", parent_ref=FOLDER, target_user_id=USER,
        is_deleted=0, version=1, payload_hash=PAYLOAD_HASH)
    return {"id": ID, "object_type": "entry", "parent_ref": FOLDER, "target_user_id": USER,
            "is_deleted": 0, "version": 1, "payload": "eA==", "payload_hash": PAYLOAD_HASH,
            "client_signature": sk.sign(canonical).signature.hex()}


@pytest.mark.parametrize("field", ["parent_ref", "id", "target_user_id"])
def test_the_desktop_refuses_an_id_longer_than_its_signature(field):
    sk = SigningKey.generate()
    device = _Device(bytes(sk.verify_key))
    honest = _entry(sk)
    assert SyncClient._verify_object_signature(device, honest)
    for name, tail in LONGER.items():
        lie = {**honest, field: honest[field] + tail}
        assert SyncClient._verify_object_signature(device, lie) is False, (field, name)


def test_every_desktop_id_field_takes_one_id_or_refuses():
    key = bytes(32)
    for longer in (ID + "x", ID + "\x00", "A\x00"):
        with pytest.raises(ValueError):
            ulid_to_bytes(longer)
        with pytest.raises(ValueError):
            PushMixin._id_to_bytes(longer)
        with pytest.raises(ValueError):
            key_rotation_message(longer, key, key, key, key)
        with pytest.raises(ValueError):
            voucher_message(longer, key, [])
        with pytest.raises(ValueError):
            reseed_message(bytes(32), longer, "u", key, key, 1)
    assert ulid_to_bytes(ID) == ID.encode()
    assert ulid_to_bytes("short") == b"short" + b"\x00" * 21


def test_the_web_refuses_an_id_longer_than_its_signature():
    script = """(() => {
      const seen = [];
      const sodium = { crypto_sign_verify_detached: (_sig, canonical) => {
        seen.push(Array.from(canonical).join(','));
        return seen[seen.length - 1] === seen[0];
      } };
      const honest = { id: '%s', object_type: 'entry', parent_ref: '%s', target_user_id: '%s',
                       is_deleted: 0, version: 1, payload_hash: '%s', client_signature: '00'.repeat(64) };
      const out = { honest: verifyObjectSignature(honest, new Uint8Array(32), sodium) };
      for (const field of ['id', 'parent_ref', 'target_user_id']) {
        for (const [name, tail] of Object.entries({ x: 'x', nul: '\\0', two: 'AB' })) {
          let verdict;
          try { verdict = verifyObjectSignature({ ...honest, [field]: honest[field] + tail },
                                                new Uint8Array(32), sodium); }
          catch (e) { verdict = 'threw ' + e.message; }
          out[field + '_' + name] = verdict;
        }
      }
      return out;
    })()""" % (ID, FOLDER, USER, PAYLOAD_HASH)
    source = "".join(_function(name) for name in ("hexToBytes", "idBytes26", "signedObjectMessage",
                                                "verifyObjectSignature"))
    result = _run_source(source, script)
    assert result.pop("honest") is True
    assert result == dict.fromkeys(result, False), result


def test_every_web_id_field_takes_one_id_or_refuses():
    script = """(() => {
      const out = {};
      for (const [name, f] of Object.entries({
          aad_object: () => buildAAD(1, '%s', '%s' + 'x', 1),
          aad_dek: () => buildAAD(1, '%s' + '\\0', '%s', 1),
          envelope_dek: () => idBytes26('%s' + 'AB'),
          rotation: () => keyRotationMessage('%s' + 'x', new Uint8Array(32), new Uint8Array(32),
                                             new Uint8Array(32), new Uint8Array(32)),
          non_ascii: () => idBytes26('\\u010d') })) {
        try { f(); out[name] = 'accepted'; } catch (e) { out[name] = false; }
      }
      out.exact = Array.from(idBytes26('%s')).join(',') === Array.from(new TextEncoder().encode('%s')).join(',');
      out.short = Array.from(idBytes26('ab')).join(',') === [97, 98, ...new Array(24).fill(0)].join(',');
      return out;
    })()""" % (FOLDER, ID, FOLDER, ID, FOLDER, USER, ID, ID)
    source = "".join(_function(name) for name in ("idBytes26", "buildAAD", "keyRotationMessage"))
    result = _run_source(source, "const ENVELOPE_ALG = 1, SCHEMA_VERSION = 1;\n" + script)
    assert result.pop("exact") is True and result.pop("short") is True
    assert result == dict.fromkeys(result, False), result

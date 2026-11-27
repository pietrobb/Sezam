"""Review c02cc47 R17-N1 (S4 style, INV-2/INV-3): every proof of a copy
covers every field its signature covers.

The voucher entry named (id, version, payload_hash) and against_held compared
the payload alone, while the signature covers the type, parent, target and
tombstone flag too: a server re-signed a held or vouched version with another
parent or as deleted and every client took it as the same copy.

``key_vouchers.SIGNED_FIELDS`` is the register: signed_message takes exactly
those fields, and tests/vectors/signed_fields.json gives each one another
value. For each, the signed message, the voucher entry and the held-copy
comparison change, on the desktop and the web here and on the phone in
mobile/test/r17_n1_signed_fields_test.dart; the voucher entry also changes
with the signer and the key. A new signed field fails here until every proof
covers it.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path

from sezam import key_vouchers
from tests.test_review_web import _run, pytestmark  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]
V = json.loads((ROOT / "tests" / "vectors" / "signed_fields.json").read_text(encoding="utf-8"))


def _variants() -> list[tuple[str, dict]]:
    """(label, object) for the base object and each field changed."""
    out = [("base", dict(V["object"]))]
    for field in V["fields"]:
        out.append((field, {**V["object"], field: V["other"][field]}))
        if field in V["none"]:
            out.append((f"{field}=none", {**V["object"], field: None}))
    return out


def _all_distinct(values: dict) -> None:
    seen: dict = {}
    for label, value in values.items():
        assert value is not None, label
        assert value not in seen, f"{label} gives the same proof as {seen.get(value)}"
        seen[value] = label


def test_the_register_is_what_the_signature_covers():
    assert tuple(V["fields"]) == key_vouchers.SIGNED_FIELDS
    assert tuple(inspect.signature(key_vouchers.signed_message).parameters) == key_vouchers.SIGNED_FIELDS
    # One builder: the desktop signs and verifies through it.
    from sezam.vault import sync_push

    assert "key_vouchers.signed_message(" in inspect.getsource(sync_push.PushMixin._build_signature_payload)
    web = (ROOT / "web" / "static" / "js" / "app.js").read_text(encoding="utf-8")
    message = web.split("function signedObjectMessage(", 1)[1].split("\n}\n", 1)[0]
    for field in key_vouchers.SIGNED_FIELDS:
        assert f"obj.{field}" in message, f"the web's signed message leaves out {field}"


def _desktop_proofs(obj: dict, signer: str, key: bytes) -> dict:
    from sezam.vault.sync_vouchers import _local_key

    fields = {name: obj[name] for name in key_vouchers.SIGNED_FIELDS}
    return {
        "message": key_vouchers.signed_message(**fields),
        "entry": key_vouchers.object_entry(obj, signer, key),
        # Capability review 677: an identity rotation of a vault from before
        # held_signed carries a served copy forward when its id and this key
        # match the copy held (_rotation_vouchers / _held_locally).
        "legacy": (obj["id"], _local_key(obj)),
    }


def test_every_desktop_proof_covers_every_signed_field():
    signer, key = V["signer_id"], bytes.fromhex(V["signing_pk"])
    proofs = {label: _desktop_proofs(obj, signer, key) for label, obj in _variants()}
    for kind in ("message", "entry", "legacy"):
        _all_distinct({label: p[kind] for label, p in proofs.items()})
    # The entry names the signer's account and key too.
    entries = {label: p["entry"] for label, p in proofs.items()}
    entries["other signer"] = key_vouchers.object_entry(V["object"], V["other_signer_id"], key)
    entries["other key"] = key_vouchers.object_entry(V["object"], signer, bytes.fromhex(V["other_signing_pk"]))
    _all_distinct(entries)


def test_every_web_proof_covers_every_signed_field():
    result = _run(
        ["idBytes26", "hexToBytes", "signedObjectMessage", "keyVoucherObjectEntry", "heldCopyKey"],
        f"""(() => {{
        const v = {json.dumps(V)};
        const variants = {json.dumps(_variants())};
        const sodium = globalThis.sodium;
        const key = hex(v.signing_pk);
        const out = {{}};
        for (const [label, obj] of variants) {{
            out[label] = {{
                message: bytesToHex(signedObjectMessage(obj)),
                entry: JSON.stringify(keyVoucherObjectEntry(obj, v.signer_id, key, sodium)),
                // against_held compares (id, version, heldCopyKey) of the copies.
                held: JSON.stringify([obj.id, obj.version, heldCopyKey(obj)]),
            }};
        }}
        out.signer = JSON.stringify(keyVoucherObjectEntry(v.object, v.other_signer_id, key, sodium));
        out.key = JSON.stringify(keyVoucherObjectEntry(v.object, v.signer_id, hex(v.other_signing_pk), sodium));
        return out;
    }})()""",
    )
    signer, key = result.pop("signer"), result.pop("key")
    for kind in ("message", "entry", "held"):
        _all_distinct({label: p[kind] for label, p in result.items()})
    _all_distinct({"base": result["base"]["entry"], "other signer": signer, "other key": key})
    # The web builds the very entry the desktop does.
    desktop = key_vouchers.object_entry(V["object"], V["signer_id"], bytes.fromhex(V["signing_pk"]))
    assert json.loads(result["base"]["entry"]) == list(desktop)

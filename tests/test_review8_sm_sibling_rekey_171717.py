"""Review a159e97 state machine, seed 171717: two re-keys of one folder key.

Two devices of the admin re-keyed the same folder key and both batches landed,
so two archives retire it. Pull binding moved the folder to whichever
successor arrived last: device A and a new device C took one key, device B and
the folder's items stayed on the other, and the new-device check (archives
withheld vs honest) disagreed. The scripted run below is the shrunk example;
every device must now bind the folder to the key its items are sealed under.
"""

from __future__ import annotations

import sys

from sezam.crypto.aead import parse_envelope
from sezam.models import bytes_to_ulid
from tests import test_sync_state_machine as sm
from tests.test_sync_state_machine import SecondAdminMachine, loopback_server  # noqa: F401


class _Draws:
    """Fixed answers for the rules' draws (first element otherwise)."""

    def __init__(self, **answers):
        self.answers = answers

    def draw(self, strategy, label=None):
        if label in self.answers:
            value = self.answers[label]
            return value(list(strategy.elements)) if callable(value) else value
        if label and label.startswith("keep "):
            return "server"
        elements = getattr(strategy, "elements", None)
        return list(elements)[0] if elements is not None else False


def _sealed_under(payload: bytes, object_type: str) -> str:
    if object_type == "entry":
        payload = payload[4:4 + int.from_bytes(payload[:4], "big")]
    return bytes_to_ulid(parse_envelope(payload).dek_id)


def test_every_device_binds_the_folder_to_the_key_its_items_use(loopback_server, monkeypatch):  # noqa: F811
    monkeypatch.setattr(sys.modules[sm.__name__], "coverage_event", lambda _name: None)
    SecondAdminMachine.server = loopback_server
    m = SecondAdminMachine()
    try:
        m6, m7 = sorted(m.members, key=lambda u: m.members[u].name)[:2]
        f1 = m._folders("A")[0]
        m.server_swaps_a_member_key(_Draws(device="A", member=m6, folder=f1), "read")
        m.settle(_Draws())
        m.open_second_process(_Draws(device="A"))
        m.server_lies_into_full_resync(_Draws(device="A"), "check_token", True)
        m.second_process_pull(_Draws(device="A"))
        m.gc_tombstones()
        m.delete_folder(_Draws(device="B", folder=f1))
        m.server_lies_about_users(_Draws(device="B"), "member_admin")
        m.change_password(_Draws(device="A"), None)
        m.revoke(_Draws(device="B", member=m7), "before")
        m.gc_tombstones()
        m.abandon_rekey(_Draws(device="B"))
        m.open_web_tab()
        m.second_process_pull(_Draws(device="A"))
        m.revoke(_Draws(device="B", member=m6), "after")
        m.push(_Draws(device="A"), None)
        m.restore_from_trash(_Draws(
            device="B", **{"trash item": lambda items: next(i for i in items if i["id"] == f1)},
        ))
        m.connect_another_device()
        m.member_sync(_Draws(member=m7))
        m.full_resync(_Draws(device="B"))
        m._settle(lambda _o: "server")  # before: the new-device check failed here

        content_keys = {
            _sealed_under(bytes(o["payload"]), o["object_type"])
            for o in m.db._storage["vault_objects"]
            if o.get("parent_ref") == f1 and o["object_type"] in ("node", "entry")
            and not o["is_deleted"]
        }
        assert len(content_keys) == 1
        bound = {
            name: dev.vault.db.fetchone("SELECT dek_id FROM nodes WHERE id = ?", (f1,))["dek_id"]
            for name, dev in m.devices.items()
        }
        assert set(bound.values()) == content_keys, bound
    finally:
        m.teardown()

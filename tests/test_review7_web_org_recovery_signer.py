"""Review 7c10379 (web, medium): org recovery decided by the unsigned owner_id.

owner_id is the server's ACL metadata. A server naming a colleague the owner
of one of our DEKs had the recovery leave it out of the rewrap, so it stayed
under the KEK the recovery replaced and nothing opened it again; naming us the
owner of a colleague's DEK stopped the recovery. Ours is now what our KEK
opened or what we signed (the verified signature_user_id).
"""

from __future__ import annotations

import json

from tests.test_review_web import _run, pytestmark  # noqa: F401


def _own(pulled: list[dict], opened: list[str]):
    script = f"""(() => {{
      const syncObjects = {{}};
      for (const obj of {json.dumps(pulled)}) syncObjects[obj.id] = syncObjectRecord(obj);
      return ownKekDekIdsToRewrap(syncObjects, {json.dumps(opened)}, 'ME');
    }})()"""
    return _run(["syncObjectRecord", "ownKekDekIdsToRewrap"], script)


def _dek(dek_id: str, signer: str, owner: str) -> dict:
    return {"id": dek_id, "object_type": "dek", "signature_user_id": signer, "owner_id": owner,
            "version": 1, "is_deleted": 0, "payload": ""}


def test_our_dek_the_server_says_is_a_colleagues_is_still_rewrapped():
    pulled = [_dek("MINE", "ME", "ME"), _dek("ALSO_MINE", "ME", "BOB"), _dek("THEIRS", "BOB", "BOB")]
    assert sorted(_own(pulled, ["MINE", "ALSO_MINE"])) == ["ALSO_MINE", "MINE"]


def test_our_signed_dek_the_server_hides_as_a_colleagues_stops_recovery_if_unopened():
    """Signed by us but not opened: rewrapping the rest would strand it."""
    pulled = [_dek("MINE", "ME", "ME"), _dek("BROKEN", "ME", "BOB")]
    assert _own(pulled, ["MINE"]) is None


def test_a_colleagues_dek_the_server_says_is_ours_does_not_stop_recovery():
    pulled = [_dek("MINE", "ME", "ME"), _dek("THEIRS", "BOB", "ME")]
    assert _own(pulled, ["MINE"]) == ["MINE"]

"""Review e443cbc P2 (mutant B4): an append carries only the uploader's own
records. B holds a record the admin signed and never pushed (an access grant
for B) and appends it together with its own rotation; each record replays,
so only the server's own-records rule refuses it."""
import tests.test_inv2_restore_within_append as T
from sezam import teamlog

IDS = T.IDS


def test_a_member_cannot_append_the_admins_record_with_its_own():
    h = T.Honest(T.Keys())
    assert h._commit("A", [("member.add", "A", {
        "user_id": IDS["B"], "signing_pk": h.current("B").pk,
        "encryption_pk": h.current("B").enc, "role": "member"})])
    folder = T.FOLDERS[0]
    assert h._commit("A", [("folder.key", "A", {"folder": folder, "gen": 0, "dek_id": T._dek(1), "prev_dek_id": None})])
    grant = teamlog.next_body(h.state, "access.set", IDS["A"], {"folder": folder, "user_id": IDS["B"], "level": "write"})
    grant = teamlog.sign_record(grant, h.current("A").sk)
    state = teamlog.apply_record(h.state, grant)
    new = h.keys.new()
    _, _, payload = T._rotation(state, "B", new)
    own = teamlog.sign_record(teamlog.next_body(state, "member.keys", IDS["B"], payload), h.current("B").sk)
    teamlog.apply_record(state, own)  # both replay

    T.REFUSALS.clear()
    assert not T.append(h.db, [grant, own], IDS["B"], (new.pk, new.enc))
    assert "must be your own" in T.REFUSALS[-1]["message"]
    assert T.append(h.db, [grant], IDS["A"]), T.REFUSALS[-1:]  # the admin's own append

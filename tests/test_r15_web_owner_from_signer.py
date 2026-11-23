"""Review e443cbc, goal #439 (INV-3): the web asks who signed a copy, never
the server's unsigned PullObject.owner_id.

resolveInheritedPersonalDekId walked past an unreadable folder whose
owner_id named another account, so a server that renamed the owner of this
account's own unreadable folder had a new item sealed outside the personal
tree. migrateLegacyPersonalDescendants re-sealed what owner_id gave to this
account and skipped what it gave to another. A personal object is signed by
its author only (TL7): the verified signer decides both.
"""

from __future__ import annotations

from tests.test_review_web import _function, _run_source, pytestmark  # noqa: F401

ME = "01ME000000000000000000000A"
ADMIN = "01AD000000000000000000000A"


def _state(root_owner: str, root_signer: str) -> dict:
    return {
        "userId": ME,
        "deks": {"PDEK": "x"},
        "rootDekId": "ROOT_DEK",
        "nodes": {
            "ROOT": {"id": "ROOT", "parent_ref": None, "_undecryptable": True,
                     "owner_id": root_owner, "signer": root_signer},
            "TEAM": {"id": "TEAM", "parent_ref": "ROOT", "owner_id": ADMIN, "signer": ADMIN},
            "MINE": {"id": "MINE", "parent_ref": None, "personal": True, "dekId": "PDEK",
                     "owner_id": ME, "signer": ME},
        },
    }


RESOLVE = """(() => {
  try { return resolveInheritedPersonalDekId('TEAM') ?? 'none'; }
  catch (e) { return e.message; }
})()"""


def test_own_unreadable_folder_the_server_gives_to_another_fails_closed():
    source = _function("resolveInheritedPersonalDekId")
    assert _run_source(source, RESOLVE, _state(root_owner=ADMIN, root_signer=ME)) == (
        "Parent folder is unavailable.")


def test_another_accounts_unreadable_folder_the_server_gives_to_me_is_walked_past():
    source = _function("resolveInheritedPersonalDekId")
    assert _run_source(source, RESOLVE, _state(root_owner=ME, root_signer=ADMIN)) == "none"


def _migrate(entry_owner: str, entry_signer: str) -> int:
    source = _function("resolveInheritedPersonalDekId") + "\n" + _function("migrateLegacyPersonalDescendants")
    state = _state(root_owner=ADMIN, root_signer=ADMIN)
    state["allNodes"] = list(state["nodes"].values())
    state["allEntries"] = [{"id": "E", "parent_ref": "MINE", "dekId": "ROOT_DEK", "version": 1,
                            "owner_id": entry_owner, "signer": entry_signer}]
    script = """(async () => {
      let pushed = 0;
      storedPayload = () => ({});
      pushVaultObjectLocked = async () => { pushed++; };
      await migrateLegacyPersonalDescendants();
      return pushed;
    })()"""
    return _run_source(source, script, state)


def test_migration_repairs_what_this_account_signed_whatever_owner_id_says():
    assert _migrate(entry_owner=ADMIN, entry_signer=ME) == 1


def test_migration_never_reseals_what_another_signed_though_owner_id_names_me():
    assert _migrate(entry_owner=ME, entry_signer=ADMIN) == 0


def test_every_decrypted_copy_carries_its_verified_signer():
    pull = _function("pullAndBuildTreeLocked")
    pushes = [line for line in pull.splitlines() if "decryptedNodes.push(" in line
              or "decryptedEntries.push(" in line]
    assert len(pushes) == 7
    tail = pull.split("decryptedEntries.push({\n", 1)[1].split("});", 1)[0]
    # R16-H2: the signed fields come from signedFields(obj), after the content.
    signed = pull.split("const signedFields = obj => ({", 1)[1].split("});", 1)[0]
    assert "signer: verifiedSigner(obj)" in signed
    assert all("...signedFields(obj)" in line or "signer: verifiedSigner(obj)" in line
               for line in pushes[:-1])
    assert "signer: verifiedSigner(obj)" in tail
    assert "candidateSyncObjects[obj.id]?.signer" in pull


def test_web_owner_id_decides_nothing_any_more():
    from tests.test_unsigned_fields import KNOWN_CLIENT_DECIDES

    assert ("web", "PullObject.owner_id") not in KNOWN_CLIENT_DECIDES

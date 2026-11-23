"""Review 18c300f R16-M1, web: an edit racing a pull overwrote the pulled version.

The page took the base of an edit (the server copy it replaces) when it sent
it, not when it was made. A pull that brought another device's version while
the edit was sealed (or waited for the sync lock) became its base, and the
edit was renumbered over it: the other device's change was lost and no
conflict was shown. The edit now names the copy it was made on.
"""

from __future__ import annotations

from tests.test_review_web import APP, _function, _run, requires_node

pytestmark = requires_node

SCRIPT = r"""
(async () => {
  let pushed = null;
  globalThis.sealVaultObject = async (obj) => {
    await Promise.resolve();
    // the periodic pull, meanwhile: another device's version 2
    state.syncObjects.E = { id: 'E', object_type: 'entry', version: 2, payload_hash: 'h2' };
    return { id: obj.id, object_type: obj.object_type, version: obj.version, payload: 'p' };
  };
  globalThis.pushEncryptedVaultObject = async (obj) => { pushed = withWebBase(obj); };
  await pushVaultObject({ id: 'E', object_type: 'entry', version: 2, payloadData: {} });
  return { version: pushed.version, base_version: pushed.base_version, base: pushed.base_payload_hash };
})()
"""


def test_an_edit_names_the_copy_it_was_made_on():
    functions = ["pushVaultObject", "webBase", "withWebBase"]
    if "function webBaseNow(" in APP:
        functions.append("webBaseNow")
    state = {"outbox": {}, "syncObjects": {"E": {"id": "E", "object_type": "entry", "version": 1,
                                                 "payload_hash": "h1"}}}
    result = _run(functions, SCRIPT, state)
    # version 2 on base 1: the server holds 2, so it is a conflict the user sees
    assert result == {"version": 2, "base_version": 1, "base": "h1"}


def test_a_delete_names_the_copy_it_was_made_on():
    source = _function("handleDeleteConfirm")
    assert "webBaseNow(entryId)" in source
    assert source.index("webBaseNow(entryId)") < source.index("await sha256hexBytes")

"""Review c02cc47 R17-N1, web: the checkpoint's state hash covers a held
object's parent and deleted flag, and a checkpoint from before (no state_v)
is compared by its own formula (tests/test_r17_n1_state_hash_signed_fields.py
for the desktop)."""

from __future__ import annotations

from tests.test_review_web import APP, _run, pytestmark  # noqa: F401

FUNCTIONS = [
    "liveSyncObjects", "checkPulledStateAgainstCheckpoint", "computeWebStateHash",
]

SCRIPT = """
(async () => {
    const _sodium = sodium;
    const obj = (id, parent, deleted) => ({
        id: id.padEnd(26, '0'), version: 1, is_deleted: deleted ? 1 : 0, parent_ref: parent,
        payload: Buffer.from(id).toString('base64'),
    });
    const map = (...objs) => Object.fromEntries(objs.map(o => [o.id, o]));
    async function pulledOf(objects, legacy) {
        const hashes = async (old) => ({
            stateHash: await computeWebStateHash(objects, _sodium, old),
            liveStateHash: await computeWebStateHash(liveSyncObjects(objects), _sodium, old),
        });
        return { responseSeq: 5, headSeq: 5, gcFloor: 0, ...(await hashes(false)),
                 legacy: legacy ? await hashes(true) : null };
    }
    async function attempt(checkpoint, objects) {
        try {
            checkPulledStateAgainstCheckpoint(checkpoint, await pulledOf(objects, !checkpoint.state_v));
            return 'ok';
        } catch (err) {
            return err.message.split(':')[0];
        }
    }
    const F = obj('F', null, false);
    const E = obj('E', F.id, false);
    const held = map(F, E);
    const v2 = { last_sync_seq: 5, state_v: 2,
                 state_hash: await computeWebStateHash(held, _sodium),
                 live_state_hash: await computeWebStateHash(liveSyncObjects(held), _sodium) };
    const old = { last_sync_seq: 5,
                  state_hash: await computeWebStateHash(held, _sodium, true),
                  live_state_hash: await computeWebStateHash(liveSyncObjects(held), _sodium, true) };
    return {
        same: await attempt(v2, held),
        moved: await attempt(v2, map(F, obj('E', null, false))),
        deleted: await attempt(v2, map(F, obj('E', F.id, true))),
        upgraded: await attempt(old, held),
        upgradedChanged: await attempt(old, map(F, { ...E, payload: 'eA==' })),
    };
})()
"""


def test_a_held_object_moved_or_deleted_at_the_same_seq_is_a_mismatch():
    result = _run(FUNCTIONS, SCRIPT)
    assert result == {
        "same": "ok", "moved": "STATE MISMATCH at seq 5", "deleted": "STATE MISMATCH at seq 5",
        "upgraded": "ok", "upgradedChanged": "STATE MISMATCH at seq 5",
    }


def test_the_checkpoint_names_the_formula_it_was_made_with():
    assert "state_v: 2," in APP

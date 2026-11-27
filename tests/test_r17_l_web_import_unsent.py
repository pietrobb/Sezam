"""Review c02cc47 R17-L (web): the forget and the full resync download the
unsent changes (exportWebDirtyObjects), but nothing read that file back. The
import queues again only what this account signed with its current key and
whose payload matches its hash; a delete, a forged or tampered object and one
already queued are skipped. The base is not signed: it counts only when it is
the copy this browser holds now, otherwise the import is a conflict."""

from __future__ import annotations

import json

import pytest

from tests.node_support import node_problem
from tests.test_review_web import WEB_DIRTY_SAVE, _function, _run_source
from tests.test_team_log_web_rekey import _secrets
from tests.team_log_vectors import A, B

SCRIPT = """
    const me = %s, other = %s;
    const sodiumOk = sodium;
    btoa = value => Buffer.from(value, 'binary').toString('base64');
    t = (key, args) => key + (args ? ' ' + JSON.stringify(args) : '');
    let saved = null;
    saveWebDirtyState = async (outbox, conflicts) => { saved = { outbox, conflicts }; };
    state.userId = me.uid;
    state.keypair = { signingSk: hexToBytes(me.signingSk), signingPk: hexToBytes(me.signingPk) };
    const signed = async (fields, keys = me) => {
        const payload = new Uint8Array(64); payload[0] = fields.fill || 1;
        const hash = await sha256hexBytes(payload);
        const sk = state.keypair.signingSk;
        state.keypair.signingSk = hexToBytes(keys.signingSk);
        const sig = signSyncObject(sodiumOk, fields.id, fields.object_type || 'entry', fields.parent_ref || null,
            null, fields.is_deleted || 0, fields.version || 2, hexToBytes(hash));
        state.keypair.signingSk = sk;
        return { id: fields.id, object_type: fields.object_type || 'entry', parent_ref: fields.parent_ref || null,
                 is_deleted: fields.is_deleted || 0, version: fields.version || 2, payload: bytesToBase64(payload),
                 payload_hash: hash, signature: bytesToHex(sig), ...(fields.extra || {}) };
    };
    const ID = n => '01JE00000000000000000000' + String(n).padStart(2, '0');
    const held = { id: ID(2), version: 1, payload_hash: 'c'.repeat(64), is_deleted: 0 };
    state.syncObjects = { [ID(2)]: held, [ID(3)]: { ...held, id: ID(3) } };
    state.outbox = { [ID(7)]: { id: ID(7) } };
    state.syncConflicts = {};
    const tampered = await signed({ id: ID(4) });
    tampered.payload = bytesToBase64(new Uint8Array(64).fill(9));
    const objects = [
        await signed({ id: ID(1), extra: { access_level: 'admin', base_version: 5 } }),   // new here
        await signed({ id: ID(2), extra: { base_version: 1, base_payload_hash: 'c'.repeat(64) } }),
        await signed({ id: ID(3), extra: { base_version: 1, base_payload_hash: 'd'.repeat(64) } }),
        tampered,
        await signed({ id: ID(5) }, other),
        await signed({ id: ID(6), is_deleted: 1 }),
        await signed({ id: ID(7) }),
        await signed({ id: ID(8), object_type: 'dek' }),
    ];
    const counts = await importWebUnsentChangesLocked(JSON.stringify({ reason: 'full_resync', objects }), sodiumOk);
    let notExport = null;
    try { await importWebUnsentChangesLocked('{"objects": 1}', sodiumOk); } catch (err) { notExport = err.message; }
    return {
        counts,
        queued: Object.keys(saved.outbox).filter(id => id !== ID(7)).sort(),
        new_fields: Object.keys(saved.outbox[ID(1)]).sort(),
        base_kept: [saved.outbox[ID(2)].base_version, saved.outbox[ID(2)].base_payload_hash === 'c'.repeat(64)],
        conflict: Object.keys(saved.conflicts),
        conflict_server: saved.conflicts[ID(3)]?.server_object.payload_hash === 'c'.repeat(64),
        not_export: notExport,
    };
"""

NAMES = ["importWebUnsentChangesLocked", "verifyObjectSignature", "signedObjectMessage", "idBytes26",
         "signSyncObject", "sha256hexBytes", "bytesToBase64", "hexToBytes"]


@pytest.mark.skipif(node_problem() is not None, reason="node is needed for app.js")
def test_the_import_queues_only_what_this_account_signed():
    helpers = ("var MAX_UNSENT_IMPORT_CHARS = 64 * 1024 * 1024;\n"
               "var UNSENT_SIGNED_FIELDS = ['id', 'object_type', 'parent_ref', 'target_user_id', 'is_deleted', "
               "'version', 'payload', 'payload_hash', 'signature'];\n"
               + "\n".join(_function(n) for n in NAMES + WEB_DIRTY_SAVE))
    me = {**_secrets(B), "uid": B.uid}
    got = _run_source(helpers, "(async () => {" + SCRIPT % (json.dumps(me), json.dumps(_secrets(A))) + "\n})()")
    first, second, third = (f"01JE00000000000000000000{n:02d}" for n in (1, 2, 3))
    assert got["counts"] == {"queued": 2, "conflicted": 1, "skipped": 5}
    assert got["queued"] == [first, second]
    # Only the signed fields: no level, no unsigned base for a copy not held here.
    assert got["new_fields"] == sorted(["id", "object_type", "parent_ref", "is_deleted", "version",
                                        "payload", "payload_hash", "signature"])
    assert got["base_kept"] == [1, True]
    assert got["conflict"] == [third] and got["conflict_server"]
    assert got["not_export"] == "sync.import_unsent_not_export"

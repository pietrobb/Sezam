"""Review a159e97 H4 (web).

unauthorizedWrites only kept a forged folder out of view. The admin's
re-key and the successor sweep sealed and signed state.syncObjects as it was,
so a folder a server-made account ('Eve') wrote directly below the admin's
root came back as the admin's own signed v2, which every client then trusted.
Eve signing one envelope also made her an 'admin' there (capability run 196,
desktop 7a9840b). And the web re-key sealed the new key to every holder of an
envelope on the old one, whoever signed it (desktop D1 / reseal_key_row).
"""

from __future__ import annotations

from tests.test_review_web import _run, pytestmark  # noqa: F401

SEAL = ["writesNotToSeal", "unauthorizedWrites", "sealingDekId", "isEncryptedEnvelope"]
REKEY = ["buildWebRekeyBatch", "generateULID", "rekeyArchiveChars", "removalArchiveId", *SEAL]
SWEEP = ["resealOwnWritesUnderSuccessors", *SEAL]

STATE = r"""
  var ENVELOPE_ALG = 1, SCHEMA_VERSION = 1, BLOB_KIND = { NODE_META: 1 };
  const OLD = '01JF0000000000000000000000';
  const rec = (id, object_type, parent_ref, signer, extra = {}) => ({
    id, object_type, parent_ref, signer, owner_id: signer, version: 1, is_deleted: 0, payload: '', ...extra });
  const env = (id, user, signer) => rec(id, 'envelope', OLD, signer,
                                        { target_user_id: user, access_level: 'read' });
  state.userId = 'ADMIN';
  state.isAdmin = true;
  state.kek = new Uint8Array(32);
  state.keypair = { encryptionSk: new Uint8Array(32) };
  state.deks = { [OLD]: new Uint8Array(32).fill(7) };
  state.syncObjects = Object.fromEntries([
    rec('ROOT', 'node', null, 'ADMIN'),
    rec(OLD, 'dek', 'ROOT', 'ADMIN', { scope: 'root' }),
    rec('TEAM', 'node', 'ROOT', 'ADMIN'),
    rec('ITEM', 'entry', 'TEAM', 'CAROL'),
    // Eve, an account the server made: one envelope she signed made her an
    // 'admin'; her folder directly below the admin's root, with an item.
    env('E_EVE', 'EVE', 'EVE'),
    rec('FORGED', 'node', 'ROOT', 'EVE'),
    rec('FORGED_ITEM', 'entry', 'FORGED', 'EVE'),
    // Below a folder the server withholds (or that never was).
    rec('ORPHAN', 'node', 'GONE', 'EVE'),
    rec('ORPHAN_ITEM', 'entry', 'ORPHAN', 'EVE'),
    rec('OWN_ORPHAN', 'entry', 'GONE', 'ADMIN'),
    env('E_BOB', 'BOB', 'ADMIN'), env('E_CAROL', 'CAROL', 'ADMIN'),
  ].map(o => [o.id, o]));
"""

REKEY_SCRIPT = STATE + r"""
  apiFetch = async () => ['ADMIN', 'CAROL', 'EVE'].map(id => ({ id, status: 'active' }))
                           .concat([{ id: 'BOB', status: 'revoked' }]);
  wrapDEK = () => new Uint8Array(72);
  wrapDEKWithKey = () => new Uint8Array(72);
  encryptedPayloadDekId = () => OLD;
  decryptEnvelope = () => ({ name: 'x' });
  decryptEntryPayload = () => ({ name: 'x' });
  encryptEnvelope = () => new Uint8Array(60);
  encryptEntryPayload = () => new Uint8Array(60);
  getVerifiedEncryptionPkForRekey = async () => sodium.crypto_box_keypair().publicKey;
  buildSignedSyncObject = async (_s, meta) => meta;
  loadWebWriteGrants = async () => new Set();
  saveWebWriteGrants = async () => {};
  (async () => {
    const batch = await buildWebRekeyBatch('BOB', sodium);
    return {
      resealed: batch.objects.filter(o => ['node', 'entry'].includes(o.object_type)).map(o => o.id).sort(),
      sealed: batch.objects.filter(o => o.object_type === 'envelope' && !o.is_deleted)
                           .map(o => o.target_user_id).sort(),
      not_resealed: batch.not_resealed,
    };
  })()
"""


def test_the_rekey_does_not_sign_a_forged_folder_again():
    result = _run(REKEY, REKEY_SCRIPT)
    # Before: FORGED, FORGED_ITEM, ORPHAN and ORPHAN_ITEM came back admin-signed.
    assert result["resealed"] == ["ITEM", "OWN_ORPHAN", "ROOT", "TEAM"]


def test_the_rekey_seals_the_new_key_only_to_members_this_account_granted():
    result = _run(REKEY, REKEY_SCRIPT)
    assert result["sealed"] == ["CAROL"]  # before: Eve too
    assert result["not_resealed"] == ["EVE"]


def test_the_successor_sweep_does_not_sign_a_forged_folder_again():
    script = STATE + r"""
      ensureSodium = async () => sodium;
      state.outbox = {}; state.syncConflicts = {};
      state.kekDekIds = [OLD];
      retiredFolderDekIds = () => new Set([OLD]);
      payloadDekId = obj => (['node', 'entry'].includes(obj.object_type) ? OLD : null);
      const pushed = [];
      resealUnderFolderSuccessor = async held => ({ ...held });
      pushEncryptedVaultObjectLocked = async obj => { pushed.push(obj.id); };
      (async () => { await resealOwnWritesUnderSuccessors(); return pushed.sort(); })()
    """
    assert _run(SWEEP, script) == ["ITEM", "OWN_ORPHAN", "ROOT", "TEAM"]


def test_eves_folder_is_hidden_below_the_admins_root():
    """The display filter itself (capability run 196, ported from the desktop)."""
    script = STATE + "[...unauthorizedWrites(state.syncObjects, 'ADMIN')].sort()"
    assert _run(SEAL, script) == ["FORGED", "FORGED_ITEM"]


def test_a_write_grant_this_account_made_still_writes_below_its_root():
    script = STATE + r"""
      state.syncObjects.E_EVE = { ...state.syncObjects.E_EVE, signer: 'ADMIN', owner_id: 'ADMIN',
                                  access_level: 'write' };
      [...unauthorizedWrites(state.syncObjects, 'ADMIN')]
    """
    assert _run(SEAL, script) == []


def test_a_personal_root_makes_its_member_no_admin():
    """TL7: Carol's personal root (top-level, sealed with a key of hers that
    names no folder) makes her no admin: her folder below the org root stays
    hidden from Bob."""
    script = STATE + r"""
      sealingDekId = rec => rec._dek || null;
      for (const o of [
        rec('CK', 'dek', null, 'CAROL', { scope: 'personal' }),
        rec('CAROL_ROOT', 'node', null, 'CAROL', { _dek: 'CK' }),
        rec('CAROL_FOLDER', 'node', 'ROOT', 'CAROL', { _dek: OLD }),
      ]) state.syncObjects[o.id] = o;
      [...unauthorizedWrites(state.syncObjects, 'BOB')].sort()
    """
    # (Eve signed an envelope, so to Bob she is the server's admin.)
    assert _run(SEAL, script) == ["CAROL_FOLDER"]

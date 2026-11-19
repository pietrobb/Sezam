"""Capability review run 141: the web re-key withdrew members it did not name.

buildWebRekeyBatch tombstoned every envelope on the folder key and sealed the
new key only for holders the server listed as 'active'. Its archive tag names
only the removed member, and another admin's device grants again to every
member a tagged re-key did not name: for a holder dropped this way only the
server's unsigned status kept the new key from them. As on desktop, the web
now drops only the removed member and refuses while another holder is not
active.
"""

from __future__ import annotations

from tests.test_review_web import _run, pytestmark  # noqa: F401

FUNCTIONS = ["buildWebRekeyBatch", "generateULID", "rekeyArchiveChars", "removalArchiveId",
             "writesNotToSeal", "unauthorizedWrites", "sealingDekId"]

SCRIPT = r"""
(async () => {
  const OLD = '01JF0000000000000000000000';
  const env = (id, user) => ({ id, object_type: 'envelope', parent_ref: OLD, target_user_id: user,
                               access_level: 'read', version: 1, payload: '', signer: 'ADMIN' });
  state.userId = 'ADMIN';
  state.isAdmin = true;
  state.kek = new Uint8Array(32);
  state.keypair = { encryptionSk: new Uint8Array(32) };
  state.deks = { [OLD]: new Uint8Array(32).fill(7) };
  state.syncObjects = {
    [OLD]: { id: OLD, object_type: 'dek', parent_ref: 'FOLDER', version: 1, scope: 'folder' },
    E1: env('E1', 'ADMIN'), E2: env('E2', 'BOB'), E3: env('E3', 'CAROL'), E4: env('E4', 'DAVE'),
  };
  apiFetch = async () => [
    { id: 'ADMIN', status: 'active' }, { id: 'BOB', status: 'revoked' },
    { id: 'CAROL', status: 'active' }, { id: 'DAVE', status: DAVE_STATUS },
  ];
  wrapDEK = () => new Uint8Array(72);
  wrapDEKWithKey = () => new Uint8Array(72);
  encryptedPayloadDekId = () => null;
  getVerifiedEncryptionPkForRekey = async () => sodium.crypto_box_keypair().publicKey;
  buildSignedSyncObject = async (_s, meta) => meta;
  loadWebWriteGrants = async () => new Set();
  saveWebWriteGrants = async () => {};
  try {
    const batch = await buildWebRekeyBatch('BOB', sodium);
    return { sealed: batch.objects.filter(o => o.object_type === 'envelope' && !o.is_deleted)
                                  .map(o => o.target_user_id).sort() };
  } catch (err) {
    return { error: err.message };
  }
})()
"""


def _rekey(dave_status: str) -> dict:
    return _run(FUNCTIONS, SCRIPT.replace("DAVE_STATUS", repr(dave_status)))


def test_a_holder_that_is_not_active_is_not_withdrawn_unnamed():
    result = _rekey("revoked")
    assert "sealed" not in result, result  # before: Dave tombstoned, not sealed, not named
    assert "DAVE" in result["error"]
    assert "sezam revoke-user" in result["error"]


def test_every_holder_but_the_removed_member_gets_the_new_key():
    assert _rekey("active") == {"sealed": ["ADMIN", "CAROL", "DAVE"]}

"""Review a159e97 H3 on the web (desktop vouched_access_level, #345).

An envelope's access_level is not signed. The web re-key copied it into the
envelope this account signs on the new key, so a server that turned a
member's 'read' into 'write' had the escalation made permanent by the admin's
own signature. 'write' now carries over only from an envelope this browser
made (its earlier re-keys, recorded under the account key); every other
member gets 'read' and is named to the admin.
"""

from __future__ import annotations

from tests.test_review8_web_rekey_h4 import REKEY, STATE
from tests.test_review_web import _run, pytestmark  # noqa: F401

SCRIPT = STATE + r"""
  apiFetch = async () => ['ADMIN', 'CAROL', 'EVE'].map(id => ({ id, status: 'active' }))
                           .concat([{ id: 'BOB', status: 'revoked' }]);
  let saved = null;
  loadWebWriteGrants = async () => VOUCHED;
  saveWebWriteGrants = async grants => { saved = [...grants]; };
  // The server says Carol (granted 'read' by the admin) may write.
  state.syncObjects.E_CAROL = { ...state.syncObjects.E_CAROL, access_level: 'write' };
  wrapDEK = () => new Uint8Array(72);
  wrapDEKWithKey = () => new Uint8Array(72);
  encryptedPayloadDekId = () => OLD;
  decryptEnvelope = () => ({ name: 'x' });
  decryptEntryPayload = () => ({ name: 'x' });
  encryptEnvelope = () => new Uint8Array(60);
  encryptEntryPayload = () => new Uint8Array(60);
  getVerifiedEncryptionPkForRekey = async () => sodium.crypto_box_keypair().publicKey;
  buildSignedSyncObject = async (_s, meta) => meta;
  (async () => {
    const batch = await buildWebRekeyBatch('BOB', sodium);
    const sealed = batch.objects.filter(o => o.object_type === 'envelope' && !o.is_deleted);
    const writeIds = sealed.filter(o => o.access_level === 'write').map(o => o.id);
    return {
      levels: Object.fromEntries(sealed.map(o => [o.target_user_id, o.access_level])),
      downgraded: batch.write_downgraded,
      // The new write envelope is vouched for, so the next re-key keeps it.
      saved: saved === null ? null : writeIds.every(id => saved.includes(id)),
    };
  })()
"""


def test_a_write_level_the_server_claims_is_sealed_as_read():
    result = _run(REKEY, SCRIPT.replace("VOUCHED", "new Set()"))
    assert result["levels"] == {"CAROL": "read"}  # before: 'write'
    assert result["downgraded"] == ["CAROL"]
    assert result["saved"] is None  # nothing new to vouch for


def test_a_write_grant_this_browser_made_keeps_write():
    result = _run(REKEY, SCRIPT.replace("VOUCHED", "new Set(['E_CAROL'])"))
    assert result["levels"] == {"CAROL": "write"}
    assert result["downgraded"] == []
    assert result["saved"] is True  # recorded, so the next re-key keeps it too


GRANTS = ["loadWebWriteGrants", "saveWebWriteGrants", "webWriteGrantsAAD", "hexToBytes"]

STORE = r"""
  const store = {};
  idbKeysRequest = async (_mode, op) => op({
    get: id => store[id], put: rec => { store[rec.id] = rec; },
  });
  state.userId = 'ADMIN';
  state.kek = new Uint8Array(32).fill(3);
"""


def test_the_vouched_grants_are_sealed_under_the_account_key():
    script = STORE + r"""
      (async () => {
        await saveWebWriteGrants(new Set(['E2', 'E1']), sodium);
        const raw = JSON.stringify(store);
        const back = [...await loadWebWriteGrants(sodium)].sort();
        state.kek = new Uint8Array(32).fill(4);  // another account key
        const other = [...await loadWebWriteGrants(sodium)];
        state.kek = new Uint8Array(32).fill(3);
        state.userId = 'EVE';  // bound to the account
        const eve = [...await loadWebWriteGrants(sodium)];
        return { plain: raw.includes('E1'), back, other, eve };
      })()
    """
    result = _run(GRANTS, script)
    assert result["plain"] is False
    assert result["back"] == ["E1", "E2"]
    assert result["other"] == [] and result["eve"] == []  # unreadable: read only

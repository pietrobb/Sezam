"""Lockout review #3 (web): stale org recovery and replacing another admin's setup."""

from __future__ import annotations

import json

from tests.test_review_web import _function, _run, pytestmark  # noqa: F401

STUBS = """
  const calls = { alerts: [], confirms: [], stored: [], shown: 0 };
  t = key => key;
  API_BASE = '';
  alert = message => calls.alerts.push(message);
  const el = () => ({ value: '', textContent: '', classList: { add() {}, remove() {} } });
  const els = { 'shamir-threshold': { ...el(), value: '2' }, 'shamir-total': { ...el(), value: '3' } };
  document.getElementById = id => els[id] || (els[id] = el());
  document.createElement = () => ({ ...el(), addEventListener() {} });
  document.body = { appendChild() {} };
  escapeHtml = value => String(value);
  ensureSodium = async () => sodium;
  shamirSplit = () => [[1, new Uint8Array(32)]];
  closeShamirSetupModal = () => {};
  showShamirSharesModal = () => { calls.shown += 1; };
  state.kek = new Uint8Array(32); state.userId = 'ME';
  currentPasswordProof = async password => (password === 'pw' ? 'ab'.repeat(32) : null);
  els['shamir-password'] = { ...el(), value: 'pw' };
"""


def test_stale_org_recovery_is_refused_before_asking_for_shares():
    script = STUBS + """
      fetch = async () => ({ json: async () => ({ configured: true, threshold: 2, stale: true }) });
      await openOrgRecoveryModal();
      return calls;
    """
    calls = _run(["openOrgRecoveryModal"], f"(async () => {{ {script} }})()")
    assert calls["alerts"] == ["recovery.stale"]


def test_stale_blob_is_refused_before_any_recovery_request():
    body = _function("handleOrgRecovery")
    blob = body.index("const blobData = await blobResp.json();")
    assert body.index("if (blobData.stale) throw", blob) < body.index("/api/org-recovery/challenge")


def _generate(status: dict, answer: bool):
    script = STUBS + f"""
      const status = {json.dumps(status)};
      confirm = message => {{ calls.confirms.push(message); return {str(answer).lower()}; }};
      apiFetch = async (path, options = {{}}) => {{
        if (path === '/api/org-recovery/status') return status;
        if (path === '/api/org-recovery/store') calls.stored.push(options.body);
        return {{}};
      }};
      await handleShamirGenerate();
      return calls;
    """
    return _run(
        ["handleShamirGenerate", "bytesToHex", "anchorWebOrgRecovery", "sendWebTeamRecords", "noteWebTeamRecordsSent", "noteWebTeamRecordsTaken"], f"(async () => {{ {script} }})()"
    )


def test_replacing_another_admins_setup_needs_confirmation():
    status = {"configured": True, "created_by": "OTHER", "stale": False}
    refused = _generate(status, False)
    assert refused["confirms"] == ["recovery.replace_other_admin"]
    assert refused["stored"] == [] and refused["shown"] == 0

    confirmed = _generate(status, True)
    assert confirmed["stored"][0]["replace_other_admin"] is True
    assert confirmed["shown"] == 1


def test_own_setup_again_warns_and_stale_one_says_why():
    own = _generate({"configured": True, "created_by": "ME", "stale": False}, True)
    assert own["confirms"] == ["recovery.replace_own"]
    assert own["stored"][0]["replace_other_admin"] is False
    stale = _generate({"configured": True, "created_by": "ME", "stale": True}, True)
    assert stale["confirms"] == ["recovery.replace_stale"]


def test_first_setup_asks_nothing():
    first = _generate({"configured": False}, False)
    assert first["confirms"] == [] and len(first["stored"]) == 1
    assert first["stored"][0]["current_auth_proof"] == "ab" * 32


ANCHOR = STUBS + """
  const posted = [];
  globalThis.SezamTeamLog = {
    isAdmin: (team, userId) => userId === 'ME',
    nextBody: (team, type, author, data) => ({ type, author, data }),
    signRecord: body => ({ body }),
    applyRecord: team => team,
  };
  state.teamLog = { records: [{}], team: { genesisHash: 'G', orgRecovery: {} } };
  state.keypair = { signingSk: new Uint8Array(64) };
  state.keyEpoch = 3;
  confirm = () => true;
  apiFetch = async (path, options = {}) => {
    if (path === '/api/org-recovery/status') return { configured: false };
    if (path === '/api/org-recovery/store') calls.stored.push(options.body);
    if (path === '/api/team-log') posted.push(options.body.records);
    return {};
  };
"""
ANCHOR_FUNCTIONS = ["handleShamirGenerate", "bytesToHex", "anchorWebOrgRecovery", "webTeamLogTrusted",
                    "sendWebTeamRecords", "noteWebTeamRecordsSent", "noteWebTeamRecordsTaken"]


def test_web_setup_names_the_recovery_key_in_the_team_log():
    """Review 8595ec1 #4 (capability run 314): a server restored from before
    the setup takes the recovery's reset proof only for a key the log names."""
    script = ANCHOR + """
      state.confirmedTeamGenesis = 'G';
      await handleShamirGenerate();
      return { ...calls, posted };
    """
    out = _run(ANCHOR_FUNCTIONS, f"(async () => {{ {script} }})()")
    assert out["shown"] == 1
    stored = out["stored"][0]
    assert out["posted"] == [[{"body": {
        "type": "org.recovery", "author": "ME",
        "data": {"recovery_pk": stored["recovery_signing_pk"]},
    }}, {"body": {
        # Capability run 316: and the KEK wrap the shares open.
        "type": "org.recovery.wrap", "author": "ME",
        "data": {key: stored[key] for key in ("wrapped_kek", "key_epoch", "threshold", "total_shares")},
    }}]]


def test_web_setup_says_when_the_log_refused_the_new_key():
    """Review 4acfdde R11 #2: only console.warn said so. The server voids the
    older shares either way (tests/test_review11_org_recovery_current.py), so
    the new ones are still shown, and the admin is told."""
    script = ANCHOR + """
      state.confirmedTeamGenesis = 'G';
      const plain = apiFetch;
      apiFetch = async (path, options = {}) => {
        if (path === '/api/team-log') throw new Error('team log refused');
        return plain(path, options);
      };
      await handleShamirGenerate();
      return { ...calls, posted };
    """
    out = _run(ANCHOR_FUNCTIONS, f"(async () => {{ {script} }})()")
    assert out["shown"] == 1 and len(out["stored"]) == 1 and out["posted"] == []
    assert out["alerts"] == ["recovery.anchor_failed"]


def test_web_setup_signs_nothing_into_an_untrusted_log():
    script = ANCHOR + """
      state.confirmedTeamGenesis = 'OTHER';
      await handleShamirGenerate();
      return { ...calls, posted };
    """
    out = _run(ANCHOR_FUNCTIONS, f"(async () => {{ {script} }})()")
    assert out["shown"] == 1 and len(out["stored"]) == 1 and out["posted"] == []


def test_setup_without_the_current_password_stores_nothing():
    """Review e4cd15a #1: the server registers a new recovery key only with
    proof of the current password (a recovery key can reset it)."""
    script = STUBS + """
      els['shamir-password'].value = 'wrong';
      apiFetch = async (path, options = {}) => {
        if (path === '/api/org-recovery/status') return { configured: false };
        if (path === '/api/org-recovery/store') calls.stored.push(options.body);
        return {};
      };
      await handleShamirGenerate();
      return { ...calls, error: els['shamir-setup-error'].textContent };
    """
    out = _run(["handleShamirGenerate", "bytesToHex"], f"(async () => {{ {script} }})()")
    assert out["stored"] == [] and out["shown"] == 0
    assert out["error"] == "recovery.setup_wrong_password"

// Signed team log: the web page's door to the Rust core (docs/DESIGN_TEAM_LOG.md).
// The replay and every decision from it live once in core/src/teamlog
// (docs/CORE_UNIFICATION.md), built for the page as vendor/sezam-sync-core.js;
// the desktop, the server and the phone ask the same core. This file only
// checks the signatures the core names (libsodium), signs new records and
// gives the replayed state to the code that reads it. The core must be ready
// (await SezamSyncCore.ready) before any of it is asked.
'use strict';

const SezamTeamLog = (() => {
  const FORMAT_VERSION = 2;
  const ZERO_HASH = '0'.repeat(64);

  class TeamLogError extends Error {
    constructor(code, seq, detail = '') {
      super(`team log record ${seq}: ${code}${detail ? ` (${detail})` : ''}`);
      this.name = 'TeamLogError';
      this.code = code;
      this.seq = seq;
    }
  }

  const call = (op, args) => globalThis.SezamSyncCore.call(op, args);

  function answer(out, name) {
    if (out.refused) throw new TeamLogError(out.refused.code, out.refused.seq, out.refused.detail);
    return out[name];
  }

  const fromHex = (hex) => Uint8Array.from(hex.match(/../g) || [], (b) => parseInt(b, 16));
  const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  const setOf = (names) => Object.fromEntries(names.map((name) => [name, true]));
  const mapValues = (obj, fn) => Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, fn(v)]));

  // ── State: the core's, read by the code around it (never changed) ───
  const CORE = Symbol('core state');
  const HANDLE = Symbol('loaded in the core');
  const loaded = typeof FinalizationRegistry === 'function'
    ? new FinalizationRegistry((handle) => { try { call('team_log_free', { handle }); } catch { /* page gone */ } })
    : null;

  function fromCore(core) {
    const state = {
      org: core.org, genesisHash: core.genesis_hash, headSeq: core.head_seq, headHash: core.head_hash,
      members: mapValues(core.members, (m) => ({
        signingPk: m.signing_pk, encryptionPk: m.encryption_pk, role: m.role, active: m.active,
      })),
      folders: mapValues(core.folders, (gens) => gens.map((g) => [g.dek_id, g.author])),
      access: mapValues(core.access, (a) => ({ ...a })),
      stale: mapValues(core.stale, setOf),
      seenKeys: { ...core.seen_keys },
      dekIndex: mapValues(core.dek_index, (where) => [...where]),
      formerAdmins: mapValues(core.former_admins, setOf),
      rules: core.rules,
      orgRecovery: { ...core.org_recovery },
      orgRecoveryWrap: mapValues(core.org_recovery_wrap, (w) => ({ ...w })),
    };
    Object.defineProperty(state, CORE, { value: core });
    return state;
  }

  function toCore(state) {
    if (state[CORE]) return state[CORE];
    const keys = (set) => Object.keys(set).sort();
    return {
      org: state.org, genesis_hash: state.genesisHash, head_seq: state.headSeq, head_hash: state.headHash,
      members: mapValues(state.members, (m) => ({
        signing_pk: m.signingPk, encryption_pk: m.encryptionPk, role: m.role, active: !!m.active,
      })),
      folders: mapValues(state.folders, (gens) => gens.map(([dekId, author]) => ({ dek_id: dekId, author }))),
      access: mapValues(state.access, (a) => ({ ...a })),
      stale: mapValues(state.stale, keys),
      seen_keys: { ...state.seenKeys },
      dek_index: mapValues(state.dekIndex, (where) => [...where]),
      former_admins: mapValues(state.formerAdmins || {}, keys),
      rules: state.rules || 0,
      org_recovery: { ...(state.orgRecovery || {}) },
      org_recovery_wrap: mapValues(state.orgRecoveryWrap || {}, (w) => ({ ...w })),
    };
  }

  // Review 8bc70f7 M8: a state the core gave is loaded there once, not sent
  // whole with every question.
  // The state as the core's other operations take it: `team_handle` or `team`.
  function teamArgument(state) {
    if (!state[CORE]) return { team: toCore(state) };
    if (state[HANDLE] === undefined) {
      Object.defineProperty(state, HANDLE, { value: call('team_log_load', { state: state[CORE] }) });
      if (loaded) loaded.register(state, state[HANDLE]);
    }
    return { team_handle: state[HANDLE] };
  }

  function ask(state, fn, ...args) {
    const team = teamArgument(state);
    const questions = [{ fn, args }];
    if (team.team) return call('team_log_ask', { state: team.team, questions })[0];
    return call('team_log_ask', { handle: team.team_handle, questions })[0];
  }

  const emptyState = () => fromCore(call('team_log_empty_state', {}));

  // ── Records ─────────────────────────────────────────────────────────
  function canonical(value, seq = null) {
    try {
      return answer(call('team_log_canonical', { value }), 'text');
    } catch (err) {
      if (err instanceof TeamLogError) throw new TeamLogError(err.code, seq);
      throw err;
    }
  }

  function parseBody(body, seq) {
    if (typeof body !== 'string') throw new TeamLogError('bad_encoding', seq, 'body is not a string');
    try {
      return answer(call('team_log_parse_body', { body }), 'body');
    } catch (err) {
      if (err instanceof TeamLogError) throw new TeamLogError(err.code, seq);
      throw err;
    }
  }

  const recordHash = (record) => call('team_log_record_hash', { body: record.body, sig: record.sig });

  const newKeyMessage = (prev, userId, signingPk, encryptionPk) => fromHex(call('team_log_new_key_message', {
    prev, user_id: userId, signing_pk: signingPk, encryption_pk: encryptionPk,
  }));

  function signRecord(body, signingSk, sodium) {
    const text = canonical(body, body.seq ?? null);
    const message = fromHex(call('team_log_sig_message', { body: text }));
    return { body: text, sig: toHex(sodium.crypto_sign_detached(message, signingSk)) };
  }

  const stateToJson = (state) => ask(state, 'state_json');

  // ── Replay ──────────────────────────────────────────────────────────
  // How many of the core's signature checks pass, from the first.
  function passed(checks, sodium) {
    for (let i = 0; i < checks.length; i++) {
      let ok = false;
      try {
        ok = sodium.crypto_sign_verify_detached(fromHex(checks[i].sig), fromHex(checks[i].message), fromHex(checks[i].pk));
      } catch {
        ok = false;
      }
      if (!ok) return i;
    }
    return checks.length;
  }

  // Replay records onto state (a fresh log when null); the whole call fails
  // on the first bad record, state is never changed.
  function replay(records, sodium, state = null) {
    const base = state ? toCore(state) : null;
    const { checks } = call('team_log_replay', { records, state: base });
    return fromCore(answer(call('team_log_replay', { records, state: base, verified: passed(checks, sodium) }), 'state'));
  }

  const applyRecord = (state, record, sodium) => replay([record], sodium, state);

  const nextBody = (state, kind, author, data) => ask(state, 'next_body', kind, author, data);

  // ── Decisions (design §4.3), all the core's. Unknown is always "no". ─
  const isTeamFolder = (state, folder) => ask(state, 'is_team_folder', folder);
  const currentKey = (state, folder) => ask(state, 'current_key', folder);
  const keyGeneration = (state, folder, dekId) => ask(state, 'key_generation', folder, dekId);
  const isStale = (state, folder) => ask(state, 'is_stale', folder);
  const maySeal = (state, folder) => ask(state, 'may_seal', folder);
  const isAdmin = (state, userId) => ask(state, 'is_admin', userId);
  const mayWrite = (state, folder, userId) => ask(state, 'may_write', folder, userId);
  const keyRecipients = (state, folder) => ask(state, 'key_recipients', folder);
  const mayHoldKey = (state, userId, dekId) => ask(state, 'may_hold_key', userId, dekId);
  const envelopeValid = (state, signerId, targetId, dekId, level, targetEncryptionPk) =>
    ask(state, 'envelope_valid', signerId, targetId, dekId, level, targetEncryptionPk);
  // Why a live folder/item by userId sealed with dekId is not valid, or null
  // (the server's push rule; sealing=false for a pulled copy).
  const itemRefusal = (state, userId, objId, folder, dekId, ownDek, sealing = true) =>
    ask(state, 'item_refusal', userId, objId, folder, dekId, !!ownDek, !!sealing);
  const adminPolicyRefusal = (state) => ask(state, 'admin_policy_refusal');
  // Capability run 294: the log rotated userId away from signing key pkHex.
  const signingKeyRetired = (state, userId, pkHex) => !!state && ask(state, 'signing_key_retired', userId, pkHex);
  const tombstoneRefusal = (state, userId, storedDekId) => ask(state, 'tombstone_refusal', userId, storedDekId);
  const moveRefusal = (state, userId, oldFolder, newFolder, ownPersonal = false) =>
    ask(state, 'move_refusal', userId, oldFolder, newFolder, !!ownPersonal);

  // ── Forks and restores ──────────────────────────────────────────────
  const readmitted = (bodies, index) => call('team_log_readmitted', { bodies, index });
  const restorePartEnd = (bodies, start, limit) => call('team_log_restore_part_end', { bodies, start, limit });
  const changeKey = (body) => answer(call('team_log_change_key', { body: canonical(body) }), 'key');

  // Review 18c300f R16-H1 (tests/vectors/team_log_fork.json): whether a device
  // follows a server log that forks from its copy. heldKeys: [signingPk,
  // encryptionPk] or null; withdrawn: a Set of record hashes.
  const forkRefusal = (lost, theirs, userId, heldKeys, withdrawn) => answer(call('team_log_fork', {
    lost, theirs, user_id: userId, held_keys: heldKeys, withdrawn: [...withdrawn].sort(),
  }), 'fork');

  // The hashes of this account's lost records a device withdraws when it
  // follows a fork (capability finding 505).
  const forkAbandoned = (lost, userId) => answer(call('team_log_abandoned', { lost, user_id: userId }), 'hashes');

  // U7d (core/src/teamlog/fork_follow.rs, tests/vectors/team_log_fork_follow.json):
  // where a server log forks from this copy and whether it is followed
  // ({stand}, {refusal} or {fork, missing, relink}); then, on the served
  // records replayed, {stand} or {follow: {remake, link, abandoned}}.
  const forkFollows = (cause) => call('team_log_fork_follows', { cause });
  const forkSplit = (local, served, pins, userId, heldKeys, withdrawn) => call('team_log_fork_split', {
    local, served, pins, user_id: userId, held_keys: heldKeys, withdrawn: [...withdrawn].sort(),
  });
  const forkTake = (state, head, lost, missing, userId, heldKeys, oldSigningPk) => call('team_log_fork_take', {
    state: toCore(state), head, lost, missing, user_id: userId, held_keys: heldKeys, old_signing_pk: oldSigningPk,
  });

  // The data a lost change is made again with on `state`, or null when the log
  // has it already; TeamLogError when it can never land (the core's,
  // docs/CORE_UNIFICATION.md U7a).
  function resolveChange(state, kind, data) {
    return answer(ask(state, 'resolve_change', kind, data), 'data');
  }

  return {
    FORMAT_VERSION, ZERO_HASH, TeamLogError, canonical, parseBody, recordHash, newKeyMessage, signRecord,
    emptyState, stateToJson, applyRecord, replay, nextBody, teamArgument,
    isTeamFolder, currentKey, keyGeneration, isStale, maySeal, isAdmin, mayWrite, keyRecipients,
    mayHoldKey, envelopeValid, itemRefusal, tombstoneRefusal, moveRefusal, adminPolicyRefusal,
    signingKeyRetired, changeKey, readmitted, restorePartEnd, forkRefusal, forkAbandoned, forkFollows, forkSplit, forkTake,
    resolveChange,
  };
})();

if (typeof globalThis !== 'undefined') globalThis.SezamTeamLog = SezamTeamLog;

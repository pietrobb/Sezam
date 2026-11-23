// Signed team log: replay and decisions (docs/DESIGN_TEAM_LOG.md).
// Port of src/sezam/teamlog.py; must pass tests/vectors/team_log.json exactly
// (same state, same answers, same error code at the same record).
'use strict';

const SezamTeamLog = (() => {
  // A body's "v" names the rules its record is judged by (review 8595ec1,
  // R10-B); 1 = a member could get a retired key back, 2 = it stays retired.
  const RULES_VERSIONS = [1, 2];
  const FORMAT_VERSION = 2;
  const SIG_DOMAIN = 'sezam-team-log-v1\0';
  const HASH_DOMAIN = 'sezam-team-log-hash-v1\0';
  const NEW_KEY_DOMAIN = 'sezam-team-log-newkey-v1\0';
  const ZERO_HASH = '0'.repeat(64);
  const MAX_INT = 2 ** 53 - 1;
  const ROLES = ['admin', 'member'];
  const LEVELS = ['read', 'write'];
  const ULID = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
  const HEX64 = /^[0-9a-f]{64}$/;
  const HEX128 = /^[0-9a-f]{128}$/;
  const HEX144 = /^[0-9a-f]{144}$/;
  const SAFE_STR = /^[\x20-\x21\x23-\x5b\x5d-\x7e]*$/;
  const BODY_FIELDS = ['author', 'data', 'prev', 'seq', 'type', 'v'];
  // Field order matters: errors name the first failing field, as in Python.
  const DATA_SCHEMA = {
    genesis: [['org', 'ulid'], ['user_id', 'ulid'], ['signing_pk', 'hex64'], ['encryption_pk', 'hex64']],
    'member.add': [['user_id', 'ulid'], ['signing_pk', 'hex64'], ['encryption_pk', 'hex64'], ['role', 'role']],
    'member.role': [['user_id', 'ulid'], ['role', 'role']],
    'member.remove': [['user_id', 'ulid']],
    'member.keys': [['user_id', 'ulid'], ['signing_pk', 'hex64'], ['encryption_pk', 'hex64'],
      ['new_key_sig', 'hex128']],
    'folder.key': [['folder', 'ulid'], ['gen', 'int'], ['dek_id', 'ulid'], ['prev_dek_id', 'ulid?']],
    'access.set': [['folder', 'ulid'], ['user_id', 'ulid'], ['level', 'level?']],
    // Review 8595ec1 (R10-D): the admin's org recovery key (null: none), from rules 2.
    'org.recovery': [['recovery_pk', 'hex64?']],
    // Review 8595ec1 (capability run 316): the KEK wrap the shares of the
    // author's named recovery key open, so a restored server still serves it.
    'org.recovery.wrap': [['wrapped_kek', 'hex144'], ['key_epoch', 'int'], ['threshold', 'int'],
      ['total_shares', 'int']],
  };
  const RECOVERY_TYPES = ['org.recovery', 'org.recovery.wrap'];
  const own = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

  class TeamLogError extends Error {
    constructor(code, seq, detail = '') {
      super(`team log record ${seq}: ${code}${detail ? ` (${detail})` : ''}`);
      this.name = 'TeamLogError';
      this.code = code;
      this.seq = seq;
    }
  }

  // ── Canonical encoding ──────────────────────────────────────────────
  function isPlainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }

  function checkValue(value, seq) {
    if (value === null) return;
    if (typeof value === 'boolean') throw new TeamLogError('bad_encoding', seq, 'boolean');
    if (typeof value === 'number') {
      if (!Number.isInteger(value) || value < 0 || value > MAX_INT || Object.is(value, -0)) {
        throw new TeamLogError('bad_encoding', seq, 'integer out of range');
      }
      return;
    }
    if (typeof value === 'string') {
      if (!SAFE_STR.test(value)) throw new TeamLogError('bad_encoding', seq, 'string');
      return;
    }
    if (isPlainObject(value)) {
      for (const key of Object.keys(value)) {
        if (!SAFE_STR.test(key)) throw new TeamLogError('bad_encoding', seq, 'key');
        checkValue(value[key], seq);
      }
      return;
    }
    throw new TeamLogError('bad_encoding', seq, typeof value);
  }

  function encode(value) {
    if (value === null) return 'null';
    if (typeof value === 'number') return String(value);
    if (typeof value === 'string') return `"${value}"`;
    // Keys are printable ASCII, so UTF-16 order is byte order.
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `"${k}":${encode(value[k])}`).join(',')}}`;
  }

  function canonical(value, seq = null) {
    checkValue(value, seq);
    return encode(value);
  }

  function parseBody(body, seq) {
    if (typeof body !== 'string') throw new TeamLogError('bad_encoding', seq, 'body is not a string');
    let parsed;
    try {
      parsed = JSON.parse(body);
    } catch {
      throw new TeamLogError('bad_encoding', seq, 'json');
    }
    // A duplicate key, a float, an escape or whitespace changes the re-encoding.
    if (!isPlainObject(parsed) || canonical(parsed, seq) !== body) {
      throw new TeamLogError('bad_encoding', seq, 'not canonical');
    }
    return parsed;
  }

  // ── Bytes ───────────────────────────────────────────────────────────
  const ascii = (text) => Uint8Array.from(text, (c) => c.charCodeAt(0));
  const fromHex = (hex) => Uint8Array.from(hex.match(/../g) || [], (b) => parseInt(b, 16));
  const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  function concat(...parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let offset = 0;
    for (const part of parts) { out.set(part, offset); offset += part.length; }
    return out;
  }

  const sigMessage = (body) => ascii(SIG_DOMAIN + body);

  function recordHash(record, sodium) {
    return toHex(sodium.crypto_hash_sha256(concat(ascii(HASH_DOMAIN + record.body), fromHex(record.sig))));
  }

  function newKeyMessage(prev, userId, signingPk, encryptionPk) {
    return concat(ascii(NEW_KEY_DOMAIN), fromHex(prev), ascii(userId), fromHex(signingPk), fromHex(encryptionPk));
  }

  function signRecord(body, signingSk, sodium) {
    const text = canonical(body, body.seq ?? null);
    return { body: text, sig: toHex(sodium.crypto_sign_detached(sigMessage(text), signingSk)) };
  }

  // ── State ───────────────────────────────────────────────────────────
  function emptyState() {
    return {
      org: '', genesisHash: '', headSeq: -1, headHash: ZERO_HASH,
      members: {}, // uid -> {signingPk, encryptionPk, role, active}
      folders: {}, // folder -> [[dekId, author], ...]
      access: {}, // folder -> {uid: level}
      stale: {}, // folder -> {uid: true}
      seenKeys: {}, // pk -> uid
      dekIndex: {}, // dekId -> [folder, gen]
      // folder -> {uid: true}: admins handed over while its current key was
      // current; what they sealed with it then is still theirs.
      formerAdmins: {},
      rules: 0, // the rules version of the last record
      orgRecovery: {}, // admin uid -> org recovery signing key (hex)
      orgRecoveryWrap: {}, // admin uid -> org.recovery.wrap data of that key
    };
  }

  const cloneState = (state) => JSON.parse(JSON.stringify(state));

  function sortedObject(obj, map = (v) => v) {
    const out = {};
    for (const key of Object.keys(obj).sort()) out[key] = map(obj[key]);
    return out;
  }

  function stateToJson(state) {
    const access = {};
    for (const f of Object.keys(state.access).sort()) {
      if (Object.keys(state.access[f]).length) access[f] = sortedObject(state.access[f]);
    }
    const stale = {};
    for (const f of Object.keys(state.stale).sort()) {
      const users = Object.keys(state.stale[f]).sort();
      if (users.length) stale[f] = users;
    }
    const recovery = state.orgRecovery || {};
    const wraps = state.orgRecoveryWrap || {};
    return {
      ...(Object.keys(recovery).length ? { org_recovery: sortedObject(recovery) } : {}),
      ...(Object.keys(wraps).length ? { org_recovery_wrap: sortedObject(wraps, (w) => sortedObject(w)) } : {}),
      rules: state.rules || 0,
      org: state.org,
      genesis_hash: state.genesisHash,
      head_seq: state.headSeq,
      head_hash: state.headHash,
      members: sortedObject(state.members, (m) => ({
        signing_pk: m.signingPk, encryption_pk: m.encryptionPk, role: m.role, active: m.active ? 1 : 0,
      })),
      folders: sortedObject(state.folders, (gens) => gens.map(([dek]) => dek)),
      access,
      stale,
    };
  }

  function is(kind, value) {
    if (kind === 'ulid') return typeof value === 'string' && ULID.test(value);
    if (kind === 'hex64') return typeof value === 'string' && HEX64.test(value);
    if (kind === 'hex128') return typeof value === 'string' && HEX128.test(value);
    if (kind === 'hex144') return typeof value === 'string' && HEX144.test(value);
    if (kind === 'role') return ROLES.includes(value);
    if (kind === 'level') return LEVELS.includes(value);
    return Number.isInteger(value); // 'int'
  }

  function sameKeys(obj, names) {
    const keys = Object.keys(obj).sort();
    const want = [...names].sort();
    return keys.length === want.length && keys.every((k, i) => k === want[i]);
  }

  function validateBody(body, seq) {
    if (!sameKeys(body, BODY_FIELDS)) throw new TeamLogError('bad_schema', seq, 'body fields');
    if (!RULES_VERSIONS.includes(body.v)) throw new TeamLogError('bad_schema', seq, 'version');
    if (!Number.isInteger(body.seq)) throw new TeamLogError('bad_schema', seq, 'seq');
    if (!is('hex64', body.prev)) throw new TeamLogError('bad_schema', seq, 'prev');
    if (!is('ulid', body.author)) throw new TeamLogError('bad_schema', seq, 'author');
    const schema = typeof body.type === 'string' && own(DATA_SCHEMA, body.type) ? DATA_SCHEMA[body.type] : null;
    if (schema === null || (RECOVERY_TYPES.includes(body.type) && body.v < 2)) {
      throw new TeamLogError('bad_schema', seq, 'type');
    }
    const data = body.data;
    if (!isPlainObject(data) || !sameKeys(data, schema.map(([name]) => name))) {
      throw new TeamLogError('bad_schema', seq, 'data fields');
    }
    for (const [name, kind] of schema) {
      const value = data[name];
      if (value === null && kind.endsWith('?')) continue;
      if (!is(kind.replace('?', ''), value)) throw new TeamLogError('bad_schema', seq, name);
    }
  }

  function verify(sodium, pkHex, message, sigHex, seq, code = 'bad_signature') {
    let ok = false;
    try {
      ok = sodium.crypto_sign_verify_detached(fromHex(sigHex), message, fromHex(pkHex));
    } catch {
      ok = false;
    }
    if (!ok) throw new TeamLogError(code, seq);
  }

  function claimKeys(state, userId, seq, ...pks) {
    for (const pk of pks) {
      const current = state.members[userId];
      // Rules 2: a key the log retired stays retired, also for its owner.
      if (own(state.seenKeys, pk) && (state.seenKeys[pk] !== userId || (state.rules >= 2 && (!current ||
          ![current.signingPk, current.encryptionPk].includes(pk))))) throw new TeamLogError('key_reused', seq);
    }
    if (new Set(pks).size !== pks.length) throw new TeamLogError('key_reused', seq);
    for (const pk of pks) state.seenKeys[pk] = userId;
  }

  // Capability run 294: the log rotated userId away from signing key pkHex; a
  // server restored from before the rotation still calls it current.
  function signingKeyRetired(state, userId, pkHex) {
    const member = state && own(state.members, userId) ? state.members[userId] : null;
    return !!member && member.signingPk !== pkHex && own(state.seenKeys, pkHex) && state.seenKeys[pkHex] === userId;
  }

  const activeAdmins = (state) => Object.values(state.members).filter((m) => m.active && m.role === 'admin').length;

  function loseAccess(state, folder, userId) {
    if (own(state.access, folder)) delete state.access[folder][userId];
    (state.stale[folder] ||= {})[userId] = true;
  }

  function applyInPlace(state, record, sodium) {
    const expectedSeq = state.headSeq + 1;
    if (!isPlainObject(record) || !sameKeys(record, ['body', 'sig'])) {
      throw new TeamLogError('bad_schema', expectedSeq, 'record fields');
    }
    if (!is('hex128', record.sig)) throw new TeamLogError('bad_schema', expectedSeq, 'sig');
    const body = parseBody(record.body, expectedSeq);
    validateBody(body, expectedSeq);
    const seq = body.seq;
    if (seq !== expectedSeq) throw new TeamLogError('bad_seq', expectedSeq);
    if (body.prev !== state.headHash) throw new TeamLogError('bad_prev', seq);
    if (body.v < (state.rules || 0)) throw new TeamLogError('rules_downgrade', seq);
    state.rules = body.v;
    const { type: kind, author, data } = body;
    const message = sigMessage(record.body);

    if (kind === 'genesis') {
      if (seq !== 0) throw new TeamLogError('bad_genesis', seq, 'not first');
      if (author !== data.user_id) throw new TeamLogError('bad_genesis', seq, 'author');
      verify(sodium, data.signing_pk, message, record.sig, seq);
      claimKeys(state, author, seq, data.signing_pk, data.encryption_pk);
      state.org = data.org;
      state.members[author] = {
        signingPk: data.signing_pk, encryptionPk: data.encryption_pk, role: 'admin', active: true,
      };
    } else {
      if (seq === 0) throw new TeamLogError('bad_genesis', seq, 'first record is not genesis');
      const signer = own(state.members, author) ? state.members[author] : null;
      if (signer === null || !signer.active) throw new TeamLogError('not_member', seq);
      verify(sodium, signer.signingPk, message, record.sig, seq);
      if (kind !== 'member.keys' && signer.role !== 'admin') throw new TeamLogError('not_admin', seq);
      applyChange(state, seq, kind, author, data, body.prev, sodium);
    }
    state.headSeq = seq;
    state.headHash = recordHash(record, sodium);
    if (seq === 0) state.genesisHash = state.headHash;
  }

  function applyChange(state, seq, kind, author, data, prev, sodium) {
    const userId = own(data, 'user_id') ? data.user_id : null;
    const member = userId !== null && own(state.members, userId) ? state.members[userId] : null;

    if (kind === 'member.add') {
      if (member !== null && member.active) throw new TeamLogError('member_exists', seq);
      claimKeys(state, userId, seq, data.signing_pk, data.encryption_pk);
      state.members[userId] = {
        signingPk: data.signing_pk, encryptionPk: data.encryption_pk, role: data.role, active: true,
      };
    } else if (kind === 'member.role') {
      if (member === null || !member.active) throw new TeamLogError('not_active', seq);
      if (member.role === data.role) throw new TeamLogError('unchanged', seq);
      if (member.role === 'admin' && activeAdmins(state) === 1) throw new TeamLogError('last_admin', seq);
      if (member.role === 'admin') {
        state.formerAdmins ||= {};
        for (const folder of Object.keys(state.folders)) (state.formerAdmins[folder] ||= {})[userId] = true;
        if (state.orgRecovery) delete state.orgRecovery[userId];
        if (state.orgRecoveryWrap) delete state.orgRecoveryWrap[userId];
      }
      member.role = data.role;
    } else if (kind === 'member.remove') {
      if (member === null || !member.active) throw new TeamLogError('not_active', seq);
      if (member.role === 'admin' && activeAdmins(state) === 1) throw new TeamLogError('last_admin', seq);
      member.active = false;
      if (state.orgRecovery) delete state.orgRecovery[userId];
      if (state.orgRecoveryWrap) delete state.orgRecoveryWrap[userId];
      for (const folder of Object.keys(state.folders)) {
        const gens = state.folders[folder];
        const hasAccess = own(state.access, folder) && own(state.access[folder], userId);
        if (hasAccess || gens[gens.length - 1][1] === userId) loseAccess(state, folder, userId);
      }
    } else if (kind === 'member.keys') {
      if (author !== userId) throw new TeamLogError('not_self', seq);
      verify(sodium, data.signing_pk, newKeyMessage(prev, userId, data.signing_pk, data.encryption_pk),
        data.new_key_sig, seq, 'bad_new_key_signature');
      // Review e443cbc H1: two keys the member does not hold in either role (a
      // swap X -> Y -> X made the server's rotation walk loop for good).
      const held = [member.signingPk, member.encryptionPk];
      if (held.includes(data.signing_pk) || held.includes(data.encryption_pk)) {
        throw new TeamLogError('key_reused', seq);
      }
      claimKeys(state, userId, seq, data.signing_pk, data.encryption_pk);
      member.signingPk = data.signing_pk;
      member.encryptionPk = data.encryption_pk;
    } else if (kind === 'folder.key') {
      const folder = data.folder;
      if (own(state.dekIndex, data.dek_id)) throw new TeamLogError('dek_reused', seq);
      let gens = own(state.folders, folder) ? state.folders[folder] : null;
      if (gens === null) {
        if (data.gen !== 0 || data.prev_dek_id !== null) throw new TeamLogError('bad_generation', seq);
        gens = state.folders[folder] = [];
      } else if (data.gen !== gens.length || data.prev_dek_id !== gens[gens.length - 1][0]) {
        throw new TeamLogError('bad_generation', seq);
      }
      gens.push([data.dek_id, author]);
      state.dekIndex[data.dek_id] = [folder, data.gen];
      delete state.stale[folder];
      if (state.formerAdmins) delete state.formerAdmins[folder];
    } else if (kind === 'access.set') {
      const { folder, level } = data;
      if (!own(state.folders, folder)) throw new TeamLogError('folder_unknown', seq);
      const current = own(state.access, folder) && own(state.access[folder], userId)
        ? state.access[folder][userId] : null;
      if (level === null) {
        if (current === null) throw new TeamLogError('unchanged', seq);
        loseAccess(state, folder, userId);
        return;
      }
      if (member === null || !member.active) throw new TeamLogError('not_active', seq);
      if (current === level) throw new TeamLogError('unchanged', seq);
      if (current === 'write' && level === 'read') (state.stale[folder] ||= {})[userId] = true;
      (state.access[folder] ||= {})[userId] = level;
    } else if (kind === 'org.recovery') {
      const pk = data.recovery_pk;
      state.orgRecovery ||= {};
      const current = own(state.orgRecovery, author) ? state.orgRecovery[author] : null;
      if (current === pk) throw new TeamLogError('unchanged', seq);
      if (pk !== null && own(state.seenKeys, pk)) throw new TeamLogError('key_reused', seq);
      if (state.orgRecoveryWrap) delete state.orgRecoveryWrap[author]; // it wraps for the old key
      if (pk === null) delete state.orgRecovery[author];
      else state.orgRecovery[author] = pk;
    } else if (kind === 'org.recovery.wrap') {
      if (!own(state.orgRecovery || {}, author)) throw new TeamLogError('no_recovery_key', seq);
      if (!(data.threshold >= 1 && data.threshold <= data.total_shares && data.total_shares <= 255)) {
        throw new TeamLogError('bad_shares', seq);
      }
      state.orgRecoveryWrap ||= {};
      const current = own(state.orgRecoveryWrap, author) ? state.orgRecoveryWrap[author] : null;
      if (current !== null && Object.keys(data).every((k) => current[k] === data[k])) {
        throw new TeamLogError('unchanged', seq);
      }
      state.orgRecoveryWrap[author] = { ...data };
    }
  }

  function applyRecord(state, record, sodium) {
    const next = cloneState(state);
    applyInPlace(next, record, sodium);
    return next;
  }

  function replay(records, sodium, state = null) {
    const current = state ? cloneState(state) : emptyState();
    for (const record of records) applyInPlace(current, record, sodium);
    return current;
  }

  function nextBody(state, kind, author, data) {
    return { v: FORMAT_VERSION, seq: state.headSeq + 1, prev: state.headHash, type: kind, author, data };
  }

  // ── Decisions (design §4.3). Unknown is always "no". ────────────────
  const isTeamFolder = (state, folder) => own(state.folders, folder);

  function currentKey(state, folder) {
    if (!isTeamFolder(state, folder)) return null;
    const gens = state.folders[folder];
    return gens[gens.length - 1][0];
  }

  function keyGeneration(state, folder, dekId) {
    if (!own(state.dekIndex, dekId) || state.dekIndex[dekId][0] !== folder) return ['unknown', null];
    const gen = state.dekIndex[dekId][1];
    return [gen === state.folders[folder].length - 1 ? 'current' : 'old', gen];
  }

  const isStale = (state, folder) => own(state.stale, folder) && Object.keys(state.stale[folder]).length > 0;
  const maySeal = (state, folder) => isTeamFolder(state, folder) && !isStale(state, folder);

  function memberOf(state, userId) {
    return own(state.members, userId) ? state.members[userId] : null;
  }

  function isAdmin(state, userId) {
    const m = memberOf(state, userId);
    return m !== null && m.active && m.role === 'admin';
  }

  function accessOf(state, folder, userId) {
    return own(state.access, folder) && own(state.access[folder], userId) ? state.access[folder][userId] : null;
  }

  function mayWrite(state, folder, userId) {
    const m = memberOf(state, userId);
    if (m === null || !m.active || !isTeamFolder(state, folder)) return false;
    return m.role === 'admin' || accessOf(state, folder, userId) === 'write';
  }

  function keyRecipients(state, folder) {
    if (!isTeamFolder(state, folder) || !own(state.access, folder)) return [];
    return Object.keys(state.access[folder]).sort()
      .filter((uid) => state.members[uid].active)
      .map((uid) => [uid, state.members[uid].encryptionPk, state.access[folder][uid]]);
  }

  function mayHoldKey(state, userId, dekId) {
    const m = memberOf(state, userId);
    if (!own(state.dekIndex, dekId) || m === null || !m.active) return false;
    const [folder, gen] = state.dekIndex[dekId];
    const gens = state.folders[folder];
    if (gen !== gens.length - 1) return false;
    // Review 8bc70f7 M1: the admin holds every current key by the role.
    return accessOf(state, folder, userId) !== null || gens[gens.length - 1][1] === userId || m.role === 'admin';
  }

  function envelopeValid(state, signerId, targetId, dekId, level, targetEncryptionPk) {
    if (!mayHoldKey(state, targetId, dekId)) return false;
    const folder = state.dekIndex[dekId][0];
    // Or an admin who handed the role over while this key was current (R13-8).
    const signer = memberOf(state, signerId);
    const former = state.formerAdmins || {};
    const handedOver = signer !== null && signer.active && own(former, folder) && own(former[folder], signerId);
    if (!isAdmin(state, signerId) && !handedOver) return false;
    if (state.members[targetId].encryptionPk !== targetEncryptionPk) return false;
    const granted = accessOf(state, folder, targetId);
    return (granted !== null ? granted : isAdmin(state, targetId) ? 'write' : null) === level;
  }

  // Why a live folder/item by userId sealed with dekId is not valid, or null
  // (the server's push rule; sealing=false for a pulled copy). folder is the
  // team folder at or above the object's parent.
  function itemRefusal(state, userId, objId, folder, dekId, ownDek, sealing = true) {
    // A pulled copy by an admin who handed the role over while the folder's
    // current key was current was written while admin.
    const wrote = (where) => {
      if (mayWrite(state, where, userId)) return true;
      const m = memberOf(state, userId);
      const former = state.formerAdmins || {};
      return !sealing && m !== null && m.active && own(former, where) && own(former[where], userId);
    };
    const found = dekId !== null && own(state.dekIndex, dekId) ? state.dekIndex[dekId] : null;
    if (found === null) {
      if (folder === null) return null;
      if (!ownDek) return 'sealed with a key the team log does not know';
      if (!wrote(folder)) return 'team log gives no write access here';
      return null;
    }
    const keyFolder = found[0];
    if (keyFolder !== folder && keyFolder !== objId) return "sealed with another folder's team key";
    if (keyGeneration(state, keyFolder, dekId)[0] !== 'current') return 'sealed with an old key generation';
    if (sealing && !maySeal(state, keyFolder)) return 'folder waits for a re-key';
    if (!wrote(keyFolder)) return 'team log gives no write access here';
    return null;
  }

  // TL7: one active admin per organisation at a head a client follows.
  function adminPolicyRefusal(state) {
    const admins = Object.keys(state.members).filter((uid) => isAdmin(state, uid));
    return admins.length > 1 ? 'more than one admin' : null;
  }

  // The change a record made, as a device makes it again on another head:
  // a folder.key's generation and a member.keys' proof are bound to the head.
  function changeKey(body) {
    const { gen: _gen, new_key_sig: _sig, ...data } = body.data;
    return canonical({ type: body.type, data });
  }

  // Review 18c300f R16-H1 (src/sezam/teamlog.py fork_refusal,
  // tests/vectors/team_log_fork.json): whether a device follows a server log
  // that forks from its copy. lost: its records from the fork on; theirs: the
  // server's; heldKeys: [signingPk, encryptionPk] hex or null; withdrawn: a
  // Set of record hashes. { refusal, missing }: refusal null follows, missing
  // the seqs of this account's lost changes not on the server's side.
  function forkRefusal(lost, theirs, userId, heldKeys, withdrawn, sodium) {
    const lostBodies = lost.map((record) => parseBody(record.body, null));
    const theirBodies = theirs.map((record) => parseBody(record.body, null));
    const was = new Set(lostBodies.map(changeKey));
    for (let i = 0; i < theirs.length; i++) {
      const body = theirBodies[i];
      if (userId === null || body.author !== userId) continue;
      const seq = body.seq;
      if (withdrawn.has(recordHash(theirs[i], sodium))) {
        return { refusal: `its record ${seq} is one this device withdrew`, missing: [] };
      }
      if (body.type === 'member.role' && !was.has(changeKey(body))) {
        return { refusal: `its record ${seq} changes a role this device did not lose`, missing: [] };
      }
      if (body.type === 'member.add' && !was.has(changeKey(body))) {
        return { refusal: `its record ${seq} adds a member this device did not lose`, missing: [] };
      }
      if (body.type === 'member.keys' && !was.has(changeKey(body)) && (heldKeys === null ||
          body.data.signing_pk !== heldKeys[0] || body.data.encryption_pk !== heldKeys[1])) {
        return { refusal: `its record ${seq} names keys this device does not hold`, missing: [] };
      }
    }
    const made = new Set(theirBodies.map(changeKey));
    for (let i = 0; i + 1 < lostBodies.length; i++) {
      // A readmit (member.remove + member.add of one member, one append)
      // is on the server's side whole or not at all.
      const [first, second] = [lostBodies[i], lostBodies[i + 1]];
      if (first.type === 'member.remove' && second.type === 'member.add' &&
          first.data.user_id === second.data.user_id &&
          made.has(changeKey(first)) !== made.has(changeKey(second))) {
        return { refusal: `it holds one half of the readmit at record ${first.seq}`, missing: [] };
      }
    }
    const missing = [];
    for (const body of lostBodies) {
      if (made.has(changeKey(body))) continue;
      if (userId === null || body.author !== userId) {
        return { refusal: `record ${body.seq} this device saw is not on the server's side (it follows once its author makes that change again)`, missing: [] };
      }
      missing.push(body.seq);
    }
    return { refusal: null, missing };
  }

  // Review 18c300f R16-M5: the kinds of this account's lost changes a device
  // makes again on the server's head (a genesis or member.keys is bound to the
  // head it was signed on).
  const REMADE_KINDS = ['member.add', 'member.role', 'member.remove', 'access.set', 'folder.key',
                        'org.recovery', 'org.recovery.wrap'];

  // The data a lost change is made again with on `state` (the desktop's
  // resolve_change, src/sezam/vault/team_log_state.py), or null when the log
  // has it already. A folder.key whose folder moved on to another key throws.
  function resolveChange(state, kind, data) {
    const member = own(state.members, data.user_id || '') ? state.members[data.user_id] : null;
    const same = (a, b) => canonical(a) === canonical(b);
    switch (kind) {
      case 'member.add':
        return member !== null && member.active && member.signingPk === data.signing_pk &&
          member.encryptionPk === data.encryption_pk ? null : data;
      case 'member.role':
        return member !== null && member.role === data.role ? null : data;
      case 'member.remove':
        return member === null || !member.active ? null : data;
      case 'access.set': {
        const access = own(state.access, data.folder) ? state.access[data.folder] : {};
        return (own(access, data.user_id) ? access[data.user_id] : null) === data.level ? null : data;
      }
      case 'folder.key': {
        if (own(state.dekIndex, data.dek_id)) return null;
        const current = currentKey(state, data.folder);
        if (current !== data.prev_dek_id) {
          throw new TeamLogError('folder_key_moved', state.headSeq + 1,
            `folder ${data.folder} is at key ${current}, not ${data.prev_dek_id}`);
        }
        return { ...data, gen: own(state.folders, data.folder) ? state.folders[data.folder].length : 0 };
      }
      case 'org.recovery':
        return Object.values(state.orgRecovery || {}).includes(data.recovery_pk) ? null : data;
      case 'org.recovery.wrap':
        return Object.values(state.orgRecoveryWrap || {}).some((wrap) => same(wrap, data)) ? null : data;
      default:
        throw new TeamLogError('not_remade', state.headSeq + 1, `a lost ${kind} is not made again`);
    }
  }

  function tombstoneRefusal(state, userId, storedDekId) {
    const found = storedDekId !== null && own(state.dekIndex, storedDekId) ? state.dekIndex[storedDekId] : null;
    if (found !== null && !mayWrite(state, found[0], userId)) return 'team log gives no write access here';
    return null;
  }

  // Leaving the team folder oldFolder is a removal from it (needs write access there).
  // ownPersonal (TL7): the stored object is userId's own, sealed with a key of theirs
  // the log does not know; it may leave for outside every team folder.
  function moveRefusal(state, userId, oldFolder, newFolder, ownPersonal = false) {
    if (ownPersonal && newFolder === null) return null;
    if (oldFolder !== null && oldFolder !== newFolder && !mayWrite(state, oldFolder, userId)) {
      return 'team log gives no write access here';
    }
    return null;
  }

  return {
    FORMAT_VERSION, ZERO_HASH, TeamLogError, canonical, parseBody, recordHash, newKeyMessage, signRecord,
    emptyState, stateToJson, applyRecord, replay, nextBody,
    isTeamFolder, currentKey, keyGeneration, isStale, maySeal, isAdmin, mayWrite, keyRecipients,
    mayHoldKey, envelopeValid, itemRefusal, tombstoneRefusal, moveRefusal, adminPolicyRefusal,
    signingKeyRetired, changeKey, forkRefusal, REMADE_KINDS, resolveChange,
  };
})();

if (typeof globalThis !== 'undefined') globalThis.SezamTeamLog = SezamTeamLog;

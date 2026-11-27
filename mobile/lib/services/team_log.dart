// Signed team log: replay and decisions (docs/DESIGN_TEAM_LOG.md).
//
// Port of src/sezam/teamlog.py; must pass tests/vectors/team_log.json exactly
// (same state, same answers, same error code at the same record). Ed25519
// verification is injected (libsodium in the app and in tests), SHA-256 is
// package:crypto.

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto_pkg;

typedef Ed25519Verify = bool Function(
    Uint8List signature, Uint8List message, Uint8List publicKey);

class TeamLogError implements Exception {
  TeamLogError(this.code, this.seq, [this.detail = '']);
  final String code;
  final int seq;
  final String detail;

  @override
  String toString() =>
      'team log record $seq: $code${detail.isEmpty ? '' : ' ($detail)'}';
}

class TeamMember {
  TeamMember(this.signingPk, this.encryptionPk, this.role, this.active);
  String signingPk;
  String encryptionPk;
  String role;
  bool active;

  TeamMember copy() => TeamMember(signingPk, encryptionPk, role, active);
}

class TeamState {
  String org = '';
  String genesisHash = '';
  int headSeq = -1;
  String headHash = TeamLog.zeroHash;
  final Map<String, TeamMember> members = {};
  // folder -> [(dekId, author)] by generation
  final Map<String, List<List<String>>> folders = {};
  final Map<String, Map<String, String>> access = {};
  final Map<String, Set<String>> stale = {};
  final Map<String, String> seenKeys = {};
  final Map<String, List<Object>> dekIndex = {}; // dekId -> [folder, gen]
  // folder -> admins handed over while its current key was current: what
  // they sealed with it then is still theirs (review 1141a20).
  final Map<String, Set<String>> formerAdmins = {};
  int rules = 0; // the rules version of the last record (0: no log yet)
  // admin -> org recovery signing key (hex), review 8595ec1 (R10-D).
  final Map<String, String> orgRecovery = {};
  // admin -> org.recovery.wrap data of that key (capability run 316).
  final Map<String, Map<String, Object?>> orgRecoveryWrap = {};

  TeamState copy() {
    final out = TeamState()
      ..rules = rules
      ..org = org
      ..genesisHash = genesisHash
      ..headSeq = headSeq
      ..headHash = headHash;
    members.forEach((k, v) => out.members[k] = v.copy());
    folders.forEach(
        (k, v) => out.folders[k] = [for (final g in v) List.of(g)]);
    access.forEach((k, v) => out.access[k] = Map.of(v));
    stale.forEach((k, v) => out.stale[k] = Set.of(v));
    out.seenKeys.addAll(seenKeys);
    dekIndex.forEach((k, v) => out.dekIndex[k] = List.of(v));
    formerAdmins.forEach((k, v) => out.formerAdmins[k] = Set.of(v));
    out.orgRecovery.addAll(orgRecovery);
    orgRecoveryWrap.forEach((k, v) => out.orgRecoveryWrap[k] = Map.of(v));
    return out;
  }

  /// Comparable form used by the decision vectors.
  Map<String, Object?> toJson() {
    List<String> sorted(Iterable<String> keys) => keys.toList()..sort();
    return {
      if (orgRecovery.isNotEmpty)
        'org_recovery': {
          for (final u in sorted(orgRecovery.keys)) u: orgRecovery[u],
        },
      if (orgRecoveryWrap.isNotEmpty)
        'org_recovery_wrap': {
          for (final u in sorted(orgRecoveryWrap.keys))
            u: {
              for (final k in sorted(orgRecoveryWrap[u]!.keys))
                k: orgRecoveryWrap[u]![k],
            },
        },
      'rules': rules,
      'org': org,
      'genesis_hash': genesisHash,
      'head_seq': headSeq,
      'head_hash': headHash,
      'members': {
        for (final uid in sorted(members.keys))
          uid: {
            'signing_pk': members[uid]!.signingPk,
            'encryption_pk': members[uid]!.encryptionPk,
            'role': members[uid]!.role,
            'active': members[uid]!.active ? 1 : 0,
          },
      },
      'folders': {
        for (final f in sorted(folders.keys))
          f: [for (final g in folders[f]!) g[0]],
      },
      'access': {
        for (final f in sorted(access.keys))
          if (access[f]!.isNotEmpty)
            f: {for (final u in sorted(access[f]!.keys)) u: access[f]![u]},
      },
      'stale': {
        for (final f in sorted(stale.keys))
          if (stale[f]!.isNotEmpty) f: sorted(stale[f]!),
      },
    };
  }
}

class TeamLog {
  TeamLog(this.verify);

  final Ed25519Verify verify;

  // A body's "v" names the rules its record is judged by (review 8595ec1,
  // R10-B); 1 = a member could get a retired key back, 2 = it stays retired.
  static const rulesVersions = [1, 2];
  static const formatVersion = 2;
  static const sigDomain = 'sezam-team-log-v1\u0000';
  static const hashDomain = 'sezam-team-log-hash-v1\u0000';
  static const newKeyDomain = 'sezam-team-log-newkey-v1\u0000';
  static final zeroHash = '0' * 64;
  static const maxInt = 9007199254740991;
  static const roles = ['admin', 'member'];
  static const levels = ['read', 'write'];
  static final _ulid = RegExp(r'^[0-7][0-9A-HJKMNP-TV-Z]{25}$');
  static final _hex64 = RegExp(r'^[0-9a-f]{64}$');
  static final _hex128 = RegExp(r'^[0-9a-f]{128}$');
  static final _hex144 = RegExp(r'^[0-9a-f]{144}$');
  static final _safeStr = RegExp(r'^[\x20-\x21\x23-\x5b\x5d-\x7e]*$');
  static const _bodyFields = ['author', 'data', 'prev', 'seq', 'type', 'v'];
  // Field order matters: errors name the first failing field, as in Python.
  static const _dataSchema = <String, List<List<String>>>{
    'genesis': [
      ['org', 'ulid'], ['user_id', 'ulid'], ['signing_pk', 'hex64'],
      ['encryption_pk', 'hex64'],
    ],
    'member.add': [
      ['user_id', 'ulid'], ['signing_pk', 'hex64'], ['encryption_pk', 'hex64'],
      ['role', 'role'],
    ],
    'member.role': [['user_id', 'ulid'], ['role', 'role']],
    'member.remove': [['user_id', 'ulid']],
    'member.keys': [
      ['user_id', 'ulid'], ['signing_pk', 'hex64'], ['encryption_pk', 'hex64'],
      ['new_key_sig', 'hex128'],
    ],
    'folder.key': [
      ['folder', 'ulid'], ['gen', 'int'], ['dek_id', 'ulid'],
      ['prev_dek_id', 'ulid?'],
    ],
    'access.set': [['folder', 'ulid'], ['user_id', 'ulid'], ['level', 'level?']],
    // Review 8595ec1 (R10-D): the admin's org recovery key (null: none),
    // from rules 2.
    'org.recovery': [['recovery_pk', 'hex64?']],
    // Capability run 316: the KEK wrap the shares of the author's named
    // recovery key open, so a restored server still serves it.
    'org.recovery.wrap': [
      ['wrapped_kek', 'hex144'], ['key_epoch', 'int'], ['threshold', 'int'],
      ['total_shares', 'int'],
    ],
  };
  static const _recoveryTypes = ['org.recovery', 'org.recovery.wrap'];

  // ── Canonical encoding ──────────────────────────────────────────────

  static void _checkValue(Object? value, int seq) {
    if (value == null) return;
    if (value is bool) throw TeamLogError('bad_encoding', seq, 'boolean');
    if (value is int) {
      if (value < 0 || value > maxInt) {
        throw TeamLogError('bad_encoding', seq, 'integer out of range');
      }
      return;
    }
    if (value is String) {
      if (!_safeStr.hasMatch(value)) {
        throw TeamLogError('bad_encoding', seq, 'string');
      }
      return;
    }
    if (value is Map) {
      for (final entry in value.entries) {
        final key = entry.key;
        if (key is! String || !_safeStr.hasMatch(key)) {
          throw TeamLogError('bad_encoding', seq, 'key');
        }
        _checkValue(entry.value, seq);
      }
      return;
    }
    throw TeamLogError('bad_encoding', seq, value.runtimeType.toString());
  }

  static String _encode(Object? value) {
    if (value == null) return 'null';
    if (value is int) return value.toString();
    if (value is String) return '"$value"';
    final map = value as Map;
    final keys = map.keys.cast<String>().toList()..sort();
    return '{${keys.map((k) => '"$k":${_encode(map[k])}').join(',')}}';
  }

  static String canonical(Object? value, [int seq = -1]) {
    _checkValue(value, seq);
    return _encode(value);
  }

  static Map<String, dynamic> parseBody(Object? body, int seq) {
    if (body is! String) {
      throw TeamLogError('bad_encoding', seq, 'body is not a string');
    }
    Object? parsed;
    try {
      parsed = jsonDecode(body);
    } on FormatException {
      throw TeamLogError('bad_encoding', seq, 'json');
    }
    // A duplicate key, a float, an escape or whitespace changes the re-encoding.
    if (parsed is! Map<String, dynamic> || canonical(parsed, seq) != body) {
      throw TeamLogError('bad_encoding', seq, 'not canonical');
    }
    return parsed;
  }

  // ── Bytes ───────────────────────────────────────────────────────────

  static Uint8List _ascii(String text) => Uint8List.fromList(ascii.encode(text));

  static Uint8List fromHex(String hex) => Uint8List.fromList([
        for (var i = 0; i + 1 < hex.length; i += 2)
          int.parse(hex.substring(i, i + 2), radix: 16),
      ]);

  static String toHex(List<int> bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  static Uint8List _concat(List<Uint8List> parts) {
    final out = BytesBuilder(copy: false);
    for (final p in parts) {
      out.add(p);
    }
    return out.toBytes();
  }

  static Uint8List sigMessage(String body) => _ascii(sigDomain + body);

  static String recordHash(Map<String, dynamic> record) => toHex(crypto_pkg
      .sha256
      .convert(_concat([
        _ascii(hashDomain + (record['body'] as String)),
        fromHex(record['sig'] as String),
      ]))
      .bytes);

  static Uint8List newKeyMessage(
          String prev, String userId, String signingPk, String encryptionPk) =>
      _concat([
        _ascii(newKeyDomain), fromHex(prev), _ascii(userId),
        fromHex(signingPk), fromHex(encryptionPk),
      ]);

  /// A record ready to send: [sign] signs the message with the author's key.
  static Map<String, String> signRecord(
      Map<String, Object?> body, Uint8List Function(Uint8List message) sign) {
    final text = canonical(body, body['seq'] as int? ?? -1);
    return {'body': text, 'sig': toHex(sign(sigMessage(text)))};
  }

  static Map<String, Object?> nextBody(
          TeamState state, String kind, String author, Map<String, Object?> data) =>
      {
        'v': formatVersion,
        'seq': state.headSeq + 1,
        'prev': state.headHash,
        'type': kind,
        'author': author,
        'data': data,
      };

  // ── Replay ──────────────────────────────────────────────────────────

  static bool _is(String kind, Object? value) {
    switch (kind) {
      case 'ulid':
        return value is String && _ulid.hasMatch(value);
      case 'hex64':
        return value is String && _hex64.hasMatch(value);
      case 'hex128':
        return value is String && _hex128.hasMatch(value);
      case 'hex144':
        return value is String && _hex144.hasMatch(value);
      case 'role':
        return roles.contains(value);
      case 'level':
        return levels.contains(value);
      default:
        return value is int; // 'int'
    }
  }

  static bool _sameKeys(Map map, List<String> names) {
    final keys = map.keys.map((k) => '$k').toList()..sort();
    final want = List.of(names)..sort();
    if (keys.length != want.length) return false;
    for (var i = 0; i < keys.length; i++) {
      if (keys[i] != want[i]) return false;
    }
    return true;
  }

  static void _validateBody(Map<String, dynamic> body, int seq) {
    if (!_sameKeys(body, _bodyFields)) {
      throw TeamLogError('bad_schema', seq, 'body fields');
    }
    if (!rulesVersions.contains(body['v'])) {
      throw TeamLogError('bad_schema', seq, 'version');
    }
    if (body['seq'] is! int) throw TeamLogError('bad_schema', seq, 'seq');
    if (!_is('hex64', body['prev'])) {
      throw TeamLogError('bad_schema', seq, 'prev');
    }
    if (!_is('ulid', body['author'])) {
      throw TeamLogError('bad_schema', seq, 'author');
    }
    final type = body['type'];
    final schema = type is String ? _dataSchema[type] : null;
    if (schema == null || _recoveryTypes.contains(type) && (body['v'] as int) < 2) {
      throw TeamLogError('bad_schema', seq, 'type');
    }
    final data = body['data'];
    if (data is! Map || !_sameKeys(data, [for (final f in schema) f[0]])) {
      throw TeamLogError('bad_schema', seq, 'data fields');
    }
    for (final field in schema) {
      final value = data[field[0]];
      if (value == null && field[1].endsWith('?')) continue;
      if (!_is(field[1].replaceAll('?', ''), value)) {
        throw TeamLogError('bad_schema', seq, field[0]);
      }
    }
  }

  void _verify(String pkHex, Uint8List message, String sigHex, int seq,
      [String code = 'bad_signature']) {
    bool ok;
    try {
      ok = verify(fromHex(sigHex), message, fromHex(pkHex));
    } catch (_) {
      ok = false;
    }
    if (!ok) throw TeamLogError(code, seq);
  }

  static void _claimKeys(
    TeamState state,
    String userId,
    int seq,
    List<String> pks,
  ) {
    for (final pk in pks) {
      final owner = state.seenKeys[pk];
      final current = state.members[userId];
      // Rules 2: a key the log retired stays retired, also for its owner.
      if (owner != null &&
          (owner != userId ||
              state.rules >= 2 &&
                  (current == null ||
                      (pk != current.signingPk && pk != current.encryptionPk)))) {
        throw TeamLogError('key_reused', seq);
      }
    }
    if (pks.toSet().length != pks.length) throw TeamLogError('key_reused', seq);
    for (final pk in pks) {
      state.seenKeys[pk] = userId;
    }
  }

  static int _activeAdmins(TeamState state) => state.members.values
      .where((m) => m.active && m.role == 'admin')
      .length;

  static void _loseAccess(TeamState state, String folder, String userId) {
    state.access[folder]?.remove(userId);
    state.stale.putIfAbsent(folder, () => <String>{}).add(userId);
  }

  void _apply(TeamState state, Object? record) {
    final expectedSeq = state.headSeq + 1;
    if (record is! Map || !_sameKeys(record, const ['body', 'sig'])) {
      throw TeamLogError('bad_schema', expectedSeq, 'record fields');
    }
    if (!_is('hex128', record['sig'])) {
      throw TeamLogError('bad_schema', expectedSeq, 'sig');
    }
    final body = parseBody(record['body'], expectedSeq);
    _validateBody(body, expectedSeq);
    final seq = body['seq'] as int;
    if (seq != expectedSeq) throw TeamLogError('bad_seq', expectedSeq);
    if (body['prev'] != state.headHash) throw TeamLogError('bad_prev', seq);
    final rules = body['v'] as int;
    if (rules < state.rules) throw TeamLogError('rules_downgrade', seq);
    state.rules = rules;
    final kind = body['type'] as String;
    final author = body['author'] as String;
    final data = body['data'] as Map<String, dynamic>;
    final sig = record['sig'] as String;
    final message = sigMessage(record['body'] as String);

    if (kind == 'genesis') {
      if (seq != 0) throw TeamLogError('bad_genesis', seq, 'not first');
      if (author != data['user_id']) {
        throw TeamLogError('bad_genesis', seq, 'author');
      }
      _verify(data['signing_pk'] as String, message, sig, seq);
      _claimKeys(state, author, seq,
          [data['signing_pk'] as String, data['encryption_pk'] as String]);
      state.org = data['org'] as String;
      state.members[author] = TeamMember(data['signing_pk'] as String,
          data['encryption_pk'] as String, 'admin', true);
    } else {
      if (seq == 0) {
        throw TeamLogError('bad_genesis', seq, 'first record is not genesis');
      }
      final signer = state.members[author];
      if (signer == null || !signer.active) {
        throw TeamLogError('not_member', seq);
      }
      _verify(signer.signingPk, message, sig, seq);
      if (kind != 'member.keys' && signer.role != 'admin') {
        throw TeamLogError('not_admin', seq);
      }
      _applyChange(state, seq, kind, author, data, body['prev'] as String);
    }
    state.headSeq = seq;
    state.headHash = recordHash(Map<String, dynamic>.from(record));
    if (seq == 0) state.genesisHash = state.headHash;
  }

  void _applyChange(TeamState state, int seq, String kind, String author,
      Map<String, dynamic> data, String prev) {
    final userId = data['user_id'] as String?;
    final member = userId == null ? null : state.members[userId];

    switch (kind) {
      case 'member.add':
        if (member != null && member.active) {
          throw TeamLogError('member_exists', seq);
        }
        _claimKeys(state, userId!, seq,
            [data['signing_pk'] as String, data['encryption_pk'] as String]);
        state.members[userId] = TeamMember(data['signing_pk'] as String,
            data['encryption_pk'] as String, data['role'] as String, true);
      case 'member.role':
        if (member == null || !member.active) {
          throw TeamLogError('not_active', seq);
        }
        if (member.role == data['role']) throw TeamLogError('unchanged', seq);
        if (member.role == 'admin' && _activeAdmins(state) == 1) {
          throw TeamLogError('last_admin', seq);
        }
        if (member.role == 'admin') {
          for (final folder in state.folders.keys) {
            state.formerAdmins.putIfAbsent(folder, () => <String>{}).add(userId!);
          }
          state.orgRecovery.remove(userId);
          state.orgRecoveryWrap.remove(userId);
        }
        member.role = data['role'] as String;
      case 'member.remove':
        if (member == null || !member.active) {
          throw TeamLogError('not_active', seq);
        }
        if (member.role == 'admin' && _activeAdmins(state) == 1) {
          throw TeamLogError('last_admin', seq);
        }
        member.active = false;
        state.orgRecovery.remove(userId);
        state.orgRecoveryWrap.remove(userId);
        for (final entry in state.folders.entries) {
          final hasAccess = state.access[entry.key]?.containsKey(userId) ?? false;
          if (hasAccess || entry.value.last[1] == userId) {
            _loseAccess(state, entry.key, userId!);
          }
        }
      case 'member.keys':
        if (author != userId) throw TeamLogError('not_self', seq);
        final spk = data['signing_pk'] as String;
        final epk = data['encryption_pk'] as String;
        _verify(spk, newKeyMessage(prev, userId!, spk, epk),
            data['new_key_sig'] as String, seq, 'bad_new_key_signature');
        // Review e443cbc H1: two keys the member does not hold in either role
        // (a swap X -> Y -> X made the server's rotation walk loop for good).
        final held = {member!.signingPk, member.encryptionPk};
        if (held.contains(spk) || held.contains(epk)) {
          throw TeamLogError('key_reused', seq);
        }
        _claimKeys(state, userId, seq, [spk, epk]);
        member
          ..signingPk = spk
          ..encryptionPk = epk;
      case 'folder.key':
        final folder = data['folder'] as String;
        final dekId = data['dek_id'] as String;
        final gen = data['gen'] as int;
        if (state.dekIndex.containsKey(dekId)) {
          throw TeamLogError('dek_reused', seq);
        }
        var gens = state.folders[folder];
        if (gens == null) {
          if (gen != 0 || data['prev_dek_id'] != null) {
            throw TeamLogError('bad_generation', seq);
          }
          gens = state.folders[folder] = [];
        } else if (gen != gens.length || data['prev_dek_id'] != gens.last[0]) {
          throw TeamLogError('bad_generation', seq);
        }
        gens.add([dekId, author]);
        state.dekIndex[dekId] = [folder, gen];
        state.stale.remove(folder);
        state.formerAdmins.remove(folder);
      case 'access.set':
        final folder = data['folder'] as String;
        final level = data['level'] as String?;
        if (!state.folders.containsKey(folder)) {
          throw TeamLogError('folder_unknown', seq);
        }
        final current = state.access[folder]?[userId];
        if (level == null) {
          if (current == null) throw TeamLogError('unchanged', seq);
          _loseAccess(state, folder, userId!);
          return;
        }
        if (member == null || !member.active) {
          throw TeamLogError('not_active', seq);
        }
        if (current == level) throw TeamLogError('unchanged', seq);
        if (current == 'write' && level == 'read') {
          state.stale.putIfAbsent(folder, () => <String>{}).add(userId!);
        }
        state.access.putIfAbsent(folder, () => {})[userId!] = level;
      case 'org.recovery':
        final pk = data['recovery_pk'] as String?;
        if (state.orgRecovery[author] == pk) {
          throw TeamLogError('unchanged', seq);
        }
        if (pk != null && state.seenKeys.containsKey(pk)) {
          throw TeamLogError('key_reused', seq);
        }
        state.orgRecoveryWrap.remove(author); // it wraps for the old key
        if (pk == null) {
          state.orgRecovery.remove(author);
        } else {
          state.orgRecovery[author] = pk;
        }
      case 'org.recovery.wrap':
        if (!state.orgRecovery.containsKey(author)) {
          throw TeamLogError('no_recovery_key', seq);
        }
        final threshold = data['threshold'] as int;
        final total = data['total_shares'] as int;
        if (threshold < 1 || threshold > total || total > 255) {
          throw TeamLogError('bad_shares', seq);
        }
        final current = state.orgRecoveryWrap[author];
        if (current != null && data.keys.every((k) => current[k] == data[k])) {
          throw TeamLogError('unchanged', seq);
        }
        state.orgRecoveryWrap[author] = Map<String, Object?>.from(data);
    }
  }

  /// The state after [record]; throws [TeamLogError] and leaves [state] as is.
  TeamState applyRecord(TeamState state, Object? record) {
    final next = state.copy();
    _apply(next, record);
    return next;
  }

  /// Replay [records] onto a copy of [state] (a fresh log when null).
  TeamState replay(List<Object?> records, [TeamState? state]) {
    final current = state?.copy() ?? TeamState();
    for (final record in records) {
      _apply(current, record);
    }
    return current;
  }

  // ── Decisions (design §4.3). Unknown is always "no". ────────────────

  static bool isTeamFolder(TeamState s, String folder) =>
      s.folders.containsKey(folder);

  static String? currentKey(TeamState s, String folder) =>
      s.folders[folder]?.last[0];

  /// ['current', gen] / ['old', gen] / ['unknown', null].
  static List<Object?> keyGeneration(TeamState s, String folder, String dekId) {
    final found = s.dekIndex[dekId];
    if (found == null || found[0] != folder) return ['unknown', null];
    final gen = found[1] as int;
    return [gen == s.folders[folder]!.length - 1 ? 'current' : 'old', gen];
  }

  static bool isStale(TeamState s, String folder) =>
      s.stale[folder]?.isNotEmpty ?? false;

  static bool maySeal(TeamState s, String folder) =>
      isTeamFolder(s, folder) && !isStale(s, folder);

  static bool isAdmin(TeamState s, String userId) {
    final m = s.members[userId];
    return m != null && m.active && m.role == 'admin';
  }

  static bool mayWrite(TeamState s, String folder, String userId) {
    final m = s.members[userId];
    if (m == null || !m.active || !isTeamFolder(s, folder)) return false;
    return m.role == 'admin' || s.access[folder]?[userId] == 'write';
  }

  static List<List<String>> keyRecipients(TeamState s, String folder) {
    if (!isTeamFolder(s, folder)) return [];
    final access = s.access[folder] ?? const <String, String>{};
    final users = access.keys.toList()..sort();
    return [
      for (final uid in users)
        if (s.members[uid]!.active)
          [uid, s.members[uid]!.encryptionPk, access[uid]!],
    ];
  }

  /// Capability run 294: the log rotated [userId] away from signing key
  /// [pkHex]; a server restored from before the rotation still calls it current.
  static bool signingKeyRetired(TeamState? s, String userId, String pkHex) {
    final m = s?.members[userId];
    return m != null && m.signingPk != pkHex && s!.seenKeys[pkHex] == userId;
  }

  static bool mayHoldKey(TeamState s, String userId, String dekId) {
    final found = s.dekIndex[dekId];
    final m = s.members[userId];
    if (found == null || m == null || !m.active) return false;
    final folder = found[0] as String;
    final gens = s.folders[folder]!;
    if (found[1] != gens.length - 1) return false;
    // Review 8bc70f7 M1: the admin holds every current key by the role.
    return (s.access[folder]?.containsKey(userId) ?? false) ||
        gens.last[1] == userId ||
        m.role == 'admin';
  }

  static bool envelopeValid(TeamState s, String signerId, String targetId,
      String dekId, String? level, String targetEncryptionPk) {
    if (!mayHoldKey(s, targetId, dekId)) return false;
    final folder = s.dekIndex[dekId]![0] as String;
    // Or an admin who handed the role over while this key was current (R13-8).
    final signer = s.members[signerId];
    final handedOver = signer != null &&
        signer.active &&
        (s.formerAdmins[folder]?.contains(signerId) ?? false);
    if (!isAdmin(s, signerId) && !handedOver) return false;
    if (s.members[targetId]!.encryptionPk != targetEncryptionPk) return false;
    final byRole = isAdmin(s, targetId) ? 'write' : null;
    return (s.access[folder]?[targetId] ?? byRole) == level;
  }

  /// Why a live folder/item by [userId] sealed with [dekId] is not valid, or
  /// null (the server's push rule; [sealing] false for a pulled copy).
  /// [folder] is the team folder at or above the object's parent.
  static String? itemRefusal(TeamState s, String userId, String objId,
      String? folder, String? dekId, bool ownDek, [bool sealing = true]) {
    // A pulled copy by an admin who handed the role over while the folder's
    // current key was current was written while admin.
    bool wrote(String where) {
      if (mayWrite(s, where, userId)) return true;
      final m = s.members[userId];
      return !sealing &&
          m != null &&
          m.active &&
          (s.formerAdmins[where]?.contains(userId) ?? false);
    }

    final found = dekId == null ? null : s.dekIndex[dekId];
    if (found == null) {
      if (folder == null) return null;
      if (!ownDek) return 'sealed with a key the team log does not know';
      if (!wrote(folder)) return 'team log gives no write access here';
      return null;
    }
    final keyFolder = found[0] as String;
    if (keyFolder != folder && keyFolder != objId) {
      return "sealed with another folder's team key";
    }
    if (keyGeneration(s, keyFolder, dekId!)[0] != 'current') {
      return 'sealed with an old key generation';
    }
    if (sealing && !maySeal(s, keyFolder)) return 'folder waits for a re-key';
    if (!wrote(keyFolder)) return 'team log gives no write access here';
    return null;
  }

  /// TL7: one active admin per organisation at a head a client follows.
  static String? adminPolicyRefusal(TeamState s) {
    final admins = s.members.keys.where((uid) => isAdmin(s, uid)).length;
    return admins > 1 ? 'more than one admin' : null;
  }

  /// src/sezam/teamlog.py readmitted: where the member.remove [bodies][index]
  /// is undone by its author's member.add of the same account in the same
  /// run of that author's records (one append: a readmit); null otherwise.
  static int? readmitted(List<Map<String, dynamic>> bodies, int index) {
    final body = bodies[index];
    if (body['type'] != 'member.remove') return null;
    for (var later = index + 1; later < bodies.length; later++) {
      final other = bodies[later];
      if (other['author'] != body['author']) return null;
      if (other['type'] == 'member.add' &&
          (other['data'] as Map)['user_id'] == (body['data'] as Map)['user_id']) {
        return later;
      }
    }
    return null;
  }

  /// Review c02cc47 R17-L (src/sezam/teamlog.py restore_part_end,
  /// tests/vectors/team_log_restore_parts.json): the end (exclusive) of a
  /// restore upload part from [start], at most [limit] records, not inside
  /// a readmit.
  static int restorePartEnd(List<Map<String, dynamic>> bodies, int start, int limit) {
    final end = start + limit < bodies.length ? start + limit : bodies.length;
    if (end == bodies.length) return end;
    for (var index = start; index < end; index++) {
      final undone = readmitted(bodies, index);
      if (undone != null && undone >= end) return index > start ? index : end;
    }
    return end;
  }

  /// The change a record made, as a device makes it again on another head:
  /// a folder.key's generation and a member.keys' proof are bound to the head.
  static String changeKey(Map<String, dynamic> body) {
    final data = Map<String, dynamic>.from(body['data'] as Map)
      ..remove('gen')
      ..remove('new_key_sig');
    return canonical({'type': body['type'], 'data': data});
  }

  /// Review 18c300f R16-H1 (src/sezam/teamlog.py fork_refusal,
  /// tests/vectors/team_log_fork.json): whether a device follows a server
  /// log that forks from its copy. [lost]: its records from the fork on;
  /// [theirs]: the server's; [heldKeys]: [signing, encryption] pk hex or
  /// null; [withdrawn]: record hashes. (refusal, missing): a refusal null
  /// follows, missing are the seqs of this account's lost changes not on
  /// the server's side.
  static (String?, List<int>) forkRefusal(
    List<Map<String, dynamic>> lost,
    List<Map<String, dynamic>> theirs,
    String? userId,
    List<String>? heldKeys,
    Set<String> withdrawn,
  ) {
    final lostBodies = [for (final r in lost) parseBody(r['body'], -1)];
    final theirBodies = [for (final r in theirs) parseBody(r['body'], -1)];
    final was = {for (final body in lostBodies) changeKey(body)};
    for (var i = 0; i < theirs.length; i++) {
      final body = theirBodies[i];
      if (userId == null || body['author'] != userId) continue;
      final seq = body['seq'];
      if (withdrawn.contains(recordHash(theirs[i]))) {
        return ('its record $seq is one this device withdrew', const []);
      }
      if (body['type'] == 'member.role' && !was.contains(changeKey(body))) {
        return ('its record $seq changes a role this device did not lose', const []);
      }
      if (body['type'] == 'member.add' && !was.contains(changeKey(body))) {
        return ('its record $seq adds a member this device did not lose', const []);
      }
      final data = body['data'] as Map;
      if (body['type'] == 'member.keys' &&
          !was.contains(changeKey(body)) &&
          (heldKeys == null ||
              data['signing_pk'] != heldKeys[0] ||
              data['encryption_pk'] != heldKeys[1])) {
        return ('its record $seq names keys this device does not hold', const []);
      }
    }
    final made = {for (final body in theirBodies) changeKey(body)};
    for (var i = 0; i + 1 < lostBodies.length; i++) {
      // A readmit (member.remove + member.add of one member, one append)
      // is on the server's side whole or not at all.
      final first = lostBodies[i];
      final second = lostBodies[i + 1];
      if (first['type'] == 'member.remove' &&
          second['type'] == 'member.add' &&
          (first['data'] as Map)['user_id'] == (second['data'] as Map)['user_id'] &&
          made.contains(changeKey(first)) != made.contains(changeKey(second))) {
        return ('it holds one half of the readmit at record ${first['seq']}', const []);
      }
    }
    // R16-Z SM21 (src/sezam/teamlog.py fork_refusal): a stale device of this
    // account put the lost log back with one link onto the keys held here;
    // the rotations lost here in between are moot.
    bool ownKeys(Map<String, dynamic> body) =>
        body['type'] == 'member.keys' &&
        userId != null &&
        body['author'] == userId &&
        (body['data'] as Map)['user_id'] == userId;
    final landed = [for (final body in theirBodies) if (ownKeys(body)) body['data'] as Map];
    final onHeld = landed.isNotEmpty &&
        heldKeys != null &&
        landed.last['signing_pk'] == heldKeys[0] &&
        landed.last['encryption_pk'] == heldKeys[1];
    final missing = <int>[];
    for (final body in lostBodies) {
      if (made.contains(changeKey(body))) continue;
      if (onHeld && ownKeys(body)) continue;
      if (userId == null || body['author'] != userId) {
        return ("record ${body['seq']} this device saw is not on the server's side (it follows once its author makes that change again)", const []);
      }
      missing.add(body['seq'] as int);
    }
    return (null, missing);
  }

  /// The hashes of this account's lost records a device goes on without
  /// when it follows a fork (src/sezam/teamlog.py fork_abandoned): withdrawn,
  /// so a server that serves them again later is refused (capability
  /// finding 505).
  static List<String> forkAbandoned(List<Map<String, dynamic>> lost, String? userId) => [
        if (userId != null)
          for (final r in lost)
            if (parseBody(r['body'], -1)['author'] == userId) recordHash(r),
      ];

  /// Review 18c300f R16-M5: the kinds of this account's lost changes a
  /// device makes again on the server's head (a genesis or member.keys is
  /// bound to the head it was signed on).
  static const remadeKinds = [
    'member.add', 'member.role', 'member.remove', 'access.set', 'folder.key', 'org.recovery', 'org.recovery.wrap',
  ];

  /// The data a lost change is made again with on [s] (the desktop's
  /// resolve_change, src/sezam/vault/team_log_state.py), or null when the
  /// log has it already. A folder.key whose folder moved on to another key
  /// throws.
  static Map<String, dynamic>? resolveChange(TeamState s, String kind, Map<String, dynamic> data) {
    final member = s.members[data['user_id'] ?? ''];
    switch (kind) {
      case 'member.add':
        return member != null &&
                member.active &&
                member.signingPk == data['signing_pk'] &&
                member.encryptionPk == data['encryption_pk']
            ? null
            : data;
      case 'member.role':
        return member != null && member.role == data['role'] ? null : data;
      case 'member.remove':
        return member == null || !member.active ? null : data;
      case 'access.set':
        // R17-N8: a member's removal takes every access they had, also a queued one.
        if (member != null && !member.active && data['level'] != null) return null;
        return s.access[data['folder']]?[data['user_id']] == data['level'] ? null : data;
      case 'folder.key':
        if (s.dekIndex.containsKey(data['dek_id'])) return null;
        final current = currentKey(s, data['folder'] as String);
        if (current != data['prev_dek_id']) {
          throw TeamLogError('folder_key_moved', s.headSeq + 1,
              "folder ${data['folder']} is at key $current, not ${data['prev_dek_id']}");
        }
        return {...data, 'gen': s.folders[data['folder']]?.length ?? 0};
      case 'org.recovery':
        return s.orgRecovery.values.contains(data['recovery_pk']) ? null : data;
      case 'org.recovery.wrap':
        final wanted = canonical(data);
        return s.orgRecoveryWrap.values.any((wrap) => canonical(wrap) == wanted) ? null : data;
      default:
        throw TeamLogError('not_remade', s.headSeq + 1, 'a lost $kind is not made again');
    }
  }

  /// A deletion of an object sealed with a team key needs write access there.
  static String? tombstoneRefusal(TeamState s, String userId, String? storedDekId) {
    final found = storedDekId == null ? null : s.dekIndex[storedDekId];
    if (found != null && !mayWrite(s, found[0] as String, userId)) {
      return 'team log gives no write access here';
    }
    return null;
  }

  /// Leaving the team folder [oldFolder] is a removal from it (needs write access there).
  /// [ownPersonal] (TL7): the stored object is [userId]'s own, sealed with a key of
  /// theirs the log does not know; it may leave for outside every team folder.
  static String? moveRefusal(
      TeamState s, String userId, String? oldFolder, String? newFolder,
      [bool ownPersonal = false]) {
    if (ownPersonal && newFolder == null) return null;
    if (oldFolder != null && oldFolder != newFolder && !mayWrite(s, oldFolder, userId)) {
      return 'team log gives no write access here';
    }
    return null;
  }
}

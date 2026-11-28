// Signed team log: the phone's door to the Rust core (docs/DESIGN_TEAM_LOG.md).
//
// The replay and every decision from it live once in core/src/teamlog
// (docs/CORE_UNIFICATION.md), reached over FFI (sync_core.dart); the
// desktop, the server and the web page ask the same core. This file only
// checks the signatures the core names (Ed25519 is injected: libsodium in
// the app and in tests), signs new records and gives the replayed state to
// the code that reads it.

import 'dart:convert';
import 'dart:typed_data';

import 'sync_core.dart';

typedef Ed25519Verify =
    bool Function(Uint8List signature, Uint8List message, Uint8List publicKey);

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
  final String signingPk;
  final String encryptionPk;
  final String role;
  final bool active;
}

/// The replayed state as the core gave it: read it, never change it (the
/// core answers from the state it gave). `TeamState()` is the empty log.
class TeamState {
  TeamState() : _core = null;

  TeamState._fromCore(Map<String, dynamic> core) : _core = core {
    org = core['org'] as String;
    genesisHash = core['genesis_hash'] as String;
    headSeq = core['head_seq'] as int;
    headHash = core['head_hash'] as String;
    rules = core['rules'] as int;
    (core['members'] as Map).forEach((uid, m) {
      members[uid as String] = TeamMember(
        m['signing_pk'] as String,
        m['encryption_pk'] as String,
        m['role'] as String,
        m['active'] as bool,
      );
    });
    (core['folders'] as Map).forEach((f, gens) {
      folders[f as String] = [
        for (final g in gens as List)
          [g['dek_id'] as String, g['author'] as String],
      ];
    });
    (core['access'] as Map).forEach(
      (f, a) => access[f as String] = Map<String, String>.from(a as Map),
    );
    (core['stale'] as Map).forEach(
      (f, s) => stale[f as String] = Set<String>.from(s as List),
    );
    seenKeys.addAll(Map<String, String>.from(core['seen_keys'] as Map));
    (core['dek_index'] as Map).forEach(
      (d, w) => dekIndex[d as String] = List<Object>.from(w as List),
    );
    (core['former_admins'] as Map).forEach(
      (f, s) => formerAdmins[f as String] = Set<String>.from(s as List),
    );
    orgRecovery.addAll(Map<String, String>.from(core['org_recovery'] as Map));
    (core['org_recovery_wrap'] as Map).forEach(
      (a, w) =>
          orgRecoveryWrap[a as String] = Map<String, Object?>.from(w as Map),
    );
  }

  final Map<String, dynamic>? _core;
  int? _handle;

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
  // folder -> admins handed over while its current key was current (review 1141a20).
  final Map<String, Set<String>> formerAdmins = {};
  int rules = 0; // the rules version of the last record (0: no log yet)
  // admin -> org recovery signing key (hex), review 8595ec1 (R10-D).
  final Map<String, String> orgRecovery = {};
  // admin -> org.recovery.wrap data of that key (capability run 316).
  final Map<String, Map<String, Object?>> orgRecoveryWrap = {};

  static final _loaded = Finalizer<int>((handle) {
    try {
      syncCore('team_log_free', {'handle': handle});
    } catch (_) {
      // the isolate is shutting down
    }
  });

  /// The core's form of this state (the one it gave, when it gave it).
  Map<String, Object?> toCore() {
    if (_core != null) return _core;
    List<String> sorted(Iterable<String> keys) => keys.toList()..sort();
    return {
      'org': org,
      'genesis_hash': genesisHash,
      'head_seq': headSeq,
      'head_hash': headHash,
      'members': {
        for (final e in members.entries)
          e.key: {
            'signing_pk': e.value.signingPk,
            'encryption_pk': e.value.encryptionPk,
            'role': e.value.role,
            'active': e.value.active,
          },
      },
      'folders': {
        for (final e in folders.entries)
          e.key: [
            for (final g in e.value) {'dek_id': g[0], 'author': g[1]},
          ],
      },
      'access': access,
      'stale': {for (final e in stale.entries) e.key: sorted(e.value)},
      'seen_keys': seenKeys,
      'dek_index': dekIndex,
      'former_admins': {
        for (final e in formerAdmins.entries) e.key: sorted(e.value),
      },
      'rules': rules,
      'org_recovery': orgRecovery,
      'org_recovery_wrap': orgRecoveryWrap,
    };
  }

  /// One answer from the core. Review 8bc70f7 M8: a state the core gave is
  /// loaded there once, not sent whole with every question.
  Object? ask(String fn, List<Object?> args) {
    final questions = [
      {'fn': fn, 'args': args},
    ];
    final team = coreArgument();
    return (syncCore('team_log_ask', {
          if (team.containsKey('team')) 'state': team['team'],
          if (team.containsKey('team_handle')) 'handle': team['team_handle'],
          'questions': questions,
        })
        as List)[0];
  }

  /// This state as the core's other operations take it: `team_handle`
  /// (loaded there once) or `team`.
  Map<String, Object?> coreArgument() {
    if (_core == null) return {'team': toCore()};
    if (_handle == null) {
      _handle = syncCore('team_log_load', {'state': _core}) as int;
      _loaded.attach(this, _handle!);
    }
    return {'team_handle': _handle};
  }

  /// Comparable form used by the decision vectors.
  Map<String, Object?> toJson() =>
      Map<String, Object?>.from(ask('state_json', []) as Map);
}

class TeamLog {
  TeamLog(this.verify);

  final Ed25519Verify verify;

  static const formatVersion = 2;
  static final zeroHash = '0' * 64;

  static T _answer<T>(Object? out, String name) {
    final map = out as Map;
    final refused = map['refused'] as Map?;
    if (refused != null) {
      throw TeamLogError(
        refused['code'] as String,
        refused['seq'] as int? ?? -1,
        refused['detail'] as String? ?? '',
      );
    }
    return map[name] as T;
  }

  // ── Records ─────────────────────────────────────────────────────────

  /// The restricted canonical JSON of the design (§3.3).
  static String canonical(Object? value, [int seq = -1]) {
    try {
      return _answer<String>(
        syncCore('team_log_canonical', {'value': value}),
        'text',
      );
    } on TeamLogError catch (e) {
      throw TeamLogError(e.code, seq);
    } on JsonUnsupportedObjectError {
      throw TeamLogError('bad_encoding', seq, value.runtimeType.toString());
    }
  }

  /// Parse a transmitted body; it must already be in canonical form.
  static Map<String, dynamic> parseBody(Object? body, int seq) {
    if (body is! String) {
      throw TeamLogError('bad_encoding', seq, 'body is not a string');
    }
    try {
      return Map<String, dynamic>.from(
        _answer<Map>(syncCore('team_log_parse_body', {'body': body}), 'body'),
      );
    } on TeamLogError catch (e) {
      throw TeamLogError(e.code, seq);
    }
  }

  static Uint8List fromHex(String hex) => Uint8List.fromList([
    for (var i = 0; i + 1 < hex.length; i += 2)
      int.parse(hex.substring(i, i + 2), radix: 16),
  ]);

  static String toHex(List<int> bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  static Uint8List sigMessage(String body) =>
      fromHex(syncCore('team_log_sig_message', {'body': body}) as String);

  static String recordHash(Map<String, dynamic> record) =>
      syncCore('team_log_record_hash', {
            'body': record['body'],
            'sig': record['sig'],
          })
          as String;

  static Uint8List newKeyMessage(
    String prev,
    String userId,
    String signingPk,
    String encryptionPk,
  ) => fromHex(
    syncCore('team_log_new_key_message', {
          'prev': prev,
          'user_id': userId,
          'signing_pk': signingPk,
          'encryption_pk': encryptionPk,
        })
        as String,
  );

  /// A record ready to send: [sign] signs the message with the author's key.
  static Map<String, String> signRecord(
    Map<String, Object?> body,
    Uint8List Function(Uint8List message) sign,
  ) {
    final text = canonical(body, body['seq'] as int? ?? -1);
    return {'body': text, 'sig': toHex(sign(sigMessage(text)))};
  }

  static Map<String, Object?> nextBody(
    TeamState state,
    String kind,
    String author,
    Map<String, Object?> data,
  ) => Map<String, Object?>.from(
    state.ask('next_body', [kind, author, data]) as Map,
  );

  // ── Replay ──────────────────────────────────────────────────────────

  /// How many of the core's signature checks pass, from the first.
  int _passed(List checks) {
    for (var i = 0; i < checks.length; i++) {
      final c = checks[i] as Map;
      bool ok;
      try {
        ok = verify(
          fromHex(c['sig'] as String),
          fromHex(c['message'] as String),
          fromHex(c['pk'] as String),
        );
      } catch (_) {
        ok = false;
      }
      if (!ok) return i;
    }
    return checks.length;
  }

  /// Replay [records] onto [state] (a fresh log when null); throws
  /// [TeamLogError] on the first bad record and never changes [state].
  TeamState replay(List<Object?> records, [TeamState? state]) {
    final base = state?.toCore();
    final checks =
        (syncCore('team_log_replay', {'records': records, 'state': base})
            as Map)['checks'];
    final out = syncCore('team_log_replay', {
      'records': records,
      'state': base,
      'verified': _passed(checks as List),
    });
    return TeamState._fromCore(
      Map<String, dynamic>.from(_answer<Map>(out, 'state')),
    );
  }

  /// The state after [record]; throws [TeamLogError] and leaves [state] as is.
  TeamState applyRecord(TeamState state, Object? record) =>
      replay([record], state);

  // ── Decisions (design §4.3), all the core's. Unknown is always "no". ─

  static bool isTeamFolder(TeamState s, String folder) =>
      s.ask('is_team_folder', [folder]) as bool;

  static String? currentKey(TeamState s, String folder) =>
      s.ask('current_key', [folder]) as String?;

  /// ['current', gen] / ['old', gen] / ['unknown', null].
  static List<Object?> keyGeneration(
    TeamState s,
    String folder,
    String dekId,
  ) => List<Object?>.from(s.ask('key_generation', [folder, dekId]) as List);

  static bool isStale(TeamState s, String folder) =>
      s.ask('is_stale', [folder]) as bool;

  static bool maySeal(TeamState s, String folder) =>
      s.ask('may_seal', [folder]) as bool;

  static bool isAdmin(TeamState s, String userId) =>
      s.ask('is_admin', [userId]) as bool;

  static bool mayWrite(TeamState s, String folder, String userId) =>
      s.ask('may_write', [folder, userId]) as bool;

  static List<List<String>> keyRecipients(TeamState s, String folder) => [
    for (final r in s.ask('key_recipients', [folder]) as List)
      List<String>.from(r as List),
  ];

  /// Capability run 294: the log rotated [userId] away from signing key
  /// [pkHex]; a server restored from before the rotation still calls it current.
  static bool signingKeyRetired(TeamState? s, String userId, String pkHex) =>
      s != null && s.ask('signing_key_retired', [userId, pkHex]) as bool;

  static bool mayHoldKey(TeamState s, String userId, String dekId) =>
      s.ask('may_hold_key', [userId, dekId]) as bool;

  static bool envelopeValid(
    TeamState s,
    String signerId,
    String targetId,
    String dekId,
    String? level,
    String targetEncryptionPk,
  ) =>
      s.ask('envelope_valid', [
            signerId,
            targetId,
            dekId,
            level,
            targetEncryptionPk,
          ])
          as bool;

  /// Why a live folder/item by [userId] sealed with [dekId] is not valid, or
  /// null (the server's push rule; [sealing] false for a pulled copy).
  /// [folder] is the team folder at or above the object's parent.
  static String? itemRefusal(
    TeamState s,
    String userId,
    String objId,
    String? folder,
    String? dekId,
    bool ownDek, [
    bool sealing = true,
  ]) =>
      s.ask('item_refusal', [userId, objId, folder, dekId, ownDek, sealing])
          as String?;

  /// TL7: one active admin per organisation at a head a client follows.
  static String? adminPolicyRefusal(TeamState s) =>
      s.ask('admin_policy_refusal', []) as String?;

  /// A deletion of an object sealed with a team key needs write access there.
  static String? tombstoneRefusal(
    TeamState s,
    String userId,
    String? storedDekId,
  ) => s.ask('tombstone_refusal', [userId, storedDekId]) as String?;

  /// Leaving the team folder [oldFolder] is a removal from it (needs write access there).
  /// [ownPersonal] (TL7): the stored object is [userId]'s own, sealed with a key of
  /// theirs the log does not know; it may leave for outside every team folder.
  static String? moveRefusal(
    TeamState s,
    String userId,
    String? oldFolder,
    String? newFolder, [
    bool ownPersonal = false,
  ]) =>
      s.ask('move_refusal', [userId, oldFolder, newFolder, ownPersonal])
          as String?;

  // ── Forks and restores ──────────────────────────────────────────────

  /// Where the member.remove [bodies][index] is undone by its author's
  /// member.add of the same account in the same run of that author's records.
  static int? readmitted(List<Map<String, dynamic>> bodies, int index) =>
      syncCore('team_log_readmitted', {'bodies': bodies, 'index': index})
          as int?;

  /// Review c02cc47 R17-L: the end (exclusive) of a restore upload part from
  /// [start], at most [limit] records, not inside a readmit.
  static int restorePartEnd(
    List<Map<String, dynamic>> bodies,
    int start,
    int limit,
  ) =>
      syncCore('team_log_restore_part_end', {
            'bodies': bodies,
            'start': start,
            'limit': limit,
          })
          as int;

  /// The change a record made, as a device makes it again on another head.
  static String changeKey(Map<String, dynamic> body) => _answer<String>(
    syncCore('team_log_change_key', {'body': canonical(body)}),
    'key',
  );

  /// Review 18c300f R16-H1 (tests/vectors/team_log_fork.json): whether a
  /// device follows a server log that forks from its copy. (refusal,
  /// missing): a refusal null follows, missing are the seqs of this
  /// account's lost changes not on the server's side.
  static (String?, List<int>) forkRefusal(
    List<Map<String, dynamic>> lost,
    List<Map<String, dynamic>> theirs,
    String? userId,
    List<String>? heldKeys,
    Set<String> withdrawn,
  ) {
    final out = _answer<Map>(
      syncCore('team_log_fork', {
        'lost': lost,
        'theirs': theirs,
        'user_id': userId,
        'held_keys': heldKeys,
        'withdrawn': withdrawn.toList()..sort(),
      }),
      'fork',
    );
    return (out['refusal'] as String?, List<int>.from(out['missing'] as List));
  }

  /// The hashes of this account's lost records a device goes on without
  /// when it follows a fork (capability finding 505).
  static List<String> forkAbandoned(
    List<Map<String, dynamic>> lost,
    String? userId,
  ) => List<String>.from(
    _answer<List>(
      syncCore('team_log_abandoned', {'lost': lost, 'user_id': userId}),
      'hashes',
    ),
  );

  /// Review 18c300f R16-M5: the kinds of this account's lost changes a
  /// device makes again on the server's head (a genesis or member.keys is
  /// bound to the head it was signed on).
  static const remadeKinds = [
    'member.add',
    'member.role',
    'member.remove',
    'access.set',
    'folder.key',
    'org.recovery',
    'org.recovery.wrap',
  ];

  /// The data a lost change is made again with on [s], or null when the log
  /// has it already; [TeamLogError] when it can never land (the core's,
  /// docs/CORE_UNIFICATION.md U7a).
  static Map<String, dynamic>? resolveChange(
    TeamState s,
    String kind,
    Map<String, dynamic> data,
  ) {
    final out = _answer<Object?>(s.ask('resolve_change', [kind, data]), 'data');
    return out == null ? null : Map<String, dynamic>.from(out as Map);
  }
}

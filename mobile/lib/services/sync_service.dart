/// Sezam SyncService — delta sync with the server.
///
/// Implements:
///   - Challenge-response authentication -> JWT
///   - Delta push (dirty objects -> server)
///   - Delta pull (server -> local DB)
///   - Ed25519 signatures on pushed objects
///   - The checkpoint as the only pull state (no ETag / 304)
///
/// Protocol matches server/app/routers/sync.py and auth.py.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:path/path.dart' as p;
import 'package:shared_preferences/shared_preferences.dart';

import '../models/vault_models.dart';
import 'crypto_service.dart';
import 'database_service.dart';
import 'key_rotation.dart';
import 'sync_checkpoint.dart';
import 'sync_core.dart';
import 'sync_limits.dart';
import 'team_log.dart';
import 'team_log_client.dart';
import 'timeout_client.dart';
import 'unsent_changes.dart';
import 'vault_service.dart';

class CanonicalAuditRecord {
  final String id;
  final String actorId;
  final List<String> parentIds;
  final String action;
  final int timestamp;
  final Uint8List encryptedDetails;
  final Uint8List signature;

  const CanonicalAuditRecord({
    required this.id,
    required this.actorId,
    required this.parentIds,
    required this.action,
    required this.timestamp,
    required this.encryptedDetails,
    required this.signature,
  });
}

bool _isAsciiId(String value) =>
    value.length == 26 && value.codeUnits.every((unit) => unit <= 0x7f);

CanonicalAuditRecord parseCanonicalAuditRecord(
  String objectId,
  Uint8List payload,
  int version,
) {
  if (version != 2) {
    throw SyncIntegrityException(
      'REJECT audit $objectId — audit records require version 2',
    );
  }
  late String payloadText;
  late Object? decoded;
  try {
    payloadText = utf8.decode(payload, allowMalformed: false);
    decoded = jsonDecode(payloadText);
  } catch (e) {
    throw SyncIntegrityException(
      'REJECT audit $objectId — invalid audit payload',
    );
  }
  const expectedFields = {
    'action',
    'actor_id',
    'encrypted_details',
    'format',
    'id',
    'parent_ids',
    'signature',
    'timestamp',
  };
  if (decoded is! Map<String, dynamic> ||
      decoded.length != expectedFields.length ||
      !decoded.keys.every(expectedFields.contains)) {
    throw SyncIntegrityException(
      'REJECT audit $objectId — incomplete audit payload',
    );
  }
  final record = decoded;
  final canonical = <String, dynamic>{
    'action': record['action'],
    'actor_id': record['actor_id'],
    'encrypted_details': record['encrypted_details'],
    'format': record['format'],
    'id': record['id'],
    'parent_ids': record['parent_ids'],
    'signature': record['signature'],
    'timestamp': record['timestamp'],
  };
  if (payloadText != jsonEncode(canonical) ||
      record['format'] != 'sezam-audit-v1' ||
      record['id'] != objectId) {
    throw SyncIntegrityException(
      'REJECT audit $objectId — non-canonical or mismatched payload',
    );
  }

  final actorId = record['actor_id'];
  final action = record['action'];
  final timestamp = record['timestamp'];
  final rawParents = record['parent_ids'];
  final detailsBase64 = record['encrypted_details'];
  final signatureHex = record['signature'];
  if (actorId is! String ||
      !_isAsciiId(actorId) ||
      action is! String ||
      action.isEmpty ||
      utf8.encode(action).length > 65535 ||
      timestamp is! int ||
      timestamp < 0 ||
      timestamp > 0x7fffffffffffffff ||
      rawParents is! List ||
      rawParents.any((parent) => parent is! String || !_isAsciiId(parent)) ||
      detailsBase64 is! String ||
      signatureHex is! String ||
      !RegExp(r'^[0-9a-f]{128}$').hasMatch(signatureHex)) {
    throw SyncIntegrityException(
      'REJECT audit $objectId — invalid audit fields',
    );
  }
  final parentIds = rawParents.cast<String>();
  final canonicalParents = parentIds.toSet().toList()..sort();
  if (parentIds.length != canonicalParents.length ||
      !List.generate(
        parentIds.length,
        (i) => parentIds[i] == canonicalParents[i],
      ).every((same) => same) ||
      parentIds.contains(objectId)) {
    throw SyncIntegrityException(
      'REJECT audit $objectId — invalid audit parents',
    );
  }

  late Uint8List encryptedDetails;
  late Uint8List signature;
  try {
    encryptedDetails = base64Decode(detailsBase64);
    signature = hexToBytes(signatureHex);
    if (base64Encode(encryptedDetails) != detailsBase64 ||
        bytesToHex(signature) != signatureHex ||
        signature.length != 64) {
      throw const FormatException('non-canonical encoding');
    }
  } catch (e) {
    throw SyncIntegrityException(
      'REJECT audit $objectId — invalid audit encoding',
    );
  }

  return CanonicalAuditRecord(
    id: objectId,
    actorId: actorId,
    parentIds: parentIds,
    action: action,
    timestamp: timestamp,
    encryptedDetails: encryptedDetails,
    signature: signature,
  );
}

Uint8List buildAuditCanonical(
  CanonicalAuditRecord record,
  CryptoService crypto,
) {
  final id = ascii.encode(record.id);
  final actor = ascii.encode(record.actorId);
  final parents = utf8.encode(jsonEncode(record.parentIds));
  final action = utf8.encode(record.action);
  final detailsHash = record.encryptedDetails.isEmpty
      ? Uint8List(32)
      : crypto.sha256Bytes(record.encryptedDetails);
  final result = Uint8List(
    26 + 26 + 2 + parents.length + 2 + action.length + 8 + 32,
  );
  final view = ByteData.sublistView(result);
  var offset = 0;
  result.setRange(offset, offset + 26, id);
  offset += 26;
  result.setRange(offset, offset + 26, actor);
  offset += 26;
  view.setUint16(offset, parents.length, Endian.big);
  offset += 2;
  result.setRange(offset, offset + parents.length, parents);
  offset += parents.length;
  view.setUint16(offset, action.length, Endian.big);
  offset += 2;
  result.setRange(offset, offset + action.length, action);
  offset += action.length;
  view.setUint64(offset, record.timestamp, Endian.big);
  offset += 8;
  result.setRange(offset, offset + 32, detailsHash);
  return result;
}

void validateAuditDag(Iterable<CanonicalAuditRecord> records) {
  final byId = {for (final record in records) record.id: record};
  final children = {for (final id in byId.keys) id: <String>[]};
  final indegree = <String, int>{};
  for (final record in byId.values) {
    if (record.parentIds.any((parent) => !byId.containsKey(parent))) {
      throw SyncIntegrityException(
        'REJECT audit DAG ${record.id} — missing parent',
      );
    }
    indegree[record.id] = record.parentIds.length;
    for (final parent in record.parentIds) {
      children[parent]!.add(record.id);
    }
  }
  final ready = indegree.entries
      .where((entry) => entry.value == 0)
      .map((entry) => entry.key)
      .toList();
  var visited = 0;
  while (ready.isNotEmpty) {
    final parent = ready.removeLast();
    visited++;
    for (final child in children[parent]!) {
      indegree[child] = indegree[child]! - 1;
      if (indegree[child] == 0) ready.add(child);
    }
  }
  if (visited != byId.length) {
    throw const SyncIntegrityException('REJECT audit DAG — cycle detected');
  }
}

/// Whether a local row belongs to the server state the sync checkpoint
/// authenticates. A local object the server has never confirmed (created
/// offline, or its push failed) has no commit_seq yet; hashing it would fail
/// the next pull closed with STATE MISMATCH.
bool isServerConfirmedRow(Map<String, dynamic> row) =>
    !(row['queued'] == 1 && row['commit_seq'] == null);

/// Review d615826 H6: what a full resync keeps of a server that lost it.
///
/// After a tombstone GC the server is ahead, and an object it no longer has
/// was deleted elsewhere. A server restored from a backup lost what this
/// phone had confirmed, and the resync deleted it here too; desktop keeps it
/// and sends it again (`_local_objects_ahead_of`). Kept are this user's live
/// folders, entries and keys ([ownSigned]: the stored signature verifies with
/// this user's key, so the server takes it back) that the server
/// - lacks although it confirmed them above the GC floor (a GC'd delete
///   leaves no row above it, a newer delete leaves a tombstone), or
/// - holds at an older version, when the server went back ([rolledBack]).
/// Unsent rows are not here: the resync exports and re-applies them. A row
/// whose parent neither the server nor the kept rows have is dropped (the
/// server would refuse it on every push).
List<Map<String, dynamic>> rowsTheServerLost(
  List<Map<String, dynamic>> localRows,
  Map<String, int> serverVersions, {
  required int gcFloor,
  required bool rolledBack,
  required bool Function(Map<String, dynamic> row) ownSigned,
}) {
  final kept = <String, Map<String, dynamic>>{};
  for (final row in localRows) {
    if (!const {'node', 'entry', 'dek'}.contains(row['object_type'])) continue;
    if (row['queued'] == 1 || row['is_deleted'] == 1) continue;
    final id = row['id'] as String;
    final version = row['version'] as int;
    final server = serverVersions[id];
    final lost = server == null && ((row['commit_seq'] as int?) ?? 0) > gcFloor;
    final newer = rolledBack && version > (server ?? 0);
    if ((lost || newer) && ownSigned(row)) kept[id] = row;
  }
  var changed = true;
  while (changed) {
    changed = false;
    for (final id in kept.keys.toList()) {
      final parent = kept[id]!['parent_ref'] as String?;
      if (parent != null &&
          !serverVersions.containsKey(parent) &&
          !kept.containsKey(parent)) {
        kept.remove(id);
        changed = true;
      }
    }
  }
  return kept.values.toList();
}

/// Local owner_id of a pulled object whose signature already verified. A DEK
/// is wrapped under its owner's KEK, so its owner is the user whose signature
/// verified — never the server's unsigned owner_id. A forged one would hide
/// our own DEK from the password-change rekey, or make a colleague's DEK look
/// like an own key the KEK cannot open (unlock refused).
String verifiedOwnerId(PullObject obj) =>
    obj.objectType == 'dek' ? obj.signatureUserId : obj.ownerId;

/// Spec 8.3 state_hash over raw sync objects ({id, version, payload}):
/// SHA-256(concat(sorted by id: id(26) || u32be(version) || SHA-256(payload))).
/// Desktop and web compute the same (tests/vectors/cross_client.json).
String computeStateHash(
  Iterable<Map<String, dynamic>> objects,
  CryptoService crypto,
) {
  final elements = <Uint8List>[];
  for (final object in objects) {
    final id = object['id'] as String;
    final idBytes = Uint8List.fromList(
      utf8.encode(id.padRight(26, '\x00').substring(0, 26)),
    );
    final versionBytes = ByteData(4)
      ..setUint32(0, object['version'] as int, Endian.big);
    final payloadHash = crypto.sha256Bytes(object['payload'] as Uint8List);
    final element = Uint8List(62)
      ..setRange(0, 26, idBytes)
      ..setRange(26, 30, versionBytes.buffer.asUint8List())
      ..setRange(30, 62, payloadHash);
    elements.add(element);
  }
  elements.sort((left, right) {
    for (var i = 0; i < 26; i++) {
      final comparison = left[i].compareTo(right[i]);
      if (comparison != 0) return comparison;
    }
    return 0;
  });
  final canonical = BytesBuilder(copy: false);
  for (final element in elements) {
    canonical.add(element);
  }
  return crypto.sha256Hex(canonical.toBytes());
}

class SyncService {
  static final SyncService _instance = SyncService._();
  factory SyncService() => _instance;
  SyncService._();

  /// SharedPreferences key of the account name this phone signs in with.
  static const usernamePrefKey = 'sezam_username';

  final _crypto = CryptoService();
  final _db = DatabaseService();
  final _vault = VaultService();
  final http.Client _http = TimeoutClient(http.Client());

  String? _serverUrl;
  String? _token;

  // Review d615826: the app syncs after unlock, on pull-to-refresh and after
  // changes; overlapping syncs ran their pushes and pulls interleaved on one
  // checkpoint. Sync, push, pull, full resync and the local re-key now run
  // one at a time; a call made while holding the lock (sync -> push) runs at
  // once.
  Future<void> _lockTail = Future.value();
  static final _lockHeld = Object();

  Future<T> _exclusive<T>(Future<T> Function() op) {
    if (identical(Zone.current[_lockHeld], this)) return op();
    final previous = _lockTail;
    final released = Completer<void>();
    _lockTail = released.future;
    return previous
        .then((_) => runZoned(op, zoneValues: {_lockHeld: this}))
        .whenComplete(released.complete);
  }

  /// A new app process has no sync running. Only for tests that simulate a
  /// killed app inside one process: the killed sync must not hold the lock.
  void forgetRunningSyncsForTesting() => _lockTail = Future.value();

  bool get isConfigured => _serverUrl != null && _serverUrl!.isNotEmpty;
  bool get isAuthenticated => _token != null;
  String? get serverUrl => _serverUrl;
  String? get token => _token;

  /// Configure the server URL.
  void configure(String serverUrl) {
    _serverUrl = serverUrl.endsWith('/')
        ? serverUrl.substring(0, serverUrl.length - 1)
        : serverUrl;
  }

  static Future<List<Uint8List>> resolveAuthorSigningKeys({
    required String ownerId,
    required String currentUserId,
    required Uint8List currentUserSigningPk,
    required Future<Map<String, dynamic>?> Function(String userId) loadKnownKey,
    required Future<Map<String, dynamic>> Function(String userId)
    fetchPublicKeys,
    required Future<void> Function(Map<String, dynamic> key) saveKnownKey,
    Map<String, int>? archiveBoundsOut,
    Future<String?> Function(String key)? loadSetting,
    Future<void> Function(String key, String value)? saveSetting,
  }) async {
    final Map<String, dynamic>? existing;
    final Map<String, dynamic> remote;
    try {
      existing = ownerId == currentUserId ? null : await loadKnownKey(ownerId);
      remote = await fetchPublicKeys(ownerId);
    } catch (e) {
      throw SyncIntegrityException(
        'REJECT owner $ownerId — public keys unavailable: $e',
      );
    }

    late Uint8List signingPk;
    late Uint8List encryptionPk;
    final archivedSigningKeys = <Uint8List>[];
    try {
      final signingHex = remote['signing_pk'];
      final encryptionHex = remote['encryption_pk'];
      if (signingHex is! String || encryptionHex is! String) {
        throw const FormatException('missing public key');
      }
      signingPk = hexToBytes(signingHex);
      encryptionPk = hexToBytes(encryptionHex);
      if (signingPk.length != 32 || encryptionPk.length != 32) {
        throw const FormatException('public keys must be 32 bytes');
      }

      final archives = remote['archived_keys'] ?? const [];
      if (archives is! List || archives.length > 64) {
        throw const FormatException('malformed archived key list');
      }
      final candidates = <_ArchivedKeyCandidate>[];
      for (final archive in archives) {
        if (archive is! Map<String, dynamic>) {
          throw const FormatException('malformed archived key');
        }
        // Uncertified legacy archives are never trusted.
        final successorHex = archive['successor_signing_pk'];
        final certificateHex = archive['rotation_signature'];
        if (successorHex is! String || certificateHex is! String) continue;
        final archivedSigningPk = hexToBytes(archive['signing_pk'] as String);
        final archivedEncryptionPk = hexToBytes(
          archive['encryption_pk'] as String,
        );
        if (archivedSigningPk.length != 32 ||
            archivedEncryptionPk.length != 32) {
          throw const FormatException('archived public keys must be 32 bytes');
        }
        final archivedFingerprint = CryptoService().computeFingerprint(
          archivedSigningPk,
          archivedEncryptionPk,
        );
        if (archive['key_fingerprint'] != archivedFingerprint) {
          throw const FormatException('archived key fingerprint mismatch');
        }
        final authorizationHex = archive['authorization_signature'];
        if (authorizationHex != null && authorizationHex is! String) {
          throw const FormatException('malformed archived key authorization');
        }
        final retiredSeq = archive['retired_seq'];
        candidates.add(
          _ArchivedKeyCandidate(
            signingPk: archivedSigningPk,
            encryptionPk: archivedEncryptionPk,
            successorSigningPk: hexToBytes(successorHex),
            certificate: hexToBytes(certificateHex),
            authorization:
                authorizationHex is String && authorizationHex.isNotEmpty
                ? hexToBytes(authorizationHex)
                : null,
            retiredSeq: retiredSeq is int ? retiredSeq : null,
          ),
        );
      }
      // Trust an archived key only through a rotation certificate signed by
      // its successor (the current key or an already trusted archive), so
      // the server cannot inject historical keys. The current key is the
      // root; callers below reject the response if it is not trusted.
      final trusted = <MapEntry<Uint8List, Uint8List>>[
        MapEntry(signingPk, encryptionPk),
      ];
      var progress = true;
      while (progress) {
        progress = false;
        for (final c in candidates) {
          if (trusted.any((t) => _sameBytes(t.key, c.signingPk))) continue;
          MapEntry<Uint8List, Uint8List>? successor;
          for (final t in trusted) {
            if (_sameBytes(t.key, c.successorSigningPk)) successor = t;
          }
          if (successor == null || c.certificate.length != 64) continue;
          final message = keyRotationMessage(
            ownerId,
            c.signingPk,
            c.encryptionPk,
            successor.key,
            successor.value,
          );
          final valid = CryptoService().verifyDetached(
            signature: c.certificate,
            message: message,
            publicKey: successor.key,
          );
          if (!valid) continue;
          // Review 688edcb V4: when the server kept the old key's own
          // authorization of the rotation, it must verify as well.
          final authorization = c.authorization;
          if (authorization != null &&
              (authorization.length != 64 ||
                  !CryptoService().verifyDetached(
                    signature: authorization,
                    message: message,
                    publicKey: c.signingPk,
                  ))) {
            continue;
          }
          trusted.add(MapEntry(c.signingPk, c.encryptionPk));
          archivedSigningKeys.add(c.signingPk);
          progress = true;
        }
      }
      // An archived key vouches only for objects committed up to its
      // rotation. The first bound seen is pinned, so a server holding the
      // leaked key cannot stretch it later; without one (a server from
      // before V4) it vouches for no pulled object.
      if (archiveBoundsOut != null) {
        for (final c in candidates) {
          if (!archivedSigningKeys.any((k) => _sameBytes(k, c.signingPk))) {
            continue;
          }
          final keyHex = bytesToHex(c.signingPk);
          final settingKey = 'archived_key_bound:$ownerId:$keyHex';
          final pinned = int.tryParse(
            (loadSetting == null ? null : await loadSetting(settingKey)) ?? '',
          );
          var bound = pinned;
          final served = c.retiredSeq;
          if (served != null && (bound == null || served < bound)) {
            bound = served;
            if (saveSetting != null) await saveSetting(settingKey, '$served');
          }
          archiveBoundsOut[keyHex] = bound ?? 0;
        }
      }
    } catch (e) {
      throw SyncIntegrityException(
        'REJECT owner $ownerId — malformed public keys: $e',
      );
    }

    if (ownerId == currentUserId) {
      if (!_sameBytes(signingPk, currentUserSigningPk)) {
        throw SyncIntegrityException(
          'REJECT owner $ownerId — server current key differs from local identity',
        );
      }
      return [currentUserSigningPk, ...archivedSigningKeys];
    }

    final fingerprint = CryptoService().computeFingerprint(
      signingPk,
      encryptionPk,
    );
    if (existing != null) {
      final cachedSigningPk = Uint8List.fromList(
        existing['signing_pk'] as List<int>,
      );
      final cachedEncryptionPk = Uint8List.fromList(
        existing['encryption_pk'] as List<int>,
      );
      final cachedFingerprint = existing['fingerprint'] as String;
      final cachedFingerprintValid =
          CryptoService().computeFingerprint(
            cachedSigningPk,
            cachedEncryptionPk,
          ) ==
          cachedFingerprint;
      if (!cachedFingerprintValid ||
          !_sameBytes(cachedSigningPk, signingPk) ||
          !_sameBytes(cachedEncryptionPk, encryptionPk)) {
        throw TofuKeyChangeException(
          userId: ownerId,
          oldFingerprint: cachedFingerprint,
          newFingerprint: fingerprint,
          signingPk: signingPk,
          encryptionPk: encryptionPk,
        );
      }
      return [cachedSigningPk, ...archivedSigningKeys];
    }

    final now = DateTime.now().millisecondsSinceEpoch;
    await saveKnownKey({
      'user_id': ownerId,
      'signing_pk': signingPk,
      'encryption_pk': encryptionPk,
      'fingerprint': fingerprint,
      'first_seen': now,
      'last_verified': now,
    });
    return [signingPk, ...archivedSigningKeys];
  }

  /// Re-pins a changed peer key, but only the exact key the user saw in the
  /// warning, verified out of band, and only if the old pin is still the one
  /// the warning was about. Mirrors desktop SyncClient.confirm_tofu_key_change.
  static Future<void> confirmTofuKeyChange(
    TofuKeyChangeException change,
    String verifiedFingerprint, {
    required Future<Map<String, dynamic>?> Function(String userId) loadKnownKey,
    required Future<void> Function(Map<String, dynamic> key) saveKnownKey,
  }) async {
    final detected = CryptoService().computeFingerprint(
      change.signingPk,
      change.encryptionPk,
    );
    if (verifiedFingerprint != change.newFingerprint ||
        change.newFingerprint != detected) {
      throw ArgumentError(
        'Verified fingerprint does not match the detected key change',
      );
    }
    final existing = await loadKnownKey(change.userId);
    if (existing == null || existing['fingerprint'] != change.oldFingerprint) {
      throw StateError('Pinned key changed while confirmation was pending');
    }
    await saveKnownKey({
      ...existing,
      'signing_pk': change.signingPk,
      'encryption_pk': change.encryptionPk,
      'fingerprint': change.newFingerprint,
      'last_verified': DateTime.now().millisecondsSinceEpoch,
    });
  }

  Future<void> acceptTofuKeyChange(
    TofuKeyChangeException change,
    String verifiedFingerprint,
  ) => confirmTofuKeyChange(
    change,
    verifiedFingerprint,
    loadKnownKey: _db.getKnownKey,
    saveKnownKey: _db.upsertKnownKey,
  );

  /// Review 688edcb V4: whether [signingPk] may vouch for an object with
  /// [commitSeq] in a pull that started after [sinceSeq]. Current keys (not
  /// in [archiveBounds]) always may; an archived key only for what was
  /// committed before its rotation, and never for a seq the delta excludes.
  static bool keyMayVouch(
    Uint8List signingPk,
    Map<String, int> archiveBounds, {
    required int sinceSeq,
    required int commitSeq,
  }) {
    final bound = archiveBounds[bytesToHex(signingPk)];
    return bound == null || (sinceSeq < commitSeq && commitSeq <= bound);
  }

  /// Must match server/app/auth.py:key_rotation_message.
  static Uint8List keyRotationMessage(
    String userId,
    Uint8List oldSigningPk,
    Uint8List oldEncryptionPk,
    Uint8List newSigningPk,
    Uint8List newEncryptionPk,
  ) {
    final userIdBytes = Uint8List(26);
    final encoded = utf8.encode(userId);
    userIdBytes.setRange(0, encoded.length.clamp(0, 26), encoded);
    return Uint8List.fromList([
      ...utf8.encode('sezam-key-rotation-v1'),
      ...userIdBytes,
      ...oldSigningPk,
      ...oldEncryptionPk,
      ...newSigningPk,
      ...newEncryptionPk,
    ]);
  }

  static bool _sameBytes(Uint8List left, Uint8List right) {
    if (left.length != right.length) return false;
    var difference = 0;
    for (var i = 0; i < left.length; i++) {
      difference |= left[i] ^ right[i];
    }
    return difference == 0;
  }

  Future<Map<String, dynamic>> _fetchPublicKeys(String userId) async {
    final response = await _http.get(
      Uri.parse('$_serverUrl/api/users/${Uri.encodeComponent(userId)}/keys'),
      headers: _authHeaders(),
    );
    _checkResponse(response, 'fetchPublicKeys');
    return jsonDecode(response.body) as Map<String, dynamic>;
  }

  // ── Authentication ──

  /// Fetch server metadata (argon2 params, per-user salts).
  /// No auth required — public endpoint.
  Future<Map<String, dynamic>> fetchMeta({String? username}) async {
    _ensureConfigured();

    var url = '$_serverUrl/api/meta';
    if (username != null) {
      url += '?username=${Uri.encodeComponent(username)}';
    }

    final response = await _http.get(Uri.parse(url), headers: _headers());
    _checkResponse(response, 'fetchMeta');

    return jsonDecode(response.body) as Map<String, dynamic>;
  }

  /// Challenge-response authentication.
  ///
  /// 1. POST /api/auth/challenge -> get challenge
  /// 2. Sign challenge with Ed25519
  /// 3. POST /api/auth/verify -> get JWT
  ///
  /// Returns {token, user_id, is_admin}.
  Future<Map<String, dynamic>> authenticate({
    required String username,
    required Uint8List signingSecretKey,
  }) async {
    _ensureConfigured();

    // Step 1: Get challenge
    final challengeResp = await _http.post(
      Uri.parse('$_serverUrl/api/auth/challenge'),
      headers: _headers(),
      body: jsonEncode({'username': username}),
    );
    _checkResponse(challengeResp, 'challenge');
    final challengeData =
        jsonDecode(challengeResp.body) as Map<String, dynamic>;
    final challengeHex = challengeData['challenge'] as String;
    final challengeBytes = hexToBytes(challengeHex);

    // Step 2: Sign challenge with Ed25519
    final signature = _crypto.signAuthChallenge(
      challengeBytes,
      signingSecretKey,
    );

    // Step 3: Verify with server
    final verifyResp = await _http.post(
      Uri.parse('$_serverUrl/api/auth/verify'),
      headers: _headers(),
      body: jsonEncode({
        'username': username,
        'challenge': challengeHex,
        'signature': bytesToHex(signature),
      }),
    );
    // Another device rotated the identity key: the new keypair is taken
    // over with the password, like a password change made elsewhere.
    if (verifyResp.statusCode == 409 &&
        verifyResp.body.contains('Identity key rotated')) {
      // Review 526419e N8: a renamed account is taken over under its current
      // name, not the old one another account holds now.
      final currentName = _rotatedAccountName(verifyResp.body);
      if (currentName != null && currentName != username) {
        final prefs = await SharedPreferences.getInstance();
        await prefs.setString(usernamePrefKey, currentName);
      }
      throw const KeyEpochStaleException();
    }
    if (verifyResp.statusCode == 401 &&
        namedByTeamLog(Uint8List.sublistView(signingSecretKey, 32, 64))) {
      throw const AccountLostOnServerException();
    }
    _checkResponse(verifyResp, 'verify');
    final authData = jsonDecode(verifyResp.body) as Map<String, dynamic>;

    _token = authData['token'] as String;

    // Review e4cd15a (low): the server's name migration may have moved this
    // account off the name it signed in with; the answer carries the current
    // one, which every later login of this phone uses. The name is unsigned
    // (INV-3, review e443cbc #428): it is kept only once this phone's key
    // logs in under it, so a lie cannot lock the phone out.
    final rawName = authData['username'];
    final currentName = rawName is String && rawName.isNotEmpty
        ? rawName
        : null;
    _signedInAs = username;
    _accountName =
        currentName != null &&
            (currentName == username ||
                await _logsInAs(currentName, signingSecretKey))
        ? currentName
        : null;
    if (_accountName != null && _accountName != username) {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(usernamePrefKey, _accountName!);
    }

    return authData;
  }

  /// Whether the team log this phone holds names its account as a current
  /// member with [signingPk] (this phone's key by default).
  bool namedByTeamLog([Uint8List? signingPk]) {
    final userId = _vault.userId;
    final key = signingPk ?? _vault.signingPublicKey;
    final member = userId == null ? null : _vault.teamLog?.team.members[userId];
    return member != null && member.active && key != null &&
        member.signingPk == bytesToHex(key);
  }

  /// Review 8595ec1 #1: bring this member account back, under the id the
  /// team log names, on a server restored from a backup older than it
  /// (POST /api/auth/rejoin, a proof by the keys the log holds). Leaves an
  /// onboarding session for the key material upload. Returns false when the
  /// server has the account already (409).
  Future<bool> rejoin({required String username, required int keyEpoch}) async {
    _ensureConfigured();
    final userId = _vault.userId;
    final signingSk = _vault.signingSecretKey;
    final signingPk = _vault.signingPublicKey;
    final encryptionPk = _vault.encryptionPublicKey;
    if (userId == null || signingSk == null || signingPk == null || encryptionPk == null) {
      throw StateError('Unlock the vault first');
    }
    final challengeResp = await _http.post(
      Uri.parse('$_serverUrl/api/auth/challenge'),
      headers: _headers(),
      body: jsonEncode({'username': username}),
    );
    _checkResponse(challengeResp, 'rejoin challenge');
    final challengeHex =
        (jsonDecode(challengeResp.body) as Map<String, dynamic>)['challenge'] as String;
    final message = rejoinMessage(
      hexToBytes(challengeHex), userId, username, signingPk, encryptionPk, keyEpoch,
    );
    final response = await _http.post(
      Uri.parse('$_serverUrl/api/auth/rejoin'),
      headers: _headers(),
      body: jsonEncode({
        'username': username,
        'user_id': userId,
        'signing_pk': bytesToHex(signingPk),
        'encryption_pk': bytesToHex(encryptionPk),
        'key_epoch': keyEpoch,
        'challenge': challengeHex,
        'signature': bytesToHex(_crypto.signChallenge(message, signingSk)),
      }),
    );
    if (response.statusCode == 409 && _errorCode(response) == 'username_taken') {
      throw UsernameTakenException(username);
    }
    if (response.statusCode == 409) return false;
    _checkResponse(response, 'rejoin');
    _token = (jsonDecode(response.body) as Map<String, dynamic>)['token'] as String;
    return true;
  }

  Future<Map<String, dynamic>> resumeRegistration({
    required String username,
    required Uint8List signingSecretKey,
  }) async {
    _ensureConfigured();
    final challenge = await _http.post(
      Uri.parse('$_serverUrl/api/auth/challenge'),
      headers: _headers(), body: jsonEncode({'username': username}),
    );
    _checkResponse(challenge, 'registration challenge');
    final challengeHex = (jsonDecode(challenge.body) as Map)['challenge'] as String;
    final response = await _http.post(
      Uri.parse('$_serverUrl/api/auth/registration-resume'),
      headers: _headers(),
      body: jsonEncode({
        'username': username, 'challenge': challengeHex,
        'signature': bytesToHex(_crypto.signAuthChallenge(hexToBytes(challengeHex), signingSecretKey)),
      }),
    );
    _checkResponse(response, 'registration resume');
    final result = jsonDecode(response.body) as Map<String, dynamic>;
    _token = result['token'] as String;
    return result;
  }

  String? _signedInAs;
  String? _accountName;

  /// Whether the server lets [signingSecretKey] log in under [name]; the
  /// session of that login replaces the current one.
  Future<bool> _logsInAs(String name, Uint8List signingSecretKey) async {
    try {
      final challengeResp = await _http.post(
        Uri.parse('$_serverUrl/api/auth/challenge'),
        headers: _headers(),
        body: jsonEncode({'username': name}),
      );
      if (challengeResp.statusCode != 200) {
        return false;
      }
      final challengeHex =
          (jsonDecode(challengeResp.body) as Map<String, dynamic>)['challenge']
              as String;
      final signature = _crypto.signAuthChallenge(
        hexToBytes(challengeHex),
        signingSecretKey,
      );
      final verifyResp = await _http.post(
        Uri.parse('$_serverUrl/api/auth/verify'),
        headers: _headers(),
        body: jsonEncode({
          'username': name,
          'challenge': challengeHex,
          'signature': bytesToHex(signature),
        }),
      );
      if (verifyResp.statusCode != 200) {
        return false;
      }
      final token =
          (jsonDecode(verifyResp.body) as Map<String, dynamic>)['token'];
      if (token is! String || token.isEmpty) {
        return false;
      }
      _token = token;
      return true;
    } catch (_) {
      return false;
    }
  }

  static String? _rotatedAccountName(String body) {
    try {
      final detail = (jsonDecode(body) as Map<String, dynamic>)['detail'];
      final name = detail is Map ? detail['username'] : null;
      return name is String && name.isNotEmpty ? name : null;
    } catch (_) {
      return null;
    }
  }

  /// The name to store for a login typed as [username]: the server's current
  /// name of the account when this service just signed in under [username].
  String accountNameFor(String username) =>
      username == _signedInAs && _accountName != null
      ? _accountName!
      : username;

  /// Recover encrypted keypair from server using auth_proof (Path B).
  ///
  /// POST /api/auth/recover {username, auth_proof} -> {encrypted_keypair, argon2_salt}
  Future<Map<String, dynamic>> recover({
    required String username,
    required Uint8List authProof,
    Map<String, int>? argon2Params,
  }) async {
    _ensureConfigured();

    final response = await _http.post(
      Uri.parse('$_serverUrl/api/auth/recover'),
      headers: _headers(),
      body: jsonEncode({
        'username': username,
        'auth_proof': bytesToHex(authProof),
        // An account stored without params adopts the ones this proof was
        // derived with (lockout review N2).
        if (argon2Params != null) 'argon2_params': argon2Params,
      }),
    );
    _checkResponse(response, 'recover');

    return jsonDecode(response.body) as Map<String, dynamic>;
  }

  /// Provision a new device using a one-time token (from QR code).
  ///
  /// POST /api/auth/provision {token, username} -> {encrypted_keypair, argon2_salt}
  Future<Map<String, dynamic>> provision({
    required String token,
    required String username,
  }) async {
    _ensureConfigured();

    final response = await _http.post(
      Uri.parse('$_serverUrl/api/auth/provision'),
      headers: _headers(),
      body: jsonEncode({'token': token, 'username': username}),
    );
    _checkResponse(response, 'provision');

    return jsonDecode(response.body) as Map<String, dynamic>;
  }

  /// Logout — revoke JWT.
  Future<void> logout() async {
    if (_token == null || _serverUrl == null) return;

    try {
      await _http.post(
        Uri.parse('$_serverUrl/api/auth/logout'),
        headers: _authHeaders(),
        body: jsonEncode({'token': _token}),
      );
    } catch (_) {
      // Ignore logout errors (network offline, etc.)
    }

    _token = null;
  }

  // ── Delta Push ──

  /// Push all dirty objects to the server.
  ///
  /// POST /api/sync {objects: [...], atomic_batch: false}
  /// Server assigns commit_seq for each accepted object.
  Future<PushResult> push() => _exclusive(_push);

  Future<PushResult> _push() async {
    _ensureAuthenticated();
    // INV-7: a log refused at unlock holds back the team's rows only, each
    // reported with the refusal (its cause and way out); the personal tree's go.
    final refused = _vault.userId == null ? null : _vault.teamLogRefusal;
    final sendable = refused == null ? null : await _vault.sendableWhileRefused();
    if (_vault.userId != null && refused == null) {
      requireConfirmedGenesis(await readConfirmedTeamGenesis(_vault.userId!), _vault.teamLog?.team.genesisHash);
    }

    // R9-G: what waits here sealed with a folder key a re-key replaced goes
    // out with the folder's current key (the log refuses the old one).
    if (_vault.isUnlocked) await _vault.resealUnsentOnCurrentKeys();
    final dirtyRows = await _db.getDirtyObjects();
    if (dirtyRows.isEmpty) {
      return PushResult(accepted: 0, conflicts: 0, errors: []);
    }

    final objects = <Map<String, dynamic>>[];
    // Review 526419e #1: an object over the server's 1 MiB stays local and
    // is reported; it used to sink every push of the vault.
    final errors = <String>[];
    // Review 8595ec1 (R10-F): a row the log does not let out yet stays
    // queued and is reported, as an oversized one; it used to throw for the
    // whole push, so none of the phone's other changes went out.
    final held = {for (final row in await _db.getAllObjects()) row['id'] as String: row};
    for (final row in dirtyRows) {
      if (sendable != null && !sendable(row)) {
        errors.add("${row['id']}: $refused");
        continue;
      }
      try {
        if (sendable == null) await _vault.assertTrustedTeamWrites([row], heldRows: held);
      } on TeamLogRefused catch (e) {
        errors.add("${row['id']}: $e");
        continue;
      }
      final payload = row['payload'] as Uint8List;
      if (payload.length > maxObjectPayloadBytes) {
        errors.add("${row['id']}: exceeds the server's 1 MiB limit per object");
        continue;
      }
      final payloadBase64 = base64Encode(payload);

      objects.add({
        'id': row['id'],
        'object_type': row['object_type'],
        'payload': payloadBase64,
        'parent_ref': row['parent_ref'],
        'target_user_id': row['target_user_id'],
        'version': row['version'],
        'is_deleted': row['is_deleted'] ?? 0,
        'payload_hash': row['payload_hash'] ?? '',
        'signature': row['client_signature'] != null
            ? bytesToHex(row['client_signature'] as Uint8List)
            : '',
        'write_policy': row['write_policy'] as String? ?? 'owner_only',
        // S1: the server copy this change builds on; none for a new object.
        if (row['base_version'] != null) ...{
          'base_version': row['base_version'],
          'base_payload_hash': row['base_hash'],
        },
      });
    }

    final keyEpoch =
        int.tryParse(await _db.getSetting('key_epoch') ?? '0') ?? 0;
    // Review 7c10379: what this phone sends may build on a commit a restored
    // server lost (as desktop SM7); the server refuses it with
    // history_changed and the full resync keeps and resends what was lost.
    final checkpoint = _vault.userId == null
        ? null
        : await _loadSyncCheckpoint();
    final checkSeq = checkpoint == null ? 0 : _commitTokenSeq(checkpoint);
    final checkToken = checkSeq > 0
        ? checkpoint!['commit_token'] as String?
        : null;
    var acceptedCount = 0;
    var conflictCount = errors.length;
    // Review 526419e #1: at most 1000 objects / 16 MiB per request; each
    // chunk is marked clean as soon as it landed.
    for (final chunk in splitForPush(objects)) {
      await _db.rememberSent(chunk);
      final response = await _http.post(
        Uri.parse('$_serverUrl/api/sync'),
        headers: _authHeaders(),
        body: jsonEncode({
          'objects': chunk,
          'atomic_batch': false,
          'key_epoch': keyEpoch,
          if (checkToken != null) ...{
            'check_seq': checkSeq,
            'check_token': checkToken,
          },
        }),
      );
      if (response.statusCode == 409 && response.body.contains('key epoch')) {
        throw const KeyEpochStaleException();
      }
      if (response.statusCode == 409 &&
          _errorCode(response) == 'history_changed') {
        await _db.setSetting(serverRollbackSetting, '$checkSeq');
        throw const FullResyncRequiredException(
          'The server lost a commit this device saw (restored from a '
          'backup?); a full resync is required before pushing',
        );
      }
      _checkResponse(response, 'push');

      final data = jsonDecode(response.body) as Map<String, dynamic>;
      final accepted = data['accepted'] as List? ?? [];
      final conflicts = data['conflicts'] as List? ?? [];

      // Mark accepted objects as clean (the version that was sent).
      final sent = {for (final obj in chunk) obj['id'] as String: obj};
      final db = await _db.database;
      await db.transaction((txn) async {
        for (final acc in accepted) {
          final id = acc['id'] as String;
          final obj = sent[id];
          if (obj == null) continue;
          final seq = acc['commit_seq'] as int?;
          await _db.markClean(
            id,
            seq,
            version: obj['version'] as int,
            isDeleted: obj['is_deleted'] as int,
            payloadHash: obj['payload_hash'] as String?,
            transaction: txn,
          );
        }
      });
      acceptedCount += accepted.length;
      conflictCount += conflicts.length;
      errors.addAll(
        conflicts.map((c) => '${c['id']}: ${c['error'] ?? 'conflict'}'),
      );
    }

    return PushResult(
      accepted: acceptedCount,
      conflicts: conflictCount,
      errors: errors,
    );
  }

  // ── Delta Pull ──

  String _checkpointKey([String? userId]) {
    userId ??= _vault.userId;
    if (userId == null || userId.isEmpty) {
      throw StateError('Vault user identity is required for sync checkpoints');
    }
    return 'sync_checkpoint:$userId';
  }

  Uint8List _checkpointAAD([String? userId]) => Uint8List.fromList(
    utf8.encode('sezam-sync-checkpoint-v1:${userId ?? _vault.userId}'),
  );

  Future<Map<String, dynamic>?> _loadSyncCheckpoint({
    Uint8List? kek,
    String? userId,
  }) async {
    final raw = await _db.getSyncState(_checkpointKey(userId));
    if (raw == null) return null;
    if (!raw.startsWith('enc:v1:')) {
      throw const SyncIntegrityException(
        'Refusing plaintext or malformed sync checkpoint',
      );
    }

    kek ??= _vault.currentKek;
    if (kek == null) throw StateError('Vault must be unlocked');
    try {
      return decodeSyncCheckpoint(raw, kek, userId ?? _vault.userId!);
    } catch (e) {
      throw SyncIntegrityException('Invalid encrypted sync checkpoint: $e');
    }
  }

  /// The commit_seq whose server token the checkpoint holds. It is below
  /// last_sync_seq when a snapshot ended below the GC floor: the pull
  /// cursor moved up to the floor, the token stays with the last commit seen.
  static int _commitTokenSeq(Map<String, dynamic> checkpoint) =>
      checkpoint['commit_token_seq'] as int? ??
      checkpoint['last_sync_seq'] as int;

  String _encryptSyncCheckpoint(
    int seq,
    String stateHash, {
    required String? commitToken,
    int? commitTokenSeq,
    Object? teamLog,
    Uint8List? kek,
    String? userId,
  }) {
    kek ??= _vault.currentKek;
    if (kek == null) throw StateError('Vault must be unlocked');
    final plaintext = Uint8List.fromList(
      utf8.encode(
        jsonEncode({
          'last_sync_seq': seq,
          'state_hash': stateHash,
          'timestamp': DateTime.now().millisecondsSinceEpoch,
          'commit_token': ?commitToken,
          if (commitTokenSeq != null && commitTokenSeq != seq)
            'commit_token_seq': commitTokenSeq,
          // The team log head this phone saw (TL5).
          'team_log': ?teamLog,
        }),
      ),
    );
    final nonce = _crypto.randomBytes(_crypto.aeadNonceBytes);
    final ciphertext = _crypto.aeadEncrypt(
      plaintext: plaintext,
      additionalData: _checkpointAAD(userId),
      nonce: nonce,
      key: kek,
    );
    final packed = Uint8List(nonce.length + ciphertext.length)
      ..setRange(0, nonce.length, nonce)
      ..setRange(nonce.length, nonce.length + ciphertext.length, ciphertext);
    return 'enc:v1:${base64Encode(packed)}';
  }

  // ── Password changed on another device (review 2052248, finding 1) ──

  Future<DekRekeyCrypto> _rekeyCrypto(Uint8List? signingSecretKey) async {
    final kekDekId = await _db.getSetting('kek_dek_id');
    if (kekDekId == null) throw StateError('Local KEK id is missing');
    return CryptoServiceRekey(_crypto, kekDekId, signingSecretKey);
  }

  /// Own local DEKs [kek] cannot open (they need the previous password).
  Future<List<String>> unreadableOwnDeks(Uint8List kek, String? userId) async {
    // A device whose vault was never opened has no KEK id and no keys yet
    // (an empty phone recovering its account by password).
    if (await _db.getSetting('kek_dek_id') == null &&
        (await _db.getAllObjects()).isEmpty) {
      return const [];
    }
    try {
      planLocalDekRekey(
        rows: await _db.getAllObjects(),
        userId: userId,
        newKek: kek,
        oldKek: null,
        crypto: await _rekeyCrypto(null),
        isEnvelope: _crypto.isEncryptedEnvelope,
      );
      return const [];
    } on LocalDekRekeyException catch (e) {
      return e.unreadableDekIds;
    }
  }

  /// Move the local vault from [oldKek] to [newKek]: DEK wraps in place and
  /// the sync checkpoint, in one transaction. Throws
  /// [LocalDekRekeyException] (nothing changed) when [oldKek] is not the
  /// previous KEK either. Safe to resume: wraps already under [newKek] stay.
  Future<void> rekeyLocalVault({
    required Uint8List oldKek,
    required Uint8List newKek,
    required String? userId,
    required String? checkpointUserId,
    required Uint8List signingSecretKey,
    Map<String, String> settings = const {},
  }) => _exclusive(
    () => _vault.whileKekFixed(() async {
      await _rekeyLocalVault(
        oldKek: oldKek,
        newKek: newKek,
        userId: userId,
        checkpointUserId: checkpointUserId,
        signingSecretKey: signingSecretKey,
        settings: settings,
      );
      // Review 7c10379 (R7-H): new keys and edits follow the move at once; a
      // sync waiting for the lock reads the checkpoint under the new KEK.
      _vault.localDeksMovedTo(newKek, signingSecretKey);
    }),
  );

  /// Review 1141a20 H2 (capability run 264): a password change made on this
  /// phone. Own DEKs go under [newKek] at the next version, in one atomic
  /// push with [keyRotation] (new key material, the current password's
  /// proof) and the epoch advance. Only the server changes: the caller then
  /// takes the change over like one made elsewhere. Refuses unsent changes.
  /// Returns the server's answer.
  Future<Map<String, dynamic>> advanceKeyEpoch({
    required String username,
    required Uint8List newKek,
    required Uint8List signingSecretKey,
    required Map<String, dynamic> keyRotation,
  }) => _exclusive(() async {
    _ensureConfigured();
    final oldKek = _vault.currentKek;
    if (oldKek == null) throw StateError('Vault must be unlocked');
    if ((await _db.getDirtyObjects()).isNotEmpty) {
      throw StateError('Send the unsent changes first');
    }
    final keyEpoch =
        (int.tryParse(await _db.getSetting('key_epoch') ?? '0') ?? 0) + 1;
    final objects = [
      for (final obj in planKeyEpochDekRewrap(
        rows: await _db.getAllObjects(),
        userId: _vault.userId,
        oldKek: oldKek,
        newKek: newKek,
        crypto: await _rekeyCrypto(signingSecretKey),
        isEnvelope: _crypto.isEncryptedEnvelope,
      ))
        {
          ...obj,
          'payload': base64Encode(obj['payload'] as Uint8List),
          'signature': bytesToHex(obj['signature'] as Uint8List),
        },
    ];
    final chunks = splitForPush(objects);
    final body = <String, dynamic>{
      'objects': chunks.isEmpty ? const [] : chunks.last,
      'atomic_batch': true,
      'key_epoch': keyEpoch,
    };
    if (chunks.length > 1) {
      const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
      final batchId = [
        '0',
        for (final b in _crypto.randomBytes(25)) alphabet[b % 32],
      ].join();
      var staged = 0;
      for (final chunk in chunks.sublist(0, chunks.length - 1)) {
        final staging = await _http.post(
          Uri.parse('$_serverUrl/api/sync/stage'),
          headers: _authHeaders(),
          body: jsonEncode({'batch_id': batchId, 'start': staged, 'objects': chunk}),
        );
        _checkResponse(staging, 'stage');
        staged += chunk.length;
      }
      body['staged_batch_id'] = batchId;
      body['staged_count'] = staged;
    }
    // Replacing key material needs a fresh challenge signed by this account.
    final challengeResp = await _http.post(
      Uri.parse('$_serverUrl/api/auth/challenge'),
      headers: _headers(),
      body: jsonEncode({'username': username}),
    );
    _checkResponse(challengeResp, 'challenge');
    final challenge =
        (jsonDecode(challengeResp.body) as Map<String, dynamic>)['challenge']
            as String;
    body['key_rotation'] = {
      ...keyRotation,
      'challenge': challenge,
      'signature': bytesToHex(
        _crypto.signAuthChallenge(hexToBytes(challenge), signingSecretKey),
      ),
    };
    final response = await _http.post(
      Uri.parse('$_serverUrl/api/sync'),
      headers: _authHeaders(),
      body: jsonEncode(body),
    );
    if (response.statusCode == 409 && response.body.contains('key epoch')) {
      throw const KeyEpochStaleException();
    }
    _checkResponse(response, 'key epoch advance');
    final data = jsonDecode(response.body) as Map<String, dynamic>;
    final accepted = {
      for (final a in data['accepted'] as List? ?? const []) a['id'],
    };
    final conflicts = {
      for (final c in data['conflicts'] as List? ?? const []) c['id']: c,
    };
    for (final obj in objects) {
      if (accepted.contains(obj['id'])) continue;
      if (conflicts[obj['id']]?['server_payload_hash'] != obj['payload_hash']) {
        throw SyncException(
          operation: 'key epoch advance',
          statusCode: 409,
          message: 'A key was refused: ${obj['id']}',
        );
      }
    }
    final token = data['token'];
    if (token is String && token.isNotEmpty) _token = token;
    return data;
  });

  /// Org recovery state (public): whether this account set it up.
  Future<Map<String, dynamic>> orgRecoveryStatus() async {
    _ensureConfigured();
    final response = await _http.get(
      Uri.parse('$_serverUrl/api/org-recovery/status'),
      headers: _headers(),
    );
    _checkResponse(response, 'org recovery status');
    return jsonDecode(response.body) as Map<String, dynamic>;
  }

  Future<void> _rekeyLocalVault({
    required Uint8List oldKek,
    required Uint8List newKek,
    required String? userId,
    required String? checkpointUserId,
    required Uint8List signingSecretKey,
    required Map<String, String> settings,
  }) async {
    final changed = planLocalDekRekey(
      rows: await _db.getAllObjects(),
      userId: userId,
      newKek: newKek,
      oldKek: oldKek,
      crypto: await _rekeyCrypto(signingSecretKey),
      isEnvelope: _crypto.isEncryptedEnvelope,
    );
    // Review d615826: taking over an identity rotation replaces the signing
    // key. Unsent rows kept the retired key's signature and the server
    // refused them on every push; they are re-signed with the account's key
    // (payload and version unchanged), in the same transaction.
    final signingPk = Uint8List.fromList(signingSecretKey.sublist(32, 64));
    final changedIds = {for (final row in changed) row['id']};
    for (final row in await _db.getDirtyObjects()) {
      final hash = row['payload_hash'];
      if (changedIds.contains(row['id']) || hash is! String) continue;
      if (_signedByMe(row, signingPk)) continue;
      changed.add({
        ...row,
        'client_signature': _crypto.signSyncObject(
          id: row['id'] as String,
          objectType: row['object_type'] as String,
          parentRef: row['parent_ref'] as String?,
          targetUserId: row['target_user_id'] as String?,
          isDeleted: row['is_deleted'] as int? ?? 0,
          version: row['version'] as int,
          payloadHashHex: hash,
          signingSecretKey: signingSecretKey,
        ),
      });
    }

    String? checkpointKey;
    String? encryptedCheckpoint;
    if (checkpointUserId != null && checkpointUserId.isNotEmpty) {
      Map<String, dynamic>? checkpoint;
      try {
        checkpoint = await _loadSyncCheckpoint(
          kek: newKek,
          userId: checkpointUserId,
        );
      } on SyncIntegrityException {
        checkpoint = await _loadSyncCheckpoint(
          kek: oldKek,
          userId: checkpointUserId,
        );
      }
      if (checkpoint != null) {
        final stateHash = await _computeStateHash(
          replacements: [
            for (final row in changed)
              if (isServerConfirmedRow(row))
                {
                  'id': row['id'],
                  'version': row['version'],
                  'payload': row['payload'],
                },
          ],
        );
        checkpointKey = _checkpointKey(checkpointUserId);
        encryptedCheckpoint = _encryptSyncCheckpoint(
          checkpoint['last_sync_seq'] as int,
          stateHash,
          commitToken: checkpoint['commit_token'] as String?,
          commitTokenSeq: checkpoint['commit_token_seq'] as int?,
          teamLog: checkpoint['team_log'],
          kek: newKek,
          userId: checkpointUserId,
        );
      }
    }
    if (changed.isEmpty && encryptedCheckpoint == null) return;
    await _db.applyLocalRekey(
      rows: changed,
      checkpointKey: checkpointKey,
      encryptedCheckpoint: encryptedCheckpoint,
      settings: settings,
    );
  }

  Future<String> _computeStateHash({
    List<Map<String, dynamic>> replacements = const [],
    bool replaceAll = false,
  }) async {
    final objects = <String, Map<String, dynamic>>{};
    if (!replaceAll) {
      for (final row in await _db.getAllObjects()) {
        if (!isServerConfirmedRow(row)) continue;
        objects[row['id'] as String] = {
          'id': row['id'] as String,
          'version': row['version'] as int,
          'payload': Uint8List.fromList(row['payload'] as List<int>),
        };
      }
      for (final conflict in await _db.getSyncConflicts()) {
        objects[conflict['object_id'] as String] = {
          'id': conflict['object_id'] as String,
          'version': conflict['server_version'] as int,
          'payload': Uint8List.fromList(
            conflict['server_payload'] as List<int>,
          ),
        };
      }
    }
    for (final replacement in replacements) {
      objects[replacement['id'] as String] = replacement;
    }
    return computeStateHash(objects.values, _crypto);
  }

  /// The keypair this phone stores is the one the server holds now
  /// ([serverHash]: SHA-256 of the server's encrypted keypair).
  Future<bool> _holdsServerKeyMaterial(Object? serverHash) async {
    if (serverHash is! String || serverHash.isEmpty) return false;
    final local = await const FlutterSecureStorage(
      aOptions: AndroidOptions(encryptedSharedPreferences: true),
      iOptions: IOSOptions(
        accessibility: KeychainAccessibility.first_unlock_this_device,
      ),
    ).read(key: 'sezam_encrypted_keypair');
    if (local == null || local.isEmpty) return false;
    return _crypto.sha256Hex(hexToBytes(local)) == serverHash;
  }

  bool _signedByMe(Map<String, dynamic> row, Uint8List signingPk) {
    final signature = row['client_signature'];
    final hash = row['payload_hash'];
    if (signature is! Uint8List || hash is! String) return false;
    try {
      return _crypto.verifyDetached(
        signature: signature,
        message: _crypto.buildSyncSignatureData(
          id: row['id'] as String,
          objectType: row['object_type'] as String,
          parentRef: row['parent_ref'] as String?,
          targetUserId: row['target_user_id'] as String?,
          isDeleted: row['is_deleted'] as int? ?? 0,
          version: row['version'] as int,
          payloadHashHex: hash,
        ),
        publicKey: signingPk,
      );
    } catch (_) {
      return false;
    }
  }

  /// Review 7c10379 H9: taking a password over re-wraps this user's keys in
  /// place (planLocalDekRekey); a confirmed row keeps the signature of its
  /// old wrap. A full resync after a server restore then dropped the key and
  /// kept its folder, which nobody could read. Only this account's KEK makes
  /// a wrap that KEK opens, so such a key is this user's like a signed row.
  bool _ownRewrappedKey(Map<String, dynamic> row) {
    final kek = _vault.currentKek;
    if (row['object_type'] != 'dek' ||
        kek == null ||
        _vault.signingSecretKey == null) {
      return false;
    }
    try {
      _crypto.zeroize(
        _crypto.unwrapDEK(
          Uint8List.fromList(row['payload'] as List<int>),
          kek,
          row['id'] as String,
          version: row['version'] as int,
        ),
      );
      return true;
    } catch (_) {
      return false;
    }
  }

  /// [row] signed with this account's key over its current payload, as the
  /// server takes it on the next push.
  Map<String, dynamic> _signedForPush(
    Map<String, dynamic> row,
    Uint8List signingPk,
  ) {
    if (_signedByMe(row, signingPk)) return row;
    final payloadHash = _crypto.sha256Hex(
      Uint8List.fromList(row['payload'] as List<int>),
    );
    return {
      ...row,
      'payload_hash': payloadHash,
      'client_signature': _crypto.signSyncObject(
        id: row['id'] as String,
        objectType: row['object_type'] as String,
        parentRef: row['parent_ref'] as String?,
        targetUserId: row['target_user_id'] as String?,
        isDeleted: row['is_deleted'] as int? ?? 0,
        version: row['version'] as int,
        payloadHashHex: payloadHash,
        signingSecretKey: _vault.signingSecretKey!,
      ),
    };
  }

  Future<int> getDirtyObjectCount() async =>
      (await _db.getDirtyObjects()).length;

  Future<({String path, List<Map<String, dynamic>> objects})?>
  _exportDirtyObjects() async {
    final dirtyRows = await _db.getDirtyObjects();
    if (dirtyRows.isEmpty) return null;
    final objects = dirtyRows.map((row) {
      final encoded = Map<String, dynamic>.from(row);
      encoded['payload'] = base64Encode(row['payload'] as Uint8List);
      final signature = row['client_signature'];
      encoded['client_signature'] = signature == null
          ? null
          : bytesToHex(signature as Uint8List);
      return encoded;
    }).toList();
    final dir = await DatabaseService.exportDirectory();
    final timestamp = DateTime.now().toUtc().toIso8601String().replaceAll(
      ':',
      '-',
    );
    final path = p.join(dir.path, 'sezam_unsent_$timestamp.json');
    await File(path).writeAsBytes(encodeUnsentExport(objects), flush: true);
    return (path: path, objects: objects);
  }

  /// The newest unsent-changes export a full resync left in the app folder
  /// (lockout review M4), so the user can still save it elsewhere.
  Future<File?> latestUnsentExport() async {
    final dir = await DatabaseService.exportDirectory();
    final files =
        dir.listSync().whereType<File>().where((f) {
          final name = p.basename(f.path);
          return name.endsWith('.json') && isExportFileName(name);
        }).toList()..sort(
          (a, b) => b.lastModifiedSync().compareTo(a.lastModifiedSync()),
        );
    return files.isEmpty ? null : files.first;
  }

  /// Explicit tombstone-GC recovery. Confirmation is mandatory before export,
  /// network access, or local mutation.
  Future<FullResyncResult> fullResync({required bool confirmed}) =>
      _exclusive(() => _fullResync(confirmed: confirmed));

  Future<FullResyncResult> _fullResync({required bool confirmed}) async {
    if (!confirmed) {
      throw StateError('Full resync requires explicit confirmation');
    }
    _ensureAuthenticated();
    final dirtyCount = await getDirtyObjectCount();
    final export = await _exportDirtyObjects();
    final pullResult = await _pull(fullResync: true);
    await _db.deleteSetting(serverRollbackSetting);
    await _db.deleteSetting(forgottenLogResyncSetting);
    var reapplied = UnsentReapplyResult.empty;
    if (_vault.isUnlocked) {
      await _vault.reloadData();
      // The resync replaced the unsent changes; put them back on top of
      // the server copy (lockout review M4). The export file stays.
      if (export != null) {
        reapplied = await _vault.reapplyUnsentChanges(export.objects);
      }
    }
    return FullResyncResult(
      pull: pullResult,
      dirtyCount: dirtyCount,
      dirtyExportPath: export?.path,
      reapplied: reapplied,
    );
  }

  /// Pull new objects from server since last known commit_seq.
  Future<PullResult> pull() => _exclusive(() => _pull(fullResync: false));

  Future<PullResult> _pull({required bool fullResync}) async {
    _ensureAuthenticated();
    // Review c78fd19 (medium): a re-key this pull brings drops the envelope
    // a member's unsent rows were sealed with; their key is kept first.
    if (_vault.isUnlocked) await _vault.keepKeysOfUnsent();

    final checkpoint = await _loadSyncCheckpoint();
    final storedSeq = await _db.getLastCommitSeq();
    if (checkpoint != null && checkpoint['last_sync_seq'] != storedSeq) {
      throw const SyncIntegrityException(
        'Sync sequence does not match the authenticated checkpoint',
      );
    }
    final lastSeq = fullResync
        ? 0
        : (checkpoint?['last_sync_seq'] as int? ?? storedSeq);
    final query = fullResync
        ? 'since_commit_seq=0&full_resync=true'
        : 'since_commit_seq=$lastSeq';
    // Review 7c10379 (as desktop SM7 and web SM71): a server restored from a
    // backup that other devices pushed past this checkpoint again hands the
    // same commit_seq out for other commits. Its head is not behind, so only
    // the token of the commit this phone saw at the checkpoint tells.
    final checkSeq = checkpoint == null ? 0 : _commitTokenSeq(checkpoint);
    final checkToken = checkSeq > 0
        ? checkpoint!['commit_token'] as String?
        : null;
    final checkQuery = checkToken == null
        ? ''
        : '&check_seq=$checkSeq'
              '&check_token=${Uri.encodeQueryComponent(checkToken)}';
    // Review d150605 #5: once the server went back behind the checkpoint,
    // what it commits again reuses sequence numbers this device has passed;
    // a delta pull would skip it even after the head moves on.
    final rollbackHead = await _db.getSetting(serverRollbackSetting);
    if (!fullResync && rollbackHead != null) {
      throw FullResyncRequiredException(
        'The server went back to commit_seq $rollbackHead, below this '
        "device's checkpoint $lastSeq (restored from a backup?); a full "
        'resync is required',
      );
    }
    if (!fullResync && await _db.getSetting(forgottenLogResyncSetting) != null) {
      throw const FullResyncRequiredException(
        'Unsent changes were exported and dropped when this phone left the lost team log; '
        "a full resync puts the server's copy back in their place",
      );
    }

    var response = await _http.get(
      Uri.parse('$_serverUrl/api/sync?$query$checkQuery'),
      headers: _authHeaders(),
    );

    // No ETag / 304 (sync redesign S2): the checkpoint is the only pull state.
    if (response.statusCode == 410) {
      throw const FullResyncRequiredException(
        'Server compacted past the authenticated checkpoint; explicit full resync is required',
      );
    }

    _checkResponse(response, 'pull');

    var data = jsonDecode(response.body) as Map<String, dynamic>;
    final head = data['head_commit_seq'];
    // May the reply be applied: the shared sync core decides
    // (core/src/gate.rs), as on the desktop and the web. A full resync is
    // applied anyway; the answer tells it whether the server went back.
    final gate =
        (syncCore('gate', {
              'checkpoint': {'seq': lastSeq, 'anchor_token': checkToken},
              'reply': {
                'gone': false, // a 410 threw FullResyncRequiredException above
                'head_commit_seq': head is int ? head : null,
                'check_token': data['check_token'],
              },
              'rollback_pending': rollbackHead != null,
            })
            as Map<String, Object?>)['gate'];
    if (!fullResync && gate == 'head_behind') {
      await _db.setSetting(serverRollbackSetting, head.toString());
      throw FullResyncRequiredException(
        'Sync rollback detected: server head commit_seq $head < local '
        'checkpoint $lastSeq (restored from a backup?); a full resync is required',
      );
    }
    if (!fullResync && gate == 'reissued') {
      await _db.setSetting(
        serverRollbackSetting,
        '${head is int ? head : checkSeq}',
      );
      throw FullResyncRequiredException(
        'Sync rollback detected: the server committed commit_seq $checkSeq '
        'again for another change (restored from a backup?); a full resync '
        'is required',
      );
    }
    final pagedObjects = List<dynamic>.from(data['objects'] as List? ?? []);
    var previousCursor = lastSeq;
    while (data['has_more'] == true) {
      final nextCursor = data['next_cursor'];
      final pageMax = data['max_commit_seq'];
      if (nextCursor is! int ||
          pageMax is! int ||
          nextCursor <= previousCursor ||
          nextCursor != pageMax) {
        throw const SyncIntegrityException(
          'Invalid continuation cursor in sync response',
        );
      }
      previousCursor = nextCursor;
      response = await _http.get(
        Uri.parse('$_serverUrl/api/sync?$query&cursor=$nextCursor'),
        headers: _authHeaders(),
      );
      _checkResponse(response, 'pull continuation');
      data = jsonDecode(response.body) as Map<String, dynamic>;
      pagedObjects.addAll(data['objects'] as List? ?? []);
    }
    data['objects'] = pagedObjects;
    // Review 1141a20 (R9-G): the last page's head, as on the desktop. Objects
    // of a later page can need log records the first page's head has not
    // reached yet (a team folder shared while the pages were fetched).
    final teamLogHead = data['team_log_head'];

    final localKeyEpoch =
        int.tryParse(await _db.getSetting('key_epoch') ?? '0') ?? 0;
    final serverKeyEpoch = data['key_epoch'] ?? localKeyEpoch;
    if (serverKeyEpoch is! int || serverKeyEpoch < 0) {
      throw const SyncIntegrityException('Invalid key_epoch in sync response');
    }
    var adoptKeyEpoch = false;
    // Review d615826: a server restored from a backup from before a password
    // change has the older epoch and key material. This was refused on every
    // pull, a dead end. It is the server's current key material: taken over
    // with the password the server has (adoptPasswordChangedElsewhere), as
    // desktop does (stateful test SM12). A session KEK from a login before
    // the restore no longer matches it, so the older epoch is taken only
    // when this phone holds exactly the server's keypair.
    if (serverKeyEpoch < localKeyEpoch &&
        !await _holdsServerKeyMaterial(data['key_material_hash'])) {
      throw KeyEpochStaleException(serverKeyEpoch);
    }
    if (serverKeyEpoch != localKeyEpoch) {
      // Adopt only when this session's KEK was derived from the server's
      // current salt (password login), otherwise the user must re-login.
      // Review 7c10379 H9: and only for the key material that login stored.
      // The flag outlived a password change made elsewhere after the login:
      // the sign-in again on the 401 took the newer epoch over and pushed
      // new keys under the old KEK, which no other device opens.
      if (!_vault.kekMatchesServer ||
          !await _holdsServerKeyMaterial(data['key_material_hash'])) {
        throw KeyEpochStaleException(serverKeyEpoch);
      }
      adoptKeyEpoch = true;
    }
    final objects = data['objects'] as List? ?? [];
    final maxSeq = data['max_commit_seq'];
    if (maxSeq is! int || maxSeq < 0) {
      throw const SyncIntegrityException(
        'Invalid max_commit_seq in sync response',
      );
    }

    final signingPk = _vault.signingPublicKey;
    final currentUserId = _vault.userId;
    if (signingPk == null || currentUserId == null || currentUserId.isEmpty) {
      throw const SyncIntegrityException(
        'Vault signing identity is required to verify sync objects',
      );
    }
    // The log this pull brings decides which keys it retired (capability run
    // 294), as on the desktop: a fresh phone holds no log of its own yet.
    final teamLog = await _syncTeamLog(teamLogHead, checkpoint);
    final authorKeys = <String, List<Uint8List>>{};
    final archiveBounds = <String, Map<String, int>>{};
    final verified = <Map<String, dynamic>>[];
    final stateReplacements = <Map<String, dynamic>>[];
    // Review 8595ec1 (R10-C): what the log refused for want of write access
    // and now allows is judged again with this pull (verified as served).
    // A full resync's snapshot decides them all again.
    final noWriteAccess = fullResync
        ? <String, dynamic>{}
        : Map<String, dynamic>.from(
            jsonDecode(
                  await _db.getSetting(teamLogNoWriteAccessSetting) ?? '{}',
                )
                as Map,
          );
    final inBatch = {for (final obj in objects) (obj as Map)['id']};
    final revived = teamLog == null || noWriteAccess.isEmpty || fullResync
        ? const <Map<String, dynamic>>[]
        : [
            for (final obj in writesTheLogNowAllows(noWriteAccess, {
              for (final row in await _db.getAllObjects())
                row['id'] as String: row,
            }, teamLog.team))
              if (!inBatch.contains(obj['id'])) obj,
          ];
    final revivedIds = {for (final obj in revived) obj['id'] as String};

    // Verify the complete response before mutating local state. Any malformed,
    // unsigned, unknown-key, payload-hash-mismatched or forged object aborts the
    // whole pull, preserving both checkpoint and sequence.
    for (final obj in [...revived, ...objects]) {
      try {
        final pullObj = PullObject.fromJson(obj as Map<String, dynamic>);
        late Uint8List payloadBytes;
        try {
          payloadBytes = base64Decode(pullObj.payload);
        } catch (e) {
          throw SyncIntegrityException(
            'REJECT object ${pullObj.id} — invalid payload encoding',
          );
        }
        final actualPayloadHash = _crypto.sha256Hex(payloadBytes);
        if (actualPayloadHash != pullObj.payloadHash.toLowerCase()) {
          throw SyncIntegrityException(
            'REJECT object ${pullObj.id} — payload_hash does not match ciphertext',
          );
        }

        final sigHex = pullObj.clientSignature;
        if (sigHex == null || sigHex.isEmpty) {
          throw SyncIntegrityException(
            'REJECT object ${pullObj.id} — missing client signature',
          );
        }
        final signerId = pullObj.signatureUserId;
        final authorPks =
            authorKeys[signerId] ??
            await resolveAuthorSigningKeys(
              ownerId: signerId,
              currentUserId: currentUserId,
              currentUserSigningPk: signingPk,
              loadKnownKey: _db.getKnownKey,
              fetchPublicKeys: _fetchPublicKeys,
              saveKnownKey: _db.upsertKnownKey,
              archiveBoundsOut: archiveBounds.putIfAbsent(signerId, () => {}),
              loadSetting: _db.getSetting,
              saveSetting: _db.setSetting,
            );
        authorKeys[signerId] = authorPks;
        final signerBounds = archiveBounds[signerId] ?? const <String, int>{};

        bool sigValid;
        try {
          final signature = hexToBytes(sigHex);
          final message = _crypto.buildSyncSignatureData(
            id: pullObj.id,
            objectType: pullObj.objectType,
            parentRef: pullObj.parentRef,
            targetUserId: pullObj.targetUserId,
            isDeleted: pullObj.isDeleted,
            version: pullObj.version,
            payloadHashHex: pullObj.payloadHash,
          );
          sigValid = authorPks.any(
            (authorPk) =>
                keyMayVouch(
                  authorPk,
                  signerBounds,
                  sinceSeq: lastSeq,
                  commitSeq: pullObj.commitSeq,
                ) &&
                (signerBounds.containsKey(bytesToHex(authorPk)) ||
                    !TeamLog.signingKeyRetired(
                      teamLog?.team,
                      signerId,
                      bytesToHex(authorPk),
                    )) &&
                _crypto.verifyDetached(
                  signature: signature,
                  message: message,
                  publicKey: authorPk,
                ),
          );
        } catch (e) {
          sigValid = false;
        }
        if (!sigValid) {
          throw SyncIntegrityException(
            'REJECT object ${pullObj.id} — invalid Ed25519 signature',
          );
        }

        verified.add({'object': pullObj, 'payload': payloadBytes});
        stateReplacements.add({
          'id': pullObj.id,
          'version': pullObj.version,
          'payload': payloadBytes,
        });
      } on SyncIntegrityException {
        // A kept copy that no longer verifies (its key retired since) is
        // dropped; it never fails the pull of what the server sends now.
        final id = (obj as Map)['id'];
        if (!revivedIds.remove(id)) rethrow;
        noWriteAccess.remove(id);
      }
    }

    final candidateAudits = <String, Map<String, Object>>{};
    if (!fullResync) {
      for (final row in await _db.getAllObjects()) {
        if (row['object_type'] == 'audit' && row['is_deleted'] != 1) {
          candidateAudits[row['id'] as String] = {
            'payload': row['payload'] as Uint8List,
            'version': row['version'] as int,
          };
        }
      }
    }
    for (final item in verified) {
      final pullObj = item['object'] as PullObject;
      if (pullObj.objectType == 'audit') {
        if (pullObj.isDeleted != 0) {
          throw SyncIntegrityException(
            'REJECT audit ${pullObj.id} — audit records are append-only',
          );
        }
        candidateAudits[pullObj.id] = {
          'payload': item['payload'] as Uint8List,
          'version': pullObj.version,
        };
      }
    }

    final auditRecords = <CanonicalAuditRecord>[];
    for (final entry in candidateAudits.entries) {
      final record = parseCanonicalAuditRecord(
        entry.key,
        entry.value['payload']! as Uint8List,
        entry.value['version']! as int,
      );
      final actorPks =
          authorKeys[record.actorId] ??
          await resolveAuthorSigningKeys(
            ownerId: record.actorId,
            currentUserId: currentUserId,
            currentUserSigningPk: signingPk,
            loadKnownKey: _db.getKnownKey,
            fetchPublicKeys: _fetchPublicKeys,
            saveKnownKey: _db.upsertKnownKey,
          );
      authorKeys[record.actorId] = actorPks;
      final canonical = buildAuditCanonical(record, _crypto);
      if (!actorPks.any(
        (actorPk) => _crypto.verifyDetached(
          signature: record.signature,
          message: canonical,
          publicKey: actorPk,
        ),
      )) {
        throw SyncIntegrityException(
          'REJECT audit ${record.id} — invalid audit signature',
        );
      }
      auditRecords.add(record);
    }
    validateAuditDag(auditRecords);

    // Review d615826 H6: a full resync is how the phone recovers from a
    // server that went back; checking the old checkpoint here refused it
    // every time. It keeps what the restored server lost instead.
    // The last commit seen, not a cursor moved up to the GC floor.
    final previousSeq = checkpoint == null ? null : _commitTokenSeq(checkpoint);
    var kept = const <Map<String, dynamic>>[];
    // The server copy a kept row is sent on top of (S1: version and hash).
    final serverHashes = <String, String>{};
    final serverVersions = <String, int>{};
    if (fullResync) {
      for (final item in verified) {
        final obj = item['object'] as PullObject;
        serverVersions[obj.id] = obj.version;
        serverHashes[obj.id] = obj.payloadHash;
      }
      final gcFloor = data['gc_floor_seq'];
      // Review a159e97: after an identity rotation this user's confirmed rows
      // carry the previous key's signature. Its archive is trusted only
      // through a rotation certificate chained to the current key, so the
      // server cannot add one; a row stored here passed its pull check.
      final ownKeys = await resolveAuthorSigningKeys(
        ownerId: currentUserId,
        currentUserId: currentUserId,
        currentUserSigningPk: signingPk,
        loadKnownKey: _db.getKnownKey,
        fetchPublicKeys: _fetchPublicKeys,
        saveKnownKey: _db.upsertKnownKey,
      );
      kept = rowsTheServerLost(
        await _db.getAllObjects(),
        serverVersions,
        gcFloor: gcFloor is int ? gcFloor : 0,
        rolledBack:
            previousSeq != null && maxSeq < previousSeq || gate != 'apply',
        ownSigned: (row) =>
            ownKeys.any((pk) => _signedByMe(row, pk)) || _ownRewrappedKey(row),
      );
      final keptIds = {for (final row in kept) row['id'] as String};
      verified.removeWhere(
        (item) => keptIds.contains((item['object'] as PullObject).id),
      );
      stateReplacements.removeWhere((r) => keptIds.contains(r['id']));
    }

    // TL5 (§4.3.4, §6): follow the server's team log, then let it decide
    // what lands in a team folder. A change it refuses is not applied; the
    // copy this phone held stays (a full resync keeps it too).
    final heldBack = <Map<String, dynamic>>[];
    final refusalReasons = <String, String>{};
    if (teamLog != null) {
      final held = {
        for (final row in await _db.getAllObjects()) row['id'] as String: row,
      };
      final refused = teamLogRefusedPulls(
        [
          for (final item in verified)
            {
              'id': (item['object'] as PullObject).id,
              'object_type': (item['object'] as PullObject).objectType,
              'parent_ref': (item['object'] as PullObject).parentRef,
              'signer_id': (item['object'] as PullObject).signatureUserId,
              'target_user_id': (item['object'] as PullObject).targetUserId,
              'access_level': (item['object'] as PullObject).accessLevel,
              'payload': item['payload'],
              'is_deleted': (item['object'] as PullObject).isDeleted,
            },
        ],
        held,
        teamLog.team,
        currentUserId,
        ownEncryptionPk: _vault.encryptionPublicKey == null
            ? null
            : bytesToHex(_vault.encryptionPublicKey!),
        reasons: refusalReasons,
      );
      final served = {
        for (final obj in [...revived, ...objects]) (obj as Map)['id']: obj,
      };
      for (final item in verified) {
        final pullObj = item['object'] as PullObject;
        noWriteAccess.remove(pullObj.id); // this copy decides now
        if (refusalReasons[pullObj.id] == teamLogNoWriteAccess &&
            pullObj.isDeleted == 0) {
          noWriteAccess[pullObj.id] = served[pullObj.id];
        }
      }
      verified.removeWhere(
        (item) => refused.contains((item['object'] as PullObject).id),
      );
      stateReplacements.removeWhere((r) => refused.contains(r['id']));
      if (fullResync) {
        for (final row in [
          for (final id in refused)
            if (held[id] != null) held[id]!,
        ]) {
          final id = row['id'] as String;
          heldBack.add(Map<String, dynamic>.from(row));
          stateReplacements.add({
            'id': id,
            'version': row['version'],
            'payload': row['payload'],
          });
        }
      }
    }

    if (!fullResync) {
      // Review c78fd19: an older copy (or another one of the version held)
      // does not replace the server copy this phone holds.
      final held = {
        for (final row in await _db.getAllObjects()) row['id'] as String: row,
      };
      final floor = data['gc_floor_seq'];
      final stale = {
        for (final item in verified)
          if (pulledIsStale(
            held[(item['object'] as PullObject).id],
            objectType: (item['object'] as PullObject).objectType,
            version: (item['object'] as PullObject).version,
            hash: (item['object'] as PullObject).payloadHash,
            gcFloor: floor is int ? floor : 0,
          ))
            (item['object'] as PullObject).id,
      };
      verified.removeWhere(
        (item) => stale.contains((item['object'] as PullObject).id),
      );
      stateReplacements.removeWhere((r) => stale.contains(r['id']));
    }

    final candidateStateHash = await _computeStateHash(
      replacements: stateReplacements,
      replaceAll: fullResync,
    );
    if (checkpoint != null && !fullResync) {
      final previousSeq = checkpoint['last_sync_seq'] as int;
      final previousHash = checkpoint['state_hash'] as String;
      // Applying only writes the log now allows (served before) changes the
      // state at this seq here, not on the server.
      final servedNow = verified.any(
        (item) => !revivedIds.contains((item['object'] as PullObject).id),
      );
      // The shared sync core decides (core/src/gate.rs check_state).
      final verdict =
          syncCore('check_state', {
                'stored': {'seq': previousSeq, 'state_hash': previousHash},
                'candidate': {
                  'max_commit_seq': maxSeq,
                  'state_hash': candidateStateHash,
                  'served': servedNow || revivedIds.isEmpty,
                },
              })
              as Map<String, Object?>;
      if (verdict['state'] == 'rollback') {
        throw SyncIntegrityException(
          'ROLLBACK DETECTED: server seq $maxSeq < stored $previousSeq',
        );
      }
      if (verdict['state'] == 'mismatch') {
        throw SyncIntegrityException(
          'STATE MISMATCH at seq $maxSeq: ciphertext state changed',
        );
      }
    }

    final rowsToApply = <Map<String, Object?>>[];
    for (final item in verified) {
      final pullObj = item['object'] as PullObject;
      rowsToApply.add({
        'id': pullObj.id,
        'object_type': pullObj.objectType,
        'payload': item['payload'] as Uint8List,
        'owner_id': verifiedOwnerId(pullObj),
        'signer_id': pullObj.signatureUserId,
        'parent_ref': pullObj.parentRef,
        'target_user_id': pullObj.targetUserId,
        'version': pullObj.version,
        'commit_seq': pullObj.commitSeq,
        'is_deleted': pullObj.isDeleted,
        'payload_hash': pullObj.payloadHash,
        'client_signature': hexToBytes(pullObj.clientSignature!),
        'modified_at': pullObj.modifiedAt,
        'write_policy': pullObj.writePolicy,
        'access_level': pullObj.accessLevel,
      });
    }
    rowsToApply.addAll(heldBack);
    // Sent again with the next push; unconfirmed, so outside the checkpoint.
    for (final row in kept) {
      final id = row['id'] as String;
      rowsToApply.add({
        ..._signedForPush(row, signingPk),
        'queued': 1,
        'commit_seq': null,
        'base_version': serverVersions[id],
        'base_hash': serverHashes[id],
      });
    }

    // data is the last page here: its max_token is the token of maxSeq.
    final maxToken = data['max_token'];
    // Review a159e97 (port of desktop 1cff856): a snapshot whose newest
    // commits were collected tombstones ends below the GC floor. Stored as
    // the cursor, every later pull asked from below the floor and got 410
    // for good. The cursor continues from the floor (nothing exists between
    // the two); the token stays anchored at the last commit seen.
    final floor = data['gc_floor_seq'];
    final cursor =
        syncCore('next_cursor', {
              'last_seq': fullResync || checkpoint == null ? 0 : lastSeq,
              'max_commit_seq': maxSeq,
              'gc_floor_seq': floor is int ? floor : 0,
              'head_commit_seq': head is int ? head : null,
            })
            as int;
    var tokenSeq = maxSeq;
    String? token = maxToken is String && maxToken.isNotEmpty ? maxToken : null;
    if (!fullResync &&
        checkpoint != null &&
        maxSeq <= _commitTokenSeq(checkpoint)) {
      tokenSeq = _commitTokenSeq(checkpoint);
      token = checkpoint['commit_token'] as String?;
    }
    final encryptedCheckpoint = _encryptSyncCheckpoint(
      cursor,
      candidateStateHash,
      commitToken: token,
      commitTokenSeq: tokenSeq,
      teamLog: teamLogPin(teamLog?.team),
    );
    // Before the checkpoint that pins its head: a copy ahead of the pin is
    // checked again by the next pull, one behind it is fetched again.
    if (!identical(teamLog, _vault.teamLog)) {
      if (teamLog == null) {
        await _db.deleteSetting(teamLogRecordsSetting);
      } else {
        await _db.setSetting(
          teamLogRecordsSetting,
          jsonEncode(teamLog.records),
        );
      }
    }
    List<Map<String, dynamic>> conflictRows;
    if (fullResync) {
      await _db.replaceSnapshotAndCommitCheckpoint(
        objects: rowsToApply,
        seq: cursor,
        checkpointKey: _checkpointKey(),
        encryptedCheckpoint: encryptedCheckpoint,
      );
      conflictRows = const [];
    } else {
      conflictRows = await _db.applyPullAndCommitCheckpoint(
        objects: rowsToApply,
        seq: cursor,
        checkpointKey: _checkpointKey(),
        encryptedCheckpoint: encryptedCheckpoint,
      );
    }
    final conflicts = conflictRows.map(PullConflict.fromMap).toList();
    _vault.teamLog = teamLog;
    // INV-7: the copy fetched again ends the refusal; the team keys open now.
    if (_vault.teamLogRefusal != null && _vault.isUnlocked) await _vault.reloadData();
    // After the commit: a revived copy lost to a crash here is judged again.
    if (noWriteAccess.isEmpty) {
      await _db.deleteSetting(teamLogNoWriteAccessSetting);
    } else {
      await _db.setSetting(
        teamLogNoWriteAccessSetting,
        jsonEncode(noWriteAccess),
      );
    }
    if (adoptKeyEpoch) {
      await _db.setSetting('key_epoch', serverKeyEpoch.toString());
    }
    // A folder deleted elsewhere that holds work this phone has not sent
    // comes back (the server refuses the work below a deleted folder).
    // Review c78fd19 (medium): the pull is committed by now; a revive that
    // fails is retried by the next pull and does not fail this one (it
    // failed every pull, with the rest of the pull's bookkeeping left out).
    if (_vault.isUnlocked) {
      try {
        await _vault.reviveFoldersOfUnsent();
      } catch (_) {
        // The item stays queued; the push reports it.
      }
    }

    return PullResult(
      newObjects: verified.length - conflicts.length,
      maxCommitSeq: maxSeq,
      conflicts: conflicts,
    );
  }

  /// The organisation's log at the pull's [head] (TL5, §6); a log that does
  /// not continue what this phone saw ([checkpoint]'s pin) aborts the pull.
  Future<LocalTeamLog?> _syncTeamLog(
    Object? head,
    Map<String, dynamic>? checkpoint,
  ) async {
    // INV-7: conflicting pins are forgotten together, never followed; a
    // damaged copy (local_damaged) is fetched again below under its pins.
    final refused = _vault.teamLogRefusal;
    if (refused?.cause == 'anchor_conflict') {
      throw SyncIntegrityException('$refused', teamLog: refused);
    }
    try {
      return await syncTeamLog(
        log: TeamLog(_vault.verifyEd25519),
        head: head is Map<String, dynamic> ? head : null,
        local: _vault.teamLog,
        pin: checkpoint?['team_log'] as Map<String, dynamic>?,
        confirmedGenesis: await readConfirmedTeamGenesis(_vault.userId!),
        leftEarlierLog: (await readForgottenTeamGenesis(_vault.userId!)).isNotEmpty,
        fetchPage: (since) async {
          final response = await _http.get(
            Uri.parse('$_serverUrl/api/team-log?since=$since'),
            headers: _authHeaders(),
          );
          _checkResponse(response, 'team log');
          final body = jsonDecode(response.body) as Map<String, dynamic>;
          return [
            for (final r in body['records'] as List? ?? const [])
              Map<String, dynamic>.from(r as Map),
          ];
        },
        // R9-E: put back what a server restored from a backup lost.
        restore: (records) async {
          final response = await _http.post(
            Uri.parse('$_serverUrl/api/team-log/restore'),
            headers: _authHeaders(),
            body: jsonEncode({'records': records}),
          );
          // 409 (its head is not the one it announced: another device put
          // them back meanwhile, or a lie) throws too: the next pull compares again.
          _checkResponse(response, 'team log restore');
          return (jsonDecode(response.body) as Map<String, dynamic>)['head'] as Map<String, dynamic>?;
        },
      );
    } on TeamLogMismatch catch (e) {
      throw SyncIntegrityException('$e', teamLog: e);
    }
  }

  /// Why this phone refuses the server's team log now (the pull's own
  /// judgment), or null: it follows it. INV-8: forgetting the pin asks this;
  /// INV-7: settings offer the forget only where [TeamLogMismatch.offersForget].
  Future<TeamLogMismatch?> teamLogRefusal() => _exclusive(_teamLogRefusal);

  Future<TeamLogMismatch?> _teamLogRefusal() async {
    final response = await _http.get(
      Uri.parse('$_serverUrl/api/team-log?since=${_vault.teamLog?.team.headSeq ?? -1}'),
      headers: _authHeaders(),
    );
    _checkResponse(response, 'team log');
    final head = (jsonDecode(response.body) as Map<String, dynamic>)['head'];
    try {
      await _syncTeamLog(head, await _loadSyncCheckpoint());
    } on SyncIntegrityException catch (e) {
      if (e.teamLog != null) return e.teamLog;
      rethrow;
    }
    return null;
  }

  /// Fetch the team log before an unlock when the cached copy is missing or
  /// does not verify ([verifiedTeamLogCopy]), under every pin this phone
  /// holds: the confirmed genesis and the head its checkpoint saw. INV-7:
  /// before, a checkpoint that pinned a log made a lost or damaged copy a
  /// mismatch with no way out, every unlock failed on it; the pins, not the
  /// copy, refuse a server that went back, forked or changed its genesis.
  /// Review 8595ec1 #6: a phone that last pulled before the log was founded
  /// has a checkpoint without a pin, and taking an anchor password over must
  /// bring the log. Review c78fd19 #4: [kek] is the KEK the unlock about to
  /// run derived; without one the checkpoint is not read and the unlock decides.
  Future<void> prepareInitialTeamLog(String userId, {Uint8List? kek}) => _exclusive(() async {
    final String? genesis;
    try {
      genesis = await readConfirmedTeamGenesis(userId);
    } on TeamLogMismatch {
      // Capability run 412: a pin that cannot be read holds nothing to fetch
      // under; the unlock opens and refuses the team (local_damaged).
      return;
    }
    if (_vault.teamLog != null) return;
    Map<String, dynamic>? pin;
    if (await _db.getSyncState(_checkpointKey(userId)) != null) {
      final key = kek ?? _vault.currentKek;
      if (key == null) return;
      final checkpoint = await _loadSyncCheckpoint(kek: key, userId: userId);
      pin = checkpoint?['team_log'] as Map<String, dynamic>?;
    }
    if (genesis == null && pin == null) return;
    try {
      verifiedTeamLogCopy(await _db.getSetting(teamLogRecordsSetting), genesis,
          [?pin], _vault.verifyEd25519);
      return;
    } catch (_) {
      // Missing or not verified: fetched again below under the same pins.
    }
    Future<Map<String, dynamic>> page(int since) async {
      final response = await _http.get(
        Uri.parse('$_serverUrl/api/team-log?since=$since'), headers: _authHeaders());
      _checkResponse(response, 'initial team log');
      return jsonDecode(response.body) as Map<String, dynamic>;
    }
    final first = await page(-1);
    final verified = await syncTeamLog(
      log: TeamLog(_vault.verifyEd25519),
      head: first['head'] as Map<String, dynamic>?,
      local: null, pin: pin, confirmedGenesis: genesis,
      fetchPage: (since) async {
        final body = since == -1 ? first : await page(since);
        return [for (final r in body['records'] as List) Map<String, dynamic>.from(r as Map)];
      },
    );
    await _db.setSetting(teamLogRecordsSetting, jsonEncode(verified!.records));
  });

  /// Every genesis this phone holds on to: its confirmed pin, its copy of
  /// the log, the head its checkpoint pins.
  Future<List<String>> pinnedTeamGenesis() => _exclusive(_pinnedTeamGenesis);

  Future<List<String>> _pinnedTeamGenesis() async {
    final userId = _vault.userId;
    if (userId == null || _vault.currentKek == null) throw StateError('Vault must be unlocked');
    final pin = (await _loadSyncCheckpoint())?['team_log'] as Map<String, dynamic>?;
    // Unreadable trust records are no pin to type (run 412); an unreadable
    // list of left hashes hides nothing.
    Future<T?> readable<T>(Future<T> Function(String) read) async {
      try {
        return await read(userId);
      } on TeamLogMismatch {
        return null;
      }
    }
    final forgotten = await readable(readForgottenTeamGenesis) ?? const <String>[];
    final anchor = await _storedKeypairAnchor(userId);
    return ({
      if (anchor != null && !forgotten.contains(anchor)) anchor,
      ?await readable(readAccountTeamGenesis),
      ?await readable(readConfirmedTeamGenesis),
      ?_vault.teamLog?.team.genesisHash,
      ?pin?['genesis_hash'] as String?,
    }.toList()..sort());
  }

  /// The genesis the keypair stored on this phone is anchored to, if any.
  Future<String?> _storedKeypairAnchor(String userId) async {
    const storage = FlutterSecureStorage(
      aOptions: AndroidOptions(encryptedSharedPreferences: true),
      iOptions: IOSOptions(
        accessibility: KeychainAccessibility.first_unlock_this_device,
      ),
    );
    if (await storage.read(key: 'sezam_user_object_id') != userId) return null;
    final local = await storage.read(key: 'sezam_encrypted_keypair');
    if (local == null || local.isEmpty) return null;
    final account = _crypto.openAccountKeypair(hexToBytes(local), _vault.currentKek!, userId);
    _crypto.zeroize(account.keypairData);
    return account.confirmedGenesis;
  }

  /// Review c78fd19 (medium): leave a team log the server lost for good
  /// (moved, reseeded, no restore), which otherwise left the phone with TEAM
  /// LOG MISMATCH for good. [typed] is the pinned genesis, at least its first
  /// [forgetPinMinChars] characters. The phone drops its pin, its copy and its
  /// checkpoint's head, and the next pull follows the server's log as a new
  /// one, trusted only once its founder is confirmed again. Returns the
  /// genesis hashes left.
  ///
  /// Unsent changes cannot reach the lost log: refused with
  /// [UnsentChangesBlockForget] unless [discardUnsent] (review 8bc70f7 M2: the
  /// phone had no way out). Then they are exported ([latestUnsentExport]),
  /// dropped, and the next sync asks for a full resync, which puts the
  /// server's copy back in place of the edits.
  Future<List<String>> forgetTeamLogPin(String typed, {bool discardUnsent = false}) => _exclusive(() async {
    final userId = _vault.userId!;
    final pins = await _pinnedTeamGenesis();
    if (pins.isEmpty) throw StateError('This phone pins no team log; nothing to forget.');
    // INV-7: conflicting pins (anchor_conflict: the account keys name another
    // log than this phone holds) are left together, each one typed.
    final parts = typed.replaceAll(',', ' ').toLowerCase().split(RegExp(r'\s+')).where((p) => p.isNotEmpty).toList();
    if (parts.isEmpty ||
        parts.any((part) => part.length < forgetPinMinChars) ||
        !pins.every((pin) => parts.any(pin.startsWith)) ||
        !parts.every((part) => pins.any((pin) => pin.startsWith(part)))) {
      throw FormatException('Type the pinned genesis, every one (at least its first $forgetPinMinChars '
          'characters), to forget it: ${pins.join(', ')}');
    }
    // INV-8: only a log this phone refuses as lost now (teamLogMismatchForget),
    // never a fork; asked before any unsent change is dropped.
    final refusal = await _teamLogRefusal();
    if (refusal == null || !refusal.offersForget) throw TeamLogNotLost(refusal);
    final unsent = (await _db.getDirtyObjects()).length;
    if (unsent > 0 && !discardUnsent) throw UnsentChangesBlockForget(unsent);
    // Only what the file holds is dropped: an edit saved meanwhile stays queued.
    final exported = unsent > 0 ? await _exportDirtyObjects() : null;
    final dropped = [for (final o in exported?.objects ?? const <Map<String, dynamic>>[]) o['id'] as String];
    final checkpoint = await _loadSyncCheckpoint();
    // Left first: a crash below never takes it back from the account bundle.
    await forgetConfirmedTeamGenesis(userId, pins);
    await _db.leaveTeamLog(
      recordsSetting: teamLogRecordsSetting,
      checkpointKey: _checkpointKey(),
      encryptedCheckpoint: checkpoint == null
          ? null
          : _encryptSyncCheckpoint(
              checkpoint['last_sync_seq'] as int,
              checkpoint['state_hash'] as String,
              commitToken: checkpoint['commit_token'] as String?,
              commitTokenSeq: _commitTokenSeq(checkpoint),
            ),
      dropWrites: dropped,
      resyncSetting: forgottenLogResyncSetting,
    );
    _vault.teamLog = null;
    await _vault.reloadData();
    return pins;
  });

  /// Full sync cycle: push dirty, then pull new.
  Future<SyncResult> sync() => _exclusive(_sync);

  Future<SyncResult> _sync() async {
    try {
      return await _syncOnce();
    } on SyncException catch (e) {
      // Review d615826: an identity rotation or password change elsewhere
      // revokes this session's token. Every sync failed with 401 and nothing
      // signed in again, so the phone never learned of the rotation and its
      // unsent changes never went out. Signing in again reports it
      // (KeyEpochStaleException) or gives a fresh session.
      if (e.statusCode != 401 || !await _signInAgain()) rethrow;
      return _syncOnce();
    }
  }

  Future<bool> _signInAgain() async {
    final signingKey = _vault.signingSecretKey;
    final prefs = await SharedPreferences.getInstance();
    final username = prefs.getString(usernamePrefKey);
    if (signingKey == null || username == null || username.isEmpty) {
      return false;
    }
    _token = null;
    await authenticate(username: username, signingSecretKey: signingKey);
    return true;
  }

  Future<SyncResult> _syncOnce() async {
    PushResult pushResult;
    // INV-7: a damaged copy holds the team's rows back; the pull fetches it
    // again first so they go too. That fetch failing never holds the personal
    // tree's back: the push sends them, the pull below fetches again (and throws).
    if (_vault.teamLogRefusal?.cause == 'local_damaged') {
      try {
        await pull();
      } on Exception {
        // Reported by the pull after the push.
      }
    }
    try {
      pushResult = await push();
    } on KeyEpochStaleException {
      // Review d615826: the push still carries the epoch this phone had; the
      // server's moved (a change taken over, or a restore took it back).
      // With the KEK from the server's current salt the pull takes the
      // server's epoch over first, and the unsent changes go out under it.
      if (!_vault.kekMatchesServer) rethrow;
      await pull();
      pushResult = await push();
    }
    final pullResult = await pull();

    // If we pulled new data, reload decrypted cache in vault_service
    if (pullResult.newObjects > 0 && _vault.isUnlocked) {
      await _vault.reloadData();
    }

    return SyncResult(push: pushResult, pull: pullResult);
  }

  // ── Helpers ──

  Map<String, String> _headers() => {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  };

  Map<String, String> _authHeaders() => {
    ..._headers(),
    'Authorization': 'Bearer $_token',
  };

  void _ensureConfigured() {
    if (!isConfigured) {
      throw StateError('Server not configured. Call configure() first.');
    }
  }

  void _ensureAuthenticated() {
    _ensureConfigured();
    if (!isAuthenticated) {
      throw StateError('Not authenticated. Call authenticate() first.');
    }
  }

  void _checkResponse(http.Response response, String operation) {
    if (response.statusCode >= 200 && response.statusCode < 300) return;

    String message;
    try {
      final body = jsonDecode(response.body);
      message = body['detail']?.toString() ?? response.body;
    } catch (_) {
      message = response.body;
    }

    throw SyncException(
      operation: operation,
      statusCode: response.statusCode,
      message: message,
    );
  }

  /// The machine-readable `code` of a server error answer (server/app/errors.py).
  String? _errorCode(http.Response response) {
    try {
      final body = jsonDecode(response.body);
      return body is Map && body['code'] is String
          ? body['code'] as String
          : null;
    } catch (_) {
      return null;
    }
  }

  /// Set the token directly (for restoring sessions).
  void setToken(String token) {
    _token = token;
  }

  /// Forget the token locally, without telling any server.
  void clearToken() {
    _token = null;
  }

  // ── Bootstrap & Registration ──

  /// Check if the server needs initial admin setup.
  /// GET /api/bootstrap-status -> {needs_setup: bool}
  Future<Map<String, dynamic>> bootstrapStatus() async {
    _ensureConfigured();

    final response = await _http.get(
      Uri.parse('$_serverUrl/api/bootstrap-status'),
      headers: _headers(),
    );
    _checkResponse(response, 'bootstrapStatus');
    return jsonDecode(response.body) as Map<String, dynamic>;
  }

  /// Bootstrap the server — create first admin user.
  /// POST /api/bootstrap {username, signing_pk, encryption_pk}
  /// -> {user_id, token}
  Future<Map<String, dynamic>> bootstrap({
    required String username,
    required String signingPkHex,
    required String encryptionPkHex,
  }) async {
    _ensureConfigured();

    final response = await _http.post(
      Uri.parse('$_serverUrl/api/bootstrap'),
      headers: _headers(),
      body: jsonEncode({
        'username': username,
        'signing_pk': signingPkHex,
        'encryption_pk': encryptionPkHex,
      }),
    );
    _checkResponse(response, 'bootstrap');

    final data = jsonDecode(response.body) as Map<String, dynamic>;
    _token = data['token'] as String;
    return data;
  }

  /// Register a new user via invitation token.
  /// POST /api/users/register {invitation_token, username, signing_pk, encryption_pk}
  /// -> {user_id, token}
  Future<Map<String, dynamic>> register({
    required String invitationToken,
    required String username,
    required String signingPkHex,
    required String encryptionPkHex,
  }) async {
    _ensureConfigured();

    final response = await _http.post(
      Uri.parse('$_serverUrl/api/users/register'),
      headers: _headers(),
      body: jsonEncode({
        'invitation_token': invitationToken,
        'username': username,
        'signing_pk': signingPkHex,
        'encryption_pk': encryptionPkHex,
      }),
    );
    _checkResponse(response, 'register');

    final data = jsonDecode(response.body) as Map<String, dynamic>;
    _token = data['token'] as String;
    return data;
  }

  /// Upload encrypted keypair to server.
  /// PUT /api/me/keypair {encrypted_keypair, argon2_salt, auth_salt, auth_proof}
  Future<void> uploadKeypair({
    required String encryptedKeypairHex,
    required String argon2SaltHex,
    required String authSaltHex,
    required String authProofHex,
    required Map<String, int> argon2Params,
    ({String username, Uint8List signingSecretKey})? signedBy,
  }) async {
    _ensureConfigured();
    if (_token == null) {
      throw StateError(
        'Not authenticated. Call authenticate() or bootstrap() first.',
      );
    }

    final body = <String, dynamic>{
      'encrypted_keypair': encryptedKeypairHex,
      'argon2_salt': argon2SaltHex,
      'auth_salt': authSaltHex,
      'auth_proof': authProofHex,
      // Per-account KDF params: other clients derive the same KEK.
      'argon2_params': argon2Params,
    };
    if (signedBy != null) {
      // A full session (not the onboarding one) uploads the first key
      // material only with a fresh challenge signed by the account.
      final challengeResp = await _http.post(
        Uri.parse('$_serverUrl/api/auth/challenge'),
        headers: _headers(),
        body: jsonEncode({'username': signedBy.username}),
      );
      _checkResponse(challengeResp, 'challenge');
      final challenge =
          (jsonDecode(challengeResp.body) as Map<String, dynamic>)['challenge'] as String;
      body['challenge'] = challenge;
      body['signature'] = bytesToHex(
        _crypto.signAuthChallenge(hexToBytes(challenge), signedBy.signingSecretKey),
      );
    }
    final response = await _http.put(
      Uri.parse('$_serverUrl/api/me/keypair'),
      headers: _authHeaders(),
      body: jsonEncode(body),
    );
    _checkResponse(response, 'uploadKeypair');
    if (signedBy != null) {
      // Older sessions are revoked with this upload.
      final token = (jsonDecode(response.body) as Map<String, dynamic>)['token'];
      if (token is String && token.isNotEmpty) _token = token;
    }
  }

  /// Check user status (for approval polling).
  /// Uses challenge-response — if auth succeeds, user is active.
  /// Returns true if user can authenticate (is active).
  Future<bool> checkUserActive({
    required String username,
    required Uint8List signingSecretKey,
  }) async {
    try {
      await authenticate(
        username: username,
        signingSecretKey: signingSecretKey,
      );
      return true;
    } on SyncException catch (e) {
      if (e.statusCode == 401 || e.statusCode == 403) {
        return false;
      }
      rethrow;
    }
  }
}

// ── Result types ──

class PushResult {
  final int accepted;
  final int conflicts;
  final List<String> errors;

  const PushResult({
    required this.accepted,
    required this.conflicts,
    required this.errors,
  });
}

class PullConflict {
  final String id;
  final String objectType;
  final int localVersion;
  final int serverVersion;

  const PullConflict({
    required this.id,
    required this.objectType,
    required this.localVersion,
    required this.serverVersion,
  });

  factory PullConflict.fromMap(Map<String, dynamic> value) => PullConflict(
    id: (value['id'] ?? value['object_id']) as String,
    objectType: value['object_type'] as String,
    localVersion: value['local_version'] as int,
    serverVersion: value['server_version'] as int,
  );
}

class PullResult {
  final int newObjects;
  final int maxCommitSeq;
  final List<PullConflict> conflicts;

  const PullResult({
    required this.newObjects,
    required this.maxCommitSeq,
    required this.conflicts,
  });
}

class SyncResult {
  final PushResult push;
  final PullResult pull;

  const SyncResult({required this.push, required this.pull});
}

class FullResyncResult {
  final PullResult pull;
  final int dirtyCount;
  final String? dirtyExportPath;
  final UnsentReapplyResult reapplied;

  const FullResyncResult({
    required this.pull,
    required this.dirtyCount,
    required this.dirtyExportPath,
    this.reapplied = UnsentReapplyResult.empty,
  });
}

class SyncIntegrityException implements Exception {
  final String message;

  /// The team log refusal this stands for (its cause decides the offer, INV-7).
  final TeamLogMismatch? teamLog;

  const SyncIntegrityException(this.message, {this.teamLog});

  @override
  String toString() => 'SyncIntegrityException: $message';
}

/// The server's key_epoch moved on (password changed on another device) and
/// this session's KEK is the previous one: take the change over with the
/// current password (AuthService.adoptPasswordChangedElsewhere).
class KeyEpochStaleException extends SyncIntegrityException {
  final int? serverKeyEpoch;

  const KeyEpochStaleException([this.serverKeyEpoch])
    : super(
        'The password was changed on another device; enter the current '
        'password to continue syncing',
      );
}

class FullResyncRequiredException extends SyncIntegrityException {
  const FullResyncRequiredException(super.message);
}

/// Server head seen behind this device's checkpoint (review d150605 #5).
const serverRollbackSetting = 'server_rollback_head';

/// Set when forgetting the team log dropped unsent changes (review 8bc70f7 M2).
const forgottenLogResyncSetting = 'forgotten_log_resync';

/// Forgetting the team log waits for these unsent changes, or drops them.
class UnsentChangesBlockForget implements Exception {
  const UnsentChangesBlockForget(this.count);
  final int count;

  @override
  String toString() => 'This phone holds $count unsent changes the lost team log no longer takes.';
}

/// INV-8: the server's team log is not lost (this phone follows it, or it
/// lies: a fork, a log going back), so the pin is not forgotten.
class TeamLogNotLost implements Exception {
  const TeamLogNotLost(this.refusal);
  final TeamLogMismatch? refusal;

  @override
  String toString() => 'Tímový denník na serveri nie je stratený, preto sa nezabúda '
      '(len denník stratený natrvalo, nikdy fork či návrat späť): ${refusal ?? 'telefón ho nasleduje'}';
}

class TofuKeyChangeException extends SyncIntegrityException {
  final String userId;
  final String oldFingerprint;
  final String newFingerprint;
  final Uint8List signingPk;
  final Uint8List encryptionPk;

  TofuKeyChangeException({
    required this.userId,
    required this.oldFingerprint,
    required this.newFingerprint,
    required this.signingPk,
    required this.encryptionPk,
  }) : super('TOFU key change for $userId: $oldFingerprint -> $newFingerprint');
}

class SyncException implements Exception {
  final String operation;
  final int statusCode;
  final String message;

  const SyncException({
    required this.operation,
    required this.statusCode,
    required this.message,
  });

  @override
  String toString() => 'SyncException($operation, $statusCode): $message';
}

/// Review 4acfdde R11 (low): another account took the name a rejoin asked
/// for (registered after the backup the server was restored from).
class UsernameTakenException extends SyncException {
  final String username;

  const UsernameTakenException(this.username)
    : super(operation: 'rejoin', statusCode: 409, message: 'username taken: $username');
}

/// Review 8595ec1 #1: the server refuses the login of an account the team
/// log names as a current member with this phone's keys. A server restored
/// from a backup older than the account: AuthService.rejoinServer brings it
/// back under its id.
class AccountLostOnServerException extends SyncException {
  const AccountLostOnServerException()
    : super(
        operation: 'verify',
        statusCode: 401,
        message:
            'The server does not know this account although the team log '
            "names it with this phone's keys. If the server was restored from "
            'a backup older than the account, rejoin it with your password.',
      );
}

/// Must equal server.app.auth.reseed_message(..., REJOIN_CONTEXT) byte for byte.
Uint8List rejoinMessage(
  Uint8List challenge,
  String userId,
  String username,
  Uint8List signingPk,
  Uint8List encryptionPk,
  int keyEpoch,
) {
  final name = utf8.encode(username);
  final id = Uint8List(26)..setAll(0, ascii.encode(userId).take(26));
  final epoch = ByteData(8)..setUint64(0, keyEpoch);
  return (BytesBuilder(copy: false)
        ..add(utf8.encode('sezam-rejoin-v1'))
        ..add(challenge)
        ..add(id)
        ..add([(name.length >> 8) & 0xff, name.length & 0xff])
        ..add(name)
        ..add(signingPk)
        ..add(encryptionPk)
        ..add(epoch.buffer.asUint8List()))
      .toBytes();
}

class _ArchivedKeyCandidate {
  _ArchivedKeyCandidate({
    required this.signingPk,
    required this.encryptionPk,
    required this.successorSigningPk,
    required this.certificate,
    this.authorization,
    this.retiredSeq,
  });

  final Uint8List signingPk;
  final Uint8List encryptionPk;
  final Uint8List successorSigningPk;
  final Uint8List certificate;
  final Uint8List? authorization;
  final int? retiredSeq;
}

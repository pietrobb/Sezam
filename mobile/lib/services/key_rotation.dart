/// Taking over a password change made on another device (review 2052248,
/// finding 1): the local DEK wraps move from the previous KEK to the server's
/// current KEK in place (same version, dirty flag kept), so the local vault
/// stays readable and nothing is lost.
library;

import 'dart:typed_data';

import 'crypto_service.dart';

/// The crypto operations the rekey needs (real libsodium in the app, a fake
/// in `flutter test` where libsodium is not available).
abstract class DekRekeyCrypto {
  /// The raw DEK, or null when [kek] does not open the wrap.
  Uint8List? tryUnwrap(Uint8List payload, Uint8List kek, String dekId, int version);

  Uint8List wrap(Uint8List dek, String dekId, Uint8List kek, int version);

  String sha256Hex(Uint8List data);

  /// Signature of [row] with its new [payloadHashHex].
  Uint8List sign(Map<String, dynamic> row, String payloadHashHex);

  void zeroize(Uint8List bytes);
}

class CryptoServiceRekey implements DekRekeyCrypto {
  CryptoServiceRekey(this._crypto, this._kekDekId, this._signingSecretKey);

  final CryptoService _crypto;
  final String _kekDekId;
  final Uint8List? _signingSecretKey;

  @override
  Uint8List? tryUnwrap(Uint8List payload, Uint8List kek, String dekId, int version) {
    try {
      return _crypto.unwrapDEK(payload, kek, dekId, version: version);
    } catch (_) {
      return null;
    }
  }

  @override
  Uint8List wrap(Uint8List dek, String dekId, Uint8List kek, int version) =>
      _crypto.wrapDEK(dek, dekId, kek, _kekDekId, version: version);

  @override
  String sha256Hex(Uint8List data) => _crypto.sha256Hex(data);

  @override
  Uint8List sign(Map<String, dynamic> row, String payloadHashHex) {
    final key = _signingSecretKey;
    if (key == null) throw StateError('Signing key required to re-sign a DEK');
    return _crypto.signSyncObject(
      id: row['id'] as String,
      objectType: 'dek',
      parentRef: row['parent_ref'] as String?,
      targetUserId: row['target_user_id'] as String?,
      isDeleted: row['is_deleted'] as int? ?? 0,
      version: row['version'] as int? ?? 1,
      payloadHashHex: payloadHashHex,
      signingSecretKey: key,
    );
  }

  @override
  void zeroize(Uint8List bytes) => _crypto.zeroize(bytes);
}

/// Own DEKs that neither the new KEK nor the previous one can open.
class LocalDekRekeyException implements Exception {
  LocalDekRekeyException(this.unreadableDekIds);

  final List<String> unreadableDekIds;

  @override
  String toString() =>
      'LocalDekRekeyException: ${unreadableDekIds.length} local key(s) are '
      'wrapped under the previous password';
}

bool _isOwnDek(Map<String, dynamic> row, String? userId) {
  final ownerId = row['owner_id'] as String?;
  return ownerId == null || ownerId == 'local' || ownerId == userId;
}

/// Rows whose DEK wrap moves from [oldKek] to [newKek].
///
/// A wrap [newKek] already opens is left alone (resumed or server-rotated);
/// other users' DEKs stay opaque. With [oldKek] null this only checks: it
/// throws [LocalDekRekeyException] when an own DEK needs the previous KEK.
/// Versions, commit_seq and the dirty flag are kept; a dirty row is re-signed
/// because its signature covers the payload hash it will be pushed with.
List<Map<String, dynamic>> planLocalDekRekey({
  required List<Map<String, dynamic>> rows,
  required String? userId,
  required Uint8List newKek,
  required Uint8List? oldKek,
  required DekRekeyCrypto crypto,
  required bool Function(Uint8List payload) isEnvelope,
}) {
  final changed = <Map<String, dynamic>>[];
  final unreadable = <String>[];
  for (final row in rows) {
    if (row['object_type'] != 'dek' || row['is_deleted'] == 1) continue;
    final payload = Uint8List.fromList(row['payload'] as List<int>);
    if (!isEnvelope(payload)) continue;
    final dekId = row['id'] as String;
    final version = row['version'] as int? ?? 1;

    final current = crypto.tryUnwrap(payload, newKek, dekId, version);
    if (current != null) {
      crypto.zeroize(current);
      continue;
    }
    final dek = oldKek == null
        ? null
        : crypto.tryUnwrap(payload, oldKek, dekId, version);
    if (dek == null) {
      if (_isOwnDek(row, userId)) unreadable.add(dekId);
      continue;
    }
    try {
      final wrapped = crypto.wrap(dek, dekId, newKek, version);
      final payloadHash = crypto.sha256Hex(wrapped);
      changed.add({
        ...row,
        'payload': wrapped,
        'payload_hash': payloadHash,
        if (row['queued'] == 1)
          'client_signature': crypto.sign(row, payloadHash),
      });
    } finally {
      crypto.zeroize(dek);
    }
  }
  if (unreadable.isNotEmpty) throw LocalDekRekeyException(unreadable);
  return changed;
}

/// A password change made on this phone (review 1141a20 H2): every own DEK
/// [oldKek] opens, wrapped under [newKek] at the next version and signed, as
/// the push objects of the key epoch advance (the server requires all of
/// them). Throws [LocalDekRekeyException] when an own DEK does not open.
List<Map<String, dynamic>> planKeyEpochDekRewrap({
  required List<Map<String, dynamic>> rows,
  required String? userId,
  required Uint8List oldKek,
  required Uint8List newKek,
  required DekRekeyCrypto crypto,
  required bool Function(Uint8List payload) isEnvelope,
}) {
  final objects = <Map<String, dynamic>>[];
  final unreadable = <String>[];
  for (final row in rows) {
    if (row['object_type'] != 'dek' || row['is_deleted'] == 1) continue;
    if (!_isOwnDek(row, userId)) continue;
    final dekId = row['id'] as String;
    final payload = Uint8List.fromList(row['payload'] as List<int>);
    final version = row['version'] as int? ?? 1;
    final dek = isEnvelope(payload)
        ? crypto.tryUnwrap(payload, oldKek, dekId, version)
        : null;
    if (dek == null) {
      unreadable.add(dekId);
      continue;
    }
    try {
      final next = {...row, 'version': version + 1, 'is_deleted': 0};
      final wrapped = crypto.wrap(dek, dekId, newKek, version + 1);
      final payloadHash = crypto.sha256Hex(wrapped);
      objects.add({
        'id': dekId,
        'object_type': 'dek',
        'payload': wrapped,
        'parent_ref': row['parent_ref'],
        'target_user_id': row['target_user_id'],
        'version': version + 1,
        'is_deleted': 0,
        'payload_hash': payloadHash,
        'signature': crypto.sign(next, payloadHash),
        'write_policy': row['write_policy'] as String? ?? 'owner_only',
      });
    } finally {
      crypto.zeroize(dek);
    }
  }
  if (unreadable.isNotEmpty) throw LocalDekRekeyException(unreadable);
  return objects;
}

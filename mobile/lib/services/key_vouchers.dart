// Key vouchers (review e443cbc R15, goal #443, INV-3): which object versions a
// retired identity key still vouches for.
//
// A retired key's signature counts only for an (id, version, digest) named by
// a list signed by the account's CURRENT signing key. R17-N1: the digest is
// that of the whole signed message, its signer and key.
//
// The rules and every byte are the Rust core's (core/src/vouchers.rs, the
// copy the desktop, the server and the web use; docs/CORE_UNIFICATION.md U5),
// reached over FFI (sync_core.dart). The phone only verifies the Ed25519
// signatures the core names.

import 'dart:typed_data';

import 'crypto_service.dart';
import 'sync_core.dart';

const _signedFields = [
  'id',
  'object_type',
  'parent_ref',
  'target_user_id',
  'is_deleted',
  'version',
  'payload_hash',
];

String keyVoucherKey(String id, int version, String digest) =>
    '$id:$version:${digest.toLowerCase()}';

(String, int, String) _entry(Object? raw) {
  final e = raw as List;
  return (e[0] as String, e[1] as int, e[2] as String);
}

/// Run a voucher operation; a refused input is a [FormatException].
Object? _core(String op, Map<String, Object?> args) {
  try {
    return syncCore(op, args);
  } on StateError catch (e) {
    throw FormatException(e.message);
  }
}

/// R17-N1: the entry a voucher names for an object as [signingPk] of
/// [signerId] signed it; null when malformed.
(String, int, String)? keyVoucherObjectEntry({
  required String id,
  required String objectType,
  required String? parentRef,
  required String? targetUserId,
  required int isDeleted,
  required int version,
  required String payloadHash,
  required String signerId,
  required Uint8List signingPk,
}) {
  final values = [
    id,
    objectType,
    parentRef,
    targetUserId,
    isDeleted,
    version,
    payloadHash,
  ];
  try {
    final out = _core('key_voucher_object_entry', {
      'object': {
        for (var i = 0; i < _signedFields.length; i++)
          _signedFields[i]: values[i],
      },
      'signer_id': signerId,
      'signing_pk': bytesToHex(signingPk),
    });
    return out == null ? null : _entry(out);
  } on FormatException {
    return null;
  }
}

/// Sorted, de-duplicated entries; FormatException on any malformed one.
List<(String, int, String)> canonicalKeyVoucherEntries(Object? entries) {
  if (entries is! List) {
    throw const FormatException('voucher entries must be a list');
  }
  final out = _core('key_voucher_canonical', {'entries': entries}) as List;
  return out.map(_entry).toList();
}

/// Bytes the account's current key signs for a voucher list.
Uint8List keyVoucherMessage(
  String userId,
  Uint8List signingPk,
  Object? entries,
) {
  if (signingPk.length != 32) {
    throw const FormatException('a voucher signing key is 32 bytes');
  }
  if (entries is! List) {
    throw const FormatException('voucher entries must be a list');
  }
  final out =
      _core('key_voucher_message', {
            'user_id': userId,
            'signing_pk': bytesToHex(signingPk),
            'entries': entries,
          })
          as Map;
  return hexToBytes(out['message'] as String);
}

/// Every keyVoucherKey a list signed by [currentSigningPk] names; a list by
/// another key, for another account, or not verifying vouches for nothing.
Set<String> vouchedEntries(
  String userId,
  Uint8List currentSigningPk,
  Object? lists,
) {
  try {
    final args = <String, Object?>{
      'user_id': userId,
      'current_signing_pk': bytesToHex(currentSigningPk),
      'lists': lists is List ? lists : null,
    };
    final checks = _core('key_voucher_lists', args) as List;
    final verified = [
      for (final check in checks) _verifies(check, currentSigningPk),
    ];
    final out =
        _core('key_voucher_vouched', {...args, 'verified': verified}) as List;
    return {
      for (final raw in out)
        if (_entry(raw) case (final id, final version, final digest))
          keyVoucherKey(id, version, digest),
    };
  } on FormatException {
    return {};
  }
}

bool _verifies(Object? check, Uint8List publicKey) {
  if (check is! Map) return false;
  try {
    return CryptoService().verifyDetached(
      signature: hexToBytes(check['signature'] as String),
      message: hexToBytes(check['message'] as String),
      publicKey: publicKey,
    );
  } catch (_) {
    return false;
  }
}

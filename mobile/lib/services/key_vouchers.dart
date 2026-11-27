// Key vouchers (review e443cbc R15, goal #443, INV-3): which object versions a
// retired identity key still vouches for. Mirrors src/sezam/key_vouchers.py
// and must pass tests/vectors/key_vouchers.json.
//
// A retired key's signature counts only for an (id, version, digest) named by
// a list signed by the account's CURRENT signing key, not for whatever the
// server dates before the rotation (retired_seq, commit_seq). R17-N1: the
// digest is that of the whole signed message, its signer and key
// (keyVoucherObjectEntry), not the payload hash alone.

import 'dart:convert';
import 'dart:typed_data';

import 'crypto_service.dart';

final _id = RegExp(r'^[0-9A-Za-z]{26}$');
final _hash = RegExp(r'^[0-9a-f]{64}$');

// R17-L (review c02cc47): one parse in all three clients
// (src/sezam/key_vouchers.py): at most this many entries as posted, a version
// an integral number up to JavaScript's Number.MAX_SAFE_INTEGER (3.0 is 3),
// keys and signatures plain hex.
const keyVoucherMaxEntries = 200000;
const keyVoucherMaxVersion = 9007199254740991; // 2^53 - 1
final _pkHex = RegExp(r'^[0-9a-fA-F]{64}$');
final _sigHex = RegExp(r'^[0-9a-fA-F]{128}$');

String keyVoucherKey(String id, int version, String digest) =>
    '$id:$version:${digest.toLowerCase()}';

/// R17-N1 (key_vouchers.object_entry): the entry a voucher names for an
/// object as [signingPk] of [signerId] signed it; null when malformed.
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
  try {
    if (signingPk.length != 32) return null;
    final crypto = CryptoService();
    final message = crypto.buildSyncSignatureData(
      id: id,
      objectType: objectType,
      parentRef: parentRef == null || parentRef.isEmpty ? null : parentRef,
      targetUserId: targetUserId == null || targetUserId.isEmpty
          ? null
          : targetUserId,
      isDeleted: isDeleted,
      version: version,
      payloadHashHex: payloadHash.toLowerCase(),
    );
    final input = BytesBuilder()
      ..add(utf8.encode('sezam-key-voucher-entry-v2\x00'))
      ..add(CryptoService.idBytes26(signerId))
      ..add(signingPk)
      ..add(message);
    return (id, version, crypto.sha256Hex(input.toBytes()));
  } catch (_) {
    return null;
  }
}

/// Sorted, de-duplicated entries; FormatException on any malformed one.
List<(String, int, String)> canonicalKeyVoucherEntries(Object? entries) {
  if (entries is! List) {
    throw const FormatException('voucher entries must be a list');
  }
  if (entries.length > keyVoucherMaxEntries) {
    throw const FormatException('too many voucher entries');
  }
  final byKey = <String, (String, int, String)>{};
  for (final entry in entries) {
    if (entry is! List || entry.length != 3) {
      throw const FormatException('a voucher entry is [id, version, digest]');
    }
    final id = entry[0];
    final raw = entry[1];
    final payloadHash = entry[2];
    if (id is! String || !_id.hasMatch(id)) {
      throw const FormatException(
        'a voucher entry needs a 26-character object id',
      );
    }
    final version = raw is double && raw.isFinite && raw == raw.truncate()
        ? raw.toInt()
        : raw;
    if (version is! int || version < 0 || version > keyVoucherMaxVersion) {
      throw const FormatException(
        'a voucher entry needs an unsigned version of at most 2^53 - 1',
      );
    }
    if (payloadHash is! String || !_hash.hasMatch(payloadHash)) {
      throw const FormatException(
        'a voucher entry needs a lowercase hex SHA-256 digest',
      );
    }
    byKey[keyVoucherKey(id, version, payloadHash)] = (id, version, payloadHash);
  }
  return byKey.values.toList()..sort((a, b) {
    final byId = a.$1.compareTo(b.$1);
    if (byId != 0) return byId;
    final byVersion = a.$2.compareTo(b.$2);
    return byVersion != 0 ? byVersion : a.$3.compareTo(b.$3);
  });
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
  final items = canonicalKeyVoucherEntries(entries);
  final out = BytesBuilder()..add(utf8.encode('sezam-key-vouchers-v2\x00'));
  final user = CryptoService.idBytes26(userId);
  out
    ..add(user)
    ..add(signingPk);
  final count = ByteData(4)..setUint32(0, items.length);
  out.add(count.buffer.asUint8List());
  for (final (id, version, payloadHash) in items) {
    final seq = ByteData(8)..setUint64(0, version);
    out
      ..add(ascii.encode(id))
      ..add(seq.buffer.asUint8List())
      ..add(hexToBytes(payloadHash));
  }
  return out.toBytes();
}

/// Every keyVoucherKey a list signed by [currentSigningPk] names; a list by
/// another key, for another account, or not verifying vouches for nothing.
Set<String> vouchedEntries(
  String userId,
  Uint8List currentSigningPk,
  Object? lists,
) {
  final currentHex = bytesToHex(currentSigningPk);
  final vouched = <String>{};
  for (final list in lists is List ? lists : const []) {
    try {
      if (list is! Map) continue;
      final pk = list['signing_pk'];
      final signatureHex = list['signature'];
      if (pk is! String ||
          !_pkHex.hasMatch(pk) ||
          pk.toLowerCase() != currentHex ||
          signatureHex is! String ||
          !_sigHex.hasMatch(signatureHex)) {
        continue;
      }
      final entries = list['entries'] ?? const [];
      final signature = hexToBytes(signatureHex);
      final message = keyVoucherMessage(userId, currentSigningPk, entries);
      if (signature.length != 64 ||
          !CryptoService().verifyDetached(
            signature: signature,
            message: message,
            publicKey: currentSigningPk,
          )) {
        continue;
      }
      for (final (id, version, payloadHash) in canonicalKeyVoucherEntries(
        entries,
      )) {
        vouched.add(keyVoucherKey(id, version, payloadHash));
      }
    } catch (_) {
      continue;
    }
  }
  return vouched;
}

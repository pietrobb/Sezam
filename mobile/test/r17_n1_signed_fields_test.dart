// Review c02cc47 R17-N1 (S4 style, as tests/test_r17_n1_signed_fields_proofs.py
// on the desktop and the web): every proof of a copy the phone makes - the
// signed message, the voucher entry and the held-copy comparison - changes
// with every field a sync object's signature covers
// (tests/vectors/signed_fields.json); the voucher entry also with the signer
// and the key.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/key_vouchers.dart';

Uint8List _hex(String hex) => Uint8List.fromList([
  for (var i = 0; i < hex.length; i += 2)
    int.parse(hex.substring(i, i + 2), radix: 16),
]);

void main() {
  final v =
      jsonDecode(File('../tests/vectors/signed_fields.json').readAsStringSync())
          as Map<String, dynamic>;
  final base = v['object'] as Map<String, dynamic>;
  final other = v['other'] as Map<String, dynamic>;
  final fields = (v['fields'] as List).cast<String>();
  final variants = <String, Map<String, dynamic>>{'base': base};
  for (final field in fields) {
    variants[field] = {...base, field: other[field]};
    if ((v['none'] as List).contains(field)) {
      variants['$field=none'] = {...base, field: null};
    }
  }
  final crypto = CryptoService();
  final key = _hex(v['signing_pk'] as String);

  String message(Map<String, dynamic> o) => bytesToHex(
    crypto.buildSyncSignatureData(
      id: o['id'] as String,
      objectType: o['object_type'] as String,
      parentRef: o['parent_ref'] as String?,
      targetUserId: o['target_user_id'] as String?,
      isDeleted: o['is_deleted'] as int,
      version: o['version'] as int,
      payloadHashHex: o['payload_hash'] as String,
    ),
  );

  String entry(Map<String, dynamic> o, String signer, Uint8List pk) =>
      keyVoucherObjectEntry(
        id: o['id'] as String,
        objectType: o['object_type'] as String,
        parentRef: o['parent_ref'] as String?,
        targetUserId: o['target_user_id'] as String?,
        isDeleted: o['is_deleted'] as int,
        version: o['version'] as int,
        payloadHash: o['payload_hash'] as String,
        signerId: signer,
        signingPk: pk,
      ).toString();

  // against_held compares (id, version, heldCopyKey) of the copies.
  String held(Map<String, dynamic> o) => [
    o['id'],
    o['version'],
    heldCopyKey(
      o['object_type'] as String,
      o['parent_ref'] as String?,
      o['target_user_id'] as String?,
      o['is_deleted'] == 1,
      o['payload_hash'] as String?,
    ),
  ].join('/');

  void allDistinct(Map<String, String> proofs) {
    final seen = <String, String>{};
    proofs.forEach((label, proof) {
      expect(
        seen.containsKey(proof),
        isFalse,
        reason: '$label gives the same proof as ${seen[proof]}',
      );
      seen[proof] = label;
    });
  }

  test('the register is the desktop one', () {
    expect(fields, [
      'id',
      'object_type',
      'parent_ref',
      'target_user_id',
      'is_deleted',
      'version',
      'payload_hash',
    ]);
  });

  test('the signed message covers every signed field', () {
    allDistinct({for (final e in variants.entries) e.key: message(e.value)});
  });

  test('the voucher entry covers every signed field, the signer and key', () {
    final signer = v['signer_id'] as String;
    allDistinct({
      for (final e in variants.entries) e.key: entry(e.value, signer, key),
      'other signer': entry(base, v['other_signer_id'] as String, key),
      'other key': entry(base, signer, _hex(v['other_signing_pk'] as String)),
    });
    expect(entry(base, signer, key), isNot('null'));
  });

  test('the held-copy comparison covers every signed field', () {
    allDistinct({for (final e in variants.entries) e.key: held(e.value)});
  });
}

// tests/vectors/key_ring.json (capability review 716): which archived keys
// of GET /api/users/{id}/keys the phone trusts is the core's rule
// (core/src/keyring.rs), the answers the desktop and the web give.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/key_vouchers.dart';

import 'support/real_server_phone.dart';

void main() {
  final vectors =
      jsonDecode(File('../tests/vectors/key_ring.json').readAsStringSync())
          as Map<String, dynamic>;
  final current = vectors['current'] as Map<String, dynamic>;
  final cases = (vectors['cases'] as List).cast<Map<String, dynamic>>();

  late Directory appDir;

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_key_ring_');
    await setUpPhone(appDir.path);
    initPhoneCrypto();
  });

  tearDownAll(() => appDir.delete(recursive: true));

  test('the phone trusts what the vectors name', () {
    for (final c in cases) {
      Object answer;
      try {
        answer = [
          for (final (signing, encryption) in keyRing(
            vectors['user_id'] as String,
            hexToBytes(current['signing_pk'] as String),
            hexToBytes(current['encryption_pk'] as String),
            c['archived_keys'],
          ))
            {
              'signing_pk': bytesToHex(signing),
              'encryption_pk': bytesToHex(encryption),
            },
        ];
      } on FormatException {
        answer = 'error';
      }
      expect(answer, c['trusted'], reason: c['name'] as String);
    }
    expect(cases.length, greaterThanOrEqualTo(30));
  });
}

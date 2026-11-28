// tests/vectors/kdf.json on the phone (docs/CORE_UNIFICATION.md U6): the
// Argon2id parameter bounds are the core's (core/src/kdf.rs); the derivation
// stays the phone's.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/auth_service.dart';

void main() {
  final vectors =
      jsonDecode(File('../tests/vectors/kdf.json').readAsStringSync())
          as Map<String, dynamic>;
  List<Map<String, dynamic>> cases(String name) =>
      (vectors[name] as List).cast<Map<String, dynamic>>();

  test('account params from the server are refused as the vectors say', () {
    var checked = 0;
    for (final c in cases('account')) {
      // The phone has no local params and derives only within the cap.
      if (c['local'] != null || c['stored'] == true) continue;
      bool refused;
      try {
        accountKdfParams({'argon2_params': c['params']});
        refused = false;
      } on FormatException {
        refused = true;
      }
      expect(refused, c['refused'], reason: jsonEncode(c['params']));
      checked++;
    }
    expect(checked, greaterThan(300));
  });

  test('.sezam-key params are refused as the vectors say', () {
    var checked = 0;
    for (final c in cases('sezam_key')) {
      // The phone writes hash_len 64 and int fields; a pending migration
      // (stored) goes through the same core op with stored: true.
      if (c['stored'] == true ||
          c['hash_len'] != 64 ||
          c['salt_len'] is! int ||
          c['time_cost'] is! int) {
        continue;
      }
      String? argon2Refusal;
      try {
        encodeSezamKeyBackup(
          SezamKeyBackup(
            argon2Salt: Uint8List(c['salt_len'] as int),
            timeCost: c['time_cost'] as int,
            memoryCost: c['memory_cost'] as int,
            parallelism: c['parallelism'] as int,
            signingPublicKey: Uint8List(32),
            encryptionPublicKey: Uint8List(32),
            kekDekId: '01HZZZZZZZZZZZZZZZZZZZZZZZ',
            userObjectId: '01HZZZZZZZZZZZZZZZZZZZZZZY',
            encryptedEnvelope: Uint8List(0),
          ),
        );
      } on FormatException catch (e) {
        // Past the Argon2 bounds the bogus envelope is refused too.
        if (e.message.contains('Argon2')) argon2Refusal = e.message;
      }
      expect(argon2Refusal != null, c['refused'], reason: jsonEncode(c));
      checked++;
    }
    expect(checked, greaterThan(1000));
  });
}

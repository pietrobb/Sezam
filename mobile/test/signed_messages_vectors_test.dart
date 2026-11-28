// tests/vectors/signed_messages.json on the phone (docs/CORE_UNIFICATION.md
// U6c): the key rotation and rejoin messages are the core's. libsodium is not
// available under `flutter test`, so a login is checked only for refusing a
// challenge of another layout before anything is signed.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';

void main() {
  final vectors =
      jsonDecode(
            File('../tests/vectors/signed_messages.json').readAsStringSync(),
          )
          as Map<String, dynamic>;
  List<Map<String, dynamic>> cases(String name) =>
      (vectors[name] as List).cast<Map<String, dynamic>>();

  test('key rotation messages match the vectors', () {
    for (final v in cases('key_rotation')) {
      final message = SyncService.keyRotationMessage(
        v['user_id'] as String,
        hexToBytes(v['old_signing_pk'] as String),
        hexToBytes(v['old_encryption_pk'] as String),
        hexToBytes(v['new_signing_pk'] as String),
        hexToBytes(v['new_encryption_pk'] as String),
      );
      expect(bytesToHex(message), v['message'], reason: v['user_id']);
    }
  });

  test('a key rotation the message cannot hold is refused', () {
    final good = cases('key_rotation').first;
    for (final v in cases('key_rotation_refused')) {
      final signing = hexToBytes(good['old_signing_pk'] as String);
      expect(
        () => SyncService.keyRotationMessage(
          (v['user_id'] ?? good['user_id']) as String,
          v['short_key'] == true
              ? Uint8List.sublistView(signing, 0, 31)
              : signing,
          hexToBytes(good['old_encryption_pk'] as String),
          hexToBytes(good['new_signing_pk'] as String),
          hexToBytes(good['new_encryption_pk'] as String),
        ),
        throwsStateError,
        reason: v['why'] as String,
      );
    }
  });

  test('rejoin messages match the vectors', () {
    final rejoins = cases('reseed').where((v) => v['rejoin'] == true).toList();
    expect(rejoins, isNotEmpty);
    for (final v in rejoins) {
      final message = rejoinMessage(
        hexToBytes(v['challenge'] as String),
        v['user_id'] as String,
        v['username'] as String,
        hexToBytes(v['signing_pk'] as String),
        hexToBytes(v['encryption_pk'] as String),
        v['key_epoch'] as int,
      );
      expect(bytesToHex(message), v['message'], reason: v['username']);
    }
  });

  test('a challenge of another layout is never signed', () {
    final crypto = CryptoService();
    for (final v in cases('auth_challenge_refused')) {
      final hex = v['challenge'] as String;
      if (hex.length.isOdd || !RegExp(r'^[0-9a-f]*$').hasMatch(hex)) continue;
      expect(
        () => crypto.signAuthChallenge(hexToBytes(hex), Uint8List(64)),
        throwsArgumentError,
        reason: hex,
      );
    }
  });
}

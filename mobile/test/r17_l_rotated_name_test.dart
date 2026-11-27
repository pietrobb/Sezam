// Review c02cc47 R17-L: the 409 'Identity key rotated' carries the account's
// current name (review 526419e N8), unsigned. The phone stored it as its
// login name at once, so a server could move the phone's login, and the
// takeover with the password, onto another account's name.
// The takeover tries it as a candidate (AuthService.adoptPasswordChangedElsewhere).

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';

import 'support/real_server_phone.dart';

void main() {
  late Directory appDir;

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_rotated_name_');
    await setUpPhone(appDir.path);
  });

  tearDownAll(() => appDir.delete(recursive: true));

  test('the name a 409 carries is no login name', () async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('sezam_username', 'carol');
    final client = MockClient((request) async {
      if (request.url.path == '/api/auth/challenge') {
        return http.Response(
          jsonEncode({'challenge': List.filled(80, '0').join()}),
          200,
        );
      }
      return http.Response(
        jsonEncode({
          'detail': {'error': 'Identity key rotated', 'username': 'mallory'},
          'code': 'identity_key_rotated',
        }),
        409,
      );
    });
    late SyncService sync;
    late CryptoService crypto;
    http.runWithClient(() {
      sync = SyncService()..configure('https://sezam.test');
      crypto = CryptoService();
      initPhoneCrypto();
    }, () => client);
    final keys = crypto.generateSigningKeypair();
    await expectLater(
      sync.authenticate(username: 'carol', signingSecretKey: keys.sk),
      throwsA(isA<KeyEpochStaleException>()),
    );
    expect(prefs.getString('sezam_username'), 'carol');
  });
}

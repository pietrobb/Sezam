// Review e443cbc #428 (INV-3): the account name in the verify reply is
// unsigned. The phone stores a new one (the server's rename, review e4cd15a)
// only once its key logs in under it; a lie about the name must not lock
// every later login of the phone out.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'support/real_server_phone.dart';

void main() {
  late Directory appDir;
  late SyncService sync;
  late CryptoService crypto;
  final verifiedAs = <String>[];
  var renameIsReal = true;

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_inv3_name_');
    await setUpPhone(appDir.path);
    final challenge = List.generate(
      40,
      (i) => i,
    ).map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    final client = MockClient((request) async {
      if (request.url.path == '/api/auth/challenge') {
        return http.Response(jsonEncode({'challenge': challenge}), 200);
      }
      final name =
          (jsonDecode(request.body) as Map<String, dynamic>)['username']
              as String;
      verifiedAs.add(name);
      if (name == 'alice') {
        return http.Response(
          jsonEncode({'token': 'jwt', 'username': 'alice-2'}),
          200,
        );
      }
      return renameIsReal
          ? http.Response(
              jsonEncode({'token': 'jwt-2', 'username': 'alice-2'}),
              200,
            )
          : http.Response(jsonEncode({'detail': 'Authentication failed'}), 401);
    });
    http.runWithClient(() {
      sync = SyncService()..configure('https://sezam.test');
      crypto = CryptoService();
      initPhoneCrypto();
    }, () => client);
  });

  tearDownAll(() => appDir.delete(recursive: true));

  setUp(() async {
    verifiedAs.clear();
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(SyncService.usernamePrefKey, 'alice');
  });

  test('a renamed account is stored once the key logs in under it', () async {
    renameIsReal = true;
    final keys = crypto.generateSigningKeypair();
    await sync.authenticate(username: 'alice', signingSecretKey: keys.sk);
    final prefs = await SharedPreferences.getInstance();
    expect(verifiedAs, ['alice', 'alice-2']);
    expect(prefs.getString(SyncService.usernamePrefKey), 'alice-2');
    expect(sync.accountNameFor('alice'), 'alice-2');
  });

  test('a lie about the name keeps the stored one', () async {
    renameIsReal = false;
    final keys = crypto.generateSigningKeypair();
    await sync.authenticate(username: 'alice', signingSecretKey: keys.sk);
    final prefs = await SharedPreferences.getInstance();
    expect(verifiedAs, ['alice', 'alice-2']);
    expect(prefs.getString(SyncService.usernamePrefKey), 'alice');
    expect(sync.accountNameFor('alice'), 'alice');
  });
}

// Review 8595ec1 (R10-F, low): a biometric unlock takes the account the
// server signed in only when it is the one this phone's keys belong to.
import 'dart:convert';
import 'dart:io';

import 'package:biometric_storage/biometric_storage.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

class _ReleasedBiometricKek extends MethodChannelBiometricStorage {
  _ReleasedBiometricKek(this.kek);
  final String kek;
  @override
  Future<String?> read(String name, PromptInfo promptInfo) async => kek;
}

/// Answers the sign-in with another account's id.
class _OtherAccountNet extends Net {
  bool lie = false;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final response = await super.send(request);
    if (!lie || request.url.path != '/api/auth/verify') return response;
    final body = jsonDecode(await response.stream.bytesToString()) as Map<String, dynamic>;
    body['user_id'] = '01JZZZZZZZZZZZZZZZZZZZZZZZ';
    return http.StreamedResponse(Stream.value(utf8.encode(jsonEncode(body))), response.statusCode,
        headers: response.headers);
  }
}

void main() {
  final server = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];
  test(
    'biometric unlock refuses another account',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      await setUpPhone('$dir/app');
      final net = _OtherAccountNet();
      await http.runWithClient(() async {
        final auth = AuthService();
        final vault = VaultService();
        initPhoneCrypto();
        await vault.init();
        final unlocked = await auth.unlockWithPassword(
          serverUrl: server!,
          username: 'bob',
          password: cfg['password'] as String,
        );
        expect(unlocked.success, isTrue, reason: unlocked.error);
        await net.settle();
        final kek = bytesToHex(vault.currentKek!);
        await auth.lock();
        await net.settle();
        await DatabaseService().close();

        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(
          const MethodChannel('biometric_storage'), (call) async => call.method == 'read' ? kek : true,
        );
        final original = BiometricStorage();
        BiometricStorage.instance = _ReleasedBiometricKek(kek);
        addTearDown(() => BiometricStorage.instance = original);

        net.lie = true;
        final refused = await auth.unlockWithBiometrics();
        expect(refused.success, isFalse);
        expect(refused.error, contains('identity mismatch'));
        expect(vault.isUnlocked, isFalse);

        net.lie = false;
        final opened = await auth.unlockWithBiometrics();
        expect(opened.success, isTrue, reason: opened.error);
        expect(vault.userId, cfg['user_id']);
        await auth.lock();
        await net.settle();
        await DatabaseService().close();
      }, () => net);
      net.close();
    },
    skip: server == null || dir == null,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

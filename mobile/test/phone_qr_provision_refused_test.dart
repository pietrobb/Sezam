// Review a159e97 (mobile, medium): a refused QR provisioning left the phone
// signed in to the scanned account. Here the phone's own vault is locked, so
// provisioning refuses after the sign-in; the session must not stay.
// tests/test_review8_phone_qr_provision_refused.py starts the server, lets
// desktop A make the account, mints the provisioning token and runs this file
// with SEZAM_X3_* set; without them the test is skipped.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  final serverUrl = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];

  test(
    'a refused QR provisioning does not leave the phone signed in',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      final username = cfg['username'] as String;
      final password = cfg['password'] as String;
      await setUpPhone('$dir/app');
      final net = Net();
      await http.runWithClient(() async {
        final auth = AuthService();
        final sync = SyncService();
        final vault = VaultService();
        initPhoneCrypto();
        await vault.init();

        final r = await auth.createNewVault(password: 'phone-only-Pw-1234');
        expect(r.success, isTrue, reason: r.error);
        await auth.lock();
        expect(vault.isUnlocked, isFalse);

        await handshake(dir!, 'token'); // A mints the provisioning token
        final token = File('$dir/token.txt').readAsStringSync().trim();
        final p = await auth.provisionFromQR(
          provisionToken: token,
          username: username,
          password: password,
          serverUrl: serverUrl!,
        );
        await net.settle();
        expect(p.success, isFalse);
        expect(sync.isAuthenticated, isFalse, reason: 'still signed in');
        expect(vault.isUnlocked, isFalse);
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_review8_phone_qr_provision_refused.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

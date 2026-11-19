// Review d615826 (mobile): taking over a password change moved the DEKs to
// the new KEK in one database transaction and only then wrote the new
// keypair and salt to the Keychain. Killed in between, the phone held keys no
// stored salt derives: neither password opened the records again. The
// keypair state now lands in the transaction that moves the DEKs, and the
// next unlock finishes it.
// tests/test_review6_phone_adopt_killed.py starts the server, plays desktop A
// and runs this file with SEZAM_X3_* set; without them the test is skipped.

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
    'a take-over killed before the Keychain write is finished by the next unlock',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      final oldPassword = cfg['old_password'] as String;
      final newPassword = cfg['new_password'] as String;
      await setUpPhone('$dir/app');
      final net = Net();
      await http.runWithClient(() async {
        final auth = AuthService();
        final sync = SyncService();
        final vault = VaultService();
        initPhoneCrypto();
        await vault.init();

        final c = await auth.connectToServer(
          serverUrl: serverUrl!,
          password: oldPassword,
          username: cfg['username'] as String,
        );
        expect(c.outcome, ConnectOutcome.connected, reason: c.message);
        await net.settle();
        expect(passwords(vault), {'db01': 's3cret'});
        await auth.lock();
        await net.settle();

        await handshake(dir!, 'changed'); // A changes the password

        var r = await auth.unlockOffline(password: oldPassword);
        expect(r.success, isTrue, reason: r.error);
        await net.settle();
        await expectLater(sync.sync(), throwsA(isA<KeyEpochStaleException>()));

        secureWriteKillsApp = 'sezam_pending_keypair_migration';
        r = await auth.adoptPasswordChangedElsewhere(
          currentPassword: newPassword,
        );
        expect(r.success, isFalse);
        expect(secureWriteKillsApp, isNull, reason: 'the kill never happened');

        // The app starts again: the password the server has opens it all.
        sync.forgetRunningSyncsForTesting();
        await auth.lock();
        await vault.init();
        r = await auth.unlockOffline(password: newPassword);
        expect(r.success, isTrue, reason: r.error);
        await net.settle();
        expect(passwords(vault), {'db01': 's3cret'});
        // Offline, the phone cannot know the salt is still the server's: the
        // app's sync asks for the current password once more, as before.
        await expectLater(sync.sync(), throwsA(isA<KeyEpochStaleException>()));
        r = await auth.adoptPasswordChangedElsewhere(
          currentPassword: newPassword,
        );
        expect(r.success, isTrue, reason: r.error);
        await net.settle();
        await sync.sync();
        await vault.reloadData();
        expect(passwords(vault), {'db01': 's3cret', 'desk': 'after'});
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_review6_phone_adopt_killed.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

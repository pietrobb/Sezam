// Review 7c10379 (mobile): the app's full resync after a restore to a server
// with an older password. Its pull asks for the password the server has; the
// app said "Full resync failed" and the next sync asked for the full resync
// again, for good. It now asks for the password, takes it over and finishes.
// tests/test_review7_phone_full_resync_asks_password.py starts the server,
// plays desktop A, restores the server between the steps and runs this file
// with SEZAM_X3_* set; without them the test is skipped.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/sync_recovery.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  final serverUrl = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];

  test(
    "the app's full resync asks for the restored server's password",
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
        await auth.lock();
        await net.settle();

        await handshake(dir!, 'changed'); // A: backup, then password change

        var r = await auth.unlockOffline(password: oldPassword);
        expect(r.success, isTrue, reason: r.error);
        await net.settle();
        await expectLater(sync.sync(), throwsA(isA<KeyEpochStaleException>()));
        r = await auth.adoptPasswordChangedElsewhere(
          currentPassword: newPassword,
        );
        expect(r.success, isTrue, reason: r.error);
        await net.settle();
        await sync.sync();
        expect(passwords(vault), {'db01': 's3cret'});

        await handshake(dir, 'restored');

        // What the vault screen does on the sync button.
        await expectLater(
          sync.sync(),
          throwsA(isA<FullResyncRequiredException>()),
        );
        var asked = 0;
        final refused = <String>[];
        final result = await fullResyncTakingPasswordOver(
          fullResync: () => sync.fullResync(confirmed: true),
          askPassword: () async {
            asked++;
            return oldPassword;
          },
          takeOver: (password) =>
              auth.adoptPasswordChangedElsewhere(currentPassword: password),
          onRefused: refused.add,
        );
        expect(refused, isEmpty);
        expect(asked, 1);
        expect(result, isNotNull);
        await vault.reloadData();

        final cycle = await sync.sync();
        expect(cycle.push.errors, isEmpty);
        expect(await sync.getDirtyObjectCount(), 0);
        expect(passwords(vault), {'db01': 's3cret'});
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_review7_phone_full_resync_asks_password.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

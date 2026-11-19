// Review d615826 (mobile): the server was restored from a backup taken before
// a password change the phone had taken over, so its key_epoch is lower than
// the phone's. Every pull refused it ("rolled-back key_epoch"), for good. The
// phone now asks for the password the server has, takes the older epoch over
// and sends what it edited offline.
// tests/test_review6_phone_lowered_key_epoch.py starts the server, plays
// desktop A, restores the server between the steps and runs this file with
// SEZAM_X3_* set; without them the test is skipped.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/sync_recovery.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  final serverUrl = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];

  test(
    'a key_epoch lowered by a server restore is taken over, not a dead end',
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

        // An edit made offline, then the server goes back to the backup.
        final servers = vault.allNodes.firstWhere((n) => n.name == 'Servers');
        await vault.createEntry(
          parentRef: servers.id,
          name: 'offline',
          fields: const [
            EntryField(key: 'password', value: 'o1', sensitive: true),
          ],
        );
        await auth.lock();
        await net.settle();

        await handshake(dir, 'restored');

        r = await auth.unlockOffline(password: newPassword);
        expect(r.success, isTrue, reason: r.error);
        await net.settle();
        // The server lost what the phone pushed after the backup (its push
        // answers history_changed) and has the older password again: the
        // app's full resync asks for it (vault screen).
        await expectLater(
          sync.sync(),
          throwsA(isA<FullResyncRequiredException>()),
        );
        final full = await fullResyncTakingPasswordOver(
          fullResync: () => sync.fullResync(confirmed: true),
          askPassword: () async => oldPassword,
          takeOver: (password) =>
              auth.adoptPasswordChangedElsewhere(currentPassword: password),
          onRefused: (error) => fail(error),
        );
        expect(full, isNotNull);
        await vault.reloadData();
        await net.settle();
        final result = await sync.sync();
        expect(result.push.errors, isEmpty);
        expect(result.push.conflicts, 0);
        expect(await sync.getDirtyObjectCount(), 0);
        expect(passwords(vault), {'db01': 's3cret', 'offline': 'o1'});
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_review6_phone_lowered_key_epoch.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

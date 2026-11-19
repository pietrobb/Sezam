// Review 7c10379 H9 (mobile): a full resync after a server restore kept a
// folder the restored server had lost but dropped its key. Taking the older
// password over re-wrapped the key and left its old signature, so the resync
// no longer counted the key as the phone's own; the folder went back to the
// server with a key nobody had.
// tests/test_review7_phone_resync_keeps_rekeyed_key_h9.py starts the server,
// plays desktop A, restores the server between the steps and runs this file
// with SEZAM_X3_* set; without them the test is skipped.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  final serverUrl = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];

  test(
    'a full resync after a restore keeps the key of a folder it keeps',
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

        // A personal folder with its own key, confirmed by the server.
        final mine = await vault.createPersonalFolder(name: 'Mine');
        await vault.createEntry(
          parentRef: mine.id,
          name: 'deep',
          fields: const [
            EntryField(key: 'password', value: 'd1', sensitive: true),
          ],
        );
        var result = await sync.sync();
        expect(result.push.errors, isEmpty);
        expect(await sync.getDirtyObjectCount(), 0);
        await auth.lock();
        await net.settle();

        await handshake(dir, 'restored'); // the server lost the folder

        r = await auth.unlockOffline(password: newPassword);
        expect(r.success, isTrue, reason: r.error);
        await net.settle();
        // The app: the rollback asks for a full resync, whose pull asks for
        // the password the server has; then the full resync again.
        await expectLater(
          sync.sync(),
          throwsA(isA<FullResyncRequiredException>()),
        );
        await expectLater(
          sync.fullResync(confirmed: true),
          throwsA(isA<KeyEpochStaleException>()),
        );
        r = await auth.adoptPasswordChangedElsewhere(
          currentPassword: oldPassword,
        );
        expect(r.success, isTrue, reason: r.error);
        await net.settle();
        await sync.fullResync(confirmed: true);
        await vault.reloadData();
        final expected = {'db01': 's3cret', 'deep': 'd1'};
        expect(passwords(vault), expected);

        result = await sync.sync();
        expect(result.push.errors, isEmpty);
        expect(result.push.conflicts, 0);
        expect(await sync.getDirtyObjectCount(), 0);
        expect(passwords(vault), expected);
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_review7_phone_resync_keeps_rekeyed_key_h9.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

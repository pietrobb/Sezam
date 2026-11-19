// Review a159e97 (mobile, medium): a full resync after a server restore,
// with an identity rotation in between. The phone's entry the restored server
// lost carries the signature of the account's previous key; the resync kept
// only rows signed with the current key (and the account's own DEKs), so it
// deleted the entry. tests/test_review8_phone_resync_after_restore_rotation.py
// starts the server, plays desktop A and runs this file with SEZAM_X3_* set;
// without them the test is skipped.

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
    'a full resync after a restore and a rotation keeps the lost own entry',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      final password = cfg['password'] as String;
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
          password: password,
          username: cfg['username'] as String,
        );
        expect(c.outcome, ConnectOutcome.connected, reason: c.message);
        await net.settle();

        await handshake(dir!, 'backup'); // A keeps a copy of the server

        final servers = vault.allNodes.firstWhere((n) => n.name == 'Servers');
        await vault.createEntry(
          parentRef: servers.id,
          name: 'kept',
          fields: const [
            EntryField(key: 'password', value: 'k1', sensitive: true),
          ],
        );
        var result = await sync.sync();
        expect(result.push.errors, isEmpty);
        expect(await sync.getDirtyObjectCount(), 0);
        await net.settle();

        // A puts the copy back, then rotates the identity keys on it.
        await handshake(dir, 'restored_and_rotated');

        await expectLater(sync.sync(), throwsA(isA<KeyEpochStaleException>()));
        final r = await auth.adoptPasswordChangedElsewhere(
          currentPassword: password,
        );
        expect(r.success, isTrue, reason: r.error);
        await net.settle();

        final resync = await sync.fullResync(confirmed: true);
        expect(resync.dirtyCount, 0);
        await vault.reloadData();
        final expected = {'db01': 's3cret', 'kept': 'k1'};
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
        ? 'run by tests/test_review8_phone_resync_after_restore_rotation.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

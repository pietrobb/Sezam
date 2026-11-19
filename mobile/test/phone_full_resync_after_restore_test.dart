// Review d615826 H6: the phone's full resync after the server was restored
// from a backup. The rollback check also ran in full-resync mode, so the
// resync the phone asked for never finished; and the resync deleted what the
// restored server had lost, where desktop keeps it and sends it again.
// tests/test_review6_phone_resync_after_restore.py starts the server, lets
// desktop A make the account, restores the server between the steps and runs
// this file with SEZAM_X3_* set; without them the test is skipped.

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
    'a full resync after a server restore finishes and keeps what it lost',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
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
          password: cfg['password'] as String,
          username: cfg['username'] as String,
        );
        expect(c.outcome, ConnectOutcome.connected, reason: c.message);
        await net.settle();
        expect(passwords(vault), {'db01': 's3cret'});

        await handshake(dir!, 'backup'); // A keeps a copy of the server

        final servers = vault.allNodes.firstWhere((n) => n.name == 'Servers');
        await vault.createEntry(
          parentRef: servers.id,
          name: 'kept',
          fields: const [
            EntryField(key: 'password', value: 'k1', sensitive: true),
          ],
        );
        final mine = await vault.createNode(
          name: 'PhoneOnly',
          parentRef: vault.rootNodeId!,
        );
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
        await net.settle();

        await handshake(dir, 'restored'); // A puts the copy back

        await expectLater(
          sync.pull(),
          throwsA(isA<FullResyncRequiredException>()),
        );
        final resync = await sync.fullResync(confirmed: true);
        expect(resync.dirtyCount, 0);
        await vault.reloadData();
        final expected = {'db01': 's3cret', 'kept': 'k1', 'deep': 'd1'};
        expect(passwords(vault), expected);

        // Sent again: the server has them back and nothing is left over.
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
        ? 'run by tests/test_review6_phone_resync_after_restore.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

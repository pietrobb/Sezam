// Review 7c10379 (mobile): a server restored from a backup and then pushed
// past the phone's checkpoint by another device. Its head is not behind, so
// only the commit token at the checkpoint shows the history changed.
// tests/test_review7_phone_commit_token_rollback.py starts the server, plays
// desktop A, restores the server between the steps and runs this file with
// SEZAM_X3_* set; without them the test is skipped.

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
    'a restored server pushed past the checkpoint asks for a full resync',
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

        await handshake(dir!, 'backup');

        final servers = vault.allNodes.firstWhere((n) => n.name == 'Servers');
        await vault.createEntry(
          parentRef: servers.id,
          name: 'phone',
          fields: const [
            EntryField(key: 'password', value: 'p1', sensitive: true),
          ],
        );
        var result = await sync.sync();
        expect(result.push.errors, isEmpty);
        await net.settle();

        await handshake(dir, 'restored'); // and A pushed past the checkpoint

        await expectLater(
          sync.sync(),
          throwsA(isA<FullResyncRequiredException>()),
        );
        await sync.fullResync(confirmed: true);
        await vault.reloadData();
        final expected = {
          'db01': 's3cret',
          'phone': 'p1',
          for (var i = 0; i < 6; i++) 'a$i': 'v$i',
        };
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
        ? 'run by tests/test_review7_phone_commit_token_rollback.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

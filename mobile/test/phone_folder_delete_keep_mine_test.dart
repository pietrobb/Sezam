// Capability run 567 (R16-Z SM22), phone: a folder delete kept after another
// device moved the folder was refused as folder_move_cycle on every push.
// tests/test_phone_folder_delete_keep_mine.py sets it up and runs this file
// with SEZAM_X3_* set; without them the test is skipped.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  final serverUrl = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];

  test(
    'a kept folder delete settles after another device moved the folder',
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
        await sync.pull();
        await vault.reloadData();

        final x = cfg['x'] as String;
        Future<Map<String, dynamic>> rowOf(String id) async =>
            (await DatabaseService().getAllObjects()).singleWhere(
              (r) => r['id'] == id,
            );
        expect((await rowOf(x))['parent_ref'], cfg['y']);

        // Offline: X goes. Meanwhile the desktop moves X up and Y below it.
        await vault.deleteNode(x);
        await handshake(dir!, 'moved');
        await sync.pull();
        await vault.reloadData();
        final [conflict] = await DatabaseService().getSyncConflicts();
        expect(conflict['object_id'], x);
        var sent = await sync.push();
        expect(sent.errors, hasLength(1));

        expect(
          await vault.keepLocalChange(x, conflict['server_version'] as int),
          isTrue,
        );
        for (var round = 0; round < 2; round++) {
          sent = await sync.push();
          expect(sent.errors, isEmpty, reason: 'round $round');
          await sync.pull();
        }
        expect(await DatabaseService().getDirtyObjects(), isEmpty);
        final row = await rowOf(x);
        expect((row['is_deleted'], row['parent_ref']), (1, cfg['top']));
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_phone_folder_delete_keep_mine.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

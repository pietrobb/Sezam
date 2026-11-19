// Review a159e97 (mobile, port of desktop 1cff856): the server's newest
// commits were tombstones its GC collected, so a snapshot (the first pull of
// a new phone, or a full resync) ends below the GC floor. The phone stored
// that seq as its cursor and every later pull was refused with 410 for good.
// tests/test_review8_phone_snapshot_below_gc_floor.py starts the server, plays
// desktop A and runs this file with SEZAM_X3_* set; without them the test is
// skipped.

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
    'pulls go on after a snapshot that ends below the GC floor',
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

        await handshake(dir!, 'after'); // A adds a folder
        final pulled = await sync.pull();
        expect(pulled.newObjects, greaterThan(0));
        await vault.reloadData();
        expect(vault.allNodes.any((n) => n.name == 'After'), isTrue);

        await handshake(dir, 'collected'); // newest commits collected again
        await sync.fullResync(confirmed: true);
        await sync.pull();
        await handshake(dir, 'later'); // A adds another folder
        await sync.pull();
        await vault.reloadData();
        expect(vault.allNodes.any((n) => n.name == 'Later'), isTrue);
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_review8_phone_snapshot_below_gc_floor.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

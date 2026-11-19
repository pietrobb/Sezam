// Review d615826 (mobile): SyncService had no lock. The app syncs after
// unlock, on pull-to-refresh and after changes; overlapping syncs ran their
// pushes and pulls interleaved on one checkpoint. They now run one after the
// other: with the first push held up, the second sync sends nothing before
// the first one ends, and both end without conflicts.
// tests/test_review6_phone_overlapping_syncs.py starts the server, lets
// desktop A make the account and runs this file with SEZAM_X3_* set; without
// them the test is skipped.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

/// Logs each request with the sync that sent it; the first push answers late.
class _SlowFirstPush extends Net {
  final log = <String>[];
  String who = '';
  bool _delayed = false;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final tag = Zone.current[#who] as String? ?? who;
    log.add('$tag ${request.method} ${request.url.path}');
    final response = await super.send(request);
    if (!_delayed && request.method == 'POST' && request.url.path == '/api/sync') {
      _delayed = true;
      await Future<void>.delayed(const Duration(milliseconds: 800));
    }
    return response;
  }
}

void main() {
  final serverUrl = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];

  test(
    'overlapping syncs run one after the other, without conflicts',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      await setUpPhone('$dir/app');
      final net = _SlowFirstPush();
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

        final servers = vault.allNodes.firstWhere((n) => n.name == 'Servers');
        await vault.createEntry(
          parentRef: servers.id,
          name: 'phone',
          fields: const [
            EntryField(key: 'password', value: 'p1', sensitive: true),
          ],
        );
        final entry = vault.allEntries.firstWhere((e) => e.name == 'db01');
        await vault.updateEntry(
          entryId: entry.id,
          fields: const [
            EntryField(key: 'password', value: 'r1', sensitive: true),
          ],
        );

        net.log.clear();
        final first = runZoned(sync.sync, zoneValues: {#who: 'A'});
        await Future<void>.delayed(const Duration(milliseconds: 200));
        final second = runZoned(sync.sync, zoneValues: {#who: 'B'});
        final results = await Future.wait([first, second]);

        final syncs = net.log.where((l) => l.contains('/api/sync')).toList();
        final lastOfA = syncs.lastIndexWhere((l) => l.startsWith('A '));
        final firstOfB = syncs.indexWhere((l) => l.startsWith('B '));
        expect(firstOfB, greaterThan(lastOfA), reason: syncs.join('\n'));
        for (final result in results) {
          expect(result.push.errors, isEmpty);
          expect(result.push.conflicts, 0);
          expect(result.pull.conflicts, isEmpty);
        }
        expect(await DatabaseService().getSyncConflicts(), isEmpty);
        expect(await sync.getDirtyObjectCount(), 0);
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_review6_phone_overlapping_syncs.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

// TL7, phone: a member's personal folder is a personal root (top-level,
// sealed with the member's own key), never the account's root, and listed
// among the root's folders. tests/test_team_log_personal_root_phone.py sets
// it up and runs this file with SEZAM_X3_* set; without them it is skipped.

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

void main() {
  final serverUrl = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];

  test(
    'a personal folder is a personal root',
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
        final root = vault.rootNodeId;
        expect(root, isNotNull);

        final mine = await vault.createPersonalFolder(name: 'Z telefonu');
        await vault.createEntry(
          parentRef: mine.id,
          name: 'pin',
          fields: [EntryField(key: 'pin', value: '7', sensitive: true)],
        );
        final row = (await DatabaseService().getAllObjects()).firstWhere(
          (r) => r['id'] == mine.id,
        );
        expect(row['parent_ref'], isNull);
        final pushed = await sync.push();
        expect(pushed.errors, isEmpty);
        expect(pushed.conflicts, 0);

        await sync.pull();
        await vault.reloadData();
        expect(vault.rootNodeId, root);
        expect(vault.listNodes(root).map((n) => n.id), contains(mine.id));
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_team_log_personal_root_phone.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

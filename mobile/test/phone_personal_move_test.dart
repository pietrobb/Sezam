// Review 1141a20 (R9-G), phone: a member's own item (sealed with a key of
// theirs outside the log) that leaves a team folder for their personal root
// stayed hidden: the pull judged the move without ownPersonal, as if the
// member took a team item out without write access.
// tests/test_team_log_phone_personal_move.py sets it up and runs this file
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
    'an own item moved to the personal root stays on the phone',
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

        final item = cfg['item'] as String;
        Future<void> expectAt(String parent, {bool? shown}) async {
          final row = (await DatabaseService().getAllObjects()).where(
            (r) => r['id'] == item,
          );
          expect(row, hasLength(1), reason: 'the item is gone from the phone');
          expect(row.single['parent_ref'], parent);
          if (shown == null) return;
          expect(
            vault.allEntries.where((e) => e.id == item).map((e) => e.name),
            shown ? ['own-item'] : isEmpty,
          );
        }

        // Held in Ops while Bob still writes there.
        await vault.reloadData();
        await expectAt(cfg['ops'] as String);

        await handshake(dir!, 'moved');
        await sync.pull();
        await vault.reloadData();
        await expectAt(cfg['home'] as String, shown: true);
        await sync.fullResync(confirmed: true);
        await vault.reloadData();
        await expectAt(cfg['home'] as String, shown: true);
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_team_log_phone_personal_move.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

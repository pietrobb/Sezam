// TL5, phone: the signed team log decides team folders. A lying server took
// an item a member the log gives only read pushed into a team folder; the
// phone does not store it (first sync, pull, full resync). What the phone
// writes there is sealed with the log's current generation of the folder key.
// tests/test_team_log_phone.py sets it up and runs this file with SEZAM_X3_*
// set; without them the test is skipped.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/team_log_client.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  final serverUrl = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];

  test(
    'the phone follows the team log',
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

        Future<void> expectRefused() async {
          final ids = {
            for (final row in await DatabaseService().getAllObjects())
              row['id'] as String,
          };
          expect(ids, isNot(contains(cfg['forged'])));
          if (cfg['accepted_envelope'] != null) {
            expect(ids, contains(cfg['accepted_envelope']));
          }
          expect(passwords(vault), {'vpn': 'ops-pw'});
          expect(vault.teamLog, isNotNull);
        }

        await expectRefused();
        await sync.pull();
        await vault.reloadData();
        await expectRefused();
        await sync.fullResync(confirmed: true);
        await vault.reloadData();
        await expectRefused();

        final ops = vault.allNodes.firstWhere((n) => n.name == 'Ops');
        if (cfg['stale_folder'] == true) {
          await expectLater(
            vault.createEntry(parentRef: ops.id, name: 'blocked', fields: []),
            throwsA(isA<TeamLogRefused>()),
          );
          await auth.lock();
          await net.settle();
          return;
        }
        final entry = await vault.createEntry(
          parentRef: ops.id,
          name: 'from-phone',
          fields: [
            EntryField(key: 'password', value: 'phone-pw', sensitive: true),
          ],
        );
        final row = (await DatabaseService().getAllObjects()).firstWhere(
          (r) => r['id'] == entry.id,
        );
        expect(row['parent_ref'], ops.id);
        final pushed = await sync.push();
        expect(pushed.errors, isEmpty);
        expect(pushed.conflicts, 0);
        expect(pushed.accepted, greaterThanOrEqualTo(1));
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_team_log_phone.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

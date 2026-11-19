// TL7, phone: a tier-2 item in a team folder (from before the log) is neither
// shown nor edited - its key is not in the log, and an edit would be sealed
// under the folder's key, readable by every member there. A plain item there
// is edited.
// tests/test_team_log_tier2_phone.py sets it up and runs this file with
// SEZAM_X3_* set; without them it is skipped.

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
    'a tier-2 item in a team folder is not edited',
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
        expect(vault.teamLog, isNotNull);

        // Its key is not in the log: the phone neither shows nor edits it,
        // so it is never sealed under the folder's key.
        final tier2 = cfg['tier2'] as String;
        final ops = cfg['ops'] as String;
        final shown = vault.listEntries(ops).map((e) => e.id);
        expect(shown, isNot(contains(tier2)));
        expect(shown, contains(cfg['plain']));
        await expectLater(
          vault.updateEntry(
            entryId: tier2,
            fields: [EntryField(key: 'pin', value: '9', sensitive: true)],
          ),
          throwsA(isA<StateError>()),
        );

        await vault.updateEntry(
          entryId: cfg['plain'] as String,
          fields: [EntryField(key: 'pin', value: '8', sensitive: true)],
        );
        final pushed = await sync.push();
        expect(pushed.errors, isEmpty);
        expect(pushed.conflicts, 0);
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_team_log_tier2_phone.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

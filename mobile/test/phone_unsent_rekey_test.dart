// Review 1141a20 (R9-G), phone: writes not yet sent when the admin re-keys
// the team folder were sealed with the folder's old key. The log refuses an
// old key generation, so the phone refused its whole push, for good; the
// writes never left the phone. They must be sealed again with the folder's
// current key and sent.
// tests/test_team_log_phone_unsent_rekey.py sets it up and runs this file
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
    'unsent writes survive a folder re-key and are sent with the current key',
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

        final ops = cfg['ops'] as String;
        final vpn = cfg['vpn'] as String;
        // Offline: a new item and an edit, both sealed with the key held now.
        final added = await vault.createEntry(
          parentRef: ops,
          name: 'offline-new',
          fields: const [],
        );
        await vault.updateEntry(entryId: vpn, name: 'vpn-edited');
        final sealedWith = vault.allEntries
            .singleWhere((e) => e.id == added.id)
            .dekId;

        await handshake(dir!, 'rekeyed');
        await sync.pull();
        await vault.reloadData();
        Map<String, String> shown() => {
          for (final e in vault.allEntries)
            if (e.id == added.id || e.id == vpn) e.id: e.name,
        };
        expect(shown(), {added.id: 'offline-new', vpn: 'vpn-edited'});

        // The re-key sealed vpn again on the server: the edit is a conflict
        // with that copy, as on the desktop; kept, it goes out.
        final [conflict] = await DatabaseService().getSyncConflicts();
        expect(conflict['object_id'], vpn);
        var sent = await sync.push();
        expect(sent.errors, hasLength(1));
        expect(sent.errors.single, startsWith(vpn));
        expect(
          await vault.keepLocalChange(vpn, conflict['server_version'] as int),
          isTrue,
        );
        sent = await sync.push();
        expect(sent.errors, isEmpty);
        expect(await DatabaseService().getDirtyObjects(), isEmpty);
        await sync.pull();
        await vault.reloadData();
        expect(shown(), {added.id: 'offline-new', vpn: 'vpn-edited'});
        expect(
          vault.allEntries.singleWhere((e) => e.id == added.id).dekId,
          isNot(sealedWith),
        );
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_team_log_phone_unsent_rekey.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

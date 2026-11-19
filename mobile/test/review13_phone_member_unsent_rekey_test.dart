// Review c78fd19 (medium), phone: a member's writes not yet sent when the
// admin re-keys the team folder stayed on the phone for good. Sealed with the
// folder's replaced key, which a member held only through the admin's access
// envelope (never under its own KEK, as the admin's), the phone could not open
// it again to seal them with the current key. Fixed only for the admin before.
// tests/test_review13_phone_member_unsent_rekey.py sets it up and runs this
// file with SEZAM_X3_* set; without them the test is skipped.

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
    "a member's unsent writes are sent with the folder's current key after a re-key",
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
        await vault.confirmTeamFounder(
          await vault.reviewTeamFounder(),
          cfg['fingerprint'] as String,
        );
        await sync.pull();
        await vault.reloadData();

        expect(
          vault.allNodes.map((n) => n.id),
          contains(cfg['ops']),
          reason: 'the member reads Ops',
        );
        // Offline: a new item in Ops (or in the member's own subfolder Sub,
        // which the admin deletes before the re-key; only its owner may bring
        // it back), sealed with the key the member holds.
        String? sub;
        if (cfg['in_sub'] == true) {
          sub = (await vault.createNode(
            name: 'Sub',
            parentRef: cfg['ops'] as String,
          )).id;
          expect((await sync.push()).errors, isEmpty);
          File('$dir/sub.txt').writeAsStringSync(sub);
        }
        final added = await vault.createEntry(
          parentRef: sub ?? cfg['ops'] as String,
          name: 'member-offline',
          fields: const [],
        );
        final sealedWith = vault.allEntries
            .singleWhere((e) => e.id == added.id)
            .dekId;

        await handshake(dir!, 'rekeyed');
        await sync.pull();
        await vault.reloadData();
        final sent = await sync.push();
        expect(sent.errors, isEmpty);
        expect(await DatabaseService().getDirtyObjects(), isEmpty);
        await sync.pull();
        await vault.reloadData();
        final shown = vault.allEntries.singleWhere((e) => e.id == added.id);
        expect(shown.name, 'member-offline');
        expect(shown.dekId, isNot(sealedWith));
        if (sub != null) {
          // Brought back from its tombstone (sealed under the replaced key)
          // after the pull's checkpoint, with the folder's current key.
          final folder = vault.allNodes.singleWhere((n) => n.id == sub);
          expect(folder.name, 'Sub');
          expect(folder.dekId, isNot(sealedWith));
        }
        File('$dir/added.txt').writeAsStringSync(added.id);
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_review13_phone_member_unsent_rekey.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

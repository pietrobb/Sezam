// Review 7c10379 (mobile): QR provisioning of a phone that already keeps
// entries offline in its own vault. The DEKs were re-wrapped in place and the
// phone's own root stayed, so its push gave the account a second root. The
// phone now joins the account like a password connect: its folders and
// entries move under the account's root.
// tests/test_review7_phone_qr_provision_local_vault.py starts the server, lets
// desktop A make the account, mints the provisioning token and runs this file
// with SEZAM_X3_* set; without them the test is skipped.

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
    'QR provisioning moves a local vault into the account, no second root',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      final username = cfg['username'] as String;
      final password = cfg['password'] as String;
      await setUpPhone('$dir/app');
      final net = Net();
      await http.runWithClient(() async {
        final auth = AuthService();
        final sync = SyncService();
        final vault = VaultService();
        initPhoneCrypto();
        await vault.init();

        final r = await auth.createNewVault(password: 'phone-only-Pw-1234');
        expect(r.success, isTrue, reason: r.error);
        final mine = await vault.createNode(
          name: 'Mine',
          parentRef: vault.rootNodeId!,
        );
        await vault.createEntry(
          parentRef: mine.id,
          name: 'offline',
          fields: const [
            EntryField(key: 'password', value: 'o1', sensitive: true),
          ],
        );

        await handshake(dir!, 'token'); // A mints the provisioning token
        final token = File('$dir/token.txt').readAsStringSync().trim();
        final p = await auth.provisionFromQR(
          provisionToken: token,
          username: username,
          password: password,
          serverUrl: serverUrl!,
        );
        expect(p.success, isTrue, reason: p.error);
        await net.settle();
        await vault.reloadData();

        final cycle = await sync.sync();
        expect(cycle.push.errors, isEmpty);
        expect(cycle.push.conflicts, 0);
        expect(await sync.getDirtyObjectCount(), 0);
        expect(vault.allNodes.where((n) => n.parentRef == null).length, 1);
        expect(passwords(vault), {'db01': 's3cret', 'offline': 'o1'});
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_review7_phone_qr_provision_local_vault.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

// Review 7c10379 H9 (mobile): the phone took a newer key_epoch over without
// checking key_material_hash. It signed in with the password (the KEK came
// from the server's salt then), stayed unlocked, and desktop A changed the
// password. The sign-in again on the 401 took epoch 1 over under the old KEK,
// and the phone pushed a new key under it, which no other device opens. The
// phone now asks for the password the server has first.
// tests/test_review7_phone_epoch_key_material_h9.py starts the server, plays
// desktop A and runs this file with SEZAM_X3_* set; without them it is skipped.

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
    'a newer key_epoch is taken over only with the key material it belongs to',
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
          password: cfg['old_password'] as String,
          username: cfg['username'] as String,
        );
        expect(c.outcome, ConnectOutcome.connected, reason: c.message);
        await net.settle();

        await handshake(dir!, 'changed'); // A changes the password

        // Still unlocked under the old password: a new key of its own.
        final mine = await vault.createPersonalFolder(name: 'Mine');
        await vault.createEntry(
          parentRef: mine.id,
          name: 'phone',
          fields: const [
            EntryField(key: 'password', value: 'p1', sensitive: true),
          ],
        );
        await expectLater(sync.sync(), throwsA(isA<KeyEpochStaleException>()));

        final r = await auth.adoptPasswordChangedElsewhere(
          currentPassword: cfg['new_password'] as String,
        );
        expect(r.success, isTrue, reason: r.error);
        await net.settle();
        final result = await sync.sync();
        expect(result.push.errors, isEmpty);
        expect(await sync.getDirtyObjectCount(), 0);
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_review7_phone_epoch_key_material_h9.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

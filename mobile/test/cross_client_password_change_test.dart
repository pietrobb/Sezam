// Lockout review X3: the password is changed on desktop or web A, then this
// phone B (the real AuthService/SyncService/VaultService) takes it over
// against the real server. tests/test_cross_client_password_change.py starts
// the server, plays A and runs this file with SEZAM_X3_* set; without them
// the test is skipped. The phone itself never changes the password: a change
// made elsewhere is only taken over (adoptPasswordChangedElsewhere, or the
// next password unlock with the previous password). B sets the server up as
// its admin and A joins that account (phone_joins_account_test.dart covers
// the other way round).

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
    'password changed on A, phone B takes it over against the real server',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      final username = cfg['username'] as String;
      final oldPassword = cfg['old_password'] as String;
      final newPassword = cfg['new_password'] as String;
      final before = Map<String, String>.from(cfg['before'] as Map);
      final after = Map<String, String>.from(cfg['after'] as Map);

      await setUpPhone('$dir/app');
      final net = Net();
      await http.runWithClient(() async {
        // Constructed inside the zone: SyncService's client is [net].
        final auth = AuthService();
        final sync = SyncService();
        final vault = VaultService();
        initPhoneCrypto();
        await vault.init();

        // Before the change: phone B creates its vault and sets the empty
        // server up as its admin (the app's connect flow); A then joins the
        // same account and writes a record, which B reads.
        var r = await auth.createNewVault(password: oldPassword);
        expect(r.success, isTrue, reason: r.error);
        final connected = await auth.connectToServer(
          serverUrl: serverUrl!,
          password: oldPassword,
          username: username,
        );
        expect(
          connected.outcome,
          ConnectOutcome.connected,
          reason: connected.message,
        );
        await net.settle();
        await handshake(dir!, 'joined');
        await sync.sync(); // the app's sync: push, pull, reload
        expect(passwords(vault), before);
        await auth.lock();
        await net.settle();

        await handshake(dir, 'changed');

        // The phone still opens offline with the old password; its sync
        // stops on the newer key epoch.
        r = await auth.unlockOffline(password: oldPassword);
        expect(r.success, isTrue, reason: r.error);
        await net.settle();
        expect(passwords(vault), before);
        await expectLater(sync.sync(), throwsA(isA<KeyEpochStaleException>()));

        // The old password is refused by the server and changes nothing.
        r = await auth.adoptPasswordChangedElsewhere(
          currentPassword: oldPassword,
        );
        expect(r.success, isFalse);
        expect(r.error, contains('Wrong password'));

        // The new password with the network failing before the session:
        // nothing moves either (lockout review #9), the old password still
        // opens every record on the phone.
        net.failPath = '/api/auth/challenge';
        r = await auth.adoptPasswordChangedElsewhere(
          currentPassword: newPassword,
        );
        expect(r.success, isFalse);
        expect(net.failPath, isNull, reason: 'challenge was never requested');
        await auth.lock();
        await net.settle();
        r = await auth.unlockOffline(password: oldPassword);
        expect(r.success, isTrue, reason: r.error);
        await net.settle();
        expect(passwords(vault), before);

        // The new password takes the change over: A's records, old and new.
        r = await auth.adoptPasswordChangedElsewhere(
          currentPassword: newPassword,
        );
        expect(r.success, isTrue, reason: r.error);
        await net.settle();
        await sync.sync(); // the app's sync: push, pull, reload
        expect(passwords(vault), after);

        // B keeps syncing under the new password.
        final folder = vault.allNodes.firstWhere((n) => n.name == 'Servers');
        await vault.createEntry(
          parentRef: folder.id,
          name: 'phone',
          fields: const [
            EntryField(key: 'password', value: 'from-phone', sensitive: true),
          ],
        );
        final pushed = (await sync.sync()).push;
        expect(pushed.errors, isEmpty);
        expect(pushed.conflicts, 0);
        expect(pushed.accepted, greaterThan(0));
        final withPhone = {...after, 'phone': 'from-phone'};
        expect(passwords(vault), withPhone);
        await auth.lock();
        await net.settle();

        // From now on only the new password opens the phone, offline and
        // online.
        r = await auth.unlockOffline(password: oldPassword);
        expect(r.success, isFalse);
        r = await auth.unlockOffline(password: newPassword);
        expect(r.success, isTrue, reason: r.error);
        await net.settle();
        expect(passwords(vault), withPhone);
        await auth.lock();
        await net.settle();
        r = await auth.unlockWithPassword(
          password: oldPassword,
          username: username,
          serverUrl: serverUrl,
        );
        expect(r.success, isFalse);
        r = await auth.unlockWithPassword(
          password: newPassword,
          username: username,
          serverUrl: serverUrl,
        );
        expect(r.success, isTrue, reason: r.error);
        await net.settle();
        await sync.sync(); // the app's sync: push, pull, reload
        expect(passwords(vault), withPhone);
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_cross_client_password_change.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

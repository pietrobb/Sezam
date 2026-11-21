// Review d615826 (mobile): desktop A rotated the account's identity keys
// while this phone had an edit it had not sent. The phone took the rotation
// over with the password, but the edit kept the signature of the retired key
// and the server refused it on every push.
// tests/test_review6_phone_identity_rotation_offline.py starts the server,
// plays desktop A and runs this file with SEZAM_X3_* set; without them the
// test is skipped.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/team_log_client.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  final serverUrl = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];

  test(
    'an offline edit syncs after the phone takes over an identity rotation',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      final password = cfg['password'] as String;
      final currentPassword = cfg['current_password'] as String? ?? password;
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
          password: password,
          username: cfg['username'] as String,
        );
        expect(c.outcome, ConnectOutcome.connected, reason: c.message);
        await net.settle();
        await auth.lock();
        await net.settle();

        // Offline: an edit the phone has not sent yet.
        var r = await auth.unlockOffline(password: password);
        expect(r.success, isTrue, reason: r.error);
        await net.settle();
        final servers = vault.allNodes.firstWhere((n) => n.name == 'Servers');
        await vault.createEntry(
          parentRef: servers.id,
          name: 'offline',
          fields: const [
            EntryField(key: 'password', value: 'o1', sensitive: true),
          ],
        );

        var qrAttempt = 0;
        Future<AuthResult> takeOver() async {
          if (cfg['qr'] == true) {
            if (qrAttempt == 0) await handshake(dir!, 'qr_token');
            return auth.provisionFromQR(
              provisionToken: File(
                '$dir/qr-token.txt',
              ).readAsLinesSync()[qrAttempt++],
              serverUrl: serverUrl,
              username: cfg['username'] as String,
              password: currentPassword,
            );
          }
          if (cfg['reconnect'] != true) {
            return auth.adoptPasswordChangedElsewhere(
              currentPassword: currentPassword,
            );
          }
          final result = await auth.connectToServer(
            serverUrl: serverUrl,
            username: cfg['username'] as String,
            password: currentPassword,
          );
          return result.outcome == ConnectOutcome.connected
              ? AuthResult.success(userId: vault.userId!)
              : AuthResult.failure(result.message);
        }

        await handshake(dir!, 'rotated'); // A rotates the account keys/KEK

        await expectLater(sync.sync(), throwsA(isA<KeyEpochStaleException>()));
        if (cfg['qr'] == true) {
          await auth.lock();
          await net.settle();
          const storage = FlutterSecureStorage();
          final beforeSecure = await storage.readAll();
          final beforeObjects = await DatabaseService().getAllObjects();
          r = await takeOver();
          expect(
            r.success,
            isFalse,
            reason: 'locked QR must require the local KEK',
          );
          expect(await storage.readAll(), beforeSecure);
          expect(await DatabaseService().getAllObjects(), beforeObjects);
          final db = await DatabaseService().database;
          final deks = await db.query(
            'vault_objects',
            where: 'object_type = ?',
            whereArgs: ['dek'],
          );
          expect(deks, isNotEmpty);
          await db.delete(
            'vault_objects',
            where: 'object_type = ?',
            whereArgs: ['dek'],
          );
          final withoutDeks = await DatabaseService().getAllObjects();
          try {
            r = await takeOver();
            expect(
              r.success,
              isFalse,
              reason: 'locked anchor continuity is independent of DEKs',
            );
            expect(await storage.readAll(), beforeSecure);
            expect(await DatabaseService().getAllObjects(), withoutDeks);
          } finally {
            for (final dek in deks) {
              await db.insert('vault_objects', dek);
            }
          }
          r = await auth.unlockOffline(password: password);
          expect(r.success, isTrue, reason: r.error);
          expect(passwords(vault), {'db01': 's3cret', 'offline': 'o1'});
        }
        if (cfg['locked'] == true) {
          await auth.lock();
          await net.settle();
          const storage = FlutterSecureStorage();
          final beforeSecure = await storage.readAll();
          final beforeObjects = await DatabaseService().getAllObjects();
          if (cfg['recover'] == true) {
            r = await auth.recoverFromServer(
              password: currentPassword,
              username: cfg['username'] as String,
              serverUrl: serverUrl,
            );
            expect(r.success, isFalse);
            expect(await storage.readAll(), beforeSecure);
            expect(await DatabaseService().getAllObjects(), beforeObjects);
          }
          for (final oldPassword in <String?>[null, 'incorrect-old-password']) {
            r = await auth.unlockWithPassword(
              password: currentPassword,
              previousPassword: oldPassword,
              username: cfg['username'] as String,
              serverUrl: serverUrl,
            );
            expect(r.success, isFalse);
            expect(vault.isUnlocked, isFalse);
            expect(await storage.readAll(), beforeSecure);
            expect(await DatabaseService().getAllObjects(), beforeObjects);
          }
        }
        if (cfg['refuse'] == true) {
          const storage = FlutterSecureStorage();
          final beforeSecure = await storage.readAll();
          final beforeObjects = await DatabaseService().getAllObjects();
          if (cfg['locked'] != true && cfg['downgrade'] != true) {
            final reconnect = await auth.connectToServer(
              serverUrl: serverUrl,
              username: cfg['username'] as String,
              password: currentPassword,
            );
            expect(reconnect.outcome, isNot(ConnectOutcome.connected));
            expect(await storage.readAll(), beforeSecure);
            expect(await DatabaseService().getAllObjects(), beforeObjects);
          }
          r = cfg['qr'] == true
              ? await takeOver()
              : cfg['locked'] == true
              ? await auth.unlockWithPassword(
                  password: currentPassword,
                  previousPassword: password,
                  username: cfg['username'] as String,
                  serverUrl: serverUrl,
                )
              : await auth.adoptPasswordChangedElsewhere(
                  currentPassword: currentPassword,
                );
          if (cfg['locked'] == true) {
            // INV-7 (capability run 416): the server's keys after a password
            // change elsewhere opening the vault this phone holds never keep it
            // locked, whatever genesis they name (before: refused, locked).
            // The pin never moves; a changed anchor refuses the team, and
            // forgetting the pins on the open vault is the way out.
            expect(r.success, isTrue, reason: r.error);
            await net.settle();
            expect(vault.isUnlocked, isTrue);
            // The refused team's folder is not shown until the way out.
            expect(passwords(vault), cfg['conflict'] == true
                ? isEmpty : {'db01': 's3cret', 'offline': 'o1'});
            final uid = vault.userId!;
            expect(await readConfirmedTeamGenesis(uid), cfg['genesis']);
            if (cfg['conflict'] == true) {
              expect(vault.teamLogRefusal?.cause, 'anchor_conflict');
              final genesis = cfg['genesis'] as String;
              final typed = '${genesis.substring(0, 16)} ${'cd' * 8}';
              // Asked before the unsent edit the left log no longer takes goes.
              await expectLater(
                sync.forgetTeamLogPin(typed),
                throwsA(isA<UnsentChangesBlockForget>()),
              );
              await sync.forgetTeamLogPin(typed, discardUnsent: true);
              // The way out exported the unsent edit; the full resync it
              // requires puts the server's copy back in its place.
              await sync.fullResync(confirmed: true);
            }
            expect(vault.teamLogRefusal, isNull);
            await auth.lock();
            r = await auth.unlockOffline(password: currentPassword);
            expect(r.success, isTrue, reason: r.error);
            await net.settle();
            expect(passwords(vault), {
              'db01': 's3cret',
              if (cfg['conflict'] != true) 'offline': 'o1',
            });
            await handshake(dir, 'restore_bundle');
          } else if (cfg['downgrade'] == true) {
            // Review e443cbc R15 (goal #429), INV-7 as for the locked phone:
            // keys naming no anchor under a password state this phone never
            // left without it come from a device that holds the password but
            // not the anchor (no server can wrap them). Refused, the phone
            // stayed on a stale key epoch for good; it takes them over and
            // the pin stays. A replayed pre-anchor state is still refused
            // (test_review10_phone, r15_phone_anchorless_change_test).
            expect(r.success, isTrue, reason: r.error);
            await net.settle();
            expect(await readConfirmedTeamGenesis(vault.userId!), cfg['genesis']);
            expect(passwords(vault), {'db01': 's3cret', 'offline': 'o1'});
            await handshake(dir, 'restore_bundle');
          } else {
            expect(
              r.success,
              isFalse,
              reason: 'replacement removed or changed the account anchor',
            );
            expect(await storage.readAll(), beforeSecure);
            expect(await DatabaseService().getAllObjects(), beforeObjects);
            expect(passwords(vault), {'db01': 's3cret', 'offline': 'o1'});
            await auth.lock();
            r = await auth.unlockOffline(password: password);
            expect(r.success, isTrue, reason: r.error);
            expect(passwords(vault), {'db01': 's3cret', 'offline': 'o1'});
            // The test server's rollback restores its whole storage: a refused
            // background sync still in flight would undo the restored bundle.
            await net.settle();
            await handshake(dir, 'restore_bundle');
          }
        }
        if (cfg['authfail'] == true) {
          await net.settle();
          const storage = FlutterSecureStorage();
          final beforeSecure = await storage.readAll();
          final beforeObjects = await DatabaseService().getAllObjects();
          net.failPath = '/api/auth/verify';
          r = await takeOver();
          expect(r.success, isFalse);
          expect(await storage.readAll(), beforeSecure);
          expect(await DatabaseService().getAllObjects(), beforeObjects);
          expect(passwords(vault), {'db01': 's3cret', 'offline': 'o1'});
          await auth.lock();
          r = await auth.unlockOffline(password: password);
          expect(r.success, isTrue, reason: r.error);
        }
        if (cfg['autolock'] == true) {
          await net.settle();
          net.onSend = (path) {
            if (path == '/api/auth/verify') {
              net.onSend = null;
              vault.lock();
            }
          };
          r = await takeOver();
          expect(r.success, isFalse);
          expect(vault.isUnlocked, isFalse);
          await DatabaseService().close();
          r = await auth.unlockOffline(password: currentPassword);
          expect(r.success, isTrue, reason: r.error);
          expect(passwords(vault), {'db01': 's3cret', 'offline': 'o1'});
        }
        if (cfg['crash'] == true) {
          secureWriteKillsApp = 'sezam_encrypted_keypair';
        }
        if (cfg['locked'] == true) await auth.lock();
        r = cfg['locked'] == true
            ? await auth.unlockWithPassword(
                password: currentPassword,
                previousPassword: password,
                username: cfg['username'] as String,
                serverUrl: serverUrl,
              )
            : await takeOver();
        if (cfg['crash'] == true) {
          expect(r.success, isFalse);
          await auth.lock();
          await net.settle();
          await DatabaseService().close();
          r = await auth.unlockOffline(password: currentPassword);
          expect(r.success, isTrue, reason: r.error);
          expect(passwords(vault), {'db01': 's3cret', 'offline': 'o1'});
          await net.settle();
          r = await takeOver();
        }
        expect(r.success, isTrue, reason: r.error);
        await net.settle();

        final result = await sync.sync();
        expect(result.push.errors, isEmpty);
        expect(result.push.conflicts, 0);
        expect(await sync.getDirtyObjectCount(), 0);
        expect(passwords(vault), {
          'db01': 's3cret',
          if (cfg['conflict'] != true) 'offline': 'o1',
        });
        if (cfg['genesis'] != null && cfg['conflict'] != true) {
          expect(await readConfirmedTeamGenesis(vault.userId!), cfg['genesis']);
        }
        // The locked phone took the swapped bundle's key material over (it
        // syncs only on the server's key_material_hash); the pin decided.
        if (cfg['genesis'] != null && !(cfg['locked'] == true && cfg['refuse'] == true)) {
          final encoded = await const FlutterSecureStorage().read(
            key: 'sezam_encrypted_keypair',
          );
          final account = CryptoService().openAccountKeypair(
            hexToBytes(encoded!),
            vault.currentKek!,
            vault.userId!,
          );
          expect(account.confirmedGenesis, cfg['genesis']);
          CryptoService().zeroize(account.keypairData);
        }
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_review6_phone_identity_rotation_offline.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

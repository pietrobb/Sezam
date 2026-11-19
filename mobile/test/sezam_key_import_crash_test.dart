// Review 688edcb (mobile): a .sezam-key import moves the local DEKs to the
// backup's KEK in the database, then stores the backup's salt/keypair in the
// Keychain. An app killed between the two left DEKs under a KEK no stored
// salt derives: a purely local vault was lost. The database transaction now
// also records the keypair state, and the next unlock finishes it.

import 'dart:io';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';
import 'package:sezam_mobile/services/team_log_client.dart';

import 'support/real_server_phone.dart';

const _password = 'import-crash-pw';

void main() {
  late Directory appDir;
  final secure = <String, String>{};
  String? failWriteOf;

  setUp(() async {
    secure.clear();
    failWriteOf = null;
    appDir = await Directory.systemTemp.createTemp('sezam_import_crash_');
    await setUpPhone(appDir.path);
    // The Keychain, with a write that dies like a killed app.
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
          const MethodChannel('plugins.it_nomads.com/flutter_secure_storage'),
          (call) async {
            final args = (call.arguments as Map?) ?? {};
            final key = args['key'] as String?;
            switch (call.method) {
              case 'read':
                return secure[key];
              case 'write':
                if (key == failWriteOf) {
                  failWriteOf = null;
                  throw PlatformException(code: 'killed');
                }
                secure[key!] = args['value'] as String;
                return null;
              case 'delete':
                secure.remove(key);
                return null;
              case 'containsKey':
                return secure.containsKey(key);
              case 'readAll':
                return Map<String, String>.from(secure);
              case 'deleteAll':
                secure.clear();
                return null;
            }
            return null;
          },
        );
  });

  tearDown(() async {
    await AuthService().lock();
    await DatabaseService().close();
    await appDir.delete(recursive: true);
  });

  for (final scenario in [
    'legacy',
    'portable',
    'downgrade',
    'independent-pin',
    'pin-storage',
    'conflict',
    'signing-public',
    'encryption-public',
    'other-signing',
    'other-encryption',
  ]) {
    final portable = scenario != 'legacy' && scenario != 'independent-pin';
    test(
      'backup import validates trust and survives a Keychain crash: $scenario',
      () async {
        final auth = AuthService();
        final vault = VaultService();
        initPhoneCrypto();
        final crypto = CryptoService();
        await vault.init();
        var r = await auth.createNewVault(password: _password);
        expect(r.success, isTrue, reason: r.error);
        final folder = await vault.createNode(
          name: 'Mine',
          parentRef: vault.rootNodeId!,
        );
        await vault.createEntry(
          parentRef: folder.id,
          name: 'offline',
          fields: const [
            EntryField(key: 'password', value: 'o1', sensitive: true),
          ],
        );

        // A backup of this keypair under another salt (made before a password
        // change, say): importing it moves the DEKs to its KEK.
        final exported = decodeSezamKeyBackup(
          await File(
            await auth.exportSezamKey(
              signingPublicKey: vault.signingPublicKey!,
              encryptionPublicKey: vault.encryptionPublicKey!,
            ),
          ).readAsBytes(),
        );
        final salt = crypto.randomBytes(16);
        final derived = await crypto.deriveBackupKEK(
          _password,
          salt,
          timeCost: exported.timeCost,
          memoryCost: exported.memoryCost,
          parallelism: exported.parallelism,
        );
        final keypair = Uint8List.fromList([
          ...vault.signingSecretKey!,
          ...vault.encryptionSecretKey!,
        ]);
        final other = SezamKeyBackup(
          argon2Salt: salt,
          timeCost: exported.timeCost,
          memoryCost: exported.memoryCost,
          parallelism: exported.parallelism,
          signingPublicKey: exported.signingPublicKey,
          encryptionPublicKey: exported.encryptionPublicKey,
          kekDekId: exported.kekDekId,
          userObjectId: exported.userObjectId,
          encryptedEnvelope: crypto.wrapKeypair(
            portable
                ? crypto.encodeAccountKeypair(keypair, 'ab' * 32)
                : keypair,
            Uint8List.sublistView(derived, 0, 32),
            exported.kekDekId,
            exported.userObjectId,
          ),
        );
        final file = File('${appDir.path}/other.sezam-key')
          ..writeAsBytesSync(encodeSezamKeyBackup(other));

        if (scenario == 'independent-pin') {
          await confirmTeamGenesis(exported.userObjectId, 'ab' * 32);
        }
        if (scenario == 'downgrade') {
          final imported = await auth.importSezamKey(
            filePath: file.path,
            password: _password,
          );
          crypto.zeroize(imported.kek);
          crypto.zeroize(imported.keypairBytes);
          await auth.lock();
          r = await auth.unlockOffline(password: _password);
          expect(r.success, isTrue, reason: r.error);
        }
        if (scenario != 'legacy' &&
            scenario != 'portable' &&
            scenario != 'independent-pin') {
          if (scenario == 'conflict') {
            await confirmTeamGenesis(exported.userObjectId, 'ab' * 32);
          }
          final rejectedKeys = Uint8List.fromList(keypair);
          if (scenario == 'other-signing') {
            rejectedKeys.setRange(0, 32, crypto.randomBytes(32));
            rejectedKeys.setRange(
              32,
              64,
              crypto.signingPublicKeyFromSeed(
                Uint8List.sublistView(rejectedKeys, 0, 32),
              ),
            );
          }
          if (scenario == 'other-encryption') {
            rejectedKeys.setRange(64, 96, crypto.randomBytes(32));
          }
          final rejected = SezamKeyBackup(
            argon2Salt: salt,
            timeCost: other.timeCost,
            memoryCost: other.memoryCost,
            parallelism: other.parallelism,
            signingPublicKey: scenario == 'signing-public'
                ? crypto.randomBytes(32)
                : Uint8List.fromList(rejectedKeys.sublist(32, 64)),
            encryptionPublicKey: scenario == 'encryption-public'
                ? crypto.randomBytes(32)
                : crypto.scalarmultBase(
                    Uint8List.sublistView(rejectedKeys, 64),
                  ),
            kekDekId: other.kekDekId,
            userObjectId: other.userObjectId,
            encryptedEnvelope: crypto.wrapKeypair(
              scenario == 'downgrade'
                  ? rejectedKeys
                  : crypto.encodeAccountKeypair(
                      rejectedKeys,
                      (scenario == 'conflict' ? 'cd' : 'ab') * 32,
                    ),
              Uint8List.sublistView(derived, 0, 32),
              other.kekDekId,
              other.userObjectId,
            ),
          );
          file.writeAsBytesSync(encodeSezamKeyBackup(rejected));
          final beforeSecure = Map<String, String>.from(secure);
          final beforeDeks = await DatabaseService().getObjectsByType('dek');
          if (scenario == 'pin-storage') {
            failWriteOf =
                'sezam_confirmed_team_genesis:${exported.userObjectId}';
          }
          await expectLater(
            auth.importSezamKey(filePath: file.path, password: _password),
            throwsA(anything),
          );
          expect(failWriteOf, isNull);
          expect(secure, beforeSecure);
          expect(await DatabaseService().getObjectsByType('dek'), beforeDeks);
          expect(passwords(vault), {'offline': 'o1'});
          await auth.lock();
          r = await auth.unlockOffline(password: _password);
          expect(r.success, isTrue, reason: r.error);
          expect(passwords(vault), {'offline': 'o1'});
          file.writeAsBytesSync(encodeSezamKeyBackup(other));
        }

        // Killed at the first Keychain write after the database moved.
        failWriteOf = 'sezam_pending_keypair_migration';
        await expectLater(
          auth.importSezamKey(filePath: file.path, password: _password),
          throwsA(anything),
        );
        expect(
          failWriteOf,
          isNull,
          reason: 'the import never reached the Keychain',
        );
        await auth.lock();

        // The app starts again: the password opens the vault and its entries.
        r = await auth.unlockOffline(password: _password);
        expect(r.success, isTrue, reason: r.error);
        expect(passwords(vault), {'offline': 'o1'});
        await auth.lock();
        r = await auth.unlockOffline(password: _password);
        expect(r.success, isTrue, reason: r.error);
        expect(passwords(vault), {'offline': 'o1'});
        final stored = crypto.openAccountKeypair(
          hexToBytes(secure['sezam_encrypted_keypair']!),
          Uint8List.sublistView(derived, 0, 32),
          exported.userObjectId,
        );
        expect(stored.confirmedGenesis, portable ? 'ab' * 32 : null);
        expect(
          await readConfirmedTeamGenesis(exported.userObjectId),
          portable || scenario == 'independent-pin' ? 'ab' * 32 : null,
        );
        crypto.zeroize(stored.keypairData);
        crypto.zeroize(derived);
        crypto.zeroize(keypair);
        await auth.lock();
      },
      timeout: const Timeout(Duration(minutes: 3)),
    );
  }
}

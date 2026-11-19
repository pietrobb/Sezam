// Review 7c10379 (R7-H, mobile): moving the local DEKs to another KEK (a
// .sezam-key import, a password take-over, a QR join) read the rows, wrote
// them back and switched the unlocked vault only afterwards, while creating a
// personal folder took no part in it. A folder made in that gap kept its key
// under the old KEK: the import failed with 'Cannot unwrap N own key(s)' and
// so did every unlock after it; a purely local vault was lost.

import 'dart:io';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

const _password = 'import-race-pw';

void main() {
  late Directory appDir;
  final secure = <String, String>{};

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_import_race_');
    await setUpPhone(appDir.path);
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

  tearDownAll(() async {
    await DatabaseService().close();
    await appDir.delete(recursive: true);
  });

  test(
    'personal folders made during a .sezam-key import stay readable',
    () async {
      final auth = AuthService();
      final vault = VaultService();
      final sync = SyncService();
      initPhoneCrypto();
      final crypto = CryptoService();
      await vault.init();
      var r = await auth.createNewVault(password: _password);
      expect(r.success, isTrue, reason: r.error);
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
          keypair,
          Uint8List.sublistView(derived, 0, 32),
          exported.kekDekId,
          exported.userObjectId,
        ),
      );
      final file = File('${appDir.path}/other.sezam-key')
        ..writeAsBytesSync(encodeSezamKeyBackup(other));

      // The user keeps adding personal folders while the import runs (its
      // Argon2, the DEK move, the Keychain writes and the unlock).
      var done = false;
      final import = auth
          .importSezamKey(filePath: file.path, password: _password)
          .whenComplete(() => done = true);
      final created = <String>{};
      var n = 0;
      while (!done) {
        created.add((await vault.createPersonalFolder(name: 'F${n++}')).name);
      }
      await import; // old code: 'Cannot unwrap N own key(s)'
      expect(created.length, greaterThan(1));
      // One more after the import, under the backup's KEK.
      created.add((await vault.createPersonalFolder(name: 'after')).name);
      expect(
        await sync.unreadableOwnDeks(
          Uint8List.fromList(vault.currentKek!),
          vault.userId,
        ),
        isEmpty,
      );

      // The app starts again: the password opens the vault and every folder.
      for (var i = 0; i < 2; i++) {
        await auth.lock();
        r = await auth.unlockOffline(password: _password);
        expect(r.success, isTrue, reason: r.error);
        expect({
          for (final node in vault.allNodes)
            if (node.personal) node.name,
        }, created);
      }
      await auth.lock();
    },
    timeout: const Timeout(Duration(minutes: 3)),
  );
}

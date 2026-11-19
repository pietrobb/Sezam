// Review 7c10379 (R7-H, mobile): taking over an identity rotation re-signs
// the unsent rows with the account's new key (d615826, f6125ac). The move
// read them, re-signed copies and wrote payload, hash and signature back
// later; an edit saved in between was overwritten by the older copy (its
// version kept, so its signature no longer matched either), and an edit
// after the move was signed with the retired key until the unlock. The
// server refuses both on every push, and the edit is gone after a reload.

import 'dart:io';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  late Directory appDir;
  final secure = <String, String>{};

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_resign_race_');
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
    'edits during an identity take-over keep their content and sign',
    () async {
      final auth = AuthService();
      final vault = VaultService();
      final sync = SyncService();
      final db = DatabaseService();
      initPhoneCrypto();
      final crypto = CryptoService();
      await vault.init();
      final r = await auth.createNewVault(password: 'pw-resign');
      expect(r.success, isTrue, reason: r.error);
      final entries = <String>[];
      for (var i = 0; i < 20; i++) {
        final e = await vault.createEntry(
          parentRef: vault.rootNodeId!,
          name: 'e$i',
          fields: [EntryField(key: 'password', value: 'v0', sensitive: true)],
        );
        entries.add(e.id);
      }
      final oldKek = Uint8List.fromList(vault.currentKek!);
      final newKek = crypto.randomBytes(32);
      final rotated = crypto.generateSigningKeypair();
      var done = false;
      final rekey = sync
          .rekeyLocalVault(
            oldKek: oldKek,
            newKek: newKek,
            userId: vault.userId,
            checkpointUserId: null,
            signingSecretKey: rotated.sk,
          )
          .whenComplete(() => done = true);
      final edited = <String>{};
      var i = 0;
      while (!done) {
        final id = entries[i++ % entries.length];
        await vault.updateEntry(
          entryId: id,
          fields: [EntryField(key: 'password', value: 'v$i', sensitive: true)],
        );
        edited.add(id);
      }
      await rekey;
      expect(edited, isNotEmpty);
      var badSig = 0;
      for (final row in await db.getDirtyObjects()) {
        if (row['object_type'] != 'entry') continue;
        final ok = crypto.verifyDetached(
          signature: row['client_signature'] as Uint8List,
          message: crypto.buildSyncSignatureData(
            id: row['id'] as String,
            objectType: 'entry',
            parentRef: row['parent_ref'] as String?,
            targetUserId: null,
            isDeleted: 0,
            version: row['version'] as int,
            payloadHashHex: row['payload_hash'] as String,
          ),
          publicKey: rotated.pk,
        );
        final hashOk =
            crypto.sha256Hex(row['payload'] as Uint8List) ==
            row['payload_hash'];
        if (!ok || !hashOk) badSig++;
      }
      expect(badSig, 0, reason: 'unsent entries the server refuses');
      final before = {
        for (final id in entries) id: vault.entries[id]!.fields.first.value,
      };
      await vault.unlock(
        kek: newKek,
        signingSecretKey: rotated.sk,
        signingPublicKey: rotated.pk,
        encryptionSecretKey: Uint8List.fromList(vault.encryptionSecretKey!),
        userId: vault.userId!,
      );
      expect(
        {for (final id in entries) id: vault.entries[id]?.fields.first.value},
        before,
        reason: 'an edit saved during the take-over is gone after a reload',
      );
      await auth.lock();
    },
    timeout: const Timeout(Duration(minutes: 3)),
  );
}

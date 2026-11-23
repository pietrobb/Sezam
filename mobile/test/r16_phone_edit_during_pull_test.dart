// Review 18c300f R16-M1, phone: an edit racing a pull got stuck silently.
//
// updateEntry read the entry, awaited (the team log check, the stored row)
// and stored the edit numbered one above what it had read. A sync that
// stored another device's version in that gap was overwritten by an edit
// numbered like it, built on the version before: the server answers every
// push with a conflict nobody sees. The edit now replaces only the version it
// was made on; otherwise it is the typed "changed meanwhile" error the editor
// shows.

import 'dart:io';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  late Directory appDir;
  final secure = <String, String>{};

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_edit_pull_');
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

  test('an edit does not replace a version a sync stored meanwhile', () async {
    final auth = AuthService();
    final vault = VaultService();
    final db = DatabaseService();
    initPhoneCrypto();
    await vault.init();
    final r = await auth.createNewVault(password: 'pw-edit-pull');
    expect(r.success, isTrue, reason: r.error);
    final entry = await vault.createEntry(
      parentRef: vault.rootNodeId!,
      name: 'db',
      fields: [EntryField(key: 'password', value: 'v1', sensitive: true)],
    );
    final batch = (await db.database).batch()..delete('outbox');
    await batch.commit();

    // The sync stores another device's next version; the edit already read v1.
    final server = Uint8List.fromList(List.filled(64, 7));
    await db.upsertObject(
      id: entry.id,
      objectType: 'entry',
      payload: server,
      parentRef: entry.parentRef,
      version: entry.version + 1,
      payloadHash: 'server-hash',
    );

    await expectLater(
      vault.updateEntry(entryId: entry.id, name: 'db-renamed'),
      throwsA(isA<StaleEntryEditException>()),
    );
    final row = (await db.getObject(entry.id))!;
    expect(row['payload_hash'], 'server-hash');
    expect(await db.getDirtyObjects(), isEmpty);
    await auth.lock();
  });
}

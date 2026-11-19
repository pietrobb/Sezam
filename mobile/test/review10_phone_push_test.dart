// Review 8595ec1 (R10-F, medium): one queued row in a team folder the log
// does not let out yet (founder not confirmed on this phone) no longer holds
// back every other change of the phone; it stays queued and is reported.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  final server = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];
  test(
    'a team folder row held back does not block the push',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      final ops = cfg['ops'] as String;
      await setUpPhone('$dir/app');
      final net = Net();
      await http.runWithClient(() async {
        final auth = AuthService();
        final sync = SyncService();
        final vault = VaultService();
        final db = DatabaseService();
        initPhoneCrypto();
        await vault.init();
        final unlocked = await auth.unlockWithPassword(
          serverUrl: server!,
          username: 'bob',
          password: cfg['password'] as String,
        );
        expect(unlocked.success, isTrue, reason: unlocked.error);
        await net.settle();
        await sync.sync();
        expect(vault.teamLog, isNull);

        await handshake(dir!, 'founded');
        await sync.pull();
        expect(vault.teamLog, isNotNull);
        // A row queued in the team folder (by an earlier app version, before
        // the log reached the phone) that the log does not let out yet.
        const teamId = '01JZZZZZZZZZZZZZZZZZZZZZZZ';
        final payload = Uint8List.fromList(List.filled(64, 7));
        await db.upsertObject(id: teamId, objectType: 'entry', payload: payload,
            ownerId: vault.userId, parentRef: ops, version: 1,
            payloadHash: CryptoService().sha256Hex(payload),
            clientSignature: Uint8List(64), queued: true);

        final mine = await vault.createNode(name: 'Mine', parentRef: vault.rootNodeId!);
        final personal = await vault.createEntry(parentRef: mine.id, name: 'personal', fields: const [
          EntryField(key: 'password', value: 'personal-secret', sensitive: true),
        ]);
        final result = await sync.push();
        expect(result.accepted, greaterThanOrEqualTo(2), reason: result.errors.join('; '));
        expect(result.errors, [contains(teamId)]);
        expect(result.errors.single, contains('founder is not confirmed'));
        final dirty = {for (final r in await db.getDirtyObjects()) r['id'] as String};
        expect(dirty, contains(teamId));
        expect(dirty, isNot(contains(personal.id)));
        await handshake(dir, 'pushed');
        await auth.lock();
        await net.settle();
        await db.close();
      }, () => net);
      net.close();
    },
    skip: server == null || dir == null,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

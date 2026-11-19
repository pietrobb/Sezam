// Real local writes and persisted push retry must not trust an observed log.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/team_log_client.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  final server = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];
  test(
    'unconfirmed local writes and push leave ciphertext untouched',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      await setUpPhone('$dir/app');
      final net = Net();
      await http.runWithClient(() async {
        initPhoneCrypto();
        final auth = AuthService();
        final vault = VaultService();
        final db = DatabaseService();
        final sync = SyncService();
        await vault.init();
        final uid = cfg['user_id'] as String;
        final genesis = cfg['genesis'] as String;
        final folder = cfg['folder'] as String;
        final operation = cfg['operation'] as String;
        await confirmTeamGenesis(uid, genesis);
        final login = await auth.unlockWithPassword(
          serverUrl: server!,
          username: 'bob',
          password: cfg['password'] as String,
        );
        expect(login.success, isTrue, reason: login.error);
        await sync.sync(); // Serialize after login's background pull and cache reload.
        final entry = await vault.createEntry(
          parentRef: folder,
          name: 'original',
          fields: const [],
        );
        expect((await sync.push()).conflicts, 0);
        final node = vault.allNodes.singleWhere((n) => n.id == folder);
        Future<void> change() async {
          switch (operation) {
            case 'node':
              await vault.createNode(name: 'new folder', parentRef: folder);
            case 'update':
              await vault.updateEntry(entryId: entry.id, name: 'edited');
            case 'delete':
              await vault.deleteEntry(entry.id);
            case 'tier2':
              await vault.addCarriedItems(
                fromRootId: vault.rootNodeId,
                nodes: [node],
                entries: [
                  CarriedEntry(
                    parentRef: folder,
                    meta: const {'name': 'tier2', 'tier': 2},
                    data: const {'fields': []},
                    writePolicy: 'owner_only',
                  ),
                ],
              );
            default:
              await vault.createEntry(
                parentRef: folder,
                name: 'queued',
                fields: const [],
              );
          }
        }

        Future<void> unconfirm() => const FlutterSecureStorage().delete(
          key: 'sezam_confirmed_team_genesis:$uid',
        );
        if (operation != 'retry') {
          await unconfirm();
          final before = await db.getAllObjects();
          final calls = net.paths.length;
          await expectLater(change(), throwsA(isA<TeamLogRefused>()));
          expect(await db.getAllObjects(), before);
          expect(net.paths.length, calls);
          // An independent personal tree must remain writable without a pin.
          final personal = await vault.createPersonalFolder(name: 'private');
          await vault.createEntry(
            parentRef: personal.id,
            name: 'private item',
            fields: const [],
          );
          await confirmTeamGenesis(uid, genesis);
        }
        await change();
        await auth.lock();
        await net.settle();
        await db.close();
        await unconfirm();
        final offline = await auth.unlockOffline(
          password: cfg['password'] as String,
        );
        expect(offline.success, isTrue, reason: offline.error);
        await sync.authenticate(
          username: 'bob',
          signingSecretKey: vault.signingSecretKey!,
        );
        await net.settle();
        final queued = await db.getDirtyObjects();
        expect(queued, isNotEmpty);
        if (operation == 'delete') {
          await expectLater(
            vault.keepLocalChange(entry.id, 9),
            throwsA(isA<TeamLogRefused>()),
          );
          expect(await db.getDirtyObjects(), queued);
        }
        // Review 8595ec1 (R10-F): the team rows stay queued and are reported;
        // they no longer hold the rest of the push back.
        final held = await sync.push();
        final left = await db.getDirtyObjects();
        expect(left, isNotEmpty);
        expect(held.errors, hasLength(left.length));
        final queuedById = {for (final row in queued) row['id']: row};
        for (final row in left) {
          expect(row, equals(queuedById[row['id']]));
          expect(held.errors.join(';'), contains(row['id'] as String));
        }
        await confirmTeamGenesis(uid, genesis);
        await vault.reloadData();
        final sent = await sync.push();
        expect(sent.conflicts, 0, reason: sent.errors.join(';'));
        expect(sent.accepted, greaterThan(0));
        expect(await db.getDirtyObjects(), isEmpty);
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: server == null || dir == null
        ? 'run by tests/test_team_log_phone.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

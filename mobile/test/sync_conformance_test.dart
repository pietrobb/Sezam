// Sync conformance (docs/SYNC_SINGLE_SOURCE.md point 4a): the phone driver.
// tests/test_sync_conformance.py runs this file with SEZAM_X3_* set, a
// scenario of tests/conformance/ in config.json. The phone does the
// "client" steps; at every other step it waits (handshake) while Python has
// the account's desktop or the server do it. At the end it settles with the
// desktop and writes what it holds to view.json (path -> password, null for
// a folder), which must match the desktop and the web for the same scenario.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

const _settleRounds = 3;

void main() {
  final serverUrl = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];

  test(
    'the phone runs a conformance scenario',
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
          password: cfg['password'] as String,
          username: cfg['username'] as String,
        );
        expect(c.outcome, ConnectOutcome.connected, reason: c.message);
        await net.settle();
        await vault.reloadData();

        String folder(String? name) => name == null
            ? vault.rootNodeId!
            : vault.allNodes.firstWhere((n) => n.name == name).id;
        String entry(String name) =>
            vault.allEntries.firstWhere((e) => e.name == name).id;
        List<EntryField> fields(String password) => [
          EntryField(key: 'password', value: password, sensitive: true),
        ];

        // Push, then pull. True when nothing is queued or in conflict.
        final said = <String>[];
        Future<bool> syncOnce() async {
          final SyncResult r;
          try {
            r = await sync.sync();
          } on KeyEpochStaleException catch (e) {
            // Another device changed the account keys: the vault screen asks
            // for the password and takes the change over (the desktop's
            // adopt_rotated_key_material, the web's new login).
            said
              ..clear()
              ..add('$e: taken over');
            final adopted = await auth.adoptPasswordChangedElsewhere(
              currentPassword: cfg['password'] as String,
            );
            expect(adopted.success, isTrue, reason: adopted.error);
            await vault.reloadData();
            return false;
          } on SyncIntegrityException catch (e) {
            // A restore is only reported until accept_restore.
            said
              ..clear()
              ..add('$e');
            return false;
          }
          said
            ..clear()
            ..addAll(r.push.errors);
          await vault.reloadData();
          final db = DatabaseService();
          return (await db.getDirtyObjects()).isEmpty &&
              (await db.getSyncConflicts()).isEmpty;
        }

        final steps = (cfg['steps'] as List).cast<Map<String, dynamic>>();
        for (var i = 0; i < steps.length; i++) {
          final step = steps[i];
          if (step['on'] != 'client') {
            await handshake(dir!, 's$i');
            continue;
          }
          switch (step['do']) {
            case 'create_folder':
              await vault.createNode(
                name: step['name'] as String,
                parentRef: folder(step['folder'] as String?),
              );
            case 'create_entry':
              await vault.createEntry(
                parentRef: folder(step['folder'] as String),
                name: step['name'] as String,
                fields: fields(step['password'] as String),
              );
            case 'edit_entry':
              await vault.updateEntry(
                entryId: entry(step['name'] as String),
                fields: fields(step['password'] as String),
              );
            case 'delete_entry':
              await vault.deleteEntry(entry(step['name'] as String));
            case 'sync':
              await syncOnce();
            case 'resolve':
              expect(step['keep'], 'server');
              final conflicts = await DatabaseService().getSyncConflicts();
              expect(conflicts, isNotEmpty, reason: 'nothing to resolve');
              for (final conflict in conflicts) {
                await vault.takeServerVersion(conflict['object_id'] as String);
              }
              await vault.reloadData();
            case 'accept_restore':
              await sync.fullResync(confirmed: true);
              await vault.reloadData();
            default:
              fail('unknown client step $step');
          }
        }

        // Settle: phone, desktop, phone, a fixed number of rounds (Python
        // waits for each); the last must leave nothing behind.
        var quiet = false;
        for (var round = 0; round < _settleRounds; round++) {
          final first = await syncOnce();
          await handshake(dir!, 'settle$round');
          quiet = first && await syncOnce();
        }
        expect(quiet, isTrue, reason: 'sync does not settle: $said');

        final root = vault.rootNodeId!;
        final nodes = {for (final n in vault.allNodes) n.id: n};
        String? path(String id) {
          final parts = <String>[];
          var at = id;
          while (at != root) {
            final node = nodes[at];
            if (node == null) return null;
            parts.add(node.name);
            at = node.parentRef ?? '';
          }
          return parts.reversed.join('/');
        }

        final view = <String, String?>{};
        for (final n in nodes.values) {
          if (n.id == root) continue;
          final p = path(n.id);
          if (p != null && p.isNotEmpty) view[p] = null;
        }
        for (final e in vault.allEntries) {
          final parent = e.parentRef;
          final p = parent == null ? null : path(parent);
          if (p == null) continue;
          view[p.isEmpty ? e.name : '$p/${e.name}'] = e.fields
              .firstWhere((f) => f.key == 'password')
              .value;
        }
        File('$dir/view.json').writeAsStringSync(jsonEncode(view));
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_sync_conformance.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

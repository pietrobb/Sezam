import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';

const root = 'ROOT0000000000000000000000';
const personal = 'PERS0000000000000000000000';
const nested = 'NEST0000000000000000000000';
const shared = 'SHAR0000000000000000000000';

Map<String, VaultNode> _tree() => {
  root: const VaultNode(id: root, name: 'root', dekId: 'ROOTDEK'),
  personal: const VaultNode(
    id: personal,
    name: 'mine',
    parentRef: root,
    dekId: 'PERSDEK',
    personal: true,
  ),
  nested: const VaultNode(
    id: nested,
    name: 'inner',
    parentRef: personal,
    dekId: 'PERSDEK',
  ),
  shared: const VaultNode(
    id: shared,
    name: 'team',
    parentRef: root,
    dekId: 'ROOTDEK',
  ),
};

void main() {
  group('resolveWriteDekId (review item 28)', () {
    final held = {'ROOTDEK', 'PERSDEK', 'TEAMDEK'};

    test('items in a personal subtree never use the root DEK', () {
      for (final parent in [personal, nested]) {
        expect(
          resolveWriteDekId(
            parentRef: parent,
            nodes: _tree(),
            heldDekIds: held,
            rootDekId: 'ROOTDEK',
          ),
          'PERSDEK',
        );
      }
    });

    test('edit inside a personal folder ignores a stale root header', () {
      expect(
        resolveWriteDekId(
          parentRef: nested,
          nodes: _tree(),
          heldDekIds: held,
          rootDekId: 'ROOTDEK',
          existingDekId: 'ROOTDEK',
          existingParentRef: nested,
        ),
        'PERSDEK',
      );
    });

    test('missing personal key fails closed instead of using root', () {
      expect(
        () => resolveWriteDekId(
          parentRef: nested,
          nodes: _tree(),
          heldDekIds: {'ROOTDEK'},
          rootDekId: 'ROOTDEK',
        ),
        throwsStateError,
      );
    });

    test('unknown parent folder fails closed', () {
      expect(
        () => resolveWriteDekId(
          parentRef: 'GONE000000000000000000000X',
          nodes: _tree(),
          heldDekIds: held,
          rootDekId: 'ROOTDEK',
        ),
        throwsStateError,
      );
    });

    test('existing shared item keeps its folder DEK on edit', () {
      expect(
        resolveWriteDekId(
          parentRef: shared,
          nodes: _tree(),
          heldDekIds: held,
          rootDekId: 'ROOTDEK',
          existingDekId: 'TEAMDEK',
          existingParentRef: shared,
        ),
        'TEAMDEK',
      );
      expect(
        resolveWriteDekId(
          parentRef: shared,
          nodes: _tree(),
          heldDekIds: held,
          rootDekId: 'ROOTDEK',
        ),
        'ROOTDEK',
      );
    });

    test('VaultService create/update paths use the resolver', () {
      final source = File('lib/services/vault_service.dart').readAsStringSync();
      // definition + create node/entry, update entry, carried entry (join)
      expect(RegExp(r'_writeDekId\(').allMatches(source).length, 5);
      // Only the root folder itself is encrypted with the root DEK directly.
      expect(
        RegExp(r'final dekId = _rootDekId!;').allMatches(source).length,
        1,
      );
      expect(
        source.split('Future<void> _createRootNode()')[1],
        contains('final dekId = _rootDekId!;'),
      );
    });
  });

  group('sync pushes local changes (review item 29)', () {
    test('never-confirmed local objects are outside the checkpoint hash', () {
      expect(
        isServerConfirmedRow({'queued': 1, 'commit_seq': null}),
        isFalse,
      );
      expect(isServerConfirmedRow({'queued': 1, 'commit_seq': 7}), isTrue);
      expect(isServerConfirmedRow({'queued': 0, 'commit_seq': 7}), isTrue);
    });

    test('Sync button and background sync push before pulling', () {
      final screen = File('lib/screens/vault_screen.dart').readAsStringSync();
      final syncVault = screen
          .split('Future<void> _syncVault()')[1]
          .split('Future<void> _confirmAndRunFullResync()')[0];
      expect(syncVault, contains('_sync.sync()'));
      expect(syncVault.contains('_sync.pull()'), isFalse);

      final auth = File('lib/services/auth_service.dart').readAsStringSync();
      final background = auth
          .split('void _syncInBackground()')[1]
          .split('// ── Server Connect Flow')[0];
      expect(background, contains('_sync.sync()'));
    });

    test('local edit keeps the server-confirmed commit_seq', () {
      final source = File('lib/services/vault_service.dart').readAsStringSync();
      final update = source
          .split('Future<VaultEntry> updateEntry(')[1]
          .split('Future<void> _softDeleteObject(')[0];
      expect(update, contains("commitSeq: storedRow?['commit_seq']"));
    });
  });
}

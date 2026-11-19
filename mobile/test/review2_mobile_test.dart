// Review 2052248 R-E (mobile): finding 4 (connect verifies the password) and
// the medium mobile findings. libsodium and sqflite are not available under
// `flutter test`, so pure helpers run directly and service wiring is checked
// in the source.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';

const _root = 'ROOT0000000000000000000000';
const _team = 'TEAM0000000000000000000000';
const _sub = 'SUBF0000000000000000000000';
const _me = '01ARZ3NDEKTSV4RRFFQ69G5FAV';
const _colleague = '01BX5ZZKBKACTAV9WEVGEMMVRZ';

String _body(String file, String start, String end) {
  final src = File(file).readAsStringSync().replaceAll('\r\n', '\n');
  final from = src.indexOf(start);
  expect(from, greaterThanOrEqualTo(0), reason: start);
  final to = src.indexOf(end, from + start.length);
  return src.substring(from, to < 0 ? src.length : to);
}

Map<String, VaultNode> _tree() => {
  _root: const VaultNode(id: _root, name: 'root', dekId: 'ROOTDEK'),
  _team: const VaultNode(
    id: _team,
    name: 'team',
    parentRef: _root,
    dekId: 'ROOTDEK',
  ),
  _sub: const VaultNode(id: _sub, name: 'sub', parentRef: _team, dekId: 'T1'),
};

Map<String, dynamic> _dekRow(String id, String? folder, {int deleted = 0}) => {
  'id': id,
  'parent_ref': folder,
  'is_deleted': deleted,
};

PullObject _pulled(String type, {required String owner, String? signer}) =>
    PullObject.fromJson({
      'id': '01C00000000000000000000000',
      'object_type': type,
      'payload': '',
      'owner_id': owner,
      'signature_user_id': ?signer,
      'version': 1,
      'commit_seq': 5,
      'payload_hash': '00',
      'modified_at': 0,
    });

void main() {
  group('finding 4: connect verifies the typed password', () {
    const auth = 'lib/services/auth_service.dart';

    test('an unlocked vault still has to prove the password', () {
      final connect = _body(
        auth,
        'Future<ConnectResult> connectToServer(',
        'Future<ConnectResult> _handleBootstrap(',
      );
      expect(
        connect,
        contains('} else if (!await _passwordOpensUnlockedVault(password)) {'),
      );
      final register = _body(
        auth,
        'Future<ConnectResult> registerWithInvitation(',
        'Future<bool> pollForApproval(',
      );
      expect(register, contains('_passwordOpensUnlockedVault(password)'));
      expect(register, contains('ConnectOutcome.wrongPassword'));
    });

    test('the check compares the derived KEK with the vault KEK', () {
      final check = _body(
        auth,
        'Future<bool> _passwordOpensUnlockedVault(',
        'Future<void> _refreshBiometricKek(',
      );
      expect(check, contains('_deriveLocalKek('));
      expect(check, contains('_bytesEqual(candidate, current)'));
      expect(check, contains('_bytesEqual(kek, current)'));
    });

    test('no keypair upload with a proof from another password', () {
      final upload = _body(
        auth,
        'Future<void> _uploadKeypairToServer(',
        'typedef ConnectProgressCallback',
      );
      final guard = upload.indexOf(
        '_bytesEqual(Uint8List.sublistView(derived, 0, 32), kek)',
      );
      expect(guard, greaterThanOrEqualTo(0));
      expect(guard, lessThan(upload.indexOf('_sync.uploadKeypair(')));
    });
  });

  group('new items use the folder DEK, never the root DEK', () {
    final held = {'ROOTDEK', 'T1', 'T2', 'TIER2'};

    test('the folder DEK and its newest re-key replacement are found', () {
      final folders = folderDekIdsFrom(
        dekRows: [
          _dekRow('T1', _team),
          _dekRow('T2', _team),
          _dekRow('GONE', _sub, deleted: 1),
          _dekRow('NOTHELD', _sub),
          _dekRow('ROOTDEK', null),
        ],
        heldDekIds: held,
        tier2DekIds: const {},
      );
      expect(folders, {_team: 'T2'});
    });

    test('a tier-2 entry DEK is never a folder DEK', () {
      final folders = folderDekIdsFrom(
        dekRows: [_dekRow('T1', _team), _dekRow('TIER2', _team)],
        heldDekIds: held,
        tier2DekIds: const {'TIER2'},
      );
      expect(folders, {_team: 'T1'});
    });

    test(
      'new item in a team folder (and its subfolder) uses the folder DEK',
      () {
        for (final parent in [_team, _sub]) {
          expect(
            resolveWriteDekId(
              parentRef: parent,
              nodes: _tree(),
              heldDekIds: held,
              rootDekId: 'ROOTDEK',
              folderDekIds: const {_team: 'T1'},
            ),
            'T1',
          );
        }
        // The nearest folder wins.
        expect(
          resolveWriteDekId(
            parentRef: _sub,
            nodes: _tree(),
            heldDekIds: held,
            rootDekId: 'ROOTDEK',
            folderDekIds: const {_team: 'T1', _sub: 'T2'},
          ),
          'T2',
        );
        // No folder DEK we hold: root DEK.
        expect(
          resolveWriteDekId(
            parentRef: _team,
            nodes: _tree(),
            heldDekIds: {'ROOTDEK'},
            rootDekId: 'ROOTDEK',
            folderDekIds: const {_team: 'T1'},
          ),
          'ROOTDEK',
        );
      },
    );

    test('the vault feeds the resolver and keeps the desktop tier', () {
      final vault = File(
        'lib/services/vault_service.dart',
      ).readAsStringSync().replaceAll('\r\n', '\n');
      expect(vault, contains('folderDekIds: _folderDekIds,'));
      expect(vault, contains("entry.tier == 2"));
      expect(vault, contains("'tier': existing.tier"));
      final entry = VaultEntry.fromJson('E', {'name': 'x', 'tier': 2});
      expect(entry.tier, 2);
    });
  });

  group('DEK ownership comes from the verified signature', () {
    test('a forged owner_id on a DEK is ignored', () {
      expect(
        verifiedOwnerId(_pulled('dek', owner: _me, signer: _colleague)),
        _colleague,
      );
      expect(
        verifiedOwnerId(_pulled('dek', owner: _colleague, signer: _me)),
        _me,
      );
      // Without signature_user_id the signature was checked against owner_id.
      expect(verifiedOwnerId(_pulled('dek', owner: _me)), _me);
      // Entries keep their owner (a shared entry can be edited by others).
      expect(
        verifiedOwnerId(_pulled('entry', owner: _me, signer: _colleague)),
        _me,
      );
    });

    test('pull stores the verified owner', () {
      final sync = File(
        'lib/services/sync_service.dart',
      ).readAsStringSync().replaceAll('\r\n', '\n');
      expect(sync, contains("'owner_id': verifiedOwnerId(pullObj),"));
      expect(sync, isNot(contains("'owner_id': pullObj.ownerId,")));
    });
  });

  test('a failed unlock leaves the vault fully locked', () {
    final unlock = _body(
      'lib/services/vault_service.dart',
      'Future<void> unlock({',
      'void lock() {',
    );
    final guarded = unlock.indexOf('try {');
    expect(guarded, greaterThanOrEqualTo(0));
    expect(guarded, lessThan(unlock.indexOf('await _loadDEKs();')));
    expect(unlock, contains('lock();\n      rethrow;'));
  });

  group('conflict dialog choices work per object', () {
    test('the verified server row survives the round trip', () {
      final signature = Uint8List.fromList([1, 2, 3]);
      final payload = Uint8List.fromList([9, 9]);
      final row = decodeConflictServerRow(
        encodeConflictServerRow({
          'id': 'E',
          'object_type': 'entry',
          'payload': payload,
          'owner_id': _colleague,
          'parent_ref': _team,
          'version': 7,
          'commit_seq': 42,
          'is_deleted': 0,
          'payload_hash': 'ab',
          'client_signature': signature,
          'write_policy': 'shared',
          'access_level': 'write',
        }),
        payload,
      );
      expect(row['client_signature'], signature);
      expect(row['payload'], payload);
      expect(row['version'], 7);
      expect(row['commit_seq'], 42);
      expect(row['base_version'], 7);
      expect(row['owner_id'], _colleague);
      expect(jsonEncode(row['write_policy']), '"shared"');
    });

    test('pull keeps the server row; DB v6 adds the column', () {
      final db = File(
        'lib/services/database_service.dart',
      ).readAsStringSync().replaceAll('\r\n', '\n');
      expect(db, contains("'server_row': encodeConflictServerRow(object),"));
      expect(db, contains('if (oldVersion < 6 && oldVersion >= 3) {'));
      expect(db, contains('ALTER TABLE sync_conflicts ADD COLUMN server_row'));
    });

    test('keep mine rebases on the server version; server takes one copy', () {
      final vault = File(
        'lib/services/vault_service.dart',
      ).readAsStringSync().replaceAll('\r\n', '\n');
      final keep = _body(
        'lib/services/vault_service.dart',
        'Future<bool> keepLocalChange(',
        'Future<bool> takeServerVersion(',
      );
      expect(keep, contains('final version = serverVersion + 1;'));
      expect(
        keep,
        contains('rebaseOn: (version: serverVersion, hash: serverHash)'),
      );
      expect(
        vault,
        contains('final newVersion = (rebaseOn?.version ?? existing.version) + 1;'),
      );
      expect(vault, contains('_db.takeServerConflictCopy(objectId)'));

      final screen = _body(
        'lib/screens/vault_screen.dart',
        'Future<void> _resolveConflicts(',
        'Future<void> _confirmAndRunFullResync()',
      );
      expect(screen, contains('_vault.takeServerVersion(conflict.id)'));
      expect(
        screen,
        contains('_vault.keepLocalChange(conflict.id, conflict.serverVersion)'),
      );
      expect(screen, contains('await _sync.push();'));
    });
  });

  test('mobile bootstrap admin stays admin offline', () {
    final bootstrap = _body(
      'lib/services/auth_service.dart',
      'Future<ConnectResult> _handleBootstrap(',
      'Future<ConnectResult> _handleExistingServer(',
    );
    expect(bootstrap, contains('await prefs.setBool(_isAdminKey, true);'));
    final existing = _body(
      'lib/services/auth_service.dart',
      'Future<ConnectResult> _handleExistingServer(',
      'Future<ConnectResult> registerWithInvitation(',
    );
    expect(existing, contains('_isAdminKey,'));
  });

  group('an edit from an old snapshot never overwrites a newer version', () {
    const v4 = VaultEntry(id: 'E', name: 'x', fields: [], version: 4);

    test('stale base is a typed error', () {
      expect(
        () => ensureEditBase(v4, 3),
        throwsA(
          isA<StaleEntryEditException>()
              .having((e) => e.expectedVersion, 'expected', 3)
              .having((e) => e.currentVersion, 'current', 4),
        ),
      );
      ensureEditBase(v4, 4);
      ensureEditBase(v4, null);
    });

    test('the editor passes the version it shows', () {
      final screen = File(
        'lib/screens/entry_detail_screen.dart',
      ).readAsStringSync().replaceAll('\r\n', '\n');
      expect(screen, contains('final baseVersion = _entry!.version;'));
      expect(screen, contains('expectedVersion: baseVersion,'));
      expect(screen, contains('on StaleEntryEditException'));
      final update = _body(
        'lib/services/vault_service.dart',
        'Future<VaultEntry> updateEntry(',
        'Future<bool> keepLocalChange(',
      );
      expect(update, contains('ensureEditBase(existing, expectedVersion);'));
    });
  });

  test('iOS covers the app switcher snapshot', () {
    final delegate = File(
      'ios/Runner/AppDelegate.swift',
    ).readAsStringSync().replaceAll('\r\n', '\n');
    expect(delegate, contains('override func applicationWillResignActive('));
    expect(delegate, contains('window.addSubview(cover)'));
    expect(delegate, contains('override func applicationDidBecomeActive('));
    expect(delegate, contains('privacyCover?.removeFromSuperview()'));
  });
}

// Lockout review 2026-11-08 M4 (mobile): unsent changes replaced by a full
// resync were only written into the app sandbox, where the user cannot reach
// them and nothing could import them again.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/unsent_changes.dart';

String _src(String file) => File(file).readAsStringSync();

String _body(String file, String start, String end) {
  final src = _src(file);
  final from = src.indexOf(start);
  expect(from, greaterThanOrEqualTo(0), reason: start);
  final to = src.indexOf(end, from + start.length);
  return src.substring(from, to < 0 ? src.length : to);
}

Map<String, dynamic> _obj(
  String id,
  String type, {
  int version = 1,
  String? parent,
  int deleted = 0,
  EntryBase? base,
}) => {
  'id': id,
  'object_type': type,
  'version': version,
  'parent_ref': parent,
  'is_deleted': deleted,
  'base_version': base?.version,
  'base_hash': base?.hash,
  'payload': base64Encode([1, 2, 3]),
};

const EntryBase _v3 = (version: 3, hash: 'h3');
const EntryBase _v4 = (version: 4, hash: 'h4');

void main() {
  group('export file', () {
    test('round-trips the exported rows', () {
      final rows = [_obj('E1', 'entry'), _obj('N1', 'node')];
      final parsed = parseUnsentExport(encodeUnsentExport(rows));
      expect(parsed.map((o) => o['id']), ['E1', 'N1']);
      expect(parsed.first['payload'], rows.first['payload']);
    });

    test('older sezam_dirty exports without a format tag still import', () {
      final legacy = utf8.encode(
        jsonEncode({
          'exported_at': '2026-01-01T00:00:00Z',
          'reason': 'full_resync',
          'objects': [_obj('E1', 'entry')],
        }),
      );
      expect(parseUnsentExport(Uint8List.fromList(legacy)), hasLength(1));
    });

    test('anything else is refused', () {
      for (final bad in [
        'not json',
        '[]',
        '{"objects": "x"}',
        '{"objects": [{"id": "E1"}]}',
      ]) {
        expect(
          () => parseUnsentExport(Uint8List.fromList(utf8.encode(bad))),
          throwsFormatException,
          reason: bad,
        );
      }
      expect(
        () => parseUnsentExport(Uint8List(maxUnsentExportBytes + 1)),
        throwsFormatException,
      );
    });
  });

  group('re-apply plan', () {
    test('folders come before what is inside them, entries last', () {
      final plan = planUnsentReapply(
        [
          _obj('E1', 'entry', parent: 'N2'),
          _obj('N2', 'node', parent: 'N1'),
          _obj('N1', 'node', parent: 'ROOT'),
        ],
        liveNodeIds: {'ROOT'},
        liveEntryBases: {},
      );
      expect(plan.map((s) => s.id), ['N1', 'N2', 'E1']);
      expect(plan.map((s) => s.action), [
        UnsentAction.createNode,
        UnsentAction.createNode,
        UnsentAction.createEntry,
      ]);
    });

    test('an edit overwrites only an entry nobody changed since', () {
      final plan = planUnsentReapply(
        [
          _obj('E1', 'entry', version: 4, base: _v3),
          _obj('E2', 'entry', version: 4, base: _v3),
        ],
        liveNodeIds: {},
        liveEntryBases: {'E1': _v3, 'E2': _v4},
      );
      expect(plan[0].action, UnsentAction.updateEntry);
      // Another device committed E2 since: the edit stays on v3, the push
      // is the conflict.
      expect(plan[1].action, UnsentAction.updateOnItsBase);
    });

    test('more offline edits than the other device never overwrite', () {
      // Capability review run 52: server v3, this phone edits twice offline
      // (dirty v5), another device edits once (live v4). Comparing versions
      // (4 < 5) overwrote the other device's edit.
      final plan = planUnsentReapply(
        [_obj('E1', 'entry', version: 5, base: _v3)],
        liveNodeIds: {},
        liveEntryBases: {'E1': _v4},
      );
      expect(plan.single.action, UnsentAction.updateOnItsBase);
    });

    test('the same number with other content is another version', () {
      // Stateful seed run 44260509986: the entry the edit was made on (v4)
      // was deleted and collected by tombstone GC; another device's older
      // edit came back as a new v4. commit_seq could not tell; the hash does.
      final plan = planUnsentReapply(
        [_obj('E1', 'entry', version: 5, base: _v4)],
        liveNodeIds: {},
        liveEntryBases: {'E1': (version: 4, hash: 'other')},
      );
      expect(plan.single.action, UnsentAction.updateOnItsBase);
    });

    test('an export without a confirmed base never overwrites', () {
      // Never-synced rows and older exports carry no base.
      final plan = planUnsentReapply(
        [
          _obj('E1', 'entry', version: 9),
          {..._obj('E2', 'entry', version: 9)}..remove('base_hash'),
        ],
        liveNodeIds: {},
        liveEntryBases: {'E1': null, 'E2': _v3},
      );
      expect(plan.map((s) => s.action), [
        UnsentAction.copyEntry,
        UnsentAction.copyEntry,
      ]);
    });

    test('a live entry with unsent edits of its own is never overwritten', () {
      // Capability review run 55: the re-apply set E1 to the export (seq 10),
      // the user edited it again offline (still seq 10, dirty), then imported
      // the same export from Settings. Matching seq overwrote the newer edit.
      final live = liveEntryConfirmedBases([
        {'id': 'E1', 'base_version': 3, 'base_hash': 'h3', 'queued': 1},
        {'id': 'E2', 'base_version': 3, 'base_hash': 'h3', 'queued': 0},
        {'id': 'E3', 'base_version': null, 'base_hash': null, 'queued': 0},
      ]);
      expect(live, {'E1': null, 'E2': _v3, 'E3': null});
      final plan = planUnsentReapply(
        [
          _obj('E1', 'entry', version: 4, base: _v3),
          _obj('E2', 'entry', version: 4, base: _v3),
        ],
        liveNodeIds: {},
        liveEntryBases: live,
      );
      expect(plan.map((s) => s.action), [
        UnsentAction.copyEntry,
        UnsentAction.updateEntry,
      ]);
    });

    test('deletes, keys, shares and folder cycles are not replayed', () {
      final plan = planUnsentReapply(
        [
          _obj('E1', 'entry', deleted: 1),
          _obj('D1', 'dek'),
          _obj('S1', 'share'),
          _obj('N1', 'node', parent: 'N2'),
          _obj('N2', 'node', parent: 'N1'),
          _obj('N3', 'node'),
        ],
        liveNodeIds: {'N3'},
        liveEntryBases: {},
      );
      expect(plan.every((s) => s.action == UnsentAction.skip), isTrue);
      expect(plan, hasLength(6));
    });
  });

  test('same content is recognised, so importing twice adds nothing', () {
    final field = EntryField.fromJson({
      'label': 'password',
      'type': 'password',
      'value': 'x',
    });
    final a = VaultEntry(id: 'A', name: 'Bank', fields: [field], tags: ['t']);
    final b = VaultEntry(id: 'B', name: 'Bank', fields: [field], tags: ['t']);
    final copy = VaultEntry(
      id: 'C',
      name: 'Bank (unsent copy)',
      fields: [field],
      tags: ['t'],
    );
    expect(sameEntryContent(a, b), isTrue);
    expect(sameEntryContent(copy, b, asName: 'Bank (unsent copy)'), isTrue);
    expect(sameEntryContent(copy, b), isFalse);
    final edited = VaultEntry(id: 'B', name: 'Bank', fields: [], tags: ['t']);
    expect(sameEntryContent(a, edited), isFalse);
  });

  group('wiring', () {
    test('full resync puts the unsent changes back after the pull', () {
      final resync = _body(
        'lib/services/sync_service.dart',
        'Future<FullResyncResult> fullResync(',
        'return FullResyncResult(',
      );
      final pull = resync.indexOf('_pull(fullResync: true)');
      final reapply = resync.indexOf('reapplyUnsentChanges(');
      expect(pull, greaterThan(0));
      expect(reapply, greaterThan(pull));
    });

    test('the re-apply reads each live entry\'s base from its DB row', () {
      // In-memory entries keep commit_seq after a reload even when dirty.
      final reapply = _body(
        'lib/services/vault_service.dart',
        'Future<UnsentReapplyResult> reapplyUnsentChanges(',
        'final newIds = <String, String>{};',
      );
      expect(reapply, contains('liveEntryConfirmedBases('));
      expect(reapply, contains("_db.getObjectsByType('entry')"));
      expect(reapply, isNot(contains('e.id: e.commitSeq')));
    });

    test('Android saves and opens files through the document picker', () {
      final kt = _src(
        'android/app/src/main/kotlin/sk/sezam/sezam_mobile/MainActivity.kt',
      );
      expect(kt, contains('"sk.sezam/files"'));
      expect(kt, contains('ActivityResultContracts.CreateDocument'));
      expect(kt, contains('ActivityResultContracts.OpenDocument'));
      final dart = _src('lib/services/document_service.dart');
      expect(dart, contains("MethodChannel('sk.sezam/files')"));
    });

    test('the user can save the backup and import it again', () {
      final screen = _src('lib/screens/vault_screen.dart');
      expect(screen, contains('showUnsentChangesResult('));
      final dialog = _src('lib/widgets/unsent_changes_dialog.dart');
      expect(dialog, contains('saveDocument('));
      final settings = _src('lib/screens/settings_screen.dart');
      expect(settings, contains('onTap: _saveUnsentBackup'));
      expect(settings, contains('onTap: _importUnsentChanges'));
      final import = _body(
        'lib/screens/settings_screen.dart',
        'Future<void> _importUnsentChanges()',
        '// ── Prompt helpers',
      );
      expect(import, contains('parseUnsentExport('));
      expect(import, contains('reapplyUnsentChanges('));
    });
  });
}

// Review d615826 (mobile): `.sezam-key` exports (wrapped keypair and salt,
// enough for an offline password guess) and unsent-changes exports were
// written to Documents, which iOS backs up to iCloud/iTunes. They now go to
// Application Support/exports, excluded from backups on iOS, and older
// exports are moved there out of Documents.

import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:sezam_mobile/services/database_service.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late Directory root;
  late Directory docs;
  late Directory support;

  setUp(() {
    root = Directory.systemTemp.createTempSync('sezam_exports');
    docs = Directory(p.join(root.path, 'Documents'))..createSync();
    support = Directory(p.join(root.path, 'Support'))..createSync();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
          const MethodChannel('plugins.flutter.io/path_provider'),
          (call) async => switch (call.method) {
            'getApplicationDocumentsDirectory' => docs.path,
            'getApplicationSupportDirectory' => support.path,
            _ => null,
          },
        );
  });

  tearDown(() => root.deleteSync(recursive: true));

  test('exports live outside Documents and old ones are moved out', () async {
    File(p.join(docs.path, 'sezam-1.sezam-key')).writeAsStringSync('key');
    File(p.join(docs.path, 'sezam_unsent_x.json')).writeAsStringSync('u');
    File(p.join(docs.path, 'sezam_dirty_y.json')).writeAsStringSync('d');
    File(p.join(docs.path, 'notes.json')).writeAsStringSync('other');

    final dir = await DatabaseService.exportDirectory();

    expect(p.isWithin(support.path, dir.path), isTrue);
    expect(
      docs.listSync().map((e) => p.basename(e.path)).toList(),
      ['notes.json'],
    );
    expect(
      dir.listSync().map((e) => p.basename(e.path)).toSet(),
      {'sezam-1.sezam-key', 'sezam_unsent_x.json', 'sezam_dirty_y.json'},
    );
  });

  test('moving never overwrites an export already in place', () {
    final target = Directory(p.join(support.path, 'exports'))..createSync();
    File(p.join(docs.path, 'sezam-1.sezam-key')).writeAsStringSync('old');
    File(p.join(target.path, 'sezam-1.sezam-key')).writeAsStringSync('new');

    moveLegacyExports(docs.path, target.path);

    expect(
      File(p.join(target.path, 'sezam-1.sezam-key')).readAsStringSync(),
      'new',
    );
    expect(File(p.join(docs.path, 'sezam-1.sezam-key')).existsSync(), isTrue);
  });

  test('every export is written through the excluded directory', () {
    for (final path in [
      'lib/services/auth_service.dart',
      'lib/services/sync_service.dart',
    ]) {
      final source = File(path).readAsStringSync();
      expect(source, isNot(contains('getApplicationDocumentsDirectory')),
          reason: path);
      expect(source, contains('DatabaseService.exportDirectory()'),
          reason: path);
    }
    final db = File('lib/services/database_service.dart').readAsStringSync();
    final body = db.split('static Future<Directory> exportDirectory()')[1];
    expect(body, contains("invokeMethod('excludeFromBackup', dir.path)"));
    expect(body.split('moveLegacyExports')[0], isNot(contains('catch')),
        reason: 'fails closed when the backup exclusion fails');
  });
}

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:sezam_mobile/services/database_service.dart';

void main() {
  test('legacy Documents vault DB moves with its side files', () {
    final root = Directory.systemTemp.createTempSync('sezam_db_move');
    addTearDown(() => root.deleteSync(recursive: true));
    final docs = Directory(p.join(root.path, 'Documents'))..createSync();
    final vault = Directory(p.join(root.path, 'Support', 'vault'))
      ..createSync(recursive: true);
    final legacy = p.join(docs.path, 'sezam_vault.db');
    final target = p.join(vault.path, 'sezam_vault.db');
    File(legacy).writeAsStringSync('db');
    File('$legacy-wal').writeAsStringSync('wal');

    migrateLegacyVaultDb(legacy, target);

    expect(File(target).readAsStringSync(), 'db');
    expect(File('$target-wal').readAsStringSync(), 'wal');
    expect(File(legacy).existsSync(), isFalse);
    expect(File('$legacy-wal').existsSync(), isFalse);
  });

  test('migration never overwrites an existing vault DB', () {
    final root = Directory.systemTemp.createTempSync('sezam_db_keep');
    addTearDown(() => root.deleteSync(recursive: true));
    final legacy = p.join(root.path, 'old.db');
    final target = p.join(root.path, 'new.db');
    File(legacy).writeAsStringSync('stale');
    File(target).writeAsStringSync('current');

    migrateLegacyVaultDb(legacy, target);

    expect(File(target).readAsStringSync(), 'current');
    expect(File(legacy).existsSync(), isTrue);
  });

  test('vault DB is not kept in Documents', () {
    final source =
        File('lib/services/database_service.dart').readAsStringSync();
    final body = source.split('static Future<String> vaultDbPath()')[1];
    expect(body, contains('getApplicationSupportDirectory()'));
    expect(body, contains("invokeMethod('excludeFromBackup'"));
    expect(
      RegExp(r"getApplicationDocumentsDirectory\(\)").allMatches(source).length,
      1, // only the legacy migration source
    );
    final delegate = File('ios/Runner/AppDelegate.swift').readAsStringSync();
    expect(delegate, contains('isExcludedFromBackup = true'));
    expect(delegate, contains('"sk.sezam/storage"'));
  });

  test('Android disables backup and device transfer', () {
    final manifest =
        File('android/app/src/main/AndroidManifest.xml').readAsStringSync();
    expect(manifest, contains('android:allowBackup="false"'));
    expect(manifest, contains('android:fullBackupContent="false"'));
    expect(
      manifest,
      contains('android:dataExtractionRules="@xml/data_extraction_rules"'),
    );
    final rules = File(
      'android/app/src/main/res/xml/data_extraction_rules.xml',
    ).readAsStringSync();
    expect(rules, contains('<cloud-backup>'));
    expect(rules, contains('<device-transfer>'));
  });
}

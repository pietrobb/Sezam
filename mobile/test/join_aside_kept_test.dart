// Review e4cd15a S4: the first start of the version with the join journal
// deleted every `*.before-join` file it found without a journal. A join
// interrupted in the version before (no journal yet) leaves exactly that: the
// only copy of the phone's own vault. Those files are now kept; a join past
// its commit point says so in the journal, and only then is the set-aside
// copy deleted.

import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/database_service.dart';

import 'support/real_server_phone.dart';

void main() {
  late Directory appDir;
  final secure = <String, String>{};

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_join_aside_');
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

  tearDownAll(() => appDir.delete(recursive: true));

  List<String> asideFiles(String dbPath) {
    final dir = File(dbPath).parent;
    final name = File(dbPath).uri.pathSegments.last;
    return dir
        .listSync()
        .map((f) => f.uri.pathSegments.last)
        .where((n) => n.startsWith(name) && n.contains('.before-join'))
        .toList()
      ..sort();
  }

  test('set-aside vault of a pre-journal join is kept, not deleted', () async {
    final dbPath = await DatabaseService.vaultDbPath();
    File(dbPath).parent.createSync(recursive: true);
    // What the version before the journal leaves when killed mid-join.
    File('$dbPath.before-join').writeAsStringSync('the only copy');
    File('$dbPath-wal.before-join').writeAsStringSync('its wal');
    secure.remove('sezam_join_restore');

    await AuthService().recoverInterruptedJoin(); // as the app starts

    final left = asideFiles(dbPath);
    expect(left, hasLength(2), reason: '$left');
    expect(left.every((n) => n.contains('.before-join.kept-')), isTrue);
    final main = left.firstWhere((n) => !n.contains('-wal'));
    expect(
      File('${File(dbPath).parent.path}/$main').readAsStringSync(),
      'the only copy',
    );
    // Kept files no longer count as an interrupted join.
    await AuthService().recoverInterruptedJoin();
    expect(asideFiles(dbPath), left);
    for (final n in left) {
      File('${File(dbPath).parent.path}/$n').deleteSync();
    }
  });

  // Review 526419e N7: the kept vault was only named in a debug log.
  test('a kept vault is listed for settings and can be deleted', () async {
    final dbPath = await DatabaseService.vaultDbPath();
    File(dbPath).parent.createSync(recursive: true);
    File('$dbPath.before-join').writeAsStringSync('own vault');
    File('$dbPath-wal.before-join').writeAsStringSync('its wal');
    File('${dbPath}x.before-join.kept-1').writeAsStringSync('not ours');
    secure.remove('sezam_join_restore');
    final auth = AuthService();
    expect(await auth.keptAsideVaults(), isEmpty);

    await auth.recoverInterruptedJoin();

    final kept = await auth.keptAsideVaults();
    expect(kept, hasLength(1));
    expect(File(kept.single.path).readAsStringSync(), 'own vault');
    expect(kept.single.files, hasLength(2));
    expect(
      DateTime.now().difference(kept.single.keptAt).inMinutes,
      lessThan(5),
    );

    auth.deleteKeptAsideVault(kept.single);
    expect(await auth.keptAsideVaults(), isEmpty);
    expect(File('${dbPath}x.before-join.kept-1').existsSync(), isTrue);
    File('${dbPath}x.before-join.kept-1').deleteSync();
    expect(asideFiles(dbPath), isEmpty);
  });

  test('a join past its commit point deletes its set-aside copy', () async {
    final dbPath = await DatabaseService.vaultDbPath();
    File('$dbPath.before-join').writeAsStringSync('carried over already');
    secure['sezam_join_restore'] = 'committed';

    await AuthService().recoverInterruptedJoin();

    expect(asideFiles(dbPath), isEmpty);
    expect(secure.containsKey('sezam_join_restore'), isFalse);
  });
}

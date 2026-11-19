// Sync redesign S3 (docs/SYNC_SINGLE_SOURCE.md point 3): the outbox, not an
// is_dirty flag, says what waits for the server. A v8 database moves its
// dirty rows into the outbox in their old send order; clean rows stay out.

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

import 'support/real_server_phone.dart';

void main() {
  late Directory appDir;

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_s3_outbox_');
    await setUpPhone(appDir.path);
  });

  tearDownAll(() async {
    await DatabaseService().close();
    await appDir.delete(recursive: true);
  });

  test('a v8 database moves its dirty rows into the outbox', () async {
    final path = await DatabaseService.vaultDbPath();
    final old = await databaseFactory.openDatabase(
      path,
      options: OpenDatabaseOptions(
        version: 8,
        onCreate: (db, _) async {
          await db.execute('''
            CREATE TABLE vault_objects (
              id TEXT PRIMARY KEY, object_type TEXT NOT NULL,
              payload BLOB NOT NULL, owner_id TEXT, parent_ref TEXT,
              target_user_id TEXT, version INTEGER NOT NULL DEFAULT 1,
              commit_seq INTEGER, is_dirty INTEGER NOT NULL DEFAULT 0,
              is_deleted INTEGER NOT NULL DEFAULT 0, payload_hash TEXT,
              client_signature BLOB, modified_at INTEGER, write_policy TEXT,
              access_level TEXT, signer_id TEXT, base_version INTEGER,
              base_hash TEXT)
          ''');
          await db.execute(
            'CREATE INDEX idx_vo_dirty ON vault_objects(is_dirty)',
          );
          await db.execute(
            'CREATE TABLE sync_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)',
          );
          await db.execute(
            'CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)',
          );
          for (final (id, dirty, at) in [
            ('b', 1, 2),
            ('clean', 0, 1),
            ('a', 1, 3),
          ]) {
            await db.insert('vault_objects', {
              'id': id,
              'object_type': 'entry',
              'payload': Uint8List(4),
              'is_dirty': dirty,
              'modified_at': at,
            });
          }
        },
      ),
    );
    await old.close();

    final db = DatabaseService();
    final queued = await db.getDirtyObjects();
    expect(queued.map((r) => r['id']), ['b', 'a']);
    expect((await db.getObject('clean'))!['queued'], 0);
    expect((await db.getObject('a'))!['queued'], 1);
  });

  // Capability run 359: the rejoin's stage waited in the settings table,
  // beside the outbox. A v9 database moves it into the outbox.
  test('a v9 database moves a rejoin under way into the outbox', () async {
    await DatabaseService().close();
    final path = await DatabaseService.vaultDbPath();
    await databaseFactory.deleteDatabase(path);
    final old = await databaseFactory.openDatabase(
      path,
      options: OpenDatabaseOptions(
        version: 9,
        onCreate: (db, _) async {
          await db.execute('''
            CREATE TABLE vault_objects (
              id TEXT PRIMARY KEY, object_type TEXT NOT NULL,
              payload BLOB NOT NULL, owner_id TEXT, parent_ref TEXT,
              target_user_id TEXT, version INTEGER NOT NULL DEFAULT 1,
              commit_seq INTEGER, is_dirty INTEGER NOT NULL DEFAULT 0,
              is_deleted INTEGER NOT NULL DEFAULT 0, payload_hash TEXT,
              client_signature BLOB, modified_at INTEGER, write_policy TEXT,
              access_level TEXT, signer_id TEXT, base_version INTEGER,
              base_hash TEXT)
          ''');
          await db.execute(
            'CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)',
          );
          await db.execute('''
            CREATE TABLE outbox (
              seq INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL,
              object_id TEXT, UNIQUE (kind, object_id))
          ''');
          await db.insert('outbox', {'kind': 'write', 'object_id': 'E1'});
          await db.insert('settings', {
            'key': 'pending_server_rejoin',
            'value': 'resync',
          });
        },
      ),
    );
    await old.close();

    final db = DatabaseService();
    expect(await db.outboxOperation(outboxRejoin), 'resync');
    expect(await db.getSetting('pending_server_rejoin'), isNull);
    final raw = await db.database;
    Future<List<String>> kinds() async => [
      for (final row in await raw.query('outbox', orderBy: 'seq'))
        '${row['kind']}:${row['body']}',
    ];
    expect(await kinds(), ['write:null', 'rejoin:resync']);
    // A later stage keeps its place in the queue; done, it leaves.
    await db.putOutboxOperation(outboxRejoin, 'rejoin');
    await db.putOutboxOperation(outboxRejoin, 'resync');
    expect(await kinds(), ['write:null', 'rejoin:resync']);
    await db.dropOutboxOperation(outboxRejoin);
    expect(await db.outboxOperation(outboxRejoin), isNull);
  });
}

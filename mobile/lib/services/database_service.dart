/// Sezam DatabaseService — SQLite local vault storage.
///
/// Schema mirrors the server's vault_objects table for seamless sync.
/// All payloads are stored encrypted (E2E envelope blobs).

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/services.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:sqflite/sqflite.dart';

import 'sync_core.dart';

/// Moves a vault DB (and its SQLite side files) from the legacy Documents
/// location to [newPath]. No-op when there is nothing to move or the new DB
/// already exists (never overwrites).
void migrateLegacyVaultDb(String legacyPath, String newPath) {
  if (!File(legacyPath).existsSync() || File(newPath).existsSync()) return;
  for (final suffix in const ['-journal', '-wal', '-shm', '']) {
    final source = File('$legacyPath$suffix');
    if (source.existsSync()) source.renameSync('$newPath$suffix');
  }
}

/// A `.sezam-key` or unsent-changes export this app writes.
bool isExportFileName(String name) =>
    (name.startsWith('sezam-') && name.endsWith('.sezam-key')) ||
    (name.endsWith('.json') &&
        (name.startsWith('sezam_unsent_') || name.startsWith('sezam_dirty_')));

/// Moves the exports an older version wrote to Documents into [exportDir].
/// Never overwrites.
void moveLegacyExports(String documentsDir, String exportDir) {
  final docs = Directory(documentsDir);
  if (!docs.existsSync() || p.equals(documentsDir, exportDir)) return;
  for (final file in docs.listSync().whereType<File>()) {
    final name = p.basename(file.path);
    final target = p.join(exportDir, name);
    if (isExportFileName(name) && !File(target).existsSync()) {
      file.renameSync(target);
    }
  }
}

/// The accepted copy is now the server's: it becomes the row's base.
Map<String, Object?> buildMarkCleanUpdate(
  int? commitSeq, {
  required int version,
  required String? payloadHash,
}) => {
  if (commitSeq != null) 'commit_seq': commitSeq,
  'base_version': version,
  'base_hash': payloadHash,
};

/// docs/SYNC_SINGLE_SOURCE.md point 3: an object has an unsent change exactly
/// when the outbox holds a write for it; the row carries no flag. Rows read
/// through [DatabaseService] carry it as the computed column `queued` (0/1).
const queuedSql =
    "EXISTS (SELECT 1 FROM outbox o WHERE o.kind = 'write' "
    'AND o.object_id = vault_objects.id)';
const _rowColumns = ['*', '$queuedSql AS queued'];

/// The account's rejoin to a server restored from an older backup
/// (AuthService.rejoinServer); its body is the stage ('rejoin', 'resync').
const outboxRejoin = 'rejoin';

/// A row as the verified server copy: its own base, nothing queued.
Map<String, Object?> asServerCopy(Map<String, Object?> row) => {
  for (final entry in row.entries)
    if (entry.key != 'queued') entry.key: entry.value,
  'base_version': row['version'],
  'base_hash': row['payload_hash'],
};

Future<void> _queueWrite(DatabaseExecutor db, String id) => db.rawInsert(
  "INSERT OR IGNORE INTO outbox (kind, object_id) VALUES ('write', ?)",
  [id],
);

Future<void> _dropWrite(DatabaseExecutor db, String id) => db.delete(
  'outbox',
  where: "kind = 'write' AND object_id = ?",
  whereArgs: [id],
);

/// What [DatabaseService.rememberSent] kept on a write's outbox row.
List<({int version, String hash})> decodeSentVersions(String? body) {
  if (body == null) return const [];
  try {
    return [
      for (final item in jsonDecode(body) as List)
        if (item is List && item.length == 2 && item[0] is int && item[1] is String)
          (version: item[0] as int, hash: item[1] as String),
    ];
  } on FormatException {
    return const [];
  }
}

/// Review c78fd19 (as the web): a delta pull never takes a folder or entry
/// back to an older version than the copy the phone holds of the server, nor
/// to another copy of that version (equivocation); the held copy stays, as on
/// the desktop: the shared core decides (core/src/pull.rs against_held). A
/// queued change meets every copy in decide_pulled instead, and a tombstone
/// the server collected below its GC floor may come back (stateful test SM8).
bool pulledIsStale(
  Map<String, dynamic>? held, {
  required String objectType,
  required int version,
  required String? hash,
  required int gcFloor,
}) {
  if (held == null || held['queued'] == 1) return false;
  if (objectType != 'node' && objectType != 'entry') return false;
  final seq = held['commit_seq'];
  final decision =
      (syncCore('against_held', {
                'items': [
                  {
                    'held': {
                      'version': held['version'] as int,
                      'hash': held['payload_hash'] as String? ?? '',
                      'is_deleted': held['is_deleted'] == 1,
                      'queued': false,
                      'commit_seq': seq is int ? seq : null,
                    },
                    'pulled': {'version': version, 'hash': hash ?? ''},
                  },
                ],
                'gc_floor_seq': gcFloor,
              })
              as List)
          .first;
  return decision == 'keep_held' || decision == 'equivocation';
}

/// The verified server row behind a conflict shadow (payload is stored in
/// its own column; the signature bytes as base64).
String encodeConflictServerRow(Map<String, Object?> row) => jsonEncode({
  for (final entry in row.entries)
    if (entry.key != 'payload')
      entry.key: entry.value is Uint8List
          ? base64Encode(entry.value! as Uint8List)
          : entry.value,
});

/// vault_objects row (clean) rebuilt from [encodeConflictServerRow].
Map<String, Object?> decodeConflictServerRow(String json, Uint8List payload) {
  final row = Map<String, Object?>.from(jsonDecode(json) as Map);
  final signature = row['client_signature'];
  return asServerCopy({
    ...row,
    'payload': payload,
    'client_signature': signature is String ? base64Decode(signature) : null,
  });
}

class DatabaseService {
  static final DatabaseService _instance = DatabaseService._();
  factory DatabaseService() => _instance;
  DatabaseService._();

  Database? _db;

  Future<void> _createSyncConflictsTable(DatabaseExecutor db) async {
    await db.execute('''
      CREATE TABLE IF NOT EXISTS sync_conflicts (
        object_id TEXT PRIMARY KEY,
        object_type TEXT NOT NULL,
        local_version INTEGER NOT NULL,
        server_version INTEGER NOT NULL,
        server_payload BLOB NOT NULL,
        server_payload_hash TEXT,
        server_commit_seq INTEGER,
        detected_at INTEGER NOT NULL,
        server_row TEXT
      )
    ''');
  }

  /// What waits for the server, in send order (vault/outbox.py on desktop):
  /// a write per object, and operations ([object_id] '') with their state
  /// in [body] (a rejoin's stage).
  Future<void> _createOutboxTable(DatabaseExecutor db) async {
    await db.execute('''
      CREATE TABLE IF NOT EXISTS outbox (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL,
        object_id TEXT,
        body TEXT,
        UNIQUE (kind, object_id)
      )
    ''');
  }

  Future<void> _createKnownKeysTable(DatabaseExecutor db) async {
    await db.execute('''
      CREATE TABLE IF NOT EXISTS known_keys (
        user_id TEXT PRIMARY KEY,
        signing_pk BLOB NOT NULL,
        encryption_pk BLOB NOT NULL,
        fingerprint TEXT NOT NULL,
        first_seen INTEGER NOT NULL,
        last_verified INTEGER NOT NULL
      )
    ''');
  }

  /// Check if the vault database file exists on disk.
  static Future<bool> vaultExists() async {
    return File(await vaultDbPath()).existsSync();
  }

  static const _storageChannel = MethodChannel('sk.sezam/storage');
  static const _dbName = 'sezam_vault.db';

  /// Vault DB location: Application Support/vault (never the user-visible,
  /// iCloud/iTunes-backed-up Documents directory). On iOS the directory is
  /// excluded from backups so the DB and its journal stay device-bound.
  static Future<String> vaultDbPath() async {
    final support = await getApplicationSupportDirectory();
    final dir = Directory(p.join(support.path, 'vault'));
    if (!dir.existsSync()) dir.createSync(recursive: true);
    if (Platform.isIOS) {
      try {
        await _storageChannel.invokeMethod('excludeFromBackup', dir.path);
      } catch (_) {
        // Non-fatal: the DB content is encrypted; the next start retries.
      }
    }
    final path = p.join(dir.path, _dbName);
    migrateLegacyVaultDb(p.join(await _legacyDocumentsPath(), _dbName), path);
    return path;
  }

  /// Exports (`.sezam-key` with the wrapped keypair and salt, unsent
  /// changes) never go to Documents, which iOS backs up to iCloud/iTunes
  /// (review d615826): Application Support/exports, excluded from backups on
  /// iOS. Unlike the vault DB this fails closed: no export is written where
  /// a backup would copy it. Older exports in Documents are moved here.
  static Future<Directory> exportDirectory() async {
    final support = await getApplicationSupportDirectory();
    final dir = Directory(p.join(support.path, 'exports'));
    if (!dir.existsSync()) dir.createSync(recursive: true);
    if (Platform.isIOS) {
      await _storageChannel.invokeMethod('excludeFromBackup', dir.path);
    }
    moveLegacyExports(await _legacyDocumentsPath(), dir.path);
    return dir;
  }

  /// The pre-move location only, never written to.
  static Future<String> _legacyDocumentsPath() async =>
      (await getApplicationDocumentsDirectory()).path;

  /// Open (or create) the local vault database.
  Future<Database> get database async {
    if (_db != null) return _db!;
    _db = await _open();
    return _db!;
  }

  Future<Database> _open() async {
    final path = await vaultDbPath();

    return openDatabase(
      path,
      version: 10,
      onUpgrade: (db, oldVersion, newVersion) async {
        // v1 -> v2: ownership ACL (spec 3.4) — per-object write_policy.
        if (oldVersion < 2) {
          await db.execute(
            "ALTER TABLE vault_objects ADD COLUMN write_policy TEXT",
          );
        }
        if (oldVersion < 3) {
          await _createSyncConflictsTable(db);
        }
        if (oldVersion < 4) {
          await _createKnownKeysTable(db);
        }
        if (oldVersion < 5) {
          await db.execute(
            "ALTER TABLE vault_objects ADD COLUMN access_level TEXT",
          );
        }
        // v6: the verified server row behind a conflict, so "use server
        // version" can replace just that object.
        if (oldVersion < 6 && oldVersion >= 3) {
          await db.execute(
            "ALTER TABLE sync_conflicts ADD COLUMN server_row TEXT",
          );
        }
        // v7: the account whose signature a pulled object carried (review
        // 7c10379 H4: write_authority.dart judges by it, not by owner_id).
        if (oldVersion < 7) {
          await db.execute(
            "ALTER TABLE vault_objects ADD COLUMN signer_id TEXT",
          );
        }
        // v8 (sync redesign S1): the server copy a row builds on, as the pair
        // (version, payload hash). A clean row is that copy; an unsent change
        // made before v8 has no known base and the server treats it as a
        // conflict, which the conflict screen resolves.
        if (oldVersion < 8) {
          await db.execute(
            "ALTER TABLE vault_objects ADD COLUMN base_version INTEGER",
          );
          await db.execute(
            "ALTER TABLE vault_objects ADD COLUMN base_hash TEXT",
          );
          await db.execute(
            'UPDATE vault_objects SET base_version = version, base_hash = payload_hash '
            'WHERE is_dirty = 0',
          );
        }
        // v9 (sync redesign S3): the outbox replaces the is_dirty flag. The
        // old column stays (DROP COLUMN needs SQLite 3.35, newer than some
        // Android releases) but nothing reads or writes it any more.
        if (oldVersion < 9) {
          await _createOutboxTable(db);
          await db.execute(
            "INSERT INTO outbox (kind, object_id) SELECT 'write', id "
            'FROM vault_objects WHERE is_dirty = 1 ORDER BY modified_at, id',
          );
          await db.execute('DROP INDEX IF EXISTS idx_vo_dirty');
        }
        // v10 (S3, capability run 359): an operation's state is its outbox
        // row; the rejoin's stage leaves the settings table.
        if (oldVersion < 10) {
          if (oldVersion >= 9) {
            await db.execute('ALTER TABLE outbox ADD COLUMN body TEXT');
          }
          await db.execute(
            'INSERT OR IGNORE INTO outbox (kind, object_id, body) '
            "SELECT '$outboxRejoin', '', value FROM settings "
            "WHERE key = 'pending_server_rejoin'",
          );
          await db.delete('settings', where: "key = 'pending_server_rejoin'");
        }
      },
      onCreate: (db, version) async {
        // vault_objects — encrypted sync objects
        await db.execute('''
          CREATE TABLE vault_objects (
            id TEXT PRIMARY KEY,
            object_type TEXT NOT NULL,
            payload BLOB NOT NULL,
            owner_id TEXT,
            parent_ref TEXT,
            target_user_id TEXT,
            version INTEGER NOT NULL DEFAULT 1,
            commit_seq INTEGER,
            is_deleted INTEGER NOT NULL DEFAULT 0,
            payload_hash TEXT,
            client_signature BLOB,
            modified_at INTEGER,
            write_policy TEXT,
            access_level TEXT,
            signer_id TEXT,
            base_version INTEGER,
            base_hash TEXT
          )
        ''');

        await db.execute(
          'CREATE INDEX idx_vo_type ON vault_objects(object_type)',
        );
        await db.execute(
          'CREATE INDEX idx_vo_parent ON vault_objects(parent_ref)',
        );
        await db.execute(
          'CREATE INDEX idx_vo_seq ON vault_objects(commit_seq)',
        );

        // sync_state — track last pull commit_seq
        await db.execute('''
          CREATE TABLE sync_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
          )
        ''');
        await _createSyncConflictsTable(db);
        await _createOutboxTable(db);
        await _createKnownKeysTable(db);

        // settings — app settings
        await db.execute('''
          CREATE TABLE settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
          )
        ''');
      },
    );
  }

  /// Close the database.
  Future<void> close() async {
    await _db?.close();
    _db = null;
  }

  // ── CRUD for vault_objects ──

  /// Insert or replace a vault object. [queued]: a local change, its write
  /// goes into the outbox; otherwise the row is the server copy.
  Future<void> upsertObject({
    required String id,
    required String objectType,
    required Uint8List payload,
    String? ownerId,
    String? parentRef,
    String? targetUserId,
    required int version,
    int? commitSeq,
    int isDeleted = 0,
    String? payloadHash,
    Uint8List? clientSignature,
    int? modifiedAt,
    bool queued = false,
    String? writePolicy,
    String? accessLevel,
    ({int version, String? hash})? rebaseOn,
    int? replacesVersion,
  }) async {
    final db = await database;
    await db.transaction((txn) async {
      // Review 18c300f R16-M1: a local edit replaces the version it was made
      // on. A sync that stored another version meanwhile (the edit awaited in
      // between) is not overwritten by an edit numbered like it.
      if (replacesVersion != null) {
        final held = await txn.query(
          'vault_objects',
          columns: ['version'],
          where: 'id = ?',
          whereArgs: [id],
        );
        final current = held.isEmpty ? null : held.first['version'] as int?;
        if (current != replacesVersion) {
          throw StaleRowException(id, replacesVersion, current);
        }
      }
      // A server copy is its own base. A local change keeps the base of the
      // row it replaces, unless it is rebased on a newer server copy
      // (conflict "keep mine").
      final ({int? version, String? hash}) base;
      if (!queued) {
        base = (version: version, hash: payloadHash);
      } else if (rebaseOn != null) {
        base = (version: rebaseOn.version, hash: rebaseOn.hash);
      } else {
        final rows = await txn.query(
          'vault_objects',
          columns: ['base_version', 'base_hash'],
          where: 'id = ?',
          whereArgs: [id],
        );
        base = rows.isEmpty
            ? (version: null, hash: null)
            : (
                version: rows.first['base_version'] as int?,
                hash: rows.first['base_hash'] as String?,
              );
      }
      await txn.insert('vault_objects', {
        'id': id,
        'object_type': objectType,
        'payload': payload,
        'owner_id': ownerId,
        'parent_ref': parentRef,
        'target_user_id': targetUserId,
        'version': version,
        'commit_seq': commitSeq,
        'is_deleted': isDeleted,
        'payload_hash': payloadHash,
        'client_signature': clientSignature,
        'modified_at': modifiedAt ?? DateTime.now().millisecondsSinceEpoch,
        'write_policy': writePolicy,
        'access_level': accessLevel,
        'base_version': base.version,
        'base_hash': base.hash,
      }, conflictAlgorithm: ConflictAlgorithm.replace);
      await (queued ? _queueWrite(txn, id) : _dropWrite(txn, id));
    });
  }

  /// Get all objects of a given type.
  Future<List<Map<String, dynamic>>> getObjectsByType(String objectType) async {
    final db = await database;
    return db.query(
      'vault_objects',
      columns: _rowColumns,
      where: 'object_type = ? AND is_deleted = 0',
      whereArgs: [objectType],
    );
  }

  /// Get a single object by ID.
  Future<Map<String, dynamic>?> getObject(String id) async {
    final db = await database;
    final results = await db.query(
      'vault_objects',
      columns: _rowColumns,
      where: 'id = ?',
      whereArgs: [id],
    );
    return results.isEmpty ? null : results.first;
  }

  /// The objects with a queued write, in outbox order (to push).
  Future<List<Map<String, dynamic>>> getDirtyObjects() async {
    final db = await database;
    return db.rawQuery(
      'SELECT v.*, 1 AS queued FROM vault_objects v JOIN outbox o '
      "ON o.kind = 'write' AND o.object_id = v.id ORDER BY o.seq",
    );
  }

  /// Mark an object as clean (synced) — only the version that was sent.
  /// Review 526419e #2: an edit saved while the push was out was marked
  /// clean too and never reached the server.
  Future<void> markClean(
    String id,
    int? commitSeq, {
    required int version,
    required int isDeleted,
    required String? payloadHash,
    Transaction? transaction,
  }) async {
    Future<void> apply(DatabaseExecutor txn) async {
      final cleaned = await txn.update(
        'vault_objects',
        buildMarkCleanUpdate(
          commitSeq,
          version: version,
          payloadHash: payloadHash,
        ),
        where:
            'id = ? AND version = ? AND is_deleted = ? AND payload_hash IS ?',
        whereArgs: [id, version, isDeleted, payloadHash],
      );
      if (cleaned > 0) await _dropWrite(txn, id);
      if (cleaned == 0 && commitSeq != null) {
        // Review d150605 N2: edited while the push was out. What the server
        // now holds is this device's own copy: the edit is based on it, and
        // its pull is no conflict.
        await txn.update(
          'vault_objects',
          {
            'commit_seq': commitSeq,
            'base_version': version,
            'base_hash': payloadHash,
          },
          where: 'id = ? AND $queuedSql',
          whereArgs: [id],
        );
      }
      // Review d150605 N3: only what the accepted copy superseded goes. A
      // pull during the push can have held aside a later change from another
      // device; dropping its shadow hid that conflict.
      if (commitSeq != null) {
        await txn.delete(
          'sync_conflicts',
          where:
              'object_id = ? AND '
              '(server_commit_seq IS NULL OR server_commit_seq < ?)',
          whereArgs: [id, commitSeq],
        );
      } else if (cleaned > 0) {
        await txn.delete(
          'sync_conflicts',
          where: 'object_id = ?',
          whereArgs: [id],
        );
      }
    }

    if (transaction != null) {
      await apply(transaction);
    } else {
      final db = await database;
      await db.transaction(apply);
    }
  }

  /// Soft-delete an object (mark as deleted and dirty).
  Future<void> softDelete(
    String id, {
    required int version,
    required String payloadHash,
    required Uint8List clientSignature,
  }) async {
    final db = await database;
    // The base stays the server copy the deleted row was (or was built on).
    await db.transaction((txn) async {
      final deleted = await txn.update(
        'vault_objects',
        {
          'is_deleted': 1,
          'version': version,
          'payload_hash': payloadHash,
          'client_signature': clientSignature,
          'modified_at': DateTime.now().millisecondsSinceEpoch,
        },
        where: 'id = ? AND is_deleted = 0',
        whereArgs: [id],
      );
      if (deleted > 0) await _queueWrite(txn, id);
    });
  }

  /// Deleted folders holding a live item with a queued write (one level).
  Future<List<Map<String, dynamic>>> deletedFoldersWithUnsentWork() async {
    final db = await database;
    return db.rawQuery(
      'SELECT * FROM vault_objects n WHERE n.object_type = ? AND n.is_deleted = 1 '
      'AND EXISTS (SELECT 1 FROM vault_objects c JOIN outbox o '
      "ON o.kind = 'write' AND o.object_id = c.id "
      'WHERE c.parent_ref = n.id AND c.is_deleted = 0)',
      ['node'],
    );
  }

  /// A folder deleted elsewhere back as [version] (a queued write on the
  /// tombstone it replaces, docs/SYNC_SINGLE_SOURCE.md point 4a). The queued
  /// work below it is queued again behind it: the server refuses an item
  /// in a deleted folder, so the folder goes out first.
  Future<void> reviveFolder(
    String id, {
    required Uint8List payload,
    required int version,
    required String payloadHash,
    required Uint8List clientSignature,
  }) async {
    final db = await database;
    await db.transaction((txn) async {
      final revived = await txn.update(
        'vault_objects',
        {
          'payload': payload,
          'is_deleted': 0,
          'version': version,
          'payload_hash': payloadHash,
          'client_signature': clientSignature,
          'modified_at': DateTime.now().millisecondsSinceEpoch,
        },
        where: 'id = ? AND is_deleted = 1',
        whereArgs: [id],
      );
      if (revived == 0) return;
      await _queueWrite(txn, id);
      final below = await txn.rawQuery(
        'SELECT o.object_id FROM outbox o JOIN vault_objects c '
        "ON o.kind = 'write' AND o.object_id = c.id "
        'WHERE c.parent_ref = ? ORDER BY o.seq',
        [id],
      );
      for (final row in below) {
        final child = row['object_id'] as String;
        await _dropWrite(txn, child);
        await _queueWrite(txn, child);
      }
    });
  }

  /// Get children of a parent node (entries or sub-folders).
  Future<List<Map<String, dynamic>>> getChildren(
    String parentRef,
    String objectType,
  ) async {
    final db = await database;
    return db.query(
      'vault_objects',
      columns: _rowColumns,
      where: 'parent_ref = ? AND object_type = ? AND is_deleted = 0',
      whereArgs: [parentRef, objectType],
    );
  }

  /// Get all objects (including deleted) for full sync comparison.
  Future<List<Map<String, dynamic>>> getAllObjects() async {
    final db = await database;
    return db.query(
      'vault_objects',
      columns: _rowColumns,
      orderBy: 'commit_seq ASC',
    );
  }

  /// The server copy held aside for [objectId], if any.
  Future<Map<String, dynamic>?> getSyncConflict(String objectId) async {
    final db = await database;
    final rows = await db.query(
      'sync_conflicts',
      where: 'object_id = ?',
      whereArgs: [objectId],
    );
    return rows.isEmpty ? null : rows.first;
  }

  /// Server copies held aside while a conflicting local object stays dirty.
  Future<List<Map<String, dynamic>>> getSyncConflicts() async {
    final db = await database;
    return db.query('sync_conflicts', orderBy: 'detected_at ASC');
  }

  /// Hold [serverRow] (a clean row: the verified server copy) aside as the
  /// conflict shadow of a local change of [localVersion] made on another
  /// version, as [applyPullAndCommitCheckpoint] does when a pull meets one.
  /// Sync redesign S4a: a full resync re-applies such an edit, and no later
  /// pull brings this copy again to tell.
  Future<void> holdServerCopyAside(
    Map<String, Object?> serverRow, {
    required int localVersion,
  }) async {
    final db = await database;
    await db.insert('sync_conflicts', {
      'object_id': serverRow['id'],
      'object_type': serverRow['object_type'],
      'local_version': localVersion,
      'server_version': serverRow['version'],
      'server_payload': serverRow['payload'],
      'server_payload_hash': serverRow['payload_hash'],
      'server_commit_seq': serverRow['commit_seq'],
      'detected_at': DateTime.now().millisecondsSinceEpoch,
      'server_row': encodeConflictServerRow({
        for (final entry in serverRow.entries)
          if (!const {
            'queued',
            'base_version',
            'base_hash',
          }.contains(entry.key))
            entry.key: entry.value,
      }),
    }, conflictAlgorithm: ConflictAlgorithm.replace);
  }

  /// Resolve a conflict with the verified server copy: it replaces the local
  /// change of that one object (clean), and the shadow goes. The checkpoint
  /// already authenticates exactly this copy. False when the shadow predates
  /// v6 and has no stored server row (only a full resync can take it then).
  Future<bool> takeServerConflictCopy(String objectId) async {
    final db = await database;
    return db.transaction((txn) async {
      final rows = await txn.query(
        'sync_conflicts',
        where: 'object_id = ?',
        whereArgs: [objectId],
      );
      final serverRow = rows.isEmpty ? null : rows.first['server_row'];
      if (serverRow is! String) return false;
      await txn.insert(
        'vault_objects',
        decodeConflictServerRow(
          serverRow,
          Uint8List.fromList(rows.first['server_payload']! as List<int>),
        ),
        conflictAlgorithm: ConflictAlgorithm.replace,
      );
      await _dropWrite(txn, objectId);
      await txn.delete(
        'sync_conflicts',
        where: 'object_id = ?',
        whereArgs: [objectId],
      );
      return true;
    });
  }

  Future<Map<String, dynamic>?> getKnownKey(String userId) async {
    final db = await database;
    final rows = await db.query(
      'known_keys',
      where: 'user_id = ?',
      whereArgs: [userId],
    );
    return rows.isEmpty ? null : rows.first;
  }

  Future<void> upsertKnownKey(Map<String, dynamic> key) async {
    final db = await database;
    await db.insert(
      'known_keys',
      key,
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }

  // ── Sync state ──

  /// Get a raw sync-state value.
  Future<String?> getSyncState(String key) async {
    final db = await database;
    final results = await db.query(
      'sync_state',
      where: 'key = ?',
      whereArgs: [key],
    );
    return results.isEmpty ? null : results.first['value'] as String;
  }

  /// Get the last synced commit_seq.
  Future<int> getLastCommitSeq() async {
    final db = await database;
    final results = await db.query(
      'sync_state',
      where: 'key = ?',
      whereArgs: ['last_commit_seq'],
    );
    if (results.isEmpty) return 0;
    return int.tryParse(results.first['value'] as String) ?? 0;
  }

  /// Set the last synced commit_seq.
  Future<void> setLastCommitSeq(int seq) async {
    final db = await database;
    await db.insert('sync_state', {
      'key': 'last_commit_seq',
      'value': seq.toString(),
    }, conflictAlgorithm: ConflictAlgorithm.replace);
  }

  /// Atomically apply a complete pull response and its authenticated checkpoint.
  Future<List<Map<String, dynamic>>> applyPullAndCommitCheckpoint({
    required List<Map<String, Object?>> objects,
    required int seq,
    required String checkpointKey,
    required String encryptedCheckpoint,
  }) async {
    final db = await database;
    return db.transaction((txn) async {
      final conflicts = <Map<String, dynamic>>[];
      for (final object in objects) {
        final id = object['id']! as String;
        final localRows = await txn.query(
          'vault_objects',
          columns: [
            'version',
            '$queuedSql AS queued',
            'payload_hash',
            'parent_ref',
            'is_deleted',
            'base_version',
            'base_hash',
          ],
          where: 'id = ?',
          whereArgs: [id],
        );
        Map<String, Object?> local = localRows.isEmpty ? const {} : localRows.first;
        final queued = local['queued'] == 1;
        if (queued &&
            local['base_version'] == null &&
            (object['object_type'] == 'node' ||
                object['object_type'] == 'entry') &&
            object['payload_hash'] != null &&
            object['version'] == (local['version']! as int) - 1) {
          // Review c78fd19: an edit an older version queued without its base
          // was refused as a new object on every push. It was made one
          // version above the copy it changed: the server's copy one below.
          local = {
            ...local,
            'base_version': object['version'],
            'base_hash': object['payload_hash'],
          };
          await txn.update(
            'vault_objects',
            {
              'base_version': object['version'],
              'base_hash': object['payload_hash'],
            },
            where: 'id = ?',
            whereArgs: [id],
          );
        }
        final sentRows = queued
            ? await txn.query(
                'outbox',
                columns: ['body'],
                where: "kind = 'write' AND object_id = ?",
                whereArgs: [id],
              )
            : const <Map<String, Object?>>[];
        final sent = decodeSentVersions(
          sentRows.isEmpty ? null : sentRows.first['body'] as String?,
        );
        // What the pulled copy does to an unsent write: the shared sync core
        // decides (core/src/pull.rs), as on the desktop and the web.
        final decision = !queued
            ? 'apply'
            : syncCore('decide_pulled', {
                'unsent': {
                  'version': local['version'],
                  'hash': local['payload_hash'] ?? '',
                  'parent_ref': local['parent_ref'],
                  'is_deleted': local['is_deleted'] == 1,
                  'base': local['base_version'] == null
                      ? null
                      : {
                          'version': local['base_version'],
                          'hash': local['base_hash'] ?? '',
                        },
                },
                'pulled': {
                  'version': object['version'],
                  'hash': object['payload_hash'] ?? '',
                  'parent_ref': object['parent_ref'],
                  'is_deleted': object['is_deleted'] == 1,
                  'own_earlier_push': sent.any(
                    (s) =>
                        s.version == object['version'] &&
                        s.hash == object['payload_hash'],
                  ),
                },
              });
        if (decision == 'keep_unsent') {
          continue; // The unsent edit builds on this copy.
        }
        if (decision == 'adopt_as_base') {
          // This phone's push whose reply was lost: the edit after it is a
          // change of that copy and goes out with it as its base.
          await txn.update(
            'vault_objects',
            {
              'base_version': object['version'],
              'base_hash': object['payload_hash'],
              'commit_seq': object['commit_seq'],
            },
            where: 'id = ?',
            whereArgs: [id],
          );
          await txn.delete(
            'sync_conflicts',
            where: 'object_id = ?',
            whereArgs: [id],
          );
          continue;
        }
        if (decision == 'conflict') {
          final localVersion = localRows.first['version']! as int;
          final serverVersion = object['version']! as int;
          await txn.insert('sync_conflicts', {
            'object_id': id,
            'object_type': object['object_type'],
            'local_version': localVersion,
            'server_version': serverVersion,
            'server_payload': object['payload'],
            'server_payload_hash': object['payload_hash'],
            'server_commit_seq': object['commit_seq'],
            'detected_at': DateTime.now().millisecondsSinceEpoch,
            'server_row': encodeConflictServerRow(object),
          }, conflictAlgorithm: ConflictAlgorithm.replace);
          conflicts.add({
            'id': id,
            'object_type': object['object_type'],
            'local_version': localVersion,
            'server_version': serverVersion,
          });
          continue;
        }

        await txn.insert(
          'vault_objects',
          asServerCopy(object),
          conflictAlgorithm: ConflictAlgorithm.replace,
        );
        await _dropWrite(txn, id);
        await txn.delete(
          'sync_conflicts',
          where: 'object_id = ?',
          whereArgs: [id],
        );
      }
      await txn.insert('sync_state', {
        'key': checkpointKey,
        'value': encryptedCheckpoint,
      }, conflictAlgorithm: ConflictAlgorithm.replace);
      await txn.insert('sync_state', {
        'key': 'last_commit_seq',
        'value': seq.toString(),
      }, conflictAlgorithm: ConflictAlgorithm.replace);
      return conflicts;
    });
  }

  /// Atomically replace the complete local ciphertext snapshot after a verified
  /// explicit full resync. Dirty rows and conflict shadows are removed only in
  /// the same transaction that stores the new checkpoint and sequence.
  Future<void> replaceSnapshotAndCommitCheckpoint({
    required List<Map<String, Object?>> objects,
    required int seq,
    required String checkpointKey,
    required String encryptedCheckpoint,
  }) async {
    final db = await database;
    await db.transaction((txn) async {
      await txn.delete('vault_objects');
      await txn.delete('sync_conflicts');
      await txn.delete('outbox', where: "kind = 'write'");
      for (final object in objects) {
        final queued = object['queued'] == 1;
        await txn.insert(
          'vault_objects',
          queued
              ? {
                  for (final entry in object.entries)
                    if (entry.key != 'queued') entry.key: entry.value,
                }
              : asServerCopy(object),
          conflictAlgorithm: ConflictAlgorithm.abort,
        );
        if (queued) await _queueWrite(txn, object['id']! as String);
      }
      await txn.insert('sync_state', {
        'key': checkpointKey,
        'value': encryptedCheckpoint,
      }, conflictAlgorithm: ConflictAlgorithm.replace);
      await txn.insert('sync_state', {
        'key': 'last_commit_seq',
        'value': seq.toString(),
      }, conflictAlgorithm: ConflictAlgorithm.replace);
    });
  }

  /// Atomically store DEK wraps moved to a new KEK and the checkpoint
  /// re-encrypted under it (taking over a password change), plus [settings]
  /// that must land together with them.
  Future<void> applyLocalRekey({
    required List<Map<String, dynamic>> rows,
    String? checkpointKey,
    String? encryptedCheckpoint,
    Map<String, String> settings = const {},
  }) async {
    final db = await database;
    await db.transaction((txn) async {
      for (final row in rows) {
        await txn.update(
          'vault_objects',
          {
            'payload': row['payload'],
            'payload_hash': row['payload_hash'],
            'client_signature': row['client_signature'],
          },
          where: 'id = ?',
          whereArgs: [row['id']],
        );
      }
      if (checkpointKey != null && encryptedCheckpoint != null) {
        await txn.insert('sync_state', {
          'key': checkpointKey,
          'value': encryptedCheckpoint,
        }, conflictAlgorithm: ConflictAlgorithm.replace);
      }
      for (final setting in settings.entries) {
        await txn.insert('settings', {
          'key': setting.key,
          'value': setting.value,
        }, conflictAlgorithm: ConflictAlgorithm.replace);
      }
    });
  }

  // ── Outbox operations ──

  /// Review c78fd19: remember on each queued folder or entry write what this
  /// phone sends of it (version, payload hash), as the desktop's
  /// object_sent_version. A pulled copy that is one of them is this phone's
  /// own push whose reply was lost, not another device's write: the edit
  /// after it was a conflict with itself. The record leaves with the write.
  Future<void> rememberSent(List<Map<String, dynamic>> objects) async {
    final db = await database;
    await db.transaction((txn) async {
      for (final object in objects) {
        if (object['object_type'] != 'node' && object['object_type'] != 'entry') {
          continue;
        }
        final where = "kind = 'write' AND object_id = ?";
        final rows = await txn.query(
          'outbox',
          columns: ['body'],
          where: where,
          whereArgs: [object['id']],
        );
        if (rows.isEmpty) continue;
        final version = object['version'] as int;
        final hash = object['payload_hash'] as String;
        final sent = [
          for (final s in decodeSentVersions(rows.first['body'] as String?))
            if (!(s.version == version && s.hash == hash)) s,
          (version: version, hash: hash),
        ];
        await txn.update(
          'outbox',
          {
            'body': jsonEncode([
              for (final s in sent.skip(sent.length > 8 ? sent.length - 8 : 0))
                [s.version, s.hash],
            ]),
          },
          where: where,
          whereArgs: [object['id']],
        );
      }
    });
  }

  /// The state of the queued operation [kind], or null when none waits.
  Future<String?> outboxOperation(String kind) async {
    final db = await database;
    final rows = await db.query(
      'outbox',
      columns: ['body'],
      where: "kind = ? AND object_id = ''",
      whereArgs: [kind],
    );
    return rows.isEmpty ? null : rows.first['body'] as String?;
  }

  /// Queue [kind] with [body], or move a queued one on to [body] in its place.
  Future<void> putOutboxOperation(String kind, String body) async {
    final db = await database;
    await db.transaction((txn) async {
      final updated = await txn.update(
        'outbox',
        {'body': body},
        where: "kind = ? AND object_id = ''",
        whereArgs: [kind],
      );
      if (updated == 0) {
        await txn.insert('outbox', {
          'kind': kind,
          'object_id': '',
          'body': body,
        });
      }
    });
  }

  Future<void> dropOutboxOperation(String kind) async {
    final db = await database;
    await db.delete(
      'outbox',
      where: "kind = ? AND object_id = ''",
      whereArgs: [kind],
    );
  }

  // ── Settings ──

  /// Get a setting value.
  Future<String?> getSetting(String key) async {
    final db = await database;
    final results = await db.query(
      'settings',
      where: 'key = ?',
      whereArgs: [key],
    );
    return results.isEmpty ? null : results.first['value'] as String;
  }

  /// Set a setting value.
  Future<void> setSetting(String key, String value) async {
    final db = await database;
    await db.insert('settings', {
      'key': key,
      'value': value,
    }, conflictAlgorithm: ConflictAlgorithm.replace);
  }

  Future<void> deleteSetting(String key) async {
    final db = await database;
    await db.delete('settings', where: 'key = ?', whereArgs: [key]);
  }

  /// Review c78fd19: drop the team log copy ([recordsSetting]) and the
  /// checkpoint's pin of it ([encryptedCheckpoint]) together. Review 8bc70f7
  /// M2: the queued writes of [dropWrites] go with them, and [resyncSetting]
  /// marks that the next pull must be a full resync.
  Future<void> leaveTeamLog({
    required String recordsSetting,
    required String checkpointKey,
    required String? encryptedCheckpoint,
    List<String> dropWrites = const [],
    required String resyncSetting,
  }) async {
    final db = await database;
    await db.transaction((txn) async {
      await txn.delete('settings', where: 'key = ?', whereArgs: [recordsSetting]);
      for (final id in dropWrites) {
        await _dropWrite(txn, id);
      }
      if (dropWrites.isNotEmpty) {
        await txn.insert('settings', {'key': resyncSetting, 'value': '1'},
            conflictAlgorithm: ConflictAlgorithm.replace);
      }
      if (encryptedCheckpoint != null) {
        await txn.insert('sync_state', {'key': checkpointKey, 'value': encryptedCheckpoint},
            conflictAlgorithm: ConflictAlgorithm.replace);
      }
    });
  }

  /// Delete the entire database (for logout/wipe).
  Future<void> deleteDatabase() async {
    final path = await vaultDbPath();
    await close();
    await databaseFactory.deleteDatabase(path);
  }
}

/// A local edit found another version stored than the one it was made on
/// (R16-M1); nothing was written.
class StaleRowException implements Exception {
  final String id;
  final int expected;
  final int? current;
  const StaleRowException(this.id, this.expected, this.current);

  @override
  String toString() => 'Object $id changed meanwhile (edited v$expected, now v$current)';
}

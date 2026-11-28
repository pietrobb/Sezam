/// Sezam VaultService — local vault management with E2E encryption.
///
/// Manages the full lifecycle:
///   - init/unlock/lock
///   - CRUD on entries and folders
///   - in-memory search
///   - offline access via SQLite
///
/// All data is stored encrypted in SQLite. Decryption happens in memory
/// only when the vault is unlocked (KEK available).

import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../models/vault_models.dart';
import 'crypto_service.dart';
import 'database_service.dart';
import 'sync_checkpoint.dart';
import 'sync_core.dart';
import 'sync_limits.dart';
import 'team_log.dart';
import 'team_log_client.dart';
import 'unsent_changes.dart';
import 'write_authority.dart';

/// An entry of this device's own vault as a join carries it into an account:
/// the complete decrypted meta and data (every key, not only those the model
/// knows) and its write policy.
class CarriedEntry {
  final String? parentRef;
  final Map<String, dynamic> meta;
  final Map<String, dynamic> data;
  final String writePolicy;

  const CarriedEntry({
    required this.parentRef,
    required this.meta,
    required this.data,
    required this.writePolicy,
  });

  int? get tier => meta['tier'] is int ? meta['tier'] as int : null;

  VaultEntry get entry => VaultEntry.fromJson(
    '',
    {...meta, ...data},
    parentRef: parentRef,
    writePolicy: writePolicy,
  );
}

Map<String, String> deriveFolderAccessLevels(
  Iterable<Map<String, dynamic>> objects,
  String? currentUserId, {
  TeamState? team,
}) {
  if (currentUserId == null || currentUserId.isEmpty) return const {};

  final folderByDek = <String, String>{};
  for (final object in objects) {
    if (object['object_type'] != 'dek' || object['is_deleted'] == 1) continue;
    final dekId = object['id'] as String?;
    final folderId = object['parent_ref'] as String?;
    if (dekId != null && folderId != null && folderId.isNotEmpty) {
      folderByDek[dekId] = folderId;
    }
  }

  final accessByFolder = <String, String>{};
  for (final object in objects) {
    if (object['object_type'] != 'envelope' ||
        object['is_deleted'] == 1 ||
        object['target_user_id'] != currentUserId) {
      continue;
    }
    final folderId = folderByDek[object['parent_ref']];
    if (team != null &&
        (team.dekIndex.containsKey(object['parent_ref']) ||
            team.folders.containsKey(folderId))) {
      continue;
    }
    final accessLevel = object['access_level'];
    if (folderId == null || (accessLevel != 'read' && accessLevel != 'write')) {
      continue;
    }
    if (accessLevel == 'write' || accessByFolder[folderId] == null) {
      accessByFolder[folderId] = accessLevel as String;
    }
  }
  if (team != null) {
    for (final folder in team.folders.keys) {
      final key = TeamLog.currentKey(team, folder)!;
      final level = team.access[folder]?[currentUserId];
      if (level != null && TeamLog.mayHoldKey(team, currentUserId, key)) {
        accessByFolder[folder] = level;
      }
    }
  }
  return accessByFolder;
}

/// The vault was locked after a flow captured [VaultService.lockGeneration]:
/// it must not unlock it again (review a159e97).
class VaultLockedMeanwhile implements Exception {
  const VaultLockedMeanwhile();

  @override
  String toString() =>
      'The vault was locked meanwhile; unlock it with the current password.';
}

/// The entry changed (a sync pulled a newer version) after the editor opened.
class StaleEntryEditException implements Exception {
  final String entryId;
  final int expectedVersion;
  final int currentVersion;

  const StaleEntryEditException(
    this.entryId, {
    required this.expectedVersion,
    required this.currentVersion,
  });

  @override
  String toString() =>
      'Entry $entryId changed meanwhile (edited v$expectedVersion, '
      'now v$currentVersion)';
}

/// An editor opened on [expectedVersion] must not overwrite a newer version.
void ensureEditBase(VaultEntry existing, int? expectedVersion) {
  if (expectedVersion != null && existing.version != expectedVersion) {
    throw StaleEntryEditException(
      existing.id,
      expectedVersion: expectedVersion,
      currentVersion: existing.version,
    );
  }
}

/// The folder's own DEK for every folder whose DEK we hold (parity with web
/// nearestFolderDekId): a live DEK object whose parent_ref names the folder,
/// the newest ULID winning (a re-key replacement). Tier-2 entry DEKs share
/// the folder's parent_ref but are never the folder's DEK.
Map<String, String> folderDekIdsFrom({
  required Iterable<Map<String, dynamic>> dekRows,
  required Set<String> heldDekIds,
  required Set<String> tier2DekIds,
  TeamState? team,
  String? userId,
}) {
  final result = <String, String>{};
  for (final row in dekRows) {
    final id = row['id'] as String;
    final folderId = row['parent_ref'] as String?;
    if (folderId == null || folderId.isEmpty) continue;
    if ((row['is_deleted'] as int? ?? 0) != 0) continue;
    if (!heldDekIds.contains(id) || tier2DekIds.contains(id)) continue;
    if (team != null &&
        (team.dekIndex.containsKey(id) || team.folders.containsKey(folderId))) {
      continue;
    }
    final current = result[folderId];
    if (current == null || id.compareTo(current) > 0) result[folderId] = id;
  }
  if (team != null) {
    for (final folder in team.folders.keys) {
      final id = TeamLog.currentKey(team, folder)!;
      if (heldDekIds.contains(id) &&
          TeamLog.mayHoldKey(team, userId ?? '', id)) {
        result[folder] = id;
      }
    }
  }
  return result;
}

/// DEK for (re-)encrypting an object under [parentRef] (parity with web
/// resolveWriteDekId). A personal subtree always uses its private DEK, so the
/// admin's root DEK can never read it. An existing object that stays in its
/// folder keeps the DEK named in its header; anything else uses the nearest
/// folder DEK ([folderDekIds], also one shared with us through an envelope),
/// else the root DEK.
String resolveWriteDekId({
  required String? parentRef,
  required Map<String, VaultNode> nodes,
  required Set<String> heldDekIds,
  required String rootDekId,
  Map<String, String> folderDekIds = const {},
  String? existingDekId,
  String? existingParentRef,
  TeamState? team,
}) {
  final visited = <String>{};
  String? nearestFolderDekId;
  String? teamFolder;
  var nodeId = parentRef;
  while (nodeId != null && nodeId.isNotEmpty) {
    if (!visited.add(nodeId)) {
      throw StateError('Folder hierarchy contains a cycle');
    }
    final node = nodes[nodeId];
    if (node == null) throw StateError('Parent folder is unavailable');
    if (node.personal) {
      final dekId = node.dekId;
      if (dekId == null || !heldDekIds.contains(dekId)) {
        throw StateError('Personal folder key is unavailable');
      }
      return dekId;
    }
    if (team != null &&
        teamFolder == null &&
        TeamLog.isTeamFolder(team, nodeId)) {
      teamFolder = nodeId;
    }
    final folderDekId = folderDekIds[nodeId];
    if (folderDekId != null && heldDekIds.contains(folderDekId)) {
      nearestFolderDekId ??= folderDekId;
    }
    nodeId = node.parentRef;
  }
  if (teamFolder != null) {
    // TL5 (§4.3.2): in a team folder the key is the log's current generation
    // only, never one the rules below pick.
    final current = TeamLog.currentKey(team!, teamFolder)!;
    if (!heldDekIds.contains(current)) {
      throw TeamLogRefused(
        "this device does not hold the folder's current key",
      );
    }
    return current;
  }
  if (existingDekId != null &&
      existingParentRef == parentRef &&
      heldDekIds.contains(existingDekId)) {
    return existingDekId;
  }
  return nearestFolderDekId ?? rootDekId;
}

class VaultService {
  static final VaultService _instance = VaultService._();
  factory VaultService() => _instance;
  VaultService._();

  final _crypto = CryptoService();
  final _db = DatabaseService();

  // Crockford's Base32 alphabet for ULID encoding
  static const _ulidAlphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

  // ── In-memory state (cleared on lock) ──
  Uint8List? _kek;
  final Map<String, Uint8List> _deks = {};
  final Map<String, String> _folderDekIds = {};
  String? _rootDekId;
  String? _kekDekId;
  Uint8List? _signingSecretKey;
  Uint8List? _signingPublicKey;
  Uint8List? _encryptionSecretKey;
  Uint8List? _encryptionPublicKey;
  String? _userId;
  bool _serverAdmin = false;
  String? _rootNodeId;

  // The organisation's signed team log, replayed (null while it has none).
  LocalTeamLog? teamLog;

  // Decrypted in-memory cache
  final Map<String, VaultNode> _nodes = {};
  final Map<String, VaultEntry> _entries = {};

  bool get isUnlocked => _kek != null;
  Map<String, VaultNode> get nodes => Map.unmodifiable(_nodes);
  Map<String, VaultEntry> get entries => Map.unmodifiable(_entries);
  String? get rootNodeId => _rootNodeId;
  String? get kekDekId => _kekDekId;
  String? get userId => _userId;

  /// INV-3 (review e443cbc): admin as the verified team log says (as on the
  /// desktop). The server's unsigned is_admin ([serverSaysAdmin], kept for
  /// offline unlock too) only stands while this phone knows no team log at
  /// all, where the server authorizes that vault's admin calls itself (S6);
  /// a refused log, or one pinned (anchor, confirmed, checkpoint) but not
  /// held yet (capability run 473), makes nobody admin here.
  bool get isAdmin {
    final team = teamLog?.team;
    if (team != null) return _userId != null && TeamLog.isAdmin(team, _userId!);
    return teamLogRefusal == null && !_teamGenesisPinned && _serverAdmin;
  }

  /// Set by [_loadTeamLog]: this phone knows a team log exists.
  bool _teamGenesisPinned = false;

  /// The server's role for this account, passed again to a re-unlock.
  bool get serverSaysAdmin => _serverAdmin;
  Uint8List? get signingSecretKey => _signingSecretKey;
  Uint8List? get signingPublicKey => _signingPublicKey;
  Uint8List? get encryptionPublicKey => _encryptionPublicKey;
  Uint8List? get encryptionSecretKey => _encryptionSecretKey;

  /// Expose the current KEK for biometric enrollment.
  /// Only available while the vault is unlocked.
  Uint8List? get currentKek => _kek;

  // Review 7c10379 (R7-H, mobile): a personal folder created while a
  // .sezam-key import, a password take-over or a QR join moved the local DEKs
  // to another KEK wrapped its key under the old KEK, after the move had read
  // the rows or before the vault switched: the next unlock refused the vault
  // for good. An edit in that gap of a take-over of an identity rotation was
  // overwritten by the move's re-signed copy, or kept the retired key's
  // signature the server refuses. Writing a signed object or a new key and
  // moving the DEKs run one at a time, and the move switches the KEK and the
  // signing key in memory before it lets go.
  Future<void> _kekTail = Future.value();
  static final _kekHeld = Object();

  /// Runs [op] while no other code signs an object, wraps a new key under the
  /// KEK or moves the local DEKs to another KEK; a call made while holding it
  /// runs at once.
  Future<T> whileKekFixed<T>(Future<T> Function() op) {
    if (identical(Zone.current[_kekHeld], this)) return op();
    final previous = _kekTail;
    final released = Completer<void>();
    _kekTail = released.future;
    return previous
        .then((_) => runZoned(op, zoneValues: {_kekHeld: this}))
        .whenComplete(released.complete);
  }

  /// The local DEKs now sit under [kek] and unsent rows are signed with
  /// [signingSecretKey] (SyncService.rekeyLocalVault): an unlocked vault
  /// wraps and signs with them at once, not after its unlock.
  void localDeksMovedTo(Uint8List kek, Uint8List signingSecretKey) {
    if (_kek == null) return;
    _kek = Uint8List.fromList(kek);
    _signingSecretKey = Uint8List.fromList(signingSecretKey);
    _signingPublicKey = Uint8List.fromList(signingSecretKey.sublist(32, 64));
  }

  /// Initialize the database.
  Future<void> init() async {
    await _crypto.init();
    await _db.database; // Ensure DB is created
  }

  /// Unlock the vault with a pre-derived KEK and keypair.
  ///
  /// Called after successful authentication (Argon2id derivation + keypair decrypt).
  Future<void> unlock({
    required Uint8List kek,
    required Uint8List signingSecretKey,
    required Uint8List signingPublicKey,
    Uint8List? encryptionSecretKey,
    Uint8List? encryptionPublicKey,
    required String userId,
    bool isAdmin = false,
    int? unlessLockedSince,
  }) => whileKekFixed(() async {
    if (unlessLockedSince != null && unlessLockedSince != _lockGeneration) {
      throw const VaultLockedMeanwhile();
    }
    _kekMatchesServer = false;
    _kek = kek;
    _signingSecretKey = signingSecretKey;
    _signingPublicKey = signingPublicKey;
    _encryptionSecretKey = encryptionSecretKey;
    _serverAdmin = isAdmin;
    _userId = userId;
    _rootDekId = null;
    _rootNodeId = null;
    try {
      // Derive encryption public key from secret key if not provided
      if (encryptionPublicKey != null) {
        _encryptionPublicKey = encryptionPublicKey;
      } else if (encryptionSecretKey != null) {
        _encryptionPublicKey = _crypto.scalarmultBase(encryptionSecretKey);
      }

      // Load or generate kekDekId (synthetic KEK ULID for AAD)
      _kekDekId = await _db.getSetting('kek_dek_id');
      if (_kekDekId == null) {
        _kekDekId = _generateId();
        await _db.setSetting('kek_dek_id', _kekDekId!);
      }

      // Unwrap all DEKs from local DB
      await _loadTeamLogOrRefusal();
      await _loadDEKs();

      // Decrypt all nodes and entries into memory
      await _loadDecryptedData();
    } catch (_) {
      // A failed unlock leaves the vault fully locked: no KEK, keys or
      // half-loaded DEKs/items behind an isUnlocked == true.
      lock();
      rethrow;
    }
  });

  // Review a159e97: a password take-over waits on the network and then
  // unlocks with the new KEK, so an auto-lock in between was undone. Every
  // lock() counts; unlock(unlessLockedSince:) refuses after a newer one.
  int _lockGeneration = 0;
  int get lockGeneration => _lockGeneration;

  /// Lock the vault — zeroize all keys and clear decrypted data.
  void lock() {
    _lockGeneration++;
    if (_kek != null) _crypto.zeroize(_kek!);
    if (_signingSecretKey != null) _crypto.zeroize(_signingSecretKey!);
    if (_encryptionSecretKey != null) _crypto.zeroize(_encryptionSecretKey!);
    for (final dek in _deks.values) {
      _crypto.zeroize(dek);
    }

    _kek = null;
    _signingSecretKey = null;
    _signingPublicKey = null;
    _encryptionSecretKey = null;
    _encryptionPublicKey = null;
    _rootDekId = null;
    _kekDekId = null;
    _userId = null;
    _serverAdmin = false;
    _rootNodeId = null;
    _kekMatchesServer = false;
    teamLog = null;
    teamLogRefusal = null;
    _teamGenesisPinned = false;
    _deks.clear();
    _folderDekIds.clear();
    _nodes.clear();
    _entries.clear();
  }

  bool _kekMatchesServer = false;

  /// True when the KEK was derived from the server's current salt/params in
  /// this session, so a newer server key_epoch can be adopted on pull.
  bool get kekMatchesServer => _kekMatchesServer;

  void markKekMatchesServer() => _kekMatchesServer = true;

  // Registration keeps this device's keys; pulls must use the canonical
  // account's trust and envelope recipient, not the temporary 'local' identity.
  void bindRegisteredAccount(String userId, String previousUserId) {
    _ensureUnlocked();
    if (_userId != 'local' && _userId != previousUserId && _userId != userId) {
      throw StateError('Cannot register an already connected vault');
    }
    _userId = userId;
    _serverAdmin = false;
  }

  // ── Load encrypted data ──

  /// Load and unwrap all DEK objects from local DB.
  Future<void> _loadDEKs() async {
    if (_kek == null) return;
    // No log (or a refused one, INV-7): no pin is read, an unreadable one is the refusal.
    final trusted =
        teamLog != null &&
        localTeamLogTrusted(
          teamLog,
          await readConfirmedTeamGenesis(_userId!),
          _userId!,
          _signingPublicKey == null ? null : bytesToHex(_signingPublicKey!),
          _encryptionPublicKey == null
              ? null
              : bytesToHex(_encryptionPublicKey!),
        );
    for (final key in _deks.values) {
      _crypto.zeroize(key);
    }
    _deks.clear();

    final dekRows = await _db.getObjectsByType('dek');
    final unreadableOwn = <String>[];
    final refusedKeys = teamLogRefusal == null
        ? const <String>{}
        : await _teamKeyIds();
    for (final row in dekRows) {
      final payload = row['payload'] as Uint8List;
      final dekId = row['id'] as String;
      if (refusedKeys.contains(dekId)) continue;
      final team = teamLog?.team;
      if (team != null &&
          team.dekIndex.containsKey(dekId) &&
          (!trusted || !TeamLog.mayHoldKey(team, _userId ?? '', dekId))) {
        continue;
      }
      final ownerId = row['owner_id'] as String?;
      if (!_crypto.isEncryptedEnvelope(payload)) continue;
      try {
        final dekBytes = _crypto.unwrapDEK(
          payload,
          _kek!,
          dekId,
          version: row['version'] as int? ?? 1,
        );
        _deks[dekId] = dekBytes;
        _rootDekId ??= dekId;
      } catch (e) {
        // Other users' DEKs are wrapped with their KEK and stay opaque; an
        // own DEK that cannot be opened means a stale KEK — never hide it.
        if (ownerId == null || ownerId == _userId || _userId == 'local') {
          unreadableOwn.add(dekId);
        }
      }
    }
    final team = teamLog?.team;
    if (team != null &&
        _encryptionSecretKey != null &&
        _encryptionPublicKey != null &&
        await readConfirmedTeamGenesis(_userId!) == team.genesisHash) {
      for (final row in await _db.getObjectsByType('envelope')) {
        final dekId = row['parent_ref'] as String?;
        final signer = row['signer_id'] as String? ?? '';
        if (dekId == null ||
            row['target_user_id'] != _userId ||
            !TeamLog.envelopeValid(
              team,
              signer,
              _userId!,
              dekId,
              row['access_level'] as String?,
              bytesToHex(_encryptionPublicKey!),
            )) {
          continue;
        }
        final sender = team.members[signer]!;
        try {
          final payload = row['payload'] as Uint8List;
          if (!_crypto.verifyDetached(
            signature: row['client_signature'] as Uint8List,
            message: _crypto.buildSyncSignatureData(
              id: row['id'] as String,
              objectType: 'envelope',
              parentRef: dekId,
              targetUserId: _userId,
              isDeleted: 0,
              version: row['version'] as int,
              payloadHashHex: _crypto.sha256Hex(payload),
            ),
            publicKey: hexToBytes(sender.signingPk),
          )) {
            continue;
          }
          final key = _crypto.openAccessEnvelope(
            payload,
            _encryptionSecretKey!,
            hexToBytes(sender.encryptionPk),
          );
          final held = _deks[dekId];
          if (held != null) {
            var difference = 0;
            for (var i = 0; i < held.length; i++) {
              difference |= held[i] ^ key[i];
            }
            _crypto.zeroize(key);
            if (difference != 0)
              throw TeamLogMismatch('conflicting access envelope');
          } else {
            _deks[dekId] = key;
          }
        } on TeamLogMismatch {
          rethrow;
        } catch (_) {
          // A damaged or old-identity envelope supplies no key.
        }
      }
    }
    if (unreadableOwn.isNotEmpty) {
      throw StateError(
        'Cannot unwrap ${unreadableOwn.length} own key(s); the password was '
        'probably changed on another device. Sign in again with the current '
        'password.',
      );
    }
  }

  /// Load and decrypt all nodes and entries from local DB into memory.
  Future<void> _loadDecryptedData() async {
    _nodes.clear();
    _entries.clear();

    final allObjects = await _db.getAllObjects();
    final folderAccessLevels = deriveFolderAccessLevels(
      allObjects,
      _userId,
      team: teamLog?.team,
    );
    // Review 7c10379 H4: not what its author could not write there.
    final unauthorized = unauthorizedWrites(
      allObjects,
      _userId,
      team: teamLog?.team,
      teamAdmins: teamLog == null
          ? null
          : logAdmins(teamLog!.records, teamLog!.team),
    );

    // Decrypt nodes
    final nodeRows = await _db.getObjectsByType('node');
    for (final row in nodeRows) {
      if (unauthorized.contains(row['id'])) continue;
      try {
        final payload = row['payload'] as Uint8List;
        final id = row['id'] as String;
        final parentRef = row['parent_ref'] as String?;
        final version = row['version'] as int;
        final commitSeq = row['commit_seq'] as int?;

        if (_crypto.isEncryptedEnvelope(payload)) {
          // Review 18c300f R16-H2: the personal mark is what the sealed meta
          // says; it counts on a folder this account signed (a teammate
          // holding a team key could seal one that says it), as the web's.
          final json = _crypto.decryptEnvelope(
            payload,
            id,
            version,
            _deks,
            expectedBlobKind: BlobKind.nodeMeta,
          );
          json['personal'] = json['personal'] == true && isOwnRow(row, _userId);
          _nodes[id] = VaultNode.fromJson(
            id,
            json,
            parentRef: parentRef,
            version: version,
            commitSeq: commitSeq,
            dekId: _crypto.envelopeDekId(payload),
          );
        } else {
          // Legacy plaintext
          final json = jsonDecode(utf8.decode(payload)) as Map<String, dynamic>
            ..remove('personal');
          _nodes[id] = VaultNode.fromJson(
            id,
            json,
            parentRef: parentRef,
            version: version,
            commitSeq: commitSeq,
          );
        }

        // Find root node (no parent). TL7: a personal root is top-level
        // too but never the root.
        if ((parentRef == null || parentRef.isEmpty) && !_nodes[id]!.personal) {
          _rootNodeId = id;
        }
      } catch (e) {
        // Skip nodes that fail to decrypt
      }
    }

    // The root DEK is the one the root folder is encrypted with — not merely
    // the first DEK that unwraps (that could be a personal DEK).
    final rootNodeDekId = _nodes[_rootNodeId]?.dekId;
    if (rootNodeDekId != null && _deks.containsKey(rootNodeDekId)) {
      _rootDekId = rootNodeDekId;
    }

    // Decrypt entries
    final entryRows = await _db.getObjectsByType('entry');
    for (final row in entryRows) {
      if (unauthorized.contains(row['id'])) continue;
      try {
        final payload = row['payload'] as Uint8List;
        final id = row['id'] as String;
        final parentRef = row['parent_ref'] as String?;
        final version = row['version'] as int;
        final commitSeq = row['commit_seq'] as int?;
        final ownerId = row['owner_id'] as String?;
        final writePolicy = row['write_policy'] as String? ?? 'owner_only';

        if (_crypto.isCanonicalEntryPayload(payload)) {
          // Canonical two-envelope framing: u32be(meta_len) || meta_env || data_env
          final json = _crypto.decryptEntryPayload(payload, id, version, _deks);
          _entries[id] = VaultEntry.fromJson(
            id,
            json,
            parentRef: parentRef,
            version: version,
            commitSeq: commitSeq,
            ownerId: ownerId,
            dekId: _crypto.entryPayloadDekId(payload),
            writePolicy: writePolicy,
            accessLevel: parentRef == null
                ? null
                : folderAccessLevels[parentRef],
          );
        } else if (_crypto.isEncryptedEnvelope(payload)) {
          // Legacy single-envelope entry (pre-C6 mobile format)
          final json = _crypto.decryptEnvelope(
            payload,
            id,
            version,
            _deks,
            expectedBlobKind: BlobKind.entryData,
          );
          _entries[id] = VaultEntry.fromJson(
            id,
            json,
            parentRef: parentRef,
            version: version,
            commitSeq: commitSeq,
            ownerId: ownerId,
            dekId: _crypto.envelopeDekId(payload),
            writePolicy: writePolicy,
            accessLevel: parentRef == null
                ? null
                : folderAccessLevels[parentRef],
          );
        } else {
          // Legacy plaintext
          final json = jsonDecode(utf8.decode(payload)) as Map<String, dynamic>;
          _entries[id] = VaultEntry.fromJson(
            id,
            json,
            parentRef: parentRef,
            version: version,
            commitSeq: commitSeq,
            ownerId: ownerId,
            writePolicy: writePolicy,
            accessLevel: parentRef == null
                ? null
                : folderAccessLevels[parentRef],
          );
        }
      } catch (e) {
        // Skip entries that fail to decrypt
      }
    }

    // INV-7: while the log is refused only the personal tree shows; the
    // rules from before the log no longer decide (a server's folder, a
    // plaintext one, the organisation's tree under a key it holds).
    if (teamLogRefusal != null) {
      final shown = refusedLogPersonalTree(
        allObjects,
        _userId,
        personalNodes: {
          for (final n in _nodes.values)
            if (n.personal) n.id,
        },
        dekIds: {
          for (final n in _nodes.values) n.id: n.dekId,
          for (final e in _entries.values) e.id: e.dekId,
        },
        heldDekIds: _deks.keys.toSet(),
        tier2Entries: {
          for (final e in _entries.values)
            if (e.tier == 2) e.id,
        },
      );
      _nodes.removeWhere((id, _) => !shown.contains(id));
      _entries.removeWhere((id, _) => !shown.contains(id));
      if (!_nodes.containsKey(_rootNodeId)) _rootNodeId = null;
    }

    _folderDekIds
      ..clear()
      ..addAll(
        folderDekIdsFrom(
          dekRows: await _db.getObjectsByType('dek'),
          heldDekIds: _deks.keys.toSet(),
          team: teamLog?.team,
          userId: _userId,
          tier2DekIds: {
            for (final entry in _entries.values)
              if (entry.tier == 2 && entry.dekId != null) entry.dekId!,
          },
        ),
      );
  }

  // ── CRUD Operations ──

  /// Generate a proper ULID (26 chars, Crockford's Base32).
  ///
  /// Format: 10 chars timestamp (ms since epoch) + 16 chars random.
  /// Uses Crockford's Base32 alphabet: 0-9A-HJKMNP-TV (no I, L, O, U).
  String _generateId() {
    final now = DateTime.now().millisecondsSinceEpoch;
    final rng = Random.secure();

    // Encode 48-bit timestamp as 10 Crockford Base32 chars (big-endian)
    final ts = StringBuffer();
    var t = now;
    for (var i = 9; i >= 0; i--) {
      ts.write(_ulidAlphabet[t & 0x1F]);
      t >>= 5;
    }
    final tsStr = ts.toString().split('').reversed.join();

    // 16 random Crockford Base32 chars (80 bits of randomness)
    final rand = StringBuffer();
    for (var i = 0; i < 16; i++) {
      rand.write(_ulidAlphabet[rng.nextInt(32)]);
    }

    return '$tsStr${rand.toString()}';
  }

  String _writeDekId(
    String? parentRef, {
    String? existingDekId,
    String? existingParentRef,
  }) => resolveWriteDekId(
    parentRef: parentRef,
    nodes: _nodes,
    heldDekIds: _deks.keys.toSet(),
    rootDekId: _rootDekId!,
    folderDekIds: _folderDekIds,
    existingDekId: existingDekId,
    existingParentRef: existingParentRef,
    team: teamLog?.team,
  );

  /// Verify cached signatures and continuity before any local key is used.
  /// Corruption must not downgrade the vault to the pre-log permission rules.
  /// INV-7: a refusal names its cause; unlock and reload keep it in
  /// [teamLogRefusal] and open the personal tree only, never lock on it.
  /// [replacingUnreadableTrust]: the founder review, whose confirmation
  /// replaces trust records that cannot be read (capability run 411), reads
  /// them as absent; the copy is still held to the pins of the checkpoint.
  Future<LocalTeamLog?> _loadTeamLog({
    bool replacingUnreadableTrust = false,
  }) async {
    Future<String?> trust(Future<String?> Function(String) read) async {
      try {
        return await read(_userId!);
      } on TeamLogMismatch {
        if (!replacingUnreadableTrust) rethrow;
        return null;
      }
    }

    try {
      final confirmed = await trust(readConfirmedTeamGenesis);
      final raw = await _db.getSetting(teamLogRecordsSetting);
      final saved = await _db.getSyncState('sync_checkpoint:$_userId');
      final checkpoint = saved == null
          ? null
          : decodeSyncCheckpoint(saved, _kek!, _userId!);
      final pins = [
        if (teamLog != null) teamLogPin(teamLog!.team)!,
        if (checkpoint?['team_log'] != null)
          checkpoint!['team_log'] as Map<String, dynamic>,
      ];
      // Unreadable, it may hold any pin above: the team is refused
      // (local_damaged) even with no account anchor noted (run 412).
      await trust(
        (userId) async => (await readForgottenTeamGenesis(userId)).firstOrNull,
      );
      final anchor = await trust(readAccountTeamGenesis);
      if (anchor != null &&
          [
            confirmed,
            for (final pin in pins) pin['genesis_hash'],
            _heldGenesis(raw),
          ].any((genesis) => genesis != null && genesis != anchor)) {
        throw TeamLogMismatch(
          'names another genesis than the account keys (another server, or a log left elsewhere)',
          'anchor_conflict',
        );
      }
      _teamGenesisPinned =
          anchor != null || confirmed != null || pins.isNotEmpty;
      if (raw == null &&
          pins.isEmpty &&
          (confirmed == null || (await _db.getAllObjects()).isEmpty)) {
        return null;
      }
      return verifiedTeamLogCopy(raw, confirmed, pins, verifyEd25519);
    } on TeamLogMismatch catch (e) {
      if (e.cause != null) rethrow;
      throw _localDamaged(e.detail);
    } catch (e) {
      throw _localDamaged('$e');
    }
  }

  static TeamLogMismatch _localDamaged(String detail) => TeamLogMismatch(
    'copy held on this phone cannot be verified ($detail); the next sync fetches it '
        'again, held to the genesis and the head this phone saw',
    'local_damaged',
  );

  /// The genesis the cached copy [raw] holds: its first record, once it
  /// verifies as a genesis. Capability run 418: a damaged first record named
  /// its own hash as another genesis (anchor_conflict) instead of local
  /// damage the next sync repairs under the pins.
  String? _heldGenesis(String? raw) {
    try {
      final records = jsonDecode(raw!) as List;
      return TeamLog(
        verifyEd25519,
      ).replay([Map<String, dynamic>.from(records.first as Map)]).genesisHash;
    } catch (_) {
      return null;
    }
  }

  /// INV-7: why the team log is refused on this phone now (cause and way
  /// out), or null. While set, [teamLog] is null, no team key is opened, and
  /// only writes in the personal tree are taken.
  TeamLogMismatch? teamLogRefusal;

  Future<void> _loadTeamLogOrRefusal() async {
    try {
      teamLog = await _loadTeamLog();
      teamLogRefusal = null;
    } on TeamLogMismatch catch (e) {
      teamLog = null;
      teamLogRefusal = e;
    }
  }

  /// Keys a team envelope, a folder or a record of the cached copy names:
  /// while the log is refused only the others (personal, tier-2) are opened.
  Future<Set<String>> _teamKeyIds() async {
    final ids = <String>{
      for (final row in await _db.getObjectsByType('envelope'))
        if (row['parent_ref'] != null) row['parent_ref'] as String,
      for (final row in await _db.getObjectsByType('dek'))
        if (row['parent_ref'] != null) row['id'] as String,
    };
    try {
      final records =
          jsonDecode((await _db.getSetting(teamLogRecordsSetting))!) as List;
      final bodies = [
        for (final record in records)
          if (record is Map && record['body'] is String) record['body'],
      ];
      ids.addAll(
        (syncCore('authority_team_key_ids', {'bodies': bodies}) as List)
            .cast<String>(),
      );
    } catch (_) {
      // No copy, or one that does not parse.
    }
    return ids;
  }

  /// INV-7: which queued rows go out while the log is refused: the personal
  /// tree's (the write gate checked from and to when they were written) and
  /// keys of its own. The team's wait, named with the refusal.
  Future<bool Function(Map<String, dynamic>)> sendableWhileRefused() async {
    final teamKeys = await _teamKeyIds();
    final tree = _personalTree();
    return (row) {
      final id = row['id'] as String;
      final parent = row['parent_ref'] as String?;
      return switch (row['object_type']) {
        'dek' => parent == null && !teamKeys.contains(id),
        'node' =>
          parent == null ? _nodes[id]?.personal == true : tree.contains(parent),
        'entry' => tree.contains(parent),
        _ => false,
      };
    };
  }

  /// The folders that are a personal root or lie below one (the core's
  /// authority_personal_tree over the folders this phone opened).
  Set<String> _personalTree() => personalTree([
    for (final node in _nodes.values)
      {
        'id': node.id,
        'object_type': 'node',
        'parent_ref': node.parentRef,
        'dek_id': node.dekId,
        'personal': node.personal,
      },
  ], null)['tree']!;

  Future<({String userId, String genesis, int generation})>
  reviewTeamFounder() => whileKekFixed(() async {
    _ensureUnlocked();
    final userId = _userId!;
    final generation = _lockGeneration;
    final local = await _loadTeamLog(replacingUnreadableTrust: true);
    if (!isUnlocked || _userId != userId || _lockGeneration != generation) {
      throw const VaultLockedMeanwhile();
    }
    if (local == null) throw TeamLogMismatch('has no downloaded founder');
    return (
      userId: userId,
      genesis: local.team.genesisHash,
      generation: generation,
    );
  });

  Future<void> confirmTeamFounder(
    ({String userId, String genesis, int generation}) review,
    String fingerprint,
  ) => whileKekFixed(() async {
    void checkSession() {
      if (!isUnlocked ||
          _userId != review.userId ||
          _lockGeneration != review.generation) {
        throw const VaultLockedMeanwhile();
      }
    }

    checkSession();
    final expected = fingerprint.trim().toLowerCase();
    if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(expected)) {
      throw TeamLogMismatch(
        'requires an independent 64-character founder fingerprint',
      );
    }
    final local = await _loadTeamLog(replacingUnreadableTrust: true);
    checkSession();
    if (local == null || local.team.genesisHash != review.genesis) {
      throw TeamLogMismatch('changed since the founder review');
    }
    final matches = teamFounderLineage(local).keys.any(
      (pair) =>
          _crypto.computeFingerprint(
            TeamLog.fromHex(pair.$1),
            TeamLog.fromHex(pair.$2),
          ) ==
          expected,
    );
    if (!matches)
      throw TeamLogMismatch(
        'does not match the independent founder fingerprint',
      );
    await confirmTeamGenesis(
      review.userId,
      review.genesis,
      beforeWrite: checkSession,
      replaceUnreadable: true,
    );
    checkSession();
    // Reopen already held ciphertext without resetting the checkpoint or queue.
    await reloadData();
    checkSession();
  });

  bool verifyEd25519(
    Uint8List signature,
    Uint8List message,
    Uint8List publicKey,
  ) => _crypto.verifyDetached(
    signature: signature,
    message: message,
    publicKey: publicKey,
  );

  Future<void> assertTrustedTeamWrites(
    List<Map<String, dynamic>> writes, {
    Map<String, Map<String, dynamic>>? heldRows,
  }) async {
    if (_userId == null) return;
    final confirmed = await readConfirmedTeamGenesis(_userId!);
    requireTrustedTeamWrites(
      teamLog,
      confirmed,
      _userId!,
      _signingPublicKey == null ? null : TeamLog.toHex(_signingPublicKey!),
      _encryptionPublicKey == null
          ? null
          : TeamLog.toHex(_encryptionPublicKey!),
      writes,
      heldRows ??
          {
            for (final row in await _db.getAllObjects())
              row['id'] as String: row,
          },
    );
  }

  /// Before a folder or item this account wrote is stored to be sent: what
  /// the log refuses is not queued (the server would refuse it for good).
  /// [extraRows] are rows written with it (a new key of its own).
  Future<void> _assertTeamLogAllows({
    required String id,
    required String objectType,
    required String? parentRef,
    required Uint8List payload,
    int isDeleted = 0,
    List<Map<String, dynamic>> extraRows = const [],
  }) async {
    final refusal = teamLogRefusal;
    if (refusal != null) {
      // INV-7: a refused log refuses the team, never a write in the personal
      // tree (which holds no team folder), from and to.
      final tree = _personalTree();
      bool personal(String? parent) =>
          parent == null ? _nodes[id]?.personal == true : tree.contains(parent);
      final held = await _db.getObject(id);
      if (personal(parentRef) &&
          (held == null || personal(held['parent_ref'] as String?))) {
        return;
      }
      throw refusal;
    }
    final team = teamLog?.team;
    requireConfirmedGenesis(
      await readConfirmedTeamGenesis(_userId!),
      team?.genesisHash,
    );
    if (team == null) return;
    final rows = {
      for (final r in [...await _db.getAllObjects(), ...extraRows])
        r['id'] as String: r,
    };
    final write = <String, dynamic>{
      'id': id,
      'object_type': objectType,
      'parent_ref': parentRef,
      'payload': payload,
      'is_deleted': isDeleted,
      'signer_id': _userId,
    };
    await assertTrustedTeamWrites([write], heldRows: rows);
    final refused = teamLogWriteRefusal(team, _userId!, write, rows);
    if (refused != null) throw TeamLogRefused(refused);
  }

  /// Create a new folder node.
  Future<VaultNode> createNode({
    required String name,
    String? icon,
    required String parentRef,
  }) => whileKekFixed(() async {
    _ensureUnlocked();

    final id = _generateId();
    final dekId = _writeDekId(parentRef);
    final dek = _deks[dekId]!;

    final meta = {'name': name};
    if (icon != null) meta['icon'] = icon;

    final payload = _crypto.encryptEnvelope(
      meta,
      dek,
      dekId,
      id,
      1,
      BlobKind.nodeMeta,
    );
    await _assertTeamLogAllows(
      id: id,
      objectType: 'node',
      parentRef: parentRef,
      payload: payload,
    );
    final payloadHash = _crypto.sha256Hex(payload);

    final signature = _crypto.signSyncObject(
      id: id,
      objectType: 'node',
      parentRef: parentRef,
      targetUserId: null,
      isDeleted: 0,
      version: 1,
      payloadHashHex: payloadHash,
      signingSecretKey: _signingSecretKey!,
    );

    await _db.upsertObject(
      id: id,
      objectType: 'node',
      payload: payload,
      ownerId: _userId,
      parentRef: parentRef,
      version: 1,
      payloadHash: payloadHash,
      clientSignature: signature,
      queued: true,
    );

    final node = VaultNode(
      id: id,
      name: name,
      icon: icon,
      parentRef: parentRef,
      version: 1,
      dekId: dekId,
    );
    _nodes[id] = node;
    return node;
  });

  /// Create a personal folder with its own DEK — no admin envelope.
  ///
  /// Only the creating user can decrypt entries in this folder.
  /// Admin sees encrypted blobs but cannot read contents.
  Future<VaultNode> createPersonalFolder({required String name}) =>
      whileKekFixed(() => _createPersonalFolder(name));

  Future<VaultNode> _createPersonalFolder(String name) async {
    _ensureUnlocked();

    // 1. Generate a personal DEK (separate from root DEK)
    final personalDekBytes = _crypto.generateDEK();
    final personalDekId = _generateId();
    final wrappedDek = _crypto.wrapDEK(
      personalDekBytes,
      personalDekId,
      _kek!,
      _kekDekId!,
    );
    final dekPayloadHash = _crypto.sha256Hex(wrappedDek);

    final dekSignature = _crypto.signSyncObject(
      id: personalDekId,
      objectType: 'dek',
      parentRef: null,
      targetUserId: null,
      isDeleted: 0,
      version: 1,
      payloadHashHex: dekPayloadHash,
      signingSecretKey: _signingSecretKey!,
    );

    await _db.upsertObject(
      id: personalDekId,
      objectType: 'dek',
      payload: wrappedDek,
      ownerId: _userId,
      version: 1,
      payloadHash: dekPayloadHash,
      clientSignature: dekSignature,
      queued: true,
    );

    _deks[personalDekId] = personalDekBytes;

    // 2. Create the personal folder node, encrypted with the personal DEK
    final id = _generateId();
    // TL7: a personal root, top-level, not below the organisation's root.
    const String? parentRef = null;

    final meta = {'name': name, 'personal': true};
    final payload = _crypto.encryptEnvelope(
      meta,
      personalDekBytes,
      personalDekId,
      id,
      1,
      BlobKind.nodeMeta,
    );
    final payloadHash = _crypto.sha256Hex(payload);

    final signature = _crypto.signSyncObject(
      id: id,
      objectType: 'node',
      parentRef: parentRef,
      targetUserId: null,
      isDeleted: 0,
      version: 1,
      payloadHashHex: payloadHash,
      signingSecretKey: _signingSecretKey!,
    );

    await _db.upsertObject(
      id: id,
      objectType: 'node',
      payload: payload,
      ownerId: _userId,
      parentRef: parentRef,
      version: 1,
      payloadHash: payloadHash,
      clientSignature: signature,
      queued: true,
    );

    final node = VaultNode(
      id: id,
      name: name,
      icon: 'lock',
      parentRef: parentRef,
      version: 1,
      dekId: personalDekId,
      personal: true,
    );
    _nodes[id] = node;
    return node;
  }

  /// Create a new entry.
  ///
  /// Produces ONE vault_object (id = entry id) in the canonical cross-client
  /// wire format (spec §4.1 + §8.2, matching desktop/web):
  ///   payload = u32be(len(metaEnv)) || metaEnv(ENTRY_META=2) || dataEnv(ENTRY_DATA=3)
  ///   metaEnv over {name, tags}; dataEnv over {fields, notes?}
  Future<VaultEntry> createEntry({
    required String parentRef,
    required String name,
    required List<EntryField> fields,
    List<String> tags = const [],
    String? notes,
    String writePolicy = 'owner_only',
  }) => whileKekFixed(() async {
    _ensureUnlocked();

    final entryId = _generateId();
    final dekId = _writeDekId(parentRef);
    final dek = _deks[dekId]!;

    final metaJson = {'name': name, 'tags': tags};
    final dataJson = {
      'fields': fields.map((f) => f.toJson()).toList(),
      if (notes != null) 'notes': notes,
    };
    final payload = _crypto.encryptEntryPayload(
      metaJson,
      dataJson,
      dek,
      dekId,
      entryId,
      1,
    );
    // Review 526419e #1: never saved if the server can never take it.
    requireSyncablePayload(payload);
    await _assertTeamLogAllows(
      id: entryId,
      objectType: 'entry',
      parentRef: parentRef,
      payload: payload,
    );
    final payloadHash = _crypto.sha256Hex(payload);

    final signature = _crypto.signSyncObject(
      id: entryId,
      objectType: 'entry',
      parentRef: parentRef,
      targetUserId: null,
      isDeleted: 0,
      version: 1,
      payloadHashHex: payloadHash,
      signingSecretKey: _signingSecretKey!,
    );

    await _db.upsertObject(
      id: entryId,
      objectType: 'entry',
      payload: payload,
      ownerId: _userId,
      parentRef: parentRef,
      version: 1,
      payloadHash: payloadHash,
      clientSignature: signature,
      queued: true,
      writePolicy: writePolicy,
    );

    final entry = VaultEntry(
      id: entryId,
      name: name,
      fields: fields,
      tags: tags,
      parentRef: parentRef,
      version: 1,
      notes: notes,
      ownerId: _userId,
      writePolicy: writePolicy,
      dekId: dekId,
    );
    _entries[entryId] = entry;
    return entry;
  });

  /// Read a decrypted entry from the in-memory cache.
  VaultEntry? readEntry(String entryId) {
    _ensureUnlocked();
    return _entries[entryId];
  }

  /// Update an existing entry.
  Future<VaultEntry> updateEntry({
    required String entryId,
    String? name,
    List<EntryField>? fields,
    List<String>? tags,
    String? notes,
    String? writePolicy,
    int? expectedVersion,
    ({int version, String? hash})? rebaseOn,
  }) => whileKekFixed(() async {
    _ensureUnlocked();

    final existing = _entries[entryId];
    if (existing == null) throw StateError('Entry not found: $entryId');
    if (!existing.canEdit(_userId, isAdmin)) {
      throw StateError('Entry is read-only');
    }
    ensureEditBase(existing, expectedVersion);

    final updatedName = name ?? existing.name;
    final updatedFields = fields ?? existing.fields;
    final updatedTags = tags ?? existing.tags;
    final updatedNotes = notes ?? existing.notes;
    final updatedPolicy = writePolicy ?? existing.writePolicy;
    // [rebaseOn]: keep a conflicting local change on top of the server's.
    final newVersion = (rebaseOn?.version ?? existing.version) + 1;

    final dekId = _writeDekId(
      existing.parentRef,
      existingDekId: existing.dekId,
      existingParentRef: existing.parentRef,
    );
    final dek = _deks[dekId]!;

    // Keep the desktop tier: it marks a tier-2 entry DEK, never a folder DEK.
    final metaJson = <String, dynamic>{
      'name': updatedName,
      'tags': updatedTags,
      if (existing.tier != null) 'tier': existing.tier,
    };
    final dataJson = {
      'fields': updatedFields.map((f) => f.toJson()).toList(),
      if (updatedNotes != null) 'notes': updatedNotes,
    };

    final payload = _crypto.encryptEntryPayload(
      metaJson,
      dataJson,
      dek,
      dekId,
      entryId,
      newVersion,
    );
    requireSyncablePayload(payload);
    await _assertTeamLogAllows(
      id: entryId,
      objectType: 'entry',
      parentRef: existing.parentRef,
      payload: payload,
    );
    final payloadHash = _crypto.sha256Hex(payload);

    final signature = _crypto.signSyncObject(
      id: entryId,
      objectType: 'entry',
      parentRef: existing.parentRef,
      targetUserId: null,
      isDeleted: 0,
      version: newVersion,
      payloadHashHex: payloadHash,
      signingSecretKey: _signingSecretKey!,
    );

    final storedRow = await _db.getObject(entryId);
    try {
      await _db.upsertObject(
        id: entryId,
        objectType: 'entry',
        payload: payload,
        ownerId: existing.ownerId ?? _userId,
        parentRef: existing.parentRef,
        version: newVersion,
        // Keep the last server-confirmed sequence: a local edit is not a new
        // never-synced object (see SyncService._computeStateHash).
        commitSeq: storedRow?['commit_seq'] as int?,
        payloadHash: payloadHash,
        clientSignature: signature,
        queued: true,
        writePolicy: updatedPolicy,
        accessLevel: storedRow?['access_level'] as String?,
        rebaseOn: rebaseOn,
        // R16-M1: a sync awaited above stored another version: not replaced.
        replacesVersion: rebaseOn == null ? existing.version : null,
      );
    } on StaleRowException catch (e) {
      throw StaleEntryEditException(
        entryId,
        expectedVersion: e.expected,
        currentVersion: e.current ?? e.expected,
      );
    }

    final updated = VaultEntry(
      id: entryId,
      name: updatedName,
      fields: updatedFields,
      tags: updatedTags,
      parentRef: existing.parentRef,
      version: newVersion,
      notes: updatedNotes,
      ownerId: existing.ownerId,
      writePolicy: updatedPolicy,
      accessLevel: existing.accessLevel,
      dekId: dekId,
      tier: existing.tier,
    );
    _entries[entryId] = updated;
    return updated;
  });

  /// Conflict "keep mine": put this device's change on top of the server
  /// version (version = server + 1, re-encrypted and re-signed, still dirty),
  /// so the next push is accepted. The conflict shadow stays until then.
  /// False for a change that cannot be rebased here (keep it held aside).
  Future<bool> keepLocalChange(String objectId, int serverVersion) =>
      whileKekFixed(() async {
        _ensureUnlocked();
        final row = await _db.getObject(objectId);
        if (row == null || row['queued'] != 1) return false;
        // S1: rebased on the server copy held aside, as (version, hash). With
        // no such copy the hash is unknown and the server answers a conflict.
        final shadow = await _db.getSyncConflict(objectId);
        final serverHash = shadow?['server_version'] == serverVersion
            ? shadow!['server_payload_hash'] as String?
            : null;
        final version = serverVersion + 1;
        if ((row['is_deleted'] as int? ?? 0) == 1) {
          final payload = row['payload'] as Uint8List;
          final payloadHash = _crypto.sha256Hex(payload);
          // Capability run 567: the phone moves nothing, so a delete kept on
          // top of the server copy stays where that copy is. Its own older
          // parent read as a move; with that parent moved below the folder
          // meanwhile, the server refused it (folder_move_cycle) every push.
          final serverRow = serverHash == null ? null : shadow!['server_row'];
          final String? parentRef = serverRow is String
              ? (jsonDecode(serverRow) as Map)['parent_ref'] as String?
              : row['parent_ref'] as String?;
          await assertTrustedTeamWrites([
            {...row, 'parent_ref': parentRef},
          ]);
          await _db.upsertObject(
            id: objectId,
            objectType: row['object_type'] as String,
            payload: payload,
            ownerId: row['owner_id'] as String?,
            parentRef: parentRef,
            targetUserId: row['target_user_id'] as String?,
            version: version,
            commitSeq: row['commit_seq'] as int?,
            isDeleted: 1,
            payloadHash: payloadHash,
            clientSignature: _crypto.signSyncObject(
              id: objectId,
              objectType: row['object_type'] as String,
              parentRef: parentRef,
              targetUserId: row['target_user_id'] as String?,
              isDeleted: 1,
              version: version,
              payloadHashHex: payloadHash,
              signingSecretKey: _signingSecretKey!,
            ),
            queued: true,
            writePolicy: row['write_policy'] as String?,
            accessLevel: row['access_level'] as String?,
            rebaseOn: (version: serverVersion, hash: serverHash),
          );
          return true;
        }
        if (row['object_type'] == 'entry' && _entries.containsKey(objectId)) {
          await updateEntry(
            entryId: objectId,
            rebaseOn: (version: serverVersion, hash: serverHash),
          );
          return true;
        }
        return false;
      });

  /// Conflict "use server version": the verified server copy replaces this
  /// device's change of that one object. False when only a full resync can.
  Future<bool> takeServerVersion(String objectId) async {
    _ensureUnlocked();
    if (!await _db.takeServerConflictCopy(objectId)) return false;
    await reloadData();
    return true;
  }

  /// Re-apply exported unsent changes on top of the current vault (lockout
  /// review M4): new folders and entries are created again, edited entries
  /// get the exported content as a new version on the server version it was
  /// made on, so a newer server copy is a conflict on the next push (a copy
  /// when the live entry has unsent edits of its own or the export has no
  /// base; see [planUnsentReapply]). What is already in the vault is not added twice, so
  /// the same export can be imported again. All of it stays dirty for the
  /// next push. Keys created in the export (e.g. a new personal folder's
  /// DEK) are only used to read it.
  Future<UnsentReapplyResult> reapplyUnsentChanges(
    List<Map<String, dynamic>> objects,
  ) async {
    _ensureUnlocked();
    final readDeks = Map<String, Uint8List>.of(_deks);
    for (final object in objects) {
      if (object['object_type'] != 'dek' ||
          readDeks.containsKey(object['id'])) {
        continue;
      }
      try {
        readDeks[object['id'] as String] = _crypto.unwrapDEK(
          base64Decode(object['payload'] as String),
          _kek!,
          object['id'] as String,
          version: object['version'] as int,
        );
      } catch (_) {
        // Another user's wrap or a damaged one: its objects stay unread.
      }
    }

    // A row with unsent edits of its own is not a server-confirmed state,
    // even though it keeps its old base (capability review run 55).
    final rows = {
      for (final row in await _db.getObjectsByType('entry'))
        row['id'] as String: row,
    };
    final plan = planUnsentReapply(
      objects,
      liveNodeIds: {
        for (final n in _nodes.values)
          if (!n.isDeleted) n.id,
      },
      liveEntryBases: liveEntryConfirmedBases([
        for (final e in _entries.values)
          if (!e.isDeleted && rows[e.id] != null) rows[e.id]!,
      ]),
    );
    final newIds = <String, String>{};
    String parentFor(String? exported) {
      if (exported != null && newIds.containsKey(exported)) {
        return newIds[exported]!;
      }
      final live = exported == null ? null : _nodes[exported];
      if (live != null && !live.isDeleted) return live.id;
      return _rootNodeId!;
    }

    var applied = 0;
    var alreadyPresent = 0;
    final notApplied = <String>[];
    try {
      for (final step in plan) {
        final object = step.object;
        final type = object['object_type'] as String;
        if (step.action == UnsentAction.skip) {
          notApplied.add('$type ${step.id}: ${step.reason}');
          continue;
        }
        final payload = base64Decode(object['payload'] as String);
        final version = object['version'] as int;
        try {
          if (step.action == UnsentAction.createNode) {
            final meta = _crypto.decryptEnvelope(
              payload,
              step.id,
              version,
              readDeks,
              expectedBlobKind: BlobKind.nodeMeta,
            );
            final name = meta['name'] as String? ?? 'Recovered folder';
            final personal = meta['personal'] == true;
            final String? parentRef = personal
                ? null // TL7: a personal root
                : parentFor(object['parent_ref'] as String?);
            // Importing the same export again reuses what it created.
            final existing = _nodes.values.where(
              (n) =>
                  !n.isDeleted &&
                  n.parentRef == parentRef &&
                  n.name == name &&
                  n.personal == personal,
            );
            if (existing.isNotEmpty) {
              newIds[step.id] = existing.first.id;
              alreadyPresent++;
              continue;
            }
            final node = personal
                ? await createPersonalFolder(name: name)
                : await createNode(
                    name: name,
                    icon: meta['icon'] as String?,
                    parentRef: parentRef!,
                  );
            newIds[step.id] = node.id;
          } else {
            final json = _crypto.isCanonicalEntryPayload(payload)
                ? _crypto.decryptEntryPayload(
                    payload,
                    step.id,
                    version,
                    readDeks,
                  )
                : _crypto.decryptEnvelope(
                    payload,
                    step.id,
                    version,
                    readDeks,
                    expectedBlobKind: BlobKind.entryData,
                  );
            final exported = VaultEntry.fromJson(step.id, json);
            final live = _entries[step.id];
            if (live != null && sameEntryContent(live, exported)) {
              alreadyPresent++;
              continue;
            }
            if (step.action == UnsentAction.updateEntry) {
              await updateEntry(
                entryId: step.id,
                name: exported.name,
                fields: exported.fields,
                tags: exported.tags,
                notes: exported.notes,
              );
            } else if (step.action == UnsentAction.updateOnItsBase) {
              // The server copy becomes the conflict shadow, the edit stays
              // on the version it was made on: the state a pull leaves.
              final serverRow = (await _db.getObject(step.id))!;
              final edited = await updateEntry(
                entryId: step.id,
                name: exported.name,
                fields: exported.fields,
                tags: exported.tags,
                notes: exported.notes,
                rebaseOn: entryBase(object),
              );
              await _db.holdServerCopyAside(
                serverRow,
                localVersion: edited.version,
              );
            } else {
              final parentRef = parentFor(object['parent_ref'] as String?);
              final name = step.action == UnsentAction.copyEntry
                  ? '${exported.name} (unsent copy)'
                  : exported.name;
              if (_entries.values.any(
                (e) =>
                    !e.isDeleted &&
                    e.parentRef == parentRef &&
                    sameEntryContent(e, exported, asName: name),
              )) {
                alreadyPresent++;
                continue;
              }
              await createEntry(
                parentRef: parentRef,
                name: name,
                fields: exported.fields,
                tags: exported.tags,
                notes: exported.notes,
                writePolicy: object['write_policy'] as String? ?? 'owner_only',
              );
            }
          }
          applied++;
        } catch (_) {
          notApplied.add('$type ${step.id}: cannot be read or written here');
        }
      }
    } finally {
      for (final entry in readDeks.entries) {
        if (!_deks.containsKey(entry.key)) _crypto.zeroize(entry.value);
      }
    }
    return UnsentReapplyResult(
      applied: applied,
      alreadyPresent: alreadyPresent,
      notApplied: notApplied,
    );
  }

  /// Add the folders and entries of another vault (this device's own vault
  /// before it joined an account) to this one, written again under this
  /// vault's keys. [fromRootId] is that vault's root: its items land in this
  /// root. A folder or entry already here (same parent and content) is
  /// reused, so a retry does not add it twice. Returns the number added.
  Future<int> addCarriedItems({
    required String? fromRootId,
    required List<VaultNode> nodes,
    required List<CarriedEntry> entries,
  }) async {
    _ensureUnlocked();
    final root = _rootNodeId;
    if (root == null) throw StateError('The vault has no root folder');
    final newIds = <String, String>{?fromRootId: root};
    String parentFor(String? ref) => newIds[ref] ?? root;
    var added = 0;
    final pending = [
      for (final n in nodes)
        if (n.id != fromRootId) n,
    ];
    // Parents before children; a folder whose parent is gone lands in root.
    while (pending.isNotEmpty) {
      final ready = pending.firstWhere(
        (n) =>
            newIds.containsKey(n.parentRef) ||
            !pending.any((p) => p.id == n.parentRef),
      );
      pending.remove(ready);
      final parentRef = ready.personal ? root : parentFor(ready.parentRef);
      final existing = _nodes.values.where(
        (n) =>
            !n.isDeleted &&
            n.parentRef == parentRef &&
            n.name == ready.name &&
            n.personal == ready.personal,
      );
      if (existing.isNotEmpty) {
        newIds[ready.id] = existing.first.id;
        continue;
      }
      final node = ready.personal
          ? await createPersonalFolder(name: ready.name)
          : await createNode(
              name: ready.name,
              icon: ready.icon,
              parentRef: parentRef,
            );
      newIds[ready.id] = node.id;
      added++;
    }
    for (final item in entries) {
      final parentRef = parentFor(item.parentRef);
      final carried = item.entry;
      if (_entries.values.any(
        (e) =>
            !e.isDeleted &&
            e.parentRef == parentRef &&
            sameEntryContent(e, carried),
      )) {
        continue;
      }
      await whileKekFixed(() => _writeCarriedEntry(parentRef, item));
      added++;
    }
    return added;
  }

  /// Every live entry of this vault with its complete payload, for a join to
  /// carry (review 688edcb: the model-only copy dropped the tier, field
  /// extras and anything a newer client keeps). Throws when a live folder or
  /// entry cannot be read, so the join refuses instead of dropping it.
  Future<List<CarriedEntry>> carriedEntries() async {
    _ensureUnlocked();
    for (final row in await _db.getObjectsByType('node')) {
      if ((row['is_deleted'] as int? ?? 0) == 0 &&
          !_nodes.containsKey(row['id'])) {
        throw StateError('Folder ${row['id']} cannot be read');
      }
    }
    final carried = <CarriedEntry>[];
    for (final row in await _db.getObjectsByType('entry')) {
      if ((row['is_deleted'] as int? ?? 0) == 1) continue;
      final id = row['id'] as String;
      final payload = row['payload'] as Uint8List;
      final version = row['version'] as int;
      Map<String, dynamic> meta;
      Map<String, dynamic> data;
      try {
        if (_crypto.isCanonicalEntryPayload(payload)) {
          (meta, data) = _crypto.decryptEntryParts(payload, id, version, _deks);
        } else {
          final json = _crypto.isEncryptedEnvelope(payload)
              ? _crypto.decryptEnvelope(
                  payload,
                  id,
                  version,
                  _deks,
                  expectedBlobKind: BlobKind.entryData,
                )
              : jsonDecode(utf8.decode(payload)) as Map<String, dynamic>;
          meta = {
            for (final key in const ['name', 'tags', 'tier'])
              if (json.containsKey(key)) key: json[key],
          };
          data = {
            for (final e in json.entries)
              if (!meta.containsKey(e.key)) e.key: e.value,
          };
        }
      } catch (_) {
        throw StateError('Entry $id cannot be read');
      }
      carried.add(
        CarriedEntry(
          parentRef: row['parent_ref'] as String?,
          meta: meta,
          data: data,
          writePolicy: row['write_policy'] as String? ?? 'owner_only',
        ),
      );
    }
    return carried;
  }

  /// A carried entry written as a new entry of this vault: its payload as it
  /// was, and a tier-2 entry under a new DEK of its own (as desktop keeps it).
  Future<void> _writeCarriedEntry(String parentRef, CarriedEntry item) async {
    final entryId = _generateId();
    String dekId;
    Uint8List dek;
    Future<void> Function()? storeOwnKey;
    if (item.tier == 2) {
      dek = _crypto.generateDEK();
      dekId = _generateId();
      final ownKeyId = dekId;
      final ownKey = dek;
      final wrapped = _crypto.wrapDEK(dek, dekId, _kek!, _kekDekId!);
      final wrappedHash = _crypto.sha256Hex(wrapped);
      storeOwnKey = () async {
        await _db.upsertObject(
          id: ownKeyId,
          objectType: 'dek',
          payload: wrapped,
          ownerId: _userId,
          version: 1,
          payloadHash: wrappedHash,
          clientSignature: _crypto.signSyncObject(
            id: ownKeyId,
            objectType: 'dek',
            parentRef: null,
            targetUserId: null,
            isDeleted: 0,
            version: 1,
            payloadHashHex: wrappedHash,
            signingSecretKey: _signingSecretKey!,
          ),
          queued: true,
        );
        _deks[ownKeyId] = ownKey;
      };
    } else {
      dekId = _writeDekId(parentRef);
      dek = _deks[dekId]!;
    }
    final payload = _crypto.encryptEntryPayload(
      item.meta,
      item.data,
      dek,
      dekId,
      entryId,
      1,
    );
    await _assertTeamLogAllows(
      id: entryId,
      objectType: 'entry',
      parentRef: parentRef,
      payload: payload,
      extraRows: [
        if (storeOwnKey != null)
          {
            'id': dekId,
            'object_type': 'dek',
            'parent_ref': null,
            'signer_id': _userId,
          },
      ],
    );
    await storeOwnKey?.call();
    final payloadHash = _crypto.sha256Hex(payload);
    await _db.upsertObject(
      id: entryId,
      objectType: 'entry',
      payload: payload,
      ownerId: _userId,
      parentRef: parentRef,
      version: 1,
      payloadHash: payloadHash,
      clientSignature: _crypto.signSyncObject(
        id: entryId,
        objectType: 'entry',
        parentRef: parentRef,
        targetUserId: null,
        isDeleted: 0,
        version: 1,
        payloadHashHex: payloadHash,
        signingSecretKey: _signingSecretKey!,
      ),
      queued: true,
      writePolicy: item.writePolicy,
    );
    _entries[entryId] = VaultEntry.fromJson(
      entryId,
      {...item.meta, ...item.data},
      parentRef: parentRef,
      ownerId: _userId,
      writePolicy: item.writePolicy,
      dekId: dekId,
    );
  }

  /// Brings back a folder another device deleted while this phone created or
  /// edited an item in it (desktop sync_state._revive_folders_of_unsent; the
  /// conformance scenario offline_write_under_deleted_folder). The server
  /// refuses an item below a deleted folder, so without this the item stayed
  /// queued for good. The folder comes back one version above its tombstone
  /// (whose blob is sealed at a version below it) and is sent ahead of the
  /// item. Returns the folders brought back.
  Future<List<String>> reviveFoldersOfUnsent() => whileKekFixed(() async {
    _ensureUnlocked();
    final revived = <String>[];
    final refused = <String>{};
    for (var level = 0; level < 64; level++) {
      final rows = [
        for (final row in await _db.deletedFoldersWithUnsentWork())
          if (!refused.contains(row['id'])) row,
      ];
      if (rows.isEmpty) break;
      // Runs right after the pull's commit: the keys it brought (a re-key's
      // new generation) are not loaded yet.
      if (level == 0) await _loadDEKs();
      // docs/CORE_UNIFICATION.md U7e: which come back, at which version
      // (above every version this phone sent too, R16-Z SM18), is the
      // core's (core/src/revive.rs).
      final byId = {for (final row in rows) row['id'] as String: row};
      final due =
          syncCore('revive_folders', {
                'work_in': byId.keys.toList(),
                'deleted': [
                  for (final row in rows)
                    {
                      'id': row['id'],
                      'version': row['version'],
                      'sent': await _db.highestSentVersion(row['id'] as String),
                    },
                ],
              })
              as List;
      for (final revive in due.cast<Map>()) {
        final row = byId[revive['id'] as String]!;
        final id = row['id'] as String;
        final payload = row['payload'] as Uint8List;
        final parentRef = row['parent_ref'] as String?;
        final tombstone = row['version'] as int;
        // Review c78fd19 (medium): runs after the pull's checkpoint is
        // stored, so a folder this phone could not open threw on every later
        // pull too. It stays deleted now; the push reports the item.
        if (!_crypto.isEncryptedEnvelope(payload)) {
          refused.add(id);
          continue;
        }
        final sealedWith = _crypto.envelopeDekId(payload);
        // A tombstone sealed with a key a re-key replaced since (kept for
        // the unsent work below it, as in _resealUnsent): the folder comes
        // back under the folder's current key.
        final team = teamLog?.team;
        final replaced = _deks[sealedWith] == null
            ? await _ownWrappedDek(sealedWith) ??
                  await _keptUnsentDek(sealedWith) ??
                  (team == null
                      ? null
                      : await _ownEnvelopeDek(sealedWith, team))
            : null;
        final opening = replaced ?? _deks[sealedWith];
        var dekId = sealedWith;
        if (opening != null && team != null) {
          final to =
              (syncCore('reseal_targets', {
                            'team': syncCoreTeam(
                              team,
                              _userId ?? '',
                              keys: [sealedWith],
                            ),
                            'held': _deks.keys.toList(),
                            'keys': [sealedWith],
                          })
                          as List)
                      .first
                  as Map;
          if (to['send'] == 'reseal') dekId = to['key'] as String;
        }
        final dek = _deks[dekId];
        Map<String, dynamic>? meta;
        for (
          var sealedAt = tombstone;
          opening != null &&
              dek != null &&
              sealedAt >= 0 &&
              sealedAt > tombstone - 256;
          sealedAt--
        ) {
          try {
            meta = _crypto.decryptEnvelope(payload, id, sealedAt, {
              sealedWith: opening,
            }, expectedBlobKind: BlobKind.nodeMeta);
            break;
          } catch (_) {
            continue;
          }
        }
        if (replaced != null) _crypto.zeroize(replaced);
        if (meta == null || dek == null) {
          refused.add(id);
          continue;
        }
        final version = revive['version'] as int;
        final sealed = _crypto.encryptEnvelope(
          meta,
          dek,
          dekId,
          id,
          version,
          BlobKind.nodeMeta,
        );
        try {
          await _assertTeamLogAllows(
            id: id,
            objectType: 'node',
            parentRef: parentRef,
            payload: sealed,
          );
        } on TeamLogRefused {
          refused.add(id); // stays deleted; the push reports the item
          continue;
        }
        final payloadHash = _crypto.sha256Hex(sealed);
        await _db.reviveFolder(
          id,
          payload: sealed,
          version: version,
          payloadHash: payloadHash,
          clientSignature: _crypto.signSyncObject(
            id: id,
            objectType: 'node',
            parentRef: parentRef,
            targetUserId: null,
            isDeleted: 0,
            version: version,
            payloadHashHex: payloadHash,
            signingSecretKey: _signingSecretKey!,
          ),
        );
        revived.add(id);
      }
    }
    return revived;
  });

  Future<void> _softDeleteObject(String id) => whileKekFixed(() async {
    final row = await _db.getObject(id);
    if (row == null || (row['is_deleted'] as int? ?? 0) == 1) return;

    final payload = row['payload'] as Uint8List;
    if (row['object_type'] == 'node' || row['object_type'] == 'entry') {
      await _assertTeamLogAllows(
        id: id,
        objectType: row['object_type'] as String,
        parentRef: row['parent_ref'] as String?,
        payload: payload,
        isDeleted: 1,
      );
    }
    final payloadHash = _crypto.sha256Hex(payload);
    final version = (row['version'] as int) + 1;
    final signature = _crypto.signSyncObject(
      id: id,
      objectType: row['object_type'] as String,
      parentRef: row['parent_ref'] as String?,
      targetUserId: row['target_user_id'] as String?,
      isDeleted: 1,
      version: version,
      payloadHashHex: payloadHash,
      signingSecretKey: _signingSecretKey!,
    );

    await _db.softDelete(
      id,
      version: version,
      payloadHash: payloadHash,
      clientSignature: signature,
    );
  });

  /// Soft-delete an entry (tombstone).
  Future<void> deleteEntry(String entryId) async {
    _ensureUnlocked();

    final existing = _entries[entryId];
    if (existing == null) return;
    if (!existing.canEdit(_userId, isAdmin)) {
      throw StateError('Entry is read-only');
    }

    await _softDeleteObject(entryId);
    _entries.remove(entryId);
  }

  /// Soft-delete a node (folder) and all its children.
  Future<void> deleteNode(String nodeId) async {
    _ensureUnlocked();

    // Delete all entries in this folder
    final childEntries = _entries.values
        .where((e) => e.parentRef == nodeId)
        .toList();
    for (final entry in childEntries) {
      await deleteEntry(entry.id);
    }

    // Delete all child nodes recursively
    final childNodes = _nodes.values
        .where((n) => n.parentRef == nodeId)
        .toList();
    for (final node in childNodes) {
      await deleteNode(node.id);
    }

    await _softDeleteObject(nodeId);
    _nodes.remove(nodeId);
  }

  // ── Query ──

  /// List all nodes under a parent. TL7: personal roots are listed among
  /// the root's folders.
  List<VaultNode> listNodes(String? parentId) {
    _ensureUnlocked();
    final atRoot = parentId != null && parentId == _rootNodeId;
    return _nodes.values
        .where(
          (n) =>
              !n.isDeleted &&
              (n.parentRef == parentId ||
                  (atRoot && n.parentRef == null && n.personal)),
        )
        .toList();
  }

  /// List all entries under a parent node.
  List<VaultEntry> listEntries(String? parentRef) {
    _ensureUnlocked();
    return _entries.values
        .where((e) => e.parentRef == parentRef && !e.isDeleted)
        .toList();
  }

  /// Search entries by name, tags, or field keys/values (in-memory).
  List<VaultEntry> search(String query) {
    _ensureUnlocked();
    if (query.isEmpty) return [];

    final q = query.toLowerCase();
    return _entries.values.where((entry) {
      if (entry.isDeleted) return false;
      if (entry.name.toLowerCase().contains(q)) return true;
      if (entry.tags.any((t) => t.toLowerCase().contains(q))) return true;
      if (entry.fields.any(
        (f) =>
            f.key.toLowerCase().contains(q) ||
            (!f.sensitive && f.value.toLowerCase().contains(q)),
      )) {
        return true;
      }
      return false;
    }).toList();
  }

  /// Get all entries as a flat list (for display).
  List<VaultEntry> get allEntries =>
      _entries.values.where((e) => !e.isDeleted).toList();

  /// Get all nodes as a flat list.
  List<VaultNode> get allNodes =>
      _nodes.values.where((n) => !n.isDeleted).toList();

  // ── DEK management ──

  /// Create a new root DEK and store it (for new vault initialization).
  Future<void> createRootDEK() async {
    _ensureUnlocked();

    final dekBytes = _crypto.generateDEK();
    final dekId = _generateId();
    final wrappedDek = _crypto.wrapDEK(dekBytes, dekId, _kek!, _kekDekId!);
    final payloadHash = _crypto.sha256Hex(wrappedDek);

    final signature = _crypto.signSyncObject(
      id: dekId,
      objectType: 'dek',
      parentRef: null,
      targetUserId: null,
      isDeleted: 0,
      version: 1,
      payloadHashHex: payloadHash,
      signingSecretKey: _signingSecretKey!,
    );

    await _db.upsertObject(
      id: dekId,
      objectType: 'dek',
      payload: wrappedDek,
      ownerId: _userId,
      version: 1,
      payloadHash: payloadHash,
      clientSignature: signature,
      queued: true,
    );

    _deks[dekId] = dekBytes;
    _rootDekId = dekId;
  }

  /// Store a pulled DEK object from the server (already encrypted).
  Future<void> storeDEKObject({
    required String id,
    required Uint8List payload,
    required String ownerId,
    required int version,
    required int commitSeq,
    required String payloadHash,
    Uint8List? clientSignature,
  }) async {
    await _db.upsertObject(
      id: id,
      objectType: 'dek',
      payload: payload,
      ownerId: ownerId,
      version: version,
      commitSeq: commitSeq,
      payloadHash: payloadHash,
      clientSignature: clientSignature,
      queued: false,
    );
  }

  // ── Helpers ──

  /// Reload decrypted data from DB (after a sync pull).
  /// Requires vault to already be unlocked (KEK available).
  Future<void> reloadData() => whileKekFixed(() async {
    _ensureUnlocked();
    try {
      await _loadTeamLogOrRefusal();
      await _loadDEKs();
      await _resealUnsent();
      await _loadDecryptedData();
    } catch (_) {
      lock();
      rethrow;
    }
  });

  /// Review 1141a20 (R9-G): this phone's unsent folders and items sealed with
  /// a team folder's key the log has since replaced (the folder was re-keyed
  /// meanwhile) are sealed again with its current key, at their version: the
  /// log refuses an old generation, so they were hidden and refused on every
  /// push, for good. As the desktop does after a re-key. A row whose keys
  /// this phone does not hold stays as it is.
  Future<void> resealUnsentOnCurrentKeys() => whileKekFixed(() async {
    _ensureUnlocked();
    await _resealUnsent();
  });

  /// [dekId] unwrapped from its key row under this account's KEK, or null.
  Future<Uint8List?> _ownWrappedDek(String dekId) async {
    final row = await _db.getObject(dekId);
    if (row == null || row['object_type'] != 'dek' || _kek == null) return null;
    final payload = row['payload'] as Uint8List;
    if (!_crypto.isEncryptedEnvelope(payload)) return null;
    try {
      return _crypto.unwrapDEK(
        payload,
        _kek!,
        dekId,
        version: row['version'] as int? ?? 1,
      );
    } catch (_) {
      return null;
    }
  }

  static const _unsentKeysSetting = 'unsent_team_keys';

  /// Review c78fd19 (medium): a member holds a team folder's key only through
  /// the admin's access envelope, never under its own KEK (the admin's case),
  /// and the pull that brings a re-key drops that envelope. Its unsent rows
  /// under the replaced key could then not be sealed again and stayed on the
  /// phone for good. So each key sealing an unsent row that this account does
  /// not wrap itself is kept here, under the KEK, until no unsent row needs it.
  Future<void> keepKeysOfUnsent() => whileKekFixed(() async {
    if (!isUnlocked || _kekDekId == null) return;
    final needed = <String>{};
    for (final row in await _db.getDirtyObjects()) {
      final type = row['object_type'] as String;
      if ((type != 'node' && type != 'entry') || row['is_deleted'] == 1) {
        continue;
      }
      final payload = row['payload'] as Uint8List;
      if (type == 'entry' && _crypto.isCanonicalEntryPayload(payload)) {
        needed.add(_crypto.entryPayloadDekId(payload));
      } else if (type == 'node' && _crypto.isEncryptedEnvelope(payload)) {
        needed.add(_crypto.envelopeDekId(payload));
      }
    }
    final raw = await _db.getSetting(_unsentKeysSetting);
    final kept = raw == null
        ? <String, dynamic>{}
        : jsonDecode(raw) as Map<String, dynamic>;
    final before = jsonEncode(kept);
    kept.removeWhere((dekId, _) => !needed.contains(dekId));
    for (final dekId in needed) {
      final key = _deks[dekId];
      if (key == null || kept.containsKey(dekId)) continue;
      // The key row of the folder is its admin's: this account's KEK opens
      // it only when this account is that admin.
      final own = await _ownWrappedDek(dekId);
      if (own != null) {
        _crypto.zeroize(own);
        continue;
      }
      kept[dekId] = base64Encode(
        _crypto.wrapDEK(key, dekId, _kek!, _kekDekId!),
      );
    }
    final after = jsonEncode(kept);
    if (after != before) await _db.setSetting(_unsentKeysSetting, after);
  });

  /// [dekId] kept by [keepKeysOfUnsent], or null (a KEK changed since).
  Future<Uint8List?> _keptUnsentDek(String dekId) async {
    final raw = await _db.getSetting(_unsentKeysSetting);
    final wrapped = raw == null ? null : (jsonDecode(raw) as Map)[dekId];
    if (wrapped is! String || _kek == null) return null;
    try {
      return _crypto.unwrapDEK(base64Decode(wrapped), _kek!, dekId);
    } catch (_) {
      return null;
    }
  }

  /// [dekId] opened from an access envelope addressed to this account, while
  /// the phone still holds it (the log moved on before the objects were
  /// pulled), or null. Only for this account's own unsent ciphertext: the
  /// caller decrypts with it, which fails for any other key.
  Future<Uint8List?> _ownEnvelopeDek(String dekId, TeamState team) async {
    final sk = _encryptionSecretKey;
    if (sk == null || _userId == null) return null;
    for (final row in await _db.getObjectsByType('envelope')) {
      if (row['parent_ref'] != dekId || row['target_user_id'] != _userId)
        continue;
      final sender = team.members[row['signer_id'] as String? ?? ''];
      if (sender == null) continue;
      final payload = row['payload'] as Uint8List;
      try {
        if (!_crypto.verifyDetached(
          signature: row['client_signature'] as Uint8List,
          message: _crypto.buildSyncSignatureData(
            id: row['id'] as String,
            objectType: 'envelope',
            parentRef: dekId,
            targetUserId: _userId,
            isDeleted: 0,
            version: row['version'] as int,
            payloadHashHex: _crypto.sha256Hex(payload),
          ),
          publicKey: hexToBytes(sender.signingPk),
        )) {
          continue;
        }
        return _crypto.openAccessEnvelope(
          payload,
          sk,
          hexToBytes(sender.encryptionPk),
        );
      } catch (_) {
        continue; // A damaged or old-identity envelope supplies no key.
      }
    }
    return null;
  }

  Future<void> _resealUnsent() async {
    final team = teamLog?.team;
    if (team == null || _signingSecretKey == null) return;
    // Review 8bc70f7 M8: the held keys and the whole team went to the core
    // again for each unsent write. Opening a replaced key adds none to _deks.
    final held = _deks.keys.toList();
    for (final row in await _db.getDirtyObjects()) {
      final type = row['object_type'] as String;
      if ((type != 'node' && type != 'entry') || row['is_deleted'] == 1)
        continue;
      final payload = row['payload'] as Uint8List;
      final isEntry = type == 'entry';
      if (isEntry
          ? !_crypto.isCanonicalEntryPayload(payload)
          : !_crypto.isEncryptedEnvelope(payload)) {
        continue;
      }
      final sealed = isEntry
          ? _crypto.entryPayloadDekId(payload)
          : _crypto.envelopeDekId(payload);
      // The shared core decides (capability review run 365), as on the
      // desktop and web: the folder's current key, only if the log lets this
      // account hold it and it is held (only once the log is trusted,
      // _loadDEKs). A revoked account opens no replaced key.
      final to =
          (syncCore('reseal_targets', {
                        'team': syncCoreTeam(
                          team,
                          _userId ?? '',
                          keys: [sealed],
                        ),
                        'held': held,
                        'keys': [sealed],
                      })
                      as List)
                  .first
              as Map;
      // 'wait': the folder's new key is not here; the push refuses the row
      // under the replaced key (assertTrustedTeamWrites) and it stays queued.
      if (to['send'] != 'reseal') continue;
      final current = to['key'] as String;
      // The log lets no one hold a replaced generation, so it is not in
      // _deks: opened here, from this account's own wrap (the admin) or the
      // envelope it was given (a member), for its own unsent ciphertext only.
      final old = _deks[sealed] == null
          ? await _ownWrappedDek(sealed) ??
                await _keptUnsentDek(sealed) ??
                await _ownEnvelopeDek(sealed, team)
          : null;
      final key = old ?? _deks[sealed];
      if (key == null) continue;
      final keys = {sealed: key};
      final id = row['id'] as String;
      final version = row['version'] as int;
      final Uint8List resealed;
      try {
        if (isEntry) {
          final (meta, data) = _crypto.decryptEntryParts(
            payload,
            id,
            version,
            keys,
          );
          resealed = _crypto.encryptEntryPayload(
            meta,
            data,
            _deks[current]!,
            current,
            id,
            version,
          );
        } else {
          resealed = _crypto.encryptEnvelope(
            _crypto.decryptEnvelope(
              payload,
              id,
              version,
              keys,
              expectedBlobKind: BlobKind.nodeMeta,
            ),
            _deks[current]!,
            current,
            id,
            version,
            BlobKind.nodeMeta,
          );
        }
      } catch (_) {
        continue; // Not this account's ciphertext under that key: left as it is.
      } finally {
        if (old != null) _crypto.zeroize(old);
      }
      final payloadHash = _crypto.sha256Hex(resealed);
      await _db.upsertObject(
        id: id,
        objectType: type,
        payload: resealed,
        ownerId: row['owner_id'] as String?,
        parentRef: row['parent_ref'] as String?,
        targetUserId: row['target_user_id'] as String?,
        version: version,
        commitSeq: row['commit_seq'] as int?,
        payloadHash: payloadHash,
        clientSignature: _crypto.signSyncObject(
          id: id,
          objectType: type,
          parentRef: row['parent_ref'] as String?,
          targetUserId: row['target_user_id'] as String?,
          isDeleted: 0,
          version: version,
          payloadHashHex: payloadHash,
          signingSecretKey: _signingSecretKey!,
        ),
        queued: true,
        writePolicy: row['write_policy'] as String?,
        accessLevel: row['access_level'] as String?,
      );
    }
  }

  void _ensureUnlocked() {
    if (!isUnlocked) {
      throw StateError('Vault is locked. Call unlock() first.');
    }
  }

  // ── Offline vault creation ──

  /// Create a brand-new local vault (like desktop `sezam init`).
  ///
  /// 1. Generate Ed25519 + X25519 keypairs
  /// 2. Generate Argon2id salt, derive KEK from password
  /// 3. Encrypt keypair with KEK
  /// 4. Store encrypted keypair + salt in secure storage
  /// 5. Create SQLite database with root DEK, audit DEK, root node
  ///
  /// After this, the vault is unlocked and ready for use.
  Future<void> createVault(String password) async {
    await _crypto.init();

    // 1. Generate keypairs
    final signingKp = _crypto.generateSigningKeypair();
    final encryptionKp = _crypto.generateEncryptionKeypair();

    // Build combined keypair bytes: signing_sk(64) + encryption_sk(32)
    final keypairBytes = Uint8List(96);
    keypairBytes.setRange(0, 64, signingKp.sk);
    keypairBytes.setRange(64, 96, encryptionKp.sk);

    // 2. Generate Argon2id salt (16 bytes)
    final argon2Salt = _crypto.randomBytes(16);

    // Mobile-friendly Argon2id params
    const timeCost = 2;
    const memoryCost = 131072; // 128 MB
    const parallelism = 4;

    // Derive KEK + auth_proof
    final derived = await _crypto.deriveKEK(
      password,
      argon2Salt,
      timeCost: timeCost,
      memoryCost: memoryCost,
      parallelism: parallelism,
    );
    final kek = Uint8List.sublistView(derived, 0, 32);
    derived.fillRange(32, derived.length, 0);

    // 2b. Initialize database early so we can persist kekDekId
    await _db.database; // Ensure DB schema is created

    // Generate and persist kekDekId (synthetic KEK ULID for AAD)
    final kekDekId = _generateId();
    await _db.setSetting('kek_dek_id', kekDekId);

    // 3. Encrypt keypair with KEK
    final userObjectId = _generateId();
    final encryptedKeypair = _crypto.wrapKeypair(
      keypairBytes,
      kek,
      kekDekId,
      userObjectId,
    );

    // 4. Store encrypted keypair + salt + IDs in secure storage
    final secureStorage = const FlutterSecureStorage(
      aOptions: AndroidOptions(encryptedSharedPreferences: true),
      iOptions: IOSOptions(
        accessibility: KeychainAccessibility.first_unlock_this_device,
      ),
    );

    await secureStorage.write(
      key: 'sezam_encrypted_keypair',
      value: bytesToHex(encryptedKeypair),
    );
    await secureStorage.write(
      key: 'sezam_argon2_salt',
      value: bytesToHex(argon2Salt),
    );
    await secureStorage.write(
      key: 'sezam_argon2_time_cost',
      value: timeCost.toString(),
    );
    await secureStorage.write(
      key: 'sezam_argon2_memory_cost',
      value: memoryCost.toString(),
    );
    await secureStorage.write(
      key: 'sezam_argon2_parallelism',
      value: parallelism.toString(),
    );
    await secureStorage.write(key: 'sezam_user_object_id', value: userObjectId);

    // 5. Unlock with the derived keys
    _kek = kek;
    _kekDekId = kekDekId;
    _signingSecretKey = signingKp.sk;
    _signingPublicKey = signingKp.pk;
    _encryptionSecretKey = encryptionKp.sk;
    _encryptionPublicKey = encryptionKp.pk;
    _userId = 'local';

    // Create root DEK
    await createRootDEK();

    // Create audit DEK (separate DEK for audit log entries)
    await _createAuditDEK();

    // Create root node (top-level folder)
    await _createRootNode();
  }

  /// Create audit DEK for audit log entries.
  Future<void> _createAuditDEK() async {
    _ensureUnlocked();

    final dekBytes = _crypto.generateDEK();
    final dekId = _generateId();
    final wrappedDek = _crypto.wrapDEK(dekBytes, dekId, _kek!, _kekDekId!);
    final payloadHash = _crypto.sha256Hex(wrappedDek);

    final signature = _crypto.signSyncObject(
      id: dekId,
      objectType: 'dek',
      parentRef: null,
      targetUserId: null,
      isDeleted: 0,
      version: 1,
      payloadHashHex: payloadHash,
      signingSecretKey: _signingSecretKey!,
    );

    await _db.upsertObject(
      id: dekId,
      objectType: 'dek',
      payload: wrappedDek,
      ownerId: _userId,
      version: 1,
      payloadHash: payloadHash,
      clientSignature: signature,
      queued: true,
    );

    _deks[dekId] = dekBytes;
  }

  /// Create the root node (top-level folder that contains all other folders).
  Future<void> _createRootNode() async {
    _ensureUnlocked();

    final id = _generateId();
    final dekId = _rootDekId!;
    final dek = _deks[dekId]!;

    final meta = {'name': 'Root'};
    final payload = _crypto.encryptEnvelope(
      meta,
      dek,
      dekId,
      id,
      1,
      BlobKind.nodeMeta,
    );
    final payloadHash = _crypto.sha256Hex(payload);

    final signature = _crypto.signSyncObject(
      id: id,
      objectType: 'node',
      parentRef: null,
      targetUserId: null,
      isDeleted: 0,
      version: 1,
      payloadHashHex: payloadHash,
      signingSecretKey: _signingSecretKey!,
    );

    await _db.upsertObject(
      id: id,
      objectType: 'node',
      payload: payload,
      ownerId: _userId,
      version: 1,
      payloadHash: payloadHash,
      clientSignature: signature,
      queued: true,
    );

    final node = VaultNode(id: id, name: 'Root', version: 1);
    _nodes[id] = node;
    _rootNodeId = id;
  }
}

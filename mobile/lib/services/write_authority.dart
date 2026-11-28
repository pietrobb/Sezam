// Review 7c10379 H4: before b8c3cb8 the server let a read-only member write a
// folder directly below the shared root, sealed with the root's shared key,
// and items in it ('IT - new VPN login') that colleagues saw as the
// company's own; a lying server can serve such objects again.
//
// The server's _has_write_authority, judged by signatures (the account whose
// signature verified, not the unsigned owner_id): directly below a top-level
// folder writes this account, an account that signed what only an admin may
// push (a top-level folder, envelope, key archive, folder key, audit record),
// a member with a write grant on a key of that folder, and - a folder only -
// its author under a key of the author's own (a personal folder). Inside a
// member's personal folder everything is sealed with that member's keys.
// The rules are the core's (core/src/authority.rs, docs/CORE_UNIFICATION.md
// U5); this file hands it the phone's rows.

import 'dart:typed_data';

import 'sync_core.dart';
import 'team_log.dart';

/// The account that signed [row]: what the pull verified, for rows from
/// before that was kept the server's owner, for unsent rows this account.
String? _signer(Map<String, dynamic> row, String? ownUserId) =>
    row['signer_id'] as String? ?? row['owner_id'] as String? ?? ownUserId;

/// [row] is this account's: its verified signer, or a row never pulled
/// written before this vault was connected (the temporary 'local' identity).
bool isOwnRow(Map<String, dynamic> row, String? ownUserId) {
  final signer = _signer(row, ownUserId);
  return ownUserId != null &&
      (signer == ownUserId || (row['signer_id'] == null && signer == 'local'));
}

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// The DEK id a sealed folder meta or item meta names in its header (the
/// core's rule, core/src/authority.rs: 57 bytes of the payload suffice).
String? sealingDekId(Map<String, dynamic> row) {
  final payload = row['payload'];
  if (payload is! Uint8List) return null;
  final head = payload.length > 57
      ? Uint8List.sublistView(payload, 0, 57)
      : payload;
  return syncCore('authority_sealing_dek_id', {
        'object_type': row['object_type'],
        'head': _hex(head),
      })
      as String?;
}

// ── Signed team log (TL5; docs/DESIGN_TEAM_LOG.md §4.3.4) ──
// Once the organisation has a team log, a folder or item in a team folder is
// decided by the log alone, by the server's own push rule (TeamLog.itemRefusal):
// its signer may write there and it is sealed with the folder's current key,
// or with the author's own key and write access. A removal (tombstone, or a
// move out of a team folder: finding 205) needs write access where it was.
// Write envelopes and accounts the server takes for admins decide nothing there.

/// The team folder at or above node [nodeId] in [rows], or null.
String? teamFolderAbove(
  Map<String, Map<String, dynamic>> rows,
  TeamState team,
  String? nodeId,
) {
  var current = nodeId;
  for (var i = 0; i < 64 && current != null && current.isNotEmpty; i++) {
    if (TeamLog.isTeamFolder(team, current)) return current;
    final row = rows[current];
    if (row == null || row['object_type'] != 'node') return null;
    current = row['parent_ref'] as String?;
  }
  return null;
}

/// Signer of each key with no folder (an account's own key).
Map<String, String?> ownKeySigners(
  Iterable<Map<String, dynamic>> rows,
  String? ownUserId,
) => {
  for (final row in rows)
    if (row['object_type'] == 'dek' &&
        ((row['parent_ref'] as String?) ?? '').isEmpty)
      row['id'] as String: _signer(row, ownUserId),
};

/// The log's verdict on folder/item [row] in [rows] (the state with it):
/// `decided` false when the log has no say (outside every team folder,
/// sealed with a key it does not know); else `refusal` null when valid, or
/// why not. [held] is the copy this device had before, [heldRows] the rows
/// it sat in. [sealing] false for a pulled copy (design §4.3.4).
({bool decided, String? refusal}) teamLogVerdict(
  Map<String, dynamic> row,
  Map<String, Map<String, dynamic>> rows,
  TeamState team, {
  required Map<String, String?> ownKeys,
  required String? ownUserId,
  required bool sealing,
  Map<String, dynamic>? held,
  Map<String, Map<String, dynamic>>? heldRows,
}) {
  final author = _signer(row, ownUserId) ?? '';
  final folder = teamFolderAbove(rows, team, row['parent_ref'] as String?);
  final before = held != null && held['is_deleted'] != 1 ? held : null;
  bool known(String? dekId) =>
      dekId != null && team.dekIndex.containsKey(dekId);
  if (row['is_deleted'] == 1) {
    final stored = before == null ? null : sealingDekId(before);
    if (folder == null && !known(stored))
      return (decided: false, refusal: null);
    return (
      decided: true,
      refusal: TeamLog.tombstoneRefusal(team, author, stored),
    );
  }
  final left = before == null
      ? null
      : teamFolderAbove(
          heldRows ?? rows,
          team,
          before['parent_ref'] as String?,
        );
  final dekId = sealingDekId(row);
  // TL7 (review 1141a20): a personal object (sealed, before and now, with one
  // key outside the log) may leave for the personal root, as the server and
  // the desktop decide. Only its author holds that key.
  final stored = before == null ? null : sealingDekId(before);
  final ownPersonal = stored != null && stored == dekId && !known(stored);
  final moved = TeamLog.moveRefusal(team, author, left, folder, ownPersonal);
  if (moved != null) return (decided: true, refusal: moved);
  if (folder == null && !known(dekId)) return (decided: false, refusal: null);
  final ownDek =
      dekId != null && ownKeys.containsKey(dekId) && ownKeys[dekId] == author;
  return (
    decided: true,
    refusal: TeamLog.itemRefusal(
      team,
      author,
      row['id'] as String,
      folder,
      dekId,
      ownDek,
      sealing,
    ),
  );
}

/// Accounts the log [records] ever made admin that are still active members
/// of [team]: what they wrote outside team folders while admin stays valid
/// after a handover (review 1141a20), an account the server calls admin is
/// not. The core's rule (core/src/authority.rs).
Set<String> logAdmins(List<Map<String, dynamic>> records, TeamState team) => {
  for (final id
      in syncCore('authority_log_admins', {
            'bodies': [for (final record in records) record['body']],
            ...team.coreArgument(),
          })
          as List)
    id as String,
};

/// The fields core/src/authority.rs judges [row] by: the account that
/// signed it (as [isOwnRow] has it) and the key its header names.
Map<String, Object?> _authorityObject(
  Map<String, dynamic> row,
  String? ownUserId,
) {
  final kind = row['object_type'] as String;
  final parent = row['parent_ref'] as String?;
  return {
    'id': row['id'],
    'object_type': kind,
    'parent_ref': parent == null || parent.isEmpty ? null : parent,
    'is_deleted': row['is_deleted'] == 1,
    'signer': _signer(row, ownUserId),
    'access_level': row['access_level'],
    'target_user_id': row['target_user_id'],
    'dek_id': kind == 'node' || kind == 'entry' ? sealingDekId(row) : null,
  };
}

/// Ids of folders and items (and all below them) not to show: the core's
/// rule (core/src/authority.rs; review 7c10379 H4, a159e97 H4, 1141a20
/// H5/H6, TL5, TL7). With [team] (the organisation's log) a team folder's
/// content is the log's to decide, and outside team folders only
/// [teamAdmins] (default: the log's current admins) count as admins.
Set<String> unauthorizedWrites(
  List<Map<String, dynamic>> rows,
  String? ownUserId, {
  TeamState? team,
  Set<String>? teamAdmins,
}) {
  final out =
      syncCore('authority_unauthorized_writes', {
            'objects': [
              for (final row in rows) _authorityObject(row, ownUserId),
            ],
            'own_user_id': ownUserId,
            if (team != null) ...team.coreArgument(),
            if (team != null && teamAdmins != null)
              'team_admins': teamAdmins.toList()..sort(),
          })
          as Map;
  return {for (final id in out['blocked'] as List) id as String};
}

/// INV-7, rule 3 of the INV-5/INV-7 precedence (docs/ROOT_CAUSE_PLAN.md):
/// the folders and items that show while the team log is refused. Only this
/// account's personal tree: a top-level personal root it signed, under a key
/// it holds, and what it signed below, under that root's key (an item also
/// under a tier-2 key of its own it holds). No rule from before the log
/// decides: a folder the server brings, a plaintext one and the
/// organisation's tree do not show. Parity with the web's
/// refusedLogPersonalKeys and webInPersonalTree.
Set<String> refusedLogPersonalTree(
  List<Map<String, dynamic>> rows,
  String? ownUserId, {
  required Set<String> personalNodes,
  required Map<String, String?> dekIds,
  required Set<String> heldDekIds,
  required Set<String> tier2Entries,
}) {
  final byId = {for (final row in rows) row['id'] as String: row};
  // A row never pulled (no verified signer) written before this vault was
  // connected names the temporary 'local' identity.
  bool own(Map<String, dynamic> row) => isOwnRow(row, ownUserId);
  final rootKeys = <String, String?>{};

  /// The key of the personal root above folder [id] (itself included), when
  /// each folder on the way is this account's, under that key.
  String? rootKey(String id) {
    if (rootKeys.containsKey(id)) return rootKeys[id];
    rootKeys[id] = null; // a cycle names no root
    final row = byId[id];
    final dekId = dekIds[id];
    String? key;
    if (row != null &&
        row['object_type'] == 'node' &&
        dekId != null &&
        own(row)) {
      final parent = row['parent_ref'] as String?;
      if (parent == null) {
        key = personalNodes.contains(id) && heldDekIds.contains(dekId)
            ? dekId
            : null;
      } else {
        final above = rootKey(parent);
        key = above == dekId ? above : null;
      }
    }
    return rootKeys[id] = key;
  }

  final shown = <String>{};
  for (final row in rows) {
    final id = row['id'] as String;
    if (!dekIds.containsKey(id)) continue;
    if (row['object_type'] == 'node') {
      if (rootKey(id) != null) shown.add(id);
    } else if (row['object_type'] == 'entry' && own(row)) {
      final parent = row['parent_ref'] as String?;
      final key = parent == null ? null : rootKey(parent);
      final dekId = dekIds[id];
      if (key != null &&
          (dekId == key ||
              (tier2Entries.contains(id) &&
                  dekId != null &&
                  heldDekIds.contains(dekId)))) {
        shown.add(id);
      }
    }
  }
  return shown;
}

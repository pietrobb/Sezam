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

String? _parent(Map<String, dynamic> row) {
  final parent = row['parent_ref'] as String?;
  return parent == null || parent.isEmpty ? null : parent;
}

/// The team folder at or above node [nodeId] in [rows], or null (the
/// core's walk).
String? teamFolderAbove(
  Map<String, Map<String, dynamic>> rows,
  TeamState team,
  String? nodeId,
) {
  if (nodeId == null || nodeId.isEmpty) return null;
  return syncCore('authority_team_folder_above', {
        'node_id': nodeId,
        'parents': {
          for (final row in rows.values)
            if (row['object_type'] == 'node') row['id'] as String: _parent(row),
        },
        ...team.coreArgument(),
      })
      as String?;
}

/// What the core's write rule reads of [rows]: the folders, the keys and
/// who signed them, and the copies of [ids].
List<Map<String, Object?>> _writeState(
  Map<String, Map<String, dynamic>> rows,
  Set<String> ids,
  String? ownUserId,
) => [
  for (final row in rows.values)
    if (row['object_type'] == 'node' ||
        row['object_type'] == 'dek' ||
        ids.contains(row['id']))
      ids.contains(row['id'])
          ? _authorityObject(row, ownUserId)
          : {
              'id': row['id'],
              'object_type': row['object_type'],
              'parent_ref': _parent(row),
              'is_deleted': row['is_deleted'] == 1,
              'signer': _signer(row, ownUserId),
            },
];

/// The log's verdict on each folder/item of [writes] (core/src/authority.rs
/// write_refusals): `decided` false when the log has no say (outside every
/// team folder, sealed with a key it does not know); else `refusal` null
/// when valid, or why not. [before] holds the copies this device had and
/// the folders they sat in, [after] the state they land in (default:
/// [before] with them). [sealing] false for a pulled copy (design §4.3.4).
List<({bool decided, String? refusal})> teamLogVerdicts(
  List<Map<String, dynamic>> writes,
  Map<String, Map<String, dynamic>> before,
  TeamState team, {
  required String? ownUserId,
  required bool sealing,
  Map<String, Map<String, dynamic>>? after,
}) {
  if (writes.isEmpty) return const [];
  final ids = {for (final row in writes) row['id'] as String};
  final out =
      syncCore('authority_write_refusal', {
            'writes': [
              for (final row in writes) _authorityObject(row, ownUserId),
            ],
            'objects': _writeState(before, ids, ownUserId),
            if (after != null) 'after': _writeState(after, const {}, ownUserId),
            'sealing': sealing,
            ...team.coreArgument(),
          })
          as List;
  return [
    for (final v in out.cast<Map>())
      (decided: v['decided'] as bool, refusal: v['refusal'] as String?),
  ];
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

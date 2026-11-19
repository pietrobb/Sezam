/// Unsent changes that a full resync replaced (lockout review M4).
///
/// Before a full resync the dirty rows are exported as JSON (encrypted
/// payloads only). The export is re-applied on top of the fresh server copy
/// right after the resync, and can be saved outside the app and imported
/// again later from Settings.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../models/vault_models.dart';
import 'sync_core.dart';

/// An export bigger than this is not a Sezam export.
const maxUnsentExportBytes = 64 * 1024 * 1024;

enum UnsentAction {
  createNode,
  createEntry,
  updateEntry,

  /// The export's edit, still on the server version it was made on: the
  /// next push meets the newer server copy and the conflict is the user's.
  updateOnItsBase,
  copyEntry,
  skip,
}

/// A server version as sync redesign S1 names it: number and content hash.
typedef EntryBase = ({int version, String hash});

class UnsentStep {
  final UnsentAction action;
  final Map<String, dynamic> object;
  final String? reason;

  const UnsentStep(this.action, this.object, [this.reason]);

  String get id => object['id'] as String;
}

class UnsentReapplyResult {
  final int applied;
  final int alreadyPresent;
  final List<String> notApplied;

  const UnsentReapplyResult({
    required this.applied,
    this.alreadyPresent = 0,
    required this.notApplied,
  });

  static const empty = UnsentReapplyResult(applied: 0, notApplied: []);
}

/// Same name (or [asName]), fields, tags and notes.
bool sameEntryContent(VaultEntry live, VaultEntry exported, {String? asName}) {
  final a = live.toJson();
  final b = exported.toJson()..['name'] = asName ?? exported.name;
  return jsonEncode(a) == jsonEncode(b);
}

/// JSON body of an export file; [objects] are the dirty rows as exported.
Uint8List encodeUnsentExport(List<Map<String, dynamic>> objects) =>
    Uint8List.fromList(
      utf8.encode(
        jsonEncode({
          'format': 'sezam-unsent-changes',
          'exported_at': DateTime.now().toUtc().toIso8601String(),
          'reason': 'full_resync',
          'objects': objects,
        }),
      ),
    );

/// The dirty rows of an export file. Throws [FormatException] for anything
/// that is not one.
List<Map<String, dynamic>> parseUnsentExport(Uint8List bytes) {
  if (bytes.length > maxUnsentExportBytes) {
    throw const FormatException('File is too large for a Sezam export');
  }
  final Object? decoded;
  try {
    decoded = jsonDecode(utf8.decode(bytes));
  } on FormatException {
    throw const FormatException('Not a Sezam unsent-changes export');
  }
  if (decoded is! Map || decoded['objects'] is! List) {
    throw const FormatException('Not a Sezam unsent-changes export');
  }
  final objects = <Map<String, dynamic>>[];
  for (final raw in decoded['objects'] as List) {
    if (raw is! Map ||
        raw['id'] is! String ||
        raw['object_type'] is! String ||
        raw['version'] is! int ||
        raw['payload'] is! String) {
      throw const FormatException('Damaged object in the export');
    }
    objects.add(Map<String, dynamic>.from(raw));
  }
  return objects;
}

/// The server version (S1: number and content hash) an object row or an
/// exported row stands on; null without one (never synced, older exports).
EntryBase? entryBase(Map<String, dynamic> row) {
  final version = row['base_version'];
  final hash = row['base_hash'];
  return version is int && hash is String && hash.isNotEmpty
      ? (version: version, hash: hash)
      : null;
}

/// Each live entry row's server version, for [planUnsentReapply]. A row
/// with unsent edits of its own maps to null: its content is no longer that
/// version, so an export must not overwrite it.
Map<String, EntryBase?> liveEntryConfirmedBases(
  List<Map<String, dynamic>> rows,
) => {
  for (final row in rows)
    row['id'] as String: (row['queued'] as int? ?? 0) == 0
        ? entryBase(row)
        : null,
};

/// What re-applying [objects] on top of the current vault does, in order:
/// folders before the folders and entries inside them, then entries.
///
/// An edited entry is compared by the server version it was made on (sync
/// redesign S1: number and content hash, the same identity the server checks
/// a push against), with [liveEntryBases] from [liveEntryConfirmedBases]:
/// - the live entry is still that version: the edit overwrites it;
/// - the server holds another version since (another device's edit, or a
///   write the server took after tombstone GC under the same number): the
///   edit is kept on its own base, and the next push is the conflict the
///   desktop and the web page report too (stateful seed run 44260509986:
///   commit_seq could not tell that copy from the one the edit was made on);
/// - the live entry has unsent edits of its own, or the export has no base:
///   the export becomes a separate copy so neither edit is lost.
///
/// Deletes and key/share changes are never replayed: deleting from an old
/// export could remove what other devices added since, and sharing must be
/// redone knowingly. They are listed as not applied.
List<UnsentStep> planUnsentReapply(
  List<Map<String, dynamic>> objects, {
  required Set<String> liveNodeIds,
  required Map<String, EntryBase?> liveEntryBases,
}) {
  // The shared sync core plans it (core/src/reapply.rs), as on the desktop.
  final steps =
      syncCore('plan_reapply', {
            'rows': [
              for (final object in objects)
                {
                  'id': object['id'],
                  'object_type': object['object_type'],
                  'parent_ref': object['parent_ref'],
                  'is_deleted': (object['is_deleted'] as int? ?? 0) != 0,
                  'base': switch (entryBase(object)) {
                    null => null,
                    final base => {'version': base.version, 'hash': base.hash},
                  },
                },
            ],
            'live': {
              'nodes': liveNodeIds.toList(),
              'entries': {
                for (final MapEntry(:key, :value) in liveEntryBases.entries)
                  key: value == null
                      ? null
                      : {'version': value.version, 'hash': value.hash},
              },
            },
          })
          as List<Object?>;
  return [
    for (final step in steps.cast<Map<String, Object?>>())
      UnsentStep(
        _actions[step['action']]!,
        objects[step['index']! as int],
        step['reason'] as String?,
      ),
  ];
}

const _actions = {
  'create_node': UnsentAction.createNode,
  'create_entry': UnsentAction.createEntry,
  'update_entry': UnsentAction.updateEntry,
  'update_on_its_base': UnsentAction.updateOnItsBase,
  'copy_entry': UnsentAction.copyEntry,
  'skip': UnsentAction.skip,
};

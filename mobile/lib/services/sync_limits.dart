import 'dart:convert';

import 'sync_core.dart';

/// What one POST /api/sync may carry (review 526419e #1). Must stay within
/// server/app/models/schemas.py: a push over any limit was refused as a
/// whole with 422, on every sync.
const int maxObjectPayloadBytes = 1024 * 1024;

/// An object the server can never take (over 1 MiB).
class SyncObjectTooLargeException implements Exception {
  const SyncObjectTooLargeException(this.sizeBytes);

  final int sizeBytes;

  @override
  String toString() =>
      'The entry is ${sizeBytes ~/ 1024} KiB encrypted; the server takes at '
      'most ${maxObjectPayloadBytes ~/ 1024} KiB per entry. Shorten the note '
      'or split it into several entries.';
}

void requireSyncablePayload(List<int> payload) {
  if (payload.length > maxObjectPayloadBytes) {
    throw SyncObjectTooLargeException(payload.length);
  }
}

/// Consecutive chunks within the per-request limits, order kept (the core's
/// rule, docs/CORE_UNIFICATION.md U6).
List<List<Map<String, dynamic>>> splitForPush(
  List<Map<String, dynamic>> objects,
) {
  final counts =
      syncCore('split_for_push', {
            'sizes': [
              for (final obj in objects)
                utf8.encode(jsonEncode(obj)).length + 1,
            ],
          })
          as List;
  var start = 0;
  return [
    for (final count in counts.cast<int>())
      objects.sublist(start, start += count),
  ];
}

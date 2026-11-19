import 'dart:convert';

/// What one POST /api/sync may carry (review 526419e #1). Must stay within
/// server/app/models/schemas.py: a push over any limit was refused as a
/// whole with 422, on every sync.
const int maxPushObjects = 1000;
const int maxObjectPayloadBytes = 1024 * 1024;

/// 16 MiB minus room for the request's own fields.
const int maxPushRequestBytes = 15 * 1024 * 1024;

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

/// Consecutive chunks within the per-request limits, order kept.
List<List<Map<String, dynamic>>> splitForPush(
  List<Map<String, dynamic>> objects,
) {
  final chunks = <List<Map<String, dynamic>>>[];
  var chunk = <Map<String, dynamic>>[];
  var size = 0;
  for (final obj in objects) {
    final objSize = utf8.encode(jsonEncode(obj)).length + 1;
    if (chunk.isNotEmpty &&
        (chunk.length >= maxPushObjects ||
            size + objSize > maxPushRequestBytes)) {
      chunks.add(chunk);
      chunk = <Map<String, dynamic>>[];
      size = 0;
    }
    chunk.add(obj);
    size += objSize;
  }
  if (chunk.isNotEmpty) chunks.add(chunk);
  return chunks;
}

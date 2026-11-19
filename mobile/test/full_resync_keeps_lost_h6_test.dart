// Review d615826 H6: what a full resync keeps of a server that lost it
// (end to end: tests/test_review6_phone_resync_after_restore.py).

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/sync_service.dart';

Map<String, dynamic> _row(
  String id, {
  String type = 'entry',
  int version = 1,
  int? seq = 10,
  String? parent,
  int dirty = 0,
  int deleted = 0,
  bool mine = true,
}) => {
  'id': id,
  'object_type': type,
  'version': version,
  'commit_seq': seq,
  'parent_ref': parent,
  'queued': dirty,
  'is_deleted': deleted,
  'mine': mine,
};

List<String> _kept(
  List<Map<String, dynamic>> rows,
  Map<String, int> server, {
  int gcFloor = 0,
  bool rolledBack = false,
}) => rowsTheServerLost(
  rows,
  server,
  gcFloor: gcFloor,
  rolledBack: rolledBack,
  ownSigned: (row) => row['mine'] == true,
).map((r) => r['id'] as String).toList();

void main() {
  test('confirmed above the GC floor and missing on the server: lost', () {
    expect(
      _kept([_row('E1', seq: 10), _row('E2', seq: 4)], {}, gcFloor: 5),
      ['E1'], // E2 went with tombstone GC: deleted elsewhere
    );
  });

  test('older on the server is kept only when the server went back', () {
    final rows = [_row('E1', version: 3)];
    expect(_kept(rows, {'E1': 2}), isEmpty);
    expect(_kept(rows, {'E1': 2}, rolledBack: true), ['E1']);
    expect(_kept(rows, {'E1': 3}, rolledBack: true), isEmpty);
  });

  test('unsent, deleted, others\' and other kinds are not kept', () {
    expect(
      _kept([
        _row('E1', dirty: 1),
        _row('E2', deleted: 1),
        _row('E3', mine: false),
        _row('V1', type: 'envelope'),
        _row('N1', type: 'node'),
        _row('D1', type: 'dek'),
      ], {}),
      ['N1', 'D1'],
    );
  });

  test('a kept row needs its parent on the server or kept', () {
    expect(
      _kept([
        _row('N1', type: 'node', parent: 'ROOT'),
        _row('E1', parent: 'N1'),
        _row('E2', parent: 'GONE'),
        _row('N2', type: 'node', parent: 'GONE'),
        _row('E3', parent: 'N2'),
      ], {'ROOT': 1}),
      ['N1', 'E1'],
    );
  });
}

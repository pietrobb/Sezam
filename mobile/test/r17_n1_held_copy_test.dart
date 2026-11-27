// R17-N1 (review c02cc47, INV-3): the version the phone holds, served again
// with another parent or as deleted, is an equivocation, never the copy held
// (against_held compared the payload hash alone).
import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/database_service.dart';

const _hash =
    'aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11';
const _parent = '01M8EE0000000000000000000A';
const _other = '01M8EE0000000000000000000B';

Map<String, dynamic> _held() => {
  'object_type': 'entry',
  'parent_ref': _parent,
  'target_user_id': null,
  'is_deleted': 0,
  'version': 3,
  'payload_hash': _hash,
  'queued': 0,
  'commit_seq': 7,
};

bool _stale({String? parentRef = _parent, bool isDeleted = false}) =>
    pulledIsStale(
      _held(),
      objectType: 'entry',
      version: 3,
      hash: _hash,
      gcFloor: 0,
      parentRef: parentRef,
      isDeleted: isDeleted,
    );

void main() {
  test('the very copy held is not stale', () {
    expect(_stale(), isFalse);
  });

  test('the held version with another parent is an equivocation', () {
    expect(_stale(parentRef: _other), isTrue);
  });

  test('the held version as deleted is an equivocation', () {
    expect(_stale(isDeleted: true), isTrue);
  });
}

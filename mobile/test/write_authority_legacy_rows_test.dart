// Capability run 174: forgeries the phone stored before it kept the signer
// (database v7, signer_id NULL) are judged on every load, by owner_id.
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/write_authority.dart';

const admin = '01AAAAAAAAAAAAAAAAAAAAAAAA';
const alice = '01BBBBBBBBBBBBBBBBBBBBBBBB';
const sharedKey = '01CCCCCCCCCCCCCCCCCCCCCCCC';
const aliceKey = '01DDDDDDDDDDDDDDDDDDDDDDDD';

Uint8List sealedWith(String dekId) {
  final bytes = Uint8List(60);
  bytes[0] = 1;
  bytes[1] = 1;
  bytes.setRange(3, 29, ascii.encode(dekId));
  return bytes;
}

Map<String, dynamic> row(
  String id,
  String kind,
  String? parent,
  String owner, {
  String? dek,
}) => {
  'id': id,
  'object_type': kind,
  'parent_ref': parent,
  'owner_id': owner,
  'signer_id': null, // stored before v7
  'is_deleted': 0,
  'payload': dek == null ? Uint8List(0) : sealedWith(dek),
};

void main() {
  test('legacy rows: a member folder under the shared key stays hidden', () {
    final rows = [
      row('root', 'node', null, admin, dek: sharedKey),
      row(sharedKey, 'dek', 'root', admin),
      row(aliceKey, 'dek', null, alice),
      row('forged', 'node', 'root', alice, dek: sharedKey),
      row('forged-item', 'entry', 'forged', alice, dek: sharedKey),
      row('personal', 'node', 'root', alice, dek: aliceKey),
      row('own-item', 'entry', 'personal', alice, dek: aliceKey),
      row('admin-folder', 'node', 'root', admin, dek: sharedKey),
    ];
    expect(unauthorizedWrites(rows, admin), {'forged', 'forged-item'});
  });

  test('TL7: a personal root makes its member no admin', () {
    const bob = '01EEEEEEEEEEEEEEEEEEEEEEEE';
    final rows = [
      row('root', 'node', null, admin, dek: sharedKey),
      row(sharedKey, 'dek', 'root', admin),
      row(aliceKey, 'dek', null, alice),
      row('alice-root', 'node', null, alice, dek: aliceKey),
      row('forged', 'node', 'root', alice, dek: sharedKey),
      row('admin-folder', 'node', 'root', admin, dek: sharedKey),
    ];
    expect(unauthorizedWrites(rows, bob), {'forged'});
  });
}

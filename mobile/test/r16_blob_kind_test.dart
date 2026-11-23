// Review 18c300f R16-L2: an entry's meta and data blobs share its id, version
// and key, so both decrypt wherever they stand; only the kind in the header
// tells them apart. On 18c300f a server that swapped them got the entry shown
// empty (its name read as fields, its fields as name). The phone reads every
// blob as the kind it expects, as the desktop (aead.decrypt
// expected_blob_kind) and the page (decryptEnvelope expectedKind) do.

import 'dart:ffi';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sodium/sodium_sumo.dart';

import 'support/real_server_phone.dart' show hostLibsodium, nodeArgon2id;

const entryId = '01JE0000000000000000000001';
const dekId = '01JD0000000000000000000001';

void main() {
  final crypto = CryptoService();
  late Uint8List dek;

  setUpAll(() async {
    final sodium = await SodiumSumoInit.init2(
      () => DynamicLibrary.open(hostLibsodium()),
    );
    crypto.initForTesting(sodium, argon2: nodeArgon2id);
    dek = Uint8List.fromList(List.generate(32, (i) => i));
  });

  Uint8List sealed() => crypto.encryptEntryPayload(
    {'name': 'bank', 'tags': <String>[]},
    {
      'fields': [
        {'key': 'password', 'value': 's3cret', 'sensitive': true},
      ],
    },
    dek,
    dekId,
    entryId,
    1,
  );

  (Uint8List, Uint8List) parts(Uint8List payload) {
    final metaLen = ByteData.sublistView(payload).getUint32(0, Endian.big);
    return (
      Uint8List.sublistView(payload, 4, 4 + metaLen),
      Uint8List.sublistView(payload, 4 + metaLen),
    );
  }

  test('an entry reads back as it was sealed', () {
    final (meta, data) = crypto.decryptEntryParts(sealed(), entryId, 1, {
      dekId: dek,
    });
    expect(meta['name'], 'bank');
    expect((data['fields'] as List).single['value'], 's3cret');
  });

  test('meta and data swapped by the server are refused', () {
    final (meta, data) = parts(sealed());
    final swapped = Uint8List(4 + data.length + meta.length);
    ByteData.sublistView(swapped).setUint32(0, data.length, Endian.big);
    swapped.setRange(4, 4 + data.length, data);
    swapped.setRange(4 + data.length, swapped.length, meta);
    expect(
      () => crypto.decryptEntryParts(swapped, entryId, 1, {dekId: dek}),
      throwsArgumentError,
    );
  });

  test('a meta blob served as a whole single-envelope entry is refused', () {
    final (meta, _) = parts(sealed());
    expect(
      () => crypto.decryptEnvelope(
        meta,
        entryId,
        1,
        {dekId: dek},
        expectedBlobKind: BlobKind.entryData,
      ),
      throwsArgumentError,
    );
  });
}

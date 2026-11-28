// Review 2052248, finding 1 (R-C5): a password change made on another device
// is taken over on mobile instead of locking the local vault.
//
// libsodium is not available under `flutter test`, so the rekey planner runs
// with a fake wrap (first byte = KEK tag) and the service wiring is checked in
// the source.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/key_rotation.dart';

class _FakeCrypto implements DekRekeyCrypto {
  int signed = 0;

  @override
  Uint8List? tryUnwrap(
    Uint8List payload,
    Uint8List kek,
    String dekId,
    int version,
  ) {
    if (payload.length < 3 || payload[0] != kek[0] || payload[1] != version) {
      return null;
    }
    return Uint8List.fromList(payload.sublist(2));
  }

  @override
  Uint8List wrap(Uint8List dek, String dekId, Uint8List kek, int version) =>
      Uint8List.fromList([kek[0], version, ...dek]);

  @override
  String sha256Hex(Uint8List data) =>
      data.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  @override
  Uint8List sign(Map<String, dynamic> row, String payloadHashHex) {
    signed++;
    return Uint8List.fromList(utf8.encode('sig:$payloadHashHex'));
  }

  @override
  void zeroize(Uint8List bytes) => bytes.fillRange(0, bytes.length, 0);
}

final _old = Uint8List.fromList([1, ...List.filled(31, 0)]);
final _new = Uint8List.fromList([2, ...List.filled(31, 0)]);
final _other = Uint8List.fromList([9, ...List.filled(31, 0)]);
const _me = '01ARZ3NDEKTSV4RRFFQ69G5FAV';
const _colleague = '01BX5ZZKBKACTAV9WEVGEMMVRZ';

Map<String, dynamic> _dek(
  String id,
  Uint8List kek, {
  String? owner = _me,
  int version = 3,
  int dirty = 0,
  int deleted = 0,
}) => {
  'id': id,
  'object_type': 'dek',
  'payload': Uint8List.fromList([kek[0], version, 7, 7, 7]),
  'owner_id': owner,
  'version': version,
  'commit_seq': dirty == 1 ? null : 42,
  'queued': dirty,
  'is_deleted': deleted,
  'payload_hash': 'old',
  'client_signature': Uint8List.fromList([1]),
};

List<Map<String, dynamic>> _plan(
  List<Map<String, dynamic>> rows, {
  Uint8List? oldKek,
  _FakeCrypto? crypto,
}) => planLocalDekRekey(
  rows: rows,
  userId: _me,
  newKek: _new,
  oldKek: oldKek,
  crypto: crypto ?? _FakeCrypto(),
  isEnvelope: (payload) => payload.isNotEmpty,
);

String _body(String file, String start, String end) {
  final src = File(file).readAsStringSync();
  final from = src.indexOf(start);
  expect(from, greaterThanOrEqualTo(0), reason: start);
  final to = src.indexOf(end, from + start.length);
  return src.substring(from, to < 0 ? src.length : to);
}

void main() {
  group('planLocalDekRekey', () {
    test(
      'own DEKs move to the new KEK in place, keeping version and flags',
      () {
        final crypto = _FakeCrypto();
        final changed = _plan(
          [_dek('CLEAN', _old), _dek('DIRTY', _old, dirty: 1, version: 1)],
          oldKek: _old,
          crypto: crypto,
        );
        expect(changed.map((r) => r['id']), ['CLEAN', 'DIRTY']);
        for (final row in changed) {
          final payload = row['payload'] as Uint8List;
          expect(payload[0], _new[0], reason: 'wrapped under the new KEK');
          expect(payload.sublist(2), [7, 7, 7], reason: 'same DEK');
          expect(row['payload_hash'], crypto.sha256Hex(payload));
        }
        final clean = changed[0];
        expect(
          [clean['version'], clean['commit_seq'], clean['queued']],
          [3, 42, 0],
        );
        // A clean row is server-confirmed: no rival signed version is made.
        expect(clean['client_signature'], [1]);
        final dirty = changed[1];
        expect([dirty['version'], dirty['queued']], [1, 1]);
        expect(
          utf8.decode(dirty['client_signature'] as Uint8List),
          'sig:${dirty['payload_hash']}',
          reason: 'a dirty DEK is pushed later, its signature must match',
        );
        expect(crypto.signed, 1);
      },
    );

    test('wraps already under the new KEK and colleagues\' DEKs stay', () {
      final changed = _plan([
        _dek('DONE', _new),
        _dek('THEIRS', _other, owner: _colleague),
        _dek('GONE', _other, deleted: 1),
        {'id': 'NODE', 'object_type': 'node', 'payload': Uint8List(3)},
      ], oldKek: _old);
      expect(changed, isEmpty);
    });

    test('a never-connected vault (owner "local") is moved too', () {
      final changed = _plan([
        _dek('LOCAL', _old, owner: 'local'),
      ], oldKek: _old);
      expect(changed.single['id'], 'LOCAL');
    });

    test('own DEK neither key opens -> nothing changes', () {
      expect(
        () => _plan([_dek('OK', _old), _dek('LOST', _other)], oldKek: _old),
        throwsA(
          isA<LocalDekRekeyException>().having(
            (e) => e.unreadableDekIds,
            'ids',
            ['LOST'],
          ),
        ),
      );
    });

    test('check-only mode reports own DEKs that need the previous KEK', () {
      expect(_plan([_dek('DONE', _new)]), isEmpty);
      expect(
        () => _plan([_dek('DONE', _new), _dek('OLD', _old)]),
        throwsA(isA<LocalDekRekeyException>()),
      );
    });
  });

  group('service wiring', () {
    const auth = 'lib/services/auth_service.dart';
    const sync = 'lib/services/sync_service.dart';

    test('QR re-provisioning moves local DEKs before replacing the KDF', () {
      final body = _body(auth, 'Future<AuthResult> provisionFromQR', '// ──');
      final rekey = body.indexOf('_sync.rekeyLocalVault(');
      final persist = body.indexOf('_persistKeypairState(');
      expect(rekey, greaterThan(0));
      expect(persist, greaterThan(rekey));
      expect(body, contains('_sync.unreadableOwnDeks('));
      expect(body, contains('Unlock the local vault before provisioning'));
      // Review 7c10379: a vault of the phone's own joins the account first.
      final join = body.indexOf('_moveDeviceToAccount(');
      expect(join, greaterThan(0));
      expect(rekey, greaterThan(join));
    });

    test('password login never strands the vault under the old KEK', () {
      final body = _body(
        auth,
        'Future<AuthResult> unlockWithPassword',
        '// ── Offline Unlock',
      );
      final check = body.indexOf('_sync.unreadableOwnDeks(kek, userObjectId)');
      final persist = body.indexOf('_persistKeypairState(');
      expect(check, greaterThan(0));
      expect(persist, greaterThan(check));
      expect(body, contains('AuthResult.needsPreviousPassword()'));
      expect(body, contains('_deriveLocalKek('));
      expect(body, contains('previousPassword,'));
    });

    test(
      'an unlocked vault takes the change over with the current password',
      () {
        final body = _body(
          auth,
          'Future<AuthResult> adoptPasswordChangedElsewhere',
          'Future<void> _persistKeypairState',
        );
        expect(body, contains('_recoverWithForms('));
        expect(
          body,
          contains('requireCanonicalUserObjectId(recovered.resp) != userId'),
        );
        final rekey = body.indexOf('_sync.rekeyLocalVault(');
        final persist = body.indexOf('_persistKeypairState(');
        expect(rekey, greaterThan(0));
        expect(persist, greaterThan(rekey));
        expect(body, contains('_vault.markKekMatchesServer()'));
        expect(body, contains('_refreshBiometricKek(newKek)'));
      },
    );

    test('a stale key epoch is a typed error on pull and push', () {
      final src = File(sync).readAsStringSync();
      expect(src, contains('throw KeyEpochStaleException(serverKeyEpoch);'));
      expect(src, isNot(contains('Local key epoch is stale')));
      final push = _body(sync, 'Future<PushResult> push()', '// ── Delta Pull');
      expect(push, contains('response.statusCode == 409'));
      expect(push, contains('throw const KeyEpochStaleException();'));
      // The checkpoint is encrypted under the KEK: it moves with the DEKs.
      final rekey = _body(
        sync,
        'Future<void> rekeyLocalVault',
        'Future<String> _computeStateHash',
      );
      expect(rekey, contains('_encryptSyncCheckpoint('));
      expect(rekey, contains('kek: newKek'));
      expect(rekey, contains('_db.applyLocalRekey('));
    });

    test('the UI asks for the right password', () {
      final vault = File('lib/screens/vault_screen.dart').readAsStringSync();
      expect(vault, contains('on KeyEpochStaleException'));
      expect(vault, contains('_auth.adoptPasswordChangedElsewhere('));
      final unlock = File('lib/screens/unlock_screen.dart').readAsStringSync();
      expect(
        unlock,
        contains('_unlockWithServer(fallbackError: result.error)'),
      );
      expect(unlock, contains('previousPassword: previous'));
    });
  });
}

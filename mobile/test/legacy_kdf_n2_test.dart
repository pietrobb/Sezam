// Lockout review N2 (mobile): accounts stored before per-account KDF params.
// The server reports them with the 128 MiB default, so the device must not
// guess: missing params are refused, its own params win while its salt is the
// server's, and /recover carries the params the proof was derived with.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/auth_service.dart';

const _auth = 'lib/services/auth_service.dart';
const _sync = 'lib/services/sync_service.dart';

String _body(String file, String start, String end) {
  final src = File(file).readAsStringSync();
  final from = src.indexOf(start);
  expect(from, greaterThanOrEqualTo(0), reason: start);
  final to = src.indexOf(end, from + start.length);
  return src.substring(from, to < 0 ? src.length : to);
}

void main() {
  test('missing account params are refused, not guessed as 128 MiB', () {
    expect(() => accountKdfParams({}), throwsFormatException);
    expect(
      () => accountKdfParams({
        'argon2_params': {'time_cost': 3, 'parallelism': 4},
      }),
      throwsFormatException,
    );
    final kdf = accountKdfParams({
      'argon2_params': {'time_cost': 2, 'memory_cost': 65536, 'parallelism': 2},
    });
    expect([kdf.timeCost, kdf.memoryCost, kdf.parallelism], [2, 65536, 2]);
  });

  test('own params win while the local salt is the server salt', () {
    final pick = _body(
      _auth,
      'Future<AccountKdf> _accountKdfFor(',
      '/// True only when [password]',
    );
    expect(pick, contains('local.saltHex.toLowerCase() == serverSalt'));
    expect(pick, contains('return local.kdf;'));
    final src = File(_auth).readAsStringSync();
    expect('final kdf = accountKdfParams(meta);'.allMatches(src), isEmpty);
    expect('await _accountKdfFor(meta)'.allMatches(src).length, 3);
    // Local params are never defaulted either.
    final local = _body(_auth, '_localKdf() async {', '/// KDF params of the');
    expect(local, isNot(contains('?? 131072')));
    expect(local, contains('return null;'));
  });

  test('/recover carries the params the proof was derived with', () {
    final recover = _body(
      _sync,
      'Future<Map<String, dynamic>> recover({',
      '/// Provision',
    );
    expect(recover, contains("'argon2_params': argon2Params"));
    final forms = _body(_auth, '_recoverWithForms({', '/// KEK of [password]');
    expect(forms, contains("'memory_cost': memoryCost"));
    expect(forms, contains('argon2Params:'));
  });
}

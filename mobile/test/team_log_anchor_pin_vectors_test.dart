// U7f (docs/CORE_UNIFICATION.md, capability run 709):
// tests/vectors/team_log_anchor_pin.json, from the desktop's rule before the
// move, through the core as the phone's recordAccountTeamGenesis asks it.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/sync_core.dart';
import 'package:sezam_mobile/services/team_log_client.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final vectors =
      jsonDecode(
            File('../tests/vectors/team_log_anchor_pin.json').readAsStringSync(),
          )
          as Map<String, dynamic>;

  test('the phone gives each case', () {
    final cases = vectors['cases'] as List;
    expect(cases.length, greaterThanOrEqualTo(300));
    for (final c in cases) {
      final m = Map<String, Object?>.from(c as Map)
        ..remove('name')
        ..remove('expect');
      expect(
        syncCore('team_log_anchor_pin', m),
        (c)['expect'],
        reason: c['name'] as String,
      );
    }
  });

  test('a copy and checkpoint of another log keep the keys\' anchor unpinned '
      '(the probe of run 709)', () async {
    FlutterSecureStorage.setMockInitialValues({});
    const user = 'u709';
    final a = 'aa' * 32, b = 'bb' * 32;
    final held = <String, Object?>{
      'pins': [b],
      'held': {'genesis': b},
    };
    await recordAccountTeamGenesis(user, a, held: held);
    expect(await readConfirmedTeamGenesis(user), isNull);
    expect(await readAccountTeamGenesis(user), a);
    await expectLater(
      importAccountTeamGenesis(user, a, held: held),
      throwsA(
        isA<TeamLogMismatch>().having((e) => e.cause, 'cause', 'anchor_conflict'),
      ),
    );
    await recordAccountTeamGenesis(user, a);
    expect(await readConfirmedTeamGenesis(user), a);
  });
}

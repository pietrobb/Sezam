// U7f (docs/CORE_UNIFICATION.md, capability run 707):
// tests/vectors/team_log_local_refusal.json, from the desktop's rule before
// the move, through the core as the phone's _loadTeamLog asks it.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/sync_core.dart';

void main() {
  final vectors =
      jsonDecode(
            File(
              '../tests/vectors/team_log_local_refusal.json',
            ).readAsStringSync(),
          )
          as Map<String, dynamic>;

  test('the phone gives each case', () {
    final cases = vectors['cases'] as List;
    expect(cases.length, greaterThanOrEqualTo(200));
    for (final c in cases) {
      final m = Map<String, Object?>.from(c as Map)
        ..remove('name')
        ..remove('expect');
      expect(
        syncCore('team_log_local_refusal', m),
        (c)['expect'],
        reason: c['name'] as String,
      );
    }
  });

  test('the phone keeps no rules of its own', () {
    final text = File(
      'lib/services/vault_service.dart',
    ).readAsStringSync().replaceAll('\r\n', '\n');
    final start = text.indexOf('Future<LocalTeamLog?> _loadTeamLog(');
    final body = text.substring(start, text.indexOf('\n  }\n', start));
    expect(body.contains('genesis != anchor'), isFalse);
    expect(body.contains("syncCore('team_log_local_refusal'"), isTrue);
  });
}

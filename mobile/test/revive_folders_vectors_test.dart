// U7e (docs/CORE_UNIFICATION.md): tests/vectors/revive_folders.json, from the
// desktop's _revive_folders_of_unsent before the move, through the core as
// the phone's reviveFoldersOfUnsent asks it. The phone seals no team keys, so
// tests/vectors/rotated_seals.json is the desktop's and the page's.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/sync_core.dart';

void main() {
  final vectors =
      jsonDecode(
            File('../tests/vectors/revive_folders.json').readAsStringSync(),
          )
          as Map<String, dynamic>;

  test('the phone gives each case', () {
    final cases = vectors['cases'] as List;
    expect(cases.length, greaterThanOrEqualTo(8));
    for (final c in cases) {
      final m = c as Map;
      final got = syncCore('revive_folders', {
        'deleted': m['deleted'],
        'work_in': m['work_in'],
      });
      expect(got, m['expect'], reason: m['name'] as String);
    }
  });

  test('the phone keeps no rules of its own', () {
    final text = File(
      'lib/services/vault_service.dart',
    ).readAsStringSync().replaceAll('\r\n', '\n');
    final start = text.indexOf('reviveFoldersOfUnsent() =>');
    final body = text.substring(start, text.indexOf('\n  });\n', start));
    expect(body.contains('tombstone + 1'), isFalse);
    expect(body.contains("syncCore('revive_folders'"), isTrue);
  });
}

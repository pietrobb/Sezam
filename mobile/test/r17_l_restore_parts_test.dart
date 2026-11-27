// Review c02cc47 R17-L: a restore upload part ended inside a readmit, and the
// server took the removal alone (the member's share links went). The phone
// ends each part where tests/vectors/team_log_restore_parts.json says.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/team_log.dart';

void main() {
  final vectors =
      jsonDecode(
            File(
              '../tests/vectors/team_log_restore_parts.json',
            ).readAsStringSync(),
          )
          as Map<String, dynamic>;

  test('the phone core ends every part where the vectors say', () {
    final got = <String, int>{};
    final expected = <String, int>{};
    for (final c in (vectors['cases'] as List).cast<Map<String, dynamic>>()) {
      final bodies = [
        for (final r in (c['records'] as List).cast<List>())
          <String, dynamic>{
            'type': r[0],
            'author': r[1],
            'data': <String, dynamic>{'user_id': r[2]},
          },
      ];
      got[c['name'] as String] = TeamLog.restorePartEnd(
        bodies,
        c['start'] as int,
        c['limit'] as int,
      );
      expected[c['name'] as String] = c['end'] as int;
    }
    expect(got, expected);
  });
}

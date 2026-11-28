// Authority over folders and items (lib/services/write_authority.dart, the
// core's rule) against the shared vectors tests/vectors/authority.json
// (docs/CORE_UNIFICATION.md U5): the key a header names, the log's admins and
// which pulled writes are not shown. The phone passes no previous snapshot,
// so it runs the cases without one.

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/team_log.dart';
import 'package:sezam_mobile/services/write_authority.dart';
import 'package:sodium/sodium_sumo.dart';

import 'support/real_server_phone.dart' show hostLibsodium;

const scenarios = [
  'second_admin_removes_founder',
  'org_recovery_wrap',
  'handover_on_ends_the_role_keys',
];

Uint8List fromHex(String hex) => Uint8List.fromList([
  for (var i = 0; i < hex.length; i += 2)
    int.parse(hex.substring(i, i + 2), radix: 16),
]);

void main() {
  final vectors =
      jsonDecode(File('../tests/vectors/authority.json').readAsStringSync())
          as Map<String, dynamic>;
  final log =
      jsonDecode(File('../tests/vectors/team_log.json').readAsStringSync())
          as Map<String, dynamic>;
  final records = {
    for (final s in (log['scenarios'] as List).cast<Map<String, dynamic>>())
      s['name'] as String: (s['records'] as List)
          .map((r) => Map<String, dynamic>.from(r as Map))
          .toList(),
  };
  late List<TeamState> teams;

  setUpAll(() async {
    final sodium = await SodiumSumoInit.init2(
      () => DynamicLibrary.open(hostLibsodium()),
    );
    final teamLog = TeamLog(
      (sig, msg, pk) => sodium.crypto.sign.verifyDetached(
        message: msg,
        signature: sig,
        publicKey: pk,
      ),
    );
    teams = [for (final name in scenarios) teamLog.replay(records[name]!)];
  });

  List<Map<String, dynamic>> rows(List objects) => [
    for (final o in objects.cast<Map<String, dynamic>>())
      {
        'id': o['id'],
        'object_type': o['object_type'],
        'parent_ref': o['parent_ref'],
        'is_deleted': o['is_deleted'],
        'signer_id': o['signer'],
        'access_level': o['access_level'],
        'target_user_id': o['target_user_id'],
        'payload': fromHex(o['head'] as String),
      },
  ];

  test('every header names the reference key', () {
    for (final c in (vectors['cases'] as List).cast<Map<String, dynamic>>()) {
      for (final row in rows(c['objects'] as List)) {
        expect(
          sealingDekId(row),
          (c['dek_ids'] as Map)['${row['id']}/${row['object_type']}'],
          reason: '${c['name']} ${row['id']}',
        );
      }
    }
  });

  test(
    'every case without a previous snapshot blocks what the reference blocks',
    () {
      var checked = 0;
      for (final c in (vectors['cases'] as List).cast<Map<String, dynamic>>()) {
        if (c['previous'] != null) continue;
        // The vectors draw no unsigned write with a log; without a signer the
        // phone takes the row for this account's own unsent one.
        if ((c['objects'] as List).any((o) => (o as Map)['signer'] == null)) {
          continue;
        }
        final index = c['team'] as int?;
        final admins = (c['team_admins'] as List?)?.cast<String>().toSet();
        expect(
          unauthorizedWrites(
            rows(c['objects'] as List),
            c['own_user_id'] as String?,
            team: index == null ? null : teams[index],
            teamAdmins: admins,
          ).toList(),
          c['blocked'],
          reason: c['name'] as String,
        );
        checked++;
      }
      expect(checked, greaterThan(30));
    },
  );

  test('a refused log shows what tests/vectors/personal_tree.json shows', () {
    final tree =
        jsonDecode(
              File('../tests/vectors/personal_tree.json').readAsStringSync(),
            )
            as Map<String, dynamic>;
    var checked = 0;
    for (final c in (tree['cases'] as List).cast<Map<String, dynamic>>()) {
      final objects = (c['objects'] as List).cast<Map<String, dynamic>>();
      // The phone names held keys, not opened rows, and passes no team keys.
      if (c['own_user_id'] == null ||
          (c['team_keys'] as List).isNotEmpty ||
          objects.any((o) => o['opened'] == false)) {
        continue;
      }
      expect(
        refusedLogPersonalTree(
          [
            for (final o in objects)
              {
                'id': o['id'],
                'object_type': o['object_type'],
                'parent_ref': o['parent_ref'],
                'signer_id': o['signer'],
              },
          ],
          c['own_user_id'] as String,
          personalNodes: {
            for (final o in objects)
              if (o['personal'] == true) o['id'] as String,
          },
          dekIds: {for (final o in objects) o['id'] as String: o['dek_id']},
          heldDekIds: {
            for (final o in objects)
              if (o['dek_id'] != null) o['dek_id'] as String,
          },
          tier2Entries: {
            for (final o in objects)
              if (o['tier2'] == true) o['id'] as String,
          },
        ).toList()..sort(),
        (c['expect'] as Map)['shown'],
        reason: c['name'] as String,
      );
      checked++;
    }
    expect(checked, greaterThanOrEqualTo(10));
  });

  test('the log admins are the reference', () {
    for (final c in (vectors['cases'] as List).cast<Map<String, dynamic>>()) {
      final index = c['team'] as int?;
      if (index == null || c['team_admins'] == null) continue;
      expect(
        logAdmins(records[scenarios[index]]!, teams[index]).toList()..sort(),
        c['team_admins'],
        reason: c['name'] as String,
      );
    }
  });
}

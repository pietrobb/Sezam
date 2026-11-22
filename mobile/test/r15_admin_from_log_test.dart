// Review e443cbc (R15-M, goal #439; INV-3, capability run 458): the phone took
// the server's unsigned is_admin (sezam_is_admin, kept for offline unlock too)
// as the admin flag, and VaultEntry.canEdit opened another's item on it. Once
// a team log is known, admin is who the verified log says (as on the desktop);
// a refused log makes nobody admin; only a vault with no log at all keeps the
// server's role. The web side: tests/test_r15_admin_from_log.py.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/team_log.dart';
import 'package:sezam_mobile/services/team_log_client.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart' show setUpPhone, initPhoneCrypto;

const admin = '01JM0000000000000000000001'; // the 'basic' log's admin
const member = '01JM0000000000000000000002';

void main() {
  late Directory appDir;
  late VaultService vault;
  final records = [
    for (final r in ((jsonDecode(File('../tests/vectors/team_log.json').readAsStringSync())['scenarios'] as List)
            .firstWhere((s) => (s as Map)['name'] == 'basic') as Map)['records'] as List)
      Map<String, dynamic>.from(r as Map),
  ];

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_admin_from_log_');
    await setUpPhone(appDir.path);
    initPhoneCrypto();
    vault = VaultService();
  });

  tearDownAll(() async {
    await DatabaseService().close();
    await appDir.delete(recursive: true);
  });

  const theirs = VaultEntry(id: 'item', parentRef: 'folder', name: 'theirs', fields: [], ownerId: 'someone-else');

  Future<Map<String, bool>> judge(String userId, bool serverSaysAdmin, {bool log = false, bool refused = false}) async {
    await vault.unlock(
      kek: Uint8List(32),
      signingSecretKey: Uint8List(64),
      signingPublicKey: Uint8List(32),
      userId: userId,
      isAdmin: serverSaysAdmin,
    );
    vault.teamLog = log ? LocalTeamLog(records, TeamLog(vault.verifyEd25519).replay(records)) : null;
    vault.teamLogRefusal = refused ? TeamLogMismatch('damaged in this test', 'local_damaged') : null;
    return {'admin': vault.isAdmin, 'edit': theirs.canEdit(userId, vault.isAdmin)};
  }

  test('with a team log the phone takes admin from the log, never from the server', () async {
    const yes = {'admin': true, 'edit': true};
    const no = {'admin': false, 'edit': false};
    expect({
      'member the server calls admin': await judge(member, true, log: true),
      'admin the server calls member': await judge(admin, false, log: true),
      'refused log': await judge(admin, true, refused: true),
      'no log, server admin': await judge('solo', true),
      'no log, server member': await judge('solo', false),
    }, {
      'member the server calls admin': no,
      'admin the server calls member': yes,
      'refused log': no,
      'no log, server admin': yes,
      'no log, server member': no,
    });
  });

  // Capability run 473: a phone that knows a team log exists (the account
  // anchor, a confirmed genesis) before it holds a copy, e.g. a sign-in before
  // its pull, is no vault without a log: the server's flag makes nobody admin
  // there, as webIsAdmin's pinned_no_copy.
  test('pinned to a team log but holding no copy yet: the server makes nobody admin', () async {
    final genesis = TeamLog(vault.verifyEd25519).replay(records).genesisHash;
    Future<Map<String, Object?>> pinnedOnly(String userId, Future<void> Function() pin) async {
      await pin();
      await vault.unlock(
        kek: Uint8List(32),
        signingSecretKey: Uint8List(64),
        signingPublicKey: Uint8List(32),
        userId: userId,
        isAdmin: true,
      );
      return {
        'copy': vault.teamLog != null,
        'refused': vault.teamLogRefusal != null,
        'admin': vault.isAdmin,
        'edit': theirs.canEdit(userId, vault.isAdmin),
      };
    }

    const no = {'copy': false, 'refused': false, 'admin': false, 'edit': false};
    expect({
      'confirmed genesis, empty vault': await pinnedOnly('member-confirmed', () => confirmTeamGenesis('member-confirmed', genesis)),
      'account anchor': await pinnedOnly('member-anchor', () => recordAccountTeamGenesis('member-anchor', genesis)),
    }, {
      'confirmed genesis, empty vault': no,
      'account anchor': no,
    });
  });
}

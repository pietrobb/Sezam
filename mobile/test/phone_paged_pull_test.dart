// Review 1141a20 (R9-G), phone: a pull in several pages judged every object
// by the team log head of its first page. A team folder the admin created and
// shared while the phone fetched the later pages came with those pages, but
// the log the phone checked them with did not have it yet: the folder was not
// shown, and the checkpoint had passed it.
// tests/test_team_log_phone_paged_pull.py sets it up and runs this file with
// SEZAM_X3_* set; without them the test is skipped.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

/// Waits for the admin's step before the first continuation page.
class _PauseBetweenPages extends Net {
  _PauseBetweenPages(this.dir);
  final String dir;
  bool armed = false;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    if (armed && request.url.queryParameters.containsKey('cursor')) {
      armed = false;
      await handshake(dir, 'between');
    }
    return super.send(request);
  }
}

void main() {
  final serverUrl = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];

  test(
    'a team folder shared between the pages of a pull is shown',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      await setUpPhone('$dir/app');
      final net = _PauseBetweenPages(dir!);
      await http.runWithClient(() async {
        final auth = AuthService();
        final sync = SyncService();
        final vault = VaultService();
        initPhoneCrypto();
        await vault.init();

        final c = await auth.connectToServer(
          serverUrl: serverUrl!,
          password: cfg['password'] as String,
          username: cfg['username'] as String,
        );
        expect(c.outcome, ConnectOutcome.connected, reason: c.message);
        await net.settle();
        await vault.confirmTeamFounder(
          await vault.reviewTeamFounder(),
          cfg['fingerprint'] as String,
        );
        await sync.pull();
        await vault.reloadData();
        expect(
          vault.allEntries.map((e) => e.name),
          contains('ops-seed'),
          reason: 'the member reads Ops',
        );

        // A member does not read a team folder's name (idea #40): its item.
        List<String> shown() => [
          for (final e in vault.allEntries)
            if (e.name == 'hr-item') e.name,
        ];
        expect(shown(), isEmpty);

        await handshake(dir, 'filled');
        net.armed = true;
        await sync.pull();
        expect(net.armed, isFalse, reason: 'the pull had a single page');
        await vault.reloadData();
        const expected = ['hr-item'];
        expect(shown(), expected);
        await sync.pull();
        await vault.reloadData();
        expect(shown(), expected);
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_team_log_phone_paged_pull.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

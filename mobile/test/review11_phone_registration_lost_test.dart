// Review 4acfdde R11 (medium): the answer to an invitation registration was
// lost, and the retry's resume asked before that registration landed. The
// retry's own register then got 409/410 (the server saw that very account)
// and the phone dropped its pending registration: the account stayed
// orphaned on the server with the name taken. The phone now asks again
// whether an account under its keys exists before it lets the intent go.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

void main() {
  final server = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];
  test(
    'a registration whose answer was lost is resumed, not dropped',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      final password = cfg['password'] as String;
      await setUpPhone('$dir/app');
      final net = Net();
      await http.runWithClient(() async {
        const storage = FlutterSecureStorage();
        const pendingKey = 'sezam_pending_invitation_registration';
        final auth = AuthService();
        final vault = VaultService();
        initPhoneCrypto();
        await vault.init();
        final created = await auth.createNewVault(password: password);
        expect(created.success, isTrue, reason: created.error);
        Future<ConnectResult> register() => auth.registerWithInvitation(
          serverUrl: server!,
          username: 'lost-answer-phone',
          password: password,
          invitationToken: cfg['invitation'] as String,
        );

        net.dropResponsePath = '/api/users/register';
        final lost = await register();
        expect(lost.outcome, ConnectOutcome.error, reason: lost.message);
        expect(await storage.read(key: pendingKey), isNotNull);

        // The retry's resume comes before the first registration landed.
        net.refusePath = '/api/auth/registration-resume';
        final retried = await register();
        expect(retried.outcome, ConnectOutcome.needsApproval, reason: retried.message);
        final pending = jsonDecode((await storage.read(key: pendingKey))!) as Map;
        expect(pending['response'], isNotNull);
        File('$dir/user_id.txt').writeAsStringSync(
          (pending['response'] as Map)['user_id'] as String,
        );
        await auth.lock();
        await net.settle();
      }, () => net);
      net.close();
    },
    skip: server == null || dir == null,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

// Review 8595ec1 #7 (R10-F): a registration the server refuses outright (a
// mistyped invitation 404, a used one 410, a taken name 409) leaves no pending
// intent behind, so the phone can register again or connect elsewhere.
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
    'a refused invitation registration can be retried',
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

        final valid = cfg['invitation'] as String;
        final token = Uri.parse(valid).queryParameters['invite']!;
        final typo = valid.replaceFirst(token, '${token.substring(0, token.length - 4)}AAAA');
        for (final (invitation, username, message) in [
          (typo, 'invited-phone', 'Neplatny invitation token.'),
          (cfg['used'] as String, 'invited-phone', 'Invitation token uz bol pouzity alebo exspiroval.'),
          (valid, 'bob', 'Pouzivatelske meno uz existuje.'),
        ]) {
          final refused = await auth.registerWithInvitation(
            serverUrl: server!,
            username: username,
            password: password,
            invitationToken: invitation,
          );
          expect(refused.outcome, ConnectOutcome.error);
          expect(refused.message, message);
          expect(await storage.read(key: pendingKey), isNull, reason: message);
        }

        final registered = await auth.registerWithInvitation(
          serverUrl: server!,
          username: 'invited-phone',
          password: password,
          invitationToken: valid,
        );
        expect(registered.outcome, ConnectOutcome.needsApproval, reason: registered.message);
        expect(await storage.read(key: pendingKey), isNotNull);
        await auth.lock();
        await net.settle();
      }, () => net);
      net.close();
    },
    skip: server == null || dir == null,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

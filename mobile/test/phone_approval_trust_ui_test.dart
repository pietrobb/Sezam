// Real approval polling must not navigate successfully after a refused pull.
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/screens/server_connect_screen.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/team_log_client.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'phone_qr_team_anchor_test.dart' show LyingNet;
import 'support/real_server_phone.dart';

class RealHttp extends HttpOverrides {}

void main() {
  LiveTestWidgetsFlutterBinding().framePolicy =
      LiveTestWidgetsFlutterBindingFramePolicy.onlyPumps;
  final server = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];
  testWidgets(
    'approval trust failure stays on screen and honest retry succeeds',
    (tester) async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      final net = HttpOverrides.runWithHttpOverrides(
        () => LyingNet(),
        RealHttp(),
      );
      final locked = cfg['lie'] == 'locked-none';
      final vault = VaultService();
      final auth = http.runWithClient(() => AuthService(), () => net);
      final db = DatabaseService();
      await tester.runAsync(() async {
        await setUpPhone('$dir/app');
        initPhoneCrypto();
        await vault.init();
        expect(
          (await auth.createNewVault(
            password: cfg['password'] as String,
          )).success,
          isTrue,
        );
        if (locked) {
          final registered = await http.runWithClient(() => auth.registerWithInvitation(
            serverUrl: server!, username: 'invited-phone', password: cfg['password'] as String,
            invitationToken: cfg['invitation'] as String), () => net);
          expect(registered.outcome, ConnectOutcome.needsApproval);
          await auth.lock();
          await db.close();
        }
      });
      tester.view.resetPhysicalSize();
      tester.view.physicalSize = const Size(1200, 1600);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      bool? returned;
      await http.runWithClient(() async {
        await tester.pumpWidget(
          MaterialApp(
            home: Builder(
              builder: (context) => Scaffold(
                body: TextButton(
                  onPressed: () async {
                    returned = await Navigator.of(context).push<bool>(
                      MaterialPageRoute(
                        builder: (_) =>
                            ServerConnectScreen(vaultUnlocked: !locked),
                      ),
                    );
                  },
                  child: const Text('Open'),
                ),
              ),
            ),
          ),
        );
        await tester.tap(find.text('Open'));
        await tester.pump();
        await tester.runAsync(() async {
          await Future<void>.delayed(const Duration(milliseconds: 100));
        });
        await tester.pump(const Duration(milliseconds: 400));
        final fields = find.byType(TextField);
        await tester.enterText(fields.at(0), server!);
        await tester.enterText(fields.at(1), 'invited-phone');
        await tester.enterText(fields.at(2), cfg['password'] as String);
        Future<void> submit() async {
          final button = tester.widget<ElevatedButton>(
            find.byWidgetPredicate((w) => w is ElevatedButton),
          );
          await tester.runAsync(
            () => http
                .runWithClient(() async {
                  await (button.onPressed as dynamic)();
                }, () => net)
                .timeout(const Duration(seconds: 30)),
          );
          await tester.pump();
        }

        await submit();
        if (locked) {
          expect(find.text('Cakam na schvalenie...'), findsOneWidget);
          expect(vault.isUnlocked, isFalse);
          expect(net.paths.where((p) => p == '/api/users/register').length, 1);
          await tester.runAsync(() async {
            await handshake(dir!, 'approve');
            await Future<void>.delayed(const Duration(seconds: 8));
          });
          for (var i = 0; i < 40 && returned == null; i++) {
            await tester.pump(const Duration(milliseconds: 500));
            await tester.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 200)));
          }
          expect(returned, isTrue, reason: 'locked approval must finish through the real polling UI');
          expect(passwords(vault)['vpn'], 'ops-pw');
          await tester.pumpWidget(const SizedBox.shrink());
          await tester.runAsync(() async {
            await auth.lock();
            await net.settle();
            await db.close();
          });
          net.close();
          return;
        }
        expect(
          find.text('Zaregistrovat'),
          findsOneWidget,
          reason:
              '${tester.widgetList<Text>(find.byType(Text)).map((w) => w.data).toList()} requests=${net.paths}',
        );
        await tester.enterText(
          find.byType(TextField),
          cfg['invitation'] as String,
        );
        await submit();
        expect(find.text('Cakam na schvalenie...'), findsOneWidget);
        final before = await tester.runAsync(db.getAllObjects);
        await tester.runAsync(() async {
          net.lie = cfg['lie'] as String;
          await handshake(dir!, 'approve');
          // Timer.periodic is created by the real submit callback in runAsync.
          await Future<void>.delayed(const Duration(seconds: 8));
        });
        for (
          var i = 0;
          i < 30 &&
              returned == null &&
              find.textContaining('Synchronizacia zlyhala').evaluate().isEmpty;
          i++
        ) {
          await tester.pump(const Duration(seconds: 1));
          await tester.runAsync(() async {
            await Future<void>.delayed(const Duration(milliseconds: 100));
          });
        }
        expect(
          returned,
          isNull,
          reason: 'a refused approval pull must not return success',
        );
        expect(find.byType(ServerConnectScreen), findsOneWidget);
        expect(
          find.textContaining('Synchronizacia zlyhala'),
          findsOneWidget,
          reason:
              '${tester.widgetList<Text>(find.byType(Text)).map((w) => w.data).toList()} requests=${net.paths}',
        );
        expect(
          find.text('Pripojit'),
          findsOneWidget,
          reason: 'allow an explicit retry, not silent polling',
        );
        expect(find.textContaining('TEAM LOG MISMATCH'), findsOneWidget);
        expect(net.paths, contains('/api/sync'));
        expect(await tester.runAsync(db.getAllObjects), before);
        final userId = File('$dir/user-id.txt').readAsStringSync();
        expect(
          await tester.runAsync(() => readConfirmedTeamGenesis(userId)),
          cfg['genesis'],
        );
        final attempts = net.paths.length;
        await tester.runAsync(() async {
          await Future<void>.delayed(const Duration(seconds: 6));
        });
        expect(
          net.paths.length,
          attempts,
          reason: 'approval timer stopped after refusal',
        );
        net.lie = 'none';
        await submit();
        await tester.pump(const Duration(seconds: 2));
        expect(returned, isTrue);
        expect(passwords(vault)['vpn'], 'ops-pw');
        await tester.pumpWidget(const SizedBox.shrink());
        await tester.runAsync(() async {
          await auth.lock();
          await net.settle();
          await db.close();
        });
        net.close();
      }, () => net);
    },
    skip: server == null || dir == null,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

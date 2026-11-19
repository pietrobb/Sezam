// Real settings UI, independent fingerprint, secure pin and offline restart.
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/screens/settings_screen.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/team_log_client.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

class RealHttp extends HttpOverrides {}

void main() {
  LiveTestWidgetsFlutterBinding().framePolicy =
      LiveTestWidgetsFlutterBindingFramePolicy.onlyPumps;
  final server = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];
  testWidgets(
    'settings confirms only independent founder fingerprint and survives restart',
    (tester) async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      final net = HttpOverrides.runWithHttpOverrides(() => Net(), RealHttp());
      final auth = http.runWithClient(() => AuthService(), () => net);
      final vault = VaultService();
      final db = DatabaseService();
      final uid = cfg['user_id'] as String;
      await tester.runAsync(() async {
        await setUpPhone('$dir/app');
        initPhoneCrypto();
        await vault.init();
        final result = await auth.unlockWithPassword(
          serverUrl: server!,
          username: 'bob',
          password: cfg['password'] as String,
        );
        expect(result.success, isTrue, reason: result.error);
        await net.settle();
      });
      expect(passwords(vault)['anchor-secret'], isNull);
      tester.view.physicalSize = const Size(1200, 2000);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      await tester.pumpWidget(
        const MaterialApp(home: Scaffold(body: SettingsScreen())),
      );
      await tester.runAsync(
        () => Future<void>.delayed(const Duration(milliseconds: 100)),
      );
      await tester.pump();
      expect(find.text('Dôvera tímu'), findsOneWidget);
      Future<void> open() async {
        await tester.runAsync(() async {
          await tester.tap(find.text('Dôvera tímu'));
          await Future<void>.delayed(const Duration(milliseconds: 100));
        });
        await tester.pump(const Duration(milliseconds: 400));
        expect(find.byType(AlertDialog), findsOneWidget);
        expect(
          tester.widget<TextField>(find.byType(TextField)).controller!.text,
          isEmpty,
        );
      }

      Future<void> submit() async {
        final button = tester.widget<ElevatedButton>(
          find.widgetWithText(ElevatedButton, 'Potvrdiť'),
        );
        await tester.runAsync(
          () async => await (button.onPressed as dynamic)(),
        );
        await tester.pump();
        await tester.pump(const Duration(milliseconds: 400));
      }

      await open();
      await tester.tap(find.text('Zrušiť'));
      await tester.pump(const Duration(milliseconds: 400));
      expect(
        await tester.runAsync(() => readConfirmedTeamGenesis(uid)),
        isNull,
      );
      await open();
      final before = await tester.runAsync(db.getAllObjects);
      final checkpoint = await tester.runAsync(
        () => db.getSyncState('sync_checkpoint:$uid'),
      );
      await tester.enterText(find.byType(TextField), 'ff' * 32);
      await submit();
      expect(find.byType(AlertDialog), findsOneWidget);
      expect(
        await tester.runAsync(() => readConfirmedTeamGenesis(uid)),
        isNull,
      );
      expect(passwords(vault)['anchor-secret'], isNull);
      await tester.enterText(
        find.byType(TextField),
        cfg['fingerprint'] as String,
      );
      await tester.runAsync(() async {
        await auth.lock();
        await net.settle();
        net.onSend = (_) => throw const SocketException('offline restart');
        expect(
          (await auth.unlockOffline(
            password: cfg['password'] as String,
          )).success,
          isTrue,
        );
      });
      await submit();
      expect(
        find.byType(AlertDialog),
        findsOneWidget,
        reason: 'old dialog cannot confirm a new session',
      );
      expect(
        await tester.runAsync(() => readConfirmedTeamGenesis(uid)),
        isNull,
      );
      await tester.tap(find.text('Zrušiť'));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 400));
      await open();
      await tester.enterText(
        find.byType(TextField),
        cfg['fingerprint'] as String,
      );
      secureWriteKillsApp = 'sezam_confirmed_team_genesis:$uid';
      await submit();
      expect(find.byType(AlertDialog), findsOneWidget);
      expect(
        await tester.runAsync(() => readConfirmedTeamGenesis(uid)),
        isNull,
      );
      expect(await tester.runAsync(db.getAllObjects), before);
      expect(
        await tester.runAsync(() => db.getSyncState('sync_checkpoint:$uid')),
        checkpoint,
      );
      await submit();
      expect(
        find.byType(AlertDialog),
        findsNothing,
        reason: tester
            .widgetList<Text>(find.byType(Text))
            .map((w) => w.data)
            .join('\n'),
      );
      expect(
        await tester.runAsync(() => readConfirmedTeamGenesis(uid)),
        cfg['genesis'],
      );
      expect(passwords(vault)['anchor-secret'], 'must-stay-sealed');
      expect(await tester.runAsync(db.getAllObjects), before);
      expect(
        await tester.runAsync(() => db.getSyncState('sync_checkpoint:$uid')),
        checkpoint,
      );
      await tester.pumpWidget(const SizedBox.shrink());
      await tester.runAsync(() async {
        await auth.lock();
        await net.settle();
        await db.close();
        final restarted = await auth.unlockOffline(
          password: cfg['password'] as String,
        );
        expect(restarted.success, isTrue, reason: restarted.error);
        expect(passwords(vault)['anchor-secret'], 'must-stay-sealed');
        await auth.lock();
        await net.settle();
        await db.close();
      });
      net.close();
    },
    skip: server == null || dir == null,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

// A new phone joins an account another client made, by its password alone
// (the real AuthService/SyncService/VaultService against the real server).
// tests/test_cross_client_password_change.py starts the server, lets desktop
// A make the account and runs this file with SEZAM_X3_* set; without them the
// test is skipped. Scenario "empty": a phone without a vault. "local": a
// phone that already keeps entries offline under its own password; they move
// into the account, and a failure halfway leaves the phone as it was.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:sezam_mobile/models/vault_models.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';

import 'support/real_server_phone.dart';

String _ulid() {
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  final rnd = Random.secure();
  var ms = DateTime.now().millisecondsSinceEpoch;
  final time = List.filled(10, '0');
  for (var i = 9; i >= 0; i--) {
    time[i] = alphabet[ms % 32];
    ms ~/= 32;
  }
  return time.join() +
      List.generate(16, (_) => alphabet[rnd.nextInt(32)]).join();
}

/// A tier-2 entry under its own DEK, as desktop writes it: tier, creation
/// time and AI policy in the meta (keys the phone's model does not know).
Future<void> _addDesktopStyleEntry(VaultService vault, String folderId) async {
  final crypto = CryptoService();
  final db = DatabaseService();
  final dek = crypto.generateDEK();
  final dekId = _ulid();
  final wrapped = crypto.wrapDEK(
    dek,
    dekId,
    vault.currentKek!,
    vault.kekDekId!,
  );
  Future<void> put(
    String id,
    String type,
    String? parentRef,
    List<int> payload,
  ) async {
    final bytes = Uint8List.fromList(payload);
    final hash = crypto.sha256Hex(bytes);
    await db.upsertObject(
      id: id,
      objectType: type,
      payload: bytes,
      ownerId: vault.userId,
      parentRef: parentRef,
      version: 1,
      payloadHash: hash,
      clientSignature: crypto.signSyncObject(
        id: id,
        objectType: type,
        parentRef: parentRef,
        targetUserId: null,
        isDeleted: 0,
        version: 1,
        payloadHashHex: hash,
        signingSecretKey: vault.signingSecretKey!,
      ),
      queued: true,
      writePolicy: type == 'entry' ? 'shared' : null,
    );
  }

  await put(dekId, 'dek', null, wrapped);
  final entryId = _ulid();
  await put(
    entryId,
    'entry',
    folderId,
    crypto.encryptEntryPayload(
      {
        'name': 'tiered',
        'tags': <String>[],
        'tier': 2,
        'created_at': 1700000000000,
        'ai_read_secret': false,
        'allowed_actions': ['connect'],
        'max_session_minutes': 15,
      },
      {
        'fields': [
          {'key': 'password', 'value': 't2', 'sensitive': true},
        ],
      },
      dek,
      dekId,
      entryId,
      1,
    ),
  );
}

void main() {
  final serverUrl = env['SEZAM_X3_SERVER'];
  final dir = env['SEZAM_X3_DIR'];

  test(
    'a phone joins an existing account by its password',
    () async {
      final cfg =
          jsonDecode(File('$dir/config.json').readAsStringSync())
              as Map<String, dynamic>;
      final scenario = cfg['scenario'] as String;
      final username = cfg['username'] as String;
      final password = cfg['password'] as String;
      final localPassword = cfg['local_password'] as String;
      final expected = Map<String, String>.from(cfg['account'] as Map);

      await setUpPhone('$dir/app');
      final net = Net();
      await http.runWithClient(() async {
        final auth = AuthService();
        final sync = SyncService();
        final vault = VaultService();
        initPhoneCrypto();
        await vault.init(); // as the app starts: an empty database file
        expect(await auth.hasLocalVault(), isFalse);

        Future<ConnectResult> connect(String pw) => auth.connectToServer(
          serverUrl: serverUrl!,
          password: pw,
          username: username,
        );

        if (scenario == 'local') {
          var r = await auth.createNewVault(password: localPassword);
          expect(r.success, isTrue, reason: r.error);
          final mine = await vault.createNode(
            name: 'Mine',
            parentRef: vault.rootNodeId!,
          );
          await vault.createEntry(
            parentRef: mine.id,
            name: 'offline',
            fields: const [
              EntryField(key: 'password', value: 'o1', sensitive: true),
            ],
          );
          // The network failing after sign-in: the phone stays as it was.
          net.failPath = '/api/sync';
          final failed = await connect(password);
          expect(failed.outcome, ConnectOutcome.error, reason: failed.message);
          expect(net.failPath, isNull, reason: 'the pull was never tried');
          expect(passwords(vault), {'offline': 'o1'});
          await auth.lock();
          await net.settle();
          r = await auth.unlockOffline(password: localPassword);
          expect(r.success, isTrue, reason: r.error);
          expect(passwords(vault), {'offline': 'o1'});
          expected['offline'] = 'o1';

          // Review 688edcb: an entry as desktop keeps it (tier 2 under its
          // own DEK, creation time, AI policy) — the join must carry all
          // of it.
          await _addDesktopStyleEntry(vault, mine.id);
          await vault.reloadData();
          expect(passwords(vault), {'offline': 'o1', 'tiered': 't2'});
          expected['tiered'] = 't2';

          // Killed while the vault is set aside (the pull never answers):
          // the next start puts the phone back as it was.
          net.hangPath = '/api/sync';
          unawaited(connect(password));
          await net.hung.future;
          sync.forgetRunningSyncsForTesting(); // a new process: no sync runs
          await auth.recoverInterruptedJoin(); // as the app starts
          await vault.init();
          expect(await auth.hasLocalVault(), isTrue);
          r = await auth.unlockOffline(password: localPassword);
          expect(r.success, isTrue, reason: r.error);
          await net.settle();
          expect(passwords(vault), {'offline': 'o1', 'tiered': 't2'});
        }

        // A wrong password joins nothing.
        var c = await connect('wrong-$password');
        expect(c.outcome, ConnectOutcome.needsInvitation, reason: c.message);
        expect(await auth.hasLocalVault(), scenario == 'local');

        // The account password joins: the account's entries, and this
        // phone's own ones moved into it.
        c = await connect(password);
        expect(c.outcome, ConnectOutcome.connected, reason: c.message);
        await net.settle();
        expect(passwords(vault), expected);
        final pushed = (await sync.sync()).push;
        expect(pushed.errors, isEmpty);
        expect(pushed.conflicts, 0);
        expect(await sync.getDirtyObjectCount(), 0);
        expect(passwords(vault), expected);
        await auth.lock();
        await net.settle();

        // From now on the account password opens the phone, offline and
        // online; the phone's former own password does not.
        var r = await auth.unlockOffline(password: localPassword);
        expect(r.success, isFalse);
        r = await auth.unlockOffline(password: password);
        expect(r.success, isTrue, reason: r.error);
        await net.settle();
        expect(passwords(vault), expected);
        await auth.lock();
        await net.settle();
        r = await auth.unlockWithPassword(
          password: password,
          username: username,
          serverUrl: serverUrl!,
        );
        expect(r.success, isTrue, reason: r.error);
        await net.settle();
        await sync.sync(); // the app's sync: push, pull, reload
        expect(passwords(vault), expected);
        await auth.lock();
        await net.settle();
      }, () => net);
    },
    skip: serverUrl == null || dir == null
        ? 'run by tests/test_cross_client_password_change.py'
        : false,
    timeout: const Timeout(Duration(minutes: 5)),
  );
}

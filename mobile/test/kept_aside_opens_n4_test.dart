// Review d150605 N4: a join of an earlier version replaced the salt and
// keypair in secure storage without keeping them, so the vault it set aside
// may be sealed with a key nothing can derive any more. Settings offered
// "Save copy" as the way to rescue it all the same. The phone now checks the
// copy against its current key and says what is true.

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/database_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';
import 'package:sqflite/sqflite.dart';

import 'support/real_server_phone.dart';

void main() {
  late Directory appDir;
  late String dbPath;
  final kekHere = Uint8List.fromList(List.filled(32, 1));
  final kekBefore = Uint8List.fromList(List.filled(32, 2));
  final dekId = 'D' * 26;

  Future<KeptAsideVault> keepVaultSealedWith(Uint8List kek) async {
    final aside = '$dbPath.before-join.kept-1';
    final db = await openDatabase(aside, singleInstance: false);
    await db.execute(
      'CREATE TABLE vault_objects (id TEXT PRIMARY KEY, object_type TEXT, '
      'payload BLOB, owner_id TEXT, version INTEGER, is_deleted INTEGER)',
    );
    await db.insert('vault_objects', {
      'id': dekId,
      'object_type': 'dek',
      'payload': CryptoService().wrapDEK(
        Uint8List(32),
        dekId,
        kek,
        'K' * 26,
      ),
      'owner_id': 'local',
      'version': 1,
      'is_deleted': 0,
    });
    await db.close();
    final [kept] = await AuthService().keptAsideVaults();
    return kept;
  }

  setUpAll(() async {
    appDir = await Directory.systemTemp.createTemp('sezam_kept_opens_');
    await setUpPhone(appDir.path);
    initPhoneCrypto();
    dbPath = await DatabaseService.vaultDbPath();
  });

  tearDown(() async {
    for (final kept in await AuthService().keptAsideVaults()) {
      AuthService().deleteKeptAsideVault(kept);
    }
    VaultService().lock();
  });

  tearDownAll(() async {
    await DatabaseService().close();
    await appDir.delete(recursive: true);
  });

  Future<void> unlockWith(Uint8List kek) => VaultService().unlock(
    kek: Uint8List.fromList(kek),
    signingSecretKey: Uint8List(64),
    signingPublicKey: Uint8List(32),
    userId: 'U' * 26,
  );

  test('a copy sealed with the key from before the join does not open', () async {
    final kept = await keepVaultSealedWith(kekBefore);
    await unlockWith(kekHere);
    expect(await AuthService().keptAsideOpensHere(kept), isFalse);
  });

  test('a copy sealed with the current key opens', () async {
    final kept = await keepVaultSealedWith(kekHere);
    await unlockWith(kekHere);
    expect(await AuthService().keptAsideOpensHere(kept), isTrue);
  });

  test('locked: not known', () async {
    final kept = await keepVaultSealedWith(kekHere);
    expect(await AuthService().keptAsideOpensHere(kept), isNull);
  });

  test('settings words the dialog by the check', () {
    final screen = File('lib/screens/settings_screen.dart').readAsStringSync();
    final dialog = screen.substring(
      screen.indexOf('Future<void> _openKeptAside('),
      screen.indexOf('static String _formatKeptAt('),
    );
    expect(dialog, contains('await _auth.keptAsideOpensHere(kept)'));
    expect(dialog, contains('Neither'));
    expect(dialog, contains('nor a saved copy can open it'));
  });
}

// Lockout review 2026-11-08 (mobile): paths that could lock the user out of
// the local vault for good.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sezam_mobile/services/auth_service.dart';
import 'package:sezam_mobile/services/sync_service.dart';

const _auth = 'lib/services/auth_service.dart';

String _body(String file, String start, String end) {
  final src = File(file).readAsStringSync();
  final from = src.indexOf(start);
  expect(from, greaterThanOrEqualTo(0), reason: start);
  final to = src.indexOf(end, from + start.length);
  return src.substring(from, to < 0 ? src.length : to);
}

void main() {
  group('#5 .sezam-key import keeps the local vault readable', () {
    late String import;
    late String move;
    setUpAll(() {
      import = _body(_auth, 'importSezamKey({', '// ── Create Local Vault');
      move = _body(
        _auth,
        'Future<bool> _moveVaultToBackupKek(',
        '/// Biometric unlock stores the KEK itself',
      );
    });

    test('identity and DEK move happen before the salt is replaced', () {
      final check = import.indexOf('_moveVaultToBackupKek(');
      final persist = import.indexOf('_persistKeypairState(');
      expect(check, greaterThan(0));
      expect(persist, greaterThan(check));
    });

    test('a backup of another account or keypair changes nothing', () {
      expect(move, contains('!_bytesEqual(localEncryptionPk, backup.encryptionPublicKey)'));
      expect(import, contains('_canonicalUserObjectIdPattern.hasMatch(localUserId)'));
      expect(import, contains('? localUserId : await _secureStorage.read(key: _userObjectIdKey)'));
      expect(import, contains('userObjectId: userObjectId'));
      expect(
        move,
        contains('!_bytesEqual(localSigningPk, backup.signingPublicKey)'),
      );
      expect(move, contains('Unlock the vault before importing'));
      final identity = move.indexOf('backup.signingPublicKey');
      expect(move.indexOf('_sync.rekeyLocalVault('), greaterThan(identity));
    });

    test('own DEKs the backup KEK cannot open move from the current KEK', () {
      final probe = move.indexOf('_sync.unreadableOwnDeks(backupKek');
      final rekey = move.indexOf('_sync.rekeyLocalVault(');
      expect(probe, greaterThan(0));
      expect(rekey, greaterThan(probe));
      expect(move, contains('newKek: backupKek'));
      expect(move, contains('on LocalDekRekeyException'));
    });

    test('biometrics and the unlocked vault follow the backup KEK', () {
      final persist = import.indexOf('_persistKeypairState(');
      expect(import.indexOf('_refreshBiometricKek(kek)'), greaterThan(persist));
      expect(import.indexOf('_vault.unlock('), greaterThan(persist));
    });
  });

  group('#6 one Argon2 memory cap, checked before anything is stored', () {
    Map<String, dynamic> meta(int memoryCost) => {
      'argon2_params': {
        'time_cost': 3,
        'memory_cost': memoryCost,
        'parallelism': 4,
      },
    };

    test('the account params accept 256 MiB and refuse more', () {
      expect(accountKdfParams(meta(262144)).memoryCost, 262144);
      expect(() => accountKdfParams(meta(262145)), throwsFormatException);
      expect(() => accountKdfParams(meta(1048576)), throwsFormatException);
    });

    test('the keypair journal is validated before it is written', () {
      final persist = _body(
        _auth,
        'Future<void> _persistKeypairState(',
        'Future<void> _completePendingKeypairMigration()',
      );
      // The journal is built (and validated) by _keypairMigration first.
      final build = persist.indexOf('= _keypairMigration(');
      final write = persist.indexOf('key: _pendingKeypairMigrationKey');
      expect(build, greaterThan(0));
      expect(write, greaterThan(build));
      final validated = _body(
        _auth,
        'Map<String, dynamic> _keypairMigration(',
        'Future<void> _completePendingKeypairMigration()',
      );
      final check = validated.indexOf(
        '_validatePendingKeypairMigration(migration)',
      );
      expect(check, greaterThan(0));
      expect(validated.indexOf('return migration'), greaterThan(check));
    });

    test('a journal from before the cap still completes', () {
      final complete = _body(
        _auth,
        'Future<void> _completePendingKeypairMigration()',
        'void _validatePendingKeypairMigration(',
      );
      expect(
        complete,
        contains(
          '_validatePendingKeypairMigration(migration, stored: true)',
        ),
      );
    });
  });

  group('#9 password changed elsewhere: network before disk', () {
    late String adopt;
    setUp(() {
      adopt = _body(
        _auth,
        'Future<AuthResult> adoptPasswordChangedElsewhere',
        'Future<void> _persistKeypairState',
      );
    });

    test('authenticate runs before the local DEKs move', () {
      final auth = adopt.indexOf('_sync.authenticate(');
      final rekey = adopt.indexOf('_sync.rekeyLocalVault(');
      expect(auth, greaterThan(0));
      expect(rekey, greaterThan(auth));
    });

    test('the unlocked vault follows the moved DEKs before keypair state', () {
      final rekey = adopt.indexOf('_sync.rekeyLocalVault(');
      final unlock = adopt.indexOf('_vault.unlock(');
      final persist = adopt.indexOf('_persistKeypairState(');
      expect(unlock, greaterThan(rekey));
      expect(persist, greaterThan(unlock));
      // No network call between the re-key and the in-memory switch.
      final between = adopt.substring(rekey, unlock);
      expect(between, isNot(contains('_sync.authenticate(')));
      expect(between, isNot(contains('_sync.recover(')));
      expect(between, isNot(contains('_sync.fetchMeta(')));
    });
  });

  group('#7 a throttled or locked /recover is not "Wrong password"', () {
    SyncException refused(int status) =>
        SyncException(operation: 'recover', statusCode: status, message: 'x');

    test('each refusal tells the user what to do', () {
      expect(recoverFailureMessage(refused(401)), 'Wrong password');
      expect(recoverFailureMessage(refused(429)), contains('too many failed attempts'));
      expect(recoverFailureMessage(refused(423)), contains('lift the lock'));
      expect(
        recoverFailureMessage(const SocketException('down')),
        contains('Could not reach the server'),
      );
    });

    test('limits survive the offline "Wrong password" fallback', () {
      expect(AuthResult.recoverFailure(refused(429)).recoveryLimited, isTrue);
      expect(AuthResult.recoverFailure(refused(423)).recoveryLimited, isTrue);
      expect(AuthResult.recoverFailure(refused(401)).recoveryLimited, isFalse);
      final screen = _body(
        'lib/screens/unlock_screen.dart',
        'Future<void> _unlockWithServer(',
        'HapticFeedback.heavyImpact()',
      );
      expect(screen, contains('result.recoveryLimited'));
      final auth = File(_auth).readAsStringSync();
      expect(
        RegExp(r"_sync\.recover\([^;]*;[\s\S]{0,700}?catch \(_\) \{\s*return AuthResult\.failure\('Wrong password'\)")
            .hasMatch(auth),
        isFalse,
      );
    });
  });
}

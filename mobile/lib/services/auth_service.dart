/// Sezam AuthService — handles vault unlock, biometrics, and recovery.
///
/// Authentication flow:
///   1. Password -> Argon2id -> KEK (32B) + auth_proof (32B)
///   2. Recover encrypted keypair (from secure storage or server Path B)
///   3. Decrypt keypair with KEK (AEAD envelope, blob_kind=7)
///   4. Challenge-response auth with server -> JWT
///   5. Unlock vault (unwrap DEKs, decrypt data)
///
/// Biometric flow:
///   1. KEK is read from biometric-bound storage (OS biometric prompt
///      releases the hardware key; see biometric_kek_store.dart)
///   2. Encrypted keypair loaded from secure storage
///   3. Continue from step 3 above

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:biometric_storage/biometric_storage.dart';
import 'package:flutter/foundation.dart' show debugPrint;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:sqflite/sqflite.dart';
import 'package:unorm_dart/unorm_dart.dart' as unorm;

import '../models/vault_models.dart';
import 'biometric_kek_store.dart';
import 'crypto_service.dart';
import 'database_service.dart';
import 'key_rotation.dart';
import 'sync_service.dart';
import 'team_log_client.dart';
import 'vault_service.dart';
import 'password_forms.dart';

final _canonicalUserObjectIdPattern = RegExp(
  r'^[01234567][0123456789ABCDEFGHJKMNPQRSTVWXYZ]{25}$',
);

String requireCanonicalUserObjectId(Map<String, dynamic> response) {
  final userObjectId = response['user_id'];
  if (userObjectId is! String ||
      !_canonicalUserObjectIdPattern.hasMatch(userObjectId)) {
    throw const FormatException('Missing or invalid canonical user object ID');
  }
  return userObjectId;
}

/// `/api/auth/recover` failure → what the user can do about it (lockout
/// review #7): a throttled address, a locked name or a server outage is not
/// a wrong password. Only a plain rejection keeps the exact 'Wrong password'.
String recoverFailureMessage(Object error) {
  if (error is SyncException) {
    switch (error.statusCode) {
      case 401:
        return 'Wrong password';
      case 423:
        return 'Wrong password. After many failed attempts the server checks '
            'the next password for this account only in a few minutes (an '
            'admin can lift the lock at once).';
      case 429:
        return 'The server is not checking more passwords for this account '
            'or from this network for now (too many failed attempts). '
            'Try again in a few minutes.';
    }
  }
  return 'Could not reach the server. Try again.';
}

/// Argon2id params of an account as reported by `/api/meta?username=`.
class AccountKdf {
  final int timeCost;
  final int memoryCost;
  final int parallelism;
  const AccountKdf(this.timeCost, this.memoryCost, this.parallelism);
}

/// Account Argon2 memory cap (KiB) shared with the server and every client.
const accountKdfMaxMemoryCost = 262144;

/// Lockout review N3: " alice" is the server account "alice" (the server
/// strips too); an older install may have stored the untrimmed name.
/// Review 688edcb N3: trimmed of the union of what Python, JS and Dart trim
/// (NBSP, BOM, NEL, \x1c-\x1f, zero-width space) and NFC, so one visible name
/// is one account. Must equal server.app.models.schemas.normalize_username.
final _usernameEdge = RegExp(
  r'^[\s\ufeff\u200b\x1c-\x1f\x85]+|[\s\ufeff\u200b\x1c-\x1f\x85]+$',
);

String normalizeUsername(String username) =>
    unorm.nfc(username).replaceAll(_usernameEdge, '');

/// Shortest new master password (the web's NEW_PASSWORD_MIN_LENGTH).
const newPasswordMinLength = 14;
const preAnchorPasswordRefused =
    'This password opened the account before the team anchor was published; a server '
    'could still give a new device the older keys under it. Choose a password never used before.';

/// Per-account params (server >= 1.1) with fallback to the legacy global web
/// defaults. Bounds mirror the server policy so a hostile server cannot make
/// the device derive with absurd costs, and nothing is derived or stored with
/// params the keypair state below would later refuse (lockout review #6).
AccountKdf accountKdfParams(Map<String, dynamic> meta) {
  final raw =
      (meta['argon2_params'] ?? meta['argon2_web_params'])
          as Map<String, dynamic>?;
  // Missing params are refused, never guessed as 128 MiB: that default
  // opens nothing for an account created with other params (review N2).
  final timeCost = raw?['time_cost'];
  final memoryCost = raw?['memory_cost'];
  final parallelism = raw?['parallelism'];
  if (timeCost is! int || memoryCost is! int || parallelism is! int) {
    throw const FormatException('Server did not return the account KDF params');
  }
  if (timeCost < 2 ||
      timeCost > 20 ||
      memoryCost < 65536 ||
      memoryCost > accountKdfMaxMemoryCost ||
      parallelism < 1 ||
      parallelism > 8) {
    throw const FormatException('Server returned unsafe Argon2 parameters');
  }
  return AccountKdf(timeCost, memoryCost, parallelism);
}

final _sezamKeyMagicV2 = Uint8List.fromList(utf8.encode('SEZAMK02'));
const _sezamKeyHeaderLength = 24;
const _keypairWrapKind = 7;

class SezamKeyBackup {
  final Uint8List argon2Salt;
  final int timeCost;
  final int memoryCost;
  final int parallelism;
  final Uint8List signingPublicKey;
  final Uint8List encryptionPublicKey;
  final String kekDekId;
  final String userObjectId;
  final Uint8List encryptedEnvelope;

  const SezamKeyBackup({
    required this.argon2Salt,
    required this.timeCost,
    required this.memoryCost,
    required this.parallelism,
    required this.signingPublicKey,
    required this.encryptionPublicKey,
    required this.kekDekId,
    required this.userObjectId,
    required this.encryptedEnvelope,
  });
}

void _validateSezamKeyMetadata({
  required Uint8List argon2Salt,
  required int timeCost,
  required int memoryCost,
  required int parallelism,
  required String kekDekId,
  required String userObjectId,
  required Uint8List signingPublicKey,
  required Uint8List encryptionPublicKey,
  required Uint8List encryptedEnvelope,
  int maxMemoryCost = accountKdfMaxMemoryCost,
}) {
  if (argon2Salt.length < 16 || argon2Salt.length > 64) {
    throw const FormatException('Invalid .sezam-key Argon2 salt length');
  }
  if (timeCost < 1 || timeCost > 20) {
    throw const FormatException('Invalid .sezam-key Argon2 time cost');
  }
  if (memoryCost < 8192 || memoryCost > maxMemoryCost) {
    throw const FormatException('Invalid .sezam-key Argon2 memory cost');
  }
  if (parallelism < 1 || parallelism > 16) {
    throw const FormatException('Invalid .sezam-key Argon2 parallelism');
  }
  if (!_canonicalUserObjectIdPattern.hasMatch(kekDekId) ||
      !_canonicalUserObjectIdPattern.hasMatch(userObjectId)) {
    throw const FormatException('Invalid .sezam-key object ID');
  }
  if (signingPublicKey.length != 32 || encryptionPublicKey.length != 32) {
    throw const FormatException('Invalid .sezam-key public key length');
  }
  if (encryptedEnvelope.length < 69 ||
      encryptedEnvelope[0] != 1 ||
      encryptedEnvelope[1] != 1 ||
      encryptedEnvelope[2] != _keypairWrapKind) {
    throw const FormatException('Invalid .sezam-key keypair envelope');
  }
  final envelopeKekId = utf8.decode(encryptedEnvelope.sublist(3, 29));
  if (envelopeKekId != kekDekId) {
    throw const FormatException('Mismatched .sezam-key KEK ID');
  }
}

Uint8List encodeSezamKeyBackup(SezamKeyBackup backup) {
  _validateSezamKeyMetadata(
    argon2Salt: backup.argon2Salt,
    timeCost: backup.timeCost,
    memoryCost: backup.memoryCost,
    parallelism: backup.parallelism,
    kekDekId: backup.kekDekId,
    userObjectId: backup.userObjectId,
    signingPublicKey: backup.signingPublicKey,
    encryptionPublicKey: backup.encryptionPublicKey,
    encryptedEnvelope: backup.encryptedEnvelope,
  );

  final bytes = Uint8List(
    _sezamKeyHeaderLength +
        backup.argon2Salt.length +
        116 +
        backup.encryptedEnvelope.length,
  );
  final header = ByteData.view(bytes.buffer);
  bytes.setRange(0, 8, _sezamKeyMagicV2);
  header.setUint16(8, backup.argon2Salt.length, Endian.big);
  header.setUint32(10, backup.timeCost, Endian.big);
  header.setUint32(14, backup.memoryCost, Endian.big);
  header.setUint32(18, backup.parallelism, Endian.big);
  header.setUint16(22, 64, Endian.big);

  var offset = _sezamKeyHeaderLength;
  bytes.setRange(offset, offset + backup.argon2Salt.length, backup.argon2Salt);
  offset += backup.argon2Salt.length;
  bytes.setRange(offset, offset + 32, backup.signingPublicKey);
  offset += 32;
  bytes.setRange(offset, offset + 32, backup.encryptionPublicKey);
  offset += 32;
  bytes.setRange(offset, offset + 26, utf8.encode(backup.kekDekId));
  offset += 26;
  bytes.setRange(offset, offset + 26, utf8.encode(backup.userObjectId));
  offset += 26;
  bytes.setRange(offset, bytes.length, backup.encryptedEnvelope);
  return bytes;
}

SezamKeyBackup decodeSezamKeyBackup(Uint8List bytes) {
  if (bytes.length < _sezamKeyHeaderLength ||
      !_bytesEqual(bytes.sublist(0, 8), _sezamKeyMagicV2)) {
    throw const FormatException('Invalid .sezam-key file');
  }

  final header = ByteData.view(
    bytes.buffer,
    bytes.offsetInBytes,
    bytes.lengthInBytes,
  );
  final saltLength = header.getUint16(8, Endian.big);
  final timeCost = header.getUint32(10, Endian.big);
  final memoryCost = header.getUint32(14, Endian.big);
  final parallelism = header.getUint32(18, Endian.big);
  final hashLength = header.getUint16(22, Endian.big);
  final bodyOffset = _sezamKeyHeaderLength + saltLength;
  if (hashLength != 64 || bytes.length <= bodyOffset + 116) {
    throw const FormatException('Truncated or invalid .sezam-key file');
  }

  final backup = SezamKeyBackup(
    argon2Salt: Uint8List.fromList(
      bytes.sublist(_sezamKeyHeaderLength, bodyOffset),
    ),
    timeCost: timeCost,
    memoryCost: memoryCost,
    parallelism: parallelism,
    signingPublicKey: Uint8List.fromList(
      bytes.sublist(bodyOffset, bodyOffset + 32),
    ),
    encryptionPublicKey: Uint8List.fromList(
      bytes.sublist(bodyOffset + 32, bodyOffset + 64),
    ),
    kekDekId: utf8.decode(bytes.sublist(bodyOffset + 64, bodyOffset + 90)),
    userObjectId: utf8.decode(bytes.sublist(bodyOffset + 90, bodyOffset + 116)),
    encryptedEnvelope: Uint8List.fromList(bytes.sublist(bodyOffset + 116)),
  );
  _validateSezamKeyMetadata(
    argon2Salt: backup.argon2Salt,
    timeCost: backup.timeCost,
    memoryCost: backup.memoryCost,
    parallelism: backup.parallelism,
    kekDekId: backup.kekDekId,
    userObjectId: backup.userObjectId,
    signingPublicKey: backup.signingPublicKey,
    encryptionPublicKey: backup.encryptionPublicKey,
    encryptedEnvelope: backup.encryptedEnvelope,
  );
  return backup;
}

bool _bytesEqual(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  var difference = 0;
  for (var i = 0; i < left.length; i++) {
    difference |= left[i] ^ right[i];
  }
  return difference == 0;
}

Uint8List normalizeSezamKeypair(
  SezamKeyBackup backup,
  Uint8List decrypted, {
  required Uint8List Function(Uint8List) signingPublicKeyFromSeed,
  required Uint8List Function(Uint8List) encryptionPublicKeyFromSecret,
  void Function(Uint8List)? zeroize,
}) {
  final normalized = Uint8List(96);
  if (decrypted.length == 64) {
    normalized
      ..setRange(0, 32, decrypted.sublist(0, 32))
      ..setRange(32, 64, backup.signingPublicKey)
      ..setRange(64, 96, decrypted.sublist(32, 64));
  } else if (decrypted.length == 96) {
    normalized.setAll(0, decrypted);
  } else {
    throw const FormatException('Invalid .sezam-key private key length');
  }

  final derivedSigningPk = signingPublicKeyFromSeed(
    Uint8List.sublistView(normalized, 0, 32),
  );
  final derivedEncryptionPk = encryptionPublicKeyFromSecret(
    Uint8List.sublistView(normalized, 64, 96),
  );
  if (!_bytesEqual(derivedSigningPk, backup.signingPublicKey) ||
      !_bytesEqual(derivedEncryptionPk, backup.encryptionPublicKey) ||
      !_bytesEqual(normalized.sublist(32, 64), backup.signingPublicKey)) {
    zeroize?.call(normalized);
    throw const FormatException('Invalid .sezam-key public keys');
  }
  return normalized;
}

class AuthService {
  static final AuthService _instance = AuthService._();
  factory AuthService() => _instance;
  AuthService._();

  final _crypto = CryptoService();
  final _sync = SyncService();
  final _vault = VaultService();
  final _secureStorage = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(
      accessibility: KeychainAccessibility.first_unlock_this_device,
    ),
  );
  // Storage keys
  static const _legacyKekKey = 'sezam_kek';
  static const _encryptedKeypairKey = 'sezam_encrypted_keypair';
  static const _preAnchorHistoryKey = 'sezam_pre_anchor_history';
  static const _usernameKey = SyncService.usernamePrefKey;
  static const _serverUrlKey = 'sezam_server_url';
  static const _biometricEnabledKey = 'sezam_biometric_enabled';
  static const _argon2SaltKey = 'sezam_argon2_salt';
  static const _argon2TimeCostKey = 'sezam_argon2_time_cost';
  static const _argon2MemoryCostKey = 'sezam_argon2_memory_cost';
  static const _argon2ParallelismKey = 'sezam_argon2_parallelism';
  static const _userObjectIdKey = 'sezam_user_object_id';
  static const _isAdminKey = 'sezam_is_admin';
  static const _pendingKeypairMigrationKey = 'sezam_pending_keypair_migration';
  static const _dbKeypairMigrationSetting = 'pending_keypair_migration';

  /// Check if biometric-bound key storage is available on this device.
  Future<bool> isBiometricAvailable() => canUseBiometricKekStorage();

  /// Check if biometric unlock is enabled (KEK in biometric-bound storage).
  Future<bool> isBiometricEnabled() async {
    final prefs = await SharedPreferences.getInstance();
    // Older builds kept the KEK in plain secure storage behind a UI-only
    // biometric gate. Purge it; the user re-enables biometric unlock, which
    // stores the KEK under a biometric-bound key instead.
    if (await _secureStorage.containsKey(key: _legacyKekKey)) {
      await _secureStorage.delete(key: _legacyKekKey);
      await prefs.setBool(_biometricEnabledKey, false);
    }
    return prefs.getBool(_biometricEnabledKey) ?? false;
  }

  /// Check if there's a stored session (encrypted keypair saved locally).
  Future<bool> hasStoredSession() async {
    final keypair = await _secureStorage.read(key: _encryptedKeypairKey);
    return keypair != null && keypair.isNotEmpty;
  }

  /// Get the stored username.
  Future<String?> getStoredUsername() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_usernameKey);
  }

  /// Get the stored server URL.
  Future<String?> getStoredServerUrl() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_serverUrlKey);
  }

  // ── Password Unlock ──

  /// Unlock with master password.
  ///
  /// 1. Derive KEK + auth_proof via Argon2id
  /// 2. Load encrypted keypair (secure storage or server recovery)
  /// 3. Decrypt keypair with KEK
  /// 4. Authenticate with server (challenge-response)
  /// 5. Unlock vault
  Future<AuthResult> unlockWithPassword({
    required String password,
    required String username,
    required String serverUrl,
    String? previousPassword,
  }) async {
    username = normalizeUsername(username);
    Uint8List? continuityKek;
    try {
      await _crypto.init();
      await _completePendingKeypairMigration();
      final pendingRegistration = await _secureStorage.read(
        key: 'sezam_pending_invitation_registration',
      );
      if (pendingRegistration != null) {
        final context =
            (jsonDecode(pendingRegistration) as Map)['context'] as Map;
        if (context['server'] != serverUrl || context['username'] != username) {
          throw StateError('Finish the pending invitation registration first');
        }
      }
      _sync.configure(serverUrl);

      // 1. Fetch meta (argon2 params + salts)
      final meta = await _sync.fetchMeta(username: username);
      final argon2SaltHex = meta['argon2_salt'] as String?;
      if (argon2SaltHex == null || argon2SaltHex.isEmpty) {
        return AuthResult.failure('User not found or not configured');
      }

      final argon2Salt = hexToBytes(argon2SaltHex);

      // 2. Derive KEK + auth_proof with the ACCOUNT's params
      final kdf = await _accountKdfFor(meta);
      final timeCost = kdf.timeCost;
      final memoryCost = kdf.memoryCost;
      final parallelism = kdf.parallelism;
      // 3. Try local encrypted keypair first, then server recovery. A local
      // copy that the server-derived KEK cannot open is stale (password or
      // KDF changed on another device) → fetch the current one (Path B).
      String? encryptedKeypairHex = await _secureStorage.read(
        key: _encryptedKeypairKey,
      );
      final localObjectId = await _secureStorage.read(key: _userObjectIdKey);
      final localHex = encryptedKeypairHex;
      bool opensLocal(Uint8List d) {
        if (localHex == null || localHex.isEmpty) return false;
        try {
          return _opensKeypair(
            Uint8List.sublistView(d, 0, 32),
            hexToBytes(localHex),
            localObjectId ?? '',
          );
        } catch (_) {
          return false;
        }
      }

      var derived = await _deriveExisting(
        password,
        argon2Salt,
        timeCost: timeCost,
        memoryCost: memoryCost,
        parallelism: parallelism,
        opens: opensLocal,
      );
      String? recoveredUserObjectId;
      if (!opensLocal(derived)) encryptedKeypairHex = null;

      if (encryptedKeypairHex == null || encryptedKeypairHex.isEmpty) {
        // Path B: password-based recovery from server
        try {
          final recovered = await _recoverWithForms(
            username: username,
            password: password,
            salt: argon2Salt,
            timeCost: timeCost,
            memoryCost: memoryCost,
            parallelism: parallelism,
            first: derived,
          );
          derived = recovered.derived;
          final recoverResp = recovered.resp;
          encryptedKeypairHex = recoverResp['encrypted_keypair'] as String?;
          if (encryptedKeypairHex == null || encryptedKeypairHex.isEmpty) {
            _crypto.zeroize(derived);
            return AuthResult.failure(
              'No encrypted keypair. Re-onboard required.',
            );
          }
          recoveredUserObjectId = requireCanonicalUserObjectId(recoverResp);
        } on FormatException {
          _crypto.zeroize(derived);
          return AuthResult.failure('Wrong password');
        } catch (e) {
          _crypto.zeroize(derived);
          return AuthResult.recoverFailure(e);
        }
      }
      derived.fillRange(32, derived.length, 0);
      final kek = Uint8List.sublistView(derived, 0, 32);

      // 4. Decrypt keypair with KEK (AEAD envelope format)
      final encryptedData = hexToBytes(encryptedKeypairHex);
      final userObjectId =
          recoveredUserObjectId ??
          await _secureStorage.read(key: _userObjectIdKey);
      if (userObjectId == null ||
          !_canonicalUserObjectIdPattern.hasMatch(userObjectId)) {
        _crypto.zeroize(derived);
        return AuthResult.failure('Missing or invalid keypair object ID');
      }
      // Keys taken from the server for the account this phone already holds
      // (its object id), not a fresh phone or a pending enrollment (run 416).
      final holdsVault =
          recoveredUserObjectId != null &&
          localObjectId == userObjectId &&
          pendingRegistration == null;
      if (recoveredUserObjectId != null &&
          localObjectId == userObjectId &&
          localHex != null &&
          localHex.isNotEmpty) {
        // Authenticate the old carrier even when there are no local DEKs.
        try {
          final unlockedKek = _vault.currentKek;
          continuityKek = unlockedKek == null
              ? await _deriveLocalKek(
                  previousPassword ?? password,
                  opens: (candidate) => _opensKeypair(
                    candidate,
                    hexToBytes(localHex),
                    userObjectId,
                  ),
                )
              : Uint8List.fromList(unlockedKek);
          if (continuityKek == null ||
              !_opensKeypair(
                continuityKek,
                hexToBytes(localHex),
                userObjectId,
              )) {
            _crypto.zeroize(derived);
            return AuthResult.needsPreviousPassword();
          }
        } catch (_) {
          _crypto.zeroize(derived);
          return AuthResult.needsPreviousPassword();
        }
      }
      Uint8List keypairBytes;
      try {
        if (_crypto.isEncryptedEnvelope(encryptedData)) {
          keypairBytes = await _openAnchoredAccountKeypair(
            encryptedData,
            kek,
            userObjectId,
            previousKek: continuityKek,
            fromServer: recoveredUserObjectId != null,
            heldVault: holdsVault,
          );
        } else {
          // Legacy format: nonce(24) + ciphertext (no AAD)
          throw ArgumentError('Legacy format not supported on mobile');
        }
      } on TeamLogMismatch {
        // A named refusal (run 411), never "Wrong password".
        _crypto.zeroize(derived);
        rethrow;
      } catch (e) {
        _crypto.zeroize(derived);
        return AuthResult.failure('Wrong password or corrupted keypair');
      }

      if (keypairBytes.length != 96) {
        _crypto.zeroize(keypairBytes);
        _crypto.zeroize(derived);
        return AuthResult.failure('Invalid recovered keypair');
      }
      // Password changed on another device: local DEKs are still under the
      // previous KEK. Move them over BEFORE the new salt/keypair replace the
      // local ones, otherwise neither password opens the vault any more.
      if ((await _sync.unreadableOwnDeks(kek, userObjectId)).isNotEmpty) {
        final oldKek = continuityKek != null
            ? Uint8List.fromList(continuityKek)
            : previousPassword == null
            ? null
            : await _deriveLocalKek(
                previousPassword,
                opens: (candidate) => _opensKeypair(
                  candidate,
                  hexToBytes(localHex ?? ''),
                  localObjectId ?? '',
                ),
              );
        if (oldKek == null) {
          _crypto.zeroize(keypairBytes);
          _crypto.zeroize(derived);
          return AuthResult.needsPreviousPassword();
        }
        // Review d615826: the keypair state lands in the DEK-move transaction.
        final migration = recoveredUserObjectId == null
            ? null
            : _keypairMigration(
                userObjectId: recoveredUserObjectId,
                encryptedKeypairHex: encryptedKeypairHex,
                argon2SaltHex: argon2SaltHex,
                timeCost: timeCost,
                memoryCost: memoryCost,
                parallelism: parallelism,
              );
        try {
          await _sync.rekeyLocalVault(
            oldKek: oldKek,
            newKek: kek,
            userId: userObjectId,
            checkpointUserId: userObjectId,
            signingSecretKey: Uint8List.fromList(keypairBytes.sublist(0, 64)),
            settings: {
              if (migration != null)
                _dbKeypairMigrationSetting: jsonEncode(migration),
            },
          );
        } on LocalDekRekeyException {
          _crypto.zeroize(keypairBytes);
          _crypto.zeroize(derived);
          return AuthResult.needsPreviousPassword();
        } finally {
          _crypto.zeroize(oldKek);
        }
        await _refreshBiometricKek(kek);
      }
      if (recoveredUserObjectId != null) {
        await _persistKeypairState(
          userObjectId: recoveredUserObjectId,
          encryptedKeypairHex: encryptedKeypairHex,
          argon2SaltHex: argon2SaltHex,
          timeCost: timeCost,
          memoryCost: memoryCost,
          parallelism: parallelism,
        );
      }

      // Parse keypair: signing_sk (64B) + encryption_sk (32B)
      final signingSecretKey = Uint8List.fromList(keypairBytes.sublist(0, 64));
      final encryptionSecretKey = Uint8List.fromList(
        keypairBytes.sublist(64, 96),
      );
      // Ed25519 pk is last 32B of sk
      final signingPublicKey = Uint8List.fromList(
        signingSecretKey.sublist(32, 64),
      );

      // 5. Authenticate with server
      Map<String, dynamic> authData;
      try {
        authData = await _sync.authenticate(
          username: username,
          signingSecretKey: signingSecretKey,
        );
      } catch (e) {
        // If server auth fails, still allow offline access
        authData = {'user_id': '', 'is_admin': false};
      }

      final serverAuthenticated =
          (authData['user_id'] as String? ?? '').isNotEmpty;
      final prefs = await SharedPreferences.getInstance();
      final userId = serverAuthenticated
          ? authData['user_id'] as String
          : (await _secureStorage.read(key: _userObjectIdKey) ?? '');
      final isAdmin = serverAuthenticated
          ? authData['is_admin'] as bool? ?? false
          : prefs.getBool(_isAdminKey) ?? false;

      if (serverAuthenticated) {
        if (userId != userObjectId)
          throw const FormatException('Authentication identity mismatch');
        try {
          await _sync.prepareInitialTeamLog(userId, kek: kek);
        } catch (_) {
          // INV-7: a log this phone refuses, or cannot fetch (the server
          // down altogether opens offline too), never keeps the vault it
          // already holds locked; the team is refused with a way out. Keys a
          // fresh phone takes from the server, or an enrollment pending, are not that
          // vault: a refused log must not adopt them or finish the enrollment.
          if ((recoveredUserObjectId != null && !holdsVault) ||
              pendingRegistration != null)
            rethrow;
        }
      }
      // 6. Unlock vault
      await _vault.unlock(
        kek: kek,
        signingSecretKey: signingSecretKey,
        signingPublicKey: signingPublicKey,
        encryptionSecretKey: encryptionSecretKey,
        userId: userId,
        isAdmin: isAdmin,
      );
      // The KEK was derived from the server's CURRENT salt/params, so a newer
      // server key_epoch (password changed elsewhere) can be adopted on pull.
      if (serverAuthenticated) _vault.markKekMatchesServer();

      // Save session info
      await prefs.setString(_usernameKey, _sync.accountNameFor(username));
      await prefs.setString(_serverUrlKey, serverUrl);
      if (serverAuthenticated) await prefs.setBool(_isAdminKey, isAdmin);
      if (serverAuthenticated && pendingRegistration != null) {
        await _secureStorage.delete(
          key: 'sezam_pending_invitation_registration',
        );
      }

      // Try to sync (non-blocking)
      _syncInBackground();

      return AuthResult.success(userId: userId);
    } on TeamLogMismatch catch (e) {
      return AuthResult.teamLogRefused(e);
    } catch (e) {
      return AuthResult.failure(e.toString());
    } finally {
      if (continuityKek != null) _crypto.zeroize(continuityKek);
    }
  }

  // ── Offline Unlock ──

  /// Unlock vault offline using only the local encrypted keypair and
  /// Argon2id parameters stored in secure storage.
  ///
  /// No server call is made. The password is used to derive KEK,
  /// which decrypts the keypair. If decryption succeeds, the vault
  /// is unlocked.
  Future<AuthResult> unlockOffline({required String password}) async {
    try {
      await _crypto.init();
      await _completePendingKeypairMigration();

      // 1. Load Argon2id salt and params from secure storage
      final argon2SaltHex = await _secureStorage.read(key: _argon2SaltKey);
      if (argon2SaltHex == null || argon2SaltHex.isEmpty) {
        return AuthResult.failure('No vault found. Create a new vault first.');
      }
      final argon2Salt = hexToBytes(argon2SaltHex);

      final timeCostStr = await _secureStorage.read(key: _argon2TimeCostKey);
      final memoryCostStr = await _secureStorage.read(
        key: _argon2MemoryCostKey,
      );
      final parallelismStr = await _secureStorage.read(
        key: _argon2ParallelismKey,
      );

      final timeCost = int.tryParse(timeCostStr ?? '') ?? 2;
      final memoryCost = int.tryParse(memoryCostStr ?? '') ?? 131072;
      final parallelism = int.tryParse(parallelismStr ?? '') ?? 4;

      // 2. Load encrypted keypair from secure storage
      final encryptedKeypairHex = await _secureStorage.read(
        key: _encryptedKeypairKey,
      );
      if (encryptedKeypairHex == null || encryptedKeypairHex.isEmpty) {
        return AuthResult.failure('No encrypted keypair found.');
      }
      final encryptedData = hexToBytes(encryptedKeypairHex);
      final userObjectId =
          await _secureStorage.read(key: _userObjectIdKey) ?? '';

      // 3. Derive KEK from password
      final derived = await _deriveExisting(
        password,
        argon2Salt,
        timeCost: timeCost,
        memoryCost: memoryCost,
        parallelism: parallelism,
        opens: (d) => _opensKeypair(
          Uint8List.sublistView(d, 0, 32),
          encryptedData,
          userObjectId,
        ),
      );
      final kek = Uint8List.sublistView(derived, 0, 32);
      derived.fillRange(32, derived.length, 0);

      // 4. Decrypt keypair with KEK
      Uint8List keypairBytes;
      try {
        keypairBytes = await _openAnchoredAccountKeypair(
          encryptedData,
          kek,
          userObjectId,
        );
      } on TeamLogMismatch {
        _crypto.zeroize(derived);
        rethrow;
      } catch (e) {
        _crypto.zeroize(derived);
        return AuthResult.failure('Wrong password');
      }

      // Parse keypair: signing_sk (64B) + encryption_sk (32B)
      final signingSecretKey = Uint8List.fromList(keypairBytes.sublist(0, 64));
      final encryptionSecretKey = Uint8List.fromList(
        keypairBytes.sublist(64, 96),
      );
      final signingPublicKey = Uint8List.fromList(
        signingSecretKey.sublist(32, 64),
      );

      // 5. Unlock vault (no server auth needed). Use the canonical account
      // id/role from the last server session so own items stay editable and
      // own-key checks are not bypassed; 'local' only for never-connected vaults.
      final prefs = await SharedPreferences.getInstance();
      final offlineUserId =
          _canonicalUserObjectIdPattern.hasMatch(userObjectId) &&
              ((prefs.getString(_serverUrlKey) ?? '').isNotEmpty ||
                  (await _secureStorage.read(
                            key: 'sezam_pending_invitation_registration',
                          ) !=
                          null &&
                      await readConfirmedTeamGenesis(userObjectId) != null))
          ? userObjectId
          : 'local';
      await _vault.unlock(
        kek: kek,
        signingSecretKey: signingSecretKey,
        signingPublicKey: signingPublicKey,
        encryptionSecretKey: encryptionSecretKey,
        userId: offlineUserId,
        isAdmin:
            offlineUserId != 'local' && (prefs.getBool(_isAdminKey) ?? false),
      );

      // 6. Try to sync in background if server is configured
      final serverUrl = prefs.getString(_serverUrlKey);
      if (serverUrl != null && serverUrl.isNotEmpty) {
        _sync.configure(serverUrl);
        final username = prefs.getString(_usernameKey);
        if (username != null && username.isNotEmpty) {
          // Fire-and-forget: try server auth + sync
          Future.microtask(() async {
            try {
              await _sync.authenticate(
                username: username,
                signingSecretKey: signingSecretKey,
              );
              await _sync.sync(); // push local changes, then pull
            } catch (_) {
              // Offline or auth failed — no problem
            }
          });
        }
      }

      return AuthResult.success(userId: offlineUserId);
    } on TeamLogMismatch catch (e) {
      return AuthResult.teamLogRefused(e);
    } catch (e) {
      return AuthResult.failure(e.toString());
    }
  }

  // ── Biometric Unlock ──

  /// Unlock with biometrics.
  ///
  /// 1. Read the KEK from biometric-bound storage (the OS prompts for
  ///    FaceID/fingerprint and only then releases the key)
  /// 2. Load + decrypt keypair
  /// 3. Challenge-response with server
  /// 4. Unlock vault
  Future<AuthResult> unlockWithBiometrics() async {
    try {
      // 1. Biometric-bound KEK read
      String? kekHex;
      try {
        kekHex = await (await openBiometricKekStorage()).read();
      } on AuthException catch (e) {
        return AuthResult.failure(
          e.code == AuthExceptionCode.userCanceled
              ? 'Biometric authentication cancelled'
              : 'Biometric authentication failed',
        );
      }
      if (kekHex == null || kekHex.isEmpty) {
        // Key was invalidated (e.g. new biometric enrollment) or never set.
        await disableBiometrics();
        return AuthResult.failure(
          'Biometric key not found. Use password to unlock.',
        );
      }
      await _completePendingKeypairMigration();
      final kek = hexToBytes(kekHex);

      // 3. Load encrypted keypair
      final encryptedKeypairHex = await _secureStorage.read(
        key: _encryptedKeypairKey,
      );
      if (encryptedKeypairHex == null || encryptedKeypairHex.isEmpty) {
        return AuthResult.failure('No stored keypair. Use password to unlock.');
      }

      // 4. Decrypt keypair
      final encryptedData = hexToBytes(encryptedKeypairHex);
      final userObjectId =
          await _secureStorage.read(key: _userObjectIdKey) ?? '';
      Uint8List keypairBytes;
      try {
        keypairBytes = await _openAnchoredAccountKeypair(
          encryptedData,
          kek,
          userObjectId,
        );
      } on TeamLogMismatch {
        rethrow;
      } catch (e) {
        return AuthResult.failure(
          'Failed to decrypt keypair. Use password to unlock.',
        );
      }

      final signingSecretKey = Uint8List.fromList(keypairBytes.sublist(0, 64));
      final encryptionSecretKey = Uint8List.fromList(
        keypairBytes.sublist(64, 96),
      );
      final signingPublicKey = Uint8List.fromList(
        signingSecretKey.sublist(32, 64),
      );

      // 5. Restore server config
      final prefs = await SharedPreferences.getInstance();
      final username = prefs.getString(_usernameKey) ?? '';
      final serverUrl = prefs.getString(_serverUrlKey) ?? '';

      if (serverUrl.isNotEmpty) {
        _sync.configure(serverUrl);
      }

      // 6. Authenticate with server (if configured)
      String userId = '';
      bool isAdmin = false;
      if (serverUrl.isNotEmpty && username.isNotEmpty) {
        try {
          final authData = await _sync.authenticate(
            username: username,
            signingSecretKey: signingSecretKey,
          );
          userId = authData['user_id'] as String? ?? '';
          isAdmin = authData['is_admin'] as bool? ?? false;
        } catch (_) {
          // Offline — proceed with local data
        }
        // Review 8595ec1 (R10-F): as the password login, the account the
        // server signed in must be the one these keys belong to.
        if (userId.isNotEmpty && userId != userObjectId) {
          return AuthResult.failure('Authentication identity mismatch');
        }
        if (userId.isNotEmpty) await prefs.setBool(_isAdminKey, isAdmin);
      }
      if (userId.isEmpty &&
          _canonicalUserObjectIdPattern.hasMatch(userObjectId)) {
        userId = userObjectId;
        isAdmin = prefs.getBool(_isAdminKey) ?? false;
      }

      // 7. Unlock vault
      await _vault.unlock(
        kek: kek,
        signingSecretKey: signingSecretKey,
        signingPublicKey: signingPublicKey,
        encryptionSecretKey: encryptionSecretKey,
        userId: userId,
        isAdmin: isAdmin,
      );

      _syncInBackground();

      return AuthResult.success(userId: userId);
    } on TeamLogMismatch catch (e) {
      return AuthResult.teamLogRefused(e);
    } catch (e) {
      return AuthResult.failure(e.toString());
    }
  }

  // ── Biometric Key Management ──

  /// Store the KEK under a biometric-bound key for biometric unlock.
  Future<void> enableBiometrics(Uint8List kek) async {
    if (!await canUseBiometricKekStorage()) {
      throw StateError('Biometric key storage is not available');
    }
    await (await openBiometricKekStorage()).write(bytesToHex(kek));
    await _secureStorage.delete(key: _legacyKekKey);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_biometricEnabledKey, true);
  }

  /// Remove the biometric-bound KEK (disable biometric unlock).
  Future<void> disableBiometrics() async {
    try {
      await (await openBiometricKekStorage()).delete();
    } catch (_) {
      // Key already invalidated by the OS or storage unavailable.
    }
    await _secureStorage.delete(key: _legacyKekKey);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_biometricEnabledKey, false);
  }

  // ── Device Provisioning (QR) ──

  /// Provision this device from a QR code token.
  ///
  /// 1. Scan QR -> provisioning token
  /// 2. POST /api/auth/provision -> encrypted_keypair + argon2_salt
  /// 3. User enters password -> derive KEK -> decrypt keypair
  /// 4. Challenge-response -> JWT
  Future<AuthResult> provisionFromQR({
    required String provisionToken,
    String genesisFragment = '',
    required String username,
    required String password,
    required String serverUrl,
  }) async {
    username = normalizeUsername(username);
    // Review a159e97: a refusal after the sign-in (identity mismatch, locked
    // or foreign local vault, failed re-key or join) left this phone signed
    // in to the scanned account. Until the device is committed to it, the
    // previous server and session come back.
    final previousUrl = _sync.serverUrl;
    final previousToken = _sync.token;
    var signedIn = false;
    var committed = false;
    final lockGeneration = _vault.isUnlocked ? _vault.lockGeneration : null;
    var previousKek = _vault.currentKek == null
        ? null
        : Uint8List.fromList(_vault.currentKek!);
    try {
      final genesis = provisioningGenesis(genesisFragment);
      await _crypto.init();
      await _completePendingKeypairMigration();
      // Review 1141a20 (R9-G): the session of the previous server never goes
      // to the scanned one; it comes back below unless the device commits.
      _sync.configure(serverUrl);
      _sync.clearToken();

      // 1. Exchange provisioning token for encrypted keypair
      final provResp = await _sync.provision(
        token: provisionToken,
        username: username,
      );

      final encryptedKeypairHex = provResp['encrypted_keypair'] as String?;
      final argon2SaltHex = provResp['argon2_salt'] as String?;
      final userObjectId = requireCanonicalUserObjectId(provResp);

      if (encryptedKeypairHex == null || argon2SaltHex == null) {
        return AuthResult.failure('Invalid provisioning response');
      }

      final sameAccount =
          await _secureStorage.read(key: _userObjectIdKey) == userObjectId &&
          await _secureStorage.read(key: _encryptedKeypairKey) != null;
      if (sameAccount && previousKek == null) {
        final localEnvelope = hexToBytes(
          (await _secureStorage.read(key: _encryptedKeypairKey))!,
        );
        try {
          previousKek = await _deriveLocalKek(
            password,
            opens: (candidate) =>
                _opensKeypair(candidate, localEnvelope, userObjectId),
          );
          if (previousKek == null ||
              !_opensKeypair(previousKek, localEnvelope, userObjectId)) {
            return AuthResult.failure(
              'Unlock the local vault before provisioning this device',
            );
          }
        } catch (_) {
          return AuthResult.failure(
            'Unlock the local vault before provisioning this device',
          );
        }
      }
      // 2. Derive KEK from password with the account's KDF params
      final argon2Salt = hexToBytes(argon2SaltHex);
      final kdf = accountKdfParams(provResp);
      final encryptedData = hexToBytes(encryptedKeypairHex);
      final derived = await _deriveExisting(
        password,
        argon2Salt,
        timeCost: kdf.timeCost,
        memoryCost: kdf.memoryCost,
        parallelism: kdf.parallelism,
        opens: (d) => _opensKeypair(
          Uint8List.sublistView(d, 0, 32),
          encryptedData,
          userObjectId,
        ),
      );
      final kek = Uint8List.sublistView(derived, 0, 32);
      derived.fillRange(32, derived.length, 0);

      // 3. Decrypt keypair
      Uint8List keypairBytes;
      try {
        keypairBytes = await _openAnchoredAccountKeypair(
          encryptedData,
          kek,
          userObjectId,
          expectedGenesis: genesis,
          previousKek: previousKek,
          fromServer: true,
        );
      } on TeamLogMismatch {
        _crypto.zeroize(derived);
        rethrow;
      } catch (e) {
        _crypto.zeroize(derived);
        return AuthResult.failure('Wrong password');
      }

      final signingSecretKey = Uint8List.fromList(keypairBytes.sublist(0, 64));
      final encryptionSecretKey = Uint8List.fromList(
        keypairBytes.sublist(64, 96),
      );
      final signingPublicKey = Uint8List.fromList(
        signingSecretKey.sublist(32, 64),
      );

      // 4. Authenticate with server before committing recovered key material
      final authData = await _sync.authenticate(
        username: username,
        signingSecretKey: signingSecretKey,
      );
      signedIn = true;
      final authenticatedUserId = requireCanonicalUserObjectId(authData);
      if (authenticatedUserId != userObjectId) {
        throw const FormatException('Provisioning identity mismatch');
      }
      if (genesis != null) {
        if (_vault.userId == userObjectId && _vault.teamLog != null) {
          requireConfirmedGenesis(genesis, _vault.teamLog!.team.genesisHash);
        }
        // Retain an explicit trust decision even if the join is rolled back.
        // It belongs to this account, not to the replaceable local vault DB.
        await confirmTeamGenesis(userObjectId, genesis);
      }
      final isAdmin = authData['is_admin'] as bool? ?? false;
      final unreadable = (await _sync.unreadableOwnDeks(
        kek,
        userObjectId,
      )).isNotEmpty;
      final localSigningPk = _vault.signingPublicKey;
      // Review 7c10379: a vault of this phone's own (not the account's
      // keypair) joins the account like a password connect. Re-wrapping it
      // in place kept its own root, and its push gave the account a second.
      if (unreadable &&
          !sameAccount &&
          !(_vault.isUnlocked &&
              localSigningPk != null &&
              _bytesEqual(localSigningPk, signingPublicKey))) {
        final joined = await _moveDeviceToAccount(
          serverUrl: serverUrl,
          username: username,
          kek: kek,
          keypairBytes: keypairBytes,
          userObjectId: userObjectId,
          encryptedKeypairHex: encryptedKeypairHex,
          argon2SaltHex: argon2SaltHex,
          kdf: kdf,
        );
        _crypto.zeroize(keypairBytes);
        committed = joined.outcome == ConnectOutcome.connected;
        return committed
            ? AuthResult.success(userId: userObjectId)
            : AuthResult.failure(joined.message);
      }
      // Re-provisioning must not lock the local vault: move local DEK wraps
      // to the account KEK before the account salt/keypair replace the local
      // ones (they used to be replaced first, leaving the DEKs under a KEK
      // neither password derives any more).
      if (unreadable || sameAccount) {
        final localKek = previousKek;
        final localUserId = sameAccount ? userObjectId : _vault.userId;
        if (localKek == null) {
          return AuthResult.failure(
            'Unlock the local vault before provisioning this device',
          );
        }
        if (localUserId != null &&
            _canonicalUserObjectIdPattern.hasMatch(localUserId) &&
            localUserId != userObjectId) {
          return AuthResult.failure(
            'This device holds the vault of another account',
          );
        }
        await _sync.prepareInitialTeamLog(authenticatedUserId);
        final oldKek = Uint8List.fromList(localKek);
        // Review d615826: the keypair state lands in the DEK-move transaction.
        final migration = _keypairMigration(
          userObjectId: userObjectId,
          encryptedKeypairHex: encryptedKeypairHex,
          argon2SaltHex: argon2SaltHex,
          timeCost: kdf.timeCost,
          memoryCost: kdf.memoryCost,
          parallelism: kdf.parallelism,
        );
        try {
          await _sync.rekeyLocalVault(
            oldKek: oldKek,
            newKek: kek,
            userId: userObjectId,
            checkpointUserId: localUserId,
            signingSecretKey: signingSecretKey,
            settings: {_dbKeypairMigrationSetting: jsonEncode(migration)},
          );
        } on LocalDekRekeyException catch (e) {
          return AuthResult.failure(e.toString());
        } finally {
          _crypto.zeroize(oldKek);
        }
      }
      // From here the device belongs to the scanned account.
      committed = true;
      await _persistKeypairState(
        userObjectId: userObjectId,
        encryptedKeypairHex: encryptedKeypairHex,
        argon2SaltHex: argon2SaltHex,
        timeCost: kdf.timeCost,
        memoryCost: kdf.memoryCost,
        parallelism: kdf.parallelism,
      );
      await _refreshBiometricKek(kek);

      await _sync.prepareInitialTeamLog(authenticatedUserId, kek: kek);
      // 5. Unlock vault
      await _vault.unlock(
        kek: kek,
        signingSecretKey: signingSecretKey,
        signingPublicKey: signingPublicKey,
        encryptionSecretKey: encryptionSecretKey,
        userId: authenticatedUserId,
        isAdmin: isAdmin,
        unlessLockedSince: lockGeneration,
      );
      _vault.markKekMatchesServer();

      // 7. Save session
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(_usernameKey, _sync.accountNameFor(username));
      await prefs.setString(_serverUrlKey, serverUrl);
      await prefs.setBool(_isAdminKey, isAdmin);

      // 8. Full pull to populate local DB
      await _sync.pull();

      return AuthResult.success(userId: authenticatedUserId);
    } catch (e) {
      if (committed) _vault.lock();
      return AuthResult.failure(e.toString());
    } finally {
      if (previousKek != null) _crypto.zeroize(previousKek);
      // A failure before the sign-in too: the scanned server stays configured
      // otherwise, and the next sync sends it the previous session.
      if (!committed) {
        if (signedIn) await _sync.logout();
        if (previousUrl != null) _sync.configure(previousUrl);
        if (previousToken != null) _sync.setToken(previousToken);
      }
    }
  }

  // ── Password Recovery (Path B) ──

  /// Recover access using password only (no local keypair needed).
  /// Used when secure storage is wiped (iOS reinstall, etc.).
  Future<AuthResult> recoverFromServer({
    required String username,
    required String password,
    required String serverUrl,
  }) async {
    username = normalizeUsername(username);
    // Missing or stale keypairs already fall through to server recovery.
    // Keep an existing carrier so failure cannot erase its anchor or prevent
    // offline unlock and continuity verification with the previous password.
    return unlockWithPassword(
      password: password,
      username: username,
      serverUrl: serverUrl,
    );
  }

  // ── .sezam-key Export / Import ──

  /// Export the current keypair using the desktop-compatible SEZAMK02 format.
  Future<String> exportSezamKey({
    required Uint8List signingPublicKey,
    required Uint8List encryptionPublicKey,
  }) async {
    final values = await Future.wait([
      _secureStorage.read(key: _encryptedKeypairKey),
      _secureStorage.read(key: _argon2SaltKey),
      _secureStorage.read(key: _argon2TimeCostKey),
      _secureStorage.read(key: _argon2MemoryCostKey),
      _secureStorage.read(key: _argon2ParallelismKey),
      _secureStorage.read(key: _userObjectIdKey),
    ]);
    if (values.any((value) => value == null || value.isEmpty)) {
      throw StateError('Local keypair backup metadata is incomplete');
    }

    final encryptedEnvelope = hexToBytes(values[0]!);
    if (!_crypto.isEncryptedEnvelope(encryptedEnvelope)) {
      throw const FormatException('Invalid stored keypair envelope');
    }
    final kekDekId = utf8.decode(encryptedEnvelope.sublist(3, 29));
    final backup = SezamKeyBackup(
      argon2Salt: hexToBytes(values[1]!),
      timeCost: int.tryParse(values[2]!) ?? -1,
      memoryCost: int.tryParse(values[3]!) ?? -1,
      parallelism: int.tryParse(values[4]!) ?? -1,
      signingPublicKey: signingPublicKey,
      encryptionPublicKey: encryptionPublicKey,
      kekDekId: kekDekId,
      userObjectId: values[5]!,
      encryptedEnvelope: encryptedEnvelope,
    );

    final dir = await DatabaseService.exportDirectory();
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    final filePath = '${dir.path}/sezam-$timestamp.sezam-key';
    await File(
      filePath,
    ).writeAsBytes(encodeSezamKeyBackup(backup), flush: true);
    return filePath;
  }

  /// Import and verify a self-contained backup without contacting the server.
  Future<
    ({
      Uint8List signingPk,
      Uint8List encryptionPk,
      Uint8List kek,
      Uint8List keypairBytes,
    })
  >
  importSezamKey({required String filePath, required String password}) async {
    await _crypto.init();

    final file = File(filePath);
    if (!await file.exists()) {
      throw StateError('File not found: $filePath');
    }
    final backup = decodeSezamKeyBackup(await file.readAsBytes());
    final derived = await _deriveExisting(
      password,
      backup.argon2Salt,
      timeCost: backup.timeCost,
      memoryCost: backup.memoryCost,
      parallelism: backup.parallelism,
      backup: true,
      opens: (d) => _opensKeypair(
        Uint8List.sublistView(d, 0, 32),
        backup.encryptedEnvelope,
        backup.userObjectId,
      ),
    );
    final kek = Uint8List.sublistView(derived, 0, 32);
    derived.fillRange(32, derived.length, 0);

    ({Uint8List keypairData, String? confirmedGenesis, Uint8List? preAnchor})
    account;
    try {
      account = _crypto.openAccountKeypair(
        backup.encryptedEnvelope,
        kek,
        backup.userObjectId,
      );
    } catch (_) {
      _crypto.zeroize(derived);
      throw ArgumentError('Wrong password or corrupted .sezam-key file');
    }

    Uint8List? normalized;
    try {
      normalized = normalizeSezamKeypair(
        backup,
        account.keypairData,
        signingPublicKeyFromSeed: _crypto.signingPublicKeyFromSeed,
        encryptionPublicKeyFromSecret: _crypto.scalarmultBase,
        zeroize: _crypto.zeroize,
      );

      // Desktop backup IDs are random AAD contexts, not server account IDs.
      final localUserId = _vault.userId;
      final userObjectId =
          localUserId != null &&
              _canonicalUserObjectIdPattern.hasMatch(localUserId)
          ? localUserId
          : await _secureStorage.read(key: _userObjectIdKey) ??
                backup.userObjectId;
      final cachedEnvelope = userObjectId == backup.userObjectId
          ? backup.encryptedEnvelope
          : account.confirmedGenesis != null
          ? _crypto.wrapAccountKeypair(
              account.keypairData,
              account.confirmedGenesis!,
              kek,
              backup.kekDekId,
              userObjectId,
              account.preAnchor,
            )
          : _crypto.wrapKeypair(normalized, kek, backup.kekDekId, userObjectId);
      // The backup's salt replaces the one the local DEKs are wrapped under
      // (lockout review #5): first prove it is this vault's keypair and move
      // the DEKs to the backup's KEK, else nothing may change.
      // The keypair state lands in the same transaction as the DEK move, so
      // a kill before the Keychain write is finished by the next unlock.
      final migration = _keypairMigration(
        userObjectId: userObjectId,
        encryptedKeypairHex: bytesToHex(cachedEnvelope),
        argon2SaltHex: bytesToHex(backup.argon2Salt),
        timeCost: backup.timeCost,
        memoryCost: backup.memoryCost,
        parallelism: backup.parallelism,
      );
      final kekStillMatchesServer = await _moveVaultToBackupKek(
        backup,
        kek,
        normalized,
        confirmedGenesis: account.confirmedGenesis,
        userObjectId: userObjectId,
        settings: {_dbKeypairMigrationSetting: jsonEncode(migration)},
      );
      await _persistKeypairState(
        userObjectId: userObjectId,
        encryptedKeypairHex: bytesToHex(cachedEnvelope),
        argon2SaltHex: bytesToHex(backup.argon2Salt),
        timeCost: backup.timeCost,
        memoryCost: backup.memoryCost,
        parallelism: backup.parallelism,
      );
      await _refreshBiometricKek(kek);
      // New items must be wrapped under the KEK the stored salt derives.
      final userId = _vault.userId!;
      final isAdmin = _vault.serverSaysAdmin;
      await _vault.unlock(
        kek: Uint8List.fromList(kek),
        signingSecretKey: Uint8List.fromList(normalized.sublist(0, 64)),
        signingPublicKey: backup.signingPublicKey,
        encryptionSecretKey: Uint8List.fromList(normalized.sublist(64, 96)),
        encryptionPublicKey: backup.encryptionPublicKey,
        userId: userId,
        isAdmin: isAdmin,
      );
      if (kekStillMatchesServer) _vault.markKekMatchesServer();
    } catch (_) {
      _crypto.zeroize(derived);
      if (normalized != null) _crypto.zeroize(normalized);
      rethrow;
    } finally {
      _crypto.zeroize(account.keypairData);
    }

    return (
      signingPk: backup.signingPublicKey,
      encryptionPk: backup.encryptionPublicKey,
      kek: kek,
      keypairBytes: normalized,
    );
  }

  // ── Create Local Vault ──

  /// Create a brand-new offline vault.
  /// Delegates to VaultService.createVault which generates keypairs,
  /// derives KEK, creates the database, root DEK, and root node.
  Future<AuthResult> createNewVault({required String password}) async {
    try {
      await _vault.createVault(password);
      return AuthResult.success(userId: 'local');
    } catch (e) {
      return AuthResult.failure(e.toString());
    }
  }

  /// Check if this device has a vault of its own: its keypair is stored.
  /// The database file alone is not one (the app creates it empty on start).
  Future<bool> hasLocalVault() => hasStoredSession();

  // ── Lock ──

  /// Lock the vault and clear sensitive data.
  Future<void> lock() async {
    _vault.lock();
    await _sync.logout();
  }

  // ── Background sync ──

  void _syncInBackground() {
    // Fire-and-forget sync (don't block UI)
    Future.microtask(() async {
      try {
        if (_sync.isAuthenticated) {
          await _sync.sync(); // push local changes, then pull
        }
      } catch (_) {
        // Sync errors are non-fatal
      }
    });
  }

  // ── Server Connect Flow ──

  /// Orchestrates the full "Connect to Server" flow.
  ///
  /// Steps:
  ///  1. Check bootstrap-status
  ///  2. Route based on needs_setup
  ///  3. Handle bootstrap, recovery, or registration
  ///
  /// Returns a [ConnectResult] with the outcome and any message.
  Future<ConnectResult> connectToServer({
    required String serverUrl,
    required String password,
    required String username,
    ConnectProgressCallback? onProgress,
  }) async {
    username = normalizeUsername(username);
    try {
      await _crypto.init();
      await _completePendingKeypairMigration();
      _sync.configure(serverUrl);

      final pendingRegistration = await _secureStorage.read(
        key: 'sezam_pending_invitation_registration',
      );
      if (pendingRegistration != null) {
        final context =
            (jsonDecode(pendingRegistration) as Map)['context'] as Map;
        if (context['server'] != serverUrl || context['username'] != username) {
          throw StateError('Finish the pending invitation registration first');
        }
        final genesis = context['genesis'] as String?;
        return await registerWithInvitation(
          serverUrl: serverUrl,
          username: username,
          password: password,
          invitationToken:
              '${context['invitation']}${genesis == null ? '' : '#g=$genesis'}',
          onProgress: onProgress,
        );
      }

      // Step 1: Check server status
      onProgress?.call('Kontrolujem server...');
      Map<String, dynamic> status;
      try {
        status = await _sync.bootstrapStatus();
      } on SyncException {
        return ConnectResult(
          outcome: ConnectOutcome.unreachable,
          message:
              'Server nie je dostupny. Skontroluj URL a internetove pripojenie.',
        );
      } catch (e) {
        if (e.toString().contains('SocketException') ||
            e.toString().contains('HandshakeException') ||
            e.toString().contains('Connection refused') ||
            e.toString().contains('No route to host') ||
            e.toString().contains('Connection timed out') ||
            e.toString().contains('Failed host lookup')) {
          return ConnectResult(
            outcome: ConnectOutcome.unreachable,
            message:
                'Server nie je dostupny. Skontroluj URL a internetove pripojenie.',
          );
        }
        return ConnectResult(
          outcome: ConnectOutcome.unreachable,
          message: 'Chyba pripojenia: ${e.toString().split(':').last.trim()}',
        );
      }

      final needsSetup = status['needs_setup'] as bool? ?? false;

      final hasVault = await hasLocalVault();
      if (!needsSetup) {
        // An existing account opens with its own password (the server
        // proves it). A local vault only has to be open so its items can
        // move into the account; a new phone may have none at all.
        if (hasVault && !_vault.isUnlocked) {
          final unlockResult = await unlockOffline(password: password);
          if (!unlockResult.success) {
            return ConnectResult(
              outcome: ConnectOutcome.wrongPassword,
              message: 'Nespravne heslo.',
            );
          }
        }
        return await _handleExistingServer(
          serverUrl: serverUrl,
          username: username,
          password: password,
          onProgress: onProgress,
        );
      }

      // Load local vault keys
      if (!hasVault) {
        return ConnectResult(
          outcome: ConnectOutcome.error,
          message: 'Najprv vytvor lokalny vault.',
        );
      }

      // We need the vault to be unlocked to get keys. An already unlocked
      // vault still has to prove the typed password: it becomes the account
      // password (auth_proof) on the server, so a typo would break recovery.
      if (!_vault.isUnlocked) {
        final unlockResult = await unlockOffline(password: password);
        if (!unlockResult.success) {
          return ConnectResult(
            outcome: ConnectOutcome.wrongPassword,
            message: 'Nespravne heslo.',
          );
        }
      } else if (!await _passwordOpensUnlockedVault(password)) {
        return ConnectResult(
          outcome: ConnectOutcome.wrongPassword,
          message: 'Nespravne heslo.',
        );
      }

      final signingPk = _vault.signingPublicKey!;
      final signingPkHex = bytesToHex(signingPk);
      final encryptionPk = _vault.encryptionPublicKey ?? signingPk;
      final encryptionPkHex = bytesToHex(encryptionPk);
      final signingSecretKey = _vault.signingSecretKey!;

      // ── Empty server → become admin ──
      return await _handleBootstrap(
        serverUrl: serverUrl,
        username: username,
        password: password,
        signingPkHex: signingPkHex,
        encryptionPkHex: encryptionPkHex,
        signingSecretKey: signingSecretKey,
        onProgress: onProgress,
      );
    } catch (e) {
      return ConnectResult(
        outcome: ConnectOutcome.error,
        message: 'Neocakavana chyba: ${e.toString().split(':').last.trim()}',
      );
    }
  }

  /// Handle bootstrap flow (empty server → become admin).
  Future<ConnectResult> _handleBootstrap({
    required String serverUrl,
    required String username,
    required String password,
    required String signingPkHex,
    required String encryptionPkHex,
    required Uint8List signingSecretKey,
    ConnectProgressCallback? onProgress,
  }) async {
    onProgress?.call('Vytvarim administratorsky ucet...');

    try {
      // POST /api/bootstrap
      final bootstrapResp = await _sync.bootstrap(
        username: username,
        signingPkHex: signingPkHex,
        encryptionPkHex: encryptionPkHex,
      );
      final canonicalUserObjectId = requireCanonicalUserObjectId(bootstrapResp);
      final canonicalEncryptedKeypair = await _rewrapStoredKeypairForUser(
        canonicalUserObjectId,
      );

      // Upload encrypted keypair before changing the valid local AAD pair.
      onProgress?.call('Nahratavam sifrovany keypair...');
      await _uploadKeypairToServer(
        password,
        encryptedKeypairHex: canonicalEncryptedKeypair,
      );
      await _persistKeypairState(
        userObjectId: canonicalUserObjectId,
        encryptedKeypairHex: canonicalEncryptedKeypair,
      );

      // Authenticate via challenge-response
      onProgress?.call('Overujem identitu...');
      try {
        await _sync.authenticate(
          username: username,
          signingSecretKey: signingSecretKey,
        );
      } catch (_) {
        // Bootstrap token may still be valid, continue
      }

      // Push local vault data to server
      onProgress?.call('Synchronizujem data...');
      try {
        await _sync.push();
      } catch (_) {
        // Non-fatal
      }

      // Save session. The bootstrap account is the server admin; offline
      // unlock reads the role from here, so it must not fall back to user.
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(_usernameKey, _sync.accountNameFor(username));
      await prefs.setString(_serverUrlKey, serverUrl);
      await prefs.setBool(_isAdminKey, true);

      return ConnectResult(
        outcome: ConnectOutcome.connected,
        message:
            'Hotovo! Si administrator servera. Tvoje data boli synchronizovane.',
      );
    } on SyncException catch (e) {
      return ConnectResult(
        outcome: ConnectOutcome.error,
        message: 'Chyba bootstrapu: ${e.message}',
      );
    }
  }

  static const _noAccountMessage =
      'Na tomto serveri nemas ucet. Potrebujes pozvanku od administratora.';

  /// Existing server: open the account by its password (Path B), else ask
  /// for an invitation. A device that does not hold the account keypair yet
  /// (a new phone) takes it over; see [_moveDeviceToAccount].
  Future<ConnectResult> _handleExistingServer({
    required String serverUrl,
    required String username,
    required String password,
    ConnectProgressCallback? onProgress,
  }) async {
    onProgress?.call('Skusam obnovit pristup...');

    Map<String, dynamic> meta;
    try {
      meta = await _sync.fetchMeta(username: username);
    } on SyncException {
      return ConnectResult(
        outcome: ConnectOutcome.needsInvitation,
        message: _noAccountMessage,
      );
    }
    final argon2SaltHex = meta['argon2_salt'] as String?;
    if (argon2SaltHex == null || argon2SaltHex.isEmpty) {
      return ConnectResult(
        outcome: ConnectOutcome.needsInvitation,
        message: _noAccountMessage,
      );
    }
    final kdf = await _accountKdfFor(meta);
    ({Uint8List derived, Map<String, dynamic> resp}) recovered;
    try {
      recovered = await _recoverWithForms(
        username: username,
        password: password,
        salt: hexToBytes(argon2SaltHex),
        timeCost: kdf.timeCost,
        memoryCost: kdf.memoryCost,
        parallelism: kdf.parallelism,
      );
    } on SyncException catch (e) {
      if (e.statusCode == 401) {
        // No such account, or a wrong password.
        return ConnectResult(
          outcome: ConnectOutcome.needsInvitation,
          message: _noAccountMessage,
        );
      }
      return ConnectResult(
        outcome: ConnectOutcome.error,
        message: 'Obnova pristupu zlyhala: ${e.message}',
      );
    }

    onProgress?.call('Ucet najdeny, overujem...');
    final derived = recovered.derived;
    derived.fillRange(32, derived.length, 0);
    final kek = Uint8List.sublistView(derived, 0, 32);
    final encryptedKeypairHex = recovered.resp['encrypted_keypair'] as String?;
    Uint8List? keypairBytes;
    try {
      if (encryptedKeypairHex == null || encryptedKeypairHex.isEmpty) {
        return ConnectResult(
          outcome: ConnectOutcome.error,
          message: 'Ucet na serveri nema ulozene kluce.',
        );
      }
      final userObjectId = requireCanonicalUserObjectId(recovered.resp);
      try {
        keypairBytes = await _openAnchoredAccountKeypair(
          hexToBytes(encryptedKeypairHex),
          kek,
          userObjectId,
          fromServer: true,
        );
      } catch (_) {
        return ConnectResult(
          outcome: ConnectOutcome.wrongPassword,
          message: 'Nespravne heslo.',
        );
      }
      if (keypairBytes.length != 96) {
        return ConnectResult(
          outcome: ConnectOutcome.error,
          message: 'Kluce uctu na serveri su poskodene.',
        );
      }
      final signingSecretKey = Uint8List.fromList(keypairBytes.sublist(0, 64));
      final local = _vault.signingPublicKey;
      if (_vault.isUnlocked &&
          local != null &&
          _bytesEqual(local, signingSecretKey.sublist(32, 64))) {
        // Same identity does not imply the same KEK or account bundle.
        final oldKek = Uint8List.fromList(_vault.currentKek!);
        final previousUserId = _vault.userId;
        final lockGeneration = _vault.lockGeneration;
        late final Map<String, dynamic> authData;
        try {
          authData = await _sync.authenticate(
            username: username,
            signingSecretKey: signingSecretKey,
          );
          if (requireCanonicalUserObjectId(authData) != userObjectId) {
            throw const FormatException('Account identity mismatch');
          }
          await _sync.prepareInitialTeamLog(userObjectId);
          final migration = _keypairMigration(
            userObjectId: userObjectId,
            encryptedKeypairHex: encryptedKeypairHex,
            argon2SaltHex: argon2SaltHex,
            timeCost: kdf.timeCost,
            memoryCost: kdf.memoryCost,
            parallelism: kdf.parallelism,
          );
          await _sync.rekeyLocalVault(
            oldKek: oldKek,
            newKek: kek,
            userId: previousUserId,
            checkpointUserId: previousUserId,
            signingSecretKey: signingSecretKey,
            settings: {_dbKeypairMigrationSetting: jsonEncode(migration)},
          );
          var lockedMeanwhile = false;
          try {
            await _vault.unlock(
              kek: Uint8List.fromList(kek),
              signingSecretKey: signingSecretKey,
              signingPublicKey: Uint8List.fromList(
                keypairBytes.sublist(32, 64),
              ),
              encryptionSecretKey: Uint8List.fromList(
                keypairBytes.sublist(64, 96),
              ),
              userId: userObjectId,
              isAdmin: authData['is_admin'] as bool? ?? false,
              unlessLockedSince: lockGeneration,
            );
            _vault.markKekMatchesServer();
          } on VaultLockedMeanwhile {
            lockedMeanwhile = true;
          }
          await _persistKeypairState(
            userObjectId: userObjectId,
            encryptedKeypairHex: encryptedKeypairHex,
            argon2SaltHex: argon2SaltHex,
            timeCost: kdf.timeCost,
            memoryCost: kdf.memoryCost,
            parallelism: kdf.parallelism,
          );
          await _refreshBiometricKek(kek);
          if (lockedMeanwhile) throw const VaultLockedMeanwhile();
        } finally {
          _crypto.zeroize(oldKek);
        }
        final prefs = await SharedPreferences.getInstance();
        await prefs.setBool(
          _isAdminKey,
          authData['is_admin'] as bool? ?? false,
        );
        onProgress?.call('Synchronizujem...');
        try {
          await _sync.pull();
          await _vault.reloadData();
        } catch (e) {
          return ConnectResult(
            outcome: ConnectOutcome.error,
            message: 'Synchronizacia zlyhala: $e',
          );
        }
        await prefs.setString(_usernameKey, _sync.accountNameFor(username));
        await prefs.setString(_serverUrlKey, serverUrl);
        return ConnectResult(
          outcome: ConnectOutcome.connected,
          message: 'Pripojeny k serveru.',
        );
      }
      return await _moveDeviceToAccount(
        serverUrl: serverUrl,
        username: username,
        kek: kek,
        keypairBytes: keypairBytes,
        userObjectId: userObjectId,
        encryptedKeypairHex: encryptedKeypairHex,
        argon2SaltHex: argon2SaltHex,
        kdf: kdf,
        onProgress: onProgress,
      );
    } on SyncException catch (e) {
      return ConnectResult(
        outcome: ConnectOutcome.error,
        message: 'Prihlasenie k uctu zlyhalo: ${e.message}',
      );
    } finally {
      if (keypairBytes != null) _crypto.zeroize(keypairBytes);
      _crypto.zeroize(derived);
    }
  }

  static const _accountKeypairKeys = [
    _encryptedKeypairKey,
    _argon2SaltKey,
    _argon2TimeCostKey,
    _argon2MemoryCostKey,
    _argon2ParallelismKey,
    _userObjectIdKey,
    _pendingKeypairMigrationKey,
    _preAnchorHistoryKey,
  ];

  static const _joinRestoreKey = 'sezam_join_restore';
  static const _joinAsideSuffix = '.before-join';
  static const _joinKeptSuffix = '.kept';
  static const _joinCommitted = 'committed';
  static const _dbSideFiles = ['', '-journal', '-wal', '-shm'];

  Future<bool> _joinInterrupted() async {
    final journal = await _secureStorage.read(key: _joinRestoreKey);
    if (journal != null && journal.isNotEmpty) return true;
    final dbPath = await DatabaseService.vaultDbPath();
    return _dbSideFiles.any(
      (s) => File('$dbPath$s$_joinAsideSuffix').existsSync(),
    );
  }

  /// Review 688edcb: an account join killed after it set this device's vault
  /// aside puts the device back as it was (vault file and the Keychain values
  /// the journal kept) — run at start, before the database opens. A join past
  /// its commit point (journal [_joinCommitted]) only leaves set-aside files
  /// to delete.
  ///
  /// Review e4cd15a S4: set-aside files WITHOUT a journal were deleted too,
  /// but that is what a join interrupted in the version before the journal
  /// leaves: the only copy of the phone's own vault. They are now kept under
  /// another name ([_joinKeptSuffix]) and never deleted.
  Future<void> recoverInterruptedJoin() async {
    if (!await _joinInterrupted()) return;
    _vault.lock();
    await _sync.logout();
    await DatabaseService().close();
    final dbPath = await DatabaseService.vaultDbPath();
    final journal = await _secureStorage.read(key: _joinRestoreKey);
    if (journal == _joinCommitted) {
      _deleteAsideDb(dbPath);
      await _secureStorage.delete(key: _joinRestoreKey);
      return;
    }
    if (journal == null || journal.isEmpty) {
      _keepAsideDb(dbPath);
      return;
    }
    await _undoJoin(
      dbPath,
      (jsonDecode(journal) as Map<String, dynamic>).cast<String, String?>(),
    );
  }

  /// Put the set-aside vault back and the Keychain values it was opened
  /// with. The database file is set aside last, so without it aside the
  /// original is still in place and only set-aside side files return.
  Future<void> _undoJoin(String dbPath, Map<String, String?> savedKeys) async {
    final mainAside = File('$dbPath$_joinAsideSuffix').existsSync();
    for (final suffix in _dbSideFiles) {
      final aside = File('$dbPath$suffix$_joinAsideSuffix');
      final f = File('$dbPath$suffix');
      if (aside.existsSync()) {
        if (f.existsSync()) f.deleteSync();
        aside.renameSync('$dbPath$suffix');
      } else if (mainAside && f.existsSync()) {
        f.deleteSync();
      }
    }
    for (final saved in savedKeys.entries) {
      if (saved.value == null) {
        await _secureStorage.delete(key: saved.key);
      } else {
        await _secureStorage.write(key: saved.key, value: saved.value!);
      }
    }
    await _secureStorage.delete(key: _joinRestoreKey);
  }

  void _deleteAsideDb(String dbPath) {
    for (final suffix in _dbSideFiles) {
      final f = File('$dbPath$suffix$_joinAsideSuffix');
      if (f.existsSync()) f.deleteSync();
    }
  }

  void _keepAsideDb(String dbPath) {
    final stamp = DateTime.now().millisecondsSinceEpoch;
    for (final suffix in _dbSideFiles) {
      final f = File('$dbPath$suffix$_joinAsideSuffix');
      if (!f.existsSync()) continue;
      final kept = '$dbPath$suffix$_joinAsideSuffix$_joinKeptSuffix-$stamp';
      f.renameSync(kept);
      debugPrint(
        'Sezam: an account join of an earlier version was interrupted; '
        'the vault it set aside is kept as $kept',
      );
    }
  }

  /// Review 526419e N7: vaults [_keepAsideDb] kept, oldest first. They were
  /// only named in a debug log, so nobody knew the phone's own vault from
  /// before an interrupted join was still there; settings now lists them.
  Future<List<KeptAsideVault>> keptAsideVaults() async {
    final dbPath = await DatabaseService.vaultDbPath();
    final dir = File(dbPath).parent;
    if (!dir.existsSync()) return [];
    final base = File(dbPath).uri.pathSegments.last;
    final marker = '$_joinAsideSuffix$_joinKeptSuffix-';
    final byStamp = <int, List<File>>{};
    for (final f in dir.listSync().whereType<File>()) {
      final name = f.uri.pathSegments.last;
      final at = name.lastIndexOf(marker);
      if (at < 0 || !name.startsWith(base)) continue;
      if (!_dbSideFiles.contains(name.substring(base.length, at))) continue;
      final stamp = int.tryParse(name.substring(at + marker.length));
      if (stamp == null) continue;
      byStamp.putIfAbsent(stamp, () => []).add(f);
    }
    final stamps = byStamp.keys.toList()..sort();
    return [
      for (final stamp in stamps)
        KeptAsideVault(
          DateTime.fromMillisecondsSinceEpoch(stamp),
          '$dbPath$marker$stamp',
          byStamp[stamp]!,
        ),
    ];
  }

  /// Review d150605 N4: whether a kept vault opens with this phone's key.
  /// A join of an earlier version replaced the salt and keypair in secure
  /// storage without keeping the old ones, so its copy may be sealed with a
  /// key nothing can derive any more; settings offered it as a rescue anyway.
  /// True or false once one of its own keys was tried; null when the vault
  /// is locked or the copy holds nothing to try.
  Future<bool?> keptAsideOpensHere(KeptAsideVault kept) async {
    final kek = _vault.currentKek;
    final main = File(kept.path);
    if (kek == null || !main.existsSync()) return null;
    final dir = await Directory.systemTemp.createTemp('sezam_kept_');
    try {
      // SQLite finds the WAL only next to the database under its own name.
      final copy = '${dir.path}/kept.db';
      main.copySync(copy);
      final wal = File(
        kept.path.replaceFirst(_joinAsideSuffix, '-wal$_joinAsideSuffix'),
      );
      if (wal.existsSync()) wal.copySync('$copy-wal');
      final db = await openDatabase(copy, singleInstance: false);
      try {
        final rows = await db.query(
          'vault_objects',
          where: "object_type = 'dek' AND is_deleted = 0",
        );
        var tried = false;
        for (final row in rows) {
          final payload = row['payload'];
          if (payload is! Uint8List || !_crypto.isEncryptedEnvelope(payload)) {
            continue;
          }
          tried = true;
          try {
            _crypto.unwrapDEK(
              payload,
              kek,
              row['id']! as String,
              version: row['version'] as int? ?? 1,
            );
            return true;
          } catch (_) {
            // Another key, or sealed with one this phone no longer has.
          }
        }
        return tried ? false : null;
      } finally {
        await db.close();
      }
    } on DatabaseException {
      return null;
    } finally {
      dir.deleteSync(recursive: true);
    }
  }

  /// Delete a kept vault once its owner no longer needs it.
  void deleteKeptAsideVault(KeptAsideVault vault) {
    for (final f in vault.files) {
      if (f.existsSync()) f.deleteSync();
    }
  }

  /// A device without the account keypair joins the account it just proved
  /// the password of (a new phone; the desktop does the same). The account
  /// keypair, salt and KDF replace this device's own; its local vault, if
  /// any, is set aside and its folders and entries are written again into
  /// the account. A vault holding anything a server confirmed belongs to
  /// another account and is left alone. Until the account vault is open and
  /// those items are in it, every failure puts the device back as it was.
  Future<ConnectResult> _moveDeviceToAccount({
    required String serverUrl,
    required String username,
    required Uint8List kek,
    required Uint8List keypairBytes,
    required String userObjectId,
    required String encryptedKeypairHex,
    required String argon2SaltHex,
    required AccountKdf kdf,
    ConnectProgressCallback? onProgress,
  }) async {
    final db = DatabaseService();
    final hadVault = await hasLocalVault();
    if (hadVault && !_vault.isUnlocked) {
      return ConnectResult(
        outcome: ConnectOutcome.error,
        message: 'Najprv odomkni lokalny trezor.',
      );
    }
    if (hadVault &&
        (await db.getAllObjects()).any((r) => r['commit_seq'] != null)) {
      return ConnectResult(
        outcome: ConnectOutcome.error,
        message:
            'Tento telefon uz obsahuje trezor ineho uctu. Pripojenie '
            'k uctu $username by ho nahradilo, preto sa nic nezmenilo.',
      );
    }

    // A join killed earlier is undone first: its set-aside vault is the
    // only copy of this device's items, and a second set-aside overwrote it.
    if (await _joinInterrupted()) {
      await recoverInterruptedJoin();
      return ConnectResult(
        outcome: ConnectOutcome.error,
        message:
            'Predchadzajuce pripojenie k uctu sa nedokoncilo, telefon je '
            'vrateny do povodneho stavu. Odomkni trezor a skus to znova.',
      );
    }

    // What to carry over, and how to put this device back on failure.
    final fromRootId = _vault.rootNodeId;
    final nodes = _vault.isUnlocked ? _vault.allNodes : <VaultNode>[];
    final List<CarriedEntry> entries;
    try {
      entries = _vault.isUnlocked ? await _vault.carriedEntries() : [];
    } on StateError catch (e) {
      return ConnectResult(
        outcome: ConnectOutcome.error,
        message:
            'Pripojenie k uctu by stratilo polozku, ktoru tento telefon '
            'nevie precitat (${e.message}), preto sa nic nezmenilo.',
      );
    }
    Uint8List? copy(Uint8List? b) => b == null ? null : Uint8List.fromList(b);
    final before = _vault.isUnlocked
        ? (
            kek: copy(_vault.currentKek)!,
            signingSk: copy(_vault.signingSecretKey)!,
            signingPk: copy(_vault.signingPublicKey)!,
            encryptionPk: copy(_vault.encryptionPublicKey),
            encryptionSk: copy(_vault.encryptionSecretKey),
            userId: _vault.userId ?? '',
            isAdmin: _vault.serverSaysAdmin,
          )
        : null;
    final savedKeys = {
      for (final key in _accountKeypairKeys)
        key: await _secureStorage.read(key: key),
    };
    final dbPath = await DatabaseService.vaultDbPath();

    _vault.lock();
    await _sync.logout();
    await db.close();
    try {
      // Journal first: a kill from here on is undone at the next start.
      await _secureStorage.write(
        key: _joinRestoreKey,
        value: jsonEncode(savedKeys),
      );
      // The database file last: once it is aside, every side file is too.
      for (final suffix in _dbSideFiles.reversed) {
        final f = File('$dbPath$suffix');
        if (f.existsSync()) f.renameSync('$dbPath$suffix$_joinAsideSuffix');
      }
      onProgress?.call('Preberam kluce uctu...');
      await _persistKeypairState(
        userObjectId: userObjectId,
        encryptedKeypairHex: encryptedKeypairHex,
        argon2SaltHex: argon2SaltHex,
        timeCost: kdf.timeCost,
        memoryCost: kdf.memoryCost,
        parallelism: kdf.parallelism,
      );
      final signingSecretKey = Uint8List.fromList(keypairBytes.sublist(0, 64));
      final authData = await _sync.authenticate(
        username: username,
        signingSecretKey: signingSecretKey,
      );
      if (requireCanonicalUserObjectId(authData) != userObjectId) {
        throw const FormatException('Account identity mismatch');
      }
      final isAdmin = authData['is_admin'] as bool? ?? false;
      await _vault.unlock(
        kek: Uint8List.fromList(kek),
        signingSecretKey: signingSecretKey,
        signingPublicKey: Uint8List.fromList(keypairBytes.sublist(32, 64)),
        encryptionSecretKey: Uint8List.fromList(keypairBytes.sublist(64, 96)),
        userId: userObjectId,
        isAdmin: isAdmin,
      );
      _vault.markKekMatchesServer();
      onProgress?.call('Synchronizujem...');
      await _sync.pull();
      await _vault.reloadData();
      final added = await _vault.addCarriedItems(
        fromRootId: fromRootId,
        nodes: nodes,
        entries: entries,
      );
      // Commit point: the items are in the account vault. The journal says
      // so until the set-aside copy is gone (set-aside files without one
      // come from an older version and are kept).
      await _secureStorage.write(key: _joinRestoreKey, value: _joinCommitted);
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(_usernameKey, _sync.accountNameFor(username));
      await prefs.setString(_serverUrlKey, serverUrl);
      await prefs.setBool(_isAdminKey, isAdmin);
      _deleteAsideDb(dbPath);
      await _secureStorage.delete(key: _joinRestoreKey);
      await _refreshBiometricKek(kek);
      if (before != null) {
        _crypto.zeroize(before.kek);
        _crypto.zeroize(before.signingSk);
        if (before.encryptionSk != null) _crypto.zeroize(before.encryptionSk!);
      }
      if (added > 0) {
        try {
          await _sync.push();
        } catch (_) {
          // Stays dirty for the next sync.
        }
      }
      return ConnectResult(
        outcome: ConnectOutcome.connected,
        message: added > 0
            ? 'Pripojeny k uctu. Polozky z tohto telefonu ($added) su teraz v nom.'
            : 'Pripojeny k uctu.',
      );
    } catch (e) {
      _vault.lock();
      await _sync.logout();
      await db.close();
      await _undoJoin(dbPath, savedKeys);
      if (before != null) {
        await _vault.unlock(
          kek: before.kek,
          signingSecretKey: before.signingSk,
          signingPublicKey: before.signingPk,
          encryptionSecretKey: before.encryptionSk,
          encryptionPublicKey: before.encryptionPk,
          userId: before.userId,
          isAdmin: before.isAdmin,
        );
      }
      return ConnectResult(
        outcome: ConnectOutcome.error,
        message:
            'Pripojenie k uctu zlyhalo, telefon zostal bez zmeny: '
            '${e is SyncException ? e.message : e}',
      );
    }
  }

  /// The onboarding of an account registered under these keys, or null when
  /// the server has none (401).
  Future<Map<String, dynamic>?> _resumedRegistration(
    String username,
    Uint8List signingSk,
  ) async {
    try {
      return await _sync.resumeRegistration(
        username: username,
        signingSecretKey: signingSk,
      );
    } on SyncException catch (e) {
      if (e.statusCode == 401) return null;
      rethrow;
    }
  }

  /// Register via invitation token.
  Future<ConnectResult> registerWithInvitation({
    required String serverUrl,
    required String username,
    required String password,
    required String invitationToken,
    ConnectProgressCallback? onProgress,
  }) async {
    username = normalizeUsername(username);
    Uint8List? registrationKek;
    Uint8List? registrationKeys;
    try {
      final invitation = invitationDetails(invitationToken, serverUrl);
      await _crypto.init();
      await _completePendingKeypairMigration();
      _sync.configure(serverUrl);

      // Enrollment needs a signing proof, not an unlocked data vault. In
      // particular, no trusted log exists yet after a preapproval restart.
      final localUserId = await _secureStorage.read(key: _userObjectIdKey);
      final localEnvelope = await _secureStorage.read(
        key: _encryptedKeypairKey,
      );
      if (localUserId == null || localEnvelope == null) {
        throw StateError('Local keypair state is incomplete');
      }
      if (_vault.isUnlocked && !await _passwordOpensUnlockedVault(password)) {
        return const ConnectResult(
          outcome: ConnectOutcome.wrongPassword,
          message: 'Nespravne heslo.',
        );
      }
      registrationKek = _vault.isUnlocked
          ? Uint8List.fromList(_vault.currentKek!)
          : await _deriveLocalKek(
              password,
              opens: (kek) =>
                  _opensKeypair(kek, hexToBytes(localEnvelope), localUserId),
            );
      if (registrationKek == null ||
          !_opensKeypair(
            registrationKek,
            hexToBytes(localEnvelope),
            localUserId,
          ) ||
          (_vault.isUnlocked &&
              !_bytesEqual(registrationKek, _vault.currentKek!))) {
        return const ConnectResult(
          outcome: ConnectOutcome.wrongPassword,
          message: 'Nespravne heslo.',
        );
      }
      final account = _crypto.openAccountKeypair(
        hexToBytes(localEnvelope),
        registrationKek,
        localUserId,
      );
      registrationKeys = expandDesktopKeypair(
        account.keypairData,
        _crypto.signingPublicKeyFromSeed(
          Uint8List.sublistView(account.keypairData, 0, 32),
        ),
      );
      final signingSk = Uint8List.sublistView(registrationKeys, 0, 64);
      final signingPkHex = bytesToHex(Uint8List.sublistView(signingSk, 32, 64));
      final encryptionPkHex = bytesToHex(
        _crypto.scalarmultBase(Uint8List.sublistView(registrationKeys, 64, 96)),
      );
      String? registrationGenesis;
      try {
        final pinned = await readConfirmedTeamGenesis(localUserId);
        // An anchor this phone left (forgetTeamLogPin) is no anchor any more.
        final anchor =
            (await readForgottenTeamGenesis(
              localUserId,
            )).contains(account.confirmedGenesis)
            ? null
            : account.confirmedGenesis;
        registrationGenesis = invitation.genesis ?? anchor ?? pinned;
        if ([
          anchor,
          pinned,
        ].any((anchor) => anchor != null && anchor != registrationGenesis)) {
          throw const FormatException('Account anchor changed or removed');
        }
      } finally {
        _crypto.zeroize(account.keypairData);
      }
      onProgress?.call('Registrujem ucet...');

      try {
        // The single-use invitation is already consumed when local storage or
        // upload fails. Keep the scoped response so retry does not register twice.
        const pendingKey = 'sezam_pending_invitation_registration';
        final pending = await _secureStorage.read(key: pendingKey);
        final context = {
          'server': serverUrl,
          'username': username,
          'invitation': invitation.token,
          'genesis': registrationGenesis,
          'signing_pk': signingPkHex,
          'encryption_pk': encryptionPkHex,
        };
        final saved = pending == null
            ? <String, dynamic>{'context': context}
            : jsonDecode(pending) as Map<String, dynamic>;
        if (jsonEncode(saved['context']) != jsonEncode(context)) {
          throw StateError('Finish the pending invitation registration first');
        }
        await _secureStorage.write(key: pendingKey, value: jsonEncode(saved));
        Map<String, dynamic>? registerResp;
        if (pending != null) {
          try {
            registerResp = await _sync.resumeRegistration(
              username: username,
              signingSecretKey: signingSk,
            );
            final previous = saved['response'] as Map?;
            if (previous != null &&
                previous['user_id'] != registerResp['user_id']) {
              throw StateError('Registration account changed');
            }
          } on SyncException catch (e) {
            if (e.statusCode != 401 || saved['response'] != null) rethrow;
          }
        }
        try {
          registerResp ??= await _sync.register(
            invitationToken: invitation.token,
            username: username,
            signingPkHex: signingPkHex,
            encryptionPkHex: encryptionPkHex,
          );
        } on SyncException catch (e) {
          // Review 8595ec1 #7: the server refused this registration outright
          // (no such invitation, used/expired, name taken), and no earlier
          // try landed (resume found no account under these keys). Nothing
          // is registered: keeping the intent would bind the phone to it.
          if (!{404, 409, 410}.contains(e.statusCode) ||
              saved['response'] != null)
            rethrow;
          // Review 4acfdde R11: an earlier try whose answer was lost can land
          // after this try's resume found nothing; the refusal is then the
          // server seeing that very account (name taken, invitation used).
          // Dropping the intent left it orphaned with the name taken.
          registerResp = pending == null
              ? null
              : await _resumedRegistration(username, signingSk);
          if (registerResp == null) {
            await _secureStorage.delete(key: pendingKey);
            rethrow;
          }
        }
        requireCanonicalUserObjectId(registerResp);
        saved['response'] = registerResp;
        await _secureStorage.write(key: pendingKey, value: jsonEncode(saved));
        final canonicalUserObjectId = requireCanonicalUserObjectId(
          registerResp,
        );
        if (registrationGenesis != null) {
          await confirmTeamGenesis(canonicalUserObjectId, registrationGenesis);
        }
        var canonicalEncryptedKeypair = saved['encrypted_keypair'] as String?;
        if (canonicalEncryptedKeypair == null) {
          final envelope = hexToBytes(localEnvelope);
          if (registrationGenesis == null) {
            canonicalEncryptedKeypair = bytesToHex(
              _crypto.rewrapKeypairObjectId(
                envelope,
                registrationKek,
                localUserId,
                canonicalUserObjectId,
              ),
            );
          } else {
            // The account envelope carries the invitation anchor, so a new
            // device of this member trusts it rather than the server.
            final local = _crypto.openAccountKeypair(
              envelope,
              registrationKek,
              localUserId,
            );
            try {
              canonicalEncryptedKeypair = bytesToHex(
                _crypto.wrapAccountKeypair(
                  local.keypairData,
                  registrationGenesis,
                  registrationKek,
                  utf8.decode(envelope.sublist(3, 29)).replaceAll('\x00', ''),
                  canonicalUserObjectId,
                  local.preAnchor,
                ),
              );
            } finally {
              _crypto.zeroize(local.keypairData);
            }
          }
        }
        final pendingAccount = _crypto.openAccountKeypair(
          hexToBytes(canonicalEncryptedKeypair),
          registrationKek,
          canonicalUserObjectId,
        );
        try {
          if (pendingAccount.confirmedGenesis != registrationGenesis) {
            throw StateError('Registration anchor changed');
          }
        } finally {
          _crypto.zeroize(pendingAccount.keypairData);
        }
        saved['encrypted_keypair'] = canonicalEncryptedKeypair;
        await _secureStorage.write(key: pendingKey, value: jsonEncode(saved));
        final uploadedHash = registerResp['key_material_hash'] as String?;
        if (uploadedHash != null) {
          if (_crypto.sha256Hex(hexToBytes(canonicalEncryptedKeypair)) !=
              uploadedHash) {
            throw StateError('Registration key material changed');
          }
        } else {
          onProgress?.call('Nahratavam sifrovany keypair...');
          await _uploadKeypairToServer(
            password,
            encryptedKeypairHex: canonicalEncryptedKeypair,
            wrappingKek: registrationKek,
          );
        }
        final previousUserId = await _secureStorage.read(key: _userObjectIdKey);
        await _persistKeypairState(
          userObjectId: canonicalUserObjectId,
          encryptedKeypairHex: canonicalEncryptedKeypair,
        );
        if (_vault.isUnlocked)
          _vault.bindRegisteredAccount(canonicalUserObjectId, previousUserId!);
      } on SyncException catch (e) {
        if (e.statusCode == 404) {
          return ConnectResult(
            outcome: ConnectOutcome.error,
            message: 'Neplatny invitation token.',
          );
        } else if (e.statusCode == 410) {
          return ConnectResult(
            outcome: ConnectOutcome.error,
            message: 'Invitation token uz bol pouzity alebo exspiroval.',
          );
        } else if (e.statusCode == 409) {
          return ConnectResult(
            outcome: ConnectOutcome.error,
            message: 'Pouzivatelske meno uz existuje.',
          );
        }
        return ConnectResult(
          outcome: ConnectOutcome.error,
          message: 'Chyba registracie: ${e.message}',
        );
      }

      // Save session
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(_usernameKey, _sync.accountNameFor(username));
      await prefs.setString(_serverUrlKey, serverUrl);

      // Keep the intent until approval, so a locked restart can resume here.
      return ConnectResult(
        outcome: ConnectOutcome.needsApproval,
        message: 'Registracia odoslana. Cakas na schvalenie administratorom.',
      );
    } catch (e) {
      return ConnectResult(
        outcome: ConnectOutcome.error,
        message: 'Chyba: ${e.toString().split(':').last.trim()}',
      );
    } finally {
      if (registrationKeys != null) _crypto.zeroize(registrationKeys);
      if (registrationKek != null) _crypto.zeroize(registrationKek);
    }
  }

  /// Poll for admin approval.
  /// Returns true when user is approved (can authenticate).
  Future<bool> pollForApproval({
    required String username,
    String? password,
    String? serverUrl,
  }) async {
    username = normalizeUsername(username);
    final wasLocked = !_vault.isUnlocked;
    try {
      if (wasLocked) {
        if (password == null || serverUrl == null) return false;
        final pending = await _secureStorage.read(
          key: 'sezam_pending_invitation_registration',
        );
        if (pending == null) return false;
        final context = (jsonDecode(pending) as Map)['context'] as Map;
        if (context['server'] != serverUrl || context['username'] != username)
          return false;
        final opened = await unlockWithPassword(
          password: password,
          username: username,
          serverUrl: serverUrl,
        );
        if (!opened.success) return false;
      }
      final signingSecretKey = _vault.signingSecretKey;
      if (signingSecretKey == null) return false;
      // A scoped upload token (or offline unlock) is not approval.
      final active = await _sync.checkUserActive(
        username: username,
        signingSecretKey: signingSecretKey,
      );
      if (active)
        await _secureStorage.delete(
          key: 'sezam_pending_invitation_registration',
        );
      if (!active && wasLocked) _vault.lock();
      return active;
    } catch (_) {
      if (wasLocked) _vault.lock();
      return false;
    }
  }

  Future<String> _rewrapStoredKeypairForUser(
    String canonicalUserObjectId,
  ) async {
    final currentUserObjectId = await _secureStorage.read(
      key: _userObjectIdKey,
    );
    final encryptedKeypairHex = await _secureStorage.read(
      key: _encryptedKeypairKey,
    );
    final kek = _vault.currentKek;
    if (currentUserObjectId == null ||
        !_canonicalUserObjectIdPattern.hasMatch(currentUserObjectId) ||
        encryptedKeypairHex == null ||
        encryptedKeypairHex.isEmpty ||
        kek == null) {
      throw StateError('Local keypair state is incomplete');
    }

    return bytesToHex(
      _crypto.rewrapKeypairObjectId(
        hexToBytes(encryptedKeypairHex),
        kek,
        currentUserObjectId,
        canonicalUserObjectId,
      ),
    );
  }

  /// Argon2id output of the first form of an EXISTING [password] that
  /// [opens] accepts, NFC first (lockout review M8): an account or vault from
  /// before normalization opens with the password as typed or decomposed.
  /// When no form is accepted the NFC derivation is returned, so the
  /// caller's normal wrong-password path runs.
  Future<Uint8List> _deriveExisting(
    String password,
    Uint8List salt, {
    required int timeCost,
    required int memoryCost,
    required int parallelism,
    required bool Function(Uint8List derived) opens,
    bool backup = false,
  }) async {
    final forms = passwordForms(password);
    Uint8List? canonical;
    for (final form in forms) {
      final derived = backup
          ? await _crypto.deriveBackupKEK(
              form,
              salt,
              timeCost: timeCost,
              memoryCost: memoryCost,
              parallelism: parallelism,
              exact: true,
            )
          : await _crypto.deriveKEK(
              form,
              salt,
              timeCost: timeCost,
              memoryCost: memoryCost,
              parallelism: parallelism,
              exact: true,
            );
      if (forms.length == 1) return derived;
      var accepted = false;
      try {
        accepted = opens(derived);
      } catch (_) {
        accepted = false;
      }
      if (accepted) {
        if (canonical != null) _crypto.zeroize(canonical);
        return derived;
      }
      if (canonical == null) {
        canonical = derived;
      } else {
        _crypto.zeroize(derived);
      }
    }
    return canonical!;
  }

  /// The anchor this phone's own keys name when the keys just opened
  /// ([genesis]) changed or removed it, null otherwise.
  Future<String?> _changedAccountAnchor(
    String userId,
    String? genesis,
    Uint8List previousKek,
  ) async {
    if (await _secureStorage.read(key: _userObjectIdKey) != userId) return null;
    final encoded = await _secureStorage.read(key: _encryptedKeypairKey);
    if (encoded == null) throw StateError('Local keypair state is incomplete');
    final previous = _crypto.openAccountKeypair(
      hexToBytes(encoded),
      previousKek,
      userId,
    );
    try {
      final anchor = previous.confirmedGenesis;
      // An unreadable list of left hashes leaves nothing (run 411): only keys
      // that changed their anchor are refused, never local damage alone.
      List<String> forgotten = const [];
      try {
        forgotten = await readForgottenTeamGenesis(userId);
      } on TeamLogMismatch {}
      return anchor != null && anchor != genesis && !forgotten.contains(anchor)
          ? anchor
          : null;
    } finally {
      _crypto.zeroize(previous.keypairData);
    }
  }

  /// [kek] (the server's password state) is one this phone left while its
  /// keys named no anchor: its keys' pre-anchor states and those it recorded.
  Future<bool> _leftWithoutAnchor(
    Uint8List kek,
    String userId,
    Uint8List previousKek,
  ) async {
    final encoded = await _secureStorage.read(key: _encryptedKeypairKey);
    if (encoded == null) throw StateError('Local keypair state is incomplete');
    final previous = _crypto.openAccountKeypair(
      hexToBytes(encoded),
      previousKek,
      userId,
    );
    _crypto.zeroize(previous.keypairData);
    final check = bytesToHex(_crypto.preAnchorCheck(kek));
    final known = _crypto.mergePreAnchor(
      previous.preAnchor,
      await _preAnchorHistory(),
    );
    return _crypto
        .parsePreAnchor(known)
        .any((e) => bytesToHex(e.check) == check);
  }

  Future<Uint8List> _openAnchoredAccountKeypair(
    Uint8List envelope,
    Uint8List kek,
    String userId, {
    Uint8List? previousKek,
    String? expectedGenesis,
    bool fromServer = false,
    bool heldVault = false,
  }) async {
    final account = _crypto.openAccountKeypair(envelope, kek, userId);
    try {
      final genesis = account.confirmedGenesis;
      if (genesis != null && expectedGenesis != null) {
        requireConfirmedGenesis(expectedGenesis, genesis);
      }
      final oldKek = previousKek ?? _vault.currentKek;
      var changed = oldKek == null
          ? null
          : await _changedAccountAnchor(userId, genesis, oldKek);
      if (changed != null &&
          genesis == null &&
          fromServer &&
          expectedGenesis == null &&
          !await _leftWithoutAnchor(kek, userId, oldKek!)) {
        // R15 (goal #429): keys without the anchor this phone's keys named
        // are a downgrade only under a password state this phone left before
        // it had the anchor. Under another one a device that never held the
        // anchor changed the password (an org recovery while this phone's
        // anchored change had not landed): the server held no anchor to
        // strip. The keys are taken; the anchor stays pinned here.
        try {
          if (await readConfirmedTeamGenesis(userId) == null)
            await confirmTeamGenesis(userId, changed);
        } catch (_) {}
        changed = null;
      }
      // Capability run 416: the server's keys of the vault this phone holds
      // (the password changed on another device) naming another log are no
      // password error and never keep it locked. The anchor this phone's own
      // keys named stays pinned, never followed away from; the team is
      // refused as anchor_conflict and the pin forgotten on the open vault.
      if (heldVault && expectedGenesis == null) {
        if (changed != null) {
          try {
            if (await readConfirmedTeamGenesis(userId) == null)
              await confirmTeamGenesis(userId, changed);
          } catch (_) {}
        }
        try {
          await recordAccountTeamGenesis(userId, genesis);
        } catch (_) {}
      } else if (changed != null) {
        throw const FormatException('Account anchor changed or removed');
      } else if (fromServer || expectedGenesis != null) {
        // Keys this phone is just taking from a server: one naming a genesis
        // this phone pins otherwise is refused before anything is written.
        if (genesis != null) await importAccountTeamGenesis(userId, genesis);
      } else {
        // INV-7: keys this phone already holds naming another log never fail
        // the unlock (it read "Wrong password"); team operations refuse it
        // as anchor_conflict. Capability run 411: nor does any trust record
        // that cannot be read or written; the team is refused where it is
        // used (local_damaged), only the decrypt above is a password error.
        try {
          await recordAccountTeamGenesis(userId, genesis);
        } catch (_) {}
      }
      return expandDesktopKeypair(
        account.keypairData,
        _crypto.signingPublicKeyFromSeed(
          Uint8List.sublistView(account.keypairData, 0, 32),
        ),
      );
    } finally {
      _crypto.zeroize(account.keypairData);
    }
  }

  /// True when [kek] opens the keypair [envelope] (throws otherwise).
  bool _opensKeypair(Uint8List kek, Uint8List envelope, String objectId) {
    final keypair = _crypto.unwrapKeypair(envelope, kek, objectId);
    _crypto.zeroize(keypair);
    return true;
  }

  /// POST /api/auth/recover with the proof of an EXISTING [password]: NFC
  /// first (reusing [first] when given), the other forms after a 401
  /// (lockout review M8). Returns the Argon2id output that was accepted and
  /// the response; rethrows the last failure.
  Future<({Uint8List derived, Map<String, dynamic> resp})> _recoverWithForms({
    required String username,
    required String password,
    required Uint8List salt,
    required int timeCost,
    required int memoryCost,
    required int parallelism,
    Uint8List? first,
  }) async {
    final forms = passwordForms(password);
    for (var i = 0; i < forms.length; i++) {
      final derived = i == 0 && first != null
          ? first
          : await _crypto.deriveKEK(
              forms[i],
              salt,
              timeCost: timeCost,
              memoryCost: memoryCost,
              parallelism: parallelism,
              exact: true,
            );
      try {
        final resp = await _sync.recover(
          username: username,
          authProof: Uint8List.sublistView(derived, 32, 64),
          argon2Params: {
            'time_cost': timeCost,
            'memory_cost': memoryCost,
            'parallelism': parallelism,
            'hash_len': 64,
          },
        );
        return (derived: derived, resp: resp);
      } on SyncException catch (e) {
        _crypto.zeroize(derived);
        if (e.statusCode == 401 && i + 1 < forms.length) continue;
        rethrow;
      } catch (_) {
        _crypto.zeroize(derived);
        rethrow;
      }
    }
    throw StateError('passwordForms is never empty');
  }

  /// KEK of [password] under the LOCAL salt/params (the previous password
  /// after a change elsewhere), or null when this device has no local KDF.
  /// [opens] picks the form of a password from before normalization.
  Future<Uint8List?> _deriveLocalKek(
    String password, {
    required bool Function(Uint8List kek) opens,
  }) async {
    final local = await _localKdf();
    if (local == null) return null;
    final derived = await _deriveExisting(
      password,
      hexToBytes(local.saltHex),
      opens: (d) => opens(Uint8List.sublistView(d, 0, 32)),
      timeCost: local.kdf.timeCost,
      memoryCost: local.kdf.memoryCost,
      parallelism: local.kdf.parallelism,
    );
    derived.fillRange(32, derived.length, 0);
    return Uint8List.sublistView(derived, 0, 32);
  }

  /// Salt and KDF params this device stores for its key material, or null
  /// when any of them is missing (never guessed — lockout review N2).
  Future<({String saltHex, AccountKdf kdf})?> _localKdf() async {
    final saltHex = await _secureStorage.read(key: _argon2SaltKey);
    final t = await _secureStorage.read(key: _argon2TimeCostKey);
    final m = await _secureStorage.read(key: _argon2MemoryCostKey);
    final p = await _secureStorage.read(key: _argon2ParallelismKey);
    if (saltHex == null || saltHex.isEmpty) return null;
    final timeCost = int.tryParse(t ?? '');
    final memoryCost = int.tryParse(m ?? '');
    final parallelism = int.tryParse(p ?? '');
    if (timeCost == null || memoryCost == null || parallelism == null) {
      return null;
    }
    try {
      return (
        saltHex: saltHex,
        kdf: accountKdfParams({
          'argon2_params': {
            'time_cost': timeCost,
            'memory_cost': memoryCost,
            'parallelism': parallelism,
          },
        }),
      );
    } on FormatException {
      return null;
    }
  }

  /// Capability run 273: the password states this phone left while the
  /// account had no anchor (pre-anchor format); a publication carries them.
  Future<Uint8List?> _preAnchorHistory() async {
    final hex = await _secureStorage.read(key: _preAnchorHistoryKey);
    return hex == null || hex.isEmpty ? null : hexToBytes(hex);
  }

  /// The local password state (under [kek]) is about to be left; without
  /// the anchor it opened bundles a server may keep, so it is recorded.
  Future<void> _recordLeftPreAnchorState(Uint8List kek, String userId) async {
    final local = await _localKdf();
    final envelope = await _secureStorage.read(key: _encryptedKeypairKey);
    if (local == null || envelope == null) return;
    final ({
      Uint8List keypairData,
      String? confirmedGenesis,
      Uint8List? preAnchor,
    })
    account;
    try {
      account = _crypto.openAccountKeypair(hexToBytes(envelope), kek, userId);
    } on Object {
      return; // a half-finished migration: the stored state is not this KEK's
    }
    _crypto.zeroize(account.keypairData);
    if (account.confirmedGenesis != null) return;
    final history = _crypto.addPreAnchor(
      await _preAnchorHistory(),
      hexToBytes(local.saltHex),
      local.kdf.timeCost,
      local.kdf.memoryCost,
      local.kdf.parallelism,
      kek,
    );
    await _secureStorage.write(
      key: _preAnchorHistoryKey,
      value: bytesToHex(history!),
    );
  }

  /// KDF params of the account key material [meta] describes: this device's
  /// own params while its salt is the server's (an account stored before
  /// per-account params is reported with the 128 MiB default, which opens
  /// nothing when it was created with others — lockout review N2), else the
  /// server's.
  Future<AccountKdf> _accountKdfFor(Map<String, dynamic> meta) async {
    final local = await _localKdf();
    final serverSalt = (meta['argon2_salt'] as String? ?? '').toLowerCase();
    if (local != null && local.saltHex.toLowerCase() == serverSalt) {
      return local.kdf;
    }
    return accountKdfParams(meta);
  }

  /// INV-8 (review e443cbc): an emergency action (forget the team log pin,
  /// drop unsent changes) asks for the account password, as on desktop and web.
  Future<bool> passwordOpensUnlockedVault(String password) =>
      _passwordOpensUnlockedVault(password);

  /// True only when [password] derives (under the local salt/params) the KEK
  /// the unlocked vault runs on.
  Future<bool> _passwordOpensUnlockedVault(String password) async {
    final current = _vault.currentKek;
    if (current == null) return false;
    final kek = await _deriveLocalKek(
      password,
      opens: (candidate) => _bytesEqual(candidate, current),
    );
    if (kek == null) return false;
    try {
      return _bytesEqual(kek, current);
    } finally {
      _crypto.zeroize(kek);
    }
  }

  /// Before a `.sezam-key` import replaces the stored salt/keypair: the
  /// vault must be unlocked, the backup must hold this vault's account and
  /// keypair, and own DEKs the backup KEK cannot open are moved to it from
  /// the current KEK (throws, nothing changed, when that is impossible).
  /// Returns whether the vault KEK still matches the server afterwards.
  Future<bool> _moveVaultToBackupKek(
    SezamKeyBackup backup,
    Uint8List backupKek,
    Uint8List keypair, {
    String? confirmedGenesis,
    required String userObjectId,
    Map<String, String> settings = const {},
  }) async {
    final currentKek = _vault.currentKek;
    final localUserId = _vault.userId;
    if (currentKek == null || localUserId == null) {
      throw StateError('Unlock the vault before importing a .sezam-key backup');
    }
    final localSigningPk = _vault.signingPublicKey;
    final localEncryptionPk = _vault.encryptionPublicKey;
    if (localSigningPk == null ||
        localEncryptionPk == null ||
        !_bytesEqual(localSigningPk, backup.signingPublicKey) ||
        !_bytesEqual(localEncryptionPk, backup.encryptionPublicKey)) {
      throw StateError('This backup holds a different keypair than this vault');
    }
    if (await _changedAccountAnchor(
          userObjectId,
          confirmedGenesis,
          currentKek,
        ) !=
        null) {
      throw const FormatException('Account anchor changed or removed');
    }
    if (confirmedGenesis != null) {
      await importAccountTeamGenesis(userObjectId, confirmedGenesis);
    }
    if ((await _sync.unreadableOwnDeks(backupKek, localUserId)).isEmpty) {
      return _vault.kekMatchesServer && _bytesEqual(currentKek, backupKek);
    }
    final oldKek = Uint8List.fromList(currentKek);
    try {
      await _sync.rekeyLocalVault(
        oldKek: oldKek,
        newKek: backupKek,
        userId: localUserId,
        checkpointUserId: localUserId,
        signingSecretKey: Uint8List.fromList(keypair.sublist(0, 64)),
        settings: settings,
      );
    } on LocalDekRekeyException catch (e) {
      throw StateError(e.toString());
    } finally {
      _crypto.zeroize(oldKek);
    }
    return false;
  }

  /// Biometric unlock stores the KEK itself; keep it in step with a KEK
  /// change (or switch biometrics off when the OS refuses the update).
  Future<void> _refreshBiometricKek(Uint8List kek) async {
    if (!await isBiometricEnabled()) return;
    try {
      await enableBiometrics(kek);
    } catch (_) {
      await disableBiometrics();
    }
  }

  /// The vault is unlocked with the previous KEK (offline/biometric unlock)
  /// and sync reported [KeyEpochStaleException]: take the password change
  /// made on another device over with the CURRENT password. Derives the KEK
  /// from the server's salt/params, proves it via /auth/recover, opens the
  /// account keypair (same account required), moves local DEK wraps and the
  /// checkpoint to the new KEK, then stores the new salt/params/keypair.
  /// A wrong password changes nothing.
  Future<AuthResult> adoptPasswordChangedElsewhere({
    required String currentPassword,
  }) async {
    final currentKek = _vault.currentKek;
    final userId = _vault.userId;
    if (currentKek == null ||
        userId == null ||
        !_canonicalUserObjectIdPattern.hasMatch(userId)) {
      return AuthResult.failure('Unlock the vault first');
    }
    final oldKek = Uint8List.fromList(currentKek);
    final lockGeneration = _vault.lockGeneration;
    Uint8List? derived;
    Uint8List? keypairBytes;
    var adopted = false;
    try {
      final prefs = await SharedPreferences.getInstance();
      final stored = prefs.getString(_usernameKey) ?? '';
      final serverUrl = prefs.getString(_serverUrlKey) ?? '';
      if (stored.isEmpty || serverUrl.isEmpty) {
        return AuthResult.failure('No server configured');
      }
      _sync.configure(serverUrl);

      // Review c02cc47 R17-L: the name a 409 'Identity key rotated' carried
      // is unsigned. It is tried first and kept only once /auth/recover
      // under it opens this account; a lie falls back to the stored name.
      final candidate =
          prefs.getString(SyncService.rotatedUsernamePrefKey) ?? '';
      final names = [
        if (candidate.isNotEmpty && candidate != stored) candidate,
        stored,
      ];
      String? username;
      String? argon2SaltHex;
      AccountKdf? kdf;
      Map<String, dynamic>? recoverResp;
      AuthResult? refusal;
      for (final name in names) {
        if (derived != null) _crypto.zeroize(derived);
        derived = null;
        try {
          final meta = await _sync.fetchMeta(username: name);
          final salt = meta['argon2_salt'] as String?;
          if (salt == null || salt.isEmpty) {
            refusal = AuthResult.failure('User not found or not configured');
            continue;
          }
          final nameKdf = await _accountKdfFor(meta);
          final ({Uint8List derived, Map<String, dynamic> resp}) recovered;
          try {
            recovered = await _recoverWithForms(
              username: name,
              password: currentPassword,
              salt: hexToBytes(salt),
              timeCost: nameKdf.timeCost,
              memoryCost: nameKdf.memoryCost,
              parallelism: nameKdf.parallelism,
            );
          } catch (e) {
            refusal = AuthResult.recoverFailure(e);
            continue;
          }
          derived = recovered.derived;
          if (requireCanonicalUserObjectId(recovered.resp) != userId) {
            refusal = AuthResult.failure(
              'The server account does not match this vault',
            );
            continue;
          }
          (username, argon2SaltHex, kdf, recoverResp) = (
            name,
            salt,
            nameKdf,
            recovered.resp,
          );
          break;
        } catch (e) {
          if (name == names.last) rethrow;
        }
      }
      if (username == null ||
          argon2SaltHex == null ||
          kdf == null ||
          recoverResp == null ||
          derived == null) {
        return refusal ??
            AuthResult.failure('User not found or not configured');
      }
      if (candidate.isNotEmpty) {
        if (username == candidate) {
          await prefs.setString(_usernameKey, candidate);
        }
        await prefs.remove(SyncService.rotatedUsernamePrefKey);
      }
      derived.fillRange(32, derived.length, 0);
      final newKek = Uint8List.sublistView(derived, 0, 32);
      final encryptedKeypairHex = recoverResp['encrypted_keypair'] as String?;
      final recoveredUserId = userId;
      if (encryptedKeypairHex == null || encryptedKeypairHex.isEmpty) {
        return AuthResult.failure('No encrypted keypair on the server');
      }
      try {
        keypairBytes = await _openAnchoredAccountKeypair(
          hexToBytes(encryptedKeypairHex),
          newKek,
          recoveredUserId,
          previousKek: oldKek,
          fromServer: true,
        );
      } catch (_) {
        return AuthResult.failure('Wrong password or corrupted keypair');
      }
      if (keypairBytes.length != 96) {
        return AuthResult.failure('Invalid recovered keypair');
      }
      final signingSecretKey = Uint8List.fromList(keypairBytes.sublist(0, 64));
      await _recordLeftPreAnchorState(oldKek, userId);

      // Every network step BEFORE the disk moves (lockout review #9): a
      // failed authenticate after the re-key left the disk on the new KEK
      // and the unlocked vault on the old one, writing with a dead KEK.
      final authData = await _sync.authenticate(
        username: username,
        signingSecretKey: signingSecretKey,
      );
      final isAdmin = authData['is_admin'] as bool? ?? false;
      // Review 8595ec1 #6: the anchor this password brought names a log this
      // phone may never have pulled; unlocking without it fails closed.
      await _sync.prepareInitialTeamLog(userId);

      // Review d615826: the keypair state lands in the transaction that
      // moves the DEKs; killed before the Keychain write, the next unlock
      // finishes it instead of holding keys no stored salt derives.
      final migration = _keypairMigration(
        userObjectId: recoveredUserId,
        encryptedKeypairHex: encryptedKeypairHex,
        argon2SaltHex: argon2SaltHex,
        timeCost: kdf.timeCost,
        memoryCost: kdf.memoryCost,
        parallelism: kdf.parallelism,
      );
      await _sync.rekeyLocalVault(
        oldKek: oldKek,
        newKek: newKek,
        userId: userId,
        checkpointUserId: userId,
        signingSecretKey: signingSecretKey,
        settings: {_dbKeypairMigrationSetting: jsonEncode(migration)},
      );
      // The local DEKs are on the new KEK now: memory follows at once, even
      // if persisting the keypair state below fails.
      adopted = true; // the vault now holds the KEK view of [derived]
      var lockedMeanwhile = false;
      try {
        await _vault.unlock(
          kek: newKek,
          signingSecretKey: signingSecretKey,
          signingPublicKey: Uint8List.fromList(
            signingSecretKey.sublist(32, 64),
          ),
          encryptionSecretKey: Uint8List.fromList(keypairBytes.sublist(64, 96)),
          userId: userId,
          isAdmin: isAdmin,
          // Review a159e97: an auto-lock during the network steps stays.
          unlessLockedSince: lockGeneration,
        );
        _vault.markKekMatchesServer();
      } on VaultLockedMeanwhile {
        lockedMeanwhile = true;
        adopted = false;
      }
      await _persistKeypairState(
        userObjectId: recoveredUserId,
        encryptedKeypairHex: encryptedKeypairHex,
        argon2SaltHex: argon2SaltHex,
        timeCost: kdf.timeCost,
        memoryCost: kdf.memoryCost,
        parallelism: kdf.parallelism,
      );
      await _refreshBiometricKek(newKek);
      await prefs.setBool(_isAdminKey, isAdmin);
      if (lockedMeanwhile) {
        // The change is taken over on disk; the vault stays locked.
        return AuthResult.failure(const VaultLockedMeanwhile().toString());
      }
      try {
        await _sync.pull();
      } on FullResyncRequiredException {
        // Review d615826: the server was restored from a backup (the reason
        // its password went back). The change is taken over; the app's
        // next sync asks for the full resync.
      }
      await _vault.reloadData();
      return AuthResult.success(userId: userId);
    } catch (e) {
      return AuthResult.failure(e.toString());
    } finally {
      _crypto.zeroize(oldKek);
      if (derived != null && !adopted) _crypto.zeroize(derived);
      if (keypairBytes != null) _crypto.zeroize(keypairBytes);
    }
  }

  /// Review 1141a20 H2: the genesis this phone confirmed independently goes
  /// into the encrypted account bundle, so the account's next phone, browser
  /// or desktop trusts the same team log without the server. Capability run
  /// 264: only together with a NEW password. The keypair wrap binds no
  /// epoch, so under the same password a server could hand a fresh device the
  /// older salt + bundle without the genesis; the new password opens neither.
  /// The server takes the change on the proof of [currentPassword]; this
  /// phone then takes it over like a change made elsewhere. A lost response
  /// is told apart by the salt the server serves.
  Future<AuthResult> publishTeamAnchor({
    required String currentPassword,
    required String newPassword,
  }) async {
    final kek = _vault.currentKek;
    final userId = _vault.userId;
    final signingSk = _vault.signingSecretKey;
    final encryptionSk = _vault.encryptionSecretKey;
    if (kek == null ||
        userId == null ||
        signingSk == null ||
        encryptionSk == null ||
        !_canonicalUserObjectIdPattern.hasMatch(userId)) {
      return AuthResult.failure('Unlock the vault first');
    }
    if (!_vault.kekMatchesServer) {
      return AuthResult.failure(
        'Take over the password change made on another device first',
      );
    }
    final genesis = await readConfirmedTeamGenesis(userId);
    if (genesis == null || _vault.teamLog?.team.genesisHash != genesis) {
      return AuthResult.failure('Confirm the team founder on this phone first');
    }
    if (newPassword.length < newPasswordMinLength) {
      return AuthResult.failure(
        'The new password needs at least $newPasswordMinLength characters',
      );
    }
    final prefs = await SharedPreferences.getInstance();
    final username = prefs.getString(_usernameKey) ?? '';
    final serverUrl = prefs.getString(_serverUrlKey) ?? '';
    final local = await _localKdf();
    final kekDekId = await DatabaseService().getSetting('kek_dek_id');
    if (username.isEmpty ||
        serverUrl.isEmpty ||
        local == null ||
        kekDekId == null) {
      return AuthResult.failure('No server account on this phone');
    }
    Uint8List? current;
    Uint8List? derived;
    Uint8List? keys;
    final newSalt = _crypto.randomBytes(16);
    try {
      current = await _deriveExisting(
        currentPassword,
        hexToBytes(local.saltHex),
        timeCost: local.kdf.timeCost,
        memoryCost: local.kdf.memoryCost,
        parallelism: local.kdf.parallelism,
        opens: (d) => _bytesEqual(Uint8List.sublistView(d, 0, 32), kek),
      );
      if (!_bytesEqual(Uint8List.sublistView(current, 0, 32), kek)) {
        return AuthResult.failure('Wrong current password');
      }
      if (await _passwordOpensUnlockedVault(newPassword)) {
        return AuthResult.failure(
          'Choose a new password: under the current one the server could '
          'hand a new device the account keys without the team anchor',
        );
      }
      // Capability run 269: the password states left here opened bundles
      // without the anchor; the anchored bundle records them so no client
      // moves the account back to one.
      final localEnvelope = await _secureStorage.read(
        key: _encryptedKeypairKey,
      );
      if (localEnvelope == null) {
        return AuthResult.failure('Local keypair state is incomplete');
      }
      final localAccount = _crypto.openAccountKeypair(
        hexToBytes(localEnvelope),
        kek,
        userId,
      );
      _crypto.zeroize(localAccount.keypairData);
      // Capability run 273: with every earlier state this phone left.
      final known = _crypto.mergePreAnchor(
        localAccount.preAnchor,
        await _preAnchorHistory(),
      );
      if (await _crypto.passwordReopensPreAnchor(newPassword, known)) {
        return AuthResult.failure(preAnchorPasswordRefused);
      }
      final preAnchor = _crypto.addPreAnchor(
        known,
        hexToBytes(local.saltHex),
        local.kdf.timeCost,
        local.kdf.memoryCost,
        local.kdf.parallelism,
        kek,
      );
      _sync.configure(serverUrl);
      // Review c02cc47 R17-R9s: who set it up is told to a session only.
      await _sync.authenticate(username: username, signingSecretKey: signingSk);
      final recovery = await _sync.orgRecoveryStatus();
      if (recovery['configured'] == true &&
          recovery['created_by'] == userId &&
          recovery['stale'] != true) {
        return AuthResult.failure(
          'This account set up the org recovery; change the password where '
          'it was set up (desktop or browser)',
        );
      }
      derived = await _crypto.deriveKEK(
        newPassword,
        newSalt,
        timeCost: local.kdf.timeCost,
        memoryCost: local.kdf.memoryCost,
        parallelism: local.kdf.parallelism,
      );
      final newKek = Uint8List.sublistView(derived, 0, 32);
      keys = Uint8List.fromList([...signingSk, ...encryptionSk]);
      final envelope = _crypto.wrapAccountKeypair(
        keys,
        genesis,
        newKek,
        kekDekId,
        userId,
        preAnchor,
      );
      try {
        await _sync.advanceKeyEpoch(
          username: username,
          newKek: newKek,
          signingSecretKey: signingSk,
          keyRotation: {
            'encrypted_keypair': bytesToHex(envelope),
            'argon2_salt': bytesToHex(newSalt),
            'auth_salt': bytesToHex(newSalt),
            'auth_proof': bytesToHex(Uint8List.sublistView(derived, 32, 64)),
            'argon2_params': {
              'time_cost': local.kdf.timeCost,
              'memory_cost': local.kdf.memoryCost,
              'parallelism': local.kdf.parallelism,
              'hash_len': 64,
            },
            'current_auth_proof': bytesToHex(
              Uint8List.sublistView(current, 32, 64),
            ),
          },
        );
      } on KeyEpochStaleException {
        return AuthResult.failure(
          'The password was changed on another device; nothing was published',
        );
      } on SyncException catch (e) {
        if (e.statusCode < 500) {
          return AuthResult.failure('Nothing was published: ${e.message}');
        }
        final landed = await _servesSalt(username, newSalt);
        if (landed != true) return _unpublished(landed, e.message);
      } on StateError catch (e) {
        return AuthResult.failure('Nothing was published: ${e.message}');
      } on LocalDekRekeyException catch (e) {
        return AuthResult.failure('Nothing was published: $e');
      } catch (e) {
        // No answer: the salt the server serves tells whether it landed.
        final landed = await _servesSalt(username, newSalt);
        if (landed != true) return _unpublished(landed, e);
      }
    } on StateError catch (e) {
      return AuthResult.failure(e.message);
    } catch (e) {
      return AuthResult.failure('Nothing was published: $e');
    } finally {
      if (current != null) _crypto.zeroize(current);
      if (derived != null) _crypto.zeroize(derived);
      if (keys != null) _crypto.zeroize(keys);
    }
    // The server holds the new key material: take it over with the new
    // password (DEK wraps, checkpoint, Keychain, biometrics), then pull.
    return adoptPasswordChangedElsewhere(currentPassword: newPassword);
  }

  /// Whether the server serves [salt] for [username] (null: no answer).
  Future<bool?> _servesSalt(String username, Uint8List salt) async {
    try {
      final served =
          (await _sync.fetchMeta(username: username))['argon2_salt'] as String?;
      return served?.toLowerCase() == bytesToHex(salt);
    } catch (_) {
      return null;
    }
  }

  AuthResult _unpublished(bool? landed, Object error) => AuthResult.failure(
    landed == null
        ? 'No answer from the server ($error). If the change landed, the next '
              'online unlock asks for the new password.'
        : 'Nothing was published: $error',
  );

  Future<void> _persistKeypairState({
    required String userObjectId,
    required String encryptedKeypairHex,
    String? argon2SaltHex,
    int? timeCost,
    int? memoryCost,
    int? parallelism,
  }) async {
    final migration = _keypairMigration(
      userObjectId: userObjectId,
      encryptedKeypairHex: encryptedKeypairHex,
      argon2SaltHex: argon2SaltHex,
      timeCost: timeCost,
      memoryCost: memoryCost,
      parallelism: parallelism,
    );
    await _secureStorage.write(
      key: _pendingKeypairMigrationKey,
      value: jsonEncode(migration),
    );
    await _completePendingKeypairMigration();
  }

  /// The keypair state [_persistKeypairState] stores, validated BEFORE any
  /// journal is written: a journal its own completion refuses failed every
  /// later unlock (lockout review #6).
  Map<String, dynamic> _keypairMigration({
    required String userObjectId,
    required String encryptedKeypairHex,
    String? argon2SaltHex,
    int? timeCost,
    int? memoryCost,
    int? parallelism,
  }) {
    requireCanonicalUserObjectId({'user_id': userObjectId});
    final encryptedKeypair = hexToBytes(encryptedKeypairHex);
    if (!_crypto.isEncryptedEnvelope(encryptedKeypair)) {
      throw const FormatException('Invalid keypair envelope');
    }
    final hasKdfMetadata =
        argon2SaltHex != null ||
        timeCost != null ||
        memoryCost != null ||
        parallelism != null;
    if (hasKdfMetadata &&
        (argon2SaltHex == null ||
            timeCost == null ||
            memoryCost == null ||
            parallelism == null)) {
      throw const FormatException('Incomplete keypair KDF metadata');
    }

    final migration = <String, dynamic>{
      'user_id': userObjectId,
      'encrypted_keypair': encryptedKeypairHex,
      if (hasKdfMetadata) 'argon2_salt': argon2SaltHex,
      if (hasKdfMetadata) 'time_cost': timeCost,
      if (hasKdfMetadata) 'memory_cost': memoryCost,
      if (hasKdfMetadata) 'parallelism': parallelism,
    };
    _validatePendingKeypairMigration(migration);
    return migration;
  }

  Future<void> _completePendingKeypairMigration() async {
    var encoded = await _secureStorage.read(key: _pendingKeypairMigrationKey);
    // Review 688edcb: a .sezam-key import killed after its DEK move left the
    // keypair state in the database transaction that moved the DEKs.
    final db = DatabaseService();
    final inDb = await db.getSetting(_dbKeypairMigrationSetting);
    if (encoded == null || encoded.isEmpty) encoded = inDb;
    if (encoded == null || encoded.isEmpty) return;

    final migration = jsonDecode(encoded) as Map<String, dynamic>;
    // A journal written before the 256 MiB cap holds params this device
    // already derived with: finish it instead of failing every unlock.
    _validatePendingKeypairMigration(migration, maxMemoryCost: 1048576);
    final userObjectId = migration['user_id'] as String;
    final encryptedKeypairHex = migration['encrypted_keypair'] as String;
    final argon2SaltHex = migration['argon2_salt'] as String?;

    await _secureStorage.write(
      key: _encryptedKeypairKey,
      value: encryptedKeypairHex,
    );
    if (argon2SaltHex != null) {
      await _secureStorage.write(key: _argon2SaltKey, value: argon2SaltHex);
      await _secureStorage.write(
        key: _argon2TimeCostKey,
        value: (migration['time_cost'] as int).toString(),
      );
      await _secureStorage.write(
        key: _argon2MemoryCostKey,
        value: (migration['memory_cost'] as int).toString(),
      );
      await _secureStorage.write(
        key: _argon2ParallelismKey,
        value: (migration['parallelism'] as int).toString(),
      );
    }
    await _secureStorage.write(key: _userObjectIdKey, value: userObjectId);
    if (inDb != null) await db.deleteSetting(_dbKeypairMigrationSetting);
    await _secureStorage.delete(key: _pendingKeypairMigrationKey);
  }

  void _validatePendingKeypairMigration(
    Map<String, dynamic> migration, {
    int maxMemoryCost = accountKdfMaxMemoryCost,
  }) {
    final userObjectId = requireCanonicalUserObjectId(migration);
    final encryptedKeypairHex = migration['encrypted_keypair'];
    if (encryptedKeypairHex is! String) {
      throw const FormatException('Invalid pending keypair migration');
    }
    final encryptedKeypair = hexToBytes(encryptedKeypairHex);
    if (!_crypto.isEncryptedEnvelope(encryptedKeypair)) {
      throw const FormatException('Invalid pending keypair migration');
    }

    final argon2SaltHex = migration['argon2_salt'];
    if (argon2SaltHex != null) {
      final timeCost = migration['time_cost'];
      final memoryCost = migration['memory_cost'];
      final parallelism = migration['parallelism'];
      if (argon2SaltHex is! String ||
          timeCost is! int ||
          memoryCost is! int ||
          parallelism is! int) {
        throw const FormatException('Invalid pending keypair KDF metadata');
      }
      _validateSezamKeyMetadata(
        argon2Salt: hexToBytes(argon2SaltHex),
        timeCost: timeCost,
        memoryCost: memoryCost,
        parallelism: parallelism,
        kekDekId: utf8.decode(encryptedKeypair.sublist(3, 29)),
        userObjectId: userObjectId,
        signingPublicKey: Uint8List(32),
        encryptionPublicKey: Uint8List(32),
        encryptedEnvelope: encryptedKeypair,
        maxMemoryCost: maxMemoryCost,
      );
    }
  }

  /// Upload the encrypted keypair + salts + auth_proof to the server.
  Future<void> _uploadKeypairToServer(
    String password, {
    String? encryptedKeypairHex,
    Uint8List? wrappingKek,
    ({String username, Uint8List signingSecretKey})? signedBy,
  }) async {
    final kek = wrappingKek ?? _vault.currentKek;
    if (kek == null) {
      throw StateError('KEK not available');
    }

    // Read stored argon2 salt
    final argon2SaltHex = await _secureStorage.read(key: _argon2SaltKey);
    if (argon2SaltHex == null || argon2SaltHex.isEmpty) {
      throw StateError('Argon2 salt not found');
    }

    // Use the canonical rewrap during onboarding, otherwise the stored copy.
    encryptedKeypairHex ??= await _secureStorage.read(
      key: _encryptedKeypairKey,
    );
    if (encryptedKeypairHex == null || encryptedKeypairHex.isEmpty) {
      throw StateError('Encrypted keypair not found');
    }

    final argon2Salt = hexToBytes(argon2SaltHex);

    final timeCostStr = await _secureStorage.read(key: _argon2TimeCostKey);
    final memoryCostStr = await _secureStorage.read(key: _argon2MemoryCostKey);
    final parallelismStr = await _secureStorage.read(
      key: _argon2ParallelismKey,
    );
    final timeCost = int.tryParse(timeCostStr ?? '') ?? 2;
    final memoryCost = int.tryParse(memoryCostStr ?? '') ?? 131072;
    final parallelism = int.tryParse(parallelismStr ?? '') ?? 4;

    // Derive KEK + auth_proof from the form of the password the keypair is
    // wrapped under (lockout review M8).
    final derived = await _deriveExisting(
      password,
      argon2Salt,
      timeCost: timeCost,
      memoryCost: memoryCost,
      parallelism: parallelism,
      opens: (d) => _bytesEqual(Uint8List.sublistView(d, 0, 32), kek),
    );
    final authProof = Uint8List.sublistView(derived, 32, 64);

    // Generate auth_salt (16 bytes random) for server-side HMAC
    final authSalt = _crypto.randomBytes(16);

    try {
      // The auth_proof must come from the password the keypair is wrapped
      // under; otherwise the server stores a proof nobody can reproduce.
      if (!_bytesEqual(Uint8List.sublistView(derived, 0, 32), kek)) {
        throw StateError('Password does not open the local vault');
      }
      await _sync.uploadKeypair(
        encryptedKeypairHex: encryptedKeypairHex,
        argon2SaltHex: argon2SaltHex,
        authSaltHex: bytesToHex(authSalt),
        authProofHex: bytesToHex(authProof),
        argon2Params: {
          'time_cost': timeCost,
          'memory_cost': memoryCost,
          'parallelism': parallelism,
          'hash_len': 64,
        },
        signedBy: signedBy,
      );
    } finally {
      _crypto.zeroize(derived);
    }
  }

  /// Review 8595ec1 #1: sync reported [AccountLostOnServerException], a
  /// server restored from a backup older than this member account. The team
  /// log names the account's id and keys; the server takes them back with a
  /// proof by those keys (/auth/rejoin), then gets the key material wrapped
  /// under [password], and a full resync sends again what this account wrote
  /// that the backup lost. An interrupted rejoin continues when run again.
  ///
  /// [newUsername] rejoins under another name: the log names the member by
  /// id, and an account registered after the backup may hold the old name
  /// (review 4acfdde R11, low; [AuthResult.usernameTaken]).
  Future<AuthResult> rejoinServer({
    required String password,
    String? newUsername,
  }) async {
    final userId = _vault.userId;
    final signingSk = _vault.signingSecretKey;
    if (!_vault.isUnlocked || userId == null || signingSk == null) {
      return AuthResult.failure('Unlock the vault first');
    }
    if (!await _passwordOpensUnlockedVault(password)) {
      return AuthResult.failure('Nespravne heslo.');
    }
    final db = DatabaseService();
    final prefs = await SharedPreferences.getInstance();
    final previousName = prefs.getString(_usernameKey);
    final username = newUsername != null
        ? normalizeUsername(newUsername)
        : previousName ?? '';
    if (username.isEmpty) return AuthResult.failure('The username is empty.');
    var stage = await db.outboxOperation(outboxRejoin);
    final resumed = stage != null;
    if (stage == null) {
      if (!_sync.namedByTeamLog()) {
        return AuthResult.failure(
          "The team log does not name this account with this phone's keys; "
          'there is nothing to rejoin.',
        );
      }
      stage = 'rejoin';
      await db.putOutboxOperation(outboxRejoin, stage);
    }
    if (stage == 'rejoin') {
      final keyEpoch =
          int.tryParse(await db.getSetting('key_epoch') ?? '0') ?? 0;
      // The sign-ins below and a resumed run use the stored name.
      await prefs.setString(_usernameKey, _sync.accountNameFor(username));
      bool created;
      try {
        created = await _sync.rejoin(username: username, keyEpoch: keyEpoch);
      } on SyncException catch (e) {
        if (e.statusCode < 400 || e.statusCode >= 500) rethrow;
        await db.dropOutboxOperation(outboxRejoin);
        if (previousName != null)
          await prefs.setString(_usernameKey, previousName);
        if (e is UsernameTakenException)
          return AuthResult.usernameTaken(username);
        return AuthResult.failure(
          'The server refused the rejoin: ${e.message}',
        );
      }
      if (!created && !resumed) {
        await db.dropOutboxOperation(outboxRejoin);
        return AuthResult.failure('The account exists on the server; sign in.');
      }
      if (created) {
        await _uploadKeypairToServer(password);
      } else {
        // An earlier run's rejoin landed with its answer lost (or its
        // upload did not): sign in and upload unless the server has it.
        await _sync.authenticate(
          username: username,
          signingSecretKey: signingSk,
        );
        try {
          await _uploadKeypairToServer(
            password,
            signedBy: (username: username, signingSecretKey: signingSk),
          );
        } on SyncException catch (e) {
          if (e.statusCode != 409) rethrow;
        }
      }
      stage = 'resync';
      await db.putOutboxOperation(outboxRejoin, stage);
    }
    await _sync.authenticate(username: username, signingSecretKey: signingSk);
    await _sync.fullResync(confirmed: true);
    await db.dropOutboxOperation(outboxRejoin);
    await _sync.sync();
    return AuthResult.success(userId: userId);
  }
}

/// Callback for connect progress updates.
typedef ConnectProgressCallback = void Function(String message);

/// Outcome of a server connect attempt.
enum ConnectOutcome {
  connected,
  needsInvitation,
  needsApproval,
  wrongPassword,
  unreachable,
  error,
}

/// This phone's own vault from before an account join an earlier version
/// left interrupted (review e4cd15a S4, 526419e N7). [path] is the database
/// file; [files] includes its -wal/-shm/-journal companions.
class KeptAsideVault {
  final DateTime keptAt;
  final String path;
  final List<File> files;

  const KeptAsideVault(this.keptAt, this.path, this.files);
}

/// Result of a server connect attempt.
class ConnectResult {
  final ConnectOutcome outcome;
  final String message;

  const ConnectResult({required this.outcome, required this.message});
}

/// Authentication result.
class AuthResult {
  final bool success;
  final String? userId;
  final String? error;

  /// The password was changed on another device and the local vault is still
  /// under the previous one: retry with `previousPassword`.
  final bool needsPreviousPassword;

  /// The server refused /recover because of the address limit (429) or the
  /// account lock (423): show [error], not a generic "Wrong password".
  final bool recoveryLimited;

  /// A rejoin found its name taken by another account (review 4acfdde R11,
  /// low): ask for another name and call `rejoinServer` with it.
  final bool usernameTaken;

  /// The unlock refused this phone's team log (INV-7): the lock screen leads
  /// on to the server sign-in, which fetches the log under its pins.
  final TeamLogMismatch? teamLog;

  const AuthResult._({
    required this.success,
    this.userId,
    this.error,
    this.needsPreviousPassword = false,
    this.recoveryLimited = false,
    this.usernameTaken = false,
    this.teamLog,
  });

  factory AuthResult.success({String? userId}) =>
      AuthResult._(success: true, userId: userId);

  factory AuthResult.failure(String error) =>
      AuthResult._(success: false, error: error);

  factory AuthResult.teamLogRefused(TeamLogMismatch refusal) =>
      AuthResult._(success: false, error: '$refusal', teamLog: refusal);

  /// Failure of a `/api/auth/recover` call (lockout review #7).
  factory AuthResult.recoverFailure(Object error) => AuthResult._(
    success: false,
    error: recoverFailureMessage(error),
    recoveryLimited:
        error is SyncException &&
        (error.statusCode == 423 || error.statusCode == 429),
  );

  factory AuthResult.usernameTaken(String username) => AuthResult._(
    success: false,
    error:
        "Another account on the server took the name '$username' after the "
        'backup. Rejoin under another name.',
    usernameTaken: true,
  );

  factory AuthResult.needsPreviousPassword() => const AuthResult._(
    success: false,
    error:
        'The password was changed on another device. Enter the previous '
        'password once so this device can take the change over.',
    needsPreviousPassword: true,
  );
}

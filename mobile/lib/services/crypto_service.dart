/// Sezam CryptoService — E2E encryption matching the desktop/web protocol.
///
/// Uses sodium_libs (libsodium bindings) for:
///   - XChaCha20-Poly1305 AEAD (envelope encrypt/decrypt)
///   - Ed25519 signing (challenge-response, sync push)
///   - X25519 key exchange (not used in single-user, but for multi-device)
///
/// Uses dargon2_flutter for:
///   - Argon2id key derivation (password -> KEK + auth_proof)
///
/// Envelope format (spec 2.6):
///   alg(1) + schema(1) + kind(1) + dekId(26) + nonce(24) + ciphertext
///
/// AAD (59 bytes):
///   alg(1) + schema(1) + kind(1) + dekId(26) + objectId(26) + version_u32be(4)

import 'dart:convert';
import 'dart:math' show min;
import 'dart:typed_data';

import 'package:sodium_libs/sodium_libs_sumo.dart';
import 'package:dargon2_flutter/dargon2_flutter.dart';
import 'package:crypto/crypto.dart' as crypto_pkg;
import 'package:flutter/foundation.dart' show visibleForTesting;

import '../models/vault_models.dart';
import 'password_forms.dart';

class CryptoService {
  // Singleton
  static final CryptoService _instance = CryptoService._();
  factory CryptoService() => _instance;
  CryptoService._();

  bool _initialized = false;
  late SodiumSumo _sodium;

  /// The initialized SodiumSumo instance, available after [init].
  SodiumSumo get sodium {
    if (!_initialized) {
      throw StateError('CryptoService not initialized. Call init() first.');
    }
    return _sodium;
  }

  /// Initialize libsodium. Must be called once at app start.
  Future<void> init() async {
    if (_initialized) return;
    _sodium = await SodiumSumoInit.init();
    _initialized = true;
  }

  Future<Uint8List> Function(
    String password,
    Uint8List salt,
    int timeCost,
    int memoryCost,
    int parallelism,
  )?
  _argon2ForTesting;

  /// `flutter test` loads neither the libsodium plugin nor dargon2: a test
  /// passes a libsodium it loaded itself and an Argon2id (64-byte output).
  @visibleForTesting
  void initForTesting(
    SodiumSumo sodium, {
    required Future<Uint8List> Function(
      String password,
      Uint8List salt,
      int timeCost,
      int memoryCost,
      int parallelism,
    )
    argon2,
  }) {
    _sodium = sodium;
    _argon2ForTesting = argon2;
    _initialized = true;
  }

  // ── Argon2id Key Derivation ──

  /// Derive a 64-byte key from password + salt using Argon2id.
  /// Returns [kek(32 bytes) + authProof(32 bytes)].
  ///
  /// Parameters match server's argon2_web_params with hard floor enforcement:
  ///   time_cost >= 2, memory_cost >= 65536 (64 MB), parallelism >= 1
  ///
  /// The password is normalized to NFC unless [exact] (one of
  /// [passwordForms], for accounts from before normalization).
  Future<Uint8List> deriveKEK(
    String password,
    Uint8List salt, {
    int timeCost = 3,
    int memoryCost = 131072, // 128 MB (mobile may need lower)
    int parallelism = 4,
    bool exact = false,
  }) {
    return _deriveKEK(
      exact ? password : canonicalPassword(password),
      salt,
      timeCost: timeCost < 2 ? 2 : timeCost,
      memoryCost: memoryCost < 65536 ? 65536 : memoryCost,
      parallelism: parallelism < 1 ? 1 : parallelism,
    );
  }

  /// Derive a KEK using bounded parameters embedded in a desktop backup.
  Future<Uint8List> deriveBackupKEK(
    String password,
    Uint8List salt, {
    required int timeCost,
    required int memoryCost,
    required int parallelism,
    bool exact = false,
  }) {
    return _deriveKEK(
      exact ? password : canonicalPassword(password),
      salt,
      timeCost: timeCost,
      memoryCost: memoryCost,
      parallelism: parallelism,
    );
  }

  Future<Uint8List> _deriveKEK(
    String password,
    Uint8List salt, {
    required int timeCost,
    required int memoryCost,
    required int parallelism,
  }) async {
    final forTesting = _argon2ForTesting;
    if (forTesting != null) {
      return forTesting(password, salt, timeCost, memoryCost, parallelism);
    }
    final result = await argon2.hashPasswordBytes(
      utf8.encode(password),
      salt: Salt(salt),
      iterations: timeCost,
      memory: memoryCost,
      parallelism: parallelism,
      length: 64, // 32B KEK + 32B auth_proof
      type: Argon2Type.id,
    );

    final rawBytes = result.rawBytes;
    return rawBytes is Uint8List ? rawBytes : Uint8List.fromList(rawBytes);
  }

  // ── Envelope Encryption (spec 2.6) ──

  /// Build the 59-byte AAD for AEAD encryption.
  ///
  /// Format: alg(1) + schema(1) + kind(1) + dekId(26) + objectId(26) + version_u32be(4)
  Uint8List buildAAD(int blobKind, String dekId, String objectId, int version) {
    final aad = Uint8List(EnvelopeConstants.aadLen);
    aad[0] = EnvelopeConstants.algXChaCha20Poly1305;
    aad[1] = EnvelopeConstants.schemaVersion;
    aad[2] = blobKind;

    // DEK ID padded/truncated to 26 bytes
    final dekIdBytes = utf8.encode(dekId.padRight(26, '\x00').substring(0, 26));
    aad.setRange(3, 29, dekIdBytes);

    // Object ID padded/truncated to 26 bytes
    final objIdBytes = utf8.encode(
      objectId.padRight(26, '\x00').substring(0, 26),
    );
    aad.setRange(29, 55, objIdBytes);

    // Version as u32 big-endian
    final versionBytes = ByteData(4)..setUint32(0, version, Endian.big);
    aad.setRange(55, 59, versionBytes.buffer.asUint8List());

    return aad;
  }

  /// Pad plaintext to nearest power of 2 (min 32 bytes).
  /// Format: u16be(paddingLen) + random_padding + data
  Uint8List padPlaintext(Uint8List data) {
    const minSize = 32;
    final totalNeeded = 2 + data.length; // 2 bytes for padding_len prefix
    var targetSize = minSize;
    while (targetSize < totalNeeded) {
      targetSize *= 2;
    }
    // u16 prefix caps padding at 0xFFFF (same rule as Python/web).
    final paddingLen = min(targetSize - 2 - data.length, 0xFFFF);
    targetSize = 2 + paddingLen + data.length;
    final padded = Uint8List(targetSize);
    final view = ByteData.sublistView(padded);
    view.setUint16(0, paddingLen, Endian.big);

    if (paddingLen > 0) {
      final randomPadding = _sodium.randombytes.buf(paddingLen);
      padded.setRange(2, 2 + paddingLen, randomPadding);
    }

    padded.setRange(2 + paddingLen, targetSize, data);
    return padded;
  }

  /// Remove padding: read u16be prefix, skip padding, return actual data.
  Uint8List unpadPlaintext(Uint8List padded) {
    if (padded.length < 2) throw ArgumentError('Padded data too short');
    final view = ByteData.sublistView(padded);
    final paddingLen = view.getUint16(0, Endian.big);
    if (2 + paddingLen > padded.length) {
      throw ArgumentError('Invalid padding length');
    }
    return Uint8List.fromList(padded.sublist(2 + paddingLen));
  }

  /// Encrypt a JSON-serializable object into an envelope.
  ///
  /// Returns the full envelope bytes:
  ///   alg(1) + schema(1) + kind(1) + dekId(26) + nonce(24) + ciphertext
  Uint8List encryptEnvelope(
    Map<String, dynamic> plaintext,
    Uint8List dek,
    String dekId,
    String objectId,
    int version,
    int blobKind,
  ) {
    final jsonBytes = Uint8List.fromList(utf8.encode(jsonEncode(plaintext)));
    final padded = padPlaintext(jsonBytes);
    final aad = buildAAD(blobKind, dekId, objectId, version);
    final nonceLen = _sodium.crypto.aeadXChaCha20Poly1305IETF.nonceBytes;
    final nonce = _sodium.randombytes.buf(nonceLen); // 24 bytes

    final ciphertext = _withKey(
      dek,
      (secure) => _sodium.crypto.aeadXChaCha20Poly1305IETF.encrypt(
        message: padded,
        additionalData: aad,
        nonce: nonce,
        key: secure,
      ),
    );

    // Build envelope binary
    final dekIdBytes = utf8.encode(dekId.padRight(26, '\x00').substring(0, 26));
    final envelopeLen =
        EnvelopeConstants.headerLen + nonce.length + ciphertext.length;
    final envelope = Uint8List(envelopeLen);

    envelope[0] = EnvelopeConstants.algXChaCha20Poly1305;
    envelope[1] = EnvelopeConstants.schemaVersion;
    envelope[2] = blobKind;
    envelope.setRange(3, 29, dekIdBytes);
    envelope.setRange(29, 53, nonce);
    envelope.setRange(53, envelope.length, ciphertext);

    return envelope;
  }

  void validateEnvelopeHeader(
    Uint8List envelopeBytes, {
    int? expectedBlobKind,
  }) {
    if (envelopeBytes.length < EnvelopeConstants.minEnvelopeLen ||
        envelopeBytes[0] != EnvelopeConstants.algXChaCha20Poly1305 ||
        envelopeBytes[1] != EnvelopeConstants.schemaVersion ||
        (expectedBlobKind != null && envelopeBytes[2] != expectedBlobKind)) {
      throw ArgumentError('Invalid canonical envelope header');
    }
  }

  /// Decrypt an envelope back to a JSON object.
  ///
  /// [dekMap] maps dekId -> decrypted DEK bytes.
  Map<String, dynamic> decryptEnvelope(
    Uint8List envelopeBytes,
    String objectId,
    int version,
    Map<String, Uint8List> dekMap,
  ) {
    validateEnvelopeHeader(envelopeBytes);

    final blobKind = envelopeBytes[2];
    final dekIdRaw = envelopeBytes.sublist(3, 29);
    final dekId = utf8.decode(dekIdRaw).replaceAll('\x00', '');
    final nonce = Uint8List.fromList(envelopeBytes.sublist(29, 53));
    final ciphertext = Uint8List.fromList(envelopeBytes.sublist(53));

    final dek = dekMap[dekId];
    if (dek == null) {
      throw StateError('No DEK for id: $dekId');
    }

    final aad = buildAAD(blobKind, dekId, objectId, version);

    final padded = _withKey(
      dek,
      (secure) => _sodium.crypto.aeadXChaCha20Poly1305IETF.decrypt(
        cipherText: ciphertext,
        additionalData: aad,
        nonce: nonce,
        key: secure,
      ),
    );

    final jsonBytes = unpadPlaintext(Uint8List.fromList(padded));
    return jsonDecode(utf8.decode(jsonBytes)) as Map<String, dynamic>;
  }

  /// DEK id named in an envelope header (bytes 3..29).
  String envelopeDekId(Uint8List envelopeBytes) {
    validateEnvelopeHeader(envelopeBytes);
    return utf8.decode(envelopeBytes.sublist(3, 29)).replaceAll('\x00', '');
  }

  /// DEK id of a canonical entry payload (taken from its meta envelope).
  String entryPayloadDekId(Uint8List payload) {
    final metaLen = ByteData.sublistView(payload).getUint32(0, Endian.big);
    return envelopeDekId(Uint8List.sublistView(payload, 4, 4 + metaLen));
  }

  /// Check if raw bytes are an encrypted envelope (vs legacy plaintext JSON).
  bool isEncryptedEnvelope(Uint8List bytes) {
    return bytes.length >= EnvelopeConstants.minEnvelopeLen &&
        bytes[0] == EnvelopeConstants.algXChaCha20Poly1305 &&
        bytes[1] == EnvelopeConstants.schemaVersion;
  }

  /// Encode an entry as the canonical cross-client wire format
  /// (spec §4.1 + §8.2, matching desktop/web):
  ///   payload = u32be(len(metaEnv)) || metaEnv || dataEnv
  ///   metaEnv = ENTRY_META(blob_kind=2) envelope over {name, tags}
  ///   dataEnv = ENTRY_DATA(blob_kind=3) envelope over {fields, notes?}
  /// Both envelopes share the same dek, dekId, objectId (= entry id) and version.
  Uint8List encryptEntryPayload(
    Map<String, dynamic> metaObj,
    Map<String, dynamic> dataObj,
    Uint8List dek,
    String dekId,
    String objectId,
    int version,
  ) {
    final metaEnv = encryptEnvelope(
      metaObj,
      dek,
      dekId,
      objectId,
      version,
      BlobKind.entryMeta,
    );
    final dataEnv = encryptEnvelope(
      dataObj,
      dek,
      dekId,
      objectId,
      version,
      BlobKind.entryData,
    );
    final payload = Uint8List(4 + metaEnv.length + dataEnv.length);
    ByteData.sublistView(payload).setUint32(0, metaEnv.length, Endian.big);
    payload.setRange(4, 4 + metaEnv.length, metaEnv);
    payload.setRange(4 + metaEnv.length, payload.length, dataEnv);
    return payload;
  }

  /// Decode the canonical two-envelope entry payload into one merged JSON map.
  Map<String, dynamic> decryptEntryPayload(
    Uint8List payload,
    String objectId,
    int version,
    Map<String, Uint8List> dekMap,
  ) {
    final (meta, data) = decryptEntryParts(payload, objectId, version, dekMap);
    return {...meta, ...data};
  }

  /// The meta and data envelopes of a canonical entry payload, apart.
  (Map<String, dynamic>, Map<String, dynamic>) decryptEntryParts(
    Uint8List payload,
    String objectId,
    int version,
    Map<String, Uint8List> dekMap,
  ) {
    if (payload.length < 4) throw ArgumentError('Entry payload too short');
    final metaLen = ByteData.sublistView(payload).getUint32(0, Endian.big);
    if (4 + metaLen > payload.length) {
      throw ArgumentError('Invalid entry meta length');
    }
    final metaEnv = payload.sublist(4, 4 + metaLen);
    final dataEnv = payload.sublist(4 + metaLen);
    return (
      decryptEnvelope(metaEnv, objectId, version, dekMap),
      decryptEnvelope(dataEnv, objectId, version, dekMap),
    );
  }

  /// Detect the canonical two-envelope entry framing: a u32be meta length
  /// prefix followed by an envelope whose first bytes are alg+schema.
  bool isCanonicalEntryPayload(Uint8List bytes) {
    if (bytes.length < 4 + EnvelopeConstants.minEnvelopeLen) return false;
    final metaLen = ByteData.sublistView(bytes).getUint32(0, Endian.big);
    if (4 + metaLen > bytes.length) return false;
    return bytes[4] == EnvelopeConstants.algXChaCha20Poly1305 &&
        bytes[5] == EnvelopeConstants.schemaVersion;
  }

  // ── DEK Wrap/Unwrap ──

  /// Wrap (encrypt) a DEK with KEK, producing an envelope (blob_kind=6).
  ///
  /// [kekDekId] is the synthetic KEK ULID used as dek_id in AAD (matches desktop).
  /// [dekId] is the actual DEK's ULID used as object_id in AAD.
  ///
  /// [version] is the DEK object version (AAD-bound, same as desktop/web);
  /// every password change re-wraps with version + 1.
  Uint8List wrapDEK(
    Uint8List dekBytes,
    String dekId,
    Uint8List kek,
    String kekDekId, {
    int version = 1,
  }) {
    final padded = padPlaintext(dekBytes);
    final aad = buildAAD(BlobKind.dekWrap, kekDekId, dekId, version);
    final nonceLen = _sodium.crypto.aeadXChaCha20Poly1305IETF.nonceBytes;
    final nonce = _sodium.randombytes.buf(nonceLen);

    final ciphertext = _withKey(
      kek,
      (secure) => _sodium.crypto.aeadXChaCha20Poly1305IETF.encrypt(
        message: padded,
        additionalData: aad,
        nonce: nonce,
        key: secure,
      ),
    );

    final kekDekIdPadded = utf8.encode(
      kekDekId.padRight(26, '\x00').substring(0, 26),
    );
    final envelopeLen =
        EnvelopeConstants.headerLen + nonce.length + ciphertext.length;
    final envelope = Uint8List(envelopeLen);

    envelope[0] = EnvelopeConstants.algXChaCha20Poly1305;
    envelope[1] = EnvelopeConstants.schemaVersion;
    envelope[2] = BlobKind.dekWrap;
    envelope.setRange(3, 29, kekDekIdPadded);
    envelope.setRange(29, 53, nonce);
    envelope.setRange(53, envelope.length, ciphertext);

    return envelope;
  }

  /// Unwrap (decrypt) a DEK from its envelope using KEK.
  ///
  /// [dekId] is the actual DEK's ULID (from vault_objects.id), used as
  /// object_id in AAD. The kekDekId is extracted from the envelope header.
  /// Returns the raw DEK bytes.
  Uint8List unwrapDEK(
    Uint8List envelopeBytes,
    Uint8List kek,
    String dekId, {
    int version = 1,
  }) {
    validateEnvelopeHeader(envelopeBytes, expectedBlobKind: BlobKind.dekWrap);

    final kekDekIdRaw = envelopeBytes.sublist(3, 29);
    final kekDekId = utf8.decode(kekDekIdRaw).replaceAll('\x00', '');
    final nonce = Uint8List.fromList(envelopeBytes.sublist(29, 53));
    final ciphertext = Uint8List.fromList(envelopeBytes.sublist(53));

    final aad = buildAAD(BlobKind.dekWrap, kekDekId, dekId, version);

    final padded = _withKey(
      kek,
      (secure) => _sodium.crypto.aeadXChaCha20Poly1305IETF.decrypt(
        cipherText: ciphertext,
        additionalData: aad,
        nonce: nonce,
        key: secure,
      ),
    );

    final dekBytes = unpadPlaintext(Uint8List.fromList(padded));
    return Uint8List.fromList(dekBytes);
  }

  // Capability run 269 (aead.py PRE_ANCHOR_*): the keypair wrap binds no
  // epoch, so a pre-anchor bundle the server kept opens again under a
  // password that opened it then. The anchored bundle (SZACCT02) records each
  // such password state as salt(16) || time, memory, lanes (u32be) ||
  // SHA-256(label || KEK); no client may move the account back to one.
  static const preAnchorEntryLen = 60;
  static const preAnchorMax = 8;

  Uint8List preAnchorCheck(Uint8List kek) =>
      sha256Bytes(Uint8List.fromList([...ascii.encode('sezam-pre-anchor-kek-v1'), ...kek]));

  List<({Uint8List raw, Uint8List salt, int timeCost, int memoryCost, int parallelism, Uint8List check})>
      parsePreAnchor(Uint8List? blob) {
    if (blob == null || blob.isEmpty) return const [];
    final count = blob[0];
    if (count < 1 || count > preAnchorMax || blob.length != 1 + count * preAnchorEntryLen) {
      throw const FormatException('Invalid account keypair pre-anchor states');
    }
    return [
      for (var i = 0; i < count; i++)
        () {
          final raw = Uint8List.fromList(
            blob.sublist(1 + i * preAnchorEntryLen, 1 + (i + 1) * preAnchorEntryLen),
          );
          final view = ByteData.sublistView(raw);
          final entry = (
            raw: raw,
            salt: Uint8List.fromList(raw.sublist(0, 16)),
            timeCost: view.getUint32(16, Endian.big),
            memoryCost: view.getUint32(20, Endian.big),
            parallelism: view.getUint32(24, Endian.big),
            check: Uint8List.fromList(raw.sublist(28)),
          );
          if (entry.timeCost < 1 || entry.timeCost > 20 || entry.memoryCost < 8192 ||
              entry.memoryCost > 1048576 || entry.parallelism < 1 || entry.parallelism > 16) {
            throw const FormatException('Invalid account keypair pre-anchor KDF params');
          }
          return entry;
        }(),
    ];
  }

  /// [kept] plus the states only [other] records, newest last (never forgets one).
  Uint8List? mergePreAnchor(Uint8List? kept, Uint8List? other) {
    final raws = parsePreAnchor(kept).map((e) => bytesToHex(e.raw)).toList();
    for (final e in parsePreAnchor(other)) {
      final hex = bytesToHex(e.raw);
      if (!raws.contains(hex)) raws.add(hex);
    }
    final last = raws.length > preAnchorMax ? raws.sublist(raws.length - preAnchorMax) : raws;
    if (last.isEmpty) return null;
    return Uint8List.fromList([last.length, for (final hex in last) ...hexToBytes(hex)]);
  }

  Uint8List? addPreAnchor(Uint8List? blob, Uint8List salt, int timeCost, int memoryCost,
      int parallelism, Uint8List kek) {
    if (salt.length != 16) throw const FormatException('Invalid pre-anchor salt');
    final one = Uint8List(1 + preAnchorEntryLen);
    one[0] = 1;
    one.setRange(1, 17, salt);
    final view = ByteData.sublistView(one);
    view.setUint32(17, timeCost, Endian.big);
    view.setUint32(21, memoryCost, Endian.big);
    view.setUint32(25, parallelism, Endian.big);
    one.setRange(29, 61, preAnchorCheck(kek));
    return mergePreAnchor(blob, one);
  }

  /// Does [password] (any of its KDF forms) derive a recorded pre-anchor KEK?
  Future<bool> passwordReopensPreAnchor(String password, Uint8List? blob) async {
    for (final e in parsePreAnchor(blob)) {
      for (final form in passwordForms(password)) {
        final derived = await deriveBackupKEK(form, e.salt,
            timeCost: e.timeCost, memoryCost: e.memoryCost, parallelism: e.parallelism, exact: true);
        try {
          if (bytesToHex(preAnchorCheck(Uint8List.sublistView(derived, 0, 32))) == bytesToHex(e.check)) {
            return true;
          }
        } finally {
          zeroize(derived);
        }
      }
    }
    return false;
  }

  // SZACCT01 || signing_seed(32) || encryption_sk(32) || confirmed genesis(32);
  // with recorded pre-anchor password states SZACCT02 || the same || states.
  // Callers establish trust independently; a legacy bundle has no anchor.
  Uint8List encodeAccountKeypair(Uint8List keys, String confirmedGenesis,
      [Uint8List? preAnchor]) {
    if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(confirmedGenesis) ||
        (keys.length != 64 && keys.length != 96)) {
      throw const FormatException(
        'Invalid account keypair keys or confirmed genesis',
      );
    }
    final states = preAnchor != null && preAnchor.isNotEmpty ? preAnchor : null;
    parsePreAnchor(states);
    final decoded = decodeAccountKeypair(keys);
    try {
      return Uint8List.fromList([
        ...ascii.encode(states != null ? 'SZACCT02' : 'SZACCT01'),
        ...decoded.keypairData,
        ...hexToBytes(confirmedGenesis),
        ...?states,
      ]);
    } finally {
      zeroize(decoded.keypairData);
    }
  }

  ({Uint8List keypairData, String? confirmedGenesis, Uint8List? preAnchor}) decodeAccountKeypair(
    Uint8List payload,
  ) {
    if (payload.length > 104 &&
        utf8.decode(payload.sublist(0, 8), allowMalformed: true) == 'SZACCT02') {
      final preAnchor = Uint8List.fromList(payload.sublist(104));
      if (parsePreAnchor(preAnchor).isEmpty) {
        throw const FormatException('Invalid account keypair pre-anchor states');
      }
      return (
        keypairData: Uint8List.fromList(payload.sublist(8, 72)),
        confirmedGenesis: bytesToHex(payload.sublist(72, 104)),
        preAnchor: preAnchor,
      );
    }
    if (payload.length == 104) {
      if (utf8.decode(payload.sublist(0, 8), allowMalformed: true) !=
          'SZACCT01') {
        throw const FormatException('Invalid account keypair bundle version');
      }
      return (
        keypairData: Uint8List.fromList(payload.sublist(8, 72)),
        confirmedGenesis: bytesToHex(payload.sublist(72)),
        preAnchor: null,
      );
    }
    if (payload.length == 64) {
      return (keypairData: Uint8List.fromList(payload), confirmedGenesis: null, preAnchor: null);
    }
    if (payload.length == 96) {
      final pk = signingPublicKeyFromSeed(
        Uint8List.sublistView(payload, 0, 32),
      );
      if (bytesToHex(pk) != bytesToHex(payload.sublist(32, 64))) {
        throw const FormatException('Invalid account keypair public key');
      }
      return (
        keypairData: Uint8List.fromList([
          ...payload.sublist(0, 32),
          ...payload.sublist(64),
        ]),
        confirmedGenesis: null,
        preAnchor: null,
      );
    }
    throw const FormatException('Invalid account keypair payload length');
  }

  Uint8List wrapAccountKeypair(
    Uint8List keys,
    String confirmedGenesis,
    Uint8List kek,
    String kekDekId,
    String userObjectId, [
    Uint8List? preAnchor,
  ]) {
    if (![
      kekDekId,
      userObjectId,
    ].every((id) => RegExp(r'^[0-9A-HJKMNP-TV-Z]{26}$').hasMatch(id))) {
      throw const FormatException('Invalid account keypair ID');
    }
    final payload = encodeAccountKeypair(keys, confirmedGenesis, preAnchor);
    try {
      return wrapKeypair(payload, kek, kekDekId, userObjectId);
    } finally {
      zeroize(payload);
    }
  }

  ({Uint8List keypairData, String? confirmedGenesis, Uint8List? preAnchor}) openAccountKeypair(
    Uint8List envelope,
    Uint8List kek,
    String userObjectId,
  ) {
    if (envelope.length < 69 ||
        ![
          userObjectId,
          utf8.decode(envelope.sublist(3, 29), allowMalformed: true),
        ].every((id) => RegExp(r'^[0-9A-HJKMNP-TV-Z]{26}$').hasMatch(id))) {
      throw const FormatException('Invalid account keypair envelope');
    }
    final payload = unwrapKeypair(envelope, kek, userObjectId);
    try {
      return decodeAccountKeypair(payload);
    } finally {
      zeroize(payload);
    }
  }

  // ── Keypair Wrap/Unwrap (blob_kind=7) ──

  /// Encrypt keypair bytes with KEK in AEAD envelope format.
  ///
  /// [kekDekId] is the synthetic KEK ULID used as dek_id in AAD.
  /// [userObjectId] is the user's ULID used as object_id in AAD.
  Uint8List wrapKeypair(
    Uint8List keypairBytes,
    Uint8List kek,
    String kekDekId,
    String userObjectId,
  ) {
    final jsonBytes = keypairBytes;
    final padded = padPlaintext(jsonBytes);
    final aad = buildAAD(BlobKind.keypairWrap, kekDekId, userObjectId, 1);
    final nonceLen = _sodium.crypto.aeadXChaCha20Poly1305IETF.nonceBytes;
    final nonce = _sodium.randombytes.buf(nonceLen);

    final ciphertext = _withKey(
      kek,
      (secure) => _sodium.crypto.aeadXChaCha20Poly1305IETF.encrypt(
        message: padded,
        additionalData: aad,
        nonce: nonce,
        key: secure,
      ),
    );

    final kekDekIdPadded = utf8.encode(
      kekDekId.padRight(26, '\x00').substring(0, 26),
    );
    final envelopeLen =
        EnvelopeConstants.headerLen + nonce.length + ciphertext.length;
    final envelope = Uint8List(envelopeLen);
    envelope[0] = EnvelopeConstants.algXChaCha20Poly1305;
    envelope[1] = EnvelopeConstants.schemaVersion;
    envelope[2] = BlobKind.keypairWrap;
    envelope.setRange(3, 29, kekDekIdPadded);
    envelope.setRange(29, 53, nonce);
    envelope.setRange(53, envelope.length, ciphertext);

    return envelope;
  }

  /// Decrypt keypair from AEAD envelope.
  ///
  /// [userObjectId] is the user's ULID used as object_id in AAD.
  /// The kekDekId is extracted from the envelope header (bytes 3-29).
  Uint8List unwrapKeypair(
    Uint8List envelopeBytes,
    Uint8List kek,
    String userObjectId,
  ) {
    validateEnvelopeHeader(
      envelopeBytes,
      expectedBlobKind: BlobKind.keypairWrap,
    );

    final kekDekIdRaw = envelopeBytes.sublist(3, 29);
    final kekDekId = utf8.decode(kekDekIdRaw).replaceAll('\x00', '');
    final nonce = Uint8List.fromList(envelopeBytes.sublist(29, 53));
    final ciphertext = Uint8List.fromList(envelopeBytes.sublist(53));

    // Build AAD matching what was used for encryption
    final aad = buildAAD(BlobKind.keypairWrap, kekDekId, userObjectId, 1);

    final padded = _withKey(
      kek,
      (secure) => _sodium.crypto.aeadXChaCha20Poly1305IETF.decrypt(
        cipherText: ciphertext,
        additionalData: aad,
        nonce: nonce,
        key: secure,
      ),
    );

    return unpadPlaintext(Uint8List.fromList(padded));
  }

  /// Unwrap an account keypair as signing_sk(64) || encryption_sk(32). A
  /// desktop-created account stores signing_seed(32) || encryption_sk(32) on
  /// the server; it is expanded here so every caller sees the 96-byte form.
  Uint8List unwrapAccountKeypair(
    Uint8List envelopeBytes,
    Uint8List kek,
    String userObjectId,
  ) {
    final keypairBytes = unwrapKeypair(envelopeBytes, kek, userObjectId);
    if (keypairBytes.length != 64) return keypairBytes;
    try {
      return expandDesktopKeypair(
        keypairBytes,
        signingPublicKeyFromSeed(Uint8List.sublistView(keypairBytes, 0, 32)),
      );
    } finally {
      zeroize(keypairBytes);
    }
  }

  /// Rebind a keypair envelope from a provisional to a canonical user object ID.
  Uint8List rewrapKeypairObjectId(
    Uint8List envelopeBytes,
    Uint8List kek,
    String currentUserObjectId,
    String canonicalUserObjectId,
  ) {
    final keypairBytes = unwrapKeypair(envelopeBytes, kek, currentUserObjectId);
    final kekDekId = utf8
        .decode(envelopeBytes.sublist(3, 29))
        .replaceAll('\x00', '');
    try {
      return wrapKeypair(keypairBytes, kek, kekDekId, canonicalUserObjectId);
    } finally {
      zeroize(keypairBytes);
    }
  }

  // ── Ed25519 ──

  /// Generate a new Ed25519 keypair.
  /// Returns (signingSecretKey: 64 bytes, signingPublicKey: 32 bytes).
  ({Uint8List sk, Uint8List pk}) generateSigningKeypair() {
    final kp = _sodium.crypto.sign.keyPair();
    final result = (
      sk: Uint8List.fromList(kp.secretKey.extractBytes()),
      pk: Uint8List.fromList(kp.publicKey),
    );
    kp.dispose();
    return result;
  }

  /// Derive an Ed25519 public key from its 32-byte seed.
  Uint8List signingPublicKeyFromSeed(Uint8List seed) {
    final kp = _withKey(
      seed,
      (secure) => _sodium.crypto.sign.seedKeyPair(secure),
    );
    final publicKey = Uint8List.fromList(kp.publicKey);
    kp.dispose();
    return publicKey;
  }

  /// Generate a new X25519 keypair for key exchange.
  /// Returns (secretKey: 32 bytes, publicKey: 32 bytes).
  ({Uint8List sk, Uint8List pk}) generateEncryptionKeypair() {
    final kp = _sodium.crypto.box.keyPair();
    final result = (
      sk: Uint8List.fromList(kp.secretKey.extractBytes()),
      pk: Uint8List.fromList(kp.publicKey),
    );
    kp.dispose();
    return result;
  }

  /// Desktop access envelope: 24-byte nonce followed by crypto_box ciphertext.
  Uint8List openAccessEnvelope(
    Uint8List payload,
    Uint8List recipientSk,
    Uint8List senderPk,
  ) {
    if (payload.length != 24 + 16 + 32)
      throw const FormatException('Invalid access envelope');
    return _withKey(
      recipientSk,
      (key) => _sodium.crypto.box.openEasy(
        cipherText: Uint8List.sublistView(payload, 24),
        nonce: Uint8List.sublistView(payload, 0, 24),
        publicKey: senderPk,
        secretKey: key,
      ),
    );
  }

  /// Sign a challenge with Ed25519 secret key.
  /// Returns 64-byte detached signature.
  Uint8List signChallenge(Uint8List challenge, Uint8List signingSecretKey) {
    return Uint8List.fromList(
      _withKey(
        signingSecretKey,
        (secure) =>
            _sodium.crypto.sign.detached(message: challenge, secretKey: secure),
      ),
    );
  }

  /// Must match server/app/auth.py:AUTH_SIGNATURE_CONTEXT.
  static final Uint8List authSignatureContext = Uint8List.fromList(
    utf8.encode('sezam-auth-challenge-signature-v1'),
  );
  static const int authChallengeLength = 40;

  /// Answer a server login challenge. The identity key signs only
  /// context || challenge, and only a challenge of the server's fixed layout,
  /// so a server cannot have it sign bytes of its choosing (a sync object, a
  /// policy) under the guise of a login.
  Uint8List signAuthChallenge(Uint8List challenge, Uint8List signingSecretKey) {
    if (challenge.length != authChallengeLength) {
      throw ArgumentError(
        'Server sent a malformed login challenge (${challenge.length} bytes)',
      );
    }
    final message = Uint8List(authSignatureContext.length + challenge.length)
      ..setAll(0, authSignatureContext)
      ..setAll(authSignatureContext.length, challenge);
    return signChallenge(message, signingSecretKey);
  }

  /// Verify an Ed25519 detached signature.
  /// Returns true if valid, false otherwise.
  bool verifyDetached({
    required Uint8List signature,
    required Uint8List message,
    required Uint8List publicKey,
  }) {
    return _sodium.crypto.sign.verifyDetached(
      message: message,
      signature: signature,
      publicKey: publicKey,
    );
  }

  /// Derive X25519 public key from secret key via scalar multiplication.
  Uint8List scalarmultBase(Uint8List secretKey) {
    return Uint8List.fromList(
      _withKey(
        secretKey,
        (secure) => _sodium.crypto.scalarmult.base(n: secure),
      ),
    );
  }

  /// Build canonical signed data for a sync object (spec 8.2).
  ///
  /// Format:
  ///   id(26B) || u8(len(object_type)) || object_type
  ///   || parent_ref_or_zero(26B) || target_user_id_or_zero(26B)
  ///   || u8(is_deleted) || u32be(version) || payload_hash(32B)
  Uint8List buildSyncSignatureData({
    required String id,
    required String objectType,
    required String? parentRef,
    required String? targetUserId,
    required int isDeleted,
    required int version,
    required String payloadHashHex,
  }) {
    final idBytes = _padToLength(utf8.encode(id), 26);
    final otBytes = utf8.encode(objectType);
    final parentBytes = parentRef != null
        ? _padToLength(utf8.encode(parentRef), 26)
        : Uint8List(26);
    final targetBytes = targetUserId != null
        ? _padToLength(utf8.encode(targetUserId), 26)
        : Uint8List(26);
    final payloadHash = _hexToBytes(payloadHashHex);

    final versionBytes = ByteData(4)..setUint32(0, version, Endian.big);

    // Total: 26 + 1 + otBytes.length + 26 + 26 + 1 + 4 + 32
    final result = Uint8List(26 + 1 + otBytes.length + 26 + 26 + 1 + 4 + 32);
    var offset = 0;
    result.setRange(offset, offset + 26, idBytes);
    offset += 26;
    result[offset] = otBytes.length;
    offset += 1;
    result.setRange(offset, offset + otBytes.length, otBytes);
    offset += otBytes.length;
    result.setRange(offset, offset + 26, parentBytes);
    offset += 26;
    result.setRange(offset, offset + 26, targetBytes);
    offset += 26;
    result[offset] = isDeleted;
    offset += 1;
    result.setRange(offset, offset + 4, versionBytes.buffer.asUint8List());
    offset += 4;
    result.setRange(offset, offset + 32, payloadHash);

    return result;
  }

  /// Sign a sync object with Ed25519.
  Uint8List signSyncObject({
    required String id,
    required String objectType,
    required String? parentRef,
    required String? targetUserId,
    required int isDeleted,
    required int version,
    required String payloadHashHex,
    required Uint8List signingSecretKey,
  }) {
    final data = buildSyncSignatureData(
      id: id,
      objectType: objectType,
      parentRef: parentRef,
      targetUserId: targetUserId,
      isDeleted: isDeleted,
      version: version,
      payloadHashHex: payloadHashHex,
    );
    return Uint8List.fromList(
      _withKey(
        signingSecretKey,
        (secure) =>
            _sodium.crypto.sign.detached(message: data, secretKey: secure),
      ),
    );
  }

  // ── Fingerprint ──

  /// Compute SHA-256 fingerprint of signing_pk || encryption_pk.
  /// Returns hex string.
  String computeFingerprint(Uint8List signingPk, Uint8List encryptionPk) {
    final combined = Uint8List(signingPk.length + encryptionPk.length);
    combined.setAll(0, signingPk);
    combined.setAll(signingPk.length, encryptionPk);
    final hash = crypto_pkg.sha256.convert(combined);
    return hash.toString();
  }

  // ── Random Bytes ──

  /// Generate cryptographically secure random bytes.
  Uint8List randomBytes(int length) {
    return _sodium.randombytes.buf(length);
  }

  /// Generate a 32-byte random DEK.
  Uint8List generateDEK() {
    return _sodium.randombytes.buf(32);
  }

  // ── AEAD helpers for direct use (e.g. share service) ──

  /// Encrypt with XChaCha20-Poly1305 AEAD (raw, no envelope).
  /// Returns ciphertext bytes.
  Uint8List aeadEncrypt({
    required Uint8List plaintext,
    Uint8List? additionalData,
    required Uint8List nonce,
    required Uint8List key,
  }) {
    return Uint8List.fromList(
      _withKey(
        key,
        (secure) => _sodium.crypto.aeadXChaCha20Poly1305IETF.encrypt(
          message: plaintext,
          additionalData: additionalData,
          nonce: nonce,
          key: secure,
        ),
      ),
    );
  }

  /// Decrypt with XChaCha20-Poly1305 AEAD (raw, no envelope).
  /// Returns plaintext bytes.
  Uint8List aeadDecrypt({
    required Uint8List ciphertext,
    Uint8List? additionalData,
    required Uint8List nonce,
    required Uint8List key,
  }) {
    return Uint8List.fromList(
      _withKey(
        key,
        (secure) => _sodium.crypto.aeadXChaCha20Poly1305IETF.decrypt(
          cipherText: ciphertext,
          additionalData: additionalData,
          nonce: nonce,
          key: secure,
        ),
      ),
    );
  }

  /// Runs [use] with [bytes] in a libsodium SecureKey that is zeroed and freed
  /// right after, instead of lingering in sodium_malloc'd memory until (and
  /// unless) the finalizer runs.
  T _withKey<T>(Uint8List bytes, T Function(SecureKey secure) use) {
    final secure = SecureKey.fromList(_sodium, bytes);
    try {
      return use(secure);
    } finally {
      secure.dispose();
    }
  }

  /// Get the nonce size for XChaCha20-Poly1305 AEAD.
  int get aeadNonceBytes => _sodium.crypto.aeadXChaCha20Poly1305IETF.nonceBytes;

  // ── SHA-256 Hash ──

  /// Compute SHA-256 hash of data, returning raw bytes.
  Uint8List sha256Bytes(Uint8List data) {
    return Uint8List.fromList(crypto_pkg.sha256.convert(data).bytes);
  }

  /// Compute SHA-256 hash of data, returning hex string.
  String sha256Hex(Uint8List data) {
    return bytesToHex(sha256Bytes(data));
  }

  // ── Helpers ──

  Uint8List _padToLength(List<int> input, int length) {
    final result = Uint8List(length);
    final copyLen = input.length < length ? input.length : length;
    result.setRange(0, copyLen, input);
    return result;
  }

  Uint8List _hexToBytes(String hex) {
    final length = hex.length ~/ 2;
    final bytes = Uint8List(length);
    for (var i = 0; i < length; i++) {
      bytes[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return bytes;
  }

  /// Zeroize a byte array (overwrite with zeros).
  void zeroize(Uint8List bytes) {
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = 0;
    }
  }
}

/// signing_seed(32) || encryption_sk(32) -> signing_seed || signing_pk ||
/// encryption_sk, the libsodium Ed25519 secret key layout.
Uint8List expandDesktopKeypair(Uint8List desktopPayload, Uint8List signingPk) {
  if (desktopPayload.length != 64 || signingPk.length != 32) {
    throw const FormatException('Invalid desktop keypair payload');
  }
  return Uint8List(96)
    ..setRange(0, 32, desktopPayload.sublist(0, 32))
    ..setRange(32, 64, signingPk)
    ..setRange(64, 96, desktopPayload.sublist(32, 64));
}

/// Utility: convert bytes to hex string.
String bytesToHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

/// Utility: convert hex string to bytes.
Uint8List hexToBytes(String hex) {
  final length = hex.length ~/ 2;
  final bytes = Uint8List(length);
  for (var i = 0; i < length; i++) {
    bytes[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return bytes;
}

// Sezam ShareService — secure share link creation and consumption.
//
// Flow:
//   1. Encrypt entry JSON with random 32-byte key (XChaCha20-Poly1305)
//   2. Upload encrypted blob to POST /api/share
//   3. Return URL with decryption key in fragment (never sent to server)
//   4. Consumer fetches blob, decrypts with key from fragment

import 'dart:convert';
import 'dart:typed_data';

import 'package:dargon2_flutter/dargon2_flutter.dart';
import 'package:http/http.dart' as http;

import 'crypto_service.dart';
import 'timeout_client.dart';

typedef ShareRandomBytes = Uint8List Function(int length);
typedef SharePinHasher = Future<String> Function(String pin, Uint8List salt);
typedef ShareArgon2Hasher =
    Future<String> Function({
      required String pin,
      required Uint8List salt,
      required int iterations,
      required int memory,
      required int parallelism,
      required int length,
    });
typedef ShareEncrypt =
    Uint8List Function({
      required Uint8List plaintext,
      required Uint8List additionalData,
      required Uint8List nonce,
      required Uint8List key,
    });
typedef ShareDecrypt =
    Uint8List Function({
      required Uint8List ciphertext,
      required Uint8List additionalData,
      required Uint8List nonce,
      required Uint8List key,
    });

Future<String> deriveSharePinHash(
  String pin,
  Uint8List salt, {
  ShareArgon2Hasher? hasher,
}) async {
  const iterations = 3;
  const memory = 65536;
  const parallelism = 4;
  const length = 32;
  if (hasher != null) {
    return hasher(
      pin: pin,
      salt: salt,
      iterations: iterations,
      memory: memory,
      parallelism: parallelism,
      length: length,
    );
  }
  final result = await argon2.hashPasswordString(
    pin,
    salt: Salt(salt),
    iterations: iterations,
    memory: memory,
    parallelism: parallelism,
    length: length,
    type: Argon2Type.id,
    version: Argon2Version.V13,
  );
  return result.encodedString;
}

class ShareService {
  static final ShareService _instance = ShareService._(
    TimeoutClient(http.Client()),
  );
  factory ShareService() => _instance;
  ShareService._(this._client)
    : _randomBytes = null,
      _pinHasher = null,
      _encrypt = null,
      _decrypt = null,
      _nonceBytes = null;
  ShareService.withClient(
    this._client, {
    ShareRandomBytes? randomBytes,
    SharePinHasher? pinHasher,
    ShareEncrypt? encrypt,
    ShareDecrypt? decrypt,
    int? nonceBytes,
  }) : _randomBytes = randomBytes,
       _pinHasher = pinHasher,
       _encrypt = encrypt,
       _decrypt = decrypt,
       _nonceBytes = nonceBytes;

  final http.Client _client;
  final ShareRandomBytes? _randomBytes;
  final SharePinHasher? _pinHasher;
  final ShareEncrypt? _encrypt;
  final ShareDecrypt? _decrypt;
  final int? _nonceBytes;
  final _crypto = CryptoService();

  /// Create a share link for an entry.
  ///
  /// Encrypts entry JSON with a random 32-byte key using XChaCha20-Poly1305,
  /// uploads the ciphertext to POST /api/share, and returns a URL with
  /// the decryption key in the fragment (never sent to server).
  ///
  /// [entry] — the decrypted entry data as a JSON-serializable map
  /// [serverUrl] — base server URL
  /// [token] — JWT auth token
  /// [expiryMinutes] — link expiration in minutes (default 24 hours)
  /// [maxViews] — max number of views: 1, 3, or 10 (default 1)
  /// [pin] — optional PIN, hashed locally with the server Argon2id policy
  /// [notifyOnView] — request an owner notification for each successful view
  Future<ShareResult> createShareLink({
    required Map<String, dynamic> entry,
    required String serverUrl,
    required String token,
    int expiryMinutes = 1440,
    int maxViews = 1,
    String? pin,
    bool notifyOnView = true,
  }) async {
    if (!const {1, 3, 10}.contains(maxViews)) {
      throw ArgumentError.value(maxViews, 'maxViews', 'must be 1, 3, or 10');
    }
    if (pin != null && (pin.isEmpty || pin.length > 128)) {
      throw ArgumentError.value(pin, 'pin', 'must contain 1 to 128 characters');
    }

    // 1. Generate the encryption key and 256-bit ID before encryption.
    final shareKey = _randomBytes?.call(32) ?? _crypto.randomBytes(32);
    final rawShareId = _randomBytes?.call(32) ?? _crypto.randomBytes(32);
    final shareId = _base64UrlNoPadding(rawShareId);

    // 2. Encrypt entry JSON with the share ID bound as AAD (spec 6.1).
    // Padded so the blob tells only its size class (review 18c300f R16-L3).
    final plaintext = padJson(utf8.encode(jsonEncode(entry)));
    final nonceLength = _nonceBytes ?? _crypto.aeadNonceBytes;
    final nonce =
        _randomBytes?.call(nonceLength) ?? _crypto.randomBytes(nonceLength);
    final additionalData = buildShareAad(rawShareId);

    final ciphertext =
        _encrypt?.call(
          plaintext: plaintext,
          additionalData: additionalData,
          nonce: nonce,
          key: shareKey,
        ) ??
        _crypto.aeadEncrypt(
          plaintext: plaintext,
          additionalData: additionalData,
          nonce: nonce,
          key: shareKey,
        );

    // 3. Build blob: nonce(24) + ciphertext
    final blob = Uint8List(nonce.length + ciphertext.length);
    blob.setRange(0, nonce.length, nonce);
    blob.setRange(nonce.length, blob.length, ciphertext);

    // 4. Upload to server
    final baseUrl = serverUrl.endsWith('/')
        ? serverUrl.substring(0, serverUrl.length - 1)
        : serverUrl;

    final expiresAt =
        DateTime.now().millisecondsSinceEpoch + expiryMinutes * 60 * 1000;
    String? pinHash;
    if (pin != null) {
      final salt = _randomBytes?.call(16) ?? _crypto.randomBytes(16);
      pinHash =
          await (_pinHasher?.call(pin, salt) ?? deriveSharePinHash(pin, salt));
    }
    final requestBody = <String, dynamic>{
      'id': shareId,
      'encrypted_blob': base64Encode(blob),
      'expires_at': expiresAt,
      'max_views': maxViews,
      'notify_on_view': notifyOnView,
    };
    if (pinHash != null) requestBody['pin_hash'] = pinHash;

    final response = await _client.post(
      Uri.parse('$baseUrl/api/share'),
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer $token',
      },
      body: jsonEncode(requestBody),
    );

    if (response.statusCode < 200 || response.statusCode >= 300) {
      final detail = _parseError(response);
      throw ShareException('Failed to create share: $detail');
    }

    final data = jsonDecode(response.body) as Map<String, dynamic>;
    if (data['id'] != shareId) {
      throw const ShareException('Server returned a different share ID');
    }

    // 5. Build URL with a base64url key fragment (never sent to server).
    final keyBase64 = _base64UrlNoPadding(shareKey);
    final shareUrl = '$baseUrl/s/$shareId#$keyBase64';

    return ShareResult(
      shareId: shareId,
      shareUrl: shareUrl,
      expiryMinutes: expiryMinutes,
      maxViews: maxViews,
    );
  }

  /// Consume a share link — fetch the encrypted blob and decrypt it.
  ///
  /// [shareUrl] — the full share URL including fragment with key
  /// [pin] — optional PIN if the share is PIN-protected
  Future<Map<String, dynamic>> consumeShareLink({
    required String shareUrl,
    String? pin,
  }) async {
    // 1. Parse URL and extract key from fragment
    final uri = Uri.parse(shareUrl);
    final fragment = uri.fragment;
    if (fragment.isEmpty) {
      throw ShareException('Invalid share URL: missing decryption key');
    }
    final shareKey = _decodeBase64UrlNoPadding(fragment, 'decryption key');
    if (shareKey.length != 32) {
      throw const ShareException('Invalid share URL: bad key length');
    }

    // Extract and decode the ID used to rebuild the encryption AAD.
    final pathSegments = uri.pathSegments;
    if (pathSegments.length < 2) {
      throw const ShareException('Invalid share URL: missing share ID');
    }
    final shareId = pathSegments.last;
    final rawShareId = _decodeBase64UrlNoPadding(shareId, 'share ID');
    if (rawShareId.length != 32) {
      throw const ShareException('Invalid share URL: bad share ID length');
    }

    // 2. Fetch encrypted blob from server
    final baseUrl =
        '${uri.scheme}://${uri.host}${uri.hasPort ? ':${uri.port}' : ''}';

    final body = <String, dynamic>{};
    if (pin != null && pin.isNotEmpty) {
      body['pin'] = pin;
    }

    final response = await _client.post(
      Uri.parse('$baseUrl/api/share/$shareId'),
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: jsonEncode(body),
    );

    if (response.statusCode < 200 || response.statusCode >= 300) {
      final detail = _parseError(response);
      throw ShareException('Failed to fetch share: $detail');
    }

    final data = jsonDecode(response.body) as Map<String, dynamic>;
    final blobBase64 = data['encrypted_blob'] as String;
    final blob = base64Decode(blobBase64);

    // 3. Decrypt: nonce(24) + ciphertext
    final nonceLength = _nonceBytes ?? _crypto.aeadNonceBytes;
    if (blob.length <= nonceLength) {
      throw const ShareException('Invalid share blob: too short');
    }

    final nonce = Uint8List.fromList(blob.sublist(0, nonceLength));
    final ciphertext = Uint8List.fromList(blob.sublist(nonceLength));
    final additionalData = buildShareAad(rawShareId);

    final plaintext =
        _decrypt?.call(
          ciphertext: ciphertext,
          additionalData: additionalData,
          nonce: nonce,
          key: shareKey,
        ) ??
        _crypto.aeadDecrypt(
          ciphertext: ciphertext,
          additionalData: additionalData,
          nonce: nonce,
          key: shareKey,
        );

    return jsonDecode(utf8.decode(plaintext)) as Map<String, dynamic>;
  }

  /// List all active shares.
  ///
  /// GET /api/shares
  Future<List<Map<String, dynamic>>> listShares({
    required String serverUrl,
    required String token,
  }) async {
    final baseUrl = serverUrl.endsWith('/')
        ? serverUrl.substring(0, serverUrl.length - 1)
        : serverUrl;

    final response = await _client.get(
      Uri.parse('$baseUrl/api/shares'),
      headers: {'Accept': 'application/json', 'Authorization': 'Bearer $token'},
    );

    if (response.statusCode < 200 || response.statusCode >= 300) {
      final detail = _parseError(response);
      throw ShareException('Failed to list shares: $detail');
    }

    final data = jsonDecode(response.body);
    if (data is List) {
      return data.cast<Map<String, dynamic>>();
    }
    final shares = (data as Map<String, dynamic>)['shares'] as List?;
    return shares?.cast<Map<String, dynamic>>() ?? [];
  }

  /// Revoke (delete) a share.
  ///
  /// DELETE /api/share/:id
  Future<void> revokeShare({
    required String shareId,
    required String serverUrl,
    required String token,
  }) async {
    final baseUrl = serverUrl.endsWith('/')
        ? serverUrl.substring(0, serverUrl.length - 1)
        : serverUrl;

    final response = await _client.delete(
      Uri.parse('$baseUrl/api/share/$shareId'),
      headers: {'Accept': 'application/json', 'Authorization': 'Bearer $token'},
    );

    if (response.statusCode < 200 || response.statusCode >= 300) {
      final detail = _parseError(response);
      throw ShareException('Failed to revoke share: $detail');
    }
  }

  static Uint8List buildShareAad(Uint8List rawShareId) {
    if (rawShareId.length != 32) {
      throw ArgumentError.value(
        rawShareId.length,
        'rawShareId',
        'must be 32 bytes',
      );
    }
    final aad = Uint8List(39);
    aad.setRange(0, 3, const [1, 1, 3]);
    aad.setRange(3, 35, rawShareId);
    ByteData.sublistView(aad, 35, 39).setUint32(0, 1, Endian.big);
    return aad;
  }

  static String _base64UrlNoPadding(Uint8List value) =>
      base64UrlEncode(value).replaceAll('=', '');

  static Uint8List _decodeBase64UrlNoPadding(String value, String label) {
    try {
      final padded = value.padRight((value.length + 3) ~/ 4 * 4, '=');
      final decoded = Uint8List.fromList(base64Url.decode(padded));
      if (_base64UrlNoPadding(decoded) != value) {
        throw const FormatException('non-canonical base64url');
      }
      return decoded;
    } on FormatException {
      throw ShareException('Invalid share URL: bad $label encoding');
    }
  }

  String _parseError(http.Response response) {
    try {
      final body = jsonDecode(response.body);
      return body['detail']?.toString() ?? '${response.statusCode}';
    } catch (_) {
      return '${response.statusCode}: ${response.body}';
    }
  }
}

class ShareResult {
  final String shareId;
  final String shareUrl;
  final int expiryMinutes;
  final int maxViews;

  const ShareResult({
    required this.shareId,
    required this.shareUrl,
    required this.expiryMinutes,
    required this.maxViews,
  });
}

class ShareException implements Exception {
  final String message;
  const ShareException(this.message);

  @override
  String toString() => 'ShareException: $message';
}

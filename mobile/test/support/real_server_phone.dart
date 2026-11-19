// Shared by the phone tests the Python suite runs against a real server
// (tests/test_cross_client_password_change.py): `flutter test` has no
// libsodium/dargon2/sqflite plugins, so the libsodium of the sodium_libs
// package is loaded directly, Argon2id is node's crypto.argon2Sync (same
// algorithm, any parallelism) and SQLite runs through sqflite_common_ffi.

import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:sezam_mobile/services/crypto_service.dart';
import 'package:sezam_mobile/services/vault_service.dart';
import 'package:sodium/sodium_sumo.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

final env = Platform.environment;

/// Real HTTP to the test server, counting requests in flight (background
/// syncs settle before the next step) and failing a chosen path once.
class Net extends http.BaseClient {
  final _inner = IOClient(HttpClient());
  int _inFlight = 0;
  DateTime _last = DateTime.now();
  String? failPath;

  /// A request to this path never answers (an app killed while waiting);
  /// [hung] completes when it is sent.
  String? hangPath;
  final hung = Completer<void>();
  final paths = <String>[];

  /// The next POST to this path reaches the server, its answer never comes.
  String? dropResponsePath;

  /// Called with each request's path as it is sent (e.g. to lock the app
  /// while a flow waits on the network).
  void Function(String path)? onSend;

  /// The next request to this path gets [refuseStatus] without reaching the
  /// server (e.g. a resume that came before an earlier request landed).
  String? refusePath;
  int refuseStatus = 401;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    paths.add(request.url.path);
    onSend?.call(request.url.path);
    if (refusePath != null && request.url.path == refusePath) {
      refusePath = null;
      return http.StreamedResponse(
        Stream.value(utf8.encode('{"detail":"refused (test)"}')), refuseStatus,
      );
    }
    if (failPath != null && request.url.path == failPath) {
      failPath = null;
      throw const SocketException('network down (test)');
    }
    if (hangPath != null && request.url.path == hangPath) {
      hangPath = null;
      hung.complete();
      return Completer<http.StreamedResponse>().future;
    }
    _inFlight++;
    try {
      final response = await _inner.send(request);
      if (dropResponsePath != null &&
          request.method == 'POST' &&
          request.url.path == dropResponsePath) {
        // The server handled it; the answer is lost on the way back.
        dropResponsePath = null;
        await response.stream.drain<void>();
        throw const SocketException('response lost (test)');
      }
      return response;
    } finally {
      _inFlight--;
      _last = DateTime.now();
    }
  }

  Future<void> settle() async {
    final deadline = DateTime.now().add(const Duration(seconds: 60));
    while (DateTime.now().isBefore(deadline)) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
      final quiet = DateTime.now().difference(_last);
      if (_inFlight == 0 && quiet > const Duration(milliseconds: 600)) return;
    }
    fail('background sync did not settle');
  }
}

/// The host's libsodium: SEZAM_LIBSODIUM when set; on Windows the DLL that
/// sodium_libs ships in the pub cache (PUB_CACHE or %LOCALAPPDATA%\Pub\Cache);
/// elsewhere the system library (apt libsodium-dev, brew libsodium).
String hostLibsodium() => _libsodium();

String _libsodium() {
  final override = env['SEZAM_LIBSODIUM'];
  if (override != null && override.isNotEmpty) return override;
  if (Platform.isMacOS) return 'libsodium.dylib';
  if (!Platform.isWindows) return 'libsodium.so';
  final pubCache = env['PUB_CACHE'] ?? '${env['LOCALAPPDATA']}\\Pub\\Cache';
  return Directory('$pubCache\\hosted\\pub.dev')
      .listSync()
      .whereType<Directory>()
      .where((d) => d.path.contains('sodium_libs-'))
      .map((d) => File('${d.path}\\windows\\lib\\Release\\v143\\libsodium.dll'))
      .firstWhere((f) => f.existsSync())
      .path;
}

/// The next Keychain write of this key fails as if the app were killed.
String? secureWriteKillsApp;

void _mockPlugins(String dir) {
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  final secure = <String, String>{};
  messenger.setMockMethodCallHandler(
    const MethodChannel('plugins.it_nomads.com/flutter_secure_storage'),
    (call) async {
      final args = (call.arguments as Map?) ?? {};
      final key = args['key'] as String?;
      switch (call.method) {
        case 'read':
          return secure[key];
        case 'write':
          if (key == secureWriteKillsApp) {
            // The app is killed before this Keychain write lands.
            secureWriteKillsApp = null;
            throw PlatformException(code: 'killed', message: 'app killed (test)');
          }
          secure[key!] = args['value'] as String;
          return null;
        case 'delete':
          secure.remove(key);
          return null;
        case 'containsKey':
          return secure.containsKey(key);
        case 'readAll':
          return Map<String, String>.from(secure);
        case 'deleteAll':
          secure.clear();
          return null;
      }
      return null;
    },
  );
  messenger.setMockMethodCallHandler(
    const MethodChannel('plugins.flutter.io/path_provider'),
    (call) async => dir,
  );
}

/// Argon2id (64 bytes) from node's crypto.argon2Sync, the password on stdin.
Future<Uint8List> nodeArgon2id(
  String password,
  Uint8List salt,
  int timeCost,
  int memoryCost,
  int parallelism,
) async {
  const script =
      "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{"
      'const a=JSON.parse(s);'
      "process.stdout.write(require('crypto').argon2Sync('argon2id',{"
      "message:Buffer.from(a.p,'base64'),nonce:Buffer.from(a.s,'base64'),"
      "parallelism:a.l,memory:a.m,passes:a.t,tagLength:64}).toString('hex'))})";
  final proc = await Process.start('node', ['-e', script]);
  proc.stdin.write(
    jsonEncode({
      'p': base64Encode(utf8.encode(password)),
      's': base64Encode(salt),
      't': timeCost,
      'm': memoryCost,
      'l': parallelism,
    }),
  );
  await proc.stdin.close();
  final out = await proc.stdout.transform(utf8.decoder).join();
  final err = await proc.stderr.transform(utf8.decoder).join();
  expect(await proc.exitCode, 0, reason: err);
  return Uint8List.fromList([
    for (var i = 0; i < out.length; i += 2)
      int.parse(out.substring(i, i + 2), radix: 16),
  ]);
}

Map<String, String> passwords(VaultService vault) => {
  for (final e in vault.allEntries)
    e.name: e.fields.firstWhere((f) => f.key == 'password').value,
};

/// Tells the Python side B reached [step] and waits until A has done it.
Future<void> handshake(String dir, String step) async {
  File('$dir/$step.ready').writeAsStringSync('');
  final done = File('$dir/$step.done');
  final deadline = DateTime.now().add(const Duration(seconds: 180));
  while (!done.existsSync()) {
    if (DateTime.now().isAfter(deadline)) fail('A never did $step');
    await Future<void>.delayed(const Duration(milliseconds: 100));
  }
}

/// Test bindings, mocked plugins (app files in [appDir]), FFI SQLite and the
/// libsodium/node Argon2id crypto. Call before constructing any service.
Future<void> setUpPhone(String appDir) async {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null; // real sockets to the test server
  _mockPlugins(appDir);
  SharedPreferences.setMockInitialValues({});
  sqfliteFfiInit();
  databaseFactory = databaseFactoryFfi;
  _sodium = await SodiumSumoInit.init2(() => DynamicLibrary.open(_libsodium()));
}

SodiumSumo? _sodium;

/// Inside the [http.runWithClient] zone, after the services are constructed.
void initPhoneCrypto() =>
    CryptoService().initForTesting(_sodium!, argon2: nodeArgon2id);

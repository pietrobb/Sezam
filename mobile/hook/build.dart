// Builds the shared sync core (core/ffi, Rust) for the platform the app or
// `flutter test` runs on, and bundles it as a code asset
// (docs/SYNC_SINGLE_SOURCE.md 4b). Needs cargo and the Rust target:
//   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
//   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';

const assetName = 'services/sync_core.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) return;
    final code = input.config.code;
    final triple = _rustTarget(code);
    final crate = input.packageRoot.resolve('../core/ffi/');
    final targetDir = input.outputDirectoryShared.resolve('cargo/');
    final env = <String, String>{'CARGO_TARGET_DIR': targetDir.toFilePath()};
    if (code.targetOS == OS.android) {
      // The NDK's clang for this ABI and API level links the library.
      final cc = code.cCompiler?.compiler;
      if (cc == null) {
        throw StateError('Flutter passed no NDK compiler for the sync core');
      }
      final api = code.android.targetNdkApi;
      final clangTarget = triple == 'armv7-linux-androideabi'
          ? 'armv7a-linux-androideabi'
          : triple;
      final ext = Platform.isWindows ? '.cmd' : '';
      final linker = File.fromUri(
        cc,
      ).parent.uri.resolve('$clangTarget$api-clang$ext').toFilePath();
      env['CARGO_TARGET_${triple.toUpperCase().replaceAll('-', '_')}_LINKER'] =
          linker;
    }
    final result = await Process.run('cargo', [
      'build',
      '--release',
      '--locked',
      '--target',
      triple,
      '--manifest-path',
      crate.resolve('Cargo.toml').toFilePath(),
    ], environment: env);
    if (result.exitCode != 0) {
      throw ProcessException(
        'cargo',
        ['build', '--target', triple],
        'Building the sync core (core/ffi) failed. Is the Rust target '
            'installed (rustup target add $triple)?\n${result.stderr}',
        result.exitCode,
      );
    }
    final library = targetDir.resolve(
      '$triple/release/${code.targetOS.dylibFileName('sezam_sync_core')}',
    );
    output.assets.code.add(
      CodeAsset(
        package: input.packageName,
        name: assetName,
        linkMode: DynamicLoadingBundled(),
        file: library,
      ),
    );
    final core = Directory.fromUri(input.packageRoot.resolve('../core/'));
    output.dependencies.addAll([
      for (final entity in core.listSync(recursive: true))
        if (entity is File &&
            !entity.path.contains('${Platform.pathSeparator}target') &&
            (entity.path.endsWith('.rs') ||
                entity.path.endsWith('Cargo.toml') ||
                entity.path.endsWith('Cargo.lock')))
          entity.uri,
    ]);
  });
}

String _rustTarget(CodeConfig code) {
  final arch = code.targetArchitecture;
  return switch (code.targetOS) {
    OS.android => switch (arch) {
      Architecture.arm64 => 'aarch64-linux-android',
      Architecture.arm => 'armv7-linux-androideabi',
      Architecture.x64 => 'x86_64-linux-android',
      Architecture.ia32 => 'i686-linux-android',
      _ => throw UnsupportedError('Android $arch'),
    },
    OS.iOS => switch ((arch, code.iOS.targetSdk)) {
      (Architecture.arm64, IOSSdk.iPhoneOS) => 'aarch64-apple-ios',
      (Architecture.arm64, _) => 'aarch64-apple-ios-sim',
      (Architecture.x64, _) => 'x86_64-apple-ios',
      _ => throw UnsupportedError('iOS $arch'),
    },
    OS.windows => switch (arch) {
      Architecture.x64 => 'x86_64-pc-windows-msvc',
      Architecture.arm64 => 'aarch64-pc-windows-msvc',
      _ => throw UnsupportedError('Windows $arch'),
    },
    OS.linux => switch (arch) {
      Architecture.x64 => 'x86_64-unknown-linux-gnu',
      Architecture.arm64 => 'aarch64-unknown-linux-gnu',
      _ => throw UnsupportedError('Linux $arch'),
    },
    OS.macOS => switch (arch) {
      Architecture.x64 => 'x86_64-apple-darwin',
      Architecture.arm64 => 'aarch64-apple-darwin',
      _ => throw UnsupportedError('macOS $arch'),
    },
    _ => throw UnsupportedError('${code.targetOS}'),
  };
}

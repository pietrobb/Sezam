# Sezam mobile

Flutter app (Android, iOS) for the Sezam vault. It uses the same vault formats
and sync protocol as the desktop app and the web client, checked by the shared
golden test vectors in `test/`. See the main [README](../README.md).

```
flutter pub get
flutter test
flutter run
```

The sync decisions come from the shared Rust core in `../core`
(`docs/SYNC_SINGLE_SOURCE.md` point 4b). `hook/build.dart` builds it with
cargo for whatever the app or `flutter test` runs on, so a Rust toolchain is
needed, plus the targets you build for:

```
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios   # on a Mac
```

An Android release build needs your own signing key, configured in
`android/key.properties` (`storeFile`, `storePassword`, `keyAlias`,
`keyPassword`; the file is ignored by git).

/// Biometric-bound storage for the vault KEK.
///
/// The KEK is stored under a hardware key (Android Keystore / iOS Secure
/// Enclave access control) that the OS releases only after a successful
/// biometric authentication. A UI-only biometric gate is not enough: a KEK
/// in plain secure storage can be read by anything that runs as the app.
library;

import 'package:biometric_storage/biometric_storage.dart';

const biometricKekStorageName = 'sezam_biometric_kek';

StorageFileInitOptions biometricKekOptions() => StorageFileInitOptions(
      // -1 = every read needs a fresh biometric authentication (Android
      // CryptoObject-bound key, no validity window).
      authenticationValidityDurationSeconds: -1,
      authenticationRequired: true,
      // No device PIN fallback on Android; iOS uses .biometryCurrentSet, so
      // enrolling a new fingerprint/face invalidates the stored KEK.
      androidBiometricOnly: true,
      darwinBiometricOnly: true,
    );

const biometricKekPrompt = PromptInfo(
  androidPromptInfo: AndroidPromptInfo(
    title: 'Unlock Sezam',
    negativeButton: 'Use password',
  ),
  iosPromptInfo: IosPromptInfo(
    saveTitle: 'Enable biometric unlock for Sezam',
    accessTitle: 'Unlock Sezam',
  ),
);

Future<bool> canUseBiometricKekStorage() async {
  try {
    return await BiometricStorage().canAuthenticate() ==
        CanAuthenticateResponse.success;
  } catch (_) {
    return false;
  }
}

Future<BiometricStorageFile> openBiometricKekStorage() =>
    BiometricStorage().getStorage(
      biometricKekStorageName,
      options: biometricKekOptions(),
      promptInfo: biometricKekPrompt,
    );

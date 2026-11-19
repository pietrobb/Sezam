import Flutter
import UIKit

@main
@objc class AppDelegate: FlutterAppDelegate {
  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    GeneratedPluginRegistrant.register(with: self)
    registerStorageChannel()
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  // iOS snapshots the window for the app switcher right after the app
  // resigns active; cover it so no vault content ends up in that snapshot
  // (the iOS counterpart of Android's FLAG_SECURE).
  private var privacyCover: UIView?

  override func applicationWillResignActive(_ application: UIApplication) {
    super.applicationWillResignActive(application)
    guard privacyCover == nil, let window = self.window else { return }
    // Opaque, not a blur: large text can stay legible through a blur.
    let cover = UIView(frame: window.bounds)
    cover.backgroundColor = .systemBackground
    cover.autoresizingMask = [.flexibleWidth, .flexibleHeight]
    window.addSubview(cover)
    privacyCover = cover
  }

  override func applicationDidBecomeActive(_ application: UIApplication) {
    super.applicationDidBecomeActive(application)
    privacyCover?.removeFromSuperview()
    privacyCover = nil
  }

  // Lets Dart mark the vault directory as excluded from iCloud/iTunes backup.
  private func registerStorageChannel() {
    guard let registrar = self.registrar(forPlugin: "SezamStorage") else { return }
    let channel = FlutterMethodChannel(
      name: "sk.sezam/storage", binaryMessenger: registrar.messenger())
    channel.setMethodCallHandler { call, result in
      guard call.method == "excludeFromBackup", let path = call.arguments as? String else {
        result(FlutterMethodNotImplemented)
        return
      }
      var url = URL(fileURLWithPath: path)
      var values = URLResourceValues()
      values.isExcludedFromBackup = true
      do {
        try url.setResourceValues(values)
        result(true)
      } catch {
        result(FlutterError(
          code: "exclude_failed", message: error.localizedDescription, details: nil))
      }
    }
  }
}

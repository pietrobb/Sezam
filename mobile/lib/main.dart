import 'dart:async';

import 'package:dargon2_flutter/dargon2_flutter.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'theme/sezam_theme.dart';
import 'screens/unlock_screen.dart';
import 'screens/vault_screen.dart';
import 'screens/entry_detail_screen.dart';
import 'screens/server_connect_screen.dart';
import 'services/crypto_service.dart';
import 'services/vault_service.dart';
import 'services/auth_service.dart';
import 'services/auto_lock.dart';
import 'services/clipboard_service.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  DArgon2Flutter.init();

  SystemChrome.setPreferredOrientations([
    DeviceOrientation.portraitUp,
    DeviceOrientation.portraitDown,
  ]);

  SystemChrome.setSystemUIOverlayStyle(
    const SystemUiOverlayStyle(
      statusBarColor: Colors.transparent,
      statusBarIconBrightness: Brightness.light,
      systemNavigationBarColor: SezamColors.bg,
      systemNavigationBarIconBrightness: Brightness.light,
    ),
  );

  runApp(await startSezam(() async {
    // Initialize crypto and vault services
    await CryptoService().init();
    // Before the database opens: an account join killed midway is undone.
    await AuthService().recoverInterruptedJoin();
    await VaultService().init();

    // Check if a local vault already exists (init() above has just created
    // the database file, so that file says nothing).
    return AuthService().hasLocalVault();
  }));
}

/// Review 8595ec1 (R10-F): a failure before the app ran left a blank screen
/// with no word of what happened; it is shown instead.
Future<Widget> startSezam(Future<bool> Function() prepare) async {
  try {
    return SezamApp(vaultExists: await prepare());
  } catch (e) {
    return StartupErrorApp(error: e);
  }
}

class StartupErrorApp extends StatelessWidget {
  final Object error;

  const StartupErrorApp({super.key, required this.error});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Sezam',
      debugShowCheckedModeBanner: false,
      theme: SezamTheme.dark,
      home: Scaffold(
        body: SafeArea(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Sezam sa nepodarilo spustit',
                  style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 12),
                const Text(
                  'Data v telefone zostali bez zmeny. Zatvor aplikaciu a otvor '
                  'ju znova; ak chyba pretrvava, posli jej text spravcovi.',
                ),
                const SizedBox(height: 12),
                SelectableText('$error'),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class SezamApp extends StatefulWidget {
  final bool vaultExists;

  const SezamApp({super.key, required this.vaultExists});

  static final navigatorKey = GlobalKey<NavigatorState>();

  @override
  State<SezamApp> createState() => _SezamAppState();
}

class _SezamAppState extends State<SezamApp> with WidgetsBindingObserver {
  Timer? _autoLockTimer;
  final AutoLockTracker _autoLock = AutoLockTracker();

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _autoLockTimer?.cancel();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    super.didChangeAppLifecycleState(state);

    // A clear that came due while the process was frozen finishes now,
    // even when the vault has auto-locked in the meantime.
    if (state == AppLifecycleState.resumed) {
      unawaited(ClipboardService.shared.clearIfOverdue());
    }

    final vault = VaultService();
    if (!vault.isUnlocked) return;

    if (state != AppLifecycleState.resumed) {
      if (_autoLock.onStateChange(state, DateTime.now())) {
        _startAutoLockTimer(_autoLock.leftAt!);
      }
    } else {
      // Consume the leave timestamp synchronously so a disabled auto-lock or
      // a slow prefs read never leaves a stale value behind.
      final leftAt = _autoLock.consumeOnResume();
      _autoLockTimer?.cancel();
      _autoLockTimer = null;
      if (leftAt != null) {
        _checkAutoLockOnResume(leftAt);
      }
    }
  }

  Future<void> _startAutoLockTimer(DateTime leftAt) async {
    _autoLockTimer?.cancel();
    final prefs = await SharedPreferences.getInstance();
    final minutes = prefs.getInt('sezam_auto_lock') ?? 5;
    if (minutes <= 0) return; // 0 = disabled
    // The app may have resumed while prefs were loading.
    if (_autoLock.leftAt != leftAt) return;

    _autoLockTimer = Timer(Duration(minutes: minutes), () {
      _lockVault();
    });
  }

  Future<void> _checkAutoLockOnResume(DateTime leftAt) async {
    final prefs = await SharedPreferences.getInstance();
    final minutes = prefs.getInt('sezam_auto_lock') ?? 5;
    if (AutoLockTracker.isExpired(leftAt, DateTime.now(), minutes)) {
      _lockVault();
    }
  }

  void _lockVault() {
    final vault = VaultService();
    if (!vault.isUnlocked) return;

    AuthService().lock();
    final nav = SezamApp.navigatorKey.currentState;
    if (nav != null) {
      nav.pushNamedAndRemoveUntil(
        '/unlock',
        (_) => false,
        arguments: {'vaultExists': true},
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Sezam',
      debugShowCheckedModeBanner: false,
      theme: SezamTheme.dark,
      initialRoute: '/unlock',
      onGenerateRoute: (settings) {
        switch (settings.name) {
          case '/unlock':
            // Check if arguments carry vaultExists override (e.g., after vault creation)
            final unlockArgs = settings.arguments as Map<String, dynamic>?;
            final vaultExistsOverride = unlockArgs?['vaultExists'] as bool?;
            return _buildPageRoute(
              UnlockScreen(
                vaultExists: vaultExistsOverride ?? widget.vaultExists,
              ),
              settings,
              transitionType: _TransitionType.fade,
            );

          case '/vault':
            return _buildPageRoute(
              const VaultScreen(),
              settings,
              transitionType: _TransitionType.scale,
            );

          case '/server-connect':
            final connectArgs = settings.arguments as Map<String, dynamic>?;
            final vaultUnlocked =
                connectArgs?['vaultUnlocked'] as bool? ?? false;
            return _buildPageRoute(
              ServerConnectScreen(vaultUnlocked: vaultUnlocked),
              settings,
              transitionType: _TransitionType.slideUp,
            );

          case '/entry':
            final entryArgs = settings.arguments as Map<String, dynamic>;
            return _buildPageRoute(
              EntryDetailScreen(entryArgs: entryArgs),
              settings,
              transitionType: _TransitionType.slideUp,
            );

          default:
            return _buildPageRoute(const VaultScreen(), settings);
        }
      },
      navigatorKey: SezamApp.navigatorKey,
    );
  }

  static PageRouteBuilder _buildPageRoute(
    Widget page,
    RouteSettings settings, {
    _TransitionType transitionType = _TransitionType.slide,
  }) {
    return PageRouteBuilder(
      settings: settings,
      pageBuilder: (context, animation, secondaryAnimation) => page,
      transitionDuration: const Duration(milliseconds: 400),
      reverseTransitionDuration: const Duration(milliseconds: 300),
      transitionsBuilder: (context, animation, secondaryAnimation, child) {
        final curved = CurvedAnimation(
          parent: animation,
          curve: Curves.easeOutCubic,
          reverseCurve: Curves.easeIn,
        );

        switch (transitionType) {
          case _TransitionType.fade:
            return FadeTransition(opacity: curved, child: child);

          case _TransitionType.scale:
            return ScaleTransition(
              scale: Tween(begin: 0.85, end: 1.0).animate(curved),
              child: FadeTransition(opacity: curved, child: child),
            );

          case _TransitionType.slideUp:
            return SlideTransition(
              position: Tween(
                begin: const Offset(0, 0.15),
                end: Offset.zero,
              ).animate(curved),
              child: FadeTransition(opacity: curved, child: child),
            );

          case _TransitionType.slide:
            return SlideTransition(
              position: Tween(
                begin: const Offset(1, 0),
                end: Offset.zero,
              ).animate(curved),
              child: child,
            );
        }
      },
    );
  }
}

enum _TransitionType { fade, scale, slideUp, slide }

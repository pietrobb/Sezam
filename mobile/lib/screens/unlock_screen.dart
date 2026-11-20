import 'dart:math';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../theme/sezam_theme.dart';
import '../services/auth_service.dart';
import '../widgets/password_prompt.dart';

class UnlockScreen extends StatefulWidget {
  final bool vaultExists;

  const UnlockScreen({super.key, required this.vaultExists});

  @override
  State<UnlockScreen> createState() => _UnlockScreenState();
}

class _UnlockScreenState extends State<UnlockScreen>
    with TickerProviderStateMixin {
  final _passwordController = TextEditingController();
  final _confirmPasswordController = TextEditingController();
  bool _isUnlocking = false;
  bool _showError = false;
  String _errorMessage = 'Wrong password';
  bool _obscurePassword = true;
  bool _obscureConfirmPassword = true;
  bool _biometricAvailable = false;
  bool _biometricEnabled = false;
  String? _storedUsername;
  String? _storedServerUrl;
  late bool _vaultExists;

  final _auth = AuthService();

  // Animations
  late AnimationController _logoController;
  late AnimationController _pulseController;
  late AnimationController _shakeController;
  late Animation<double> _logoScale;
  late Animation<double> _pulseAnimation;
  late Animation<double> _shakeAnimation;

  @override
  void initState() {
    super.initState();
    _vaultExists = widget.vaultExists;

    _logoController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1200),
    );
    _logoScale = CurvedAnimation(
      parent: _logoController,
      curve: Curves.elasticOut,
    );
    _logoController.forward();

    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat(reverse: true);
    _pulseAnimation = Tween(begin: 0.8, end: 1.0).animate(
      CurvedAnimation(parent: _pulseController, curve: Curves.easeInOut),
    );

    _shakeController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 500),
    );
    _shakeAnimation = Tween(begin: 0.0, end: 1.0).animate(
      CurvedAnimation(parent: _shakeController, curve: Curves.elasticIn),
    );

    _loadStoredSession();
  }

  Future<void> _loadStoredSession() async {
    final username = await _auth.getStoredUsername();
    final serverUrl = await _auth.getStoredServerUrl();
    final bioAvailable = await _auth.isBiometricAvailable();
    final bioEnabled = await _auth.isBiometricEnabled();

    if (mounted) {
      setState(() {
        _storedUsername = username;
        _storedServerUrl = serverUrl;
        _biometricAvailable = bioAvailable;
        _biometricEnabled = bioEnabled;
      });

      // Auto-trigger biometric if vault exists, available, and enabled
      if (_vaultExists && bioAvailable && bioEnabled) {
        _unlockWithBiometrics();
      }
    }
  }

  @override
  void dispose() {
    _logoController.dispose();
    _pulseController.dispose();
    _shakeController.dispose();
    _passwordController.dispose();
    _confirmPasswordController.dispose();
    super.dispose();
  }

  /// Unlock an existing vault offline (primary path).
  Future<void> _unlockOffline() async {
    if (_isUnlocking || _passwordController.text.isEmpty) return;

    setState(() {
      _isUnlocking = true;
      _showError = false;
    });

    HapticFeedback.mediumImpact();

    final result = await _auth.unlockOffline(
      password: _passwordController.text,
    );
    if (!result.success &&
        (result.error == 'Wrong password' || result.teamLog != null) &&
        _storedUsername != null &&
        _storedServerUrl != null &&
        mounted) {
      // Maybe the password was changed on another device: the server derives
      // the current one and the local vault is taken over. INV-7: a team log
      // copy this phone cannot use is fetched there under its pins.
      setState(() => _isUnlocking = false);
      return _unlockWithServer(fallbackError: result.error);
    }

    if (result.success && mounted) {
      Navigator.pushReplacementNamed(context, '/vault');
    } else if (mounted) {
      setState(() {
        _isUnlocking = false;
        _showError = true;
        _errorMessage = result.error ?? 'Wrong password';
      });
      HapticFeedback.heavyImpact();
      _shakeController.forward(from: 0);
      _passwordController.selection = TextSelection(
        baseOffset: 0,
        extentOffset: _passwordController.text.length,
      );
    }
  }

  /// Unlock via server (existing flow).
  Future<void> _unlockWithServer({String? fallbackError}) async {
    if (_isUnlocking || _passwordController.text.isEmpty) return;

    final username = _storedUsername;
    final serverUrl = _storedServerUrl;

    if (username == null || serverUrl == null) {
      _showSetupDialog();
      return;
    }

    setState(() {
      _isUnlocking = true;
      _showError = false;
    });

    HapticFeedback.mediumImpact();

    var result = await _auth.unlockWithPassword(
      password: _passwordController.text,
      username: username,
      serverUrl: serverUrl,
    );
    // Password changed on another device: the local vault is still under the
    // previous password, which is needed once to take the change over.
    while (result.needsPreviousPassword) {
      if (!mounted) return;
      final previous = await showPasswordPrompt(
        context,
        title: 'Previous password',
        message: result.error ?? '',
        hint: 'Previous master password',
      );
      if (previous == null || previous.isEmpty) break;
      result = await _auth.unlockWithPassword(
        password: _passwordController.text,
        username: username,
        serverUrl: serverUrl,
        previousPassword: previous,
      );
    }

    if (result.success && mounted) {
      Navigator.pushReplacementNamed(context, '/vault');
    } else if (mounted) {
      setState(() {
        _isUnlocking = false;
        _showError = true;
        _errorMessage =
            (result.needsPreviousPassword || result.recoveryLimited
                    ? null
                    : fallbackError) ??
            result.error ??
            'Wrong password';
      });
      HapticFeedback.heavyImpact();
      _shakeController.forward(from: 0);
      _passwordController.selection = TextSelection(
        baseOffset: 0,
        extentOffset: _passwordController.text.length,
      );
    }
  }

  /// Create a new local vault.
  Future<void> _createNewVault() async {
    if (_isUnlocking || _passwordController.text.isEmpty) return;

    // Validate password confirmation
    if (_passwordController.text != _confirmPasswordController.text) {
      setState(() {
        _showError = true;
        _errorMessage = 'Passwords do not match';
      });
      _shakeController.forward(from: 0);
      return;
    }

    if (_passwordController.text.length < 8) {
      setState(() {
        _showError = true;
        _errorMessage = 'Password must be at least 8 characters';
      });
      _shakeController.forward(from: 0);
      return;
    }

    setState(() {
      _isUnlocking = true;
      _showError = false;
    });

    HapticFeedback.mediumImpact();

    final result = await _auth.createNewVault(
      password: _passwordController.text,
    );

    if (result.success && mounted) {
      Navigator.pushReplacementNamed(context, '/vault');
    } else if (mounted) {
      setState(() {
        _isUnlocking = false;
        _showError = true;
        _errorMessage = result.error ?? 'Failed to create vault';
      });
      HapticFeedback.heavyImpact();
      _shakeController.forward(from: 0);
    }
  }

  Future<void> _unlockWithBiometrics() async {
    if (_isUnlocking) return;

    setState(() {
      _isUnlocking = true;
      _showError = false;
    });

    HapticFeedback.mediumImpact();

    final result = await _auth.unlockWithBiometrics();

    if (result.success && mounted) {
      Navigator.pushReplacementNamed(context, '/vault');
    } else if (mounted) {
      setState(() {
        _isUnlocking = false;
        _showError = true;
        _errorMessage = result.error ?? 'Biometric auth failed';
      });
    }
  }

  void _navigateToServerConnect() {
    Navigator.pushNamed(
      context,
      '/server-connect',
      arguments: {'vaultUnlocked': _vaultExists},
    ).then((result) {
      if (result == true && mounted) {
        // Connection succeeded — reload stored session info
        _loadStoredSession();
      }
    });
  }

  void _showSetupDialog() {
    final usernameCtrl = TextEditingController(text: _storedUsername ?? '');
    final serverCtrl = TextEditingController(
        text: _storedServerUrl ?? 'https://sezam.example.com');

    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Server Setup'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: usernameCtrl,
              decoration: const InputDecoration(
                labelText: 'Username',
                prefixIcon: Icon(Icons.person_rounded),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: serverCtrl,
              decoration: const InputDecoration(
                labelText: 'Server URL',
                prefixIcon: Icon(Icons.dns_rounded),
              ),
              keyboardType: TextInputType.url,
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () async {
              final prefs =
                  await SharedPreferences.getInstance();
              await prefs.setString(
                  'sezam_username', usernameCtrl.text);
              await prefs.setString(
                  'sezam_server_url', serverCtrl.text);
              setState(() {
                _storedUsername = usernameCtrl.text;
                _storedServerUrl = serverCtrl.text;
              });
              if (mounted) Navigator.pop(ctx);
            },
            child: const Text('Save'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        decoration: const BoxDecoration(
          gradient: RadialGradient(
            center: Alignment(0, -0.3),
            radius: 1.2,
            colors: [
              Color(0xFF0A1628),
              SezamColors.bg,
            ],
          ),
        ),
        child: SafeArea(
          child: Center(
            child: SingleChildScrollView(
              padding: const EdgeInsets.symmetric(horizontal: 32),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  // Animated logo
                  _buildLogo(),

                  const SizedBox(height: 32),

                  // Title
                  Text(
                    'Sezam',
                    style: Theme.of(context)
                        .textTheme
                        .headlineLarge
                        ?.copyWith(letterSpacing: 4),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Otvor sa',
                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                          color: SezamColors.accent,
                          letterSpacing: 2,
                        ),
                  ),

                  // Show username if stored and vault exists
                  if (_vaultExists && _storedUsername != null) ...[
                    const SizedBox(height: 8),
                    Text(
                      _storedUsername!,
                      style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                            color: SezamColors.textMuted,
                            fontSize: 13,
                          ),
                    ),
                  ],

                  const SizedBox(height: 48),

                  // Build the appropriate mode
                  if (_vaultExists)
                    _buildUnlockMode()
                  else
                    _buildFirstLaunchMode(),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildLogo() {
    return ScaleTransition(
      scale: _logoScale,
      child: AnimatedBuilder(
        animation: _pulseAnimation,
        builder: (context, child) {
          return Container(
            width: 120,
            height: 120,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              border: Border.all(
                color: SezamColors.accent
                    .withValues(alpha: _pulseAnimation.value),
                width: 2,
              ),
              boxShadow: [
                BoxShadow(
                  color: SezamColors.accentGlow.withValues(
                      alpha: _pulseAnimation.value * 0.5),
                  blurRadius: 30,
                  spreadRadius: 5,
                ),
              ],
            ),
            child: Icon(
              _vaultExists
                  ? Icons.lock_outline_rounded
                  : Icons.add_moderator_rounded,
              size: 48,
              color: SezamColors.accent,
            ),
          );
        },
      ),
    );
  }

  /// Build the unlock UI for when a vault already exists.
  Widget _buildUnlockMode() {
    return Column(
      children: [
        // Password field with shake animation
        _buildPasswordField(
          controller: _passwordController,
          hintText: 'Master password',
          onSubmitted: (_) => _unlockOffline(),
        ),

        const SizedBox(height: 24),

        // Primary: Unlock vault (offline)
        SizedBox(
          width: double.infinity,
          height: 52,
          child: ElevatedButton(
            onPressed: _isUnlocking ? null : _unlockOffline,
            child: _isUnlocking
                ? const SizedBox(
                    width: 24,
                    height: 24,
                    child: CircularProgressIndicator(
                      strokeWidth: 2.5,
                      color: Colors.white,
                    ),
                  )
                : const Text('Odomknut vault'),
          ),
        ),

        const SizedBox(height: 16),

        // Biometric button (only show if available)
        if (_biometricAvailable && _biometricEnabled)
          TextButton.icon(
            onPressed:
                _isUnlocking ? null : () => _unlockWithBiometrics(),
            icon: const Icon(Icons.fingerprint_rounded, size: 28),
            label: const Text('Use biometrics'),
          ),

        const SizedBox(height: 8),

        // Server connect button
        TextButton.icon(
          onPressed: _isUnlocking ? null : () {
            _navigateToServerConnect();
          },
          icon: const Icon(Icons.cloud_rounded, size: 18,
              color: SezamColors.textMuted),
          label: Text(
            _storedServerUrl != null
                ? 'Pripojit k serveru'
                : 'Pripojit k serveru',
            style: const TextStyle(
              color: SezamColors.textMuted,
              fontSize: 13,
            ),
          ),
        ),

        // Change server
        if (_storedServerUrl != null)
          TextButton(
            onPressed: () => _navigateToServerConnect(),
            child: const Text(
              'Zmenit server',
              style: TextStyle(
                color: SezamColors.textMuted,
                fontSize: 12,
              ),
            ),
          ),
      ],
    );
  }

  /// Build the first-launch UI when no vault exists.
  Widget _buildFirstLaunchMode() {
    return Column(
      children: [
        Text(
          'Vitajte v Sezame',
          style: Theme.of(context).textTheme.titleMedium?.copyWith(
                color: SezamColors.textSecondary,
              ),
        ),

        const SizedBox(height: 8),

        Text(
          'Vytvorte novy vault alebo sa pripojte k serveru.',
          textAlign: TextAlign.center,
          style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: SezamColors.textMuted,
                fontSize: 13,
              ),
        ),

        const SizedBox(height: 32),

        // Password field
        _buildPasswordField(
          controller: _passwordController,
          hintText: 'Master password',
          onSubmitted: (_) {},
        ),

        const SizedBox(height: 12),

        // Confirm password field
        AnimatedBuilder(
          animation: _shakeAnimation,
          builder: (context, child) {
            final dx = sin(_shakeAnimation.value * pi * 4) *
                (1 - _shakeAnimation.value) *
                12;
            return Transform.translate(
              offset: Offset(dx, 0),
              child: child,
            );
          },
          child: TextField(
            controller: _confirmPasswordController,
            obscureText: _obscureConfirmPassword,
            style: const TextStyle(
              fontSize: 16,
              color: SezamColors.text,
            ),
            decoration: InputDecoration(
              hintText: 'Confirm password',
              prefixIcon: const Icon(
                Icons.key_rounded,
                color: SezamColors.textMuted,
              ),
              suffixIcon: IconButton(
                icon: Icon(
                  _obscureConfirmPassword
                      ? Icons.visibility_off_rounded
                      : Icons.visibility_rounded,
                  color: SezamColors.textMuted,
                ),
                onPressed: () {
                  setState(() =>
                      _obscureConfirmPassword = !_obscureConfirmPassword);
                },
              ),
              errorText: _showError ? _errorMessage : null,
              errorStyle: const TextStyle(color: SezamColors.error),
            ),
            onSubmitted: (_) => _createNewVault(),
          ),
        ),

        const SizedBox(height: 24),

        // Create vault button (primary)
        SizedBox(
          width: double.infinity,
          height: 52,
          child: ElevatedButton.icon(
            onPressed: _isUnlocking ? null : _createNewVault,
            icon: _isUnlocking
                ? const SizedBox(
                    width: 24,
                    height: 24,
                    child: CircularProgressIndicator(
                      strokeWidth: 2.5,
                      color: Colors.white,
                    ),
                  )
                : const Icon(Icons.add_moderator_rounded),
            label: const Text('Vytvorit novy vault'),
          ),
        ),

        const SizedBox(height: 16),

        // Connect to server (secondary)
        SizedBox(
          width: double.infinity,
          height: 48,
          child: OutlinedButton.icon(
            onPressed: _isUnlocking ? null : () => _navigateToServerConnect(),
            icon: const Icon(Icons.cloud_rounded),
            label: const Text('Pripojit k serveru'),
            style: OutlinedButton.styleFrom(
              foregroundColor: SezamColors.accent,
              side: const BorderSide(color: SezamColors.borderAccent),
            ),
          ),
        ),
      ],
    );
  }

  /// Reusable password field with shake animation.
  Widget _buildPasswordField({
    required TextEditingController controller,
    required String hintText,
    required ValueChanged<String> onSubmitted,
  }) {
    return AnimatedBuilder(
      animation: _shakeAnimation,
      builder: (context, child) {
        final dx = sin(_shakeAnimation.value * pi * 4) *
            (1 - _shakeAnimation.value) *
            12;
        return Transform.translate(
          offset: Offset(dx, 0),
          child: child,
        );
      },
      child: TextField(
        controller: controller,
        obscureText: _obscurePassword,
        autofocus: true,
        style: const TextStyle(
          fontSize: 16,
          color: SezamColors.text,
        ),
        decoration: InputDecoration(
          hintText: hintText,
          prefixIcon: const Icon(
            Icons.key_rounded,
            color: SezamColors.textMuted,
          ),
          suffixIcon: IconButton(
            icon: Icon(
              _obscurePassword
                  ? Icons.visibility_off_rounded
                  : Icons.visibility_rounded,
              color: SezamColors.textMuted,
            ),
            onPressed: () {
              setState(() => _obscurePassword = !_obscurePassword);
            },
          ),
          // Only show error on the password field in unlock mode
          errorText: (_showError && _vaultExists) ? _errorMessage : null,
          errorStyle: const TextStyle(color: SezamColors.error),
        ),
        onSubmitted: onSubmitted,
      ),
    );
  }
}

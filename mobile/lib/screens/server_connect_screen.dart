import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../theme/sezam_theme.dart';
import '../services/auth_service.dart';
import '../services/sync_service.dart';
import '../services/vault_service.dart';

/// Full-page screen for connecting to a Sezam server.
///
/// Handles all scenarios:
///   - Empty server → bootstrap as admin
///   - Existing server → recovery (Path B) or invitation registration
///   - Approval polling after registration
///   - Error states (unreachable, invalid URL, wrong password)
class ServerConnectScreen extends StatefulWidget {
  /// If true, the vault is already unlocked (coming from vault/settings).
  /// If false, coming from unlock screen first launch.
  final bool vaultUnlocked;

  const ServerConnectScreen({super.key, this.vaultUnlocked = false});

  @override
  State<ServerConnectScreen> createState() => _ServerConnectScreenState();
}

class _ServerConnectScreenState extends State<ServerConnectScreen>
    with SingleTickerProviderStateMixin {
  final _auth = AuthService();
  final _serverUrlController = TextEditingController();
  final _usernameController = TextEditingController();
  final _passwordController = TextEditingController();
  final _invitationController = TextEditingController();

  bool _isProcessing = false;
  bool _obscurePassword = true;
  String? _statusMessage;
  Color _statusColor = SezamColors.textSecondary;
  IconData? _statusIcon;

  // Current phase of the flow
  _ConnectPhase _phase = _ConnectPhase.input;

  // For approval polling
  Timer? _approvalTimer;
  int _pollCount = 0;
  static const _maxPollCount = 120; // 10 minutes at 5s intervals

  late AnimationController _pulseController;
  late Animation<double> _pulseAnimation;

  @override
  void initState() {
    super.initState();
    _loadStoredValues();

    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat(reverse: true);
    _pulseAnimation = Tween(begin: 0.6, end: 1.0).animate(
      CurvedAnimation(parent: _pulseController, curve: Curves.easeInOut),
    );
  }

  Future<void> _loadStoredValues() async {
    final username = await _auth.getStoredUsername();
    final serverUrl = await _auth.getStoredServerUrl();
    if (mounted) {
      setState(() {
        if (username != null) _usernameController.text = username;
        if (serverUrl != null) _serverUrlController.text = serverUrl;
      });
    }
  }

  @override
  void dispose() {
    _approvalTimer?.cancel();
    _pulseController.dispose();
    _serverUrlController.dispose();
    _usernameController.dispose();
    _passwordController.dispose();
    _invitationController.dispose();
    super.dispose();
  }

  /// Validate the URL format.
  bool _isValidUrl(String url) {
    final trimmed = url.trim();
    if (trimmed.isEmpty) return false;
    final uri = Uri.tryParse(trimmed);
    if (uri == null) return false;
    return uri.scheme == 'http' || uri.scheme == 'https';
  }

  /// Main connect action.
  Future<void> _connect() async {
    final serverUrl = _serverUrlController.text.trim();
    final username = _usernameController.text.trim();
    final password = _passwordController.text;

    // Validate
    if (!_isValidUrl(serverUrl)) {
      _setStatus(
        'Neplatna adresa servera. Pouzi format https://...',
        SezamColors.error,
        Icons.error_outline_rounded,
      );
      return;
    }

    if (username.isEmpty) {
      _setStatus(
        'Zadaj pouzivatelske meno.',
        SezamColors.error,
        Icons.error_outline_rounded,
      );
      return;
    }

    if (password.isEmpty) {
      _setStatus(
        'Zadaj master heslo.',
        SezamColors.error,
        Icons.error_outline_rounded,
      );
      return;
    }

    setState(() {
      _isProcessing = true;
      _statusMessage = null;
      _statusIcon = null;
    });

    HapticFeedback.mediumImpact();

    final result = await _auth.connectToServer(
      serverUrl: serverUrl,
      password: password,
      username: username,
      onProgress: (msg) {
        if (mounted) {
          setState(() {
            _statusMessage = msg;
            _statusColor = SezamColors.accent;
            _statusIcon = null;
          });
        }
      },
    );

    if (!mounted) return;

    setState(() => _isProcessing = false);

    switch (result.outcome) {
      case ConnectOutcome.connected:
        _setStatus(result.message, SezamColors.success, Icons.check_circle_rounded);
        HapticFeedback.heavyImpact();
        // Wait a moment then navigate
        await Future.delayed(const Duration(milliseconds: 1500));
        if (mounted) {
          Navigator.pop(context, true); // Return success
        }
        break;

      case ConnectOutcome.needsInvitation:
        _setStatus(result.message, SezamColors.warning, Icons.vpn_key_rounded);
        setState(() => _phase = _ConnectPhase.invitation);
        break;

      case ConnectOutcome.needsApproval:
        _setStatus(result.message, SezamColors.warning, Icons.hourglass_top_rounded);
        setState(() => _phase = _ConnectPhase.polling);
        _startApprovalPolling();
        break;

      case ConnectOutcome.wrongPassword:
        _setStatus(result.message, SezamColors.error, Icons.lock_rounded);
        HapticFeedback.heavyImpact();
        break;

      case ConnectOutcome.unreachable:
        _setStatus(result.message, SezamColors.error, Icons.wifi_off_rounded);
        HapticFeedback.heavyImpact();
        break;

      case ConnectOutcome.error:
        _setStatus(result.message, SezamColors.error, Icons.error_outline_rounded);
        HapticFeedback.heavyImpact();
        break;
    }
  }

  /// Submit invitation token.
  Future<void> _submitInvitation() async {
    final invitationToken = _invitationController.text.trim();
    if (invitationToken.isEmpty) {
      _setStatus(
        'Zadaj invitation token.',
        SezamColors.error,
        Icons.error_outline_rounded,
      );
      return;
    }

    setState(() {
      _isProcessing = true;
      _statusMessage = null;
      _statusIcon = null;
    });

    HapticFeedback.mediumImpact();

    final result = await _auth.registerWithInvitation(
      serverUrl: _serverUrlController.text.trim(),
      username: _usernameController.text.trim(),
      password: _passwordController.text,
      invitationToken: invitationToken,
      onProgress: (msg) {
        if (mounted) {
          setState(() {
            _statusMessage = msg;
            _statusColor = SezamColors.accent;
            _statusIcon = null;
          });
        }
      },
    );

    if (!mounted) return;

    setState(() => _isProcessing = false);

    switch (result.outcome) {
      case ConnectOutcome.needsApproval:
        _setStatus(result.message, SezamColors.warning, Icons.hourglass_top_rounded);
        setState(() => _phase = _ConnectPhase.polling);
        _startApprovalPolling();
        break;

      case ConnectOutcome.connected:
        _setStatus(result.message, SezamColors.success, Icons.check_circle_rounded);
        HapticFeedback.heavyImpact();
        await Future.delayed(const Duration(milliseconds: 1500));
        if (mounted) {
          Navigator.pop(context, true);
        }
        break;

      case ConnectOutcome.error:
        _setStatus(result.message, SezamColors.error, Icons.error_outline_rounded);
        HapticFeedback.heavyImpact();
        break;

      default:
        _setStatus(result.message, SezamColors.error, Icons.error_outline_rounded);
        break;
    }
  }

  /// Start polling for admin approval.
  void _startApprovalPolling() {
    _pollCount = 0;
    _approvalTimer?.cancel();
    _approvalTimer = Timer.periodic(const Duration(seconds: 5), (timer) async {
      _pollCount++;

      if (_pollCount > _maxPollCount) {
        timer.cancel();
        if (mounted) {
          _setStatus(
            'Casovy limit vyprsal. Skus to neskor.',
            SezamColors.error,
            Icons.timer_off_rounded,
          );
          setState(() => _phase = _ConnectPhase.input);
        }
        return;
      }

      final approved = await _auth.pollForApproval(
        username: _usernameController.text.trim(),
        password: _passwordController.text,
        serverUrl: _serverUrlController.text.trim(),
      );

      if (approved && mounted) {
        timer.cancel();

        // Sync data
        _setStatus('Schvaleny! Synchronizujem...', SezamColors.success, Icons.check_circle_rounded);

        // Save server URL
        final prefs = await SharedPreferences.getInstance();
        await prefs.setString('sezam_server_url', _serverUrlController.text.trim());

        try {
          final sync = SyncService();
          await sync.pull();
          final vault = VaultService();
          if (vault.isUnlocked) {
            await vault.reloadData();
          }
        } catch (e) {
          if (mounted) {
            _setStatus('Synchronizacia zlyhala: $e', SezamColors.error, Icons.error_outline_rounded);
            setState(() => _phase = _ConnectPhase.input);
          }
          return;
        }

        HapticFeedback.heavyImpact();
        await Future.delayed(const Duration(milliseconds: 1500));
        if (mounted) {
          Navigator.pop(context, true);
        }
      }
    });
  }

  void _setStatus(String message, Color color, IconData? icon) {
    setState(() {
      _statusMessage = message;
      _statusColor = color;
      _statusIcon = icon;
    });
  }

  void _resetToInput() {
    _approvalTimer?.cancel();
    setState(() {
      _phase = _ConnectPhase.input;
      _statusMessage = null;
      _statusIcon = null;
      _invitationController.clear();
    });
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
          child: Column(
            children: [
              _buildAppBar(),
              Expanded(
                child: SingleChildScrollView(
                  padding: const EdgeInsets.symmetric(horizontal: 24),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      const SizedBox(height: 16),
                      _buildHeader(),
                      const SizedBox(height: 32),

                      // Status message
                      if (_statusMessage != null) ...[
                        _buildStatusCard(),
                        const SizedBox(height: 24),
                      ],

                      // Phase-specific content
                      if (_phase == _ConnectPhase.input) _buildInputForm(),
                      if (_phase == _ConnectPhase.invitation) _buildInvitationForm(),
                      if (_phase == _ConnectPhase.polling) _buildPollingView(),

                      const SizedBox(height: 40),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildAppBar() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      child: Row(
        children: [
          IconButton(
            icon: const Icon(Icons.arrow_back_rounded, color: SezamColors.text),
            onPressed: () {
              _approvalTimer?.cancel();
              Navigator.pop(context, false);
            },
          ),
          const Spacer(),
          if (_phase != _ConnectPhase.input)
            TextButton(
              onPressed: _isProcessing ? null : _resetToInput,
              child: const Text(
                'Zacat odznova',
                style: TextStyle(color: SezamColors.textMuted, fontSize: 13),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildHeader() {
    return Column(
      children: [
        AnimatedBuilder(
          animation: _pulseAnimation,
          builder: (context, child) {
            return Container(
              width: 80,
              height: 80,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                border: Border.all(
                  color: SezamColors.accent.withValues(alpha: _pulseAnimation.value),
                  width: 2,
                ),
                boxShadow: [
                  BoxShadow(
                    color: SezamColors.accentGlow.withValues(
                        alpha: _pulseAnimation.value * 0.5),
                    blurRadius: 20,
                    spreadRadius: 3,
                  ),
                ],
              ),
              child: const Icon(
                Icons.cloud_rounded,
                size: 36,
                color: SezamColors.accent,
              ),
            );
          },
        ),
        const SizedBox(height: 16),
        Text(
          'Pripojit k serveru',
          style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                letterSpacing: 1,
              ),
        ),
        const SizedBox(height: 8),
        Text(
          'Synchronizuj vault napriec zariadeniami',
          style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: SezamColors.textMuted,
                fontSize: 13,
              ),
        ),
      ],
    );
  }

  Widget _buildStatusCard() {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: _statusColor.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: _statusColor.withValues(alpha: 0.3)),
      ),
      child: Row(
        children: [
          if (_statusIcon != null) ...[
            Icon(_statusIcon, color: _statusColor, size: 22),
            const SizedBox(width: 12),
          ] else if (_isProcessing) ...[
            SizedBox(
              width: 20,
              height: 20,
              child: CircularProgressIndicator(
                strokeWidth: 2,
                color: _statusColor,
              ),
            ),
            const SizedBox(width: 12),
          ],
          Expanded(
            child: Text(
              _statusMessage!,
              style: TextStyle(
                color: _statusColor,
                fontSize: 14,
                height: 1.4,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildInputForm() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // Server URL
        TextField(
          controller: _serverUrlController,
          decoration: const InputDecoration(
            labelText: 'Adresa servera',
            hintText: 'https://sezam.example.com',
            prefixIcon: Icon(Icons.dns_rounded, color: SezamColors.textMuted),
          ),
          keyboardType: TextInputType.url,
          enabled: !_isProcessing,
          style: const TextStyle(color: SezamColors.text, fontSize: 15),
          textInputAction: TextInputAction.next,
        ),
        const SizedBox(height: 16),

        // Username
        TextField(
          controller: _usernameController,
          decoration: const InputDecoration(
            labelText: 'Pouzivatelske meno',
            hintText: 'peter',
            prefixIcon: Icon(Icons.person_rounded, color: SezamColors.textMuted),
          ),
          enabled: !_isProcessing,
          style: const TextStyle(color: SezamColors.text, fontSize: 15),
          textInputAction: TextInputAction.next,
        ),
        const SizedBox(height: 16),

        // Password
        TextField(
          controller: _passwordController,
          obscureText: _obscurePassword,
          decoration: InputDecoration(
            labelText: 'Master heslo',
            hintText: 'Heslo k tvojmu vaultu',
            prefixIcon: const Icon(Icons.key_rounded, color: SezamColors.textMuted),
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
          ),
          enabled: !_isProcessing,
          style: const TextStyle(color: SezamColors.text, fontSize: 15),
          onSubmitted: (_) => _connect(),
        ),
        const SizedBox(height: 28),

        // Connect button
        SizedBox(
          height: 52,
          child: ElevatedButton.icon(
            onPressed: _isProcessing ? null : _connect,
            icon: _isProcessing
                ? const SizedBox(
                    width: 22,
                    height: 22,
                    child: CircularProgressIndicator(
                      strokeWidth: 2.5,
                      color: Colors.white,
                    ),
                  )
                : const Icon(Icons.cloud_sync_rounded),
            label: Text(_isProcessing ? 'Pripajam...' : 'Pripojit'),
          ),
        ),
      ],
    );
  }

  Widget _buildInvitationForm() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // Info
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: SezamColors.bgElevated,
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: SezamColors.border),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: const [
                  Icon(Icons.info_outline_rounded, color: SezamColors.accent, size: 20),
                  SizedBox(width: 8),
                  Text(
                    'Pozvanka',
                    style: TextStyle(
                      color: SezamColors.text,
                      fontSize: 15,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              const Text(
                'Poziadaj administratora servera o invitation token. '
                'Moze ho vygenerovat v administracii servera.',
                style: TextStyle(
                  color: SezamColors.textSecondary,
                  fontSize: 13,
                  height: 1.5,
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 20),

        // Invitation token input
        TextField(
          controller: _invitationController,
          decoration: const InputDecoration(
            labelText: 'Pozvanka',
            hintText: 'Vloz cely odkaz s #g alebo invitation token',
            prefixIcon: Icon(Icons.vpn_key_rounded, color: SezamColors.textMuted),
          ),
          enabled: !_isProcessing,
          style: const TextStyle(
            color: SezamColors.text,
            fontSize: 15,
            fontFamily: 'monospace',
          ),
          onSubmitted: (_) => _submitInvitation(),
        ),
        const SizedBox(height: 28),

        // Submit button
        SizedBox(
          height: 52,
          child: ElevatedButton.icon(
            onPressed: _isProcessing ? null : _submitInvitation,
            icon: _isProcessing
                ? const SizedBox(
                    width: 22,
                    height: 22,
                    child: CircularProgressIndicator(
                      strokeWidth: 2.5,
                      color: Colors.white,
                    ),
                  )
                : const Icon(Icons.send_rounded),
            label: Text(_isProcessing ? 'Registrujem...' : 'Zaregistrovat'),
          ),
        ),
      ],
    );
  }

  Widget _buildPollingView() {
    final remaining = ((_maxPollCount - _pollCount) * 5 / 60).ceil();

    return Column(
      children: [
        const SizedBox(height: 20),

        // Animated waiting indicator
        AnimatedBuilder(
          animation: _pulseAnimation,
          builder: (context, child) {
            return Container(
              width: 100,
              height: 100,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                border: Border.all(
                  color: SezamColors.warning.withValues(alpha: _pulseAnimation.value),
                  width: 2,
                ),
              ),
              child: const Icon(
                Icons.hourglass_top_rounded,
                size: 40,
                color: SezamColors.warning,
              ),
            );
          },
        ),
        const SizedBox(height: 24),

        Text(
          'Cakam na schvalenie...',
          style: Theme.of(context).textTheme.titleMedium?.copyWith(
                color: SezamColors.text,
              ),
        ),
        const SizedBox(height: 8),
        Text(
          'Administrator musi schvalit tvoj ucet.\n'
          'Kontrolujem kazdych 5 sekund.',
          textAlign: TextAlign.center,
          style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: SezamColors.textSecondary,
                fontSize: 13,
                height: 1.5,
              ),
        ),
        const SizedBox(height: 16),

        // Progress indicator
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          decoration: BoxDecoration(
            color: SezamColors.bgElevated,
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: SezamColors.border),
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const SizedBox(
                width: 16,
                height: 16,
                child: CircularProgressIndicator(
                  strokeWidth: 2,
                  color: SezamColors.warning,
                ),
              ),
              const SizedBox(width: 12),
              Text(
                'Pokus $_pollCount / $_maxPollCount (zostava ~$remaining min)',
                style: const TextStyle(
                  color: SezamColors.textMuted,
                  fontSize: 12,
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 24),

        // Cancel button
        TextButton(
          onPressed: () {
            _approvalTimer?.cancel();
            _setStatus(
              'Cakanie zrusene. Mozes to skusit neskor.',
              SezamColors.textMuted,
              Icons.cancel_rounded,
            );
            setState(() => _phase = _ConnectPhase.input);
          },
          child: const Text(
            'Zrusit cakanie',
            style: TextStyle(color: SezamColors.textMuted),
          ),
        ),
      ],
    );
  }
}

enum _ConnectPhase {
  input,
  invitation,
  polling,
}

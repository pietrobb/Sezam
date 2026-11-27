import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import '../theme/sezam_theme.dart';
import '../services/ai_brake_service.dart';
import '../services/auth_service.dart';
import '../services/vault_service.dart';
import '../services/sync_service.dart';
import '../services/crypto_service.dart';
import '../services/timeout_client.dart';
import '../services/document_service.dart';
import '../services/unsent_changes.dart';
import '../widgets/unsent_changes_dialog.dart';
import '../widgets/team_anchor_publish_dialog.dart';
import '../widgets/team_forget_pin_dialog.dart';
import '../widgets/team_trust_dialog.dart';
import 'server_connect_screen.dart';

/// Settings screen — server config, biometrics, auto-lock, clipboard timeout,
/// QR provisioning, .sezam-key export/import.
class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  final _auth = AuthService();
  final _vault = VaultService();
  final _sync = SyncService();

  bool _biometricAvailable = false;
  bool _biometricEnabled = false;
  String? _serverUrl;
  String? _username;
  int _autoLockTimeout = 5; // minutes
  int _clipboardTimeout = 15; // seconds
  String? _fingerprint;
  List<KeptAsideVault> _keptAside = const [];
  // INV-7: the forget tile shows only where this phone, judging the server's
  // log now, refuses it as lost for good (teamLogMismatchForget).
  bool _teamLogLost = false;
  // R17-N9: this account's team changes the log or the server no longer took.
  List<Map<String, dynamic>> _teamChangesSetAside = const [];

  @override
  void initState() {
    super.initState();
    _loadSettings();
  }

  Future<void> _loadSettings() async {
    final prefs = await SharedPreferences.getInstance();
    final bioAvailable = await _auth.isBiometricAvailable();
    final bioEnabled = await _auth.isBiometricEnabled();
    final username = await _auth.getStoredUsername();
    final serverUrl = await _auth.getStoredServerUrl();
    final keptAside = await _auth.keptAsideVaults();

    // Compute fingerprint if vault is unlocked — use both signing + encryption pks
    String? fp;
    if (_vault.isUnlocked && _vault.signingPublicKey != null) {
      final crypto = CryptoService();
      final encPk = _vault.encryptionPublicKey ?? _vault.signingPublicKey!;
      fp = crypto.computeFingerprint(_vault.signingPublicKey!, encPk);
    }

    if (mounted) {
      setState(() {
        _biometricAvailable = bioAvailable;
        _biometricEnabled = bioEnabled;
        _username = username;
        _serverUrl = serverUrl;
        _autoLockTimeout = prefs.getInt('sezam_auto_lock') ?? 5;
        _clipboardTimeout = prefs.getInt('sezam_clipboard_timeout') ?? 15;
        _fingerprint = fp;
        _keptAside = keptAside;
      });
    }
    if (!_vault.isUnlocked) return;
    final setAside = await _sync.teamChangesSetAside();
    if (mounted) setState(() => _teamChangesSetAside = setAside);
    if (serverUrl == null) return;
    var lost = false;
    try {
      lost = (await _sync.teamLogRefusal())?.offersForget ?? false;
    } catch (_) {
      // Offline or the server refused: nothing judged, nothing offered.
    }
    if (mounted) setState(() => _teamLogLost = lost);
  }

  /// INV-7: the team log this phone refuses now, shown with its way out.
  Widget? _teamLogRefusalTile() {
    final refusal = _vault.teamLogRefusal;
    if (refusal == null) return null;
    return _settingsTile(
      icon: Icons.report_problem_outlined,
      title: 'Tímový denník odmietnutý',
      subtitle: '$refusal',
    );
  }

  /// R17-N9: what the log or the server no longer took, and why (the
  /// desktop's 'sezam team-log queue'); before, nothing showed it.
  Widget? _teamChangesSetAsideTile() {
    if (_teamChangesSetAside.isEmpty) return null;
    return _settingsTile(
      icon: Icons.playlist_remove_outlined,
      title: 'Odložené tímové zmeny (${_teamChangesSetAside.length})',
      subtitle: [
        for (final item in _teamChangesSetAside)
          '${item['type']} ${(item['data'] as Map?)?['user_id'] ?? ''}: ${item['reason']}',
      ].join('\n'),
    );
  }

  Future<void> _toggleBiometric(bool value) async {
    if (value) {
      // Enable: check if vault is unlocked and we have KEK
      if (!_vault.isUnlocked) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Vault must be unlocked first')),
        );
        return;
      }

      final kek = _vault.currentKek;
      if (kek == null) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('KEK not available. Re-unlock with password.'),
          ),
        );
        return;
      }

      final confirmed = await showDialog<bool>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('Enable Biometrics'),
          content: const Text(
            'Your encryption key will be stored under a hardware key '
            '(iOS Secure Enclave / Android Keystore) that is released only '
            'after FaceID or fingerprint. Enrolling a new fingerprint or face '
            'turns biometric unlock off.',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel'),
            ),
            ElevatedButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('Enable'),
            ),
          ],
        ),
      );

      if (confirmed == true) {
        // Store the KEK under a biometric-bound key (OS prompt on write).
        try {
          await _auth.enableBiometrics(kek);
        } catch (_) {
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(
                content: Text('Biometric unlock could not be enabled'),
              ),
            );
          }
          return;
        }
        if (!mounted) return;
        setState(() => _biometricEnabled = true);
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Biometric unlock enabled')),
          );
        }
      }
    } else {
      await _auth.disableBiometrics();
      setState(() => _biometricEnabled = false);
    }
  }

  Future<void> _setAutoLockTimeout(int minutes) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setInt('sezam_auto_lock', minutes);
    setState(() => _autoLockTimeout = minutes);
  }

  Future<void> _setClipboardTimeout(int seconds) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setInt('sezam_clipboard_timeout', seconds);
    setState(() => _clipboardTimeout = seconds);
  }

  void _navigateToServerConnect() {
    Navigator.of(context)
        .push(
          MaterialPageRoute(
            builder: (ctx) => const ServerConnectScreen(vaultUnlocked: true),
          ),
        )
        .then((result) {
          if (result == true) {
            _loadSettings(); // Reload to show updated server URL
          }
        });
  }

  Future<void> _confirmTeamFounder() async {
    try {
      final review = await _vault.reviewTeamFounder();
      if (!mounted) return;
      await showDialog<bool>(
        context: context,
        barrierDismissible: false,
        builder: (_) => TeamTrustDialog(review: review),
      );
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text(e.toString())));
      }
    }
  }

  Future<void> _forgetTeamPin() async {
    try {
      final pinned = await _sync.pinnedTeamGenesis();
      if (!mounted) return;
      if (pinned.isEmpty) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Telefón nemá pripnutý žiadny tímový denník.'),
          ),
        );
        return;
      }
      await showDialog<bool>(
        context: context,
        barrierDismissible: false,
        builder: (_) => TeamForgetPinDialog(pinned: pinned),
      );
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text(e.toString())));
      }
    }
  }

  // ── QR Provisioning ──

  void _openQRScanner() {
    HapticFeedback.lightImpact();
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (ctx) =>
            _QRScanScreen(onScanned: (qrData) => _handleQRProvisioning(qrData)),
      ),
    );
  }

  Future<void> _handleQRProvisioning(String qrData) async {
    // Parse QR data — expected format:
    //   sezam://provision?token=<TOKEN>&server=<SERVER_URL>&username=<USERNAME>
    // or just a raw provisioning token string
    String? token;
    String? serverUrl;
    String? username;

    final uri = Uri.tryParse(qrData);
    if (uri != null && uri.scheme == 'sezam' && uri.host == 'provision') {
      token = uri.queryParameters['token'];
      serverUrl = uri.queryParameters['server'];
      username = uri.queryParameters['username'];
    } else {
      // Treat the whole string as a provisioning token
      token = qrData.trim();
      serverUrl = _serverUrl;
      username = _username;
    }

    if (token == null || token.isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Invalid QR code: no provisioning token'),
          ),
        );
      }
      return;
    }

    // Prompt for password to decrypt the provisioned keypair
    final password = await _showPasswordPrompt(
      title: 'Enter Master Password',
      message:
          'Your master password is needed to decrypt the provisioned keypair.',
    );
    if (password == null || password.isEmpty) return;

    // Show loading
    if (mounted) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Provisioning device...')));
    }

    try {
      final result = await _auth.provisionFromQR(
        provisionToken: token,
        genesisFragment: uri?.scheme == 'sezam' && uri?.host == 'provision'
            ? uri!.fragment
            : '',
        username: username ?? '',
        password: password,
        serverUrl: serverUrl ?? _serverUrl ?? '',
      );

      if (mounted) {
        if (result.success) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Device provisioned successfully!')),
          );
          _loadSettings(); // reload
        } else {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Provisioning failed: ${result.error}')),
          );
        }
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Provisioning error: $e')));
      }
    }
  }

  // ── Remote AI kill switch ──

  Future<void> _pullAiBrake() async {
    final signingKey = _vault.signingSecretKey;
    final userId = _vault.userId;
    final serverUrl = _sync.serverUrl;
    if (!_vault.isUnlocked || signingKey == null || userId == null) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Najprv odomkni trezor')));
      return;
    }
    if (serverUrl == null || _username == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Najprv sa pripoj k serveru')),
      );
      return;
    }
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Vypnúť AI prístup?'),
        content: const Text(
          'Všetky počítače tohto účtu do ~30 s zatvoria AI agentom SSH '
          'spojenia a odmietnu ďalšie požiadavky. Znova zapnúť sa to dá '
          'len na počítači príkazom „sezam ai on“ s master heslom.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Zrušiť'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Vypnúť'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    HapticFeedback.heavyImpact();
    try {
      // A fresh token: the stored one may have expired.
      await _sync.authenticate(
        username: _username!,
        signingSecretKey: signingKey,
      );
      final crypto = CryptoService();
      final client = TimeoutClient(http.Client());
      final int epoch;
      try {
        epoch = await AiBrakeService.withClient(
          client,
          sign: (message) => crypto.signChallenge(message, signingKey),
        ).pullBrake(serverUrl: serverUrl, token: _sync.token!, userId: userId);
      } finally {
        client.close();
      }
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('AI prístup vypnutý (epoch $epoch)')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('AI prístup sa nepodarilo vypnúť: $e')),
        );
      }
    }
  }

  // ── .sezam-key Export / Import ──

  Future<void> _exportSezamKey() async {
    if (!_vault.isUnlocked) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Vault must be unlocked first')),
      );
      return;
    }

    final signingPk = _vault.signingPublicKey;
    final encryptionPk = _vault.encryptionPublicKey;

    if (signingPk == null || encryptionPk == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Keys not available. Re-unlock vault.')),
      );
      return;
    }

    try {
      final filePath = await _auth.exportSezamKey(
        signingPublicKey: signingPk,
        encryptionPublicKey: encryptionPk,
      );

      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Key exported to: $filePath')));
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Export failed: $e')));
      }
    }
  }

  Future<void> _importSezamKey() async {
    // Prompt for file path
    final filePath = await _showTextInputPrompt(
      title: 'Import .sezam-key',
      message: 'Enter the path to the .sezam-key file:',
      hintText: '/path/to/file.sezam-key',
    );
    if (filePath == null || filePath.isEmpty) return;

    // Prompt for password
    final password = await _showPasswordPrompt(
      title: 'Enter Master Password',
      message: 'Your master password is needed to decrypt the key file.',
    );
    if (password == null || password.isEmpty) return;

    try {
      await _auth.importSezamKey(filePath: filePath, password: password);

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Key imported successfully!')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Import failed: $e')));
      }
    }
  }

  Future<void> _saveUnsentBackup() async {
    final file = await _sync.latestUnsentExport();
    if (!mounted) return;
    if (file == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('No unsent-changes backup on this device.'),
        ),
      );
      return;
    }
    await saveUnsentExport(context, file.path);
  }

  /// Review 526419e N7: the vault an interrupted join set aside, made visible.
  Future<void> _openKeptAside(KeptAsideVault kept) async {
    const documents = DocumentService();
    // Review d150605 N4: that earlier join may have replaced the keys the
    // copy is sealed with; do not offer it as a rescue without checking.
    final opens = await _auth.keptAsideOpensHere(kept);
    if (!mounted) return;
    final readable = switch (opens) {
      true =>
        "It still opens with this phone's current password. Entries that "
            'are not on the server are only in it. Save a copy out of the '
            'app, or delete it once you are sure you do not need it.',
      false =>
        "It is sealed with this phone's keys from before the join, which "
            'that earlier version replaced without keeping them. Neither '
            'this app nor a saved copy can open it. Delete it unless you can '
            'restore those keys from a backup of the phone.',
      null =>
        'Unlock the vault to check whether it can still be opened. Entries '
            'that are not on the server may be only in it.',
    };
    final action = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Set-aside vault'),
        content: Text(
          'An account join in an earlier version was interrupted. This '
          "phone's own vault from before the join was kept on "
          '${_formatKeptAt(kept.keptAt)}. $readable',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Close'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx, 'delete'),
            child: const Text(
              'Delete',
              style: TextStyle(color: SezamColors.error),
            ),
          ),
          if (documents.isSupported)
            ElevatedButton(
              onPressed: () => Navigator.pop(ctx, 'save'),
              child: const Text('Save copy'),
            ),
        ],
      ),
    );
    if (!mounted || action == null) return;
    if (action == 'save') {
      try {
        for (final f in kept.files) {
          final name = f.uri.pathSegments.last;
          await documents.saveDocument(name, await f.readAsBytes());
        }
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(
            context,
          ).showSnackBar(SnackBar(content: Text('Save failed: $e')));
        }
      }
      return;
    }
    final sure = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Delete the set-aside vault?'),
        content: const Text('Anything only in this vault is lost for good.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text(
              'Delete',
              style: TextStyle(color: SezamColors.error),
            ),
          ),
        ],
      ),
    );
    if (sure != true) return;
    _auth.deleteKeptAsideVault(kept);
    await _loadSettings();
  }

  static String _formatKeptAt(DateTime t) =>
      '${t.year}-${t.month.toString().padLeft(2, '0')}-'
      '${t.day.toString().padLeft(2, '0')}';

  Future<void> _importUnsentChanges() async {
    const documents = DocumentService();
    if (!documents.isSupported) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Importing files is not supported here.')),
      );
      return;
    }
    try {
      final bytes = await documents.openDocument();
      if (bytes == null) return;
      final result = await _vault.reapplyUnsentChanges(
        parseUnsentExport(bytes),
      );
      if (!mounted) return;
      await showDialog<void>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('Unsent changes imported'),
          content: Text(
            '${describeUnsentReapply(result)}\n\n'
            'Restored changes will be sent with the next sync.',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: const Text('OK'),
            ),
          ],
        ),
      );
    } on FormatException catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Import failed: ${e.message}')));
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Import failed: $e')));
      }
    }
  }

  // ── Prompt helpers ──

  Future<String?> _showPasswordPrompt({
    required String title,
    required String message,
  }) async {
    final ctrl = TextEditingController();
    return showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(title),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              message,
              style: const TextStyle(
                color: SezamColors.textSecondary,
                fontSize: 14,
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: ctrl,
              obscureText: true,
              autofocus: true,
              decoration: const InputDecoration(
                hintText: 'Master password',
                prefixIcon: Icon(Icons.key_rounded),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, ctrl.text),
            child: const Text('OK'),
          ),
        ],
      ),
    );
  }

  Future<String?> _showTextInputPrompt({
    required String title,
    required String message,
    String? hintText,
  }) async {
    final ctrl = TextEditingController();
    return showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(title),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              message,
              style: const TextStyle(
                color: SezamColors.textSecondary,
                fontSize: 14,
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: ctrl,
              autofocus: true,
              decoration: InputDecoration(hintText: hintText),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(ctx, ctrl.text),
            child: const Text('OK'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        const SizedBox(height: 8),
        Text('Settings', style: Theme.of(context).textTheme.headlineMedium),
        const SizedBox(height: 24),

        // ── Account ──
        _sectionHeader('Account'),
        _settingsTile(
          icon: Icons.person_rounded,
          title: 'Username',
          subtitle: _username ?? 'Not configured',
        ),
        _settingsTile(
          icon: Icons.dns_rounded,
          title: 'Pripojit k serveru',
          subtitle: _serverUrl ?? 'Nie je nakonfigurovany',
          onTap: _navigateToServerConnect,
          trailing: const Icon(
            Icons.chevron_right_rounded,
            color: SezamColors.textMuted,
            size: 20,
          ),
        ),
        _settingsTile(
          icon: Icons.verified_user_outlined,
          title: 'Dôvera tímu',
          subtitle: 'Potvrdiť nezávislý odtlačok zakladateľa',
          onTap: _confirmTeamFounder,
        ),
        ?_teamLogRefusalTile(),
        ?_teamChangesSetAsideTile(),
        if (_teamLogLost)
          _settingsTile(
            icon: Icons.link_off_rounded,
            title: 'Zabudnúť pripnutý tímový denník',
            subtitle: 'Len pre denník stratený natrvalo (TEAM LOG MISMATCH)',
            onTap: _forgetTeamPin,
          ),
        _settingsTile(
          icon: Icons.devices_outlined,
          title: 'Dôvera tímu pre nové zariadenia',
          subtitle: 'Zmeniť heslo účtu a uložiť potvrdeného zakladateľa',
          onTap: () => showDialog<bool>(
            context: context,
            barrierDismissible: false,
            builder: (_) => const TeamAnchorPublishDialog(),
          ),
        ),
        if (_fingerprint != null)
          _settingsTile(
            icon: Icons.fingerprint_rounded,
            title: 'Key Fingerprint',
            subtitle: '${_fingerprint!.substring(0, 16)}...',
            onTap: () {
              HapticFeedback.lightImpact();
              showDialog(
                context: context,
                builder: (ctx) => AlertDialog(
                  title: const Text('Key Fingerprint'),
                  content: SelectableText(
                    _fingerprint!,
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12,
                      color: SezamColors.text,
                    ),
                  ),
                  actions: [
                    TextButton(
                      onPressed: () {
                        Clipboard.setData(ClipboardData(text: _fingerprint!));
                        Navigator.pop(ctx);
                      },
                      child: const Text('Copy'),
                    ),
                    TextButton(
                      onPressed: () => Navigator.pop(ctx),
                      child: const Text('Close'),
                    ),
                  ],
                ),
              );
            },
            trailing: const Icon(
              Icons.chevron_right_rounded,
              color: SezamColors.textMuted,
              size: 20,
            ),
          ),

        const SizedBox(height: 24),

        // ── Security ──
        _sectionHeader('Security'),
        if (_biometricAvailable)
          _switchTile(
            icon: Icons.fingerprint_rounded,
            title: 'Biometric Unlock',
            subtitle: 'FaceID / Fingerprint',
            value: _biometricEnabled,
            onChanged: _toggleBiometric,
          ),
        _dropdownTile(
          icon: Icons.timer_rounded,
          title: 'Auto-lock',
          value: _autoLockTimeout,
          items: const {
            1: '1 minute',
            5: '5 minutes',
            15: '15 minutes',
            30: '30 minutes',
            60: '1 hour',
          },
          onChanged: (v) => _setAutoLockTimeout(v!),
        ),
        _dropdownTile(
          icon: Icons.content_copy_rounded,
          title: 'Clipboard clear',
          value: _clipboardTimeout,
          items: const {
            10: '10 seconds',
            15: '15 seconds',
            30: '30 seconds',
            60: '60 seconds',
          },
          onChanged: (v) => _setClipboardTimeout(v!),
        ),

        _settingsTile(
          icon: Icons.smart_toy_outlined,
          title: 'Vypnúť AI prístup na počítačoch',
          subtitle:
              'Núdzová brzda: AI agenti stratia prístup do ~30 s. '
              'Zapnúť sa dá len na počítači s heslom.',
          onTap: _pullAiBrake,
          trailing: const Icon(
            Icons.power_settings_new_rounded,
            color: SezamColors.error,
            size: 20,
          ),
        ),

        const SizedBox(height: 24),

        // ── Key Management ──
        _sectionHeader('Key Management'),
        _settingsTile(
          icon: Icons.file_upload_rounded,
          title: 'Export .sezam-key',
          subtitle: 'Save encrypted keypair to file',
          onTap: _exportSezamKey,
          trailing: const Icon(
            Icons.chevron_right_rounded,
            color: SezamColors.textMuted,
            size: 20,
          ),
        ),
        _settingsTile(
          icon: Icons.file_download_rounded,
          title: 'Import .sezam-key',
          subtitle: 'Restore keypair from file',
          onTap: _importSezamKey,
          trailing: const Icon(
            Icons.chevron_right_rounded,
            color: SezamColors.textMuted,
            size: 20,
          ),
        ),
        _settingsTile(
          icon: Icons.save_alt_rounded,
          title: 'Save unsent-changes backup',
          subtitle: 'Copy the last full-resync backup out of the app',
          onTap: _saveUnsentBackup,
          trailing: const Icon(
            Icons.chevron_right_rounded,
            color: SezamColors.textMuted,
            size: 20,
          ),
        ),
        _settingsTile(
          icon: Icons.restore_page_rounded,
          title: 'Import unsent changes',
          subtitle: 'Put back changes from a saved backup',
          onTap: _importUnsentChanges,
          trailing: const Icon(
            Icons.chevron_right_rounded,
            color: SezamColors.textMuted,
            size: 20,
          ),
        ),
        for (final kept in _keptAside)
          _settingsTile(
            icon: Icons.inventory_2_outlined,
            title: 'Set-aside vault (${_formatKeptAt(kept.keptAt)})',
            subtitle: 'Your vault from before an interrupted account join',
            onTap: () => _openKeptAside(kept),
            trailing: const Icon(
              Icons.warning_amber_rounded,
              color: SezamColors.error,
              size: 20,
            ),
          ),

        const SizedBox(height: 24),

        // ── About ──
        _sectionHeader('About'),
        _settingsTile(
          icon: Icons.info_outline_rounded,
          title: 'Sezam Mobile',
          subtitle: 'v1.0.0 — E2E encrypted vault',
        ),
        _settingsTile(
          icon: Icons.security_rounded,
          title: 'Encryption',
          subtitle: 'XChaCha20-Poly1305 + Argon2id + Ed25519',
        ),

        const SizedBox(height: 24),

        // Device provisioning via QR
        OutlinedButton.icon(
          onPressed: _openQRScanner,
          icon: const Icon(Icons.qr_code_scanner_rounded),
          label: const Text('Provision via QR'),
          style: OutlinedButton.styleFrom(
            foregroundColor: SezamColors.accent,
            side: const BorderSide(color: SezamColors.borderAccent),
            padding: const EdgeInsets.symmetric(vertical: 14),
          ),
        ),

        const SizedBox(height: 40),
      ],
    );
  }

  Widget _sectionHeader(String title) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Text(
        title.toUpperCase(),
        style: const TextStyle(
          color: SezamColors.accent,
          fontSize: 12,
          fontWeight: FontWeight.w700,
          letterSpacing: 1.5,
        ),
      ),
    );
  }

  Widget _settingsTile({
    required IconData icon,
    required String title,
    String? subtitle,
    VoidCallback? onTap,
    Widget? trailing,
  }) {
    return Card(
      margin: const EdgeInsets.only(bottom: 6),
      child: ListTile(
        leading: Icon(icon, color: SezamColors.textSecondary, size: 22),
        title: Text(
          title,
          style: const TextStyle(color: SezamColors.text, fontSize: 15),
        ),
        subtitle: subtitle != null
            ? Text(
                subtitle,
                style: const TextStyle(
                  color: SezamColors.textMuted,
                  fontSize: 13,
                ),
              )
            : null,
        trailing: trailing,
        onTap: onTap,
      ),
    );
  }

  Widget _switchTile({
    required IconData icon,
    required String title,
    String? subtitle,
    required bool value,
    required ValueChanged<bool> onChanged,
  }) {
    return Card(
      margin: const EdgeInsets.only(bottom: 6),
      child: SwitchListTile(
        secondary: Icon(icon, color: SezamColors.textSecondary, size: 22),
        title: Text(
          title,
          style: const TextStyle(color: SezamColors.text, fontSize: 15),
        ),
        subtitle: subtitle != null
            ? Text(
                subtitle,
                style: const TextStyle(
                  color: SezamColors.textMuted,
                  fontSize: 13,
                ),
              )
            : null,
        value: value,
        onChanged: onChanged,
        activeColor: SezamColors.accent,
      ),
    );
  }

  Widget _dropdownTile<T>({
    required IconData icon,
    required String title,
    required T value,
    required Map<T, String> items,
    required ValueChanged<T?> onChanged,
  }) {
    return Card(
      margin: const EdgeInsets.only(bottom: 6),
      child: ListTile(
        leading: Icon(icon, color: SezamColors.textSecondary, size: 22),
        title: Text(
          title,
          style: const TextStyle(color: SezamColors.text, fontSize: 15),
        ),
        trailing: DropdownButton<T>(
          value: value,
          items: items.entries
              .map(
                (e) => DropdownMenuItem<T>(
                  value: e.key,
                  child: Text(
                    e.value,
                    style: const TextStyle(
                      color: SezamColors.textSecondary,
                      fontSize: 13,
                    ),
                  ),
                ),
              )
              .toList(),
          onChanged: onChanged,
          dropdownColor: SezamColors.bgElevated,
          underline: const SizedBox(),
        ),
      ),
    );
  }
}

// ── QR Scanner Screen ──

class _QRScanScreen extends StatefulWidget {
  final void Function(String qrData) onScanned;

  const _QRScanScreen({required this.onScanned});

  @override
  State<_QRScanScreen> createState() => _QRScanScreenState();
}

class _QRScanScreenState extends State<_QRScanScreen> {
  MobileScannerController? _controller;
  bool _scanned = false;

  @override
  void initState() {
    super.initState();
    _controller = MobileScannerController();
  }

  @override
  void dispose() {
    _controller?.dispose();
    super.dispose();
  }

  void _onDetect(BarcodeCapture capture) {
    if (_scanned) return;
    final barcode = capture.barcodes.firstOrNull;
    if (barcode == null) return;
    final code = barcode.rawValue;
    if (code == null || code.isEmpty) return;

    _scanned = true;
    _controller?.stop();
    HapticFeedback.heavyImpact();

    // Pop back and pass the scanned data
    Navigator.of(context).pop();
    widget.onScanned(code);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Scan QR Code'),
        backgroundColor: SezamColors.bg,
      ),
      body: Stack(
        children: [
          MobileScanner(controller: _controller, onDetect: _onDetect),
          const Positioned(
            bottom: 80,
            left: 0,
            right: 0,
            child: Text(
              'Point camera at the provisioning QR code\nfrom your desktop app',
              textAlign: TextAlign.center,
              style: TextStyle(
                color: Colors.white,
                fontSize: 15,
                fontWeight: FontWeight.w500,
                shadows: [Shadow(blurRadius: 8, color: Colors.black)],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

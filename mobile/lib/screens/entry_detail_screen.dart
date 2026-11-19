import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../theme/sezam_theme.dart';
import '../models/vault_models.dart';
import '../services/vault_service.dart';
import '../services/sync_service.dart';
import '../services/sync_limits.dart';
import '../services/totp_service.dart';
import '../services/share_service.dart';
import '../services/clipboard_service.dart';
import '../widgets/team_log_errors.dart';

class EntryDetailScreen extends StatefulWidget {
  final Map<String, dynamic> entryArgs;
  final ClipboardService? clipboardService;

  const EntryDetailScreen({
    super.key,
    required this.entryArgs,
    this.clipboardService,
  });

  @override
  State<EntryDetailScreen> createState() => _EntryDetailScreenState();
}

class _EntryDetailScreenState extends State<EntryDetailScreen>
    with SingleTickerProviderStateMixin {
  late AnimationController _animController;
  int? _clipboardCountdown;
  Timer? _clipboardTimer;
  Timer? _totpTimer;

  final _vault = VaultService();
  final _sync = SyncService();
  final _totp = TotpService();
  final _share = ShareService();
  late final ClipboardService _clipboard;

  VaultEntry? _entry;

  @override
  void initState() {
    super.initState();
    _clipboard = widget.clipboardService ?? ClipboardService.shared;
    _animController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 600),
    )..forward();

    _loadEntry();
    _startTotpTimer();
  }

  void _loadEntry() {
    final entryId = widget.entryArgs['entryId'] as String?;
    if (entryId != null && _vault.isUnlocked) {
      _entry = _vault.readEntry(entryId);
    }
  }

  void _startTotpTimer() {
    // Update TOTP codes every second
    _totpTimer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted) setState(() {});
    });
  }

  @override
  void dispose() {
    _animController.dispose();
    _clipboardTimer?.cancel();
    _totpTimer?.cancel();
    super.dispose();
  }

  Future<int> _copyField(String value, {bool showCopiedMessage = true}) async {
    final prefs = await SharedPreferences.getInstance();
    final timeout = prefs.getInt('sezam_clipboard_timeout') ?? 15;
    await _clipboard.copySensitive(value, timeout: Duration(seconds: timeout));
    HapticFeedback.mediumImpact();

    if (!mounted) return timeout;
    _clipboardTimer?.cancel();
    setState(() => _clipboardCountdown = timeout);

    _clipboardTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
      if (_clipboardCountdown! <= 1) {
        timer.cancel();
        if (mounted) {
          setState(() => _clipboardCountdown = null);
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Clipboard auto-clear complete'),
              duration: Duration(seconds: 2),
            ),
          );
        }
      } else if (mounted) {
        setState(() => _clipboardCountdown = _clipboardCountdown! - 1);
      }
    });

    if (showCopiedMessage) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Copied! Auto-clear in ${timeout}s'),
          duration: const Duration(seconds: 2),
        ),
      );
    }
    return timeout;
  }

  void _showEditDialog() {
    if (_entry == null) return;
    HapticFeedback.lightImpact();

    final nameCtrl = TextEditingController(text: _entry!.name);
    // The version this form shows; saving must not overwrite a newer one.
    final baseVersion = _entry!.version;
    bool shared = _entry!.writePolicy == 'shared';
    final fields = _entry!.fields
        .map(
          (f) => {
            'key': TextEditingController(text: f.key),
            'value': TextEditingController(text: f.value),
            'sensitive': f.sensitive,
            'totp': f.totp,
          },
        )
        .toList();

    showDialog(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setDialogState) => AlertDialog(
          title: const Text('Edit Entry'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                TextField(
                  controller: nameCtrl,
                  decoration: const InputDecoration(labelText: 'Entry name'),
                ),
                const SizedBox(height: 16),
                ...fields.asMap().entries.map((e) {
                  final i = e.key;
                  final f = e.value;
                  return Padding(
                    padding: const EdgeInsets.only(bottom: 8),
                    child: Row(
                      children: [
                        Expanded(
                          flex: 2,
                          child: TextField(
                            controller: f['key'] as TextEditingController,
                            decoration: const InputDecoration(hintText: 'Key'),
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          flex: 3,
                          child: TextField(
                            controller: f['value'] as TextEditingController,
                            decoration: const InputDecoration(
                              hintText: 'Value',
                            ),
                            obscureText: f['sensitive'] as bool,
                          ),
                        ),
                        IconButton(
                          icon: const Icon(
                            Icons.remove_circle_outline,
                            size: 20,
                            color: SezamColors.error,
                          ),
                          onPressed: () {
                            setDialogState(() => fields.removeAt(i));
                          },
                        ),
                      ],
                    ),
                  );
                }),
                TextButton.icon(
                  onPressed: () {
                    setDialogState(() {
                      fields.add({
                        'key': TextEditingController(),
                        'value': TextEditingController(),
                        'sensitive': false,
                        'totp': null,
                      });
                    });
                  },
                  icon: const Icon(Icons.add, size: 18),
                  label: const Text('Add field'),
                ),
                const Divider(height: 8),
                SwitchListTile(
                  contentPadding: EdgeInsets.zero,
                  dense: true,
                  value: shared,
                  onChanged: (v) => setDialogState(() => shared = v),
                  title: const Text('Shared'),
                  subtitle: const Text(
                    'Anyone with vault access can edit',
                    style: TextStyle(fontSize: 11),
                  ),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('Cancel'),
            ),
            ElevatedButton(
              onPressed: () async {
                final updatedFields = fields
                    .where(
                      (f) =>
                          (f['key'] as TextEditingController).text.isNotEmpty,
                    )
                    .map((f) {
                      final key = (f['key'] as TextEditingController).text;
                      return EntryField(
                        key: key,
                        value: (f['value'] as TextEditingController).text,
                        sensitive:
                            f['sensitive'] as bool? ??
                            key.toLowerCase().contains('password') ||
                                key.toLowerCase().contains('secret') ||
                                key.toLowerCase().contains('token'),
                        totp: f['totp'] as String?,
                      );
                    })
                    .toList();

                try {
                  final saved = await runTeamLogWrite(
                    context,
                    () => _vault.updateEntry(
                      entryId: _entry!.id,
                      name: nameCtrl.text,
                      fields: updatedFields,
                      writePolicy: shared ? 'shared' : 'owner_only',
                      expectedVersion: baseVersion,
                    ),
                  );
                  if (!saved) return;
                } on SyncObjectTooLargeException catch (e) {
                  // Review d150605 N1: not saved, and the user is told why.
                  if (mounted) {
                    ScaffoldMessenger.of(
                      context,
                    ).showSnackBar(SnackBar(content: Text(e.toString())));
                  }
                  return;
                } on StaleEntryEditException {
                  if (ctx.mounted) Navigator.pop(ctx);
                  if (mounted) {
                    setState(() => _entry = _vault.readEntry(_entry!.id));
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                        content: Text(
                          'Záznam bol medzitým zmenený. Zobrazujem novšiu '
                          'verziu, uprav ju znova.',
                        ),
                      ),
                    );
                  }
                  return;
                }

                // Push changes
                try {
                  await _sync.push();
                } catch (_) {}

                if (mounted) {
                  Navigator.pop(ctx);
                  setState(() {
                    _entry = _vault.readEntry(_entry!.id);
                  });
                }
              },
              child: const Text('Save'),
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_entry == null) {
      return Scaffold(
        appBar: AppBar(title: const Text('Entry')),
        body: const Center(child: Text('Entry not found')),
      );
    }

    final entry = _entry!;
    final tags = entry.tags;
    final canEdit = entry.canEdit(_vault.userId, _vault.isAdmin);

    return Scaffold(
      appBar: AppBar(
        title: Text(entry.name),
        actions: [
          IconButton(
            icon: const Icon(Icons.share_rounded),
            onPressed: () => _showShareDialog(context),
            tooltip: 'Share',
          ),
          // Ownership ACL (spec 3.4): only the owner/admin (or 'shared'
          // entries) may edit or delete. Others get read-only access.
          if (canEdit) ...[
            IconButton(
              icon: const Icon(Icons.edit_rounded),
              onPressed: _showEditDialog,
            ),
            IconButton(
              icon: const Icon(Icons.delete_rounded, color: SezamColors.error),
              onPressed: () => _confirmDelete(context),
            ),
          ],
        ],
      ),
      body: Column(
        children: [
          // Read-only badge — shown when the current user cannot edit
          if (!canEdit)
            Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 16),
              color: SezamColors.bgElevated,
              child: Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const Icon(
                    Icons.lock_outline_rounded,
                    size: 16,
                    color: SezamColors.textSecondary,
                  ),
                  const SizedBox(width: 8),
                  Text(
                    'Read-only — owned by another user',
                    style: const TextStyle(
                      color: SezamColors.textSecondary,
                      fontSize: 13,
                    ),
                  ),
                ],
              ),
            ),

          // Clipboard countdown
          if (_clipboardCountdown != null)
            Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(vertical: 8),
              color: SezamColors.accentDim.withValues(alpha: 0.3),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const Icon(
                    Icons.timer_rounded,
                    size: 16,
                    color: SezamColors.accent,
                  ),
                  const SizedBox(width: 8),
                  Text(
                    'Clipboard clearing in ${_clipboardCountdown}s',
                    style: const TextStyle(
                      color: SezamColors.accent,
                      fontSize: 13,
                    ),
                  ),
                ],
              ),
            ),

          Expanded(
            child: ListView(
              padding: const EdgeInsets.all(16),
              children: [
                // Tags
                if (tags.isNotEmpty)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 16),
                    child: Wrap(
                      spacing: 8,
                      children: tags
                          .map(
                            (tag) => Chip(
                              label: Text(
                                '#$tag',
                                style: const TextStyle(fontSize: 12),
                              ),
                              backgroundColor: SezamColors.bgElevated,
                              side: const BorderSide(
                                color: SezamColors.borderAccent,
                              ),
                              padding: EdgeInsets.zero,
                              visualDensity: VisualDensity.compact,
                            ),
                          )
                          .toList(),
                    ),
                  ),

                // Fields with staggered animation
                ...entry.fields.asMap().entries.map((e) {
                  final index = e.key;
                  final field = e.value;
                  final delay = index * 0.12;
                  final progress = (_animController.value - delay).clamp(
                    0.0,
                    1.0,
                  );
                  final curve = Curves.easeOutBack.transform(progress);

                  return Transform.translate(
                    offset: Offset(40 * (1 - curve), 0),
                    child: Opacity(
                      opacity: curve,
                      child: field.totp != null
                          ? _TotpFieldCard(
                              fieldKey: field.key,
                              totpSecret: field.totp!,
                              totpService: _totp,
                              onCopy: (code) => _copyField(code),
                            )
                          : _FieldCard(
                              fieldKey: field.key,
                              value: field.value,
                              sensitive: field.sensitive,
                              onCopy: () => _copyField(field.value),
                            ),
                    ),
                  );
                }),

                // Notes section
                if (entry.notes != null && entry.notes!.isNotEmpty) ...[
                  const SizedBox(height: 16),
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'NOTES',
                            style: Theme.of(context).textTheme.labelLarge,
                          ),
                          const SizedBox(height: 8),
                          Text(
                            entry.notes!,
                            style: const TextStyle(
                              color: SezamColors.text,
                              fontSize: 14,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }

  void _showShareDialog(BuildContext context) {
    if (_entry == null) return;
    HapticFeedback.lightImpact();

    int expiryMinutes = 1440;
    int maxViews = 1;
    String pin = '';
    bool notifyOnView = true;

    showDialog(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setDialogState) => AlertDialog(
          title: const Text('Share Entry'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Create a secure share link for "${_entry!.name}".',
                style: const TextStyle(
                  color: SezamColors.textSecondary,
                  fontSize: 14,
                ),
              ),
              const SizedBox(height: 16),
              DropdownButtonFormField<int>(
                value: expiryMinutes,
                decoration: const InputDecoration(labelText: 'Expires after'),
                items: const [
                  DropdownMenuItem(value: 15, child: Text('15 minutes')),
                  DropdownMenuItem(value: 60, child: Text('1 hour')),
                  DropdownMenuItem(value: 1440, child: Text('24 hours')),
                  DropdownMenuItem(value: 10080, child: Text('7 days')),
                ],
                onChanged: (v) => setDialogState(() => expiryMinutes = v!),
              ),
              const SizedBox(height: 12),
              DropdownButtonFormField<int>(
                value: maxViews,
                decoration: const InputDecoration(labelText: 'Max views'),
                items: const [
                  DropdownMenuItem(value: 1, child: Text('1 view')),
                  DropdownMenuItem(value: 3, child: Text('3 views')),
                  DropdownMenuItem(value: 10, child: Text('10 views')),
                ],
                onChanged: (v) => setDialogState(() => maxViews = v!),
              ),
              const SizedBox(height: 12),
              TextField(
                obscureText: true,
                maxLength: 128,
                decoration: const InputDecoration(
                  labelText: 'PIN (optional)',
                  counterText: '',
                ),
                onChanged: (value) => pin = value,
              ),
              SwitchListTile(
                contentPadding: EdgeInsets.zero,
                title: const Text('Notify me when viewed'),
                value: notifyOnView,
                onChanged: (value) =>
                    setDialogState(() => notifyOnView = value),
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
                Navigator.pop(ctx);
                await _createShareLink(
                  expiryMinutes,
                  maxViews,
                  pin.isEmpty ? null : pin,
                  notifyOnView,
                );
              },
              child: const Text('Create Link'),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _createShareLink(
    int expiryMinutes,
    int maxViews,
    String? pin,
    bool notifyOnView,
  ) async {
    if (_entry == null) return;

    final serverUrl = _sync.serverUrl;
    if (serverUrl == null || serverUrl.isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(const SnackBar(content: Text('Server not configured')));
      }
      return;
    }

    if (!_sync.isAuthenticated) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Not authenticated with server')),
        );
      }
      return;
    }

    try {
      final entryJson = _entry!.toJson();
      final token = _sync.token ?? '';
      final result = await _share.createShareLink(
        entry: entryJson,
        serverUrl: serverUrl,
        token: token,
        expiryMinutes: expiryMinutes,
        maxViews: maxViews,
        pin: pin,
        notifyOnView: notifyOnView,
      );

      if (mounted) {
        final clipboardTimeout = await _copyField(
          result.shareUrl,
          showCopiedMessage: false,
        );
        if (!mounted) return;

        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              'Share link copied. Auto-clear in ${clipboardTimeout}s.',
            ),
            duration: const Duration(seconds: 3),
          ),
        );

        // Also show a dialog with the URL
        showDialog(
          context: context,
          builder: (ctx) => AlertDialog(
            title: const Text('Share Link Created'),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Link copied and scheduled for auto-clear in '
                  '${clipboardTimeout}s. Clipboard managers may retain it.',
                  style: const TextStyle(
                    color: SezamColors.textSecondary,
                    fontSize: 14,
                  ),
                ),
                const SizedBox(height: 12),
                SelectableText(
                  result.shareUrl,
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 11,
                    color: SezamColors.accent,
                  ),
                ),
                const SizedBox(height: 12),
                Text(
                  'Expires in $expiryMinutes min, $maxViews view(s)',
                  style: const TextStyle(
                    color: SezamColors.textMuted,
                    fontSize: 12,
                  ),
                ),
              ],
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(ctx),
                child: const Text('OK'),
              ),
            ],
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Failed to create share: $e')));
      }
    }
  }

  void _confirmDelete(BuildContext context) {
    HapticFeedback.heavyImpact();
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Delete Entry'),
        content: Text(
          'Are you sure you want to delete "${_entry?.name ?? ''}"?',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () async {
              if (_entry != null) {
                final deleted = await runTeamLogWrite(
                  context,
                  () => _vault.deleteEntry(_entry!.id),
                );
                if (!deleted) {
                  if (ctx.mounted) Navigator.pop(ctx);
                  return;
                }
                // Push the deletion
                try {
                  await _sync.push();
                } catch (_) {}
              }
              if (mounted) {
                Navigator.pop(ctx);
                Navigator.pop(context);
              }
            },
            child: const Text(
              'Delete',
              style: TextStyle(color: SezamColors.error),
            ),
          ),
        ],
      ),
    );
  }
}

// ── Field Card (standard) ──

class _FieldCard extends StatefulWidget {
  final String fieldKey;
  final String value;
  final bool sensitive;
  final VoidCallback onCopy;

  const _FieldCard({
    required this.fieldKey,
    required this.value,
    required this.sensitive,
    required this.onCopy,
  });

  @override
  State<_FieldCard> createState() => _FieldCardState();
}

class _FieldCardState extends State<_FieldCard> {
  bool _revealed = false;

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            // Key
            SizedBox(
              width: 100,
              child: Text(
                widget.fieldKey.toUpperCase(),
                style: Theme.of(context).textTheme.labelLarge,
              ),
            ),
            const SizedBox(width: 12),

            // Value
            Expanded(
              child: Text(
                widget.sensitive && !_revealed
                    ? '\u2022 \u2022 \u2022 \u2022 \u2022 \u2022 \u2022 \u2022'
                    : widget.value,
                style: TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 15,
                  color: widget.sensitive && !_revealed
                      ? SezamColors.textMuted
                      : SezamColors.text,
                  letterSpacing: widget.sensitive && !_revealed ? 3 : 0,
                ),
              ),
            ),

            // Actions
            if (widget.sensitive)
              IconButton(
                icon: Icon(
                  _revealed
                      ? Icons.visibility_off_rounded
                      : Icons.visibility_rounded,
                  size: 20,
                  color: SezamColors.textSecondary,
                ),
                onPressed: () {
                  HapticFeedback.lightImpact();
                  setState(() => _revealed = !_revealed);
                },
              ),
            IconButton(
              icon: const Icon(
                Icons.copy_rounded,
                size: 20,
                color: SezamColors.textSecondary,
              ),
              onPressed: widget.onCopy,
            ),
          ],
        ),
      ),
    );
  }
}

// ── TOTP Field Card with countdown ──

class _TotpFieldCard extends StatefulWidget {
  final String fieldKey;
  final String totpSecret;
  final TotpService totpService;
  final void Function(String code) onCopy;

  const _TotpFieldCard({
    required this.fieldKey,
    required this.totpSecret,
    required this.totpService,
    required this.onCopy,
  });

  @override
  State<_TotpFieldCard> createState() => _TotpFieldCardState();
}

class _TotpFieldCardState extends State<_TotpFieldCard> {
  bool _waiting = false;

  /// M-mobile-2: If remaining < 5s, wait for next TOTP period before copying.
  Future<void> _handleCopy() async {
    final remaining = widget.totpService.getRemainingSeconds();
    if (remaining < 5) {
      setState(() => _waiting = true);
      // Wait for the next TOTP period
      await Future.delayed(Duration(seconds: remaining + 1));
      if (!mounted) return;
      setState(() => _waiting = false);
    }
    // Generate fresh code after potential wait
    final freshCode = widget.totpService.generateCode(widget.totpSecret);
    widget.onCopy(freshCode);
  }

  @override
  Widget build(BuildContext context) {
    final code = widget.totpService.generateCode(widget.totpSecret);
    final remaining = widget.totpService.getRemainingSeconds();
    final progress = widget.totpService.getProgress();

    // Format code as "XXX XXX" for readability
    final formattedCode = code.length == 6
        ? '${code.substring(0, 3)} ${code.substring(3)}'
        : code;

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            // TOTP icon with countdown
            SizedBox(
              width: 40,
              height: 40,
              child: Stack(
                children: [
                  CircularProgressIndicator(
                    value: 1.0 - progress,
                    strokeWidth: 3,
                    backgroundColor: SezamColors.border,
                    color: remaining <= 5
                        ? SezamColors.error
                        : SezamColors.accent,
                  ),
                  Center(
                    child: Text(
                      '$remaining',
                      style: TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.bold,
                        color: remaining <= 5
                            ? SezamColors.error
                            : SezamColors.accent,
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(width: 16),

            // Label + code
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    widget.fieldKey.toUpperCase(),
                    style: Theme.of(context).textTheme.labelLarge,
                  ),
                  const SizedBox(height: 4),
                  Text(
                    formattedCode,
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 24,
                      fontWeight: FontWeight.bold,
                      color: SezamColors.text,
                      letterSpacing: 4,
                    ),
                  ),
                ],
              ),
            ),

            // Copy button — shows spinner while waiting for fresh code
            _waiting
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : IconButton(
                    icon: const Icon(
                      Icons.copy_rounded,
                      size: 20,
                      color: SezamColors.textSecondary,
                    ),
                    tooltip: remaining < 5
                        ? 'Will wait for fresh code...'
                        : 'Copy TOTP code',
                    onPressed: _handleCopy,
                  ),
          ],
        ),
      ),
    );
  }
}

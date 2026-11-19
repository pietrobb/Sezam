import 'dart:math';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../theme/sezam_theme.dart';
import '../widgets/entry_card.dart';
import '../widgets/folder_chip.dart';
import '../widgets/password_prompt.dart';
import '../widgets/search_bar.dart';
import '../widgets/unsent_changes_dialog.dart';
import '../models/vault_models.dart';
import '../services/vault_service.dart';
import '../services/sync_service.dart';
import '../services/sync_limits.dart';
import '../services/sync_recovery.dart';
import '../services/auth_service.dart';
import '../services/clipboard_service.dart';
import 'settings_screen.dart';
import 'server_connect_screen.dart';

/// Main vault screen with tree, search, and entry list.
class VaultScreen extends StatefulWidget {
  const VaultScreen({super.key});

  @override
  State<VaultScreen> createState() => _VaultScreenState();
}

class _VaultScreenState extends State<VaultScreen>
    with SingleTickerProviderStateMixin {
  int _currentIndex = 0;
  String? _selectedFolderId;
  String _searchQuery = '';
  late AnimationController _listAnimController;
  bool _isSyncing = false;

  final _vault = VaultService();
  final _sync = SyncService();
  final _auth = AuthService();

  @override
  void initState() {
    super.initState();
    _listAnimController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 800),
    )..forward();
  }

  @override
  void dispose() {
    _listAnimController.dispose();
    super.dispose();
  }

  List<VaultNode> get _folders {
    if (!_vault.isUnlocked) return [];
    final rootId = _vault.rootNodeId;
    return _vault.listNodes(rootId);
  }

  List<VaultEntry> get _filteredEntries {
    if (!_vault.isUnlocked) return [];

    List<VaultEntry> entries;

    if (_searchQuery.isNotEmpty) {
      entries = _vault.search(_searchQuery);
    } else if (_selectedFolderId != null) {
      entries = _vault.listEntries(_selectedFolderId);
    } else {
      entries = _vault.allEntries;
    }

    return entries;
  }

  int _entryCountForFolder(String folderId) {
    return _vault.listEntries(folderId).length;
  }

  IconData _iconForFolder(String? iconName) {
    switch (iconName) {
      case 'dns':
        return Icons.dns_rounded;
      case 'business':
        return Icons.business_rounded;
      case 'person':
        return Icons.person_rounded;
      case 'account_balance':
        return Icons.account_balance_rounded;
      case 'code':
        return Icons.code_rounded;
      case 'cloud':
        return Icons.cloud_rounded;
      case 'vpn_key':
        return Icons.vpn_key_rounded;
      case 'wifi':
        return Icons.wifi_rounded;
      case 'lock':
        return Icons.lock_rounded;
      default:
        return Icons.folder_rounded;
    }
  }

  Future<void> _syncVault() async {
    if (_isSyncing) return;

    // Check if server is configured
    if (!_sync.isConfigured) {
      // Show dialog offering to configure server
      _showNoServerDialog();
      return;
    }

    setState(() => _isSyncing = true);
    HapticFeedback.lightImpact();

    try {
      // If not authenticated yet, try to authenticate first
      if (!_sync.isAuthenticated) {
        final prefs = await SharedPreferences.getInstance();
        final username = prefs.getString('sezam_username');
        final signingKey = _vault.signingSecretKey;
        if (username != null && signingKey != null) {
          await _sync.authenticate(
            username: username,
            signingSecretKey: signingKey,
          );
        }
      }

      // Push local changes first, then pull (SyncService.sync reloads the
      // decrypted cache when the pull brought anything new).
      final cycle = await _sync.sync();
      final result = cycle.pull;
      if (result.newObjects > 0 && mounted) {
        setState(() {}); // trigger rebuild with new data
      }
      if (mounted && cycle.push.errors.isNotEmpty) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              '${cycle.push.errors.length} change(s) were not accepted by '
              'the server',
            ),
            duration: const Duration(seconds: 3),
          ),
        );
      }
      if (mounted && result.conflicts.isNotEmpty) {
        await _resolveConflicts(result.conflicts);
      }
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              result.newObjects > 0
                  ? 'Synced ${result.newObjects} objects'
                  : result.conflicts.isNotEmpty
                  ? '${result.conflicts.length} conflict(s) preserved'
                  : 'Already up to date',
            ),
            duration: const Duration(seconds: 2),
          ),
        );
      }
    } on FullResyncRequiredException {
      if (mounted) await _confirmAndRunFullResync();
    } on KeyEpochStaleException {
      // Password changed on another device: take it over, then sync again.
      final password = await _askServerPassword();
      if (password != null && password.isNotEmpty) {
        final adopted = await _auth.adoptPasswordChangedElsewhere(
          currentPassword: password,
        );
        if (mounted) {
          if (adopted.success) {
            setState(() => _isSyncing = false);
            return _syncVault();
          }
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text(adopted.error ?? 'Wrong password')),
          );
        }
      }
    } on AccountLostOnServerException catch (lost) {
      // Review 8595ec1 #1: the server was restored from a backup older than
      // this account; the team log brings it back under its id.
      final password = await _askServerPassword(reason: lost.message);
      if (password != null && password.isNotEmpty) {
        var rejoined = await _auth.rejoinServer(password: password);
        while (mounted && rejoined.usernameTaken) {
          final name = await _askNewUsername(rejoined.error ?? '');
          if (name == null || name.isEmpty) break;
          rejoined = await _auth.rejoinServer(password: password, newUsername: name);
        }
        if (mounted) {
          if (rejoined.success) {
            setState(() => _isSyncing = false);
            return _syncVault();
          }
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text(rejoined.error ?? 'Rejoin failed')),
          );
        }
      }
    } on TofuKeyChangeException catch (change) {
      if (mounted && await _confirmTofuKeyChange(change)) {
        await _sync.acceptTofuKeyChange(change, change.newFingerprint);
        if (mounted) {
          setState(() => _isSyncing = false);
          return _syncVault();
        }
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              'Sync failed: ${e.toString().split(':').last.trim()}',
            ),
            duration: const Duration(seconds: 3),
          ),
        );
      }
    }

    if (mounted) setState(() => _isSyncing = false);
  }

  /// Resolve each conflicting object on its own: keep this device's change
  /// (rebased on the server version, then pushed) or take the server's copy.
  Future<void> _resolveConflicts(List<PullConflict> conflicts) async {
    final useServer = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Sync conflict'),
        content: Text(
          [
            'Záznam bol zmenený inde. Lokálna zmena zostala zachovaná.',
            ...conflicts.map(
              (conflict) =>
                  '${conflict.objectType} ${conflict.id}: '
                  'local v${conflict.localVersion} / '
                  'server v${conflict.serverVersion}',
            ),
          ].join('\n\n'),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Keep my changes'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('Use server versions'),
          ),
        ],
      ),
    );
    if (useServer == null || !mounted) return;

    var unresolved = 0;
    for (final conflict in conflicts) {
      final resolved = useServer
          ? await _vault.takeServerVersion(conflict.id)
          : await _vault.keepLocalChange(conflict.id, conflict.serverVersion);
      if (!resolved) unresolved++;
    }
    if (!useServer) {
      try {
        await _sync.push();
      } catch (_) {
        // Stays dirty on top of the server version; the next sync pushes it.
      }
    }
    if (!mounted) return;
    setState(() {});
    if (unresolved == 0) return;
    if (useServer) {
      // Shadows from before the per-object copy was stored: only a full
      // resync (which exports the local ciphertext first) can take them.
      await _confirmAndRunFullResync();
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            '$unresolved change(s) cannot be kept on this device; they stay '
            'held aside until you take the server version.',
          ),
        ),
      );
    }
  }

  /// The password the server has now: changed on another device, or an older
  /// one of a server restored from a backup.
  Future<String?> _askServerPassword({String? reason}) async {
    if (!mounted) return null;
    return showPasswordPrompt(
      context,
      title: reason == null ? 'Password changed' : 'Account missing on the server',
      message:
          reason ??
          'The server has another master password (changed on another '
              'device, or the server was restored from a backup). Enter that '
              'password to keep syncing.',
    );
  }

  /// Review 4acfdde R11 (low): another account took this account's name
  /// after the backup; the rejoin goes on under the name given here.
  Future<String?> _askNewUsername(String why) async {
    if (!mounted) return null;
    final controller = TextEditingController();
    try {
      return await showDialog<String>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('Name taken on the server'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(why),
              TextField(
                controller: controller,
                autofocus: true,
                decoration: const InputDecoration(labelText: 'New username'),
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () => Navigator.of(ctx).pop(controller.text.trim()),
              child: const Text('Rejoin'),
            ),
          ],
        ),
      );
    } finally {
      controller.dispose();
    }
  }

  Future<void> _confirmAndRunFullResync() async {
    final dirtyCount = await _sync.getDirtyObjectCount();
    if (!mounted) return;
    final confirmed = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => AlertDialog(
        title: const Text('Full resync required'),
        content: Text(
          dirtyCount > 0
              ? 'Máte $dirtyCount nesynchronizovaných zmien. Full resync ich prepíše. '
                    'Pred pokračovaním sa exportujú ako šifrovaná záloha, po resyncu sa vrátia '
                    'späť a zálohu si môžete uložiť mimo aplikácie.'
              : 'Server odstránil staré tombstones. Full resync nahradí celý lokálny snapshot.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('Export & full resync'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;

    try {
      final result = await fullResyncTakingPasswordOver(
        fullResync: () => _sync.fullResync(confirmed: true),
        askPassword: _askServerPassword,
        takeOver: (password) =>
            _auth.adoptPasswordChangedElsewhere(currentPassword: password),
        onRefused: (error) {
          if (!mounted) return;
          ScaffoldMessenger.of(
            context,
          ).showSnackBar(SnackBar(content: Text(error)));
        },
      );
      if (result == null || !mounted) return;
      setState(() {});
      final exportPath = result.dirtyExportPath;
      if (exportPath == null) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              'Full resync complete: ${result.pull.newObjects} objects.',
            ),
            duration: const Duration(seconds: 6),
          ),
        );
        return;
      }
      await showUnsentChangesResult(
        context,
        title: 'Full resync complete',
        result: result.reapplied,
        exportPath: exportPath,
      );
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            'Full resync failed: ${e.toString().split(':').last.trim()}',
          ),
          duration: const Duration(seconds: 4),
        ),
      );
    }
  }

  /// Sync stops on a changed peer key until the user compares the new
  /// fingerprint out of band (call, in person) and explicitly accepts it.
  Future<bool> _confirmTofuKeyChange(TofuKeyChangeException change) async {
    var verified = false;
    final accepted = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setDialogState) => AlertDialog(
          title: const Text('Public key changed'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'The keys of user ${change.userId} changed. This happens '
                  'after a legitimate key rotation, but also when the server '
                  'tries to impersonate the user. Sync is paused.',
                ),
                const SizedBox(height: 12),
                const Text('Old fingerprint:'),
                SelectableText(change.oldFingerprint),
                const SizedBox(height: 8),
                const Text('New fingerprint:'),
                SelectableText(change.newFingerprint),
                CheckboxListTile(
                  contentPadding: EdgeInsets.zero,
                  value: verified,
                  onChanged: (v) => setDialogState(() => verified = v == true),
                  title: const Text(
                    'I compared the new fingerprint with this user directly',
                  ),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(false),
              child: const Text('Keep sync paused'),
            ),
            FilledButton(
              onPressed: verified ? () => Navigator.of(ctx).pop(true) : null,
              child: const Text('Trust new key'),
            ),
          ],
        ),
      ),
    );
    return accepted == true;
  }

  void _showNoServerDialog() {
    Navigator.of(context)
        .push(
          MaterialPageRoute(
            builder: (ctx) => const ServerConnectScreen(vaultUnlocked: true),
          ),
        )
        .then((result) {
          if (result == true && mounted) {
            // Connection succeeded — reload and try sync
            setState(() {});
            _syncVault();
          }
        });
  }

  Future<void> _lockVault() async {
    HapticFeedback.mediumImpact();
    await _auth.lock();
    if (mounted) {
      Navigator.pushReplacementNamed(context, '/unlock');
    }
  }

  void _showNewEntryDialog() {
    if (_vault.allNodes.isEmpty) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Create a folder first')));
      return;
    }

    final nameCtrl = TextEditingController();
    String? parentId = _selectedFolderId ?? _vault.allNodes.first.id;
    bool shared = false;
    final fields = <Map<String, TextEditingController>>[
      {
        'key': TextEditingController(text: 'username'),
        'value': TextEditingController(),
      },
      {
        'key': TextEditingController(text: 'password'),
        'value': TextEditingController(),
      },
    ];

    showDialog(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setDialogState) => AlertDialog(
          title: const Text('New Entry'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                TextField(
                  controller: nameCtrl,
                  decoration: const InputDecoration(labelText: 'Entry name'),
                  autofocus: true,
                ),
                const SizedBox(height: 12),
                DropdownButtonFormField<String>(
                  value: parentId,
                  decoration: const InputDecoration(labelText: 'Folder'),
                  items: _vault.allNodes
                      .map(
                        (n) =>
                            DropdownMenuItem(value: n.id, child: Text(n.name)),
                      )
                      .toList(),
                  onChanged: (v) => setDialogState(() => parentId = v),
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
                            controller: f['key'],
                            decoration: const InputDecoration(hintText: 'Key'),
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          flex: 3,
                          child: TextField(
                            controller: f['value'],
                            decoration: const InputDecoration(
                              hintText: 'Value',
                            ),
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
                if (nameCtrl.text.isEmpty || parentId == null) return;

                final entryFields = fields
                    .where((f) => f['key']!.text.isNotEmpty)
                    .map(
                      (f) => EntryField(
                        key: f['key']!.text,
                        value: f['value']!.text,
                        sensitive:
                            f['key']!.text.toLowerCase().contains('password') ||
                            f['key']!.text.toLowerCase().contains('secret') ||
                            f['key']!.text.toLowerCase().contains('token') ||
                            f['key']!.text.toLowerCase().contains('key'),
                      ),
                    )
                    .toList();

                try {
                  await _vault.createEntry(
                    parentRef: parentId!,
                    name: nameCtrl.text,
                    fields: entryFields,
                    writePolicy: shared ? 'shared' : 'owner_only',
                  );
                } on SyncObjectTooLargeException catch (e) {
                  // Review d150605 N1: not saved, and the user is told why.
                  if (mounted) {
                    ScaffoldMessenger.of(
                      context,
                    ).showSnackBar(SnackBar(content: Text(e.toString())));
                  }
                  return;
                }

                if (mounted) {
                  Navigator.pop(ctx);
                  setState(() {});
                  _listAnimController.forward(from: 0);
                }
              },
              child: const Text('Create'),
            ),
          ],
        ),
      ),
    );
  }

  void _showNewFolderDialog() {
    final nameCtrl = TextEditingController();
    final parentRef = _vault.rootNodeId ?? '';

    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('New Folder'),
        content: TextField(
          controller: nameCtrl,
          decoration: const InputDecoration(labelText: 'Folder name'),
          autofocus: true,
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () async {
              if (nameCtrl.text.isEmpty) return;
              await _vault.createNode(
                name: nameCtrl.text,
                parentRef: parentRef,
              );
              if (mounted) {
                Navigator.pop(ctx);
                setState(() {});
              }
            },
            child: const Text('Create'),
          ),
        ],
      ),
    );
  }

  void _showNewPersonalFolderDialog() {
    final nameCtrl = TextEditingController();

    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Row(
          children: [
            Icon(Icons.lock_rounded, size: 20),
            SizedBox(width: 8),
            Text('Osobny priecinok'),
          ],
        ),
        content: TextField(
          controller: nameCtrl,
          decoration: const InputDecoration(
            labelText: 'Nazov priecinku',
            hintText: 'Moje osobne hesla',
          ),
          autofocus: true,
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () async {
              if (nameCtrl.text.isEmpty) return;
              await _vault.createPersonalFolder(name: nameCtrl.text);
              if (mounted) {
                Navigator.pop(ctx);
                setState(() {});
              }
            },
            child: const Text('Create'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(child: _buildCurrentTab()),
      bottomNavigationBar: _buildBottomNav(),
      floatingActionButton: _currentIndex == 0
          ? FloatingActionButton(
              onPressed: () {
                HapticFeedback.mediumImpact();
                _showNewEntryDialog();
              },
              child: const Icon(Icons.add_rounded),
            )
          : null,
    );
  }

  Widget _buildCurrentTab() {
    switch (_currentIndex) {
      case 1:
        return _buildPasswordGenerator();
      case 2:
        return const SettingsScreen();
      default:
        return Column(
          children: [
            _buildHeader(context),
            _buildFolderBar(),
            Expanded(child: _buildEntryList()),
          ],
        );
    }
  }

  Widget _buildHeader(BuildContext context) {
    return Container(
      padding: const EdgeInsets.fromLTRB(20, 12, 20, 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Text(
                'Sezam',
                style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                  color: SezamColors.accent,
                  letterSpacing: 2,
                ),
              ),
              const Spacer(),
              // New folder button
              IconButton(
                icon: const Icon(
                  Icons.create_new_folder_rounded,
                  color: SezamColors.textMuted,
                ),
                onPressed: () {
                  HapticFeedback.lightImpact();
                  _showNewFolderDialog();
                },
                tooltip: 'New folder',
              ),
              // New personal folder button
              IconButton(
                icon: const Icon(
                  Icons.lock_rounded,
                  color: SezamColors.textMuted,
                ),
                onPressed: () {
                  HapticFeedback.lightImpact();
                  _showNewPersonalFolderDialog();
                },
                tooltip: 'Osobny priečinok',
              ),
              // Sync button
              IconButton(
                icon: _isSyncing
                    ? const SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          color: SezamColors.accent,
                        ),
                      )
                    : const Icon(
                        Icons.sync_rounded,
                        color: SezamColors.textMuted,
                      ),
                onPressed: _isSyncing ? null : _syncVault,
                tooltip: 'Sync',
              ),
              // Lock button
              IconButton(
                icon: const Icon(
                  Icons.lock_rounded,
                  color: SezamColors.textMuted,
                ),
                onPressed: _lockVault,
                tooltip: 'Lock vault',
              ),
            ],
          ),
          const SizedBox(height: 12),
          // Search
          SezamSearchBar(
            onChanged: (q) {
              setState(() => _searchQuery = q);
              _listAnimController.forward(from: 0);
            },
          ),
        ],
      ),
    );
  }

  Widget _buildFolderBar() {
    final folders = _folders;
    return SizedBox(
      height: 48,
      child: ListView.builder(
        scrollDirection: Axis.horizontal,
        padding: const EdgeInsets.symmetric(horizontal: 16),
        itemCount: folders.length + 1, // +1 for "All"
        itemBuilder: (context, index) {
          if (index == 0) {
            return Padding(
              padding: const EdgeInsets.only(right: 8),
              child: FolderChip(
                label: 'All',
                icon: Icons.grid_view_rounded,
                count: _vault.allEntries.length,
                selected: _selectedFolderId == null,
                onTap: () {
                  HapticFeedback.selectionClick();
                  setState(() => _selectedFolderId = null);
                  _listAnimController.forward(from: 0);
                },
              ),
            );
          }
          final folder = folders[index - 1];
          return Padding(
            padding: const EdgeInsets.only(right: 8),
            child: FolderChip(
              label: folder.name,
              icon: _iconForFolder(folder.icon),
              count: _entryCountForFolder(folder.id),
              selected: _selectedFolderId == folder.id,
              onTap: () {
                HapticFeedback.selectionClick();
                setState(() => _selectedFolderId = folder.id);
                _listAnimController.forward(from: 0);
              },
            ),
          );
        },
      ),
    );
  }

  Widget _buildEntryList() {
    final entries = _filteredEntries;

    if (entries.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              _searchQuery.isNotEmpty
                  ? Icons.search_off_rounded
                  : Icons.shield_rounded,
              size: 48,
              color: SezamColors.textMuted,
            ),
            const SizedBox(height: 12),
            Text(
              _searchQuery.isNotEmpty ? 'No entries found' : 'Vault is empty',
              style: Theme.of(context).textTheme.bodyMedium,
            ),
            if (_searchQuery.isEmpty) ...[
              const SizedBox(height: 8),
              Text(
                'Tap + to create your first entry',
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                  color: SezamColors.textMuted,
                  fontSize: 13,
                ),
              ),
            ],
          ],
        ),
      );
    }

    return AnimatedBuilder(
      animation: _listAnimController,
      builder: (context, _) {
        return ListView.builder(
          padding: const EdgeInsets.only(top: 8, bottom: 80),
          itemCount: entries.length,
          itemBuilder: (context, index) {
            final entry = entries[index];
            // Staggered animation
            final itemDelay = index * 0.1;
            final progress = (_listAnimController.value - itemDelay).clamp(
              0.0,
              1.0,
            );
            final curve = Curves.easeOutCubic.transform(progress);

            // Find the folder name for this entry
            final parentNode = entry.parentRef != null
                ? _vault.nodes[entry.parentRef]
                : null;
            final folderName = parentNode?.name ?? '';

            return Transform.translate(
              offset: Offset(0, 30 * (1 - curve)),
              child: Opacity(
                opacity: curve,
                child: EntryCard(
                  name: entry.name,
                  folder: folderName,
                  tags: entry.tags,
                  fieldCount: entry.fields.length,
                  readOnly: !entry.canEdit(_vault.userId, _vault.isAdmin),
                  onTap: () {
                    HapticFeedback.selectionClick();
                    Navigator.pushNamed(
                      context,
                      '/entry',
                      arguments: {'entryId': entry.id},
                    ).then((_) {
                      // Refresh on return
                      if (mounted) setState(() {});
                    });
                  },
                ),
              ),
            );
          },
        );
      },
    );
  }

  // ── Password Generator state ──
  double _genLength = 20;
  bool _genUppercase = true;
  bool _genLowercase = true;
  bool _genDigits = true;
  bool _genSymbols = true;
  String _generatedPassword = '';

  String _generatePassword() {
    final rng = Random.secure();
    String chars = '';
    if (_genLowercase) chars += 'abcdefghijklmnopqrstuvwxyz';
    if (_genUppercase) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (_genDigits) chars += '0123456789';
    if (_genSymbols) chars += '!@#\$%^&*()-_=+[]{}|;:,.<>?';
    if (chars.isEmpty) chars = 'abcdefghijklmnopqrstuvwxyz';

    final length = _genLength.round();
    return List.generate(
      length,
      (_) => chars[rng.nextInt(chars.length)],
    ).join();
  }

  Widget _buildPasswordGenerator() {
    return StatefulBuilder(
      builder: (context, setGenState) {
        if (_generatedPassword.isEmpty) {
          _generatedPassword = _generatePassword();
        }

        return Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SizedBox(height: 12),
              Text(
                'Password Generator',
                style: Theme.of(
                  context,
                ).textTheme.headlineSmall?.copyWith(color: SezamColors.text),
              ),
              const SizedBox(height: 24),

              // Generated password display
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: SezamColors.bgElevated,
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: SezamColors.borderAccent),
                ),
                child: SelectableText(
                  _generatedPassword,
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 18,
                    color: SezamColors.accent,
                    letterSpacing: 1,
                  ),
                ),
              ),
              const SizedBox(height: 16),

              // Action buttons
              Row(
                children: [
                  Expanded(
                    child: ElevatedButton.icon(
                      onPressed: () {
                        HapticFeedback.mediumImpact();
                        setGenState(() {
                          _generatedPassword = _generatePassword();
                        });
                      },
                      icon: const Icon(Icons.refresh_rounded, size: 20),
                      label: const Text('Generate'),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: () {
                        HapticFeedback.lightImpact();
                        // Sensitive clip, cleared after 15 s (and on resume
                        // if the timer could not run in the background).
                        ClipboardService.shared.copySensitive(
                          _generatedPassword,
                        );
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(
                            content: Text('Password copied!'),
                            duration: Duration(seconds: 2),
                          ),
                        );
                      },
                      icon: const Icon(Icons.copy_rounded, size: 20),
                      label: const Text('Copy'),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 24),

              // Length slider
              Row(
                children: [
                  const Text(
                    'Length',
                    style: TextStyle(color: SezamColors.textSecondary),
                  ),
                  const Spacer(),
                  Text(
                    '${_genLength.round()}',
                    style: const TextStyle(
                      color: SezamColors.accent,
                      fontWeight: FontWeight.bold,
                      fontSize: 16,
                    ),
                  ),
                ],
              ),
              Slider(
                value: _genLength,
                min: 8,
                max: 64,
                divisions: 56,
                activeColor: SezamColors.accent,
                inactiveColor: SezamColors.border,
                onChanged: (v) {
                  setGenState(() {
                    _genLength = v;
                    _generatedPassword = _generatePassword();
                  });
                },
              ),
              const SizedBox(height: 8),

              // Character set toggles
              _genToggle('Uppercase (A-Z)', _genUppercase, (v) {
                setGenState(() {
                  _genUppercase = v;
                  _generatedPassword = _generatePassword();
                });
              }),
              _genToggle('Lowercase (a-z)', _genLowercase, (v) {
                setGenState(() {
                  _genLowercase = v;
                  _generatedPassword = _generatePassword();
                });
              }),
              _genToggle('Digits (0-9)', _genDigits, (v) {
                setGenState(() {
                  _genDigits = v;
                  _generatedPassword = _generatePassword();
                });
              }),
              _genToggle('Symbols (!@#\$...)', _genSymbols, (v) {
                setGenState(() {
                  _genSymbols = v;
                  _generatedPassword = _generatePassword();
                });
              }),
            ],
          ),
        );
      },
    );
  }

  Widget _genToggle(String label, bool value, ValueChanged<bool> onChanged) {
    return SwitchListTile(
      title: Text(
        label,
        style: const TextStyle(color: SezamColors.text, fontSize: 14),
      ),
      value: value,
      onChanged: onChanged,
      activeColor: SezamColors.accent,
      contentPadding: EdgeInsets.zero,
      dense: true,
    );
  }

  Widget _buildBottomNav() {
    return Container(
      decoration: const BoxDecoration(
        border: Border(top: BorderSide(color: SezamColors.border, width: 1)),
      ),
      child: BottomNavigationBar(
        currentIndex: _currentIndex,
        onTap: (i) {
          HapticFeedback.selectionClick();
          setState(() => _currentIndex = i);
        },
        items: const [
          BottomNavigationBarItem(
            icon: Icon(Icons.shield_rounded),
            label: 'Vault',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.generating_tokens_rounded),
            label: 'Generator',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.settings_rounded),
            label: 'Settings',
          ),
        ],
      ),
    );
  }
}

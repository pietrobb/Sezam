import 'dart:io';

import 'package:flutter/material.dart';
import 'package:path/path.dart' as p;

import '../services/document_service.dart';
import '../services/unsent_changes.dart';

/// Text summary of re-applying an unsent-changes export.
String describeUnsentReapply(UnsentReapplyResult result) {
  final lines = <String>[
    'Restored: ${result.applied}',
    if (result.alreadyPresent > 0)
      'Already in the vault: ${result.alreadyPresent}',
    if (result.notApplied.isNotEmpty)
      'Not restored: ${result.notApplied.length} (deletes, sharing and key '
          'changes are not replayed; redo them by hand)',
  ];
  return lines.join('\n');
}

/// Let the user save the export file outside the app (lockout review M4).
Future<void> saveUnsentExport(BuildContext context, String exportPath) async {
  final messenger = ScaffoldMessenger.of(context);
  const documents = DocumentService();
  if (!documents.isSupported) {
    messenger.showSnackBar(
      SnackBar(content: Text('Backup kept in the app folder: $exportPath')),
    );
    return;
  }
  try {
    final saved = await documents.saveDocument(
      p.basename(exportPath),
      await File(exportPath).readAsBytes(),
    );
    if (saved) {
      messenger.showSnackBar(const SnackBar(content: Text('Backup saved.')));
    }
  } catch (e) {
    messenger.showSnackBar(SnackBar(content: Text('Saving failed: $e')));
  }
}

/// Result of a full resync that had unsent changes, with a way to save the
/// export so it can be imported again from Settings.
Future<void> showUnsentChangesResult(
  BuildContext context, {
  required String title,
  required UnsentReapplyResult result,
  required String exportPath,
}) {
  return showDialog<void>(
    context: context,
    builder: (ctx) => AlertDialog(
      title: Text(title),
      content: Text(
        'Your unsent changes were put back and will be sent with the next '
        'sync.\n\n${describeUnsentReapply(result)}\n\n'
        'Save the backup somewhere you can reach (Downloads, cloud drive). '
        'It can be imported again in Settings → Import unsent changes.',
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(ctx).pop(),
          child: const Text('Close'),
        ),
        FilledButton(
          onPressed: () async {
            await saveUnsentExport(ctx, exportPath);
            if (ctx.mounted) Navigator.of(ctx).pop();
          },
          child: const Text('Save backup…'),
        ),
      ],
    ),
  );
}

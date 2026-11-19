import 'package:flutter/material.dart';

import '../services/sync_service.dart';

/// Review c78fd19 (medium): leave a team log the server lost for good.
class TeamForgetPinDialog extends StatefulWidget {
  const TeamForgetPinDialog({super.key, required this.pinned});

  final List<String> pinned;

  @override
  State<TeamForgetPinDialog> createState() => _TeamForgetPinDialogState();
}

class _TeamForgetPinDialogState extends State<TeamForgetPinDialog> {
  final _genesis = TextEditingController();
  bool _saving = false;
  String? _error;

  @override
  void dispose() {
    _genesis.dispose();
    super.dispose();
  }

  Future<void> _forget() async {
    if (_saving) return;
    setState(() {
      _saving = true;
      _error = null;
    });
    try {
      await SyncService().forgetTeamLogPin(_genesis.text);
      if (mounted) Navigator.pop(context, true);
    } catch (e) {
      if (mounted) setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  @override
  Widget build(BuildContext context) => PopScope(
    canPop: !_saving,
    child: AlertDialog(
      title: const Text('Zabudnúť pripnutý tímový denník'),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Len ak je denník tímu stratený natrvalo (iný server, nové založenie). '
              'Telefón potom nasleduje denník servera ako nový a dôveruje mu až po '
              'novom potvrdení odtlačku zakladateľa.',
            ),
            const SizedBox(height: 8),
            SelectableText('Pripnutý genesis: ${widget.pinned.join(', ')}'),
            const SizedBox(height: 12),
            TextField(
              controller: _genesis,
              enabled: !_saving,
              autocorrect: false,
              enableSuggestions: false,
              decoration: const InputDecoration(
                labelText: 'Pripnutý genesis (aspoň prvých 16 znakov)',
              ),
            ),
            if (_error != null)
              Text(
                _error!,
                style: TextStyle(color: Theme.of(context).colorScheme.error),
              ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: _saving ? null : () => Navigator.pop(context),
          child: const Text('Zrušiť'),
        ),
        ElevatedButton(
          onPressed: _saving ? null : _forget,
          child: const Text('Zabudnúť'),
        ),
      ],
    ),
  );
}

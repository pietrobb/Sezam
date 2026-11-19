import 'package:flutter/material.dart';

import '../services/vault_service.dart';

class TeamTrustDialog extends StatefulWidget {
  const TeamTrustDialog({super.key, required this.review});

  final ({String userId, String genesis, int generation}) review;

  @override
  State<TeamTrustDialog> createState() => _TeamTrustDialogState();
}

class _TeamTrustDialogState extends State<TeamTrustDialog> {
  final _fingerprint = TextEditingController();
  bool _saving = false;
  String? _error;

  @override
  void dispose() {
    _fingerprint.dispose();
    super.dispose();
  }

  Future<void> _confirm() async {
    if (_saving) return;
    setState(() {
      _saving = true;
      _error = null;
    });
    try {
      await VaultService().confirmTeamFounder(widget.review, _fingerprint.text);
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
      title: const Text('Potvrdenie zakladateľa'),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Odtlačok získajte od zakladateľa nezávislým kanálom, nie od tohto servera. '
              'SHA-256 podpisového a šifrovacieho verejného kľúča (64 hex znakov). '
              'Potvrdenie sa uloží iba na tomto zariadení.',
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _fingerprint,
              enabled: !_saving,
              autocorrect: false,
              enableSuggestions: false,
              decoration: const InputDecoration(
                labelText: 'Nezávislý odtlačok zakladateľa',
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
          onPressed: _saving ? null : _confirm,
          child: const Text('Potvrdiť'),
        ),
      ],
    ),
  );
}

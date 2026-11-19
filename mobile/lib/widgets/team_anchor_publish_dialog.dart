import 'package:flutter/material.dart';

import '../services/auth_service.dart';

/// Review 1141a20 H2: the founder this phone confirmed goes to the account's
/// new devices, only together with a change to a NEW password.
class TeamAnchorPublishDialog extends StatefulWidget {
  const TeamAnchorPublishDialog({super.key});

  @override
  State<TeamAnchorPublishDialog> createState() =>
      _TeamAnchorPublishDialogState();
}

class _TeamAnchorPublishDialogState extends State<TeamAnchorPublishDialog> {
  final _current = TextEditingController();
  final _new = TextEditingController();
  final _confirm = TextEditingController();
  bool _saving = false;
  String? _error;

  @override
  void dispose() {
    _current.dispose();
    _new.dispose();
    _confirm.dispose();
    super.dispose();
  }

  Future<void> _publish() async {
    if (_saving) return;
    if (_new.text != _confirm.text) {
      setState(() => _error = 'Nové heslá sa nezhodujú');
      return;
    }
    setState(() {
      _saving = true;
      _error = null;
    });
    try {
      final result = await AuthService().publishTeamAnchor(
        currentPassword: _current.text,
        newPassword: _new.text,
      );
      if (!mounted) return;
      if (result.success) {
        Navigator.pop(context, true);
      } else {
        setState(() => _error = result.error);
      }
    } catch (e) {
      if (mounted) setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Widget _field(TextEditingController controller, String label) => TextField(
    controller: controller,
    enabled: !_saving,
    obscureText: true,
    autocorrect: false,
    enableSuggestions: false,
    decoration: InputDecoration(labelText: label),
  );

  @override
  Widget build(BuildContext context) => PopScope(
    canPop: !_saving,
    child: AlertDialog(
      title: const Text('Dôvera tímu pre nové zariadenia'),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Nové zariadenia tohto účtu budú dôverovať zakladateľovi, ktorého '
              'ste potvrdili na tomto telefóne. Uloží sa to len spolu so zmenou '
              'na nové heslo účtu: so starým heslom by server novému zariadeniu '
              'mohol podstrčiť kľúče bez tejto dôvery.',
            ),
            const SizedBox(height: 12),
            _field(_current, 'Súčasné heslo účtu'),
            _field(
              _new,
              'Nové heslo účtu (aspoň $newPasswordMinLength znakov)',
            ),
            _field(_confirm, 'Nové heslo znova'),
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
          onPressed: _saving ? null : _publish,
          child: const Text('Zmeniť heslo a zverejniť'),
        ),
      ],
    ),
  );
}

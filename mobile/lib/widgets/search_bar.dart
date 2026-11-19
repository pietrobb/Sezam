import 'package:flutter/material.dart';
import '../theme/sezam_theme.dart';

class SezamSearchBar extends StatelessWidget {
  final ValueChanged<String> onChanged;

  const SezamSearchBar({super.key, required this.onChanged});

  @override
  Widget build(BuildContext context) {
    return TextField(
      onChanged: onChanged,
      style: const TextStyle(color: SezamColors.text, fontSize: 15),
      decoration: InputDecoration(
        hintText: 'Search entries...',
        prefixIcon: const Icon(Icons.search_rounded, color: SezamColors.textMuted),
        suffixIcon: const Icon(Icons.tune_rounded, color: SezamColors.textMuted, size: 20),
        contentPadding: const EdgeInsets.symmetric(vertical: 0),
        filled: true,
        fillColor: SezamColors.bgCard,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(14),
          borderSide: const BorderSide(color: SezamColors.border),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(14),
          borderSide: const BorderSide(color: SezamColors.border),
        ),
      ),
    );
  }
}

import 'package:flutter/material.dart';
import '../theme/sezam_theme.dart';

class EntryCard extends StatelessWidget {
  final String name;
  final String folder;
  final List<String> tags;
  final int fieldCount;
  final VoidCallback onTap;
  final bool readOnly;

  const EntryCard({
    super.key,
    required this.name,
    required this.folder,
    required this.tags,
    required this.fieldCount,
    required this.onTap,
    this.readOnly = false,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(16),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            children: [
              // Icon
              Container(
                width: 44,
                height: 44,
                decoration: BoxDecoration(
                  color: SezamColors.accentGlow,
                  borderRadius: BorderRadius.circular(12),
                ),
                child: const Icon(
                  Icons.key_rounded,
                  color: SezamColors.accent,
                  size: 22,
                ),
              ),
              const SizedBox(width: 14),

              // Info
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      name,
                      style: Theme.of(context).textTheme.titleMedium,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    const SizedBox(height: 4),
                    Row(
                      children: [
                        Text(
                          folder,
                          style: Theme.of(context)
                              .textTheme
                              .bodyMedium
                              ?.copyWith(fontSize: 12),
                        ),
                        if (tags.isNotEmpty) ...[
                          const SizedBox(width: 8),
                          ...tags.take(2).map((tag) => Container(
                                margin: const EdgeInsets.only(right: 4),
                                padding: const EdgeInsets.symmetric(
                                    horizontal: 6, vertical: 2),
                                decoration: BoxDecoration(
                                  color: SezamColors.borderAccent
                                      .withValues(alpha: 0.3),
                                  borderRadius: BorderRadius.circular(4),
                                ),
                                child: Text(
                                  tag,
                                  style: const TextStyle(
                                    color: SezamColors.accentLight,
                                    fontSize: 10,
                                    fontWeight: FontWeight.w500,
                                  ),
                                ),
                              )),
                        ],
                      ],
                    ),
                  ],
                ),
              ),

              // Read-only lock (ownership ACL — owned by another user)
              if (readOnly) ...[
                const Icon(Icons.lock_outline_rounded,
                    color: SezamColors.textMuted, size: 16),
                const SizedBox(width: 6),
              ],

              // Field count + chevron
              Text(
                '$fieldCount',
                style: const TextStyle(
                    color: SezamColors.textMuted, fontSize: 12),
              ),
              const SizedBox(width: 4),
              const Icon(Icons.chevron_right_rounded,
                  color: SezamColors.textMuted, size: 20),
            ],
          ),
        ),
      ),
    );
  }
}

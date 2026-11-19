"""Watchtower — detect weak, duplicate, and old passwords.

Phase 4: Scans vault entries and reports security issues.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional

from .password import estimate_strength


@dataclass
class WatchtowerIssue:
    """A security issue found by Watchtower."""
    entry_id: str
    entry_name: str
    entry_path: str
    issue_type: str  # 'weak', 'duplicate', 'old', 'reused'
    severity: str  # 'critical', 'warning', 'info'
    description: str
    field_key: Optional[str] = None


class Watchtower:
    """Scans vault for password security issues."""

    # Passwords older than this (ms) get flagged
    MAX_AGE_MS = 365 * 24 * 3600 * 1000  # 1 year

    def scan(self, vault) -> list[WatchtowerIssue]:
        """Scan entire vault for issues. Returns sorted by severity."""
        issues: list[WatchtowerIssue] = []

        # Collect all password values for duplicate detection
        password_map: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
        # hash -> [(entry_id, entry_name, path)]

        all_entries = self._collect_all_entries(vault)

        for entry_id, entry_name, path, fields, modified_at in all_entries:
            for f in fields:
                if not f.get("sensitive", False):
                    continue

                value = f["value"]
                field_key = f["key"]

                # Weak password check
                strength = estimate_strength(value)
                if strength["score"] <= 1:
                    issues.append(WatchtowerIssue(
                        entry_id=entry_id,
                        entry_name=entry_name,
                        entry_path=path,
                        issue_type="weak",
                        severity="critical",
                        description=f"Weak password ({strength['label']}, {strength['entropy_bits']} bits)",
                        field_key=field_key,
                    ))
                elif strength["score"] == 2:
                    issues.append(WatchtowerIssue(
                        entry_id=entry_id,
                        entry_name=entry_name,
                        entry_path=path,
                        issue_type="weak",
                        severity="warning",
                        description=f"Moderate password ({strength['entropy_bits']} bits) — consider strengthening",
                        field_key=field_key,
                    ))

                # Track for duplicate detection
                value_hash = hashlib.sha256(value.encode()).hexdigest()
                password_map[value_hash].append((entry_id, entry_name, path))

                # Old password check
                if modified_at and (self._now_ms() - modified_at > self.MAX_AGE_MS):
                    age_days = (self._now_ms() - modified_at) // (24 * 3600 * 1000)
                    issues.append(WatchtowerIssue(
                        entry_id=entry_id,
                        entry_name=entry_name,
                        entry_path=path,
                        issue_type="old",
                        severity="info",
                        description=f"Password not changed for {age_days} days",
                        field_key=field_key,
                    ))

        # Duplicate password detection
        for value_hash, locations in password_map.items():
            if len(locations) > 1:
                names = ", ".join(f"{name}" for _, name, _ in locations)
                for entry_id, entry_name, path in locations:
                    issues.append(WatchtowerIssue(
                        entry_id=entry_id,
                        entry_name=entry_name,
                        entry_path=path,
                        issue_type="duplicate",
                        severity="warning",
                        description=f"Password reused across: {names}",
                    ))

        # Sort: critical first, then warning, then info
        severity_order = {"critical": 0, "warning": 1, "info": 2}
        issues.sort(key=lambda i: severity_order.get(i.severity, 9))

        return issues

    def _collect_all_entries(self, vault):
        """Recursively collect all entries with their paths."""
        results = []
        root_id = vault.db.get_meta("root_node_id")
        self._walk_node(vault, root_id, "", results)
        return results

    def _walk_node(self, vault, node_id, path, results):
        entries = vault.list_entries(node_id)
        for e in entries:
            try:
                full = vault.read_entry(e["id"])
                entry_path = f"{path}/{e['name']}".strip("/")
                results.append((
                    e["id"],
                    e["name"],
                    entry_path,
                    full["fields"],
                    full.get("modified_at", 0),
                ))
            except Exception:
                continue

        for child in vault.list_nodes(node_id):
            child_path = f"{path}/{child['name']}".strip("/")
            self._walk_node(vault, child["id"], child_path, results)

    @staticmethod
    def _now_ms() -> int:
        import time
        return int(time.time() * 1000)

    def summary(self, issues: list[WatchtowerIssue]) -> dict:
        """Generate summary statistics."""
        critical = sum(1 for i in issues if i.severity == "critical")
        warning = sum(1 for i in issues if i.severity == "warning")
        info = sum(1 for i in issues if i.severity == "info")
        types = defaultdict(int)
        for i in issues:
            types[i.issue_type] += 1

        return {
            "total": len(issues),
            "critical": critical,
            "warning": warning,
            "info": info,
            "by_type": dict(types),
        }

#!/bin/bash
# Git bundle backup — date-stamped to Z:\Backup\Sources\Sezam
BACKUP_DIR="/z/Backup/Sources/Sezam"
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BUNDLE="${BACKUP_DIR}/sezam_${TIMESTAMP}.bundle"

mkdir -p "$BACKUP_DIR"
git -C "$REPO_DIR" bundle create "$BUNDLE" --all

if [ $? -eq 0 ]; then
    echo "Bundle created: $BUNDLE"
else
    echo "ERROR: Bundle creation failed!" >&2
    exit 1
fi

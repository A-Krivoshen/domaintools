#!/usr/bin/env bash
set -euo pipefail

APPDIR="${1:-/var/www/python.domaintools.site/htdocs}"
TEMPL="$APPDIR/templates"
TARGET="$TEMPL/index.html"

if [[ ! -f "$TARGET" ]]; then
  echo "[ERROR] File not found: $TARGET" >&2
  exit 1
fi

echo "[i] Patching: $TARGET"
install -d "$APPDIR/backups"
ts="$(date +%F_%H%M%S)"
cp -a "$TARGET" "$APPDIR/backups/index.html.$ts.bak"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
python3 "$SCRIPT_DIR/apply_home_intro.py" "$TARGET"

echo "[ok] Done. Backup: $APPDIR/backups/index.html.$ts.bak"

#!/usr/bin/env bash
set -euo pipefail

APPDIR="${1:-/var/www/python.domaintools.site/htdocs}"
TEMPL="$APPDIR/templates"
TARGET="$TEMPL/index.html"

last_bak="$(ls -1t "$APPDIR"/backups/index.html.*.bak 2>/dev/null | head -n1 || true)"
if [[ -z "$last_bak" ]]; then
  echo "[ERROR] No backups found in $APPDIR/backups" >&2
  exit 1
fi

cp -a "$last_bak" "$TARGET"
echo "[ok] Restored $TARGET from $last_bak"

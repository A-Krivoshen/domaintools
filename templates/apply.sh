#!/usr/bin/env bash
set -euo pipefail
APPDIR="${1:-/var/www/python.domaintools.site/htdocs}"
if [[ ! -d "$APPDIR" ]]; then
  echo "[ERROR] App dir not found: $APPDIR" >&2
  exit 1
fi
echo "[i] Using APPDIR=$APPDIR"
python3 "$(dirname "$0")/apply_home_intro.py" "$APPDIR"
echo "[OK] Patch applied."

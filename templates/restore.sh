#!/usr/bin/env bash
set -euo pipefail
APPDIR="${1:-/var/www/python.domaintools.site/htdocs}"
restore_one () {
  local target="$1"
  local latest
  latest=$(ls -1t "${target}".bak.* 2>/dev/null | head -n1 || true)
  if [[ -n "$latest" ]]; then
    echo "[i] Restoring $target from $latest"
    sudo cp -a "$latest" "$target"
  else
    echo "[WARN] No backup found for $target"
  fi
}
restore_one "$APPDIR/templates/index.html"
restore_one "$APPDIR/templates/dns.html"
echo "[OK] Restore finished (if backups existed)."

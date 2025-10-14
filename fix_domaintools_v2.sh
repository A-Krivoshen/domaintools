#!/usr/bin/env bash
set -euo pipefail

APP="app.py"
TPL_DIR="templates"
TPL="$TPL_DIR/dns.html"

timestamp="$(date +%Y-%m-%d_%H%M%S)"

backup() {
  local src="$1"
  if [[ -f "$src" ]]; then
    cp -a "$src" "${src}.bak.${timestamp}"
    echo "  - backup: ${src}.bak.${timestamp}"
  fi
}

echo "[1/5] Backing up files..."
backup "$APP"
mkdir -p "$TPL_DIR"
if [[ -f "$TPL" ]]; then backup "$TPL"; fi

echo "[2/5] Patching dns_lookup() safely..."
python3 - <<'PY'
import re, pathlib, textwrap, sys

APP="app.py"
p = pathlib.Path(APP)
src = p.read_text(encoding="utf-8")

m = re.search(r'^\s*def\s+dns_lookup\s*\(\s*\)\s*:\s*$', src, flags=re.M)
if not m:
    print("!! def dns_lookup() not found", file=sys.stderr)
    sys.exit(2)

# Find end of this function block by searching for next decorator or def at BOL
after = src[m.end():]
n = re.search(r'^\s*@\w|\ndef\s+\w+\s*\(', after, flags=re.M)
end = m.end() + (n.start() if n else len(after))

replacement = textwrap.dedent('''\
def dns_lookup():
    from flask import request, render_template, url_for
    import dns.resolver

    # Page meta is defined first so it always exists
    meta = {
        "title": "DNS Lookup",
        "description": "Проверка DNS записей домена (A/AAAA/CNAME/MX/NS/TXT/SOA).",
    }

    query = (request.args.get("q") or "").strip()
    if not query:
        return render_template("dns.html", meta=meta, result=None, records={}, error=None, query="", permalink=None)

    records = {}
    error = None

    def fetch(rtype: str):
        try:
            answers = dns.resolver.resolve(query, rtype)
            vals = []
            for r in answers:
                vals.append(str(r).rstrip("."))
            if vals:
                records[rtype] = vals
        except Exception:
            pass

    for rt in ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]:
        fetch(rt)

    result = {"domain": query, "has_records": bool(records)}
    permalink = url_for("dns_lookup", q=query, _external=False)

    return render_template("dns.html", meta=meta, result=result, records=records, error=error, query=query, permalink=permalink)
''')

new_src = src[:m.start()] + replacement + src[end:]
p.write_text(new_src, encoding="utf-8")
print("  - dns_lookup() replaced")
PY

echo "[3/5] Writing templates/dns.html (valid Jinja)..."
cat > "$TPL" <<'HTML'
{% extends "base.html" %}

{% block content %}
<div class="container my-4">
  <h1 class="mb-3">DNS</h1>

  <form method="get" action="{{ url_for('dns_lookup') }}" class="mb-4">
    <div class="input-group">
      <input type="text" class="form-control" name="q" placeholder="example.com" value="{{ query or '' }}">
      <button class="btn btn-primary" type="submit">Проверить</button>
    </div>
  </form>

  {% if error %}
    <div class="alert alert-danger">{{ error }}</div>
  {% endif %}

  {% if result %}
    <h2 class="h5">Результаты для <code>{{ query }}</code></h2>
    {% if permalink %}<p><small><a href="{{ permalink }}">Постоянная ссылка</a></small></p>{% endif %}

    {% if records and records|length > 0 %}
      {% for rtype, values in records.items() %}
      <div class="card mb-3">
        <div class="card-header"><strong>{{ rtype }}</strong></div>
        <div class="card-body">
          <ul class="mb-0">
            {% for v in values %}
              <li><code>{{ v }}</code></li>
            {% endfor %}
          </ul>
        </div>
      </div>
      {% endfor %}
    {% else %}
      <p>DNS-записей не найдено.</p>
    {% endif %}
  {% endif %}
</div>
{% endblock %}
HTML

echo "[4/5] Syntax check..."
python3 -m py_compile app.py
echo "  - app.py OK"

echo "[5/5] Restart service if present..."
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet python-domaintools; then
  systemctl restart python-domaintools
  echo "  - restarted python-domaintools"
else
  echo "  - systemd unit not active; restart your app server manually if needed"
fi

echo "Hotfix installed."

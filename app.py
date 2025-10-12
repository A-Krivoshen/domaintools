# app.py
import os
import re
import socket
import json
import hashlib
import time
import logging
from datetime import datetime
from typing import Optional, Dict, List, Tuple

import redis
import whois
import dns.resolver
import dns.exception
from ipwhois import IPWhois
from geopy.geocoders import Nominatim

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    url_for,
    abort,
    Response,
    send_from_directory,
)
from flask_babel import Babel, gettext as _, get_locale as babel_get_locale
from flask_caching import Cache


# -------------------------------------------------
# App & config
# -------------------------------------------------
app = Flask(__name__, template_folder="templates", static_folder="static")
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-secret"),
    TEMPLATES_AUTO_RELOAD=True,
    JSON_SORT_KEYS=False,
    # Babel
    BABEL_DEFAULT_LOCALE="ru",
    BABEL_DEFAULT_TIMEZONE="UTC",
    # Cache
    CACHE_TYPE="SimpleCache",
    CACHE_DEFAULT_TIMEOUT=120,
)

# Redis (DB=3 по умолчанию)
app.config.setdefault("REDIS_URL", os.getenv("REDIS_URL", "redis://127.0.0.1:6379/3"))
r = redis.from_url(app.config["REDIS_URL"], decode_responses=True)
HIST_NS = "dt:history"          # dt:history:{kind}:{id}
HIST_ZSET = "dt:history:index"  # zset с "kind:id" (score=ts)
HIST_LIMIT = 5000               # ограничение по количеству записей

cache = Cache(app)

babel = Babel()
SUPPORTED_LOCALES = ("en", "ru")


def _locale_selector():
    lang = (request.args.get("lang") or "").lower()
    if lang in SUPPORTED_LOCALES:
        return lang
    best = request.accept_languages.best_match(SUPPORTED_LOCALES)
    return best or app.config.get("BABEL_DEFAULT_LOCALE", "en")


babel.init_app(app, locale_selector=_locale_selector)


# Сделаем функции/фильтры доступными в Jinja
@app.context_processor
def jinja_globals():
    return {"get_locale": lambda: str(babel_get_locale())}

@app.template_filter("prettyjson")
def prettyjson(obj):
    try:
        return json.dumps(obj, ensure_ascii=False, indent=2)
    except Exception:
        return str(obj)
@app.template_filter("enumerate")
def jinja_enumerate(seq):
    try:
        # вернём список пар (value, index), чтобы в шаблоне работало: {% for v,i in ... %}
        return [(v, i) for i, v in enumerate(list(seq))]
    except Exception:
        return []

def country_flag(cc: str) -> str:
    """FR -> 🇫🇷 (если код корректный)."""
    if not cc or len(cc) != 2 or not cc.isalpha():
        return ""
    base = 127397
    return "".join(chr(ord(c.upper()) + base) for c in cc)

@app.context_processor
def jinja_more_globals():
    return {"country_flag": country_flag}


# -------------------------------------------------
# Logging
# -------------------------------------------------
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
app.logger.setLevel(logging.INFO)
app.logger.addHandler(handler)


# -------------------------------------------------
# Helpers
# -------------------------------------------------
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$"
)

def validate_domain(domain: str) -> None:
    if not DOMAIN_RE.match(domain):
        raise ValueError(_("Invalid domain name."))

def resolve_records(domain: str, qtype: str, timeout: float = 3.0) -> List[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    answers = resolver.resolve(domain, qtype)
    return [r.to_text() for r in answers]

def make_id(kind: str, query: str) -> str:
    payload = f"{kind}:{(query or '').strip().lower()}"
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]

def save_history(kind: str, query: str, result: dict) -> str:
    """Сохранить снэпшот в Redis и вернуть стабильный id."""
    hid = make_id(kind, query)
    key = f"{HIST_NS}:{kind}:{hid}"
    ts = int(time.time())

    if not r.exists(key):
        doc = {"id": hid, "kind": kind, "query": query, "result": result, "ts": ts}
        r.hset(key, mapping={"json": json.dumps(doc, ensure_ascii=False)})
        r.zadd(HIST_ZSET, {f"{kind}:{hid}": ts})

        # безопасный трим
        try:
            total = r.zcard(HIST_ZSET) or 0
            if total > HIST_LIMIT:
                cut = total - HIST_LIMIT
                r.zremrangebyrank(HIST_ZSET, 0, cut - 1)
        except Exception:
            app.logger.exception("Failed to trim history zset")

        app.logger.info("Saved history %s:%s (query=%s)", kind, hid, query)

    return hid

def load_history(kind: str, hid: str) -> Optional[dict]:
    key = f"{HIST_NS}:{kind}:{hid}"
    raw = r.hget(key, "json")
    return json.loads(raw) if raw else None

def _split_kind_id(s: str) -> Optional[Tuple[str, str]]:
    if ":" not in s:
        return None
    k, i = s.split(":", 1)
    if not k or not i:
        return None
    return k, i


# -------------------------------------------------
# Routes
# -------------------------------------------------
@app.get("/health")
def health():
    return jsonify(status="ok"), 200

@app.get("/favicon.ico")
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, "static"),
        "favicon.ico",
        mimetype="image/x-icon",
    )

@app.get("/robots.txt")
def robots():
    lines = [
        "User-agent: *",
        "Allow: /",
        f"Sitemap: {url_for('sitemap', _external=True)}",
        "",
    ]
    return Response("\n".join(lines), mimetype="text/plain")

@app.get("/sitemap.xml")
def sitemap():
    # главные страницы
    base_urls = [
        url_for("index", _external=True),
        request.url_root.rstrip("/") + "/dns",
        request.url_root.rstrip("/") + "/whois",
        request.url_root.rstrip("/") + "/geo",
        request.url_root.rstrip("/") + "/history",
    ]
    # возьмём последние 200 ссылок истории
    keys = r.zrevrange(HIST_ZSET, 0, 199)
    hist_urls = []
    for s in keys:
        pair = _split_kind_id(s)
        if not pair:
            continue
        kind, hid = pair
        hist_urls.append(url_for("history_view", kind=kind, hid=hid, _external=True))

    xml = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for u in base_urls + hist_urls:
        xml.append(f"<url><loc>{u}</loc></url>")
    xml.append("</urlset>")
    return Response("\n".join(xml), mimetype="application/xml")

@app.route("/")
def index():
    return render_template("index.html")

# ---------- DNS ----------
@app.route("/dns", methods=["GET", "POST"])
def dns_lookup():
    result: Optional[Dict[str, List[str]]] = None
    error: Optional[str] = None
    domain = None
    permalink = None

    if request.method == "POST":
        domain = (request.form.get("domain") or "").strip().lower()
        try:
            validate_domain(domain)
            app.logger.info(f"DNS lookup for: {domain}")
            result = {}
            for qtype in ["A", "AAAA", "MX", "NS", "TXT"]:
                try:
                    result[qtype] = resolve_records(domain, qtype)
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                    result[qtype] = []
            # история
            hid = save_history("dns", domain, result)
            permalink = url_for("history_view", kind="dns", hid=hid, _external=True)
        except ValueError as ve:
            error = str(ve)
        except dns.exception.DNSException as de:
            error = _("DNS error: ") + str(de)
        except Exception:
            app.logger.exception("Unexpected DNS error")
            error = _("Unexpected error during DNS lookup.")

    return render_template("dns.html", result=result, error=error, query=domain, permalink=permalink)

# ---------- WHOIS ----------
@app.route("/whois", methods=["GET", "POST"])
def whois_lookup():
    data: Optional[Dict] = None
    error: Optional[str] = None
    query = None
    permalink = None

    if request.method == "POST":
        query = (request.form.get("query") or "").strip()
        try:
            # IP или домен?
            try:
                socket.inet_aton(query)
                is_ip = True
            except OSError:
                is_ip = False

            if is_ip:
                lookup = IPWhois(query).lookup_rdap()
                data = {
                    "query": query,
                    "asn": lookup.get("asn"),
                    "asn_description": lookup.get("asn_description"),
                    "asn_country_code": lookup.get("asn_country_code"),
                    "network": lookup.get("network", {}),
                }
            else:
                validate_domain(query)
                w = whois.whois(query)
                data = {
                    k: (", ".join(v) if isinstance(v, (list, tuple)) else str(v))
                    for k, v in w.__dict__.items()
                    if not k.startswith("_")
                }

            hid = save_history("whois", query, data)
            permalink = url_for("history_view", kind="whois", hid=hid, _external=True)

        except ValueError as ve:
            error = str(ve)
        except Exception:
            app.logger.exception("WHOIS error")
            error = _("Unexpected error during WHOIS lookup.")

    return render_template("whois.html", result=data, error=error, query=query, permalink=permalink)

# ---------- GEO ----------
@app.route("/geo", methods=["GET", "POST"])
def geo_lookup():
    result: Optional[Dict] = None
    error: Optional[str] = None
    query = None
    permalink = None

    if request.method == "POST":
        query = (request.form.get("query") or "").strip()
        try:
            # домен -> IP
            try:
                socket.inet_aton(query)
                ip = query
            except OSError:
                ip = socket.gethostbyname(query)

            app.logger.info(f"Geo lookup for: {ip}")
            lookup = IPWhois(ip).lookup_rdap()
            asn = lookup.get("asn_description") or "N/A"
            country_code = lookup.get("asn_country_code") or "N/A"

            # человекочитаемое имя страны (опционально)
            country_name = country_code
            try:
                geolocator = Nominatim(user_agent="domaintools-geo")
                geo = geolocator.geocode(country_code, timeout=5)
                if geo and geo.address:
                    country_name = geo.address
            except Exception:
                pass

            result = {
                "ip": ip,
                "asn": asn,
                "country_code": country_code,
                "country_name": country_name,
            }

            hid = save_history("geo", query, result)
            permalink = url_for("history_view", kind="geo", hid=hid, _external=True)

        except socket.gaierror:
            error = _("Invalid IP or domain.")
        except Exception:
            app.logger.exception("GeoIP error")
            error = _("An error occurred during GeoIP lookup.")

    return render_template("geo.html", result=result, error=error, query=query, permalink=permalink)

# ---------- История ----------
@app.get("/history")
def history_list():
    keys = r.zrevrange(HIST_ZSET, 0, 49)  # последние 50
    items = []
    for s in keys:
        pair = _split_kind_id(s)
        if not pair:
            continue
        kind, hid = pair
        doc = load_history(kind, hid)
        if not doc:
            continue
        items.append(
            {
                "kind": kind,
                "id": hid,
                "query": doc.get("query"),
                "ts": datetime.utcfromtimestamp(doc.get("ts", 0)).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "url": url_for("history_view", kind=kind, hid=hid),
            }
        )
    return render_template("history.html", items=items)

@app.get("/h/<kind>/<hid>")
def history_view(kind: str, hid: str):
    if kind not in {"dns", "whois", "geo"}:
        abort(404)
    doc = load_history(kind, hid)
    if not doc:
        abort(404)
    q = doc.get("query")
    res = doc.get("result")
    permalink = request.url
    if kind == "dns":
        return render_template("dns.html", result=res, error=None, query=q, permalink=permalink)
    if kind == "whois":
        return render_template("whois.html", result=res, error=None, query=q, permalink=permalink)
    if kind == "geo":
        return render_template("geo.html", result=res, error=None, query=q, permalink=permalink)
    abort(404)


# -------------------------------------------------
# Error handlers
# -------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("errors/404.html"), 404

@app.errorhandler(500)
def server_error(e):
    app.logger.exception("Internal Server Error")
    return render_template("errors/500.html"), 500


# -------------------------------------------------
# Dev entry
# -------------------------------------------------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)

# app.py
import os
import re
import socket
import json
import hashlib
import time
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple

import redis
import whois
from whois.exceptions import WhoisError  # для точного перехвата
import dns.resolver
import dns.exception
from ipwhois import IPWhois
import idna
import ipaddress
import subprocess

from geopy.geocoders import Nominatim

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    url_for,
    redirect,
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
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config['PREFERRED_URL_SCHEME'] = 'https'

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
    # Domain search
    AFFILIATE_BUY_BASE=os.environ.get(
        "AFFILIATE_BUY_BASE",
        "https://beget.com/p754742/domains/search/{domain}",
    ),
    TLD_LIST=os.environ.get(
        "TLD_LIST",
        "ru,su,com,net,org,info,pro,xyz,site,online,store,app,io,ai,co,me,blog",
    ).split(","),
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

@app.context_processor
def inject_common():
    return {
        "current_year": datetime.utcnow().year,
        "yandex_rtb_block_id": os.getenv("YANDEX_RTB_BLOCK_ID", "R-A-XXXXXXX-1"),
    }

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
    r"^(?=.{1,253}$)(?!-)(?!.*\.\.)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$",
    re.IGNORECASE,
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

def _normalize_domain_query(value: str):
    if not value:
        return None, _("Invalid domain name.")
    q = value.strip()
    try:
        if q.lower().startswith(("http://", "https://")):
            from urllib.parse import urlparse
            q = urlparse(q).hostname or q
    except Exception:
        pass
    q = q.rstrip(".").lower()
    # IP?
    try:
        ipaddress.ip_address(q)
        return q, None
    except Exception:
        pass
    if "." not in q:
        return None, _("Invalid domain name.")
    try:
        if not q.isascii():
            q = idna.encode(q, uts46=True).decode("ascii")
    except Exception:
        return None, _("Invalid domain name.")
    if not DOMAIN_RE.match(q):
        return None, _("Invalid domain name.")
    return q, None

# --- Fallback-парсер текста whois (минимум полезных полей) ---
WHOIS_PATTERNS = {
    "registrar": re.compile(r"Registrar:\s*(.+)", re.I),
    "whois_server": re.compile(r"Whois Server:\s*(.+)", re.I),
    "creation_date": re.compile(r"(Creation Date|Registered on):\s*([^\r\n]+)", re.I),
    "updated_date": re.compile(r"(Updated Date|Last Updated On):\s*([^\r\n]+)", re.I),
    "expiration_date": re.compile(r"(Registry Expiry Date|Expiry Date|Expires On):\s*([^\r\n]+)", re.I),
    "status": re.compile(r"Status:\s*([^\r\n]+)", re.I),
    "name_server": re.compile(r"Name Server:\s*([^\r\n]+)", re.I),
    "org": re.compile(r"(Registrant Organization|Registrant Organization Name):\s*([^\r\n]+)", re.I),
    "country": re.compile(r"(Registrant Country|Country):\s*([A-Z]{2})\b", re.I),
}

def parse_whois_text(domain: str, text: str) -> Dict:
    data: Dict[str, object] = {
        "domain_name": domain,
        "text": text or "",
    }
    if not text:
        return data

    m = WHOIS_PATTERNS["registrar"].search(text)
    if m: data["registrar"] = m.group(1).strip()

    m = WHOIS_PATTERNS["whois_server"].search(text)
    if m: data["whois_server"] = m.group(1).strip()

    m = WHOIS_PATTERNS["creation_date"].search(text)
    if m: data["creation_date"] = m.group(2).strip()

    m = WHOIS_PATTERNS["updated_date"].search(text)
    if m: data["updated_date"] = m.group(2).strip()

    m = WHOIS_PATTERNS["expiration_date"].search(text)
    if m: data["expiration_date"] = m.group(2).strip()

    statuses = [s.strip() for s in WHOIS_PATTERNS["status"].findall(text)]
    if statuses:
        data["status"] = statuses

    nss = [ns.strip().rstrip(".") for ns in WHOIS_PATTERNS["name_server"].findall(text)]
    if nss:
        data["name_servers"] = sorted(set(nss))

    m = WHOIS_PATTERNS["org"].search(text)
    if m: data["org"] = m.group(2).strip()

    m = WHOIS_PATTERNS["country"].search(text)
    if m: data["country"] = m.group(2).upper()

    return data

def run_system_whois(domain: str, timeout: int = 8) -> str:
    """Вызвать системную утилиту 'whois'. Вернуть сырой текст или пустую строку."""
    try:
        out = subprocess.run(
            ["whois", domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        return out.stdout or ""
    except Exception:
        return ""

# --- RU/TCI WHOIS parser ------------------------------------------------------
import re as _re

def _parse_ru_whois_text(text: str) -> dict:
    """
    Быстро распарсить raw WHOIS от whois.tcinet.ru (ru/rf-зоны) и вернуть
    словарь с ключами как у обычного whois: registrar, creation_date, expiration_date,
    status (list), name_servers (list), org, name, country, domain_name, updated_date.
    """
    out: dict = {}
    if not text:
        return out

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue

        # Пример: "last updated on 2025-10-16T19:13:01Z"
        m = _re.match(r"last updated on\s+(\S+)", line, _re.I)
        if m:
            out["updated_date"] = m.group(1)
            continue

        # Пример: "created: 1999-07-12T14:40:22Z" / "paid-till: 2026-07-31T21:00:00Z"
        m = _re.match(r"([a-z\-]+):\s*(.+)$", line, _re.I)
        if not m:
            continue
        key = m.group(1).lower()
        val = m.group(2).strip()

        if key == "domain":
            out["domain_name"] = val.lower()
        elif key == "registrar":
            out["registrar"] = val
        elif key == "created":
            out["creation_date"] = val
        elif key == "paid-till":
            out["expiration_date"] = val
        elif key == "free-date":
            out["free_date"] = val
        elif key == "state":
            # "REGISTERED, DELEGATED, VERIFIED"
            out["status"] = [s.strip() for s in _re.split(r"[,\s]+", val) if s.strip()]
        elif key == "nserver":
            # "ns1.example.ru." берем первый токен и без точки
            host = val.split()[0].rstrip(".")
            out.setdefault("name_servers", []).append(host)
        elif key == "org":
            out["org"] = val
        elif key == "person":
            out["name"] = val
        elif key == "country":
            out["country"] = val

    # для красоты укажем сервер-источник
    if "whois_server" not in out:
        out["whois_server"] = "whois.tcinet.ru"
    return out

# --- Нормализация и спец-WHOIS для RU/SU/РФ -----------------------------------
def _pick_first(v):
    if isinstance(v, (list, tuple)):
        return v[0] if v else None
    return v

def _to_iso(val):
    try:
        if hasattr(val, "isoformat"):
            return val.isoformat()
        if isinstance(val, (list, tuple)) and val:
            v0 = val[0]
            return v0.isoformat() if hasattr(v0, "isoformat") else str(v0)
        return str(val) if val is not None else None
    except Exception:
        return str(val) if val is not None else None

def _listify(v):
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return [str(x) for x in v if x]
    return [str(v)]

def _whois_tcinet(domain_ascii: str) -> str:
    """Вернуть RAW whois-текст от whois.tcinet.ru (порт 43)."""
    host = "whois.tcinet.ru"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(6)
    s.connect((host, 43))
    s.send((domain_ascii + "\r\n").encode("utf-8"))
    chunks = []
    while True:
        b = s.recv(4096)
        if not b:
            break
        chunks.append(b)
    s.close()
    return b"".join(chunks).decode("utf-8", "ignore")

def _normalize_whois_dict(d: dict, query: str) -> dict:
    out = dict(d or {})
    out["domain_name"] = out.get("domain_name") or out.get("domain") or query

    # списки/строки
    out["status"] = _listify(out.get("status"))
    out["name_servers"] = [ns.strip().rstrip(".") for ns in _listify(out.get("name_servers"))]

    # даты -> строки ISO где возможно
    for k in ("creation_date", "updated_date", "expiration_date"):
        out[k] = _to_iso(out.get(k))

    # punycode -> юникод для показа
    try:
        out["domain_unicode"] = idna.decode(out["domain_name"])
    except Exception:
        out["domain_unicode"] = out["domain_name"]

    # флаг «скоро истекает»
    out["expires_soon"] = False
    try:
        ed = out.get("expiration_date") or ""
        candidates = [
            ("%Y-%m-%dT%H:%M:%S", ed[:19]),
            ("%Y-%m-%d %H:%M:%S", ed[:19]),
            ("%Y-%m-%d", ed[:10]),
            ("%Y.%m.%d %H:%M:%S", ed[:19]),
            ("%Y.%m.%d", ed[:10]),
        ]
        dt = None
        for fmt, val in candidates:
            try:
                dt = datetime.strptime(val, fmt)
                break
            except Exception:
                continue
        if dt:
            out["expires_soon"] = (dt - datetime.utcnow()) <= timedelta(days=30)
    except Exception:
        pass

    return out

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
    base_urls = [
        url_for("index", _external=True),
        url_for("dns_lookup", _external=True),
        url_for("whois_lookup", _external=True),
        url_for("geo_lookup", _external=True),
        url_for("history_list", _external=True),
    ]
    # последние 200 из истории
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
    # Page meta
    meta = {
        "title": "DNS Lookup",
        "description": "Проверка DNS записей домена (A/AAAA/CNAME/MX/NS/TXT/SOA).",
    }

    query = (request.args.get("q") or "").strip()
    if not query:
        return render_template("dns.html", meta=meta, result=None, records={}, error=None, query="", permalink=None)

    records: Dict[str, List[str]] = {}
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

# ---------- Domains ----------
def _normalize_label(label: str) -> str:
    label = (label or "").strip().lower()
    label = re.sub(r"[^a-z0-9-]+", "-", label)
    label = re.sub(r"-{2,}", "-", label).strip("-")
    if not label:
        raise ValueError(_("Введите корректное имя"))
    return label

def _is_available_via_dns(fqdn: str) -> bool:
    try:
        dns.resolver.resolve(fqdn, "A", lifetime=2)
        return False
    except Exception:
        pass
    try:
        dns.resolver.resolve(fqdn, "AAAA", lifetime=2)
        return False
    except Exception:
        pass
    try:
        dns.resolver.resolve(fqdn, "CNAME", lifetime=2)
        return False
    except Exception:
        pass
    return True

def _is_available_via_whois(fqdn: str) -> bool:
    try:
        w = whois.whois(fqdn)
        if any([w.creation_date, w.expiration_date, w.registrar, w.status]):
            return False
        return True
    except Exception as e:
        msg = str(e).lower()
        patterns = ["no match", "not found", "no entries found", "available", "status: free"]
        return any(p in msg for p in patterns)

def _check_candidates(label: str, tlds) -> list[dict]:
    out = []
    for t in tlds:
        t = t.strip().lstrip(".")
        if not t:
            continue
        fqdn = f"{label}.{t}"
        puny = idna.encode(fqdn).decode()
        try:
            avail_dns = _is_available_via_dns(puny)
            avail = _is_available_via_whois(puny) if avail_dns else False
            out.append({"fqdn": fqdn, "available": bool(avail), "error": None})
        except Exception as e:
            out.append({"fqdn": fqdn, "available": False, "error": str(e)})
    return out

@app.route("/domains", methods=["GET", "POST"])
def domain_search():
    query = ""
    items = []
    error = None
    if request.method == "POST" or (request.method == "GET" and request.args.get("query")):
        query = (request.form.get("q") or "").strip()
        try:
            if "." in query:
                query = query.split(".")[0]
            label = _normalize_label(query)
            items = _check_candidates(label, app.config.get("TLD_LIST", []))
        except Exception as e:
            error = str(e)
    return render_template("domains.html", q=query, items=items,
                           error=error, buy_base=app.config.get("AFFILIATE_BUY_BASE"))

# ---------- WHOIS ----------
@app.route("/whois", methods=["GET", "POST"])
def whois_lookup():
    data: Optional[Dict] = None
    error: Optional[str] = None
    query = None
    permalink = None

    # работаем и с GET (?query=) и с POST (форма)
    if request.method == "POST" or (request.method == "GET" and request.args.get("query")):
        query = (request.form.get("query") or request.args.get("query") or "").strip()
        query, err = _normalize_domain_query(query)
        if err:
            error = err
            return render_template("whois.html", result=None, error=error, query=(query or ""), permalink=None)

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
                tld = query.rsplit(".", 1)[-1].lower()

                # Спец: .ru / .su / .рф
                if tld in {"ru", "su", "xn--p1ai"}:
                    raw_text = _whois_tcinet(query)
                    parsed = _parse_ru_whois_text(raw_text)
                    parsed["text"] = raw_text
                    data = _normalize_whois_dict(parsed, query)

                else:
                    # 1) пробуем python-whois
                    w = whois.whois(query)
                    raw_dict = {k: v for k, v in w.__dict__.items() if not k.startswith("_")}
                    text_from_lib = (raw_dict.get("text") or raw_dict.get("raw") or "") if isinstance(raw_dict.get("text") or "", str) else ""
                    normalized = _normalize_whois_dict(raw_dict, query)

                    # 2) если не хватает ключевых полей — добираем системным whois + парсером текста
                    important = any(normalized.get(k) for k in ("registrar", "creation_date", "expiration_date", "status", "name_servers"))
                    if not important:
                        sys_text = run_system_whois(query)
                        # если у либы был сырой текст — допишем; иначе возьмём из системного
                        normalized["text"] = text_from_lib or sys_text or ""
                        # парсинг генерализованный
                        parsed_txt = parse_whois_text(query, normalized["text"])
                        # объединяем, чтобы не потерять возможные даты из python-whois
                        for k, v in parsed_txt.items():
                            if k not in normalized or not normalized[k]:
                                normalized[k] = v
                        normalized = _normalize_whois_dict(normalized, query)
                    else:
                        # просто убедимся, что text присутствует для блока «Показать полный WHOIS»
                        normalized["text"] = text_from_lib or normalized.get("text") or ""

                    data = normalized

            hid = save_history("whois", query, data)
            permalink = url_for("history_view", kind="whois", hid=hid, _external=True)

        except ValueError as ve:
            error = str(ve)
        except Exception:
            app.logger.exception("WHOIS error")
            error = _("Unexpected error during WHOIS lookup.")

    # форма у нас отправляет GET — это важно, чтобы работа совпадала со стилем DNS
    return render_template("whois.html", result=data, error=error, query=query, permalink=permalink)

# ---------- GEO ----------
@app.route("/geo", methods=["GET", "POST"])
def geo_lookup():
    result: Optional[Dict] = None
    error: Optional[str] = None
    query = None
    permalink = None

    if request.method == "POST" or (request.method == "GET" and request.args.get("query")):
        query = (request.form.get("query") or request.args.get("query") or "").strip()
        query, err = _normalize_domain_query(query)
        if err:
            error = err
            return render_template('geo.html', result=None, error=error, query=(query or ''), permalink=None)
        try:
            # домен -> IP
            try:
                ipaddress.ip_address(query)
                ip = query
            except ValueError:
                ip = socket.gethostbyname(query)

            app.logger.info(f"Geo lookup for: {ip}")
            lookup = IPWhois(ip).lookup_rdap()
            asn = lookup.get("asn_description") or "N/A"
            country_code = lookup.get("asn_country_code") or "N/A"

            # человекочитаемое имя страны (best effort)
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

# ЧПУ для /whois/<domain>
@app.route("/whois/<path:domain>", methods=["GET", "POST"])
def whois_domain_lookup(domain):
    q = (domain or '').strip().rstrip('.').lower()
    # На любой метод уводим на базовый /whois с query,
    # чтобы форма всегда работала и не ловила 405.
    return redirect(url_for('whois_lookup', query=q), code=302)

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

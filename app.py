# app.py
import os
import re
import socket
import json
import hashlib
import time
import logging
import io
import csv
import subprocess
from urllib.parse import urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.reversename
from datetime import datetime
from typing import Optional, Dict, List, Tuple
from markupsafe import Markup, escape
import redis
import whois
from whois.exceptions import WhoisError  # noqa: F401
import dns.resolver
import dns.exception
from ipwhois import IPWhois
import idna
import ipaddress
import requests

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
from werkzeug.middleware.proxy_fix import ProxyFix

# === Блюпринт Site Checker ====================================
from flask_site_checker.blueprint import site_checker_bp
# ===============================================================

# -------------------------------------------------
# App & config
# -------------------------------------------------
app = Flask(__name__, template_folder="templates", static_folder="static")
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
    # Все зоны для подбора (ориентир: доступно у популярных российских регистраторов)
    TLD_LIST=os.environ.get(
        "TLD_LIST",
        "ru,su,рф,рус,москва,дети,tatar,com,net,org,info,biz,name,pro,mobi,tel,asia,me,tv,cc,ws,bz,in,co,io,ai,app,dev,site,online,store,shop,blog,tech,xyz,top,club,space,website,fun,live,digital,group,company,center,solutions,services,agency,media,today,world,email,expert,guru,news,software,cloud,team,systems,network,plus,art,icu,life,wiki,zone,run",
    ).split(","),
    # Основные зоны (по умолчанию отмечены в форме)
    DOMAIN_DEFAULT_TLDS=os.environ.get(
        "DOMAIN_DEFAULT_TLDS",
        "ru,рф,su,рус,com,net,org,info,pro,site,online,store,app,io,ai,co,me,xyz,shop,blog",
    ).split(","),
    DOMAIN_CHECK_MAX_TLDS=int(os.environ.get("DOMAIN_CHECK_MAX_TLDS", "80")),
    DOMAIN_CHECK_WORKERS=int(os.environ.get("DOMAIN_CHECK_WORKERS", "8")),
)

# Регистрируем блюпринт (он обслуживает /site-checker)
app.register_blueprint(site_checker_bp)

# Зоны, в которых разрешаем IDN-метки (берём из общего списка зон)
IDN_READY_TLDS = {
    t.strip().lstrip(".").lower()
    for t in app.config.get("TLD_LIST", [])
    if (t or "").strip()
}

# Redis
app.config.setdefault("REDIS_URL", os.getenv("REDIS_URL", "redis://127.0.0.1:6379/3"))
r = redis.from_url(app.config["REDIS_URL"], decode_responses=True)
HIST_NS = "dt:history"
HIST_ZSET = "dt:history:index"
HIST_LIMIT = 5000

# -------------------------------------------------
# Babel (Flask-Babel v3+)
# -------------------------------------------------
def _locale_by_country_header() -> str | None:
    """Определение локали по geo-заголовкам прокси/CDN (если доступны)."""
    # На проде обычно приходит один из этих заголовков.
    for h in ("CF-IPCountry", "X-AppEngine-Country", "X-Country-Code", "CloudFront-Viewer-Country"):
        cc = (request.headers.get(h) or "").strip().upper()
        if not cc or cc in {"XX", "T1", "UNKNOWN"}:
            continue
        return "ru" if cc == "RU" else "en"
    return None



# Небольшой in-memory кэш для гео-IP фолбэка (country by IP)
_IP_COUNTRY_CACHE: Dict[str, Tuple[str, float]] = {}


def _country_code_from_remote_ip(timeout_s: float = 0.8) -> str | None:
    """Пытаемся определить country code по IP клиента, если geo-заголовков нет."""
    ip = (request.remote_addr or "").strip()
    if not ip:
        return None

    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return None
    except Exception:
        return None

    now = time.time()
    cached = _IP_COUNTRY_CACHE.get(ip)
    if cached and cached[1] > now:
        return cached[0]

    # Лёгкий публичный geo endpoint без ключа
    url = f"http://ip-api.com/json/{ip}?fields=countryCode,status"
    try:
        resp = requests.get(url, timeout=timeout_s)
        data = resp.json() if resp.ok else {}
        cc = (data.get("countryCode") or "").strip().upper()
        if data.get("status") == "success" and len(cc) == 2:
            _IP_COUNTRY_CACHE[ip] = (cc, now + 3600)
            return cc
    except Exception:
        pass

    # Кэшируем неуспех на короткое время, чтобы не спамить внешний сервис
    _IP_COUNTRY_CACHE[ip] = ("", now + 300)
    return None


def _select_locale():
    # ?lang=ru|en имеет приоритет
    lang = (request.args.get("lang") or "").strip().lower()
    if lang in {"ru", "en"}:
        return lang

    # Явно выбранный ранее язык (cookie)
    c_lang = (request.cookies.get("lang") or "").strip().lower()
    if c_lang in {"ru", "en"}:
        return c_lang

    # Geo from edge headers: RU -> ru, any non-RU -> en
    by_country = _locale_by_country_header()
    if by_country:
        return by_country

    # Fallback: best-effort geo by remote IP (useful if proxy headers absent)
    cc = _country_code_from_remote_ip()
    if cc:
        return "ru" if cc == "RU" else "en"

    # Last fallback: browser language
    return request.accept_languages.best_match(["ru", "en"]) or "en"

babel = Babel(app, locale_selector=_select_locale)

# Пробросить get_locale() в шаблоны Jinja (для base.html и др.)
@app.context_processor
def inject_babel_helpers():
    def _lang_url(lang: str) -> str:
        params = request.args.to_dict(flat=False)
        params["lang"] = [lang]
        qs = urlencode(params, doseq=True)
        return f"{request.path}?{qs}" if qs else request.path

    def _tr(ru_text: str, en_text: str) -> str:
        return en_text if str(babel_get_locale() or "ru") == "en" else ru_text

    return {
        "get_locale": (lambda: str(babel_get_locale() or "ru")),
        "lang_url": _lang_url,
        "tr": _tr,
    }


@app.after_request
def persist_lang_cookie(resp: Response):
    lang = (request.args.get("lang") or "").strip().lower()
    if lang in {"ru", "en"}:
        resp.set_cookie("lang", lang, max_age=60 * 60 * 24 * 365, samesite="Lax")
    return resp

# -------------------------------------------------
# Cache
# -------------------------------------------------
cache = Cache(app)

def cache_json(key: str, ttl: int, compute_fn):
    data = r.get(key)
    if data:
        try:
            return json.loads(data)
        except Exception:
            pass
    val = compute_fn()
    try:
        r.setex(key, ttl, json.dumps(val, ensure_ascii=False))
    except Exception:
        pass
    return val

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
    h = hashlib.sha1(f"{kind}|{query}|{time.time()}".encode("utf-8")).hexdigest()
    return h[:12]

def save_history(kind: str, query: str, result: Dict) -> str:
    hid = make_id(kind, query)
    doc = {
        "kind": kind,
        "id": hid,
        "query": query,
        "result": result,
        "ts": int(time.time()),
    }
    try:
        r.set(f"{HIST_NS}:{kind}:{hid}", json.dumps(doc, ensure_ascii=False))
        r.zadd(HIST_ZSET, {f"{kind}:{hid}": doc["ts"]})
        # trim
        total = r.zcard(HIST_ZSET)
        if total and total > HIST_LIMIT:
            to_rem = r.zrange(HIST_ZSET, 0, total - HIST_LIMIT - 1)
            if to_rem:
                r.zrem(HIST_ZSET, *to_rem)
    except Exception:
        app.logger.exception("History save failed")
    return hid

def load_history(kind: str, hid: str) -> Optional[Dict]:
    try:
        s = r.get(f"{HIST_NS}:{kind}:{hid}")
        if not s:
            return None
        return json.loads(s)
    except Exception:
        return None

def _split_kind_id(s: str) -> Optional[Tuple[str, str]]:
    try:
        if ":" in s:
            kind, hid = s.split(":", 1)
            if kind and hid:
                return kind, hid
    except Exception:
        pass
    return None

def _normalize_domain_query(q: str) -> Tuple[Optional[str], Optional[str]]:
    q = (q or "").strip().lower()
    try:
        # если пришёл URL — вытащим hostname
        if any(q.startswith(p) for p in ("http://", "https://")):
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

    # Приводим к punycode (ascii)
    try:
        if not q.isascii():
            q = idna.encode(q, uts46=True).decode("ascii")
    except Exception:
        return None, _("Invalid domain name.")

    if not DOMAIN_RE.match(q):
        return None, _("Invalid domain name.")
    return q, None

def _to_unicode(domain: str) -> str:
    try:
        return idna.decode(domain)
    except Exception:
        return domain

# --- Простой парсер RU whois (tcinet) для доп.полей ---------------------------
def _parse_ru_whois_text(text: str) -> Dict:
    out: Dict[str, object] = {}
    lines = [ln.rstrip() for ln in text.splitlines()]
    _re = re

    for ln in lines:
        if ":" not in ln:
            continue
        key, val = ln.split(":", 1)
        key = key.strip().lower()
        val = val.strip()
        if not val:
            continue
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
            out["status"] = [s.strip() for s in _re.split(r"[,\s]+", val) if s.strip()]
        elif key == "nserver":
            host = val.split()[0].rstrip(".")
            out.setdefault("name_servers", []).append(host)
        elif key == "org":
            out["org"] = val
        elif key == "person":
            out["name"] = val
        elif key == "country":
            out["country"] = val

    if "whois_server" not in out:
        out["whois_server"] = "whois.tcinet.ru"
    return out

# --- WHOIS low-level helpers --------------------------------------------------
def _whois_call(cmd: List[str], timeout: int) -> str:
    """
    Запуск системной утилиты `whois`. Возвращает stdout (может быть пустым).
    """
    try:
        out = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        return out.stdout or ""
    except Exception as e:
        return str(e) or ""

def parse_whois_text(domain: str, text: str) -> Dict:
    """
    Базовый парсер whois из whois пакет + наш парсер RU.
    """
    try:
        parsed = whois.parse.parse_raw_whois(domain, text, normalized=True)
        return parsed or {}
    except Exception:
        return {}

# --- Транслитерация для подсказок --------------------------------------------
RU_MAP = str.maketrans({
    "а":"a","б":"b","в":"v","г":"g","д":"d","е":"e","ё":"e","ж":"zh","з":"z","и":"i","й":"y",
    "к":"k","л":"l","м":"m","н":"n","о":"o","п":"p","р":"r","с":"s","т":"t","у":"u","ф":"f",
    "х":"h","ц":"c","ч":"ch","ш":"sh","щ":"sch","ъ":"","ы":"y","ь":"","э":"e","ю":"yu","я":"ya"
})
def _translit_ru(label: str) -> str:
    return "".join((ch.translate(RU_MAP) if ch in RU_MAP else ch) for ch in label.lower())

# --- Jinja filters ------------------------------------------------------------
def prettyjson_filter(value):
    try:
        if isinstance(value, (dict, list, tuple)):
            s = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
        else:
            # попробуем распарсить строку как JSON
            s = json.dumps(json.loads(str(value)), ensure_ascii=False, indent=2, sort_keys=True)
    except Exception:
        s = str(value)
    # отдать как «безопасный» текст (ничего не экранируется повторно)
    return Markup(escape(s))


def json_rows_filter(value):
    """Преобразует dict/list в плоский список пар (поле, значение) для табличного вывода."""
    rows = []

    def walk(node, prefix=""):
        if isinstance(node, dict):
            if not node:
                rows.append((prefix or "—", "{}"))
                return
            for k, v in node.items():
                key = f"{prefix}.{k}" if prefix else str(k)
                walk(v, key)
            return

        if isinstance(node, list):
            if not node:
                rows.append((prefix or "—", "[]"))
                return
            for i, v in enumerate(node):
                key = f"{prefix}[{i}]" if prefix else f"[{i}]"
                walk(v, key)
            return

        if isinstance(node, tuple):
            walk(list(node), prefix)
            return

        rows.append((prefix or "value", "" if node is None else str(node)))

    walk(value)
    return rows
# --- country_flag для geo.html ---
def country_flag(cc: str) -> str:
    if not cc or len(cc) != 2 or not cc.isalpha():
        return ""
    base = 127397
    return "".join(chr(ord(c.upper()) + base) for c in cc)

@app.context_processor
def jinja_more_globals():
    return {"country_flag": country_flag}

# регистрируем фильтр *явно* (поверх декораторов/блюпринтов)
app.jinja_env.filters['prettyjson'] = prettyjson_filter
app.jinja_env.filters['json_rows'] = json_rows_filter
# --- форматирование времени для истории ---
@app.template_filter("dt")
def dt_filter(ts):
    try:
        return datetime.fromtimestamp(int(ts)).strftime("%d.%m.%Y %H:%M:%S")
    except Exception:
        return ""


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
        "",
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
        url_for("domain_search", _external=True),
        url_for("reverse_lookup", _external=True),
        url_for("history_list", _external=True),
        # ссылка на маршрут блюпринта
        url_for("site_checker.site_checker", _external=True),
    ]
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
    dns_type_options = [
        "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV", "PTR", "NAPTR",
        "TLSA", "SSHFP", "DS", "DNSKEY", "CDS", "CDNSKEY", "SPF", "HTTPS", "SVCB", "LOC",
        "RP", "HINFO", "CERT", "DNAME", "URI",
    ]
    default_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]

    meta = {
        "title": "DNS Lookup",
        "description": "Проверка DNS записей домена (A/AAAA/CNAME/MX/NS/TXT/SOA).",
    }
    query = (request.args.get("q") or "").strip()
    selected_types = [t.strip().upper() for t in request.args.getlist("types") if t and t.strip()]
    if not selected_types:
        selected_types = list(default_types)
    if "ALL" in selected_types:
        selected_types = list(dns_type_options)
    selected_types = [t for t in selected_types if t in dns_type_options]
    if not selected_types:
        selected_types = list(default_types)

    if not query:
        return render_template(
            "dns.html",
            meta=meta,
            result=None,
            error=None,
            query="",
            selected_types=selected_types,
            dns_type_options=dns_type_options,
        )

    error = None
    try:
        # punycode
        if not query.isascii():
            query = idna.encode(query, uts46=True).decode("ascii")
        validate_domain(query)
    except Exception:
        return render_template(
            "dns.html",
            meta=meta,
            result=None,
            error=_("Invalid domain name."),
            query=query,
            selected_types=selected_types,
            dns_type_options=dns_type_options,
        )

    records: Dict[str, List[str]] = {}
    def fetch(rtype: str):
        try:
            answers = dns.resolver.resolve(query, rtype)
            vals = []
            for r in answers:
                if rtype == "MX":
                    vals.append(f"{getattr(r, 'preference', '')} {str(getattr(r, 'exchange', '')).rstrip('.')}".strip())
                elif rtype == "SOA":
                    vals.append(
                        f"{str(getattr(r, 'mname', '')).rstrip('.')} {str(getattr(r, 'rname', '')).rstrip('.')} "
                        f"{getattr(r, 'serial', '')} {getattr(r, 'refresh', '')} {getattr(r, 'retry', '')} "
                        f"{getattr(r, 'expire', '')} {getattr(r, 'minimum', '')}"
                    )
                elif rtype == "SRV":
                    vals.append(
                        f"{getattr(r, 'priority', '')} {getattr(r, 'weight', '')} {getattr(r, 'port', '')} "
                        f"{str(getattr(r, 'target', '')).rstrip('.')}"
                    )
                elif rtype == "CAA":
                    vals.append(f"{getattr(r, 'flags', '')} {getattr(r, 'tag', '')} {getattr(r, 'value', '')}".strip())
                elif rtype in {"DS", "CDS"}:
                    vals.append(
                        f"{getattr(r, 'key_tag', '')} {getattr(r, 'algorithm', '')} {getattr(r, 'digest_type', '')} {getattr(r, 'digest', '')}"
                    )
                elif rtype in {"DNSKEY", "CDNSKEY"}:
                    vals.append(
                        f"{getattr(r, 'flags', '')} {getattr(r, 'protocol', '')} {getattr(r, 'algorithm', '')} {getattr(r, 'key', '')}"
                    )
                elif rtype == "TXT":
                    chunks = getattr(r, "strings", None)
                    if chunks:
                        vals.append("".join(ch.decode("utf-8", errors="ignore") if isinstance(ch, bytes) else str(ch) for ch in chunks))
                    else:
                        vals.append(str(r).rstrip("."))
                else:
                    vals.append(str(r).rstrip("."))
            if vals:
                records[rtype] = vals
        except Exception:
            pass

    for rt in selected_types:
        fetch(rt)

    result = {"domain": query, "has_records": bool(records), "records": records}
    permalink = url_for("dns_lookup", q=query, types=selected_types, _external=False)

    return render_template(
        "dns.html",
        meta=meta,
        result=result,
        records=records,
        error=error,
        query=query,
        permalink=permalink,
        selected_types=selected_types,
        dns_type_options=dns_type_options,
    )

# ---------- Domains ----------
def _normalize_label(label: str) -> str:
    """
    Нормализация метки…
    """
    label = (label or "").strip()
    label = re.sub(r"[\s_]+", "-", label)
    label = "".join(ch for ch in label if ch.isalnum() or ch == "-")
    label = re.sub(r"-{2,}", "-", label).strip("-")
    if not label:
        raise ValueError(_("Введите корректное имя"))
    if len(label) > 63:
        raise ValueError(_("Метка домена слишком длинная"))
    return label

def _is_available_via_dns(fqdn_ascii: str) -> bool:
    # быстрый тест: A + NS
    try:
        dns.resolver.resolve(fqdn_ascii, "NS")
        return False
    except Exception:
        pass
    try:
        dns.resolver.resolve(fqdn_ascii, "A")
        return False
    except Exception:
        pass
    return True

def _is_available_via_whois(fqdn_ascii: str) -> bool:
    try:
        w = whois.whois(fqdn_ascii)
        return not bool(w.domain_name)
    except Exception:
        return False

def _check_candidates(label: str, tlds: List[str]) -> List[Dict]:
    out: List[Dict] = []
    is_idn_label = not label.isascii()

    filtered_tlds: List[str] = []
    for t in tlds:
        t = t.strip().lstrip(".")
        if not t:
            continue
        if is_idn_label and t not in IDN_READY_TLDS:
            continue
        filtered_tlds.append(t)

    def _check_single_tld(t: str) -> Dict:
        fqdn_unicode = f"{label}.{t}"
        try:
            puny = idna.encode(fqdn_unicode, uts46=True).decode("ascii")
            avail_dns = _is_available_via_dns(puny)
            avail = _is_available_via_whois(puny) if avail_dns else False
            return {"fqdn": fqdn_unicode, "puny": puny, "available": bool(avail), "error": None}
        except Exception as e:
            return {"fqdn": fqdn_unicode, "puny": None, "available": False, "error": str(e) or "IDN error"}

    max_workers = max(1, min(int(app.config.get("DOMAIN_CHECK_WORKERS", 8)), len(filtered_tlds) or 1))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_to_index = {
            pool.submit(_check_single_tld, t): i
            for i, t in enumerate(filtered_tlds)
        }
        ordered_results: List[Optional[Dict]] = [None] * len(filtered_tlds)
        for fut in as_completed(future_to_index):
            idx = future_to_index[fut]
            ordered_results[idx] = fut.result()

    out.extend(item for item in ordered_results if item)
    return out

@app.route("/domains", methods=["GET", "POST"])
def domain_search():
    query = (request.args.get("query") or request.args.get("q") or request.form.get("q") or "").strip()
    items = []
    error = None
    suggestions = []

    all_tlds = [t.strip().lstrip(".") for t in app.config.get("TLD_LIST", []) if (t or "").strip()]
    # Убираем дубли, сохраняя порядок
    all_tlds = list(dict.fromkeys(all_tlds))

    default_tlds_cfg = [t.strip().lstrip(".") for t in app.config.get("DOMAIN_DEFAULT_TLDS", []) if (t or "").strip()]
    default_tlds = [t for t in default_tlds_cfg if t in all_tlds] or all_tlds[:20]

    selected_from_req = [t.strip().lstrip(".") for t in request.values.getlist("zones") if (t or "").strip()]
    selected_tlds = [t for t in all_tlds if t in set(selected_from_req)] if selected_from_req else default_tlds

    if query:
        try:
            if "." in query:
                query = query.split(".")[0]
            label = _normalize_label(query)
            if any("а" <= ch <= "я" or ch == "ё" for ch in label):
                translit = _translit_ru(label)
                suggestions = sorted(set([
                    translit,
                    translit.replace("sch", "sh").replace("ya", "a"),
                ]))

            tlds_for_check = selected_tlds
            if not selected_from_req:
                max_tlds = max(1, int(app.config.get("DOMAIN_CHECK_MAX_TLDS", 80)))
                tlds_for_check = selected_tlds[:max_tlds]

            items = _check_candidates(label, tlds_for_check)
        except Exception as e:
            error = str(e)

    return render_template(
        "domains.html",
        q=query,
        items=items,
        error=error,
        suggestions=suggestions,
        buy_base=app.config.get("AFFILIATE_BUY_BASE"),
        all_tlds=all_tlds,
        selected_tlds=selected_tlds,
        default_tlds=default_tlds,
    )

# ---------- WHOIS ----------
@app.route("/whois", methods=["GET", "POST"])
def whois_lookup():
    query = (request.args.get("query") or request.args.get("q") or request.form.get("q") or "").strip()
    data = None
    error = None
    permalink = None

    if not query:
        return render_template("whois.html", result=None, error=None, query=query, permalink=None)

    try:
        q, err = _normalize_domain_query(query)
        if err:
            raise ValueError(err)

        def _compute_whois():
            base: Dict[str, object] = {}
            # 1) попытка системной утилиты whois (часто лучше парсится .RU/.РФ)
            maybe_text = _whois_call(["whois", "-H", q], timeout=12)
            important = False
            try:
                w = whois.whois(q)
                for k, v in w.__dict__.items():
                    if k.startswith("_"):
                        continue
                    base[k] = v
                important = True
            except Exception:
                pass

            if maybe_text and not important:
                parsed = _parse_ru_whois_text(maybe_text) or parse_whois_text(q, maybe_text)
                base.update(parsed)

            base.setdefault("domain_name", q)
            du = _to_unicode(q)
            if du and du != q:
                base["domain_unicode"] = du
            return base

        cache_key = f"cache:whois:{q}"
        ttl = 300  # 5 минут
        data = cache_json(cache_key, ttl, _compute_whois)

        hid = save_history("whois", q, data)
        permalink = url_for("history_view", kind="whois", hid=hid, _external=True)

    except ValueError as ve:
        error = str(ve)
    except Exception:
        app.logger.exception("WHOIS error for %s", query)
        error = _("Unexpected error during WHOIS lookup.")

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
            except Exception:
                ips = []
                try:
                    for rr in dns.resolver.resolve(query, "A"):
                        ips.append(rr.to_text())
                except Exception:
                    pass
                try:
                    for rr in dns.resolver.resolve(query, "AAAA"):
                        ips.append(rr.to_text())
                except Exception:
                    pass
                ip = ips[0] if ips else None

            if not ip:
                error = _("No IPs found for the host.")
                return render_template('geo.html', result=None, error=error, query=query, permalink=None)

            def _compute_geo():
                ipw = IPWhois(ip)
                who = ipw.lookup_rdap()
                country_code = (who.get("asn_country_code") or "").upper()
                country_name = who.get("network", {}).get("country", "") or country_code
                return {
                    "ip": ip,
                    "asn": who.get("asn"),
                    "country_code": country_code,
                    "country_name": country_name,
                }

            cache_key = f"cache:geo:{ip}"
            result = cache_json(cache_key, 300, _compute_geo)
            hid = save_history("geo", query, result)
            permalink = url_for("history_view", kind="geo", hid=hid, _external=True)

        except Exception:
            app.logger.exception("GeoIP error")
            error = _("An error occurred during GeoIP lookup.")

    return render_template("geo.html", result=result, error=error, query=query, permalink=permalink)

# ---------- REVERSE (rDNS + FCrDNS) ----------
@app.route("/reverse", methods=["GET", "POST"])
def reverse_lookup():
    query = (request.args.get("q") or request.args.get("query") or request.form.get("q") or "").strip()
    result = None
    error = None
    permalink = None

    def _resolve_host_ips(host: str) -> dict:
        out = {}
        for t in ("A", "AAAA"):
            try:
                answers = dns.resolver.resolve(host, t)
                out[t] = [str(r) for r in answers]
            except Exception:
                pass
        return out

    def _reverse_one_ip(ip: str) -> dict:
        row = {"ip": ip, "ptr": [], "fcrdns_ok": False, "forward_of_ptr": {}}
        try:
            rev = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(rev, "PTR")
            ptrs = [str(r).rstrip(".") for r in answers]
            row["ptr"] = ptrs

            forward_addrs = set()
            for hn in ptrs:
                ips = _resolve_host_ips(hn)
                row["forward_of_ptr"][hn] = ips
                forward_addrs.update(ips.get("A", []))
                forward_addrs.update(ips.get("AAAA", []))

            row["fcrdns_ok"] = ip in forward_addrs
        except Exception as e:
            row["error"] = str(e)
        return row

    if query:
        try:
            # IP?
            try:
                ipaddress.ip_address(query)
                is_ip = True
            except Exception:
                is_ip = False

            if is_ip:
                def _compute_reverse_ip():
                    row = _reverse_one_ip(query)
                    return {"input": query, "type": "ip", "rows": [row]}
                cache_key = f"cache:reverse:{query}"
                result = cache_json(cache_key, 300, _compute_reverse_ip)

            else:
                # Домен → A/AAAA → для каждого IP делаем rDNS
                qnorm, qerr = _normalize_domain_query(query)
                if qerr:
                    raise ValueError(qerr)
                host_ascii = qnorm

                def _compute_reverse_host():
                    fwd = _resolve_host_ips(host_ascii)
                    rows = []
                    for ip in sorted(set((fwd.get("A") or []) + (fwd.get("AAAA") or []))):
                        rows.append(_reverse_one_ip(ip))
                    return {"input": query, "input_ascii": host_ascii, "type": "host", "forward": fwd, "rows": rows}

                cache_key = f"cache:reverse:{host_ascii}"
                result = cache_json(cache_key, 300, _compute_reverse_host)

            hid = save_history("reverse", query, result)
            permalink = url_for("history_view", kind="reverse", hid=hid, _external=True)

        except ValueError as ve:
            error = str(ve)
        except Exception:
            app.logger.exception("Reverse lookup error")
            error = _("An unexpected error occurred during reverse lookup.")

    return render_template("reverse.html", result=result, error=error, query=query, permalink=permalink)

# ---------- История ----------
@app.get("/history")
def history_list():
    items = []
    history_error = None

    try:
        # последние 100
        keys = r.zrevrange(HIST_ZSET, 0, 99)
    except Exception:
        app.logger.warning("History Redis unavailable", exc_info=True)
        keys = []
        history_error = _("History storage is temporarily unavailable. Please try again later.")

    for s in keys:
        pair = _split_kind_id(s)
        if not pair:
            continue
        kind, hid = pair
        doc = load_history(kind, hid)
        if not doc:
            continue

        q = (doc.get("query") or "").strip()

        # ссылка на сохранённый результат
        view_url = url_for("history_view", kind=kind, hid=hid)

        # ссылка "повторить" под конкретный сервис
        if kind == "dns":
            repeat_url = url_for("dns_lookup", q=q)
        elif kind == "whois":
            repeat_url = url_for("whois_lookup", query=q)
        elif kind == "geo":
            repeat_url = url_for("geo_lookup", query=q)
        elif kind == "reverse":
            repeat_url = url_for("reverse_lookup", q=q)
        else:
            repeat_url = None

        items.append({
            "id": hid,
            "kind": kind,
            "query": q,
            "ts": doc.get("ts"),
            "view_url": view_url,
            "repeat_url": repeat_url,
        })

    return render_template("history.html", items=items, history_error=history_error)

@app.route("/history/<kind>/<hid>")
def history_view(kind: str, hid: str):
    if kind not in {"dns", "whois", "geo", "reverse"}:
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
    if kind == "reverse":
        return render_template("reverse.html", result=res, error=None, query=q, permalink=permalink)
    abort(404)

# ---------- Экспорт ----------
@app.get("/export/<kind>/<hid>.<fmt>")
def export_result(kind: str, hid: str, fmt: str):
    if kind not in {"dns", "whois", "geo", "reverse"}:
        abort(404)
    doc = load_history(kind, hid)
    if not doc:
        abort(404)
    result = doc.get("result") or {}
    fn = f"{kind}-{hid}.{fmt.lower()}"

    if fmt.lower() == "json":
        return Response(json.dumps(result, ensure_ascii=False, indent=2), mimetype="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{fn}"'})

    if fmt.lower() == "csv":
        si = io.StringIO()
        writer = csv.writer(si)
        if kind == "whois":
            fields = ["domain_name","registrar","whois_server","creation_date","updated_date",
                      "expiration_date","status","name_servers","org","name","country"]
            writer.writerow(fields)
            row = []
            for f in fields:
                val = result.get(f, "")
                if isinstance(val, (list, tuple)):
                    val = ", ".join(val)
                row.append(val)
            writer.writerow(row)
        elif kind == "geo":
            fields = ["ip","asn","country_code","country_name"]
            writer.writerow(fields)
            writer.writerow([result.get(f,"") for f in fields])
        elif kind == "dns":
            writer.writerow(["type","values"])
            recs = result.get("records") or {}
            for t, vals in recs.items():
                if isinstance(vals, (list, tuple)):
                    writer.writerow([t, " | ".join(vals)])
                else:
                    writer.writerow([t, str(vals)])
        elif kind == "reverse":
            writer.writerow(["IP","PTR","FCrDNS"])
            for row in (result.get("rows") or []):
                ptr = ", ".join(row.get("ptr") or [])
                ok = "OK" if row.get("fcrdns_ok") else "FAIL"
                writer.writerow([row.get("ip",""), ptr, ok])
        data = si.getvalue()
        return Response(data, mimetype="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{fn}"'})

    abort(404)

# ---------- ЧПУ для WHOIS ----------
@app.route("/whois/<path:domain>", methods=["GET", "POST"])
def whois_domain_lookup(domain):
    q = (domain or '').strip().rstrip('.').lower()
    return redirect(url_for('whois_lookup', query=q), code=302)

# ВНИМАНИЕ: отдельный legacy-роут на /site-checker (blueprint)
# отдаётся блюпринтом

# ---------- Страницы ошибок ----------
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

# app.py
import os
import sys
import re
import socket
import json
import hashlib
import time
import logging
import io
import csv
import subprocess
import uuid
import random
from urllib.parse import urlencode, urlparse, urljoin, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.reversename
from datetime import datetime, timezone, date
from dateutil import parser as date_parser
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
# === Agent API (JSON для LLM/агентов) ==========================
from agent_api import agent_api_bp
# ===============================================================

# -------------------------------------------------
# App & config
# -------------------------------------------------
def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _running_under_tests() -> bool:
    return "unittest" in sys.modules or "pytest" in sys.modules or _env_flag("FLASK_TESTING")


def _resolve_secret_key() -> str:
    explicit = (os.environ.get("SECRET_KEY") or "").strip()
    if explicit:
        return explicit
    if _running_under_tests():
        return "test-secret"
    if _env_flag("FLASK_DEBUG"):
        return "dev-secret"
    return ""


app = Flask(__name__, template_folder="templates", static_folder="static")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config['PREFERRED_URL_SCHEME'] = 'https'

app.config.update(
    SECRET_KEY=_resolve_secret_key(),
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
        "https://beget.com/p754742/ru/domains/search/{domain}#search-form-section",
    ),
    AFFILIATE_BUY_BASE_RU=os.environ.get(
        "AFFILIATE_BUY_BASE_RU",
        os.environ.get("AFFILIATE_BUY_BASE", "https://beget.com/p754742/ru/domains/search/{domain}#search-form-section"),
    ),
    AFFILIATE_BUY_BASE_EN=os.environ.get(
        "AFFILIATE_BUY_BASE_EN",
        "https://beget.com/p754742/en/domains/search/{domain}#search-form-section",
    ),
    # Все зоны для подбора (ориентир: доступно у популярных российских регистраторов)
    TLD_LIST=os.environ.get(
        "TLD_LIST",
        "ru,su,рф,рус,москва,дети,tatar,com,net,org,info,biz,name,pro,mobi,tel,asia,me,tv,cc,ws,bz,in,co,io,ai,app,dev,site,online,store,shop,blog,tech,xyz,top,club,space,website,fun,live,digital,group,company,center,solutions,services,agency,media,today,world,email,expert,guru,news,software,cloud,team,systems,network,plus,art,icu,life,wiki,zone,run",
    ).split(","),
    # Основные зоны (по умолчанию отмечены в форме)
    DOMAIN_DEFAULT_TLDS=os.environ.get(
        "DOMAIN_DEFAULT_TLDS",
        "ru,рф,com,site,online",
    ).split(","),
    DOMAIN_CHECK_MAX_TLDS=int(os.environ.get("DOMAIN_CHECK_MAX_TLDS", "80")),
    DOMAIN_CHECK_WORKERS=int(os.environ.get("DOMAIN_CHECK_WORKERS", "8")),
    # Security scanner
    PORT_SCAN_MAX_PORTS=int(os.environ.get("PORT_SCAN_MAX_PORTS", "50")),
    PORT_SCAN_MAX_WORKERS=int(os.environ.get("PORT_SCAN_MAX_WORKERS", "20")),
    PORT_SCAN_CONNECT_TIMEOUT=float(os.environ.get("PORT_SCAN_CONNECT_TIMEOUT", "0.4")),
    SECURITY_RATE_LIMIT_PER_MIN=int(os.environ.get("SECURITY_RATE_LIMIT_PER_MIN", "15")),
    SECURITY_RECAPTCHA_ENABLED=(os.environ.get("SECURITY_RECAPTCHA_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"}),
    SECURITY_RECAPTCHA_PROVIDER=(os.environ.get("SECURITY_RECAPTCHA_PROVIDER", "standard").strip().lower() or "standard"),
    SECURITY_RECAPTCHA_SITE_KEY=(os.environ.get("SECURITY_RECAPTCHA_SITE_KEY") or os.environ.get("RECAPTCHA_SITE_KEY") or "").strip(),
    SECURITY_RECAPTCHA_SECRET_KEY=(os.environ.get("SECURITY_RECAPTCHA_SECRET_KEY") or os.environ.get("RECAPTCHA_SECRET_KEY") or "").strip(),
    SECURITY_RECAPTCHA_ENTERPRISE_PROJECT=os.environ.get("SECURITY_RECAPTCHA_ENTERPRISE_PROJECT", "").strip(),
    SECURITY_RECAPTCHA_API_KEY=os.environ.get("SECURITY_RECAPTCHA_API_KEY", "").strip(),
    SECURITY_RECAPTCHA_MIN_SCORE=float(os.environ.get("SECURITY_RECAPTCHA_MIN_SCORE", "0.5")),
    SECURITY_RECAPTCHA_ACTION=os.environ.get("SECURITY_RECAPTCHA_ACTION", "security_scan").strip() or "security_scan",
    FORM_RECAPTCHA_ENABLED=(os.environ.get("FORM_RECAPTCHA_ENABLED", os.environ.get("SECURITY_RECAPTCHA_ENABLED", "0")).strip().lower() in {"1", "true", "yes", "on"}),
    FORM_RECAPTCHA_ACTION=os.environ.get("FORM_RECAPTCHA_ACTION", "form_submit").strip() or "form_submit",
    SECURITY_METRICS_PUBLIC=(os.environ.get("SECURITY_METRICS_PUBLIC", "0").strip().lower() in {"1", "true", "yes", "on"}),
    JOB_STORAGE_ALLOW_LOCAL_FALLBACK=(os.environ.get("JOB_STORAGE_ALLOW_LOCAL_FALLBACK", "0").strip().lower() in {"1", "true", "yes", "on"}),
    SAFE_HTTP_MAX_BYTES=int(os.environ.get("SAFE_HTTP_MAX_BYTES", "1048576")),
    SAFE_HTTP_MAX_REDIRECTS=int(os.environ.get("SAFE_HTTP_MAX_REDIRECTS", "5")),
    # Agent / LLM API (disabled by default; enable only with AGENT_API_KEY set)
    AGENT_API_ENABLED=(os.environ.get("AGENT_API_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"}),
    AGENT_API_KEY=(os.environ.get("AGENT_API_KEY") or "").strip(),
    AGENT_API_RATE_LIMIT_PER_MIN=int(os.environ.get("AGENT_API_RATE_LIMIT_PER_MIN", "30")),
    AGENT_API_REPORT_RATE_LIMIT_PER_MIN=int(os.environ.get("AGENT_API_REPORT_RATE_LIMIT_PER_MIN", "10")),
    TOOL_RATE_LIMIT_PER_MIN=int(os.environ.get("TOOL_RATE_LIMIT_PER_MIN", "20")),
    DOMAINS_RATE_LIMIT_PER_MIN=int(os.environ.get("DOMAINS_RATE_LIMIT_PER_MIN", "10")),
    SITE_CHECKER_RATE_LIMIT_PER_MIN=int(os.environ.get("SITE_CHECKER_RATE_LIMIT_PER_MIN", "15")),
    SITE_CANONICAL_ROOT=(os.environ.get("SITE_CANONICAL_ROOT", "https://domaintools.site").strip().rstrip("/")),
    INDEXNOW_DEBOUNCE_S=int(os.environ.get("INDEXNOW_DEBOUNCE_S", "600")),
)

if not app.config.get("SECRET_KEY"):
    raise RuntimeError(
        "SECRET_KEY is required in production. "
        "Set SECRET_KEY in the environment (see deploy/domaintools.env.example)."
    )

if app.config.get("AGENT_API_ENABLED") and not app.config.get("AGENT_API_KEY"):
    app.logger.warning(
        "AGENT_API_ENABLED=1 but AGENT_API_KEY is empty — Agent API requests will be rejected until a key is set."
    )

_indexnow_key = (os.environ.get("INDEXNOW_KEY") or "").strip()
_indexnow_explicit = os.environ.get("INDEXNOW_ENABLED", "").strip().lower()
if _indexnow_explicit in {"0", "false", "no", "off"}:
    _indexnow_wanted = False
elif _indexnow_explicit in {"1", "true", "yes", "on"} or _env_flag("INDEXNOW_AUTO_KEY"):
    _indexnow_wanted = True
else:
    _indexnow_wanted = not _env_flag("INDEXNOW_DISABLED") and not _running_under_tests()
if not _indexnow_key and _indexnow_wanted:
    _indexnow_key = hashlib.sha256(f"{app.config['SECRET_KEY']}:indexnow:v1".encode()).hexdigest()[:32]
app.config["INDEXNOW_KEY"] = _indexnow_key
app.config["INDEXNOW_ENABLED"] = bool(_indexnow_key and _indexnow_wanted and not _running_under_tests())
if app.config["INDEXNOW_ENABLED"]:
    _idx_root = app.config.get("SITE_CANONICAL_ROOT") or "https://domaintools.site"
    app.logger.info("IndexNow enabled: key file at %s/%s.txt", _idx_root.rstrip("/"), _indexnow_key)

# Регистрируем блюпринты
app.register_blueprint(site_checker_bp)  # /site-checker
app.register_blueprint(agent_api_bp)     # /api/v1/*

SECURITY_JOB_TTL_S = int(os.environ.get("SECURITY_JOB_TTL_S", "3600"))
SECURITY_ASYNC_WORKERS = int(os.environ.get("SECURITY_ASYNC_WORKERS", "4"))
_SECURITY_ASYNC_POOL = ThreadPoolExecutor(max_workers=max(1, SECURITY_ASYNC_WORKERS))
_SECURITY_JOB_LOCAL: Dict[str, Dict] = {}

REPORT_JOB_TTL_S = int(os.environ.get("REPORT_JOB_TTL_S", "3600"))
REPORT_ASYNC_WORKERS = int(os.environ.get("REPORT_ASYNC_WORKERS", "4"))
_REPORT_ASYNC_POOL = ThreadPoolExecutor(max_workers=max(1, REPORT_ASYNC_WORKERS))
_INDEXNOW_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="indexnow")
_REPORT_JOB_LOCAL: Dict[str, Dict] = {}

REPORT_DNS_TTL_S = int(os.environ.get("REPORT_DNS_TTL_S", "180"))
REPORT_WHOIS_TTL_S = int(os.environ.get("REPORT_WHOIS_TTL_S", "900"))
REPORT_GEO_TTL_S = int(os.environ.get("REPORT_GEO_TTL_S", "1800"))
REPORT_REVERSE_TTL_S = int(os.environ.get("REPORT_REVERSE_TTL_S", "300"))
REPORT_FULL_TTL_S = int(os.environ.get("REPORT_FULL_TTL_S", "120"))
REPORT_MAX_BATCH = max(1, int(os.environ.get("REPORT_MAX_BATCH", "10")))

REPORT_RATE_LIMIT_PER_MIN = max(1, int(os.environ.get("REPORT_RATE_LIMIT_PER_MIN", "30")))
REPORT_RATE_LIMIT_ASN_LOW_PER_MIN = max(1, int(os.environ.get("REPORT_RATE_LIMIT_ASN_LOW_PER_MIN", "10")))
REPORT_RATE_LIMIT_ASN_HIGH_PER_MIN = max(1, int(os.environ.get("REPORT_RATE_LIMIT_ASN_HIGH_PER_MIN", "60")))
REPORT_ASN_HIGH_TRUST = {
    s.strip()
    for s in (os.environ.get("REPORT_ASN_HIGH_TRUST", "") or "").split(",")
    if s.strip()
}
REPORT_ASN_LOW_TRUST = {
    s.strip()
    for s in (os.environ.get("REPORT_ASN_LOW_TRUST", "") or "").split(",")
    if s.strip()
}

# Зоны, в которых разрешаем IDN-метки (берём из общего списка зон)
IDN_READY_TLDS = {
    t.strip().lstrip(".").lower()
    for t in app.config.get("TLD_LIST", [])
    if (t or "").strip()
}

RU_PRIORITY_TLDS = {
    "ru", "su", "рф", "рус", "москва", "дети", "tatar",
}

GLOBAL_PRIORITY_TLDS = {
    "com", "net", "org", "info", "biz", "name", "pro", "mobi", "tel", "asia", "me", "tv", "cc", "ws",
}

NEW_GTLD_PRIORITY_TLDS = {
    "io", "ai", "app", "dev", "site", "online", "store", "shop", "blog", "tech", "xyz", "top", "club", "space",
    "website", "fun", "live", "digital", "group", "company", "center", "solutions", "services", "agency", "media",
    "today", "world", "email", "expert", "guru", "news", "software", "cloud", "team", "systems", "network", "plus",
    "art", "icu", "life", "wiki", "zone", "run",
}


def _build_tld_groups(all_tlds: List[str], default_tlds: List[str]) -> Tuple[Dict[str, List[str]], Dict[str, str]]:
    ordered = [t for t in all_tlds if t]
    ru_group = [t for t in ordered if t in RU_PRIORITY_TLDS]
    global_group = [t for t in ordered if t in GLOBAL_PRIORITY_TLDS]
    new_group = [t for t in ordered if t in NEW_GTLD_PRIORITY_TLDS]

    # fallback: if list/env changed, keep groups useful
    if not ru_group:
        ru_group = [t for t in ordered if any(c in t for c in "абвгдежзийклмнопрстуфхцчшщъыьэюяё") or t in {"ru", "su"}]
    if not global_group:
        global_group = [t for t in ordered if len(t) <= 3][:20]
    if not new_group:
        new_group = [t for t in ordered if t not in set(ru_group + global_group)]

    groups = {
        "core": [t for t in ordered if t in set(default_tlds)],
        "ru": ru_group,
        "global": global_group,
        "new": new_group,
        "all": ordered,
    }

    group_map: Dict[str, str] = {}
    for t in ordered:
        if t in set(groups["ru"]):
            group_map[t] = "ru"
        elif t in set(groups["global"]):
            group_map[t] = "global"
        elif t in set(groups["new"]):
            group_map[t] = "new"
        else:
            group_map[t] = "all"
    return groups, group_map

# Redis
app.config.setdefault("REDIS_URL", os.getenv("REDIS_URL", "redis://127.0.0.1:6379/3"))
r = redis.from_url(app.config["REDIS_URL"], decode_responses=True)
HIST_NS = "dt:history"
HIST_ZSET = "dt:history:index"
HIST_LIMIT = 5000
SEO_DOMAIN_ZSET = "dt:seo:domains"
SEO_DOMAIN_META_NS = "dt:seo:domainmeta"
SITEMAP_DYNAMIC_DOMAIN_LIMIT = int(os.environ.get("SITEMAP_DYNAMIC_DOMAIN_LIMIT", "1000"))
SITEMAP_DYNAMIC_DOMAIN_MIN_HITS = int(os.environ.get("SITEMAP_DYNAMIC_DOMAIN_MIN_HITS", "2"))
SITEMAP_DYNAMIC_DOMAIN_TTL_S = int(os.environ.get("SITEMAP_DYNAMIC_DOMAIN_TTL_S", str(90 * 24 * 3600)))
SITEMAP_ZONE_LIMIT = int(os.environ.get("SITEMAP_ZONE_LIMIT", "60"))


def _redis_health() -> Dict[str, object]:
    try:
        ok = bool(r.ping())
        return {"ok": ok, "url": app.config.get("REDIS_URL", "")}
    except Exception as e:
        app.logger.warning("Redis health check failed: %s", e)
        return {"ok": False, "url": app.config.get("REDIS_URL", ""), "error": type(e).__name__}

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

    beget_banner_sources = [
        "https://cp.beget.com/promo_data/static/970x90-14.png",
        "https://cp.beget.com/promo_data/static/970x90-13.png",
        "https://cp.beget.com/promo_data/static/970x90-12.png",
        "https://cp.beget.com/promo_data/static/970x90-11.png",
        "https://cp.beget.com/promo_data/static/970x90-10.png",
        "https://cp.beget.com/promo_data/static/970x90-9.png",
        "https://cp.beget.com/promo_data/static/970x90-8.png",
        "https://cp.beget.com/promo_data/static/970x90-6.png",
        "https://cp.beget.com/promo_data/static/970x90-5.png",
        "https://cp.beget.com/promo_data/static/970x90-4.png",
        "https://cp.beget.com/promo_data/static/970x90-3.png",
        "https://cp.beget.com/promo_data/static/970x90-2.png",
        "https://cp.beget.com/promo_data/static/970x90-1.png",
        "https://cp.beget.com/promo_data/static/970x90.png",
    ]

    return {
        "get_locale": (lambda: str(babel_get_locale() or "ru")),
        "lang_url": _lang_url,
        "tr": _tr,
        "beget_banner_src": random.choice(beget_banner_sources),
        "hosting_offers": _hosting_offers,
        "hosting_offers_featured": (lambda: _hosting_offers(featured_only=True)),
        "hosting_setup": _hosting_setup_offer(),
        "hosting_vps_landing_url": HOSTING_VPS_LANDING_URL,
        "dns_suggests_hosting": _dns_suggests_hosting,
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
    try:
        data = r.get(key)
    except Exception:
        data = None
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
        return hid
    except Exception:
        app.logger.exception("History save failed")
        return ""

def load_history(kind: str, hid: str) -> Optional[Dict]:
    try:
        s = r.get(f"{HIST_NS}:{kind}:{hid}")
        if not s:
            return None
        return json.loads(s)
    except Exception:
        return None


def _canonical_site_root() -> str:
    explicit = (app.config.get("SITE_CANONICAL_ROOT") or "").strip().rstrip("/")
    if explicit:
        return explicit
    try:
        return request.url_root.rstrip("/")
    except RuntimeError:
        return "https://domaintools.site"


def _seo_lang_code() -> str:
    try:
        loc = str(babel_get_locale() or "ru")
    except Exception:
        loc = "ru"
    return "en" if loc.startswith("en") else "ru"


def _seo_display_domain(clean: str, ascii_domain: str) -> str:
    return _to_unicode(ascii_domain) or clean


def _seo_canonical_url() -> str:
    root = _canonical_site_root()
    lang = _seo_lang_code()
    try:
        path = request.path or "/"
    except RuntimeError:
        return f"{root}/?lang={lang}"

    q = (request.args.get("q") or request.args.get("query") or "").strip()
    if q:
        clean, ascii_domain = _sanitize_lookup_domain(q)
        if clean and ascii_domain:
            display = _seo_display_domain(clean, ascii_domain)
            if path == "/dns":
                return f"{root}{url_for('lookup_dns_domain', domain=display)}?lang={lang}"
            if path == "/whois":
                return f"{root}{url_for('lookup_whois_domain', domain=display)}?lang={lang}"
            if path in ("/report", "/check") and _is_indexable_domain_host(ascii_domain):
                return f"{root}{url_for('domain_check', domain=display)}?lang={lang}"
            if path in ("/geo", "/reverse") and _is_indexable_domain_host(ascii_domain):
                return f"{root}{url_for('domain_check', domain=display)}?lang={lang}"

    return f"{root}{path}?lang={lang}"


def _seo_noindex_auto() -> bool:
    try:
        path = request.path.rstrip("/") or "/"
    except RuntimeError:
        return False
    if path == "/history" or path.startswith("/history/"):
        return True
    if request.args.get("job"):
        return True
    q = (request.args.get("q") or request.args.get("query") or "").strip()
    if q and path in {"/dns", "/whois", "/geo", "/reverse", "/report", "/domains"}:
        return True
    return False


def _indexnow_urls_for_domain(host_ascii: str) -> List[str]:
    root = _canonical_site_root()
    display = _to_unicode(host_ascii) or host_ascii
    with app.app_context():
        with app.test_request_context(base_url=f"{root}/", path="/"):
            paths = [
                url_for("domain_check", domain=display),
                url_for("lookup_whois_domain", domain=display),
                url_for("lookup_dns_domain", domain=display),
            ]
    out: List[str] = []
    for path in paths:
        if not path:
            continue
        out.append(urljoin(f"{root}/", path.lstrip("/")))
    return list(dict.fromkeys(out))


def _submit_indexnow_urls(urls: List[str]) -> None:
    if not app.config.get("INDEXNOW_ENABLED"):
        return
    key = (app.config.get("INDEXNOW_KEY") or "").strip()
    if not key or not urls:
        return
    root = _canonical_site_root()
    host = urlparse(root).netloc
    if not host:
        return
    payload = {
        "host": host,
        "key": key,
        "keyLocation": f"{root}/{key}.txt",
        "urlList": list(dict.fromkeys(urls))[:10000],
    }
    headers = {"Content-Type": "application/json; charset=utf-8"}
    for endpoint in (
        "https://api.indexnow.org/indexnow",
        "https://www.bing.com/indexnow",
        "https://yandex.com/indexnow",
    ):
        try:
            resp = requests.post(endpoint, json=payload, headers=headers, timeout=10)
            app.logger.info(
                "IndexNow %s status=%s urls=%d",
                endpoint,
                resp.status_code,
                len(payload["urlList"]),
            )
        except Exception:
            app.logger.debug("IndexNow submit failed for %s", endpoint, exc_info=True)


def _submit_indexnow_urls_async(urls: List[str]) -> None:
    with app.app_context():
        _submit_indexnow_urls(urls)


def _queue_indexnow_for_domain(host_ascii: str) -> None:
    if not app.config.get("INDEXNOW_ENABLED"):
        return
    debounce_s = max(300, int(app.config.get("INDEXNOW_DEBOUNCE_S", 1800)))
    debounce_key = f"dt:indexnow:sent:{host_ascii}"
    try:
        if not r.set(debounce_key, "1", nx=True, ex=debounce_s):
            return
    except Exception:
        app.logger.debug("IndexNow debounce check failed for %s", host_ascii)
    urls = _indexnow_urls_for_domain(host_ascii)
    if not urls:
        return
    try:
        _INDEXNOW_POOL.submit(_submit_indexnow_urls_async, urls)
    except Exception:
        app.logger.debug("IndexNow queue failed for %s", host_ascii, exc_info=True)


def _is_indexable_domain_host(host_ascii: str) -> bool:
    host = (host_ascii or "").strip().lower()
    if not host or "." not in host:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except Exception:
        return True


def _track_domain_for_seo(domain: str) -> None:
    """Track validated domains for dynamic sitemap entries and IndexNow pings."""
    q = (domain or "").strip().lower()
    if not q:
        return
    host_ascii, err = _normalize_domain_query(q)
    if err or not host_ascii or not _is_indexable_domain_host(host_ascii):
        return
    now = int(time.time())
    meta_key = f"{SEO_DOMAIN_META_NS}:{host_ascii}"
    try:
        p = r.pipeline()
        p.zincrby(SEO_DOMAIN_ZSET, 1, host_ascii)
        p.hset(meta_key, mapping={"last_seen": now})
        p.expire(meta_key, max(3600, SITEMAP_DYNAMIC_DOMAIN_TTL_S))
        p.execute()
    except Exception:
        app.logger.debug("SEO domain tracking failed for %s", host_ascii)
    _queue_indexnow_for_domain(host_ascii)


def _report_job_key(job_id: str) -> str:
    return f"dt:report:job:{job_id}"


def _job_storage_allows_local_fallback() -> bool:
    return bool(app.config.get("TESTING") or app.config.get("JOB_STORAGE_ALLOW_LOCAL_FALLBACK"))


def _save_job_payload(local_store: Dict[str, Dict], redis_key: str, job_id: str, payload: Dict, ttl_s: int, kind: str) -> bool:
    payload = dict(payload or {})
    payload["id"] = job_id
    payload["updated_ts"] = int(time.time())
    try:
        r.setex(redis_key, max(60, int(ttl_s)), json.dumps(payload, ensure_ascii=False))
    except Exception:
        app.logger.exception("%s job storage Redis write failed: job_id=%s", kind, job_id)
        if not _job_storage_allows_local_fallback():
            return False
        app.logger.warning("%s job storage using local in-process fallback: job_id=%s", kind, job_id)
    local_store[job_id] = payload
    return True


def _load_job_payload(local_store: Dict[str, Dict], redis_key: str, job_id: str, kind: str) -> Optional[Dict]:
    try:
        raw = r.get(redis_key)
        if raw:
            return json.loads(raw)
    except Exception:
        app.logger.exception("%s job storage Redis read failed: job_id=%s", kind, job_id)
    if _job_storage_allows_local_fallback():
        return local_store.get(job_id)
    return None


def _save_report_job(job_id: str, payload: Dict, ttl_s: int = REPORT_JOB_TTL_S) -> bool:
    return _save_job_payload(_REPORT_JOB_LOCAL, _report_job_key(job_id), job_id, payload, ttl_s, "report")


def _load_report_job(job_id: str) -> Optional[Dict]:
    return _load_job_payload(_REPORT_JOB_LOCAL, _report_job_key(job_id), job_id, "report")


def _touch_report_job(job_id: str, **fields) -> bool:
    job = _load_report_job(job_id) or {}
    job.update(fields)
    return _save_report_job(job_id, job)


def _is_valid_report_job_id(job_id: str) -> bool:
    txt = (job_id or "").strip()
    return bool(re.fullmatch(r"[a-f0-9]{32}", txt))


_ENDPOINT_RATE_BUCKETS: Dict[str, Dict[str, List[float]]] = {}


def _ip_rate_limited(bucket: str, ip: str, limit_per_min: int, window_s: int = 60) -> bool:
    """Return True when the IP exceeded the per-bucket limit (Redis + in-memory fallback)."""
    if not ip:
        return False
    limit = max(1, int(limit_per_min))
    win = max(1, int(window_s))
    redis_key = f"rl:{bucket}:{ip}"
    try:
        with r.pipeline() as pipe:
            pipe.incr(redis_key)
            pipe.expire(redis_key, win, nx=True)
            vals = pipe.execute()
        return int(vals[0] or 0) > limit
    except Exception:
        now = time.time()
        per_bucket = _ENDPOINT_RATE_BUCKETS.setdefault(bucket, {})
        timestamps = per_bucket.get(ip, [])
        fresh = [t for t in timestamps if now - t < win]
        limited = len(fresh) >= limit
        fresh.append(now)
        per_bucket[ip] = fresh[-200:]
        return limited


def _endpoint_ip_rate_limited(endpoint: str, ip: str, limit_per_min: int, window_s: int = 60) -> bool:
    return _ip_rate_limited(endpoint, ip, limit_per_min, window_s)


def _tool_rate_limited(tool: str) -> Optional[str]:
    """Return a user-facing error when a web tool endpoint is rate-limited."""
    limits = {
        "dns": ("TOOL_RATE_LIMIT_PER_MIN", 20),
        "whois": ("TOOL_RATE_LIMIT_PER_MIN", 20),
        "geo": ("TOOL_RATE_LIMIT_PER_MIN", 20),
        "reverse": ("TOOL_RATE_LIMIT_PER_MIN", 20),
        "domains": ("DOMAINS_RATE_LIMIT_PER_MIN", 10),
    }
    cfg_key, default = limits.get(tool, ("TOOL_RATE_LIMIT_PER_MIN", 20))
    limit = int(app.config.get(cfg_key, default))
    if _endpoint_ip_rate_limited(tool, _client_ip(), limit):
        return _("Too many requests. Please try again later.")
    return None


def _ip_asn(ip: str) -> str:
    if not ip:
        return ""
    cache_key = f"cache:asn:{ip}"
    try:
        cached = r.get(cache_key)
        if cached:
            return str(cached or "")
    except Exception:
        pass
    try:
        who = IPWhois(ip).lookup_rdap(depth=1)
        asn = str(who.get("asn") or "")
    except Exception:
        asn = ""
    try:
        if asn:
            r.setex(cache_key, 86400, asn)
    except Exception:
        pass
    return asn


def _report_limit_for_ip(ip: str) -> int:
    asn = _ip_asn(ip)
    if asn and asn in REPORT_ASN_LOW_TRUST:
        return REPORT_RATE_LIMIT_ASN_LOW_PER_MIN
    if asn and asn in REPORT_ASN_HIGH_TRUST:
        return REPORT_RATE_LIMIT_ASN_HIGH_PER_MIN
    return REPORT_RATE_LIMIT_PER_MIN


def _security_job_key(job_id: str) -> str:
    return f"dt:security:job:{job_id}"


def _save_security_job(job_id: str, payload: Dict, ttl_s: int = SECURITY_JOB_TTL_S) -> bool:
    return _save_job_payload(_SECURITY_JOB_LOCAL, _security_job_key(job_id), job_id, payload, ttl_s, "security")


def _is_valid_security_job_id(job_id: str) -> bool:
    txt = (job_id or '').strip()
    return bool(re.fullmatch(r'[a-f0-9]{32}', txt))


def _load_security_job(job_id: str) -> Optional[Dict]:
    return _load_job_payload(_SECURITY_JOB_LOCAL, _security_job_key(job_id), job_id, "security")


def _normalize_security_hints(hints: List[Dict[str, str]]) -> List[Dict[str, str]]:
    severity_map = {"low": "low", "medium": "medium", "high": "high", "critical": "high"}
    out: List[Dict[str, str]] = []
    for h in hints or []:
        sev = severity_map.get(str(h.get("severity") or h.get("level") or "").lower(), "medium")
        item = dict(h)
        item["severity"] = sev
        out.append(item)
    return out


def _security_metric_inc(endpoint: str, event: str) -> None:
    endpoint = re.sub(r"[^a-z0-9_:\-]", "", (endpoint or "security").lower())[:64] or "security"
    event = "blocked" if event == "blocked" else "allowed"
    now_utc = datetime.now(timezone.utc)
    minute = now_utc.strftime("%Y%m%d%H%M")
    day = now_utc.strftime("%Y%m%d")
    key_min = f"dt:metrics:security_rate:min:{minute}"
    key_day = f"dt:metrics:security_rate:day:{day}"
    field = f"{endpoint}:{event}"
    try:
        with r.pipeline() as pipe:
            pipe.hincrby(key_min, field, 1)
            pipe.expire(key_min, 86400 * 2)
            pipe.hincrby(key_day, field, 1)
            pipe.expire(key_day, 86400 * 14)
            pipe.execute()
    except Exception:
        pass

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


def _affiliate_buy_base() -> str:
    locale = str(babel_get_locale() or "ru")
    if locale.startswith("en"):
        return (
            app.config.get("AFFILIATE_BUY_BASE_EN")
            or app.config.get("AFFILIATE_BUY_BASE")
            or ""
        )
    return (
        app.config.get("AFFILIATE_BUY_BASE_RU")
        or app.config.get("AFFILIATE_BUY_BASE")
        or ""
    )


def _affiliate_buy_url(domain: str) -> str:
    d = (domain or "").strip().lower().rstrip(".")
    base = _affiliate_buy_base()
    if not d or not base:
        return ""
    try:
        return base.format(domain=d)
    except Exception:
        return ""


def _is_ip_host(value: str) -> bool:
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except Exception:
        return False


def _extract_affiliate_domain(query: str, kind: str) -> Optional[str]:
    q = (query or "").strip()
    if not q:
        return None

    candidate = q
    if kind == "security":
        if q.startswith("ports:"):
            candidate = q.split(":", 2)[1] if q.count(":") >= 1 else ""
        elif q.startswith("wp:"):
            candidate = q.split(":", 1)[1] if ":" in q else ""
        else:
            return None
    elif kind == "report":
        parts = [p.strip() for p in re.split(r"[\s,;]+", q) if p.strip()]
        candidate = parts[0] if parts else ""

    host_ascii, err = _normalize_domain_query(candidate)
    if err or not host_ascii or _is_ip_host(host_ascii):
        return None
    return host_ascii


def _affiliate_actions_for_domain(domain: str) -> Dict[str, str]:
    d = (domain or "").strip().lower().rstrip(".")
    if not d:
        return {}
    buy_url = _affiliate_buy_url(d)
    if not buy_url:
        return {}
    label = d.split(".", 1)[0] if "." in d else d
    return {
        "affiliate_domain": d,
        "affiliate_buy_url": buy_url,
        "affiliate_domain_search_url": url_for("domain_search", query=label),
    }


def _whois_result_indicates_taken(data: Optional[dict]) -> bool:
    if not isinstance(data, dict) or not data:
        return False
    if data.get("registrar") or data.get("creation_date") or data.get("expiration_date"):
        return True
    ns = data.get("name_servers")
    if isinstance(ns, (list, tuple)) and len(ns) > 0:
        return True
    if isinstance(ns, str) and ns.strip():
        return True
    status = data.get("status")
    if isinstance(status, (list, tuple)) and len(status) > 0:
        return True
    if isinstance(status, str) and status.strip():
        return True
    return False


def _dns_records_indicate_taken(records: Optional[dict]) -> bool:
    if not isinstance(records, dict) or not records:
        return False
    for rtype in ("NS", "A", "AAAA"):
        vals = records.get(rtype)
        if vals:
            return True
    return False


def _domain_label_from_fqdn(domain: str) -> str:
    d = (domain or "").strip().lower().rstrip(".")
    return d.split(".", 1)[0] if "." in d else d


def _build_domain_availability(domain: str, *, status: str, source: str = "") -> Dict[str, object]:
    d = (domain or "").strip().lower().rstrip(".")
    display = _to_unicode(d) if d else d
    payload: Dict[str, object] = {
        "status": status,
        "domain": d,
        "display_domain": display or d,
        "source": source,
        "zones_search_url": url_for("domain_search", query=_domain_label_from_fqdn(d)),
    }
    payload.update(_affiliate_actions_for_domain(d))
    return payload


def _evaluate_domain_availability(
    domain: str,
    *,
    whois_data: Optional[dict] = None,
    dns_records: Optional[dict] = None,
) -> Optional[Dict[str, object]]:
    host, err = _normalize_domain_query(domain)
    if err or not host or _is_ip_host(host):
        return None

    if _whois_result_indicates_taken(whois_data):
        return _build_domain_availability(host, status="taken", source="whois")

    if _dns_records_indicate_taken(dns_records):
        return _build_domain_availability(host, status="taken", source="dns")

    if whois_data is not None or dns_records is not None:
        if _is_available_via_whois(host):
            source = "whois" if whois_data is not None else "dns+whois"
            return _build_domain_availability(host, status="available", source=source)
        if whois_data is not None or _dns_records_indicate_taken(dns_records) is False and dns_records is not None:
            return _build_domain_availability(host, status="taken", source="whois" if whois_data is not None else "dns")

    return None


def _domain_availability_from_search_items(items: List[Dict]) -> Optional[Dict[str, object]]:
    available = [it for it in (items or []) if it.get("available") and it.get("fqdn")]
    if not available:
        return None
    first = available[0]
    payload = _build_domain_availability(str(first["fqdn"]), status="available", source="domains")
    payload["available_count"] = len(available)
    payload["available_domains"] = [str(it.get("fqdn")) for it in available[:8]]
    payload["available_domain_links"] = []
    for it in available[:8]:
        fqdn = str(it.get("fqdn"))
        payload["available_domain_links"].append({
            "fqdn": fqdn,
            "display": _to_unicode(fqdn),
            "buy_url": _affiliate_buy_url(fqdn),
        })
    return payload


# ---------- Hosting / VPS referrals (vps.krivoshein.site) ----------
HOSTING_VPS_LANDING_URL = os.environ.get("HOSTING_VPS_LANDING_URL", "https://vps.krivoshein.site/").strip()
HOSTING_SETUP_URL = os.environ.get("HOSTING_SETUP_URL", "https://krivoshein.site/contacts/").strip()
HOSTING_SETUP_PRICE_RUB = int(os.environ.get("HOSTING_SETUP_PRICE_RUB", "10000"))

_HOSTING_OFFERS_RAW: List[Dict[str, object]] = [
    {
        "id": "firstvds",
        "name": "FirstVDS",
        "price_rub": 249,
        "url": "https://krivoshein.site/firstvds",
        "icon": "fa-server",
        "badge": "recommended",
        "accent": "#10b981",
        "desc_ru": "Самый выгодный вариант: SSD, удобная панель. Отлично для ботов и WordPress.",
        "desc_en": "Best value: SSD, easy panel. Great for bots and WordPress.",
        "tags_ru": ["Боты", "WordPress"],
        "tags_en": ["Bots", "WordPress"],
    },
    {
        "id": "sweb",
        "name": "SpaceWeb",
        "price_rub": 277,
        "url": "https://krivoshein.site/sweb",
        "icon": "fa-shield-halved",
        "badge": "ddos",
        "accent": "#6366f1",
        "desc_ru": "Российский провайдер с защитой от DDoS и root-доступом.",
        "desc_en": "Russian provider with DDoS protection and root access.",
        "tags_ru": ["DDoS", "RU"],
        "tags_en": ["DDoS", "RU"],
    },
    {
        "id": "beget",
        "name": "Beget",
        "price_rub": 329,
        "url": "https://krivoshein.site/beget",
        "icon": "fa-cloud",
        "badge": "ecosystem",
        "accent": "#0ea5e9",
        "desc_ru": "Домен и хостинг в одном месте: удобная панель и поддержка.",
        "desc_en": "Domain and hosting in one place: easy panel and support.",
        "tags_ru": ["Домен + VPS"],
        "tags_en": ["Domain + VPS"],
    },
    {
        "id": "clo",
        "name": "CLO",
        "price_rub": 500,
        "url": "https://krivoshein.site/clo",
        "icon": "fa-gauge-high",
        "badge": None,
        "accent": "#8b5cf6",
        "desc_ru": "Гибкое облако с почасовой оплатой — удобно при плавающей нагрузке.",
        "desc_en": "Flexible cloud with hourly billing for variable workloads.",
        "tags_ru": ["Облако"],
        "tags_en": ["Cloud"],
    },
    {
        "id": "yandexcloud",
        "name": "Yandex Cloud",
        "price_rub": 990,
        "url": "https://krivoshein.site/yandexcloud",
        "icon": "fa-database",
        "badge": None,
        "accent": "#f59e0b",
        "desc_ru": "Мощное облако с интеграцией в экосистему Яндекса.",
        "desc_en": "Powerful cloud integrated with the Yandex ecosystem.",
        "tags_ru": ["Enterprise"],
        "tags_en": ["Enterprise"],
    },
]

HOSTING_FEATURED_IDS = ("firstvds", "beget", "sweb")


def _hosting_locale_en() -> bool:
    try:
        return str(babel_get_locale() or "ru").startswith("en")
    except RuntimeError:
        return False


def _localize_hosting_offer(raw: Dict[str, object]) -> Dict[str, object]:
    en = _hosting_locale_en()
    badge = raw.get("badge")
    badge_labels = {
        "recommended": ("Рекомендую", "Recommended"),
        "ddos": ("DDoS-защита", "DDoS shield"),
        "ecosystem": ("Домен + VPS", "Domain + VPS"),
    }
    badge_text = ""
    if badge and badge in badge_labels:
        badge_text = badge_labels[badge][1 if en else 0]
    return {
        "id": raw["id"],
        "name": raw["name"],
        "price_rub": raw["price_rub"],
        "url": raw["url"],
        "icon": raw.get("icon") or "fa-server",
        "badge": badge,
        "badge_text": badge_text,
        "accent": raw.get("accent") or "#6366f1",
        "desc": raw["desc_en"] if en else raw["desc_ru"],
        "tags": list(raw["tags_en"] if en else raw["tags_ru"]),
    }


def _hosting_offers(*, featured_only: bool = False) -> List[Dict[str, object]]:
    rows = [_localize_hosting_offer(o) for o in _HOSTING_OFFERS_RAW]
    if featured_only:
        featured = set(HOSTING_FEATURED_IDS)
        rows = [o for o in rows if o["id"] in featured]
        order = {k: i for i, k in enumerate(HOSTING_FEATURED_IDS)}
        rows.sort(key=lambda x: order.get(x["id"], 99))
    return rows


def _hosting_setup_offer() -> Dict[str, object]:
    en = _hosting_locale_en()
    return {
        "price_rub": HOSTING_SETUP_PRICE_RUB,
        "url": HOSTING_SETUP_URL,
        "vps_landing_url": HOSTING_VPS_LANDING_URL,
        "title": ("Настройка VPS под ключ", "Turnkey VPS setup")[int(en)],
        "lead": (
            "ОС, веб-сервер, DNS, Docker, безопасность — и 30 дней поддержки.",
            "OS, web server, DNS, Docker, security — plus 30 days of support.",
        )[int(en)],
    }


def _dns_suggests_hosting(
    records: Optional[dict],
    domain_availability: Optional[Dict[str, object]],
) -> bool:
    if not domain_availability or domain_availability.get("status") != "taken":
        return False
    if not records:
        return True
    for rtype in ("A", "AAAA", "MX"):
        vals = records.get(rtype)
        if vals:
            return False
    return True


WHOIS_EXPIRY_NOTICE_DAYS = 90
WHOIS_EXPIRY_WARNING_DAYS = 30
WHOIS_EXPIRY_CRITICAL_DAYS = 7
WHOIS_EXPIRY_RECENTLY_EXPIRED_DAYS = 30


def _parse_whois_expiration_date(value) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        for item in value:
            parsed = _parse_whois_expiration_date(item)
            if parsed:
                return parsed
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)
    raw = str(value).strip()
    if not raw:
        return None
    for fmt in (
        "%Y-%m-%d",
        "%Y.%m.%d",
        "%d.%m.%Y",
        "%d-%b-%Y",
        "%d.%b.%Y",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%a %b %d %Y",
        "%Y/%m/%d",
    ):
        try:
            dt = datetime.strptime(raw, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        dt = date_parser.parse(raw, dayfirst=True, fuzzy=False)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def _whois_expiration_raw(whois_data: Optional[dict]) -> Optional[object]:
    if not isinstance(whois_data, dict):
        return None
    for key in ("expiration_date", "paid_till", "expires", "expiry_date", "registry_expiry_date"):
        val = whois_data.get(key)
        if val in (None, "", []):
            continue
        if isinstance(val, (list, tuple)):
            val = next((x for x in val if x not in (None, "", [])), None)
        if val not in (None, "", []):
            return val
    return None


def _build_whois_expiry_urgency(
    whois_data: Optional[dict],
    *,
    domain: str = "",
) -> Optional[Dict[str, object]]:
    raw_exp = _whois_expiration_raw(whois_data)
    if raw_exp is None:
        return None
    exp_dt = _parse_whois_expiration_date(raw_exp)
    if not exp_dt:
        return None

    today = datetime.now(timezone.utc).date()
    exp_date = exp_dt.date()
    days_left = (exp_date - today).days
    if days_left > WHOIS_EXPIRY_NOTICE_DAYS:
        return None
    if days_left < -WHOIS_EXPIRY_RECENTLY_EXPIRED_DAYS:
        return None

    if days_left < 0:
        urgency = "expired"
    elif days_left <= WHOIS_EXPIRY_CRITICAL_DAYS:
        urgency = "critical"
    elif days_left <= WHOIS_EXPIRY_WARNING_DAYS:
        urgency = "warning"
    else:
        urgency = "notice"

    host = (
        (domain or (whois_data or {}).get("domain_name") or (whois_data or {}).get("domain_unicode") or "")
        .strip()
        .lower()
        .rstrip(".")
    )
    display = _to_unicode(host) if host else ""
    expiration_display = exp_date.strftime("%d.%m.%Y")
    if isinstance(raw_exp, str) and raw_exp.strip():
        expiration_display = raw_exp.strip()

    payload: Dict[str, object] = {
        "domain": host,
        "display_domain": display or host,
        "expiration_date": raw_exp,
        "expiration_display": expiration_display,
        "days_left": days_left,
        "days_abs": abs(days_left),
        "urgency": urgency,
        "zones_search_url": url_for("domain_search", query=_domain_label_from_fqdn(host)) if host else url_for("domains"),
    }
    if host:
        payload.update(_affiliate_actions_for_domain(host))
    return payload


def _landing_whois_expiry(domain_ascii: str) -> Optional[Dict[str, object]]:
    host = (domain_ascii or "").strip().lower().rstrip(".")
    if not host or _is_ip_host(host) or "." not in host:
        return None

    def _compute() -> Optional[Dict[str, object]]:
        whois_part = _report_whois_summary(host)
        return _build_whois_expiry_urgency(whois_part, domain=host)

    try:
        return cache_json(f"cache:whois-expiry:{host}", 3600, _compute)
    except Exception:
        return _compute()


_DOMAIN_IDEA_PREFIXES = ("get", "my", "go", "try", "the", "we", "hi")
_DOMAIN_IDEA_SUFFIXES = (
    "shop", "store", "app", "hub", "online", "pro", "lab", "group", "team",
    "studio", "box", "zone", "land", "place", "market",
)
_DOMAIN_IDEA_CONNECTORS = ("", "-")


def _slugify_domain_label(value: str) -> str:
    value = (value or "").strip().lower()
    value = re.sub(r"[\s_]+", "-", value)
    value = "".join(ch for ch in value if ch.isalnum() or ch == "-")
    value = re.sub(r"-{2,}", "-", value).strip("-")
    return value


def _generate_domain_name_ideas(seed: str, limit: int = 24) -> List[str]:
    raw = (seed or "").strip()
    if not raw:
        return []

    tokens = re.findall(r"[\w\u0400-\u04FF]+", raw.lower())
    if not tokens:
        return []

    bases: List[str] = []
    joined = _slugify_domain_label("".join(tokens))
    hyphenated = _slugify_domain_label("-".join(tokens))
    if joined:
        bases.append(joined)
    if hyphenated and hyphenated != joined:
        bases.append(hyphenated)
    if tokens[0]:
        bases.append(_slugify_domain_label(tokens[0]))
    if len(tokens) > 1:
        bases.append(_slugify_domain_label(tokens[0] + tokens[1]))

    if any("а" <= ch <= "я" or ch == "ё" for ch in raw.lower()):
        translit = _slugify_domain_label(_translit_ru("".join(tokens)))
        if translit:
            bases.append(translit)
        translit_hyphen = _slugify_domain_label(_translit_ru("-".join(tokens)))
        if translit_hyphen and translit_hyphen not in bases:
            bases.append(translit_hyphen)

    ideas: List[str] = []
    seen = set()

    def add(candidate: str) -> None:
        if len(ideas) >= limit:
            return
        try:
            normalized = _normalize_label(candidate)
        except Exception:
            return
        if not normalized or normalized in seen:
            return
        seen.add(normalized)
        ideas.append(normalized)

    for base in bases:
        add(base)
        if len(ideas) >= limit:
            break
        for prefix in _DOMAIN_IDEA_PREFIXES:
            for conn in _DOMAIN_IDEA_CONNECTORS:
                add(f"{prefix}{conn}{base}")
                if len(ideas) >= limit:
                    break
            if len(ideas) >= limit:
                break
        for suffix in _DOMAIN_IDEA_SUFFIXES:
            for conn in _DOMAIN_IDEA_CONNECTORS:
                add(f"{base}{conn}{suffix}")
                if len(ideas) >= limit:
                    break
            if len(ideas) >= limit:
                break

    return ideas[:limit]


def _to_unicode(domain: str) -> str:
    try:
        return idna.decode(domain)
    except Exception:
        return domain

# --- WHOIS field extraction helpers -------------------------------------------
_WHOIS_OBJECT_FIELDS = (
    "domain_name",
    "registrar",
    "whois_server",
    "creation_date",
    "expiration_date",
    "updated_date",
    "name_servers",
    "status",
    "org",
    "name",
    "emails",
    "country",
)


def _whois_object_to_dict(w) -> Dict[str, object]:
    """python-whois stores parsed values as properties, not always in __dict__."""
    out: Dict[str, object] = {}
    if w is None:
        return out
    for key in _WHOIS_OBJECT_FIELDS:
        try:
            val = getattr(w, key, None)
        except Exception:
            val = None
        if val not in (None, "", [], {}, ()):
            out[key] = val
    for key, val in getattr(w, "__dict__", {}).items():
        if key.startswith("_"):
            continue
        if val and key not in out:
            out[key] = val
    return out


def _format_whois_display_value(val) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, datetime):
        if val.tzinfo is None:
            val = val.replace(tzinfo=timezone.utc)
        return val.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if isinstance(val, date):
        return val.strftime("%Y-%m-%d")
    if isinstance(val, (list, tuple)):
        for item in val:
            formatted = _format_whois_display_value(item)
            if formatted:
                return formatted
        return None
    text = str(val).strip()
    return text or None


def _merge_whois_dict(target: Dict[str, object], source: Optional[Dict[str, object]]) -> Dict[str, object]:
    if not source:
        return target
    for key, val in source.items():
        if key.startswith("_"):
            continue
        if val in (None, "", [], {}, ()):
            continue
        if not target.get(key):
            target[key] = val
    return target


def _extract_whois_core_fields_from_text(txt: str) -> Dict[str, object]:
    out: Dict[str, object] = {}
    if not txt:
        return out
    patterns = {
        "registrar": (
            r"(?im)^\s*registrar\s*:\s*(.+?)\s*$",
        ),
        "creation_date": (
            r"(?im)^\s*created\s*:\s*(.+?)\s*$",
            r"(?im)^\s*creation date\s*:\s*(.+?)\s*$",
        ),
        "expiration_date": (
            r"(?im)^\s*paid-till\s*:\s*(.+?)\s*$",
            r"(?im)^\s*registry expiry date\s*:\s*(.+?)\s*$",
            r"(?im)^\s*registrar registration expiration date\s*:\s*(.+?)\s*$",
            r"(?im)^\s*expir(?:y|ation) date\s*:\s*(.+?)\s*$",
        ),
    }
    for field, field_patterns in patterns.items():
        for pat in field_patterns:
            m = re.search(pat, txt)
            if m:
                out[field] = m.group(1).strip()
                break
    return out


def _finalize_whois_summary(data: Dict[str, object], host_ascii: str) -> Dict[str, object]:
    alias_map = {
        "registrar": ("registrar", "sponsoring_registrar", "registrar_name"),
        "creation_date": ("creation_date", "created", "created_date", "registered"),
        "expiration_date": (
            "expiration_date",
            "paid_till",
            "paid-till",
            "expires",
            "expiry_date",
            "registry_expiry_date",
        ),
    }
    for target, aliases in alias_map.items():
        if data.get(target):
            continue
        for alias in aliases:
            val = data.get(alias)
            if val:
                data[target] = val
                break

    for field in ("registrar", "creation_date", "expiration_date"):
        formatted = _format_whois_display_value(data.get(field))
        if formatted:
            data[field] = formatted

    data["domain_name"] = host_ascii
    du = _to_unicode(host_ascii)
    if du and du != host_ascii:
        data["domain_unicode"] = du
    return data


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
    return {
        "country_flag": country_flag,
        "site_root": _canonical_site_root(),
        "seo_canonical_url": _seo_canonical_url(),
        "seo_noindex_auto": _seo_noindex_auto(),
    }

# регистрируем фильтр *явно* (поверх декораторов/блюпринтов)
app.jinja_env.filters['prettyjson'] = prettyjson_filter
app.jinja_env.filters['json_rows'] = json_rows_filter
app.jinja_env.filters['affiliate_buy_url'] = _affiliate_buy_url
app.jinja_env.filters['domain_label'] = _domain_label_from_fqdn
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
    recaptcha_ready, recaptcha_setup_error = _recaptcha_setup_status()
    redis_health = _redis_health()
    security_metrics_minute = {}
    try:
        minute = datetime.now(timezone.utc).strftime('%Y%m%d%H%M')
        security_metrics_minute = r.hgetall(f"dt:metrics:security_rate:min:{minute}") or {}
    except Exception:
        app.logger.warning("Security metrics read failed", exc_info=True)
    return jsonify(
        status="ok" if redis_health.get("ok") else "degraded",
        redis=redis_health,
        job_storage={
            "redis_required": not _job_storage_allows_local_fallback(),
            "local_fallback_enabled": _job_storage_allows_local_fallback(),
        },
        security={
            "recaptcha_enabled": bool(app.config.get("SECURITY_RECAPTCHA_ENABLED")),
            "recaptcha_provider": (app.config.get("SECURITY_RECAPTCHA_PROVIDER") or "standard"),
            "recaptcha_ready": recaptcha_ready,
            "recaptcha_setup_error": recaptcha_setup_error,
            "rate_limit_current_minute": security_metrics_minute,
        },
    ), 200

@app.get("/apple-touch-icon.png")
def apple_touch_icon():
    return send_from_directory(
        os.path.join(app.root_path, "static"),
        "apple-touch-icon.png",
        mimetype="image/png",
    )


@app.get("/favicon.ico")
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, "static"),
        "favicon.ico",
        mimetype="image/x-icon",
    )


@app.post("/track/buy-click")
def track_buy_click():
    payload = request.get_json(silent=True) or {}
    tld = re.sub(r"[^a-zа-яё0-9-]", "", str(payload.get("tld") or "").strip().lower())[:32]
    locale = str(payload.get("locale") or "").strip().lower()[:8]
    if locale not in {"ru", "en"}:
        locale = "other"
    if not tld:
        return jsonify(ok=False, error="bad_tld"), 400

    day_key = datetime.now(timezone.utc).strftime("%Y%m%d")
    redis_key = f"dt:analytics:buy_clicks:{day_key}:{locale}"
    try:
        with r.pipeline() as pipe:
            pipe.hincrby(redis_key, tld, 1)
            pipe.expire(redis_key, 86400 * 45)
            pipe.execute()
    except Exception:
        app.logger.warning("Buy click analytics write failed", exc_info=True)

    return jsonify(ok=True), 200


@app.post("/track/ref-click")
def track_ref_click():
    payload = request.get_json(silent=True) or {}
    ref_type = re.sub(r"[^a-z0-9_-]", "", str(payload.get("type") or "").strip().lower())[:24]
    ref_id = re.sub(r"[^a-z0-9_-]", "", str(payload.get("id") or "").strip().lower())[:32]
    placement = re.sub(r"[^a-z0-9_-]", "", str(payload.get("placement") or "").strip().lower())[:32]
    locale = str(payload.get("locale") or "").strip().lower()[:8]
    if locale not in {"ru", "en"}:
        locale = "other"
    if ref_type not in {"hosting", "setup", "vps_landing"} or not ref_id:
        return jsonify(ok=False, error="bad_ref"), 400

    day_key = datetime.now(timezone.utc).strftime("%Y%m%d")
    field = f"{ref_type}:{ref_id}"
    if placement:
        field = f"{field}:{placement}"
    redis_key = f"dt:analytics:ref_clicks:{day_key}:{locale}"
    try:
        with r.pipeline() as pipe:
            pipe.hincrby(redis_key, field, 1)
            pipe.expire(redis_key, 86400 * 45)
            pipe.execute()
    except Exception:
        app.logger.warning("Ref click analytics write failed", exc_info=True)

    return jsonify(ok=True), 200

@app.get("/llms.txt")
def llms_txt():
    path = os.path.join(app.root_path, "static", "llms.txt")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            body = fh.read()
    except OSError:
        abort(404)
    return Response(body, mimetype="text/plain; charset=utf-8")


@app.get("/robots.txt")
def robots():
    lines = [
        "User-agent: *",
        "Allow: /",
        "Allow: /llms.txt",
        "Disallow: /history",
        "Disallow: /history/",
        "Disallow: /export/",
        "Disallow: /track/",
        "Disallow: /api/v1/",
        "Disallow: /health",
        "Disallow: /security/metrics",
        "",
        f"Sitemap: {url_for('sitemap', _external=True)}",
        "",
    ]
    idx_key = (app.config.get("INDEXNOW_KEY") or "").strip()
    if idx_key and app.config.get("INDEXNOW_ENABLED"):
        root = _canonical_site_root()
        lines.insert(-1, f"# IndexNow key: {root}/{idx_key}.txt")
    return Response("\n".join(lines), mimetype="text/plain")

@app.get("/sitemap.xml")
def sitemap():
    static_pages = [
        (url_for("index"), "1.0", "daily"),
        (url_for("domain_search"), "0.9", "daily"),
        (url_for("hosting_landing"), "0.88", "weekly"),
        (url_for("domain_report"), "0.85", "weekly"),
        (url_for("domain_check_query"), "0.9", "daily"),
        (url_for("dns_lookup"), "0.85", "weekly"),
        (url_for("whois_lookup"), "0.85", "weekly"),
        (url_for("geo_lookup"), "0.8", "weekly"),
        (url_for("reverse_lookup"), "0.8", "weekly"),
        (url_for("site_checker.site_checker"), "0.8", "weekly"),
        (url_for("security_tools"), "0.7", "monthly"),
        (url_for("llms_txt"), "0.5", "monthly"),
    ]

    dynamic_domain_entries: List[Tuple[str, str]] = []
    zone_paths: List[str] = []
    allowed_zones = {
        t.strip().lstrip(".").lower()
        for t in app.config.get("TLD_LIST", [])
        if (t or "").strip()
    }
    for tld in list(allowed_zones)[:max(1, SITEMAP_ZONE_LIMIT)]:
        zone_paths.append(url_for("zone_landing", tld=tld))
    try:
        top_domains = r.zrevrange(SEO_DOMAIN_ZSET, 0, max(0, SITEMAP_DYNAMIC_DOMAIN_LIMIT - 1), withscores=True)
        now = int(time.time())
        for d, score in top_domains:
            try:
                if float(score) < float(SITEMAP_DYNAMIC_DOMAIN_MIN_HITS):
                    continue
            except Exception:
                continue
            meta_key = f"{SEO_DOMAIN_META_NS}:{d}"
            last_seen_raw = r.hget(meta_key, "last_seen")
            if not last_seen_raw:
                continue
            try:
                last_seen = int(last_seen_raw)
            except Exception:
                continue
            if now - last_seen > SITEMAP_DYNAMIC_DOMAIN_TTL_S:
                continue
            display = _to_unicode(d) or d
            lastmod_iso = datetime.fromtimestamp(last_seen, tz=timezone.utc).date().isoformat()
            for path in (
                url_for("domain_check", domain=display),
                url_for("lookup_whois_domain", domain=display),
                url_for("lookup_dns_domain", domain=display),
            ):
                dynamic_domain_entries.append((path, lastmod_iso))
    except Exception:
        app.logger.debug("Dynamic SEO sitemap domain load failed")

    xml = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">',
    ]
    root = _canonical_site_root()
    now_iso = datetime.now(timezone.utc).date().isoformat()

    def _append_url(path: str, priority: str, changefreq: str, lastmod: Optional[str] = None) -> None:
        loc = f"{root}{path}"
        loc_ru = f"{loc}?lang=ru"
        loc_en = f"{loc}?lang=en"
        loc_default = f"{loc}?lang=ru"
        xml.append("<url>")
        xml.append(f"<loc>{loc}</loc>")
        xml.append(f"<lastmod>{lastmod or now_iso}</lastmod>")
        xml.append(f"<changefreq>{changefreq}</changefreq>")
        xml.append(f"<priority>{priority}</priority>")
        xml.append(f'<xhtml:link rel="alternate" hreflang="ru" href="{loc_ru}" />')
        xml.append(f'<xhtml:link rel="alternate" hreflang="en" href="{loc_en}" />')
        xml.append(f'<xhtml:link rel="alternate" hreflang="x-default" href="{loc_default}" />')
        xml.append("</url>")

    for path, priority, changefreq in static_pages:
        _append_url(path, priority, changefreq)
    for path, lastmod in dynamic_domain_entries:
        _append_url(path, "0.75", "weekly", lastmod=lastmod)
    for path in zone_paths:
        _append_url(path, "0.8", "weekly")
    xml.append("</urlset>")
    return Response("\n".join(xml), mimetype="application/xml")

@app.route("/")
def index():
    return render_template("index.html")


@app.get("/hosting")
def hosting_landing():
    return render_template(
        "hosting.html",
        hosting_all_offers=_hosting_offers(),
    )


def _sanitize_lookup_domain(domain: str) -> tuple[Optional[str], Optional[str]]:
    clean = (domain or "").strip().lower().rstrip(".")
    if "/" in clean or clean.startswith(("whois", "dns")):
        return None, None
    clean = re.sub(r"[^a-zа-яё0-9.-]", "", clean)
    if not clean or len(clean) > 253 or "." not in clean:
        return None, None
    try:
        ascii_domain = idna.encode(clean).decode("ascii")
    except Exception:
        ascii_domain = clean
    return clean, ascii_domain


def _split_fqdn(domain: str) -> tuple[str, str]:
    d = (domain or "").strip().lower().rstrip(".")
    if "." not in d:
        return d, ""
    label, tld = d.rsplit(".", 1)
    return label, tld


def _related_tld_links(domain: str, limit: int = 6) -> List[Dict[str, str]]:
    label, current_tld = _split_fqdn(domain)
    if not label or not current_tld:
        return []
    preferred = [t.strip().lstrip(".") for t in app.config.get("DOMAIN_DEFAULT_TLDS", []) if (t or "").strip()]
    links: List[Dict[str, str]] = []
    for tld in preferred:
        if tld == current_tld:
            continue
        fqdn = f"{label}.{tld}"
        try:
            if not label.isascii() and tld not in IDN_READY_TLDS:
                continue
            idna.encode(fqdn, uts46=True)
        except Exception:
            continue
        links.append({
            "tld": tld,
            "fqdn": _to_unicode(fqdn),
            "search_url": url_for("domain_search", query=label, zones=[tld]),
            "buy_url": _affiliate_buy_url(fqdn),
            "overview_url": url_for("lookup_domain", domain=fqdn),
        })
        if len(links) >= limit:
            break
    return links


def _derive_check_status(report: Dict[str, object]) -> Dict[str, object]:
    domain = str(report.get("domain") or "").strip().lower()
    display = str(report.get("domain_display") or domain)
    urgency = report.get("whois_expiry_urgency") if isinstance(report.get("whois_expiry_urgency"), dict) else {}
    level = str(urgency.get("urgency") or "").lower()
    dns = report.get("dns") if isinstance(report.get("dns"), dict) else {}

    if level == "expired":
        status, label_ru, label_en = "critical", "Истёк", "Expired"
    elif level == "critical":
        status, label_ru, label_en = "critical", "Скоро истекает", "Expires soon"
    elif level in {"warning", "notice"}:
        status, label_ru, label_en = "warning", "Истекает", "Expiring"
    elif not dns.get("has_records"):
        status, label_ru, label_en = "warning", "Нет DNS", "No DNS"
    else:
        status, label_ru, label_en = "ok", "В порядке", "OK"

    return {
        "domain": domain,
        "domain_display": display,
        "status": status,
        "label_ru": label_ru,
        "label_en": label_en,
        "url": url_for("domain_check", domain=domain) if domain else url_for("domain_report"),
    }


def _lookup_landing_context(clean: str, ascii_domain: str, *, track_seo: bool = True) -> Dict[str, object]:
    if track_seo:
        _track_domain_for_seo(ascii_domain)
    label, tld = _split_fqdn(clean)
    return {
        "domain": clean,
        "domain_ascii": ascii_domain,
        "domain_label": label,
        "domain_tld": tld,
        "q": quote(clean, safe=""),
        "domain_availability": _landing_domain_availability(ascii_domain),
        "whois_expiry_urgency": _landing_whois_expiry(ascii_domain),
        "related_tld_links": _related_tld_links(clean),
        **_affiliate_actions_for_domain(ascii_domain),
    }


@app.get("/lookup/whois/<path:domain>")
def lookup_whois_domain(domain: str):
    clean, ascii_domain = _sanitize_lookup_domain(domain)
    if not clean:
        abort(404)
    try:
        return render_template("whois_landing.html", landing_kind="whois", **_lookup_landing_context(clean, ascii_domain))
    except Exception:
        app.logger.exception("WHOIS lookup landing render failed for %s", clean)
        return redirect(url_for("whois_lookup", query=clean), code=302)


@app.get("/lookup/dns/<path:domain>")
def lookup_dns_domain(domain: str):
    clean, ascii_domain = _sanitize_lookup_domain(domain)
    if not clean:
        abort(404)
    try:
        return render_template("dns_landing.html", landing_kind="dns", **_lookup_landing_context(clean, ascii_domain))
    except Exception:
        app.logger.exception("DNS lookup landing render failed for %s", clean)
        return redirect(url_for("dns_lookup", q=clean), code=302)


@app.get("/lookup/<path:domain>")
def lookup_domain(domain: str):
    clean, ascii_domain = _sanitize_lookup_domain(domain)
    if not clean:
        abort(404)
    return redirect(url_for("domain_check", domain=clean), code=301)


@app.get("/check")
def domain_check_query():
    query = (request.args.get("q") or request.args.get("query") or "").strip()
    clean, _ascii_domain = _sanitize_lookup_domain(query)
    if clean:
        return redirect(url_for("domain_check", domain=clean))
    return redirect(url_for("domain_report"))


@app.get("/check/<path:domain>")
def domain_check(domain: str):
    clean, ascii_domain = _sanitize_lookup_domain(domain)
    if not clean:
        abort(404)

    client_ip = _client_ip()
    limit = _report_limit_for_ip(client_ip)
    if _endpoint_ip_rate_limited("check", client_ip, limit):
        ctx = _lookup_landing_context(clean, ascii_domain)
        ctx["domain_availability"] = None
        ctx["whois_expiry_urgency"] = None
        ctx["related_tld_links"] = []
        return render_template(
            "check.html",
            error=_("Too many report requests. Please try again later."),
            one=None,
            check_status=None,
            **ctx,
        ), 429

    error = None
    one = None
    check_status = None
    try:
        one = cache_json(
            f"cache:report:full:{ascii_domain}",
            REPORT_FULL_TTL_S,
            lambda: _build_domain_report(ascii_domain, clean),
        )
        whois_block = (one or {}).get("whois") if isinstance(one, dict) else {}
        whois_missing_core = any(
            not (whois_block or {}).get(k)
            for k in ("registrar", "creation_date", "expiration_date")
        )
        if whois_missing_core:
            one = _build_domain_report(ascii_domain, clean)
        if isinstance(one, dict):
            hid = save_history("report", ascii_domain, one)
            if hid:
                one["permalink"] = f"/history/report/{hid}"
            check_status = _derive_check_status(one)
            _track_domain_for_seo(ascii_domain)
    except Exception:
        app.logger.exception("Domain check dashboard failed for %s", clean)
        error = _("Failed to build domain report.")
        return redirect(url_for("domain_report", q=clean), code=302)

    ctx = _lookup_landing_context(clean, ascii_domain, track_seo=False)
    return render_template(
        "check.html",
        one=one,
        check_status=check_status,
        error=error,
        **ctx,
    )


@app.get("/zones/<tld>")
def zone_landing(tld: str):
    zone = (tld or "").strip().lower().lstrip(".")
    allowed = {t.strip().lstrip(".").lower() for t in app.config.get("TLD_LIST", []) if (t or "").strip()}
    if not zone or zone not in allowed:
        abort(404)
    zone_display = _to_unicode(zone) if zone else zone
    popular_labels = ["shop", "studio", "online", "app", "blog", "pro"]
    return render_template(
        "zone_landing.html",
        zone=zone,
        zone_display=zone_display,
        popular_labels=popular_labels,
        default_tlds=[t for t in app.config.get("DOMAIN_DEFAULT_TLDS", []) if t in allowed][:12],
        name_ideas=[],
        idea_seed="",
    )

# ---------- DOMAIN REPORT ----------
def _report_dns_summary(host_ascii: str) -> Dict[str, object]:
    wanted = ("A", "AAAA", "NS", "MX", "TXT")
    records: Dict[str, List[str]] = {}
    for rtype in wanted:
        try:
            answers = dns.resolver.resolve(host_ascii, rtype)
            vals: List[str] = []
            for r in answers:
                if rtype == "MX":
                    vals.append(f"{getattr(r, 'preference', '')} {str(getattr(r, 'exchange', '')).rstrip('.')}".strip())
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
            continue
    ips = (records.get("A") or []) + (records.get("AAAA") or [])
    return {"records": records, "has_records": bool(records), "ips": ips}


def _report_whois_summary(host_ascii: str) -> Dict[str, object]:
    data: Dict[str, object] = {}
    maybe_text = _whois_call(["whois", "-H", host_ascii], timeout=12)
    source_flags = {
        "cli_text": bool((maybe_text or "").strip()),
        "pywhois_obj": False,
        "pywhois_text": False,
        "ru_parser": False,
        "generic_parser": False,
        "regex_fields": False,
    }
    try:
        w = whois.whois(host_ascii)
        parsed_obj = _whois_object_to_dict(w)
        if parsed_obj:
            _merge_whois_dict(data, parsed_obj)
            source_flags["pywhois_obj"] = True
    except Exception:
        pass

    # Некоторые провайдеры/окружения не отдают полезный stdout в whois CLI,
    # но python-whois может вернуть сырой текст в поле `text`.
    if not maybe_text:
        txt = data.get("text")
        if isinstance(txt, str) and txt.strip():
            maybe_text = txt
            source_flags["pywhois_text"] = True
        elif isinstance(txt, (list, tuple)):
            joined = "\n".join(str(x) for x in txt if x)
            if joined.strip():
                maybe_text = joined
                source_flags["pywhois_text"] = True

    # Дополняем данными из сырого whois-текста даже если python-whois вернул частичный объект.
    # Для RU/SU/РФ это часто единственный стабильный источник registrar/created/paid-till.
    if maybe_text:
        parsed_ru = _parse_ru_whois_text(maybe_text)
        parsed_generic = parse_whois_text(host_ascii, maybe_text)
        source_flags["ru_parser"] = bool(parsed_ru)
        source_flags["generic_parser"] = bool(parsed_generic)
        for parsed in (parsed_ru, parsed_generic):
            _merge_whois_dict(data, parsed)

        regex_fields = _extract_whois_core_fields_from_text(maybe_text)
        if regex_fields:
            source_flags["regex_fields"] = True
            _merge_whois_dict(data, regex_fields)

    data = _finalize_whois_summary(data, host_ascii)

    app.logger.info(
        "WHOIS report summary for %s: registrar=%s creation=%s expiration=%s sources=%s",
        host_ascii,
        bool(data.get("registrar")),
        bool(data.get("creation_date")),
        bool(data.get("expiration_date")),
        source_flags,
    )
    return data


def _report_geo_summary(ip: str | None) -> Dict[str, object]:
    if not ip:
        return {"ip": None, "error": _("No IP available for GeoIP lookup.")}
    try:
        who = IPWhois(ip).lookup_rdap()
        country_code = (who.get("asn_country_code") or "").upper()
        return {
            "ip": ip,
            "asn": who.get("asn"),
            "country_code": country_code,
            "country_name": who.get("network", {}).get("country", "") or country_code,
        }
    except Exception:
        return {"ip": ip, "error": _("GeoIP lookup failed.")}


def _report_reverse_summary(ip: str | None) -> Dict[str, object]:
    if not ip:
        return {"ip": None, "ptr": [], "fcrdns_ok": False, "error": _("No IP available for reverse lookup.")}
    row = {"ip": ip, "ptr": [], "fcrdns_ok": False, "forward_of_ptr": {}}
    try:
        rev = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev, "PTR")
        ptrs = [str(r).rstrip(".") for r in answers]
        row["ptr"] = ptrs
        forward_addrs = set()
        for hn in ptrs:
            row["forward_of_ptr"][hn] = {}
            for t in ("A", "AAAA"):
                try:
                    a = dns.resolver.resolve(hn, t)
                    vals = [str(v).rstrip(".") for v in a]
                    row["forward_of_ptr"][hn][t] = vals
                    forward_addrs.update(vals)
                except Exception:
                    continue
        row["fcrdns_ok"] = ip in forward_addrs
    except Exception as e:
        row["error"] = str(e)
    return row


def _build_domain_report(
    host_ascii: str,
    source_input: str,
    *,
    job_id: Optional[str] = None,
    progress_extra: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    def _progress(step: str) -> None:
        if not job_id:
            return
        payload: Dict[str, object] = {"status": "running", "progress_step": step}
        if progress_extra:
            payload.update(progress_extra)
        _touch_report_job(job_id, **payload)

    _progress("dns")
    dns_part = cache_json(f"cache:report:dns:{host_ascii}", REPORT_DNS_TTL_S, lambda: _report_dns_summary(host_ascii))
    _progress("whois")
    whois_part = cache_json(f"cache:report:whois:{host_ascii}", REPORT_WHOIS_TTL_S, lambda: _report_whois_summary(host_ascii))
    whois_missing_core = any(
        not (whois_part or {}).get(k)
        for k in ("registrar", "creation_date", "expiration_date")
    )
    if whois_missing_core:
        fresh_whois = _report_whois_summary(host_ascii)
        if fresh_whois:
            merged = dict(whois_part or {})
            for k, v in fresh_whois.items():
                if v and not merged.get(k):
                    merged[k] = v
            whois_part = merged
    first_ip = (dns_part.get("ips") or [None])[0]
    _progress("geo")
    geo_part = cache_json(
        f"cache:report:geo:{first_ip or 'none'}",
        REPORT_GEO_TTL_S,
        lambda: _report_geo_summary(first_ip),
    )
    _progress("reverse")
    reverse_part = cache_json(
        f"cache:report:reverse:{first_ip or 'none'}",
        REPORT_REVERSE_TTL_S,
        lambda: _report_reverse_summary(first_ip),
    )
    _progress("finalize")
    domain_unicode = _to_unicode(host_ascii)
    return {
        "input": source_input,
        "domain": host_ascii,
        "domain_display": domain_unicode or host_ascii,
        "dns": dns_part,
        "whois": whois_part,
        "whois_expiry_urgency": _build_whois_expiry_urgency(whois_part, domain=host_ascii),
        "geo": geo_part,
        "reverse": reverse_part,
    }


def _execute_report_job(job_id: str, domains: List[str], source_input: str) -> None:
    try:
        if not _save_report_job(job_id, {"status": "running", "domains": domains, "source_input": source_input}):
            app.logger.error("Report job aborted because storage is unavailable: job_id=%s", job_id)
            return
        reports = []
        total = len(domains)
        for idx, d in enumerate(domains):
            progress_extra = {
                "progress_domain_index": idx,
                "progress_domain_total": total,
                "progress_domain": d,
            }
            report = cache_json(
                f"cache:report:full:{d}",
                REPORT_FULL_TTL_S,
                lambda d=d, progress_extra=progress_extra: _build_domain_report(
                    d, source_input, job_id=job_id, progress_extra=progress_extra
                ),
            )
            whois_block = (report or {}).get("whois") if isinstance(report, dict) else {}
            whois_missing_core = any(
                not (whois_block or {}).get(k)
                for k in ("registrar", "creation_date", "expiration_date")
            )
            if whois_missing_core:
                report = _build_domain_report(d, source_input, job_id=job_id, progress_extra=progress_extra)
            hid = save_history("report", d, report)
            if hid:
                report["permalink"] = f"/history/report/{hid}"
            reports.append(report)
            _track_domain_for_seo(d)
        _save_report_job(job_id, {"status": "done", "domains": domains, "source_input": source_input, "reports": reports})
    except Exception as e:
        _save_report_job(job_id, {"status": "failed", "domains": domains, "source_input": source_input, "error": str(e)})


@app.route("/report", methods=["GET", "POST"])
def domain_report():
    query = (
        request.args.get("q")
        or request.form.get("q")
        or request.args.get("query")
        or request.form.get("query")
        or ""
    ).strip()
    job_id = (request.args.get("job") or request.form.get("job") or "").strip()
    report = None
    reports = []
    error = None
    job_status = None
    progress_step = None
    progress_domain_index = 0
    progress_domain_total = 0
    progress_domain = None

    # Poll existing async job
    if job_id:
        if not _is_valid_report_job_id(job_id):
            job_id = ""
        else:
            job = _load_report_job(job_id)
            if job:
                job_status = str(job.get("status") or "").lower() or "queued"
                query = query or str(job.get("source_input") or "")
                progress_step = str(job.get("progress_step") or "").lower() or None
                progress_domain_index = int(job.get("progress_domain_index") or 0)
                progress_domain_total = int(job.get("progress_domain_total") or 0)
                progress_domain = str(job.get("progress_domain") or "") or None
                if job_status == "done":
                    reports = list(job.get("reports") or [])
                    report = reports[0] if reports else None
                elif job_status == "failed":
                    error = str(job.get("error") or _("Failed to build domain report."))

    should_run = bool(query and not job_id and request.method == "POST")
    if should_run:
        captcha_error = _verify_form_recaptcha_if_needed()
        if captcha_error:
            error = captcha_error
        else:
            try:
                raw_items = re.split(r"[\s,;]+", query)
                uniq_items = [x for x in dict.fromkeys(i.strip() for i in raw_items if i.strip())]
                if not uniq_items:
                    raise ValueError(_("Invalid domain name."))
                if len(uniq_items) > REPORT_MAX_BATCH:
                    raise ValueError(_("Too many domains in batch."))
                normalized: List[str] = []
                for item in uniq_items:
                    host_ascii, err = _normalize_domain_query(item)
                    if err or not host_ascii:
                        raise ValueError(err or _("Invalid domain name."))
                    normalized.append(host_ascii)
                client_ip = _client_ip()
                limit = _report_limit_for_ip(client_ip)
                if _endpoint_ip_rate_limited("report", client_ip, limit):
                    raise ValueError(_("Too many report requests. Please try again later."))

                if len(normalized) == 1:
                    return redirect(url_for("domain_check", domain=normalized[0]))

                job_id = uuid.uuid4().hex
                if not _save_report_job(job_id, {"status": "queued", "domains": normalized, "source_input": query}):
                    raise RuntimeError("report job storage unavailable")
                _REPORT_ASYNC_POOL.submit(_execute_report_job, job_id, normalized, query)
                return redirect(url_for("domain_report", job=job_id, q=query))
            except ValueError as ve:
                error = str(ve)
            except Exception:
                app.logger.exception("Domain report queue error")
                error = _("Failed to queue domain report.")

    return render_template(
        "report.html",
        query=query,
        report=report,
        reports=reports,
        error=error,
        job_status=job_status,
        job_id=job_id,
        progress_step=progress_step,
        progress_domain_index=progress_domain_index,
        progress_domain_total=progress_domain_total,
        progress_domain=progress_domain,
        batch_max=REPORT_MAX_BATCH,
        seo_noindex=bool(job_id or query),
    )

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
    query = (request.args.get("q") or request.form.get("q") or "").strip()
    selected_types = [t.strip().upper() for t in request.values.getlist("types") if t and t.strip()]
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

    captcha_error = _verify_form_recaptcha_if_needed()
    if captcha_error:
        return render_template(
            "dns.html",
            meta=meta,
            result=None,
            error=captcha_error,
            query=query,
            selected_types=selected_types,
            dns_type_options=dns_type_options,
        )

    rate_error = _tool_rate_limited("dns")
    if rate_error:
        return render_template(
            "dns.html",
            meta=meta,
            result=None,
            error=rate_error,
            query=query,
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
    _track_domain_for_seo(query)
    display_domain = _to_unicode(query) or query
    permalink = url_for("lookup_dns_domain", domain=display_domain, _external=False)

    affiliate_domain = _extract_affiliate_domain(query, "dns") or ""
    domain_availability = _evaluate_domain_availability(
        affiliate_domain or query,
        dns_records=records,
    )

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
        domain_availability=domain_availability,
        dns_suggests_hosting=_dns_suggests_hosting(records, domain_availability),
        **_affiliate_actions_for_domain(affiliate_domain),
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
    is_post = request.method == "POST"
    query = (
        request.form.get("query")
        if is_post
        else (request.args.get("query") or request.args.get("q") or "")
    )
    query = (query or "").strip()
    items = []
    error = None
    suggestions = []
    permalink = None
    idea_seed = (request.args.get("idea") or "").strip()
    name_ideas: List[str] = []
    if not is_post and idea_seed and request.args.get("generate", "").strip().lower() in {"1", "true", "yes", "on"}:
        name_ideas = _generate_domain_name_ideas(idea_seed)

    all_tlds = [t.strip().lstrip(".") for t in app.config.get("TLD_LIST", []) if (t or "").strip()]
    # Убираем дубли, сохраняя порядок
    all_tlds = list(dict.fromkeys(all_tlds))

    default_tlds_cfg = [t.strip().lstrip(".") for t in app.config.get("DOMAIN_DEFAULT_TLDS", []) if (t or "").strip()]
    default_tlds = [t for t in default_tlds_cfg if t in all_tlds] or all_tlds[:20]
    tld_groups, tld_group_map = _build_tld_groups(all_tlds, default_tlds)
    max_tlds = max(1, int(app.config.get("DOMAIN_CHECK_MAX_TLDS", 80)))

    selected_source = request.form if is_post else request.args
    selected_from_req = [t.strip().lstrip(".") for t in selected_source.getlist("zones") if (t or "").strip()]
    preset = (selected_source.get("zone_preset") or "").strip().lower()
    preset_map = {
        "core": default_tlds,
        "defaults": default_tlds,
        "ru": tld_groups.get("ru", []),
        "global": tld_groups.get("global", []),
        "new": tld_groups.get("new", []),
        "newgtld": tld_groups.get("new", []),
        "all": all_tlds,
        "none": [],
    }
    if preset in preset_map:
        selected_tlds = [t for t in all_tlds if t in set(preset_map[preset])]
    else:
        selected_tlds = [t for t in all_tlds if t in set(selected_from_req)] if selected_from_req else default_tlds

    if query:
        if not selected_tlds:
            error = _("Выберите хотя бы одну зону для проверки.")
            return render_template(
                "domains.html",
                q=query,
                items=items,
                error=error,
                suggestions=suggestions,
                buy_base=(app.config.get("AFFILIATE_BUY_BASE_EN") if str(babel_get_locale() or "ru").startswith("en") else app.config.get("AFFILIATE_BUY_BASE_RU")) or app.config.get("AFFILIATE_BUY_BASE"),
                all_tlds=all_tlds,
                selected_tlds=selected_tlds,
                default_tlds=default_tlds,
                max_tlds=max_tlds,
                tld_groups=tld_groups,
                tld_group_map=tld_group_map,
                permalink=permalink,
                name_ideas=name_ideas,
                idea_seed=idea_seed,
            )
        captcha_error = _verify_form_recaptcha_if_needed() if is_post else None
        if captcha_error:
            error = captcha_error
        else:
            rate_error = _tool_rate_limited("domains")
            if rate_error:
                error = rate_error
            else:
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
                        tlds_for_check = selected_tlds[:max_tlds]

                    items = _check_candidates(label, tlds_for_check)
                    if items:
                        seen_fqdn: set[str] = set()
                        for row in items:
                            fqdn = (row.get("puny") or row.get("fqdn") or "").strip().lower()
                            if fqdn and fqdn not in seen_fqdn:
                                seen_fqdn.add(fqdn)
                                _track_domain_for_seo(fqdn)
                            if len(seen_fqdn) >= 12:
                                break
                except Exception:
                    app.logger.exception("Domain search failed", extra={"query": query})
                    error = _("Не удалось выполнить подбор доменов. Попробуйте ещё раз.")

    locale = str(babel_get_locale() or "ru")
    buy_base = app.config.get("AFFILIATE_BUY_BASE_EN") if locale.startswith("en") else app.config.get("AFFILIATE_BUY_BASE_RU")
    if query:
        permalink = url_for("domain_search", query=query, zones=selected_tlds)

    domain_availability = _domain_availability_from_search_items(items) if items and not error else None

    return render_template(
        "domains.html",
        q=query,
        items=items,
        error=error,
        suggestions=suggestions,
        buy_base=(buy_base or app.config.get("AFFILIATE_BUY_BASE")),
        all_tlds=all_tlds,
        selected_tlds=selected_tlds,
        default_tlds=default_tlds,
        max_tlds=max_tlds,
        tld_groups=tld_groups,
        tld_group_map=tld_group_map,
        permalink=permalink,
        domain_availability=domain_availability,
        name_ideas=name_ideas,
        idea_seed=idea_seed,
    )


def _landing_domain_availability(domain_ascii: str) -> Optional[Dict[str, object]]:
    host = (domain_ascii or "").strip().lower().rstrip(".")
    if not host or _is_ip_host(host) or "." not in host:
        return None

    def _compute() -> Optional[Dict[str, object]]:
        records: Dict[str, List[str]] = {}
        for rtype in ("NS", "A", "AAAA"):
            try:
                answers = dns.resolver.resolve(host, rtype)
                vals = [str(r).rstrip(".") for r in answers]
                if vals:
                    records[rtype] = vals
            except Exception:
                continue
        return _evaluate_domain_availability(host, dns_records=records)

    try:
        return cache_json(f"cache:landing-avail:{host}", 900, _compute)
    except Exception:
        return _compute()


COMMON_SAFE_PORTS = [20,21,22,25,53,80,110,111,123,135,139,143,161,389,443,445,465,587,993,995,1433,1521,1723,1883,2049,2083,2087,2096,2375,2376,3000,3128,3306,3389,3690,4369,5000,5432,5672,5900,5985,5986,6379,6443,7001,7002,7443,8000,8080,8081,8443,9000,9090,9200,9300,10000,11211,15672,27017]


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved)
    except Exception:
        return False


def _tr_no_req(msg: str, **kwargs) -> str:
    """gettext-safe helper that also works in background jobs without request context."""
    try:
        return _(msg, **kwargs)
    except RuntimeError:
        # No request context (e.g., async worker thread): return source text.
        if kwargs:
            try:
                return msg % kwargs
            except Exception:
                return msg
        return msg


def _normalize_security_host_input(host: str) -> Tuple[str | None, str | None]:
    """Accept either a hostname/IP or a full URL and return a scanner-safe host."""
    raw = (host or '').strip()
    if not raw:
        return None, _tr_no_req('Empty host')

    # Operators often paste a URL from the address bar into the port scanner.
    # Keep the actual target host and ignore scheme, path, query, and URL port.
    candidate = raw
    looks_like_url = re.match(r'^[a-z][a-z0-9+.-]*://', raw, re.I)
    has_single_host_port = raw.count(':') == 1 and not raw.startswith('[')
    if looks_like_url or has_single_host_port or any(ch in raw for ch in '/?#'):
        parsed_text = raw if looks_like_url else f'//{raw}'
        try:
            parsed = urlparse(parsed_text)
            candidate = parsed.hostname or raw
        except Exception:
            return None, _tr_no_req('Invalid URL')

    candidate = (candidate or '').strip().strip('[]').rstrip('.')
    if not candidate:
        return None, _tr_no_req('Empty host')

    # Normalize IDN domains to ASCII before validation/resolution.
    if not re.fullmatch(r'[0-9A-Fa-f:.]+', candidate):
        try:
            candidate = idna.encode(candidate).decode('ascii')
        except Exception:
            return None, _tr_no_req('Host format is invalid. Use domain or public IP.')

    return candidate.lower(), None


def _resolve_public_target_ip(host: str) -> Tuple[str | None, str | None]:
    host, host_err = _normalize_security_host_input(host)
    if host_err:
        return None, host_err

    # Simple hostname format pre-check to avoid noisy resolver errors
    if not re.match(r'^[A-Za-z0-9.-]+$', host):
        return None, _tr_no_req('Host format is invalid. Use domain or public IP.')

    # direct IP input
    try:
        ipaddress.ip_address(host)
        if not _is_public_ip(host):
            return None, _tr_no_req('Only public IP targets are allowed.')
        return host, None
    except Exception:
        pass

    # domain input
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        ips = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        public_ips = [ip for ip in ips if _is_public_ip(ip)]
        if not public_ips:
            return None, _tr_no_req('Resolved host does not have a public IP.')
        return public_ips[0], None
    except Exception:
        return None, _tr_no_req('Could not resolve host.')


def _parse_ports(raw_ports: str, max_ports: int) -> Tuple[List[int], str | None]:
    raw = (raw_ports or '').strip()
    if not raw:
        return COMMON_SAFE_PORTS[:max_ports], None

    ports: List[int] = []
    for part in raw.split(','):
        p = part.strip()
        if not p:
            continue
        if '-' in p:
            a, b = p.split('-', 1)
            if not (a.strip().isdigit() and b.strip().isdigit()):
                return [], _tr_no_req('Ports format is invalid.')
            start, end = int(a), int(b)
            if start > end:
                start, end = end, start
            if start < 1 or end > 65535:
                return [], _tr_no_req('Ports must be in range 1..65535.')
            ports.extend(range(start, end + 1))
        else:
            if not p.isdigit():
                return [], _tr_no_req('Ports format is invalid.')
            port = int(p)
            if port < 1 or port > 65535:
                return [], _tr_no_req('Ports must be in range 1..65535.')
            ports.append(port)

    ports = sorted(set(ports))
    if not ports:
        return [], _tr_no_req('Please select at least one port.')
    if len(ports) > max_ports:
        return [], _tr_no_req('Too many ports selected. Limit is %(n)s.', n=max_ports)
    return ports, None


def _scan_single_port(ip: str, port: int, timeout_s: float) -> Dict[str, object]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_s)
    try:
        rc = sock.connect_ex((ip, port))
        state = 'open' if rc == 0 else 'closed'
        return {'port': port, 'state': state}
    except Exception:
        return {'port': port, 'state': 'filtered'}
    finally:
        try:
            sock.close()
        except Exception:
            pass


SECURITY_MAX_HOST_LEN = int(os.environ.get('SECURITY_MAX_HOST_LEN', '255'))
SECURITY_MAX_PORTS_RAW_LEN = int(os.environ.get('SECURITY_MAX_PORTS_RAW_LEN', '512'))
SECURITY_MAX_WP_URL_LEN = int(os.environ.get('SECURITY_MAX_WP_URL_LEN', '2048'))

PORT_SECURITY_HINTS = {
    21: {"level":"high", "ru":"FTP открыт", "en":"FTP is exposed", "ru_fix":"Отключите FTP или используйте SFTP/FTPS.", "en_fix":"Disable FTP or use SFTP/FTPS."},
    22: {"level":"medium", "ru":"SSH открыт", "en":"SSH is exposed", "ru_fix":"Ограничьте доступ по IP и используйте только ключи.", "en_fix":"Restrict by IP and use key-only authentication."},
    23: {"level":"high", "ru":"Telnet открыт", "en":"Telnet is exposed", "ru_fix":"Закройте Telnet и используйте SSH.", "en_fix":"Disable Telnet and use SSH."},
    25: {"level":"medium", "ru":"SMTP открыт", "en":"SMTP is exposed", "ru_fix":"Проверьте, что это не open-relay, и включите SPF/DKIM/DMARC.", "en_fix":"Ensure it is not open relay and enable SPF/DKIM/DMARC."},
    3389: {"level":"high", "ru":"RDP открыт", "en":"RDP is exposed", "ru_fix":"Разрешайте доступ только через VPN/ACL.", "en_fix":"Allow access only via VPN/ACL."},
    3306: {"level":"high", "ru":"MySQL открыт", "en":"MySQL is exposed", "ru_fix":"БД не должна быть доступна из интернета.", "en_fix":"Database should not be publicly reachable."},
    5432: {"level":"high", "ru":"PostgreSQL открыт", "en":"PostgreSQL is exposed", "ru_fix":"Ограничьте доступ только внутренней сетью.", "en_fix":"Restrict access to internal network only."},
    6379: {"level":"critical", "ru":"Redis открыт", "en":"Redis is exposed", "ru_fix":"Закройте порт снаружи и включите аутентификацию.", "en_fix":"Close external access and enable authentication."},
    27017: {"level":"high", "ru":"MongoDB открыт", "en":"MongoDB is exposed", "ru_fix":"Закройте публичный доступ и включите auth.", "en_fix":"Close public access and enforce auth."},
}


def _build_port_hints(rows: List[Dict[str, object]]) -> List[Dict[str, str]]:
    open_ports = sorted(int(r["port"]) for r in rows if r.get("state") == "open")
    hints: List[Dict[str, str]] = []
    for p in open_ports:
        if p in PORT_SECURITY_HINTS:
            h = PORT_SECURITY_HINTS[p]
            hints.append({
                "port": str(p),
                "level": h["level"],
                "ru": h["ru"],
                "en": h["en"],
                "ru_fix": h["ru_fix"],
                "en_fix": h["en_fix"],
            })
    return _normalize_security_hints(hints)


def _normalize_wp_target(raw: str) -> Tuple[str | None, str | None, str | None]:
    """Return (normalized_url, host, error)."""
    txt = (raw or "").strip()
    if not txt:
        return None, None, _tr_no_req('Empty host')
    if not re.match(r"^https?://", txt, re.I):
        txt = f"https://{txt}"
    try:
        u = urlparse(txt)
    except Exception:
        return None, None, _tr_no_req('Invalid URL')
    host = (u.hostname or "").strip()
    if not host:
        return None, None, _tr_no_req('Invalid URL')
    return txt, host, None


def _safe_http_url_host(url: str) -> Tuple[str | None, str | None]:
    try:
        parsed = urlparse(url)
    except Exception:
        return None, _tr_no_req('Invalid URL')
    if parsed.scheme.lower() not in {'http', 'https'}:
        return None, _tr_no_req('Only HTTP and HTTPS URLs are allowed.')
    host = (parsed.hostname or '').strip()
    if not host:
        return None, _tr_no_req('Invalid URL')
    _, err = _resolve_public_target_ip(host)
    if err:
        return None, err
    return host, None


def _safe_get_text(url: str, timeout_s: float = 4.0) -> Tuple[int, str, Dict[str, str], str | None]:
    headers = {"User-Agent": "DomainTools-SecurityScanner/1.0"}
    max_redirects = max(0, int(app.config.get('SAFE_HTTP_MAX_REDIRECTS', 5)))
    max_bytes = max(1024, int(app.config.get('SAFE_HTTP_MAX_BYTES', 1048576)))
    current_url = url

    try:
        for _ in range(max_redirects + 1):
            _, url_err = _safe_http_url_host(current_url)
            if url_err:
                return 0, "", {}, url_err

            resp = requests.get(current_url, timeout=timeout_s, allow_redirects=False, headers=headers, stream=True)
            if resp.is_redirect or resp.is_permanent_redirect:
                location = resp.headers.get('Location')
                if not location:
                    return resp.status_code, "", dict(resp.headers), None
                current_url = urljoin(current_url, location)
                continue

            chunks: List[bytes] = []
            total = 0
            for chunk in resp.iter_content(chunk_size=16384):
                if not chunk:
                    continue
                remaining = max_bytes - total
                if remaining <= 0:
                    break
                chunks.append(chunk[:remaining])
                total += len(chunk[:remaining])
            encoding = resp.encoding or 'utf-8'
            text = b''.join(chunks).decode(encoding, errors='replace')
            return resp.status_code, text, dict(resp.headers), None
        return 0, "", {}, _tr_no_req('Too many redirects.')
    except Exception as e:
        return 0, "", {}, str(e)


def _wordpress_safe_scan(target_url: str) -> Dict[str, object]:
    status, html, headers, err = _safe_get_text(target_url)
    html_l = (html or "").lower()

    checks: Dict[str, object] = {
        "homepage_status": status,
        "reachable": status > 0 and err is None,
        "error": err,
    }

    # WP markers
    markers = ["wp-content", "wp-includes", "wp-json", "wordpress"]
    is_wp = any(m in html_l for m in markers)

    wp_login_status, wp_login_text, _, _ = _safe_get_text(target_url.rstrip('/') + '/wp-login.php')
    xmlrpc_status, xmlrpc_text, _, _ = _safe_get_text(target_url.rstrip('/') + '/xmlrpc.php')
    readme_status, readme_text, _, _ = _safe_get_text(target_url.rstrip('/') + '/readme.html')
    wpjson_status, _, _, _ = _safe_get_text(target_url.rstrip('/') + '/wp-json/')
    uploads_status, uploads_text, _, _ = _safe_get_text(target_url.rstrip('/') + '/wp-content/uploads/')

    if wp_login_status in {200, 301, 302, 403}:
        is_wp = True

    # version extraction (best-effort)
    ver = None
    m = re.search(r"wordpress\s*([0-9]+(?:\.[0-9]+){1,3})", html_l)
    if m:
        ver = m.group(1)

    sec_headers = {
        "strict-transport-security": headers.get("Strict-Transport-Security"),
        "content-security-policy": headers.get("Content-Security-Policy"),
        "x-frame-options": headers.get("X-Frame-Options"),
        "x-content-type-options": headers.get("X-Content-Type-Options"),
        "referrer-policy": headers.get("Referrer-Policy"),
    }

    checks.update({
        "is_wordpress": is_wp,
        "version": ver,
        "wp_login_status": wp_login_status,
        "xmlrpc_enabled": xmlrpc_status == 200 and ("xml-rpc" in (xmlrpc_text or "").lower()),
        "readme_exposed": readme_status == 200 and "wordpress" in (readme_text or "").lower(),
        "wp_json_enabled": wpjson_status in {200, 401, 403},
        "uploads_listing": uploads_status == 200 and "index of" in (uploads_text or "").lower(),
        "security_headers": sec_headers,
    })

    hints: List[Dict[str, str]] = []
    if checks["xmlrpc_enabled"]:
        hints.append({"level":"medium", "ru":"Доступен xmlrpc.php", "en":"xmlrpc.php is enabled", "ru_fix":"Ограничьте xmlrpc.php, если не используете Jetpack/приложения.", "en_fix":"Restrict xmlrpc.php unless required by Jetpack/apps."})
    if checks["readme_exposed"]:
        hints.append({"level":"low", "ru":"Доступен readme.html", "en":"readme.html is exposed", "ru_fix":"Удалите/скройте readme.html, чтобы не светить версию.", "en_fix":"Hide/remove readme.html to reduce version disclosure."})
    if checks["uploads_listing"]:
        hints.append({"level":"high", "ru":"Открыт листинг /wp-content/uploads/", "en":"Directory listing enabled for /wp-content/uploads/", "ru_fix":"Отключите directory listing на веб-сервере.", "en_fix":"Disable directory listing in web server config."})

    missing_headers = [k for k,v in sec_headers.items() if not v]
    if missing_headers:
        hints.append({"level":"medium", "ru":"Не хватает security-заголовков", "en":"Missing security headers", "ru_fix":"Добавьте HSTS/CSP/X-Frame-Options/X-Content-Type-Options/Referrer-Policy.", "en_fix":"Add HSTS/CSP/X-Frame-Options/X-Content-Type-Options/Referrer-Policy."})

    checks["hints"] = _normalize_security_hints(hints)
    return checks


def _run_port_scan_result(host: str, ports_raw: str) -> Tuple[Dict[str, object] | None, str | None]:
    normalized_host, host_err = _normalize_security_host_input(host)
    if host_err:
        return None, host_err
    target_ip, err = _resolve_public_target_ip(normalized_host or host)
    if err:
        return None, err

    max_ports = max(1, int(app.config.get('PORT_SCAN_MAX_PORTS', 50)))
    ports, p_err = _parse_ports(ports_raw, max_ports=max_ports)
    if p_err:
        return None, p_err

    timeout_s = float(app.config.get('PORT_SCAN_CONNECT_TIMEOUT', 0.4))
    max_workers = max(1, min(int(app.config.get('PORT_SCAN_MAX_WORKERS', 20)), len(ports)))
    rows: List[Dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futs = [pool.submit(_scan_single_port, target_ip, p, timeout_s) for p in ports]
        for fut in as_completed(futs):
            rows.append(fut.result())
    rows.sort(key=lambda x: int(x['port']))

    hints = _build_port_hints(rows)
    return {
        'host': normalized_host or host,
        'input_host': host,
        'ip': target_ip,
        'ports': ports,
        'rows': rows,
        'open_count': sum(1 for row in rows if row['state'] == 'open'),
        'closed_count': sum(1 for row in rows if row['state'] == 'closed'),
        'filtered_count': sum(1 for row in rows if row['state'] == 'filtered'),
        'limits': {
            'max_ports': max_ports,
            'timeout_s': timeout_s,
            'max_workers': max_workers,
        },
        'hints': hints,
    }, None


def _run_wp_scan_result(wp_url_raw: str) -> Tuple[Dict[str, object] | None, str | None]:
    norm_url, wp_host, n_err = _normalize_wp_target(wp_url_raw)
    if n_err:
        return None, n_err
    target_ip, err = _resolve_public_target_ip(wp_host)
    if err:
        return None, err

    wp_result = _wordpress_safe_scan(norm_url)
    wp_result['target_url'] = norm_url
    wp_result['target_host'] = wp_host
    wp_result['target_ip'] = target_ip
    wp_result['hints'] = _normalize_security_hints(wp_result.get('hints') or [])
    return wp_result, None


def _execute_security_job(job_id: str, job_kind: str, payload: Dict[str, str]) -> None:
    with app.app_context():
        started = int(time.time())
        if not _save_security_job(job_id, {
            "status": "running",
            "kind": job_kind,
            "created_ts": started,
            "started_ts": started,
            "payload": payload,
            "result": None,
            "error": None,
            "error_code": None,
            "duration_ms": None,
        }):
            app.logger.error("Security scan job aborted because storage is unavailable: job_id=%s kind=%s", job_id, job_kind)
            return
        try:
            if job_kind == "ports":
                result, err = _run_port_scan_result(payload.get("host", ""), payload.get("ports_raw", ""))
                if err:
                    raise ValueError(err)
                hid = save_history("security", f"ports:{payload.get('host', '')}:{payload.get('ports_raw') or 'default'}", result)
                permalink = f"/history/security/{hid}" if hid and load_history("security", hid) else None
            elif job_kind == "wp":
                result, err = _run_wp_scan_result(payload.get("wp_url_raw", ""))
                if err:
                    raise ValueError(err)
                hid = save_history("security", f"wp:{payload.get('wp_url_raw', '')}", result)
                permalink = f"/history/security/{hid}" if hid and load_history("security", hid) else None
            else:
                raise ValueError(_tr_no_req("Unsupported scan type."))

            _save_security_job(job_id, {
                "status": "done",
                "kind": job_kind,
                "created_ts": started,
                "finished_ts": int(time.time()),
                "payload": payload,
                "result": result,
                "error": None,
                "error_code": None,
                "duration_ms": max(0, int((time.time() - started) * 1000)),
                "permalink": permalink,
            })
        except ValueError as e:
            _save_security_job(job_id, {
                "status": "failed",
                "kind": job_kind,
                "created_ts": started,
                "finished_ts": int(time.time()),
                "payload": payload,
                "result": None,
                "error": str(e),
                "error_code": "validation_error",
                "duration_ms": max(0, int((time.time() - started) * 1000)),
                "permalink": None,
            })
        except Exception:
            app.logger.exception("Security scan job failed: kind=%s", job_kind)
            _save_security_job(job_id, {
                "status": "failed",
                "kind": job_kind,
                "created_ts": started,
                "finished_ts": int(time.time()),
                "payload": payload,
                "result": None,
                "error": _tr_no_req("Internal scan error. Please retry later."),
                "error_code": "internal_error",
                "duration_ms": max(0, int((time.time() - started) * 1000)),
                "permalink": None,
            })


def _client_ip() -> str:
    xff = (request.headers.get("X-Forwarded-For") or "").strip()
    if xff:
        return xff.split(",", 1)[0].strip()
    return (request.remote_addr or "").strip()


def _security_is_rate_limited(ip: str, limit_per_min: int, window_s: int = 60) -> bool:
    """Rate-limit security scans by IP (Redis primary, in-memory fallback)."""
    return _ip_rate_limited("security", ip, limit_per_min, window_s)



def _recaptcha_setup_status() -> Tuple[bool, str | None]:
    if not app.config.get("SECURITY_RECAPTCHA_ENABLED"):
        return True, None
    provider = (app.config.get("SECURITY_RECAPTCHA_PROVIDER") or "standard").lower()
    if provider not in {"standard", "enterprise"}:
        provider = "standard"
    if provider == "enterprise":
        ok = bool(app.config.get("SECURITY_RECAPTCHA_SITE_KEY") and app.config.get("SECURITY_RECAPTCHA_ENTERPRISE_PROJECT") and app.config.get("SECURITY_RECAPTCHA_API_KEY"))
        return (ok, None if ok else _("reCAPTCHA Enterprise config is incomplete."))
    ok = bool(app.config.get("SECURITY_RECAPTCHA_SITE_KEY") and app.config.get("SECURITY_RECAPTCHA_SECRET_KEY"))
    return (ok, None if ok else _("reCAPTCHA v3 config is incomplete."))

def _verify_form_recaptcha_if_needed() -> str | None:
    """Validate captcha for generic data-entry forms when enabled."""
    if not app.config.get("FORM_RECAPTCHA_ENABLED"):
        return None

    # Report flow must remain linkable and tolerant to clients where
    # captcha JS is blocked or race-conditions on submit.
    if request.endpoint == "domain_report":
        return None

    token = (request.values.get("recaptcha_token") or "").strip()
    if request.method != "POST" and not token:
        # keep GET permalink/repeat links working when no captcha token is present
        return None

    ok, err = _verify_recaptcha_token(token, action=str(app.config.get("FORM_RECAPTCHA_ACTION", "form_submit")))
    if ok:
        return None
    return err or _("Captcha validation failed.")


def _has_any_request_value(*keys: str) -> bool:
    for k in keys:
        v = (request.values.get(k) or "").strip()
        if v:
            return True
    return False


def _verify_recaptcha_token(token: str, action: str) -> Tuple[bool, str | None]:
    if not app.config.get("SECURITY_RECAPTCHA_ENABLED"):
        return True, None

    if not token:
        return False, _("Captcha token is missing.")

    provider = (app.config.get("SECURITY_RECAPTCHA_PROVIDER") or "standard").lower()
    if provider not in {"standard", "enterprise"}:
        provider = "standard"
    min_score = float(app.config.get("SECURITY_RECAPTCHA_MIN_SCORE", 0.5))

    try:
        if provider == "enterprise":
            api_key = app.config.get("SECURITY_RECAPTCHA_API_KEY")
            project = app.config.get("SECURITY_RECAPTCHA_ENTERPRISE_PROJECT")
            site_key = app.config.get("SECURITY_RECAPTCHA_SITE_KEY")
            if not (api_key and project and site_key):
                return False, _("reCAPTCHA Enterprise is not configured.")

            endpoint = f"https://recaptchaenterprise.googleapis.com/v1/projects/{project}/assessments?key={api_key}"
            payload = {
                "event": {
                    "token": token,
                    "siteKey": site_key,
                    "expectedAction": action,
                    "userIpAddress": _client_ip(),
                }
            }
            resp = requests.post(endpoint, json=payload, timeout=4)
            data = resp.json() if resp.ok else {}
            token_props = data.get("tokenProperties") or {}
            risk = data.get("riskAnalysis") or {}
            if not token_props.get("valid"):
                return False, _("Captcha validation failed.")
            if token_props.get("action") and token_props.get("action") != action:
                return False, _("Captcha action mismatch.")
            score = float(risk.get("score") or 0.0)
            if score < min_score:
                return False, _("Captcha score is too low.")
            return True, None

        secret = app.config.get("SECURITY_RECAPTCHA_SECRET_KEY")
        if not secret:
            return False, _("reCAPTCHA is not configured.")
        resp = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={
                "secret": secret,
                "response": token,
                "remoteip": _client_ip(),
            },
            timeout=4,
        )
        data = resp.json() if resp.ok else {}
        if not data.get("success"):
            return False, _("Captcha validation failed.")
        if data.get("action") and data.get("action") != action:
            return False, _("Captcha action mismatch.")
        score = float(data.get("score") or 0.0)
        if score < min_score:
            return False, _("Captcha score is too low.")
        return True, None
    except Exception:
        return False, _("Captcha verification is temporarily unavailable.")


# ---------- WHOIS ----------
@app.route("/whois", methods=["GET", "POST"])
def whois_lookup():
    query = (request.args.get("query") or request.args.get("q") or request.form.get("q") or "").strip()
    data = None
    error = None
    permalink = None

    if not query:
        return render_template("whois.html", result=None, error=None, query=query, permalink=None)

    captcha_error = _verify_form_recaptcha_if_needed()
    if captcha_error:
        return render_template("whois.html", result=None, error=captcha_error, query=query, permalink=None)

    rate_error = _tool_rate_limited("whois")
    if rate_error:
        return render_template("whois.html", result=None, error=rate_error, query=query, permalink=None)

    try:
        q, err = _normalize_domain_query(query)
        if err:
            raise ValueError(err)

        def _compute_whois():
            base: Dict[str, object] = {}
            maybe_text = _whois_call(["whois", "-H", q], timeout=12)
            try:
                w = whois.whois(q)
                _merge_whois_dict(base, _whois_object_to_dict(w))
            except Exception:
                pass

            if not maybe_text:
                txt = base.get("text")
                if isinstance(txt, str) and txt.strip():
                    maybe_text = txt
                elif isinstance(txt, (list, tuple)):
                    joined = "\n".join(str(x) for x in txt if x)
                    if joined.strip():
                        maybe_text = joined

            if maybe_text:
                _merge_whois_dict(base, _parse_ru_whois_text(maybe_text))
                _merge_whois_dict(base, parse_whois_text(q, maybe_text))
                _merge_whois_dict(base, _extract_whois_core_fields_from_text(maybe_text))

            return _finalize_whois_summary(base, q)

        cache_key = f"cache:whois:{q}"
        ttl = 300  # 5 минут
        data = cache_json(cache_key, ttl, _compute_whois)

        hid = save_history("whois", q, data)
        if data:
            _track_domain_for_seo(q)
        permalink = url_for("history_view", kind="whois", hid=hid, _external=True) if hid else None

    except ValueError as ve:
        error = str(ve)
    except Exception:
        app.logger.exception("WHOIS error for %s", query)
        error = _("Unexpected error during WHOIS lookup.")

    affiliate_domain = (data or {}).get("domain_name") if isinstance(data, dict) else None
    affiliate_domain = affiliate_domain or _extract_affiliate_domain(query, "whois")
    domain_availability = None
    whois_expiry_urgency = None
    if data and not error:
        domain_availability = _evaluate_domain_availability(
            affiliate_domain or query,
            whois_data=data if isinstance(data, dict) else None,
        )
        whois_expiry_urgency = _build_whois_expiry_urgency(
            data if isinstance(data, dict) else None,
            domain=affiliate_domain or query,
        )
    return render_template(
        "whois.html",
        result=data,
        error=error,
        query=query,
        permalink=permalink,
        domain_availability=domain_availability,
        whois_expiry_urgency=whois_expiry_urgency,
        **_affiliate_actions_for_domain(affiliate_domain or ""),
    )

# ---------- GEO ----------
@app.route("/geo", methods=["GET", "POST"])
def geo_lookup():
    result: Optional[Dict] = None
    error: Optional[str] = None
    query = None
    permalink = None

    if request.method == "POST" or (request.method == "GET" and request.args.get("query")):
        query = (request.form.get("query") or request.args.get("query") or "").strip()
        captcha_error = _verify_form_recaptcha_if_needed()
        if captcha_error:
            return render_template('geo.html', result=None, error=captcha_error, query=(query or ''), permalink=None)
        rate_error = _tool_rate_limited("geo")
        if rate_error:
            return render_template('geo.html', result=None, error=rate_error, query=(query or ''), permalink=None)
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
            if result:
                _track_domain_for_seo(query)
            permalink = url_for("history_view", kind="geo", hid=hid, _external=True) if hid else None

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
        captcha_error = _verify_form_recaptcha_if_needed()
        if captcha_error:
            return render_template("reverse.html", result=None, error=captcha_error, query=query, permalink=None)
        rate_error = _tool_rate_limited("reverse")
        if rate_error:
            return render_template("reverse.html", result=None, error=rate_error, query=query, permalink=None)
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
                _track_domain_for_seo(host_ascii)

            hid = save_history("reverse", query, result)
            permalink = url_for("history_view", kind="reverse", hid=hid, _external=True) if hid else None

        except ValueError as ve:
            error = str(ve)
        except Exception:
            app.logger.exception("Reverse lookup error")
            error = _("An unexpected error occurred during reverse lookup.")

    return render_template("reverse.html", result=result, error=error, query=query, permalink=permalink)


@app.route('/security', methods=['GET', 'POST'])
def security_tools():
    def _security_value(name: str) -> str:
        # On POST, prefer submitted form fields over query-string values from
        # the current URL (for example /security?host=&ports=). Otherwise empty
        # query params can shadow the user's actual form input and the page just
        # re-renders, which looks like a blink with no result.
        if request.method == 'POST' and name in request.form:
            return (request.form.get(name) or '').strip()
        return (request.args.get(name) or '').strip()

    host = _security_value('host')
    ports_raw = _security_value('ports')
    scan_target = _security_value('scan').lower()
    wp_url_raw = _security_value('wp_url')
    job_id = _security_value('job')

    active_scan = 'wp' if scan_target == 'wp' else 'ports'
    port_result = None
    port_error = None
    wp_result = None
    wp_error = None
    security_error = None
    permalink = None
    job_status = None

    recaptcha_ready, recaptcha_setup_error = _recaptcha_setup_status()

    # Poll/render existing job
    job = None
    if job_id:
        if not _is_valid_security_job_id(job_id):
            security_error = _('Invalid scan job id.')
            job_id = ''
        else:
            job = _load_security_job(job_id)
        if job:
            job_status = str(job.get('status') or '').lower() or 'queued'
            active_scan = 'wp' if str(job.get('kind')) == 'wp' else 'ports'
            payload = job.get('payload') or {}
            host = host or str(payload.get('host') or '')
            ports_raw = ports_raw or str(payload.get('ports_raw') or '')
            wp_url_raw = wp_url_raw or str(payload.get('wp_url_raw') or '')
            if job_status == 'done':
                if active_scan == 'ports':
                    port_result = job.get('result')
                else:
                    wp_result = job.get('result')
                permalink = job.get('permalink')
            elif job_status == 'failed':
                if active_scan == 'ports':
                    port_error = job.get('error') or _('Scan failed.')
                else:
                    wp_error = job.get('error') or _('Scan failed.')
        elif job_id:
            security_error = _('Scan job was not found. Please start the check again.')
            job_id = ''

    # Submit new async job
    if request.method == 'POST' and not job_id:
        if active_scan == 'ports' and not host:
            port_error = _('Please enter a host or IP.')
        elif active_scan == 'wp' and not wp_url_raw:
            wp_error = _('Please enter a site URL.')
        elif len(host) > SECURITY_MAX_HOST_LEN:
            security_error = _('Host is too long.')
        elif len(ports_raw) > SECURITY_MAX_PORTS_RAW_LEN:
            security_error = _('Ports list is too long.')
        elif len(wp_url_raw) > SECURITY_MAX_WP_URL_LEN:
            security_error = _('WordPress URL is too long.')
        elif (not recaptcha_ready) and bool(app.config.get('SECURITY_RECAPTCHA_ENABLED')):
            security_error = recaptcha_setup_error or _('reCAPTCHA is not configured.')
        else:
            ip = _client_ip()
            endpoint_name = f"security:{active_scan}"
            if _security_is_rate_limited(ip, int(app.config.get('SECURITY_RATE_LIMIT_PER_MIN', 15))):
                _security_metric_inc(endpoint_name, 'blocked')
                security_error = _('Too many security scan requests. Please retry in a minute.')
            else:
                _security_metric_inc(endpoint_name, 'allowed')
                recaptcha_token = (request.values.get('recaptcha_token') or '').strip()
                ok, recaptcha_err = _verify_recaptcha_token(recaptcha_token, action=str(app.config.get('SECURITY_RECAPTCHA_ACTION', 'security_scan')))
                if not ok:
                    security_error = recaptcha_err or _('Captcha validation failed.')
                else:
                    job_id = uuid.uuid4().hex
                    payload = {
                        'host': host,
                        'ports_raw': ports_raw,
                        'wp_url_raw': wp_url_raw,
                    }
                    saved = _save_security_job(job_id, {
                        'status': 'queued',
                        'kind': active_scan,
                        'payload': payload,
                        'created_ts': int(time.time()),
                        'result': None,
                        'error': None,
                        'error_code': None,
                        'duration_ms': None,
                        'permalink': None,
                    })
                    if not saved:
                        security_error = _('Scan storage is temporarily unavailable. Please retry later.')
                        job_id = ''
                    else:
                        try:
                            _SECURITY_ASYNC_POOL.submit(_execute_security_job, job_id, active_scan, payload)
                        except Exception:
                            app.logger.exception('Security scan queue submit failed: kind=%s', active_scan)
                            _save_security_job(job_id, {
                                'status': 'failed',
                                'kind': active_scan,
                                'payload': payload,
                                'created_ts': int(time.time()),
                                'finished_ts': int(time.time()),
                                'result': None,
                                'error': _tr_no_req('Internal scan error. Please retry later.'),
                                'error_code': 'internal_error',
                                'duration_ms': 0,
                                'permalink': None,
                            })
                            security_error = _('Could not start scan job. Please retry.')
                            job_id = ''
                        else:
                            return redirect(url_for('security_tools', scan=active_scan, job=job_id, host=host, ports=ports_raw, wp_url=wp_url_raw))

    return render_template(
        'security.html',
        host=host,
        ports_raw=ports_raw,
        port_result=port_result,
        port_error=port_error,
        wp_url_raw=wp_url_raw,
        wp_result=wp_result,
        wp_error=wp_error,
        security_error=security_error,
        active_scan=active_scan,
        recaptcha_enabled=bool(app.config.get('SECURITY_RECAPTCHA_ENABLED')),
        recaptcha_site_key=(app.config.get('SECURITY_RECAPTCHA_SITE_KEY') or ''),
        recaptcha_provider=(app.config.get('SECURITY_RECAPTCHA_PROVIDER') or 'standard'),
        recaptcha_action=(app.config.get('SECURITY_RECAPTCHA_ACTION') or 'security_scan'),
        recaptcha_ready=recaptcha_ready,
        recaptcha_setup_error=recaptcha_setup_error,
        permalink=permalink,
        common_ports=COMMON_SAFE_PORTS[:20],
        job_id=job_id,
        job_status=job_status,
    )


@app.get('/security/jobs/<job_id>')
def security_job_status(job_id: str):
    if not _is_valid_security_job_id(job_id):
        return jsonify(ok=False, error='invalid_job_id'), 400

    job = _load_security_job(job_id)
    if not job:
        return jsonify(ok=False, error='not_found'), 404
    return jsonify(
        ok=True,
        id=job_id,
        status=job.get('status') or 'queued',
        kind=job.get('kind') or 'ports',
        error=job.get('error'),
        error_code=job.get('error_code'),
        duration_ms=job.get('duration_ms'),
        permalink=job.get('permalink'),
        updated_ts=job.get('updated_ts'),
    ), 200


@app.get('/security/metrics')
def security_metrics():
    if not bool(app.config.get('SECURITY_METRICS_PUBLIC')):
        return jsonify(ok=False, error='disabled'), 404
    now_utc = datetime.now(timezone.utc)
    day = now_utc.strftime('%Y%m%d')
    minute = now_utc.strftime('%Y%m%d%H%M')
    day_key = f"dt:metrics:security_rate:day:{day}"
    minute_key = f"dt:metrics:security_rate:min:{minute}"
    data_day: Dict[str, str] = {}
    data_min: Dict[str, str] = {}
    try:
        data_day = r.hgetall(day_key) or {}
        data_min = r.hgetall(minute_key) or {}
    except Exception:
        pass
    return jsonify(ok=True, day=data_day, current_minute=data_min), 200


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
        elif kind == "security":
            if q.startswith("ports:"):
                host_part = q.split(":", 2)[1] if ":" in q else ""
                ports_part = q.split(":", 2)[2] if q.count(":") >= 2 else ""
                repeat_url = url_for("security_tools", host=host_part, ports=ports_part, scan="ports")
            elif q.startswith("wp:"):
                wp_target = q.split(":", 1)[1] if ":" in q else ""
                repeat_url = url_for("security_tools", wp_url=wp_target, scan="wp")
            else:
                repeat_url = url_for("security_tools")
        elif kind == "report":
            repeat_url = url_for("domain_report", q=q)
        else:
            repeat_url = None

        landing_url = None
        whois_landing_url = None
        affiliate_domain = _extract_affiliate_domain(q, kind)
        if affiliate_domain:
            landing_url = url_for("lookup_domain", domain=affiliate_domain)
            whois_landing_url = url_for("lookup_whois_domain", domain=affiliate_domain)

        item = {
            "id": hid,
            "kind": kind,
            "query": q,
            "ts": doc.get("ts"),
            "view_url": view_url,
            "repeat_url": repeat_url,
            "landing_url": landing_url,
            "whois_landing_url": whois_landing_url,
        }
        item.update(_affiliate_actions_for_domain(affiliate_domain or ""))
        items.append(item)

    return render_template("history.html", items=items, history_error=history_error, seo_noindex=True)

@app.route("/history/<kind>/<hid>")
def history_view(kind: str, hid: str):
    if kind not in {"dns", "whois", "geo", "reverse", "security", "report"}:
        abort(404)
    doc = load_history(kind, hid)
    if not doc:
        abort(404)
    q = doc.get("query")
    res = doc.get("result")
    permalink = request.url
    _history_seo = {"seo_noindex": True}
    if kind == "dns":
        return render_template(
            "dns.html",
            result=res,
            error=None,
            query=q,
            permalink=permalink,
            **_affiliate_actions_for_domain(_extract_affiliate_domain(q or "", "dns") or ""),
            **_history_seo,
        )
    if kind == "whois":
        whois_domain = (res or {}).get("domain_name") if isinstance(res, dict) else None
        whois_domain = whois_domain or _extract_affiliate_domain(q or "", "whois")
        return render_template(
            "whois.html",
            result=res,
            error=None,
            query=q,
            permalink=permalink,
            **_affiliate_actions_for_domain(whois_domain or ""),
            **_history_seo,
        )
    if kind == "geo":
        return render_template("geo.html", result=res, error=None, query=q, permalink=permalink, **_history_seo)
    if kind == "reverse":
        return render_template("reverse.html", result=res, error=None, query=q, permalink=permalink, **_history_seo)
    if kind == "security":
        return render_template(
            "security.html",
            host=(res or {}).get("host", ""),
            ports_raw=",".join(str(p) for p in ((res or {}).get("ports") or [])),
            port_result=res if isinstance(res, dict) and "rows" in res else None,
            port_error=None,
            wp_url_raw=(res or {}).get("target_url", "") if isinstance(res, dict) else "",
            wp_result=res if isinstance(res, dict) and "is_wordpress" in res else None,
            wp_error=None,
            security_error=None,
            active_scan='wp' if isinstance(res, dict) and "is_wordpress" in res else 'ports',
            recaptcha_enabled=bool(app.config.get('SECURITY_RECAPTCHA_ENABLED')),
            recaptcha_site_key=(app.config.get('SECURITY_RECAPTCHA_SITE_KEY') or ''),
            recaptcha_provider=(app.config.get('SECURITY_RECAPTCHA_PROVIDER') or 'standard'),
            recaptcha_action=(app.config.get('SECURITY_RECAPTCHA_ACTION') or 'security_scan'),
            recaptcha_ready=_recaptcha_setup_status()[0],
            recaptcha_setup_error=_recaptcha_setup_status()[1],
            permalink=permalink,
            common_ports=COMMON_SAFE_PORTS[:20],
            **_history_seo,
        )
    if kind == "report":
        report_obj = dict(res) if isinstance(res, dict) else None
        if report_obj:
            report_obj["permalink"] = permalink
        return render_template(
            "report.html",
            query=q,
            report=report_obj,
            reports=[report_obj] if report_obj else [],
            error=None,
            job_status=None,
            job_id="",
            batch_max=REPORT_MAX_BATCH,
            **_history_seo,
        )
    abort(404)

# ---------- Экспорт ----------
@app.get("/export/<kind>/<hid>.<fmt>")
def export_result(kind: str, hid: str, fmt: str):
    if kind not in {"dns", "whois", "geo", "reverse", "security", "report"}:
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
        elif kind == "security":
            if "rows" in result:
                writer.writerow(["target","ip","port","state"])
                for row in (result.get("rows") or []):
                    writer.writerow([result.get("host", ""), result.get("ip", ""), row.get("port", ""), row.get("state", "")])
            else:
                writer.writerow(["target_url","target_ip","check","value"])
                for key in ("is_wordpress", "homepage_status", "wp_login_status", "xmlrpc_enabled", "readme_exposed", "wp_json_enabled", "uploads_listing"):
                    writer.writerow([result.get("target_url", ""), result.get("target_ip", ""), key, result.get(key, "")])
        elif kind == "report":
            writer.writerow(["domain","section","field","value"])
            domain = result.get("domain") or result.get("input") or ""
            for section in ("dns", "whois", "geo", "reverse"):
                block = result.get(section) or {}
                if isinstance(block, dict):
                    for field, value in block.items():
                        if isinstance(value, (dict, list, tuple)):
                            value = json.dumps(value, ensure_ascii=False)
                        writer.writerow([domain, section, field, value])
        data = si.getvalue()
        return Response(data, mimetype="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{fn}"'})

    abort(404)

# ---------- IndexNow key (must stay after robots.txt / sitemap.xml) ----------
@app.get("/<indexnow_key>.txt")
def indexnow_key_file(indexnow_key: str):
    expected = (app.config.get("INDEXNOW_KEY") or "").strip()
    if not expected or indexnow_key != expected:
        abort(404)
    return Response(f"{expected}\n", mimetype="text/plain")


# ---------- ЧПУ для WHOIS ----------
@app.route("/whois/<path:domain>", methods=["GET", "POST"])
def whois_domain_lookup(domain):
    clean, ascii_domain = _sanitize_lookup_domain(domain)
    if not clean:
        abort(404)
    display = _seo_display_domain(clean, ascii_domain)
    return redirect(url_for("lookup_whois_domain", domain=display), code=301)

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

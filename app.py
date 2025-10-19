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
from datetime import datetime
from typing import Optional, Dict, List, Tuple

import redis
import whois
from whois.exceptions import WhoisError
import dns.resolver
import dns.exception
from ipwhois import IPWhois
import idna
import ipaddress

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
from werkzeug.middleware.proxy_fix import ProxyFix

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
    # TLDs (включая IDN и транслит-зоны)
    TLD_LIST=os.environ.get(
        "TLD_LIST",
        "ru,su,рф,рус,онлайн,сайт,москва,дети,ком,нет,орг,com,net,org,info,pro,xyz,site,online,store,app,io,ai,co,me,blog",
    ).split(","),
)

# Зоны, в которых разумно показывать кириллические метки (IDN)
IDN_READY_TLDS = {
    "рф", "рус", "онлайн", "сайт", "москва", "дети",
    "ком", "нет", "орг",
    "com", "net", "org", "info", "pro", "site", "online", "store",
}

# Redis
app.config.setdefault("REDIS_URL", os.getenv("REDIS_URL", "redis://127.0.0.1:6379/3"))
r = redis.from_url(app.config["REDIS_URL"], decode_responses=True)
HIST_NS = "dt:history"
HIST_ZSET = "dt:history:index"
HIST_LIMIT = 5000

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

# -------------------------------------------------
# Jinja helpers
# -------------------------------------------------
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
    hid = make_id(kind, query)
    key = f"{HIST_NS}:{kind}:{hid}"
    ts = int(time.time())

    if not r.exists(key):
        doc = {"id": hid, "kind": kind, "query": query, "result": result, "ts": ts}
        r.hset(key, mapping={"json": json.dumps(doc, ensure_ascii=False)})
        r.zadd(HIST_ZSET, {f"{kind}:{hid}": ts})

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

def cache_json(key: str, ttl: int, compute):
    """Простой JSON-кэш поверх Redis."""
    try:
        raw = r.get(key)
        if raw:
            return json.loads(raw)
    except Exception:
        pass
    val = compute()
    try:
        r.setex(key, ttl, json.dumps(val, ensure_ascii=False))
    except Exception:
        pass
    return val

def _normalize_domain_query(value: str):
    """Возвращает (punycode_ascii, None) либо (None, 'ошибка')."""
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

# --- Минимальный парсер текста WHOIS (generic) -------------------------------
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
    data: Dict[str, object] = {"domain_name": domain, "text": text or ""}
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

    nss = [ns.strip().rstrip(".").upper() for ns in WHOIS_PATTERNS["name_server"].findall(text)]
    if nss:
        data["name_servers"] = sorted(set(nss))

    m = WHOIS_PATTERNS["org"].search(text)
    if m: data["org"] = m.group(2).strip()

    m = WHOIS_PATTERNS["country"].search(text)
    if m: data["country"] = m.group(2).upper()

    return data

# --- RU/TCI WHOIS parser ------------------------------------------------------
import re as _re
def _parse_ru_whois_text(text: str) -> dict:
    """
    Быстрый парсер ответа whois.tcinet.ru (ru/su/рф).
    """
    out: dict = {}
    if not text:
        return out

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue

        m = _re.match(r"last updated on\s+(\S+)", line, _re.I)
        if m:
            out["updated_date"] = m.group(1)
            continue

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
        return (out.stdout or "").strip()
    except Exception:
        return ""

def _whois_port43(server: str, domain: str, timeout: int = 10) -> str:
    """
    Прямой WHOIS по TCP/43 — на случай, когда системная утилита вернула пусто.
    """
    try:
        with socket.create_connection((server, 43), timeout=timeout) as s:
            s.settimeout(timeout)
            q = (domain + "\r\n").encode("utf-8", errors="ignore")
            s.sendall(q)
            chunks = []
            while True:
                buf = s.recv(4096)
                if not buf:
                    break
                chunks.append(buf)
        text = b"".join(chunks).decode("utf-8", errors="replace")
        return text.strip()
    except Exception:
        return ""

def _extract_referral(text: str) -> Optional[str]:
    """
    Ищем сервер, на который ссылаются: 'refer:' (IANA), 'whois:', 'ReferralServer:'.
    """
    for pat in (
        r"(?im)^\s*refer:\s*([^\s]+)",
        r"(?im)^\s*whois:\s*([^\s]+)",
        r"(?im)^\s*ReferralServer:\s*whois://([^\s:/]+)",
    ):
        m = re.search(pat, text)
        if m:
            return m.group(1).strip()
    return None

# --- «Устойчивый» системный WHOIS --------------------------------------------
def run_system_whois(domain: str, timeout: int = 10) -> str:
    """
    Стойкий WHOIS-запрос:
      1) ru/su/рф: пробуем whois.tcinet.ru → whois.ripn.net → whois.nic.ru
         (по 3 попытки; если утилита вернула пусто — дублируем запрос через TCP/43).
      2) затем обычный 'whois <domain>'
      3) затем whois.iana.org; если есть referral — идём туда (сначала утилита, затем TCP/43).
    Возвращаем первый непустой ответ (stripped) либо "".
    """
    d = (domain or "").strip().lower().rstrip(".")
    tld = d.rsplit(".", 1)[-1] if "." in d else d

    # приоритетные сервера для ru/su/рф
    ru_chain: List[str] = ["whois.tcinet.ru", "whois.ripn.net", "whois.nic.ru"]

    candidates: List[Optional[str]] = []
    if tld in ("ru", "su", "xn--p1ai"):
        candidates += ru_chain
    candidates += [None, "whois.iana.org"]  # None => системный без -h

    def _try_one(server: Optional[str]) -> str:
        for attempt in range(3):
            cmd = ["whois"]
            if server:
                cmd += ["-h", server]
            cmd.append(domain)
            text = _whois_call(cmd, timeout)
            if text:
                ref = _extract_referral(text)
                if ref and ref.lower() != (server or "").lower():
                    ref_text = _whois_call(["whois", "-h", ref, domain], timeout)
                    if not ref_text:
                        ref_text = _whois_port43(ref, domain, timeout)
                    if ref_text:
                        return ref_text.strip()
                return text.strip()

            # утилита вернула пусто — если знаем сервер, попробуем порт-43
            if server:
                raw43 = _whois_port43(server, domain, timeout)
                if raw43:
                    return raw43.strip()

            time.sleep(0.25)  # маленькая пауза между попытками
        return ""

    # основной цикл по кандидатам
    for srv in candidates:
        txt = _try_one(srv)
        if txt:
            return txt

    # финальный fallback: пройти ru-цепочку по порт-43 напрямую
    if tld in ("ru", "su", "xn--p1ai"):
        for srv in ru_chain:
            txt = _whois_port43(srv, domain, timeout)
            if txt:
                return txt.strip()

    return ""

# --- Транслитерация для подсказок --------------------------------------------
RU_MAP = str.maketrans({
    "а":"a","б":"b","в":"v","г":"g","д":"d","е":"e","ё":"e","ж":"zh","з":"z","и":"i","й":"y",
    "к":"k","л":"l","м":"m","н":"n","о":"o","п":"p","р":"r","с":"s","т":"t","у":"u","ф":"f",
    "х":"h","ц":"c","ч":"ch","ш":"sh","щ":"sch","ъ":"","ы":"y","ь":"","э":"e","ю":"yu","я":"ya"
})
def _translit_ru(label: str) -> str:
    return "".join((ch.translate(RU_MAP) if ch in RU_MAP else ch) for ch in label.lower())

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
        url_for("domain_search", _external=True),
        url_for("history_list", _external=True),
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
    """
    Нормализация метки:
    - разрешаем Unicode (IDN),
    - пробелы/подчёркивания -> дефис,
    - оставляем только буквы/цифры/дефис,
    - длина <= 63.
    """
    label = (label or "").strip()
    label = re.sub(r"[\s_]+", "-", label)
    label = "".join(ch for ch in label if ch.isalnum() or ch == "-")
    label = re.sub(r"-{2,}", "-", label).strip("-")
    if not label:
        raise ValueError(_("Введите корректное имя"))
    if len(label) > 63:
        label = label[:63].rstrip("-")
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
    """
    Подбор имён <label>.<tld>.
    Для кириллических меток показываем только зоны из IDN_READY_TLDS.
    Проверяем доступность через DNS/WHOIS. Везде используем punycode.
    """
    out = []
    is_idn_label = not label.isascii()

    for t in tlds:
        t = t.strip().lstrip(".")
        if not t:
            continue
        if is_idn_label and t not in IDN_READY_TLDS:
            continue

        fqdn_unicode = f"{label}.{t}"
        try:
            puny = idna.encode(fqdn_unicode, uts46=True).decode("ascii")
            avail_dns = _is_available_via_dns(puny)
            avail = _is_available_via_whois(puny) if avail_dns else False
            out.append({"fqdn": fqdn_unicode, "puny": puny, "available": bool(avail), "error": None})
        except Exception as e:
            out.append({"fqdn": fqdn_unicode, "puny": None, "available": False, "error": str(e) or "IDN error"})
    return out

@app.route("/domains", methods=["GET", "POST"])
def domain_search():
    query = (request.args.get("query") or request.args.get("q") or request.form.get("q") or "").strip()
    items = []
    error = None
    suggestions = []

    if query:
        try:
            if "." in query:
                query = query.split(".")[0]
            label = _normalize_label(query)
            if any("а" <= ch <= "я" or ch == "ё" for ch in label):
                suggestions = sorted(set([
                    _translit_ru(label),
                    _translit_ru(label).replace("sch", "sh").replace("ya", "a"),
                ]))
            items = _check_candidates(label, app.config.get("TLD_LIST", []))
        except Exception as e:
            error = str(e)

    return render_template(
        "domains.html",
        q=query,
        items=items,
        error=error,
        suggestions=suggestions,
        buy_base=app.config.get("AFFILIATE_BUY_BASE"),
    )

# ---------- WHOIS ----------
@app.route("/whois", methods=["GET", "POST"])
def whois_lookup():
    data: Optional[Dict] = None
    error: Optional[str] = None
    query = None
    permalink = None

    if request.method == "POST" or (request.method == "GET" and request.args.get("query")):
        raw = (request.form.get("query") or request.args.get("query") or "").strip()
        query, err = _normalize_domain_query(raw)
        if err:
            error = err
            return render_template("whois.html", result=None, error=error, query=(query or raw), permalink=None)

        try:
            # IP?
            try:
                ipaddress.ip_address(query)
                is_ip = True
            except ValueError:
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
                # ДОМЕН
                validate_domain(query)

                def _compute_whois():
                    base: Dict[str, object] = {}
                    whois_ok = False
                    whois_err: Optional[str] = None
                    # 1) python-whois
                    try:
                        w = whois.whois(query)
                        base = {
                            k: (", ".join(v) if isinstance(v, (list, tuple)) else str(v))
                            for k, v in w.__dict__.items()
                            if not k.startswith("_")
                        }
                        whois_ok = True
                    except Exception as e:
                        whois_err = str(e)

                    # 2) устойчивый системный whois
                    if not whois_ok:
                        text = run_system_whois(query, timeout=12)
                        if not text:
                            raise RuntimeError(whois_err or "whois failed without output")

                        parsed = _parse_ru_whois_text(text) or parse_whois_text(query, text)
                        base = parsed
                        base.setdefault("text", text)

                    # если в base только raw-текст без ключевых полей — ещё раз попробуем парсить
                    maybe_text = str(base.get("text") or base.get("raw") or "")
                    important = any(base.get(k) for k in ("registrar", "creation_date", "expiration_date", "status", "name_servers"))
                    if maybe_text and not important:
                        parsed = _parse_ru_whois_text(maybe_text) or parse_whois_text(query, maybe_text)
                        base.update(parsed)

                    # домен для отображения
                    base.setdefault("domain_name", query)
                    du = _to_unicode(query)
                    if du and du != query:
                        base["domain_unicode"] = du
                    return base

                # кэшируем whois на короткое время, чтобы не упереться в лимиты
                cache_key = f"cache:whois:{query}"
                ttl = 300  # 5 минут
                data = cache_json(cache_key, ttl, _compute_whois)

            hid = save_history("whois", query, data)
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
            except ValueError:
                ip = socket.gethostbyname(query)

            def _compute_geo():
                app.logger.info(f"Geo lookup for: {ip}")
                lookup = IPWhois(ip).lookup_rdap()
                asn = lookup.get("asn_description") or "N/A"
                country_code = lookup.get("asn_country_code") or "N/A"
                country_name = country_code
                try:
                    geolocator = Nominatim(user_agent="domaintools-geo")
                    geo = geolocator.geocode(country_code, timeout=5)
                    if geo and geo.address:
                        country_name = geo.address
                except Exception:
                    pass
                return {
                    "ip": ip,
                    "asn": asn,
                    "country_code": country_code,
                    "country_name": country_name,
                }

            result = cache_json(f"cache:geo:{ip}", 900, _compute_geo)
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
    keys = r.zrevrange(HIST_ZSET, 0, 49)
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

# ---------- Экспорт ----------
@app.get("/export/<kind>/<hid>.<fmt>")
def export_result(kind: str, hid: str, fmt: str):
    if kind not in {"dns", "whois", "geo"}:
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
        data = si.getvalue()
        return Response(data, mimetype="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{fn}"'})

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

# ЧПУ для /whois/<domain>
@app.route("/whois/<path:domain>", methods=["GET", "POST"])
def whois_domain_lookup(domain):
    q = (domain or '').strip().rstrip('.').lower()
    return redirect(url_for('whois_lookup', query=q), code=302)

# app.py
import os
import re
import socket
import logging
from typing import Optional, Dict, List

from flask import Flask, render_template, request, jsonify
from flask_babel import Babel, gettext as _, get_locale as babel_get_locale
from flask_caching import Cache

import whois
import dns.resolver
import dns.exception
from ipwhois import IPWhois
from geopy.geocoders import Nominatim

# ----------------------
# App & config
# ----------------------
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

# Сделаем функцию доступной в Jinja: {{ get_locale() }}
@app.context_processor
def jinja_globals():
    return {"get_locale": lambda: str(babel_get_locale())}

# ----------------------
# Logging
# ----------------------
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
app.logger.setLevel(logging.INFO)
app.logger.addHandler(handler)

# ----------------------
# Helpers
# ----------------------
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


# ----------------------
# Routes
# ----------------------
@app.route("/health")
def health():
    return jsonify(status="ok"), 200


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dns", methods=["GET", "POST"])
def dns_lookup():
    result: Optional[Dict[str, List[str]]] = None
    error: Optional[str] = None

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
        except ValueError as ve:
            error = str(ve)
        except dns.exception.DNSException as de:
            error = _("DNS error: ") + str(de)
        except Exception:
            app.logger.exception("Unexpected DNS error")
            error = _("Unexpected error during DNS lookup.")

    return render_template("dns.html", result=result, error=error)


@app.route("/whois", methods=["GET", "POST"])
def whois_lookup():
    data: Optional[Dict] = None
    error: Optional[str] = None

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
        except ValueError as ve:
            error = str(ve)
        except Exception:
            app.logger.exception("WHOIS error")
            error = _("Unexpected error during WHOIS lookup.")

    return render_template("whois.html", result=data, error=error)


@app.route("/geo", methods=["GET", "POST"])
def geo_lookup():
    result: Optional[Dict] = None
    error: Optional[str] = None

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
        except socket.gaierror:
            error = _("Invalid IP or domain.")
        except Exception:
            app.logger.exception("GeoIP error")
            error = _("An error occurred during GeoIP lookup.")

    return render_template("geo.html", result=result, error=error)


# ----------------------
# Error handlers
# ----------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("errors/404.html"), 404


@app.errorhandler(500)
def server_error(e):
    app.logger.exception("Internal Server Error")
    return render_template("errors/500.html"), 500


# ----------------------
# Dev entry
# ----------------------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)

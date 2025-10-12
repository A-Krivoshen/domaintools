from flask import Flask, render_template, request, url_for, session, redirect
from flask_babel import Babel, _
from flask_bootstrap import Bootstrap5
import whois
import dns.resolver
from ipwhois import IPWhois
import socket
import logging
import re
from typing import Optional, Dict
from geopy.geocoders import Nominatim  # Для GeoIP
from flask import Blueprint

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['DEBUG'] = True
app.config['BABEL_DEFAULT_LOCALE'] = 'en'
app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations'

babel = Babel(app)
bootstrap = Bootstrap5(app)

# Logging
logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')
app.logger.setLevel(logging.DEBUG)

# Языки
@babel.localeselector
def get_locale():
    return session.get('lang', 'en')

@app.route('/set_lang/<lang>')
def set_lang(lang):
    if lang in ['en', 'ru']:
        session['lang'] = lang
    return redirect(request.referrer or url_for('main.index'))

# Валидация
def validate_domain(domain: str) -> None:
    if not re.match(r'^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$', domain):
        raise ValueError(_("Invalid domain format"))

# Main Blueprint
main_bp = Blueprint('main', __name__)

@main_bp.route('/', methods=['GET', 'POST'])
def index():
    result: Optional[Dict] = None
    if request.method == 'POST':
        domain = request.form.get('domain').strip()
        if domain:
            try:
                validate_domain(domain)
                app.logger.info(f"Checking domain: {domain}")
                w = whois.whois(domain)
                available = w.domain_name is None or not w.status or w.status == []
                result = {
                    'domain': domain,
                    'available': available,
                    'whois': w if not available else None
                }
            except ValueError as ve:
                app.logger.error(f"Validation error: {ve}")
                result = {'error': str(ve)}
            except whois.exceptions.WhoisCommandFailed as wcf:
                app.logger.error(f"Whois command failed: {wcf}")
                result = {'error': _('WHOIS query failed (check if whois installed or rate limit).')}
            except whois.exceptions.UnknownTld as ut:
                app.logger.error(f"Unknown TLD: {ut}")
                result = {'error': _('Unsupported domain TLD.')}
            except Exception as e:
                app.logger.error(f"Unexpected error: {e}", exc_info=True)
                result = {'error': _('An unexpected error occurred.')}
    return render_template('index.html', result=result)

@main_bp.route('/whois/<domain>', endpoint='whois')
def whois_detail(domain: str):
    try:
        w = whois.whois(domain)
        return render_template('whois.html', whois_data=w)
    except Exception as e:
        app.logger.error(f"WHOIS detail error: {e}", exc_info=True)
        return render_template('error.html', message=_("Error fetching WHOIS."))

@main_bp.route('/dns', methods=['GET', 'POST'])
def dns_lookup():
    result: Optional[Dict] = None
    error: Optional[str] = None
    if request.method == 'POST':
        domain = request.form.get('domain').strip()
        if domain:
            try:
                validate_domain(domain)
                app.logger.info(f"DNS lookup for: {domain}")
                result = {}
                for qtype in ['A', 'MX', 'NS', 'TXT']:
                    answers = dns.resolver.resolve(domain, qtype)
                    result[qtype] = [r.to_text() for r in answers]
            except dns.resolver.NoAnswer:
                error = _("No DNS records found for this type.")
            except dns.resolver.NXDOMAIN:
                error = _("Domain does not exist.")
            except ValueError as ve:
                error = str(ve)
            except Exception as e:
                app.logger.error(f"DNS error: {e}", exc_info=True)
                error = _("An error occurred during DNS lookup.")
    return render_template('dns.html', result=result, error=error)

@main_bp.route('/geo', methods=['GET', 'POST'])
def geo_lookup():
    result: Optional[Dict] = None
    error: Optional[str] = None
    if request.method == 'POST':
        query = request.form.get('query').strip()
        if query:
            try:
                ip = socket.gethostbyname(query) if not query.replace('.', '').isdigit() else query
                lookup = IPWhois(ip).lookup_rdap()
                asn = lookup.get('asn_description', 'N/A')
                country = lookup.get('asn_country_code', 'N/A')
                geolocator = Nominatim(user_agent="domaintools-geo")
                location = geolocator.reverse((lookup.get('network', {}).get('start_address'), lookup.get('network', {}).get('end_address')), timeout=10)
                result = {
                    'ip': ip,
                    'asn': asn,
                    'country': country,
                    'location': location.address if location else 'N/A'
                }
            except socket.gaierror:
                error = _("Invalid IP or domain.")
            except Exception as e:
                app.logger.error(f"GeoIP error: {e}", exc_info=True)
                error = _("An error occurred during GeoIP lookup.")
    return render_template('geo.html', result=result, error=error)

app.register_blueprint(main_bp)

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"500 error: {error}", exc_info=True)
    return render_template('error.html', message=_("Internal Server Error. Check logs.")), 500

if __name__ == '__main__':
    app.run(debug=True)
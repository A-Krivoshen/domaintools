from flask import Flask, render_template, request, url_for
import whois
import dns.resolver
from ipwhois import IPWhois
import socket
import logging
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['DEBUG'] = False  # В prod False; для теста True

# Logging
logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')
app.logger.setLevel(logging.DEBUG)

def validate_domain(domain):
    if not re.match(r'^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$', domain):
        raise ValueError("Invalid domain format")

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        domain = request.form.get('domain').strip()
        if domain:
            try:
                validate_domain(domain)
                app.logger.info(f"Checking domain: {domain}")
                w = whois.whois(domain)
                available = w.domain_name is None or not w.status
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
                result = {'error': 'WHOIS query failed (check if whois installed or rate limit).'}
            except whois.exceptions.UnknownTld as ut:
                app.logger.error(f"Unknown TLD: {ut}")
                result = {'error': 'Unsupported domain TLD.'}
            except Exception as e:
                app.logger.error(f"Unexpected error: {e}", exc_info=True)
                result = {'error': 'An unexpected error occurred.'}
    return render_template('index.html', result=result)

@app.route('/whois/<domain>')
def whois_detail(domain):
    try:
        w = whois.whois(domain)
        return render_template('whois.html', whois_data=w)
    except Exception as e:
        app.logger.error(f"WHOIS detail error: {e}")
        return render_template('error.html', message="Error fetching WHOIS.")

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"500 error: {error}", exc_info=True)
    return render_template('error.html', message="Internal Server Error. Check logs."), 500

# Другие роуты (ip, dns) остаются

if __name__ == '__main__':
    app.run(debug=True)
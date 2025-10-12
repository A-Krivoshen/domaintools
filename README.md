# python.domaintools.site

Flask + Gunicorn + Nginx.

## local run
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
FLASK_ENV=production gunicorn -w 3 -b 127.0.0.1:8000 wsgi:app

## systemd/nginx
Шаблоны в ./deploy. Не коммить реальные сертификаты/секреты.

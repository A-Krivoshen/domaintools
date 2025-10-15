# DomainTools — Home intro patch

This patch:
1) Updates the welcome paragraph on **templates/index.html** to add a **Domains** link
   and inserts an SEO-friendly paragraph under it.
2) Fixes a template link in **templates/dns.html** (`url_for('geo_lookup')` → `url_for('geoip_lookup')`).

## Apply on server

```bash
APPDIR="/var/www/python.domaintools.site/htdocs"  # change if different
unzip domaintools_home_intro_patch.zip -d /tmp
cd /tmp/home_intro_patch
sudo bash apply.sh "$APPDIR"
sudo systemctl restart python-domaintools
```

## Rollback

```bash
APPDIR="/var/www/python.domaintools.site/htdocs"
cd /tmp/home_intro_patch
sudo bash restore.sh "$APPDIR"
sudo systemctl restart python-domaintools
```

The patcher is idempotent and creates timestamped backups.

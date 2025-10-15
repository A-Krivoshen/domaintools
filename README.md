# Домашняя страница — правка приветственного блока

Этот пакет **аккуратно правит только `templates/index.html`**: обновляет приветственный текст, добавляет ссылку на **Domains** и SEO‑абзац. Всё остальное остаётся как есть. Делается бэкап.

## Что меняется
- Фраза _«Перейдите в разделы DNS, WHOIS или GeoIP. Сохранённые результаты доступны в History.»_ заменяется на расширенный блок:
  - Предлагаем начать с **Domains** (подбор доменных имён, проверка доступности, варианты).
  - Остаются ссылки **DNS**, **WHOIS**, **GeoIP**, **History**.
  - Добавляется компактный SEO‑абзац с полезной лексикой (подбор, транслитерация, зоны .ru/.рф/.com и т. д.).

## Установка
```bash
APPDIR="/var/www/python.domaintools.site/htdocs"
sudo bash apply.sh "$APPDIR"
sudo systemctl restart python-domaintools
```

## Откат
```bash
APPDIR="/var/www/python.domaintools.site/htdocs"
sudo bash restore.sh "$APPDIR"
sudo systemctl restart python-domaintools
```

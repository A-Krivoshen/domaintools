# Flask Site Checker Stylish (Blueprint)

Функционал, аналогичный WP Site Checker Stylish, но для Flask.

## Установка

1. Скопируйте папку `flask_site_checker` в ваш проект (рядом с `app.py`).
2. Установите зависимости:
   ```bash
   pip install -r flask_site_checker/requirements.txt
   ```
3. Зарегистрируйте blueprint в вашем приложении Flask:
   ```python
   # app.py (пример)
   from flask import Flask
   from flask_site_checker import site_checker_bp

   app = Flask(__name__)
   app.register_blueprint(site_checker_bp)  # маршрут /site-checker

   if __name__ == "__main__":
       app.run(debug=True)
   ```

4. Если у вас есть базовый шаблон `templates/base.html`, страница автоматически его расширит.
   Иначе шаблон отрисуется самостоятельно.

5. (Необязательно) Для повышения лимитов ipinfo.io добавьте токен в окружение:
   ```bash
   export IPINFO_TOKEN=xxxxxxxxxxxxxxxx
   ```

## Возможности

- DNS: A / AAAA / MX (для MX используется `dnspython`, иначе будет без MX).
- HTTP: HEAD/GET с редиректами и тайм‑аутами.
- IP‑инфо: страна/город/провайдер через ipinfo.io.
- РКН: проверка по списку `https://reestr.rublacklist.net/api/v3/domains/` с кешем на 3 часа.
- UI: карточка с кнопкой «📋 Скопировать».

## Замечания

- Если `dnspython` недоступен, записи MX могут не показываться.
- Список РКН большой и иногда недоступен — в этом случае блок покажет сообщение о недоступности.
- Для доменов с IDN используется punycode, чтобы запросы были корректными.

Удачи! 🐘

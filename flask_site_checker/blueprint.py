from flask import Blueprint, request, render_template, Response, current_app
from .services import resolve_dns, http_check, ip_info_for_domain, rkn_domain_list, is_in_rkn
import time
import html as _html

# Шаблоны лежат в пакете flask_site_checker/templates
site_checker_bp = Blueprint("site_checker", __name__, template_folder="templates")

# --- простецкий кэш для РКН ---------------------------------
_RKN_CACHE = {"data": None, "data_set": None, "ts": 0}
_RKN_TTL = 3 * 3600  # 3 часа

def _get_rkn_cached():
    now = time.time()
    if not _RKN_CACHE["data"] or now - _RKN_CACHE["ts"] > _RKN_TTL:
        try:
            data = rkn_domain_list()
            _RKN_CACHE["data"] = data
            _RKN_CACHE["data_set"] = {x.lower() for x in data if isinstance(x, str)}
        except Exception:
            _RKN_CACHE["data"] = []
            _RKN_CACHE["data_set"] = set()
        _RKN_CACHE["ts"] = now
    return _RKN_CACHE["data"]

# --- приведение DNS к виду, которого ждёт шаблон -------------
def _group_dns(records_list):
    """
    На вход: список словарей от resolve_dns()
      [{'type':'A','ip':'1.2.3.4'}, {'type':'MX','target':'mx.yandex.net','pri':10}, ...]
    На выход: словарь для Jinja:
      {'A': ['1.2.3.4'], 'AAAA': ['2a00::1'], 'MX': ['mx.yandex.net (pri 10)']}
    """
    out = {"A": [], "AAAA": [], "MX": []}
    for r in records_list or []:
        t = r.get("type")
        if t == "A" and r.get("ip"):
            out["A"].append(r["ip"])
        elif t == "AAAA" and r.get("ipv6"):
            out["AAAA"].append(r["ipv6"])
        elif t == "MX":
            target = r.get("target")
            pri = r.get("pri")
            if target:
                out["MX"].append(f"{target} (pri {pri})" if pri is not None else target)
    # убрать пустые ключи
    return {k: v for k, v in out.items() if v}

# --- HTML-фолбэк (если шаблон упал) --------------------------
def _inline_fallback(domain, dns_map, http_res, ip_info, rkn_flag):
    d_esc = _html.escape(domain or "")

    # DNS блок
    if dns_map:
        parts = []
        for t, vals in dns_map.items():
            for val in vals:
                color = "#17943d" if t == "A" else ("#1565c0" if t == "AAAA" else "#7a47b7")
                label = "IPv4" if t == "A" else ("IPv6" if t == "AAAA" else "MX")
                parts.append(
                    '<span style="color:{c};">{lbl}:</span> <b>{v}</b>'.format(
                        c=color, lbl=label, v=_html.escape(str(val))
                    )
                )
        dns_html = "<br>".join(parts)
    else:
        dns_html = '<span style="color:#cc0000;">❌ DNS-записи не найдены.</span>'

    # HTTP блок
    if http_res.get("error"):
        http_html = '<span style="color:#cc0000;">✖ Ошибка: {e}</span>'.format(
            e=_html.escape(http_res["error"])
        )
    else:
        code = int(http_res.get("http_code") or 0)
        ok = 200 <= code < 400
        http_html = (
            '<span style="color:#17943d;">✔ Код: <b>{c}</b></span>'.format(c=code)
            if ok else
            '<span style="color:#cc0000;">✖ Код: <b>{c}</b></span>'.format(c=code)
        )
        if http_res.get("url"):
            u = _html.escape(http_res["url"])
            http_html += '<br>URL: <a href="{u}" target="_blank">{u}</a>'.format(u=u)

    # IP блок
    if ip_info.get("error"):
        ip_html = '<span style="color:#cc0000;">❌ {e}</span>'.format(
            e=_html.escape(ip_info["error"])
        )
    else:
        ip_html = (
            'Провайдер: <b>{org}</b><br>'
            'Страна: <b>{cc}</b><br>'
            'Город: <b>{city}</b>'
        ).format(
            org=_html.escape(ip_info.get("org") or "-"),
            cc=_html.escape(ip_info.get("country") or "-"),
            city=_html.escape(ip_info.get("city") or "-"),
        )

    # РКН блок
    if rkn_flag is True:
        rkn_html = '<span style="color:#cc0000;">⚠️ <b>Домен найден в реестре блокировок.</b></span>'
    elif rkn_flag is False:
        rkn_html = (
            '<span style="color:#17943d;">✅ <b>Домен не найден в реестре.</b></span>'
            '<div style="font-size:14px;margin-top:10px;background:#fffbe4;padding:10px 16px;border-radius:8px;'
            'border:1.3px dashed #f1c40f;color:#8a6700;">'
            '⚠️ <b>Важно:</b> данные reestr.rublacklist.net могут обновляться с задержкой.<br>'
            '<a href="https://reestr.digital.gov.ru/" target="_blank" '
            'style="text-decoration:underline;color:#1761a0;font-weight:600;">Проверь на официальном сайте РКН →</a>'
            '</div>'
        )
    else:
        rkn_html = '<span style="color:#888;">Не удалось получить список РКН.</span>'

    # Верхняя часть страницы (без JS)
    head = (
        "<!doctype html><html lang=\"ru\"><head>"
        "<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<title>Site Checker — DomainTools</title>"
        "</head><body style=\"font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif;background:#f5f7fb;\">"
        "<div style=\"max-width:980px;margin:32px auto;padding:0 12px;\">"
        "<div style=\"max-width:900px;margin:0 auto;background:#fff;"
        "box-shadow:0 4px 10px rgba(0,0,0,.1);padding:25px;border-radius:12px;border-left:5px solid #2271b1;\">"
        "<div style=\"font-size:22px;font-weight:600;margin-bottom:15px;text-align:center;\">"
        "🔎 Проверка доступности сайта — инструмент от Dr. Slon</div>"
        "<p style=\"text-align:center;font-size:16px;\">Проверяем домен по DNS, HTTP, IP-информации и наличию в реестре РКН.</p>"
        "</div>"
        "<div id=\"wpsc-result\" style=\"background:#fafdff;border:2px solid #3396e6;border-radius:13px;"
        "padding:28px 26px 20px 26px;max-width:560px;margin:38px auto 30px auto;font-size:16px;"
        "box-shadow:0 6px 24px rgba(51,150,230,0.10);position:relative;\">"
        "<button onclick=\"copyWpscResult()\" style=\"position:absolute;top:15px;right:18px;background:#fff;"
        "border:1.5px solid #d5e6f7;border-radius:8px;padding:5px 12px;font-size:15px;color:#2271b1;cursor:pointer;\">"
        "📋 Скопировать</button>"
        "<div style=\"display:flex;justify-content:center;align-items:center;margin-bottom:20px;\">"
        "<span style=\"background:#eef7ff;color:#1761a0;font-size:21px;font-weight:600;padding:6px 23px;border-radius:8px;"
        "letter-spacing:.2px;box-shadow:0 1px 6px #e7f0fa;border:1.2px solid #c6e3fb;\">"
        + d_esc + "</span></div>"
        "<div><span style=\"font-size:18px;\">🔎</span> <b>DNS:</b><br>" + dns_html + "</div>"
        "<div style=\"margin-top:13px;\"><span style=\"font-size:18px;\">🌐</span> <b>HTTP-доступ:</b><br>" + http_html + "</div>"
        "<div style=\"margin-top:13px;\"><span style=\"font-size:18px;\">🧠</span> <b>Информация об IP:</b><br>" + ip_html + "</div>"
        "<div style=\"margin-top:13px;\"><span style=\"font-size:18px;\">🚫</span> <b>Проверка в реестре РКН:</b><br>" + rkn_html + "</div>"
        "</div>"
        "<form method=\"post\" style=\"background:#fff;padding:24px 20px;border:1.5px solid #c7d7eb;border-radius:12px;"
        "box-shadow:0 3px 14px rgba(34,113,177,.09);max-width:440px;margin:32px auto 0;"
        "display:flex;flex-direction:column;align-items:center;\">"
        "<label for=\"domain\" style=\"font-weight:600;width:100%;text-align:left;margin-bottom:9px;font-size:16px;\">Введите домен:</label>"
        "<input type=\"text\" name=\"domain\" id=\"domain\" placeholder=\"example.com\" required "
        "style=\"width:100%;max-width:360px;padding:10px 12px;margin-bottom:14px;border-radius:7px;"
        "border:1.3px solid #e3eaf2;font-size:15px;\" value=\"" + d_esc + "\">"
        "<div style=\"width:100%;display:flex;gap:10px;\">"
        "<input type=\"submit\" value=\"Поиск сайта\" style=\"flex:1 1 50%;\">"
        "<a href=\"/site-checker\" style=\"flex:1 1 50%;background:#f2f4f8;color:#233;text-align:center;padding:10px 0;"
        "border-radius:7px;text-decoration:none;\">Очистить</a>"
        "</div></form></div>"
    )

    # JS как raw-строка (без форматирования), чтобы фигурные скобки не ломали Python
    script = r"""
<script>
function copyWpscResult() {
  var t = document.getElementById('wpsc-result').innerText;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(t).then(function () {
      alert('Результат скопирован!');
    });
  } else {
    alert('Скопируйте вручную:\n\n' + t);
  }
}
</script>
"""

    tail = "</body></html>"
    return head + script + tail

# --- основной маршрут ---------------------------------------------------------
@site_checker_bp.route("/site-checker", methods=["GET", "POST"])
def site_checker():
    domain = (request.form.get("domain") or request.args.get("domain") or "").strip()

    # вычисления
    dns_list = resolve_dns(domain) if domain else []
    dns_map = _group_dns(dns_list)
    http_res = http_check(domain) if domain else {"http_code": 0, "url": None, "error": None}
    ip_info = ip_info_for_domain(domain) if domain else {"ip": None, "org": None, "country": None, "city": None, "error": None}
    if domain:
        _get_rkn_cached()
        rkn_flag = is_in_rkn(domain, _RKN_CACHE.get("data_set"))
    else:
        rkn_flag = None

    # контекст для шаблона (и дубли на верхний уровень)
    result = {
        "domain": domain,
        "dns_records": dns_map,   # dict -> .items() в шаблоне
        "http": http_res,
        "ip_info": ip_info,
        "rkn_flag": rkn_flag,
    }
    ctx = {
        "domain": domain,
        "result": result,
        "dns_records": dns_map,
        "http": http_res,
        "ip_info": ip_info,
        "rkn_flag": rkn_flag,
        "error": None,
    }

    # пробуем нормальные шаблоны (с меню); при фейле — inline
    try:
        return render_template("site_checker/page.html", **ctx)
    except Exception:
        current_app.logger.exception("site_checker: template failed, fallback to inline")
        html_body = _inline_fallback(domain, dns_map, http_res, ip_info, rkn_flag)
        return Response(html_body, mimetype="text/html; charset=utf-8")

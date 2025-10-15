#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, re, pathlib

if len(sys.argv) < 2:
    print("[ERROR] Specify path to templates/index.html", file=sys.stderr)
    sys.exit(2)

p = pathlib.Path(sys.argv[1])
src = p.read_text(encoding="utf-8")

pat = re.compile(r"Перейдите\s+в\s+разделы[\s\S]*?History\.", re.IGNORECASE)

replacement = (
    'Начните с раздела <a href="/domains">Domains</a> — '
    'умный подбор доменных имён для вашего проекта: найдём подходящие варианты, '
    'проверим доступность и подскажем, где их зарегистрировать. '
    'Также доступны инструменты: <a href="{{ url_for(\'dns_lookup\') }}">DNS</a>, '
    '<a href="{{ url_for(\'whois_lookup\') }}">WHOIS</a> и '
    '<a href="{{ url_for(\'geoip_lookup\') }}">GeoIP</a>. '
    'Сохранённые результаты ищите в <a href="{{ url_for(\'history\') }}">History</a>.'
    '</p>\n'
    '<hr class="my-3">\n'
    '<p class="text-muted small mb-0">'
    'Сервис «Domains» помогает подбирать имена по ключевым словам и транслитерации, '
    'показывает занятость в популярных зонах (.ru, .рф, .com, .net, .org и др.), '
    'предлагает альтернативные написания (с/без дефисов, короткие формы, синонимы) '
    'и даёт быстрые ссылки на WHOIS, базовый DNS‑срез и GeoIP для сравнения вариантов.'
)

new_src, count = pat.subn(replacement, src, count=1)

if count == 0:
    new_src = re.sub(
        r"(Добро\s+пожаловать.*?</h\d>[\s\S]*?)<p>",
        r"\1<p>" + replacement,
        src,
        count=1,
        flags=re.IGNORECASE
    )

p.write_text(new_src, encoding="utf-8")
print("[ok] index.html updated")

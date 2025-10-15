#!/usr/bin/env python3
import sys, re, time, pathlib, shutil

def backup(p: pathlib.Path):
    bk = p.with_name(p.name + f".bak.{time.strftime('%Y%m%d_%H%M%S')}")
    shutil.copy2(p, bk)
    print(f"[i] Backup: {p} -> {bk}")
    return bk

def patch_index_html(path: pathlib.Path):
    if not path.exists():
        print(f"[WARN] index not found: {path}")
        return False
    txt = path.read_text(encoding='utf-8')
    changed = False

    # Insert Domains link after "Перейдите в разделы"
    def add_domains_link(m):
        return m.group(0) + ' <a href="/domains">Domains</a>, '
    new_txt, n1 = re.subn(r"(Перейдите\s+в\s+разделы\s*)", add_domains_link, txt, count=1, flags=re.I)
    if n1:
        txt = new_txt
        changed = True

    # Add SEO paragraph right after the matched paragraph
    seo_block = '''
<p class="small text-muted mt-2">
  Начните с <a href="/domains">Domains</a> — умный подбор доменных имён под ваш проект:
  проверим доступность, подскажем альтернативы в популярных зонах (.ru, .рф, .com, .net, .org и др.),
  предложим транслитерации, короткие и брендовые варианты. Для любой позиции — быстрые действия:
  WHOIS, DNS, GeoIP и сохранение результата в историю.
</p>
'''.lstrip()

    start = re.search(r"Перейдите\s+в\s+разделы", txt, flags=re.I)
    if start:
        close = re.search(r"</p\s*>", txt[start.start():], flags=re.I)
        if close:
            insert_at = start.start() + close.end()
            txt = txt[:insert_at] + "\n" + seo_block + txt[insert_at:]
            changed = True

    if changed:
        backup(path)
        path.write_text(txt, encoding='utf-8')
        print(f"[OK] Patched: {path}")
    else:
        print(f"[i] No changes made to: {path}")
    return changed

def patch_dns_html(path: pathlib.Path):
    if not path.exists():
        print(f"[WARN] dns template not found: {path}")
        return False
    txt = path.read_text(encoding='utf-8')
    new_txt, n = re.subn(r"url_for\(\s*'geo_lookup'\s*\)", "url_for('geoip_lookup')", txt)
    if n:
        backup(path)
        path.write_text(new_txt, encoding='utf-8')
        print(f"[OK] Fixed geo link in: {path}")
        return True
    print(f"[i] dns template already OK: {path}")
    return False

def main():
    if len(sys.argv) < 2:
        print("Usage: apply_home_intro.py <APPDIR>", file=sys.stderr)
        sys.exit(2)
    appdir = pathlib.Path(sys.argv[1])
    idx = appdir / "templates" / "index.html"
    dns = appdir / "templates" / "dns.html"
    c1 = patch_index_html(idx)
    c2 = patch_dns_html(dns)
    if not (c1 or c2):
        print("[i] Nothing changed. Patch was likely already applied.")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Собрать одностраничный index.html: page.html + ptcore.js + шаблон (base64).

  build_page.py [--template ../template_plus.pkt] [--out index.html] [--vendor DIR]

--vendor DIR — брать pako и js-yaml из локальной папки (vendor/…) вместо CDN,
чтобы страница работала без интернета.
"""
import argparse
import base64
from pathlib import Path

HERE = Path(__file__).resolve().parent
CDN = {
    "pako": "https://cdnjs.cloudflare.com/ajax/libs/pako/2.1.0/pako.min.js",
    "js-yaml": "https://cdnjs.cloudflare.com/ajax/libs/js-yaml/4.1.0/js-yaml.min.js",
}

ap = argparse.ArgumentParser()
ap.add_argument("--template", default=str(HERE.parent / "template_plus.pkt"))
ap.add_argument("--out", default=str(HERE / "index.html"))
ap.add_argument("--vendor", help="папка с pako.min.js и js-yaml.min.js (пути в странице станут vendor/…)")
ap.add_argument("--standalone", action="store_true", help="полный HTML-документ для обычного веб-сервера")
a = ap.parse_args()

page = (HERE / "page.html").read_text(encoding="utf-8")
core = (HERE / "ptcore.js").read_text(encoding="utf-8")
if "</script" in core:
    raise SystemExit("ptcore.js не должен содержать </script")
tpl = Path(a.template)
page = page.replace("/*PTCORE*/", core)
page = page.replace("/*TEMPLATE_B64*/", base64.b64encode(tpl.read_bytes()).decode())
page = page.replace('name: "template_plus.pkt" };', 'name: "%s" };' % tpl.name)
if a.vendor:
    for lib, url in CDN.items():
        if (Path(a.vendor) / f"{lib}.min.js").exists():
            page = page.replace(url, f"vendor/{lib}.min.js")
if a.standalone:
    page = ('<!doctype html><html lang="ru"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">'
            '<style>:root{color-scheme:light}body{margin:0}img{max-width:100%}'
            '[hidden]{display:none!important}</style></head><body>' + page + '</body></html>')
Path(a.out).write_text(page, encoding="utf-8")
print(f"OK: {a.out} ({len(page) // 1024} КБ, шаблон {tpl.name})")

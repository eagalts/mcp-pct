#!/usr/bin/env python3
"""
ptgen MCP-сервер: даёт Claude (Desktop / Code) инструменты для сборки
файлов Cisco Packet Tracer из YAML и разбора .pkt обратно в YAML.

Сценарий: кидаешь в чат скриншот схемы → Claude распознаёт её в YAML →
вызывает build_pkt → готовый .pkt лежит в папке вывода.

Переменные окружения:
  PTGEN_TEMPLATE  путь к шаблонному .pkt (по умолчанию template_plus.pkt рядом с сервером)
  PTGEN_OUT       папка для готовых файлов (по умолчанию ~/ptgen)

Запуск: python3 mcp_server.py            (stdio, для Claude Desktop/Code)
        python3 mcp_server.py --http 8765 (streamable HTTP на PTGEN_HOST, по умолчанию 127.0.0.1)
  PTGEN_PUBLIC_URL — если задан, build_pkt возвращает ссылку на файл вместо пути
"""
import os
import re
import sys
from pathlib import Path
from urllib.parse import quote

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ptcodec  # noqa: E402
import ptgen    # noqa: E402

try:  # mcp >= 2
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server

TEMPLATE = Path(os.environ.get("PTGEN_TEMPLATE", HERE / "template_plus.pkt")).expanduser()
OUT_DIR = Path(os.environ.get("PTGEN_OUT", "~/ptgen")).expanduser()
PUBLIC_URL = os.environ.get("PTGEN_PUBLIC_URL", "").rstrip("/")  # напр. http://ptgen.lan/files

FORMAT = """Формат YAML:
devices:
  - {name: R1, model: "1941", x: 400, y: 100, config: "interface GigabitEthernet0/0\\n ip address 10.0.0.1 255.255.255.0\\n no shutdown\\n"}
  - {name: SW1, model: 2960-24TT}
  - {name: PC1, model: PC-PT, ip: 10.0.0.10/24, gateway: 10.0.0.1}
links:
  - [R1, Gi0/0, SW1, Gi0/1]
  - [PC1, Fa0, SW1, Fa0/1]
model — только из list_models. x/y необязательны (авто-раскладка). ip/gateway — для PC/Server/Laptop,
для роутеров и коммутаторов адреса задаются в config (синтаксис IOS, сливается с show run).
Порты сокращаются (Gi/Fa/Se/Eth). Тип кабеля выбирается автоматически."""

server = _Server(
    "ptgen",
    instructions=(
        "Сборка схем Cisco Packet Tracer (.pkt). Когда пользователь даёт скриншот схемы или "
        "описание сети и просит .pkt: 1) вызови list_models, 2) составь YAML строго по формату "
        "из описания build_pkt, используя только доступные модели и их порты, 3) вызови "
        "validate_yaml и исправь ошибки, 4) вызови build_pkt. Если подпись порта на скриншоте "
        "не видна — назначь свободный порт и скажи об этом пользователю."),
)


def _template(path: str | None) -> bytes:
    p = Path(path).expanduser() if path else TEMPLATE
    if not p.exists():
        raise ValueError(f"шаблон не найден: {p}")
    return p.read_bytes()


def _load(yaml_text: str) -> dict:
    try:
        topo = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        raise ValueError(f"YAML не разбирается: {e}")
    if not isinstance(topo, dict):
        raise ValueError("YAML должен быть объектом с ключами devices и links")
    return topo


@server.tool()
def list_models(template_path: str | None = None) -> str:
    """Модели устройств, доступные в шаблоне, с известными именами портов. Вызывай перед составлением YAML."""
    T = ptgen.Template(ptcodec.decrypt(_template(template_path)))
    ver = re.search(rb"<VERSION>([^<]*)", ptcodec.decrypt(_template(template_path))[:400])
    lines = [f"Шаблон: {template_path or TEMPLATE} (PT {ver.group(1).decode() if ver else '?'})"]
    for m, d in T.proto.items():
        if m == "Power Distribution Device":
            continue
        ports = list(ptgen.port_map(d))
        lines.append(f"- {m} ({d.findtext('ENGINE/TYPE')})" + (f": {', '.join(ports)}" if ports else ""))
    return "\n".join(lines)


@server.tool()
def validate_yaml(yaml_text: str, template_path: str | None = None) -> str:
    """Проверить YAML схемы без сборки: неизвестные устройства/модели/порты, занятые порты, дубли имён."""
    try:
        topo = _load(yaml_text)
        specs = topo.get("devices") or []
        links = ptgen.parse_links(topo.get("links"))
        T = ptgen.Template(ptcodec.decrypt(_template(template_path)))
        models = T.proto
        missing = sorted({str(s["model"]) for s in specs} - set(models))
        if missing:
            return "Ошибка: в шаблоне нет моделей: " + ", ".join(missing)
        ptgen.validate(specs, links, T)
        return f"OK: устройств {len(specs)}, кабелей {len(links)}"
    except SystemExit as e:
        return str(e)
    except (ValueError, KeyError, TypeError) as e:
        return f"Ошибка: {e}"


build_doc = f"""Собрать файл .pkt из YAML и сохранить его. Возвращает путь к файлу.

{FORMAT}

output_name — имя файла без расширения; файл кладётся в папку PTGEN_OUT (по умолчанию ~/ptgen)."""


@server.tool(description=build_doc)
def build_pkt(yaml_text: str, output_name: str = "topology", template_path: str | None = None) -> str:
    try:
        topo = _load(yaml_text)
        data, nd, nl = ptgen.build(topo, _template(template_path))
    except SystemExit as e:
        return str(e)
    except (ValueError, KeyError, TypeError) as e:
        return f"Ошибка: {e}"
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    name = re.sub(r'[\\/:*?"<>|]+', "_", output_name).removesuffix(".pkt") or "topology"
    path = OUT_DIR / f"{name}.pkt"
    path.write_bytes(data)
    where = f"{PUBLIC_URL}/{quote(path.name)}" if PUBLIC_URL else str(path)
    return f"Готово: {where} — устройств {nd}, кабелей {nl}"


@server.tool()
def export_pkt(pkt_path: str) -> str:
    """Разобрать готовый .pkt/.pkz в YAML (устройства, координаты, IP хостов, значимые строки конфигов, кабели)."""
    p = Path(pkt_path).expanduser()
    if not p.exists():
        return f"Ошибка: файл не найден: {p}"
    data = ptgen.export(p.read_bytes())
    for d in data["devices"]:
        if "config" in d:
            d["config"] = ptgen._Lit(d["config"])
    data["links"] = [ptgen._Flow(l) for l in data["links"]]
    return yaml.dump(data, allow_unicode=True, sort_keys=False, width=200)


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--http":
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8765
        server.run("streamable-http", host=os.environ.get("PTGEN_HOST", "127.0.0.1"), port=port)
    else:
        server.run()

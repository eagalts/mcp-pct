# ptcodec / ptgen

Веб-версия (тот же генератор в браузере): `web/index.html`; исходники страницы — `web/page.html` + `web/ptcore.js`. — сборка схем Packet Tracer из YAML

Python 3.8+, зависимость одна — `pip install pyyaml`. Шифрование реализовано внутри, внешних крипто-библиотек не нужно.

## Что умеет

| Команда | Что делает |
|---|---|
| `python3 ptcodec.py decode in.pkt out.xml` | .pkt/.pka/.pkz → XML |
| `python3 ptcodec.py encode in.xml out.pkt` | XML → .pkt (открывается в PT) |
| `python3 ptgen.py models template.pkt` | какие модели устройств есть в шаблоне |
| `python3 ptgen.py export in.pkt out.yaml` | готовая схема → YAML |
| `python3 ptgen.py build topo.yaml template.pkt out.pkt` | YAML → готовая схема |
| `python3 ptgen.py addmodel template.pkt donor.pkt 3560-24PS ... out.pkt` | перенести модели из любого .pkt в шаблон со сбросом настроек |

Проверено: 47 реальных файлов PT 7.3 / 8.0 / 8.2 / 9.0 / 9.0.0 расшифровываются и шифруются обратно **байт-в-байт**.

## Как это работает

Генератор не пишет XML с нуля. Он берёт **шаблонный .pkt** и клонирует из него устройства нужной модели со всеми модулями и портами. Поэтому:

- в шаблоне должно быть хотя бы по одному устройству каждой модели, которая встречается в YAML, и хотя бы один кабель;
- новая модель — кинуть её в шаблон в PT и сохранить, или `addmodel` из любой готовой лабы;
- `template_plus.pkt` — шаблон по умолчанию: 1941, 2960-24TT, 3560-24PS, PC-PT, Server-PT.

Имена портов вычисляются из дерева модулей устройства (проверено на 14 моделях, 462 из 464 кабелей в реальных лабах; не распознаются только консольные). Адреса из `config` пишутся и в running-config, и в поля портов, как это делает сам PT (сверено на 48 настроенных роутерах); конфиг сохраняется в startup-config (`save: false` — не сохранять).

## Формат YAML

```yaml
devices:
  - name: R1
    model: "1941"             # как в `ptgen.py models`
    x: 400                    # координаты необязательны — иначе авто-раскладка
    y: 100
    config: |                 # IOS-конфиг, сливается с секциями show run
      interface GigabitEthernet0/0
       ip address 10.0.0.1 255.255.0.0
       no shutdown
  - name: SW1
    model: 2960-24TT
  - name: PC1
    model: PC-PT
    ip: 10.0.1.10/16           # для PC/Server/Laptop
    gateway: 10.0.0.1
links:
  - [R1, Gi0/0, SW1, Gi0/1]    # сокращения Gi/Fa/Se/Eth понимаются
  - [PC1, Fa0, SW1, Fa0/1]
```

Перед сборкой проверяется: неизвестные устройства и порты, порт занят дважды, дубли имён.

## MCP-сервер (Claude Desktop / Claude Code)

Нужен Python 3.10+ и `pip install mcp pyyaml`. Инструменты: `list_models`, `validate_yaml`, `build_pkt`, `export_pkt`.
Сценарий: кидаешь в чат скриншот схемы и пишешь «собери pkt» — Claude сам распознаёт, проверяет и сохраняет файл в `~/ptgen`.

**Claude Code:**
```bash
claude mcp add --scope user --env PTGEN_OUT=$HOME/ptgen --transport stdio ptgen \
  -- python3 /путь/к/ptcodec/mcp_server.py
```

**Claude Desktop** — Settings → Developer → Edit Config, добавить в `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "ptgen": {
      "command": "python3",
      "args": ["/путь/к/ptcodec/mcp_server.py"],
      "env": { "PTGEN_OUT": "/путь/куда/класть/pkt" }
    }
  }
}
```
На Windows — `"command": "python"` и путь вида `C:\\tools\\ptcodec\\mcp_server.py`.

Переменные: `PTGEN_TEMPLATE` — свой шаблон (.pkt с нужными моделями), `PTGEN_OUT` — папка вывода.

**Общий сервер:** `python3 mcp_server.py --http 8765` поднимает streamable HTTP на `/mcp`. Его можно подключить как custom connector в claude.ai, если он доступен по HTTPS. Но тогда файлы сохраняются на сервере, а не у коллег, так что для раздачи файлов удобнее веб-страница.

## Ограничения (пока)

- Физический вид (стойки/столы) — клоны кладутся рядом с прототипом; на логическую схему не влияет.
- Поддерживаются медные Ethernet-линки; serial/оптика — следующий шаг.

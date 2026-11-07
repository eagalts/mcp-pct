# Packet Tracer MCP

MCP-сервер для Cisco Packet Tracer 9: сборка `.pkt` из YAML (ptgen) плюс [Mats2208/MCP-Packet-Tracer](https://github.com/Mats2208/MCP-Packet-Tracer) (MIT, `vendor/`) с живым PT на Windows. Устройство описано в `docs/ARCHITECTURE.md`.

**Windows** (там работает PT). Нужны Packet Tracer 9 и Python 3.10+. Из корня репозитория от администратора:

```powershell
powershell -ExecutionPolicy Bypass -File agent\install.ps1 -User 'HOST\svc_pt' -AllowFrom <IP сервера> -HostName <имя или IP этого хоста>
```

Затем войдите учёткой `-User`, в PT: Extensions → Scripting → Add → `C:\ptmcp\ext\ptmcp.pts`, запуск On Startup.

**Сервер (Linux).** Скопируйте `live/`, `vendor/` и `app/` в `/opt/ptgen` и создайте venv: `pip install "mcp>=1" pydantic httpx`. Поставьте юнит `deploy/ptgen-mcp.service`. Положите `C:\ptmcp\server\agent.crt` в `/etc/ptgen-live/agent.crt`, а строки из `C:\ptmcp\server\ptgen-live.env` — в `/etc/default/ptgen-live`. Туда же допишите `PTLIVE_INTROSPECT_URL`, `PTLIVE_INTROSPECT_SECRET`, `PTLIVE_RESOURCE_METADATA` (ваш OAuth) и `PTGEN_PUBLIC_URL`.

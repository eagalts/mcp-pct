#!/usr/bin/env python3
"""ptgen-live -- MCP-сервер «Packet Tracer».

Один сервер = прежний ptgen (YAML -> .pkt и .pkt -> YAML) + весь Mats2208/MCP-Packet-Tracer
(79 инструментов, 6 ресурсов, 3 промпта; код образца в ../vendor, MIT, без правок).

Живой Packet Tracer 9 работает на отдельном Windows-хосте в сеансе служебной учётки; там же агент
(../agent/ptagent.py): файловый ящик расширения, окна устройств (UI Automation), снимки.
Здесь образец получает вместо локального моста и Presenter их удалённые версии (RemoteBridge,
RemotePresenter), а каждый вызов инструмента проходит через обёртку:
  * вход -- OAuth-токен, проверка через introspect-эндпоинт сервера авторизации (PTLIVE_INTROSPECT_URL);
  * очередь -- один вызов за раз (PT однопоточен), остальные ждут;
  * у каждого пользователя свой холст: перед живым вызовом открывается его файл
    (work/<user>/_canvas.pkt на Windows-хосте), после -- сохраняется туда же;
  * свой рабочий каталог на сервере (планы, экспорт, снимки);
  * картинки (pt_screenshot, снимки окон устройств) возвращаются ИИ как изображения;
  * pt_send_raw и инструменты рабочего стола -- только администраторам.
"""
from __future__ import annotations

import base64
import functools
import logging
import hashlib
import hmac
import json
import os
import re
import ssl
import sys
import threading
import time
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

import anyio
import httpx
import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path[:0] = [str(ROOT / "vendor"), str(ROOT / "app")]

from mcp.server.fastmcp import FastMCP  # noqa: E402
from mcp.types import CallToolResult, ImageContent, TextContent  # noqa: E402

import ptcodec  # noqa: E402  (ptgen)
import ptgen  # noqa: E402
from packet_tracer_mcp.adapters.mcp import device_panel_tools as _dpt  # noqa: E402
from packet_tracer_mcp.adapters.mcp.bridge_context import BridgeContext  # noqa: E402
from packet_tracer_mcp.adapters.mcp.prompt_registry import register_prompts  # noqa: E402
from packet_tracer_mcp.adapters.mcp.resource_registry import register_resources  # noqa: E402
from packet_tracer_mcp.adapters.mcp.tool_registry import register_tools  # noqa: E402
from packet_tracer_mcp.infrastructure.ui.presenter import PresenterError  # noqa: E402
from packet_tracer_mcp.settings import SERVER_INSTRUCTIONS  # noqa: E402

ENV = os.environ.get
AGENT_URL = ENV("PTLIVE_AGENT_URL", "https://pt-agent.example.com:39410").rstrip("/")
AGENT_TOKEN = ENV("PTLIVE_AGENT_TOKEN", "")
AGENT_CA = ENV("PTLIVE_AGENT_CA", "/etc/ptgen-live/agent.crt")
DATA = Path(ENV("PTLIVE_DATA", "/var/lib/ptgen/live"))
OUT_DIR = Path(ENV("PTGEN_OUT", "/var/lib/ptgen/out"))
PUBLIC_URL = ENV("PTGEN_PUBLIC_URL", "").rstrip("/")
TEMPLATE = Path(ENV("PTGEN_TEMPLATE", ROOT / "app" / "template_plus.pkt"))
AUTH = ENV("PTLIVE_AUTH", "oauth")  # oauth | none (только для локальной отладки на 127.0.0.1)
INTROSPECT_URL = ENV("PTLIVE_INTROSPECT_URL", "https://auth.example.com/oauth/introspect")
INTROSPECT_SECRET = ENV("PTLIVE_INTROSPECT_SECRET", "")
RESOURCE_METADATA = ENV("PTLIVE_RESOURCE_METADATA",
                        "https://auth.example.com/.well-known/oauth-protected-resource/ptgen")
REALM = ENV("PTLIVE_REALM", "ptgen")
FILES_SECRET = ENV("PTLIVE_FILES_SECRET", AGENT_TOKEN or "dev").encode()

ADMIN_ONLY = {"pt_send_raw", "pt_desktop_screenshot", "pt_desktop_input", "pt_restart_packet_tracer"}
# инструменты, которым живой PT не нужен (холст не переключаем, Windows-хост не трогаем)
OFFLINE = {"pt_plan_topology", "pt_validate_plan", "pt_fix_plan", "pt_explain_plan", "pt_estimate_plan",
           "pt_generate_script", "pt_generate_configs", "pt_export", "pt_list_devices", "pt_get_device_details",
           "pt_list_templates", "pt_list_projects", "pt_load_project", "pt_deploy",
           "list_models", "validate_yaml", "build_pkt", "export_pkt", "pt_bridge_status", "pt_list_saved_projects",
           "pt_desktop_screenshot", "pt_desktop_input", "pt_restart_packet_tracer"}
MAX_IMAGES = 4
NL = chr(10)
SHOT_HINT = "Ссылки на снимки (https; для Office436: image_upload с source_url, затем word_insert_image):"
logging.getLogger("httpx").setLevel(logging.WARNING)
LOCK = threading.Lock()  # очередь: Packet Tracer однопоточен, один вызов за раз


def log(msg: str) -> None:
    print(time.strftime("%Y-%m-%d %H:%M:%S ") + msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- агент на Windows-хосте
class Agent:
    def __init__(self):
        ctx = ssl.create_default_context(cafile=AGENT_CA) if Path(AGENT_CA).exists() else False
        self.cli = httpx.Client(verify=ctx, headers={"Authorization": f"Bearer {AGENT_TOKEN}"})
        self._h: tuple[float, dict | None] = (0.0, None)

    def call(self, path: str, payload: dict | None = None, timeout: float = 30.0) -> dict:
        r = self.cli.post(AGENT_URL + path, json=payload or {}, timeout=timeout + 15)
        if r.status_code == 401:
            raise RuntimeError("агент Windows-хоста отклонил токен")
        r.raise_for_status()
        return r.json()

    def health(self, fresh: bool = False) -> dict | None:
        t, h = self._h
        if not fresh and time.monotonic() - t < 3:
            return h
        try:
            h = self.call("/health", timeout=5)
        except Exception as exc:  # noqa: BLE001
            h = {"error": f"{type(exc).__name__}: {exc}"}
        self._h = (time.monotonic(), h)
        return h

    def alive(self) -> bool:
        h = self.health()
        if h and h.get("pt_alive") and h.get("pt_pids"):
            return True
        # PT закрыт агентом по простою (экономия ОЗУ на Windows-хосте): запрос живого PT поднимает его сам
        if h and "error" not in h and not h.get("pt_pids"):
            try:
                self.call("/pt/start", timeout=10)
            except Exception as exc:  # noqa: BLE001
                log(f"agent /pt/start: {exc}")
                return False
            for _ in range(45):
                time.sleep(2)
                h = self.health(fresh=True)
                if h and h.get("pt_alive") and h.get("pt_pids"):
                    return True
        return False

    def js(self, code: str, timeout: float = 10.0, wait: bool = True):
        try:
            r = self.call("/js", {"code": code, "timeout": timeout, "wait": wait}, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            log(f"agent /js: {exc}")
            return None if wait else False
        return r.get("result") if wait else bool(r.get("sent"))


AGENT = Agent()
NOT_CONNECTED = ("Живой Packet Tracer сейчас недоступен (агент на Windows-хосте не отвечает). "
                 "Проверьте pt_bridge_status. Инструменты планирования, валидации, генерации и .pkt "
                 "(pt_plan_topology, pt_validate_plan, pt_fix_plan, pt_generate_*, pt_export, build_pkt, export_pkt) работают и без него.")


class _AliveProxy:
    def pt_alive(self) -> bool:
        return AGENT.alive()


class RemoteBridge(BridgeContext):
    """BridgeContext образца, но JS уходит в файловый ящик PT на Windows-хосте через агента."""

    def __init__(self):
        super().__init__(file_bridge=_AliveProxy())
        self.instance = None

    def bridge_identity(self) -> str:
        return "ours" if AGENT.alive() else "none"

    def bridge_is_up(self) -> bool:
        return AGENT.alive()

    def bridge_pt_connected(self) -> bool:
        return AGENT.alive()

    def ensure_bridge(self, grace: bool = True) -> bool:
        return AGENT.alive()

    def pick_channel(self) -> str:
        return "file" if AGENT.alive() else ""

    def channel_send(self, payload: str) -> bool:
        self._note(payload)
        return AGENT.js(payload, wait=False)

    def send_and_wait(self, js_call: str, timeout: float = 10.0) -> str | None:
        self._note(js_call)
        guarded = "try{" + js_call + "}catch(__pterr){reportResult('PT_ERROR: '+__pterr);}"
        return AGENT.js(guarded, timeout=timeout)

    def check_bridge(self) -> str | None:
        return None if AGENT.alive() else NOT_CONNECTED

    def stale_client_message(self) -> str:
        return NOT_CONNECTED


class RemotePresenter:
    """Presenter образца (окна устройств, UI Automation) -- исполняется агентом на Windows-хосте."""

    def __init__(self, send_and_wait=None, **_):
        pass

    def _ui(self, method: str, *args, **kwargs):
        try:
            r = AGENT.call("/ui", {"method": method, "args": list(args), "kwargs": kwargs}, timeout=90)
        except Exception as exc:  # noqa: BLE001
            raise PresenterError(f"агент Windows-хоста: {exc}") from exc
        if r.get("error"):
            raise PresenterError(r["error"])
        return r.get("result")

    def device_info(self, device: str) -> dict:
        return self._ui("device_info", device)

    def open(self, device: str, **kw) -> dict:
        return self._ui("open", device, **kw)

    def close(self, device: str = "") -> str:
        return self._ui("close", device)

    def capture(self, device: str, target: Path) -> dict:
        info = self._ui("capture", device)
        target = Path(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(base64.b64decode(info.pop("png")))
        info["path"] = str(target)
        return info

    def fill_and_go(self, hwnd: int, edit_suffix: str, text: str, button_suffix: str) -> bool:
        return self._ui("fill_and_go", hwnd, edit_suffix, text, button_suffix)

    def invoke_button(self, hwnd: int, name: str) -> bool:
        return self._ui("invoke_button", hwnd, name)

    def scroll_consoles(self, hwnd: int, u=None) -> bool:
        return self._ui("scroll_consoles", hwnd)


_dpt.Presenter = RemotePresenter
_dpt.is_available = lambda: (True, "")  # реальная проверка -- у агента


# --------------------------------------------------------------------------- пользователи
def slug(username: str) -> str:
    return re.sub(r"[^a-z0-9._-]+", "_", username.lower())[:60] or "user"


def user_dir(user: dict) -> Path:
    d = DATA / "users" / user["slug"]
    d.mkdir(parents=True, exist_ok=True)
    return d


def files_token(user: dict) -> str:
    return hmac.new(FILES_SECRET, user["slug"].encode(), hashlib.sha256).hexdigest()[:20]


def user_out(user: dict) -> Path:
    d = OUT_DIR / files_token(user)
    d.mkdir(parents=True, exist_ok=True)
    return d


def file_url(user: dict, name: str) -> str:
    if PUBLIC_URL:
        return f"{PUBLIC_URL}/{files_token(user)}/{quote(name)}"
    return str(user_out(user) / name)


def safe_file(name: str, ext: str = ".pkt") -> str:
    name = re.sub(r'[\\/:*?"<>|\s]+', "_", str(name).strip()).strip("._")
    name = re.sub(r"\.(pkt|pkz)$", "", name, flags=re.I) or "topology"
    return name[:80] + ext


LOCAL = threading.local()


def current_user() -> dict:
    return getattr(LOCAL, "user", None) or {"username": "anonymous", "slug": "anonymous", "admin": False}


# --------------------------------------------------------------------------- холсты
class Canvas:
    """Один PT на всех: у каждого пользователя свой файл холста на Windows-хосте."""

    STATE = DATA / "canvas.json"

    def __init__(self):
        try:
            self.state = json.loads(self.STATE.read_text())
        except (OSError, ValueError):
            self.state = {}

    def _persist(self):
        self.STATE.parent.mkdir(parents=True, exist_ok=True)
        self.STATE.write_text(json.dumps(self.state))

    @staticmethod
    def _pt_key(h: dict) -> str:
        return ",".join(map(str, h.get("pt_pids") or []))

    def _path(self, user: dict) -> dict:
        return AGENT.call("/file/path", {"name": f"{user['slug']}/_canvas.pkt"})

    def save(self, user: dict) -> str | None:
        p = self._path(user)["path"]
        js = (f"var p={json.dumps(p)};ipc.appWindow().fileSaveAsNoPrompt(p,false);"
              "var fm=ipc.systemFileManager();reportResult(fm.fileExists(p)?'OK':'ERR')")
        return AGENT.js(js, timeout=30)

    def new_canvas(self) -> str | None:
        # Пустой холст: PT 9 -- fileNew(false) без вопроса о сохранении; запасной путь -- удалить всё.
        js = ("var aw=ipc.appWindow();var ok=false;"
              "try{if(typeof aw.fileNew==='function'){aw.fileNew(false);ok=true;}}catch(e){}"
              "var net=ipc.network();"
              "if(net.getDeviceCount()>0){var lw=aw.getActiveWorkspace().getLogicalWorkspace();"
              "for(var i=net.getDeviceCount()-1;i>=0;i--){try{lw.removeDevice(net.getDeviceAt(i).getName());}catch(e){}}}"
              "reportResult('OK:'+net.getDeviceCount()+':'+ok)")
        return AGENT.js(js, timeout=30)

    def open_file(self, path: str) -> str | None:
        js = (f"var p={json.dumps(path)};var fm=ipc.systemFileManager();"
              "if(!fm.fileExists(p)){reportResult('ERR:нет файла')}else{ipc.appWindow().fileOpen(p);"
              "reportResult('OK:'+ipc.network().getDeviceCount())}")
        return AGENT.js(js, timeout=60)

    def ensure(self, user: dict) -> str | None:
        h = AGENT.health(fresh=True) or {}
        if not h.get("pt_alive"):
            return None  # инструмент сам скажет, что PT недоступен
        key = self._pt_key(h)
        if self.state.get("user") == user["slug"] and self.state.get("pt") == key:
            return None
        p = self._path(user)
        r = self.open_file(p["path"]) if p.get("exists") else self.new_canvas()
        if not r or not r.startswith("OK"):
            return f"Не удалось открыть ваш холст в Packet Tracer: {r}"
        self.state = {"user": user["slug"], "pt": key, "since": time.time()}
        self._persist()
        log(f"canvas -> {user['slug']} ({r})")
        return None

    def after(self, user: dict) -> None:
        if self.state.get("user") == user["slug"] and AGENT.alive():
            r = self.save(user)
            if r != "OK":
                log(f"canvas save {user['slug']}: {r}")


CANVAS = Canvas()


# --------------------------------------------------------------------------- обёртка инструментов
def _images_since(wd: Path, t0: float) -> list[Path]:
    out = []
    for p in wd.rglob("*"):
        if p.suffix.lower() in (".png", ".jpg", ".jpeg") and p.is_file() and p.stat().st_mtime >= t0 - 1:
            out.append(p)
    return sorted(out, key=lambda p: p.stat().st_mtime)[-MAX_IMAGES:]


def _publish_images(user: dict, images: list[Path]) -> list[str]:
    """Снимки лежат на сервере; копия в личной папке и https-ссылка позволяют забрать их из другого сервиса
    (Office436: image_upload с source_url, затем word_insert_image)."""
    urls = []
    for p in images:
        name = re.sub(r"[^A-Za-z0-9._-]+", "_", f"shot-{time.strftime('%Y%m%d-%H%M%S')}-{p.stem}{p.suffix.lower()}")
        try:
            (user_out(user) / name).write_bytes(p.read_bytes())
        except OSError as e:
            log(f"publish image {p}: {e}")
            continue
        urls.append(file_url(user, name))
    return urls


def _result(tool, res, images: list[Path]):
    if not isinstance(res, str):
        return res
    content = [TextContent(type="text", text=res)]
    for p in images:
        mime = "image/png" if p.suffix.lower() == ".png" else "image/jpeg"
        content.append(ImageContent(type="image", data=base64.b64encode(p.read_bytes()).decode(), mimeType=mime))
    structured = {"result": res} if tool.output_schema is not None else None
    return CallToolResult(content=content, structuredContent=structured)


def wrap(mcp: FastMCP, tool) -> None:
    orig, name = tool.fn, tool.name
    live = name not in OFFLINE
    orig_async = tool.is_async

    def work(user: dict, kw: dict):
        with LOCK:
            LOCAL.user = user
            wd = user_dir(user)
            os.chdir(wd)
            t0 = time.time()
            try:
                if live:
                    err = CANVAS.ensure(user)
                    if err:
                        return err, []
                res = anyio.from_thread.run(functools.partial(orig, **kw)) if orig_async else orig(**kw)
                if live:
                    CANVAS.after(user)
                return res, _images_since(wd, t0)
            finally:
                LOCAL.user = None

    async def runner(**kw):
        user = request_user(mcp)
        if name in ADMIN_ONLY and not user["admin"]:
            return f"{name} доступен только администраторам."
        t0 = time.monotonic()
        res, imgs = await anyio.to_thread.run_sync(work, user, kw)
        if isinstance(res, str) and imgs and PUBLIC_URL:
            urls = await anyio.to_thread.run_sync(_publish_images, user, imgs)
            if urls:
                res += NL * 2 + SHOT_HINT + NL + NL.join(urls)
        log(f"{user['slug']} {name} {time.monotonic() - t0:.1f}s imgs={len(imgs)}")
        return _result(tool, res, imgs)

    functools.update_wrapper(runner, orig)
    tool.fn = runner
    tool.is_async = True


def request_user(mcp: FastMCP) -> dict:
    try:
        req = mcp.get_context().request_context.request
        u = req.scope.get("ptgen_user") if req is not None else None
    except (LookupError, ValueError, AttributeError):
        u = None
    if u:
        return u
    if AUTH == "none":
        return {"username": "local", "slug": "local", "admin": True}
    return {"username": "anonymous", "slug": "anonymous", "admin": False}


# --------------------------------------------------------------------------- свои инструменты
PTGEN_FORMAT = """Формат YAML:
devices:
  - {name: R1, model: "1941", x: 400, y: 100, config: "interface GigabitEthernet0/0\\n ip address 10.0.0.1 255.255.255.0\\n no shutdown\\n"}
  - {name: SW1, model: 2960-24TT}
  - {name: PC1, model: PC-PT, ip: 10.0.0.10/24, gateway: 10.0.0.1}
links:
  - [R1, Gi0/0, SW1, Gi0/1]
  - [PC1, Fa0, SW1, Fa0/1]
model -- только из list_models. x/y необязательны (авто-раскладка). ip/gateway -- для PC/Server/Laptop,
для роутеров и коммутаторов адреса задаются в config (синтаксис IOS, сливается с show run).
Порты сокращаются (Gi/Fa/Se/Eth). Тип кабеля выбирается автоматически."""


def _template() -> bytes:
    return TEMPLATE.read_bytes()


def _load_yaml(text: str) -> dict:
    try:
        topo = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ValueError(f"YAML не разбирается: {e}")
    if not isinstance(topo, dict):
        raise ValueError("YAML должен быть объектом с ключами devices и links")
    return topo


def _user_pkt(ref: str) -> tuple[str, bytes]:
    """Свой файл пользователя: имя из build_pkt / pt_save_project или ссылка на него."""
    user = current_user()
    ref = ref.strip()
    if ref.startswith(("http://", "https://")):
        parts = [unquote(x) for x in urlparse(ref).path.split("/") if x]
        if len(parts) < 2 or parts[-2] != files_token(user):
            raise ValueError("это не ваш файл (ссылка другого пользователя или чужого сервера)")
        ref = parts[-1]
    name = safe_file(Path(ref).name)
    p = user_out(user) / name
    if not p.exists():
        raise ValueError(f"файл не найден: {name}. Ваши файлы: " + ", ".join(sorted(x.name for x in user_out(user).glob("*.pkt"))))
    return name, p.read_bytes()


def register_own(mcp: FastMCP, ctx: RemoteBridge) -> None:
    @mcp.tool()
    def list_models() -> str:
        """[ptgen] Модели устройств шаблона ptgen (для build_pkt) с именами портов. Вызывай перед составлением YAML."""
        xml = ptcodec.decrypt(_template())
        T = ptgen.Template(xml)
        ver = re.search(rb"<VERSION>([^<]*)", xml[:400])
        lines = [f"Шаблон ptgen (PT {ver.group(1).decode() if ver else '?'})"]
        for m, d in T.proto.items():
            if m == "Power Distribution Device":
                continue
            ports = list(ptgen.port_map(d))
            lines.append(f"- {m} ({d.findtext('ENGINE/TYPE')})" + (f": {', '.join(ports)}" if ports else ""))
        return "\n".join(lines)

    @mcp.tool()
    def validate_yaml(yaml_text: str) -> str:
        """[ptgen] Проверить YAML схемы без сборки: неизвестные устройства/модели/порты, занятые порты, дубли имён."""
        try:
            topo = _load_yaml(yaml_text)
            specs = topo.get("devices") or []
            links = ptgen.parse_links(topo.get("links"))
            T = ptgen.Template(ptcodec.decrypt(_template()))
            missing = sorted({str(s["model"]) for s in specs} - set(T.proto))
            if missing:
                return "Ошибка: в шаблоне нет моделей: " + ", ".join(missing)
            ptgen.validate(specs, links, T)
            return f"OK: устройств {len(specs)}, кабелей {len(links)}"
        except SystemExit as e:
            return str(e)
        except (ValueError, KeyError, TypeError) as e:
            return f"Ошибка: {e}"

    @mcp.tool(description=f"""[ptgen] Собрать файл .pkt из YAML (без живого PT). Возвращает ссылку на файл
(личная папка пользователя). Открыть его в живом PT: pt_open_project(path=<имя или ссылка>).

{PTGEN_FORMAT}

output_name -- имя файла без расширения.""")
    def build_pkt(yaml_text: str, output_name: str = "topology") -> str:
        try:
            data, nd, nl = ptgen.build(_load_yaml(yaml_text), _template())
        except SystemExit as e:
            return str(e)
        except (ValueError, KeyError, TypeError) as e:
            return f"Ошибка: {e}"
        user = current_user()
        name = safe_file(output_name)
        (user_out(user) / name).write_bytes(data)
        return f"Готово: {file_url(user, name)} -- устройств {nd}, кабелей {nl}"

    @mcp.tool()
    def export_pkt(pkt: str = "") -> str:
        """[ptgen] Разобрать .pkt/.pkz в YAML (устройства, координаты, IP хостов, значимые строки конфигов, кабели).

        pkt -- имя или ссылка вашего файла (из build_pkt / pt_save_project). Пусто -- текущий живой холст
        Packet Tracer (он сохраняется и разбирается)."""
        try:
            if pkt.strip():
                _, raw = _user_pkt(pkt)
            else:
                if ctx.check_bridge():
                    return NOT_CONNECTED
                user = current_user()
                if CANVAS.save(user) != "OK":
                    return "Не удалось сохранить живой холст."
                got = AGENT.call("/file/get", {"name": f"{user['slug']}/_canvas.pkt"})
                raw = base64.b64decode(got["b64"])
            data = ptgen.export(raw)
        except (ValueError, KeyError) as e:
            return f"Ошибка: {e}"
        for d in data["devices"]:
            if "config" in d:
                d["config"] = ptgen._Lit(d["config"])
        data["links"] = [ptgen._Flow(x) for x in data["links"]]
        return yaml.dump(data, allow_unicode=True, sort_keys=False, width=200)

    @mcp.tool()
    def pt_save_project(filename: str) -> str:
        """Сохранить живой холст Packet Tracer как .pkt в вашу личную папку и получить ссылку на файл.

        Parameters:
        - filename: имя файла (.pkt добавится)"""
        err = ctx.check_bridge()
        if err:
            return err
        user = current_user()
        name = safe_file(filename)
        p = AGENT.call("/file/path", {"name": f"{user['slug']}/{name}"})["path"]
        js = (f"var p={json.dumps(p)};ipc.appWindow().fileSaveAsNoPrompt(p,false);"
              "var fm=ipc.systemFileManager();reportResult(fm.fileExists(p)?('OK:'+fm.getFileSize(p)):'ERR')")
        r = AGENT.js(js, timeout=30)
        if not r or not r.startswith("OK"):
            return f"PT не сохранил файл: {r}"
        got = AGENT.call("/file/get", {"name": f"{user['slug']}/{name}"})
        (user_out(user) / name).write_bytes(base64.b64decode(got["b64"]))
        return f"Сохранено: {file_url(user, name)} ({got['size']} байт). Открыть снова: pt_open_project(path='{name}')."

    @mcp.tool()
    def pt_open_project(path: str) -> str:
        """Открыть .pkt в живом Packet Tracer (заменит ваш текущий холст; он сохранён автоматически).

        Parameters:
        - path: имя или ссылка вашего файла -- из build_pkt (ptgen) или pt_save_project."""
        err = ctx.check_bridge()
        if err:
            return err
        user = current_user()
        try:
            name, raw = _user_pkt(path)
        except ValueError as e:
            return f"Ошибка: {e}"
        put = AGENT.call("/file/put", {"name": f"{user['slug']}/{name}", "b64": base64.b64encode(raw).decode()})
        r = CANVAS.open_file(put["path"])
        if not r or not r.startswith("OK"):
            return f"PT не открыл файл: {r}"
        return f"Открыт {name}: устройств {r[3:]}."

    @mcp.tool()
    def pt_list_saved_projects() -> str:
        """Ваши файлы .pkt (из build_pkt и pt_save_project) со ссылками."""
        user = current_user()
        files = sorted(user_out(user).glob("*.pkt"), key=lambda p: -p.stat().st_mtime)
        if not files:
            return "Файлов пока нет."
        return "\n".join(f"- {p.name} ({p.stat().st_size} байт, {time.strftime('%d.%m %H:%M', time.localtime(p.stat().st_mtime))}): "
                         f"{file_url(user, p.name)}" for p in files)

    @mcp.tool()
    def pt_bridge_status() -> str:
        """Состояние живого Packet Tracer: агент на Windows-хосте, PT, расширение, UI, чей холст открыт, очередь."""
        h = AGENT.health(fresh=True) or {}
        user = current_user()
        lines = [
            f"Агент Windows-хоста: {'на связи' if 'error' not in h else 'НЕТ СВЯЗИ: ' + h['error']}",
            f"Packet Tracer: {'запущен, pid ' + ','.join(map(str, h['pt_pids'])) if h.get('pt_pids') else 'не запущен'}",
            f"Расширение MCP (файловый ящик): {'отвечает' if h.get('pt_alive') else 'не отвечает (PT не запущен, ждёт входа NetAcad или расширение не установлено)'}",
            f"Окна устройств (UI Automation): {'да' if h.get('ui') else 'нет: ' + str(h.get('ui_why'))}",
            f"Сеанс: {h.get('user')} #{h.get('session')}",
            f"Открыт холст: {'ваш' if CANVAS.state.get('user') == user['slug'] else 'другого пользователя (ваш откроется при первом живом вызове)'}",
            f"Вы: {user['username']}{' (администратор)' if user['admin'] else ''}",
        ]
        return "\n".join(lines)

    @mcp.tool()
    def pt_desktop_screenshot() -> str:
        """[администраторы] Снимок всего рабочего стола служебного сеанса на Windows-хосте (диалоги PT, вход NetAcad)."""
        r = AGENT.call("/screen", timeout=30)
        p = user_dir(current_user()) / "desktop" / f"desktop-{time.strftime('%Y%m%d-%H%M%S')}.png"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(base64.b64decode(r["png"]))
        w = AGENT.call("/windows")
        return "Окна PT: " + json.dumps(w.get("windows"), ensure_ascii=False)

    @mcp.tool()
    def pt_desktop_input(action: str, x: int = 0, y: int = 0, text: str = "", keys: str = "") -> str:
        """[администраторы] Мышь/клавиатура в служебном сеансе: action = click|dblclick|rclick|move|scroll|type|key.
        Координаты -- как на pt_desktop_screenshot. keys -- например "enter", "ctrl+s", "alt+f4". Пароли сюда не вводить."""
        r = AGENT.call("/input", {"action": action, "x": x, "y": y, "text": text, "keys": keys})
        return json.dumps(r, ensure_ascii=False)

    @mcp.tool()
    def pt_restart_packet_tracer() -> str:
        """[администраторы] Перезапустить Packet Tracer в служебном сеансе (после этого может понадобиться вход NetAcad)."""
        AGENT.call("/pt/stop", {"pause": True})
        time.sleep(3)
        r = AGENT.call("/pt/start")
        CANVAS.state = {}
        return json.dumps(r, ensure_ascii=False)


# --------------------------------------------------------------------------- сервер
INSTRUCTIONS = (
    "Packet Tracer: живой Cisco Packet Tracer 9 (общий для всех, у каждого пользователя свой холст, "
    "вызовы идут по очереди) + сборка .pkt из YAML (ptgen). Скриншоты холста (pt_screenshot) и окон устройств "
    "(capture=True / pt_ui_capture) приходят как изображения. Свои файлы: build_pkt, pt_save_project, "
    "pt_list_saved_projects, pt_open_project. Если PT недоступен -- pt_bridge_status.\n\n" + SERVER_INSTRUCTIONS
)


def build_server(host: str = "127.0.0.1", port: int = 8765) -> FastMCP:
    mcp = FastMCP("ptgen", instructions=INSTRUCTIONS, host=host, port=port, stateless_http=True)
    ctx = RemoteBridge()
    register_tools(mcp, ctx)
    manager = mcp._tool_manager
    for n in ("pt_save_project", "pt_open_project", "pt_bridge_status"):
        manager._tools.pop(n, None)  # заменены своими: личные папки и Windows-хост
    register_own(mcp, ctx)
    register_resources(mcp)
    register_prompts(mcp)
    for tool in manager.list_tools():
        wrap(mcp, tool)
    return mcp


# --------------------------------------------------------------------------- вход
_auth_cache: dict[str, tuple[float, dict | None]] = {}


async def introspect(token: str) -> dict | None:
    key = hashlib.sha256(token.encode()).hexdigest()
    hit = _auth_cache.get(key)
    if hit and time.monotonic() - hit[0] < 60:
        return hit[1]
    info = None
    try:
        async with httpx.AsyncClient(timeout=10) as cli:
            r = await cli.post(INTROSPECT_URL, json={"token": token, "server": "ptgen"},
                               headers={"X-Introspect-Secret": INTROSPECT_SECRET})
        d = r.json() if r.status_code == 200 else {}
        if d.get("active"):
            info = {"username": d["username"], "slug": slug(d["username"]), "admin": bool(d.get("is_admin")),
                    "scope": d.get("scope", "")}
    except (httpx.HTTPError, ValueError) as exc:
        log(f"introspect: {exc}")
        return None
    _auth_cache[key] = (time.monotonic(), info)
    return info


class AuthMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or AUTH == "none":
            return await self.app(scope, receive, send)
        # каталог MCP портала читает список инструментов (tools/list) по секрету интроспекции, без пользователя
        cat = dict(scope.get("headers") or []).get(b"x-catalog-secret", b"").decode()
        if cat and INTROSPECT_SECRET and hmac.compare_digest(cat, INTROSPECT_SECRET):
            return await self._catalog(scope, receive, send)
        hdr = dict(scope.get("headers") or []).get(b"authorization", b"").decode()
        user = None
        if hdr.lower().startswith("bearer "):
            user = await introspect(hdr[7:].strip())
        if not user:
            body = json.dumps({"error": "invalid_token", "error_description": "Нужен вход"}).encode()
            await send({"type": "http.response.start", "status": 401, "headers": [
                (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                (b"www-authenticate", f'Bearer realm="{REALM}", error="invalid_token", resource_metadata="{RESOURCE_METADATA}"'.encode())]})
            await send({"type": "http.response.body", "body": body})
            return
        scope["ptgen_user"] = user
        await self.app(scope, receive, send)

    CATALOG_METHODS = {"initialize", "notifications/initialized", "ping", "tools/list"}

    async def _catalog(self, scope, receive, send):
        body, more = b"", True
        while more:
            m = await receive()
            body += m.get("body", b"")
            more = m.get("more_body", False)
        ok = scope.get("method") == "DELETE"
        if scope.get("method") == "POST":
            try:
                d = json.loads(body or b"null")
            except ValueError:
                d = None
            items = d if isinstance(d, list) else [d]
            ok = bool(items) and all(isinstance(i, dict) and i.get("method") in self.CATALOG_METHODS for i in items)
        if not ok:
            out = json.dumps({"error": "forbidden", "error_description": "каталогу доступны только initialize и tools/list"}).encode()
            await send({"type": "http.response.start", "status": 401, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(out)).encode())]})
            await send({"type": "http.response.body", "body": out})
            return
        scope["ptgen_user"] = {"username": "catalog", "slug": "_catalog", "admin": False, "scope": "read"}
        sent = False

        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()
        await self.app(scope, replay, send)


def main():
    import uvicorn

    host = ENV("PTGEN_HOST", "127.0.0.1")
    port = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[1] == "--http" else 8765
    mcp = build_server(host, port)
    if len(sys.argv) < 2:
        mcp.run()  # stdio
        return
    DATA.mkdir(parents=True, exist_ok=True)
    app = AuthMiddleware(mcp.streamable_http_app())
    log(f"ptgen-live: {len(mcp._tool_manager.list_tools())} инструментов, auth={AUTH}, агент {AGENT_URL}")
    uvicorn.run(app, host=host, port=port, log_level="warning", proxy_headers=True)


if __name__ == "__main__":
    main()

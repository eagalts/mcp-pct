"""ptagent -- агент живого Packet Tracer на Windows-хосте.

Работает в сеансе служебной учётки рядом с Packet Tracer 9 и расширением
«MCP Control Center» (файловый ящик в %LOCALAPPDATA%\\packet-tracer-mcp\\bridge).
Сам ничего не решает: сервер ptgen-MCP присылает ему JS для Script Engine,
вызовы окон устройств (UI Automation) и просит снимки. Наружу не публикуется:
TLS + токен, брандмауэр пускает порт только с адреса сервера.

Конечные точки (POST, JSON, Authorization: Bearer <token>):
  /health                      PT жив? pid, UI, сеанс
  /js      {code, timeout, wait}   JS в Script Engine через файловый ящик
  /ui      {method, args, kwargs}  Presenter образца (окна устройств); capture -> PNG
  /screen  {}                      снимок всего рабочего стола сеанса (PNG)
  /window  {title}                 снимок окна PT по заголовку ("" -- главное окно)
  /input   {action, x, y, text, keys}  мышь/клавиатура (только для администраторов, проверяет сервер)
  /windows {}                      список окон PT (заголовки)
  /file/put|get|list|delete {name, b64}  файлы .pkt в рабочем каталоге (без подкаталогов вне него)
  /pt/start, /pt/stop          запустить / остановить свой PacketTracer.exe

Код образца (MIT, Mats2208/MCP-Packet-Tracer) лежит рядом в vendor/ без изменений.
"""
from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes as wt
import hashlib
import hmac
import json
import os
import re
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _crash(t, v, tb):  # pythonw без консоли: всё, что упало до журнала, -- в logs/crash.log
    import traceback
    (HERE / "logs").mkdir(exist_ok=True)
    with (HERE / "logs" / "crash.log").open("a", encoding="utf-8") as f:
        f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + "".join(traceback.format_exception(t, v, tb)))


sys.excepthook = _crash
for p in (HERE / "vendor", HERE / "pylib"):
    sys.path.insert(0, str(p))

from packet_tracer_mcp.infrastructure.execution.file_bridge import FileBridge  # noqa: E402
from packet_tracer_mcp.infrastructure.ui import win32 as w32  # noqa: E402
from packet_tracer_mcp.infrastructure.ui.png import bgra_to_png, looks_blank  # noqa: E402
from packet_tracer_mcp.infrastructure.ui.presenter import Presenter, PresenterError, is_available  # noqa: E402

CFG = json.loads((HERE / "agent.json").read_text(encoding="utf-8-sig"))
TOKEN_SHA = CFG["token_sha256"]
ALLOW = set(CFG.get("allow", []))
WORK = Path(CFG.get("work", HERE / "work"))
PT_EXE = CFG.get("pt_exe", r"C:\Program Files\Cisco Packet Tracer 9.0.0\bin\PacketTracer.exe")
LOG = HERE / "logs" / "ptagent.log"
MAX_BODY = 40 * 1024 * 1024
UI_METHODS = {"device_info", "open", "close", "capture", "fill_and_go", "invoke_button", "scroll_consoles"}

BRIDGE = FileBridge()
PRESENTER = Presenter(lambda js, timeout=10.0: BRIDGE.send_and_wait(js, timeout=timeout))
LOCK = threading.RLock()  # PT однопоточен: одна операция за раз

user32 = ctypes.WinDLL("user32", use_last_error=True)
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
try:
    user32.SetProcessDPIAware()
except Exception:
    pass


def log(msg: str) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg + "\n")


# ------------------------------------------------------------------ PT process
def pt_pids() -> list[int]:
    """PID PacketTracer.exe ТЕКУЩЕГО сеанса (чужие сеансы не трогаем)."""
    sid = ctypes.c_ulong()
    ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(sid))
    out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq PacketTracer.exe", "/FI", f"SESSION eq {sid.value}", "/FO", "CSV", "/NH"],
                         capture_output=True, text=True, timeout=15).stdout
    return [int(m.group(1)) for m in re.finditer(r'^"PacketTracer\.exe","(\d+)"', out, re.M)]


def pt_start() -> dict:
    PAUSE.unlink(missing_ok=True)
    if pt_pids():
        return {"started": False, "pids": pt_pids()}
    subprocess.Popen([PT_EXE], cwd=str(Path(PT_EXE).parent), close_fds=True)
    log("PT start")
    return {"started": True}


def pt_stop(pause: bool = False) -> dict:
    if pause:
        PAUSE.write_text("1")
    pids = pt_pids()
    for pid in pids:
        subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, timeout=15)
    log(f"PT stop {pids}")
    return {"stopped": pids}


# ------------------------------------------------------------------ capture / input
def screen_png() -> bytes:
    SM_XV, SM_YV, SM_CXV, SM_CYV = 76, 77, 78, 79
    x, y = user32.GetSystemMetrics(SM_XV), user32.GetSystemMetrics(SM_YV)
    w, h = user32.GetSystemMetrics(SM_CXV), user32.GetSystemMetrics(SM_CYV)
    hdc = user32.GetDC(0)
    mdc = gdi32.CreateCompatibleDC(hdc)
    bmp = gdi32.CreateCompatibleBitmap(hdc, w, h)
    old = gdi32.SelectObject(mdc, bmp)
    try:
        gdi32.BitBlt(mdc, 0, 0, w, h, hdc, x, y, 0x00CC0020 | 0x40000000)  # SRCCOPY|CAPTUREBLT
        bih = w32._BITMAPINFOHEADER(ctypes.sizeof(w32._BITMAPINFOHEADER), w, -h, 1, 32, 0, 0, 0, 0, 0, 0)
        buf = ctypes.create_string_buffer(w * h * 4)
        gdi32.GetDIBits(mdc, bmp, 0, h, buf, ctypes.byref(bih), 0)
        return bgra_to_png(w, h, buf.raw)
    finally:
        gdi32.SelectObject(mdc, old)
        gdi32.DeleteObject(bmp)
        gdi32.DeleteDC(mdc)
        user32.ReleaseDC(0, hdc)


def pt_windows() -> list[dict]:
    res = []
    for pid in pt_pids():
        for hwnd, title in w32.top_windows(pid):
            r = wt.RECT()
            user32.GetWindowRect(hwnd, ctypes.byref(r))
            res.append({"hwnd": hwnd, "title": title, "rect": [r.left, r.top, r.right, r.bottom]})
    return res


def window_png(title: str) -> dict:
    pids = pt_pids()
    if not pids:
        raise PresenterError("Packet Tracer не запущен")
    hwnd = None
    for pid in pids:
        hwnd = w32.find_window(pid, title) if title else w32.main_window(pid)
        if hwnd:
            break
    if not hwnd:
        raise PresenterError(f"окно «{title}» не найдено")
    w32.raise_window(hwnd)
    time.sleep(0.2)
    w, h, bgra = w32.capture(hwnd)
    return {"png": base64.b64encode(bgra_to_png(w, h, bgra)).decode(), "width": w, "height": h, "blank": looks_blank(bgra)}


class _MI(ctypes.Structure):
    _fields_ = [("dx", ctypes.c_long), ("dy", ctypes.c_long), ("mouseData", ctypes.c_ulong), ("dwFlags", ctypes.c_ulong),
                ("time", ctypes.c_ulong), ("dwExtraInfo", ctypes.c_size_t)]


class _KI(ctypes.Structure):
    _fields_ = [("wVk", ctypes.c_ushort), ("wScan", ctypes.c_ushort), ("dwFlags", ctypes.c_ulong), ("time", ctypes.c_ulong),
                ("dwExtraInfo", ctypes.c_size_t)]


class _IU(ctypes.Union):
    _fields_ = [("mi", _MI), ("ki", _KI), ("pad", ctypes.c_byte * 32)]


class _INPUT(ctypes.Structure):
    _fields_ = [("type", ctypes.c_ulong), ("u", _IU)]


def _send(*inputs):
    arr = (_INPUT * len(inputs))(*inputs)
    user32.SendInput(len(inputs), arr, ctypes.sizeof(_INPUT))


def _mouse(flags, data=0):
    return _INPUT(0, _IU(mi=_MI(0, 0, data, flags, 0, 0)))


def _key(vk=0, scan=0, flags=0):
    return _INPUT(1, _IU(ki=_KI(vk, scan, flags, 0, 0)))


VK = {"enter": 0x0D, "tab": 0x09, "esc": 0x1B, "escape": 0x1B, "backspace": 0x08, "delete": 0x2E, "space": 0x20,
      "up": 0x26, "down": 0x28, "left": 0x25, "right": 0x27, "home": 0x24, "end": 0x23, "pageup": 0x21, "pagedown": 0x22,
      "ctrl": 0x11, "shift": 0x10, "alt": 0x12, "win": 0x5B, "f1": 0x70, "f2": 0x71, "f4": 0x73, "f5": 0x74, "f10": 0x79}


def do_input(a: dict) -> dict:
    act = a.get("action")
    if act in ("click", "dblclick", "rclick", "move"):
        user32.SetCursorPos(int(a["x"]), int(a["y"]))
        time.sleep(0.05)
        down, up = (0x0008, 0x0010) if act == "rclick" else (0x0002, 0x0004)
        for _ in range({"click": 1, "rclick": 1, "dblclick": 2, "move": 0}[act]):
            _send(_mouse(down), _mouse(up))
            time.sleep(0.06)
    elif act == "scroll":
        user32.SetCursorPos(int(a["x"]), int(a["y"]))
        _send(_mouse(0x0800, ctypes.c_ulong(int(a.get("amount", -3)) * 120).value))
    elif act == "type":
        for ch in str(a.get("text", "")):
            code = ord(ch)
            _send(_key(0, code, 0x0004), _key(0, code, 0x0004 | 0x0002))  # KEYEVENTF_UNICODE
            time.sleep(0.01)
    elif act == "key":
        combo = [VK.get(k.lower(), ord(k.upper()[0]) if len(k) == 1 else None) for k in str(a.get("keys", "")).split("+")]
        if None in combo:
            raise ValueError(f"неизвестная клавиша в {a.get('keys')}")
        _send(*[_key(v) for v in combo])
        _send(*[_key(v, 0, 0x0002) for v in reversed(combo)])
    else:
        raise ValueError(f"неизвестное действие {act}")
    return {"ok": True}


# ------------------------------------------------------------------ files
def _safe(name: str) -> Path:
    name = str(name).replace("\\", "/").strip("/")
    if not re.fullmatch(r"[A-Za-z0-9._@\-]+(/[A-Za-z0-9._@\-]+)?", name) or ".." in name:
        raise ValueError("недопустимое имя файла")
    p = (WORK / name).resolve()
    if WORK.resolve() not in p.parents:
        raise ValueError("вне рабочего каталога")
    return p


def files(op: str, a: dict) -> dict:
    if op == "list":
        sub = _safe(a["dir"]) if a.get("dir") else WORK
        return {"files": [{"name": str(f.relative_to(WORK)).replace("\\", "/"), "size": f.stat().st_size, "mtime": f.stat().st_mtime}
                          for f in sorted(sub.rglob("*")) if f.is_file()] if sub.exists() else []}
    p = _safe(a["name"])
    if op == "put":
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(base64.b64decode(a["b64"]))
        return {"path": str(p).replace("\\", "/"), "size": p.stat().st_size}
    if op == "get":
        return {"b64": base64.b64encode(p.read_bytes()).decode(), "size": p.stat().st_size} if p.exists() else {"missing": True}
    if op == "delete":
        p.unlink(missing_ok=True)
        return {"deleted": True}
    if op == "path":
        p.parent.mkdir(parents=True, exist_ok=True)
        return {"path": str(p).replace("\\", "/"), "exists": p.exists()}
    raise ValueError(op)


# ------------------------------------------------------------------ ui
def ui_call(a: dict) -> dict:
    m = a.get("method")
    if m not in UI_METHODS:
        raise ValueError(f"метод {m} не разрешён")
    args, kw = list(a.get("args") or []), dict(a.get("kwargs") or {})
    if m == "capture":
        tmp = WORK / "_captures" / f"cap_{time.time_ns()}.png"
        info = PRESENTER.capture(args[0] if args else kw.get("device", ""), tmp)
        info["png"] = base64.b64encode(tmp.read_bytes()).decode()
        tmp.unlink(missing_ok=True)
        return {"result": info}
    if m == "scroll_consoles":
        args = args[:1]
    return {"result": getattr(PRESENTER, m)(*args, **kw)}


def health() -> dict:
    sid = ctypes.c_ulong()
    ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(sid))
    ok, why = is_available()
    return {"pt_alive": BRIDGE.pt_alive(), "pt_pids": pt_pids(), "ui": ok, "ui_why": why, "session": sid.value,
            "user": os.environ.get("USERNAME"), "bridge_dir": str(BRIDGE.dir), "time": time.time()}


ROUTES = {
    "/health": lambda a: health(),
    "/js": lambda a: {"result": BRIDGE.send_and_wait(a["code"], timeout=float(a.get("timeout", 10)))} if a.get("wait", True)
    else {"sent": BRIDGE.send(a["code"])},
    "/ui": ui_call,
    "/screen": lambda a: {"png": base64.b64encode(screen_png()).decode()},
    "/window": lambda a: window_png(a.get("title", "")),
    "/windows": lambda a: {"windows": pt_windows()},
    "/input": do_input,
    "/pt/start": lambda a: pt_start(),
    "/pt/stop": lambda a: pt_stop(bool(a.get("pause"))),
}


class H(BaseHTTPRequestHandler):
    server_version = "ptagent"

    def log_message(self, *args):
        pass

    def _reply(self, code: int, obj: dict) -> None:
        body = json.dumps(obj, ensure_ascii=False, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._reply(405, {"error": "POST only"})

    def do_POST(self):
        if ALLOW and self.client_address[0] not in ALLOW:
            return self._reply(403, {"error": "forbidden"})
        tok = (self.headers.get("Authorization") or "")[7:].strip()
        if not hmac.compare_digest(hashlib.sha256(tok.encode()).hexdigest(), TOKEN_SHA):
            log(f"401 from {self.client_address[0]} {self.path}")
            return self._reply(401, {"error": "unauthorized"})
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            return self._reply(413, {"error": "too large"})
        try:
            a = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._reply(400, {"error": "bad json"})
        path = self.path.split("?")[0]
        try:
            if path.startswith("/file/"):
                fn = lambda x: files(path[6:], x)  # noqa: E731
            else:
                fn = ROUTES.get(path)
            if fn is None:
                return self._reply(404, {"error": "no route"})
            global LAST_USE
            if path != "/health":
                LAST_USE = time.time()
            with LOCK:
                if path in NEEDS_PT:
                    ensure_pt()
                res = fn(a)
            self._reply(200, res)
        except PresenterError as e:
            self._reply(200, {"error": str(e), "presenter": True})
        except Exception as e:  # noqa: BLE001
            log(f"{path} {type(e).__name__}: {e}")
            self._reply(500, {"error": f"{type(e).__name__}: {e}"})


def main():
    WORK.mkdir(parents=True, exist_ok=True)
    srv = ThreadingHTTPServer((CFG.get("bind", "0.0.0.0"), int(CFG.get("port", 39410))), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(HERE / "tls" / "agent.crt"), str(HERE / "tls" / "agent.key"))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    log(f"listen {CFG.get('bind', '0.0.0.0')}:{CFG.get('port', 39410)} session-user={os.environ.get('USERNAME')}")
    threading.Thread(target=keep_pt, daemon=True).start()
    threading.Thread(target=idle_watch, daemon=True).start()
    srv.serve_forever()


LAST_USE = time.time()
NEEDS_PT = {"/js", "/ui", "/screen", "/window", "/windows", "/input"}
IDLE_STOP_MIN = float(CFG.get("idle_stop_min", 0) or 0)


def ensure_pt() -> None:
    """Packet Tracer по требованию: запрос, которому нужен PT, сам его поднимает (вызывается под LOCK).
    Пульс Script Engine живёт 6 с после остановки PT, поэтому ждём пульс, свежее момента запуска."""
    if pt_pids() and BRIDGE.pt_alive():
        return
    t0 = time.time()
    if not pt_pids():
        pt_start()
    for _ in range(60):
        time.sleep(2)
        try:
            beat = (BRIDGE.dir / "alive.txt").stat().st_mtime
        except OSError:
            beat = 0.0
        if pt_pids() and beat > t0 and BRIDGE.pt_alive():
            return
    log("ensure_pt: PT не ответил за 120 с")

def idle_watch():
    """Экономия ОЗУ и процессора: PT не нужен без запросов -- через idle_stop_min минут простоя закрываем его."""
    while IDLE_STOP_MIN > 0:
        time.sleep(60)
        try:
            if time.time() - LAST_USE > IDLE_STOP_MIN * 60 and pt_pids():
                with LOCK:
                    if time.time() - LAST_USE > IDLE_STOP_MIN * 60:
                        log(f"idle {IDLE_STOP_MIN:.0f} min: stop PT")
                        pt_stop()
        except Exception as e:  # noqa: BLE001
            log(f"idle_watch: {e}")

def keep_pt():
    """Сторож: PT должен быть запущен всегда (кроме паузы после /pt/stop)."""
    while CFG.get("keep_pt", True):
        try:
            if not PAUSE.exists():
                with LOCK:
                    if not pt_pids():
                        pt_start()
        except Exception as e:  # noqa: BLE001
            log(f"keep_pt: {e}")
        time.sleep(30)


PAUSE = HERE / "pt.pause"  # есть файл -- сторож PT не перезапускает


if __name__ == "__main__":
    main()

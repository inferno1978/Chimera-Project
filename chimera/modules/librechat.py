#!/usr/bin/env python3
"""
chimera/modules/librechat.py
───────────────────────────────────────────────────────────────────────────────
LibreChat (LibreChat-AI/LibreChat, MIT) — AI-чат платформа в Chimera:
TUI-модуль жизненного цикла по образцу dpi_bypass (B4) и панелей
Triple Panel / WPP Web Panel.

ЧТО ЭТО:
  Self-hosted ИИ-чат (мультипровайдерный: OpenAI-совместимые endpoint'ы,
  Anthropic, Google, Agents, MCP, RAG) в docker compose стеке апстрима:
  api + admin-panel + mongodb + meilisearch + vectordb + rag_api.

    • скачивание     → download_manager.py (тарболл апстрима, зеркала)
    • порты          → port_registry.py (конфликт-чек + регистрация)
    • доступ         → panel_nginx_front.py (SSH-туннель / self-signed /
                       Let's Encrypt домен + ufw deny прямого порта)
    • версии         → GitHub API releases/latest + TTL-кэш 5 мин
                       (паттерн dpi_bypass.py) + смоук с откатом
    • сервис         → librechat.service (docker compose up -d)
    • docker         → apt docker.io + docker-compose-v2 (Ubuntu/Debian)

АРХИТЕКТУРА:
  • /opt/librechat — вендореный код апстрима (compose + .env + данные);
    bind-mount'ы данных (data-node, meili_data, images, uploads, logs)
    живут рядом и НЕ трогаются при обновлении кода.
  • Композ апстрима публикует порты на 0.0.0.0 — модуль патчит маппинги
    на 127.0.0.1 (loopback): наружу только через nginx front (TLS).
  • .env генерируется из .env.example апстрима: PORT, CREDS_KEY/CREDS_IV
    (openssl rand hex), MEILI_MASTER_KEY, UID/GID, ALLOW_REGISTRATION.
  • GLM (Z.ai) подключается опционально как custom endpoint
    (librechat.yaml + ZAI_API_KEY в .env) — OpenAI-совместимый API.
  • Обновление: rollback-теги образов (docker tag) + свежий compose +
    pull + up -d + смоук GET /api/version; провал → откат образов/файлов.

ВЕРСИИ:
  version — тег апстрима, чей код вендорен (v0.8.8 на момент порта).
  upstream_version — последний релиз на GitHub (кэш 5 мин).

Точка входа из TUI (раздел 1 → W → 9):
    from chimera.modules.librechat import do_librechat_menu

ПОЛНАЯ АВТОНОМНОСТЬ: модуль НЕ требует изменений в _core.py. Ядро
резолвится лениво через _core_module() (паттерн warp.py).
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

# ── Прямой запуск (python3 .../librechat.py) — bootstrap корня проекта ─────
if __package__ in (None, ""):
    _ROOT = Path(__file__).resolve().parent.parent.parent
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))

from chimera.modules.proto_common import proto_ask, ProtoCancelled
# Единая ANSI/emoji-осведомлённая ширина строк — как во всех модулях
# с box-рендером (naiveproxy/mieru/triple_panel/...).
from chimera.modules.text_width import wlen as _wlen, plain as _plain
# Конвенция проекта: локальный алиас (см. triple_panel.py — proto_common
# НЕ экспортирует имя `_Cancelled`, импорт падает ImportError).
_Cancelled = ProtoCancelled

# ════════════════════════════════════════════════════════════════════════════
#  КОНСТАНТЫ
# ════════════════════════════════════════════════════════════════════════════
STATE_DIR      = Path("/var/lib/xray-installer")
_STATE_FILE    = STATE_DIR / "librechat_state.json"
_APP_DIR       = Path("/opt/librechat")              # код + данные апстрима
_STAGING_DIR   = STATE_DIR / "librechat_staging"     # atomic staging тарболла
_BACKUP_DIR    = STATE_DIR / "librechat_update_backup"  # откат обновления
_SERVICE_FILE  = Path("/etc/systemd/system/librechat.service")
_SERVICE_NAME  = "librechat"
_DEFAULT_PORT  = 3080                                 # api (loopback)
_DEFAULT_ADMIN_PORT = 3095                            # admin-panel (loopback)
_PORT_TAG      = "librechat_web"
_PROJECT_ROOT  = Path(__file__).resolve().parent.parent.parent

_NGINX_STATE_FILE = STATE_DIR / "librechat_nginx.json"
_NGINX_SITE_NAME  = "chimera-librechat"
DEFAULT_NGINX_PORT = 3443

# Апстрим (MIT). Лицензия сохраняется в вендореном коде.
_UPSTREAM_REPO       = "LibreChat-AI/LibreChat"
_UPSTREAM_API_LATEST = f"https://api.github.com/repos/{_UPSTREAM_REPO}/releases/latest"
_UPSTREAM_CACHE_TTL  = 300        # сек (5 мин) — паттерн _b4_latest_cache
_LC_VERSION          = "0.8.8"    # версия порта: код+контракт вендорены

# Образы стека (справочно; сам compose — источник истины). Откат
# обновления помечает эти образы тегами librechat-rollback:*.
_ROLLBACK_TAG_PREFIX = "librechat-rollback"

# Каталоги данных апстрима внутри /opt/librechat — НЕ удаляются при
# обновлении кода и опционально сохраняются при удалении.
_DATA_DIRS = ("data-node", "meili_data_v1.35.1", "images", "uploads",
              "logs", "skill")

# ── Цвета (канон проекта: naiveproxy.py / mieru.py — НЕ bright-палитра) ─────
def _detect_colors() -> dict:
    if os.environ.get("NO_COLOR"):
        return {k: "" for k in ("CYAN", "NC", "GREEN", "YELLOW", "RED",
                                 "BOLD", "DIM", "WHITE")}
    if not sys.stdout.isatty() and os.environ.get("FORCE_COLOR") is None:
        return {k: "" for k in ("CYAN", "NC", "GREEN", "YELLOW", "RED",
                                 "BOLD", "DIM", "WHITE")}
    # Точная палитра модулей проекта (naiveproxy dark): 0;3x, а не яркие 9x
    return {
        "CYAN": "\033[0;36m", "NC": "\033[0m", "GREEN": "\033[0;32m",
        "YELLOW": "\033[1;33m", "RED": "\033[0;31m",
        "BOLD": "\033[1m", "DIM": "\033[2m", "WHITE": "\033[1;37m",
    }
_C = _detect_colors()
CYAN, NC   = _C["CYAN"], _C["NC"]
GREEN, YELLOW, RED = _C["GREEN"], _C["YELLOW"], _C["RED"]
BOLD, DIM, WHITE = _C["BOLD"], _C["DIM"], _C["WHITE"]

_BOX_W = 66

# ════════════════════════════════════════════════════════════════════════════
#  ЯДРО / STATE / ЛОГ (лениво, как warp.py / triple_panel.py)
# ════════════════════════════════════════════════════════════════════════════
def _core_module():
    import importlib
    return importlib.import_module("chimera._core")

def _log(level: str, msg: str) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        with open("/var/log/chimera.log", "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S")
                    + f" [LIBRECHAT][{level}] {msg}\n")
    except Exception:
        pass

def _info(msg): print(f"{CYAN}[INFO]{NC}  {msg}"); _log("INFO", msg)
def _ok(msg):   print(f"{GREEN}[OK]{NC}    {msg}"); _log("OK", msg)
def _warn(msg): print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)
def _err(msg):  print(f"{RED}[ERR]{NC}   {msg}");   _log("ERR", msg)

def _load_state() -> dict:
    from chimera.modules.proto_common import proto_load_state
    defaults = {
        "installed": False,
        "web_port": _DEFAULT_PORT,
        "admin_port": _DEFAULT_ADMIN_PORT,
        "version": "",                 # тег вендореного кода (v0.8.8)
        "runtime_version": "",         # фактическая версия api (смоук)
        "zai_enabled": False,
        "allow_registration": True,
        "upstream_cache": {"version": "", "ts": 0},
        "installed_at": "",
    }
    return proto_load_state(_STATE_FILE, defaults)

def _save_state(state: dict) -> None:
    from chimera.modules.proto_common import proto_save_state
    proto_save_state(_STATE_FILE, state)

# ════════════════════════════════════════════════════════════════════════════
#  BOX-РЕНДЕРИНГ (канон проекта: naiveproxy.py / mieru.py / triple_panel.py)
# ════════════════════════════════════════════════════════════════════════════
def _box_top(title: str = "") -> None:
    print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")
    if title:
        pad = _BOX_W - _wlen(title); lpad = pad // 2; rpad = pad - lpad
        print(f"{CYAN}║{NC}{' ' * lpad}{BOLD}{WHITE}{title}{NC}{' ' * rpad}{CYAN}║{NC}")
        print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")

def _box_sep() -> None: print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")
def _box_bot() -> None: print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")

def _truncate_ansi(text: str, max_w: int) -> str:
    """Обрезает text до видимой ширины max_w-1 + «…», не рвя ANSI-коды."""
    out, acc, i, n = [], 0, 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "\x1b":                      # CSI-код — целиком, ширина 0
            j = i + 1
            if j < n and text[j] == "[":
                j += 1
                while j < n and not text[j].isalpha():
                    j += 1
                if j < n:
                    j += 1
            out.append(text[i:j]); i = j
            continue
        w = _wlen(ch)
        if acc + w > max_w - 1:               # резерв под «…»
            return "".join(out) + "…"
        out.append(ch); acc += w; i += 1
    return "".join(out)

def _render_box_row(text: str) -> str:
    w = _wlen(text)
    if w > _BOX_W:
        text = _truncate_ansi(text, _BOX_W); w = _wlen(text)
    pad = max(0, _BOX_W - w)
    return f"{CYAN}║{NC}{text}{' ' * pad}{CYAN}║{NC}"

def _box_row(text: str = "") -> None:
    print(_render_box_row(text))

def _box_item(key: str, label: str) -> None:
    col = RED + BOLD if key.strip().upper() in ("Q", "0") else WHITE + BOLD
    _box_row(f"  {DIM}[{NC}{col}{key}{NC}{DIM}]{NC}  {label}")

def _box_kv(key: str, val: str, kw: int = 22) -> None:
    key_colored = f"{CYAN}{key}{NC}"
    key_pad = kw - _wlen(key_colored)
    _box_row(f"  {key_colored}{' ' * max(0, key_pad)}  {val}")

def _box_ok(msg: str)   -> None: _box_row(f"  {GREEN}✓{NC}  {msg}")
def _box_warn(msg: str) -> None: _box_row(f"  {YELLOW}⚠{NC}  {msg}")
def _box_info(msg: str) -> None: _box_row(f"  {CYAN}→{NC}  {msg}")
def _box_err(msg: str)  -> None: _box_row(f"  {RED}✗{NC}  {msg}")

def _box_link(link: str, color: str = "") -> None:
    color = color or YELLOW; max_w = _BOX_W - 2
    plain_link = _plain(link); i = 0
    while i < len(plain_link):
        chunk = plain_link[i:i + max_w]
        pad = max(0, _BOX_W - 2 - _wlen(chunk))
        print(f"{CYAN}║{NC}  {color}{chunk}{NC}{' ' * pad}{CYAN}║{NC}")
        i += max_w

# ════════════════════════════════════════════════════════════════════════════
#  LIVE-BOX — сырой вывод стороннего кода строками бокса (канон triple_panel)
# ════════════════════════════════════════════════════════════════════════════
def _ansi_wrap(text: str, first_w: int, cont_w: int, cont_prefix: str) -> list:
    rows, cur, cur_w, width, prefix = [], [], 0, first_w, ""
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "\x1b":
            j = i + 1
            if j < n and text[j] == "[":
                j += 1
                while j < n and not text[j].isalpha():
                    j += 1
                if j < n:
                    j += 1
            cur.append(text[i:j]); i = j
            continue
        if ch == "\r":
            i += 1
            continue
        w = _wlen(ch)
        if cur and cur_w + w > width:
            rows.append(prefix + "".join(cur))
            cur, cur_w = [], 0
            width, prefix = cont_w, cont_prefix
            if ch == " ":
                i += 1
            continue
        cur.append(ch); cur_w += w; i += 1
    if cur or not rows:
        rows.append(prefix + "".join(cur))
    return rows

class _BoxedStdout:
    """Прокси sys.stdout: полные строки → строки бокса (live-frame)."""

    def __init__(self, real):
        self._real = real
        self._buf = ""
        self._raw_open = False

    def write(self, s):
        if not s:
            return 0
        if self._raw_open:
            self._raw_open = False
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            self._emit(line)
        return len(s)

    def _emit(self, line: str) -> None:
        line = line.rstrip()
        if not line.strip():
            self._real.write(f"{CYAN}║{NC}{' ' * _BOX_W}{CYAN}║{NC}\n")
            return
        p = _plain(line)
        if (p.startswith("║") and p.endswith("║")
                and _wlen(p) == _BOX_W + 2):
            self._real.write(line + "\n")
            return
        for row in _ansi_wrap(line, _BOX_W, _BOX_W - 2, "  "):
            self._real.write(_render_box_row(row) + "\n")

    def flush(self):
        if self._buf and not self._raw_open:
            self._real.write(self._buf)
            self._buf = ""
            self._raw_open = True
        self._real.flush()

    def isatty(self):
        return self._real.isatty()

    def fileno(self):
        return self._real.fileno()

    @property
    def encoding(self):
        return getattr(self._real, "encoding", "utf-8")

    def __getattr__(self, name):
        return getattr(self._real, name)

@contextmanager
def _boxed_output():
    real = sys.stdout
    sys.stdout = _BoxedStdout(real)
    try:
        yield
    finally:
        sys.stdout = real
        try:
            real.flush()
        except Exception:
            pass

def _redraw_ask_row(label: str, value: str) -> None:
    try:
        row = _render_box_row(f"  {CYAN}{label}{NC} {value}")
        sys.stdout.write("\033[A\033[2K" + row + "\n")
        sys.stdout.flush()
    except Exception:
        pass

def _box_ask(label: str, default: str = "") -> str:
    label = (label or "").rstrip()
    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    prompt = f"{CYAN}║{NC}  {CYAN}{label} {NC}" if interactive else ""
    try:
        val = proto_ask(prompt, default=default, c=True)
    except _Cancelled:
        if interactive:
            _redraw_ask_row(label, f"{DIM}— отмена —{NC}")
        raise
    val = (val or "").strip()
    shown = val if val else default
    if interactive:
        _redraw_ask_row(label, str(shown))
    else:
        _box_row(f"  {CYAN}{label}{NC} {shown}")
    return val

def _pause() -> None:
    try:
        print(f"\n  {DIM}Нажмите Enter...{NC}", end="", flush=True); input()
    except (KeyboardInterrupt, EOFError, UnicodeDecodeError, OSError):
        print()

def _run(cmd: list, capture: bool = False, check: bool = False,
         timeout: "Optional[int]" = None, cwd: "Optional[str]" = None):
    return subprocess.run(cmd, capture_output=capture, check=check,
                          timeout=timeout, cwd=cwd)

# ════════════════════════════════════════════════════════════════════════════
#  ВЕРСИИ (паттерн dpi_bypass.py: installed / latest / кэш / header row)
# ════════════════════════════════════════════════════════════════════════════
def _version_key(version: str) -> tuple:
    """'v0.8.8' / '0.8.8' → (0, 8, 8). Паттерн _b4_version_key."""
    nums = re.findall(r"\d+", str(version or ""))
    return tuple(int(n) for n in nums[:4]) or (0,)

def _strip_v(version: str) -> str:
    return str(version or "").lstrip("vV")

def _detect_latest_version(timeout: int = 10) -> str:
    """Последний релиз апстрима через GitHub API ('' при недоступности)."""
    req = urllib.request.Request(
        _UPSTREAM_API_LATEST,
        headers={"User-Agent": "Chimera-LibreChat-module",
                 "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        return _strip_v(data.get("tag_name") or "")
    except Exception:
        return ""

def _refresh_upstream_cache(force: bool = False) -> str:
    """Кэш latest-версии в state (TTL 5 мин) — меню не дёргает GitHub."""
    state = _load_state()
    cache = state.get("upstream_cache", {}) or {}
    if (not force and cache.get("version")
            and time.time() - float(cache.get("ts") or 0) < _UPSTREAM_CACHE_TTL):
        return cache.get("version", "")
    version = _detect_latest_version()
    if version:
        state["upstream_cache"] = {"version": version,
                                   "ts": int(time.time())}
        _save_state(state)
    return version

def _update_availability(installed: str = "", latest: str = "") -> str:
    """'update-available' / 'up-to-date' / 'unknown' — как _b4_update_availability."""
    if not latest:
        return "unknown"
    if not installed:
        return "update-available"
    if _version_key(installed) < _version_key(latest):
        return "update-available"
    return "up-to-date"

def _update_header_row(installed: str = "", latest: str = "") -> str:
    """Строка шапки про версии — зелёное «доступно» / серое «актуально»."""
    if not installed:
        installed = _load_state().get("version", "") or ""
    avail = _update_availability(installed, latest)
    if avail == "update-available":
        return (f"  Версия:       {CYAN}v{_strip_v(installed) or '?'}{NC}"
                f"  →  доступно {GREEN}v{_strip_v(latest)}{NC}")
    if avail == "up-to-date":
        return (f"  Версия:       {CYAN}v{_strip_v(installed) or '?'}{NC}"
                f"  {DIM}(актуальна){NC}")
    return (f"  Версия:       {CYAN}v{_strip_v(installed) or '?'}{NC}"
            f"  {DIM}(апстрим недоступен){NC}")

# ════════════════════════════════════════════════════════════════════════════
#  DOCKER (apt docker.io + docker-compose-v2 — Ubuntu/Debian канон)
# ════════════════════════════════════════════════════════════════════════════
def _docker_present() -> bool:
    return shutil.which("docker") is not None

def _docker_ready() -> bool:
    """docker установлен И демон отвечает (docker info)."""
    if not _docker_present():
        return False
    r = _run(["docker", "info", "--format", "{{.ServerVersion}}"],
             capture=True, check=False, timeout=60)
    return r.returncode == 0 and bool((r.stdout or b"").strip())

def _compose_cmd() -> list:
    """База compose-команды (cwd задаётся через subprocess cwd)."""
    return ["docker", "compose"]

def _compose(args: list, timeout: "Optional[int]" = None,
             capture: bool = False):
    """docker compose <args> в /opt/librechat."""
    return _run(_compose_cmd() + args, capture=capture, check=False,
                timeout=timeout, cwd=str(_APP_DIR)) if _APP_DIR.exists() else None

def _ensure_docker() -> bool:
    """Устанавливает docker.io + docker-compose-v2 из дистрибутива."""
    if _docker_ready():
        return True
    if not _docker_present():
        _box_info("Устанавливаю Docker (docker.io + docker-compose-v2)...")
        with _boxed_output():
            env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
            r = subprocess.run(
                ["apt-get", "update", "-qq"], capture_output=True, text=True,
                check=False, timeout=300, env=env)
            if r.returncode != 0:
                print(f"apt-get update: rc={r.returncode} "
                      f"{(r.stderr or '').strip()[:120]}")
            r = subprocess.run(
                ["apt-get", "install", "-y", "-qq",
                 "docker.io", "docker-compose-v2"],
                capture_output=True, text=True, check=False, timeout=900,
                env=env)
            if r.returncode != 0:
                print(f"apt-get install: rc={r.returncode} "
                      f"{(r.stderr or '').strip()[-200:]}")
                return False
    # демон: enable --now + ожидание готовности
    _run(["systemctl", "enable", "--now", "docker"],
         capture=True, check=False, timeout=120)
    for _ in range(20):
        if _docker_ready():
            return True
        time.sleep(1.5)
    return _docker_ready()

# ════════════════════════════════════════════════════════════════════════════
#  КОД АПСТРИМА (download_manager: тарболл → staging → /opt/librechat)
# ════════════════════════════════════════════════════════════════════════════
def _app_mirror_urls(filename: str) -> list:
    """Лестница зеркал для тарболла кода апстрима (тег — первым).

    LibreChat тегает релизы (v0.8.8) — теговый архив детерминирован.
    GitHub-прокси (рабочие хосты из github_mirrors.GITHUB_PROXY_HOSTS)
    добавлены как зеркало на случай блокировки github.com с ноды.
    jsDelivr/statically тарболлы не раздают — только GitHub-архивы.
    """
    m = re.search(r"v(\d+\.\d+\.\d+)", filename)
    tag = f"v{m.group(1)}" if m else f"v{_LC_VERSION}"
    urls = [
        f"https://github.com/{_UPSTREAM_REPO}/archive/refs/tags/{tag}.tar.gz",
        f"https://codeload.github.com/{_UPSTREAM_REPO}/tar.gz/refs/tags/{tag}",
    ]
    for host in ("ghproxy.net", "gh-proxy.com", "gh.llkk.cc"):
        urls.append(
            f"https://{host}/https://github.com/{_UPSTREAM_REPO}"
            f"/archive/refs/tags/{tag}.tar.gz")
    return urls

def _app_spec(version: str):
    """PackageSpec для кода апстрима (download_manager)."""
    from chimera.modules.download_manager import PackageSpec
    v = _strip_v(version) or _LC_VERSION
    return PackageSpec(
        name=f"LibreChat v{v}",
        filename_builder=lambda: f"librechat-v{v}.tar.gz",
        mirror_urls_builder=_app_mirror_urls,
        install_dests=[STATE_DIR],
        manual_incoming_dir=Path("/root"),
        min_size=1_500_000,   # полный репо-тарболл > 1.5 МБ (страница-заглушка меньше)
    )

def _extract_app(tar_path: Path, dest: Path) -> bool:
    """Извлекает тарболл апстрима (корень <repo>-<tag>/) в dest.

    Path-traversal guard: члены архива с '..' или абсолютными путями
    отбрасываются (ручной guard — совместимость с Python 3.8+).
    Исключаем тяжёлые каталоги, не нужные для docker-стека (api/node_modules
    в тарболле нет — GitHub-архивы чистые, но страховка от мусора).
    """
    try:
        dest.mkdir(parents=True, exist_ok=True)
        with tarfile.open(tar_path, "r:gz") as tar:
            for member in tar.getmembers():
                name = member.name
                parts = [p for p in name.split("/") if p not in ("", ".")]
                if not parts:
                    continue
                if ".." in parts or name.startswith("/"):
                    continue
                rel = "/".join(parts[1:])       # срез <repo>-<tag>/
                if not rel:
                    continue
                target = dest / rel
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with tar.extractfile(member) as src, \
                            open(target, "wb") as out:
                        shutil.copyfileobj(src, out)
        # Лицензия MIT — обязательный кредит (условие лицензии апстрима).
        lic = dest / "LICENSE.upstream"
        if not lic.exists():
            lic.write_text(
                f"Vendored from github.com/{_UPSTREAM_REPO} (MIT).\n"
                f"Upstream license applies to vendored code.\n",
                encoding="utf-8")
        return (dest / "docker-compose.yml").exists()
    except Exception as e:
        _err(f"Распаковка кода: {e}")
        return False

def _app_actual_version(app_dir: "Optional[Path]" = None) -> str:
    """Фактическая версия вендореного кода (package.json). '' если нет."""
    d = app_dir or _APP_DIR
    try:
        pkg = json.loads((d / "package.json").read_text(encoding="utf-8"))
        ver = _strip_v(pkg.get("version") or "")
        return ver if re.fullmatch(r"\d+\.\d+\.\d+", ver or "") else ""
    except Exception:
        return ""

def _fetch_app(version: str) -> bool:
    """Скачивает код версии version → staging (download_manager)."""
    from chimera.modules.download_manager import fetch_package
    spec = _app_spec(version)
    with _boxed_output():
        ok = fetch_package(spec, progress_label="librechat code")
        if not ok:
            return False
        tar_path = STATE_DIR / spec.filename_builder()
        if _STAGING_DIR.exists():
            shutil.rmtree(_STAGING_DIR, ignore_errors=True)
        if not _extract_app(tar_path, _STAGING_DIR):
            return False
        try:
            tar_path.unlink(missing_ok=True)
        except Exception:
            pass
        return _STAGING_DIR.exists()

def _vendor_app() -> bool:
    """Staging → /opt/librechat (поверх, БЕЗ удаления данных юзера:
    data-node/meili/images/uploads/logs и .env переживают обновление)."""
    try:
        _APP_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copytree(_STAGING_DIR, _APP_DIR, dirs_exist_ok=True)
        shutil.rmtree(_STAGING_DIR, ignore_errors=True)
        return (_APP_DIR / "docker-compose.yml").exists()
    except Exception as e:
        _err(f"Вендоринг кода: {e}")
        return False

# ════════════════════════════════════════════════════════════════════════════
#  ENV / COMPOSE-ПАТЧИ (чистые функции — тестируются без файловой системы)
# ════════════════════════════════════════════════════════════════════════════
def _patch_env_text(text: str, *, port: int, creds_key: str, creds_iv: str,
                    meili_key: str, allow_registration: bool,
                    zai_key: str = "", admin_port: int = _DEFAULT_ADMIN_PORT,
                    admin_secret: str = "", jwt_secret: str = "",
                    ) -> str:
    """Генерирует .env из .env.example апстрима (idempotent replace).

    Обязательные правки (без них стек апстрима не стартует/небезопасен;
    форматы LIVE-валидированы на vds13195 01.11 — api отказывается
    стартовать с «CREDS_IV must be exactly 32 hexadecimal characters
    (16 bytes)», admin-panel — с «SESSION_SECRET must be set to at least
    32 characters»):
      • PORT — loopback-порт api (маппинг в compose);
      • CREDS_KEY — hex 64 (32 байта), CREDS_IV — hex 32 (16 байт);
      • MEILI_MASTER_KEY — поиск (hex 32+);
      • ADMIN_PANEL_SESSION_SECRET — hex 32+ (панель не стартует без него);
      • JWT_SECRET — постоянный JWT (иначе api — временные секреты с warn);
      • UID/GID — compose интерполирует user: "${UID}:${GID}";
      • ALLOW_REGISTRATION — тумблер регистрации (пункт меню 4);
      • ADMIN_PANEL_PORT — admin-panel на отдельном loopback-порту
        (3000 занят AdGuard Home на RU-нодах);
      • ZAI_API_KEY — для custom endpoint GLM (если задан).
    """
    def _sub(pattern: str, repl: str, s: str, flags: int = 0) -> str:
        out, n = re.subn(pattern, repl, s, flags=flags)
        return out if n else None

    lines = text.splitlines()
    out = []
    seen = set()
    wanted = {
        "PORT": str(port),
        "CREDS_KEY": creds_key,
        "CREDS_IV": creds_iv,
        "MEILI_MASTER_KEY": meili_key,
        "ALLOW_REGISTRATION": "true" if allow_registration else "false",
        "ADMIN_PANEL_PORT": str(admin_port),
        "ADMIN_PANEL_SESSION_SECRET": admin_secret,
        # постоянный JWT (без него api стартует на временных секретах
        # с warn «Configure permanent values before production use»)
        "JWT_SECRET": jwt_secret,
        "UID": "0",
        "GID": "0",
    }
    if zai_key:
        wanted["ZAI_API_KEY"] = zai_key
    for line in lines:
        # '#' + опциональный пробел: апстрим пишет '# UID=1000' — тоже
        # заменяем на активную строку с нашим значением (без дублей в конце)
        m = re.match(r"^#?\s*([A-Z0-9_]+)=(.*)$", line)
        if m and m.group(1) in wanted:
            key = m.group(1)
            out.append(f"{key}={wanted[key]}")
            seen.add(key)
        else:
            out.append(line)
    for key, val in wanted.items():
        if key not in seen:
            out.append(f"{key}={val}")
    return "\n".join(out) + "\n"

def _patch_compose_text(text: str, *, mount_yaml: bool = True) -> str:
    """Патчи вендореного docker-compose.yml (мы владеем копией):

    1. Маппинги портов наружу → 127.0.0.1 (loopback-only). Апстрим
       публикует api ${PORT}:${PORT} и admin-panel ${ADMIN_PANEL_PORT:-3000}:3000
       на 0.0.0.0 — наружу только через nginx front (TLS), эталон B4.
    2. Volume ./librechat.yaml → /app/librechat.yaml (custom endpoint'ы;
       в апстримном compose файл не смонтирован).
    Идемпотентно: повторный вызов не дублирует правки.
    """
    # api: ports
    text = re.sub(
        r'- "\$\{PORT\}:\$\{PORT\}"',
        '- "127.0.0.1:${PORT}:${PORT}"', text)
    # admin-panel: ports
    text = re.sub(
        r'- "\$\{ADMIN_PANEL_PORT:-3000\}:3000"',
        '- "127.0.0.1:${ADMIN_PANEL_PORT:-3000}:3000"', text)
    # volume librechat.yaml (только если ещё не смонтирован)
    if mount_yaml and "librechat.yaml:/app/librechat.yaml" not in text:
        text = text.replace(
            "      - ./skill:/app/skill",
            "      - ./skill:/app/skill\n"
            "      - ./librechat.yaml:/app/librechat.yaml")
    return text

def _render_librechat_yaml() -> str:
    """librechat.yaml: custom endpoint GLM (Z.ai) — OpenAI-совместимый API.

    models.default — ОБЯЗАТЕЛЬНЫЙ массив (Zod-валидатор апстрима: «expected
    array, received undefined» → «Exiting due to invalid configuration»;
    LIVE-валидировано на vds13195 01.11) даже при fetch: true — fetch
    дополняет список моделей, но не заменяет дефолт.
    """
    return """# Chimera — custom endpoints для LibreChat.
# Сгенерировано chimera/modules/librechat.py. НЕ редактировать вручную.
# Управление: TUI → раздел 1 → W → 9 (LibreChat) → пункт 9.
version: 1.2.1
endpoints:
  custom:
    - name: 'zai'
      apiKey: '${ZAI_API_KEY}'
      baseURL: 'https://api.z.ai/api/paas/v4'
      models:
        default: ['glm-4.7']
        fetch: true
      titleConvo: true
      titleModel: 'glm-4.7'
      modelDisplayLabel: 'GLM (Z.ai)'
"""

def _write_env_file(port: int, allow_registration: bool, zai_key: str = "",
                    admin_port: int = _DEFAULT_ADMIN_PORT) -> bool:
    """Пишет /opt/librechat/.env поверх .env.example (креды — secrets)."""
    example = _APP_DIR / ".env.example"
    if not example.exists():
        _err(".env.example не найден в тарболле апстрима")
        return False
    text = example.read_text(encoding="utf-8", errors="replace")
    # Форматы LIVE-валидированы (vds13195, 01.11): api требует CREDS_KEY
    # = 64 hex (32 байта) и CREDS_IV = 32 hex (16 байт) — hex(N) даёт
    # 2N символов; admin-panel требует SESSION_SECRET >= 32 символов.
    env = _patch_env_text(
        text,
        port=port,
        creds_key=secrets.token_hex(32),   # 64 hex-символов = 32 байта
        creds_iv=secrets.token_hex(16),    # 32 hex-символов = 16 байт
        meili_key=secrets.token_hex(32),
        allow_registration=allow_registration,
        zai_key=zai_key,
        admin_port=admin_port,
        admin_secret=secrets.token_hex(32),  # 64 символа ≥ 32 (панель)
        jwt_secret=secrets.token_hex(32),    # постоянный JWT (не временный)
    )
    (_APP_DIR / ".env").write_text(env, encoding="utf-8")
    # librechat.yaml (custom endpoint GLM)
    (_APP_DIR / "librechat.yaml").write_text(
        _render_librechat_yaml(), encoding="utf-8")
    return True

def _patch_compose_file() -> bool:
    """Применяет _patch_compose_text к вендореному docker-compose.yml."""
    compose = _APP_DIR / "docker-compose.yml"
    if not compose.exists():
        _err("docker-compose.yml не найден")
        return False
    text = compose.read_text(encoding="utf-8", errors="replace")
    compose.write_text(_patch_compose_text(text), encoding="utf-8")
    return True

# ════════════════════════════════════════════════════════════════════════════
#  SYSTEMD-ЮНИТ (docker compose lifecycle; по канону vless-web/b4)
# ════════════════════════════════════════════════════════════════════════════
def _write_service_unit() -> None:
    unit = f"""[Unit]
Description=Chimera LibreChat (AI chat, docker compose stack)
Requires=docker.service
After=network-online.target docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory={_APP_DIR}
ExecStart=/usr/bin/docker compose up -d --remove-orphans
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=1800
TimeoutStopSec=180

[Install]
WantedBy=multi-user.target
"""
    _SERVICE_FILE.write_text(unit)
    _run(["systemctl", "daemon-reload"], capture=True, check=False)

# ════════════════════════════════════════════════════════════════════════════
#  СМОУК (GET /api/config — публичный эндпоинт апстрима; ProxyHandler({}))
# ════════════════════════════════════════════════════════════════════════════
def _smoke_check(port: int, timeout: int = 5) -> bool:
    """GET /api/config на локальный порт — api жив? (ProxyHandler({}) —
    на серверах с http_proxy в окружении 127.0.0.1 гнался через прокси).

    /api/version в новых образах апстрима УДАЛЁН (404, LIVE-проверено
    vds13195 01.11, образ v0.8.9-rc1) — смоук переведён на /api/config:
    публичный, без авторизации, отвечает только на поднятом api.
    """
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}))
        with opener.open(f"http://127.0.0.1:{port}/api/config",
                         timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False

def _runtime_version(timeout: int = 15) -> str:
    """Фактическая версия api: package.json внутри контейнера
    (docker exec — /api/version в новых образах удалён, LIVE 01.11)."""
    try:
        r = _run(["docker", "exec", "LibreChat",
                  "cat", "/app/package.json"],
                 capture=True, check=False, timeout=timeout)
        body = (r.stdout or b"").decode("utf-8", "replace")
        m = re.search(r'"version"\s*:\s*"v?(\d+\.\d+\.\d+[\w.-]*)"', body)
        return m.group(1) if m else ""
    except Exception:
        return ""

def _wait_service_http(port: int, attempts: int = 60, delay: float = 3.0,
                       announce: bool = False) -> bool:
    """Ждёт ответа GET /api/config (первый старт: mongo init + api boot)."""
    for i in range(attempts):
        if _smoke_check(port):
            return True
        if announce and i == 0:
            _box_info("Жду ответа api (первый старт стека — до пары минут)...")
        time.sleep(delay)
    return False

# ════════════════════════════════════════════════════════════════════════════
#  ВЫБОР ПОРТА (port_registry: конфликт-чек) — канон triple_panel._ask_web_port
# ════════════════════════════════════════════════════════════════════════════
def _port_conflicts(port: int, exclude_service: str = "") -> list:
    try:
        from chimera.modules.port_registry import port_get_conflicts
        return port_get_conflicts(
            port, proto="tcp",
            exclude_service=exclude_service or None)
    except Exception:
        return []

def _port_busy_system(port: int) -> list:
    try:
        from chimera.modules.port_registry import port_check_system
        return port_check_system(port, proto="tcp")
    except Exception:
        return []

def _validate_web_port(port: int, exclude_tag: str = "") -> "tuple[bool, list]":
    """(валиден, конфликты). exclude_tag — свой тег port_registry:
    собственные регистрации/ufw-правила конфликтом не считаются
    (переустановка после сбоя), системные слушатели — всегда конфликт."""
    if not isinstance(port, int) or port < 1024 or port > 65535:
        return False, ["порт должен быть 1024-65535"]
    try:
        from chimera.modules.port_registry import port_is_free
        ok, conflicts = port_is_free(port, "tcp",
                                      exclude_service=exclude_tag or None)
        if not ok:
            return False, conflicts
    except Exception:
        pass
    conflicts = _port_conflicts(port, exclude_service=exclude_tag) \
        + _port_busy_system(port)
    return (len(conflicts) == 0), conflicts

def _pick_admin_port(web_port: int) -> int:
    """Подбирает свободный loopback-порт для admin-panel (3095+)."""
    for cand in (web_port + 15, _DEFAULT_ADMIN_PORT, 3096, 3097, 3098):
        ok, _ = _validate_web_port(cand)
        if ok:
            return cand
    return _DEFAULT_ADMIN_PORT

def _ask_web_port(default: int = _DEFAULT_PORT,
                  exclude_tag: str = "") -> "Optional[int]":
    """Полный мини-бокс выбора порта (канон triple_panel). None = отмена.

    exclude_tag: тег port_registry, с которым НЕ конфликтуем (сам с собой
    — переустановка после сбоя: прошлый запуск успел зарегистрировать
    порт, но упал до записи state; живой инцидент 01.11 на vds13195).
    """
    _box_top("🔌  ВЫБОР ПОРТА  •  LIBRECHAT")
    _box_row()
    _box_row(f"  {DIM}Порт веб-интерфейса (Enter = {default}):{NC}")
    _box_row(f"  {DIM}Проверю port_registry и слушателей перед регистрацией.{NC}")
    _box_row()
    while True:
        try:
            raw = _box_ask("Порт:", default=str(default))
        except _Cancelled:
            _box_row()
            _box_row(f"  {DIM}Отмена.{NC}")
            _box_bot(); print()
            return None
        if raw.lower() == "q":
            _box_row()
            _box_row(f"  {DIM}Отмена.{NC}")
            _box_bot(); print()
            return None
        try:
            port = int(raw)
        except ValueError:
            _box_warn("Нужно число (или Q для отмены).")
            continue
        ok, conflicts = _validate_web_port(port, exclude_tag=exclude_tag)
        if ok:
            _box_row()
            _box_ok(f"Порт {port} свободен.")
            _box_bot(); print()
            return port
        _box_row()
        _box_warn(f"Порт {port} недоступен:")
        for c in conflicts[:6]:
            _box_row(f"    {RED}•{NC} {c}")
        _box_row(f"  {DIM}Выберите другой порт (или Q — отмена).{NC}")
        _box_row()

# ════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА
# ════════════════════════════════════════════════════════════════════════════
def _install() -> bool:
    # Бокс 1: интро — закрывается ДО выбора порта (канон naiveproxy)
    os.system("clear")
    _box_top("🤖  УСТАНОВКА  •  LIBRECHAT")
    _box_row()
    _box_row("  Self-hosted AI-чат платформа (LibreChat-AI/LibreChat, MIT).")
    _box_row(f"  {DIM}docker compose стек: api + admin-panel + mongodb +{NC}")
    _box_row(f"  {DIM}meilisearch + vectordb + rag_api. Мультипровайдерные{NC}")
    _box_row(f"  {DIM}модели, Agents, MCP, RAG. GLM (Z.ai) — опцией ниже.{NC}")
    _box_row()
    _box_row(f"  {DIM}Требования: ~2 ГБ RAM, ~5 ГБ диска, Ubuntu/Debian.{NC}")
    _box_row()
    _box_bot()
    print()

    # Бокс 2: выбор порта. exclude_tag=SERVICE_LIBRECHAT_WEB — порт,
    # зарегистрированный САМИМ librechat_web (хвосты незавершённой
    # установки), конфликтом не считается; ниже регистрации тега
    # снимаются целиком и перерегистрируются заново.
    from chimera.modules.port_registry import SERVICE_LIBRECHAT_WEB
    port = _ask_web_port(exclude_tag=SERVICE_LIBRECHAT_WEB)
    if port is None:
        return False
    admin_port = _pick_admin_port(port)

    # Бокс 2b: опциональный GLM (Z.ai) custom endpoint
    zai_key = ""
    try:
        os.system("clear")
        _box_top("🤖  GLM (Z.AI)  •  CUSTOM ENDPOINT")
        _box_row()
        _box_row(f"  {DIM}Z.ai — OpenAI-совместимый API (моно GLM).{NC}")
        _box_row(f"  {DIM}Ключ можно вставить позже (пункт 9) или ввести{NC}")
        _box_row(f"  {DIM}в UI LibreChat. Ключ хранится в .env на этой ноде.{NC}")
        _box_row()
        ans = _box_ask("Подключить GLM сейчас? Введите ключ (Enter = пропустить):")
    except _Cancelled:
        ans = ""
    zai_key = (ans or "").strip()
    if zai_key.lower() in ("n", "no", "нет"):
        zai_key = ""

    # Бокс 3: прогресс — docker → код → env → pull → up → смоук → итог
    os.system("clear")
    _box_top("🤖  УСТАНОВКА  •  LIBRECHAT")
    _box_row()

    # 1. Docker
    if not _ensure_docker():
        _box_err("Docker не установлен/не отвечает (см. journalctl -u docker).")
        _box_row()
        _box_bot(); _pause()
        return False
    _box_ok("Docker готов")

    # 2. Код апстрима (download_manager; лестница зеркал — в рамке)
    upstream = _refresh_upstream_cache() or _LC_VERSION
    if not _fetch_app(upstream):
        _box_err("Не удалось скачать код апстрима (подсказка выше в рамке).")
        _box_row(f"  {DIM}Ручной путь: положите librechat-v{upstream}.tar.gz в /root/{NC}")
        _box_row()
        _box_bot(); _pause()
        return False
    if not _vendor_app():
        _box_row()
        _box_bot(); _pause()
        return False
    actual = _app_actual_version() or upstream
    _box_ok(f"Код апстрима v{actual} вендорен → /opt/librechat")

    # 3. .env + compose-патчи
    if not _write_env_file(port, allow_registration=True,
                           zai_key=zai_key, admin_port=admin_port):
        _box_row(); _box_bot(); _pause()
        return False
    if not _patch_compose_file():
        _box_row(); _box_bot(); _pause()
        return False
    _box_ok(".env сгенерирован (CREDS/MEILI ключи, PORT="
            f"{port}, admin={admin_port})")
    _box_ok("compose: порты → 127.0.0.1 (наружу — только nginx front)")

    # 4. port_registry: переустановка владеет своим тегом — сначала
    # снимаем ВСЕ старые записи librechat_web (хвосты прошлых попыток:
    # упавший до записи state запуск мог оставить регистрацию порта;
    # живой инцидент 01.11), затем регистрируем актуальные порты.
    # loopback-биндинг уже не публикует порты наружу; регистрация —
    # для учёта/аудита конфликтов между модулями.
    try:
        from chimera.modules.port_registry import (
            port_register, port_unregister, SERVICE_LIBRECHAT_WEB,
        )
        port_unregister(SERVICE_LIBRECHAT_WEB)  # все записи тега
        ok, msg = port_register(SERVICE_LIBRECHAT_WEB, port, proto="tcp",
                                comment="LibreChat web UI (loopback)",
                                force=True)
        if not ok:
            _box_warn(f"port_registry: {msg}")
        port_register(SERVICE_LIBRECHAT_WEB, admin_port, proto="tcp",
                      comment="LibreChat admin panel (loopback)",
                      force=True)
    except Exception as e:
        _box_warn(f"port_registry недоступен: {e}")

    # 5. Образы: pull (первый раз — минуты; тихо, прогресс docker
    #    печатает \r-кареткой — в рамке он бы «завис»)
    _box_info("Скачиваю образы стека (первый раз — 3-10 минут)...")
    r = _compose(["pull"], timeout=1800, capture=True)
    if r is None or r.returncode != 0:
        tail = ((r.stderr or b"") if r else b"").decode(errors="replace")
        tail = tail.strip().splitlines()
        _box_err("docker compose pull не удался"
                 + (f" — {tail[-1][:80]}" if tail else ""))
        _box_row(f"  {DIM}Проверьте доступ к registry.librechat.ai / docker.io.{NC}")
        _box_row()
        _box_bot(); _pause()
        return False
    _box_ok("Образы стека скачаны")

    # 6. Юнит + старт
    _write_service_unit()
    state = _load_state()
    state.update({
        "installed": True,
        "web_port": port,
        "admin_port": admin_port,
        "version": actual,
        "zai_enabled": bool(zai_key),
        "allow_registration": True,
        "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
    _save_state(state)
    _box_info("Запускаю librechat.service...")
    r = _run(["systemctl", "enable", "--now", _SERVICE_NAME],
             capture=True, check=False, timeout=300)
    if r.returncode != 0:
        tail = (r.stderr or b"").decode(errors="replace").strip().splitlines()
        _box_warn(f"systemctl enable: rc={r.returncode}"
                  + (f" — {tail[-1][:70]}" if tail else ""))
    if _wait_service_http(port, attempts=80, delay=3, announce=True):
        rt = _runtime_version()
        if rt:
            state["runtime_version"] = rt
            _save_state(state)
        _box_ok(f"LibreChat активен (127.0.0.1:{port}, api v{rt or actual})")
    else:
        _box_err("Сервис поднялся, но api не отвечает. Лог:")
        _journal_boxed()
        _box_row()
        _box_bot(); _pause()
        return False

    # 7. Итог
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Доступ по SSH-туннелю:{NC}")
    _box_row()
    _box_link(f"ssh -L {port}:127.0.0.1:{port} root@<IP-сервера>")
    _box_row(f"  {DIM}затем: http://127.0.0.1:{port}/{NC}")
    _box_row()
    _box_row(f"  {DIM}Admin panel: http://127.0.0.1:{admin_port} (тоже loopback){NC}")
    _box_row()
    _box_sep()
    if zai_key:
        _box_ok("GLM (Z.ai) подключён как custom endpoint 'zai'")
    else:
        _box_row(f"  {DIM}GLM (Z.ai): не подключён (пункт 9 — в любой момент).{NC}")
    _box_row(f"  {DIM}Первый зарегистрированный юзер = администратор.{NC}")
    _box_row(f"  {DIM}После создания админа закройте регистрацию (пункт 4).{NC}")
    _box_row(f"  {DIM}Наружу по HTTPS — пункт 8 (nginx front, TLS/домен).{NC}")
    _box_row()
    _box_bot()
    _log("INFO", f"installed: port={port} admin={admin_port} v{actual} zai={bool(zai_key)}")
    _pause()
    return True

# ════════════════════════════════════════════════════════════════════════════
#  ОБНОВЛЕНИЕ (паттерн b4: latest → pull → up → смоук → ОТКАТ при провале)
# ════════════════════════════════════════════════════════════════════════════
def _stack_images() -> list:
    """Список образов стека (compose config --images)."""
    r = _compose(["config", "--images"], timeout=60, capture=True)
    if r is None or r.returncode != 0:
        return []
    out = []
    for line in (r.stdout or b"").decode(errors="replace").splitlines():
        line = line.strip()
        if line:
            out.append(line)
    return out

def _tag_rollback_images() -> dict:
    """Помечает текущие образы стека тегами librechat-rollback:N.

    Возвращает {оригинальный ref: image id} для отката. docker не удаляет
    образы с тегами — это мгновенный «снимок» без docker save (ГБ на диск).
    """
    mapping = {}
    n = 0
    for ref in _stack_images():
        r = _run(["docker", "images", "-q", ref],
                 capture=True, check=False, timeout=30)
        image_id = (r.stdout or b"").decode(errors="replace").strip()
        if not image_id:
            continue
        tag = f"{_ROLLBACK_TAG_PREFIX}:{n}"
        if _run(["docker", "tag", image_id, tag],
                capture=True, check=False, timeout=30).returncode == 0:
            mapping[ref] = image_id
            n += 1
    return mapping

def _rollback_images(mapping: dict) -> None:
    """Возвращает образы из rollback-тегов (docker tag id → ref)."""
    for ref, image_id in mapping.items():
        _run(["docker", "tag", image_id, ref],
             capture=True, check=False, timeout=60)

def _clear_rollback_tags() -> None:
    """Снимает rollback-теги (после успешного обновления)."""
    r = _run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
             capture=True, check=False, timeout=30)
    for line in (r.stdout or b"").decode(errors="replace").splitlines():
        line = line.strip()
        if line.startswith(_ROLLBACK_TAG_PREFIX + ":"):
            _run(["docker", "rmi", line], capture=True, check=False,
                 timeout=60)

def _backup_configs() -> bool:
    """Бэкап compose/.env/librechat.yaml перед обновлением (для откката)."""
    try:
        _BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        for name in ("docker-compose.yml", ".env", "librechat.yaml"):
            src = _APP_DIR / name
            if src.exists():
                shutil.copy2(src, _BACKUP_DIR / name)
        return True
    except Exception:
        return False

def _restore_configs() -> bool:
    """Откат compose/.env/librechat.yaml из бэкапа."""
    try:
        for name in ("docker-compose.yml", ".env", "librechat.yaml"):
            src = _BACKUP_DIR / name
            if src.exists():
                shutil.copy2(src, _APP_DIR / name)
        return True
    except Exception:
        return False

def _update_stack() -> bool:
    state = _load_state()
    current = state.get("version", "")
    upstream = _refresh_upstream_cache(force=True)
    os.system("clear")
    _box_top("⬆️  ОБНОВЛЕНИЕ  •  LIBRECHAT")
    _box_row()
    if not upstream:
        _box_err("Не удалось получить версию апстрима (GitHub API).")
        _box_row(f"  {DIM}Повторите позже — стек не тронут.{NC}")
        _box_row()
        _box_bot()
        _pause()
        return False
    _box_kv("Установлено:", f"{CYAN}v{_strip_v(current) or '—'}{NC}")
    _box_kv("Доступно:",   f"{GREEN}v{_strip_v(upstream)}{NC}")
    _box_row()
    if current and _version_key(current) >= _version_key(upstream):
        _box_ok(f"Стек актуален: v{current}.")
        _box_row()
        _box_bot()
        _pause()
        return True
    _box_row(f"  {DIM}План: код → образы (pull) → up -d → смоук. Провал{NC}")
    _box_row(f"  {DIM}смоука = откат образов и конфигов (rollback-теги).{NC}")
    _box_row()
    try:
        confirm = _box_ask(f"Обновить до v{upstream}? [y/N]:",
                           default="n").strip().lower()
    except _Cancelled:
        confirm = ""
    if confirm != "y":
        _box_row()
        _box_row(f"  {DIM}Отмена — стек не тронут.{NC}")
        _box_row()
        _box_bot(); print()
        return False

    port = int(state.get("web_port", _DEFAULT_PORT))

    # 1. rollback-снимок: теги образов + бэкап конфигов
    mapping = _tag_rollback_images()
    if not _backup_configs():
        _box_warn("Бэкап конфигов не удался — откат будет неполным.")

    # 2. свежий код (compose-файл новой версии) поверх, данные не трогаем
    if not _fetch_app(upstream):
        _box_err("Скачивание кода не удалось — стек не тронут.")
        _clear_rollback_tags()
        _box_row(); _box_bot(); _pause()
        return False
    if not _vendor_app() or not _patch_compose_file():
        _box_err("Вендоринг кода не удался — откат конфигов.")
        _restore_configs()
        _clear_rollback_tags()
        _box_row(); _box_bot(); _pause()
        return False
    # .env юзера пережил копирование (в тарболле нет .env) — версия PORT
    # не меняется. librechat.yaml из тарболла может прийти от апстрима —
    # перезапишем нашим (custom endpoint GLM).
    (_APP_DIR / "librechat.yaml").write_text(
        _render_librechat_yaml(), encoding="utf-8")

    # 3. образы + рестарт
    _box_info(f"Скачиваю образы v{upstream} (минуты)...")
    r = _compose(["pull"], timeout=1800, capture=True)
    if r is None or r.returncode != 0:
        _box_err("pull не удался — откат конфигов (образы не менялись).")
        _restore_configs()
        _clear_rollback_tags()
        _box_row(); _box_bot(); _pause()
        return False
    _run(["systemctl", "restart", _SERVICE_NAME],
         capture=True, check=False, timeout=600)

    # 4. смоук
    if not _wait_service_http(port, attempts=40, delay=3):
        _box_err("Смоук после обновления провален — ОТКАТ.")
        _restore_configs()
        if mapping:
            _rollback_images(mapping)
            _run(["systemctl", "restart", _SERVICE_NAME],
                 capture=True, check=False, timeout=600)
            if _wait_service_http(port, attempts=30, delay=3):
                _box_ok("Откат выполнен, предыдущая версия восстановлена.")
            else:
                _box_err("Откат поднялся, но api не отвечает — journal:")
                _journal_boxed()
        _clear_rollback_tags()
        _box_row(); _box_bot(); _pause()
        return False

    # 5. успех
    rt = _runtime_version()
    state["version"] = _app_actual_version() or upstream
    state["runtime_version"] = rt or state["version"]
    _save_state(state)
    _clear_rollback_tags()
    if _BACKUP_DIR.exists():
        shutil.rmtree(_BACKUP_DIR, ignore_errors=True)
    _box_row()
    _box_ok(f"Стек обновлён: v{current or '—'} → "
            f"v{state['version']} (api v{rt or state['version']})")
    _log("INFO", f"updated {current} -> {state['version']}")
    _box_row()
    _box_bot()
    _pause()
    return True

# ════════════════════════════════════════════════════════════════════════════
#  NGINX FRONT (эталон b4 → panel_nginx_front; long_timeouts — LLM-стримы)
# ════════════════════════════════════════════════════════════════════════════
def _nginx_status() -> dict:
    if not _NGINX_STATE_FILE.exists():
        return {"enabled": False}
    try:
        return json.loads(_NGINX_STATE_FILE.read_text())
    except Exception:
        return {"enabled": False}

def _nginx_install(use_self_signed: bool, domain: "Optional[str]") -> "tuple[bool, str]":
    """nginx front с TLS по эталону B4 (dpi_bypass._b4_nginx_install).

    long_timeouts=True — nginx не рубит LLM-стримы/SSE на 60-й секунде
    (proxy_read/send_timeout 3600s — параметр panel_nginx_front).
    Дополнительно обновляет DOMAIN_CLIENT/DOMAIN_SERVER в .env (cookies/
    OAuth редиректы должны знать публичный origin).
    """
    from chimera.modules.panel_nginx_front import panel_nginx_front_install
    state = _load_state()
    backend_port = int(state.get("web_port", _DEFAULT_PORT))
    ok, msg = panel_nginx_front_install(
        service_tag="chimera-librechat-nginx",
        port=DEFAULT_NGINX_PORT,
        backend_port=backend_port,
        site_name=_NGINX_SITE_NAME,
        state_file=_NGINX_STATE_FILE,
        title="LibreChat",
        use_self_signed=use_self_signed,
        domain=domain,
        websocket_origin_rewrite=False,
        backend_http_scheme="http",
        cert_name_slug="chimera-librechat",
        long_timeouts=True,   # LLM-стримы: не рубить на 60-й секунде
    )
    if ok:
        # Прямой порт панели остаётся loopback — закрывать нечего
        # (в отличие от b4, где 9700 слушал 0.0.0.0). Дополнительно
        # сообщаем LibreChat его публичный origin.
        try:
            if not use_self_signed and domain:
                origin = f"https://{domain}:{DEFAULT_NGINX_PORT}"
                envf = _APP_DIR / ".env"
                if envf.exists():
                    text = envf.read_text(encoding="utf-8", errors="replace")
                    text = re.sub(r"^DOMAIN_CLIENT=.*$", f"DOMAIN_CLIENT={origin}",
                                  text, flags=re.MULTILINE)
                    text = re.sub(r"^DOMAIN_SERVER=.*$", f"DOMAIN_SERVER={origin}",
                                  text, flags=re.MULTILINE)
                    envf.write_text(text, encoding="utf-8")
                    _run(["systemctl", "restart", _SERVICE_NAME],
                         capture=True, check=False, timeout=600)
        except Exception:
            pass
    return ok, msg

def _nginx_remove() -> "tuple[bool, str]":
    from chimera.modules.panel_nginx_front import panel_nginx_front_remove
    if not _nginx_status().get("enabled"):
        return True, "nginx front уже выключен"
    panel_nginx_front_remove(
        service_tag="chimera-librechat-nginx",
        site_name=_NGINX_SITE_NAME,
        state_file=_NGINX_STATE_FILE,
        title="LibreChat",
    )
    return True, "nginx front удалён"

def _nginx_url() -> "Optional[str]":
    st = _nginx_status()
    if not st.get("enabled"):
        return None
    port = st.get("port", DEFAULT_NGINX_PORT)
    domain = st.get("domain")
    if not domain:
        return None
    return f"https://{domain}:{port}"

def _nginx_menu() -> None:
    """Мини-меню nginx front (эталон b4 [9])."""
    from chimera.modules.panel_nginx_front import ask_tls_mode, ask_domain
    st = _nginx_status()
    if st.get("enabled"):
        os.system("clear")
        _box_top("🌐  NGINX FRONT  •  LIBRECHAT")
        _box_row()
        _box_kv("Статус:", f"{GREEN}включён{NC}")
        _box_kv("URL:", f"{YELLOW}{_nginx_url()}{NC}" if _nginx_url()
                else f"{DIM}— (нет домена в state){NC}")
        _box_row()
        try:
            ch = _box_ask("Выключить nginx front? [y/N]:", default="n").strip().lower()
        except _Cancelled:
            ch = ""
        if ch == "y":
            ok, msg = _nginx_remove()
            (_box_ok if ok else _box_err)(msg)
        _box_row(); _box_bot(); _pause()
        return
    os.system("clear")
    _box_top("🌐  NGINX FRONT  •  LIBRECHAT")
    _box_row()
    _box_row(f"  {DIM}Прямой HTTPS-доступ к LibreChat по домену/IP.{NC}")
    _box_row(f"  {DIM}LE — доверенный сертификат (нужен домен),{NC}")
    _box_row(f"  {DIM}self-signed — по IP (браузер предупредит).{NC}")
    _box_row()
    try:
        use_self_signed, _dh = ask_tls_mode("LibreChat")
        domain = None if use_self_signed else ask_domain()
    except Exception:
        return
    ok, msg = _nginx_install(use_self_signed, domain)
    (_box_ok if ok else _box_err)(msg)
    if ok and _nginx_url():
        _box_info(f"URL: {_nginx_url()}")
    _box_row(); _box_bot(); _pause()

# ════════════════════════════════════════════════════════════════════════════
#  РЕГИСТРАЦИЯ / ПОРТ / ЛОГИ / GLM
# ════════════════════════════════════════════════════════════════════════════
def _set_registration(allowed: "Optional[bool]" = None) -> None:
    """Тумблер ALLOW_REGISTRATION в .env + recreate стека."""
    state = _load_state()
    envf = _APP_DIR / ".env"
    if not envf.exists():
        _warn(".env не найден")
        _pause()
        return
    if allowed is None:
        current = state.get("allow_registration", True)
        allowed = not current
    text = envf.read_text(encoding="utf-8", errors="replace")
    if re.search(r"^ALLOW_REGISTRATION=", text, flags=re.MULTILINE):
        text = re.sub(r"^ALLOW_REGISTRATION=.*$",
                      f"ALLOW_REGISTRATION={'true' if allowed else 'false'}",
                      text, flags=re.MULTILINE)
    else:
        text += f"\nALLOW_REGISTRATION={'true' if allowed else 'false'}\n"
    envf.write_text(text, encoding="utf-8")
    state["allow_registration"] = bool(allowed)
    _save_state(state)
    _run(["systemctl", "restart", _SERVICE_NAME],
         capture=True, check=False, timeout=600)
    (_box_ok if allowed else _box_warn)(
        f"Регистрация {'ОТКРЫТА (создайте админа и закройте!)' if allowed else 'ЗАКРЫТА'}")
    _pause()

def _change_web_port() -> None:
    state = _load_state()
    old_port = int(state.get("web_port", _DEFAULT_PORT))
    new_port = _ask_web_port(default=old_port)
    if new_port is None or new_port == old_port:
        return
    envf = _APP_DIR / ".env"
    text = envf.read_text(encoding="utf-8", errors="replace")
    text = re.sub(r"^PORT=.*$", f"PORT={new_port}", text,
                  flags=re.MULTILINE)
    envf.write_text(text, encoding="utf-8")
    # port_registry: пере-регистрация
    try:
        from chimera.modules.port_registry import (
            port_register, port_unregister, SERVICE_LIBRECHAT_WEB,
        )
        port_unregister(SERVICE_LIBRECHAT_WEB, old_port, "tcp")
        port_register(SERVICE_LIBRECHAT_WEB, new_port, proto="tcp",
                      comment="LibreChat web UI (loopback)", force=True)
    except Exception:
        pass
    state["web_port"] = new_port
    _save_state(state)
    _run(["systemctl", "restart", _SERVICE_NAME],
         capture=True, check=False, timeout=600)
    if _wait_service_http(new_port, attempts=30, delay=3):
        _box_ok(f"Порт изменён: {old_port} → {new_port} (127.0.0.1)")
        _box_row(f"  {DIM}SSH-туннель: ssh -L {new_port}:127.0.0.1:{new_port} "
                 f"root@<IP>{NC}")
    else:
        _box_err("api не ответил на новом порту — journal:")
        _journal_boxed()
    _pause()

def _journal_boxed(n: int = 40) -> None:
    """Хвост логов стека (api) — строками бокса."""
    r = _compose(["logs", "--tail", str(n), "api"],
                 timeout=60, capture=True)
    if r is None:
        r = _run(["journalctl", "-u", _SERVICE_NAME, "-n", str(n),
                  "--no-pager"], capture=True, check=False)
    with _boxed_output():
        for line in ((r.stdout or b"") + (r.stderr or b"")) \
                .decode(errors="replace").splitlines():
            print(line)

def _zai_endpoint_menu() -> None:
    """Настройка GLM (Z.ai) custom endpoint: ключ в .env + restart."""
    state = _load_state()
    envf = _APP_DIR / ".env"
    os.system("clear")
    _box_top("🧠  GLM (Z.AI)  •  CUSTOM ENDPOINT")
    _box_row()
    _box_kv("Статус:",
            f"{GREEN}подключён{NC}" if state.get("zai_enabled")
            else f"{DIM}не подключён{NC}")
    _box_row()
    _box_row(f"  {DIM}Ключ хранится в {envf} (ZAI_API_KEY) и подставляется{NC}")
    _box_row(f"  {DIM}в librechat.yaml → custom endpoint 'zai'.{NC}")
    _box_row(f"  {DIM}Модели подтягиваются сами (models.fetch=true).{NC}")
    _box_row()
    try:
        key = _box_ask("API-ключ Z.ai (Enter = не менять, 'x' = отключить):")
    except _Cancelled:
        return
    key = (key or "").strip()
    if not key:
        _box_row(f"  {DIM}Без изменений.{NC}")
        _box_row(); _box_bot(); _pause()
        return
    disable = key.lower() in ("x", "off", "нет")
    if not envf.exists():
        _box_err(".env не найден — установите LibreChat (пункт 1).")
        _box_row(); _box_bot(); _pause()
        return
    text = envf.read_text(encoding="utf-8", errors="replace")
    if disable:
        if re.search(r"^ZAI_API_KEY=", text, flags=re.MULTILINE):
            text = re.sub(r"^ZAI_API_KEY=.*$", "ZAI_API_KEY=", text,
                          flags=re.MULTILINE)
        state["zai_enabled"] = False
        msg = "GLM endpoint отключён (перезапустите стек в пункте 3)."
    else:
        if re.search(r"^ZAI_API_KEY=", text, flags=re.MULTILINE):
            text = re.sub(r"^ZAI_API_KEY=.*$", f"ZAI_API_KEY={key}", text,
                          flags=re.MULTILINE)
        else:
            text += f"\nZAI_API_KEY={key}\n"
        state["zai_enabled"] = True
        msg = "GLM endpoint подключён."
    envf.write_text(text, encoding="utf-8")
    (_APP_DIR / "librechat.yaml").write_text(
        _render_librechat_yaml(), encoding="utf-8")
    _save_state(state)
    if not disable:
        _run(["systemctl", "restart", _SERVICE_NAME],
             capture=True, check=False, timeout=600)
        msg += " Стек перезапущен."
    _box_ok(msg)
    _box_row(); _box_bot(); _pause()

# ════════════════════════════════════════════════════════════════════════════
#  УДАЛЕНИЕ (выбор: полное / с сохранением данных)
# ════════════════════════════════════════════════════════════════════════════
def _uninstall() -> None:
    os.system("clear")
    _box_top("🗑️  УДАЛЕНИЕ  •  LIBRECHAT")
    _box_row()
    _box_row(f"  {RED}Будет удалено:{NC}")
    _box_row(f"  {DIM}  • контейнеры/сеть стека (docker compose down){NC}")
    _box_row(f"  {DIM}  • systemd-юнит librechat.service{NC}")
    _box_row(f"  {DIM}  • nginx front (если включён) + порты port_registry{NC}")
    _box_row(f"  {DIM}  • rollback-теги образов{NC}")
    _box_row()
    _box_row(f"  {BOLD}{WHITE}[1] Полное{NC} — данные тоже (mongodb, вектора,")
    _box_row(f"  {DIM}    загрузки, .env; docker-образы и named-volumes){NC}")
    _box_row(f"  {BOLD}{WHITE}[2] С сохранением данных{NC} — /opt/librechat/{DATA_DIRS[0]}")
    _box_row(f"  {DIM}    и прочие данные остаются на диске{NC}")
    _box_row()
    try:
        ch = _box_ask("Режим [1/2/Q — отмена]:", default="q").strip().lower()
    except _Cancelled:
        ch = "q"
    if ch not in ("1", "2"):
        _box_row(f"  {DIM}Отмена.{NC}")
        _box_row(); _box_bot(); _pause()
        return
    full = ch == "1"
    try:
        confirm = _box_ask(f"{RED}Точно удалить{' ПОЛНОСТЬЮ' if full else ''}? [y/N]:",
                           default="n").strip().lower()
    except _Cancelled:
        confirm = ""
    if confirm != "y":
        _box_row(f"  {DIM}Отмена.{NC}")
        _box_row(); _box_bot(); _pause()
        return

    # 1. compose down (полное — с volumes)
    state = _load_state()
    if _APP_DIR.exists():
        args = ["down"] + (["-v"] if full else [])
        _compose(args, timeout=600, capture=True)
    # 2. systemd
    _run(["systemctl", "stop", _SERVICE_NAME], capture=True, check=False)
    _run(["systemctl", "disable", _SERVICE_NAME], capture=True, check=False)
    _run(["systemctl", "mask", _SERVICE_NAME], capture=True, check=False)
    _SERVICE_FILE.unlink(missing_ok=True)
    _run(["systemctl", "unmask", _SERVICE_NAME], capture=True, check=False)
    _run(["systemctl", "daemon-reload"], capture=True, check=False)
    _run(["systemctl", "reset-failed", _SERVICE_NAME],
         capture=True, check=False)
    # 3. nginx front
    try:
        _nginx_remove()
    except Exception:
        pass
    # 4. port_registry
    try:
        from chimera.modules.port_registry import (
            port_unregister, SERVICE_LIBRECHAT_WEB,
        )
        port_unregister(SERVICE_LIBRECHAT_WEB,
                        int(state.get("web_port", _DEFAULT_PORT)), "tcp")
        port_unregister(SERVICE_LIBRECHAT_WEB,
                        int(state.get("admin_port", _DEFAULT_ADMIN_PORT)), "tcp")
    except Exception:
        pass
    # 5. rollback-теги
    _clear_rollback_tags()
    # 6. код/данные
    if full:
        if _APP_DIR.exists():
            shutil.rmtree(_APP_DIR, ignore_errors=True)
        _box_row(f"  {DIM}docker и его системные данные НЕ удаляются{NC}")
        _box_row(f"  {DIM}(apt remove docker.io — вручную, если больше не нужен).{NC}")
    else:
        # код/конфиги — удалить, данные — оставить
        for name in ("docker-compose.yml", ".env", ".env.example",
                     "librechat.yaml", "package.json", "LICENSE.upstream"):
            (_APP_DIR / name).unlink(missing_ok=True)
        _box_ok(f"Данные сохранены: /opt/librechat/{_DATA_DIRS[0]} и др.")
    # 7. state
    _save_state({"installed": False, "allow_registration": True})
    if _BACKUP_DIR.exists():
        shutil.rmtree(_BACKUP_DIR, ignore_errors=True)
    _box_ok("LibreChat удалён" + (" полностью" if full else " (данные на диске)"))
    _log("INFO", f"uninstalled full={full}")
    _box_row(); _box_bot(); _pause()

# ════════════════════════════════════════════════════════════════════════════
#  МЕНЮ (раздел 1 → W → 9)
# ════════════════════════════════════════════════════════════════════════════
def do_librechat_menu() -> None:
    while True:
        os.system("clear")
        state = _load_state()
        installed = bool(state.get("installed")) and \
            (_APP_DIR / "docker-compose.yml").exists()
        running = _service_active()
        port = int(state.get("web_port", _DEFAULT_PORT))
        admin_port = int(state.get("admin_port", _DEFAULT_ADMIN_PORT))
        _latest = _refresh_upstream_cache()

        svc_str = (
            f"{GREEN}● активен{NC}"  if running and installed else
            f"{RED}● остановлен{NC}" if installed else
            f"{YELLOW}● не установлен{NC}"
        )

        _box_top("🤖  LIBRECHAT  •  AI-ЧАТ ПЛАТФОРМА")
        _box_row()
        _box_kv("Статус:", svc_str)
        if installed:
            _box_kv("Порт:", f"{CYAN}127.0.0.1:{port}{NC} {DIM}(SSH-туннель){NC}")
            _box_kv("Admin panel:", f"{CYAN}127.0.0.1:{admin_port}{NC} {DIM}(loopback){NC}")
            url = _nginx_url()
            _box_kv("Напрямую:",
                    (f"{GREEN}включён{NC} — {YELLOW}{url}{NC}" if url
                     else f"{DIM}закрыто (только SSH-туннель){NC}"))
            _box_kv("Регистрация:",
                    f"{GREEN}открыта{NC}" if state.get("allow_registration", True)
                    else f"{RED}закрыта{NC}")
            _box_kv("GLM (Z.ai):",
                    f"{GREEN}подключён{NC}" if state.get("zai_enabled")
                    else f"{DIM}не подключён{NC}")
        _box_row()
        _box_row(_update_header_row(
            state.get("runtime_version") or state.get("version", ""), _latest))
        if installed:
            _box_row(f"  {DIM}Код: /opt/librechat • стек: api + admin-panel{NC}")
            _box_row(f"  {DIM}+ mongodb + meili + vectordb + rag_api{NC}")
        _box_row(); _box_sep()
        if not installed:
            _box_item("1", "🚀  Установить LibreChat (docker compose стек)")
        else:
            _box_item("1", f"{'🛑 Остановить' if running else '🚀 Запустить'} сервис")
        _box_item("2", "⬆️  Обновить стек  "
                        f"{DIM}(версии/апдейты как у b4, смоук+откат){NC}")
        _box_item("3", "🔄  Перезапустить стек")
        _box_item("4", "🔐  Регистрация вкл/выкл")
        _box_item("5", "🔀  Сменить порт")
        _box_item("6", "📋  Логи api (последние 40 строк)")
        _box_item("7", "🔌  Доступ по SSH-туннелю (инструкция)")
        _box_item("8", "🌐  nginx front (TLS)  "
                        f"{DIM}(домен/LE — эталон b4){NC}")
        _box_item("9", "🧠  GLM (Z.ai) custom endpoint")
        _box_item("0", f"{RED}🗑️  Удалить (полное / с сохранением данных){NC}")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot(); print()
        try:
            ch = proto_ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            if not installed:
                _install()
            else:
                action = "stop" if running else "start"
                _run(["systemctl", action, _SERVICE_NAME],
                     capture=True, check=False, timeout=300)
                time.sleep(1.5)
                if action == "start":
                    ok = _wait_service_http(port, attempts=30, delay=3)
                else:
                    ok = not _service_active()
                if ok:
                    _ok(f"Сервис {'остановлен' if action == 'stop' else 'запущен'}.")
                else:
                    _err("Не удалось — journalctl -u " + _SERVICE_NAME)
                _pause()
        elif ch == "2":
            if installed:
                _update_stack()
            else:
                _warn("Сначала установите LibreChat (пункт 1).")
                _pause()
        elif ch == "3":
            if installed:
                _run(["systemctl", "restart", _SERVICE_NAME],
                     capture=True, check=False, timeout=600)
                if _wait_service_http(port, attempts=40, delay=3):
                    _ok("Стек перезапущен.")
                else:
                    _err("api не ответил — journalctl -u librechat")
                _pause()
            else:
                _warn("LibreChat не установлен.")
                _pause()
        elif ch == "4":
            if installed:
                _set_registration()
            else:
                _warn("LibreChat не установлен.")
                _pause()
        elif ch == "5":
            if installed:
                _change_web_port()
            else:
                _warn("LibreChat не установлен.")
                _pause()
        elif ch == "6":
            if installed:
                _journal_boxed()
                _pause()
            else:
                _warn("LibreChat не установлен.")
                _pause()
        elif ch == "7":
            os.system("clear")
            _box_top("🔌  ДОСТУП ПО SSH-ТУННЕЛЮ  •  LIBRECHAT")
            _box_row()
            _box_row(f"  {DIM}Панель слушает только 127.0.0.1:{port} —{NC}")
            _box_row(f"  {DIM}снаружи порт не публикуется (loopback-патч).{NC}")
            _box_row()
            _box_row(f"  {BOLD}{WHITE}На своей машине:{NC}")
            _box_row()
            _box_link(f"ssh -L {port}:127.0.0.1:{port} root@<IP-сервера>")
            _box_row()
            _box_row(f"  {DIM}затем откройте: http://127.0.0.1:{port}/{NC}")
            _box_row()
            _box_row(f"  {DIM}Admin panel: ssh -L {admin_port}:127.0.0.1:{admin_port} …{NC}")
            _box_row()
            _box_row(f"  {DIM}Прямой доступ по HTTPS — пункт 8 (nginx front).{NC}")
            _box_row()
            _box_bot()
            _pause()
        elif ch == "8":
            if installed:
                _nginx_menu()
            else:
                _warn("LibreChat не установлен.")
                _pause()
        elif ch == "9":
            if installed:
                _zai_endpoint_menu()
            else:
                _warn("LibreChat не установлен.")
                _pause()
        elif ch == "0":
            if installed:
                _uninstall()
            else:
                _warn("LibreChat не установлен.")
                _pause()
        elif ch in ("q", ""):
            break

def _service_state() -> str:
    r = _run(["systemctl", "is-active", _SERVICE_NAME],
             capture=True, check=False, timeout=15)
    return (r.stdout or b"").decode(errors="replace").strip()

def _service_active() -> bool:
    return _service_state() == "active"

# CLI для ручных операций (паттерн warp.py / triple_panel.py)
if __name__ == "__main__":
    if "--smoke" in sys.argv:
        st = _load_state()
        sys.exit(0 if _smoke_check(int(st.get("web_port", _DEFAULT_PORT)))
                 else 1)
    if "--version" in sys.argv:
        st = _load_state()
        print(f"port={_LC_VERSION} code={st.get('version', '')}"
              f" runtime={st.get('runtime_version', '')}"
              f" upstream={_refresh_upstream_cache()}")
    else:
        do_librechat_menu()

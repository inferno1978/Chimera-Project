#!/usr/bin/env python3
"""
chimera/modules/triple_panel.py
───────────────────────────────────────────────────────────────────────────────
Triple Panel — порт веб-панели Panel-Naive-Mieru-by-RIXXX (CWash797-cmd)
в нативную архитектуру Chimera. Питон-порт: Node.js/PM2/SQLite НЕ тащим.

ЧТО ЭТО:
  Отдельный веб-сервис (по паттерну B4 / vless-web) с фронтендом апстрима
  (panel/public — vanilla JS, без сборки) и бэкендом, реализующим
  API-контракт панели поверх ГОТОВЫХ примитивов Chimera:

    • юзер-модель    → users.json + sync contract v4.25 (rest_api)
    • протоколы      → naiveproxy.py / mieru.py (уже установлены модулями 10/11)
    • TTL/квоты      → ttl_users.py / traffic_limits.json
    • подписка       → subscription.py (UA-детект, base64/singbox/clash)
    • доступ         → panel_nginx_front.py (SSH-туннель / self-signed / LE)
    • версии         → GitHub API + TTL-кэш (паттерн dpi_bypass.py)
    • порты          → port_registry.py (конфликт-чек + регистрация)
    • скачивание     → download_manager.py (PackageSpec + manual fallback)

АРХИТЕКТУРА (почему отдельный сервис, а не роуты в rest_api.py):
  • свой лайфсайкл: версия фронта ≠ версия Chimera (обновляется независимо)
  • свой порт (выбирает юзер) — 8443 не трогаем, rest_api не раздуваем
  • паттерн B4: TUI-пункт + systemd-юнит + nginx-front + ufw-доступ

ВЕРСИИ:
  front_version — тег апстрима, чей фронтенд вендорен (v1.11.2 на момент
  порта). upstream_version — последний релиз на GitHub (кэш 5 мин).
  Бэкенд-контракт — наш код; апстрим декларирует "No API changes" в
  минорных релизах, дельты ловим контракто-смоуком при обновлении.

Точка входа из TUI (раздел 1 → W → 8):
    from chimera.modules.triple_panel import do_triple_panel_menu

Запуск веб-сервера (systemd):
    python3 -c "from chimera.modules.triple_panel_web import start_server; start_server()"

ПОЛНАЯ АВТОНОМНОСТЬ: модуль НЕ требует изменений в _core.py. Ядро
резолвится лениво через _core_module() (паттерн warp.py — top-level
импорт из _core здесь запрещён циклической инициализацией).
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
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Optional

from chimera.modules.proto_common import proto_ask, ProtoCancelled
# Конвенция проекта (как в naiveproxy/mieru): локальный алиас, чтобы
# `except _Cancelled:` работал без изменений. ВАЖНО: proto_common НЕ
# экспортирует имя `_Cancelled` — импорт «from proto_common import
# _Cancelled» падает ImportError (латентный баг v81, пойманный тестом
# test_update_front_up_to_date_injects_shim).
_Cancelled = ProtoCancelled

# ── Прямой запуск (python3 .../triple_panel.py) — bootstrap корня проекта ───
if __package__ in (None, ""):
    _ROOT = Path(__file__).resolve().parent.parent.parent
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))
    import chimera.modules.proto_common as _pc_bootstrap  # noqa: F401

# ══════════════════════════════════════════════════════════════════════════════
#  КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════════════════════
STATE_DIR      = Path("/var/lib/xray-installer")
_STATE_FILE    = STATE_DIR / "triple_panel_state.json"
_WWW_DIR       = STATE_DIR / "triple_panel_www"      # вендореный фронт апстрима
_STAGING_DIR   = STATE_DIR / "triple_panel_staging"  # atomic-swap staging
_SERVICE_FILE  = Path("/etc/systemd/system/triple-web.service")
_SERVICE_NAME  = "triple-web"
_DEFAULT_PORT  = 9760
_PORT_TAG      = "triple_panel_web"
_PROJECT_ROOT  = Path(__file__).resolve().parent.parent.parent

_NGINX_STATE_FILE = STATE_DIR / "triple_panel_nginx.json"
_NGINX_SITE_NAME  = "chimera-triple-panel"
DEFAULT_NGINX_PORT = 9761

# Апстрим (MIT © RIXXX). Лицензия сохраняется в вендореном фронте.
_UPSTREAM_REPO     = "cwash797-cmd/Panel-Naive-Mieru-by-RIXXX"
_UPSTREAM_API_LATEST = f"https://api.github.com/repos/{_UPSTREAM_REPO}/releases/latest"
_UPSTREAM_VERSIONS_URL = f"https://api.github.com/repos/{_UPSTREAM_REPO}/releases"
_PORT_FRONT_VERSION  = "1.11.2"   # версия порта: фронт+контракт синхронизированы
_UPSTREAM_CACHE_TTL  = 300        # сек (5 мин) — паттерн _b4_latest_cache

# Путь фронтенда внутри тарбола апстрима: <repo>-<tag>/panel/public/*
_FRONT_TARBALL_SUBDIR = "panel/public"

# SHA-256 (соль) для пароля админа — сравнение hmac.compare_digest в вебе.
_SALT_LEN = 16

# ── Цвета (self-contained, паттерн naiveproxy.py) ────────────────────────────
def _detect_colors() -> dict:
    if os.environ.get("NO_COLOR"):
        return {k: "" for k in ("CYAN", "NC", "GREEN", "YELLOW", "RED",
                                 "BLUE", "BOLD", "DIM", "WHITE", "TITLE")}
    if not sys.stdout.isatty() and os.environ.get("FORCE_COLOR") is None:
        return {k: "" for k in ("CYAN", "NC", "GREEN", "YELLOW", "RED",
                                 "BLUE", "BOLD", "DIM", "WHITE", "TITLE")}
    return {
        "CYAN": "\033[96m", "NC": "\033[0m", "GREEN": "\033[92m",
        "YELLOW": "\033[93m", "RED": "\033[91m", "BLUE": "\033[94m",
        "BOLD": "\033[1m", "DIM": "\033[2m", "WHITE": "\033[97m",
        "TITLE": "\033[96m\x1b[1m",
    }
_C = _detect_colors()
CYAN, NC   = _C["CYAN"], _C["NC"]
GREEN, YELLOW, RED = _C["GREEN"], _C["YELLOW"], _C["RED"]
BLUE, BOLD, DIM, WHITE, TITLE = _C["BLUE"], _C["BOLD"], _C["DIM"], _C["WHITE"], _C["TITLE"]

_BOX_W = 64

# ══════════════════════════════════════════════════════════════════════════════
#  ЯДРО / STATE (лениво, как warp.py)
# ══════════════════════════════════════════════════════════════════════════════
def _core_module():
    import importlib
    return importlib.import_module("chimera._core")

def _log(level: str, msg: str) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        with open("/var/log/chimera.log", "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [TRIPLE-PANEL][{level}] {msg}\n")
    except Exception:
        pass

def _info(msg): print(f"{CYAN}[INFO]{NC}  {msg}"); _log("INFO", msg)
def _ok(msg):   print(f"{GREEN}[OK]{NC}    {msg}"); _log("OK", msg)
def _warn(msg): print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN", msg)
def _err(msg):  print(f"{RED}[ERR]{NC}   {msg}"); _log("ERR", msg)

# ── State (proto_common: атомарная запись + owner/mode) ──────────────────────
def _load_state() -> dict:
    from chimera.modules.proto_common import proto_load_state
    defaults = {
        "installed": False,
        "web_port": _DEFAULT_PORT,
        "admin_user": "admin",
        "admin_pass_salt": "",
        "admin_pass_sha256": "",
        "front_version": "",
        "language": "ru",
        "upstream_cache": {"version": "", "ts": 0},
    }
    return proto_load_state(_STATE_FILE, defaults)

def _save_state(state: dict) -> None:
    from chimera.modules.proto_common import proto_save_state
    proto_save_state(_STATE_FILE, state)

# ══════════════════════════════════════════════════════════════════════════════
#  BOX-РЕНДЕР (локальный, паттерн naiveproxy.py)
# ══════════════════════════════════════════════════════════════════════════════
def _box_top(title: str = "") -> None:
    if title:
        pad = _BOX_W - len(title) - 2
        left = pad // 2
        print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")
        print(f"{CYAN}║{' ' * left}{TITLE}{title}{NC}{CYAN}{' ' * (pad - left)}║{NC}")
        print(f"{CYAN}╠{'═' * _BOX_W}╣{NC}")
    else:
        print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")

def _box_row(text: str = "") -> None:
    ln = len(text)
    print(f"{CYAN}║{NC}{text}{' ' * max(0, _BOX_W - ln)}{CYAN}║{NC}")

def _box_sep() -> None:
    print(f"{CYAN}╠{'═' * _BOX_W}╣{NC}")

def _box_bot() -> None:
    print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")

def _box_item(key: str, label: str) -> None:
    print(f"{CYAN}║{NC}  {BOLD}{key:<4}{NC} {label}")

def _box_kv(key: str, val: str, kw: int = 22) -> None:
    print(f"{CYAN}║{NC}  {DIM}{key:<{kw}}{NC} {val}")

def _box_ok(msg):   _box_row(f"  {GREEN}✓{NC}  {msg}")
def _box_warn(msg): _box_row(f"  {YELLOW}⚠{NC}  {msg}")
def _box_err(msg):  _box_row(f"  {RED}✗{NC}  {msg}")
def _box_link(link: str) -> None:
    _box_row(f"  {WHITE}{link}{NC}")

def _pause() -> None:
    try:
        input(f"\n{BLUE}  Нажмите Enter...{NC}")
    except (EOFError, KeyboardInterrupt, OSError):
        print()

def _run(cmd: list, capture: bool = False, check: bool = False):
    return subprocess.run(cmd, capture_output=capture, check=check)

# ══════════════════════════════════════════════════════════════════════════════
#  ВЕРСИИ (паттерн dpi_bypass.py: installed / latest / кэш / header row)
# ══════════════════════════════════════════════════════════════════════════════
def _version_key(version: str) -> tuple:
    """'v1.11.2' / '1.11.2' → (1, 11, 2). Паттерн _b4_version_key."""
    nums = re.findall(r"\d+", str(version or ""))
    return tuple(int(n) for n in nums[:4]) or (0,)

def _strip_v(version: str) -> str:
    return str(version or "").strip().lstrip("vV")

def _detect_installed() -> bool:
    """True если веб-панель установлена (unit + www + state)."""
    st = _load_state()
    return bool(st.get("installed")) and _SERVICE_FILE.exists() and _WWW_DIR.exists()

def _service_active() -> bool:
    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True, check=False)
    return r.returncode == 0 and r.stdout.decode().strip() == "active"

def _detect_upstream_version(timeout: int = 10) -> str:
    """Последний СТАБИЛЬНЫЙ релиз апстрима (GitHub API). '' при ошибке."""
    try:
        req = urllib.request.Request(
            _UPSTREAM_API_LATEST,
            headers={"User-Agent": "chimera-triple-panel",
                     "Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        tag = data.get("tag_name", "")
        return _strip_v(tag)
    except Exception:
        return ""

def _refresh_upstream_cache(force: bool = False) -> str:
    """TTL-кэш версии апстрима в state (паттерн _b4_latest_cache)."""
    state = _load_state()
    cache = state.get("upstream_cache", {})
    now = time.time()
    if (not force and cache.get("version")
            and now - float(cache.get("ts", 0)) < _UPSTREAM_CACHE_TTL):
        return cache["version"]
    version = _detect_upstream_version()
    if version:
        state["upstream_cache"] = {"version": version, "ts": int(now)}
        _save_state(state)
        return version
    return cache.get("version", "")  # протухший лучше ничего

def _update_availability() -> str:
    """'up-to-date' | 'update-available' | 'unknown' — для header row."""
    front = _load_state().get("front_version", "")
    upstream = _refresh_upstream_cache()
    if not front or not upstream:
        return "unknown"
    if _version_key(front) >= _version_key(upstream):
        return "up-to-date"
    return "update-available"

def _update_header_row() -> str:
    """Строка шапки статуса — паттерн _b4_update_header_row."""
    state = _load_state()
    front = state.get("front_version", "") or "—"
    upstream = _refresh_upstream_cache() or "—"
    status = _update_availability()
    if status == "update-available":
        marker = f"{YELLOW}доступно обновление{NC}"
    elif status == "up-to-date":
        marker = f"{GREEN}актуален{NC}"
    else:
        marker = f"{DIM}неизвестно{NC}"
    return f"  {DIM}Фронт:{NC} {CYAN}{front}{NC}  {DIM}Апстрим:{NC} {CYAN}{upstream}{NC}  → {marker}"

# ══════════════════════════════════════════════════════════════════════════════
#  СКАЧИВАНИЕ ФРОНТА (download_manager, требование №3)
# ══════════════════════════════════════════════════════════════════════════════
def _front_mirror_urls(filename: str) -> list:
    """Кандидаты URL тарболла исходников апстрима под тег из filename.

    filename = 'triple-panel-front-v1.11.2.tar.gz' → тег 'v1.11.2'.
    jsDelivr/statically не раздают тарболлы — только GitHub-архивы.
    """
    m = re.search(r"v(\d+\.\d+\.\d+)", filename)
    tag = f"v{m.group(1)}" if m else "latest"
    if tag == "latest":
        return [
            f"https://github.com/{_UPSTREAM_REPO}/archive/refs/heads/main.tar.gz",
            f"https://codeload.github.com/{_UPSTREAM_REPO}/tar.gz/refs/heads/main",
        ]
    return [
        f"https://github.com/{_UPSTREAM_REPO}/archive/refs/tags/{tag}.tar.gz",
        f"https://codeload.github.com/{_UPSTREAM_REPO}/tar.gz/refs/tags/{tag}",
    ]

def _front_spec(version: str):
    """PackageSpec для фронтенда апстрима (download_manager)."""
    from chimera.modules.download_manager import PackageSpec
    v = _strip_v(version) or "latest"
    return PackageSpec(
        name=f"Triple Panel front v{v}",
        filename_builder=lambda: f"triple-panel-front-v{v}.tar.gz",
        mirror_urls_builder=_front_mirror_urls,
        install_dests=[STATE_DIR],
        manual_incoming_dir=Path("/root"),
        min_size=60_000,   # фронт+locales > 60 КБ; страница-заглушка меньше
    )

def _extract_front(tar_path: Path, dest: Path) -> bool:
    """Извлекает <tarball>/panel/public/* в dest. Возвращает success.

    Path-traversal guard: члены архива с '..' или абсолютными путями
    отбрасываются (tarfile extractall filter — актуально для Python 3.12+,
    здесь ручной guard для совместимости с 3.8+).
    """
    try:
        dest.mkdir(parents=True, exist_ok=True)
        with tarfile.open(tar_path, "r:gz") as tar:
            for member in tar.getmembers():
                name = member.name
                # нормализация: ведущий ./ и первый компонент (repo-tag)
                parts = [p for p in name.split("/") if p not in ("", ".")]
                if len(parts) < 3:
                    continue
                if ".." in parts or name.startswith("/"):
                    continue
                # <repo>-<tag> / panel / public / ...
                if parts[1] != "panel" or parts[2] != "public":
                    continue
                rel = "/".join(parts[3:])
                target = dest / rel
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with tar.extractfile(member) as src, open(target, "wb") as out:
                        shutil.copyfileobj(src, out)
        # Лицензия MIT — обязательный кредит (условие лицензии апстрима).
        lic = dest / "LICENSE.upstream"
        if not lic.exists():
            lic.write_text(
                f"Frontend vendored from github.com/{_UPSTREAM_REPO} "
                f"(MIT © RIXXX). Upstream license applies to frontend assets.\n",
                encoding="utf-8",
            )
        return any(dest.iterdir())
    except Exception as e:
        _err(f"Распаковка фронта: {e}")
        return False

# ══════════════════════════════════════════════════════════════════════════════
#  v82: SSE-ШИМ (фронт-патч поверх апстримного app.js)
#  Апстрим общается с бэкендом по WebSocket (только метрики). У нас SSE —
#  шим подменяет window.WebSocket классом поверх EventSource, поэтому
#  app.js не меняется и «WS-точка» в шапке живой. Плюс live-обновления
#  таблицы юзеров и логов (сверх WS-контракта апстрима).
# ══════════════════════════════════════════════════════════════════════════════
_SSE_SHIM_JS = """/* Chimera Triple Panel - SSE live-updates (port v82).
 * Upstream app.js talks to the backend via WebSocket (metrics only:
 * msg.type === 'metrics'). The Chimera backend is stdlib - no WS;
 * instead it serves /api/events (text/event-stream). This shim replaces
 * window.WebSocket with a class backed by a shared EventSource:
 *   - SSE event 'metrics' -> ws.onmessage({data}) - upstream contract;
 *   - SSE event 'users'   -> loadUsers() (live user table);
 *   - SSE event 'log'     -> loadLogs() when the logs page is open.
 * index.html loads this file BEFORE app.js. If SSE is unavailable
 * everything degrades silently (upstream 5s reconnect is harmless).
 */
(function () {
  'use strict';
  if (typeof window.EventSource === 'undefined') { return; }

  var shared = null, wired = false, latest = null;
  var lastUsers = 0, lastLogs = 0;

  function bus() {
    if (!shared) {
      var base = (typeof BASE_PATH !== 'undefined') ? BASE_PATH : '';
      shared = new EventSource(base + '/api/events');
    }
    return shared;
  }

  function wire() {
    if (wired) { return; }
    wired = true;
    var es = bus();
    es.addEventListener('open', function () {
      var dot = document.getElementById('ws-dot');
      if (dot) { dot.className = 'status-dot connected'; }
      if (latest && typeof latest.onopen === 'function') {
        try { latest.onopen(); } catch (e) {}
      }
    });
    es.addEventListener('metrics', function (ev) {
      if (latest && typeof latest.onmessage === 'function') {
        try { latest.onmessage({ data: ev.data }); } catch (e) {}
      }
    });
    es.addEventListener('error', function () {
      var dot = document.getElementById('ws-dot');
      if (dot) { dot.className = 'status-dot error'; }
      /* EventSource reconnects by itself; the upstream 5s reconnect loop
       * is harmless - new SSEWebSocket instances just update `latest`. */
      if (latest && typeof latest.onclose === 'function') {
        try { latest.onclose(); } catch (e) {}
      }
    });
    /* live updates beyond the upstream WS contract */
    es.addEventListener('users', function () {
      var now = Date.now();
      if (now - lastUsers < 1000) { return; }
      lastUsers = now;
      if (typeof loadUsers === 'function') {
        try { loadUsers(); } catch (e) {}
      }
    });
    es.addEventListener('log', function () {
      var now = Date.now();
      if (now - lastLogs < 2000) { return; }
      lastLogs = now;
      try {
        if (typeof state !== 'undefined' && state &&
            state.currentPage === 'logs' &&
            typeof loadLogs === 'function') {
          loadLogs(currentLogService);
        }
      } catch (e) {}
    });
  }

  function SSEWebSocket() {
    var self = this;
    this.readyState = 0;
    this.onopen = null; this.onclose = null;
    this.onmessage = null; this.onerror = null;
    latest = self;
    wire();
  }
  SSEWebSocket.prototype.close = function () {
    /* the shared EventSource stays alive (no refcount needed) */
  };
  SSEWebSocket.prototype.send = function () { /* not supported */ };

  window.WebSocket = SSEWebSocket;

  /* hook live updates as soon as app.js has executed (BASE_PATH is
   * declared inside app.js, so it is read lazily inside bus()) */
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { wire(); });
  } else {
    wire();
  }
})();
"""

def _inject_sse_shim(www_dir: Path) -> bool:
    """v82: пишет triple-sse.js и вставляет его в index.html ДО app.js.

    Идемпотентно: повторная установка/обновление фронта не дублирует тег.
    Возвращает True если шим на месте.
    """
    try:
        shim = www_dir / "triple-sse.js"
        shim.write_text(_SSE_SHIM_JS, encoding="utf-8")
        idx = www_dir / "index.html"
        if not idx.exists():
            return False
        html = idx.read_text(encoding="utf-8")
        if "triple-sse.js" in html:
            return True  # уже вживлён
        tag = '<script src="triple-sse.js"></script>\n'
        marker = re.search(
            r"<script[^>]*src=[\"'][^\"']*app\.js[\"'][^>]*>\s*</script>",
            html)
        if marker:
            html = html[:marker.start()] + tag + html[marker.start():]
        else:
            html = html.replace("</head>", tag + "</head>")
        idx.write_text(html, encoding="utf-8")
        return True
    except Exception as e:
        _err(f"SSE-шим: {e}")
        return False

def _fetch_front(version: str, quiet: bool = False) -> bool:
    """Скачивает и вендорит фронт версии version → _WWW_DIR (atomic swap)."""
    from chimera.modules.download_manager import fetch_package
    if not quiet:
        _info(f"Скачиваю фронтенд апстрима v{_strip_v(version)}...")
    spec = _front_spec(version)
    ok = fetch_package(spec, progress_label="triple-panel front")
    if not ok:
        return False
    tar_path = STATE_DIR / spec.filename_builder()
    # staging → atomic swap
    if _STAGING_DIR.exists():
        shutil.rmtree(_STAGING_DIR, ignore_errors=True)
    if not _extract_front(tar_path, _STAGING_DIR):
        return False
    if _WWW_DIR.exists():
        shutil.rmtree(_WWW_DIR, ignore_errors=True)
    _STAGING_DIR.rename(_WWW_DIR)
    try:
        tar_path.unlink(missing_ok=True)
    except Exception:
        pass
    # v82: SSE-шим поверх EventSource (подменяет WS апстрима во фронте)
    _inject_sse_shim(_WWW_DIR)
    return _WWW_DIR.exists() and (_WWW_DIR / "index.html").exists()

# ══════════════════════════════════════════════════════════════════════════════
#  ВЫБОР ПОРТА (требование №5: юзер выбирает порт) + port_registry (№2)
# ══════════════════════════════════════════════════════════════════════════════
def _port_conflicts(port: int) -> list:
    """Конфликты порта: порт_реестр + слушатели + ufw (port_registry API)."""
    try:
        from chimera.modules.port_registry import port_get_conflicts
        return port_get_conflicts(port, proto="tcp")
    except Exception:
        return []

def _port_busy_system(port: int) -> list:
    try:
        from chimera.modules.port_registry import port_check_system
        return port_check_system(port, proto="tcp")
    except Exception:
        return []

def _validate_web_port(port: int) -> "tuple[bool, list]":
    """(валиден, список конфликтов). 1024-65535, вне занятых реестром/системой."""
    if not isinstance(port, int) or port < 1024 or port > 65535:
        return False, ["порт должен быть 1024-65535"]
    conflicts = _port_conflicts(port) + _port_busy_system(port)
    return (len(conflicts) == 0), conflicts

def _ask_web_port(default: int = _DEFAULT_PORT) -> "Optional[int]":
    """Интерактивный выбор порта панели с показом конфликтов. None = отмена."""
    while True:
        _box_row()
        _box_row(f"  {DIM}Порт веб-панели (ввод = {default}):{NC}")
        _box_row(f"  {DIM}Проверю port_registry и слушателей перед регистрацией.{NC}")
        raw = proto_ask(f"  {CYAN}Порт: {NC}", default=str(default), c=True).strip()
        if raw.lower() == "q":
            return None
        try:
            port = int(raw)
        except ValueError:
            _box_warn("Нужно число (или Q для отмены).")
            continue
        ok, conflicts = _validate_web_port(port)
        if ok:
            return port
        _box_row()
        _box_warn(f"Порт {port} недоступен:")
        for c in conflicts[:6]:
            _box_row(f"    {RED}•{NC} {c}")
        _box_row(f"  {DIM}Выберите другой порт.{NC}")

# ══════════════════════════════════════════════════════════════════════════════
#  АДМИН-КРЕДЫ (SHA-256 + соль; вывод пароля ОДИН раз — паттерн vless-web)
# ══════════════════════════════════════════════════════════════════════════════
def _hash_admin_password(password: str, salt: str) -> str:
    import hashlib
    return hashlib.sha256((salt + password).encode()).hexdigest()

def _set_admin_password(state: dict, password: str) -> None:
    state["admin_pass_salt"] = secrets.token_hex(_SALT_LEN)
    state["admin_pass_sha256"] = _hash_admin_password(
        password, state["admin_pass_salt"])

def _gen_admin_password() -> str:
    return secrets.token_urlsafe(12)

# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEMD-ЮНИТ (по образцу vless-web.service)
# ══════════════════════════════════════════════════════════════════════════════
def _write_service_unit() -> None:
    unit = f"""[Unit]
Description=Chimera Triple Panel (Naive+Mieru+H2 web UI, RIXXX-порт)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -c "from chimera.modules.triple_panel_web import start_server; start_server()"
WorkingDirectory={_PROJECT_ROOT}
Environment=PYTHONPATH={_PROJECT_ROOT}
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
"""
    _SERVICE_FILE.write_text(unit)
    _run(["systemctl", "daemon-reload"], check=False)

def _smoke_check(port: int, timeout: int = 15) -> bool:
    """GET / на локальный порт — фронт отдаётся? (контракто-смоук v1)."""
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/", timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False

# ══════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА
# ══════════════════════════════════════════════════════════════════════════════
def _install() -> bool:
    os.system("clear")
    _box_top("🧩  TRIPLE PANEL — УСТАНОВКА")
    _box_row()
    _box_row(f"  Порт веб-панели {TITLE}Panel-Naive-Mieru-by-RIXXX{NC} в архитектуре Chimera.")
    _box_row(f"  {DIM}Фронт апстрима (MIT © RIXXX) + питон-бэкенд поверх модулей 10/11/H2.{NC}")
    _box_row()
    _box_sep()

    # 1. Порт (требование: выбор юзера + конфликт-чек)
    port = _ask_web_port()
    if port is None:
        return False

    # 2. Фронт (download_manager)
    upstream = _refresh_upstream_cache() or _PORT_FRONT_VERSION
    if not _fetch_front(upstream):
        _box_err("Не удалось скачать фронтенд (см. подсказку download_manager).")
        _box_row(f"  {DIM}Ручной путь: скачайте тарболл в /root/ и повторите.{NC}")
        _box_bot(); _pause()
        return False
    _box_ok(f"Фронтенд v{upstream} вендорен → {_WWW_DIR}")

    # 3. Креды (пароль показывается ОДИН раз)
    state = _load_state()
    state["web_port"] = port
    state["front_version"] = upstream
    state["language"] = state.get("language", "ru")
    try:
        admin_user = proto_ask(
            f"  {CYAN}Логин админа: {NC}",
            default=state.get("admin_user", "admin"), c=True).strip() or "admin"
    except _Cancelled:
        return False
    password = _gen_admin_password()
    state["admin_user"] = admin_user
    _set_admin_password(state, password)

    # 4. port_registry (требование №2): регистрация + ufw
    try:
        from chimera.modules.port_registry import port_register, ufw_open_port
        ok, msg = port_register(_PORT_TAG, port, proto="tcp",
                                comment="Chimera Triple Panel web UI")
        if not ok:
            _box_warn(f"port_registry: {msg}")
        ufw_open_port(port, "tcp", _PORT_TAG,
                      comment="Chimera Triple Panel web UI")
    except Exception as e:
        _box_warn(f"port_registry недоступен: {e}")

    # 5. Юнит + старт
    _write_service_unit()
    state["installed"] = True
    _save_state(state)
    _run(["systemctl", "enable", "--now", _SERVICE_NAME], check=False)
    for _ in range(15):
        if _service_active():
            break
        time.sleep(1)
    if not _service_active():
        _box_err("Сервис не поднялся. Журнал:")
        _run(["journalctl", "-u", _SERVICE_NAME, "-n", "20", "--no-pager"])
        _box_bot(); _pause()
        return False
    if not _smoke_check(port):
        _box_warn("Сервис активен, но GET / не отвечает — проверьте journalctl.")
    _box_ok(f"Сервис {_SERVICE_NAME} активен (127.0.0.1:{port})")

    # 6. Итог
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Доступ по SSH-туннелю:{NC}")
    _box_row()
    _box_link(f"ssh -L {port}:127.0.0.1:{port} root@<IP-сервера>")
    _box_row(f"  {DIM}затем: http://127.0.0.1:{port}/{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Админ-доступ (пароль показан ОДИН раз):{NC}")
    _box_kv("Логин:", f"{YELLOW}{admin_user}{NC}")
    _box_kv("Пароль:", f"{YELLOW}{password}{NC}")
    _box_row(f"  {DIM}Наружу панель открывается отдельно (пункт 4) — nginx+TLS.{NC}")
    _box_row()
    _box_bot()
    _log("INFO", f"installed: port={port} front={upstream}")
    _pause()
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  ОБНОВЛЕНИЕ ФРОНТА (требование №1: версии как у B4)
# ══════════════════════════════════════════════════════════════════════════════
def _update_front() -> bool:
    state = _load_state()
    current = state.get("front_version", "")
    upstream = _refresh_upstream_cache(force=True)
    if not upstream:
        _box_err("Не удалось получить версию апстрима (GitHub API).")
        _pause()
        return False
    if current and _version_key(current) >= _version_key(upstream):
        _box_ok(f"Фронт актуален: v{current} (апстрим v{upstream}).")
        # v82: даже без обновления фронта — до-вживляем SSE-шим (идемпотентно):
        # установки эпохи v81 получили бы его только с переустановкой фронта.
        if _WWW_DIR.exists():
            had_shim = (_WWW_DIR / "triple-sse.js").exists()
            if _inject_sse_shim(_WWW_DIR) and not had_shim:
                _box_ok("SSE-шим (v82) вживлён во фронт — live-обновления "
                        "включены.")
                if _service_active():
                    _run(["systemctl", "restart", _SERVICE_NAME], check=False)
                    _box_ok(f"{_SERVICE_NAME}.service перезапущен.")
        _pause()
        return True
    os.system("clear")
    _box_top("⬆️  TRIPLE PANEL — ОБНОВЛЕНИЕ ФРОНТА")
    _box_row()
    _box_kv("Установлено:", f"{CYAN}{current or '—'}{NC}")
    _box_kv("Доступно:",   f"{GREEN}{upstream}{NC}")
    _box_row()
    _box_row(f"  {DIM}Бэкенд-контракт — код Chimera, он не меняется.{NC}")
    _box_row(f"  {DIM}После swap гоняю смоук (GET /) с откатом при провале.{NC}")
    _box_row()
    try:
        confirm = proto_ask(
            f"  {CYAN}Обновить фронт до v{upstream}? [y/N]: {NC}",
            default="n", c=True).strip().lower()
    except _Cancelled:
        return False
    if confirm != "y":
        return False

    # бэкап текущего → качаем новый → swap → смоук → откат при провале
    backup = None
    if _WWW_DIR.exists():
        backup = STATE_DIR / "triple_panel_www.bak"
        if backup.exists():
            shutil.rmtree(backup, ignore_errors=True)
        shutil.copytree(_WWW_DIR, backup)
    if not _fetch_front(upstream, quiet=True):
        _box_err("Скачивание не удалось.")
        if backup and backup.exists():
            _box_warn("Текущий фронт не тронут.")
        _pause()
        return False
    if not _smoke_check(int(state.get("web_port", _DEFAULT_PORT))):
        _box_err("Смоук после обновления провален — ОТКАТ.")
        if backup and backup.exists():
            if _WWW_DIR.exists():
                shutil.rmtree(_WWW_DIR, ignore_errors=True)
            backup.rename(_WWW_DIR)
            _box_ok("Откат выполнен, предыдущий фронт восстановлен.")
        _pause()
        return False
    state["front_version"] = upstream
    _save_state(state)
    if backup and backup.exists():
        shutil.rmtree(backup, ignore_errors=True)
    _box_ok(f"Фронт обновлён: v{current or '—'} → v{upstream}")
    _log("INFO", f"front updated {current} -> {upstream}")
    _pause()
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  ДОСТУП (требование №4: эталон B4 / panel_nginx_front)
# ══════════════════════════════════════════════════════════════════════════════
def _nginx_status() -> dict:
    if not _NGINX_STATE_FILE.exists():
        return {"enabled": False}
    try:
        return json.loads(_NGINX_STATE_FILE.read_text())
    except Exception:
        return {"enabled": False}

def _nginx_install(use_self_signed: bool, domain: "Optional[str]") -> "tuple[bool, str]":
    """nginx front c TLS по эталону B4 (dpi_bypass._b4_nginx_install)."""
    from chimera.modules.panel_nginx_front import panel_nginx_front_install
    state = _load_state()
    ok, msg = panel_nginx_front_install(
        service_tag="chimera-triple-nginx",
        port=DEFAULT_NGINX_PORT,
        backend_port=int(state.get("web_port", _DEFAULT_PORT)),
        site_name=_NGINX_SITE_NAME,
        state_file=_NGINX_STATE_FILE,
        title="Triple Panel",
        use_self_signed=use_self_signed,
        domain=domain,
        websocket_origin_rewrite=False,
        backend_http_scheme="http",   # наш бэкенд — plain HTTP за nginx
        cert_name_slug="chimera-triple",
        mcp_proxy=False,
    )
    if ok:
        # Паттерн B4: прямой порт закрываем — доступ только через фронт.
        try:
            subprocess.run(
                ["ufw", "deny", f"{int(state.get('web_port', _DEFAULT_PORT))}/tcp",
                 "comment", "chimera-triple-direct-block"],
                capture_output=True, check=False)
        except Exception:
            pass
    return ok, msg

def _nginx_remove() -> "tuple[bool, str]":
    """Снятие nginx front + reopen прямого порта (для SSH-туннеля)."""
    from chimera.modules.panel_nginx_front import panel_nginx_front_remove
    state = _load_state()
    if not _nginx_status().get("enabled"):
        return True, "nginx front уже выключен"
    ok, msg = panel_nginx_front_remove(
        service_tag="chimera-triple-nginx",
        site_name=_NGINX_SITE_NAME,
        state_file=_NGINX_STATE_FILE,
        title="Triple Panel",
    )
    try:
        subprocess.run(
            ["ufw", "delete", "deny",
             f"{int(state.get('web_port', _DEFAULT_PORT))}/tcp"],
            capture_output=True, check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    return ok, msg

def _nginx_url() -> "Optional[str]":
    st = _nginx_status()
    if not st.get("enabled"):
        return None
    domain = st.get("domain")
    if not domain:
        return None
    return f"https://{domain}:{st.get('port', DEFAULT_NGINX_PORT)}"

def _access_menu() -> None:
    while True:
        os.system("clear")
        print()
        st = _nginx_status()
        _box_top("🌐  TRIPLE PANEL — ДОСТУП (эталон b4)")
        _box_row()
        state = _load_state()
        port = int(state.get("web_port", _DEFAULT_PORT))
        _box_kv("Прямой порт:", f"{CYAN}127.0.0.1:{port}{NC} {DIM}(SSH-туннель){NC}")
        url = _nginx_url()
        _box_kv("nginx front:", (f"{GREEN}включён{NC} — {url}" if url
                                 else f"{DIM}выключен (доступ только SSH-туннелем){NC}"))
        _box_row()
        _box_row(f"  {DIM}Три режима (как у b4):{NC}")
        _box_row(f"  {DIM}SSH-туннель = фронт выключен, порт loopback-only{NC}")
        _box_row(f"  {DIM}Публичный IP = self-signed TLS через nginx{NC}")
        _box_row(f"  {DIM}Домен = Let's Encrypt (сертификат/выдача через certbot){NC}")
        _box_row()
        _box_sep()
        if st.get("enabled"):
            _box_item("1", f"{RED}Выключить nginx front{NC} {DIM}(вернуть SSH-режим){NC}")
        else:
            _box_item("1", "🌐 Включить nginx front (TLS)")
        _box_item("Q", "← Назад")
        _box_bot()
        try:
            ch = proto_ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break
        if ch in ("q", ""):
            break
        if ch == "1":
            if st.get("enabled"):
                ok, msg = _nginx_remove()
                (_ok if ok else _err)(msg)
                _pause()
            else:
                from chimera.modules.panel_nginx_front import (
                    ask_tls_mode, ask_domain)
                use_self_signed, _dh = ask_tls_mode(panel_name="Triple Panel")
                domain = None
                if not use_self_signed:
                    domain = ask_domain()
                ok, msg = _nginx_install(use_self_signed, domain)
                (_ok if ok else _err)(msg)
                if ok:
                    _box_row()
                    _box_row(f"  {BOLD}{WHITE}URL панели:{NC}")
                    _box_link(_nginx_url() or "https://<домен>:9761")
                _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  СМЕНА ПОРТА / ПАРОЛЯ / УДАЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _change_web_port() -> bool:
    """Смена порта: stop → перерегистрация → unit не зависит от порта → start.

    Порт читается бэкендом из state при старте (не из юнита), поэтому
    смена порта = правка state + port_registry + рестарт сервиса.
    """
    state = _load_state()
    old = int(state.get("web_port", _DEFAULT_PORT))
    port = _ask_web_port()
    if port is None or port == old:
        return False
    _run(["systemctl", "stop", _SERVICE_NAME], check=False)
    try:
        from chimera.modules.port_registry import (port_register,
                                                   port_unregister,
                                                   ufw_open_port,
                                                   ufw_close_port)
        port_unregister(_PORT_TAG, old, "tcp")
        ufw_close_port(old, "tcp", _PORT_TAG)
        ok, msg = port_register(_PORT_TAG, port, proto="tcp",
                                comment="Chimera Triple Panel web UI")
        if not ok:
            _warn(f"port_registry: {msg}")
        ufw_open_port(port, "tcp", _PORT_TAG,
                      comment="Chimera Triple Panel web UI")
    except Exception as e:
        _warn(f"port_registry: {e}")
    state["web_port"] = port
    _save_state(state)
    _run(["systemctl", "restart", _SERVICE_NAME], check=False)
    time.sleep(2)
    if _service_active() and _smoke_check(port):
        _ok(f"Порт изменён: {old} → {port}")
    else:
        _err("Сервис не поднялся на новом порту — проверьте journalctl.")
    _pause()
    return True

def _change_admin_password() -> None:
    state = _load_state()
    password = _gen_admin_password()
    _set_admin_password(state, password)
    state["installed"] = state.get("installed", True)
    _save_state(state)
    os.system("clear")
    _box_top("🔑  TRIPLE PANEL — НОВЫЙ ПАРОЛЬ")
    _box_row()
    _box_kv("Логин:", f"{YELLOW}{state.get('admin_user', 'admin')}{NC}")
    _box_kv("Пароль:", f"{YELLOW}{password}{NC}")
    _box_row()
    _box_row(f"  {DIM}Показан один раз; сессии сбрасываются рестартом сервиса.{NC}")
    _box_row()
    _box_bot()
    _log("INFO", "admin password rotated")
    _pause()

def _uninstall() -> bool:
    try:
        confirm = proto_ask(
            f"  {RED}Удалить Triple Panel полностью? [y/N]: {NC}",
            default="n", c=True).strip().lower()
    except _Cancelled:
        return False
    if confirm != "y":
        return False
    _nginx_remove()
    _run(["systemctl", "disable", "--now", _SERVICE_NAME], check=False)
    try:
        _SERVICE_FILE.unlink()
        _run(["systemctl", "daemon-reload"], check=False)
    except Exception:
        pass
    state = _load_state()
    try:
        from chimera.modules.port_registry import (port_unregister,
                                                   ufw_close_port)
        port_unregister(_PORT_TAG)
        ufw_close_port(int(state.get("web_port", _DEFAULT_PORT)), "tcp",
                       _PORT_TAG)
    except Exception:
        pass
    for d in (_WWW_DIR, _STAGING_DIR):
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
    for f in (STATE_DIR / "triple_panel_www.bak",):
        if f.exists():
            shutil.rmtree(f, ignore_errors=True)
    state["installed"] = False
    state["front_version"] = ""
    _save_state(state)
    _ok("Triple Panel удалена (протоколы naive/mieru/hy2 не тронуты).")
    _log("INFO", "uninstalled")
    _pause()
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС ПРОТОКОЛОВ (для шапки меню)
# ══════════════════════════════════════════════════════════════════════════════
def _proto_statuses() -> dict:
    """Активность протоколов тройки (для отображения, без побочных действий)."""
    out = {"naive": False, "mieru": False, "hy2": False}
    try:
        from chimera.modules.naiveproxy import is_active as _naive_active
        out["naive"] = bool(_naive_active())
    except Exception:
        pass
    try:
        from chimera.modules.mieru import is_active as _mieru_active
        out["mieru"] = bool(_mieru_active())
    except Exception:
        pass
    try:
        r = _run(["systemctl", "is-active", "hysteria-server"],
                 capture=True, check=False)
        out["hy2"] = r.returncode == 0 and r.stdout.decode().strip() == "active"
    except Exception:
        pass
    return out

# ══════════════════════════════════════════════════════════════════════════════
#  TUI-МЕНЮ (точка входа: раздел 1 → W → 8)
# ══════════════════════════════════════════════════════════════════════════════
def do_triple_panel_menu() -> None:
    while True:
        os.system("clear")
        print()
        _box_top("🧩  TRIPLE PANEL — Naive + Mieru + Hysteria2")
        _box_row()
        state = _load_state()
        installed = _detect_installed()
        running = _service_active()
        port = int(state.get("web_port", _DEFAULT_PORT))

        if not installed:
            _box_warn("Панель НЕ установлена — пункт 1 для установки.")
            _box_row()
        else:
            _box_row(f"  Сервис:  {GREEN+'активен'+NC if running else YELLOW+'остановлен'+NC}"
                     f"  {DIM}(triple-web){NC}")
            _box_row(f"  Порт:    {CYAN}127.0.0.1:{port}{NC} {DIM}(SSH-туннель){NC}")
            url = _nginx_url()
            _box_row(f"  Напрямую: {url or DIM+'закрыто (только SSH-туннель)'+NC}")
            _box_row(f"  Админ:   {CYAN}{state.get('admin_user', 'admin')}{NC}")
        _box_row()
        _box_row(_update_header_row())
        _box_row(f"  {DIM}Порт Химеры:{NC} v{_PORT_FRONT_VERSION}  "
                 f"{DIM}апстрим: github.com/{_UPSTREAM_REPO.split('/')[0]}{NC}")
        _box_row()
        ps = _proto_statuses()
        _box_row(f"  {DIM}Протоколы:{NC} naive {GREEN+'✓'+NC if ps['naive'] else RED+'✗'+NC}"
                 f"  mieru {GREEN+'✓'+NC if ps['mieru'] else RED+'✗'+NC}"
                 f"  hy2 {GREEN+'✓'+NC if ps['hy2'] else RED+'✗'+NC}"
                 f"  {DIM}(модули 10/11/7){NC}")
        _box_row()
        _box_sep()
        if not installed:
            _box_item("1", "🚀 Установить панель")
        else:
            _box_item("1", f"{'Остановить' if running else 'Запустить'} сервис")
        _box_item("2", f"⬆️  Обновить фронт  {DIM}(версии/апдейты как у b4){NC}")
        _box_item("3", f"🔑 Сменить пароль админа")
        _box_item("4", f"🌐 Доступ  {DIM}(SSH / публичный IP / домен — эталон b4){NC}")
        _box_item("5", f"🔀 Сменить порт панели")
        _box_item("6", f"{RED}🗑️  Удалить панель{NC}")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot()
        try:
            ch = proto_ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            if not installed:
                _install()
            else:
                action = "stop" if running else "start"
                _run(["systemctl", action, _SERVICE_NAME], check=False)
                time.sleep(1.5)
                if _service_active():
                    _ok(f"Сервис {'остановлен' if action == 'stop' else 'запущен'}.")
                else:
                    _err("Не удалось — journalctl -u " + _SERVICE_NAME)
                _pause()
        elif ch == "2":
            if installed:
                _update_front()
            else:
                _warn("Сначала установите панель (пункт 1).")
                _pause()
        elif ch == "3":
            if installed:
                _change_admin_password()
            else:
                _warn("Панель не установлена.")
                _pause()
        elif ch == "4":
            if installed:
                _access_menu()
            else:
                _warn("Панель не установлена.")
                _pause()
        elif ch == "5":
            if installed:
                _change_web_port()
            else:
                _warn("Панель не установлена.")
                _pause()
        elif ch == "6":
            if installed:
                _uninstall()
            else:
                _warn("Панель не установлена.")
                _pause()
        elif ch in ("q", ""):
            break

# CLI для ручных операций (паттерн warp.py)
if __name__ == "__main__":
    if "--smoke" in sys.argv:
        st = _load_state()
        sys.exit(0 if _smoke_check(int(st.get("web_port", _DEFAULT_PORT))) else 1)
    if "--version" in sys.argv:
        print(f"port={_PORT_FRONT_VERSION} front={_load_state().get('front_version', '')}"
              f" upstream={_refresh_upstream_cache()}")
    else:
        do_triple_panel_menu()

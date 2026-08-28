"""
chimera/modules/olcrtc.py
───────────────────────────────────────────────────────────────────────────────
olcRTC — туннель TCP-over-WebRTC, маскирующий трафик под видеозвонок
в разрешённых «белым списком» сервисах (WB Stream / Jitsi / Телемост).

Архитектура (полная переработка):
  • olcrtc — сам туннель (github.com/openlibrecommunity/olcrtc, master)
  • olcrtc-manager — веб-панель + API + supervisor (github.com/BigDaddy3334/olcrtc-manager-panel, main)
  • Manager сам запускает/управляет olcrtc процессами
  • Веб-панель на https://SERVER_IP:8888/admin (self-signed TLS)
  • API: /api/state, /api/logs
  • OlcBox URI для клиента

Структура на диске:
  /usr/local/bin/olcrtc                  — туннель (собран из исходников)
  /usr/local/bin/olcrtc-manager          — панель (собрана из исходников)
  /etc/olcrtc-manager/config.json        — конфиг manager (JSON, не YAML)
  /etc/olcrtc-manager/panel.env          — basic auth для панели
  /etc/olcrtc-manager/tls.crt            — self-signed TLS сертификат
  /etc/olcrtc-manager/tls.key            — TLS ключ
  /var/lib/olcrtc/data/                  — runtime данные olcrtc
  /etc/systemd/system/olcrtc-manager.service — systemd unit
  /var/lib/xray-installer/olcrtc.json    — состояние модуля

Точка входа из _core.py:
    from chimera.modules.olcrtc import do_olcrtc_menu
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

# ── Цвета ───────────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m',
            )
        return dict(
            RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
            CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
            DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m',
        )
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BLUE', 'BOLD', 'DIM', 'WHITE', 'NC')}

_C = _detect_colors()
RED    = _C['RED']
GREEN  = _C['GREEN']
YELLOW = _C['YELLOW']
CYAN   = _C['CYAN']
BLUE   = _C['BLUE']
BOLD   = _C['BOLD']
DIM    = _C['DIM']
WHITE  = _C['WHITE']
NC     = _C['NC']

# ── Логирование ────────────────────────────────────────────────────────────────
_LOG_FILE = Path("/var/log/chimera.log")

def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = re.sub(r'\033\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [{OLCRTC_TAG}] [{level}] {clean}\n")
    except Exception:
        pass

OLCRTC_TAG = "OLCRTC"

def _info(msg: str)    -> None: print(f"{CYAN}[INFO]{NC}  {msg}");  _log("INFO",    msg)
def _success(msg: str) -> None: print(f"{GREEN}[OK]{NC}    {msg}"); _log("SUCCESS", msg)
def _warn(msg: str)    -> None: print(f"{YELLOW}[WARN]{NC}  {msg}"); _log("WARN",    msg)
def _error(msg: str)   -> None: print(f"{RED}[ERROR]{NC} {msg}");   _log("ERROR",   msg)

# ── Вспомогательные ───────────────────────────────────────────────────────────
def _run(cmd: list, capture: bool = False, check: bool = False,
         quiet: bool = False, timeout: int | None = None,
         env: dict | None = None, cwd: str | None = None,
         input_text: str | None = None) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if timeout:
        kw["timeout"] = timeout
    if env:
        kw["env"] = env
    if cwd:
        kw["cwd"] = cwd
    if input_text is not None:
        kw["input"] = input_text
    try:
        return subprocess.run(cmd, **kw)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="timeout")
    except Exception as e:
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=str(e))

from chimera.modules.box_renderer import (
    _box_top, _box_bottom, _box_sep, _box_row, _box_item, _box_back,
)

# =============================================================================
#  КОНСТАНТЫ
# =============================================================================
# Репозитории.
OLCRTC_REPO          = "https://github.com/openlibrecommunity/olcrtc"
OLCRTC_MANAGER_REPO  = "https://github.com/BigDaddy3334/olcrtc-manager-panel"
OLCRTC_BRANCH        = "master"
OLCRTC_MANAGER_BRANCH = "main"

# Бинарники.
OLC_BIN       = Path("/usr/local/bin/olcrtc")
OLC_MGR_BIN   = Path("/usr/local/bin/olcrtc-manager")

# Go toolchain.
OLC_GO_DIR    = Path("/usr/local/go")

# Manager panel файлы.
MGR_ETC_DIR   = Path("/etc/olcrtc-manager")
MGR_CONFIG    = MGR_ETC_DIR / "config.json"
MGR_PANEL_ENV = MGR_ETC_DIR / "panel.env"
MGR_TLS_CRT   = MGR_ETC_DIR / "tls.crt"
MGR_TLS_KEY   = MGR_ETC_DIR / "tls.key"
MGR_DATA_DIR  = Path("/var/lib/olcrtc/data")
MGR_UNIT_FILE = Path("/etc/systemd/system/olcrtc-manager.service")

# Состояние модуля.
OLC_STATE_FILE = Path("/var/lib/xray-installer/olcrtc.json")

# Порт manager панели (из гайда).
MGR_PORT = 8888

# Service tag для port_registry.
_OLCRTC_MANAGER_SERVICE_TAG = "olcrtc_manager"

# ── Парольная защита скрытого меню (через access_control.py) ──────────────────
# Master-пароль (админ) + OTP (одноразовый для пользователя).
OLCRTC_HASH_FILE = Path("/var/lib/xray-installer/olcrtc_access.hash")

# Carriers / Transports.
CARRIERS = {
    "1": ("wbstream",  "WB Stream", "комнату нужно создать вручную на stream.wb.ru"),
    "2": ("jitsi",     "Jitsi",     "комната придумывается на лету — полная автоматизация"),
    "3": ("telemost",  "Телемост",  "комнату нужно создать вручную на telemost.yandex.ru"),
}
TRANSPORTS = {
    "1": ("datachannel",  "максимум скорости, минимум маскировки под видео"),
    "2": ("vp8channel",   "маскировка под видео VP8, средняя скорость"),
    "3": ("seichannel",   "маскировка под видео H264/SEI, ниже скорость"),
    "4": ("videochannel", "полноценные видео-кадры (QR), самый медленный, лучшая маскировка"),
}
ROOM_CREATE_URL = {
    "telemost": "https://telemost.yandex.ru/",
    "wbstream": "https://stream.wb.ru/",
}

# Transport payload defaults — пресеты по умолчанию.
# Пользователь может выбрать пресет в TUI — они отличаются fps/batch.
TRANSPORT_PAYLOAD_PRESETS = {
    "vp8channel": {
        "1": ("Стандарт",     {"vp8-fps": "30", "vp8-batch": "64"},   "30 fps, batch 64 - баланс"),
        "2": ("Быстрый",      {"vp8-fps": "60", "vp8-batch": "128"},  "60 fps, batch 128 - выше скорость, больше CPU"),
        "3": ("Максимум",     {"vp8-fps": "60", "vp8-batch": "256"},  "60 fps, batch 256 - макс. скорость, высокий CPU"),
        "4": ("Лёгкий",       {"vp8-fps": "15", "vp8-batch": "32"},   "15 fps, batch 32 - ниже скорость, меньше CPU"),
    },
}
# Дефолтный пресет (используется если пользователь не выбирал).
TRANSPORT_PAYLOADS = {
    "vp8channel": {"vp8-fps": "30", "vp8-batch": "64"},
}


# =============================================================================
#  СОСТОЯНИЕ
# =============================================================================
def _sync_state_from_config(st: dict) -> dict:
    """Синхронизирует state с реальным config.json manager'а.
    
    Проблема: state (olcrtc.json) и config.json могут рассинхронизироваться,
    если пользователь редактировал config.json вручную или через веб-панель
    manager'а. TUI должен показывать актуальное состояние.
    
    Что делает:
    1. Читает /etc/olcrtc-manager/config.json
    2. Извлекает locations из ВСЕХ clients[] (не только clients[0])
    3. Сравнивает с state.config.locations
    4. Если отличаются — обновляет state (и сохраняет)
    5. Также читает panel.env для актуальных кредов
    6. Сохраняет mgr_clients в state для последующего восстановления
       при _generate_config_json (чтобы не потерять clients, созданные
       через веб-панель)
    
    Returns:
      Обновлённый state dict.
    """
    if not MGR_CONFIG.exists():
        return st
    
    try:
        mgr_cfg = json.loads(MGR_CONFIG.read_text())
    except Exception:
        return st
    
    clients = mgr_cfg.get("clients", [])
    if not clients:
        return st
    
    # Читаем locations из ВСЕХ clients, не только clients[0].
    # Каждая location помечается своим client_id, чтобы потом
    # _generate_config_json мог распределить их обратно.
    mgr_locations = []
    mgr_clients_meta = []  # сохраняем метаданные clients для восстановления
    for client in clients:
        client_id = client.get("client-id", "wb")
        client_refresh = client.get("refresh", "5m")
        client_quota = client.get("quota", {}).get("used_bytes", 0)
        mgr_clients_meta.append({
            "client-id": client_id,
            "refresh": client_refresh,
            "quota_used_bytes": client_quota,
        })
        for loc in client.get("locations", []):
            transport_type = loc.get("transport", {}).get("type", "vp8channel")
            payload = loc.get("transport", {}).get("payload", {})
            room_id = loc.get("endpoint", {}).get("room_id", "")
            key = loc.get("endpoint", {}).get("key", "")
            carrier = loc.get("carrier", "")
            name = loc.get("name", "")
            olcbox_uri = _generate_olcbox_uri(carrier, transport_type, room_id, key, name)
            mgr_locations.append({
                "name": name,
                "client_id": client_id,  # важно: какому client принадлежит
                "carrier": carrier,
                "transport": transport_type,
                "room_id": room_id,
                "key": key,
                "payload": payload,
                "olcbox_uri": olcbox_uri,
            })
    
    cfg = st.get("config", {})
    old_locations = cfg.get("locations", [])
    
    # Сравниваем — если locations отличаются, обновляем state.
    def _loc_sig(locs):
        return sorted([(l.get("name", ""), l.get("room_id", ""),
                        l.get("carrier", ""), l.get("client_id", "wb")) for l in locs])
    
    if _loc_sig(old_locations) != _loc_sig(mgr_locations):
        _info("Синхронизирую state с config.json manager'а...")
        cfg["locations"] = mgr_locations
        # Сохраняем метаданные clients для _generate_config_json.
        cfg["mgr_clients"] = mgr_clients_meta
        # Читаем panel.env для кредов.
        admin_user, admin_pass = _read_panel_env()
        if admin_user:
            cfg["admin_user"] = admin_user
        if admin_pass:
            cfg["admin_pass"] = admin_pass
        # Panel URL.
        public_ip = cfg.get("public_ip", "")
        if not public_ip:
            public_ip = _get_public_ip()
            cfg["public_ip"] = public_ip
        cfg["panel_url"] = f"https://{public_ip or 'SERVER_IP'}:{MGR_PORT}/admin"
        st["config"] = cfg
        _save_state(st)
        _success(f"State синхронизирован ({len(mgr_locations)} location(s) в {len(clients)} client(s))")
    
    return st


def _read_panel_env() -> tuple:
    """Читает (admin_user, admin_pass) из panel.env. Возвращает ("", "") если файла нет."""
    if not MGR_PANEL_ENV.exists():
        return ("", "")
    try:
        user, pw = "", ""
        for line in MGR_PANEL_ENV.read_text().splitlines():
            if line.startswith("OLCRTC_MANAGER_USER="):
                user = line.split("=", 1)[1].strip().strip("'\"")
            elif line.startswith("OLCRTC_MANAGER_PASS="):
                pw = line.split("=", 1)[1].strip().strip("'\"")
        return (user, pw)
    except Exception:
        return ("", "")


def _load_state() -> dict:
    if OLC_STATE_FILE.exists():
        try:
            st = json.loads(OLC_STATE_FILE.read_text())
            st.setdefault("installed", False)
            st.setdefault("manager_installed", False)
            st.setdefault("commit", "")
            st.setdefault("manager_commit", "")
            st.setdefault("built_at", "")
            st.setdefault("config", {})
            # Миграция на multi-location формат.
            # Старый формат: st["config"] = {carrier, transport, room_id, key, ...}
            # Новый формат:  st["config"] = {panel_url, admin_user, admin_pass,
            #                                 locations: [{name, carrier, transport, room_id, key, payload}]}
            cfg = st.get("config", {})
            if "locations" not in cfg and cfg.get("room_id"):
                # Старый формат — мигрируем.
                old_loc = {
                    "name": cfg.get("location_name", "wb-vps"),
                    "carrier": cfg.get("carrier", ""),
                    "transport": cfg.get("transport", "vp8channel"),
                    "room_id": cfg.get("room_id", ""),
                    "key": cfg.get("key", ""),
                    "payload": cfg.get("payload", TRANSPORT_PAYLOADS.get(cfg.get("transport", "vp8channel"), {})),
                    "olcbox_uri": cfg.get("olcbox_uri", ""),
                }
                cfg["locations"] = [old_loc]
                st["config"] = cfg
            elif "locations" not in cfg:
                cfg["locations"] = []
                st["config"] = cfg
            # Гарантируем что locations — список.
            if not isinstance(st["config"].get("locations"), list):
                st["config"]["locations"] = []
            # Синхронизируем с config.json manager'а (если он есть).
            st = _sync_state_from_config(st)
            return st
        except Exception:
            pass
    return {"installed": False, "manager_installed": False, "commit": "",
            "manager_commit": "", "built_at": "", "config": {"locations": []}}


def _save_state(st: dict) -> None:
    OLC_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        OLC_STATE_FILE.write_text(json.dumps(st, ensure_ascii=False, indent=2))
    except Exception as e:
        _warn(f"Не удалось сохранить состояние модуля: {e}")


# =============================================================================
#  ПАРОЛЬНАЯ ЗАЩИТА СКРЫТОГО МЕНЮ (через access_control.py)
# =============================================================================
def unlock_and_open_menu() -> None:
    """Точка входа в скрытое меню olcRTC.

    Использует access_control.unlock_menu() с поддержкой:
      - Master-пароля (админ, не протухает)
      - OTP (одноразовый, протухает после использования, авто-ротация)
    """
    from chimera.modules.access_control import unlock_menu
    if unlock_menu(
        OLCRTC_HASH_FILE,
        "🔒  РЕЗЕРВНЫЙ РАЗДЕЛ — АВТОРИЗАЦИЯ",
        box_top_fn=_box_top,
        box_row_fn=_box_row,
        box_sep_fn=_box_sep,
        box_bottom_fn=_box_bottom,
        box_info_fn=lambda m: _box_row(f"  {DIM}{m}{NC}"),
        box_warn_fn=lambda m: _box_row(f"  {YELLOW}{m}{NC}"),
        cyan=CYAN, nc=NC, yellow=YELLOW, green=GREEN, dim=DIM,
    ):
        do_olcrtc_menu()


# =============================================================================
#  GO TOOLCHAIN (переиспользуется из старого кода)
# =============================================================================
def _go_arch() -> str:
    r = _run(["uname", "-m"], capture=True, check=False)
    m = r.stdout.strip() if r.returncode == 0 else ""
    return {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(m, "amd64")


def _ver_tuple(s: str) -> tuple:
    parts = re.findall(r"\d+", s)[:3]
    parts += ["0"] * (3 - len(parts))
    return tuple(int(p) for p in parts)


def _go_installed_version() -> tuple | None:
    gobin = shutil.which("go") or (str(OLC_GO_DIR / "bin" / "go") if (OLC_GO_DIR / "bin" / "go").exists() else None)
    if not gobin:
        return None
    r = _run([gobin, "version"], capture=True, check=False, timeout=10)
    if r.returncode != 0:
        return None
    m = re.search(r"go(\d+\.\d+(?:\.\d+)?)", r.stdout)
    return _ver_tuple(m.group(1)) if m else None


def _go_required_version() -> str:
    """Минимальная версия Go — 1.26 (из гайда, golang:1.26-bookworm)."""
    return "1.26.0"


def _go_ok(required: str = "1.26.0") -> bool:
    cur = _go_installed_version()
    return cur is not None and cur >= _ver_tuple(required)


def _http_get_text(url: str, timeout: int = 15) -> str | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace").strip()
    except Exception:
        return None


def _install_go(required: str = "1.26.0") -> bool:
    from chimera.modules.download_manager import fetch_package
    from chimera.modules.go_toolchain_packages import GO_TOOLCHAIN_SPEC

    arch = _go_arch()
    version = _http_get_text("https://go.dev/VERSION?m=text")
    if not version or not version.startswith("go"):
        version = f"go{required}"
    else:
        version = version.splitlines()[0].strip()

    _info(f"Скачиваю {version} ({arch}, через download_manager)...")
    ok = fetch_package(GO_TOOLCHAIN_SPEC, version=version, arch=arch,
                       print_hint_on_failure=False)
    if not ok:
        _warn(f"Не удалось скачать Go {version} ({arch})")
        return False
    return _go_ok(required)


def _find_go_binary() -> str | None:
    """Поиск go бинарника (PATH или /usr/local/go/bin/go)."""
    go = shutil.which("go")
    if go:
        return go
    candidates = [
        "/usr/local/go/bin/go",
        "/usr/lib/go/bin/go",
        "/snap/bin/go",
    ]
    for c in candidates:
        if Path(c).exists() and os.access(c, os.X_OK):
            return c
    return None


# =============================================================================
#  СБОРКА olcrtc и olcrtc-manager
# =============================================================================
def _olcrtc_installed() -> bool:
    return OLC_BIN.exists() and os.access(OLC_BIN, os.X_OK)


def _manager_installed() -> bool:
    return OLC_MGR_BIN.exists() and os.access(OLC_MGR_BIN, os.X_OK)


def _git_clone_or_pull(repo: str, dest: Path, branch: str = "master") -> bool:
    """Клонирует или обновляет репозиторий через git.

    ПУНКТ 2: Если прямой git clone не удался (GitHub недоступен из РФ),
    пробует через codeload.github.com (HTTP tarball) и известные
    GitHub-зеркала (согласовано с geo_mirrors.py).
    """
    if dest.exists() and (dest / ".git").exists():
        _info(f"Обновление {dest.name}...")
        r = _run(["git", "pull", "--ff-only", "origin", branch],
                 capture=True, check=False, timeout=60, cwd=str(dest))
        return r.returncode == 0

    _info(f"Клонирование {repo} → {dest}...")
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)

    # Попытка 1: прямой git clone.
    r = _run(["git", "clone", "--depth", "1", "--branch", branch,
              repo, str(dest)],
             capture=True, check=False, timeout=120)
    if r.returncode == 0:
        return True

    _warn(f"Прямой clone не удался, пробую зеркала...")

    # Попытка 2: codeload.github.com tarball (HTTP, не git).
    # URL: https://codeload.github.com/<owner>/<repo>/tar.gz/refs/heads/<branch>
    repo_parts = repo.replace("https://github.com/", "").replace(".git", "").split("/")
    if len(repo_parts) == 2:
        owner, repo_name = repo_parts
        tarball_url = f"https://codeload.github.com/{owner}/{repo_name}/tar.gz/refs/heads/{branch}"
        # Также пробуем через GitHub-прокси (согласовано с geo_mirrors.py).
        mirror_prefixes = [
            "",  # прямой codeload
            "https://gh-proxy.com/",
            "https://gh.llkk.cc/",
            "https://ghps.cc/",
        ]
        for prefix in mirror_prefixes:
            url = f"{prefix}{tarball_url}" if prefix else tarball_url
            _info(f"  Попытка: {url[:80]}...")
            tmp_tar = Path("/tmp") / f"olcrtc_{repo_name}_{branch}.tar.gz"
            r = _run(["curl", "-fsSL", "-o", str(tmp_tar), url],
                     capture=True, check=False, timeout=60)
            if r.returncode == 0 and tmp_tar.exists() and tmp_tar.stat().st_size > 1000:
                # Распаковка.
                tmp_extract = Path("/tmp") / f"olcrtc_extract_{repo_name}"
                shutil.rmtree(tmp_extract, ignore_errors=True)
                tmp_extract.mkdir(parents=True, exist_ok=True)
                r = _run(["tar", "-xzf", str(tmp_tar), "-C", str(tmp_extract),
                          "--strip-components=1"],
                         capture=True, check=False, timeout=30)
                tmp_tar.unlink(missing_ok=True)
                if r.returncode == 0:
                    # Копируем в dest и инициализируем .git (для _get_commit_sha).
                    shutil.copytree(tmp_extract, dest, dirs_exist_ok=True)
                    shutil.rmtree(tmp_extract, ignore_errors=True)
                    _run(["git", "init"], capture=True, check=False,
                         quiet=True, cwd=str(dest), timeout=10)
                    _run(["git", "add", "-A"], capture=True, check=False,
                         quiet=True, cwd=str(dest), timeout=10)
                    _run(["git", "commit", "-m", "mirror-import", "--allow-empty"],
                         capture=True, check=False, quiet=True, cwd=str(dest), timeout=10)
                    _info(f"  Зеркало сработало (через {prefix or 'codeload'})")
                    return True

    _error(f"Не удалось клонировать {repo} ни напрямую, ни через зеркала")
    return False


def _go_mod_download(src_dir: Path) -> bool:
    """Пытается скачать Go модули с фоллбэком через три прокси.

    ПУНКТ 1: На VPS в РФ proxy.golang.org может быть недоступен.
    Пробуем три GOPROXY по очереди (как в гайде):
      1. https://proxy.golang.org,direct
      2. https://goproxy.io,direct
      3. direct (без прокси, только VCS)
    """
    go = _find_go_binary()
    if not go:
        return False
    for proxy in ("https://proxy.golang.org,direct",
                  "https://goproxy.io,direct",
                  "direct"):
        _info(f"  go mod download (GOPROXY={proxy[:30]}...)...")
        env = {**os.environ, "GOPROXY": proxy}
        r = subprocess.run([go, "mod", "download"], cwd=str(src_dir),
                           env=env, capture_output=True, text=True,
                           timeout=180)
        if r.returncode == 0:
            return True
        _warn(f"  не удалось: {(r.stderr or '').strip()[:200]}")
    return False


def _go_build(src_dir: Path, output: Path, pkg_path: str = "./cmd/olcrtc") -> bool:
    """Собирает Go бинарник из src_dir, кладёт в output.

    ПУНКТ 1: Сначала вызывает _go_mod_download() с GOPROXY-фоллбэком,
    затем go build с системным GOPROXY (модули уже в кэше).
    """
    go = _find_go_binary()
    if not go:
        _error("Go не найден — установите Go сначала")
        return False

    # Сначала go mod download с фоллбэком через три прокси.
    if not _go_mod_download(src_dir):
        _error("Не удалось скачать Go модули ни через один прокси")
        return False

    env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": _go_arch()}
    _info(f"Сборка {output.name} (это может занять несколько минут)...")

    r = subprocess.run(
        [go, "build", "-trimpath", "-ldflags", "-s -w",
         "-o", str(output), pkg_path],
        cwd=str(src_dir),
        env=env,
        capture_output=True, text=True,
        timeout=900,  # 15 минут
    )
    if r.returncode != 0 or not output.exists():
        _error(f"Сборка не удалась: {(r.stderr or '').strip()[:500]}")
        return False
    output.chmod(0o755)
    return True


def _get_commit_sha(src_dir: Path) -> str:
    """Возвращает короткий SHA коммита."""
    r = _run(["git", "rev-parse", "--short", "HEAD"],
             capture=True, check=False, timeout=10, cwd=str(src_dir))
    return r.stdout.strip()[:7] if r.returncode == 0 else "?"


def _http_get_text(url: str, timeout: int = 15) -> str | None:
    """GET-запрос, возвращает текст ответа или None при любой ошибке.

    Лёгкий хелпер для GitHub API вызовов (без внешних зависимостей).
    User-Agent обязателен: api.github.com отклоняет запросы без UA (403).
    """
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def _olcrtc_fetch_commit_sha() -> str:
    """Короткий SHA HEAD ветки olcrtc через GitHub API.

    Зачем API вместо `git rev-parse` (миграция Wave 6, Variant A — см.
    olcrtc_packages.py / olcrtc_mirrors.py): при скачивании исходников
    через HTTP-tarball зеркала .git/ отсутствует, а эмуляция
    `git init + commit` записывала в state file SHA свежесозданного
    коммита вместо настоящего upstream SHA.

    Возвращает sha[:7]. При любой ошибке (сеть / не-JSON / нет поля
    sha) — "?": state сохраняется, установка не падает.
    """
    from chimera.modules.olcrtc_mirrors import get_olcrtc_commits_api_url
    text = _http_get_text(get_olcrtc_commits_api_url())
    if not text:
        return "?"
    try:
        data = json.loads(text)
        sha = data.get("sha")
        return sha[:7] if sha else "?"
    except Exception:
        return "?"


def _olcrtc_commit(src_dir: Path | None = None) -> str:
    """Commit SHA olcrtc для state file — канонический путь.

    Делегирует к _olcrtc_fetch_commit_sha() (GitHub API вместо
    `git rev-parse --short HEAD`). Если API недоступен ("?") и передан
    src_dir с локальным git-репозиторием — fallback на локальный SHA
    (осмыслен при прямом git clone: там rev-parse даёт настоящий
    upstream SHA).
    """
    sha = _olcrtc_fetch_commit_sha()
    if sha == "?" and src_dir is not None:
        return _get_commit_sha(src_dir)
    return sha


def _install_or_update() -> bool:
    """Полная установка/обновление: Go → olcrtc → olcrtc-manager.

    Шаги:
      0. Очистка старого bare olcrtc.service (ПУНКТ 3)
      0b. Проверка runtime-зависимостей (ПУНКТ 5)
      1. Проверка/установка Go 1.26+
      2. Клонирование openlibrecommunity/olcrtc (master)
      3. Сборка /usr/local/bin/olcrtc
      4. Клонирование BigDaddy3334/olcrtc-manager-panel (main)
      5. Сборка /usr/local/bin/olcrtc-manager
      6. Сохранение state
    """
    # 0. Очистка старого "голого" olcrtc.service от предыдущей версии
    # модуля (до переработки на manager-panel архитектуру) — иначе
    # он может конфликтовать с olcrtc-manager.service, который сам
    # супервайзит olcrtc как подпроцесс.
    _run(["systemctl", "disable", "--now", "olcrtc.service"],
         check=False, quiet=True, timeout=15)
    old_unit = Path("/etc/systemd/system/olcrtc.service")
    if old_unit.exists():
        old_unit.unlink()
        _run(["systemctl", "daemon-reload"], check=False, quiet=True, timeout=15)
        _info("Удалён старый olcrtc.service от предыдущей версии модуля")
    # Также чистим template unit если был.
    old_template = Path("/etc/systemd/system/olcrtc@.service")
    if old_template.exists():
        old_template.unlink()
        _run(["systemctl", "daemon-reload"], check=False, quiet=True, timeout=15)
        _info("Удалён старый olcrtc@.service template")

    # 0b. Проверка runtime-зависимостей (ПУНКТ 5).
    # Гайд требует: ca-certificates, curl, iproute2, iptables, openssl.
    # Bootstrap Химеры обеспечивает базовые пакеты, но olcrtc может
    # быть установлен на сервере где Chimera только что поставлена —
    # проверяем явно.
    _missing_deps = []
    for cmd, pkg in [("curl", "curl"), ("openssl", "openssl"),
                     ("ip", "iproute2"), ("tar", "tar"),
                     ("git", "git")]:
        if not shutil.which(cmd):
            _missing_deps.append(pkg)
    if _missing_deps:
        _info(f"Устанавливаю runtime-зависимости: {', '.join(_missing_deps)}")
        try:
            from chimera.modules.system_deps import _pkg_install
            _pkg_install(*_missing_deps)
        except Exception as e:
            _warn(f"Не удалось установить пакеты ({e}) — продолжаю, могут быть ошибки")

    # 1. Go toolchain
    required = _go_required_version()
    if not _go_ok(required):
        _info(f"Требуется Go {required}+, устанавливаю...")
        if not _install_go(required):
            _error("Не удалось установить Go")
            return False
    _success(f"Go OK ({_go_installed_version()})")

    # Временные директории для исходников.
    tmp_base = Path("/tmp/olcrtc-build")
    tmp_base.mkdir(parents=True, exist_ok=True)
    olcrtc_src = tmp_base / "olcrtc-src"
    mgr_src    = tmp_base / "panel-src"

    # 2-3. Клонирование и сборка olcrtc.
    if not _git_clone_or_pull(OLCRTC_REPO, olcrtc_src, OLCRTC_BRANCH):
        _error("Не удалось клонировать olcrtc")
        return False
    if not _go_build(olcrtc_src, OLC_BIN, "./cmd/olcrtc"):
        return False
    # SHA из GitHub API (миграция Wave 6): при tarball-зеркале .git/
    # эмулируется и rev-parse дал бы мусорный SHA; при недоступном API —
    # fallback на локальный git (прямой clone).
    olc_commit = _olcrtc_commit(olcrtc_src)
    _success(f"olcrtc собран (коммит {olc_commit})")

    # 4-5. Клонирование и сборка olcrtc-manager.
    if not _git_clone_or_pull(OLCRTC_MANAGER_REPO, mgr_src, OLCRTC_MANAGER_BRANCH):
        _error("Не удалось клонировать olcrtc-manager-panel")
        return False
    if not _go_build(mgr_src, OLC_MGR_BIN, "./cmd/olcrtc-manager"):
        return False
    mgr_commit = _get_commit_sha(mgr_src)
    _success(f"olcrtc-manager собран (коммит {mgr_commit})")

    # 6. Сохранение state.
    st = _load_state()
    st["installed"] = True
    st["manager_installed"] = True
    st["commit"] = olc_commit
    st["manager_commit"] = mgr_commit
    st["built_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _save_state(st)

    # Cleanup.
    shutil.rmtree(olcrtc_src, ignore_errors=True)
    shutil.rmtree(mgr_src, ignore_errors=True)

    return True


# =============================================================================
#  CONFIG.JSON ГЕНЕРАЦИЯ (точно по гайду)
# =============================================================================
def _resolver_for_olcrtc() -> str:
    """v57 (agh-aware): DNS-резолвер для locations olcrtc-manager.

    Порядок (как у генераторов Xray — см. agh_probe.py):
      1. AdGuardHome 127.0.0.1:53 — если сервис активен, владеет :53 и
         РЕАЛЬНО резолвит (живая проба end-to-end AGH → upstream → интернет);
      2. DNSCrypt-proxy 127.0.0.1:5300 — если AGH нет/болен, а dnscrypt жив;
      3. 8.8.8.8:53 — прежний дефолт (нет локального DNS-стека).

    Любой сбой проверки → автооткат на следующий уровень: olcrtc-manager
    никогда не остаётся с мёртвым резолвером.
    """
    # 1. AGH: глубокий health-check (сервис → владение :53 → проба резолва)
    try:
        from chimera.modules.agh_probe import agh_dns_available
        agh_ok, _note = agh_dns_available(run=_run, autostart=True)
        if agh_ok:
            return "127.0.0.1:53"
    except Exception:
        pass

    # 2. DNSCrypt на 5300 (порождён chimera; порт дефолтный)
    r = _run(["systemctl", "is-active", "dnscrypt-proxy"],
             capture=True, check=False)
    if (getattr(r, "stdout", "") or "").strip() == "active":
        return "127.0.0.1:5300"

    # 3. Прежний дефолт
    return "8.8.8.8:53"


def _generate_config_json(locations: list, quota_used_bytes: int = 0,
                          mgr_clients_meta: list = None) -> str:
    """Генерирует config.json для olcrtc-manager с поддержкой нескольких locations
    и нескольких clients.

    Args:
      locations: список словарей вида:
        {
          "name": "wb-stream",
          "client_id": "wb",  # опционально, по умолчанию "wb"
          "carrier": "wbstream",
          "transport": "vp8channel",
          "room_id": "<ROOM_ID>",
          "key": "<KEY>",
          "payload": {"vp8-fps": "30", "vp8-batch": "64"}
        }
      quota_used_bytes: счётчик трафика для client "wb" (для совместимости).
      mgr_clients_meta: список метаданных clients из предыдущего config.json
        (сохраняется _sync_state_from_config). Если передан — используем его
        для восстановления структуры clients, чтобы не потерять clients,
        созданные через веб-панель. Формат:
        [{"client-id": "wb", "refresh": "5m", "quota_used_bytes": 0}, ...]

    Format (точно по гайду olcrtc-manager):
    {
      "version": 1,
      "name": "Chimera olcRTC",
      "port": 8888,
      "subscription_path": "sub",
      "refresh": "10m",
      "clients": [
        {
          "client-id": "<client_id>",
          "refresh": "5m",
          "quota": {"used_bytes": 0},
          "locations": [...]
        },
        ...
      ]
    }
    """
    # Группируем locations по client_id.
    # Если у location нет client_id — используем "wb".
    locations_by_client = {}
    for loc in locations:
        cid = loc.get("client_id", "wb")
        locations_by_client.setdefault(cid, []).append(loc)

    # Определяем список clients для записи.
    # Если есть mgr_clients_meta — используем его (сохраняем clients из панели).
    # Иначе — один client "wb".
    if mgr_clients_meta:
        clients_meta = mgr_clients_meta
    else:
        clients_meta = [{
            "client-id": "wb",
            "refresh": "5m",
            "quota_used_bytes": quota_used_bytes,
        }]

    # Гарантируем что client "wb" есть (если в locations есть loc без client_id).
    existing_cids = [c["client-id"] for c in clients_meta]
    for cid in locations_by_client:
        if cid not in existing_cids:
            clients_meta.append({
                "client-id": cid,
                "refresh": "5m",
                "quota_used_bytes": 0,
            })

    # v57 (agh-aware): резолвер locations — через живой AGH (:53), при сбое
    # проверки → dnscrypt:5300, без локального стека → 8.8.8.8 (прежний дефолт)
    resolver = _resolver_for_olcrtc()

    clients_json = []
    for meta in clients_meta:
        cid = meta["client-id"]
        locs = locations_by_client.get(cid, [])
        locs_json = []
        for loc in locs:
            transport = loc.get("transport", "vp8channel")
            payload = loc.get("payload") or TRANSPORT_PAYLOADS.get(transport, {})
            locs_json.append({
                "name": loc["name"],
                "client-id": cid,
                "endpoint": {
                    "room_id": loc["room_id"],
                    "key": loc["key"],
                },
                "carrier": loc["carrier"],
                "transport": {
                    "type": transport,
                    "payload": payload,
                },
                "link": "direct",
                "data": str(MGR_DATA_DIR),
                "dns": resolver,
                "proxy": {},
            })
        clients_json.append({
            "client-id": cid,
            "refresh": meta.get("refresh", "5m"),
            "quota": {"used_bytes": meta.get("quota_used_bytes", 0) if cid != "wb" else quota_used_bytes},
            "locations": locs_json,
        })

    config = {
        "version": 1,
        "name": "Chimera olcRTC",
        "port": MGR_PORT,
        "subscription_path": "sub",
        "refresh": "10m",
        "clients": clients_json,
    }
    return json.dumps(config, indent=2, ensure_ascii=False)


def _generate_panel_env(admin_user: str, admin_pass: str) -> str:
    """Генерирует panel.env для basic auth."""
    return (
        f"OLCRTC_MANAGER_USER='{admin_user}'\n"
        f"OLCRTC_MANAGER_PASS='{admin_pass}'\n"
        f"OLCRTC_MANAGER_ADMIN_PATH='/admin'\n"
        f"OLCRTC_MANAGER_TLS_CERT='{MGR_TLS_CRT}'\n"
        f"OLCRTC_MANAGER_TLS_KEY='{MGR_TLS_KEY}'\n"
    )


def _generate_systemd_unit() -> str:
    """Генерирует systemd unit для olcrtc-manager (точно по гайду)."""
    return (
        "[Unit]\n"
        "Description=OlcRTC Manager Panel\n"
        f"Documentation={OLCRTC_MANAGER_REPO}\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"Environment=OLCRTC_PATH={OLC_BIN}\n"
        f"EnvironmentFile=-{MGR_PANEL_ENV}\n"
        f"ExecStart={OLC_MGR_BIN} -addr 0.0.0.0 -config {MGR_CONFIG}\n"
        "ExecReload=/bin/kill -HUP $MAINPID\n"
        "Restart=on-failure\n"
        "RestartSec=5s\n"
        "KillSignal=SIGTERM\n"
        "TimeoutStopSec=10s\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def _generate_tls_cert(public_ip: str) -> bool:
    """Генерирует self-signed TLS сертификат (точно по гайду)."""
    _info("Генерация self-signed TLS сертификата...")
    r = _run([
        "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
        "-sha256", "-days", "825",
        "-keyout", str(MGR_TLS_KEY),
        "-out", str(MGR_TLS_CRT),
        "-subj", "/CN=olcrtc-manager",
        "-addext", f"subjectAltName=IP:{public_ip},DNS:localhost",
    ], capture=True, check=False, timeout=30)
    if r.returncode != 0:
        _error(f"openssl failed: {(r.stderr or '').strip()[:300]}")
        return False
    try:
        MGR_TLS_KEY.chmod(0o600)
        MGR_TLS_CRT.chmod(0o644)
    except Exception:
        pass
    return True


def _generate_olcbox_uri(carrier: str, transport: str, room_id: str,
                          key: str, location_name: str) -> str:
    """Генерирует OlcBox URI (точно по гайду).

    Формат: olcrtc://<carrier>?<transport><payload>@<room_id>#<key>$<location>
    Пример: olcrtc://wbstream?vp8channel<vp8-batch=64&vp8-fps=30>@ROOM_ID#KEY$wb-vps
    """
    payload = TRANSPORT_PAYLOADS.get(transport, {})
    payload_str = "&".join(f"{k}={v}" for k, v in payload.items())
    if payload_str:
        payload_str = f"<{payload_str}>"
    return f"olcrtc://{carrier}?{transport}{payload_str}@{room_id}#{key}${location_name}"


# =============================================================================
#  SERVER IP
# =============================================================================
def _get_public_ip() -> str:
    """Определяет публичный IP сервера.

    ПУНКТ 4: Переиспользует _get_public_ip() из mtproto.py, который
    правильно обрабатывает NAT (сравнение локального IP с внешним
    echo-сервисом, а не просто is_private-эвристика). Это тот же
    класс бага, что был исправлен в mtproto.py — некоторые хостеры
    (cloud.ru, Azure) используют NAT с адресами, которые выглядят
    как публичные, но публичными не являются.
    """
    try:
        from chimera.modules.mtproto import _get_public_ip as _mtproto_get_public_ip
        ipv4, _ipv6 = _mtproto_get_public_ip()
        return ipv4
    except Exception:
        pass
    # Fallback: простой curl ifconfig.me (если mtproto недоступен).
    r = _run(["curl", "-s", "--max-time", "5", "ifconfig.me"],
             capture=True, check=False, timeout=10)
    ip = r.stdout.strip() if r.returncode == 0 else ""
    if ip and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return ip
    return ""


# =============================================================================
#  УСТАНОВКА / НАСТРОЙКА / УДАЛЕНИЕ MANAGER PANEL
# =============================================================================
def _read_existing_quota() -> int:
    """Читает текущий quota.used_bytes из существующего config.json.
    
    Нужно чтобы при добавлении/удалении location не сбрасывать счётчик трафика.
    """
    if not MGR_CONFIG.exists():
        return 0
    try:
        cfg = json.loads(MGR_CONFIG.read_text())
        clients = cfg.get("clients", [])
        if clients:
            return int(clients[0].get("quota", {}).get("used_bytes", 0))
    except Exception:
        pass
    return 0


def _apply_config(locations: list) -> bool:
    """Применяет список locations к config.json и перезапускает manager.
    
    НЕ трогает panel.env (пароль остаётся прежним).
    НЕ трогает TLS сертификат.
    НЕ трогает systemd unit.
    
    Сохраняет существующие clients (созданные через веб-панель) благодаря
    передаче mgr_clients_meta из state в _generate_config_json.
    
    Args:
      locations: список словарей [{name, carrier, transport, room_id, key, payload, client_id?}, ...]
    
    Returns:
      True если сервис успешно перезапущен, False при ошибке.
    """
    if not locations:
        _warn("Список locations пуст — config.json не записан")
        return False
    
    # 1. Директории.
    MGR_ETC_DIR.mkdir(parents=True, exist_ok=True)
    MGR_DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    # 2. Сохранить quota из существующего config.
    quota = _read_existing_quota()
    
    # 3. Получить mgr_clients_meta из state (если есть — сохранит clients из панели).
    st = _load_state()
    mgr_clients_meta = st.get("config", {}).get("mgr_clients")
    
    # 4. Записать новый config.json.
    config_text = _generate_config_json(
        locations,
        quota_used_bytes=quota,
        mgr_clients_meta=mgr_clients_meta,
    )
    MGR_CONFIG.write_text(config_text)
    MGR_CONFIG.chmod(0o600)
    
    # 5. Перезапустить сервис.
    _run(["systemctl", "restart", "olcrtc-manager"],
          check=False, quiet=True, timeout=30)
    time.sleep(4)
    
    active = _manager_service_active()
    if not active:
        _warn("olcrtc-manager не поднялся — проверьте: journalctl -u olcrtc-manager -n 30")
    
    return active


def _ensure_panel_initialized(public_ip: str) -> tuple[str, str]:
    """Гарантирует что panel.env, TLS и systemd unit существуют.
    
    Если уже есть — не трогает (пароль не меняется!).
    Если нет — создаёт с новыми кредами.
    
    Returns:
      (admin_user, admin_pass) — текущие креды панели.
    """
    # 1. Директории.
    MGR_ETC_DIR.mkdir(parents=True, exist_ok=True)
    MGR_DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    # 2. panel.env — только если не существует.
    if MGR_PANEL_ENV.exists():
        # Читаем существующие креды.
        admin_user = "admin"
        admin_pass = ""
        try:
            for line in MGR_PANEL_ENV.read_text().splitlines():
                if line.startswith("OLCRTC_MANAGER_USER="):
                    admin_user = line.split("=", 1)[1].strip().strip("'\"")
                elif line.startswith("OLCRTC_MANAGER_PASS="):
                    admin_pass = line.split("=", 1)[1].strip().strip("'\"")
        except Exception:
            pass
        return admin_user, admin_pass
    
    # Создаём новый panel.env.
    admin_user = "admin"
    admin_pass = secrets.token_hex(16)
    env_text = _generate_panel_env(admin_user, admin_pass)
    MGR_PANEL_ENV.write_text(env_text)
    MGR_PANEL_ENV.chmod(0o600)
    _info(f"Создан новый panel.env (admin/{admin_pass})")
    return admin_user, admin_pass


def _ensure_tls_and_unit(public_ip: str) -> None:
    """Гарантирует что TLS сертификат и systemd unit существуют."""
    # TLS — только если не существует.
    if not (MGR_TLS_CRT.exists() and MGR_TLS_KEY.exists()):
        if not _generate_tls_cert(public_ip):
            _warn("TLS не сгенерирован — панель будет без HTTPS")
    
    # systemd unit — только если не существует.
    if not MGR_UNIT_FILE.exists():
        unit_text = _generate_systemd_unit()
        MGR_UNIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        MGR_UNIT_FILE.write_text(unit_text)
        _run(["systemctl", "daemon-reload"], check=False, quiet=True, timeout=15)
    
    # UFW — открыть порт (идемпотентно).
    try:
        from chimera.modules.port_registry import (
            ufw_open_port, port_register,
        )
        port_register(_OLCRTC_MANAGER_SERVICE_TAG, MGR_PORT, "tcp",
                      comment="olcrtc-manager panel (TLS)", force=True)
        ufw_open_port(MGR_PORT, "tcp", _OLCRTC_MANAGER_SERVICE_TAG,
                      comment="olcrtc-manager panel (TLS)")
    except Exception as e:
        _warn(f"UFW: не удалось открыть порт {MGR_PORT}: {e}")
    
    # Enable + start.
    _run(["systemctl", "enable", "--now", "olcrtc-manager"],
          check=False, quiet=True, timeout=20)


# ══════════════════════════════════════════════════════════════════════════════
#  LET'S ENCRYPT TLS SUPPORT (domain access)
# ══════════════════════════════════════════════════════════════════════════════
# olcrtc-manager берёт TLS cert/key из env-переменных OLCRTC_MANAGER_TLS_CERT
# и OLCRTC_MANAGER_TLS_KEY (см. _generate_panel_env). Это значит — можно
# подсунуть Let's Encrypt сертификат просто сменив пути в panel.env.
# 
# Раньше поддерживался только self-signed (по IP). Теперь добавлена опция
# Let's Encrypt — для доступа по домену с доверенным сертификатом.
# 
# Архитектура:
#   1. obtain_ssl_cert(domain) → /etc/letsencrypt/live/<domain>/{fullchain,privkey}.pem
#   2. chgrp olcrtc-manager /etc/letsencrypt/live/<domain>/* — чтобы бинарник мог читать
#   3. panel.env: OLCRTC_MANAGER_TLS_CERT='/etc/letsencrypt/live/<domain>/fullchain.pem'
#                 OLCRTC_MANAGER_TLS_KEY='/etc/letsencrypt/live/<domain>/privkey.pem'
#   4. systemctl restart olcrtc-manager


def _find_le_cert(domain: str) -> tuple[Path, Path] | None:
    """Ищет Let's Encrypt сертификат для домена.
    
    Returns:
      (cert_path, key_path) или None если не найден.
    """
    cert = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
    key  = Path(f"/etc/letsencrypt/live/{domain}/privkey.pem")
    if cert.exists() and key.exists():
        return (cert, key)
    return None


def _grant_cert_read_access(cert_path: Path, group: str = "olcrtc-manager") -> bool:
    """Даёт группе olcrtc-manager право читать сертификат Let's Encrypt.
    
    По умолчанию /etc/letsencrypt/live/ доступен только root. olcrtc-manager
    бинарник запускается от пользователя olcrtc-manager (если есть) или root.
    
    Returns:
      True если права настроены или не нужны (запуск от root).
    """
    # Если пользователь olcrtc-manager не существует — менеджер запускается
    # от root (через systemd unit), права не нужны.
    r = _run(["getent", "passwd", group], capture=True, check=False, quiet=True)
    if r.returncode != 0:
        return True  # запуск от root, ок
    
    # chgrp -R olcrtc-manager /etc/letsencrypt/live/<domain>/
    domain_dir = cert_path.parent
    parent_dir = domain_dir.parent
    
    # Даём группе olcrtc-manager traverse право на /etc/letsencrypt/live/
    _run(["chmod", "o+x", str(parent_dir)], check=False, quiet=True)
    # chgrp на директорию домена + рекурсивно на файлы
    _run(["chgrp", "-R", group, str(domain_dir)], check=False, quiet=True)
    _run(["chmod", "-R", "g+rX", str(domain_dir)], check=False, quiet=True)
    
    return True


def _apply_letsencrypt_tls(domain: str) -> bool:
    """Переключает olcrtc-manager на Let's Encrypt сертификат для домена.
    
    1. Получает сертификат через obtain_ssl_cert(domain) если его нет.
    2. Даёт группе olcrtc-manager право читать сертификат.
    3. Обновляет panel.env: OLCRTC_MANAGER_TLS_CERT/KEY → пути к LE сертификату.
    4. Перезапускает olcrtc-manager.
    
    Returns:
      True при успехе.
    """
    if not MGR_PANEL_ENV.exists():
        _error("panel.env не найден — сначала установите olcrtc-manager.")
        return False
    
    # 1. Получаем сертификат.
    cert_key = _find_le_cert(domain)
    if cert_key is None:
        _info(f"SSL-сертификат для {domain} не найден, получаем через certbot...")
        try:
            from chimera.modules.ssl_certbot import obtain_ssl_cert
            obtain_ssl_cert(domain)
        except Exception as e:
            _error(f"Не удалось получить SSL-сертификат: {e}")
            return False
        cert_key = _find_le_cert(domain)
        if cert_key is None:
            _error(f"SSL-сертификат для {domain} так и не получен")
            return False
    
    cert_path, key_path = cert_key
    _info(f"Используем Let's Encrypt сертификат: {cert_path}")
    
    # 2. Даём olcrtc-manager права читать.
    _grant_cert_read_access(cert_path)
    
    # 3. Обновляем panel.env — заменяем TLS_CERT и TLS_KEY пути.
    env_text = MGR_PANEL_ENV.read_text()
    new_lines = []
    for line in env_text.splitlines():
        if line.startswith("OLCRTC_MANAGER_TLS_CERT="):
            new_lines.append(f"OLCRTC_MANAGER_TLS_CERT='{cert_path}'")
        elif line.startswith("OLCRTC_MANAGER_TLS_KEY="):
            new_lines.append(f"OLCRTC_MANAGER_TLS_KEY='{key_path}'")
        else:
            new_lines.append(line)
    MGR_PANEL_ENV.write_text("\n".join(new_lines) + "\n")
    MGR_PANEL_ENV.chmod(0o600)
    _info("panel.env обновлён — пути к Let's Encrypt сертификату прописаны")
    
    # 4. Перезапуск.
    _run(["systemctl", "restart", "olcrtc-manager"],
         check=False, quiet=True, timeout=20)
    _success(f"olcrtc-manager переключён на Let's Encrypt сертификат для домена {domain}")
    return True


def _apply_self_signed_tls(public_ip: str) -> bool:
    """Переключает olcrtc-manager обратно на self-signed сертификат.
    
    1. Генерирует новый self-signed сертификат (если его нет).
    2. Обновляет panel.env: TLS_CERT/KEY → пути к self-signed.
    3. Перезапускает olcrtc-manager.
    
    Returns:
      True при успехе.
    """
    if not MGR_PANEL_ENV.exists():
        _error("panel.env не найден — сначала установите olcrtc-manager.")
        return False
    
    # 1. Генерируем self-signed если его нет.
    if not (MGR_TLS_CRT.exists() and MGR_TLS_KEY.exists()):
        if not _generate_tls_cert(public_ip):
            _error("Не удалось сгенерировать self-signed TLS")
            return False
    
    # 2. Обновляем panel.env.
    env_text = MGR_PANEL_ENV.read_text()
    new_lines = []
    for line in env_text.splitlines():
        if line.startswith("OLCRTC_MANAGER_TLS_CERT="):
            new_lines.append(f"OLCRTC_MANAGER_TLS_CERT='{MGR_TLS_CRT}'")
        elif line.startswith("OLCRTC_MANAGER_TLS_KEY="):
            new_lines.append(f"OLCRTC_MANAGER_TLS_KEY='{MGR_TLS_KEY}'")
        else:
            new_lines.append(line)
    MGR_PANEL_ENV.write_text("\n".join(new_lines) + "\n")
    MGR_PANEL_ENV.chmod(0o600)
    _info("panel.env обновлён — пути к self-signed сертификату прописаны")
    
    # 3. Перезапуск.
    _run(["systemctl", "restart", "olcrtc-manager"],
         check=False, quiet=True, timeout=20)
    _success("olcrtc-manager переключён на self-signed сертификат (доступ по IP)")
    return True


def _tls_mode_status() -> dict:
    """Возвращает текущий режим TLS для olcrtc-manager.
    
    Returns:
      dict с ключами:
        mode: 'letsencrypt' | 'self_signed' | 'unknown'
        domain: str | None (для letsencrypt)
        cert_path: str
        key_path: str
    """
    if not MGR_PANEL_ENV.exists():
        return {"mode": "unknown"}
    
    cert_path = ""
    key_path  = ""
    for line in MGR_PANEL_ENV.read_text().splitlines():
        if line.startswith("OLCRTC_MANAGER_TLS_CERT="):
            cert_path = line.split("=", 1)[1].strip().strip("'\"")
        elif line.startswith("OLCRTC_MANAGER_TLS_KEY="):
            key_path = line.split("=", 1)[1].strip().strip("'\"")
    
    if "/etc/letsencrypt/live/" in cert_path:
        # Let's Encrypt режим — извлекаем домен.
        parts = cert_path.split("/")
        if len(parts) >= 5 and parts[3] == "live":
            domain = parts[4]
            return {"mode": "letsencrypt", "domain": domain,
                    "cert_path": cert_path, "key_path": key_path}
        return {"mode": "letsencrypt", "domain": None,
                "cert_path": cert_path, "key_path": key_path}
    
    if cert_path == str(MGR_TLS_CRT) and key_path == str(MGR_TLS_KEY):
        return {"mode": "self_signed", "domain": None,
                "cert_path": cert_path, "key_path": key_path}
    
    return {"mode": "unknown", "cert_path": cert_path, "key_path": key_path}


def _toggle_tls_mode() -> None:
    """Меню переключения режима TLS для olcrtc-manager.
    
    Показывает текущий режим и позволяет переключиться:
      - Let's Encrypt (домен) — доверенный сертификат
      - Self-signed (IP) — браузер предупредит
    """
    if not _manager_installed():
        _warn("olcrtc-manager не установлен.")
        return
    
    status = _tls_mode_status()
    mode = status.get("mode", "unknown")
    domain = status.get("domain")
    
    if mode == "letsencrypt":
        mode_label = "Let's Encrypt"
    elif mode == "self_signed":
        mode_label = "Self-signed"
    else:
        mode_label = "неизвестно"
    
    if domain:
        _info(f"Текущий режим TLS: {mode_label} ({domain})")
    else:
        _info(f"Текущий режим TLS: {mode_label}")
    
    print()
    print(f"  {CYAN}1{NC}. Let's Encrypt (домен) — доверенный сертификат")
    print(f"  {CYAN}2{NC}. Self-signed (по IP) — браузер предупредит")
    try:
        ch = input(f"{CYAN}Выбор [Enter=отмена]: {NC}").strip()
    except (EOFError, KeyboardInterrupt):
        return
    
    if ch == "1":
        # Спрашиваем домен.
        try:
            from chimera._core import PARAM_DOMAIN
        except Exception:
            PARAM_DOMAIN = ""
        default_domain = PARAM_DOMAIN or ""
        prompt = f"{CYAN}Домен"
        if default_domain:
            prompt += f" (Enter={default_domain})"
        prompt += f": {NC}"
        try:
            domain = input(prompt).strip() or default_domain
        except (EOFError, KeyboardInterrupt):
            return
        if not domain:
            _warn("Домен не указан — отмена.")
            return
        _apply_letsencrypt_tls(domain)
    elif ch == "2":
        public_ip = _get_public_ip() or "127.0.0.1"
        _apply_self_signed_tls(public_ip)
    # else: отмена


def _configure_manager(locations: list) -> bool:
    """Настраивает manager panel со списком locations.
    
    НЕ перегенерирует panel.env если уже существует (пароль не меняется!).
    НЕ перегенерирует TLS если уже существует.
    
    Args:
      locations: список [{name, carrier, transport, room_id, key, payload}, ...]
    
    Returns:
      True при успехе.
    """
    st = _load_state()
    
    # Публичный IP.
    public_ip = _get_public_ip()
    if not public_ip:
        _warn("Не удалось определить публичный IP — TLS будет без IP SAN")
        public_ip = "127.0.0.1"
    
    # 1. Гарантировать panel.env, TLS, systemd, UFW (без перегенерации если уже есть).
    admin_user, admin_pass = _ensure_panel_initialized(public_ip)
    _ensure_tls_and_unit(public_ip)
    
    # 2. Применить config.json + перезапуск.
    active = _apply_config(locations)
    
    # 3. Сохранение state.
    # Генерируем OlcBox URI для каждого location.
    for loc in locations:
        loc["olcbox_uri"] = _generate_olcbox_uri(
            loc["carrier"], loc["transport"], loc["room_id"],
            loc["key"], loc["name"]
        )
    
    st["config"] = {
        "panel_url": f"https://{public_ip}:{MGR_PORT}/admin",
        "admin_user": admin_user,
        "admin_pass": admin_pass,
        "public_ip": public_ip,
        "locations": locations,
    }
    _save_state(st)
    
    return active


def _uninstall_manager() -> bool:
    """Полное удаление manager panel: сервис, бинарники, конфиги, UFW."""
    _info("Удаление olcrtc-manager...")

    # 1. Остановить сервис.
    _run(["systemctl", "stop", "olcrtc-manager"], check=False, quiet=True, timeout=20)
    _run(["systemctl", "disable", "olcrtc-manager"], check=False, quiet=True, timeout=20)

    # 2. Удалить systemd unit.
    MGR_UNIT_FILE.unlink(missing_ok=True)
    _run(["systemctl", "daemon-reload"], check=False, quiet=True, timeout=15)

    # 3. UFW — закрыть порт через port_registry.
    try:
        from chimera.modules.port_registry import (
            ufw_close_port, port_unregister,
        )
        ufw_close_port(MGR_PORT, "tcp", _OLCRTC_MANAGER_SERVICE_TAG,
                       legacy_comments=["olcrtc-manager panel (TLS)"])
        port_unregister(_OLCRTC_MANAGER_SERVICE_TAG, MGR_PORT, "tcp")
    except Exception:
        pass

    # 4. Удалить конфиги.
    shutil.rmtree(MGR_ETC_DIR, ignore_errors=True)
    shutil.rmtree(MGR_DATA_DIR.parent, ignore_errors=True)

    # 5. Удалить бинарники.
    OLC_BIN.unlink(missing_ok=True)
    OLC_MGR_BIN.unlink(missing_ok=True)

    # 6. Сброс state.
    st = _load_state()
    st["installed"] = False
    st["manager_installed"] = False
    st["config"] = {}
    _save_state(st)

    _success("olcrtc-manager полностью удалён")
    return True


# =============================================================================
#  СТАТУС / API ПРОВЕРКИ
# =============================================================================
def _manager_service_active() -> bool:
    r = _run(["systemctl", "is-active", "olcrtc-manager"],
             capture=True, check=False, timeout=10)
    return r.stdout.strip() == "active"


def _api_state() -> dict | None:
    """Запрашивает /api/state через curl (с basic auth из panel.env)."""
    if not MGR_PANEL_ENV.exists():
        return None
    # Читаем креды из panel.env.
    env_text = MGR_PANEL_ENV.read_text()
    user = ""
    passwd = ""
    for line in env_text.splitlines():
        if line.startswith("OLCRTC_MANAGER_USER="):
            user = line.split("=", 1)[1].strip().strip("'\"")
        elif line.startswith("OLCRTC_MANAGER_PASS="):
            passwd = line.split("=", 1)[1].strip().strip("'\"")
    if not user or not passwd:
        return None

    r = _run([
        "curl", "-sk", "--max-time", "10",
        "-u", f"{user}:{passwd}",
        f"https://127.0.0.1:{MGR_PORT}/api/state",
    ], capture=True, check=False, timeout=15)
    if r.returncode != 0 or not r.stdout:
        return None
    try:
        return json.loads(r.stdout)
    except Exception:
        return None


def _api_logs(room_id: str) -> str:
    """Запрашивает /api/logs через curl."""
    if not MGR_PANEL_ENV.exists():
        return ""
    env_text = MGR_PANEL_ENV.read_text()
    user = ""
    passwd = ""
    for line in env_text.splitlines():
        if line.startswith("OLCRTC_MANAGER_USER="):
            user = line.split("=", 1)[1].strip().strip("'\"")
        elif line.startswith("OLCRTC_MANAGER_PASS="):
            passwd = line.split("=", 1)[1].strip().strip("'\"")
    if not user or not passwd:
        return ""

    # transport из state.
    st = _load_state()
    transport = st.get("config", {}).get("transport", "vp8channel")

    r = _run([
        "curl", "-sk", "--max-time", "10",
        "-u", f"{user}:{passwd}",
        f"https://127.0.0.1:{MGR_PORT}/api/logs/?client_id=wb&room_id={room_id}&transport={transport}",
    ], capture=True, check=False, timeout=15)
    return r.stdout if r.returncode == 0 else ""


# =============================================================================
#  TUI: КОНФИГУРАЦИЯ
# =============================================================================
def _ask_carrier() -> str | None:
    """Спрашивает carrier (провайдера). Возвращает строку ('wbstream'/'jitsi'/'telemost') или None."""
    print()
    _box_top("Выберите провайдера")
    _box_row()
    for k, (_, title, hint) in CARRIERS.items():
        _box_item(k, f"{title}  {DIM}— {hint}{NC}")
    _box_bottom()
    try:
        c_choice = input(f"{CYAN}  Провайдер [1]:{NC} ").strip() or "1"
    except (EOFError, KeyboardInterrupt):
        return None
    if c_choice not in CARRIERS:
        _warn("Неверный выбор")
        return None
    return CARRIERS[c_choice][0]


def _ask_transport(carrier: str) -> str | None:
    """Спрашивает transport для выбранного carrier. Возвращает строку или None."""
    carrier_title = next((t for k, (c, t, _) in CARRIERS.items() if c == carrier), carrier)
    # Не все комбинации carrier+transport поддерживаются olcrtc-manager.
    # WB Stream поддерживает ТОЛЬКО vp8channel.
    SUPPORTED_TRANSPORTS = {
        "wbstream": {"2"},  # только vp8channel
        "jitsi":    {"1", "2", "3", "4"},  # все
        "telemost": {"1", "2", "3", "4"},  # все
    }
    allowed = SUPPORTED_TRANSPORTS.get(carrier, {"2"})
    default_t = "2" if "2" in allowed else sorted(allowed)[0]

    print()
    _box_top("Транспорт (маскировка)")
    for k, (_, hint) in TRANSPORTS.items():
        if k in allowed:
            marker = f" {GREEN}(по умолчанию){NC}" if k == default_t else ""
            _box_item(k, f"{hint}{marker}")
        else:
            _box_row(f"  {DIM}[{k}] {hint} — не поддерживается для {carrier_title}{NC}")
    _box_bottom()

    try:
        t_choice = input(f"{CYAN}  Транспорт [{default_t}]:{NC} ").strip() or default_t
    except (EOFError, KeyboardInterrupt):
        return None
    if t_choice not in allowed:
        _warn(f"Транспорт {t_choice} не поддерживается для {carrier_title}")
        return None
    return TRANSPORTS[t_choice][0]


def _ask_room_id(carrier: str) -> str | None:
    """Спрашивает room_id для выбранного carrier. Возвращает строку или None."""
    carrier_title = next((t for k, (c, t, _) in CARRIERS.items() if c == carrier), carrier)
    print()
    if carrier == "jitsi":
        _box_top("Jitsi — комната")
        _box_row(f"  {DIM}Для Jitsi комната генерируется автоматически.{NC}")
        _box_row(f"  {DIM}Просто нажмите Enter.{NC}")
        _box_bottom()
        room_id = f"https://meet.jitsi.ru/{secrets.token_hex(8)}"
        _info(f"Сгенерирована комната: {room_id}")
        return room_id
    else:
        _box_top(f"Комната {carrier_title}")
        _box_row(f"  {YELLOW}Комнату нужно создать вручную:{NC}")
        _box_row(f"  {CYAN}{ROOM_CREATE_URL[carrier]}{NC}")
        _box_row(f"  {DIM}Откройте ссылку в браузере, начните звонок{NC}")
        _box_row(f"  {DIM}и скопируйте ID комнаты из URL.{NC}")
        _box_sep()
        _box_row(f"  {DIM}Для WB Stream: https://stream.wb.ru/room/<ROOM_ID>{NC}")
        _box_row(f"  {DIM}ROOM_ID — последняя часть URL после /room/{NC}")
        _box_bottom()
        try:
            room_id = input(f"{CYAN}  Вставьте ROOM_ID:{NC} ").strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if not room_id:
            _warn("ROOM_ID не указан")
            return None
        return room_id


def _ask_location_name(existing_names: list) -> str | None:
    """Спрашивает имя для новой location. Возвращает строку или None.
    
    Имя должно быть уникальным (не в existing_names).
    Дефолтное имя генерируется на основе carrier.
    """
    print()
    _box_top("Имя location")
    _box_row(f"  {DIM}Имя используется в OlcBox URI ($name в конце).{NC}")
    _box_row(f"  {DIM}Должно быть уникальным. Допустимы латиница, цифры, дефис.{NC}")
    _box_bottom()
    try:
        name = input(f"{CYAN}  Имя location:{NC} ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    if not name:
        _warn("Имя не указано")
        return None
    if name in existing_names:
        _warn(f"Имя '{name}' уже существует — выберите другое")
        return None
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        _warn("Имя содержит недопустимые символы (только латиница, цифры, дефис, подчёркивание)")
        return None
    return name


def _collect_location(existing_names: list) -> dict | None:
    """Интерактивно собирает параметры для новой/изменяемой location.
    
    Returns:
      dict {name, carrier, transport, room_id, key, payload} или None при отмене.
    """
    carrier = _ask_carrier()
    if not carrier:
        return None
    
    transport = _ask_transport(carrier)
    if not transport:
        return None
    
    room_id = _ask_room_id(carrier)
    if not room_id:
        return None
    
    name = _ask_location_name(existing_names)
    if not name:
        return None
    
    # Генерация key (hex 32, как в гайде).
    key = secrets.token_hex(32)
    payload = TRANSPORT_PAYLOADS.get(transport, {}).copy()
    
    return {
        "name": name,
        "carrier": carrier,
        "transport": transport,
        "room_id": room_id,
        "key": key,
        "payload": payload,
    }


def _flow_configure() -> None:
    """Интерактивное управление locations manager panel.
    
    Меню:
      - Показать список существующих locations
      - [1] Добавить новую location
      - [2] Удалить location
      - [3] Изменить location
      - [4] Показать все OlcBox URI
    """
    while True:
        st = _load_state()
        cfg = st.get("config", {})
        locations = cfg.get("locations", [])
        
        print()
        _box_top("⚙️  Настройка olcRTC Manager Panel — Locations")
        _box_row()
        _box_row(f"  {BOLD}Текущие locations ({len(locations)}):{NC}")
        if not locations:
            _box_row(f"  {DIM}  (нет — добавьте первую){NC}")
        else:
            for i, loc in enumerate(locations, 1):
                carrier_title = next((t for k, (c, t, _) in CARRIERS.items() if c == loc.get("carrier", "")), loc.get("carrier", "?"))
                _box_row(f"  {GREEN}[{i}]{NC} {BOLD}{loc.get('name', '?')}{NC}  {DIM}— {carrier_title}/{loc.get('transport', '?')}, room={loc.get('room_id', '?')[:40]}...{NC}")
        _box_sep()
        _box_item("1", f"{GREEN}➕  Добавить location{NC}")
        if locations:
            _box_item("2", f"{YELLOW}🗑️  Удалить location{NC}")
            _box_item("3", "✏️  Изменить location")
            _box_item("4", "📄  Показать все OlcBox URI")
        _box_row()
        _box_back()
        _box_bottom()
        
        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return
        
        if ch in ("q", ""):
            return
        
        if ch == "1":
            # Добавить location.
            existing_names = [loc.get("name", "") for loc in locations]
            new_loc = _collect_location(existing_names)
            if not new_loc:
                input(f"{BLUE}  Нажмите Enter...{NC}")
                continue
            
            print()
            _info(f"Добавляю location '{new_loc['name']}' ({new_loc['carrier']}/{new_loc['transport']})...")
            locations.append(new_loc)
            ok = _configure_manager(locations)
            
            if ok:
                _success("Location добавлена, manager перезапущен!")
                # Показать OlcBox URI для новой location.
                print()
                _box_top("✅ Location добавлена")
                _box_row(f"  {BOLD}Имя:{NC}        {new_loc['name']}")
                _box_row(f"  {BOLD}Carrier:{NC}    {new_loc['carrier']}")
                _box_row(f"  {BOLD}Transport:{NC}  {new_loc['transport']}")
                _box_row(f"  {BOLD}Room ID:{NC}    {new_loc['room_id']}")
                _box_row(f"  {BOLD}Key:{NC}        {new_loc['key']}")
                _box_sep()
                _box_row(f"  {BOLD}OlcBox URI:{NC}")
                _box_row(f"  {CYAN}{new_loc.get('olcbox_uri', '?')}{NC}")
                _box_bottom()
            else:
                _warn("Location добавлена в state, но сервис не активен.")
                _warn("Проверьте: journalctl -u olcrtc-manager -n 30")
            input(f"{BLUE}  Нажмите Enter...{NC}")
        
        elif ch == "2" and locations:
            # Удалить location.
            print()
            try:
                idx_str = input(f"{CYAN}  Номер location для удаления:{NC} ").strip()
                idx = int(idx_str) - 1
            except (ValueError, EOFError, KeyboardInterrupt):
                _warn("Неверный номер")
                input(f"{BLUE}  Нажмите Enter...{NC}")
                continue
            if idx < 0 or idx >= len(locations):
                _warn("Номер вне диапазона")
                input(f"{BLUE}  Нажмите Enter...{NC}")
                continue
            
            loc = locations[idx]
            confirm = input(f"  {RED}Удалить '{loc.get('name', '?')}'? [y/N]:{NC} ").strip().lower()
            if confirm not in ("y", "yes", "д", "да"):
                _info("Отменено")
                input(f"{BLUE}  Нажмите Enter...{NC}")
                continue
            
            del locations[idx]
            if locations:
                _info("Удаляю location и перезапускаю manager...")
                ok = _configure_manager(locations)
                if ok:
                    _success("Location удалена, manager перезапущен!")
                else:
                    _warn("Location удалена из state, но сервис не активен.")
            else:
                # Нет больше locations — остановить сервис.
                _info("Последняя location удалена — останавливаю сервис...")
                _run(["systemctl", "stop", "olcrtc-manager"],
                      check=False, quiet=True, timeout=20)
                _save_state({**st, "config": {**cfg, "locations": []}})
                _success("Сервис остановлен, locations пусты")
            input(f"{BLUE}  Нажмите Enter...{NC}")
        
        elif ch == "3" and locations:
            # Изменить location.
            print()
            try:
                idx_str = input(f"{CYAN}  Номер location для изменения:{NC} ").strip()
                idx = int(idx_str) - 1
            except (ValueError, EOFError, KeyboardInterrupt):
                _warn("Неверный номер")
                input(f"{BLUE}  Нажмите Enter...{NC}")
                continue
            if idx < 0 or idx >= len(locations):
                _warn("Номер вне диапазона")
                input(f"{BLUE}  Нажмите Enter...{NC}")
                continue
            
            old_loc = locations[idx]
            # Для изменения исключаем имя старой location из existing_names.
            other_names = [loc.get("name", "") for i, loc in enumerate(locations) if i != idx]
            new_loc = _collect_location(other_names)
            if not new_loc:
                input(f"{BLUE}  Нажмите Enter...{NC}")
                continue
            
            print()
            _info(f"Изменяю location '{old_loc.get('name', '?')}' → '{new_loc['name']}'...")
            locations[idx] = new_loc
            ok = _configure_manager(locations)
            if ok:
                _success("Location изменена, manager перезапущен!")
            else:
                _warn("Location изменена в state, но сервис не активен.")
            input(f"{BLUE}  Нажмите Enter...{NC}")
        
        elif ch == "4" and locations:
            # Показать все OlcBox URI.
            print()
            _box_top("📄 Все OlcBox URI")
            _box_row()
            for i, loc in enumerate(locations, 1):
                carrier_title = next((t for k, (c, t, _) in CARRIERS.items() if c == loc.get("carrier", "")), loc.get("carrier", "?"))
                _box_row(f"  {GREEN}[{i}]{NC} {BOLD}{loc.get('name', '?')}{NC}  {DIM}({carrier_title}/{loc.get('transport', '?')}){NC}")
                _box_row(f"  {CYAN}{loc.get('olcbox_uri', '?')}{NC}")
                _box_row()
            _box_sep()
            _box_row(f"  {DIM}Panel: {cfg.get('panel_url', '?')}{NC}")
            _box_row(f"  {DIM}User:  {cfg.get('admin_user', 'admin')}{NC}")
            _box_row(f"  {DIM}Pass:  {cfg.get('admin_pass', '?')}{NC}")
            _box_bottom()
            input(f"{BLUE}  Нажмите Enter...{NC}")


# =============================================================================
#  TUI: СТАТУС
# =============================================================================
def _flow_status() -> None:
    """Показывает статус manager panel через API."""
    print()
    active = _manager_service_active()
    _box_top("📊 Статус olcRTC Manager")
    _box_row(f"  Сервис: {GREEN+'● активен' if active else RED+'○ остановлен'}{NC}")

    if active:
        state = _api_state()
        if state:
            _box_sep()
            # Показываем ключевые поля из API.
            for client in state.get("clients", []):
                cid = client.get("client-id", "?")
                _box_row(f"  Client: {CYAN}{cid}{NC}")
                for loc in client.get("locations", []):
                    name = loc.get("name", "?")
                    status = loc.get("status", "?")
                    peers = loc.get("peers", "?")
                    _box_row(f"    Location: {name}")
                    _box_row(f"    Status:   {status}")
                    _box_row(f"    Peers:    {peers}")
        else:
            _box_row(f"  {YELLOW}API недоступен — проверьте journalctl{NC}")
    _box_bottom()
    input(f"{BLUE}  Нажмите Enter...{NC}")


# =============================================================================
#  TUI: ЛОГИ
# =============================================================================
def _flow_logs() -> None:
    """Показывает логи через API."""
    st = _load_state()
    room_id = st.get("config", {}).get("room_id", "")
    if not room_id:
        _warn("Нет настроенной комнаты")
        input(f"{BLUE}  Нажмите Enter...{NC}")
        return

    print()
    logs = _api_logs(room_id)
    _box_top("📋 Логи olcRTC (API)")
    if not logs:
        _box_row(f"  {DIM}(пусто или API недоступен){NC}")
    else:
        try:
            data = json.loads(logs)
            lines = data if isinstance(data, list) else [data]
            for entry in lines[:30]:
                msg = entry.get("message", str(entry)) if isinstance(entry, dict) else str(entry)
                _box_row(f"  {DIM}{msg[:120]}{NC}")
        except Exception:
            for line in logs.splitlines()[:30]:
                _box_row(f"  {DIM}{line[:120]}{NC}")
    _box_bottom()
    input(f"{BLUE}  Нажмите Enter...{NC}")


# =============================================================================
#  TUI: ГАЙД
# =============================================================================
def _show_guide() -> None:
    os.system("clear")
    print()
    _box_top("📖 olcRTC — как это работает")
    _box_row(f"  {DIM}TCP-over-WebRTC: маскирует трафик под видеозвонок{NC}")
    _box_row(f"  {DIM}в WB Stream / Jitsi / Телемост. Для обхода блокировок{NC}")
    _box_row(f"  {DIM}по белым спискам.{NC}")
    _box_sep()
    _box_row(f"  {BOLD}Архитектура:{NC}")
    _box_row(f"  {WHITE}olcrtc — туннель (TCP-over-WebRTC){NC}")
    _box_row(f"  {WHITE}olcrtc-manager — веб-панель + API + supervisor{NC}")
    _box_row(f"  {WHITE}Manager сам запускает и управляет olcrtc процессами.{NC}")
    _box_sep()
    _box_row(f"  {BOLD}Что получает пользователь:{NC}")
    _box_row(f"  {WHITE}1. Веб-панель на https://SERVER_IP:8888/admin{NC}")
    _box_row(f"  {WHITE}   (self-signed TLS, basic auth){NC}")
    _box_row(f"  {WHITE}2. API: /api/state, /api/logs{NC}")
    _box_row(f"  {WHITE}3. OlcBox URI для клиента{NC}")
    _box_sep()
    _box_row(f"  {BOLD}Что нужно клиенту:{NC}")
    _box_row(f"  {WHITE}OlcBox (community клиент olcrtc, alpha) — вводит URI.{NC}")
    _box_row(f"  {WHITE}Или olcrtc CLI: go build ./cmd/olcrtc{NC}")
    _box_row(f"  {WHITE}На устройстве появится SOCKS5 прокси.{NC}")
    _box_sep()
    _box_row(f"  {BOLD}Провайдеры:{NC}")
    _box_row(f"  {CYAN}WB Stream{NC}  — комната на stream.wb.ru (нужно создать)")
    _box_row(f"  {CYAN}Jitsi{NC}      — комната генерируется автоматически")
    _box_row(f"  {CYAN}Телемост{NC}   — комната на telemost.yandex.ru")
    _box_sep()
    _box_row(f"  {BOLD}Транспорт (скорость по убыванию):{NC}")
    _box_row(f"  {DIM}datachannel > vp8channel > seichannel > videochannel{NC}")
    _box_sep()
    _box_row(f"  {YELLOW}Beta-проект. Используйте как запасной канал.{NC}")
    _box_bottom()
    input(f"{BLUE}  Нажмите Enter...{NC}")


# =============================================================================
#  ГЛАВНОЕ МЕНЮ
# =============================================================================
def do_olcrtc_menu() -> None:
    """Интерактивное управление olcRTC: установка, настройка, статус."""
    while True:
        st = _load_state()
        installed = _olcrtc_installed() and _manager_installed()
        locations = st.get("config", {}).get("locations", [])
        configured = len(locations) > 0
        active = _manager_service_active() if installed else False

        os.system("clear")
        print()
        _box_top("📹 olcRTC — ТУННЕЛЬ ПОД ВИДЕОЗВОНОК (Beta)")
        _box_row(f"  {DIM}TCP-over-WebRTC: маскирует трафик под звонок в{NC}")
        _box_row(f"  {DIM}WB Stream / Jitsi / Телемост.{NC}")
        _box_sep()
        if not installed:
            _box_row(f"  Статус: {RED}не установлен{NC}")
        else:
            _box_row(f"  Статус:   {GREEN}● собран{NC}  {DIM}(olcrtc: {st.get('commit','?')}, manager: {st.get('manager_commit','?')}){NC}")
            if configured:
                _box_row(f"  Настроен: {GREEN if active else YELLOW}{'● active' if active else '○ stopped'}{NC}  {DIM}({len(locations)} location{'s' if len(locations) != 1 else ''}){NC}")
                cfg = st.get("config", {})
                _box_row(f"  Panel:    {CYAN}{cfg.get('panel_url', '?')}{NC}")
                # Показать первые 3 location.
                for loc in locations[:3]:
                    carrier_title = next((t for k, (c, t, _) in CARRIERS.items() if c == loc.get("carrier", "")), loc.get("carrier", "?"))
                    _box_row(f"  {DIM}  • {loc.get('name', '?')} — {carrier_title}/{loc.get('transport', '?')}{NC}")
                if len(locations) > 3:
                    _box_row(f"  {DIM}  • ...и ещё {len(locations) - 3}{NC}")
            else:
                _box_row(f"  Настроен: {DIM}нет (нужно настроить){NC}")
        _box_sep()

        if not installed:
            _box_item("1", "📥 Установить (сборка olcrtc + olcrtc-manager из исходников)")
        else:
            _box_item("1", "🔄 Обновить (пересборка)")
        _box_item("2", "📖 Гайд — как это работает")
        if installed:
            _box_item("3", "⚙️  Настроить Manager Panel (locations: добавить/удалить/изменить)")
        if configured:
            _box_item("4", "📊 Статус (через API)")
            _box_item("5", "📋 Логи (через API)")
            _box_item("6", "📄 Показать все OlcBox URI и креды")
        if installed and configured:
            if active:
                _box_item("7", f"{YELLOW}⏸️  Остановить сервис{NC}")
            else:
                _box_item("7", f"{GREEN}▶️  Запустить сервис{NC}")
        if installed:
            _box_item("8", f"{RED}🗑️  Удалить полностью{NC}")
        if installed:
            # Показать текущий TLS режим + пункт переключения.
            _tls_st = _tls_mode_status()
            _tls_mode = _tls_st.get("mode", "unknown")
            _tls_domain = _tls_st.get("domain")
            if _tls_mode == "letsencrypt":
                _tls_label = f"Let's Encrypt ({_tls_domain or '?'})"
            elif _tls_mode == "self_signed":
                _tls_label = "Self-signed (по IP)"
            else:
                _tls_label = "неизвестно"
            _box_item("9", f"🔒  Режим TLS: {CYAN}{_tls_label}{NC}  {DIM}(переключить){NC}")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch in ("q", ""):
            break

        if ch == "1":
            print()
            if _install_or_update():
                _success("olcrtc и olcrtc-manager установлены/обновлены")
            else:
                _error("Установка не удалась — см. сообщения выше")
            input(f"{BLUE}  Нажмите Enter...{NC}")

        elif ch == "2":
            _show_guide()

        elif ch == "3" and installed:
            _flow_configure()

        elif ch == "4" and configured:
            _flow_status()

        elif ch == "5" and configured:
            _flow_logs()

        elif ch == "6" and configured:
            cfg = st.get("config", {})
            print()
            _box_top("📄 OlcBox URI и креды")
            _box_row(f"  Panel URL:  {CYAN}{cfg.get('panel_url', '?')}{NC}")
            _box_row(f"  User:       {CYAN}{cfg.get('admin_user', 'admin')}{NC}")
            _box_row(f"  Password:   {YELLOW}{cfg.get('admin_pass', '?')}{NC}")
            _box_sep()
            _box_row(f"  {BOLD}Locations ({len(locations)}):{NC}")
            _box_row()
            for i, loc in enumerate(locations, 1):
                carrier_title = next((t for k, (c, t, _) in CARRIERS.items() if c == loc.get("carrier", "")), loc.get("carrier", "?"))
                _box_row(f"  {GREEN}[{i}]{NC} {BOLD}{loc.get('name', '?')}{NC}  {DIM}({carrier_title}/{loc.get('transport', '?')}){NC}")
                _box_row(f"  {CYAN}{loc.get('olcbox_uri', '?')}{NC}")
                _box_row(f"  {DIM}Room ID: {loc.get('room_id', '?')}{NC}")
                _box_row(f"  {DIM}Key:     {loc.get('key', '?')}{NC}")
                _box_row()
            _box_bottom()
            input(f"{BLUE}  Нажмите Enter...{NC}")

        elif ch == "7" and installed and configured:
            print()
            if active:
                # Остановить сервис + закрыть порт в UFW.
                _info("Останавливаю olcrtc-manager...")
                _run(["systemctl", "stop", "olcrtc-manager"],
                     check=False, quiet=True, timeout=20)
                time.sleep(1)
                # Закрыть порт 8888 через port_registry.
                try:
                    from chimera.modules.port_registry import (
                        ufw_close_port, port_unregister,
                    )
                    ufw_close_port(MGR_PORT, "tcp", _OLCRTC_MANAGER_SERVICE_TAG,
                                   legacy_comments=["olcrtc-manager panel (TLS)"])
                    port_unregister(_OLCRTC_MANAGER_SERVICE_TAG, MGR_PORT, "tcp")
                except Exception as e:
                    _warn(f"UFW: не удалось закрыть порт {MGR_PORT}: {e}")
                _success("Сервис остановлен, порт 8888 закрыт в UFW")
            else:
                # Запустить сервис + открыть порт в UFW.
                _info("Запускаю olcrtc-manager...")
                _run(["systemctl", "start", "olcrtc-manager"],
                     check=False, quiet=True, timeout=20)
                time.sleep(3)
                # Открыть порт 8888 через port_registry.
                try:
                    from chimera.modules.port_registry import (
                        ufw_open_port, port_register,
                    )
                    port_register(_OLCRTC_MANAGER_SERVICE_TAG, MGR_PORT, "tcp",
                                  comment="olcrtc-manager panel (TLS)", force=True)
                    ufw_open_port(MGR_PORT, "tcp", _OLCRTC_MANAGER_SERVICE_TAG,
                                  comment="olcrtc-manager panel (TLS)")
                except Exception as e:
                    _warn(f"UFW: не удалось открыть порт {MGR_PORT}: {e}")
                if _manager_service_active():
                    _success("Сервис запущен, порт 8888 открыт в UFW")
                else:
                    _warn("Сервис не поднялся — проверьте: journalctl -u olcrtc-manager -n 30")
            input(f"{BLUE}  Нажмите Enter...{NC}")

        elif ch == "8" and installed:
            print()
            confirm = input(f"  {RED}Полностью удалить olcRTC (бинарники, конфиги, сервис)? [y/N]:{NC} ").strip().lower()
            if confirm in ("y", "yes", "д", "да"):
                _uninstall_manager()
            else:
                _info("Отменено")
            input(f"{BLUE}  Нажмите Enter...{NC}")

        elif ch == "9" and installed:
            print()
            _toggle_tls_mode()
            input(f"{BLUE}  Нажмите Enter...{NC}")

        else:
            _warn("Неверный выбор")
            time.sleep(1)

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

# Transport payload defaults (из гайда — vp8channel с fps=30, batch=64).
TRANSPORT_PAYLOADS = {
    "vp8channel": {"vp8-fps": "30", "vp8-batch": "64"},
}


# =============================================================================
#  СОСТОЯНИЕ
# =============================================================================
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
            return st
        except Exception:
            pass
    return {"installed": False, "manager_installed": False, "commit": "",
            "manager_commit": "", "built_at": "", "config": {}}


def _save_state(st: dict) -> None:
    OLC_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        OLC_STATE_FILE.write_text(json.dumps(st, ensure_ascii=False, indent=2))
    except Exception as e:
        _warn(f"Не удалось сохранить состояние модуля: {e}")


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
    """Клонирует или обновляет репозиторий через git."""
    if dest.exists() and (dest / ".git").exists():
        _info(f"Обновление {dest.name}...")
        r = _run(["git", "pull", "--ff-only", "origin", branch],
                 capture=True, check=False, timeout=60, cwd=str(dest))
        return r.returncode == 0
    else:
        _info(f"Клонирование {repo} → {dest}...")
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        r = _run(["git", "clone", "--depth", "1", "--branch", branch,
                  repo, str(dest)],
                 capture=True, check=False, timeout=120)
        return r.returncode == 0


def _go_build(src_dir: Path, output: Path, pkg_path: str = "./cmd/olcrtc") -> bool:
    """Собирает Go бинарник из src_dir, кладёт в output."""
    go = _find_go_binary()
    if not go:
        _error("Go не найден — установите Go сначала")
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


def _install_or_update() -> bool:
    """Полная установка/обновление: Go → olcrtc → olcrtc-manager.

    Шаги:
      1. Проверка/установка Go 1.26+
      2. Клонирование openlibrecommunity/olcrtc (master)
      3. Сборка /usr/local/bin/olcrtc
      4. Клонирование BigDaddy3334/olcrtc-manager-panel (main)
      5. Сборка /usr/local/bin/olcrtc-manager
      6. Сохранение state
    """
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
    olc_commit = _get_commit_sha(olcrtc_src)
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
def _generate_config_json(carrier: str, room_id: str, key: str,
                          transport: str, location_name: str = "wb-vps") -> str:
    """Генерирует config.json для olcrtc-manager.

    Формат — точно по гайду:
    {
      "version": 1,
      "name": "WB VPS",
      "port": 8888,
      "refresh": "10m",
      "clients": [
        {
          "client-id": "wb",
          "refresh": "5m",
          "locations": [
            {
              "name": "wb-vps",
              "endpoint": {
                "room_id": "<ROOM_ID>",
                "key": "<KEY>"
              },
              "carrier": "wbstream",
              "transport": {
                "type": "vp8channel",
                "payload": {
                  "vp8-fps": "30",
                  "vp8-batch": "64"
                }
              },
              "link": "direct",
              "data": "/var/lib/olcrtc/data",
              "dns": "8.8.8.8:53"
            }
          ]
        }
      ]
    }
    """
    # Transport payload (из гайда — vp8channel с fps=30, batch=64).
    payload = TRANSPORT_PAYLOADS.get(transport, {})

    config = {
        "version": 1,
        "name": "Chimera olcRTC",
        "port": MGR_PORT,
        "refresh": "10m",
        "clients": [
            {
                "client-id": "wb",
                "refresh": "5m",
                "locations": [
                    {
                        "name": location_name,
                        "endpoint": {
                            "room_id": room_id,
                            "key": key,
                        },
                        "carrier": carrier,
                        "transport": {
                            "type": transport,
                            "payload": payload,
                        },
                        "link": "direct",
                        "data": str(MGR_DATA_DIR),
                        "dns": "8.8.8.8:53",
                    }
                ],
            }
        ],
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
    """Пытается определить публичный IP сервера."""
    # Через curl ifconfig.me (быстро, без DNS-зависимостей).
    r = _run(["curl", "-s", "--max-time", "5", "ifconfig.me"],
             capture=True, check=False, timeout=10)
    ip = r.stdout.strip() if r.returncode == 0 else ""
    if ip and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return ip
    # Fallback: hostname -I
    r = _run(["hostname", "-I"], capture=True, check=False, timeout=5)
    if r.returncode == 0:
        ips = r.stdout.strip().split()
        for ip in ips:
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip) and not ip.startswith("127."):
                return ip
    return ""


# =============================================================================
#  УСТАНОВКА / НАСТРОЙКА / УДАЛЕНИЕ MANAGER PANEL
# =============================================================================
def _configure_manager(carrier: str, transport: str, room_id: str,
                       location_name: str = "wb-vps") -> bool:
    """Настраивает manager panel: config.json, panel.env, TLS, systemd, UFW.

    Возвращает True при успехе.
    """
    st = _load_state()

    # Генерация key (hex 32, как в гайде).
    key = secrets.token_hex(32)

    # Генерация admin кредов.
    admin_user = "admin"
    admin_pass = secrets.token_hex(16)

    # Публичный IP.
    public_ip = _get_public_ip()
    if not public_ip:
        _warn("Не удалось определить публичный IP — TLS будет без IP SAN")
        public_ip = "127.0.0.1"

    # 1. Директории.
    MGR_ETC_DIR.mkdir(parents=True, exist_ok=True)
    MGR_DATA_DIR.mkdir(parents=True, exist_ok=True)

    # 2. config.json.
    config_text = _generate_config_json(carrier, room_id, key, transport, location_name)
    MGR_CONFIG.write_text(config_text)
    MGR_CONFIG.chmod(0o600)

    # 3. panel.env.
    env_text = _generate_panel_env(admin_user, admin_pass)
    MGR_PANEL_ENV.write_text(env_text)
    MGR_PANEL_ENV.chmod(0o600)

    # 4. TLS сертификат.
    if not _generate_tls_cert(public_ip):
        _warn("TLS не сгенерирован — панель будет без HTTPS")

    # 5. systemd unit.
    unit_text = _generate_systemd_unit()
    MGR_UNIT_FILE.parent.mkdir(parents=True, exist_ok=True)
    MGR_UNIT_FILE.write_text(unit_text)
    _run(["systemctl", "daemon-reload"], check=False, quiet=True, timeout=15)

    # 6. UFW — открыть порт через port_registry.
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

    # 7. Запуск сервиса.
    _run(["systemctl", "enable", "--now", "olcrtc-manager"],
          check=False, quiet=True, timeout=20)
    _run(["systemctl", "restart", "olcrtc-manager"],
          check=False, quiet=True, timeout=20)
    time.sleep(6)

    active = _manager_service_active()
    if not active:
        _warn("olcrtc-manager не поднялся — проверьте: journalctl -u olcrtc-manager -n 30")

    # 8. Сохранение state.
    st["config"] = {
        "carrier": carrier,
        "transport": transport,
        "room_id": room_id,
        "key": key,
        "location_name": location_name,
        "admin_user": admin_user,
        "admin_pass": admin_pass,
        "public_ip": public_ip,
        "panel_url": f"https://{public_ip}:{MGR_PORT}/admin",
    }
    _save_state(st)

    # 9. OlcBox URI.
    uri = _generate_olcbox_uri(carrier, transport, room_id, key, location_name)
    st["config"]["olcbox_uri"] = uri
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
def _flow_configure() -> None:
    """Интерактивная настройка manager panel."""
    print()
    _box_top("Настройка olcRTC Manager Panel")
    _box_row()
    _box_row(f"  {BOLD}Выберите провайдера:{NC}")
    for k, (_, title, hint) in CARRIERS.items():
        _box_item(k, f"{title}  {DIM}— {hint}{NC}")
    _box_bottom()

    try:
        c_choice = input(f"{CYAN}  Провайдер [1]:{NC} ").strip() or "1"
    except (EOFError, KeyboardInterrupt):
        return
    if c_choice not in CARRIERS:
        _warn("Неверный выбор")
        input(f"{BLUE}  Нажмите Enter...{NC}")
        return
    carrier, carrier_title, _ = CARRIERS[c_choice]

    print()
    _box_top("Транспорт (маскировка)")
    for k, (_, hint) in TRANSPORTS.items():
        _box_item(k, hint)
    _box_bottom()

    try:
        t_choice = input(f"{CYAN}  Транспорт [2 — vp8channel]:{NC} ").strip() or "2"
    except (EOFError, KeyboardInterrupt):
        return
    if t_choice not in TRANSPORTS:
        _warn("Неверный выбор")
        input(f"{BLUE}  Нажмите Enter...{NC}")
        return
    transport, _ = TRANSPORTS[t_choice]

    print()
    if carrier == "jitsi":
        _box_top("Jitsi — комната")
        _box_row(f"  {DIM}Для Jitsi комната генерируется автоматически.{NC}")
        _box_row(f"  {DIM}Просто нажмите Enter.{NC}")
        _box_bottom()
        room_id = f"https://meet.jitsi.ru/{secrets.token_hex(8)}"
        _info(f"Сгенерирована комната: {room_id}")
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
            return
        if not room_id:
            _warn("ROOM_ID не указан — отменено")
            input(f"{BLUE}  Нажмите Enter...{NC}")
            return

    print()
    _info(f"Настраиваю manager panel ({carrier_title}, {transport})...")
    ok = _configure_manager(carrier, transport, room_id)

    if ok:
        st = _load_state()
        cfg = st.get("config", {})
        _success("Manager panel настроена и запущена!")

        print()
        _box_top("✅ Готово!")
        _box_row(f"  Panel URL:  {CYAN}{cfg.get('panel_url', '?')}{NC}")
        _box_row(f"  User:       {CYAN}{cfg.get('admin_user', 'admin')}{NC}")
        _box_row(f"  Password:   {YELLOW}{cfg.get('admin_pass', '?')}{NC}")
        _box_sep()
        _box_row(f"  {BOLD}OlcBox URI (для клиента):{NC}")
        _box_row(f"  {CYAN}{cfg.get('olcbox_uri', '?')}{NC}")
        _box_sep()
        _box_row(f"  {DIM}Откройте Panel URL в браузере (примите self-signed TLS).{NC}")
        _box_row(f"  {DIM}В OlcBox введите URI выше или параметры вручную:{NC}")
        _box_row(f"  {DIM}  Service: {carrier_title}{NC}")
        _box_row(f"  {DIM}  Transport: {transport}{NC}")
        _box_row(f"  {DIM}  Room ID: {room_id}{NC}")
        _box_row(f"  {DIM}  Encryption key: {cfg.get('key', '?')}{NC}")
        _box_bottom()
    else:
        _warn("Manager panel настроена, но сервис не активен.")
        _warn("Проверьте: journalctl -u olcrtc-manager -n 30")

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
        configured = bool(st.get("config", {}).get("room_id"))
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
                _box_row(f"  Настроен: {GREEN if active else YELLOW}{'● active' if active else '○ stopped'}{NC}")
                cfg = st.get("config", {})
                _box_row(f"  Panel:    {CYAN}{cfg.get('panel_url', '?')}{NC}")
                _box_row(f"  Carrier:  {cfg.get('carrier', '?')}/{cfg.get('transport', '?')}")
            else:
                _box_row(f"  Настроен: {DIM}нет (нужно настроить){NC}")
        _box_sep()

        if not installed:
            _box_item("1", "📥 Установить (сборка olcrtc + olcrtc-manager из исходников)")
        else:
            _box_item("1", "🔄 Обновить (пересборка)")
        _box_item("2", "📖 Гайд — как это работает")
        if installed and not configured:
            _box_item("3", "⚙️  Настроить Manager Panel (провайдер, комната)")
        if configured:
            _box_item("4", "📊 Статус (через API)")
            _box_item("5", "📋 Логи (через API)")
            _box_item("6", "📄 Показать OlcBox URI и креды")
        if installed:
            _box_item("7", f"{RED}🗑️  Удалить полностью{NC}")
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
            _box_row(f"  {BOLD}OlcBox URI:{NC}")
            _box_row(f"  {CYAN}{cfg.get('olcbox_uri', '?')}{NC}")
            _box_sep()
            _box_row(f"  {DIM}Carrier:    {cfg.get('carrier', '?')}{NC}")
            _box_row(f"  {DIM}Transport:  {cfg.get('transport', '?')}{NC}")
            _box_row(f"  {DIM}Room ID:    {cfg.get('room_id', '?')}{NC}")
            _box_row(f"  {DIM}Key:        {cfg.get('key', '?')}{NC}")
            _box_bottom()
            input(f"{BLUE}  Нажмите Enter...{NC}")

        elif ch == "7" and installed:
            print()
            confirm = input(f"  {RED}Полностью удалить olcRTC (бинарники, конфиги, сервис)? [y/N]:{NC} ").strip().lower()
            if confirm in ("y", "yes", "д", "да"):
                _uninstall_manager()
            else:
                _info("Отменено")
            input(f"{BLUE}  Нажмите Enter...{NC}")

        else:
            _warn("Неверный выбор")
            time.sleep(1)

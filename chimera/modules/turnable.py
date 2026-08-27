"""
chimera/modules/turnable.py
───────────────────────────────────────────────────────────────────────────────
Turnable — проброс VLESS/WireGuard через TURN ВКонтакте для WireTurn.

Назначение:
  Позволяет Android-пользователям (WireTurn) подключаться к VPS через
  TURN-серверы ВКонтакте. Turnable обеспечивает сквозное шифрование,
  управление пользователями и маршрутами. WireTurn на Android имеет
  встроенный Xray и умеет форвардить VLESS-трафик.

Схема трафика (VLESS-маршрут):
  Android (WireTurn + встроенный Xray)
    │  WebRTC DTLS поверх TURN
    ▼
  TURN-серверы ВКонтакте
    │  UDP → VPS
    ▼
  Turnable server  (:56001 UDP)
    │  TCP → Xray inbound
    ▼
  Xray inbound VLESS  (127.0.0.1:порт, plain TCP)
    │
    ▼
  Интернет

Что модуль делает:
  • Скачивает бинарник Turnable с GitHub (только amd64)
  • Генерирует пару ключей (priv_key / pub_key) через turnable keygen
  • Запрашивает Call ID ВК-звонка
  • Создаёт /opt/turnable/config.json и store.json
  • Добавляет VLESS-inbound в config.json Xray (127.0.0.1, plain TCP)
  • Создаёт systemd-сервис turnable
  • Открывает входящий UDP-порт в iptables
  • Генерирует turnable:// ссылку и QR-код для WireTurn
  • При удалении — чисто убирает всё перечисленное

Что модуль НЕ трогает:
  • Основной VLESS/REALITY inbound
  • Существующих пользователей и ключи
  • iptables-правила других модулей
  • state.json
  • Модуль turntunnel.py (vk-turn-proxy / FreeTurn)

Клиентское приложение:
  WireTurn (spkprsnts/WireTurn)
  github.com/spkprsnts/WireTurn

Точка входа:
    from chimera.modules.turnable import do_turnable_menu
    do_turnable_menu()
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from chimera.modules.text_width import wlen as _wlen, plain as _plain

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import uuid
from pathlib import Path
from typing import Optional

from chimera.modules.proto_common import (
    ProtoCancelled, proto_load_state, proto_save_state,
    proto_ask, proto_ipt_persist, proto_ipt_rule_exists,
    proto_get_latest_version, proto_get_installed_version,
)
# _Cancelled aliases ProtoCancelled so existing `except _Cancelled:` and
# `raise _Cancelled` code works unchanged after the local class definition
# was removed in favour of proto_common.ProtoCancelled.
_Cancelled = ProtoCancelled

# ══════════════════════════════════════════════════════════════════════════════
#  ЦВЕТА
# ══════════════════════════════════════════════════════════════════════════════
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BOLD='\033[1m', DIM='\033[2m',
                WHITE='\033[0;30m', NC='\033[0m',
            )
        return dict(
            RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
            CYAN='\033[0;36m', BOLD='\033[1m', DIM='\033[2m',
            WHITE='\033[1;37m', NC='\033[0m',
        )
    return {k: '' for k in ('RED', 'GREEN', 'YELLOW', 'CYAN', 'BOLD', 'DIM', 'WHITE', 'NC')}

_C = _detect_colors()
RED, GREEN, YELLOW, CYAN, BOLD, DIM, WHITE, NC = (
    _C['RED'], _C['GREEN'], _C['YELLOW'], _C['CYAN'],
    _C['BOLD'], _C['DIM'], _C['WHITE'], _C['NC'],
)

# ══════════════════════════════════════════════════════════════════════════════
#  КОНСТАНТЫ
# ══════════════════════════════════════════════════════════════════════════════
_BIN_PATH        = Path("/opt/turnable/turnable")
_BIN_DIR         = Path("/opt/turnable")
_CONFIG_FILE     = Path("/opt/turnable/config.json")
_STORE_FILE      = Path("/opt/turnable/store.json")
_SERVICE_FILE    = Path("/etc/systemd/system/turnable.service")
_SERVICE_NAME    = "turnable"
_LOG_FILE        = Path("/var/log/turnable-install.log")
_MODULE_STATE    = Path("/var/lib/xray-installer/turnable.json")

_DEFAULT_LISTEN_PORT  = 56001   # UDP — порт Turnable (56000 оставляем для vk-turn-proxy)
_DEFAULT_XRAY_PORT    = 12767   # TCP — Xray inbound (12766 занят turntunnel.py)

_ROUTE_ID_VLESS  = "vless"
_XRAY_INBOUND_TAG = "vless-turnable-inbound"

_TURNABLE_VERSION = "0.4.1"
# _GITHUB_RELEASES_URL — удалён при миграции на download_manager.
# Теперь зеркала (jsDelivr CDN + release GitHub + 3 gh-proxy) собираются в
# turn_mirrors.get_turnable_mirrors(version) и перебираются автоматически
# через fetch_package(TURNABLE_SPEC, version=_TURNABLE_VERSION).
_GITHUB_API_URL = "https://api.github.com/repos/TheAirBlow/Turnable/releases/latest"

_XRAY_CONFIG_PATHS = [
    Path("/etc/xray/config.json"),
    Path("/usr/local/etc/xray/config.json"),
]

_BOX_W = 66

# ══════════════════════════════════════════════════════════════════════════════
#  BOX-РЕНДЕРИНГ
# ══════════════════════════════════════════════════════════════════════════════


def _box_top(title: str = "") -> None:
    print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")
    if title:
        pad  = _BOX_W - _wlen(title)
        lpad = pad // 2
        rpad = pad - lpad
        print(f"{CYAN}║{NC}{' ' * lpad}{BOLD}{WHITE}{title}{NC}{' ' * rpad}{CYAN}║{NC}")
        print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")

def _box_sep() -> None:
    print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")

def _box_bot() -> None:
    print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")

def _box_row(text: str = "") -> None:
    w = _wlen(text)
    if w > _BOX_W:
        acc, plain = 0, _plain(text)
        cut = 0
        for i, ch in enumerate(plain):
            import unicodedata as _ud
            acc += 2 if _ud.east_asian_width(ch) in ('W', 'F') else 1
            if acc > _BOX_W - 1:
                cut = i
                break
        text = text[:cut] + "…"
        w = _wlen(text)
    pad = max(0, _BOX_W - w)
    print(f"{CYAN}║{NC}{text}{' ' * pad}{CYAN}║{NC}")

def _box_item(key: str, label: str) -> None:
    col = RED + BOLD if key.strip().upper() in ("Q", "0") else WHITE + BOLD
    _box_row(f"  {DIM}[{NC}{col}{key}{NC}{DIM}]{NC}  {label}")

def _box_ok(msg: str)   -> None: _box_row(f"  {GREEN}✓{NC}  {msg}")
def _box_warn(msg: str) -> None: _box_row(f"  {YELLOW}⚠{NC}  {msg}")
def _box_info(msg: str) -> None: _box_row(f"  {CYAN}→{NC}  {msg}")
def _box_err(msg: str)  -> None: _box_row(f"  {RED}✗{NC}  {msg}")

def _box_kv(key: str, val: str, kw: int = 22) -> None:
    key_colored = f"{CYAN}{key}{NC}"
    key_pad = kw - _wlen(key_colored)
    _box_row(f"  {key_colored}{' ' * max(0, key_pad)}  {val}")

def _box_link(link: str, color: str = "") -> None:
    color = color or YELLOW
    indent = "  "
    max_w = _BOX_W - 2
    plain_link = _plain(link)
    i = 0
    while i < len(plain_link):
        chunk = plain_link[i:i + max_w]
        pad = max(0, max_w - len(chunk))
        print(f"{CYAN}║{NC}{indent}{color}{chunk}{NC}{' ' * pad}{CYAN}║{NC}")
        i += max_w


def _print_link_full(link: str, color: str = "") -> None:
    """
    Выводит длинную ссылку полностью за пределами box-рамки.
    Используется для turnable:// и vless:// ссылок которые не влезают в box.
    """
    color = color or YELLOW
    plain_link = _plain(link)
    # Получаем ширину терминала, fallback 120
    try:
        term_w = os.get_terminal_size().columns
    except Exception:
        term_w = 120
    chunk_w = max(66, term_w - 2)
    i = 0
    while i < len(plain_link):
        chunk = plain_link[i:i + chunk_w]
        print(f"{color}{chunk}{NC}")
        i += chunk_w

# ══════════════════════════════════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНЫЕ
# ══════════════════════════════════════════════════════════════════════════════
def _run(cmd: list, capture: bool = False, check: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    else:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

def _log(msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            f.write(_plain(msg) + "\n")
    except Exception:
        pass

def _ok(msg: str)   -> None: print(f"  {GREEN}✓{NC}  {msg}"); _log(f"[OK] {msg}")
def _warn(msg: str) -> None: print(f"  {YELLOW}⚠{NC}  {msg}"); _log(f"[WARN] {msg}")
def _info(msg: str) -> None: print(f"  {CYAN}→{NC}  {msg}"); _log(f"[INFO] {msg}")
def _err(msg: str)  -> None: print(f"  {RED}✗{NC}  {msg}"); _log(f"[ERR] {msg}")

def _pause() -> None:
    try:
        print(f"\n  {DIM}Нажмите Enter...{NC}", end="", flush=True)
        input()
    except (KeyboardInterrupt, EOFError, UnicodeDecodeError):
        print()

def _is_amd64() -> bool:
    return platform.machine().lower() in ("x86_64", "amd64")

def _gen_uuid() -> str:
    return str(uuid.uuid4())

# ══════════════════════════════════════════════════════════════════════════════
#  STATE
# ══════════════════════════════════════════════════════════════════════════════
# State load/save, prompt, iptables-persist helpers are imported from
# chimera.modules.proto_common (see top of file). Call sites use
# proto_load_state / proto_save_state / proto_ask / proto_ipt_persist directly.

def _is_installed() -> bool:
    if not _BIN_PATH.exists() or not _SERVICE_FILE.exists():
        return False
    return proto_load_state(_MODULE_STATE).get("installed", False)

# ══════════════════════════════════════════════════════════════════════════════
#  XRAY CONFIG
# ══════════════════════════════════════════════════════════════════════════════
def _xray_config_path() -> Optional[Path]:
    for p in _XRAY_CONFIG_PATHS:
        if p.exists():
            return p
    return None

def _xray_has_turnable_inbound(cfg: dict) -> bool:
    return any(ib.get("tag") == _XRAY_INBOUND_TAG for ib in cfg.get("inbounds", []))

def _xray_inject_inbound(cfg: dict, port: int, vless_uuid: str) -> bool:
    """
    Добавляет VLESS-inbound для Turnable на 127.0.0.1:port (plain TCP, без TLS).
    Основной VLESS/REALITY inbound не затрагивается.
    """
    if _xray_has_turnable_inbound(cfg):
        return False
    inbound = {
        "tag":      _XRAY_INBOUND_TAG,
        "port":     port,
        "listen":   "127.0.0.1",
        "protocol": "vless",
        "settings": {
            "clients": [{"id": vless_uuid, "email": "wireturn@turnable"}],
            "decryption": "none",
        },
        "sniffing": {
            "enabled":      True,
            "destOverride": ["http", "tls"],
            "metadataOnly": False,
            "routeOnly":    False,
        },
        "streamSettings": {
            "network":  "tcp",
            "security": "none",
        },
    }
    cfg.setdefault("inbounds", []).append(inbound)
    return True

def _xray_remove_inbound(cfg: dict) -> bool:
    inbounds = cfg.get("inbounds", [])
    new_ib = [ib for ib in inbounds if ib.get("tag") != _XRAY_INBOUND_TAG]
    if len(new_ib) == len(inbounds):
        return False
    cfg["inbounds"] = new_ib
    return True

def _xray_write_and_test(cfg_path: Path, cfg: dict) -> Optional[str]:
    backup = cfg_path.read_text()
    try:
        cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
        cfg_path.chmod(0o640)
    except Exception as e:
        return f"Не удалось записать {cfg_path}: {e}"
    xray_bin = shutil.which("xray") or "/usr/local/bin/xray"
    if Path(xray_bin).exists():
        r = _run([xray_bin, "run", "-test", "-config", str(cfg_path)], capture=True)
        if r.returncode != 0:
            cfg_path.write_text(backup)
            return f"xray -test провалился: {(r.stderr or r.stdout)[:300]}"
    return None

# ══════════════════════════════════════════════════════════════════════════════
#  IPTABLES
# ══════════════════════════════════════════════════════════════════════════════
# _ipt_rule_exists — вынесен в proto_common (proto_ipt_rule_exists).
def _ipt_rule_exists(port: int) -> bool:
    return proto_ipt_rule_exists("filter", "INPUT", ["-p", "udp", "--dport", str(port), "-j", "ACCEPT"])

def _ipt_open_udp(port: int) -> bool:
    if _ipt_rule_exists(port):
        return True
    r = _run(
        ["iptables", "-t", "filter", "-I", "INPUT", "1",
         "-p", "udp", "--dport", str(port), "-j", "ACCEPT"],
        capture=True,
    )
    return r.returncode == 0

def _ipt_close_udp(port: int) -> None:
    for _ in range(5):
        if not _ipt_rule_exists(port):
            break
        _run(
            ["iptables", "-t", "filter", "-D", "INPUT",
             "-p", "udp", "--dport", str(port), "-j", "ACCEPT"],
            capture=True,
        )

# _ipt_persist — вынесен в proto_common (использует subprocess.run напрямую,
# не зависит от module-local _run). Call sites: proto_ipt_persist.

# ══════════════════════════════════════════════════════════════════════════════
#  БИНАРНИК
# ══════════════════════════════════════════════════════════════════════════════
# _get_latest_version — вынесен в proto_common. Turnable's GitHub release
# tags have no leading 'v' prefix → strip_v=False (default) at call sites.
def _download_binary() -> bool:
    """Скачивает turnable binary через download_manager.fetch_package().

    МИГРАЦИЯ: раньше использовался urllib.request.urlretrieve() с ОДНИМ прямым
    URL (https://github.com/TheAirBlow/Turnable/releases/download/
    {0.4.1}/turnable-linux-amd64) БЕЗ зеркал, БЕЗ fallback, БЕЗ проверки
    ручного размещения.

    Теперь используется fetch_package(TURNABLE_SPEC, version=_TURNABLE_VERSION)
    из download_manager.py. fetch_package сам:
      1. Проверяет /root/turnable-linux-amd64 (manual_incoming_dir из spec) —
         если найден и размер >= min_size, использует без сети
         (WinSCP-friendly).
      2. Иначе — перебирает зеркала (turn_mirrors.get_turnable_mirrors(ver))
         по очереди через urllib, с таймаутом 15s на connect.
      3. При успехе — post_install копирует в /opt/turnable/turnable
         (chmod 0o755 + ELF magic проверка).
      4. При провале всех зеркал — print_manual_hint() с инструкцией.

    Архитектурная проверка (_is_amd64) остаётся здесь — это бизнес-логика,
    не ответственность download_manager.
    """
    if not _is_amd64():
        _err(f"Архитектура {platform.machine()} не поддерживается (только amd64).")
        return False

    # Ленивый импорт (избегает циклического импорта на module load).
    from chimera.modules.download_manager import fetch_package
    from chimera.modules.turn_packages import TURNABLE_SPEC

    _info("Скачиваю Turnable (через download_manager)...")
    ok = fetch_package(TURNABLE_SPEC, version=_TURNABLE_VERSION)
    if ok:
        _ok(f"Установлено: {_BIN_PATH}")
    return ok

def _get_installed_version() -> Optional[str]:
    # Delegated to proto_common.proto_get_installed_version.
    # Turnable binary supports `--version`, output has no leading 'v'.
    return proto_get_installed_version(_BIN_PATH, "--version")

# ══════════════════════════════════════════════════════════════════════════════
#  KEYGEN — генерация ML-KEM-768 ключей (постквантовая криптография)
# ══════════════════════════════════════════════════════════════════════════════
def _ensure_kyber_py() -> bool:
    """Устанавливает kyber-py если не установлена."""
    try:
        from kyber_py.ml_kem import ML_KEM_768  # noqa: F401
        return True
    except ImportError:
        pass
    _info("Устанавливаю kyber-py (ML-KEM-768 для Turnable)...")
    import subprocess as _sp
    r = _sp.run(
        [sys.executable, "-m", "pip", "install", "kyber-py",
         "--break-system-packages", "-q"],
        capture_output=True, text=True,
    )
    try:
        from kyber_py.ml_kem import ML_KEM_768  # noqa: F401
        _ok("kyber-py установлен.")
        return True
    except ImportError:
        _err(f"Не удалось установить kyber-py: {r.stderr[-200:]}")
        return False


def _keygen() -> Optional[tuple[str, str]]:
    """
    Генерирует пару ML-KEM-768 ключей через key_derive(seed).
    Turnable хранит 64-байтный seed как priv_key и encapsulation key как pub_key.
    seed = d(32 байта) + z(32 байта) — стандарт FIPS 203 Section 7.1.
    pub_key (ek): 1184 байта в base64 — передаётся клиенту.
    priv_key (seed): 64 байта в base64 — остаётся на сервере.
    Возвращает (priv_key, pub_key) или None при ошибке.
    """
    if not _ensure_kyber_py():
        return None
    try:
        import base64, os
        from kyber_py.ml_kem import ML_KEM_768
        seed = os.urandom(64)          # d(32) + z(32)
        ek, _ = ML_KEM_768.key_derive(seed)
        pub_b64  = base64.b64encode(ek).decode()
        priv_b64 = base64.b64encode(seed).decode()
        return priv_b64, pub_b64
    except Exception as e:
        _err(f"keygen ошибка: {e}")
        return None

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIG.JSON / STORE.JSON
# ══════════════════════════════════════════════════════════════════════════════
def _write_turnable_config(
    call_id: str,
    priv_key: str,
    pub_key: str,
    public_ip: str,
    listen_port: int,
) -> None:
    cfg = {
        "platform_id": "vk.com",
        "call_id":     call_id,
        "priv_key":    priv_key,
        "pub_key":     pub_key,
        "relay": {
            "enabled":   True,
            "proto":     "dtls",
            "cloak":     "none",
            "public_ip": public_ip,
            "port":      listen_port,
        },
        "p2p": {
            "enabled":  False,
            "username": "",
            "cloak":    "none",
        },
        "provider": {
            "type": "json",
            "path": "store.json",
        },
    }
    _CONFIG_FILE.write_text(json.dumps(cfg, indent=4, ensure_ascii=False))
    _CONFIG_FILE.chmod(0o600)

def _write_store(vless_uuid: str, xray_port: int, username: str = "wireturn") -> None:
    store = {
        "routes": [
            {
                "id":           _ROUTE_ID_VLESS,
                "address":      "127.0.0.1",
                "port":         xray_port,
                "socket":       "tcp",
                "transport":    "kcp",
                "encryption":   "handshake",
                "name":         "VLESS",
            }
        ],
        "users": [
            {
                "uuid":           vless_uuid,
                "allowed_routes": [_ROUTE_ID_VLESS],
                "username":       username,
                "type":           "relay",
                "peers":          10,
            }
        ],
    }
    _STORE_FILE.write_text(json.dumps(store, indent=4, ensure_ascii=False))
    _STORE_FILE.chmod(0o600)

# ══════════════════════════════════════════════════════════════════════════════
#  ГЕНЕРАЦИЯ turnable:// ССЫЛКИ
# ══════════════════════════════════════════════════════════════════════════════
def _generate_link(vless_uuid: str) -> Optional[str]:
    """
    Запускает 'turnable config generate <uuid> vless'.
    Возвращает turnable:// ссылку или None при ошибке.
    """
    try:
        r = subprocess.run(
            [str(_BIN_PATH), "config", "generate", vless_uuid, _ROUTE_ID_VLESS],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", cwd=str(_BIN_DIR),
        )
        out = (r.stdout or "") + (r.stderr or "")
        m = re.search(r'(turnable://\S+)', out)
        return m.group(1) if m else None
    except Exception as e:
        _err(f"Ошибка генерации ссылки: {e}")
        return None

# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEMD СЕРВИС
# ══════════════════════════════════════════════════════════════════════════════
def _install_service() -> None:
    _SERVICE_FILE.write_text(
        "[Unit]\n"
        "Description=Turnable — TURN tunnel server for WireTurn\n"
        "After=network-online.target xray.service\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"User=root\n"
        f"WorkingDirectory={_BIN_DIR}\n"
        f"ExecStart={_BIN_PATH} server\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "NoNewPrivileges=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", _SERVICE_NAME])

# ══════════════════════════════════════════════════════════════════════════════
#  QR-КОД
# ══════════════════════════════════════════════════════════════════════════════
def _show_qr_in_box(data: str, label: str) -> None:
    """Выводит QR-код внутри box-рамки. Использует qrencode или python3-qrcode."""
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}QR-код для сканирования в WireTurn:{NC}")
    _box_row(f"  {DIM}{label}{NC}")
    _box_sep()

    qrencode = shutil.which("qrencode")
    _QR_COLOR = "\033[96m"
    _QR_RESET = "\033[0m"

    if qrencode:
        try:
            proc = subprocess.run(
                [qrencode, "-t", "ANSIUTF8", "-m", "1",
                 "--foreground=00BFFF", "--background=000000",
                 "--strict-version", data],
                capture_output=True, text=True,
            )
            lines = proc.stdout.splitlines()
        except Exception:
            lines = []
        if not lines:
            try:
                proc = subprocess.run(
                    [qrencode, "-t", "ANSIUTF8", "-m", "1", data],
                    capture_output=True, text=True,
                )
                lines = proc.stdout.splitlines()
            except Exception:
                lines = []
        for line in lines:
            if _QR_COLOR not in line and "\033[" not in line:
                _box_row(f"  {_QR_COLOR}{line}{_QR_RESET}")
            else:
                _box_row(f"  {line}")
    else:
        try:
            import qrcode as _qrcode  # type: ignore
            import io as _io
            qr = _qrcode.QRCode(border=1)
            qr.add_data(data)
            qr.make(fit=True)
            buf = _io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = buf
            qr.print_ascii(invert=True)
            sys.stdout = old_stdout
            for line in buf.getvalue().splitlines():
                _box_row(f"  {_QR_COLOR}{line}{_QR_RESET}")
        except ImportError:
            _box_warn("qrencode не найден: apt install qrencode")
        except Exception as e:
            _box_warn(f"Ошибка QR: {e}")

# ══════════════════════════════════════════════════════════════════════════════
#  IP СЕРВЕРА
# ══════════════════════════════════════════════════════════════════════════════
def _get_server_ip() -> str:
    try:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        pass
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                return r.read().decode().strip()
        except Exception:
            pass
    return "ВАШ_IP"

# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС
# ══════════════════════════════════════════════════════════════════════════════
def _get_status() -> dict:
    state = proto_load_state(_MODULE_STATE)
    listen_port = state.get("listen_port", _DEFAULT_LISTEN_PORT)
    xray_port   = state.get("xray_port",   _DEFAULT_XRAY_PORT)

    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    service_ok = r.stdout.strip() == "active"

    cfg_path = _xray_config_path()
    xray_ok = False
    if cfg_path:
        try:
            cfg = json.loads(cfg_path.read_text())
            xray_ok = _xray_has_turnable_inbound(cfg)
        except Exception:
            pass

    ipt_ok = _ipt_rule_exists(listen_port)

    return {
        "installed":   state.get("installed", False),
        "service_ok":  service_ok,
        "xray_ok":     xray_ok,
        "ipt_ok":      ipt_ok,
        "listen_port": listen_port,
        "xray_port":   xray_port,
        "vless_uuid":  state.get("vless_uuid", ""),
        "pub_key":     state.get("pub_key", ""),
        "turnable_link": state.get("turnable_link", ""),
        "bin_version": _get_installed_version(),
    }

# ══════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА
# ══════════════════════════════════════════════════════════════════════════════
def _run_install() -> None:
    try:
        _run_install_inner()
    except _Cancelled:
        print(f"\n  {YELLOW}Установка прервана.{NC}\n")
        _pause()

def _run_install_inner() -> None:  # noqa: C901
    os.system("clear")
    _box_top("📲  УСТАНОВКА  •  TURNABLE  (WireTurn)")
    _box_row()

    if not _is_amd64():
        _box_err(f"Архитектура {platform.machine()} не поддерживается (только amd64).")
        _box_bot(); _pause(); return

    cfg_path = _xray_config_path()
    if not cfg_path:
        _box_err("Xray config.json не найден.")
        _box_err("Сначала установите VLESS через инсталлятор (пункт 1).")
        _box_bot(); _pause(); return

    already = _is_installed()
    if already:
        _box_warn("Обнаружена существующая установка Turnable.")
        _box_row()
        _box_item("1", "Переустановить (сохранить ключи, UUID, порты)")
        _box_item("2", f"Переустановить полностью  {YELLOW}(новые ключи и UUID){NC}")
        _box_item("0", "← Отмена")
        _box_bot(); print()
        ch = proto_ask(f"{CYAN}Выбор [1/2/0]: {NC}", default="0", c=True).strip()
        if ch == "0" or not ch:
            return
        if ch == "2":
            _full_uninstall(silent=True)

    old = proto_load_state(_MODULE_STATE)
    old_listen    = old.get("listen_port", _DEFAULT_LISTEN_PORT)
    old_xport     = old.get("xray_port",   _DEFAULT_XRAY_PORT)
    old_uuid      = old.get("vless_uuid",  "")
    old_priv      = old.get("priv_key",    "")
    old_pub       = old.get("pub_key",     "")

    # ── Порты ─────────────────────────────────────────────────────────────────
    os.system("clear")
    _box_top("📲  НАСТРОЙКА  •  TURNABLE")
    _box_row()
    _box_info("UDP-порт Turnable — на него подключается WireTurn с телефона.")
    _box_info(f"По умолчанию: {_DEFAULT_LISTEN_PORT}  (56000 зарезервирован для FreeTurn)")
    _box_row()
    _box_info("TCP-порт Xray inbound — только локально.")
    _box_info(f"По умолчанию: {_DEFAULT_XRAY_PORT}")
    _box_row()
    _box_bot(); print()

    try:
        raw = proto_ask(f"  {CYAN}UDP-порт Turnable [{old_listen}]: {NC}",
                   default=str(old_listen), c=True)
        listen_port = int(raw) if raw.isdigit() else old_listen

        raw = proto_ask(f"  {CYAN}TCP-порт Xray inbound [{old_xport}]: {NC}",
                   default=str(old_xport), c=True)
        xray_port = int(raw) if raw.isdigit() else old_xport
    except _Cancelled:
        raise

    if not (1024 <= listen_port <= 65535) or not (1024 <= xray_port <= 65535):
        _err("Порты должны быть в диапазоне 1024–65535."); _pause(); return
    if listen_port == xray_port:
        _err("UDP и TCP порты не должны совпадать."); _pause(); return

    # ── Call ID ───────────────────────────────────────────────────────────────
    os.system("clear")
    _box_top("📲  CALL ID  •  TURNABLE")
    _box_row()
    _box_info("Создайте звонок на vk.com/calls → скопируйте ссылку.")
    _box_info("Из ссылки  vk.com/call/join/ABC123...  нужна часть после /join/")
    _box_row()
    _box_info("Альтернатива — найдите публичный звонок через Google:")
    _box_link('   site:vk.com/call/join')
    _box_row()
    _box_warn("Ссылка действует вечно — не нажимайте «Завершить для всех».")
    _box_bot(); print()

    try:
        old_call = old.get("call_id", "")
        prompt = f"  {CYAN}Call ID{f' [{old_call}]' if old_call else ''}: {NC}"
        call_id = proto_ask(prompt, default=old_call, c=True).strip()
        # принимаем и полную ссылку и только ID
        m = re.search(r'/call/join/([A-Za-z0-9_\-]+)', call_id)
        if m:
            call_id = m.group(1)
        if not call_id:
            _err("Call ID не может быть пустым."); _pause(); return
    except _Cancelled:
        raise

    # ── Установка бинарника ───────────────────────────────────────────────────
    os.system("clear")
    _box_top("📲  УСТАНОВКА  •  TURNABLE")
    _box_row()

    _box_info("Загружаю Turnable...")
    if not _download_binary():
        _box_bot(); _pause(); return
    _box_ok("Бинарник установлен.")

    # ── Keygen ────────────────────────────────────────────────────────────────
    if old_priv and old_pub and already:
        priv_key, pub_key = old_priv, old_pub
        _box_info("Использую существующие ключи шифрования.")
    else:
        _box_info("Генерирую пару ключей...")
        keys = _keygen()
        if not keys:
            _box_err("Не удалось сгенерировать ключи через turnable keygen.")
            _box_bot(); _pause(); return
        priv_key, pub_key = keys
        _box_ok("Ключи сгенерированы.")

    # ── UUID ──────────────────────────────────────────────────────────────────
    vless_uuid = old_uuid if (old_uuid and already) else _gen_uuid()

    # ── Запись конфигов Turnable ──────────────────────────────────────────────
    server_ip = _get_server_ip()
    _box_info("Записываю config.json и store.json...")
    try:
        _write_turnable_config(call_id, priv_key, pub_key, server_ip, listen_port)
        _write_store(vless_uuid, xray_port)
        _box_ok("Конфиги Turnable записаны.")
    except Exception as e:
        _box_err(f"Ошибка записи конфигов: {e}")
        _box_bot(); _pause(); return

    # ── Xray inbound ─────────────────────────────────────────────────────────
    _box_info("Добавляю VLESS-inbound в Xray config.json...")
    try:
        cfg = json.loads(cfg_path.read_text())
    except Exception as e:
        _box_err(f"Не удалось прочитать xray config: {e}")
        _box_bot(); _pause(); return

    _xray_remove_inbound(cfg)
    _xray_inject_inbound(cfg, xray_port, vless_uuid)
    err = _xray_write_and_test(cfg_path, cfg)
    if err:
        _box_err(f"Xray конфиг не прошёл проверку: {err}")
        _box_err("Откат — xray config.json не изменён.")
        _box_bot(); _pause(); return
    _box_ok("VLESS-inbound добавлен в Xray.")

    _box_info("Перезапускаю Xray...")
    _run(["systemctl", "restart", "xray"])
    time.sleep(2)
    r = _run(["systemctl", "is-active", "xray"], capture=True)
    if r.stdout.strip() == "active":
        _box_ok("Xray перезапущен.")
    else:
        _box_warn("Xray может не запуститься — journalctl -u xray -n 30")

    # ── Systemd сервис ────────────────────────────────────────────────────────
    _box_info("Устанавливаю systemd-сервис turnable...")
    _install_service()
    _box_ok("Сервис создан и включён.")

    # ── iptables ──────────────────────────────────────────────────────────────
    _box_info(f"Открываю UDP-порт {listen_port} в iptables...")
    if _ipt_open_udp(listen_port):
        proto_ipt_persist()
        _box_ok(f"UDP {listen_port} открыт.")
    else:
        _box_warn(f"Не удалось открыть UDP {listen_port} в iptables.")

    # ── Запуск сервиса ────────────────────────────────────────────────────────
    _box_info("Запускаю Turnable...")
    _run(["systemctl", "start", _SERVICE_NAME])
    time.sleep(2)
    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    if r.stdout.strip() == "active":
        _box_ok("Turnable запущен.")
    else:
        _box_warn("Сервис не запустился — journalctl -u turnable -n 30")

    # ── turnable:// ссылка ────────────────────────────────────────────────────
    _box_info("Генерирую turnable:// ссылку для WireTurn...")
    turnable_link = _generate_link(vless_uuid)
    if turnable_link:
        _box_ok("Ссылка готова.")
    else:
        _box_warn("Не удалось сгенерировать ссылку — сделайте вручную:")
        _box_row(f"  {DIM}cd {_BIN_DIR} && ./turnable config generate {vless_uuid} vless{NC}")
        turnable_link = ""

    # ── Сохраняем состояние ───────────────────────────────────────────────────
    proto_save_state(_MODULE_STATE, {
        "installed":     True,
        "listen_port":   listen_port,
        "xray_port":     xray_port,
        "vless_uuid":    vless_uuid,
        "priv_key":      priv_key,
        "pub_key":       pub_key,
        "call_id":       call_id,
        "turnable_link": turnable_link,
    })

    _show_wireturn_config(
        listen_port, xray_port, vless_uuid, pub_key,
        turnable_link, server_ip, after_install=True,
    )

# ══════════════════════════════════════════════════════════════════════════════
#  ИНСТРУКЦИЯ WireTurn
# ══════════════════════════════════════════════════════════════════════════════
def _show_wireturn_config(
    listen_port: int,
    xray_port: int,
    vless_uuid: str,
    pub_key: str,
    turnable_link: str,
    server_ip: str = "",
    after_install: bool = False,
) -> None:
    if not server_ip:
        server_ip = _get_server_ip()

    vless_link = (
        f"vless://{vless_uuid}@127.0.0.1:9000"
        f"?encryption=none&security=none&type=tcp"
        f"#WireTurn-Turnable"
    )

    os.system("clear")
    title = "✅  УСТАНОВКА ЗАВЕРШЕНА" if after_install else "📱  НАСТРОЙКА WIRETURN"
    _box_top(f"{title}  •  TURNABLE")
    _box_row()
    if after_install:
        _box_ok("Turnable установлен и запущен.")
        _box_row()
    _box_kv("UDP порт (WireTurn):", f"{YELLOW}{listen_port}{NC}")
    _box_kv("TCP порт (Xray):",    f"{DIM}{xray_port} (только localhost){NC}")
    _box_kv("Публичный ключ:",     f"{YELLOW}{pub_key or '—'}{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Настройка WireTurn на Android:{NC}")
    _box_row()
    _box_info("1. Установите WireTurn:")
    _box_link("   github.com/spkprsnts/WireTurn/releases")
    _box_row()
    _box_info("2. Создайте профиль в WireTurn:")
    _box_row(f"  {DIM}  Главная → (+) → Создать профиль{NC}")
    _box_row()

    if turnable_link:
        _box_info("3. Вставьте turnable:// ссылку в поле «Импорт»:")
        _box_info("   (ссылка выведена ниже после закрытия рамки)")
        _box_info("   Или отсканируйте QR-код ниже:")
        _show_qr_in_box(turnable_link, "turnable:// ссылка для WireTurn")
    else:
        _box_warn("3. Ссылка не сгенерирована. Выполните вручную на VPS:")
        _box_row(f"  {DIM}cd {_BIN_DIR} && ./turnable config generate {vless_uuid} vless{NC}")

    _box_row()
    _box_info("4. Выберите маршрут VLESS, нажмите «Далее».")
    _box_row()
    _box_info("5. Вкладка Xray — импортируйте VLESS-ссылку:")
    _box_info("   (ссылка выведена ниже после закрытия рамки)")
    _box_info("   Или отсканируйте QR-код ниже:")
    _show_qr_in_box(vless_link, "VLESS ссылка для Xray в WireTurn")
    _box_row()
    _box_info("6. Нажмите центральную кнопку запуска в WireTurn.")
    _box_row()
    _box_sep()
    _box_info("Логи Turnable: journalctl -u turnable -f")
    _box_info("Логи Xray:     journalctl -u xray -f")
    _box_bot()

    sep = CYAN + "─" * 66 + NC
    if turnable_link:
        print("")
        print(sep)
        print(BOLD + WHITE + "turnable:// ссылка (скопируйте в WireTurn → Импорт):" + NC)
        print(sep)
        _print_link_full(turnable_link, YELLOW)

    print("")
    print(sep)
    print(BOLD + WHITE + "VLESS ссылка (скопируйте в WireTurn → Xray):" + NC)
    print(sep)
    _print_link_full(vless_link, YELLOW)
    print("")
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  УДАЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _full_uninstall(silent: bool = False) -> bool:
    if not silent:
        os.system("clear")
        _box_top("🗑️  УДАЛЕНИЕ  •  TURNABLE")
        _box_row()
        _box_warn("Будет удалено:")
        _box_row(f"  {DIM}  • Сервис  turnable{NC}")
        _box_row(f"  {DIM}  • Бинарник и конфиги  {_BIN_DIR}{NC}")
        _box_row(f"  {DIM}  • VLESS-inbound из Xray config.json{NC}")
        _box_row(f"  {DIM}  • iptables UDP-правило{NC}")
        _box_row(f"  {DIM}  • turnable.json{NC}")
        _box_row()
        _box_warn("Основной VLESS/REALITY inbound не затрагивается.")
        _box_warn("FreeTurn / vk-turn-proxy не затрагивается.")
        _box_row()
        _box_item("Y", f"{RED}Да, удалить{NC}")
        _box_item("N", "Нет, отмена")
        _box_bot(); print()
        ans = proto_ask(f"{CYAN}Подтверждение [y/N]: {NC}", c=True).strip().lower()
        if ans != "y":
            _info("Удаление отменено."); _pause(); return False

    state = proto_load_state(_MODULE_STATE)
    listen_port = state.get("listen_port", _DEFAULT_LISTEN_PORT)

    _run(["systemctl", "stop",    _SERVICE_NAME])
    _run(["systemctl", "disable", _SERVICE_NAME])
    if _SERVICE_FILE.exists():
        _SERVICE_FILE.unlink()
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "reset-failed"], capture=True)
    if not silent: _ok("Сервис остановлен и удалён.")

    try:
        if _BIN_DIR.exists():
            shutil.rmtree(_BIN_DIR)
        if not silent: _ok("Бинарник и конфиги удалены.")
    except Exception as e:
        if not silent: _warn(f"Не удалось удалить {_BIN_DIR}: {e}")

    cfg_path = _xray_config_path()
    if cfg_path:
        try:
            cfg = json.loads(cfg_path.read_text())
            if _xray_remove_inbound(cfg):
                cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
                cfg_path.chmod(0o640)
                _run(["systemctl", "restart", "xray"])
                if not silent: _ok("VLESS-inbound удалён из Xray, Xray перезапущен.")
        except Exception as e:
            if not silent: _warn(f"Не удалось обновить Xray config: {e}")

    _ipt_close_udp(listen_port)
    proto_ipt_persist()
    if not silent: _ok(f"iptables UDP {listen_port} закрыт.")

    try:
        if _MODULE_STATE.exists():
            _MODULE_STATE.unlink()
    except Exception:
        pass

    if not silent:
        _ok("Turnable полностью удалён.")
        _pause()
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  ОБНОВЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _run_update() -> None:
    os.system("clear")
    _box_top("⬆️  ОБНОВЛЕНИЕ  •  TURNABLE")
    _box_row()
    cur = _get_installed_version()
    _box_kv("Установлена:", cur or "—")
    _box_info("Проверяю последний релиз на GitHub...")
    _box_bot(); print()

    latest = proto_get_latest_version(_GITHUB_API_URL)
    os.system("clear")
    _box_top("⬆️  ОБНОВЛЕНИЕ  •  TURNABLE")
    _box_row()
    _box_kv("Установлена:", cur or "—")
    _box_kv("Последняя:",   latest)
    _box_row()

    if cur == latest and cur != "unknown":
        _box_info("Уже установлена последняя версия.")
        _box_bot(); _pause(); return

    _box_item("Y", f"Обновить до {latest}")
    _box_item("N", "← Отмена")
    _box_bot(); print()

    try:
        ans = proto_ask(f"{CYAN}Обновить? [Y/n]: {NC}", default="y", c=True).strip().lower()
    except _Cancelled:
        return
    if ans not in ("y", ""):
        return

    _run(["systemctl", "stop", _SERVICE_NAME])
    if _download_binary():
        _run(["systemctl", "start", _SERVICE_NAME])
        _ok(f"Обновлено до {latest}.")
    else:
        _err("Обновление не удалось.")
        _run(["systemctl", "start", _SERVICE_NAME])
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС / ЛОГИ
# ══════════════════════════════════════════════════════════════════════════════
def _show_status() -> None:
    os.system("clear")
    st = _get_status()
    _box_top("📊  СТАТУС  •  TURNABLE")
    _box_row()

    svc_str = (
        f"{GREEN}● активен{NC}" if st["service_ok"] else
        f"{RED}● остановлен{NC}"
    )
    _box_kv("Сервис:",       svc_str)
    _box_kv("Бинарник:",     f"{GREEN}✓ {st['bin_version']}{NC}"
                             if st["bin_version"] else f"{RED}✗ не установлен{NC}")
    _box_kv("Xray inbound:", f"{GREEN}✓ настроен{NC}"
                             if st["xray_ok"] else f"{RED}✗ отсутствует{NC}")
    _box_kv("iptables UDP:", f"{GREEN}✓ открыт{NC}"
                             if st["ipt_ok"] else f"{YELLOW}⚠ не найдено правило{NC}")
    _box_row()
    _box_kv("UDP порт:",    str(st["listen_port"]))
    _box_kv("TCP порт:",    str(st["xray_port"]))
    _box_kv("VLESS UUID:",  st["vless_uuid"] or "—")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Последние 30 строк журнала:{NC}")
    _box_row()

    r = subprocess.run(
        ["journalctl", "-u", _SERVICE_NAME, "-n", "30",
         "--no-pager", "--output=short-monotonic"],
        capture_output=True, encoding="utf-8", errors="replace",
        env={**os.environ, "LANG": "C.UTF-8"},
    )
    for line in (r.stdout or r.stderr or "Нет записей").splitlines():
        _box_row(f"  {DIM}{line[:_BOX_W - 4]}{NC}")

    _box_row(); _box_bot()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  РЕГЕНЕРАЦИЯ ССЫЛКИ
# ══════════════════════════════════════════════════════════════════════════════
def _regen_link() -> None:
    state = proto_load_state(_MODULE_STATE)
    if not state.get("installed"):
        _warn("Turnable не установлен."); _pause(); return

    _info("Генерирую новую turnable:// ссылку...")
    link = _generate_link(state.get("vless_uuid", ""))
    if link:
        state["turnable_link"] = link
        proto_save_state(_MODULE_STATE, state)
        _ok("Ссылка обновлена.")
        _show_wireturn_config(
            state.get("listen_port", _DEFAULT_LISTEN_PORT),
            state.get("xray_port",   _DEFAULT_XRAY_PORT),
            state.get("vless_uuid",  ""),
            state.get("pub_key",     ""),
            link,
        )
    else:
        _err("Не удалось сгенерировать ссылку.")
        _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ МОДУЛЯ
# ══════════════════════════════════════════════════════════════════════════════
def do_turnable_menu() -> None:
    """
    Точка входа.
    Ctrl+C внутри подменю → возврат сюда.
    Ctrl+C здесь → пробрасывается в vkturn_menu.py.
    """
    while True:
        os.system("clear")
        st = _get_status()

        svc_str = (
            f"{GREEN}● активен   {st['bin_version'] or ''}{NC}" if st["service_ok"] else
            f"{RED}● остановлен{NC}"                             if st["installed"]  else
            f"{YELLOW}● не установлен{NC}"
        )

        _box_top("TURNABLE  •  WireTurn")
        _box_row()
        _box_kv("Статус:", svc_str)

        if st["installed"]:
            ipt_col  = GREEN if st["ipt_ok"]  else YELLOW
            xray_col = GREEN if st["xray_ok"] else RED
            _box_kv("UDP порт:", str(st["listen_port"]))
            _box_kv("Xray inbound:",
                    f"{xray_col}✓ :{st['xray_port']}{NC}" if st["xray_ok"]
                    else f"{RED}✗ отсутствует{NC}")
            _box_kv("iptables UDP:",
                    f"{ipt_col}✓ открыт{NC}" if st["ipt_ok"]
                    else f"{YELLOW}⚠ не найдено правило{NC}")

        _box_row(); _box_sep()

        if not st["installed"]:
            _box_item("1", "🚀  Установить")
        else:
            _box_item("1", "🚀  Переустановить")
            _box_item("2", "📱  Показать настройки / QR для WireTurn")
            _box_item("3", "🔗  Перегенерировать turnable:// ссылку")
            _box_item("4", "🔄  Перезапустить сервис")
            _box_item("5", "⬆️   Обновить бинарник")
            _box_item("6", "📊  Статус / логи")
            _box_sep()
            _box_item("8", f"{RED}🗑️   Удалить{NC}")

        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot(); print()

        try:
            ch = proto_ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            _run_install()

        elif ch == "2" and st["installed"]:
            state = proto_load_state(_MODULE_STATE)
            _show_wireturn_config(
                state.get("listen_port",   _DEFAULT_LISTEN_PORT),
                state.get("xray_port",     _DEFAULT_XRAY_PORT),
                state.get("vless_uuid",    ""),
                state.get("pub_key",       ""),
                state.get("turnable_link", ""),
            )

        elif ch == "3" and st["installed"]:
            _regen_link()

        elif ch == "4" and st["installed"]:
            _run(["systemctl", "restart", _SERVICE_NAME])
            time.sleep(1)
            r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
            if r.stdout.strip() == "active":
                _ok("Сервис перезапущен.")
            else:
                _warn("Сервис не запустился — проверьте логи (пункт 6).")
            _pause()

        elif ch == "5" and st["installed"]:
            try:
                _run_update()
            except _Cancelled:
                pass

        elif ch == "6" and st["installed"]:
            _show_status()

        elif ch == "8" and st["installed"]:
            try:
                _full_uninstall(silent=False)
            except _Cancelled:
                _info("Удаление отменено."); _pause()

        elif ch in ("q", ""):
            break


if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}Запустите от root.{NC}"); sys.exit(1)
    try:
        do_turnable_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}"); sys.exit(0)

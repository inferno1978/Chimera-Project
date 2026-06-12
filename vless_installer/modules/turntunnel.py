"""
vless_installer/modules/turntunnel.py
───────────────────────────────────────────────────────────────────────────────
VK Turn Tunnel — проброс VLESS через TURN-серверы ВКонтакте.

Назначение:
  Позволяет Android-пользователям (WireTurn) подключаться к VPS через
  TURN-серверы ВКонтакте, обходя белые списки мобильных операторов РФ.

Схема трафика:
  Android (WireTurn)
    │  DTLS 1.2 поверх STUN ChannelData
    ▼
  TURN-серверы ВКонтакте  (трафик выглядит как медиа-звонок)
    │  UDP → VPS
    ▼
  vk-turn-proxy server  (:56000 UDP)
    │  TCP → Xray
    ▼
  Xray inbound VLESS  (127.0.0.1:порт, plain TCP, без TLS)
    │
    ▼
  Интернет

Что модуль делает:
  • Скачивает бинарник vk-turn-proxy с GitHub (только amd64)
  • Добавляет второй VLESS-inbound в config.json Xray (127.0.0.1, plain TCP)
  • Создаёт systemd-сервис vk-turn-proxy
  • Открывает входящий UDP-порт в iptables (56000 по умолчанию)
  • Генерирует UUID для нового inbound и показывает инструкцию для WireTurn
  • При удалении — чисто убирает всё перечисленное выше

Что модуль НЕ трогает:
  • Основной VLESS/REALITY inbound (config.json основной inbound)
  • Существующих пользователей и ключи
  • iptables-правила других модулей (ipban, telemt, autoban, geoip)
  • state.json (только читает install_mode и uuid для справки)
  • Любые другие службы

Точка входа из _core.py:
    from vless_installer.modules.turntunnel import do_turntunnel_menu
    do_turntunnel_menu()

Интеграция в _core.py:
  1. Добавить импорт рядом с mtproto:
       from vless_installer.modules.turntunnel import do_turntunnel_menu
  2. Добавить пункт меню в главное меню (choice == "8"):
       elif choice == "8":
           try:
               do_turntunnel_menu()
           except ImportError as _e:
               warn(f"Модуль VK Turn Tunnel не найден: {_e}")
               time.sleep(2)
  3. Добавить строку в _box_row главного меню:
       _box_row(f"  {CYAN}8{NC}  📲 {TITLE}VK Turn Tunnel{NC}")
       _box_row(f"     {DIM}Проброс VLESS через TURN ВКонтакте (Android/WireTurn){NC}")
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
from pathlib import Path
from typing import Optional

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
_BIN_PATH        = Path("/opt/vk-turn-proxy/server")
_BIN_DIR         = Path("/opt/vk-turn-proxy")
_SERVICE_FILE    = Path("/etc/systemd/system/vk-turn-proxy.service")
_SERVICE_NAME    = "vk-turn-proxy"
_LOG_FILE        = Path("/var/log/vk-turn-proxy-install.log")
_STATE_FILE      = Path("/var/lib/xray-installer/state.json")

# Порт на котором vk-turn-proxy слушает входящий UDP от WireTurn
_DEFAULT_LISTEN_PORT = 56000

# Тег и базовый порт для второго VLESS-inbound в Xray
_XRAY_INBOUND_TAG    = "vless-turn-inbound"
_DEFAULT_XRAY_PORT   = 12766

# Пути к config.json xray (проверяем оба)
_XRAY_CONFIG_PATHS = [
    Path("/etc/xray/config.json"),
    Path("/usr/local/etc/xray/config.json"),
]

# GitHub: бинарник только amd64 (arm64 не публикуется)
_GITHUB_RELEASES_URL = (
    "https://github.com/cacggghp/vk-turn-proxy/releases/latest/download/"
    "server-linux-amd64"
)
_GITHUB_API_URL = "https://api.github.com/repos/cacggghp/vk-turn-proxy/releases/latest"

_BOX_W = 66

# ══════════════════════════════════════════════════════════════════════════════
#  BOX-РЕНДЕРИНГ  (идентичен стилю остальных модулей проекта)
# ══════════════════════════════════════════════════════════════════════════════
def _plain(s: str) -> str:
    return re.sub(r'\033\[[0-9;]*m', '', s)

def _wlen(s: str) -> int:
    import unicodedata as _ud
    plain = _plain(s)
    width = 0
    chars = list(plain)
    i = 0
    while i < len(chars):
        ch = chars[i]
        cp = ord(ch)
        next_cp = ord(chars[i + 1]) if i + 1 < len(chars) else 0
        if next_cp == 0xFE0F:
            width += 2; i += 2; continue
        if cp == 0x200D or (0x300 <= cp <= 0x36F) or (0xFE00 <= cp <= 0xFE0F):
            i += 1; continue
        eaw = _ud.east_asian_width(ch)
        if eaw in ('W', 'F'):
            width += 2
        elif eaw == 'N' and (0x1F300 <= cp <= 0x1FAFF or 0x2B00 <= cp <= 0x2BFF):
            width += 2
        else:
            width += 1
        i += 1
    return width

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
    """Выводит длинную ссылку с переносом по строкам внутри box."""
    color = color or YELLOW
    # Отступ 2 символа слева
    indent = "  "
    indent_w = 2
    max_w = _BOX_W - indent_w
    plain_link = _plain(link)
    chunks = []
    i = 0
    while i < len(plain_link):
        chunks.append(plain_link[i:i + max_w])
        i += max_w
    for j, chunk in enumerate(chunks):
        pad = max(0, _BOX_W - indent_w - len(chunk))
        print(f"{CYAN}║{NC}{indent}{color}{chunk}{NC}{' ' * pad}{CYAN}║{NC}")

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

class _Cancelled(Exception):
    """Пользователь нажал Ctrl+C — возврат в вызывающее меню."""

def _pause() -> None:
    try:
        print(f"\n  {DIM}Нажмите Enter...{NC}", end="", flush=True)
        input()
    except (KeyboardInterrupt, EOFError, UnicodeDecodeError):
        print()

def _ask(prompt: str, default: str = "", c: bool = False) -> str:
    """c=True → при Ctrl+C бросает _Cancelled вместо возврата default."""
    try:
        print(prompt, end="", flush=True)
        val = input().strip()
        return val if val else default
    except (EOFError, UnicodeDecodeError):
        print(); return default
    except KeyboardInterrupt:
        print()
        if c: raise _Cancelled()
        return default

def _gen_uuid() -> str:
    return str(uuid.uuid4())

def _is_amd64() -> bool:
    return platform.machine().lower() in ("x86_64", "amd64")

# ══════════════════════════════════════════════════════════════════════════════
#  STATE.JSON — только чтение, не пишем
# ══════════════════════════════════════════════════════════════════════════════
def _read_state() -> dict:
    if not _STATE_FILE.exists():
        return {}
    try:
        return json.loads(_STATE_FILE.read_text())
    except Exception:
        return {}

def _xray_config_path() -> Optional[Path]:
    """Возвращает первый найденный config.json xray, иначе None."""
    for p in _XRAY_CONFIG_PATHS:
        if p.exists():
            return p
    return None

# ══════════════════════════════════════════════════════════════════════════════
#  КОНФИГ МОДУЛЯ — отдельный файл, не трогает state.json
# ══════════════════════════════════════════════════════════════════════════════
_MODULE_STATE_FILE = Path("/var/lib/xray-installer/turntunnel.json")

def _load_module_state() -> dict:
    """Загружает конфиг модуля. Возвращает {} если файл не существует."""
    if not _MODULE_STATE_FILE.exists():
        return {}
    try:
        return json.loads(_MODULE_STATE_FILE.read_text())
    except Exception:
        return {}

def _save_module_state(data: dict) -> None:
    """Сохраняет конфиг модуля. Не трогает state.json."""
    try:
        _MODULE_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _MODULE_STATE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        _MODULE_STATE_FILE.chmod(0o600)
    except Exception as e:
        _warn(f"Не удалось сохранить turntunnel.json: {e}")

def _is_installed() -> bool:
    """Проверяет что всё установлено: бинарник + сервис + inbound в xray."""
    if not _BIN_PATH.exists():
        return False
    if not _SERVICE_FILE.exists():
        return False
    state = _load_module_state()
    return state.get("installed", False)

# ══════════════════════════════════════════════════════════════════════════════
#  XRAY CONFIG: добавление / удаление второго VLESS-inbound
# ══════════════════════════════════════════════════════════════════════════════
def _xray_has_turn_inbound(cfg: dict) -> bool:
    return any(ib.get("tag") == _XRAY_INBOUND_TAG for ib in cfg.get("inbounds", []))

def _xray_get_turn_inbound(cfg: dict) -> Optional[dict]:
    for ib in cfg.get("inbounds", []):
        if ib.get("tag") == _XRAY_INBOUND_TAG:
            return ib
    return None

def _xray_inject_turn_inbound(cfg: dict, port: int, vless_uuid: str) -> bool:
    """
    Добавляет второй VLESS-inbound на 127.0.0.1:port (plain TCP, без TLS).
    Это единственный inbound который принимает соединения от vk-turn-proxy.
    Основной inbound (VLESS+REALITY) не затрагивается.
    Возвращает True если конфиг изменён.
    """
    if _xray_has_turn_inbound(cfg):
        return False

    inbound = {
        "tag":      _XRAY_INBOUND_TAG,
        "port":     port,
        "listen":   "127.0.0.1",       # только локально — vk-turn-proxy форвардит сюда
        "protocol": "vless",
        "settings": {
            "clients": [
                {
                    "id":    vless_uuid,
                    "email": "wireturn@localhost",
                }
            ],
            "decryption": "none",
        },
        "sniffing": {
            "enabled":      True,
            "destOverride": ["http", "tls"],
            "metadataOnly": False,
            "routeOnly":    False,
        },
        "streamSettings": {
            "network":   "tcp",
            "security":  "none",        # plain TCP — TLS терминируется на стороне TURN
        },
    }

    cfg.setdefault("inbounds", []).append(inbound)
    return True

def _xray_remove_turn_inbound(cfg: dict) -> bool:
    """Удаляет turn-inbound из конфига. Возвращает True если что-то удалено."""
    inbounds = cfg.get("inbounds", [])
    new_ib = [ib for ib in inbounds if ib.get("tag") != _XRAY_INBOUND_TAG]
    if len(new_ib) == len(inbounds):
        return False
    cfg["inbounds"] = new_ib
    return True

def _xray_write_and_test(cfg_path: Path, cfg: dict) -> Optional[str]:
    """
    Записывает конфиг и проверяет синтаксис через xray -test.
    Возвращает None при успехе, строку с ошибкой при неудаче.
    """
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
            # Откатываем
            cfg_path.write_text(backup)
            return f"xray -test провалился: {(r.stderr or r.stdout)[:300]}"
    return None

# ══════════════════════════════════════════════════════════════════════════════
#  IPTABLES: открытие / закрытие UDP-порта
# ══════════════════════════════════════════════════════════════════════════════
def _ipt_udp_rule_exists(port: int) -> bool:
    """Проверяет наличие правила ACCEPT для входящего UDP на данный порт."""
    r = _run(
        ["iptables", "-t", "filter", "-C", "INPUT",
         "-p", "udp", "--dport", str(port), "-j", "ACCEPT"],
        capture=True,
    )
    return r.returncode == 0

def _ipt_open_udp(port: int) -> bool:
    """Открывает входящий UDP порт. Идемпотентно. Возвращает True при успехе."""
    if _ipt_udp_rule_exists(port):
        return True
    r = _run(
        ["iptables", "-t", "filter", "-I", "INPUT", "1",
         "-p", "udp", "--dport", str(port), "-j", "ACCEPT"],
        capture=True,
    )
    return r.returncode == 0

def _ipt_close_udp(port: int) -> None:
    """Закрывает UDP порт. Идемпотентно — удаляет все копии правила."""
    for _ in range(5):
        if not _ipt_udp_rule_exists(port):
            break
        _run(
            ["iptables", "-t", "filter", "-D", "INPUT",
             "-p", "udp", "--dport", str(port), "-j", "ACCEPT"],
            capture=True,
        )

def _ipt_persist() -> None:
    """Сохраняет iptables-правила для выживания после ребута."""
    if shutil.which("netfilter-persistent"):
        _run(["netfilter-persistent", "save"], capture=True)
        return
    rules_dir = Path("/etc/iptables")
    rules_dir.mkdir(parents=True, exist_ok=True)
    r4 = _run(["iptables-save"], capture=True)
    if r4.returncode == 0 and r4.stdout:
        (rules_dir / "rules.v4").write_text(r4.stdout)

# ══════════════════════════════════════════════════════════════════════════════
#  БИНАРНИК vk-turn-proxy
# ══════════════════════════════════════════════════════════════════════════════
def _get_latest_version() -> str:
    """Получает тег последнего релиза с GitHub."""
    try:
        req = urllib.request.Request(
            _GITHUB_API_URL,
            headers={"User-Agent": "VLESS-Ultimate-Installer"},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        return data.get("tag_name", "unknown")
    except Exception:
        return "unknown"

def _download_binary() -> bool:
    """
    Скачивает бинарник vk-turn-proxy.
    Поддерживается только amd64 — проверяем архитектуру заранее.
    """
    if not _is_amd64():
        _err("vk-turn-proxy доступен только для amd64 (x86_64).")
        _err(f"Текущая архитектура: {platform.machine()}")
        return False

    _BIN_DIR.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp())
    tmp_bin = tmp / "server"

    try:
        _info(f"Скачиваю vk-turn-proxy с GitHub...")
        urllib.request.urlretrieve(_GITHUB_RELEASES_URL, str(tmp_bin))
        tmp_bin.chmod(0o755)

        # Проверяем что это ELF-бинарник а не страница ошибки
        with tmp_bin.open("rb") as f:
            magic = f.read(4)
        if magic != b'\x7fELF':
            _err("Скачанный файл не является ELF-бинарником.")
            _err("Возможно GitHub недоступен или изменился URL релиза.")
            return False

        shutil.copy2(str(tmp_bin), str(_BIN_PATH))
        _BIN_PATH.chmod(0o755)
        _ok(f"Установлено: {_BIN_PATH}")
        return True

    except Exception as e:
        _err(f"Ошибка загрузки: {e}")
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def _get_installed_version() -> Optional[str]:
    """Возвращает версию установленного бинарника или None."""
    if not _BIN_PATH.exists():
        return None
    r = _run([str(_BIN_PATH), "-version"], capture=True)
    out = (r.stdout or "") + (r.stderr or "")
    m = re.search(r'(\d+\.\d+[\.\d]*)', out)
    return m.group(1) if m else "unknown"

# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEMD СЕРВИС
# ══════════════════════════════════════════════════════════════════════════════
def _install_service(listen_port: int, xray_port: int) -> None:
    """
    Создаёт systemd-сервис vk-turn-proxy.
    After=xray.service — гарантирует что xray уже слушает на xray_port
    при старте vk-turn-proxy.
    """
    _SERVICE_FILE.write_text(
        "[Unit]\n"
        "Description=VK Turn Proxy — TURN tunnel to Xray VLESS\n"
        "After=network-online.target xray.service\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"WorkingDirectory={_BIN_DIR}\n"
        f"ExecStart={_BIN_PATH} "
        f"-listen 0.0.0.0:{listen_port} "
        f"-connect 127.0.0.1:{xray_port} "
        f"-vless\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "NoNewPrivileges=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", _SERVICE_NAME])

def _update_service_ports(listen_port: int, xray_port: int) -> None:
    """Обновляет порты в существующем сервисе без переустановки."""
    _install_service(listen_port, xray_port)

# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС
# ══════════════════════════════════════════════════════════════════════════════
def _get_status() -> dict:
    """
    Возвращает полный статус модуля:
      installed     – bool
      service_ok    – bool (сервис active)
      xray_ok       – bool (inbound в config.json)
      ipt_ok        – bool (UDP порт открыт)
      listen_port   – int
      xray_port     – int
      vless_uuid    – str
      bin_version   – str или None
    """
    state = _load_module_state()
    listen_port = state.get("listen_port", _DEFAULT_LISTEN_PORT)
    xray_port   = state.get("xray_port",   _DEFAULT_XRAY_PORT)
    vless_uuid  = state.get("vless_uuid",  "")

    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    service_ok = r.stdout.strip() == "active"

    cfg_path = _xray_config_path()
    xray_ok = False
    if cfg_path:
        try:
            cfg = json.loads(cfg_path.read_text())
            xray_ok = _xray_has_turn_inbound(cfg)
        except Exception:
            pass

    ipt_ok = _ipt_udp_rule_exists(listen_port)

    return {
        "installed":   state.get("installed", False),
        "service_ok":  service_ok,
        "xray_ok":     xray_ok,
        "ipt_ok":      ipt_ok,
        "listen_port": listen_port,
        "xray_port":   xray_port,
        "vless_uuid":  vless_uuid,
        "bin_version": _get_installed_version(),
    }

def _get_server_ip() -> str:
    """Определяет публичный IPv4 сервера."""
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
#  УСТАНОВКА
# ══════════════════════════════════════════════════════════════════════════════
def _run_install() -> None:
    """Полная установка vk-turn-proxy. Перехватывает _Cancelled."""
    try:
        _run_install_inner()
    except _Cancelled:
        print(f"\n  {YELLOW}Установка прервана — возврат в меню.{NC}\n")
        _pause()

def _run_install_inner() -> None:
    os.system("clear")
    _box_top("📲  УСТАНОВКА  •  VK TURN TUNNEL")
    _box_row()

    # ── Проверка архитектуры ──────────────────────────────────────────────────
    if not _is_amd64():
        _box_err(f"Архитектура {platform.machine()} не поддерживается.")
        _box_err("vk-turn-proxy распространяется только для amd64 (x86_64).")
        _box_bot(); _pause(); return

    # ── Проверка что xray установлен ─────────────────────────────────────────
    cfg_path = _xray_config_path()
    if not cfg_path:
        _box_err("Xray config.json не найден.")
        _box_err("Сначала установите xray через VLESS Ultimate (пункт 1).")
        _box_bot(); _pause(); return

    # ── Уже установлено? ─────────────────────────────────────────────────────
    already = _is_installed()
    if already:
        _box_warn("Обнаружена существующая установка VK Turn Tunnel.")
        _box_row()
        _box_item("1", "Переустановить (сохранить UUID и порты)")
        _box_item("2", f"Переустановить полностью  {YELLOW}(новый UUID){NC}")
        _box_item("0", "← Отмена")
        _box_bot(); print()
        ch = _ask(f"{CYAN}Выбор [1/2/0]: {NC}", default="0", c=True).strip()
        if ch == "0" or not ch:
            return
        if ch == "2":
            _full_uninstall(silent=True)
        # ch == "1" → продолжаем с существующим UUID и портами

    # ── Порты ─────────────────────────────────────────────────────────────────
    old_state   = _load_module_state()
    old_listen  = old_state.get("listen_port", _DEFAULT_LISTEN_PORT)
    old_xport   = old_state.get("xray_port",   _DEFAULT_XRAY_PORT)

    os.system("clear")
    _box_top("📲  ПОРТЫ  •  VK TURN TUNNEL")
    _box_row()
    _box_info("Порт vk-turn-proxy (UDP) — на него подключается WireTurn с телефона.")
    _box_info(f"По умолчанию: {_DEFAULT_LISTEN_PORT}")
    _box_row()
    _box_info("Порт Xray inbound (TCP, только локально) — plain VLESS без TLS.")
    _box_info(f"По умолчанию: {_DEFAULT_XRAY_PORT}")
    _box_row()
    _box_warn("Убедитесь что оба порта не заняты другими службами.")
    _box_bot(); print()

    try:
        raw = _ask(
            f"  {CYAN}UDP-порт vk-turn-proxy [{old_listen}]: {NC}",
            default=str(old_listen), c=True,
        )
        listen_port = int(raw) if raw.isdigit() else old_listen

        raw = _ask(
            f"  {CYAN}TCP-порт Xray inbound  [{old_xport}]: {NC}",
            default=str(old_xport), c=True,
        )
        xray_port = int(raw) if raw.isdigit() else old_xport
    except _Cancelled:
        raise
    except Exception:
        listen_port = old_listen
        xray_port   = old_xport

    if not (1024 <= listen_port <= 65535) or not (1024 <= xray_port <= 65535):
        _err("Порты должны быть в диапазоне 1024–65535."); _pause(); return
    if listen_port == xray_port:
        _err("UDP и TCP порты не должны совпадать."); _pause(); return

    # ── UUID ──────────────────────────────────────────────────────────────────
    vless_uuid = old_state.get("vless_uuid", "") or _gen_uuid()

    # ── Установка ─────────────────────────────────────────────────────────────
    os.system("clear")
    _box_top("📲  УСТАНОВКА  •  VK TURN TUNNEL")
    _box_row()

    # 1. Бинарник
    _box_info("Загружаю vk-turn-proxy...")
    if not _download_binary():
        _box_bot(); _pause(); return
    _box_ok("Бинарник установлен.")

    # 2. Xray inbound
    _box_info("Добавляю VLESS-inbound в Xray config.json...")
    try:
        cfg = json.loads(cfg_path.read_text())
    except Exception as e:
        _box_err(f"Не удалось прочитать xray config: {e}")
        _box_bot(); _pause(); return

    # Если inbound уже есть — удалим перед добавлением чтобы обновить порт/UUID
    _xray_remove_turn_inbound(cfg)
    _xray_inject_turn_inbound(cfg, xray_port, vless_uuid)
    err = _xray_write_and_test(cfg_path, cfg)
    if err:
        _box_err(f"Xray конфиг не прошёл проверку: {err}")
        _box_err("Откат — xray config.json не изменён.")
        _box_bot(); _pause(); return
    _box_ok("VLESS-inbound добавлен в xray config.json.")

    # 3. Перезапуск xray
    _box_info("Перезапускаю xray...")
    _run(["systemctl", "restart", "xray"])
    time.sleep(2)
    r = _run(["systemctl", "is-active", "xray"], capture=True)
    if r.stdout.strip() == "active":
        _box_ok("xray перезапущен успешно.")
    else:
        _box_warn("xray может не запуститься — проверьте: journalctl -u xray -n 30")

    # 4. Systemd-сервис
    _box_info("Устанавливаю systemd-сервис vk-turn-proxy...")
    _install_service(listen_port, xray_port)
    _box_ok("Сервис создан и включён.")

    # 5. iptables UDP
    _box_info(f"Открываю UDP-порт {listen_port} в iptables...")
    if _ipt_open_udp(listen_port):
        _ipt_persist()
        _box_ok(f"UDP {listen_port} открыт.")
    else:
        _box_warn(f"Не удалось открыть UDP {listen_port} в iptables.")
        _box_warn("Откройте порт вручную или через панель хостера.")

    # 6. Запуск сервиса
    _box_info("Запускаю vk-turn-proxy...")
    _run(["systemctl", "start", _SERVICE_NAME])
    time.sleep(2)
    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    if r.stdout.strip() == "active":
        _box_ok("vk-turn-proxy запущен.")
    else:
        _box_warn("Сервис не запустился — проверьте: journalctl -u vk-turn-proxy -n 30")

    # 7. Сохраняем состояние модуля
    _save_module_state({
        "installed":   True,
        "listen_port": listen_port,
        "xray_port":   xray_port,
        "vless_uuid":  vless_uuid,
    })

    # ── Итог ──────────────────────────────────────────────────────────────────
    server_ip = _get_server_ip()
    os.system("clear")
    _box_top("✅  УСТАНОВКА ЗАВЕРШЕНА  •  VK TURN TUNNEL")
    _box_row()
    _box_ok("vk-turn-proxy установлен и запущен.")
    _box_row()
    _box_kv("UDP порт (WireTurn):", f"{YELLOW}{listen_port}{NC}")
    _box_kv("TCP порт (Xray):",    f"{DIM}{xray_port} (только localhost){NC}")
    _box_kv("VLESS UUID:",          f"{YELLOW}{vless_uuid}{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Настройка WireTurn на Android:{NC}")
    _box_row()
    _box_info("1. Скачайте WireTurn: github.com/spkprsnts/WireTurn")
    _box_info("2. Создайте звонок ВКонтакте, скопируйте ссылку-приглашение")
    _box_info("3. В WireTurn → вкладка Клиент:")
    _box_kv("   Сервер:", f"{server_ip}:{listen_port}")
    _box_info("   Ссылка на звонок: вставьте ссылку vk.com/call/join/...")
    _box_info("4. Вкладка Xray → импортируйте VLESS-ссылку:")
    _box_row()
    _vless_link = (
        f"vless://{vless_uuid}@127.0.0.1:9000"
        f"?encryption=none&security=none&type=tcp"
        f"#WireTurn"
    )
    _box_link(_vless_link)
    _box_row()
    _box_info("5. В WireTurn → Главная → запустите туннель")
    _box_row()
    _box_sep()
    _box_info("Ссылка на звонок действует вечно пока вы не завершите звонок.")
    _box_info("Команда для просмотра логов:")
    _box_row(f"  {DIM}journalctl -u vk-turn-proxy -f{NC}")
    _box_bot()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ПОЛНОЕ УДАЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _full_uninstall(silent: bool = False) -> bool:
    if not silent:
        os.system("clear")
        _box_top("🗑️  УДАЛЕНИЕ  •  VK TURN TUNNEL")
        _box_row()
        _box_warn("Будет удалено:")
        _box_row(f"  {DIM}  • Сервис systemd  (vk-turn-proxy){NC}")
        _box_row(f"  {DIM}  • Бинарник        ({_BIN_PATH}){NC}")
        _box_row(f"  {DIM}  • VLESS-inbound   (xray config.json){NC}")
        _box_row(f"  {DIM}  • iptables UDP-правило{NC}")
        _box_row(f"  {DIM}  • turntunnel.json{NC}")
        _box_row()
        _box_warn("Основной VLESS/REALITY inbound не затрагивается.")
        _box_row()
        _box_sep()
        _box_item("Y", f"{RED}Да, удалить{NC}")
        _box_item("N", "Нет, отмена")
        _box_bot(); print()
        ans = _ask(f"{CYAN}Подтверждение [y/N]: {NC}", c=True).strip().lower()
        if ans != "y":
            _info("Удаление отменено."); _pause(); return False

    state = _load_module_state()
    listen_port = state.get("listen_port", _DEFAULT_LISTEN_PORT)

    # 1. Останавливаем сервис
    _run(["systemctl", "stop", _SERVICE_NAME])
    _run(["systemctl", "disable", _SERVICE_NAME])
    if _SERVICE_FILE.exists():
        _SERVICE_FILE.unlink()
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "reset-failed"], capture=True)
    if not silent: _ok("Сервис остановлен и удалён.")

    # 2. Бинарник
    try:
        if _BIN_DIR.exists():
            shutil.rmtree(_BIN_DIR)
        if not silent: _ok("Бинарник удалён.")
    except Exception as e:
        if not silent: _warn(f"Не удалось удалить {_BIN_DIR}: {e}")

    # 3. Xray inbound
    cfg_path = _xray_config_path()
    if cfg_path:
        try:
            cfg = json.loads(cfg_path.read_text())
            if _xray_remove_turn_inbound(cfg):
                cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
                cfg_path.chmod(0o640)
                _run(["systemctl", "restart", "xray"])
                if not silent: _ok("VLESS-inbound удалён из xray config.json, xray перезапущен.")
            else:
                if not silent: _info("Turn-inbound в xray config не обнаружен — пропуск.")
        except Exception as e:
            if not silent: _warn(f"Не удалось обновить xray config: {e}")

    # 4. iptables
    _ipt_close_udp(listen_port)
    _ipt_persist()
    if not silent: _ok(f"iptables UDP {listen_port} закрыт.")

    # 5. Файл состояния модуля
    try:
        if _MODULE_STATE_FILE.exists():
            _MODULE_STATE_FILE.unlink()
    except Exception:
        pass

    if not silent:
        _ok("VK Turn Tunnel полностью удалён.")
        _pause()
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  ОБНОВЛЕНИЕ БИНАРНИКА
# ══════════════════════════════════════════════════════════════════════════════
def _run_update() -> None:
    os.system("clear")
    _box_top("⬆️  ОБНОВЛЕНИЕ  •  VK TURN PROXY")
    _box_row()
    cur = _get_installed_version()
    _box_kv("Установлена:", cur or "—")
    _box_info("Проверяю последний релиз на GitHub...")
    _box_bot(); print()

    latest = _get_latest_version()
    os.system("clear")
    _box_top("⬆️  ОБНОВЛЕНИЕ  •  VK TURN PROXY")
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
        ans = _ask(f"{CYAN}Обновить? [Y/n]: {NC}", default="y", c=True).strip().lower()
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
#  ПОКАЗ НАСТРОЕК ДЛЯ WIRETURN
# ══════════════════════════════════════════════════════════════════════════════
def _show_wireturn_config() -> None:
    os.system("clear")
    state = _load_module_state()
    if not state.get("installed"):
        _box_top("📱  НАСТРОЙКИ ДЛЯ WIRETURN")
        _box_row()
        _box_err("VK Turn Tunnel не установлен.")
        _box_bot(); _pause(); return

    listen_port = state.get("listen_port", _DEFAULT_LISTEN_PORT)
    vless_uuid  = state.get("vless_uuid", "")
    server_ip   = _get_server_ip()

    _vless_link = (
        f"vless://{vless_uuid}@127.0.0.1:9000"
        f"?encryption=none&security=none&type=tcp"
        f"#WireTurn"
    )

    _box_top("📱  НАСТРОЙКИ ДЛЯ WIRETURN")
    _box_row()
    _box_row(f"  {BOLD}{WHITE}Вкладка Клиент:{NC}")
    _box_row()
    _box_kv("  IP:порт сервера:", f"{YELLOW}{server_ip}:{listen_port}{NC}")
    _box_kv("  Ссылка на звонок:", f"{DIM}vk.com/call/join/... (создайте в ВК){NC}")
    _box_kv("  Локальный адрес:", f"{DIM}127.0.0.1:9000{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Вкладка Xray — импортировать ссылку:{NC}")
    _box_row()
    _box_link(_vless_link)
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Порядок запуска в WireTurn:{NC}")
    _box_row()
    _box_info("1. Создайте звонок ВКонтакте, скопируйте ссылку")
    _box_info("2. Вставьте ссылку в поле «Ссылка на звонок» в WireTurn")
    _box_info("3. Нажмите кнопку запуска туннеля")
    _box_info("4. Дождитесь «DTLS connection established» в логах")
    _box_info("5. Включите Xray и VPN Mode")
    _box_row()
    _box_info("Ссылка на звонок действует вечно если не завершать звонок.")
    _box_bot()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС И ЛОГИ
# ══════════════════════════════════════════════════════════════════════════════
def _show_status() -> None:
    os.system("clear")
    st = _get_status()
    _box_top("📊  СТАТУС  •  VK TURN TUNNEL")
    _box_row()

    svc_str = (
        f"{GREEN}● активен{NC}" if st["service_ok"] else
        f"{RED}● остановлен{NC}"
    )
    _box_kv("Сервис:",       svc_str)
    _box_kv("Бинарник:",     f"{GREEN}✓ {st['bin_version']}{NC}" if st["bin_version"] else f"{RED}✗ не установлен{NC}")
    _box_kv("Xray inbound:", f"{GREEN}✓ настроен{NC}" if st["xray_ok"] else f"{RED}✗ отсутствует{NC}")
    _box_kv("iptables UDP:", f"{GREEN}✓ открыт{NC}"   if st["ipt_ok"] else f"{YELLOW}⚠ не найдено правило{NC}")
    _box_row()
    _box_kv("UDP порт:",     str(st["listen_port"]))
    _box_kv("TCP порт Xray:", str(st["xray_port"]))
    _box_kv("VLESS UUID:",   st["vless_uuid"] or "—")
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
#  СМЕНА ПОРТА
# ══════════════════════════════════════════════════════════════════════════════
def _change_port() -> None:
    state = _load_module_state()
    if not state.get("installed"):
        _warn("VK Turn Tunnel не установлен."); _pause(); return

    old_listen = state.get("listen_port", _DEFAULT_LISTEN_PORT)
    old_xport  = state.get("xray_port",   _DEFAULT_XRAY_PORT)

    os.system("clear")
    _box_top("🔌  СМЕНА ПОРТА  •  VK TURN TUNNEL")
    _box_row()
    _box_kv("Текущий UDP-порт:", str(old_listen))
    _box_kv("Текущий TCP-порт:", str(old_xport))
    _box_row()
    _box_bot(); print()

    try:
        raw = _ask(
            f"  {CYAN}Новый UDP-порт [{old_listen}]: {NC}",
            default=str(old_listen), c=True,
        )
        new_listen = int(raw) if raw.isdigit() else old_listen

        raw = _ask(
            f"  {CYAN}Новый TCP-порт Xray [{old_xport}]: {NC}",
            default=str(old_xport), c=True,
        )
        new_xport = int(raw) if raw.isdigit() else old_xport
    except _Cancelled:
        return

    if new_listen == old_listen and new_xport == old_xport:
        _info("Порты не изменились."); _pause(); return

    if not (1024 <= new_listen <= 65535) or not (1024 <= new_xport <= 65535):
        _err("Порты должны быть в диапазоне 1024–65535."); _pause(); return
    if new_listen == new_xport:
        _err("UDP и TCP порты не должны совпадать."); _pause(); return

    # Обновляем xray inbound если изменился xray_port
    if new_xport != old_xport:
        cfg_path = _xray_config_path()
        if cfg_path:
            try:
                cfg = json.loads(cfg_path.read_text())
                ib = _xray_get_turn_inbound(cfg)
                if ib:
                    ib["port"] = new_xport
                    err = _xray_write_and_test(cfg_path, cfg)
                    if err:
                        _err(f"Xray конфиг не прошёл проверку: {err}")
                        _pause(); return
                    _run(["systemctl", "restart", "xray"])
                    _ok("Xray inbound обновлён.")
            except Exception as e:
                _err(f"Не удалось обновить xray config: {e}"); _pause(); return

    # Обновляем iptables если изменился listen_port
    if new_listen != old_listen:
        _ipt_close_udp(old_listen)
        _ipt_open_udp(new_listen)
        _ipt_persist()
        _ok(f"iptables: UDP {old_listen} → {new_listen}.")

    # Обновляем сервис
    _run(["systemctl", "stop", _SERVICE_NAME])
    _update_service_ports(new_listen, new_xport)
    _run(["systemctl", "start", _SERVICE_NAME])

    state["listen_port"] = new_listen
    state["xray_port"]   = new_xport
    _save_module_state(state)

    _ok(f"Порты обновлены. UDP: {new_listen}, TCP: {new_xport}.")
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ МОДУЛЯ
# ══════════════════════════════════════════════════════════════════════════════
def do_turntunnel_menu() -> None:
    """
    Точка входа из _core.py.
    Ctrl+C внутри подменю → возврат сюда.
    Ctrl+C здесь → пробрасывается в _core.py (KeyboardInterrupt не ловим).
    """
    while True:
        os.system("clear")
        st = _get_status()

        svc_str = (
            f"{GREEN}● активен   {st['bin_version'] or ''}{NC}" if st["service_ok"] else
            f"{RED}● остановлен{NC}"                             if st["installed"]  else
            f"{YELLOW}● не установлен{NC}"
        )

        _box_top("VK TURN TUNNEL")
        _box_row()
        _box_kv("Статус:", svc_str)

        if st["installed"]:
            ipt_col = GREEN if st["ipt_ok"] else YELLOW
            xray_col = GREEN if st["xray_ok"] else RED
            _box_kv("UDP порт:", str(st["listen_port"]))
            _box_kv("Xray inbound:",
                    f"{xray_col}✓ настроен :{st['xray_port']}{NC}" if st["xray_ok"]
                    else f"{RED}✗ отсутствует{NC}")
            _box_kv("iptables UDP:",
                    f"{ipt_col}✓ открыт{NC}" if st["ipt_ok"]
                    else f"{YELLOW}⚠ не найдено правило{NC}")

        _box_row(); _box_sep()

        if not st["installed"]:
            _box_item("1", "🚀  Установить")
        else:
            _box_item("1", "🚀  Переустановить")
            _box_item("2", "📱  Показать настройки для WireTurn")
            _box_item("3", "🔌  Сменить порт")
            _box_item("4", "🔄  Перезапустить сервис")
            _box_item("5", "⬆️   Обновить бинарник")
            _box_item("6", "📊  Статус / логи")
            _box_item("L", "🔗  Менеджер ссылок ВК-звонков")
            _box_sep()
            _box_item("8", f"{RED}🗑️   Удалить{NC}")

        _box_sep()
        _box_item("Q", "← Назад в главное меню VLESS")
        _box_bot(); print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            _run_install()

        elif ch == "2" and st["installed"]:
            _show_wireturn_config()

        elif ch == "3" and st["installed"]:
            try:
                _change_port()
            except _Cancelled:
                pass

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

        elif ch == "l" and st["installed"]:
            try:
                from vless_installer.modules.turntunnel_links import do_links_menu
                do_links_menu()
            except ImportError:
                _warn("Модуль turntunnel_links не найден.")
                _pause()

        elif ch == "8" and st["installed"]:
            try:
                _full_uninstall(silent=False)
            except _Cancelled:
                _info("Удаление отменено."); _pause()

        elif ch in ("q", ""):
            break

# ══════════════════════════════════════════════════════════════════════════════
#  АВТОНОМНЫЙ ЗАПУСК (для отладки)
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}Запустите от root.{NC}"); sys.exit(1)
    try:
        do_turntunnel_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}"); sys.exit(0)

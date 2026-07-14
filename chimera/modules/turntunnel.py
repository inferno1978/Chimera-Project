"""
chimera/modules/turntunnel.py
───────────────────────────────────────────────────────────────────────────────
VK Turn Tunnel — vk-turn-proxy (cacggghp/vk-turn-proxy).

Назначение:
  Позволяет Android-пользователям (FreeTurn) подключаться к VPS через
  TURN-серверы ВКонтакте, обходя белые списки мобильных операторов РФ.
  Трафик пробрасывается напрямую к WireGuard / Hysteria2 на VPS.

Схема трафика:
  Android (FreeTurn)
    │  DTLS 1.2 поверх STUN ChannelData
    ▼
  TURN-серверы ВКонтакте  (трафик выглядит как медиа-звонок)
    │  UDP → VPS
    ▼
  vk-turn-proxy server  (:56000 UDP)
    │  UDP → WireGuard / Hysteria2
    ▼
  Интернет

Что модуль делает:
  • Скачивает бинарник vk-turn-proxy с GitHub (только amd64)
  • Создаёт systemd-сервис vk-turn-proxy
  • Открывает входящий UDP-порт в iptables (56000 по умолчанию)
  • Генерирует инструкцию для FreeTurn
  • При удалении — чисто убирает всё перечисленное выше

Что модуль НЕ трогает:
  • config.json Xray (в отличие от предыдущей реализации — Xray здесь не нужен)
  • Основной VLESS/REALITY inbound
  • Существующих пользователей и ключи
  • iptables-правила других модулей
  • state.json (только читает для определения IP/режима)

Клиентское приложение:
  FreeTurn (samosvalishe/turn-proxy-android)
  github.com/samosvalishe/turn-proxy-android

Точка входа:
    from chimera.modules.turntunnel import do_turntunnel_menu
    do_turntunnel_menu()
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
_BIN_PATH        = Path("/opt/vk-turn-proxy/server")
_BIN_DIR         = Path("/opt/vk-turn-proxy")
_SERVICE_FILE    = Path("/etc/systemd/system/vk-turn-proxy.service")
_SERVICE_NAME    = "vk-turn-proxy"
_LOG_FILE        = Path("/var/log/vk-turn-proxy-install.log")
_STATE_FILE      = Path("/var/lib/xray-installer/state.json")
_MODULE_STATE    = Path("/var/lib/xray-installer/turntunnel.json")

_DEFAULT_LISTEN_PORT = 56000   # UDP — порт на который подключается FreeTurn
_DEFAULT_TARGET_PORT = 51820   # порт WireGuard / Hysteria2 на VPS (редактируется)

# _GITHUB_RELEASES_URL — удалён при миграции на download_manager.
# Теперь зеркала (jsDelivr CDN + raw GitHub + release GitHub + 7 gh-proxy +
# Statically) собираются в turn_mirrors.get_turntunnel_mirrors() и
# перебираются автоматически через fetch_package(TURNTUNNEL_SPEC).
_GITHUB_API_URL = "https://api.github.com/repos/cacggghp/vk-turn-proxy/releases/latest"

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

# _Cancelled was a local Exception subclass; it is now an alias for
# proto_common.ProtoCancelled (see the `_Cancelled = ProtoCancelled` line
# near the top of this file). proto_ask raises ProtoCancelled, and existing
# `except _Cancelled:` / `raise _Cancelled` code keeps working unchanged.

def _pause() -> None:
    try:
        print(f"\n  {DIM}Нажмите Enter...{NC}", end="", flush=True)
        input()
    except (KeyboardInterrupt, EOFError, UnicodeDecodeError):
        print()

# _ask — вынесен в proto_common (proto_ask).

def _is_amd64() -> bool:
    return platform.machine().lower() in ("x86_64", "amd64")

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
# _get_latest_version — вынесен в proto_common. vk-turn-proxy's GitHub
# release tags have no leading 'v' → strip_v=False (default) at call sites.
# _get_installed_version — also in proto_common; vk-turn-proxy uses the
# `-version` flag (single dash). Call sites use proto_get_installed_version.

def _download_binary() -> bool:
    """Скачивает vk-turn-proxy binary через download_manager.fetch_package().

    МИГРАЦИЯ: раньше использовался urllib.request.urlretrieve() с ОДНИМ прямым
    URL (https://github.com/cacggghp/vk-turn-proxy/releases/latest/download/
    server-linux-amd64) БЕЗ зеркал, БЕЗ fallback, БЕЗ проверки ручного
    размещения.

    Теперь используется fetch_package(TURNTUNNEL_SPEC) из download_manager.py.
    fetch_package сам:
      1. Проверяет /root/server-linux-amd64 (manual_incoming_dir из spec) —
         если найден и размер >= min_size, использует без сети
         (WinSCP-friendly).
      2. Иначе — перебирает зеркала (turn_mirrors.get_turntunnel_mirrors())
         по очереди через urllib, с таймаутом 15s на connect.
      3. При успехе — post_install копирует в /opt/vk-turn-proxy/server
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
    from chimera.modules.turn_packages import TURNTUNNEL_SPEC

    _info("Скачиваю vk-turn-proxy (через download_manager)...")
    ok = fetch_package(TURNTUNNEL_SPEC)
    if ok:
        _ok(f"Установлено: {_BIN_PATH}")
    return ok

# _get_installed_version — вынесен в proto_common. vk-turn-proxy binary
# uses single-dash `-version` flag, output has no leading 'v' prefix.
# Call sites use proto_get_installed_version(_BIN_PATH, "-version").

# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEMD СЕРВИС
# ══════════════════════════════════════════════════════════════════════════════
def _install_service(listen_port: int, target_port: int, target_proto: str) -> None:
    """
    Создаёт systemd-сервис vk-turn-proxy.
    target_proto: 'udp' для WireGuard, 'tcp' для Hysteria2 (если поддержит).
    В обычном режиме vk-turn-proxy форвардит UDP → target_port без флага -vless.
    """
    _SERVICE_FILE.write_text(
        "[Unit]\n"
        "Description=VK Turn Proxy — TURN tunnel to WireGuard/Hysteria2\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"WorkingDirectory={_BIN_DIR}\n"
        f"ExecStart={_BIN_PATH} "
        f"-listen 0.0.0.0:{listen_port} "
        f"-connect 127.0.0.1:{target_port}\n"
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
    _box_row(f"  {BOLD}{WHITE}QR-код для сканирования в FreeTurn:{NC}")
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
        # fallback: python3-qrcode
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
    target_port = state.get("target_port", _DEFAULT_TARGET_PORT)

    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    service_ok = r.stdout.strip() == "active"
    ipt_ok = _ipt_rule_exists(listen_port)

    return {
        "installed":   state.get("installed", False),
        "service_ok":  service_ok,
        "ipt_ok":      ipt_ok,
        "listen_port": listen_port,
        "target_port": target_port,
        "target_type": state.get("target_type", "wireguard"),
        "bin_version": proto_get_installed_version(_BIN_PATH, "-version"),
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

def _run_install_inner() -> None:
    os.system("clear")
    _box_top("📲  УСТАНОВКА  •  VK TURN PROXY  (FreeTurn)")
    _box_row()

    if not _is_amd64():
        _box_err(f"Архитектура {platform.machine()} не поддерживается.")
        _box_bot(); _pause(); return

    already = _is_installed()
    if already:
        _box_warn("Обнаружена существующая установка.")
        _box_row()
        _box_item("1", "Переустановить (сохранить порты)")
        _box_item("2", f"Переустановить полностью")
        _box_item("0", "← Отмена")
        _box_bot(); print()
        ch = proto_ask(f"{CYAN}Выбор [1/2/0]: {NC}", default="0", c=True).strip()
        if ch == "0" or not ch:
            return
        if ch == "2":
            _full_uninstall(silent=True)

    old = proto_load_state(_MODULE_STATE)
    old_listen  = old.get("listen_port", _DEFAULT_LISTEN_PORT)
    old_target  = old.get("target_port", _DEFAULT_TARGET_PORT)
    old_ttype   = old.get("target_type", "wireguard")

    os.system("clear")
    _box_top("📲  НАСТРОЙКА ПОРТОВ  •  VK TURN PROXY")
    _box_row()
    _box_info("UDP-порт vk-turn-proxy — на него подключается FreeTurn с телефона.")
    _box_info(f"По умолчанию: {_DEFAULT_LISTEN_PORT}")
    _box_row()
    _box_info("Целевой порт — локальный WireGuard или Hysteria2 на этом VPS.")
    _box_info(f"По умолчанию: {_DEFAULT_TARGET_PORT} (WireGuard)")
    _box_row()
    _box_item("1", "WireGuard (UDP)")
    _box_item("2", "Hysteria2  (UDP)")
    _box_bot(); print()

    try:
        raw = proto_ask(f"  {CYAN}UDP-порт vk-turn-proxy [{old_listen}]: {NC}",
                   default=str(old_listen), c=True)
        listen_port = int(raw) if raw.isdigit() else old_listen

        ttype_ch = proto_ask(f"  {CYAN}Целевой сервис [1=WG/2=H2, Enter={old_ttype}]: {NC}",
                        default="", c=True).strip()
        target_type = "hysteria2" if ttype_ch == "2" else (
            "wireguard" if ttype_ch == "1" else old_ttype
        )

        raw = proto_ask(f"  {CYAN}Целевой порт [{old_target}]: {NC}",
                   default=str(old_target), c=True)
        target_port = int(raw) if raw.isdigit() else old_target
    except _Cancelled:
        raise

    if not (1024 <= listen_port <= 65535) or not (1024 <= target_port <= 65535):
        _err("Порты должны быть в диапазоне 1024–65535."); _pause(); return
    if listen_port == target_port:
        _err("UDP и целевой порты не должны совпадать."); _pause(); return

    os.system("clear")
    _box_top("📲  УСТАНОВКА  •  VK TURN PROXY  (FreeTurn)")
    _box_row()

    _box_info("Загружаю vk-turn-proxy...")
    if not _download_binary():
        _box_bot(); _pause(); return
    _box_ok("Бинарник установлен.")

    _box_info("Устанавливаю systemd-сервис...")
    _install_service(listen_port, target_port, target_type)
    _box_ok("Сервис создан и включён.")

    _box_info(f"Открываю UDP-порт {listen_port} в iptables...")
    if _ipt_open_udp(listen_port):
        proto_ipt_persist()
        _box_ok(f"UDP {listen_port} открыт.")
    else:
        _box_warn(f"Не удалось открыть UDP {listen_port} в iptables.")

    _box_info("Запускаю vk-turn-proxy...")
    _run(["systemctl", "start", _SERVICE_NAME])
    time.sleep(2)
    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    if r.stdout.strip() == "active":
        _box_ok("vk-turn-proxy запущен.")
    else:
        _box_warn("Сервис не запустился — проверьте: journalctl -u vk-turn-proxy -n 30")

    proto_save_state(_MODULE_STATE, {
        "installed":   True,
        "listen_port": listen_port,
        "target_port": target_port,
        "target_type": target_type,
    })

    _show_freeturn_config(listen_port, target_port, target_type, after_install=True)

# ══════════════════════════════════════════════════════════════════════════════
#  ИНСТРУКЦИЯ FreeTurn
# ══════════════════════════════════════════════════════════════════════════════
def _show_freeturn_config(
    listen_port: int,
    target_port: int,
    target_type: str,
    after_install: bool = False,
) -> None:
    server_ip  = _get_server_ip()
    ttype_name = "WireGuard" if target_type == "wireguard" else "Hysteria2"

    os.system("clear")
    title = "✅  УСТАНОВКА ЗАВЕРШЕНА" if after_install else "📱  НАСТРОЙКА FREETURN"
    _box_top(f"{title}  •  VK TURN PROXY")
    _box_row()
    _box_ok("vk-turn-proxy установлен и запущен." if after_install else "")
    if after_install:
        _box_row()
    _box_kv("UDP порт (FreeTurn):", f"{YELLOW}{listen_port}{NC}")
    _box_kv("Целевой сервис:",     f"{DIM}{ttype_name} → 127.0.0.1:{target_port}{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Рекомендуемый клиент — WDTT (amurcanov):{NC}")
    _box_row()
    _box_ok("WDTT поддерживает WRAP-слой — шейпинг ВКонтакте обойдён!")
    _box_info("Скачайте APK:")
    _box_link("   github.com/amurcanov/proxy-turn-vk-android/releases")
    _box_row()
    _box_info("Настройка в приложении WDTT:")
    _box_kv("   Адрес сервера:", f"{YELLOW}{server_ip}:{listen_port}{NC}")
    _box_kv("   Ссылка на звонок:", f"{DIM}vk.com/call/join/... (создать в ВК){NC}")
    _box_kv("   Пароль:", f"{DIM}пароль из настроек сервера{NC}")
    _box_row()
    _box_info(f"В {ttype_name}-клиенте укажите Endpoint: 127.0.0.1:9000")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Альтернативный клиент — FreeTurn:{NC}")
    _box_row()
    _box_warn("FreeTurn не поддерживает WRAP — скорость ниже.")
    _box_info("Установите FreeTurn:")
    _box_link("   github.com/samosvalishe/turn-proxy-android/releases")
    _box_row()
    _box_info("Вкладка «Клиент» в FreeTurn:")
    _box_kv("   Адрес vk-turn-proxy:", f"{YELLOW}{server_ip}:{listen_port}{NC}")
    _box_kv("   Ссылка на звонок:", f"{DIM}vk.com/call/join/... (создать в ВК){NC}")
    _box_kv("   Локальный адрес:", f"{DIM}127.0.0.1:9000{NC}")
    _box_row()
    _box_info(f"В {ttype_name}-клиенте укажите Endpoint: 127.0.0.1:9000")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}QR-код адреса сервера:{NC}")

    server_addr = f"{server_ip}:{listen_port}"
    _show_qr_in_box(server_addr, f"Адрес vk-turn-proxy сервера: {server_addr}")

    _box_row()
    _box_info("Ссылка на звонок действует вечно — не нажимайте «Завершить для всех».")
    _box_info("Логи: journalctl -u vk-turn-proxy -f")
    _box_bot()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  УДАЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _full_uninstall(silent: bool = False) -> bool:
    if not silent:
        os.system("clear")
        _box_top("🗑️  УДАЛЕНИЕ  •  VK TURN PROXY")
        _box_row()
        _box_warn("Будет удалено:")
        _box_row(f"  {DIM}  • Сервис  vk-turn-proxy{NC}")
        _box_row(f"  {DIM}  • Бинарник {_BIN_PATH}{NC}")
        _box_row(f"  {DIM}  • iptables UDP-правило{NC}")
        _box_row(f"  {DIM}  • turntunnel.json{NC}")
        _box_row()
        _box_warn("Xray, WireGuard и Hysteria2 не затрагиваются.")
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
        if not silent: _ok("Бинарник удалён.")
    except Exception as e:
        if not silent: _warn(f"Не удалось удалить {_BIN_DIR}: {e}")

    _ipt_close_udp(listen_port)
    proto_ipt_persist()
    if not silent: _ok(f"iptables UDP {listen_port} закрыт.")

    try:
        if _MODULE_STATE.exists():
            _MODULE_STATE.unlink()
    except Exception:
        pass

    if not silent:
        _ok("VK Turn Proxy полностью удалён.")
        _pause()
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  ОБНОВЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _run_update() -> None:
    os.system("clear")
    _box_top("⬆️  ОБНОВЛЕНИЕ  •  VK TURN PROXY")
    _box_row()
    cur = proto_get_installed_version(_BIN_PATH, "-version")
    _box_kv("Установлена:", cur or "—")
    _box_info("Проверяю последний релиз на GitHub...")
    _box_bot(); print()

    latest = proto_get_latest_version(_GITHUB_API_URL)
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
    _box_top("📊  СТАТУС  •  VK TURN PROXY")
    _box_row()

    svc_str = (
        f"{GREEN}● активен{NC}" if st["service_ok"] else
        f"{RED}● остановлен{NC}"
    )
    _box_kv("Сервис:",       svc_str)
    _box_kv("Бинарник:",     f"{GREEN}✓ {st['bin_version']}{NC}"
                             if st["bin_version"] else f"{RED}✗ не установлен{NC}")
    _box_kv("iptables UDP:", f"{GREEN}✓ открыт{NC}"
                             if st["ipt_ok"] else f"{YELLOW}⚠ не найдено правило{NC}")
    _box_row()
    _box_kv("UDP порт:",        str(st["listen_port"]))
    _box_kv("Целевой порт:",    str(st["target_port"]))
    _box_kv("Целевой сервис:",  st["target_type"])
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
    state = proto_load_state(_MODULE_STATE)
    if not state.get("installed"):
        _warn("VK Turn Proxy не установлен."); _pause(); return

    old_listen = state.get("listen_port", _DEFAULT_LISTEN_PORT)
    old_target = state.get("target_port", _DEFAULT_TARGET_PORT)
    old_ttype  = state.get("target_type", "wireguard")

    os.system("clear")
    _box_top("🔌  СМЕНА ПОРТА  •  VK TURN PROXY")
    _box_row()
    _box_kv("Текущий UDP-порт:",    str(old_listen))
    _box_kv("Текущий целевой порт:", str(old_target))
    _box_row(); _box_bot(); print()

    try:
        raw = proto_ask(f"  {CYAN}Новый UDP-порт [{old_listen}]: {NC}",
                   default=str(old_listen), c=True)
        new_listen = int(raw) if raw.isdigit() else old_listen

        raw = proto_ask(f"  {CYAN}Новый целевой порт [{old_target}]: {NC}",
                   default=str(old_target), c=True)
        new_target = int(raw) if raw.isdigit() else old_target
    except _Cancelled:
        return

    if new_listen == old_listen and new_target == old_target:
        _info("Порты не изменились."); _pause(); return

    if not (1024 <= new_listen <= 65535) or not (1024 <= new_target <= 65535):
        _err("Порты должны быть в диапазоне 1024–65535."); _pause(); return
    if new_listen == new_target:
        _err("Порты не должны совпадать."); _pause(); return

    if new_listen != old_listen:
        _ipt_close_udp(old_listen)
        _ipt_open_udp(new_listen)
        proto_ipt_persist()
        _ok(f"iptables: UDP {old_listen} → {new_listen}.")

    _run(["systemctl", "stop", _SERVICE_NAME])
    _install_service(new_listen, new_target, old_ttype)
    _run(["systemctl", "start", _SERVICE_NAME])

    state["listen_port"] = new_listen
    state["target_port"] = new_target
    proto_save_state(_MODULE_STATE, state)

    _ok(f"Порты обновлены. UDP: {new_listen}, цель: {new_target}.")
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ МОДУЛЯ
# ══════════════════════════════════════════════════════════════════════════════
def do_turntunnel_menu() -> None:
    """
    Точка входа.
    Ctrl+C внутри подменю → возврат сюда.
    Ctrl+C здесь → пробрасывается в _core.py.
    """
    while True:
        os.system("clear")
        st = _get_status()

        svc_str = (
            f"{GREEN}● активен   {st['bin_version'] or ''}{NC}" if st["service_ok"] else
            f"{RED}● остановлен{NC}"                             if st["installed"]  else
            f"{YELLOW}● не установлен{NC}"
        )

        _box_top("VK TURN PROXY  •  FreeTurn")
        _box_row()
        _box_kv("Статус:", svc_str)

        if st["installed"]:
            ipt_col = GREEN if st["ipt_ok"] else YELLOW
            _box_kv("UDP порт:",        str(st["listen_port"]))
            _box_kv("Целевой порт:",    str(st["target_port"]))
            _box_kv("Целевой сервис:",  st["target_type"])
            _box_kv("iptables UDP:",
                    f"{ipt_col}✓ открыт{NC}" if st["ipt_ok"]
                    else f"{YELLOW}⚠ не найдено правило{NC}")

        _box_row(); _box_sep()

        if not st["installed"]:
            _box_item("1", "🚀  Установить")
        else:
            _box_item("1", "🚀  Переустановить")
            _box_item("2", "📱  Показать настройки / QR для FreeTurn")
            _box_item("3", "🔌  Сменить порт")
            _box_item("4", "🔄  Перезапустить сервис")
            _box_item("5", "⬆️   Обновить бинарник")
            _box_item("6", "📊  Статус / логи")
            _box_item("L", "🔗  Менеджер ссылок ВК-звонков")
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
            _show_freeturn_config(
                state.get("listen_port", _DEFAULT_LISTEN_PORT),
                state.get("target_port", _DEFAULT_TARGET_PORT),
                state.get("target_type", "wireguard"),
            )

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
                from chimera.modules.turntunnel_links import do_links_menu
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


if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}Запустите от root.{NC}"); sys.exit(1)
    try:
        do_turntunnel_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}"); sys.exit(0)

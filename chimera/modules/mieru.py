"""
chimera/modules/mieru.py
───────────────────────────────────────────────────────────────────────────────
Mieru — mTLS туннель с рандомным padding и защитой от анализа трафика.

Как это работает:
  Mieru использует mTLS (mutual TLS) поверх TCP или UDP.
  Трафик выглядит как случайный зашумлённый поток — нет паттернов
  которые DPI может идентифицировать. Дополнительно — рандомный padding
  и задержки делают статистический анализ неэффективным.
  Не требует домена — работает по IP.

Схема трафика:
  Клиент (Karing / sing-box / Nekobox)
    │  mTLS + random padding, TCP или UDP
    ▼
  mita server :2012  (или диапазон портов)
    │  проверка временной метки ±30 сек
    ▼
  SOCKS5 :1080 (встроенный)
    │
    ▼
  Интернет

Схема с каскадом (Entry→Exit):
  Клиент
    │  mTLS
    ▼
  mita Entry (RU)
    │  redsocks + iptables → Exit
    ▼
  mita Exit (EU)
    │
    ▼
  Интернет

Отличия от NaiveProxy:
  • Не требует домена — только IP и порт
  • mTLS вместо HTTPS — другой fingerprint
  • Рандомный padding — против статистического анализа
  • Требует синхронизацию времени ±30 сек (ntpd/chrony)
  • Клиенты: Karing, sing-box, Nekobox

Что модуль делает:
  • Скачивает mita (server) и mieru (client CLI) с GitHub
  • Генерирует server config (mita apply config)
  • Создаёт systemd-сервис mita
  • Открывает TCP/UDP порты в iptables
  • Управление пользователями через mita CLI
  • Генерация sing-box JSON конфига и QR-кода для клиента
  • Проверка синхронизации времени

Что модуль НЕ трогает:
  • Xray config.json и VLESS-inbound
  • state.json инсталлера
  • iptables-правила других модулей
  • Любые другие службы

Точка входа из _core.py:
    from chimera.modules.mieru import do_mieru_menu
    do_mieru_menu()

Статистика трафика (отдельный модуль):
    from chimera.modules.mieru_stats import do_mieru_stats_menu
    do_mieru_stats_menu()
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from chimera.modules.text_width import wlen as _wlen, plain as _plain

import base64
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Optional

from chimera.modules.proto_common import (
    ProtoCancelled, proto_load_state, proto_save_state,
    proto_ask, proto_gen_password, proto_ipt_persist, proto_ipt_rule_exists,
    proto_get_latest_version, proto_get_installed_version,
)
from chimera.modules.mieru_mirrors import (
    get_mita_mirrors, get_mieru_mirrors, get_deb_mirrors, get_rpm_mirrors,
    MANUAL_UPLOAD_PATHS as _MIERU_MANUAL_PATHS,
    MIERU_MIRRORS_COUNT, find_manual_upload as _find_mieru_manual_upload,
    print_mieru_manual_download_hint as _print_mieru_manual_hint,
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
_MITA_BIN        = Path("/usr/local/bin/mita")
_MIERU_BIN       = Path("/usr/local/bin/mieru")
_CFG_DIR         = Path("/etc/mita")
_SERVER_CFG      = Path("/etc/mita/server.json")
_SERVICE_FILE    = Path("/etc/systemd/system/mita.service")
_SERVICE_NAME    = "mita"
_MODULE_STATE    = Path("/var/lib/xray-installer/mieru.json")

_GITHUB_API      = "https://api.github.com/repos/enfein/mieru/releases/latest"

# Порты по умолчанию — диапазон для мультиплексирования
_DEFAULT_PORT_START = 2012
_DEFAULT_PORT_END   = 2022
_DEFAULT_PROTOCOL   = "TCP"  # TCP или UDP

# Валидация логина: только ASCII-латиница, цифры, _ и -.
# Защищает от случайной кириллицы при не переключённой раскладке клавиатуры
# (частая ошибка при вводе через мобильные SSH-клиенты типа Termius).
_RE_USERNAME      = re.compile(r"^[A-Za-z0-9_-]+$")
_RE_USERNAME_CHAR = re.compile(r"^[A-Za-z0-9_-]$")

_BOX_W = 66

# ══════════════════════════════════════════════════════════════════════════════
#  BOX-РЕНДЕРИНГ
# ══════════════════════════════════════════════════════════════════════════════


def _box_top(title: str = "") -> None:
    print(f"{CYAN}╔{'═' * _BOX_W}╗{NC}")
    if title:
        pad = _BOX_W - _wlen(title); lpad = pad // 2; rpad = pad - lpad
        print(f"{CYAN}║{NC}{' ' * lpad}{BOLD}{WHITE}{title}{NC}{' ' * rpad}{CYAN}║{NC}")
        print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")

def _box_sep() -> None: print(f"{CYAN}╠{'═' * _BOX_W}║{NC}")
def _box_bot() -> None: print(f"{CYAN}╚{'═' * _BOX_W}╝{NC}")

def _box_row(text: str = "") -> None:
    w = _wlen(text)
    if w > _BOX_W:
        acc, plain = 0, _plain(text); cut = 0
        for i, ch in enumerate(plain):
            import unicodedata as _ud
            acc += 2 if _ud.east_asian_width(ch) in ('W', 'F') else 1
            if acc > _BOX_W - 1: cut = i; break
        text = text[:cut] + "…"; w = _wlen(text)
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

def _box_log_line(line: str, indent: str = "  ") -> None:
    """
    Выводит одну строку журнала (journalctl), разбивая её максимум на 2
    строки бокса, если она не помещается целиком. Длинные строки (DPI-лог,
    JSON-ошибки, stack trace) иначе обрезались бы посередине и становились
    нечитаемыми — см. CHANGELOG.

    Первая строка — с обычным отступом indent, вторая (продолжение) —
    с тем же отступом плюс "↳ " для визуальной связи со строкой выше.
    Если текст не уместился и в 2 строки — добавляется "…" в конце.
    """
    avail_1 = _BOX_W - _wlen(indent)          # ширина первой строки
    cont_indent = indent + "↳ "
    avail_2 = _BOX_W - _wlen(cont_indent)      # ширина второй строки

    plain = line  # journalctl-строки практически всегда без ANSI — без _plain() ок
    if _wlen(plain) <= avail_1:
        _box_row(f"{indent}{DIM}{plain}{NC}")
        return

    # Режем по символам (не по словам — это лог, а не текст для чтения вслух)
    first_part  = plain[:avail_1]
    rest        = plain[avail_1:]
    if _wlen(rest) > avail_2:
        rest = rest[:max(0, avail_2 - 1)] + "…"

    _box_row(f"{indent}{DIM}{first_part}{NC}")
    _box_row(f"{cont_indent}{DIM}{rest}{NC}")

def _box_link(link: str, color: str = "") -> None:
    color = color or YELLOW; max_w = _BOX_W - 2; plain_link = _plain(link); i = 0
    while i < len(plain_link):
        chunk = plain_link[i:i + max_w]
        pad = max(0, _BOX_W - 2 - _wlen(chunk))
        print(f"{CYAN}║{NC}  {color}{chunk}{NC}{' ' * pad}{CYAN}║{NC}")
        i += max_w

# Также используется из hybrid_addon.py (do_hybrid_addon_menu) — при правке
# сигнатуры проверь использование там.
def _print_qr(data: str, label: str = "") -> None:
    if not shutil.which("qrencode"):
        print(f"  {YELLOW}⚠{NC}  qrencode не установлен: apt install qrencode")
        return
    if label:
        print(f"  {CYAN}→{NC}  QR: {YELLOW}{label}{NC}")
    print()
    try:
        subprocess.run(["qrencode", "-t", "UTF8", "-m", "1", data], check=True)
    except Exception as e:
        print(f"  {RED}✗{NC}  QR ошибка: {e}")
    print()

# ══════════════════════════════════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНЫЕ
# ══════════════════════════════════════════════════════════════════════════════
def _pause() -> None:
    try:
        print(f"\n  {DIM}Нажмите Enter...{NC}", end="", flush=True); input()
    except (KeyboardInterrupt, EOFError, UnicodeDecodeError):
        print()

def _run(cmd: list, capture: bool = False, check: bool = False,
         cwd: Optional[str] = None) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if cwd: kw["cwd"] = cwd
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    else:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

def _get_server_ip() -> str:
    try:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80)); return s.getsockname()[0]
    except Exception: pass
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
            return r.read().decode().strip()
    except Exception: pass
    return "ВАШ_IP"

def _is_amd64() -> bool:
    return platform.machine().lower() in ("x86_64", "amd64")

# ══════════════════════════════════════════════════════════════════════════════
#  СОСТОЯНИЕ МОДУЛЯ
# ══════════════════════════════════════════════════════════════════════════════
# State load/save, prompt, password-gen and iptables-persist helpers are
# imported from chimera.modules.proto_common (see top of file).
# Call sites use proto_load_state / proto_save_state / proto_ask /
# proto_gen_password / proto_ipt_persist directly.

def _is_installed() -> bool:
    return _MITA_BIN.exists() and _SERVICE_FILE.exists()

# ══════════════════════════════════════════════════════════════════════════════
#  БИНАРНИКИ
# ══════════════════════════════════════════════════════════════════════════════
# _get_latest_version / _get_installed_version — вынесены в proto_common.
# mieru's GitHub API strips leading 'v' (release tags look like 'v1.x.y')
# and the mita binary prints versions prefixed with 'v' → strip_v=True.
def _get_download_urls(version: str) -> tuple[str, str]:
    """Возвращает (mita_url, mieru_url) для текущей архитектуры."""
    arch = "amd64" if _is_amd64() else "arm64"
    base = f"https://github.com/enfein/mieru/releases/download/v{version}"
    mita_url  = f"{base}/mita_{version}_linux_{arch}.tar.gz"
    mieru_url = f"{base}/mieru_{version}_linux_{arch}.tar.gz"
    return mita_url, mieru_url

def _atomic_install_binary(src: Path, dest: Path) -> None:
    """
    Копирует src → dest атомарно через os.replace(), а не shutil.copy2()
    напрямую поверх dest.

    Причина: если dest сейчас исполняется работающим процессом (mita.service
    активен во время переустановки/обновления поверх существующей установки),
    прямая запись в файл (copy2 открывает dest на запись с truncate) падает
    с 'Errno 26 Text file busy' — ядро Linux не даёт менять содержимое файла,
    пока он замаплен в память запущенного процесса.

    os.replace() этой проблемы не имеет: он просто переключает directory
    entry на новый inode во временном файле рядом (та же ФС — иначе rename
    не атомарен), а уже запущенный процесс продолжает работать со старым
    (отсоединённым от каталога, но ещё не освобождённым) inode до своего
    перезапуска. Именно поэтому сразу после установки бинарника сервис
    нужно перезапустить — это уже делает вызывающий код ниже по потоку.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp_dest = dest.with_name(dest.name + f".new.{os.getpid()}")
    try:
        shutil.copy2(str(src), str(tmp_dest))
        tmp_dest.chmod(0o755)
        os.replace(str(tmp_dest), str(dest))
    finally:
        tmp_dest.unlink(missing_ok=True)


def _install_mita_package(version: str) -> bool:
    """
    Устанавливает mita используя пакетный менеджер (deb/rpm) если доступен,
    иначе fallback на tar.gz.

    МИГРАЦИЯ: использует fetch_package() из download_manager.py с PackageSpec
    из mieru_packages.py. fetch_package сам:
      1. Проверяет /root/{filename} (manual_incoming_dir) — если найден,
         использует без сети (WinSCP-friendly).
      2. Иначе — перебирает зеркала через urllib (14 зеркал).
      3. При успехе — вызывает post_install (dpkg -i / rpm -Uvh / tar -xzf).
      4. При провале — возвращает False.

    PackageSpec.__post_init__ assert гарантирует manual_incoming_dir (/root/)
    != install_dests (/tmp/mieru_packages) — баг 21d7baf невозможен.
    """
    arch = "amd64" if _is_amd64() else "arm64"
    rpm_arch = "x86_64" if _is_amd64() else "aarch64"

    # Ленивый импорт specs (избегает циклического импорта на module load)
    from chimera.modules.mieru_packages import (
        MITA_DEB_SPEC, MITA_RPM_SPEC, MITA_TARGZ_SPEC, MIERU_TARGZ_SPEC,
    )
    from chimera.modules.download_manager import fetch_package

    # --- Debian/Ubuntu (.deb) ---
    if shutil.which("dpkg"):
        print(f"  {CYAN}→{NC}  Скачиваю mita {version} (.deb, 14 зеркал в fallback)...")
        try:
            ok = fetch_package(MITA_DEB_SPEC, print_hint_on_failure=False,
                               version=version, arch=arch)
            if ok:
                return True
            print(f"  {YELLOW}⚠{NC}  .deb не удалось скачать/установить, пробую tar.gz...")
        except Exception as e:
            print(f"  {YELLOW}⚠{NC}  Ошибка .deb: {e}, пробую tar.gz...")

    # --- RPM (RedHat/CentOS) ---
    elif shutil.which("rpm"):
        print(f"  {CYAN}→{NC}  Скачиваю mita {version} (.rpm, 14 зеркал в fallback)...")
        try:
            ok = fetch_package(MITA_RPM_SPEC, print_hint_on_failure=False,
                               version=version, rpm_arch=rpm_arch)
            if ok:
                return True
            print(f"  {YELLOW}⚠{NC}  .rpm не удалось скачать/установить, пробую tar.gz...")
        except Exception as e:
            print(f"  {YELLOW}⚠{NC}  Ошибка .rpm: {e}, пробую tar.gz...")

    # --- Fallback: tar.gz ---
    print(f"  {CYAN}→{NC}  Скачиваю mita {version} (.tar.gz, 14 зеркал в fallback)...")
    result = fetch_package(MITA_TARGZ_SPEC, print_hint_on_failure=False,
                           version=version, arch=arch)
    if result:
        # Клиентский mieru — опционально, не критично если упадёт
        fetch_package(MIERU_TARGZ_SPEC, print_hint_on_failure=False,
                      version=version, arch=arch)
    return result


# _get_installed_version — вынесен в proto_common (mita binary uses
# subcommand `version`, output prefix `v` → strip_v=True at call sites).
# Local call sites use proto_get_installed_version(_MITA_BIN, "version", strip_v=True).

# ══════════════════════════════════════════════════════════════════════════════
#  КОНФИГ СЕРВЕРА
# ══════════════════════════════════════════════════════════════════════════════
def _build_server_config(users: list, port_start: int, port_end: int,
                          protocol: str,
                          traffic_pattern: dict = None) -> dict:
    """
    Генерирует server config для mita apply config.
    Формат: https://github.com/enfein/mieru/blob/main/docs/server-config.md

    traffic_pattern — опциональный dict для поля trafficPattern (server-side).
    Формат: {"tcpFragment": {...}, "nonce": {...}, "padding": {...}, "unlockAll": bool}
    ВАЖНО: mita не поддерживает hot-reload trafficPattern — после изменения
    конфига нужен systemctl restart mita (см. _apply_server_config_with_restart).
    """
    port_bindings = []
    if port_start == port_end:
        port_bindings.append({
            "port": port_start,
            "protocol": protocol,
        })
    else:
        port_bindings.append({
            "portRange": f"{port_start}-{port_end}",
            "protocol": protocol,
        })

    user_entries = []
    for u in users:
        user_entries.append({
            "name":     u["username"],
            "password": u["password"],
        })

    cfg = {
        "portBindings": port_bindings,
        "users": user_entries,
        "loggingLevel": "INFO",
        "mtu": 1400,
    }
    if traffic_pattern:
        cfg["trafficPattern"] = traffic_pattern
    return cfg

def _apply_server_config(cfg: dict) -> Optional[str]:
    """Применяет конфиг через mita apply config. Возвращает ошибку или None."""
    _CFG_DIR.mkdir(parents=True, exist_ok=True)
    cfg_path = _CFG_DIR / "server.json"
    cfg_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    cfg_path.chmod(0o600)
    _SERVER_CFG.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))

    r = _run([str(_MITA_BIN), "apply", "config", str(cfg_path)], capture=True)
    if r.returncode != 0:
        return (r.stderr or r.stdout or "")[:300]
    return None

# ══════════════════════════════════════════════════════════════════════════════
#  IPTABLES
# ══════════════════════════════════════════════════════════════════════════════
# _ipt_rule_exists — вынесен в proto_common (proto_ipt_rule_exists).
def _ipt_rule_exists(proto: str, port: int) -> bool:
    return proto_ipt_rule_exists("filter", "INPUT", ["-p", proto.lower(), "--dport", str(port), "-j", "ACCEPT"])

def _ipt_open_port(proto: str, port_start: int, port_end: int) -> None:
    proto = proto.lower()
    if port_start == port_end:
        if not _ipt_rule_exists(proto, port_start):
            _run(["iptables", "-t", "filter", "-I", "INPUT", "1",
                  "-p", proto, "--dport", str(port_start), "-j", "ACCEPT"])
    else:
        # Диапазон портов
        r = _run(
            ["iptables", "-t", "filter", "-C", "INPUT",
             "-p", proto, "--dport", f"{port_start}:{port_end}", "-j", "ACCEPT"],
            capture=True,
        )
        if r.returncode != 0:
            _run(["iptables", "-t", "filter", "-I", "INPUT", "1",
                  "-p", proto, "--dport", f"{port_start}:{port_end}", "-j", "ACCEPT"])

def _ipt_close_port(proto: str, port_start: int, port_end: int) -> None:
    proto = proto.lower()
    if port_start == port_end:
        for _ in range(5):
            if not _ipt_rule_exists(proto, port_start): break
            _run(["iptables", "-t", "filter", "-D", "INPUT",
                  "-p", proto, "--dport", str(port_start), "-j", "ACCEPT"])
    else:
        for _ in range(5):
            r = _run(
                ["iptables", "-t", "filter", "-C", "INPUT",
                 "-p", proto, "--dport", f"{port_start}:{port_end}", "-j", "ACCEPT"],
                capture=True,
            )
            if r.returncode != 0: break
            _run(["iptables", "-t", "filter", "-D", "INPUT",
                  "-p", proto, "--dport", f"{port_start}:{port_end}", "-j", "ACCEPT"])

# _ipt_persist — вынесен в proto_common (использует subprocess.run напрямую,
# не зависит от module-local _run). Call sites: proto_ipt_persist().

def _ufw_is_active() -> bool:
    """Проверяет активен ли UFW."""
    if not shutil.which("ufw"):
        return False
    r = _run(["ufw", "status"], capture=True)
    # ВАЖНО: "inactive" содержит подстроку "active" — поэтому проверяем
    # именно "status: active", а не просто "active" в выводе.
    return "status: active" in r.stdout.lower()

def _ufw_open_port(proto: str, port_start: int, port_end: int) -> None:
    """Открывает порты через UFW если он активен.

     миграция на port_registry (с backward compat fallback).
    """
    # v49: port_register — БЕЗУСЛОВНО; UFW-правило — только если UFW активен.
    proto = proto.lower()
    ufw_on = _ufw_is_active()
    #  сначала port_registry.
    try:
        from chimera.modules.port_registry import (
            ufw_open_port, ufw_open_port_range, port_register, SERVICE_MIERU,
        )
        if port_start == port_end:
            port_register(SERVICE_MIERU, port_start, proto,
                          comment="Mieru", force=True)
            if ufw_on:
                ufw_open_port(port_start, proto, SERVICE_MIERU, comment="Mieru")
        else:
            # Для range регистрируем каждый порт отдельно (для conflict detection).
            for p in range(port_start, port_end + 1):
                port_register(SERVICE_MIERU, p, proto,
                              comment="Mieru range", force=True)
            if ufw_on:
                ufw_open_port_range(port_start, port_end, proto, SERVICE_MIERU,
                                    comment="Mieru range")
        return
    except Exception:
        pass
    if not ufw_on:
        return
    if port_start == port_end:
        _run(["ufw", "allow", f"{port_start}/{proto}"], capture=True)
    else:
        _run(["ufw", "allow", f"{port_start}:{port_end}/{proto}"], capture=True)

def _ufw_close_port(proto: str, port_start: int, port_end: int) -> None:
    """Закрывает порты через UFW если он активен.

     миграция на port_registry (с backward compat).
    """
    # v49: port_unregister — БЕЗУСЛОВНО (stale-записи после uninstall
    # при неактивном UFW больше не остаются).
    proto = proto.lower()
    #  сначала port_registry.
    try:
        from chimera.modules.port_registry import (
            ufw_close_port, ufw_close_port_range, port_unregister, SERVICE_MIERU,
        )
        if port_start == port_end:
            ufw_close_port(port_start, proto, SERVICE_MIERU)
            port_unregister(SERVICE_MIERU, port_start, proto)
        else:
            ufw_close_port_range(port_start, port_end, proto, SERVICE_MIERU)
            for p in range(port_start, port_end + 1):
                port_unregister(SERVICE_MIERU, p, proto)
        return
    except Exception:
        pass
    if port_start == port_end:
        _run(["ufw", "delete", "allow", f"{port_start}/{proto}"], capture=True)
    else:
        _run(["ufw", "delete", "allow", f"{port_start}:{port_end}/{proto}"], capture=True)

def _open_ports(proto: str, port_start: int, port_end: int) -> str:
    """Открывает порты через UFW (если активен) или iptables. Возвращает описание."""
    if _ufw_is_active():
        _ufw_open_port(proto, port_start, port_end)
        return f"UFW: {proto} {port_start}-{port_end} открыт."
    else:
        _ipt_open_port(proto, port_start, port_end)
        proto_ipt_persist()
        return f"iptables: {proto} {port_start}-{port_end} открыт."

def _close_ports(proto: str, port_start: int, port_end: int) -> None:
    """Закрывает порты через UFW (если активен) или iptables."""
    if _ufw_is_active():
        _ufw_close_port(proto, port_start, port_end)
    else:
        _ipt_close_port(proto, port_start, port_end)
        proto_ipt_persist()

# ══════════════════════════════════════════════════════════════════════════════
#  SYSTEMD
# ══════════════════════════════════════════════════════════════════════════════
def _ensure_mita_user() -> None:
    """mita требует системного пользователя 'mita' для управления сокетом."""
    r = _run(["id", "mita"], capture=True)
    if r.returncode != 0:
        _run(["useradd", "--system", "--no-create-home",
              "--shell", "/usr/sbin/nologin", "mita"])

def _install_service() -> None:
    # mita run — запуск в foreground (для systemd Type=simple).
    # mita start пытается подключиться к уже запущенному демону через сокет
    # и немедленно падает с "daemon is not running".
    _SERVICE_FILE.write_text(
        "[Unit]\n"
        "Description=Mieru Proxy Server (mita)\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={_MITA_BIN} run\n"
        "RuntimeDirectory=mita\n"
        "Restart=on-failure\n"
        "RestartSec=5\n"
        "NoNewPrivileges=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "enable", _SERVICE_NAME])

# ══════════════════════════════════════════════════════════════════════════════
#  СИНХРОНИЗАЦИЯ ВРЕМЕНИ
# ══════════════════════════════════════════════════════════════════════════════
def _check_time_sync() -> tuple[bool, str]:
    """Проверяет синхронизацию времени. Mieru требует ±30 сек."""
    # Через timedatectl
    r = _run(["timedatectl", "status"], capture=True)
    if r.returncode == 0:
        out = r.stdout or ""
        if "synchronized: yes" in out or "NTP synchronized: yes" in out:
            return True, "NTP синхронизирован (timedatectl)"
        if "synchronized: no" in out or "NTP synchronized: no" in out:
            return False, "NTP не синхронизирован!"

    # Через chronyc
    r2 = _run(["chronyc", "tracking"], capture=True)
    if r2.returncode == 0:
        return True, "Chrony активен"

    return True, "Статус неизвестен — проверьте вручную"

def _ensure_time_sync() -> None:
    """Устанавливает chrony если нет NTP."""
    if shutil.which("chronyc") or shutil.which("ntpd"):
        return
    print(f"  {CYAN}→{NC}  Устанавливаю chrony для синхронизации времени...")
    _run(["apt-get", "install", "-y", "chrony"], capture=True)
    _run(["systemctl", "enable", "--now", "chrony"])

# ══════════════════════════════════════════════════════════════════════════════
#  SING-BOX КОНФИГ ДЛЯ КЛИЕНТА
# ══════════════════════════════════════════════════════════════════════════════
# Эти три функции (до _run_install) — чистые, без обращения к глобальному
# состоянию модуля. Также используются из hybrid_addon.py
# (_show_mieru_client_links) — при правке формата/сигнатуры проверь и там.
def _gen_singbox_outbound(server_ip: str, port_start: int, port_end: int,
                           protocol: str, username: str, password: str) -> dict:
    """
    Генерирует sing-box outbound для mieru.
    Импортируется в Karing / Nekobox / sing-box CLI.
    Проверено на рабочем конфиге:
      - server_port: int (один порт, НЕ диапазон строкой)
      - username: обязателен
      - multiplexing: "MULTIPLEXING_HIGH" — обязателен для Karing
    """
    return {
        "type": "mieru",
        "tag": f"mieru-{username}",
        "server": server_ip,
        "server_port": port_start,
        "transport": protocol.upper(),
        "username": username,
        "password": password,
        "multiplexing": "MULTIPLEXING_HIGH",
    }

def _gen_client_share_link(server_ip: str, port_start: int, port_end: int,
                            protocol: str, username: str, password: str,
                            traffic_preset: str = "basic") -> str:
    """
    Генерирует mierus:// share link для Karing (sing-box).
    Karing парсит ссылку в sing-box outbound JSON.
    Требования (проверено на рабочем конфиге):
      - server_port должен быть одним портом (int), не диапазоном
      - multiplexing=MULTIPLEXING_HIGH обязателен
      - traffic-pattern — base64-protobuf TrafficPattern для синхронизации
        обфускации между клиентом и сервером (поддерживается Karing/sing-box-extended)
    Используем port_start как основной порт.
    """
    import urllib.parse
    from chimera.modules.mieru_traffic_presets import get_preset_base64
    pattern_b64 = get_preset_base64(traffic_preset)
    pattern_encoded = urllib.parse.quote(pattern_b64, safe="")
    return (
        f"mierus://{username}:{password}@{server_ip}"
        f"?port={port_start}&protocol={protocol.upper()}&profile=default"
        f"&mtu=1400&multiplexing=MULTIPLEXING_HIGH"
        f"&traffic-pattern={pattern_encoded}"
    )

def _gen_client_share_link_nekobox(server_ip: str, port_start: int,
                                    protocol: str, username: str, password: str) -> str:
    """
    Генерирует mierus:// share link для Nekobox / Nyamebox.
    Формат: mierus://user:pass@host:PORT?transport=TCP&mtu=1400
    Отличия от Karing:
      - порт через двоеточие после IP (не query-параметр port=)
      - параметр transport= вместо protocol=
      - только один конкретный порт (не диапазон)
    """
    return (
        f"mierus://{username}:{password}@{server_ip}:{port_start}"
        f"?transport={protocol.upper()}&mtu=1400"
    )

# ══════════════════════════════════════════════════════════════════════════════
#  УСТАНОВКА
# ══════════════════════════════════════════════════════════════════════════════
def _run_install() -> None:
    try: _run_install_inner()
    except _Cancelled:
        print(f"\n  {YELLOW}Установка прервана.{NC}\n"); _pause()

def _run_install_inner() -> None:
    os.system("clear")
    _box_top("🔒  УСТАНОВКА  •  MIERU")
    _box_row()

    if _is_installed():
        _box_warn("Mieru уже установлен.")
        _box_row()
        _box_item("1", "Переустановить (сохранить пользователей)")
        _box_item("2", f"Переустановить полностью  {YELLOW}(новые пользователи){NC}")
        _box_item("Q", "← Отмена")
        _box_bot(); print()
        try:
            ch = proto_ask(f"{CYAN}Выбор [1/2/Q]: {NC}", c=True).strip().lower()
        except _Cancelled: return
        if ch == "q" or not ch: return
        if ch == "2": _full_uninstall(silent=True)

    # ── Параметры ─────────────────────────────────────────────────────────────
    state = proto_load_state(_MODULE_STATE)
    old_port_start = state.get("port_start", _DEFAULT_PORT_START)
    old_port_end   = state.get("port_end",   _DEFAULT_PORT_END)
    old_protocol   = state.get("protocol",   _DEFAULT_PROTOCOL)

    os.system("clear")
    _box_top("🔒  НАСТРОЙКА  •  MIERU")
    _box_row()
    _box_info("Mieru не требует домена — работает по IP.")
    _box_info("Рекомендуется диапазон портов для лучшей маскировки.")
    _box_row()
    _box_warn("ВАЖНО: синхронизация времени ±30 сек обязательна!")
    _box_bot(); print()

    try:
        raw = proto_ask(
            f"  {CYAN}Начальный порт [{old_port_start}]: {NC}",
            default=str(old_port_start), c=True,
        )
        port_start = int(raw) if raw.isdigit() else old_port_start

        raw = proto_ask(
            f"  {CYAN}Конечный порт [{old_port_end}] (=начальный для одного порта): {NC}",
            default=str(old_port_end), c=True,
        )
        port_end = int(raw) if raw.isdigit() else old_port_end
        if port_end < port_start:
            port_end = port_start

        raw = proto_ask(
            f"  {CYAN}Протокол [TCP/UDP, Enter={old_protocol}]: {NC}",
            default=old_protocol, c=True,
        ).strip().upper()
        protocol = raw if raw in ("TCP", "UDP") else old_protocol

    except _Cancelled: raise

    # ── Установка ─────────────────────────────────────────────────────────────
    os.system("clear")
    _box_top("🔒  УСТАНОВКА  •  MIERU")
    _box_row()

    # 1. Версия
    _box_info("Определяю последнюю версию...")
    _box_bot(); print()
    version = proto_get_latest_version(_GITHUB_API, strip_v=True)
    if version == "unknown":
        print(f"  {YELLOW}⚠{NC}  Не удалось определить версию, использую 3.33.0")
        version = "3.33.0"
    print(f"  {GREEN}✓{NC}  Версия: {version}")

    # 2. Бинарники — используем .deb если доступен dpkg, иначе tar.gz
    if not _install_mita_package(version):
        print(f"  {RED}✗{NC}  Не удалось установить mita из всех зеркал.")
        # Показываем инструкцию для ручного скачивания (WinSCP-friendly)
        _print_mieru_manual_hint(version)
        try:
            ans = input(f"{CYAN}  Разместили файлы вручную? Повторить установку? [Y/n]:{NC} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans != "n":
            # Повторная попытка — _install_mita_package теперь найдёт файл
            # в /root/ автоматически через _find_mieru_manual_upload.
            if _install_mita_package(version):
                print(f"  {GREEN}✓{NC}  mita установлен из ручного размещения.")
            else:
                print(f"  {RED}✗{NC}  Файлы не найдены в {', '.join(str(p) for p in _MIERU_MANUAL_PATHS)}.")
                _pause(); return
        else:
            _pause(); return

    # 3. Синхронизация времени
    print(f"  {CYAN}→{NC}  Проверяю синхронизацию времени...")
    _ensure_time_sync()
    sync_ok, sync_msg = _check_time_sync()
    if sync_ok:
        print(f"  {GREEN}✓{NC}  {sync_msg}")
    else:
        print(f"  {YELLOW}⚠{NC}  {sync_msg}")
        print(f"  {DIM}Mieru может не работать без синхронизации времени!{NC}")

    # 4. Пользователи
    users = state.get("users") or []
    if not users:
        # v4.24: спрашиваем имя первого пользователя (был хардкод 'admin').
        # Запрос идём здесь, после ввода портов, т.к. только тут есть
        # полный контекст (state loaded, ports validated).
        try:
            first_user = proto_ask(
                f"  {CYAN}Логин первого пользователя [admin]: {NC}",
                default="admin", c=True,
            ).strip() or "admin"
        except _Cancelled:
            first_user = "admin"
        # Валидация логина — только латиница/цифры/_- (Mieru строгий).
        if not _RE_USERNAME.match(first_user):
            print(f"  {YELLOW}⚠{NC}  Логин содержит недопустимые символы — используем 'admin'.")
            first_user = "admin"
        first_pass = proto_gen_password()
        users = [{"username": first_user, "password": first_pass}]
        print(f"  {GREEN}✓{NC}  Создан первый пользователь: "
              f"{YELLOW}{first_user}{NC} / {YELLOW}{first_pass}{NC}")

    # 5. Чистим остатки предыдущих установок
    _run(["systemctl", "stop",    _SERVICE_NAME])
    _run(["systemctl", "disable", _SERVICE_NAME])
    if _SERVICE_FILE.exists():
        _SERVICE_FILE.unlink()
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "reset-failed"], capture=True)

    # 6. Системный пользователь mita (требуется для Unix-сокета)
    _ensure_mita_user()

    # 7. Systemd — сначала установить и запустить сервис,
    #    т.к. mita apply config работает через Unix-сокет запущенного демона
    #    /etc/mita и /var/run/mita должны существовать до старта
    _CFG_DIR.mkdir(parents=True, exist_ok=True)
    Path("/var/run/mita").mkdir(parents=True, exist_ok=True)
    _install_service()
    _run(["systemctl", "start", _SERVICE_NAME])
    time.sleep(2)
    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    svc_ok = r.stdout.strip() == "active"
    if svc_ok:
        print(f"  {GREEN}✓{NC}  mita запущен.")
    else:
        print(f"  {YELLOW}⚠{NC}  Сервис не запустился — проверьте логи (пункт 4).")

    # 6. Конфиг — только после запуска сервиса
    #    (mita apply config требует работающий /var/run/mita/mita.sock)
    _CFG_DIR.mkdir(parents=True, exist_ok=True)
    cfg = _build_server_config(users, port_start, port_end, protocol)
    err = _apply_server_config(cfg)
    if err:
        print(f"  {RED}✗{NC}  Ошибка применения конфига: {err}")
        _pause(); return
    print(f"  {GREEN}✓{NC}  Конфиг применён.")

    # КРИТИЧНО: перезапуск после apply config — без него mita слушает только
    # UNIX-сокет и не открывает TCP порты
    _run(["systemctl", "restart", _SERVICE_NAME])
    time.sleep(3)
    r2 = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    svc_ok = r2.stdout.strip() == "active"
    if svc_ok:
        print(f"  {GREEN}✓{NC}  mita перезапущен, TCP порты активированы.")
    else:
        print(f"  {YELLOW}⚠{NC}  Сервис не запустился после перезапуска — проверьте логи.")

    # 7. Фаервол (UFW если активен, иначе iptables)
    fw_msg = _open_ports(protocol, port_start, port_end)
    print(f"  {GREEN}✓{NC}  {fw_msg}")

    # 9. Сохраняем состояние (сохраняем traffic_preset если был)
    new_state = {
        "installed":  True,
        "port_start": port_start,
        "port_end":   port_end,
        "protocol":   protocol,
        "version":    version,
        "users":      users,
    }
    # Сохраняем traffic_preset из старого state (если был установлен)
    old_tp = state.get("traffic_preset")
    if old_tp:
        new_state["traffic_preset"] = old_tp
    proto_save_state(_MODULE_STATE, new_state)
    # Обновляем локальную переменную для использования ниже
    state = new_state

    # v4.25: bulk-provisioning всех существующих VLESS-пользователей в Mieru.
    # После успешной установки Mieru активируется is_active()=True, и все
    # VLESS-юзеры автоматически получают аккаунты в Mieru.
    try:
        from chimera.modules.rest_api import _sync_all_from_vless
        from chimera.modules.users_manager import _unified_load_users
        _vless_users = _unified_load_users()
        if _vless_users:
            print(f"  {CYAN}→{NC}  Синхронизирую {len(_vless_users)} VLESS-юзеров в Mieru...")
            _stats = _sync_all_from_vless(_vless_users)
            _mieru_stats = _stats.get("mieru", {})
            if _mieru_stats.get("created", 0) > 0:
                print(f"  {GREEN}✓{NC}  Добавлено в Mieru: {_mieru_stats['created']} юзеров")
    except Exception as _e:
        print(f"  {YELLOW}⚠{NC}  Sync VLESS-юзеров не удался: {_e}")

    # ── Итог ──────────────────────────────────────────────────────────────────
    server_ip      = _get_server_ip()
    uname          = users[0]["username"]
    pwd            = users[0]["password"]
    share_link     = _gen_client_share_link(server_ip, port_start, port_end, protocol, uname, pwd,
                                              traffic_preset=state.get("traffic_preset", "basic"))
    share_link_neko = _gen_client_share_link_nekobox(server_ip, port_start, protocol, uname, pwd)

    os.system("clear")
    _box_top("✅  УСТАНОВКА ЗАВЕРШЕНА  •  MIERU")
    _box_row()
    _box_ok("mita установлен и запущен." if svc_ok else
            "Установлен, но сервис не запустился — проверьте логи.")
    _box_row()
    _box_kv("IP сервера:", f"{YELLOW}{server_ip}{NC}")
    port_str = str(port_start) if port_start == port_end else f"{port_start}-{port_end}"
    _box_kv("Порт(ы):",    f"{YELLOW}{port_str}/{protocol}{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Ссылка для Karing (sing-box core):{NC}")
    _box_row()
    _box_link(share_link)
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Ссылка для Nekobox / Nyamebox:{NC}")
    _box_row()
    _box_link(share_link_neko)
    _box_row()
    _box_sep()
    _box_warn("Karing: убедитесь что выбрано ядро sing-box (не Xray-core!)")
    _box_info("Добавьте пользователей через пункт [2].")
    _box_warn("Убедитесь что время на клиенте синхронизировано!")
    _box_bot()
    print()
    _print_qr(share_link, f"Karing / mierus:// для {uname}")
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ
# ══════════════════════════════════════════════════════════════════════════════
def _users_menu() -> None:
    while True:
        os.system("clear")
        state  = proto_load_state(_MODULE_STATE)
        users  = state.get("users", [])
        server_ip  = _get_server_ip()
        port_start = state.get("port_start", _DEFAULT_PORT_START)
        port_end   = state.get("port_end",   _DEFAULT_PORT_END)
        protocol   = state.get("protocol",   _DEFAULT_PROTOCOL)

        _box_top("👥  ПОЛЬЗОВАТЕЛИ  •  MIERU")
        _box_row()
        _box_kv("Пользователей:", str(len(users)))
        port_str = str(port_start) if port_start == port_end else f"{port_start}-{port_end}"
        _box_kv("Порт(ы):", f"{port_str}/{protocol}")
        _box_row(); _box_sep()

        if users:
            _box_row(f"  {BOLD}{CYAN}{'№':<4}{'Логин':<20}{'Пароль'}{NC}")
            _box_sep()
            for i, u in enumerate(users, 1):
                _box_row(
                    f"  {DIM}{i:<4}{NC}"
                    f"{CYAN}{u.get('username','?'):<20}{NC}"
                    f"{DIM}{u.get('password','?')[:16]}...{NC}"
                )
        else:
            _box_warn("Пользователей нет.")

        _box_row(); _box_sep()
        _box_item("1", "➕  Добавить пользователя")
        _box_item("2", "🔗  Показать ссылку + QR")
        _box_item("3", "📋  Показать sing-box JSON")
        _box_item("4", f"{RED}🗑️   Удалить пользователя{NC}")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot(); print()

        try:
            ch = proto_ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled: break

        if ch == "1":
            try: _add_user(state)
            except _Cancelled: pass
        elif ch == "2":
            try: _show_user_link(users, server_ip, port_start, port_end, protocol)
            except _Cancelled: pass
        elif ch == "3":
            try: _show_singbox_json(users, server_ip, port_start, port_end, protocol)
            except _Cancelled: pass
        elif ch == "4":
            try: _delete_user(users, state)
            except _Cancelled: pass
        elif ch in ("q", ""): break

def _add_user(state: dict) -> None:
    os.system("clear")
    _box_top("➕  ДОБАВИТЬ ПОЛЬЗОВАТЕЛЯ  •  MIERU")
    _box_row(); _box_bot(); print()

    try:
        while True:
            username = proto_ask(f"  {CYAN}Логин: {NC}", c=True).strip()
            if not username:
                print(f"  {RED}✗{NC}  Логин не может быть пустым."); _pause(); return

            if not _RE_USERNAME.match(username):
                bad_chars = sorted(set(ch for ch in username if not _RE_USERNAME_CHAR.match(ch)))
                print(f"  {RED}✗{NC}  Недопустимые символы: {YELLOW}{' '.join(bad_chars)}{NC}")
                print(f"  {DIM}Разрешены только латиница (a-z, A-Z), цифры и _ -{NC}")
                print(f"  {DIM}Похоже, при вводе была активна не та раскладка клавиатуры.{NC}")
                print(f"  {DIM}Переключите раскладку на английскую и введите логин ещё раз.{NC}\n")
                continue

            break

        users = state.get("users", [])
        if any(u["username"] == username for u in users):
            print(f"  {YELLOW}⚠{NC}  Пользователь уже существует."); _pause(); return

        raw_pass = proto_ask(
            f"  {CYAN}Пароль (Enter=авто): {NC}", default="", c=True,
        ).strip()
        password = raw_pass or proto_gen_password()
    except _Cancelled: raise

    users.append({"username": username, "password": password})
    state["users"] = users
    proto_save_state(_MODULE_STATE, state)

    # Применяем новый конфиг (с traffic_pattern если установлен)
    _tp_name = state.get("traffic_preset", "basic")
    _tp_config = _MIERU_TRAFFIC_PRESETS.get(_tp_name, {}).get("config")
    cfg = _build_server_config(
        users,
        state.get("port_start", _DEFAULT_PORT_START),
        state.get("port_end",   _DEFAULT_PORT_END),
        state.get("protocol",   _DEFAULT_PROTOCOL),
        traffic_pattern=_tp_config,
    )
    err = _apply_server_config(cfg)
    if not err:
        _run(["systemctl", "reload-or-restart", _SERVICE_NAME])

    server_ip  = _get_server_ip()
    port_start = state.get("port_start", _DEFAULT_PORT_START)
    port_end   = state.get("port_end",   _DEFAULT_PORT_END)
    protocol   = state.get("protocol",   _DEFAULT_PROTOCOL)
    share_link      = _gen_client_share_link(server_ip, port_start, port_end, protocol, username, password,
                                               traffic_preset=state.get("traffic_preset", "basic"))
    share_link_neko = _gen_client_share_link_nekobox(server_ip, port_start, protocol, username, password)

    os.system("clear")
    _box_top("✅  ПОЛЬЗОВАТЕЛЬ ДОБАВЛЕН")
    _box_row()
    _box_kv("Логин:", f"{YELLOW}{username}{NC}")
    _box_kv("Пароль:", f"{YELLOW}{password}{NC}")
    if err: _box_warn(f"Ошибка конфига: {err}")
    else: _box_ok("Конфиг применён.")
    _box_row(); _box_sep()
    _box_row(f"  {BOLD}{WHITE}Ссылка для Karing (sing-box core):{NC}")
    _box_row()
    _box_link(share_link)
    _box_row(); _box_sep()
    _box_row(f"  {BOLD}{WHITE}Ссылка для Nekobox / Nyamebox:{NC}")
    _box_row()
    _box_link(share_link_neko)
    _box_row(); _box_bot()
    print()
    _print_qr(share_link, f"Karing / mierus:// для {username}")
    _pause()

def _show_user_link(users: list, server_ip: str,
                    port_start: int, port_end: int, protocol: str) -> None:
    if not users:
        print(f"  {YELLOW}⚠{NC}  Пользователей нет."); _pause(); return

    os.system("clear")
    _box_top("🔗  ССЫЛКА  •  MIERU")
    _box_row()
    for i, u in enumerate(users, 1):
        _box_row(f"  {DIM}{i}.{NC}  {CYAN}{u.get('username','?')}{NC}")
    _box_row(); _box_item("Q", "← Отмена"); _box_bot(); print()

    try:
        num = proto_ask(f"{CYAN}Номер: {NC}", c=True).strip()
    except _Cancelled: raise
    if num.lower() == "q" or not num: return
    try:
        idx = int(num) - 1; user = users[idx]
    except (ValueError, IndexError):
        print(f"  {RED}✗{NC}  Неверный номер."); _pause(); return

    # Загружаем state для получения traffic_preset
    _state = proto_load_state(_MODULE_STATE)
    share_link      = _gen_client_share_link(server_ip, port_start, port_end, protocol,
                                               user["username"], user["password"],
                                               traffic_preset=_state.get("traffic_preset", "basic"))
    share_link_neko = _gen_client_share_link_nekobox(server_ip, port_start, protocol,
                                                      user["username"], user["password"])
    os.system("clear")
    _box_top(f"🔗  {user['username']}  •  MIERU")
    _box_row()
    _box_kv("Логин:", f"{YELLOW}{user['username']}{NC}")
    _box_kv("Пароль:", f"{YELLOW}{user['password']}{NC}")
    _box_row(); _box_sep()
    _box_row(f"  {BOLD}{WHITE}Ссылка для Karing (sing-box core):{NC}")
    _box_row()
    _box_link(share_link)
    _box_row(); _box_sep()
    _box_row(f"  {BOLD}{WHITE}Ссылка для Nekobox / Nyamebox:{NC}")
    _box_row()
    _box_link(share_link_neko)
    _box_row(); _box_bot()
    print()
    _print_qr(share_link, f"Karing / mierus:// для {user['username']}")
    _pause()

def _show_singbox_json(users: list, server_ip: str,
                        port_start: int, port_end: int, protocol: str) -> None:
    if not users:
        print(f"  {YELLOW}⚠{NC}  Пользователей нет."); _pause(); return

    os.system("clear")
    _box_top("📋  SING-BOX JSON  •  MIERU")
    _box_row()
    for i, u in enumerate(users, 1):
        _box_row(f"  {DIM}{i}.{NC}  {CYAN}{u.get('username','?')}{NC}")
    _box_row(); _box_item("Q", "← Отмена"); _box_bot(); print()

    try:
        num = proto_ask(f"{CYAN}Номер: {NC}", c=True).strip()
    except _Cancelled: raise
    if num.lower() == "q" or not num: return
    try:
        idx = int(num) - 1; user = users[idx]
    except (ValueError, IndexError):
        print(f"  {RED}✗{NC}  Неверный номер."); _pause(); return

    outbound = _gen_singbox_outbound(
        server_ip, port_start, port_end, protocol,
        user["username"], user["password"],
    )

    # Полный sing-box конфиг для импорта в Karing
    full_config = {
        "log": {"level": "info"},
        "dns": {
            "servers": [
                {"tag": "google", "address": "8.8.8.8"},
                {"tag": "local", "address": "1.1.1.1", "detour": "direct"}
            ]
        },
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct"}
        ],
        "route": {"final": outbound["tag"]}
    }
    json_str = json.dumps(full_config, indent=2, ensure_ascii=False)

    # Сохраняем в файл чтобы можно было скопировать
    cfg_path = Path(f"/tmp/karing-mieru-{user['username']}.json")
    cfg_path.write_text(json_str)

    os.system("clear")
    _box_top("📋  SING-BOX КОНФИГ ДЛЯ KARING")
    _box_row()
    _box_ok(f"Конфиг сохранён: {cfg_path}")
    _box_row()
    _box_info("Импорт в Karing: Добавить подписку → вставить путь к файлу или JSON")
    _box_warn("mierus:// ссылка НЕ работает в Karing — используйте JSON файл!")
    _box_row(); _box_sep()
    for line in json_str.splitlines():
        _box_row(f"  {DIM}{line}{NC}")
    _box_row(); _box_bot()
    _pause()

def _delete_user(users: list, state: dict) -> None:
    if not users:
        print(f"  {YELLOW}⚠{NC}  Пользователей нет."); _pause(); return
    if len(users) == 1:
        print(f"  {RED}✗{NC}  Нельзя удалить последнего пользователя."); _pause(); return

    os.system("clear")
    _box_top("🗑️  УДАЛИТЬ ПОЛЬЗОВАТЕЛЯ  •  MIERU")
    _box_row()
    for i, u in enumerate(users, 1):
        _box_row(f"  {DIM}{i}.{NC}  {CYAN}{u.get('username','?')}{NC}")
    _box_row(); _box_item("Q", "← Отмена"); _box_bot(); print()

    try:
        num = proto_ask(f"{CYAN}Номер: {NC}", c=True).strip()
    except _Cancelled: raise
    if num.lower() == "q" or not num: return
    try:
        idx = int(num) - 1; user = users[idx]
    except (ValueError, IndexError):
        print(f"  {RED}✗{NC}  Неверный номер."); _pause(); return

    try:
        confirm = proto_ask(
            f"  {YELLOW}Удалить {user['username']}? [y/N]: {NC}",
            default="n", c=True,
        ).strip().lower()
    except _Cancelled: raise
    if confirm != "y": return

    users.pop(idx)
    state["users"] = users
    proto_save_state(_MODULE_STATE, state)

    cfg = _build_server_config(
        users,
        state.get("port_start", _DEFAULT_PORT_START),
        state.get("port_end",   _DEFAULT_PORT_END),
        state.get("protocol",   _DEFAULT_PROTOCOL),
    )
    err = _apply_server_config(cfg)
    if not err:
        _run(["systemctl", "reload-or-restart", _SERVICE_NAME])
    print(f"  {GREEN}✓{NC}  Пользователь удалён.")
    _pause()


# ══════════════════════════════════════════════════════════════════════════════
#  SYNC CONTRACT (v4.25) — для реестра _SYNCABLE_PROTOCOLS в rest_api.py
#  См. naiveproxy.py для документации контракта.
# ══════════════════════════════════════════════════════════════════════════════
def _username_from_email(email: str) -> str:
    """Convention: username = email.split('@')[0].strip()."""
    return (email or "").split("@")[0].strip()

def is_active() -> bool:
    """True если Mieru установлен И сервис mita запущен."""
    try:
        if not _is_installed():
            return False
        r = _run(["systemctl", "is-active", _SERVICE_NAME],
                 capture=True, check=False)
        return r.returncode == 0 and r.stdout.strip() == "active"
    except Exception:
        return False

def ensure_user_full(user: dict) -> bool:
    """Создаёт Mieru-аккаунт из full user dict.

    Username = email.split('@')[0]. Валидируется через _RE_USERNAME.
    Пароль генерируется автоматически. /etc/mita/server.json
    перегенерируется, mita перезапускается.
    """
    try:
        if not _is_installed():
            return True  # не установлено — пропускаем
        email = user.get("email", "") or ""
        if not email:
            return False
        username = _username_from_email(email)
        if not username or not _RE_USERNAME.match(username):
            return False
        state = proto_load_state(_MODULE_STATE)
        users = state.get("users", [])
        if any(u.get("username") == username for u in users):
            return True  # уже есть — идемпотентность
        password = proto_gen_password()
        users.append({"username": username, "password": password})
        state["users"] = users
        proto_save_state(_MODULE_STATE, state)
        # Регенерируем server.json и перезапускаем mita.
        _tp_name = state.get("traffic_preset", "basic")
        _tp_config = _MIERU_TRAFFIC_PRESETS.get(_tp_name, {}).get("config")
        cfg = _build_server_config(
            users,
            state.get("port_start", _DEFAULT_PORT_START),
            state.get("port_end",   _DEFAULT_PORT_END),
            state.get("protocol",   _DEFAULT_PROTOCOL),
            traffic_pattern=_tp_config,
        )
        err = _apply_server_config(cfg)
        if not err:
            _run(["systemctl", "reload-or-restart", _SERVICE_NAME])
        return True
    except Exception as e:
        try:
            print(f"  {RED}✗{NC}  mieru.ensure_user_full: {e}")
        except Exception:
            pass
        return False

def ensure_user(name: str) -> bool:
    """Legacy contract — принимает email или name."""
    return ensure_user_full({"email": name, "name": name})

def remove_user_full(user: dict) -> bool:
    """Удаляет Mieru-аккаунт по full user dict."""
    try:
        if not _is_installed():
            return True
        email = user.get("email", "") or ""
        username = _username_from_email(email)
        if not username:
            return False
        state = proto_load_state(_MODULE_STATE)
        users = state.get("users", [])
        new_users = [u for u in users if u.get("username") != username]
        if len(new_users) == len(users):
            return True  # не было такого — идемпотентность
        state["users"] = new_users
        proto_save_state(_MODULE_STATE, state)
        _tp_name = state.get("traffic_preset", "basic")
        _tp_config = _MIERU_TRAFFIC_PRESETS.get(_tp_name, {}).get("config")
        cfg = _build_server_config(
            new_users,
            state.get("port_start", _DEFAULT_PORT_START),
            state.get("port_end",   _DEFAULT_PORT_END),
            state.get("protocol",   _DEFAULT_PROTOCOL),
            traffic_pattern=_tp_config,
        )
        err = _apply_server_config(cfg)
        if not err:
            _run(["systemctl", "reload-or-restart", _SERVICE_NAME])
        return True
    except Exception as e:
        try:
            print(f"  {RED}✗{NC}  mieru.remove_user_full: {e}")
        except Exception:
            pass
        return False

def remove_user(name: str) -> bool:
    """Legacy contract — принимает email или name."""
    return remove_user_full({"email": name, "name": name})

def rename_user_full(old_user: dict, new_user: dict) -> bool:
    """Переименование = remove + add (mita не поддерживает rename in-place)."""
    try:
        ok1 = remove_user_full(old_user)
        ok2 = ensure_user_full(new_user)
        return ok1 and ok2
    except Exception:
        return False

def rename_user(old_name: str, new_name: str) -> bool:
    """Legacy contract — принимает email или name."""
    return rename_user_full(
        {"email": old_name, "name": old_name},
        {"email": new_name, "name": new_name},
    )

# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС
# ══════════════════════════════════════════════════════════════════════════════
def _show_status() -> None:
    os.system("clear")
    state = proto_load_state(_MODULE_STATE)
    _box_top("📊  СТАТУС  •  MIERU")
    _box_row()

    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    svc_ok = r.stdout.strip() == "active"
    _box_kv("Сервис:",
            f"{GREEN}● активен{NC}" if svc_ok else f"{RED}● остановлен{NC}")
    _box_kv("Версия:", state.get("version", proto_get_installed_version(_MITA_BIN, "version", strip_v=True) or "—"))

    port_start = state.get("port_start", "—")
    port_end   = state.get("port_end",   "—")
    protocol   = state.get("protocol",   "—")
    port_str   = str(port_start) if port_start == port_end else f"{port_start}-{port_end}"
    _box_kv("Порт(ы):", f"{port_str}/{protocol}")
    _box_kv("Пользователей:", str(len(state.get("users", []))))

    sync_ok, sync_msg = _check_time_sync()
    _box_kv("Время NTP:",
            f"{GREEN}✓ {sync_msg}{NC}" if sync_ok else f"{RED}✗ {sync_msg}{NC}")

    _box_row(); _box_sep()
    _box_row(f"  {BOLD}{WHITE}Последние 30 строк журнала:{NC}")
    _box_row()

    r2 = subprocess.run(
        ["journalctl", "-u", _SERVICE_NAME, "-n", "30",
         "--no-pager", "--output=short-monotonic"],
        capture_output=True, encoding="utf-8", errors="replace",
        env={**os.environ, "LANG": "C.UTF-8"},
    )
    for line in (r2.stdout or "Нет записей").splitlines():
        _box_log_line(line)
    _box_row(); _box_bot()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ГАЙД
# ══════════════════════════════════════════════════════════════════════════════
def _show_guide() -> None:
    while True:
        os.system("clear")
        _box_top("📖  ГАЙД  •  MIERU")
        _box_row()
        _box_item("1", "Как работает Mieru")
        _box_item("2", "Синхронизация времени — почему важна")
        _box_item("3", "Клиентские приложения")
        _box_item("4", "TCP vs UDP — что выбрать")
        _box_item("5", "Чем Mieru отличается от NaiveProxy")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot(); print()

        try:
            ch = proto_ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled: break

        if ch == "1":   _guide_how()
        elif ch == "2": _guide_time()
        elif ch == "3": _guide_clients()
        elif ch == "4": _guide_protocol()
        elif ch == "5": _guide_diff()
        elif ch in ("q", ""): break

def _guide_how() -> None:
    os.system("clear")
    _box_top("⚙️  КАК РАБОТАЕТ MIERU")
    _box_row()
    _box_info("Mieru — mTLS туннель с защитой от анализа трафика.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Принцип:")
    _box_row()
    _box_info("mTLS — взаимная аутентификация клиента и сервера")
    _box_info("Рандомный padding — размер пакетов непредсказуем")
    _box_info("Временная метка — защита от replay атак (±30 сек)")
    _box_info("DPI видит зашумлённый зашифрованный поток без паттернов")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Схема:")
    _box_row()
    _box_row(f"  {CYAN}Клиент → mTLS/random padding → mita → SOCKS5 → Интернет{NC}")
    _box_row()
    _box_sep()
    _box_info("Домен не нужен — достаточно IP и порта.")
    _box_info("Работает на портах 2012-2022 по умолчанию.")
    _box_bot(); _pause()

def _guide_time() -> None:
    os.system("clear")
    _box_top("⏱️  СИНХРОНИЗАЦИЯ ВРЕМЕНИ  •  MIERU")
    _box_row()
    _box_warn("Mieru проверяет временную метку в каждом пакете!")
    _box_warn("Расхождение более ±30 сек = соединение отклоняется.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}На сервере:")
    _box_row()
    _box_row(f"  {DIM}timedatectl status{NC}")
    _box_row(f"  {DIM}# NTP synchronized: yes{NC}")
    _box_row()
    _box_row(f"  {DIM}# Если нет — установить chrony:{NC}")
    _box_row(f"  {DIM}apt install chrony && systemctl enable --now chrony{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}На клиенте (Android):")
    _box_row()
    _box_info("Настройки → Дата и время → Авто-синхронизация: ВКЛ")
    _box_row()
    _box_sep()
    _box_warn("Модуль автоматически устанавливает chrony при установке.")
    _box_bot(); _pause()

def _guide_clients() -> None:
    os.system("clear")
    state     = proto_load_state(_MODULE_STATE)
    server_ip = _get_server_ip()
    port_start = state.get("port_start", _DEFAULT_PORT_START)
    port_end   = state.get("port_end",   _DEFAULT_PORT_END)

    _box_top("📱  КЛИЕНТСКИЕ ПРИЛОЖЕНИЯ  •  MIERU")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Клиенты с поддержкой Mieru:")
    _box_row()
    _box_kv("  Karing",   "iOS / Android / Windows / macOS", 16)
    _box_kv("  Nekobox",  "Android", 16)
    _box_kv("  sing-box", "CLI — все платформы", 16)
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Импорт:")
    _box_row()
    _box_info("1. Через QR-код: пункт [2] → выбрать пользователя → QR")
    _box_info("2. Через mierus:// ссылку: пункт [2] → скопировать ссылку")
    _box_info("3. Через sing-box JSON: пункт [3] → вставить в конфиг")
    _box_row()
    _box_sep()
    _box_warn("Убедитесь что время синхронизировано на клиенте!")
    _box_bot(); _pause()

def _guide_protocol() -> None:
    os.system("clear")
    _box_top("🔌  TCP vs UDP  •  MIERU")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}TCP:")
    _box_row()
    _box_info("Надёжная доставка, встроенное управление потоком")
    _box_info("Лучше для HTTP/HTTPS трафика")
    _box_info("Стабильнее на плохих каналах")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}UDP:")
    _box_row()
    _box_info("Меньше задержки, лучше для VoIP/игр")
    _box_info("Может быть заблокирован операторами РФ")
    _box_info("Нужно открыть UDP-порты на firewall")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Рекомендация:")
    _box_row()
    _box_info("Для большинства случаев — TCP")
    _box_info("UDP — только если TCP медленный или недоступен")
    _box_bot(); _pause()

def _guide_diff() -> None:
    os.system("clear")
    _box_top("⚖️  MIERU vs NAIVEPROXY")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}NaiveProxy:")
    _box_row()
    _box_info("Маскировка: HTTPS/HTTP2 с Chromium fingerprint")
    _box_info("Требует домен + TLS сертификат")
    _box_info("Probe resistance — фейковый сайт для зондов")
    _box_info("Клиенты: Karing, Nekobox, ShadowRocket")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Mieru:")
    _box_row()
    _box_info("Маскировка: mTLS + random padding (нет паттернов)")
    _box_info("Домен НЕ нужен — только IP и порт")
    _box_info("Требует синхронизацию времени ±30 сек")
    _box_info("Клиенты: Karing, Nekobox, sing-box CLI")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Когда что выбрать:")
    _box_row()
    _box_info("Есть домен + нужен probe resistance → NaiveProxy")
    _box_info("Нет домена + нужна маскировка трафика → Mieru")
    _box_info("Максимальная защита → оба одновременно")
    _box_bot(); _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  УДАЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _full_uninstall(silent: bool = False) -> bool:
    if not silent:
        os.system("clear")
        _box_top("🗑️  УДАЛЕНИЕ  •  MIERU")
        _box_row()
        _box_warn("Будет удалено:")
        _box_row(f"  {DIM}  • Сервис systemd  (mita){NC}")
        _box_row(f"  {DIM}  • Бинарники       ({_MITA_BIN}, {_MIERU_BIN}){NC}")
        _box_row(f"  {DIM}  • Конфиги          ({_CFG_DIR}){NC}")
        _box_row(f"  {DIM}  • iptables порты{NC}")
        _box_row()
        _box_warn("Xray, VLESS и другие службы не затрагиваются.")
        _box_row()
        _box_item("Y", f"{RED}Да, удалить{NC}")
        _box_item("N", "Нет, отмена")
        _box_bot(); print()
        try:
            ans = proto_ask(f"{CYAN}Подтверждение [y/N]: {NC}", c=True).strip().lower()
        except _Cancelled: return False
        if ans != "y":
            print(f"  {DIM}Отменено.{NC}"); _pause(); return False

    state = proto_load_state(_MODULE_STATE)
    port_start = state.get("port_start", _DEFAULT_PORT_START)
    port_end   = state.get("port_end",   _DEFAULT_PORT_END)
    protocol   = state.get("protocol",   _DEFAULT_PROTOCOL)

    _run(["systemctl", "stop",    _SERVICE_NAME])
    _run(["systemctl", "disable", _SERVICE_NAME])
    if _SERVICE_FILE.exists(): _SERVICE_FILE.unlink()
    _run(["systemctl", "daemon-reload"])
    _run(["systemctl", "reset-failed"], capture=True)

    for b in (_MITA_BIN, _MIERU_BIN):
        if b.exists(): b.unlink()
    if _CFG_DIR.exists():
        shutil.rmtree(_CFG_DIR, ignore_errors=True)

    _close_ports(protocol, port_start, port_end)

    try:
        if _MODULE_STATE.exists(): _MODULE_STATE.unlink()
    except Exception: pass

    if not silent:
        print(f"  {GREEN}✓{NC}  Mieru полностью удалён.")
        _pause()
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ
# ══════════════════════════════════════════════════════════════════════════════
def do_mieru_menu() -> None:
    """Точка входа из _core.py."""
    while True:
        os.system("clear")
        installed  = _is_installed()
        state      = proto_load_state(_MODULE_STATE)

        r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
        svc_ok = r.stdout.strip() == "active"

        svc_str = (
            f"{GREEN}● активен{NC}"  if svc_ok    else
            f"{RED}● остановлен{NC}" if installed else
            f"{YELLOW}● не установлен{NC}"
        )

        _box_top("MIERU  •  mTLS / random padding")
        _box_row()
        _box_kv("Статус:", svc_str)

        if installed:
            port_start = state.get("port_start", "—")
            port_end   = state.get("port_end",   "—")
            protocol   = state.get("protocol",   "—")
            port_str   = (str(port_start) if port_start == port_end
                          else f"{port_start}-{port_end}")
            _box_kv("Порт(ы):",       f"{YELLOW}{port_str}/{protocol}{NC}")
            _box_kv("Пользователей:", str(len(state.get("users", []))))
            # Показываем текущий пресет обфускации
            tp_name = state.get("traffic_preset", "basic")
            _box_kv("Обфускация:",    f"{CYAN}{tp_name}{NC}")
            sync_ok, _ = _check_time_sync()
            _box_kv("Время NTP:",
                    f"{GREEN}✓ синхронизировано{NC}" if sync_ok
                    else f"{RED}✗ не синхронизировано{NC}")

        _box_row(); _box_sep()

        if not installed:
            _box_item("1", "🚀  Установить Mieru")
        else:
            _box_item("1", "🚀  Переустановить")
            _box_item("2", "👥  Управление пользователями")
            _box_item("3", "🔄  Перезапустить сервис")
            _box_item("4", "📊  Статус / логи")
            _box_item("5", "📈  Статистика трафика")
            _box_item("6", "🔒  Пресеты обфускации (traffic pattern)")
            _box_sep()
            _box_item("9", f"{RED}🗑️   Удалить Mieru{NC}")

        _box_sep()
        _box_item("G", "📖  Гайд: как работает, клиенты, TCP vs UDP")
        _box_sep()
        _box_item("Q", "← Назад в главное меню VLESS")
        _box_bot(); print()

        try:
            ch = proto_ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled: break

        if ch == "1":
            _run_install()
        elif ch == "2" and installed:
            try: _users_menu()
            except _Cancelled: pass
        elif ch == "3" and installed:
            _run(["systemctl", "restart", _SERVICE_NAME])
            time.sleep(1)
            r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
            print(f"\n  {'✓' if r.stdout.strip()=='active' else '⚠'}  "
                  f"{'Перезапущен.' if r.stdout.strip()=='active' else 'Проверьте логи.'}")
            _pause()
        elif ch == "4" and installed:
            _show_status()
        elif ch == "5" and installed:
            try:
                from chimera.modules.mieru_stats import do_mieru_stats_menu
                do_mieru_stats_menu()
            except ImportError as _e:
                print(f"\n  {RED}✗{NC}  Модуль статистики не найден: {_e}"); _pause()
            except _Cancelled:
                pass
        elif ch == "6" and installed:
            try: _obfuscation_menu()
            except _Cancelled: pass
        elif ch == "9" and installed:
            try: _full_uninstall(silent=False)
            except _Cancelled:
                print(f"  {DIM}Отменено.{NC}"); _pause()
        elif ch == "g":
            try: _show_guide()
            except _Cancelled: pass
        elif ch in ("q", ""):
            break


# ══════════════════════════════════════════════════════════════════════════════
#  ПРЕСЕТЫ ОБФУСКАЦИИ (traffic pattern)
# ══════════════════════════════════════════════════════════════════════════════

# Пресеты для серверного конфига mita (JSON-объект trafficPattern).
# Формат: https://github.com/enfein/mieru/blob/main/docs/traffic-pattern.md
# ВАЖНО: mita НЕ поддерживает hot-reload trafficPattern — нужен restart.
_MIERU_TRAFFIC_PRESETS = {
    "disabled": {
        "label": "🔓 Disabled (без обфускации)",
        "description": "Минимум оверхеда, максимальная скорость",
        "config": None,  # trafficPattern не добавляется в конфиг
    },
    "basic": {
        "label": "🔒 Basic (базовый)",
        "description": "Лёгкая обфускация: printable-нонсы. Рекомендуется по умолчанию.",
        "config": {
            "nonce": {"type": "NONCE_TYPE_PRINTABLE"},
        },
    },
    "medium": {
        "label": "🔒 Medium (средний)",
        "description": "Нонсы + TCP-фрагментация с задержкой 10мс",
        "config": {
            "nonce": {"type": "NONCE_TYPE_PRINTABLE"},
            "tcpFragment": {"enable": True, "maxSleepMs": 10},
        },
    },
    "aggressive": {
        "label": "🔒 Aggressive (максимальный)",
        "description": "Нонсы + агрессивная фрагментация + паддинг",
        "config": {
            "nonce": {"type": "NONCE_TYPE_PRINTABLE"},
            "tcpFragment": {"enable": True, "maxSleepMs": 20},
            "padding": {"maxMiddlePaddingLen": 64, "maxEndPaddingLen": 128},
        },
    },
}


def _obfuscation_menu() -> None:
    """TUI-меню выбора пресета обфускации Mieru (traffic pattern).

    Выбор пресета = немедленное применение: обновление state,
    перегенерация server.json с trafficPattern, mita apply config +
    systemctl restart mita (mita не поддерживает hot-reload trafficPattern).
    """
    state = proto_load_state(_MODULE_STATE)
    current = state.get("traffic_preset", "basic")

    os.system("clear")
    print()
    _box_top("🔒  Пресеты обфускации Mieru (traffic pattern)")
    _box_row()
    _box_kv("Текущий пресет:", f"{CYAN}{current}{NC}")
    _box_row()
    _box_sep()

    presets = list(_MIERU_TRAFFIC_PRESETS.items())
    for i, (name, preset) in enumerate(presets, 1):
        marker = f" {GREEN}← текущий{NC}" if name == current else ""
        _box_item(str(i), f"{preset['label']}{marker}")
        _box_row(f"    {DIM}{preset['description']}{NC}")

    _box_row()
    _box_sep()
    _box_item("Q", "← Назад")
    _box_bot()
    print()

    try:
        ch = proto_ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
    except _Cancelled:
        return

    if ch in ("q", ""):
        return

    try:
        idx = int(ch) - 1
    except ValueError:
        _box_warn("Неверный выбор")
        _pause()
        return

    if not (0 <= idx < len(presets)):
        _box_warn("Неверный выбор")
        _pause()
        return

    selected_name, selected_preset = presets[idx]
    if selected_name == current:
        _box_info("Этот пресет уже активен")
        _pause()
        return

    # Подтверждение
    print()
    if not proto_ask(f"{CYAN}Применить пресет '{selected_name}'?{NC} "
                     f"(mita будет перезапущен) [y/N]: ", default="").strip().lower() in ("y", "yes", "д", "да"):
        print(f"  {DIM}Отменено.{NC}")
        _pause()
        return

    # Применяем
    _box_info(f"Применение пресета '{selected_name}'...")

    # Перегенерация server.json
    users = state.get("users", [])
    port_start = state.get("port_start", _DEFAULT_PORT_START)
    port_end = state.get("port_end", _DEFAULT_PORT_END)
    protocol = state.get("protocol", _DEFAULT_PROTOCOL)
    tp_config = selected_preset["config"]

    cfg = _build_server_config(users, port_start, port_end, protocol,
                               traffic_pattern=tp_config)
    err = _apply_server_config(cfg)
    if err:
        _box_warn(f"Ошибка применения конфига: {err}")
        _box_warn("State не изменён — сервер работает с прежним пресетом.")
        _pause()
        return

    # mita НЕ поддерживает hot-reload trafficPattern — нужен restart
    _box_info("Перезапуск mita (trafficPattern не поддерживает hot-reload)...")
    _run(["systemctl", "restart", _SERVICE_NAME])
    time.sleep(2)

    r = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
    if r.stdout.strip() == "active":
        # mita успешно перезапущен — теперь безопасно коммитить state
        state["traffic_preset"] = selected_name
        proto_save_state(_MODULE_STATE, state)
        _box_ok(f"Пресет '{selected_name}' применён. mita перезапущен.")
    else:
        # mita не поднялся — state НЕ меняем, пользователю нужно разобраться
        _box_warn(f"mita не запустился после restart. "
                  f"State не изменён — пресет '{current}' остаётся активным.")
        _box_warn(f"Проверьте: journalctl -u {_SERVICE_NAME}")
        # Пытаемся откатить server.json на прежний конфиг
        old_tp = _MIERU_TRAFFIC_PRESETS.get(current, {}).get("config")
        old_cfg = _build_server_config(users, port_start, port_end, protocol,
                                       traffic_pattern=old_tp)
        _apply_server_config(old_cfg)
        _run(["systemctl", "restart", _SERVICE_NAME])
        time.sleep(2)
        r2 = _run(["systemctl", "is-active", _SERVICE_NAME], capture=True)
        if r2.stdout.strip() == "active":
            _box_info("Откат на прежний пресет выполнен, mita активна.")
        else:
            _box_warn("Откат не удался — mita не активна. Требуется ручное вмешательство.")

    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  УЧАСТИЕ В ОБЩЕМ БЭКАПЕ (единая автообнаружаемая система chimera.modules.backup_registry)
# ══════════════════════════════════════════════════════════════════════════════
def get_backup_paths() -> list[tuple[Path, str]]:
    """Возвращает [(реальный_путь, имя_в_архиве), ...] — всё необходимое для
    восстановления Mieru (mita) БЕЗ переиздания пользовательских секретов.

    Файлы:
      • /etc/mita/server.json — основной конфиг mita-сервера.
      • /etc/systemd/system/mita.service — systemd unit.
      • /var/lib/xray-installer/mieru.json — module state (порт, версия и т.д.).

    Пустой список если протокол не установлен. Никогда не бросает исключение.
    """
    try:
        candidates = [
            (_SERVER_CFG,   "mita/server.json"),
            (_SERVICE_FILE, "etc/systemd/system/mita.service"),
            (_MODULE_STATE, "mieru/mieru_state.json"),
        ]
        return [(p, arcname) for p, arcname in candidates if p.exists()]
    except Exception:
        return []


# ══════════════════════════════════════════════════════════════════════════════
#  АВТОНОМНЫЙ ЗАПУСК
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}Запустите от root.{NC}"); sys.exit(1)
    try:
        do_mieru_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}"); sys.exit(0)

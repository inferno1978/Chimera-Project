"""
vless_installer/modules/slipgate.py
───────────────────────────────────────────────────────────────────────────────
SlipGate — DNS-туннельный транспорт для обхода полных блокировок.

Назначение:
  Когда все прямые соединения заблокированы (VLESS, WireGuard, TURN) —
  DNS-туннель работает потому что операторы не могут заблокировать DNS
  не нарушив работу всего интернета.
  Трафик прячется внутри DNS-запросов и выглядит как обычные DNS-резолвы.

Схема трафика:
  Android (SlipNet)
    │  DNS-запросы (UDP/53) с данными внутри
    ▼
  DNS-сервер оператора / публичный резолвер
    │  NS-делегирование на поддомен
    ▼
  VPS :53/udp — SlipGate (DNSTT/NoizDNS/Slipstream/VayDNS)
    │  расшифровка, Curve25519
    ▼
  SOCKS5 :1080 или SSH :22
    │
    ▼
  Интернет

Протоколы:
  • DNSTT    — стабильный DNS-туннель, Curve25519
  • NoizDNS  — DNSTT + DPI-обфускация (base36, CDN-prefix stripping)
  • Slipstream — QUIC поверх DNS
  • VayDNS   — KCP + Curve25519, настраиваемый wire format
  • NaiveProxy — HTTPS с Chromium-fingerprint, Auto-TLS (нужен домен)
  • StunTLS  — SSH over TLS + WebSocket, без домена

Требования для DNS-туннелей:
  • Свой домен с NS-записями делегированными на VPS
  • Порт 53/udp открыт на VPS

Требования для NaiveProxy:
  • Домен с A-записью на VPS
  • Порт 443/tcp открыт

Требования для StunTLS:
  • Порт 443/tcp открыт, домен не нужен

Клиентское приложение:
  SlipNet (Android) — github.com/anonvector/SlipNet
  CLI-клиент — slipnet-linux-amd64 (из релизов SlipNet)

Что модуль делает:
  • Устанавливает SlipGate одной командой (install.sh от авторов)
  • Предоставляет меню управления туннелями внутри инсталлера
  • Показывает полный гайд по настройке DNS и использованию SlipNet
  • Запускает/останавливает/перезапускает SlipGate и его сервисы
  • Показывает статус, логи, диагностику
  • При удалении — чисто убирает всё через slipgate uninstall

Что модуль НЕ трогает:
  • config.json Xray
  • state.json инсталлера
  • iptables-правила других модулей
  • Пользователей и ключи VLESS
  • Любые другие службы

Точка входа из _core.py:
    from vless_installer.modules.slipgate import do_slipgate_menu
    do_slipgate_menu()

Интеграция в _core.py:
  1. Импорт:
       from vless_installer.modules.slipgate import do_slipgate_menu
  2. Пункт меню (9):
       _box_row(f"  {CYAN}9{NC}  🌐 {TITLE}SlipGate / SlipNet{NC}")
       _box_row(f"     {DIM}DNS-туннели (DNSTT, NoizDNS, Slipstream) — обход полных блокировок{NC}")
  3. Обработчик:
       elif choice == "9":
           try:
               do_slipgate_menu()
           except ImportError as _e:
               warn(f"Модуль SlipGate не найден: {_e}")
               time.sleep(2)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
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
_SLIPGATE_BIN      = Path("/usr/local/bin/slipgate")
_SLIPGATE_CFG_DIR  = Path("/etc/slipgate")
_INSTALL_SCRIPT    = "https://raw.githubusercontent.com/anonvector/slipgate/main/install.sh"
_GITHUB_API        = "https://api.github.com/repos/anonvector/slipgate/releases/latest"
_SLIPNET_RELEASES  = "https://github.com/anonvector/SlipNet/releases/latest"
_MODULE_STATE_FILE = Path("/var/lib/xray-installer/slipgate.json")
_BOX_W             = 66

# ══════════════════════════════════════════════════════════════════════════════
#  BOX-РЕНДЕРИНГ
# ══════════════════════════════════════════════════════════════════════════════
def _plain(s: str) -> str:
    return re.sub(r'\033\[[0-9;]*m', '', s)

def _wlen(s: str) -> int:
    import unicodedata as _ud
    plain = _plain(s)
    width, chars = 0, list(plain)
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
                cut = i; break
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

# ══════════════════════════════════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНЫЕ
# ══════════════════════════════════════════════════════════════════════════════
class _Cancelled(Exception):
    pass

def _pause() -> None:
    try:
        print(f"\n  {DIM}Нажмите Enter...{NC}", end="", flush=True)
        input()
    except (KeyboardInterrupt, EOFError, UnicodeDecodeError):
        print()

def _ask(prompt: str, default: str = "", c: bool = False) -> str:
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

def _run(cmd: list, capture: bool = False, check: bool = False,
         env: Optional[dict] = None) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if env:
        kw["env"] = env
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    else:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

def _run_interactive(cmd: list) -> int:
    """Запускает команду с полным доступом к tty — для интерактивных меню."""
    return subprocess.call(cmd)

# ══════════════════════════════════════════════════════════════════════════════
#  СОСТОЯНИЕ МОДУЛЯ
# ══════════════════════════════════════════════════════════════════════════════
def _load_state() -> dict:
    if not _MODULE_STATE_FILE.exists():
        return {}
    try:
        return json.loads(_MODULE_STATE_FILE.read_text())
    except Exception:
        return {}

def _save_state(data: dict) -> None:
    try:
        _MODULE_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _MODULE_STATE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        _MODULE_STATE_FILE.chmod(0o600)
    except Exception as e:
        print(f"  {YELLOW}⚠{NC}  Не удалось сохранить slipgate.json: {e}")

def _is_installed() -> bool:
    return _SLIPGATE_BIN.exists()

# ══════════════════════════════════════════════════════════════════════════════
#  ВЕРСИЯ
# ══════════════════════════════════════════════════════════════════════════════
def _get_installed_version() -> Optional[str]:
    if not _SLIPGATE_BIN.exists():
        return None
    r = _run([str(_SLIPGATE_BIN), "version"], capture=True)
    out = (r.stdout or "") + (r.stderr or "")
    m = re.search(r'v?(\d+\.\d+[\.\d]*)', out)
    return m.group(1) if m else "unknown"

def _get_latest_version() -> str:
    try:
        req = urllib.request.Request(
            _GITHUB_API,
            headers={"User-Agent": "VLESS-Ultimate-Installer"},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        return data.get("tag_name", "unknown").lstrip("v")
    except Exception:
        return "unknown"

# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС СЕРВИСОВ
# ══════════════════════════════════════════════════════════════════════════════
def _get_services_status() -> dict:
    """
    Возвращает статус основных systemd-сервисов SlipGate.
    Сервисы динамические (по тегу туннеля), поэтому ищем по паттерну.
    """
    r = _run(
        ["systemctl", "list-units", "--type=service", "--no-pager",
         "--output=json", "slipgate*"],
        capture=True,
    )
    services: list = []
    if r.returncode == 0 and r.stdout.strip():
        try:
            units = json.loads(r.stdout)
            for u in units:
                services.append({
                    "name":   u.get("unit", ""),
                    "active": u.get("active", "") == "active",
                    "sub":    u.get("sub", ""),
                })
        except Exception:
            pass

    # Фоллбек через grep если json не сработал
    if not services:
        r2 = _run(
            ["systemctl", "list-units", "--type=service", "--no-pager",
             "--all", "slipgate*"],
            capture=True,
        )
        for line in (r2.stdout or "").splitlines():
            if "slipgate" in line:
                parts = line.split()
                if len(parts) >= 4:
                    services.append({
                        "name":   parts[0],
                        "active": parts[2] == "active",
                        "sub":    parts[3],
                    })

    return {"services": services, "count": len(services)}

def _get_tunnel_list() -> list:
    """Получает список туннелей через slipgate tunnel status."""
    if not _SLIPGATE_BIN.exists():
        return []
    r = _run([str(_SLIPGATE_BIN), "tunnel", "status"], capture=True)
    tunnels = []
    if r.returncode == 0:
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("─"):
                tunnels.append(line)
    return tunnels

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
    _box_top("🌐  УСТАНОВКА  •  SLIPGATE")
    _box_row()

    if _is_installed():
        _box_warn("SlipGate уже установлен.")
        _box_info(f"Версия: {_get_installed_version() or '?'}")
        _box_row()
        _box_item("1", "Переустановить / обновить")
        _box_item("Q", "← Отмена")
        _box_bot(); print()
        try:
            ch = _ask(f"{CYAN}Выбор [1/Q]: {NC}", c=True).strip().lower()
        except _Cancelled:
            return
        if ch != "1":
            return

    # Проверка curl
    if not shutil.which("curl"):
        _box_err("curl не найден. Установите: apt install curl")
        _box_bot(); _pause(); return

    os.system("clear")
    _box_top("🌐  УСТАНОВКА  •  SLIPGATE")
    _box_row()
    _box_info("Запускаю официальный установщик SlipGate...")
    _box_info("install.sh от anonvector/slipgate (AGPL-3.0)")
    _box_row()
    _box_warn("Установщик интерактивный — отвечайте на его вопросы.")
    _box_warn("Для DNS-туннелей потребуется домен с NS-записями.")
    _box_bot()
    print()

    try:
        _ask(f"  {CYAN}Нажмите Enter для запуска или Ctrl+C для отмены: {NC}", c=True)
    except _Cancelled:
        return

    print()
    ret = _run_interactive(
        ["bash", "-c",
         f"curl -fsSL {_INSTALL_SCRIPT} | sudo bash"]
    )

    if ret == 0:
        _save_state({"installed": True})
        print()
        print(f"  {GREEN}✓{NC}  SlipGate установлен.")
    else:
        print()
        print(f"  {YELLOW}⚠{NC}  Установщик завершился с кодом {ret}.")
        print(f"  {DIM}Проверьте вывод выше на наличие ошибок.{NC}")
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  УПРАВЛЕНИЕ ТУННЕЛЯМИ (проксирование в slipgate TUI)
# ══════════════════════════════════════════════════════════════════════════════
def _open_slipgate_tui() -> None:
    """Открывает интерактивное меню SlipGate напрямую."""
    if not _SLIPGATE_BIN.exists():
        print(f"  {RED}✗{NC}  SlipGate не установлен."); _pause(); return
    os.system("clear")
    print(f"\n  {CYAN}→{NC}  Открываю SlipGate TUI... (выход: Ctrl+C или Q)\n")
    _run_interactive([str(_SLIPGATE_BIN)])

def _slipgate_cmd(args: list, interactive: bool = False) -> int:
    """Выполняет команду slipgate с указанными аргументами."""
    if not _SLIPGATE_BIN.exists():
        print(f"  {RED}✗{NC}  SlipGate не установлен."); return 1
    cmd = [str(_SLIPGATE_BIN)] + args
    if interactive:
        return _run_interactive(cmd)
    r = _run(cmd, capture=True)
    out = (r.stdout or "") + (r.stderr or "")
    if out.strip():
        print(out)
    return r.returncode

# ══════════════════════════════════════════════════════════════════════════════
#  СТАТУС
# ══════════════════════════════════════════════════════════════════════════════
def _show_status() -> None:
    os.system("clear")
    _box_top("📊  СТАТУС  •  SLIPGATE")
    _box_row()

    if not _is_installed():
        _box_err("SlipGate не установлен.")
        _box_bot(); _pause(); return

    ver = _get_installed_version()
    _box_kv("Версия:", ver or "—")
    _box_row()

    svc = _get_services_status()
    if svc["services"]:
        _box_sep()
        _box_row(f"  {BOLD}{WHITE}Systemd-сервисы:{NC}")
        _box_row()
        for s in svc["services"]:
            col = GREEN if s["active"] else RED
            mark = "●" if s["active"] else "○"
            name = s["name"].replace(".service", "")
            _box_row(f"  {col}{mark}{NC}  {name:<30} {DIM}{s['sub']}{NC}")
    else:
        _box_warn("Сервисы SlipGate не обнаружены.")
        _box_info("Запустите: slipgate install → tunnel add")

    _box_row(); _box_sep()
    _box_row(f"  {BOLD}{WHITE}Полный статус туннелей:{NC}")
    _box_bot()
    print()

    _slipgate_cmd(["tunnel", "status"])
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ДИАГНОСТИКА
# ══════════════════════════════════════════════════════════════════════════════
def _show_diag() -> None:
    os.system("clear")
    print(f"\n  {CYAN}→{NC}  Запускаю диагностику SlipGate...\n")
    _slipgate_cmd(["diag"])
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ЛОГИ
# ══════════════════════════════════════════════════════════════════════════════
def _show_logs() -> None:
    os.system("clear")
    _box_top("📋  ЛОГИ  •  SLIPGATE")
    _box_row()

    tunnels = _get_tunnel_list()
    if not tunnels:
        _box_warn("Туннели не найдены.")
        _box_info("Создайте туннель: пункт [2] → Управление туннелями")
        _box_bot(); _pause(); return

    _box_info("Доступные туннели:")
    _box_row()
    for i, t in enumerate(tunnels[:10], 1):
        _box_row(f"  {DIM}{i}.{NC}  {t}")
    _box_row()
    _box_item("A", "Логи всех сервисов SlipGate")
    _box_item("Q", "← Отмена")
    _box_bot(); print()

    try:
        ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
    except _Cancelled:
        return

    if ch == "q" or not ch:
        return

    os.system("clear")
    if ch == "a":
        _run_interactive(
            ["journalctl", "-u", "slipgate*", "-n", "50",
             "--no-pager", "--output=short-monotonic"]
        )
    else:
        try:
            idx = int(ch) - 1
            if 0 <= idx < len(tunnels):
                tag = tunnels[idx].split()[0] if tunnels[idx].split() else tunnels[idx]
                _slipgate_cmd(["tunnel", "logs", tag], interactive=True)
        except (ValueError, IndexError):
            print(f"  {RED}✗{NC}  Неверный выбор.")
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ГЕНЕРАЦИЯ ССЫЛКИ ДЛЯ КЛИЕНТА
# ══════════════════════════════════════════════════════════════════════════════
def _share_tunnel() -> None:
    os.system("clear")
    _box_top("📱  ССЫЛКА ДЛЯ SLIPNET  •  SLIPGATE")
    _box_row()

    tunnels = _get_tunnel_list()
    if not tunnels:
        _box_warn("Туннели не найдены.")
        _box_info("Создайте туннель через пункт [2].")
        _box_bot(); _pause(); return

    _box_info("Выберите туннель для генерации slipnet:// URI:")
    _box_row()
    for i, t in enumerate(tunnels[:10], 1):
        _box_row(f"  {DIM}{i}.{NC}  {t}")
    _box_row()
    _box_item("Q", "← Отмена")
    _box_bot(); print()

    try:
        ch = _ask(f"{CYAN}Номер туннеля: {NC}", c=True).strip().lower()
    except _Cancelled:
        return

    if ch == "q" or not ch:
        return

    try:
        idx = int(ch) - 1
        if not (0 <= idx < len(tunnels)):
            raise ValueError
    except ValueError:
        print(f"  {RED}✗{NC}  Неверный выбор."); _pause(); return

    tag = tunnels[idx].split()[0] if tunnels[idx].split() else tunnels[idx]
    os.system("clear")
    print(f"\n  {CYAN}→{NC}  Генерирую slipnet:// URI для туннеля {YELLOW}{tag}{NC}...\n")
    _slipgate_cmd(["tunnel", "share", tag], interactive=True)
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  УДАЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _run_uninstall() -> None:
    os.system("clear")
    _box_top("🗑️  УДАЛЕНИЕ  •  SLIPGATE")
    _box_row()
    _box_warn("Будет удалено:")
    _box_row(f"  {DIM}  • Все туннели и их конфиги{NC}")
    _box_row(f"  {DIM}  • Systemd-сервисы slipgate*{NC}")
    _box_row(f"  {DIM}  • Бинарники в /usr/local/bin/{NC}")
    _box_row(f"  {DIM}  • /etc/slipgate/{NC}")
    _box_row()
    _box_warn("VLESS/Xray конфиги не затрагиваются.")
    _box_row()
    _box_item("Y", f"{RED}Да, удалить{NC}")
    _box_item("N", "Нет, отмена")
    _box_bot(); print()

    try:
        ans = _ask(f"{CYAN}Подтверждение [y/N]: {NC}", c=True).strip().lower()
    except _Cancelled:
        return

    if ans != "y":
        print(f"  {DIM}Отменено.{NC}"); _pause(); return

    print(f"\n  {CYAN}→{NC}  Запускаю slipgate uninstall...\n")
    ret = _slipgate_cmd(["uninstall"], interactive=True)

    if ret == 0:
        try:
            if _MODULE_STATE_FILE.exists():
                _MODULE_STATE_FILE.unlink()
        except Exception:
            pass
        print(f"\n  {GREEN}✓{NC}  SlipGate удалён.")
    else:
        print(f"\n  {YELLOW}⚠{NC}  Команда завершилась с кодом {ret}.")
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ГАЙД ПО НАСТРОЙКЕ
# ══════════════════════════════════════════════════════════════════════════════
def _show_guide() -> None:
    """Полный гайд: DNS-настройка, установка клиента, импорт профиля."""
    while True:
        os.system("clear")
        _box_top("📖  ГАЙД ПО НАСТРОЙКЕ  •  SLIPGATE + SLIPNET")
        _box_row()
        _box_item("1", "DNS-записи для туннеля (обязательно для DNSTT)")
        _box_item("2", "Клиент SlipNet — установка на Android")
        _box_item("3", "CLI-клиент для Linux/Windows/macOS")
        _box_item("4", "Добавить туннель и получить ссылку для клиента")
        _box_item("5", "Типы туннелей — что выбрать")
        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot(); print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            _guide_dns()
        elif ch == "2":
            _guide_android()
        elif ch == "3":
            _guide_cli()
        elif ch == "4":
            _guide_add_tunnel()
        elif ch == "5":
            _guide_tunnel_types()
        elif ch in ("q", ""):
            break

def _guide_dns() -> None:
    os.system("clear")
    _box_top("🌐  DNS-НАСТРОЙКА ДЛЯ SLIPGATE")
    _box_row()
    _box_info("DNS-туннели требуют делегирования поддомена на VPS.")
    _box_info("Настройте у своего DNS-провайдера (Cloudflare, reg.ru и др.):")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Шаг 1 — A-запись для NS-сервера:{NC}")
    _box_row()
    _box_row(f"  {CYAN}ns.ваш-домен.com{NC}  →  {YELLOW}IP вашего VPS{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Шаг 2 — NS-записи для каждого туннеля:{NC}")
    _box_row()
    _box_kv("  DNSTT/NoizDNS:", f"{YELLOW}NS  t.ваш-домен.com → ns.ваш-домен.com{NC}", 20)
    _box_kv("  Slipstream:",    f"{YELLOW}NS  s.ваш-домен.com → ns.ваш-домен.com{NC}", 20)
    _box_kv("  VayDNS:",        f"{YELLOW}NS  v.ваш-домен.com → ns.ваш-домен.com{NC}", 20)
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Шаг 3 — A-запись для NaiveProxy (если нужен):{NC}")
    _box_row()
    _box_row(f"  {CYAN}ваш-домен.com{NC}  →  {YELLOW}IP вашего VPS{NC}")
    _box_row()
    _box_sep()
    _box_warn("StunTLS не требует домена — только порт 443/tcp.")
    _box_row()
    _box_info("После настройки DNS проверьте делегирование:")
    _box_row(f"  {DIM}dig NS t.ваш-домен.com{NC}")
    _box_row(f"  {DIM}Должен вернуть: ns.ваш-домен.com{NC}")
    _box_row()
    _box_info("Распространение DNS занимает до 24 часов.")
    _box_bot()
    _pause()

def _guide_android() -> None:
    os.system("clear")
    _box_top("📱  SLIPNET ДЛЯ ANDROID")
    _box_row()
    _box_info("SlipNet — официальный клиент для SlipGate.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Установка:{NC}")
    _box_row()
    _box_info("1. Откройте в браузере:")
    _box_row(f"  {YELLOW}github.com/anonvector/SlipNet/releases/latest{NC}")
    _box_info("2. Скачайте SlipNet-vX.X.X.apk")
    _box_info("3. Разрешите установку из неизвестных источников")
    _box_info("4. Установите APK")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Импорт профиля:{NC}")
    _box_row()
    _box_info("1. На VPS: slipgate tunnel share <тег>")
    _box_info("2. Скопируйте slipnet:// ссылку")
    _box_info("3. В SlipNet → + → вставьте ссылку")
    _box_info("4. Нажмите Connect")
    _box_row()
    _box_sep()
    _box_warn("Приложение не распространяется через Google Play.")
    _box_warn("Только официальный GitHub — других источников не существует.")
    _box_bot()
    _pause()

def _guide_cli() -> None:
    os.system("clear")
    _box_top("💻  CLI-КЛИЕНТ SLIPNET")
    _box_row()
    _box_info("Кроссплатформенный CLI — Linux, macOS, Windows.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Скачать (Linux amd64):{NC}")
    _box_row()
    _box_row(f"  {DIM}wget -O slipnet {NC}")
    _box_row(f"  {DIM}  github.com/anonvector/SlipNet/releases/latest/{NC}")
    _box_row(f"  {DIM}  download/slipnet-linux-amd64{NC}")
    _box_row(f"  {DIM}chmod +x slipnet{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Использование:{NC}")
    _box_row()
    _box_row(f"  {DIM}# Подключиться (запускает SOCKS5 на :1080){NC}")
    _box_row(f"  {CYAN}./slipnet 'slipnet://BASE64...'{NC}")
    _box_row()
    _box_row(f"  {DIM}# Проверить через curl:{NC}")
    _box_row(f"  {CYAN}curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me{NC}")
    _box_row()
    _box_row(f"  {DIM}# Кастомный порт:{NC}")
    _box_row(f"  {CYAN}./slipnet --port 9050 'slipnet://BASE64...'{NC}")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Интерактивный режим:{NC}")
    _box_row()
    _box_row(f"  {CYAN}./slipnet{NC}  {DIM}(без аргументов — меню){NC}")
    _box_row()
    _box_info("slipnet:// ссылку получите командой: slipgate tunnel share <тег>")
    _box_bot()
    _pause()

def _guide_add_tunnel() -> None:
    os.system("clear")
    _box_top("🔧  ДОБАВИТЬ ТУННЕЛЬ  •  ПОШАГОВО")
    _box_row()
    _box_info("Все действия выполняются через SlipGate TUI или CLI.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Через TUI (пункт 2 главного меню):{NC}")
    _box_row()
    _box_info("1. Откройте SlipGate TUI")
    _box_info("2. Tunnel Management → Add Tunnel")
    _box_info("3. Выберите тип (DNSTT рекомендуется)")
    _box_info("4. Введите домен: t.ваш-домен.com")
    _box_info("5. После создания: Tunnel → Share → скопируйте slipnet://")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Через CLI (быстрый способ):{NC}")
    _box_row()
    _box_row(f"  {CYAN}slipgate tunnel add \\{NC}")
    _box_row(f"  {CYAN}  --transport dnstt \\{NC}")
    _box_row(f"  {CYAN}  --backend socks \\{NC}")
    _box_row(f"  {CYAN}  --tag mytunnel \\{NC}")
    _box_row(f"  {CYAN}  --domain t.ваш-домен.com{NC}")
    _box_row()
    _box_row(f"  {DIM}# Получить ссылку для клиента:{NC}")
    _box_row(f"  {CYAN}slipgate tunnel share mytunnel{NC}")
    _box_row()
    _box_sep()
    _box_warn("Перед добавлением DNS-туннеля убедитесь что NS-записи")
    _box_warn("настроены и распространились (dig NS t.домен.com).")
    _box_bot()
    _pause()

def _guide_tunnel_types() -> None:
    os.system("clear")
    _box_top("📡  ТИПЫ ТУННЕЛЕЙ  •  ЧТО ВЫБРАТЬ")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{GREEN}DNSTT{NC}  {DIM}— рекомендуется для начала{NC}")
    _box_row()
    _box_info("Стабильный DNS-туннель, Curve25519. Работает везде где")
    _box_info("есть DNS. Нужен домен + NS-записи. Порт 53/udp.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{GREEN}NoizDNS{NC}  {DIM}— DNSTT + защита от DPI{NC}")
    _box_row()
    _box_info("Тот же сервер что DNSTT, клиент выбирает тип при импорте.")
    _box_info("base36/hex кодирование, CDN prefix stripping.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{CYAN}Slipstream{NC}  {DIM}— QUIC поверх DNS{NC}")
    _box_row()
    _box_info("Высокая пропускная способность. Нужен домен + NS + порт 53.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{CYAN}VayDNS{NC}  {DIM}— KCP + Curve25519{NC}")
    _box_row()
    _box_info("Настраиваемый wire format, типы DNS-записей, rate limiting.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{YELLOW}StunTLS{NC}  {DIM}— SSH over TLS + WebSocket, без домена{NC}")
    _box_row()
    _box_info("Порт 443/tcp. Самоподписанный сертификат. Быстрая настройка.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{YELLOW}NaiveProxy{NC}  {DIM}— HTTPS с Chromium-fingerprint{NC}")
    _box_row()
    _box_info("Caddy + Let's Encrypt. Нужен домен с A-записью. Порт 443.")
    _box_info("Probe-resistant: имитирует обычный HTTPS-сайт.")
    _box_row()
    _box_sep()
    _box_row(f"  {BOLD}{WHITE}Рекомендация:{NC}")
    _box_row()
    _box_info("Белые списки (мобильные операторы) → начни с DNS-туннеля (DNSTT)")
    _box_info("Нет домена → StunTLS (443/tcp, быстро)")
    _box_info("Нужна маскировка под HTTPS → NaiveProxy")
    _box_bot()
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ОБНОВЛЕНИЕ
# ══════════════════════════════════════════════════════════════════════════════
def _run_update() -> None:
    os.system("clear")
    _box_top("⬆️  ОБНОВЛЕНИЕ  •  SLIPGATE")
    _box_row()
    cur = _get_installed_version()
    _box_kv("Установлена:", cur or "—")
    _box_info("Проверяю последнюю версию...")
    _box_bot(); print()

    latest = _get_latest_version()
    os.system("clear")
    _box_top("⬆️  ОБНОВЛЕНИЕ  •  SLIPGATE")
    _box_row()
    _box_kv("Установлена:", cur or "—")
    _box_kv("Последняя:",   latest)
    _box_row()

    if cur and cur == latest and cur != "unknown":
        _box_info("Уже установлена последняя версия.")
        _box_bot(); _pause(); return

    _box_item("Y", f"Обновить через slipgate update")
    _box_item("N", "← Отмена")
    _box_bot(); print()

    try:
        ans = _ask(f"{CYAN}Обновить? [Y/n]: {NC}", default="y", c=True).strip().lower()
    except _Cancelled:
        return
    if ans not in ("y", ""):
        return

    print()
    _slipgate_cmd(["update"], interactive=True)
    _pause()

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ МОДУЛЯ
# ══════════════════════════════════════════════════════════════════════════════
def do_slipgate_menu() -> None:
    """
    Точка входа из _core.py.
    Ctrl+C → возврат в главное меню VLESS.
    """
    while True:
        os.system("clear")
        installed = _is_installed()
        ver = _get_installed_version() if installed else None

        svc_str = f"{GREEN}✓ установлен  v{ver}{NC}" if installed else f"{YELLOW}● не установлен{NC}"

        _box_top("SLIPGATE  •  DNS TUNNEL")
        _box_row()
        _box_kv("SlipGate:", svc_str)

        if installed:
            svc = _get_services_status()
            svc_count = svc["count"]
            col = GREEN if svc_count > 0 else YELLOW
            _box_kv("Сервисов:",
                    f"{col}{svc_count} активных{NC}" if svc_count
                    else f"{YELLOW}нет активных{NC}")

        _box_row(); _box_sep()
        _box_row(f"  {DIM}DNS-туннели — работают даже при полной блокировке IP{NC}")
        _box_row(f"  {DIM}Трафик прячется внутри DNS-запросов{NC}")
        _box_row(); _box_sep()

        if not installed:
            _box_item("1", "🚀  Установить SlipGate")
        else:
            _box_item("1", "🚀  Переустановить / обновить")
            _box_item("2", "⚙️   Управление туннелями (SlipGate TUI)")
            _box_item("3", "📱  Получить ссылку для SlipNet")
            _box_item("4", "📊  Статус туннелей и сервисов")
            _box_item("5", "🔍  Диагностика")
            _box_item("6", "📋  Логи")
            _box_item("7", "⬆️   Обновить SlipGate")
            _box_sep()
            _box_item("8", f"{RED}🗑️   Удалить SlipGate{NC}")

        _box_sep()
        _box_item("G", "📖  Гайд: DNS-настройка, клиент, типы туннелей")
        _box_sep()
        _box_item("Q", "← Назад в главное меню VLESS")
        _box_bot(); print()

        try:
            ch = _ask(f"{CYAN}Выбор: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            _run_install()

        elif ch == "2" and installed:
            _open_slipgate_tui()

        elif ch == "3" and installed:
            try:
                _share_tunnel()
            except _Cancelled:
                pass

        elif ch == "4" and installed:
            _show_status()

        elif ch == "5" and installed:
            _show_diag()

        elif ch == "6" and installed:
            try:
                _show_logs()
            except _Cancelled:
                pass

        elif ch == "7" and installed:
            try:
                _run_update()
            except _Cancelled:
                pass

        elif ch == "8" and installed:
            try:
                _run_uninstall()
            except _Cancelled:
                print(f"  {DIM}Отменено.{NC}"); _pause()

        elif ch == "g":
            try:
                _show_guide()
            except _Cancelled:
                pass

        elif ch in ("q", ""):
            break

# ══════════════════════════════════════════════════════════════════════════════
#  АВТОНОМНЫЙ ЗАПУСК (отладка)
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}Запустите от root.{NC}"); sys.exit(1)
    try:
        do_slipgate_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}"); sys.exit(0)

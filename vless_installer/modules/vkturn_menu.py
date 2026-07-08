"""
vless_installer/modules/vkturn_menu.py
───────────────────────────────────────────────────────────────────────────────
VK Turn Tunnel — диспетчер пункта 8 главного меню.

Предлагает пользователю выбор между двумя независимыми подсистемами:

  [1] vk-turn-proxy + FreeTurn (Android)
      • Простая схема без криптографических ключей
      • Форвардит UDP напрямую в WireGuard / Hysteria2
      • Клиент: github.com/samosvalishe/turn-proxy-android

  [2] Turnable + WireTurn (Android)
      • Сквозное шифрование, keygen, turnable:// ссылки и QR
      • Форвардит VLESS через встроенный Xray в WireTurn
      • Клиент: github.com/spkprsnts/WireTurn

Оба модуля могут быть установлены одновременно — разные порты,
разные сервисы, не конфликтуют.

Точка входа для _core.py:
    from vless_installer.modules.vkturn_menu import do_vkturn_menu
    do_vkturn_menu()
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

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

_BOX_W = 66

# ══════════════════════════════════════════════════════════════════════════════
#  BOX-РЕНДЕРИНГ
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
                cut = i; break
        text = text[:cut] + "…"
        w = _wlen(text)
    pad = max(0, _BOX_W - w)
    print(f"{CYAN}║{NC}{text}{' ' * pad}{CYAN}║{NC}")

def _box_item(key: str, label: str) -> None:
    col = RED + BOLD if key.strip().upper() in ("Q", "0") else WHITE + BOLD
    _box_row(f"  {DIM}[{NC}{col}{key}{NC}{DIM}]{NC}  {label}")

def _box_kv(key: str, val: str, kw: int = 24) -> None:
    key_colored = f"{CYAN}{key}{NC}"
    key_pad = kw - _wlen(key_colored)
    _box_row(f"  {key_colored}{' ' * max(0, key_pad)}  {val}")

# ══════════════════════════════════════════════════════════════════════════════
#  СОСТОЯНИЕ ПОДМОДУЛЕЙ
# ══════════════════════════════════════════════════════════════════════════════
_STATE_FREETURN  = Path("/var/lib/xray-installer/turntunnel.json")
_STATE_TURNABLE  = Path("/var/lib/xray-installer/turnable.json")
_BIN_FREETURN    = Path("/opt/vk-turn-proxy/server")
_BIN_TURNABLE    = Path("/opt/turnable/turnable")

def _module_status(state_file: Path, bin_path: Path) -> str:
    """Возвращает цветную строку статуса модуля для отображения в меню."""
    import json
    import subprocess
    try:
        state = json.loads(state_file.read_text())
        if not state.get("installed"):
            return f"{DIM}не установлен{NC}"
    except Exception:
        return f"{DIM}не установлен{NC}"

    svc = "vk-turn-proxy" if "freeturn" in str(state_file) or "turntunnel" in str(state_file) else "turnable"
    try:
        r = subprocess.run(
            ["systemctl", "is-active", svc],
            capture_output=True, text=True,
        )
        active = r.stdout.strip() == "active"
    except Exception:
        active = False

    return f"{GREEN}● активен{NC}" if active else f"{YELLOW}● установлен / не запущен{NC}"

class _Cancelled(Exception):
    pass

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

# ══════════════════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ МЕНЮ ДИСПЕТЧЕРА
# ══════════════════════════════════════════════════════════════════════════════
def do_vkturn_menu() -> None:
    """
    Точка входа из _core.py.
    Показывает выбор между FreeTurn и WireTurn/Turnable.
    Ctrl+C → возврат в главное меню.
    """
    while True:
        os.system("clear")

        ft_status = _module_status(_STATE_FREETURN, _BIN_FREETURN)
        tb_status = _module_status(_STATE_TURNABLE,  _BIN_TURNABLE)

        _box_top("📲  VK TURN TUNNEL")
        _box_row()
        _box_row(f"  {DIM}Проброс трафика через TURN-серверы ВКонтакте.{NC}")
        _box_row(f"  {DIM}Обход белых списков мобильных операторов РФ.{NC}")
        _box_row()
        _box_row(f"  {DIM}Оба варианта могут работать одновременно.{NC}")
        _box_row()
        _box_sep()

        # FreeTurn
        _box_row(f"  {BOLD}{WHITE}[1]  vk-turn-proxy  →  FreeTurn{NC}")
        _box_row(f"       {DIM}Простая схема • UDP relay • без ключей{NC}")
        _box_row(f"       {DIM}Клиент: FreeTurn (samosvalishe){NC}")
        _box_kv("       Статус:", ft_status)
        _box_row()

        # Turnable
        _box_row(f"  {BOLD}{WHITE}[2]  Turnable  →  WireTurn{NC}")
        _box_row(f"       {DIM}Шифрование • keygen • VLESS через Xray{NC}")
        _box_row(f"       {DIM}Клиент: WireTurn (spkprsnts){NC}")
        _box_kv("       Статус:", tb_status)
        _box_row()

        _box_sep()
        _box_item("Q", "← Назад")
        _box_bot()
        print()

        try:
            ch = _ask(f"{CYAN}Выбор [1/2/Q]: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            try:
                from vless_installer.modules.turntunnel import do_turntunnel_menu
                do_turntunnel_menu()
            except ImportError as e:
                print(f"  {RED}✗{NC}  Модуль turntunnel не найден: {e}")
                import time; time.sleep(2)

        elif ch == "2":
            try:
                from vless_installer.modules.turnable import do_turnable_menu
                do_turnable_menu()
            except ImportError as e:
                print(f"  {RED}✗{NC}  Модуль turnable не найден: {e}")
                import time; time.sleep(2)

        elif ch in ("q", ""):
            break


if __name__ == "__main__":
    try:
        do_vkturn_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}")
        sys.exit(0)

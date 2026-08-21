"""
chimera/modules/vk_bypass_menu.py
───────────────────────────────────────────────────────────────────────────────
VK Whitelist Bypass — единый диспетчер пункта главного меню.

Объединяет 4 модуля обхода белых списков РКН через звонки ВКонтакте:

  [1] FreeTurn  (vk-turn-proxy + FreeTurn Android)   ← подпроект бывшего «VK Turn Tunnel»
  [2] WireTurn  (Turnable + WireTurn Android)        ← подпроект бывшего «VK Turn Tunnel»
  [3] qWDTT     (WireGuard-over-TURN, qWDTT Android)
  [4] CSQTT     (RTP/TURN Tunnel, CSQTT Android)

Все 4 модуля маскируют трафик под RTP/DTLS медиа-поток звонка ВКонтакте
и проходят через TURN-серверы VK. Отличаются протоколом туннеля и
особенностями клиента.

Все 4 могут работать одновременно — разные порты, разные сервисы,
не конфликтуют друг с другом.

Точка входа для _core.py:
    from chimera.modules.vk_bypass_menu import do_vk_bypass_menu
    do_vk_bypass_menu()
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from chimera.modules.text_width import wlen as _wlen, plain as _plain

import os
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

_BOX_W = 70

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
                cut = i; break
        text = text[:cut] + "…"
        w = _wlen(text)
    pad = max(0, _BOX_W - w)
    print(f"{CYAN}║{NC}{text}{' ' * pad}{CYAN}║{NC}")

def _box_item(key: str, label: str) -> None:
    col = RED + BOLD if key.strip().upper() in ("Q", "0") else WHITE + BOLD
    _box_row(f"  {DIM}[{NC}{col}{key}{NC}{DIM}]{NC}  {label}")

def _box_kv(key: str, val: str, kw: int = 18) -> None:
    key_colored = f"{CYAN}{key}{NC}"
    key_pad = kw - _wlen(key_colored)
    _box_row(f"       {key_colored}{' ' * max(0, key_pad)}  {val}")

# ══════════════════════════════════════════════════════════════════════════════
#  СОСТОЯНИЕ ПОДМОДУЛЕЙ
# ══════════════════════════════════════════════════════════════════════════════
_STATE_FREETURN  = Path("/var/lib/xray-installer/turntunnel.json")
_STATE_TURNABLE  = Path("/var/lib/xray-installer/turnable.json")
_STATE_WDTT      = Path("/var/lib/xray-installer/wdtt.json")
_STATE_CSQTT     = Path("/var/lib/xray-installer/csqtt.json")

_BIN_FREETURN    = Path("/opt/vk-turn-proxy/server")
_BIN_TURNABLE    = Path("/opt/turnable/turnable")
_BIN_WDTT        = Path("/usr/local/bin/wdtt-server")
_BIN_CSQTT       = Path("/usr/local/bin/csqtt-server")

# (state_file, binary_path, service_name, label_short)
_MODULES = [
    ("freeturn", _STATE_FREETURN, _BIN_FREETURN, "vk-turn-proxy"),
    ("turnable", _STATE_TURNABLE, _BIN_TURNABLE, "turnable"),
    ("wdtt",     _STATE_WDTT,     _BIN_WDTT,     "wdtt"),
    ("csqtt",    _STATE_CSQTT,    _BIN_CSQTT,    "csqtt"),
]

def _module_status(state_file: Path, bin_path: Path, svc: str) -> str:
    """Возвращает цветную строку статуса модуля для отображения в меню."""
    import json
    import subprocess
    try:
        state = json.loads(state_file.read_text())
        if not state.get("installed"):
            return f"{DIM}не установлен{NC}"
    except Exception:
        # Если state-файла нет, проверим хотя бы наличие бинарника
        if bin_path.exists():
            return f"{YELLOW}● установлен / не настроен{NC}"
        return f"{DIM}не установлен{NC}"

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
def do_vk_bypass_menu() -> None:
    """
    Точка входа из _core.py.
    Показывает выбор между FreeTurn / WireTurn / qWDTT / CSQTT.
    Ctrl+C → возврат в главное меню.
    """
    while True:
        os.system("clear")

        ft_status = _module_status(_STATE_FREETURN, _BIN_FREETURN, "vk-turn-proxy")
        tb_status = _module_status(_STATE_TURNABLE,  _BIN_TURNABLE, "turnable")
        wd_status = _module_status(_STATE_WDTT,      _BIN_WDTT,     "wdtt")
        cs_status = _module_status(_STATE_CSQTT,     _BIN_CSQTT,    "csqtt")

        _box_top("📱  VK WHITELIST BYPASS  •  4 МОДУЛЯ")
        _box_row()
        _box_row(f"  {DIM}Обход белых списков РКН через звонки ВКонтакте.{NC}")
        _box_row(f"  {DIM}Трафик маскируется под RTP/DTLS медиа-поток VK-звонка.{NC}")
        _box_row(f"  {DIM}Все 4 модуля могут работать одновременно — разные порты.{NC}")
        _box_row()
        _box_sep()

        # [1] FreeTurn
        _box_row(f"  {BOLD}{WHITE}[1]  FreeTurn  ←  vk-turn-proxy{NC}")
        _box_row(f"       {DIM}Простая схема • UDP relay • без ключей{NC}")
        _box_row(f"       {DIM}Клиент: FreeTurn (Android, samosvalishe){NC}")
        _box_kv("Статус:", ft_status)
        _box_row()

        # [2] WireTurn
        _box_row(f"  {BOLD}{WHITE}[2]  WireTurn  ←  Turnable{NC}")
        _box_row(f"       {DIM}Шифрование • keygen • VLESS через Xray{NC}")
        _box_row(f"       {DIM}Клиент: WireTurn (Android, spkprsnts){NC}")
        _box_kv("Статус:", tb_status)
        _box_row()

        # [3] qWDTT
        _box_row(f"  {BOLD}{WHITE}[3]  qWDTT  ←  WireGuard-over-TURN{NC}")
        _box_row(f"       {DIM}WireGuard внутри WRAP RTP AEAD • TG-бот • пароли{NC}")
        _box_row(f"       {DIM}Клиент: qWDTT (Android, SpaceNeuroX){NC}")
        _box_kv("Статус:", wd_status)
        _box_row()

        # [4] CSQTT
        _box_row(f"  {BOLD}{WHITE}[4]  CSQTT  ←  RTP/TURN Tunnel{NC}")
        _box_row(f"       {DIM}Rust/io_uring • Web Panel • макс. обфускация{NC}")
        _box_row(f"       {DIM}Клиент: CSQTT (Android, amurcanov){NC}")
        _box_kv("Статус:", cs_status)
        _box_row()

        _box_sep()
        _box_item("G", "📖  Гайд: сравнение, установка, подключение (FAQ)")
        _box_item("Q", "← Назад в главное меню")
        _box_bot()
        print()

        try:
            ch = _ask(f"{CYAN}Выбор [1/2/3/4/G/Q]: {NC}", c=True).strip().lower()
        except _Cancelled:
            break

        if ch == "1":
            try:
                from chimera.modules.turntunnel import do_turntunnel_menu
                do_turntunnel_menu()
            except ImportError as e:
                print(f"  {RED}✗{NC}  Модуль turntunnel не найден: {e}")
                import time; time.sleep(2)

        elif ch == "2":
            try:
                from chimera.modules.turnable import do_turnable_menu
                do_turnable_menu()
            except ImportError as e:
                print(f"  {RED}✗{NC}  Модуль turnable не найден: {e}")
                import time; time.sleep(2)

        elif ch == "3":
            try:
                from chimera.modules.wdtt import do_wdtt_menu
                do_wdtt_menu()
            except ImportError as e:
                print(f"  {RED}✗{NC}  Модуль wdtt не найден: {e}")
                import time; time.sleep(2)

        elif ch == "4":
            try:
                from chimera.modules.csqtt import do_csqtt_menu
                do_csqtt_menu()
            except ImportError as e:
                print(f"  {RED}✗{NC}  Модуль csqtt не найден: {e}")
                import time; time.sleep(2)

        elif ch == "g":
            _show_faq_hint()

        elif ch in ("q", ""):
            break


def _show_faq_hint() -> None:
    """Показывает путь к FAQ-файлу и краткую справку."""
    os.system("clear")
    _box_top("📖  VK WHITELIST BYPASS  •  FAQ")
    _box_row()
    _box_row(f"  {BOLD}{WHITE}Полная документация по всем 4 модулям:{NC}")
    _box_row()
    _box_row(f"  {CYAN}docs/faq/VK_BYPASS_FAQ.md{NC}")
    _box_row()
    _box_row(f"  {DIM}Разделы FAQ:{NC}")
    _box_row(f"  {DIM}• Контекст: что такое белые списки РКН, история{NC}")
    _box_row(f"  {DIM}• Сравнительная таблица 4 модулей{NC}")
    _box_row(f"  {DIM}• Архитектура каждого модуля (с ASCII-диаграммами){NC}")
    _box_row(f"  {DIM}• Установка и подключение для каждого{NC}")
    _box_row(f"  {DIM}• Диагностика и частые вопросы{NC}")
    _box_row()
    _box_row(f"  {DIM}Открыть на сервере:{NC}")
    _box_row(f"  {CYAN}less /opt/chimera/docs/faq/VK_BYPASS_FAQ.md{NC}")
    _box_row()
    _box_row(f"  {DIM}Или онлайн:{NC}")
    _box_row(f"  {CYAN}https://gitlab.com/netwalker071778/chimera-project/-/blob/chimera-v5/docs/faq/VK_BYPASS_FAQ.md{NC}")
    _box_bot()
    print()
    input(f"  {DIM}Enter чтобы вернуться...{NC}")


if __name__ == "__main__":
    try:
        do_vk_bypass_menu()
    except KeyboardInterrupt:
        print(f"\n{GREEN}До свидания!{NC}")
        sys.exit(0)

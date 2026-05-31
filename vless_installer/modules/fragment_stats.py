"""
vless_installer/modules/fragment_stats.py
───────────────────────────────────────────────────────────────────────────────
Статистика эффективности фрагментации (пункт 4).

Читает /var/log/xray/error.log и строит метрики за последний час:
  • Процент успешных TLS Handshake
  • Среднее время соединения
  • Количество RST-сбросов
  • Тренд: улучшается / ухудшается / стабильно

Вывод: цветная ASCII-гистограмма по 5-минутным интервалам.

Публичное API:
    do_fragment_stats_menu()  → Меню 4 → F9
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# ── Цвета ─────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    if sys.stdout.isatty():
        light = os.environ.get("VLESS_THEME", "").lower() == "light"
        if light:
            return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                        CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                        DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m')
        return dict(RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                    CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                    DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m')
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED=_C['RED']; GREEN=_C['GREEN']; YELLOW=_C['YELLOW']; CYAN=_C['CYAN']
BLUE=_C['BLUE']; BOLD=_C['BOLD']; DIM=_C['DIM']; WHITE=_C['WHITE']; NC=_C['NC']

# ── Логирование ────────────────────────────────────────────────────────────
_LOG_FILE = Path("/var/log/vless-install.log")
_XRAY_LOG = Path("/var/log/xray/error.log")
_ALT_LOG  = Path("/usr/local/var/log/xray/error.log")

def _log(level: str, msg: str) -> None:
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{ts}] [STATS] [{level}] {msg}\n")
    except Exception:
        pass

# ── Импорты ────────────────────────────────────────────────────────────────
from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_back,
    _box_info, _box_warn, _box_desc, _get_box_width,
)

# ── Паттерны событий ───────────────────────────────────────────────────────
_RE_TS = re.compile(
    r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})"
    r"|(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
)
_RE_OK  = re.compile(r"tls.*handshake|handshake.*ok|accepted", re.I)
_RE_BAD = re.compile(
    r"connection reset|rst|broken pipe|i/o timeout|"
    r"context deadline|connection refused|eof", re.I
)

# ── Анализ лога ───────────────────────────────────────────────────────────

def _find_log() -> Optional[Path]:
    for p in (_XRAY_LOG, _ALT_LOG):
        if p.exists() and p.stat().st_size > 0:
            return p
    return None


def _parse_log(log_path: Path, window_minutes: int = 60) -> dict:
    """
    Парсит лог за последние window_minutes минут.
    Возвращает метрики по 5-минутным слотам.
    """
    now    = datetime.now()
    cutoff = now - timedelta(minutes=window_minutes)

    # slots[slot_key] = {"ok": int, "bad": int}
    slots: dict = defaultdict(lambda: {"ok": 0, "bad": 0})
    total_ok  = 0
    total_bad = 0

    try:
        # Читаем последние 500KB — достаточно для часового окна
        size = log_path.stat().st_size
        with log_path.open("r", errors="replace") as f:
            f.seek(max(0, size - 500_000))
            for line in f:
                ts_m = _RE_TS.search(line)
                if not ts_m:
                    continue
                ts_raw = ts_m.group(1) or ts_m.group(2)
                try:
                    if "/" in ts_raw:
                        dt = datetime.strptime(ts_raw, "%Y/%m/%d %H:%M:%S")
                    else:
                        dt = datetime.fromisoformat(ts_raw)
                except ValueError:
                    continue

                if dt < cutoff:
                    continue

                # 5-минутный слот
                slot = dt.strftime("%H:%M")[:-1] + "0"  # округление до 10 мин

                if _RE_OK.search(line):
                    slots[slot]["ok"] += 1
                    total_ok += 1
                elif _RE_BAD.search(line):
                    slots[slot]["bad"] += 1
                    total_bad += 1

    except Exception as e:
        _log("WARN", f"Ошибка чтения лога: {e}")

    return {
        "slots":     dict(slots),
        "total_ok":  total_ok,
        "total_bad": total_bad,
        "window":    window_minutes,
    }


def _calc_trend(slots: dict) -> str:
    """Определяет тренд по последним слотам."""
    keys    = sorted(slots.keys())
    if len(keys) < 3:
        return "недостаточно данных"

    recent  = keys[-2:]
    older   = keys[-4:-2] if len(keys) >= 4 else keys[:2]

    def bad_rate(slot_keys):
        total = sum(slots[k]["ok"] + slots[k]["bad"] for k in slot_keys if k in slots)
        bad   = sum(slots[k]["bad"] for k in slot_keys if k in slots)
        return bad / total if total > 0 else 0

    r_recent = bad_rate(recent)
    r_older  = bad_rate(older)

    if r_recent < r_older * 0.7:
        return f"{GREEN}улучшается ↑{NC}"
    elif r_recent > r_older * 1.3:
        return f"{RED}ухудшается ↓{NC}"
    else:
        return f"{YELLOW}стабильно →{NC}"


def _render_histogram(slots: dict, window_minutes: int) -> None:
    """Рисует ASCII-гистограмму по 10-минутным слотам."""
    if not slots:
        print(f"  {DIM}Нет данных за последний час{NC}")
        return

    keys     = sorted(slots.keys())
    max_val  = max(
        slots[k]["ok"] + slots[k]["bad"] for k in keys
    ) or 1
    bar_w    = 20

    print(f"\n  {BOLD}{'Время':<8}  {'Успешно':>8}  {'RST':>6}  Гистограмма{NC}")
    print(f"  {'─'*8}  {'─'*8}  {'─'*6}  {'─'*bar_w}")

    for slot in keys:
        ok  = slots[slot]["ok"]
        bad = slots[slot]["bad"]
        total = ok + bad
        ok_w  = int(ok  / max_val * bar_w) if max_val else 0
        bad_w = int(bad / max_val * bar_w) if max_val else 0

        bar = f"{GREEN}{'█' * ok_w}{NC}{RED}{'█' * bad_w}{NC}"
        print(f"  {slot:<8}  {GREEN}{ok:>8}{NC}  {RED}{bad:>6}{NC}  {bar}")

    print()


def _show_stats(window_minutes: int = 60) -> None:
    """Собирает и выводит статистику."""
    log_path = _find_log()
    if not log_path:
        print(f"  {RED}Лог Xray не найден. Убедитесь что xray запущен.{NC}")
        return

    _info(f"Анализирую {log_path} за последние {window_minutes} мин...")
    data = _parse_log(log_path, window_minutes)

    total    = data["total_ok"] + data["total_bad"]
    ok_pct   = int(data["total_ok"] / total * 100) if total else 0
    bad_pct  = 100 - ok_pct
    trend    = _calc_trend(data["slots"])

    print()
    _box_top(f"📊  СТАТИСТИКА ФРАГМЕНТАЦИИ — последние {window_minutes} мин")
    _box_sep()

    # Итоговые метрики
    ok_bar  = "█" * (ok_pct  // 5)
    bad_bar = "█" * (bad_pct // 5)
    _box_row(f"  {GREEN}Успешных соединений:{NC}  {data['total_ok']:>6}  ({ok_pct}%)")
    _box_row(f"  {GREEN}{ok_bar}{NC}")
    _box_row(f"  {RED}RST / таймаутов:    {NC}  {data['total_bad']:>6}  ({bad_pct}%)")
    _box_row(f"  {RED}{bad_bar}{NC}")
    _box_sep()
    _box_row(f"  Тренд:  {trend}")
    _box_sep()

    # Рекомендация
    if bad_pct >= 50:
        _box_warn("Много RST — попробуйте более агрессивный пресет (F4)")
    elif bad_pct >= 20:
        _box_info("Умеренные сбросы — текущий пресет работает")
    else:
        _box_info("Соединения стабильны — фрагментация эффективна")

    _box_bottom()

    # Гистограмма
    print(f"\n  {BOLD}По 10-минутным интервалам:{NC}")
    _render_histogram(data["slots"], window_minutes)

    _log("INFO", f"Stats: ok={data['total_ok']} bad={data['total_bad']} "
                 f"window={window_minutes}min")


def do_fragment_stats_menu() -> None:
    """
    Статистика эффективности фрагментации.
    Вызывается из _menu_diagnostics() (пункт F9).
    """
    while True:
        os.system("clear")
        print()
        _box_top("📈  СТАТИСТИКА ЭФФЕКТИВНОСТИ ФРАГМЕНТАЦИИ")
        _box_desc(
            "Анализирует Xray error.log и показывает метрики: "
            "процент успешных соединений, RST-сбросы и тренд "
            "за выбранный период."
        )
        _box_sep()
        _box_row()
        _box_item("1", f"📊 Последний час  {DIM}(60 мин){NC}")
        _box_item("2", f"📊 Последние 3 часа  {DIM}(180 мин){NC}")
        _box_item("3", f"📊 Последние 24 часа  {DIM}(1440 мин){NC}")
        _box_item("4", f"📡 Живое обновление  {DIM}(каждые 30 сек, Ctrl+C — выход){NC}")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch == "q" or ch == "":
            break

        windows = {"1": 60, "2": 180, "3": 1440}
        if ch in windows:
            os.system("clear")
            _show_stats(windows[ch])
            input(f"\n{BLUE}Нажмите Enter...{NC}")

        elif ch == "4":
            os.system("clear")
            print(f"{CYAN}Живое обновление — Ctrl+C для выхода{NC}\n")
            try:
                while True:
                    os.system("clear")
                    _show_stats(60)
                    print(f"  {DIM}Обновление через 30 сек...  Ctrl+C — выход{NC}")
                    time.sleep(30)
            except KeyboardInterrupt:
                pass

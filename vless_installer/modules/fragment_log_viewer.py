"""
vless_installer/modules/fragment_log_viewer.py
───────────────────────────────────────────────────────────────────────────────
Визуализация фрагментации в логах Xray.

Парсит /var/log/xray/error.log в реальном времени (tail -f или snapshot),
выделяет события, связанные с TLS/TCP-соединениями, и отображает
цветную ASCII-таблицу:

  Колонка  │ Что показывает
  ─────────┼──────────────────────────────────────────────────────────────
  Time     │ Время события (HH:MM:SS)
  Status   │ ✓ ОК / ✗ RST / ⚡ Fragment / ⚠ Warn / ℹ Info
  Event    │ Краткое описание (TLS Handshake, Connection reset, ...)
  Detail   │ Адрес/домен или фрагмент сообщения лога

Живой режим обновляется каждые 2 секунды без очистки экрана —
только дописывает новые строки (удобно в SSH).

Точка входа из _core.py:
    from vless_installer.modules.fragment_log_viewer import do_fragment_log_viewer_menu
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import re
import sys
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Цвета ─────────────────────────────────────────────────────────────────
def _detect_colors() -> dict:
    _light = os.environ.get("VLESS_THEME", "").lower() == "light"
    if sys.stdout.isatty():
        if _light:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[0;33m',
                CYAN='\033[0;34m', BLUE='\033[0;35m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[0;30m', NC='\033[0m',
            )
        else:
            return dict(
                RED='\033[0;31m', GREEN='\033[0;32m', YELLOW='\033[1;33m',
                CYAN='\033[0;36m', BLUE='\033[0;34m', BOLD='\033[1m',
                DIM='\033[2m', WHITE='\033[1;37m', NC='\033[0m',
            )
    return {k: '' for k in ('RED','GREEN','YELLOW','CYAN','BLUE','BOLD','DIM','WHITE','NC')}

_C = _detect_colors()
RED    = _C['RED'];   GREEN  = _C['GREEN'];  YELLOW = _C['YELLOW']
CYAN   = _C['CYAN'];  BLUE   = _C['BLUE'];   BOLD   = _C['BOLD']
DIM    = _C['DIM'];   WHITE  = _C['WHITE'];  NC     = _C['NC']

# ── Логирование ────────────────────────────────────────────────────────────
_LOG_FILE   = Path("/var/log/vless-install.log")
_XRAY_LOG   = Path("/var/log/xray/error.log")
_ALT_LOG    = Path("/usr/local/var/log/xray/error.log")

def _log(level: str, msg: str) -> None:
    try:
        from datetime import datetime as _dt
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_FILE.open("a") as f:
            ts = _dt.now().strftime("%Y-%m-%d %H:%M:%S")
            clean = re.sub(r'\x1b\[[0-9;]*m', '', msg)
            f.write(f"[{ts}] [FRAG_VIS] [{level}] {clean}\n")
    except Exception:
        pass

# ── Импорт ────────────────────────────────────────────────────────────────
from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row, _box_item, _box_back,
    _box_info, _box_warn, _box_desc, _get_box_width,
)

# ── Паттерны распознавания событий ────────────────────────────────────────
# Каждый паттерн: (regex, status_icon, status_color, event_label)
# Матч производится по строке лога (без временно́й метки).

_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    # TLS Handshake успешен
    (re.compile(r"tls.*handshake|handshake.*ok|tls.*established", re.I),
     "✓ TLS OK", "green", "TLS Handshake"),

    # Connection reset / RST
    (re.compile(r"connection reset|rst|connection.*refused|broken pipe|eof", re.I),
     "✗ RST", "red", "Connection reset / RST"),

    # Фрагментация — Xray логирует fragment при отправке сегментов
    (re.compile(r"fragment|split.*packet|packet.*split", re.I),
     "⚡ Frag", "cyan", "Fragment sent"),

    # TLS-ошибки (alert, certificate и т.п.)
    (re.compile(r"tls.*alert|certificate|x509|ssl.*error|tls.*error", re.I),
     "⚠ TLS Err", "yellow", "TLS / Certificate error"),

    # Timeout / deadline
    (re.compile(r"timeout|deadline|context deadline|i/o timeout", re.I),
     "⏱ Timeout", "yellow", "Timeout"),

    # Dial / connect attempt
    (re.compile(r"dial(?:ing)?\s+tcp|connecting to|outbound.*dial", re.I),
     "→ Dial", "cyan", "Outbound dial"),

    # Accepted inbound connection
    (re.compile(r"accepted|new.*connection|inbound.*accept", re.I),
     "↓ Accept", "green", "Inbound accepted"),

    # Xray general error
    (re.compile(r"\[error\]|\[warning\]", re.I),
     "⚠ Warn", "yellow", "Xray warning/error"),
]

# Финальный fallback — показываем строку как инфо
_PATTERN_INFO = ("ℹ Info", "dim", "Info")


# ── Парсинг одной строки лога Xray ────────────────────────────────────────

_RE_TIMESTAMP = re.compile(
    r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})"  # 2024/01/15 14:23:05
    r"|(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"    # 2024-01-15T14:23:05 (journald)
)

_RE_DOMAIN = re.compile(
    r"(?:->|to|from|dial)\s+([\w.\-]+(?::\d+)?)"
    r"|\"([\w.\-]+(?::\d+)?)\""
)


def _parse_log_line(raw: str) -> Optional[dict]:
    """
    Парсит одну строку error.log Xray.
    Возвращает dict или None (если строка пустая / служебная).
    """
    line = raw.strip()
    if not line or line.startswith("#"):
        return None

    # Извлекаем временну́ю метку
    ts_match = _RE_TIMESTAMP.search(line)
    if ts_match:
        ts_raw = ts_match.group(1) or ts_match.group(2)
        try:
            if "/" in ts_raw:
                ts_dt = datetime.strptime(ts_raw, "%Y/%m/%d %H:%M:%S")
            else:
                ts_dt = datetime.fromisoformat(ts_raw)
            ts_str = ts_dt.strftime("%H:%M:%S")
        except ValueError:
            ts_str = ts_raw[-8:]
        body = line[ts_match.end():].strip().lstrip(":").strip()
    else:
        ts_str = datetime.now().strftime("%H:%M:%S")
        body   = line

    # Определяем тип события
    icon, color, event = _PATTERN_INFO
    for pat, p_icon, p_color, p_event in _PATTERNS:
        if pat.search(body):
            icon, color, event = p_icon, p_color, p_event
            break

    # Извлекаем домен/адрес
    dm = _RE_DOMAIN.search(body)
    detail = (dm.group(1) or dm.group(2)) if dm else ""
    if not detail:
        # Берём последнюю значимую часть строки (до 40 символов)
        detail = body[-40:] if len(body) > 40 else body

    # Убираем ANSI-коды и лишние пробелы из detail
    detail = re.sub(r'\x1b\[[0-9;]*m', '', detail).strip()

    return {
        "ts":     ts_str,
        "icon":   icon,
        "color":  color,
        "event":  event,
        "detail": detail,
        "raw":    body,
    }


# ── Рендер строки таблицы ─────────────────────────────────────────────────

_COLOR_MAP = {
    "green":  GREEN,
    "red":    RED,
    "yellow": YELLOW,
    "cyan":   CYAN,
    "dim":    DIM,
    "blue":   BLUE,
}

def _render_row(entry: dict, box_w: int) -> str:
    """Форматирует одну запись в строку таблицы с цветом."""
    col  = _COLOR_MAP.get(entry["color"], DIM)
    ts   = entry["ts"][:8]
    icon = entry["icon"][:10].ljust(10)
    evt  = entry["event"][:18].ljust(18)
    # Оставшееся место под detail
    used  = 2 + 8 + 3 + 10 + 2 + 18 + 2  # ║ + ts + sep + icon + sep + event + sep
    avail = max(10, box_w - used - 2)
    detail = entry["detail"][:avail].ljust(avail)
    return f"  {DIM}{ts}{NC} │ {col}{icon}{NC} │ {evt} │ {DIM}{detail}{NC}"


def _print_table_header(box_w: int) -> None:
    used  = 2 + 8 + 3 + 10 + 2 + 18 + 2
    avail = max(10, box_w - used - 2)
    h_ts     = "Time".ljust(8)
    h_icon   = "Status".ljust(10)
    h_event  = "Event".ljust(18)
    h_detail = "Detail".ljust(avail)
    print(f"  {BOLD}{h_ts} │ {h_icon} │ {h_event} │ {h_detail}{NC}")
    print(f"  {'─'*8}─┼─{'─'*10}─┼─{'─'*18}─┼─{'─'*avail}")


# ── Snapshot-режим (последние N строк) ────────────────────────────────────

def _show_snapshot(log_path: Path, n_lines: int = 50) -> None:
    """Читает последние n_lines строк лога и отображает таблицу."""
    os.system("clear")
    box_w = _get_box_width()
    _box_top(f"📋  ВИЗУАЛИЗАЦИЯ ФРАГМЕНТАЦИИ — последние {n_lines} строк")
    _box_info(f"Лог: {log_path}")
    _box_bottom()
    print()

    try:
        all_lines = log_path.read_text(errors="replace").splitlines()
    except Exception as e:
        print(f"{RED}Не удалось открыть лог: {e}{NC}")
        return

    tail = all_lines[-n_lines:]
    entries = [_parse_log_line(l) for l in tail]
    entries = [e for e in entries if e is not None]

    if not entries:
        print(f"  {DIM}(нет событий для отображения){NC}")
        return

    _print_table_header(box_w)

    # Счётчики событий
    counts = {"green": 0, "red": 0, "cyan": 0, "yellow": 0, "dim": 0, "blue": 0}
    for e in entries:
        print(_render_row(e, box_w))
        counts[e.get("color", "dim")] = counts.get(e.get("color", "dim"), 0) + 1

    print()
    print(f"  {BOLD}Итого:{NC}  "
          f"{GREEN}✓ OK={counts['green']}{NC}  "
          f"{RED}✗ RST={counts['red']}{NC}  "
          f"{CYAN}⚡ Frag={counts['cyan']}{NC}  "
          f"{YELLOW}⚠ Warn={counts['yellow']}{NC}")


# ── Живой режим (tail -f эмуляция) ───────────────────────────────────────

def _live_tail(log_path: Path, max_rows: int = 40) -> None:
    """
    Живой режим: читает новые строки из лога по мере их появления.
    Выводит не более max_rows последних строк, дописывая новые сверху.
    Прерывается по Ctrl+C.
    """
    os.system("clear")
    box_w    = _get_box_width()
    _box_top("📡  ЖИВАЯ ВИЗУАЛИЗАЦИЯ ФРАГМЕНТАЦИИ  (Ctrl+C — выход)")
    _box_info(f"Лог: {log_path}")
    _box_bottom()
    print()
    _print_table_header(box_w)

    ring: deque[dict] = deque(maxlen=max_rows)
    counts = {"green": 0, "red": 0, "cyan": 0, "yellow": 0, "dim": 0, "blue": 0}

    try:
        with log_path.open("r", errors="replace") as fh:
            # Перемещаемся в конец файла
            fh.seek(0, 2)
            _log("INFO", "Живой режим визуализации фрагментации запущен")

            while True:
                raw = fh.readline()
                if not raw:
                    time.sleep(0.5)
                    continue

                entry = _parse_log_line(raw)
                if entry is None:
                    continue

                ring.append(entry)
                counts[entry.get("color", "dim")] = counts.get(entry.get("color", "dim"), 0) + 1

                # Перерисовываем последние строки
                # (лёгкий подход: только дописываем новую строку без полного clear)
                print(_render_row(entry, box_w))
                sys.stdout.flush()

    except KeyboardInterrupt:
        print()
        _log("INFO", "Живой режим визуализации завершён (Ctrl+C)")

    print()
    print(f"  {BOLD}Сессия итого:{NC}  "
          f"{GREEN}✓ OK={counts['green']}{NC}  "
          f"{RED}✗ RST={counts['red']}{NC}  "
          f"{CYAN}⚡ Frag={counts['cyan']}{NC}  "
          f"{YELLOW}⚠ Warn={counts['yellow']}{NC}")


# ── Поиск лог-файла Xray ─────────────────────────────────────────────────

def _find_xray_log() -> Optional[Path]:
    """Возвращает путь к error.log Xray (пробует несколько вариантов)."""
    candidates = [
        _XRAY_LOG,
        _ALT_LOG,
        Path("/var/log/xray.log"),
        Path("/tmp/xray-error.log"),
    ]
    # Также ищем через systemd
    for c in candidates:
        if c.exists() and c.stat().st_size > 0:
            return c

    # Пробуем найти по пути из конфига
    cfg_path = Path("/etc/xray/config.json")
    if cfg_path.exists():
        try:
            import json
            cfg = json.loads(cfg_path.read_text())
            error_path = cfg.get("log", {}).get("error", "")
            if error_path and Path(error_path).exists():
                return Path(error_path)
        except Exception:
            pass

    return None


# ── Публичное меню ────────────────────────────────────────────────────────

def do_fragment_log_viewer_menu() -> None:
    """
    Интерактивное меню визуализации фрагментации в логах.
    Вызывается из _menu_diagnostics() в _core.py.
    """
    while True:
        os.system("clear")
        print()
        _box_top("📊  ВИЗУАЛИЗАЦИЯ ФРАГМЕНТАЦИИ В ЛОГАХ")
        _box_desc(
            "Показывает, какие пакеты были разбиты, успешность TLS Handshake "
            "и наличие RST-сбросов от провайдера — на основе Xray error.log."
        )
        _box_sep()
        _box_row()
        _box_item("1", f"📡 Живой режим  {DIM}(следить за логом в реальном времени){NC}")
        _box_item("2", f"📋 Снапшот      {DIM}(последние 50 строк лога){NC}")
        _box_item("3", f"📋 Снапшот      {DIM}(последние 200 строк лога){NC}")
        _box_sep()

        log_path = _find_xray_log()
        if log_path:
            _box_info(f"Лог найден: {log_path}")
        else:
            _box_warn("Лог Xray не найден — убедитесь, что Xray запущен")
        _box_row()
        _box_back()
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch == "q" or ch == "":
            break

        if log_path is None:
            print(f"\n{RED}Лог Xray не найден. Убедитесь, что сервис запущен.{NC}")
            input(f"\n{BLUE}Нажмите Enter...{NC}")
            continue

        if ch == "1":
            _live_tail(log_path)
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "2":
            _show_snapshot(log_path, n_lines=50)
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        elif ch == "3":
            _show_snapshot(log_path, n_lines=200)
            input(f"\n{BLUE}Нажмите Enter...{NC}")
        else:
            print(f"{YELLOW}Неверный выбор.{NC}")
            time.sleep(1)

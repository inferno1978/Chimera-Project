"""
vless_installer/modules/scheduler.py
───────────────────────────────────────────────────────────────────────────────
Единый планировщик задач — отображение и управление cron/systemd задачами.

Экспортирует render_scheduler_menu(tasks) — чистую логику меню.
Список задач с callbacks строится в _core.py и передаётся как параметр,
что позволяет избежать circular import.

Точка входа из _core.py:
    from vless_installer.modules.scheduler import render_scheduler_menu

    def do_scheduler_menu() -> None:
        tasks = [...]   # строится в _core.py
        render_scheduler_menu(tasks)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Any

from vless_installer.modules.box_renderer import (
    _box_top, _box_sep, _box_bottom, _box_row,
    _wcslen,
    RED, GREEN, CYAN, BOLD, DIM, NC,
)

# ── Вспомогательные ───────────────────────────────────────────────────────────
def _run(cmd: list, capture: bool = False, check: bool = False,
         quiet: bool = False) -> subprocess.CompletedProcess:
    kw: dict = {"check": check}
    if capture:
        kw.update(capture_output=True, text=True, encoding="utf-8", errors="replace")
    elif quiet:
        kw.update(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd, **kw)

def _warn(msg: str) -> None:
    print(f"  {RED}⚠{NC}  {msg}")

# ── Статус задач ───────────────────────────────────────────────────────────────
def _cron_exists(p: str) -> bool:
    return Path(p).exists()

def _systemd_enabled(unit: str) -> bool:
    r = _run(["systemctl", "is-enabled", unit], capture=True, check=False)
    return r.stdout.strip() == "enabled"

def _task_status(cron: "str | None", unit: "str | None") -> bool:
    if cron:
        return _cron_exists(cron)
    if unit:
        return _systemd_enabled(unit)
    return False

def _pad(s: str, width: int) -> str:
    """Дополняет строку пробелами до нужной видимой ширины (учитывает эмодзи)."""
    diff = width - _wcslen(s)
    return s + " " * max(diff, 0)

# ── Главная функция меню ───────────────────────────────────────────────────────
def render_scheduler_menu(tasks: "list[dict[str, Any]]") -> None:
    """
    Отображает меню планировщика задач и обрабатывает выбор пользователя.

    Args:
        tasks: список словарей задач. Каждый словарь содержит:
            id, emoji, label, schedule, cron, unit, log, configure (callable|None)
    """
    _COL_ID    = 3
    _COL_LBL   = 34
    _COL_SCHED = 20

    while True:
        os.system("clear")
        print()
        _box_top("🗓️  ПЛАНИРОВЩИК ЗАДАЧ")
        _box_row(f"  {DIM}Все автоматические задачи cron и systemd в одном месте{NC}")
        _box_sep()

        _box_row(f"  {'№':<{_COL_ID}}  {'Задача':<{_COL_LBL}}  {'Расписание':<{_COL_SCHED}}  Статус")
        _box_row(f"  {'─'*_COL_ID}  {'─'*_COL_LBL}  {'─'*_COL_SCHED}  {'─'*10}")

        for i, t in enumerate(tasks, 1):
            active     = _task_status(t.get("cron"), t.get("unit"))
            status_str = f"{GREEN}вкл{NC}" if active else f"{DIM}выкл{NC}"
            emoji      = t["emoji"]
            label      = f"{emoji} {t['label']}"
            sched_plain = t["schedule"]
            sched_ansi  = f"{DIM}{sched_plain}{NC}"
            sched_pad   = sched_ansi + " " * max(_COL_SCHED - len(sched_plain), 0)
            _box_row(f"  {_pad(str(i), _COL_ID)}  {_pad(label, _COL_LBL)}  {sched_pad}  {status_str}")

        _box_sep()
        _box_row(f"  {CYAN}Введите номер задачи{NC} — открыть настройки")
        _box_row(f"  {RED}{BOLD}Q{NC} — назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            break

        if ch in ("q", ""):
            break

        if not ch.isdigit() or not (1 <= int(ch) <= len(tasks)):
            _warn("Неверный выбор")
            time.sleep(1)
            continue

        task = tasks[int(ch) - 1]
        if task.get("configure"):
            task["configure"]()
        else:
            _warn(f"Задача '{task['label']}' управляется из меню установки (пункт 1)")
            time.sleep(2)

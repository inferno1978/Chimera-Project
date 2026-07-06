"""
vless_installer/modules/backup_manager.py
───────────────────────────────────────────────────────────────────────────────
Автоматический бэкап конфигурации Xray по расписанию (cron).

Содержит:
  • ``_SCHEDULED_BACKUP_CRON`` — путь к /etc/cron.d/xray-backup.
  • ``_scheduled_backup_run()`` — CLI entry point для ``--scheduled-backup``
    (запускается из cron): создаёт tar.gz архив конфигов в /root/ и ротирует
    последние 7 копий.
  • ``do_manage_scheduled_backup()`` — интерактивное меню настройки расписания
    (включить/выключить/запустить прямо сейчас).

Точки входа из _core.py:
    from vless_installer.modules.backup_manager import (
        _SCHEDULED_BACKUP_CRON, _scheduled_backup_run, do_manage_scheduled_backup,
    )

Доступ к helpers ядра (log_to_file, success, info, warn, dim, _box_*,
ANSI-цвета) — через importlib (см. _core_module()), как и в других
извлечённых модулях (asn_cache.py, autoban.py и т.д.).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import os
import sys
import time
from datetime import datetime
from pathlib import Path


# ── Константы ─────────────────────────────────────────────────────────────────
_SCHEDULED_BACKUP_CRON = Path("/etc/cron.d/xray-backup")


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль vless_installer._core, импортируя его лениво."""
    import importlib
    return importlib.import_module("vless_installer._core")


# =============================================================================
#  АВТОМАТИЧЕСКИЙ БЭКАП ПО РАСПИСАНИЮ
# =============================================================================
def _scheduled_backup_run() -> None:
    """
    Выполняется из cron (``python3 <script> --scheduled-backup``).
    Создаёт архив конфигурации и ротирует старые архивы.
    """
    core = _core_module()
    log_to_file = core.log_to_file

    import gzip as _gzip, tarfile as _tarfile
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = Path(f"/root/xray-backup-{ts}.tar.gz")
    files_to_backup = [
        Path("/etc/xray"),
        Path("/usr/local/etc/xray"),
        Path("/var/lib/xray-installer/state.json"),
    ]
    with _tarfile.open(out, "w:gz") as tar:
        for src in files_to_backup:
            if src.exists():
                tar.add(str(src), arcname=src.name)
    sz = out.stat().st_size // 1024
    log_to_file("SUCCESS", f"Scheduled backup created: {out} ({sz} КБ)")
    # Ротация: оставляем последние 7 архивов
    all_archives = sorted(Path("/root").glob("xray-backup-*.tar.gz"), reverse=True)
    for old in all_archives[7:]:
        try:
            old.unlink()
            log_to_file("INFO", f"Scheduled backup rotated (removed): {old.name}")
        except Exception:
            pass


def do_manage_scheduled_backup() -> None:
    """Меню настройки автоматического бэкапа по расписанию."""
    core = _core_module()
    _box_top    = core._box_top
    _box_row    = core._box_row
    _box_sep    = core._box_sep
    _box_item   = core._box_item
    _box_bottom = core._box_bottom
    GREEN = core.GREEN
    NC    = core.NC
    DIM   = core.DIM
    CYAN  = core.CYAN
    BLUE  = core.BLUE
    success = core.success
    dim     = core.dim
    info    = core.info
    warn    = core.warn

    _BACKUP_SCRIPT = Path(sys.argv[0]).resolve()

    def _current_schedule() -> str | None:
        if not _SCHEDULED_BACKUP_CRON.exists():
            return None
        for line in _SCHEDULED_BACKUP_CRON.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                return line
        return None

    while True:
        os.system("clear")
        print()
        _box_top("📦  АВТОМАТИЧЕСКИЙ БЭКАП ПО РАСПИСАНИЮ")
        _box_row()
        cur = _current_schedule()
        if cur:
            _box_row(f"  Статус:     {GREEN}включён{NC}")
            _box_row(f"  Cron:       {DIM}{cur}{NC}")
        else:
            _box_row(f"  Статус:     {DIM}выключен{NC}")
        _box_row()
        all_archives = sorted(Path("/root").glob("xray-backup-*.tar.gz"), reverse=True)
        if all_archives:
            _box_row(f"  Последние архивы (из /root/):")
            for bp in all_archives[:5]:
                sz = bp.stat().st_size // 1024
                _box_row(f"    {DIM}{bp.name}{NC}  ({sz} КБ)")
        else:
            _box_row(f"  {DIM}Архивов пока нет{NC}")
        _box_sep()
        _box_item("1", f"Включить / изменить расписание  {DIM}(каждые N ночей){NC}")
        _box_item("2", f"Выключить автобэкап")
        _box_item("3", f"Запустить бэкап прямо сейчас")
        _box_item("Q", f"Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            break

        if ch == "1":
            print()
            print(f"  {DIM}Введите интервал в днях (1 = каждую ночь, 7 = раз в неделю).{NC}")
            try:
                days_s = input(f"  Интервал [1-30, по умолчанию 1]: ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            days = 1
            if days_s.isdigit() and 1 <= int(days_s) <= 30:
                days = int(days_s)
            try:
                hour_s = input(f"  Час ночного запуска [0-5, по умолчанию 3]: ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            hour = 3
            if hour_s.isdigit() and 0 <= int(hour_s) <= 5:
                hour = int(hour_s)

            # Генерируем cron-строку
            # Каждую ночь: 0 3 * * *
            # Каждые N ночей: 0 3 */N * *  (стандартный шаг по дням месяца)
            day_field = "*" if days == 1 else f"*/{days}"
            cron_line = (
                f"# Xray scheduled backup (every {days} day(s) at {hour}:00)\n"
                f"0 {hour} {day_field} * * root"
                f" python3 {_BACKUP_SCRIPT} --scheduled-backup"
                f" >> /var/log/xray-scheduled-backup.log 2>&1\n"
            )
            _SCHEDULED_BACKUP_CRON.write_text(cron_line)
            _SCHEDULED_BACKUP_CRON.chmod(0o644)
            success(f"Автобэкап включён: каждые {days} д. в {hour:02d}:00")
            dim(f"  Файл: {_SCHEDULED_BACKUP_CRON}")
            dim(f"  Лог:  /var/log/xray-scheduled-backup.log")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "2":
            if _SCHEDULED_BACKUP_CRON.exists():
                _SCHEDULED_BACKUP_CRON.unlink()
                success("Автобэкап выключен")
            else:
                info("Автобэкап уже выключен")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "3":
            info("Запуск бэкапа...")
            try:
                _scheduled_backup_run()
                new_arch = sorted(Path("/root").glob("xray-backup-*.tar.gz"), reverse=True)
                if new_arch:
                    sz = new_arch[0].stat().st_size // 1024
                    success(f"Готово: {new_arch[0].name} ({sz} КБ)")
                else:
                    warn("Архив не создан — проверьте права на /root/")
            except Exception as e:
                warn(f"Ошибка бэкапа: {e}")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in ("q", "Q", ""):
            break
        else:
            warn("Неверный выбор")
            time.sleep(1)

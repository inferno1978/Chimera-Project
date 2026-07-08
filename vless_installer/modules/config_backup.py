"""
config_backup.py — бэкап /etc/xray/config.json перед пересборкой.

Публичный API:
    backup_xray_config()        → (ok: bool, path: str)  — сделать бэкап
    list_backups()              → list[dict]              — список бэкапов
    restore_backup(filename)    → (ok: bool, msg: str)    — восстановить бэкап
    cleanup_old_backups(keep)   → int                     — удалить старые, вернуть кол-во
    do_backup_menu()            → None                    — интерактивное меню
"""

from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path

# ── Константы ─────────────────────────────────────────────────────────────────
XRAY_CONFIG   = Path("/etc/xray/config.json")
BACKUP_DIR    = Path("/var/lib/xray-installer/config-backups")
MAX_BACKUPS   = 10          # сколько бэкапов хранить по умолчанию
BACKUP_PREFIX = "config-"
BACKUP_SUFFIX = ".json"

# ── Цвета (дублируем минимально, чтобы не тащить весь _core) ──────────────────
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
CYAN   = "\033[36m"
DIM    = "\033[2m"
BOLD   = "\033[1m"
NC     = "\033[0m"


# ── Вспомогательные ───────────────────────────────────────────────────────────

def _ensure_backup_dir() -> None:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)


def _backup_filename() -> str:
    """Генерирует имя файла бэкапа с временной меткой."""
    ts = time.strftime("%Y%m%d-%H%M%S")
    return f"{BACKUP_PREFIX}{ts}{BACKUP_SUFFIX}"


def _parse_backup_ts(filename: str) -> float:
    """Возвращает timestamp из имени файла бэкапа, или 0."""
    try:
        stem = filename.replace(BACKUP_PREFIX, "").replace(BACKUP_SUFFIX, "")
        return time.mktime(time.strptime(stem, "%Y%m%d-%H%M%S"))
    except Exception:
        return 0.0


# ── Публичный API ─────────────────────────────────────────────────────────────

def backup_xray_config() -> tuple[bool, str]:
    """
    Копирует /etc/xray/config.json в BACKUP_DIR с временной меткой.
    Возвращает (True, путь_к_бэкапу) или (False, сообщение_об_ошибке).
    """
    if not XRAY_CONFIG.exists():
        return False, f"Файл {XRAY_CONFIG} не найден — бэкап пропущен"

    try:
        _ensure_backup_dir()
        dst = BACKUP_DIR / _backup_filename()
        shutil.copy2(str(XRAY_CONFIG), str(dst))
        # Сразу чистим старые бэкапы
        cleanup_old_backups(MAX_BACKUPS)
        return True, str(dst)
    except Exception as e:
        return False, f"Ошибка при создании бэкапа: {e}"


def list_backups() -> list[dict]:
    """
    Возвращает список бэкапов отсортированный от новых к старым.
    Каждый элемент: {'filename': str, 'path': str, 'ts': float, 'size': int, 'date': str}
    """
    if not BACKUP_DIR.exists():
        return []

    result = []
    for f in BACKUP_DIR.iterdir():
        if f.name.startswith(BACKUP_PREFIX) and f.name.endswith(BACKUP_SUFFIX):
            ts = _parse_backup_ts(f.name)
            result.append({
                "filename": f.name,
                "path":     str(f),
                "ts":       ts,
                "size":     f.stat().st_size,
                "date":     time.strftime("%d.%m.%Y %H:%M:%S", time.localtime(ts)),
            })

    result.sort(key=lambda x: x["ts"], reverse=True)
    return result


def restore_backup(filename: str) -> tuple[bool, str]:
    """
    Восстанавливает указанный бэкап в /etc/xray/config.json.
    Перед восстановлением создаёт бэкап текущего конфига с суффиксом -pre-restore.
    Возвращает (True, сообщение) или (False, сообщение_об_ошибке).
    """
    src = BACKUP_DIR / filename
    if not src.exists():
        return False, f"Бэкап не найден: {filename}"

    # Валидируем JSON перед восстановлением
    try:
        json.loads(src.read_text(encoding="utf-8"))
    except Exception as e:
        return False, f"Бэкап повреждён (невалидный JSON): {e}"

    # Сохраняем текущий конфиг как pre-restore бэкап
    if XRAY_CONFIG.exists():
        try:
            _ensure_backup_dir()
            ts = time.strftime("%Y%m%d-%H%M%S")
            pre = BACKUP_DIR / f"{BACKUP_PREFIX}{ts}-pre-restore{BACKUP_SUFFIX}"
            shutil.copy2(str(XRAY_CONFIG), str(pre))
        except Exception:
            pass  # не критично

    try:
        shutil.copy2(str(src), str(XRAY_CONFIG))
        return True, f"Восстановлен: {filename}"
    except Exception as e:
        return False, f"Ошибка при восстановлении: {e}"


def cleanup_old_backups(keep: int = MAX_BACKUPS) -> int:
    """
    Оставляет `keep` последних бэкапов, удаляет остальные.
    Не трогает бэкапы с суффиксом -pre-restore (они особенные).
    Возвращает количество удалённых файлов.
    """
    backups = [b for b in list_backups() if "pre-restore" not in b["filename"]]
    to_delete = backups[keep:]
    deleted = 0
    for b in to_delete:
        try:
            Path(b["path"]).unlink()
            deleted += 1
        except Exception:
            pass
    return deleted


# ── Интерактивное меню ────────────────────────────────────────────────────────

def do_backup_menu() -> None:
    """Интерактивное меню управления бэкапами конфига Xray."""
    from vless_installer._core import (
        _box_top, _box_row, _box_sep, _box_bottom, _box_item, _box_back,
        _box_ok, _box_warn,
    )
    import subprocess

    while True:
        os.system("clear")
        backups = list_backups()

        _box_top("💾  БЭКАПЫ КОНФИГА XRAY")
        _box_row(f"  Директория: {DIM}{BACKUP_DIR}{NC}")
        _box_row(f"  Хранится бэкапов: {BOLD}{len(backups)}{NC} / {MAX_BACKUPS} максимум")
        _box_sep()

        if backups:
            _box_row(f"  {'№':<4} {'Дата':<22} {'Размер':>8}")
            _box_sep()
            for i, b in enumerate(backups[:10], 1):
                size_kb = b["size"] / 1024
                marker = f" {GREEN}← текущий{NC}" if i == 1 else ""
                _box_row(f"  [{i:<2}] {b['date']:<22} {size_kb:>6.1f} KB{marker}")
        else:
            _box_row(f"  {DIM}Бэкапов пока нет{NC}")

        _box_sep()
        _box_item("B", "Создать бэкап сейчас")
        if backups:
            _box_item("R", "Восстановить бэкап")
            _box_item("D", "Удалить все бэкапы")
        _box_back()
        _box_bottom()

        ch = input(f"{CYAN}Выбор: {NC}").strip().upper()

        if ch in ("0", "Q", "q", ""):
            break

        elif ch == "B":
            ok, msg = backup_xray_config()
            if ok:
                _box_ok(f"Бэкап создан: {DIM}{msg}{NC}")
            else:
                _box_warn(msg)
            input(f"{CYAN}Нажмите Enter...{NC}")

        elif ch == "R" and backups:
            _box_row(f"\n  Введите номер бэкапа для восстановления (1-{min(len(backups), 10)}):")
            try:
                n = int(input(f"{CYAN}  Номер: {NC}").strip())
                if 1 <= n <= min(len(backups), 10):
                    b = backups[n - 1]
                    _box_row(f"\n  Восстановить: {BOLD}{b['date']}{NC}?")
                    confirm = input(f"{YELLOW}  Подтвердить? [y/N]: {NC}").strip().lower()
                    if confirm == "y":
                        ok, msg = restore_backup(b["filename"])
                        if ok:
                            _box_ok(msg)
                            _box_row(f"  {YELLOW}Перезапустите Xray вручную: systemctl restart xray{NC}")
                        else:
                            _box_warn(msg)
                    else:
                        _box_row(f"  {DIM}Отменено{NC}")
                else:
                    _box_warn("Неверный номер")
            except (ValueError, KeyboardInterrupt):
                _box_row(f"  {DIM}Отменено{NC}")
            input(f"{CYAN}Нажмите Enter...{NC}")

        elif ch == "D" and backups:
            confirm = input(f"{YELLOW}  Удалить все бэкапы? [y/N]: {NC}").strip().lower()
            if confirm == "y":
                deleted = 0
                for b in backups:
                    try:
                        Path(b["path"]).unlink()
                        deleted += 1
                    except Exception:
                        pass
                _box_ok(f"Удалено бэкапов: {deleted}")
            else:
                _box_row(f"  {DIM}Отменено{NC}")
            input(f"{CYAN}Нажмите Enter...{NC}")

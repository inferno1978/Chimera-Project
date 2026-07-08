"""
vless_installer/modules/awg_backup.py
───────────────────────────────────────────────────────────────────────────────
Backup / Restore для AmneziaWG standalone.

Создаёт .tar.gz архив со всеми конфигами + state.
Restore с rollback при ошибке (как в bivlked).
"""
from __future__ import annotations

import json
import tarfile
import tempfile
import time
from datetime import datetime
from pathlib import Path

from .awg_constants import (
    AWGS_CONF_DIR, AWGS_SERVER_CONF, AWGS_AWG_DIR, AWGS_KEYS_DIR,
    AWGS_STATE_FILE, AWGS_BACKUP_DIR,
)
from .awg_state import awgs_state_load, awgs_state_save


def _core_module():
    import importlib
    return importlib.import_module("vless_installer._core")


# ── BACKUP ──────────────────────────────────────────────────────────────────

def awgs_backup_create(label: str = "") -> Path | None:
    """
    Создаёт backup в /root/awg/backups/awg-standalone-<timestamp>.tar.gz.
    Включает:
      • /etc/amnezia/amneziawg/awg0.conf
      • /var/lib/xray-installer/awg_standalone_state.json
      • /root/awg/keys/ (все клиентские конфиги)
    """
    core = _core_module()
    info = core.info
    success = core.success
    warn = core.warn

    if not AWGS_STATE_FILE.exists():
        warn("Standalone AWG не установлен — backup невозможен")
        return None

    AWGS_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    suffix = f"-{label}" if label else ""
    backup_path = AWGS_BACKUP_DIR / f"awg-standalone-{ts}{suffix}.tar.gz"

    info(f"Создание backup: {backup_path}")

    try:
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        try:
            with tarfile.open(tmp_path, "w:gz") as tar:
                # State
                if AWGS_STATE_FILE.exists():
                    tar.add(AWGS_STATE_FILE, arcname="state/awg_standalone_state.json")
                # Server conf
                if AWGS_SERVER_CONF.exists():
                    tar.add(AWGS_SERVER_CONF, arcname="conf/awg0.conf")
                # Keys
                if AWGS_KEYS_DIR.exists():
                    for f in AWGS_KEYS_DIR.iterdir():
                        if f.is_file():
                            tar.add(f, arcname=f"keys/{f.name}")
                # Метаданные
                meta = {
                    "created_at":  datetime.now().isoformat(),
                    "version":     "1.0.0",
                    "label":       label,
                }
                meta_file = tmp_path.parent / f"{tmp_path.stem}.meta.json"
                meta_file.write_text(json.dumps(meta, indent=2))
                tar.add(meta_file, arcname="META.json")
                meta_file.unlink()

            # Atomic move
            tmp_path.replace(backup_path)
            backup_path.chmod(0o600)
        finally:
            tmp_path.unlink(missing_ok=True)

        success(f"Backup создан: {backup_path}")
        core.log_to_file("INFO", f"awgs_backup_create: {backup_path}")
        return backup_path
    except Exception as e:
        warn(f"Backup не удался: {e}")
        core.log_to_file("ERROR", f"awgs_backup_create: {e}")
        return None


# ── RESTORE ────────────────────────────────────────────────────────────────

def awgs_backup_list() -> list:
    """Возвращает список backup'ов."""
    if not AWGS_BACKUP_DIR.exists():
        return []
    return sorted(
        [f for f in AWGS_BACKUP_DIR.iterdir() if f.name.endswith(".tar.gz")],
        key=lambda f: f.stat().st_mtime,
        reverse=True,
    )


def awgs_backup_restore(backup_path: Path) -> bool:
    """
    Восстанавливает из backup'а с rollback при ошибке.
    Алгоритм:
      1. Останавливаем awg-quick@awg0
      2. Создаём snapshot текущего состояния (для rollback)
      3. Распаковываем backup во временную директорию
      4. Копируем файлы на место
      5. Запускаем awg-quick@awg0
      6. Если что-то не так — откатываем snapshot
    """
    core = _core_module()
    info = core.info
    success = core.success
    warn = core.warn

    if not backup_path.exists():
        warn(f"Backup не найден: {backup_path}")
        return False

    info(f"Восстановление из: {backup_path}")

    # 1. Snapshot текущего состояния (для rollback)
    snapshot_files = []
    for src in (AWGS_STATE_FILE, AWGS_SERVER_CONF):
        if src.exists():
            snap = src.with_suffix(src.suffix + ".snapshot")
            try:
                snap.write_bytes(src.read_bytes())
                snapshot_files.append((src, snap))
            except Exception:
                pass
    if AWGS_KEYS_DIR.exists():
        snap_keys = AWGS_KEYS_DIR.parent / "keys.snapshot"
        try:
            if snap_keys.exists():
                import shutil
                shutil.rmtree(snap_keys)
            import shutil
            shutil.copytree(AWGS_KEYS_DIR, snap_keys)
            snapshot_files.append((AWGS_KEYS_DIR, snap_keys))
        except Exception:
            pass

    # 2. Останавливаем сервис
    from .awg_standalone import awgs_stop_systemd
    info("Остановка awg-quick@awg0...")
    awgs_stop_systemd()

    # 3. Распаковываем backup
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            with tarfile.open(backup_path, "r:gz") as tar:
                tar.extractall(tmpdir)

            # 4. Копируем файлы на место
            state_src = tmpdir / "state" / "awg_standalone_state.json"
            if state_src.exists():
                AWGS_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
                AWGS_STATE_FILE.write_bytes(state_src.read_bytes())
                AWGS_STATE_FILE.chmod(0o600)

            conf_src = tmpdir / "conf" / "awg0.conf"
            if conf_src.exists():
                AWGS_CONF_DIR.mkdir(parents=True, exist_ok=True)
                AWGS_SERVER_CONF.write_bytes(conf_src.read_bytes())
                AWGS_SERVER_CONF.chmod(0o600)

            keys_src = tmpdir / "keys"
            if keys_src.exists():
                AWGS_KEYS_DIR.mkdir(parents=True, exist_ok=True)
                # Очищаем текущие ключи
                for f in AWGS_KEYS_DIR.iterdir():
                    if f.is_file():
                        f.unlink()
                # Копируем из backup
                for f in keys_src.iterdir():
                    if f.is_file():
                        dst = AWGS_KEYS_DIR / f.name
                        dst.write_bytes(f.read_bytes())
                        dst.chmod(0o600)

        # 5. Запускаем сервис
        from .awg_standalone import awgs_setup_systemd
        info("Запуск awg-quick@awg0...")
        if not awgs_setup_systemd():
            warn("Сервис не запустился после restore — откатываю")
            _awgs_backup_rollback(snapshot_files)
            return False

        # 6. Удаляем snapshot (всё ок)
        _awgs_backup_cleanup_snapshots(snapshot_files)

        success("Restore завершён успешно")
        core.log_to_file("INFO", f"awgs_backup_restore: {backup_path}")
        return True

    except Exception as e:
        warn(f"Restore не удался: {e} — откатываю")
        core.log_to_file("ERROR", f"awgs_backup_restore: {e}")
        _awgs_backup_rollback(snapshot_files)
        return False


def _awgs_backup_rollback(snapshot_files: list) -> None:
    """Откатывает изменения из snapshot."""
    core = _core_module()
    for src, snap in snapshot_files:
        try:
            if src.is_file() and snap.is_file():
                src.write_bytes(snap.read_bytes())
                snap.unlink()
            elif src.is_dir() and snap.is_dir():
                import shutil
                if src.exists():
                    shutil.rmtree(src)
                shutil.copytree(snap, src)
                shutil.rmtree(snap)
        except Exception as e:
            core.log_to_file("ERROR", f"awgs_backup_rollback {src}: {e}")


def _awgs_backup_cleanup_snapshots(snapshot_files: list) -> None:
    """Удаляет snapshot-файлы после успешного restore."""
    for src, snap in snapshot_files:
        try:
            if snap.is_file():
                snap.unlink()
            elif snap.is_dir():
                import shutil
                shutil.rmtree(snap)
        except Exception:
            pass


# ── TUI-МЕНЮ ────────────────────────────────────────────────────────────────

def do_manage_awg_backup() -> None:
    """TUI-меню Backup/Restore."""
    core = _core_module()
    _box_top = core._box_top
    _box_row = core._box_row
    _box_bottom = core._box_bottom
    _box_item = core._box_item
    warn = core.warn
    CYAN, NC, BLUE, DIM = core.CYAN, core.NC, core.BLUE, core.DIM

    while True:
        import os
        os.system("clear")
        print()
        backups = awgs_backup_list()
        _box_top(f"Backup / Restore ({len(backups)} доступно)")
        _box_row()
        if not backups:
            _box_row(f"  {DIM}Пока нет backup'ов{NC}")
        else:
            for i, b in enumerate(backups[:10], 1):
                size_kb = b.stat().st_size // 1024
                mtime = datetime.fromtimestamp(b.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                _box_row(f"  {CYAN}[{i}]{NC} {b.name}  {DIM}({size_kb} KB, {mtime}){NC}")
        _box_row()
        _box_item("B", f"Создать backup")
        _box_item("R", f"Восстановить из backup (укажите номер)")
        _box_item("Q", f"Назад")
        _box_bottom()
        ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()

        if ch == "b":
            label = input(f"{CYAN}Метка backup (пусто = без метки): {NC}").strip()
            awgs_backup_create(label=label)
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch == "r":
            num_str = input(f"{CYAN}Номер backup для restore: {NC}").strip()
            try:
                num = int(num_str)
                if 1 <= num <= len(backups):
                    confirm = input(f"{core.YELLOW}Восстановить '{backups[num-1].name}'? "
                                    f"Текущее состояние будет заменено! [y/N]: {NC}").strip().lower()
                    if confirm in ("y", "yes", "д", "да"):
                        awgs_backup_restore(backups[num-1])
                else:
                    warn("Неверный номер")
            except ValueError:
                warn("Нужно число")
            input(f"{BLUE}Нажмите Enter...{NC}")
        elif ch in ("q", ""):
            break

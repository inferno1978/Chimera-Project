"""
vless_installer/modules/awg_apply.py
───────────────────────────────────────────────────────────────────────────────
Применение конфига awg0.conf к работающему сервису.

Два режима (как в bivlked):
  • syncconf  — без даунтайма (по умолчанию). Использует `awg syncconf` для
                атомарного обновления peer'ов без разрыва соединений.
  • restart   — fallback при kernel panic / нестабильности. Полный рестарт
                awg-quick@awg0.service.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from .awg_constants import (
    AWGS_BIN, AWGS_QUICK_BIN, AWGS_INTERFACE, AWGS_SERVER_CONF,
    AWGS_APPLY_MODE_SYNCCONF, AWGS_APPLY_MODE_RESTART,
    AWGS_SYNC_TIMEOUT_SEC, AWGS_RESTART_TIMEOUT_SEC,
)


def _core_module():
    import importlib
    return importlib.import_module("vless_installer._core")


def awgs_apply_syncconf() -> bool:
    """
    Применяет конфиг без даунтайма через `awg syncconf`.
    Возвращает True при успехе.
    """
    core = _core_module()
    # syncconf требует, чтобы конфиг был в специальном формате.
    # Используем `awg-quick strip` для подготовки, затем `awg syncconf`.
    if not AWGS_SERVER_CONF.exists():
        core.log_to_file("ERROR", f"awgs_apply_syncconf: {AWGS_SERVER_CONF} не существует")
        return False

    # Создаём временный файл со strip'нутым конфигом
    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        # strip — убирает комментарии и форматирует для syncconf
        r = core._run([AWGS_QUICK_BIN, "strip", str(AWGS_SERVER_CONF)],
                      capture=True, check=False, timeout=AWGS_SYNC_TIMEOUT_SEC)
        if r.returncode != 0:
            core.log_to_file("ERROR", f"awg syncconf strip: {r.stderr}")
            return False
        Path(tmp_path).write_text(r.stdout)

        # syncconf — атомарное обновление
        r = core._run(
            [AWGS_BIN, "syncconf", AWGS_INTERFACE, tmp_path],
            capture=True, check=False, timeout=AWGS_SYNC_TIMEOUT_SEC,
        )
        if r.returncode != 0:
            core.log_to_file("ERROR", f"awg syncconf: {r.stderr}")
            return False
        core.log_to_file("INFO", "awgs_apply: syncconf OK")
        return True
    except Exception as e:
        core.log_to_file("ERROR", f"awgs_apply_syncconf: {e}")
        return False
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def awgs_apply_restart() -> bool:
    """
    Полный рестарт awg-quick@awg0.service.
    Используется как fallback при kernel panic или нестабильности syncconf.
    """
    core = _core_module()
    from .awg_constants import AWGS_SYSTEMD_AWG_QUICK
    r = core._run(["systemctl", "restart", AWGS_SYSTEMD_AWG_QUICK],
                  capture=True, check=False, timeout=AWGS_RESTART_TIMEOUT_SEC)
    if r.returncode != 0:
        core.log_to_file("ERROR", f"awgs_apply_restart: {r.stderr}")
        return False
    core.log_to_file("INFO", "awgs_apply: restart OK")
    return True


def awgs_apply(mode: str = AWGS_APPLY_MODE_SYNCCONF) -> bool:
    """
    Применяет конфиг в указанном режиме.
    При syncconf-failure автоматически fallback на restart.
    """
    core = _core_module()
    if mode == AWGS_APPLY_MODE_RESTART:
        return awgs_apply_restart()

    # syncconf (по умолчанию)
    if awgs_apply_syncconf():
        return True
    # Fallback
    core.warn("syncconf не удался — fallback на restart (кратковременный разрыв)")
    return awgs_apply_restart()


def awgs_service_status() -> dict:
    """Возвращает статус awg-quick@awg0.service."""
    core = _core_module()
    from .awg_constants import AWGS_SYSTEMD_AWG_QUICK
    r = core._run(["systemctl", "is-active", AWGS_SYSTEMD_AWG_QUICK],
                  capture=True, check=False)
    active = r.stdout.strip() == "active"
    r2 = core._run(["systemctl", "is-enabled", AWGS_SYSTEMD_AWG_QUICK],
                   capture=True, check=False)
    enabled = r2.stdout.strip() == "enabled"
    return {
        "active":  active,
        "enabled": enabled,
        "raw":     r.stdout.strip(),
    }


def awgs_show_handshakes() -> str:
    """Возвращает вывод `awg show` (peers + handshakes + transfer)."""
    core = _core_module()
    r = core._run([AWGS_BIN, "show", AWGS_INTERFACE],
                  capture=True, check=False, timeout=10)
    return r.stdout if r.returncode == 0 else ""


def awgs_show_dump() -> list:
    """
    Возвращает `awg show all dump` — машиночитаемый формат.
    Первая строка — interface, остальные — peers.
    """
    core = _core_module()
    r = core._run([AWGS_BIN, "show", "all", "dump"],
                  capture=True, check=False, timeout=10)
    if r.returncode != 0:
        return []
    return [line for line in r.stdout.splitlines() if line.strip()]

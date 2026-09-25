#!/usr/bin/env python3
"""
chimera/modules/wpp_autoupdate.py
────────────────────────────────────────────────────────────────────────────────
Авто-обновление фронта WPP Web Panel (по образцу hysteria2_auto_update.py).

Архитектура:
  • /etc/cron.d/wpp-autoupdate — cron-файл, запускается в 03:30 ежедневно
  • python3 .../main.py --wpp-autoupdate — точка входа из cron
  • wpp_autoupdate_cron() — проверка state.auto_update.enabled, если True —
    вызывает _update_front() из wpp_panel.py (там же atomic swap + smoke test
    + rollback при HTTP-fail)
  • wpp_autoupdate_install() — устанавливает cron (idempotent)
  • wpp_autoupdate_remove()  — удаляет cron-файл

Cron path:
    30 3 * * * root /usr/bin/python3 /opt/chimera/main.py --wpp-autoupdate

NB: время 03:30 — после H2 (03:00) и Xray (03:30) — чтобы не пересекаться с
ними (т.к. каждый перезапускает свои сервисы, не должен мешать соседям).

state.auto_update.enabled — default True. Если False, cron-файл остаётся
установленным, но wpp_autoupdate_cron() просто return-ит (паттерн H2).
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Optional

# Bootstrap корня проекта
if __package__ in (None, ""):
    _ROOT = Path(__file__).resolve().parent.parent.parent
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))

from chimera.modules.wpp_state import load_state, save_state  # noqa: E402

# ─── КОНСТАНТЫ ───────────────────────────────────────────────────────────────

# NB: main.py путь — может быть /opt/chimera/main.py или /opt/vless-installer/main.py
# в зависимости от того, как chimera была установлена. Берём по фактическому
# расположению — у нас в chimera-project это /opt/chimera/main.py на server1.
_MAIN_PY = Path("/opt/chimera/main.py")
if not _MAIN_PY.exists():
    # Fallback: попробуем найти через chimera-проект root
    _ALT = Path(__file__).resolve().parent.parent.parent / "main.py"
    if _ALT.exists():
        _MAIN_PY = _ALT

_UPDATE_CRON = Path("/etc/cron.d/wpp-autoupdate")
_CRON_SCHEDULE = "30 3 * * *"  # 03:30 ежедневно (после H2 03:00)
_CRON_USER = "root"
_PYTHON_BIN = "/usr/bin/python3"


# ─── ЛЕНИВЫЙ ДОСТУП К ЯДРУ ───────────────────────────────────────────────────

def _core_module():
    """Ленивый импорт chimera._core (как в warp.py / triple_panel.py)."""
    import importlib
    return importlib.import_module("chimera._core")


# ─── ПРОВЕРКА / ПРИМЕНЕНИЕ ОБНОВЛЕНИЯ ────────────────────────────────────────

def wpp_update_check() -> dict:
    """
    Проверяет последнюю версию WPP на GitHub.
    Возвращает:
        {
            "current": str | "",         # установленная версия
            "latest":  str | None,       # последняя на GitHub
            "update_available": bool,
            "checked_at": ISO8601,
            "ok": bool
        }
    """
    from chimera.modules.wpp_panel import _detect_upstream_version, _load_state, _version_key

    state = _load_state()
    current = state.get("front_version", "") or ""
    latest, ok = _detect_upstream_version(force=True)

    update_available = False
    if current and latest and ok:
        update_available = _version_key(latest) > _version_key(current)

    import datetime as _dt
    return {
        "current":          current,
        "latest":           latest,
        "update_available": update_available,
        "checked_at":       _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "ok":               ok,
    }


def wpp_update_apply(force: bool = False) -> tuple[bool, str]:
    """
    Применяет обновление фронта WPP. Делегирует в wpp_panel._update_front().
    Возвращает (ok, msg).

    :param force: если True — обновляет даже если уже latest (ре-три).
    """
    from chimera.modules.wpp_panel import _update_front, _load_state

    if not force:
        info = wpp_update_check()
        if not info["update_available"]:
            return True, f"Уже актуально (v{info['current']})"

    state = _load_state()
    if not state.get("installed"):
        return False, "WPP Panel не установлена"
    return _update_front()


# ─── STATE TOGGLE ────────────────────────────────────────────────────────────

def _get_auto_update_enabled() -> bool:
    state = load_state()
    return bool(state.get("auto_update", {}).get("enabled", True))


def _set_auto_update_enabled(enabled: bool) -> None:
    state = load_state()
    if "auto_update" not in state or not isinstance(state["auto_update"], dict):
        state["auto_update"] = {}
    state["auto_update"]["enabled"] = bool(enabled)
    import datetime as _dt
    state["auto_update"]["last_toggle_at"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
    save_state(state)


# ─── CRON INSTALL / REMOVE ───────────────────────────────────────────────────

def wpp_autoupdate_install() -> tuple[bool, str]:
    """Устанавливает cron-файл для авто-обновления WPP (idempotent)."""
    if not _MAIN_PY.exists():
        return False, f"main.py не найден: {_MAIN_PY}"
    cron_body = (
        "# WPP AutoUpdate — Chimera Project\n"
        f"{_CRON_SCHEDULE} {_CRON_USER} {_PYTHON_BIN} {_MAIN_PY} --wpp-autoupdate\n"
    )
    try:
        _UPDATE_CRON.parent.mkdir(parents=True, exist_ok=True)
        _UPDATE_CRON.write_text(cron_body)
        _UPDATE_CRON.chmod(0o644)
        # Помечаем в state что cron установлен
        state = load_state()
        if "auto_update" not in state or not isinstance(state["auto_update"], dict):
            state["auto_update"] = {}
        state["auto_update"]["cron_installed"] = True
        save_state(state)
        return True, f"Cron установлен: {_UPDATE_CRON}"
    except PermissionError:
        return False, "Требуются права root для записи в /etc/cron.d/"
    except Exception as exc:
        return False, f"Ошибка: {type(exc).__name__}: {exc}"


def wpp_autoupdate_remove() -> tuple[bool, str]:
    """Удаляет cron-файл авто-обновления WPP."""
    try:
        if _UPDATE_CRON.exists():
            _UPDATE_CRON.unlink()
        state = load_state()
        if "auto_update" in state and isinstance(state["auto_update"], dict):
            state["auto_update"]["cron_installed"] = False
            save_state(state)
        return True, f"Cron удалён: {_UPDATE_CRON}"
    except PermissionError:
        return False, "Требуются права root"
    except Exception as exc:
        return False, f"Ошибка: {type(exc).__name__}: {exc}"


# ─── TOGGLE ───────────────────────────────────────────────────────────────────

def wpp_autoupdate_toggle(enable: bool) -> tuple[bool, str]:
    """
    Включает/выключает авто-обновление.
    Если enable=True — устанавливает cron + state.auto_update.enabled=True
    Если enable=False — удаляет cron + state.auto_update.enabled=False
    """
    if enable:
        ok, msg = wpp_autoupdate_install()
        if ok:
            _set_auto_update_enabled(True)
            return True, "Авто-обновление включено"
        return False, msg
    else:
        ok, msg = wpp_autoupdate_remove()
        _set_auto_update_enabled(False)
        return ok, f"Авто-обновление выключено ({msg})"


# ─── CRON ENTRY POINT ────────────────────────────────────────────────────────

def wpp_autoupdate_cron() -> None:
    """
    Точка входа для cron-задачи. Вызывается из main.py --wpp-autoupdate.

    Flow:
      1. Проверяем state.auto_update.enabled — если False, выходим.
      2. Проверяем что WPP установлен.
      3. Проверяем последнюю версию.
      4. Если есть обновление — _update_front() (atomic swap + smoke + rollback).
    """
    state = load_state()
    au = state.get("auto_update", {})
    if not au.get("enabled", True):
        print("[WPP-AUTOUPDATE] auto-update disabled in state, exiting", flush=True)
        return
    if not state.get("installed"):
        print("[WPP-AUTOUPDATE] WPP Panel not installed, exiting", flush=True)
        return

    print(f"[WPP-AUTOUPDATE] checking for updates "
          f"(installed: v{state.get('front_version', '?')})...", flush=True)
    ok, msg = wpp_update_apply(force=False)
    if ok:
        print(f"[WPP-AUTOUPDATE] {msg}", flush=True)
    else:
        print(f"[WPP-AUTOUPDATE] FAILED: {msg}", flush=True)


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python3 wpp_autoupdate.py [check|apply|install|remove|toggle|cron]",
              file=sys.stderr)
        return 1
    cmd = sys.argv[1]
    if cmd == "check":
        info = wpp_update_check()
        import json
        print(json.dumps(info, indent=2, ensure_ascii=False))
        return 0
    elif cmd == "apply":
        ok, msg = wpp_update_apply(force="--force" in sys.argv)
        print(("OK: " if ok else "FAIL: ") + msg)
        return 0 if ok else 1
    elif cmd == "install":
        ok, msg = wpp_autoupdate_install()
        print(("OK: " if ok else "FAIL: ") + msg)
        return 0 if ok else 1
    elif cmd == "remove":
        ok, msg = wpp_autoupdate_remove()
        print(("OK: " if ok else "FAIL: ") + msg)
        return 0 if ok else 1
    elif cmd == "toggle":
        if len(sys.argv) < 3:
            print("Usage: toggle on|off", file=sys.stderr)
            return 1
        enable = sys.argv[2].lower() in ("on", "true", "1", "yes")
        ok, msg = wpp_autoupdate_toggle(enable)
        print(("OK: " if ok else "FAIL: ") + msg)
        return 0 if ok else 1
    elif cmd == "cron":
        wpp_autoupdate_cron()
        return 0
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

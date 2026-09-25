#!/usr/bin/env python3
"""
chimera/modules/wpp_state.py
────────────────────────────────────────────────────────────────────────────────
Атомарная работа с state.json для WPP Web Panel.

Pattern: proto_common.proto_load_state / proto_save_state (atomic write,
owner/mode), как в triple_panel.py.

State file: /var/lib/xray-installer/wpp_panel_state.json (mode 0600).
Schema:
    {
        "installed": bool,
        "web_port": int,
        "admin_user": str,
        "admin_pass_salt": str (32 hex),
        "admin_pass_sha256": str (64 hex),
        "front_version": str,                # e.g. "2.4.2"
        "upstream_cache": {
            "version": str | None,
            "checked_at": ISO8601 | None,
            "ok": bool
        },
        "language": "ru",
        "installed_at": ISO8601
    }
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

# Bootstrap корня проекта (для прямого запуска `python3 wpp_state.py`)
if __package__ in (None, ""):
    _ROOT = Path(__file__).resolve().parent.parent.parent
    if str(_ROOT) not in __import__("sys").path:
        __import__("sys").path.insert(0, str(_ROOT))

from chimera.modules.proto_common import proto_load_state, proto_save_state  # noqa: E402

STATE_DIR      = Path("/var/lib/xray-installer")
STATE_FILE     = STATE_DIR / "wpp_panel_state.json"

# Дефолтный state (используется при первом запуске / uninstall).
DEFAULT_STATE: dict = {
    "installed": False,
    "web_port": 0,
    "admin_user": "admin",
    "admin_pass_salt": "",
    "admin_pass_sha256": "",
    "front_version": "",
    "upstream_cache": {
        "version": None,
        "checked_at": None,
        "ok": False,
    },
    "language": "ru",
    "installed_at": "",
}


def load_state() -> dict:
    """
    Загружает state.json. Если файл не существует или повреждён — возвращает
    дефолт. Не raise'ит.
    """
    try:
        data = proto_load_state(STATE_FILE, defaults=DEFAULT_STATE)
        if not isinstance(data, dict):
            return dict(DEFAULT_STATE)
        # Нормализуем: добавляем отсутствующие ключи из дефолта
        merged = dict(DEFAULT_STATE)
        merged.update(data)
        # Гарантируем структуру upstream_cache
        if not isinstance(merged.get("upstream_cache"), dict):
            merged["upstream_cache"] = dict(DEFAULT_STATE["upstream_cache"])
        return merged
    except Exception:
        return dict(DEFAULT_STATE)


def save_state(data: dict) -> None:
    """
    Атомарно записывает state.json (через proto_save_state: temp write +
    chmod 0600). Не raise'ит при ошибке файловой системы — пишем в
    /var/lib/xray-installer/ который гарантированно существует
    (создаётся при установке Chimera).
    """
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        proto_save_state(STATE_FILE, data, name="wpp_panel_state.json")
    except Exception as exc:  # noqa: BLE001
        # Не падаем — модуль должен быть устойчив к проблемам FS.
        # Логируем в stderr для отладки.
        import sys
        print(f"[WPP-STATE] save failed: {type(exc).__name__}: {exc}",
              file=sys.stderr, flush=True)


def get_installed() -> bool:
    """True если панель установлена и state согласован."""
    return bool(load_state().get("installed", False))


def get_web_port() -> int:
    """Возвращает web_port из state, или 0 если не установлено."""
    return int(load_state().get("web_port", 0) or 0)


def get_admin_user() -> str:
    return str(load_state().get("admin_user", "admin") or "admin")


def get_front_version() -> str:
    return str(load_state().get("front_version", "") or "")


def get_upstream_cache() -> dict:
    return dict(load_state().get("upstream_cache", {}))


def update_upstream_cache(version: Optional[str], ok: bool) -> None:
    """Обновляет поле upstream_cache в state.json (atomic merge)."""
    import datetime as _dt
    state = load_state()
    state["upstream_cache"] = {
        "version": version,
        "checked_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "ok": ok,
    }
    save_state(state)


if __name__ == "__main__":
    # Smoke-проверка: load → print → save round-trip
    import json as _json
    s = load_state()
    print(_json.dumps(s, indent=2, ensure_ascii=False))

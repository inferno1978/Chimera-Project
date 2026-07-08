"""
vless_installer/modules/awg_expires.py
───────────────────────────────────────────────────────────────────────────────
Временные клиенты для AmneziaWG standalone.

Поддерживает форматы duration:
  1h, 12h, 1d, 7d, 30d, 4w (как в bivlked)
  Также: 1m (минута), 1w (неделя), 1mo (месяц = 30d)

Cron (через awgs_setup_expires_cron в awg_standalone.py) вызывает
awgs_expires_check() каждые 5 минут — удаляет истёкших клиентов.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple


def _core_module():
    import importlib
    return importlib.import_module("vless_installer._core")


# ── Парсинг duration ────────────────────────────────────────────────────────

# Регэксп: <число><единица>
# Единицы: s (сек), m (мин), h (час), d (день), w (неделя), mo (месяц=30d)
_DURATION_RE = re.compile(r"^(\d+)\s*(s|m|h|d|w|mo)$", re.IGNORECASE)

_DURATION_UNITS = {
    "s":  timedelta(seconds=1),
    "m":  timedelta(minutes=1),
    "h":  timedelta(hours=1),
    "d":  timedelta(days=1),
    "w":  timedelta(weeks=1),
    "mo": timedelta(days=30),  # месяц ≈ 30 дней
}


def awgs_expires_parse(duration_str: str) -> Optional[timedelta]:
    """
    Парсит строку duration в timedelta.
    Поддерживаемые форматы: 1h, 12h, 1d, 7d, 30d, 4w, 1mo, 5m, 600s
    Возвращает None если строка невалидна.
    """
    if not duration_str:
        return None
    m = _DURATION_RE.match(duration_str.strip())
    if not m:
        return None
    try:
        n = int(m.group(1))
        unit = m.group(2).lower()
        delta = _DURATION_UNITS.get(unit)
        if delta is None:
            return None
        return delta * n
    except (ValueError, KeyError):
        return None


def awgs_expires_format(delta: timedelta) -> str:
    """Форматирует timedelta обратно в строку (для отображения)."""
    total_sec = int(delta.total_seconds())
    if total_sec >= 86400 * 30 and total_sec % (86400 * 30) == 0:
        return f"{total_sec // (86400 * 30)}mo"
    if total_sec >= 86400 * 7 and total_sec % (86400 * 7) == 0:
        return f"{total_sec // (86400 * 7)}w"
    if total_sec >= 86400 and total_sec % 86400 == 0:
        return f"{total_sec // 86400}d"
    if total_sec >= 3600 and total_sec % 3600 == 0:
        return f"{total_sec // 3600}h"
    if total_sec >= 60 and total_sec % 60 == 0:
        return f"{total_sec // 60}m"
    return f"{total_sec}s"


def awgs_expires_compute_iso(delta: timedelta) -> str:
    """Возвращает ISO-дату истечения (UTC)."""
    return (datetime.now(timezone.utc) + delta).isoformat()


def awgs_expires_is_expired(expires_at_iso: str) -> bool:
    """Проверяет, истёк ли срок. Пустая строка = бессрочный (не истёк)."""
    if not expires_at_iso:
        return False
    try:
        # Поддерживаем как ISO с tz, так и без
        dt = datetime.fromisoformat(expires_at_iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) >= dt
    except Exception:
        return False


def awgs_expires_remaining(expires_at_iso: str) -> Optional[timedelta]:
    """Возвращает оставшееся время или None если бессрочный/истёкший."""
    if not expires_at_iso:
        return None
    try:
        dt = datetime.fromisoformat(expires_at_iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if now >= dt:
            return timedelta(0)
        return dt - now
    except Exception:
        return None


def awgs_expires_humanize(expires_at_iso: str) -> str:
    """Возвращает человекочитаемую строку ('7 дней', '3 часа', 'бессрочно')."""
    if not expires_at_iso:
        return "бессрочно"
    remaining = awgs_expires_remaining(expires_at_iso)
    if remaining is None:
        return "?"
    if remaining == timedelta(0):
        return "истёк"
    total_sec = int(remaining.total_seconds())
    if total_sec >= 86400:
        days = total_sec // 86400
        return f"{days} дн."
    if total_sec >= 3600:
        hours = total_sec // 3600
        return f"{hours} ч."
    if total_sec >= 60:
        mins = total_sec // 60
        return f"{mins} мин."
    return f"{total_sec} сек."


# ── Cron-check (вызывается каждые 5 мин) ────────────────────────────────────

def awgs_expires_check() -> int:
    """
    Проверяет всех пиров на истечение срока. Удаляет истёкших.
    Возвращает количество удалённых.
    """
    core = _core_module()
    from .awg_state import awgs_state_load, awgs_state_save
    state = awgs_state_load()
    peers = state.get("peers", [])
    if not peers:
        return 0

    expired = [p for p in peers if awgs_expires_is_expired(p.get("expires_at", ""))]
    if not expired:
        return 0

    core.log_to_file("INFO", f"awgs_expires_check: истекло {len(expired)} пир(ов)")

    # Удаляем каждого
    for peer in expired:
        name = peer.get("name", "?")
        core.log_to_file("INFO", f"awgs_expires_check: удаляю пира '{name}'")
        # Делегируем в awg_peers для корректного удаления + syncconf
        try:
            from .awg_peers import awg_peer_remove
            awg_peer_remove(name, apply=True, save_state=False)
        except Exception as e:
            core.log_to_file("ERROR", f"awgs_expires_check remove {name}: {e}")

    return len(expired)

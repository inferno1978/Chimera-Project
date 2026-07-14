"""
chimera/modules/asn_cache.py
───────────────────────────────────────────────────────────────────────────────
Локальный SQLite-кэш префиксов ASN и lookup ASN/IP.

Содержит две логические части (объединены, т.к. обе работают с ASN):

1. **Prefix cache** (SQLite, /var/lib/xray-installer/asn_prefix_cache.sqlite3):
   Хранит префиксы конкретного ASN (из RIPE Stat API) и делегированные
   подсети РФ (delegated-ripencc-latest). Используется модулями
   ru_subnets / as_direct (в _core.py).

2. **IP→ASN lookup** (in-memory cache + ip-api.com):
   Запрашивает ASN/org/ISP для IP при логировании банов и аудите.
   Используется модулями autoban / connection_audit (в _core.py).

Точки входа из _core.py:
    from chimera.modules.asn_cache import (
        ASN_CACHE_DB, ASN_CACHE_MAX_AGE_DAYS,
        _asn_cache_connect, _asn_cache_save, _asn_cache_load,
        _asn_cache_delete, _asn_cache_info,
        _lookup_asn, _fmt_asn_short,
    )

Доступ к helpers ядра (warn) — через importlib (см. _core_module()),
как и в других извлечённых модулях (warp.py, smart_balancer.py и т.д.).
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import json
import sqlite3
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Константы ─────────────────────────────────────────────────────────────────
ASN_CACHE_DB           = Path("/var/lib/xray-installer/asn_prefix_cache.sqlite3")
ASN_CACHE_MAX_AGE_DAYS = 30   # предупреждать если кэш старше N дней


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py)
# =============================================================================
def _core_module():
    """Возвращает модуль chimera._core, импортируя его лениво.

    При запуске через cron (python -c 'from ... import ...') модуль ещё не
    загружен — importlib полноценно его импортирует. При вызове из
    интерактивного инсталлятора модуль уже в sys.modules (был импортирован
    одним из поздних lazy-вызовов внутри других модулей) — это просто lookup.
    """
    import importlib
    return importlib.import_module("chimera._core")


def _warn(msg: str) -> None:
    """Обёртка над _core.warn() — позднее связывание."""
    try:
        _core_module().warn(msg)
    except Exception:
        # Fallback: если ядро по какой-то причине недоступно (cron-режим
        # при отсутствии прав на /var/log), не роняем вызов.
        print(f"[WARN] {msg}")


# =============================================================================
#  PREFIX CACHE (SQLite) — префиксы ASN и делегированные подсети РФ
# =============================================================================
# Кэш хранит:
#   • prefixes_asn  — префиксы конкретного ASN (RIPE Stat API)
#   • prefixes_ru   — делегированные подсети РФ (delegated-ripencc-latest)
#
# Логика использования:
#   1. При успешной загрузке из RIPE → обновляем кэш.
#   2. При недоступности RIPE → берём данные из кэша (если есть).
#   3. Кэш считается «свежим» если возраст < ASN_CACHE_MAX_AGE_DAYS суток.
#      Устаревший кэш всё равно используется как запасной вариант, но
#      пользователь получает предупреждение с датой последнего обновления.


def _asn_cache_connect():
    """Открывает (и при необходимости инициализирует) БД кэша. Возвращает sqlite3.Connection."""
    ASN_CACHE_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(ASN_CACHE_DB), timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS prefix_cache (
            key        TEXT PRIMARY KEY,   -- 'asn:AS12345' или 'ru_delegated'
            updated_at INTEGER NOT NULL,   -- unix timestamp последнего обновления
            cidrs_json TEXT NOT NULL       -- JSON-массив строк CIDR
        )
    """)
    conn.commit()
    return conn


def _asn_cache_save(key: str, cidrs: list) -> None:
    """Сохраняет список CIDR в кэш под указанным ключом."""
    try:
        conn = _asn_cache_connect()
        conn.execute(
            "INSERT OR REPLACE INTO prefix_cache (key, updated_at, cidrs_json) VALUES (?, ?, ?)",
            (key, int(time.time()), json.dumps(cidrs, ensure_ascii=False))
        )
        conn.commit()
        conn.close()
    except Exception as e:
        _warn(f"  [кэш ASN] Не удалось сохранить '{key}': {e}")


def _asn_cache_load(key: str) -> tuple:
    """
    Загружает список CIDR из кэша.
    Возвращает (cidrs: list, age_days: float) или ([], None) если записи нет.
    """
    try:
        if not ASN_CACHE_DB.exists():
            return [], None
        conn = _asn_cache_connect()
        row = conn.execute(
            "SELECT updated_at, cidrs_json FROM prefix_cache WHERE key = ?", (key,)
        ).fetchone()
        conn.close()
        if row is None:
            return [], None
        updated_at, cidrs_json = row
        age_days = (time.time() - updated_at) / 86400
        cidrs = json.loads(cidrs_json)
        return cidrs, age_days
    except Exception as e:
        _warn(f"  [кэш ASN] Не удалось прочитать '{key}': {e}")
        return [], None


def _asn_cache_delete(key: str) -> None:
    """Удаляет запись из кэша (например, при явном сбросе)."""
    try:
        if not ASN_CACHE_DB.exists():
            return
        conn = _asn_cache_connect()
        conn.execute("DELETE FROM prefix_cache WHERE key = ?", (key,))
        conn.commit()
        conn.close()
    except Exception as e:
        _warn(f"  [кэш ASN] Не удалось удалить '{key}': {e}")


def _asn_cache_info() -> list:
    """
    Возвращает список dict с информацией о записях кэша:
    [{"key": ..., "count": ..., "age_days": ..., "updated_str": ...}, ...]
    """
    result = []
    try:
        if not ASN_CACHE_DB.exists():
            return result
        conn = _asn_cache_connect()
        rows = conn.execute(
            "SELECT key, updated_at, cidrs_json FROM prefix_cache ORDER BY key"
        ).fetchall()
        conn.close()
        for key, updated_at, cidrs_json in rows:
            try:
                count = len(json.loads(cidrs_json))
            except Exception:
                count = 0
            age_days = (time.time() - updated_at) / 86400
            updated_str = datetime.fromtimestamp(updated_at).strftime("%Y-%m-%d %H:%M")
            result.append({
                "key":         key,
                "count":       count,
                "age_days":    age_days,
                "updated_str": updated_str,
            })
    except Exception as e:
        _warn(f"  [кэш ASN] Ошибка при чтении списка записей: {e}")
    return result


# =============================================================================
#  IP → ASN LOOKUP (in-memory cache + ip-api.com)
# =============================================================================
_asn_cache: dict = {}  # кеш: ip -> {"asn": "AS12345", "org": "...", "isp": "..."}


def _lookup_asn(ip: str) -> dict:
    """
    Запрашивает ASN и провайдера для IP через ip-api.com (бесплатно, без ключа).
    Возвращает словарь с ключами asn, org, isp.
    При ошибке возвращает пустой словарь.
    Кеширует результаты в _asn_cache.
    """
    if ip in _asn_cache:
        return _asn_cache[ip]
    result: dict = {}
    try:
        url = f"http://ip-api.com/json/{ip}?fields=as,org,isp,status"
        req = urllib.request.Request(url, headers={"User-Agent": "xray-installer/3.99"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            result = {
                "asn": data.get("as", ""),    # "AS12345 SomeName"
                "org": data.get("org", ""),
                "isp": data.get("isp", ""),
            }
    except Exception:
        pass
    _asn_cache[ip] = result
    return result


def _fmt_asn_short(info: dict) -> str:
    """Форматирует ASN-инфо в короткую строку для отображения в рамке.
    Пример: AS12345 · Cloudflare Inc."""
    if not info:
        return ""
    asn_raw = info.get("asn", "")            # "AS12345 FullName"
    isp     = info.get("isp", "")
    # Берём только номер ASN (первое слово)
    asn_num = asn_raw.split()[0] if asn_raw else ""
    label   = isp or info.get("org", "")
    if asn_num and label:
        return f"{asn_num} · {label}"
    return asn_num or label or ""

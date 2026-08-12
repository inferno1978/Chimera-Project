"""
chimera/modules/traffic_accounting.py
───────────────────────────────────────────────────────────────────────────────
Единый модуль учёта трафика для всех протоколов с baseline-offset mechanism.

ПРОБЛЕМА
========
Разные протоколы имеют разные источники счётчиков трафика (xray Stats API,
awg show dump, nftables counter-rules, access.log, journalctl). Многие из них сбрасываются
в 0 при рестарте сервиса/ротации логов/ребуте. Без baseline-offset это
приводит к тихой потере накопленного трафика:
  • VLESS: `systemctl restart xray` сбрасывает Stats API → used_bytes в
    traffic_limits.json уменьшается → пользователь с 9GB/10GB после
    рестарта видит «использовано 0GB».
  • AWG: `systemctl restart awg-quick@awg0` сбрасывает rx/tx в ядре.
  • Mieru/NaiveProxy/Hysteria2: nftables counter-rules сбрасываются при ребуте.
  • NaiveProxy: Caddy roll_size 10mb ротирует access.log → парсер теряет
    per-user byte counter.

РЕШЕНИЕ: baseline-offset
========================
Для каждого (user_id, protocol) храним в state.json:
  {
    "baseline_bytes":   int,  # накоплено ДО прошлого снимка
    "last_raw":         int,  # последний raw счётчик из источника
    "last_ts":          ISO,  # timestamp прошлого снимка
    "real_used":        int   # baseline_bytes + (last_raw - baseline_offset)
                              # где baseline_offset = last_raw на момент
                              # установки baseline (см. _apply_sample)
  }

Алгоритм record_traffic_sample(user_id, protocol, raw_counter_bytes):
  1. Если raw >= last_raw (нормальный рост):
       delta = raw - last_raw
       accumulated += delta
       last_raw = raw
  2. Если raw < last_raw (счётчик сбросился — рестарт/ротация):
       accumulated += raw  # считаем что новый счётчик стартовал с 0
       last_raw = raw
       # baseline остаётся — накопленное не теряется
  3. Сохраняем в state.json (atomic, file-locked).

ДОКУМЕНТАЦИЯ ПО ПРОТОКОЛАМ (из аудита):
  • VLESS/Xray:  raw = xray api statsquery (сброс при restart xray)
  • AWG:         raw = awg show dump rx+tx (сброс при restart awg-quick)
  • Mieru:       raw = nft_rule_counter_read(table, "input", comment="mita-stats")
                  (сброс при restart mita/reboot)
  • NaiveProxy:  raw = sum(access.log entry.size) (сброс при Caddy roll_size)
  • MTProto:     УЖЕ имеет baseline (daily snapshots) — НЕ ТРОГАТЬ
  • sing-box:    нет источника — НЕ ТРОГАТЬ
  • FPTN:        нет per-user byte counter — НЕ ТРОГАТЬ
  • Hysteria2:   per-exit-node (не per-user) — опционально, вне scope

Публичное API:
  record_traffic_sample(user_id, protocol, raw_counter_bytes) -> int
  get_accumulated_bytes(user_id, protocol) -> int
  reset_accumulated(user_id, protocol) -> None
  parse_human_readable_bytes(s) -> int
  format_bytes(n, locale="en") -> str
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union, Dict, Literal


# =============================================================================
#  КОНСТАНТЫ
# =============================================================================
_STATE_FILE = Path("/var/lib/xray-installer/traffic_accounting.json")
_LOG_FILE   = Path("/var/log/chimera.log")
_LOCK_FILE  = Path("/var/lib/xray-installer/traffic_accounting.lock")

# Поддерживаемые протоколы (для валидации)
SUPPORTED_PROTOCOLS = frozenset({
    "xray", "awg", "mieru", "naiveproxy",
    "trusttunnel",  # aggregate-only (D5): upstream /metrics has no per-user label.
                    # Recorded under synthetic "_aggregate" user_id by trusttunnel_stats.py.
    # "mtproto" — уже имеет свой baseline, не мигрируем
    # "singbox" — нет источника данных
    # "fptn"    — нет per-user byte counter
    # "hysteria2" — per-exit-node, не per-user (опционально)
})


# =============================================================================
#  ОТЛОЖЕННАЯ ПРИВЯЗКА К ЯДРУ (_core.py) — для логирования
# =============================================================================
def _core_module():
    """Возвращает модуль chimera._core (lazy import)."""
    import importlib
    return importlib.import_module("chimera._core")


def _log(level: str, msg: str) -> None:
    """Логирует в основной лог vless-install.log."""
    try:
        core = _core_module()
        if hasattr(core, "log_to_file"):
            core.log_to_file(level, f"traffic_accounting: {msg}")
            return
    except Exception:
        pass
    # Fallback: прямой write
    try:
        _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with _LOG_FILE.open("a") as f:
            f.write(f"[{ts}] [TRAFFIC-ACC] [{level}] {msg}\n")
    except Exception:
        pass


# =============================================================================
#  ПАРСЕР ЧЕЛОВЕКОЧИТАЕМЫХ ЕДИНИЦ
# =============================================================================
# IEC-стандарт (binary, 1024-based): KiB, MiB, GiB, TiB, PiB, EiB
_IEC_UNITS = {
    "b":    1,
    "kib":  1024,
    "mib":  1024 ** 2,
    "gib":  1024 ** 3,
    "tib":  1024 ** 4,
    "pib":  1024 ** 5,
    "eib":  1024 ** 6,
}

# SI-стандарт (decimal, 1000-based): KB, MB, GB, TB, PB, EB
_SI_UNITS = {
    "b":    1,
    "kb":   1000,
    "mb":   1000 ** 2,
    "gb":   1000 ** 3,
    "tb":   1000 ** 4,
    "pb":   1000 ** 5,
    "eb":   1000 ** 6,
}

# Bare-letter aliases: "1G" → 1 GiB (IEC, VPN-конвенция)
# Это сознательное решение: в контексте VPN/DNS трафик традиционно считается
# в binary (1024), а не decimal (1000). Если пользователь пишет "1G" без
# явного "iB" — трактуем как IEC.
_BARE_LETTER_TO_IEC = {
    "k": "kib", "m": "mib", "g": "gib", "t": "tib", "p": "pib", "e": "eib",
}

# Regex: число (с опциональной дробной частью) + опциональный пробел + единица
_RE_PARSE = re.compile(
    r"""^\s*
        (?P<num>\d+(?:\.\d+)?)   # 1 / 1.5 / 100
        \s*                       # опциональный пробел(ы)
        (?P<unit>[A-Za-z]*)       # KiB / KB / G / пусто
        \s*$                      # опциональный trailing whitespace
    """,
    re.VERBOSE,
)


def parse_human_readable_bytes(s: str, *, default_unit: str = "B") -> int:
    """
    Парсит строку вида "1.5 GiB" / "100MB" / "1G" / "1024" в точные байты.

    Поддерживаемые форматы единиц:
      • IEC (binary, 1024-based): B, KiB, MiB, GiB, TiB, PiB, EiB
        — case-insensitive: "gib" == "GiB" == "GIB"
      • SI (decimal, 1000-based): B, KB, MB, GB, TB, PB, EB
        — case-insensitive: "mb" == "MB" == "Mb"
      • Bare letters: K, M, G, T, P, E → трактуем как IEC (VPN-конвенция)
        — "1G" → 1 GiB = 1073741824 байт (НЕ 1 GB = 1000000000)
      • Без единицы: используется default_unit (по умолчанию "B")
        — "1024" → 1024 байт

    Пробел между числом и единицей — опционален:
      "1.5 GiB" == "1.5GiB" == "  1.5   GiB  "

    Дробные значения поддерживаются: "1.5 GiB" → 1610612736 байт.

    Args:
      s: строка для парсинга
      default_unit: единица по умолчанию если в строке нет явной единицы
                    (по умолчанию "B" = байты)

    Returns:
      int — точное количество байт

    Raises:
      ValueError: если строка не распознана или единица неизвестна

    Examples:
      >>> parse_human_readable_bytes("1.5 GiB")
      1610612736
      >>> parse_human_readable_bytes("100MB")
      100000000
      >>> parse_human_readable_bytes("1G")
      1073741824
      >>> parse_human_readable_bytes("1024")
      1024
      >>> parse_human_readable_bytes("1.5gib")
      1610612736
    """
    if not isinstance(s, str):
        raise ValueError(f"expected string, got {type(s).__name__}")
    m = _RE_PARSE.match(s)
    if not m:
        raise ValueError(f"unrecognized size format: {s!r}")
    num_str = m.group("num")
    unit_str = m.group("unit")
    try:
        num = float(num_str)
    except ValueError:
        raise ValueError(f"invalid number: {num_str!r}")
    if num < 0:
        raise ValueError(f"negative size not allowed: {s!r}")

    # Если единица пустая — используем default_unit
    if not unit_str:
        unit_key = default_unit.lower()
    else:
        unit_key = unit_str.lower()

    # Bare letter → IEC
    if unit_key in _BARE_LETTER_TO_IEC:
        unit_key = _BARE_LETTER_TO_IEC[unit_key]

    # IEC (включая "b" = bytes)
    if unit_key in _IEC_UNITS:
        factor = _IEC_UNITS[unit_key]
    # SI (KB/MB/GB/...)
    elif unit_key in _SI_UNITS:
        factor = _SI_UNITS[unit_key]
    else:
        raise ValueError(f"unknown unit: {unit_str!r} (supported: B/KiB/MiB/GiB/TiB/PiB/EiB/KB/MB/GB/TB/PB/EB)")

    return int(num * factor)


# =============================================================================
#  ФОРМАТЕР БАЙТОВ (bytes → str)
# =============================================================================
_UNITS_EN = ("B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB")
_UNITS_RU = ("Б", "КБ", "МБ", "ГБ", "ТБ", "ПБ", "ЭБ")


def format_bytes(n: int,
                 *,
                 locale: Literal["en", "ru"] = "en",
                 precision: int = 1,
                 zero_str: Optional[str] = None) -> str:
    """
    Форматирует байты в человекочитаемую строку.

    Args:
      n: количество байт (может быть отрицательным для delta-вывода)
      locale: "en" → IEC-литералы (B/KiB/MiB/GiB/TiB/PiB/EiB)
              "ru" → кириллица (Б/КБ/МБ/ГБ/ТБ/ПБ/ЭБ) — binary-1024
      precision: количество знаков после запятой для не-B единиц
      zero_str: если n==0 и zero_str задан — вернуть zero_str
                (для табличек где 0 = «нет данных»)

    Returns:
      str — "<n> <unit>" (с пробелом между числом и единицей)

    Examples:
      >>> format_bytes(1610612736)
      '1.5 GiB'
      >>> format_bytes(1024)
      '1.0 KiB'
      >>> format_bytes(500)
      '500 B'
      >>> format_bytes(0, zero_str="—")
      '—'
      >>> format_bytes(1610612736, locale="ru")
      '1.5 ГБ'
    """
    if n == 0 and zero_str is not None:
        return zero_str
    units = _UNITS_EN if locale == "en" else _UNITS_RU
    sign = "-" if n < 0 else ""
    n = abs(n)
    for u in units:
        if n < 1024:
            if u in ("B", "Б"):
                return f"{sign}{n} {u}"
            return f"{sign}{n:.{precision}f} {u}"
        n /= 1024
    # n >= 1024 EiB — возвращаем в EiB (или ЭБ)
    return f"{sign}{n:.{precision}f} {units[-1]}"


# =============================================================================
#  STATE I/O (с file locking для thread/process safety)
# =============================================================================
def _state_load() -> dict:
    """Загружает state.json. Возвращает {} при отсутствии/ошибке."""
    try:
        if _STATE_FILE.exists():
            data = json.loads(_STATE_FILE.read_text())
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _state_save(data: dict) -> None:
    """Атомарная запись state.json с chmod 0o600."""
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    try:
        tmp.chmod(0o600)
    except Exception:
        pass
    tmp.replace(_STATE_FILE)  # atomic rename


def _with_lock(fn):
    """Декоратор: выполняет fn с эксклюзивным file lock.
    Защищает от гонок между потоками и процессами (например, cron и TUI).
    """
    def wrapper(*args, **kwargs):
        _LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        lock_fd = os.open(str(_LOCK_FILE), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            # Блокируем файл (блокирующий вызов — ждёт других)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            return fn(*args, **kwargs)
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except Exception:
                pass
            os.close(lock_fd)
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


# =============================================================================
#  BASELINE-OFFSET MECHANISM
# =============================================================================
def _get_entry(state: dict, user_id: str, protocol: str) -> dict:
    """Возвращает запись {baseline_bytes, last_raw, last_ts} или пустой шаблон."""
    proto_dict = state.get(protocol, {})
    if not isinstance(proto_dict, dict):
        proto_dict = {}
    entry = proto_dict.get(user_id, {})
    if not isinstance(entry, dict):
        entry = {}
    return {
        "baseline_bytes": entry.get("baseline_bytes", 0),
        "last_raw":       entry.get("last_raw", 0),
        "last_ts":        entry.get("last_ts", ""),
    }


def _compute_accumulated(entry: dict, raw: int) -> int:
    """Вычисляет accumulated = baseline + raw (нормальный рост) или
    (baseline + last_raw) + raw (после сброса).
    Чистая функция — не мутирует entry. Используется и в record, и в get.

    Модель:
      baseline = total accumulated BEFORE last_raw was recorded
      После записи last_raw: total = baseline + last_raw
      При новом raw (>= last_raw): new_total = baseline + raw (baseline не меняется)
      При reset (raw < last_raw): new_baseline = baseline + last_raw,
                                    new_total = new_baseline + raw
    """
    baseline = entry.get("baseline_bytes", 0)
    last_raw = entry.get("last_raw", 0)
    if raw >= last_raw:
        # Нормальный рост: baseline не меняется, total = baseline + raw
        return baseline + raw
    else:
        # Счётчик сбросился: сохраняем last_raw в baseline, new total =
        # (baseline + last_raw) + raw
        return (baseline + last_raw) + raw


@_with_lock
def record_traffic_sample(user_id: str,
                          protocol: str,
                          raw_counter_bytes: int) -> int:
    """
    Записывает новый снимок raw-счётчика и возвращает accumulated total.

    Алгоритм baseline-offset:
      1. Если raw >= last_raw (нормальный рост):
           accumulated = baseline + (raw - last_raw)
           Обновляем last_raw = raw.
      2. Если raw < last_raw (счётчик сбросился — рестарт/ротация):
           accumulated = baseline + raw  # raw накапливается с момента сброса
           baseline += last_raw          # сохраняем накопленное до сброса
           last_raw = raw                # новый baseline для future deltas

    Идемпотентность: повторный вызов с тем же raw → accumulated не меняется
    (delta = 0).

    Thread-safety: использует file lock (fcntl.flock) для защиты от гонок
    между потоками и процессами (например, cron-сборщик и TUI).

    Args:
      user_id: идентификатор пользователя (email для VLESS, owner_email для
               AWG, username для Mieru/NaiveProxy, и т.п.)
      protocol: имя протокола (должно быть в SUPPORTED_PROTOCOLS)
      raw_counter_bytes: текущее значение raw-счётчика из источника
                         (xray api / awg show / nft_counter_read / access.log)

    Returns:
      int — accumulated total bytes (после применения этого снимка)

    Raises:
      ValueError: если protocol не поддерживается
    """
    if protocol not in SUPPORTED_PROTOCOLS:
        raise ValueError(
            f"unsupported protocol: {protocol!r}. "
            f"Supported: {sorted(SUPPORTED_PROTOCOLS)}"
        )
    if not user_id:
        raise ValueError("user_id is required")
    if raw_counter_bytes < 0:
        raw_counter_bytes = 0

    state = _state_load()
    entry = _get_entry(state, user_id, protocol)
    last_raw = entry["last_raw"]
    baseline = entry["baseline_bytes"]

    if raw_counter_bytes >= last_raw:
        # Нормальный рост — baseline не меняется, total = baseline + raw
        new_accumulated = baseline + raw_counter_bytes
        new_baseline = baseline
    else:
        # Счётчик сбросился — сохраняем last_raw в baseline,
        # new total = (baseline + last_raw) + raw
        new_baseline = baseline + last_raw
        new_accumulated = new_baseline + raw_counter_bytes
        _log("INFO",
            f"counter reset detected: protocol={protocol} user={user_id} "
            f"last_raw={last_raw} new_raw={raw_counter_bytes} "
            f"baseline {baseline}→{new_baseline}")

    # Обновляем entry
    new_entry = {
        "baseline_bytes": new_baseline,
        "last_raw":       raw_counter_bytes,
        "last_ts":        datetime.now(timezone.utc).isoformat(),
    }

    # Записываем в state
    if protocol not in state or not isinstance(state.get(protocol), dict):
        state[protocol] = {}
    state[protocol][user_id] = new_entry
    _state_save(state)

    return new_accumulated


@_with_lock
def get_accumulated_bytes(user_id: str, protocol: str) -> int:
    """
    Возвращает накопленный трафик (без записи нового снимка).
    Чисто read-only — берёт last_raw из state и пересчитывает accumulated
    по тому же алгоритму, что record_traffic_sample.

    Args:
      user_id: идентификатор пользователя
      protocol: имя протокола

    Returns:
      int — accumulated total bytes (или 0 если записи нет)
    """
    if protocol not in SUPPORTED_PROTOCOLS:
        raise ValueError(f"unsupported protocol: {protocol!r}")
    if not user_id:
        return 0
    state = _state_load()
    entry = _get_entry(state, user_id, protocol)
    # accumulated = baseline + last_raw (т.к. last_raw это последний снимок,
    # и после него не было новых delta)
    return entry["baseline_bytes"] + entry["last_raw"]


@_with_lock
def reset_accumulated(user_id: str, protocol: str) -> None:
    """
    Сбрасывает накопленный трафик для (user_id, protocol).
    Используется при ручном reset counters (например, начало месяца).

    После reset: baseline_bytes=0, last_raw=0 → следующий record_traffic_sample
    начнёт копиться с нуля.
    """
    if protocol not in SUPPORTED_PROTOCOLS:
        raise ValueError(f"unsupported protocol: {protocol!r}")
    if not user_id:
        return
    state = _state_load()
    if protocol in state and user_id in state.get(protocol, {}):
        state[protocol][user_id] = {
            "baseline_bytes": 0,
            "last_raw":       0,
            "last_ts":        datetime.now(timezone.utc).isoformat(),
            "reset_at":       datetime.now(timezone.utc).isoformat(),
        }
        _state_save(state)
        _log("INFO", f"reset accumulated: protocol={protocol} user={user_id}")


@_with_lock
def get_all_accumulated(user_id: str) -> Dict[str, int]:
    """
    Возвращает accumulated по всем протоколам для пользователя.
    Полезно для суммарного отображения в TUI.

    Returns:
      dict — {protocol: accumulated_bytes}, только для протоколов где есть
      запись в state
    """
    if not user_id:
        return {}
    state = _state_load()
    result = {}
    for proto in SUPPORTED_PROTOCOLS:
        proto_dict = state.get(proto, {})
        if isinstance(proto_dict, dict) and user_id in proto_dict:
            entry = proto_dict.get(user_id, {})
            if isinstance(entry, dict):
                result[proto] = entry.get("baseline_bytes", 0) + entry.get("last_raw", 0)
    return result


# =============================================================================
#  Публичный экспорт
# =============================================================================
__all__ = [
    # Baseline-offset API
    "record_traffic_sample",
    "get_accumulated_bytes",
    "reset_accumulated",
    "get_all_accumulated",
    # Parser / formatter
    "parse_human_readable_bytes",
    "format_bytes",
    # Constants
    "SUPPORTED_PROTOCOLS",
    # State file paths (для тестов)
    "_STATE_FILE",
    "_LOCK_FILE",
    # Internal helpers (для тестов)
    "_get_entry",
    "_compute_accumulated",
    "_state_load",
    "_state_save",
]

"""
chimera/modules/warp_scan_pools.py
───────────────────────────────────────────────────────────────────────────────
Автообновление ПУЛОВ СКАНИРОВАНИЯ WARP (/24) из апстрима vernette/warpscout.

ЗАЧЕМ:
    массовый TCP-скан Endpoint Manager'а ходит по списку /24-подсетей
    (warp.WARP_SCAN_RANGES). Список однажды уже протух: новые CF-пулы 8.x
    (8.6.112/8.34.70/…— 8 из 14 эталонных пулов warpscout) пришлось
    ДОБАВЛЯТЬ РУКАМИ после жалобы «таблица подсетей не видит половину
    пулов». Cloudflare расширяет диапазоны молча —hands-off обновление
    сюда и придумано: пулы берутся из того же места, откуда брались
    в ручном порте, — из pools.go апстрима warpscout.

ИСТОЧНИК (single upstream, зеркала доставки):
    vernette/warpscout, ветка master, файл pools.go:
        var poolsV4 = []netip.Prefix{
            netip.MustParsePrefix("8.6.112.0/24"),
            ...
        }
    Парсится ТОЛЬКО блок poolsV4 (блоки masquePoolsV4/poolsV6 — другие
    режимы/семейства, их брать нельзя). Файл «сырой» Go-код — layout
    стабилен с момента порта; при переименовании блока парсер честно
    откажется, кэш останется прежним (философия layout-probe из
    upstream_updates.py: лучше отложить обновление, чем поставить мусор).

СЛИЯНИЕ СО СТАТИКОЙ (никакой регрессии офлайна):
    STATIC_SCAN_RANGES — полный офлайн-базис (8.x + классические CF
    диапазоны из документации Cloudflare One), вынесен сюда ЕДИНСТВЕННЫМ
    источником правды: warp.WARP_SCAN_RANGES теперь алиас этого кортежа.
    Эффективный набор = пулы апстрима (в их порядке) + статические,
    которых нет у апстрима. Нет синхронизации — работают статические;
    есть — во главе стоят живые пулы warpscout.

МЕХАНИКА (идиомы warp_curated_lists.py):
    • кэш /var/lib/xray-installer/warp_scan_pools_cache.json —
      fcntl.flock + атомарная перезапись; сбой сети НЕ затирает старые
      пулы (ok=False — только пометка «последняя попытка неудачна»);
    • cron /etc/cron.d/warp-scan-pools-sync (04:23 daily) — ставится,
      когда auto включён; ensure_pools_ready() самовосстанавливает
      cron-файл к следующему скану, если его снесли;
    • auto по умолчанию ВКЛЮЧЁН: пулы скана не влияют на маршрутизацию
      (только на охват интерактивного скана), а протухание уже болело;
      выключается в меню (пункт WARP → 9);
    • ensure_pools_ready() — лёгкая точка входа перед интерактивными
      сканами: восстановить cron, при пустом/протухшем (>24 ч) кэше —
      одна быстрая попытка синхронизации (2-3 зеркала × 10 с).

НЕ-ЦЕЛИ (осознанно вне модуля):
    • WARP_SCAN_PORTS — порт WARP фиксирован документацией CF, меняется
      реже пулов и не «ломает» скан;
    • poolsV6 — TCP-зонд Химеры работает по IPv4;
    • wgcf — не постоянный компонент: установщик качает его в /tmp
      каждый раз заново, с resolve latest + pinned fallback (warp.py,
      _get_latest_wgcf_url);
    • TELEGRAM_DCS — константы протокола Telegram, меняются раз в
      десятилетие.

Точки входа:
    from chimera.modules.warp_scan_pools import (
        get_scan_ranges,      # -> tuple[str, ...]  (скан в warp.py)
        ensure_pools_ready,   # -> None             (перед сканом, TUI)
        do_manage_scan_pools, # -> подменю          (меню WARP → 9)
    )
    # cron:  python3 warp_scan_pools.py --sync-pools
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import fcntl
import ipaddress
import json
import re
import sys
import time
import urllib.error as _urlerr
import urllib.request as _urlreq
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

# См. warp.py/warp_curated_lists.py — тот же приём: при запуске файла
# напрямую из cron sys.path[0] указывает на modules/, а не на корень.
if __name__ == "__main__":
    _project_root = Path(__file__).resolve().parent.parent.parent
    if str(_project_root) not in sys.path:
        sys.path.insert(0, str(_project_root))

from chimera.modules.box_renderer import (
    _box_top, _box_row, _box_sep, _box_bottom,
    RED, GREEN, BLUE, CYAN, YELLOW, DIM, NC,
)


# =============================================================================
#  ЛЕНИВАЯ ПРИВЯЗКА К ЯДРУ — только для log_to_file(), как в warp.py
# =============================================================================
def _core_module():
    import importlib
    return importlib.import_module("chimera._core")


def info(msg: str) -> None:
    print(f"{CYAN}[INFO]{NC}  {msg}")
    try:
        _core_module().log_to_file("INFO", msg)
    except Exception:
        pass


def success(msg: str) -> None:
    print(f"{GREEN}[OK]{NC}    {msg}")
    try:
        _core_module().log_to_file("SUCCESS", msg)
    except Exception:
        pass


def warn(msg: str) -> None:
    print(f"{YELLOW}[WARN]{NC}  {msg}")
    try:
        _core_module().log_to_file("WARN", msg)
    except Exception:
        pass


# =============================================================================
#  КОНСТАНТЫ
# =============================================================================
CACHE_FILE = Path("/var/lib/xray-installer/warp_scan_pools_cache.json")
CRON_FILE  = Path("/etc/cron.d/warp-scan-pools-sync")
MODULE_PATH = Path(__file__).resolve()
# Своя минута (curated-списки — 04:17, upstream-агент — 04:40 randomized):
# не бить в одну минуту с чужими задачами.
CRON_SYNC_SCHEDULE = "23 4 * * *"
FETCH_TIMEOUT = 10   # сек на каждое зеркало
STALE_AFTER_H = 24   # старше — имеет смысл обновиться перед сканом

# Зеркала одного файла: raw GitHub → jsDelivr (кэш CDNs, живёт часами).
POOLS_URLS: tuple[str, ...] = (
    "https://raw.githubusercontent.com/vernette/warpscout/master/pools.go",
    "https://cdn.jsdelivr.net/gh/vernette/warpscout@master/pools.go",
    "https://fastly.jsdelivr.net/gh/vernette/warpscout@master/pools.go",
)
POOLS_SOURCE_LABEL = "vernette/warpscout@master pools.go"

# Пулы скана не влияют на маршрутизацию — только на охват скана; протухание
# уже болело (8.x добавляли руками). Поэтому auto по умолчанию ВКЛЮЧЁН —
# в отличие от курируемых списков доменов, которые меняют SELECTIVE.
DEFAULT_AUTO = True

# Санитарные границы разбора: Go-источник стабилен, но при смене layout
# лучше отказаться, чем принять мусор (минимум пулов, максимум, ширина).
MIN_POOLS = 4
MAX_POOLS = 64
MIN_PREFIXLEN = 20   # шире /20 апстрим сам не сканирует (targetMinBitsV4)
MAX_PREFIXLEN = 24   # уже /24 в pools.go не встречается и скану не нужно

# ── Офлайн-базис: то, что сегодня в warp.WARP_SCAN_RANGES (алиас) ──────────
# Порядок осмысленный: новые CF-пулы 8.x (дефолтный набор vernette/warpscout,
# MIT) — из RU/EU часто лучше классики; далее классические диапазоны из
# документации Cloudflare One, которых у warpscout нет.
STATIC_SCAN_RANGES: tuple[str, ...] = (
    "8.6.112.0/24", "8.34.70.0/24", "8.34.146.0/24", "8.35.211.0/24",
    "8.39.125.0/24", "8.39.204.0/24", "8.39.214.0/24", "8.47.69.0/24",
    "162.159.192.0/24", "162.159.193.0/24", "162.159.195.0/24", "162.159.197.0/24",
    "162.159.204.0/24", "162.159.239.0/24",
    "188.114.96.0/24", "188.114.97.0/24", "188.114.98.0/24", "188.114.99.0/24",
    "188.114.100.0/24", "188.114.101.0/24", "188.114.102.0/24", "188.114.103.0/24",
    "188.114.104.0/24", "188.114.105.0/24", "188.114.106.0/24", "188.114.107.0/24",
    "172.65.4.0/24", "172.65.32.0/24",
    "104.16.10.0/24", "104.17.10.0/24",
)

# Блок poolsV4 в pools.go. Ленивое (.*?) до ПЕРВОЙ '}' — внутри блока нет
# вложенных фигурных скобок, поэтому стоп — корректный конец блока.
_POOLS_V4_RE = re.compile(
    r"var\s+poolsV4\s*=\s*\[\]netip\.Prefix\s*\{(.*?)\}", re.S)
_CIDR_RE = re.compile(r'MustParsePrefix\("([^"]+)"\)')


# =============================================================================
#  ЗАГРУЗКА И РАЗБОР pools.go
# =============================================================================
def _parse_pools_go(text: str) -> list[str]:
    """pools.go → список /24-CIDR (только IPv4). ValueError — раскладка
    апстрима изменилась / пул подозрителен: вызывающий обязан сохранить
    прежний кэш, а не принимать мусор."""
    m = _POOLS_V4_RE.search(text)
    if not m:
        raise ValueError("блок var poolsV4 в pools.go не найден (layout изменён?)")
    out: list[str] = []
    for cidr in _CIDR_RE.findall(m.group(1)):
        try:
            net = ipaddress.ip_network(cidr, strict=True)
        except ValueError:
            warn(f"Пул {cidr!r} не парсится как CIDR — пропускаю.")
            continue
        if net.version != 4:
            continue  # poolsV4 по смыслу v4 — но застрахуемся
        if not (MIN_PREFIXLEN <= net.prefixlen <= MAX_PREFIXLEN):
            warn(f"Пул {cidr} вне допустимой ширины /{MIN_PREFIXLEN}–/{MAX_PREFIXLEN} — пропускаю.")
            continue
        if cidr not in out:
            out.append(cidr)
    if not (MIN_POOLS <= len(out) <= MAX_POOLS):
        raise ValueError(
            f"подозрительное число пулов после разбора: {len(out)} "
            f"(ожидались {MIN_POOLS}–{MAX_POOLS}) — обновление отменено")
    return out


def _fetch_pools_go() -> Optional[tuple[str, str]]:
    """Зеркала по очереди → (текст pools.go, метка источника).
    None = все зеркала недоступны — кэш не трогаем."""
    for url in POOLS_URLS:
        try:
            req = _urlreq.Request(url, headers={"User-Agent": "vless-installer-warp-pools/1.0"})
            with _urlreq.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except (_urlerr.URLError, TimeoutError, ValueError, OSError) as e:
            warn(f"Зеркало {url} недоступно: {type(e).__name__}: {e}")
            continue
        if "poolsV4" not in body:
            warn(f"{url} вернул файл без poolsV4 — пробую следующее зеркало.")
            continue
        return body, url
    return None


# =============================================================================
#  КЭШ (собственный файл, НЕ state.json ядра — как у курируемых списков)
# =============================================================================
def _cache_load() -> dict:
    if not CACHE_FILE.exists():
        return {"pools": [], "auto": DEFAULT_AUTO}
    try:
        data = json.loads(CACHE_FILE.read_text())
    except Exception:
        return {"pools": [], "auto": DEFAULT_AUTO}
    data.setdefault("pools", [])
    data.setdefault("auto", DEFAULT_AUTO)
    return data


def _cache_update(mutator: Callable[[dict], dict]) -> dict:
    """Атомарно под fcntl.flock (ночная синхронизация из cron vs меню):
    файл открывается один раз, блокируется, перечитывается перед записью."""
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not CACHE_FILE.exists():
        CACHE_FILE.write_text(json.dumps({"pools": [], "auto": DEFAULT_AUTO}))
        CACHE_FILE.chmod(0o600)
    with CACHE_FILE.open("r+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            f.seek(0)
            content = f.read()
            try:
                cache = json.loads(content) if content else {}
            except json.JSONDecodeError:
                cache = {}
            cache.setdefault("pools", [])
            cache.setdefault("auto", DEFAULT_AUTO)
            cache = mutator(cache)
            f.seek(0)
            f.truncate()
            f.write(json.dumps(cache, indent=2, ensure_ascii=False))
            return cache
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def _age_hours(ts: Optional[str]) -> Optional[float]:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - dt).total_seconds() / 3600.0


# =============================================================================
#  СИНХРОНИЗАЦИЯ
# =============================================================================
def sync_scan_pools() -> dict:
    """Качает pools.go, парсит, обновляет кэш. Возвращает итог:
    {ok, pools, added, removed, source, fetched_at}. Сбой сети/разбора —
    прежние пулы остаются нетронутыми (ok=False)."""
    fetched = _fetch_pools_go()
    if fetched is None:
        warn("pools.go недоступен ни через одно зеркало — пулы не тронуты.")
        result = _cache_update(lambda c: dict(c, ok=False, last_error="network"))
        return {"ok": False, "pools": result.get("pools", []),
                "added": [], "removed": [], "source": None,
                "fetched_at": result.get("fetched_at")}
    body, url = fetched
    try:
        pools = _parse_pools_go(body)
    except ValueError as e:
        warn(f"Разбор pools.go провалился: {e} — пулы не тронуты.")
        result = _cache_update(lambda c: dict(c, ok=False, last_error=f"parse: {e}"))
        return {"ok": False, "pools": result.get("pools", []),
                "added": [], "removed": [], "source": None,
                "fetched_at": result.get("fetched_at")}

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    old = list(_cache_load().get("pools") or [])
    added = [p for p in pools if p not in old]
    removed = [p for p in old if p not in pools]

    def _mutator(cache: dict) -> dict:
        cache.update({
            "pools": pools, "fetched_at": now, "ok": True,
            "source": url, "last_error": None,
        })
        return cache

    cache = _cache_update(_mutator)
    return {
        "ok": True, "pools": cache.get("pools", []),
        "added": added, "removed": removed,
        "source": url, "fetched_at": cache.get("fetched_at"),
    }


# =============================================================================
#  ЭФФЕКТИВНЫЙ НАБОР ДИАПАЗОНОВ (единственная функция для warp.py)
# =============================================================================
def get_scan_ranges() -> tuple[str, ...]:
    """Пулы апстрима (их порядок) + статические, которых нет у апстрима.
    НИКОГО сетевого ввода-вывода: только чтение кэша. Нет кэша — работают
    статические (офлайн-режим без регрессии)."""
    pools = _cache_load().get("pools") or []
    seen = set(pools)
    merged = list(pools) + [c for c in STATIC_SCAN_RANGES if c not in seen]
    return tuple(merged)


def scan_pools_auto() -> bool:
    """Флаг auto для чипа в меню WARP (без сети, без cron-IO)."""
    return bool(_cache_load().get("auto", DEFAULT_AUTO))


# =============================================================================
#  CRON
# =============================================================================
def _manage_cron(enable: bool) -> None:
    CRON_FILE.unlink(missing_ok=True)
    if enable:
        content = (f"{CRON_SYNC_SCHEDULE} root {sys.executable} "
                   f"{MODULE_PATH} --sync-pools >/dev/null 2>&1\n")
        CRON_FILE.write_text(content)
        CRON_FILE.chmod(0o644)


def cron_installed() -> bool:
    return CRON_FILE.exists()


# =============================================================================
#  ТОЧКА ВХОДА ПЕРЕД СКАНОМ (интерактивные сканы Endpoint Manager'а)
# =============================================================================
def ensure_pools_ready() -> None:
    """Вызывается перед интерактивным сканом: восстановить cron (auto),
    и если кэш пуст или протух (>STALE_AFTER_H) — одна попытка синка.
    Все сбои — тихие (warn в лог), скан от этого не отменяется."""
    cache = _cache_load()
    if not cache.get("auto", DEFAULT_AUTO):
        return
    if not cron_installed():
        _manage_cron(True)
    pools = cache.get("pools") or []
    age = _age_hours(cache.get("fetched_at"))
    if pools and age is not None and age < STALE_AFTER_H:
        return
    if not pools:
        info("Пулы скана ещё не синхронизировались с warpscout — пробую сейчас...")
    res = sync_scan_pools()
    if not res["ok"]:
        return  # warn уже прозвучал; скан пойдёт по статике/старым пулам
    if res["added"] or res["removed"]:
        info(f"Пулы скана обновлены ({POOLS_SOURCE_LABEL}): "
             f"+{len(res['added'])} новых, −{len(res['removed'])} убрано, "
             f"всего {len(res['pools'])} /24.")
    else:
        info(f"Пулы скана совпадают с warpscout ({len(res['pools'])} /24).")


# =============================================================================
#  МЕНЮ (меню WARP → 9)
# =============================================================================
def _fmt_ts(ts: Optional[str]) -> str:
    if not ts:
        return f"{YELLOW}ещё не синхронизированы{NC}"
    return ts.replace("T", " ").split("+")[0] + " UTC"


def do_manage_scan_pools() -> None:
    while True:
        cache = _cache_load()
        auto = bool(cache.get("auto", DEFAULT_AUTO))
        pools: list[str] = cache.get("pools") or []
        effective = get_scan_ranges()
        static_extra = len(effective) - len(pools)
        fetched_at = _fmt_ts(cache.get("fetched_at"))
        fail_note = f"  {YELLOW}(посл. попытка неудачна{': ' + str(cache.get('last_error')) if cache.get('last_error') else ''}){NC}" \
            if cache.get("ok") is False else ""
        auto_str = f"{GREEN}вкл{NC}" if auto else f"{RED}выкл{NC}"
        cron_str = f"{GREEN}стоит{NC}" if cron_installed() else f"{YELLOW}нет{NC}"

        print()
        _box_top("ПУЛЫ СКАНИРОВАНИЯ WARP — автообновление из warpscout")
        _box_row()
        _box_row(f"  Источник:  {POOLS_SOURCE_LABEL} (MIT)")
        _box_row(f"  Пулов:     {len(pools)} от warpscout + {static_extra} статических CF"
                 f"  →  скан {len(effective)} /24")
        _box_row(f"  Синхронизированы: {fetched_at}{fail_note}")
        _box_row()
        _box_row(f"  Автообновление (04:23 daily): {auto_str}  ·  cron: {cron_str}")
        _box_row(f"  {DIM}Пулы не влияют на маршрутизацию — только на охват скана.{NC}")
        _box_row()
        _box_sep()
        _box_row(f"  {GREEN}s{NC}  Синхронизировать сейчас")
        _box_row(f"  {GREEN}a{NC}  Автообновление: {'выключить' if auto else 'включить'}")
        _box_row(f"  {GREEN}r{NC}  Сбросить к статическим (удалить пулы warpscout из кэша)")
        _box_row(f"  {RED}0{NC}  ← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор:{NC} ").strip().lower()
        except KeyboardInterrupt:
            print()
            break

        if ch in ("0", "", "q"):
            break

        elif ch == "s":
            info(f"Синхронизация пулов с {POOLS_SOURCE_LABEL}...")
            res = sync_scan_pools()
            if res["ok"]:
                if res["added"]:
                    success(f"Новые пулы warpscout: {', '.join(res['added'])}")
                if res["removed"]:
                    success(f"Убраны (нет у warpscout): {', '.join(res['removed'])}")
                if not res["added"] and not res["removed"]:
                    success(f"Изменений нет — {len(res['pools'])} /24.")
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch == "a":
            def _mutator(c: dict, _v=not auto) -> dict:
                c["auto"] = _v
                return c
            _cache_update(_mutator)
            _manage_cron(not auto)
            success(f"Автообновление пулов {'включено' if not auto else 'выключено'}"
                    f"{'' if not auto else ' (cron снят)'}.")
            time.sleep(1)

        elif ch == "r":
            def _mutator(c: dict) -> dict:
                c["pools"] = []
                c["fetched_at"] = None
                c["ok"] = None
                c["source"] = None
                return c
            _cache_update(_mutator)
            success("Кэш пулов очищен — скан работает по статическим диапазонам.")
            time.sleep(1)

        else:
            warn("Неверный выбор.")
            time.sleep(1)


# =============================================================================
#  ТОЧКА ВХОДА ДЛЯ CRON (--sync-pools)
# =============================================================================
if __name__ == "__main__":
    if "--sync-pools" in sys.argv:
        sync_scan_pools()

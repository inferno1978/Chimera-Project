"""
vless_installer/modules/warp_curated_lists.py
───────────────────────────────────────────────────────────────────────────────
Курируемые auto-update списки доменов для WARP SELECTIVE-режима
(источник — itdoginfo/allow-domains, тот же проект, что генерирует списки для
OpenWrt/dnsmasq и который многие используют для роутинга через zapret/VLESS).

Три готовых списка на выбор пользователя (переключаются независимо):
    ru        — Russia/outside-raw.lst
                Российские ресурсы. Практический смысл именно для WARP (в
                отличие от обычного использования этого списка для БЛОКИРОВКИ):
                завернуть их через Cloudflare, чтобы обращения к российским
                сервисам с сервера шли как бы "изнутри" сети Cloudflare, а не
                напрямую с IP VPS — это осложняет обнаружение сервера зондами
                РКН, которые ищут не-CDN IP, обращающиеся к рос. ресурсам.
    geoblock  — Categories/geoblock.lst
                Зарубежные сервисы, заблокированные на территории РФ.
    google_ai — Services/google_ai.lst
                Gemini/Google AI Studio и т.п. Апстрим держит их отдельно от
                geoblock, т.к. часть зарубежных серверов Google размечена как
                российская и наоборот — общего решения через geoblock нет.

Как это стыкуется с warp.py (единственная точка сопряжения):
    from vless_installer.modules.warp_curated_lists import (
        get_enabled_curated_domains,   # -> list[str]
        do_manage_curated_lists,       # -> подменю (вызывается из do_manage_warp)
    )
    ...
    all_domains = sorted(set(WARP_CUSTOM_DOMAINS) | set(get_enabled_curated_domains()))

Модуль ничего не пишет ни в state.json, ни в глобали _core.py/warp.py —
у него собственный кэш-файл и собственный список "включённых" списков.
warp.py, в свою очередь, ничего не знает о его внутреннем устройстве,
только вызывает эти две функции.

Автообновление — раз в сутки через СОБСТВЕННЫЙ cron
(/etc/cron.d/warp-curated-lists-sync), отдельно от 5-минутного cron
ререзолва IP в warp.py (тот резолвит уже готовые домены в IP, этот —
обновляет сам список доменов из апстрима). Cron ставится/снимается
автоматически при включении/выключении списков — если ни один список не
включён, ежедневная закачка не нужна и cron-файла не будет.

Устойчивость к сбоям сети: если скачивание конкретного списка не удалось,
предыдущий закэшированный результат для этого списка НЕ обнуляется — просто
остаётся тем же до следующей удачной синхронизации (см. sync_curated_lists).

Точка входа для cron:
    python3 warp_curated_lists.py --sync-lists
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import fcntl
import json
import re
import sys
import time
import urllib.error as _urlerr
import urllib.request as _urlreq
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

# См. warp.py — тот же приём и по той же причине: при запуске файла
# напрямую из cron (`python3 .../warp_curated_lists.py --sync-lists`)
# sys.path[0] указывает на каталог modules/, а не на корень проекта.
if __name__ == "__main__":
    _project_root = Path(__file__).resolve().parent.parent.parent
    if str(_project_root) not in sys.path:
        sys.path.insert(0, str(_project_root))

from vless_installer.modules.box_renderer import (
    _box_top, _box_row, _box_sep, _box_bottom,
    RED, GREEN, BLUE, CYAN, YELLOW, NC,
)


# =============================================================================
#  ЛЕНИВАЯ ПРИВЯЗКА К ЯДРУ — только для log_to_file(), как в warp.py
# =============================================================================
def _core_module():
    import importlib
    return importlib.import_module("vless_installer._core")


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
CACHE_FILE = Path("/var/lib/xray-installer/warp_curated_cache.json")
CRON_FILE  = Path("/etc/cron.d/warp-curated-lists-sync")
MODULE_PATH = Path(__file__).resolve()
# Смещено от полуночи/пятиминуток warp.py произвольно, чтобы не бить в одну
# и ту же минуту с другими cron-задачами инсталлятора.
CRON_SYNC_SCHEDULE = "17 4 * * *"
FETCH_TIMEOUT = 10  # секунд на каждый из трёх списков

CURATED_SOURCES: dict[str, dict[str, str]] = {
    "ru": {
        "url": "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/outside-raw.lst",
        "label": "RU-сервисы (outside-raw)",
        "hint": "Прячет IP VPS от зондов РКН — рос. сервисы идут как бы из сети Cloudflare",
    },
    "geoblock": {
        "url": "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Categories/geoblock.lst",
        "label": "GeoBlock",
        "hint": "Зарубежные сервисы, заблокированные на территории РФ",
    },
    "google_ai": {
        "url": "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Services/google_ai.lst",
        "label": "Google AI",
        "hint": "Gemini, Google AI Studio и другие сервисы Google AI",
    },
}
# Ничего не включено, пока пользователь сам не выберет в меню — модуль не
# должен молча менять поведение уже настроенного SELECTIVE-режима.
DEFAULT_ENABLED: tuple[str, ...] = ()

_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))+$")


# =============================================================================
#  ЗАГРУЗКА И РАЗБОР ИСХОДНЫХ СПИСКОВ
# =============================================================================
def _parse_list_body(text: str) -> list[str]:
    """Построчный формат itdoginfo/allow-domains: один домен на строку,
    комментарии — строки, начинающиеся с '#'. На всякий случай также режем
    завёрнутые с хвостовым пробелом/CR и убираем ведущий '*.' у wildcard-строк
    (для WARP нужен именно резолвимый домен, а не шаблон роутинга Xray)."""
    out: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip().lower()
        if not line or line.startswith("#"):
            continue
        line = line.split()[0]
        line = line.lstrip("*.")
        if _DOMAIN_RE.match(line):
            out.add(line)
    return sorted(out)


def _fetch_list(url: str) -> Optional[list[str]]:
    """None означает сетевую/HTTP ошибку — вызывающий код обязан в этом
    случае сохранить прежний кэш нетронутым, а не затирать его пустым
    списком."""
    try:
        req = _urlreq.Request(url, headers={"User-Agent": "vless-installer-warp-curated/1.0"})
        with _urlreq.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except (_urlerr.URLError, TimeoutError, ValueError, OSError) as e:
        warn(f"Не удалось скачать {url}: {type(e).__name__}: {e}")
        return None
    domains = _parse_list_body(body)
    if not domains:
        warn(f"Список по адресу {url} скачан, но пуст после разбора — не обновляем кэш этим списком.")
        return None
    return domains


# =============================================================================
#  КЭШ (собственный файл, НЕ state.json ядра — см. шапку файла)
# =============================================================================
def _cache_load() -> dict:
    if not CACHE_FILE.exists():
        return {"lists": {}, "enabled": list(DEFAULT_ENABLED)}
    try:
        data = json.loads(CACHE_FILE.read_text())
    except Exception:
        return {"lists": {}, "enabled": list(DEFAULT_ENABLED)}
    data.setdefault("lists", {})
    data.setdefault("enabled", list(DEFAULT_ENABLED))
    return data


def _cache_update(mutator: Callable[[dict], dict]) -> dict:
    """Атомарно обновляет кэш под fcntl.flock — по тому же рецепту, что и
    _warp_state_save_autonomously()/_standalone_sync() в warp.py: файл
    открывается один раз, блокируется, перечитывается непосредственно перед
    записью. Это нужно, потому что кэш может одновременно трогать ночной
    cron (--sync-lists) и ручное переключение списков из открытого меню."""
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not CACHE_FILE.exists():
        CACHE_FILE.write_text(json.dumps({"lists": {}, "enabled": list(DEFAULT_ENABLED)}))
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
            cache.setdefault("lists", {})
            cache.setdefault("enabled", list(DEFAULT_ENABLED))
            cache = mutator(cache)
            f.seek(0)
            f.truncate()
            f.write(json.dumps(cache, indent=2, ensure_ascii=False))
            return cache
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def sync_curated_lists() -> dict:
    """Скачивает все три источника и обновляет кэш. Список, который не
    удалось скачать в этот раз, остаётся со старым содержимым (ok=False —
    только пометка "последняя попытка неудачна", домены не трогаются)."""
    fetched: dict[str, Optional[list[str]]] = {}
    for key, meta in CURATED_SOURCES.items():
        fetched[key] = _fetch_list(meta["url"])

    def _mutator(cache: dict) -> dict:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        for key, domains in fetched.items():
            if domains is not None:
                cache["lists"][key] = {
                    "domains": domains,
                    "count": len(domains),
                    "fetched_at": now,
                    "ok": True,
                }
            else:
                existing = cache["lists"].get(key, {"domains": [], "count": 0, "fetched_at": None})
                existing["ok"] = False
                cache["lists"][key] = existing
        return cache

    cache = _cache_update(_mutator)
    ok_count = sum(1 for d in fetched.values() if d is not None)
    success(f"Синхронизация курируемых списков: {ok_count}/{len(CURATED_SOURCES)} обновлено успешно.")
    return cache


def get_enabled_curated_domains() -> list[str]:
    """Единственная функция, которую использует warp.py. Ничего не скачивает
    и не блокируется на сеть — только читает уже сохранённый кэш. Если кэша
    ещё нет (ни разу не синхронизировались) — возвращает пустой список,
    SELECTIVE-режим при этом продолжает работать как и раньше, просто без
    курируемых доменов до первой синхронизации."""
    cache = _cache_load()
    enabled = cache.get("enabled", [])
    out: set[str] = set()
    for key in enabled:
        entry = cache.get("lists", {}).get(key)
        if entry:
            out.update(entry.get("domains", []))
    return sorted(out)


# =============================================================================
#  CRON: ежедневная закачка (--sync-lists)
# =============================================================================
def _manage_cron(enable: bool) -> None:
    CRON_FILE.unlink(missing_ok=True)
    if enable:
        content = f"{CRON_SYNC_SCHEDULE} root {sys.executable} {MODULE_PATH} --sync-lists >/dev/null 2>&1\n"
        CRON_FILE.write_text(content)
        CRON_FILE.chmod(0o644)


# =============================================================================
#  МЕНЮ (вызывается из do_manage_warp() в warp.py)
# =============================================================================
def _fmt_ts(ts: Optional[str]) -> str:
    if not ts:
        return f"{YELLOW}ещё не загружен{NC}"
    return ts.replace("T", " ").split("+")[0] + " UTC"


def do_manage_curated_lists() -> None:
    while True:
        cache = _cache_load()
        enabled = set(cache.get("enabled", []))

        print()
        _box_top("Курируемые списки доменов (itdoginfo/allow-domains)")
        _box_row()
        _box_row(f"{BLUE}Подмешиваются к вашим доменам в режиме SELECTIVE.{NC}")
        _box_row("Автообновление раз в сутки, как только включён хотя бы один список.")
        _box_row()
        _box_sep()

        idx_map: dict[str, str] = {}
        for i, (key, meta) in enumerate(CURATED_SOURCES.items(), start=1):
            entry = cache.get("lists", {}).get(key, {})
            mark = f"{GREEN}[x]{NC}" if key in enabled else f"{RED}[ ]{NC}"
            count = entry.get("count", 0)
            ts = _fmt_ts(entry.get("fetched_at"))
            fail_note = f"  {YELLOW}(посл. попытка неудачна){NC}" if entry.get("ok") is False else ""
            _box_row(f"  {i}  {mark}  {meta['label']} — {count} доменов, обновлён: {ts}{fail_note}")
            _box_row(f"      {meta['hint']}")
            idx_map[str(i)] = key

        _box_row()
        _box_row(f"  {GREEN}s{NC}  Синхронизировать все списки сейчас")
        _box_row(f"  {RED}0{NC}  ← Назад")
        _box_bottom()

        try:
            ch = input(f"{CYAN}Выбор (номер — вкл/выкл):{NC} ").strip().lower()
        except KeyboardInterrupt:
            print()
            break

        if ch in ("0", "", "q"):
            break

        elif ch == "s":
            info("Синхронизация курируемых списков...")
            sync_curated_lists()
            input(f"{BLUE}Нажмите Enter...{NC}")

        elif ch in idx_map:
            key = idx_map[ch]
            if key in enabled:
                enabled.discard(key)
            else:
                enabled.add(key)
                if key not in cache.get("lists", {}):
                    info(f"Первая загрузка списка «{CURATED_SOURCES[key]['label']}»...")
                    domains = _fetch_list(CURATED_SOURCES[key]["url"])
                    if domains:
                        def _mutator(c: dict, _key=key, _domains=domains) -> dict:
                            c["lists"][_key] = {
                                "domains": _domains,
                                "count": len(_domains),
                                "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                "ok": True,
                            }
                            return c
                        _cache_update(_mutator)
                    else:
                        warn("Не удалось скачать сейчас — список включён, но будет пуст до следующей синхронизации ('s').")

            def _mutator_enabled(c: dict, _enabled=enabled) -> dict:
                c["enabled"] = sorted(_enabled)
                return c
            _cache_update(_mutator_enabled)
            _manage_cron(bool(enabled))

        else:
            warn("Неверный выбор.")
            time.sleep(1)


# =============================================================================
#  ТОЧКА ВХОДА ДЛЯ CRON (--sync-lists)
# =============================================================================
if __name__ == "__main__":
    if "--sync-lists" in sys.argv:
        sync_curated_lists()

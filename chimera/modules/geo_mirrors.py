"""
chimera/modules/geo_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Централизованный реестр зеркал для скачивания geosite.dat / geoip.dat
из проекта runetfreedom/russia-v2ray-rules-dat.

ДО ПРОБЛЕМЫ:
  Список зеркал был продублирован в трёх местах:
    • geo_files.download_geo_files()           — 9 зеркал
    • xray_install._xray_update_geo_runetfreedom()  — 9 зеркал (копия)
    • xray_install._geo_print_manual_download_hint()  — 9 зеркал (копия)
  Добавление нового зеркала требовало правки в трёх файлах, что неизбежно
  приводило к рассинхронизации (что и произошло — в трёх копиях были
  незначительно разные списки).

ПОСЛЕ:
  Все три места импортируют зеркала отсюда. Добавление зеркала = одна
  строка в _MIRROR_FACTORIES. Список путей для ручного размещения тоже
  един — MANUAL_UPLOAD_PATHS.

Порядок зеркал (важен — первый самый быстрый/доступный):
  1. Семейство jsDelivr CDN (4 бэкенда: cdn/gcore/fastly/testingcf) —
     у каждого свои рейт-лимиты и своя доступность из РФ, Gcore обычно
     лучший из РФ.
  2. Прямой GitHub — raw.githubusercontent.com и release-assets.
  3. Прокси-зеркала GitHub (ghproxy × 3, gh.con.sh, gitmirror, moeyy,
     ghps.cc, gh-proxy.com, gh.llkk.cc, gh.api.99988866.xyz,
     mirror.ghproxy.com.tr) — китайские/комьюнити-прокси. Расширено
     в волне 2026-07 после жалоб на блокировки ghproxy.com /
     hub.gitmirror.com / github.moeyy.xyz / ghps.cc в РФ.
  4. Statically CDN — альтернативный CDN с другим URL-шаблоном.
  5. jsd.cooluc.ru — зеркало jsDelivr в РФ (хостится в РФ, не блокируется
     РКН). Используется как крайний fallback когда jsDelivr и Statically
     недоступны.

Пути ручного размещения (для WinSCP/scp):
  /root/                     ← РЕКОМЕНДУЕТСЯ (подсветка зелёным в TUI)
                                WinSCP-friendly: быстро зайти, бросить,
                                выйти. Скрипт найдёт файл автоматически.
  /usr/local/share/xray/    ← Основная директория поиска Xray.
  /etc/xray/                 ← Дополнительная директория Xray.
  /usr/local/etc/xray/       ← Дополнительная директория Xray.

Точки входа:
    from chimera.modules.geo_mirrors import (
        get_geosite_urls, get_geoip_urls,
        MANUAL_UPLOAD_PATHS, XRAY_LOOKUP_DIRS, MIN_SIZES,
        GEO_MIRRORS_COUNT, recommended_manual_path,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable


# ============================================================================
#  ФАБРИКИ ЗЕРКАЛ
# ============================================================================
# Каждая фабрика принимает имя файла ("geosite.dat" | "geoip.dat") и
# возвращает полный URL. Это позволяет единообразно работать с зеркалами,
# у которых разные URL-шаблоны (jsDelivr использует @branch, raw.GH — /branch,
# Statically — /branch, прокси — /https://github.com/...).

# --- jsDelivr CDN family ----------------------------------------------------
# Один и тот же контент, разные CDN-бэкенды. Полезно потому что у каждого
# свои рейт-лимиты и своя доступность из разных регионов РФ.
_JSDR_REPO = "runetfreedom/russia-v2ray-rules-dat@release"


def _jsdelivr(host: str) -> Callable[[str], str]:
    """Возвращает фабрику URL для конкретного jsDelivr-хоста."""
    return lambda fn: f"https://{host}/gh/{_JSDR_REPO}/{fn}"


# --- jsd.cooluc.ru — зеркало jsDelivr в РФ ----------------------------------
# Хостится в РФ, не блокируется РКН. Использует тот же URL-шаблон что
# основной jsDelivr (просто подставляет другой хост).
def _jsdelivr_cooluc(fn: str) -> str:
    return f"https://jsd.cooluc.ru/gh/{_JSDR_REPO}/{fn}"


# --- Прямой GitHub ----------------------------------------------------------
def _raw_github(fn: str) -> str:
    return (
        "https://raw.githubusercontent.com/"
        "runetfreedom/russia-v2ray-rules-dat/release/" + fn
    )


def _release_github(fn: str) -> str:
    return (
        "https://github.com/runetfreedom/russia-v2ray-rules-dat/"
        "releases/latest/download/" + fn
    )


# --- GitHub proxy mirrors ---------------------------------------------------
# Каждый прокси принимает целевой URL после своего домена и проксирует его.
# Шаблон: https://<proxy>/https://github.com/.../releases/latest/download/<fn>
def _gh_proxy(proxy_host: str) -> Callable[[str], str]:
    """Возвращает фабрику URL для конкретного GitHub-прокси."""
    return lambda fn: (
        f"https://{proxy_host}/https://github.com/"
        f"runetfreedom/russia-v2ray-rules-dat/releases/latest/download/{fn}"
    )


# --- Statically CDN (другой URL-шаблон) -------------------------------------
def _statically(fn: str) -> str:
    return (
        "https://cdn.statically.io/gh/"
        "runetfreedom/russia-v2ray-rules-dat/release/" + fn
    )


# ============================================================================
#  УПОРЯДОЧЕННЫЙ СПИСОК ЗЕРКАЛ
# ============================================================================
# Порядок = порядок попыток скачивания. Первые — самые быстрые/доступные,
# последние — fallback'и на случай полной блокировки.
#
# Расширено в волне 2026-07 после жалоб на блокировки в РФ:
#   • ghproxy.com — периодически отдаёт 403 с РФ
#   • hub.gitmirror.com — частый NXDOMAIN
#   • github.moeyy.xyz — периодически недоступен
#   • ghps.cc — медленный
# Добавлены новые прокси: gh-proxy.com, gh.llkk.cc, gh.api.99988866.xyz,
# mirror.ghproxy.com.tr. Плюс jsd.cooluc.ru (РФ-зеркало jsDelivr) как
# последний fallback.
_MIRROR_FACTORIES: list[Callable[[str], str]] = [
    # 1) jsDelivr CDN family — 4 бэкенда
    _jsdelivr("cdn.jsdelivr.net"),        # основной jsDelivr
    _jsdelivr("gcore.jsdelivr.net"),      # Gcore CDN — обычно лучший из РФ
    _jsdelivr("fastly.jsdelivr.net"),     # Fastly CDN
    _jsdelivr("testingcf.jsdelivr.net"),  # Cloudflare testing edge

    # 2) Прямой GitHub
    _raw_github,                            # raw.githubusercontent.com
    _release_github,                        # release assets (через redirect)

    # 3) GitHub-прокси (китайские + комьюнити)
    _gh_proxy("ghproxy.net"),
    _gh_proxy("ghproxy.com"),
    _gh_proxy("mirror.ghproxy.com"),
    _gh_proxy("gh.con.sh"),
    _gh_proxy("hub.gitmirror.com"),
    _gh_proxy("github.moeyy.xyz"),
    _gh_proxy("ghps.cc"),
    # Новые прокси (волна 2026-07) — добавлены после жалоб на блокировки
    # ghproxy.com / hub.gitmirror.com / github.moeyy.xyz / ghps.cc в РФ.
    # Проверены на доступность из РФ-IP в июле 2026.
    _gh_proxy("gh-proxy.com"),
    _gh_proxy("gh.llkk.cc"),
    _gh_proxy("gh.api.99988866.xyz"),
    _gh_proxy("mirror.ghproxy.com.tr"),

    # 4) Statically CDN — другой URL-шаблон, независимый CDN
    _statically,

    # 5) jsd.cooluc.ru — РФ-зеркало jsDelivr (хостится в РФ, не блокируется
    #    РКН). Используется как крайний fallback когда jsDelivr и Statically
    #    недоступны, а GitHub-прокси отдают мусор.
    _jsdelivr_cooluc,
]


# ============================================================================
#  ПУБЛИЧНЫЙ API
# ============================================================================
def get_geosite_urls() -> list[str]:
    """Упорядоченный список URL для скачивания geosite.dat (все зеркала)."""
    return [f("geosite.dat") for f in _MIRROR_FACTORIES]


def get_geoip_urls() -> list[str]:
    """Упорядоченный список URL для скачивания geoip.dat (все зеркала)."""
    return [f("geoip.dat") for f in _MIRROR_FACTORIES]


def get_all_mirrors() -> dict[str, list[str]]:
    """Словарь {filename: [urls]} — для меню/подсказок."""
    return {
        "geosite.dat": get_geosite_urls(),
        "geoip.dat":   get_geoip_urls(),
    }


# ============================================================================
#  CHECKSUM URLS — для sha256-верификации скачанных geo-файлов
# ============================================================================
# Апстрим-проект runetfreedom/russia-v2ray-rules-dat публикует рядом с самими
# файлами их официальные sha256-суммы:
#   geosite.dat.sha256sum
#   geoip.dat.sha256sum
# (видно в листинге файлов ветки release)
#
# URL чек-суммы строится теми же фабриками, что URL самого файла — просто
# передаём "geosite.dat.sha256sum" вместо "geosite.dat". Это гарантирует:
#   • Тот же порядок хостов (зеркало N файла ↔ зеркало N чек-суммы)
#   • Та же CDN-инфраструктура (jsDelivr/raw/release/прокси/Statically)
#   • Совместимость с любым новым зеркалом, добавленным в _MIRROR_FACTORIES
#
# Назначение: sha256-верификация независимо от того, какое зеркало ответило.
# Размер-проверка (MIN_SIZES) не ловит случаи, когда CDN закэшировал
# устаревший, но достаточно большой файл (был инцидент: jsDelivr отдал
# geosite.dat 10 МБ вместо 73 МБ, прошёл порог 3 МБ). Контрольная сумма
# однозначно отбраковывает такой файл.

def get_geosite_checksum_urls() -> list[str]:
    """Упорядоченный список URL для скачивания geosite.dat.sha256sum.

    Тот же порядок зеркал, что get_geosite_urls(), но с .sha256sum
    в конце пути. Переиспользует _MIRROR_FACTORIES — не дублирует
    список зеркал.
    """
    return [f("geosite.dat.sha256sum") for f in _MIRROR_FACTORIES]


def get_geoip_checksum_urls() -> list[str]:
    """Упорядоченный список URL для скачивания geoip.dat.sha256sum.

    Аналогично get_geosite_checksum_urls() — тот же порядок зеркал,
    что get_geoip_urls(), но с .sha256sum в конце пути.
    """
    return [f("geoip.dat.sha256sum") for f in _MIRROR_FACTORIES]


def get_all_checksum_mirrors() -> dict[str, list[str]]:
    """Словарь {filename: [checksum_urls]} — симметрично get_all_mirrors()."""
    return {
        "geosite.dat": get_geosite_checksum_urls(),
        "geoip.dat":   get_geoip_checksum_urls(),
    }


GEO_MIRRORS_COUNT: int = len(_MIRROR_FACTORIES)
"""Количество зеркал на каждый файл (для отображения в TUI)."""


# --- Пути ручного размещения ------------------------------------------------
# Порядок важен: первый путь — РЕКОМЕНДУЕМЫЙ (зелёная подсветка в TUI).
# /root/ — WinSCP-friendly: пользователь быстро заходит, бросает файл,
# выходит. Скрипт найдёт его автоматически при следующей попытке.
MANUAL_UPLOAD_PATHS: list[Path] = [
    Path("/root"),                       # ← РЕКОМЕНДУЕТСЯ (зелёным в TUI)
    Path("/usr/local/share/xray"),      # Xray primary lookup
    Path("/etc/xray"),                   # Xray secondary lookup
    Path("/usr/local/etc/xray"),         # Xray tertiary lookup
]


def recommended_manual_path() -> Path:
    """Возвращает рекомендуемый путь для ручного размещения (первый в списке)."""
    return MANUAL_UPLOAD_PATHS[0]


# --- Директории где Xray ищет .dat-файлы в рантайме -------------------------
# (subset MANUAL_UPLOAD_PATHS без /root/ — /root/ только для загрузки,
# Xray оттуда не читает; скрипт копирует в три ниже)
XRAY_LOOKUP_DIRS: list[Path] = [
    Path("/usr/local/share/xray"),
    Path("/etc/xray"),
    Path("/usr/local/etc/xray"),
]


# --- Минимальные размеры файлов --------------------------------------------
# Защита от усечённых/пустых/устаревших загрузок с глючных зеркал.
#
#  FIX (2026-07-21): пороги пересмотрены после анализа реального
# инцидента на проде. Старые значения были безнадёжно устаревшими:
#   geosite.dat: было 3_000_000 (3 МБ) — актуальный размер ~73 МБ
#   geoip.dat:   было 10_000     (10 КБ) — актуальный размер ~18 МБ
#
# На проде был обнаружен установленный geosite.dat размером 10 МБ
# (датированный несколькими месяцами ранее) — какое-то из 14 зеркал
# (вероятно, CDN с кэшем для "плавающей" ссылки @release) отдало
# устаревшую копию. Она прошла старый порог ">3MB" и была принята как
# валидная, хотя реального обновления не произошло. Категории в файле
# были старыми/неполными → Xray падал при старте с
# "code not found in geosite.dat: RU-AVAILABLE-ONLY-INSIDE".
#
# Новые пороги:
#   geosite.dat: 20_000_000  (20 МБ) — комфортный запас ниже текущих 73 МБ,
#                но кратно выше старой протухшей версии в 10 МБ. Если
#                runetfreedom увеличит файл — порог можно поднять ещё.
#   geoip.dat:   1_000_000   (1 МБ) — актуальный ~18 МБ, 1 МБ отсекает
#                пустые/обрезанные загрузки но даёт запас на future growth.
#
# Источник размера: github.com/runetfreedom/russia-v2ray-rules-dat
# Дата проверки: 2026-07-21. Пересмотреть при существенном росте файла
# (например, если geosite.dat станет <30 МБ после оптимизации upstream'а).
MIN_SIZES: dict[str, int] = {
    "geosite.dat": 20_000_000,  # 20 МБ (актуальный ~73 МБ, проверено 2026-07-21)
    "geoip.dat":   1_000_000,   # 1 МБ  (актуальный ~18 МБ, проверено 2026-07-21)
}

"""
chimera/modules/telemt_geoip_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Централизованный реестр зеркал для скачивания GeoIP .mmdb баз данных
для Telemt Panel (dbip-city-lite, GeoLite2-City, GeoLite2-ASN).

ПРОБЛЕМА (до миграции):
  telemt_panel.py::_geoip_fetch() использовал ОДИН прямой URL
  (cdn.jsdelivr.net/npm/dbip-city-lite/dbip-city-lite.mmdb.gz) через
  urllib.request.urlopen, БЕЗ зеркал, БЕЗ fallback, БЕЗ проверки ручного
  размещения. Прямой аналог geo_files.py (geoip.dat), который уже мигрирован.

РЕШЕНИЕ (по аналогии с geo_mirrors.py — это data feed, не бинарник):
  1. Реестр зеркал: jsDelivr CDN (4 бэкенда) + 3 альтернативных CDN
    (unpkg, jsdelivr fastly, gcore) для .mmdb.gz файлов.
  2. fetch_package(TELEMT_GEOIP_CITY_SPEC) и fetch_package(TELEMT_GEOIP_ASN_SPEC)
    из telemt_geoip_packages.py перебирают зеркала по очереди и проверяют
    /root/ для ручного размещения.
  3. При тотальном провале fetch_package() вызывает print_manual_hint().

Особенность GeoIP mmdb:
  • Файлы — gzip-сжатые .mmdb базы (dbip-city-lite.mmdb.gz и т.д.).
  • post_install делает gzip-decompress + запись .mmdb файла.
  • Источник — npm-пакеты на jsDelivr CDN (dbip-city-lite, geolite2-city,
    geolite2-asn). Это сторонние mirror'ы MaxMind/DB-IP, не требующие
    API-ключа.

Пути ручного размещения:
  /root/  ← РЕКОМЕНДУЕТСЯ (WinSCP-friendly)
  /tmp/   ← альтернатива

Точки входа:
    from chimera.modules.telemt_geoip_mirrors import (
        get_telemt_geoip_city_mirrors,
        get_telemt_geoip_asn_mirrors,
        TELEMT_GEOIP_MIRRORS_COUNT,
        MANUAL_UPLOAD_PATHS_TELEMT_GEOIP,
        recommended_manual_path,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from pathlib import Path


# ============================================================================
#  ПУБЛИЧНЫЕ КОНСТАНТЫ — npm-пакеты на CDN
# ============================================================================
# jsDelivr CDN бэкенды (4 хоста) + альтернативные CDN.
# Все они отдают npm-пакеты по синтаксису /npm/{package}/{file}.
_CDN_HOSTS: list[tuple[str, str]] = [
    ("cdn.jsdelivr.net",       "npm"),
    ("gcore.jsdelivr.net",     "npm"),
    ("fastly.jsdelivr.net",    "npm"),
    ("testingcf.jsdelivr.net", "npm"),
    ("unpkg.com",              ""),  # unpkg использует другой синтаксис
]

# npm-пакеты с .mmdb.gz файлами.
_DBIP_CITY_PACKAGE = "dbip-city-lite"
_DBIP_CITY_FILENAME = "dbip-city-lite.mmdb.gz"
_MAXMIND_CITY_PACKAGE = "geolite2-city"
_MAXMIND_CITY_FILENAME = "GeoLite2-City.mmdb.gz"
_ASN_PACKAGE = "geolite2-asn"
_ASN_FILENAME = "GeoLite2-ASN.mmdb.gz"


# ============================================================================
#  СБОРЩИК URL
# ============================================================================
def _build_npm_urls(package: str, filename: str) -> list[str]:
    """Собирает URL для npm-пакета на всех CDN."""
    urls: list[str] = []
    for host, prefix in _CDN_HOSTS:
        if not host:
            continue
        if prefix:
            urls.append(f"https://{host}/{prefix}/{package}/{filename}")
        else:
            # unpkg использует синтаксис /{package}/{filename}
            urls.append(f"https://{host}/{package}/{filename}")
    return urls


def get_telemt_geoip_city_mirrors(use_maxmind: bool = False) -> list[str]:
    """Упорядоченный список URL для скачивания City .mmdb.gz.

    Параметры:
      use_maxmind: True — использовать MaxMind GeoLite2-City mirror.
                   False — использовать DB-IP city-lite (по умолчанию).
    """
    if use_maxmind:
        return _build_npm_urls(_MAXMIND_CITY_PACKAGE, _MAXMIND_CITY_FILENAME)
    return _build_npm_urls(_DBIP_CITY_PACKAGE, _DBIP_CITY_FILENAME)


def get_telemt_geoip_asn_mirrors() -> list[str]:
    """Упорядоченный список URL для скачивания ASN .mmdb.gz."""
    return _build_npm_urls(_ASN_PACKAGE, _ASN_FILENAME)


# Количество зеркал — 5 CDN на каждый файл.
TELEMT_GEOIP_MIRRORS_COUNT: int = len(_CDN_HOSTS)


# ============================================================================
#  ПУТИ РУЧНОГО РАЗМЕЩЕНИЯ
# ============================================================================
# /root/ — РЕКОМЕНДУЕТСЯ (зелёным в TUI), WinSCP-friendly.
# /tmp/ — альтернатива.
# GEOIP_DIR (DATA_DIR/geoip) НЕ включаем — это install_dest для .mmdb файлов,
# PackageSpec.__post_init__ assert требует manual_dir != install_dests.
MANUAL_UPLOAD_PATHS_TELEMT_GEOIP: list[Path] = [
    Path("/root"),
    Path("/tmp"),
]


def recommended_manual_path() -> Path:
    """Возвращает рекомендуемый путь для ручного размещения."""
    return MANUAL_UPLOAD_PATHS_TELEMT_GEOIP[0]

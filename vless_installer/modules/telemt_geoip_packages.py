"""
vless_installer/modules/telemt_geoip_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpecs для GeoIP .mmdb баз данных Telemt Panel:
  • TELEMT_GEOIP_CITY_SPEC — dbip-city-lite.mmdb.gz (или GeoLite2-City.mmdb.gz)
  • TELEMT_GEOIP_ASN_SPEC — GeoLite2-ASN.mmdb.gz

Используется telemt_panel.py::_geoip_auto_download() для скачивания и
распаковки .mmdb.gz файлов. До миграции telemt_panel.py делал это ad-hoc
через urllib.request.urlopen + gzip.decompress + write_bytes.

Особенности post_install:
  • Скачанный файл — gzip-сжатый .mmdb (dbip-city-lite.mmdb.gz).
  • post_install делает:
      1. gzip-decompress
      2. Sanity check: len(data) >= 1024
      3. Запись .mmdb (без .gz расширения) в install_dests[0]/
      4. chown {SYSTEM_USER}:{SYSTEM_USER} (best-effort)

  • use_maxmind подставляется через filename_kwargs:
    fetch_package(TELEMT_GEOIP_CITY_SPEC, use_maxmind=True)

install_dests = [GEOIP_DIR] — это DATA_DIR/geoip из telemt_panel.py.
manual_incoming_dir = /root/ — не совпадает с install_dests.

Точки входа:
    from vless_installer.modules.telemt_geoip_packages import (
        TELEMT_GEOIP_CITY_SPEC, TELEMT_GEOIP_ASN_SPEC,
    )
"""
from __future__ import annotations

import gzip
import shutil
import subprocess
from pathlib import Path

from vless_installer.modules.download_manager import PackageSpec
from vless_installer.modules.telemt_geoip_mirrors import (
    get_telemt_geoip_city_mirrors, get_telemt_geoip_asn_mirrors,
)


# ============================================================================
#  КОНСТАНТЫ
# ============================================================================

# GEOIP_DIR = DATA_DIR / "geoip" — из telemt_panel.py.
# DATA_DIR = Path("/var/lib/telemt-panel") (типичное значение).
# install_dests = [GEOIP_DIR] — post_install ставит .mmdb файлы сюда.
_TELEMT_GEOIP_INSTALL_DESTS: list[Path] = [Path("/var/lib/telemt-panel/geoip")]

# manual_incoming_dir — /root/ (WinSCP-friendly).
_MANUAL_DIR = Path("/root")

# Имена файлов в install_dests (без .gz расширения).
_DBIP_CITY_DEST_FILENAME = "dbip-city-lite.mmdb"
_MAXMIND_CITY_DEST_FILENAME = "GeoLite2-City.mmdb"
_ASN_DEST_FILENAME = "GeoLite2-ASN.mmdb"

# Системный пользователь для chown (из telemt_panel.py).
_SYSTEM_USER = "telemt"

# Минимальный размер распакованного .mmdb файла.
# Реальный размер: ~50-70 MB для City, ~5-10 MB для ASN.
# 1024 байта — нижний порог, отлавливает усечённые/битые gzip (как в старом
# _geoip_fetch: `if len(data) < 1024: return False`).
_MIN_MMDB_SIZE = 1024


# ============================================================================
#  mirror_urls_builder — обёртки для PackageSpec API
# ============================================================================
def _telemt_geoip_city_mirror_urls(
    filename: str, use_maxmind: bool = False, **kw,
) -> list[str]:
    """Собирает URL для City .mmdb.gz через telemt_geoip_mirrors."""
    return get_telemt_geoip_city_mirrors(use_maxmind=use_maxmind)


def _telemt_geoip_asn_mirror_urls(filename: str, **kw) -> list[str]:
    """Собирает URL для ASN .mmdb.gz через telemt_geoip_mirrors."""
    return get_telemt_geoip_asn_mirrors()


# ============================================================================
#  post_install — gzip-decompress + write .mmdb + chown
# ============================================================================
def _post_install_geoip_gz(src: Path, install_dests: list[Path], dest_filename: str) -> bool:
    """Распаковывает .mmdb.gz, записывает .mmdb в install_dests[0]/.

    Шаги (повторяют логику из старого telemt_panel.py::_geoip_fetch):
      1. gzip-decompress src
      2. Sanity check: len(data) >= 1024
      3. mkdir install_dest (parents=True, exist_ok=True)
      4. write_bytes(data) в install_dests[0]/{dest_filename}
      5. chown {SYSTEM_USER}:{SYSTEM_USER} (best-effort через subprocess)

    Возвращает True если файл записан и >= 1024 байт. False если gzip
    упал, файл слишком маленький или запись не удалась — даёт fetch_package
    шанс попробовать следующее зеркало.
    """
    if not install_dests:
        return False

    # 1. gzip-decompress
    try:
        with src.open("rb") as f:
            raw = f.read()
        data = gzip.decompress(raw)
    except (OSError, gzip.BadGzipFile):
        return False
    except Exception:
        return False

    # 2. Sanity check
    if len(data) < _MIN_MMDB_SIZE:
        return False

    # 3-4. Запись .mmdb
    dest_dir = install_dests[0]
    dest = dest_dir / dest_filename
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    except Exception:
        return False

    # 5. chown (best-effort)
    try:
        subprocess.run(
            ["chown", f"{_SYSTEM_USER}:{_SYSTEM_USER}", str(dest)],
            capture_output=True, check=False,
        )
    except Exception:
        pass

    return True


def _post_install_dbip_city(src: Path, install_dests: list[Path]) -> bool:
    """post_install для DB-IP city-lite."""
    return _post_install_geoip_gz(src, install_dests, _DBIP_CITY_DEST_FILENAME)


def _post_install_maxmind_city(src: Path, install_dests: list[Path]) -> bool:
    """post_install для MaxMind GeoLite2-City."""
    return _post_install_geoip_gz(src, install_dests, _MAXMIND_CITY_DEST_FILENAME)


def _post_install_asn(src: Path, install_dests: list[Path]) -> bool:
    """post_install для GeoLite2-ASN."""
    return _post_install_geoip_gz(src, install_dests, _ASN_DEST_FILENAME)


# ============================================================================
#  PackageSpec — DB-IP city-lite (default)
# ============================================================================
TELEMT_GEOIP_CITY_SPEC = PackageSpec(
    name="Telemt GeoIP City (DB-IP)",
    filename_builder=lambda: "dbip-city-lite.mmdb.gz",
    mirror_urls_builder=_telemt_geoip_city_mirror_urls,
    install_dests=_TELEMT_GEOIP_INSTALL_DESTS,
    manual_incoming_dir=_MANUAL_DIR,
    min_size=_MIN_MMDB_SIZE,
    post_install=_post_install_dbip_city,
)


# ============================================================================
#  PackageSpec — MaxMind GeoLite2-City (alternative)
# ============================================================================
TELEMT_GEOIP_CITY_MAXMIND_SPEC = PackageSpec(
    name="Telemt GeoIP City (MaxMind)",
    filename_builder=lambda: "GeoLite2-City.mmdb.gz",
    mirror_urls_builder=lambda filename, **kw: get_telemt_geoip_city_mirrors(use_maxmind=True),
    install_dests=_TELEMT_GEOIP_INSTALL_DESTS,
    manual_incoming_dir=_MANUAL_DIR,
    min_size=_MIN_MMDB_SIZE,
    post_install=_post_install_maxmind_city,
)


# ============================================================================
#  PackageSpec — GeoLite2-ASN
# ============================================================================
TELEMT_GEOIP_ASN_SPEC = PackageSpec(
    name="Telemt GeoIP ASN",
    filename_builder=lambda: "GeoLite2-ASN.mmdb.gz",
    mirror_urls_builder=_telemt_geoip_asn_mirror_urls,
    install_dests=_TELEMT_GEOIP_INSTALL_DESTS,
    manual_incoming_dir=_MANUAL_DIR,
    min_size=_MIN_MMDB_SIZE,
    post_install=_post_install_asn,
)

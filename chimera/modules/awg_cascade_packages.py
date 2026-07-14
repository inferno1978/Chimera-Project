"""
chimera/modules/awg_cascade_packages.py
───────────────────────────────────────────────────────────────────────────────
PackageSpec для ru.zone — списка российских IP-сетей (CIDR) для ipset.

Используется awg_cascade.py::awgs_cascade_download_ru_zone() для скачивания
data feed. До миграции awg_cascade.py делал это ad-hoc через subprocess curl
с inline списком из 2 URL.

Особенности:
  • Файл — простой текстовый список CIDR (по одной сети на строку).
  • post_install: copy2 в install_dests[0]/ru.zone + sanity check
    (lines_count > 100).
  • min_size: 1000 байт (защита от HTML-страниц 404).

install_dests = [AWGS_CASCADE_DIR] (/etc/amneziawg/cascade) — это
AWGS_RU_ZONE_FILE.parent из awg_constants.
manual_incoming_dir = /root/ — не совпадает с install_dests.

Точки входа:
    from chimera.modules.awg_cascade_packages import RU_ZONE_SPEC
"""
from __future__ import annotations

import shutil
from pathlib import Path

from chimera.modules.download_manager import PackageSpec
from chimera.modules.awg_cascade_mirrors import get_ru_zone_mirrors
from chimera.modules.awg_constants import AWGS_CASCADE_DIR


# ============================================================================
#  КОНСТАНТЫ
# ============================================================================

# AWGS_RU_ZONE_FILE = AWGS_CASCADE_DIR / "ru.zone"
# install_dests = [AWGS_CASCADE_DIR] — директория, post_install ставит
# файл с именем "ru.zone".
_RU_ZONE_INSTALL_DESTS: list[Path] = [AWGS_CASCADE_DIR]

# manual_incoming_dir — /root/ (WinSCP-friendly).
# /root/ != /etc/amneziawg/cascade — assert в __post_init__ проходит.
_MANUAL_DIR = Path("/root")

# Имя файла в install_dests — "ru.zone".
_RU_ZONE_DEST_FILENAME = "ru.zone"

# Минимальный размер ru.zone.
# Реальный размер: ~50-100 KB (~3000-5000 CIDR-строк).
# 1000 байт — нижний порог, отлавливает HTML-страницы 404.
_MIN_RU_ZONE_SIZE = 1000


# ============================================================================
#  mirror_urls_builder — обёртка для PackageSpec API
# ============================================================================
def _ru_zone_mirror_urls(filename: str, **kw) -> list[str]:
    """Собирает URL для ru.zone через awg_cascade_mirrors.

    filename параметр принимается для совместимости с PackageSpec API,
    но игнорируется — имя файла фиксировано (ru.zone).
    """
    return get_ru_zone_mirrors()


# ============================================================================
#  post_install — copy2 + sanity check
# ============================================================================
def _post_install_ru_zone(src: Path, install_dests: list[Path]) -> bool:
    """Копирует ru.zone в install_dests[0]/ru.zone.

    Шаги:
      1. mkdir install_dest (parents=True, exist_ok=True).
      2. shutil.copy2(src → install_dest/ru.zone).
      3. Sanity check: lines_count > 100 (защита от усечённых загрузок).

    Возвращает True если скопировано и sanity check прошёл. False если
    файл слишком маленький или копирование упало — даёт fetch_package
    шанс попробовать следующее зеркало.
    """
    if not install_dests:
        return False

    dest_dir = install_dests[0]
    dest = dest_dir / _RU_ZONE_DEST_FILENAME

    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(src), str(dest))

        # Sanity check: lines_count > 100
        try:
            lines_count = sum(1 for _ in dest.open())
        except Exception:
            return False
        if lines_count <= 100:
            # Усечённая загрузка или HTML-страница — отказываемся
            return False

        return True
    except Exception:
        return False


# ============================================================================
#  PackageSpec — ru.zone data feed
# ============================================================================
RU_ZONE_SPEC = PackageSpec(
    name="ru.zone",
    filename_builder=lambda **kw: "ru.zone",
    mirror_urls_builder=_ru_zone_mirror_urls,
    install_dests=_RU_ZONE_INSTALL_DESTS,       # [/etc/amneziawg/cascade]
    manual_incoming_dir=_MANUAL_DIR,            # /root/
    min_size=_MIN_RU_ZONE_SIZE,                 # 1 KB
    post_install=_post_install_ru_zone,         # copy2 + sanity check
)

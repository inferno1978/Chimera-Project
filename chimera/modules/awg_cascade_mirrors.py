"""
chimera/modules/awg_cascade_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Централизованный реестр зеркал для скачивания ru.zone — списка российских
IP-сетей (CIDR) для ipset в AWG-cascade.

ПРОБЛЕМА (до миграции):
  awg_cascade.py::awgs_cascade_download_ru_zone() использовал inline
  список из 2 URL (ipdeny.com + GitHub raw bivlked) через subprocess curl,
  БЕЗ проверки ручного размещения. Аналогично старому geo_files.py,
  который уже мигрирован.

  Если оба источника недоступны, создавался пустой файл и обновление
  откладывалось на cron.

РЕШЕНИЕ (по аналогии с geo_mirrors.py — это data feed, не бинарник):
  1. Реестр зеркал через github_mirrors.build_mirror_urls() для GitHub
    raw fallback + прямой ipdeny.com URL первым.
  2. fetch_package(RU_ZONE_SPEC) из awg_cascade_packages.py перебирает
    зеркала по очереди и проверяет /root/ для ручного размещения.
  3. При тотальном провале fetch_package() вызывает print_manual_hint() из
    download_manager.py.

Особенность ru.zone:
  • Primary источник: ipdeny.com (не GitHub). Это data feed, обновляется
    ежедневно.
  • Fallback: GitHub raw bivlked/amneziawg-installer@v5.18.4/cascade/ru.zone
    — статический снимок, может быть устаревшим.
  • Файл — простой текстовый список CIDR (по одной сети на строку).
  • min_size проверка: lines_count > 100 ( sanity check на количество сетей).

Архитектура:
  • URL'ы берутся из awg_constants.py (AWGS_RU_ZONE_URL,
    AWGS_RU_ZONE_FALLBACK_GH) — НЕ дублируем их здесь.
  • Здесь только сборщик URL в нужном порядке + GitHub-прокси для raw URL.

Пути ручного размещения:
  /root/  ← РЕКОМЕНДУЕТСЯ (WinSCP-friendly)
  /tmp/   ← альтернатива

Точки входа:
    from chimera.modules.awg_cascade_mirrors import (
        get_ru_zone_mirrors,
        RU_ZONE_MIRRORS_COUNT,
        MANUAL_UPLOAD_PATHS_RU_ZONE,
        recommended_manual_path,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from pathlib import Path

from chimera.modules.awg_constants import (
    AWGS_RU_ZONE_URL, AWGS_RU_ZONE_FALLBACK_GH,
)
from chimera.modules.github_mirrors import GITHUB_PROXY_HOSTS


# ============================================================================
#  СБОРЩИК URL
# ============================================================================
def get_ru_zone_mirrors() -> list[str]:
    """Упорядоченный список URL для скачивания ru.zone.

    Порядок:
      1. Прямой ipdeny.com (primary — обновляется ежедневно)
      2. GitHub raw bivlked/amneziawg-installer@v5.18.4/cascade/ru.zone
         (fallback — статический снимок)
      3. 7 GitHub-прокси оборачивают GitHub raw URL (для РФ где raw.githubusercontent.com
         заблокирован)

    Возвращает:
      Упорядоченный список URL.
    """
    urls: list[str] = []

    # 1. Primary — ipdeny.com
    if AWGS_RU_ZONE_URL:
        urls.append(AWGS_RU_ZONE_URL)

    # 2. Fallback — GitHub raw
    if AWGS_RU_ZONE_FALLBACK_GH:
        urls.append(AWGS_RU_ZONE_FALLBACK_GH)

        # 3. GitHub-прокси для raw URL
        # raw.githubusercontent.com/bivlked/amneziawg-installer/v5.18.4/cascade/ru.zone
        # Прокси оборачивают полный https://raw.githubusercontent.com/... URL
        for proxy_host in GITHUB_PROXY_HOSTS:
            if not proxy_host:
                continue
            urls.append(
                f"https://{proxy_host}/{AWGS_RU_ZONE_FALLBACK_GH}"
            )

    return urls


# Количество зеркал — 1 ipdeny + 1 raw + 3 прокси = 5.
RU_ZONE_MIRRORS_COUNT: int = len(get_ru_zone_mirrors())


# ============================================================================
#  ПУТИ РУЧНОГО РАЗМЕЩЕНИЯ
# ============================================================================
# /root/ — РЕКОМЕНДУЕТСЯ (зелёным в TUI), WinSCP-friendly.
# /tmp/ — альтернатива.
# AWGS_RU_ZONE_FILE (/etc/amneziawg/cascade/ru.zone) НЕ включаем — это
# install_dest, PackageSpec.__post_init__ assert требует
# manual_dir != install_dests.
MANUAL_UPLOAD_PATHS_RU_ZONE: list[Path] = [
    Path("/root"),
    Path("/tmp"),
]


def recommended_manual_path() -> Path:
    """Возвращает рекомендуемый путь для ручного размещения."""
    return MANUAL_UPLOAD_PATHS_RU_ZONE[0]

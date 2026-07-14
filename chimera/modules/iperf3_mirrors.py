"""
chimera/modules/iperf3_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Централизованный реестр зеркал для скачивания статического iperf3 binary
(userdocs/iperf3-static) с GitHub Releases.

ПРОБЛЕМА (до миграции):
  network_bench.py::install_iperf3() использовал inline dict
  STATIC_IPERF3_URLS с ОДНИМ прямым URL на каждую архитектуру (amd64/arm64),
  БЕЗ зеркал, БЕЗ fallback, БЕЗ проверки ручного размещения.

  Если github.com заблокирован, статический iperf3 не скачивается, и speed
  tests пропускаются.

РЕШЕНИЕ (по аналогии с turn_mirrors.py / hysteria2_mirrors.py):
  1. Реестр зеркал через github_mirrors.build_mirror_urls():
     jsDelivr CDN (4 бэкенда) + raw GitHub + release GitHub + 7 gh-proxy +
     Statically — итого до 14 URL.
  2. fetch_package(IPERF3_SPEC, arch=...) из iperf3_packages.py перебирает
    зеркала по очереди и проверяет /root/ для ручного размещения.
  3. При тотальном провале fetch_package() вызывает print_manual_hint().

Особенность iperf3-static:
  • Upstream репозиторий: userdocs/iperf3-static.
  • Бинарники в релизах: "iperf3-amd64", "iperf3-arm64" (без расширения).
  • /releases/latest/download/ — всегда последний релиз.
  • install_dests = [/tmp] — временная директория (iperf3 используется
    только для speed test, не персистентный артефакт).

Пути ручного размещения:
  /root/  ← РЕКОМЕНДУЕТСЯ (WinSCP-friendly)
  /usr/local/bin/  ← альтернатива (но это может быть install_dest)

Точки входа:
    from chimera.modules.iperf3_mirrors import (
        get_iperf3_mirrors,
        IPERF3_MIRRORS_COUNT,
        MANUAL_UPLOAD_PATHS_IPERF3,
        recommended_manual_path,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from pathlib import Path

from chimera.modules.github_mirrors import build_mirror_urls


# ============================================================================
#  ПУБЛИЧНЫЕ КОНСТАНТЫ — репозиторий
# ============================================================================
_IPERF3_OWNER = "userdocs"
_IPERF3_REPO  = "iperf3-static"


# ============================================================================
#  СБОРЩИК URL
# ============================================================================
def get_iperf3_mirrors(arch: str = "amd64") -> list[str]:
    """Упорядоченный список URL для скачивания iperf3 static binary.

    Параметры:
      arch: Архитектура ('amd64' или 'arm64').

    Возвращает:
      Упорядоченный список URL (через build_mirror_urls):
        1. jsDelivr CDN family (4 бэкенда) — через @iperf3 ветку? НЕТ, нет
           такой ветки. Отключаем для tag="latest".
        2. raw.githubusercontent.com (нет ветки "latest" — отключаем)
        3. release GitHub (/releases/latest/download/iperf3-{arch})
        4. 7 GitHub-прокси
        5. Statically CDN (нет ветки "latest" — отключаем)

    Итого 8 URL: release + 7 gh-proxy (jsDelivr/raw/Statically отключены
    для tag="latest").
    """
    filename = f"iperf3-{arch}"
    return build_mirror_urls(
        owner=_IPERF3_OWNER,
        repo=_IPERF3_REPO,
        filename=filename,
        tag="latest",
        include_raw_github=False,
        include_statically=False,
    )


# Количество зеркал — 1 release + 7 прокси = 8.
IPERF3_MIRRORS_COUNT: int = len(get_iperf3_mirrors())


# ============================================================================
#  ПУТИ РУЧНОГО РАЗМЕЩЕНИЯ
# ============================================================================
# /root/ — РЕКОМЕНДУЕТСЯ (зелёным в TUI), WinSCP-friendly.
# /tmp/ — альтернатива (но install_dest тоже /tmp).
# /tmp/iperf3 НЕ включаем в MANUAL_UPLOAD_PATHS — это install_dest,
# PackageSpec.__post_init__ assert требует manual_dir != install_dests.
MANUAL_UPLOAD_PATHS_IPERF3: list[Path] = [
    Path("/root"),
]


def recommended_manual_path() -> Path:
    """Возвращает рекомендуемый путь для ручного размещения."""
    return MANUAL_UPLOAD_PATHS_IPERF3[0]

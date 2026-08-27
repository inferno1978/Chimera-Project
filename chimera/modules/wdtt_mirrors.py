"""
chimera/modules/wdtt_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Централизованный реестр зеркал для скачивания исходников qWDTT
(SpaceNeuroX/proxy-turn-vk-android) как tar.gz-архива ветки master.

ПРОБЛЕМА (до миграции):
  wdtt.py качал исходники через ОДИН прямой URL
  https://github.com/SpaceNeuroX/proxy-turn-vk-android/archive/refs/heads/master.tar.gz
  БЕЗ зеркал, БЕЗ fallback, БЕЗ проверки ручного размещения.

  Если github.com заблокирован (что часто бывает в РФ), urllib.request.
  urlretrieve() выбрасывает исключение, вся сборка wdtt-server падает.

РЕШЕНИЕ (по аналогии с turn_mirrors.py):
  1. Реестр зеркал: прямой GitHub + codeload.github.com + 3 GitHub-прокси.
     Итого 5 URL на архив.
     (2026-08-21: мёртвые gh-proxy вычищены — было 7, осталось 3 рабочих.)
  2. fetch_package(WDTT_SOURCE_SPEC) из wdtt_packages.py перебирает зеркала
     по очереди и проверяет /root/ для ручного размещения.
  3. При тотальном провале fetch_package() вызывает print_manual_hint() из
     download_manager.py.

Особенность — archive/refs/heads/master.tar.gz:
  В отличие от release-assets (turn_mirrors, mieru_mirrors), исходники ветки
  качаются как archive/refs/heads/{branch}.tar.gz. Этот URL НЕ поддерживается
  jsDelivr CDN или Statically (они работают с отдельными файлами, не tarball'ами
  репозитория). Поэтому здесь только прямой GitHub + codeload + gh-proxy.

Пути ручного размещения:
  /root/  ← РЕКОМЕНДУЕТСЯ (WinSCP-friendly)
  /tmp/   ← альтернатива

Точки входа:
    from chimera.modules.wdtt_mirrors import (
        get_wdtt_source_mirrors,
        WDTT_SOURCE_MIRRORS_COUNT,
        MANUAL_UPLOAD_PATHS_WDTT,
        recommended_manual_path,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from pathlib import Path

from chimera.modules.github_mirrors import build_source_archive_mirror_urls


# ============================================================================
#  ПУБЛИЧНЫЕ КОНСТАНТЫ — репозиторий
# ============================================================================
_WDTT_OWNER = "SpaceNeuroX"
_WDTT_REPO  = "proxy-turn-vk-android"
_WDTT_BRANCH = "master"   # upstream использует master, не main

# Имя файла архива — фиксировано (branch всегда master).
_WDTT_FILENAME = "proxy-turn-vk-android-master.tar.gz"


# ============================================================================
#  СБОРЩИК URL
# ============================================================================
def get_wdtt_source_mirrors() -> list[str]:
    """Упорядоченный список URL для скачивания исходников qWDTT как tar.gz.

    Порядок (через build_source_archive_mirror_urls из github_mirrors.py):
      1. Прямой GitHub:
         https://github.com/SpaceNeuroX/proxy-turn-vk-android/archive/refs/heads/master.tar.gz
      2. Codeload (альтернативный домен GitHub):
         https://codeload.github.com/SpaceNeuroX/proxy-turn-vk-android/tar.gz/refs/heads/master
      3. 3 GitHub-прокси (ghproxy.net, gh-proxy.com, gh.llkk.cc) — каждый
         оборачивает прямой GitHub URL.
    """
    return build_source_archive_mirror_urls(
        owner=_WDTT_OWNER,
        repo=_WDTT_REPO,
        branch=_WDTT_BRANCH,
    )


# Количество зеркал — вычисляется через build_source_archive_mirror_urls.
# 1 прямой + 1 codeload + 3 прокси = 5 URL.
WDTT_SOURCE_MIRRORS_COUNT: int = len(get_wdtt_source_mirrors())


# ============================================================================
#  ПУТИ РУЧНОГО РАЗМЕЩЕНИЯ
# ============================================================================
# /root/ — РЕКОМЕНДУЕТСЯ (зелёным в TUI), WinSCP-friendly.
# /tmp/ — альтернатива.
# /usr/local/bin/wdtt-server НЕ включаем — это install_dest для built binary,
# не для tarball'а. PackageSpec.__post_init__ assert требует
# manual_dir != install_dests.
MANUAL_UPLOAD_PATHS_WDTT: list[Path] = [
    Path("/root"),
    Path("/tmp"),
]


def recommended_manual_path() -> Path:
    """Возвращает рекомендуемый путь для ручного размещения (первый в списке)."""
    return MANUAL_UPLOAD_PATHS_WDTT[0]

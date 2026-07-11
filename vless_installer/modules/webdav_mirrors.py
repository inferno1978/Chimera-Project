"""
vless_installer/modules/webdav_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Централизованный реестр зеркал для скачивания исходников webdav-tunnel
(spkprsnts/webdav-tunnel) как tar.gz-архива ветки main.

ПРОБЛЕМА (до миграции):
  webdav_tunnel.py качал исходники через ОДИН прямой URL
  https://github.com/spkprsnts/webdav-tunnel/archive/refs/heads/main.tar.gz
  БЕЗ зеркал, БЕЗ fallback, БЕЗ проверки ручного размещения.

  Если github.com заблокирован (что часто бывает в РФ), urllib.request.
  urlretrieve() выбрасывает исключение, вся сборка webdav-tunnel падает.

РЕШЕНИЕ (по аналогии с wdtt_mirrors.py):
  1. Реестр зеркал: прямой GitHub + codeload.github.com + 7 GitHub-прокси.
     Итого 9 URL на архив.
  2. fetch_package(WEBDAV_SOURCE_SPEC) из webdav_packages.py перебирает
     зеркала по очереди и проверяет /root/ для ручного размещения.
  3. При тотальном провале fetch_package() вызывает print_manual_hint() из
     download_manager.py.

Особенность — archive/refs/heads/main.tar.gz:
  В отличие от wdtt (branch=master), upstream webdav-tunnel использует main.
  jsDelivr/Statically не поддерживают tarball целиком — только прямой GitHub
  + codeload + gh-proxy.

Пути ручного размещения:
  /root/  ← РЕКОМЕНДУЕТСЯ (WinSCP-friendly)
  /tmp/   ← альтернатива

Точки входа:
    from vless_installer.modules.webdav_mirrors import (
        get_webdav_source_mirrors,
        WEBDAV_SOURCE_MIRRORS_COUNT,
        MANUAL_UPLOAD_PATHS_WEBDAV,
        recommended_manual_path,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from pathlib import Path

from vless_installer.modules.github_mirrors import build_source_archive_mirror_urls


# ============================================================================
#  ПУБЛИЧНЫЕ КОНСТАНТЫ — репозиторий
# ============================================================================
_WEBDAV_OWNER = "spkprsnts"
_WEBDAV_REPO  = "webdav-tunnel"
_WEBDAV_BRANCH = "main"   # upstream использует main, не master

# Имя файла архива — фиксировано (branch всегда main).
_WEBDAV_FILENAME = "webdav-tunnel-main.tar.gz"


# ============================================================================
#  СБОРЩИК URL
# ============================================================================
def get_webdav_source_mirrors() -> list[str]:
    """Упорядоченный список URL для скачивания исходников webdav-tunnel.

    Порядок (через build_source_archive_mirror_urls):
      1. Прямой GitHub:
         https://github.com/spkprsnts/webdav-tunnel/archive/refs/heads/main.tar.gz
      2. Codeload:
         https://codeload.github.com/spkprsnts/webdav-tunnel/tar.gz/refs/heads/main
      3. 7 GitHub-прокси.
    """
    return build_source_archive_mirror_urls(
        owner=_WEBDAV_OWNER,
        repo=_WEBDAV_REPO,
        branch=_WEBDAV_BRANCH,
    )


# Количество зеркал — 1 прямой + 1 codeload + 7 прокси = 9 URL.
WEBDAV_SOURCE_MIRRORS_COUNT: int = len(get_webdav_source_mirrors())


# ============================================================================
#  ПУТИ РУЧНОГО РАЗМЕЩЕНИЯ
# ============================================================================
MANUAL_UPLOAD_PATHS_WEBDAV: list[Path] = [
    Path("/root"),
    Path("/tmp"),
]


def recommended_manual_path() -> Path:
    """Возвращает рекомендуемый путь для ручного размещения."""
    return MANUAL_UPLOAD_PATHS_WEBDAV[0]

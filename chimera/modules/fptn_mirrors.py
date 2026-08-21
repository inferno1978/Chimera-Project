"""
chimera/modules/fptn_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Централизованный реестр зеркал для скачивания fptn-server .deb пакета
(fptn-project/fptn) с GitHub Releases.

ПРОБЛЕМА (до миграции):
  fptn.py::_download_binaries() качал .deb через ОДИН прямой URL (полученный
  из GitHub API) БЕЗ зеркал, БЕЗ fallback, БЕЗ проверки ручного размещения.
  urllib.request.urlretrieve() + dpkg-deb -x для извлечения бинарников.

  Если github.com заблокирован (что часто бывает в РФ), установка fptn
  тихо падает.

РЕШЕНИЕ (по аналогии с mieru_mirrors.py):
  1. Реестр зеркал через github_mirrors.build_mirror_urls():
     jsDelivr CDN (4 бэкенда) + raw GitHub + release GitHub + 3 gh-proxy +
     Statically — итого до 10 URL.
  2. fetch_package(FPTN_SPEC, tag=..., filename=...) из fptn_packages.py
     перебирает зеркала по очереди и проверяет /root/ для ручного размещения.
  3. При тотальном провале fetch_package() вызывает print_manual_hint() из
     download_manager.py.

Особенность fptn:
  • Upstream репозиторий: fptn-project/fptn.
  • .deb пакет в релизах: "fptn-server-{ubuntu_version}-{arch}.deb".
    Ubuntu-версия в имени может меняться (например "ubuntu22.04"),
    поэтому _pick_server_asset в fptn.py ищет любой .deb начинающийся на
    "fptn-server-" и заканчивающийся на "{arch}.deb".
  • GitHub Releases API возвращает tag_name (например "0.7.6") и список
    assets с browser_download_url.
  • После миграции: fptn.py получает asset URL из API (non-migration,
    metadata), затем передаёт точное filename в fetch_package(FPTN_SPEC,
    tag=..., filename=...). Зеркала строятся через build_mirror_urls.

Архитектура:
  • Запрос tag_name + asset URL через GitHub API ОСТАЁТСЯ в fptn.py — это
    API metadata (non-migration).
  • Зеркала для самого .deb пакета строятся здесь, в fptn_mirrors.py.

Пути ручного размещения:
  /root/  ← РЕКОМЕНДУЕТСЯ (WinSCP-friendly)
  /tmp/   ← альтернатива

Точки входа:
    from chimera.modules.fptn_mirrors import (
        get_fptn_mirrors,
        FPTN_MIRRORS_COUNT,
        MANUAL_UPLOAD_PATHS_FPTN,
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
_FPTN_OWNER = "fptn-project"
_FPTN_REPO  = "fptn"


# ============================================================================
#  СБОРЩИК URL
# ============================================================================
def get_fptn_mirrors(tag: str, filename: str) -> list[str]:
    """Упорядоченный список URL для скачивания fptn-server .deb пакета.

    Параметры:
      tag:      Release tag (например "0.7.6", БЕЗ префикса "v").
                Получается из GitHub API в fptn.py.
      filename: Имя .deb файла (например "fptn-server-ubuntu22.04-amd64.deb").
                Получается из GitHub API assets в fptn.py.

    Возвращает:
      Упорядоченный список URL (через build_mirror_urls):
        1. jsDelivr CDN family (4 бэкенда)
        2. raw.githubusercontent.com/{tag}/{filename}
        3. release GitHub (/releases/download/{tag}/{filename})
        4. 7 GitHub-прокси
        5. Statically CDN
    """
    if not tag or not filename:
        return []

    return build_mirror_urls(
        owner=_FPTN_OWNER,
        repo=_FPTN_REPO,
        filename=filename,
        tag=tag,
        # ref = tag. Тег без префикса "v" — все зеркала принимают.
    )


# Количество зеркал — 10 (4 jsDelivr + raw + release + 3 proxy + Statically).
FPTN_MIRRORS_COUNT: int = 10  # константа для TUI


# ============================================================================
#  ПУТИ РУЧНОГО РАЗМЕЩЕНИЯ
# ============================================================================
# /root/ — РЕКОМЕНДУЕТСЯ (зелёным в TUI), WinSCP-friendly.
# /tmp/ — альтернатива.
# /usr/bin/fptn-server и /usr/bin/fptn-passwd НЕ включаем — это install_dests
# для извлечённых бинарников, PackageSpec.__post_init__ assert требует
# manual_dir != install_dests.
MANUAL_UPLOAD_PATHS_FPTN: list[Path] = [
    Path("/root"),
    Path("/tmp"),
]


def recommended_manual_path() -> Path:
    """Возвращает рекомендуемый путь для ручного размещения."""
    return MANUAL_UPLOAD_PATHS_FPTN[0]

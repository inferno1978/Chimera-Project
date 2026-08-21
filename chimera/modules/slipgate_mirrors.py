"""
chimera/modules/slipgate_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Централизованный реестр зеркал для скачивания SlipGate install.sh
(anonvector/slipgate) — официального установочного скрипта.

ПРОБЛЕМА (до миграции):
  slipgate.py качал install.sh через `curl -fsSL | sudo bash` — пайп в
  bash, БЕЗ зеркал, БЕЗ fallback, БЕЗ проверки ручного размещения.

  Если raw.githubusercontent.com заблокирован (что часто бывает в РФ),
  установка SlipGate тихо падает.

РЕШЕНИЕ (по аналогии с xray_mirrors.py для install-release.sh):
  1. Реестр зеркал через github_mirrors.build_mirror_urls():
     jsDelivr CDN (4 бэкенда) + raw GitHub + 7 gh-proxy + Statically —
     итого 13 URL. (release-assets неприменим — это файл в репозитории,
     не релизный ассет.)
  2. fetch_package(SLIPGATE_INSTALLER_SPEC) из slipgate_packages.py
     перебирает зеркала по очереди и проверяет /root/ для ручного
     размещения.
  3. При тотальном провале fetch_package() вызывает print_manual_hint().

Особенность SlipGate:
  • install.sh — bash-скрипт, который ВНУТРИ себя качает slipgate binary
    и ставит конфиги. fetch_package контролирует только скачивание самого
    скрипта; внутренние загрузки остаются вне контроля Python.
  • Это по крайней мере даёт mirror-fallback + manual-upload для скрипта.
  • Скрипт запускается через `bash {tmpfile}` после скачивания.

Пути ручного размещения:
  /root/  ← РЕКОМЕНДУЕТСЯ (WinSCP-friendly)
  /tmp/   ← альтернатива

Точки входа:
    from chimera.modules.slipgate_mirrors import (
        get_slipgate_installer_mirrors,
        SLIPGATE_INSTALLER_MIRRORS_COUNT,
        MANUAL_UPLOAD_PATHS_SLIPGATE,
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
_SLIPGATE_OWNER = "anonvector"
_SLIPGATE_REPO  = "slipgate"
_SLIPGATE_BRANCH = "main"
_SLIPGATE_FILENAME = "install.sh"


# ============================================================================
#  СБОРЩИК URL
# ============================================================================
def get_slipgate_installer_mirrors() -> list[str]:
    """Упорядоченный список URL для скачивания install.sh.

    install.sh — это файл в репозитории anonvector/slipgate (НЕ релизный
    ассет!). Поэтому используем build_mirror_urls с tag="main" (ветка),
    include_release_github=False (нет релиза).

    Возвращает:
      Упорядоченный список URL:
        1. jsDelivr CDN family (4 бэкенда) — /gh/anonvector/slipgate@main/...
        2. raw.githubusercontent.com/main/install.sh
        3. 3 GitHub-прокси (оборачивают raw GitHub URL)
        4. Statically CDN
    """
    return build_mirror_urls(
        owner=_SLIPGATE_OWNER,
        repo=_SLIPGATE_REPO,
        filename=_SLIPGATE_FILENAME,
        tag=_SLIPGATE_BRANCH,  # ветка main
        include_release_github=False,  # нет релизных ассетов
    )


# Количество зеркал — 4 jsDelivr + raw + 3 proxy + Statically = 9.
SLIPGATE_INSTALLER_MIRRORS_COUNT: int = len(get_slipgate_installer_mirrors())


# ============================================================================
#  ПУТИ РУЧНОГО РАЗМЕЩЕНИЯ
# ============================================================================
MANUAL_UPLOAD_PATHS_SLIPGATE: list[Path] = [
    Path("/root"),
    Path("/tmp"),
]


def recommended_manual_path() -> Path:
    """Возвращает рекомендуемый путь для ручного размещения."""
    return MANUAL_UPLOAD_PATHS_SLIPGATE[0]

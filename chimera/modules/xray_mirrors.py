"""
chimera/modules/xray_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Централизованный реестр зеркал для скачивания Xray-core артефактов:
  • Xray-linux-{arch}.zip — бинарный архив (релизный ассет)
  • checksums.txt — SHA256 манифест для верификации zip
  • install-release.sh — официальный установочный скрипт XTLS/Xray-install

ПРОБЛЕМА (до миграции):
  xray_install.py содержал ТРИ inline списка зеркал:
    • _ZIP_MIRRORS — 7 URL (прямой GitHub + 6 ghproxy вариантов) для zip
    • _CHK_MIRRORS — 3 URL (прямой GitHub + 2 ghproxy) для checksums.txt
    • _xray_print_manual_download_hint — дублировал _ZIP_MIRRORS (7 URL)
  Плюс _xray_do_upgrade (L1679) использовал ОДИН прямой URL без зеркал.

  Списки захардкожены в коде, не вынесены в реестр. Обновление набора
  зеркал требует правки в 3+ местах.

РЕШЕНИЕ (по аналогии с mieru_mirrors.py / turn_mirrors.py):
  1. Реестр зеркал через github_mirrors.build_mirror_urls():
     jsDelivr CDN (4 бэкенда) + raw GitHub + release GitHub + 7 gh-proxy +
     Statically — итого до 14 URL.
  2. fetch_package(XRAY_ZIP_SPEC, tag=..., arch=...) из xray_packages.py
     перебирает зеркала по очереди и проверяет /root/ для ручного размещения.
  3. При тотальном провале fetch_package() вызывает print_manual_hint() из
     download_manager.py.

Особенность Xray-core:
  • Релизные теги: "v25.4.30", "v24.9.30" и т.д. (с префиксом "v").
  • Бинарный архив: "Xray-linux-{arch}.zip" где arch ∈ {"64", "arm64-v8a",
    "arm32-v7a", "32"} (НЕ стандартные amd64/arm64 — своя схема Xray).
  • checksums.txt — тот же tag, файл "checksums.txt".
  • install-release.sh — в репозитории XTLS/Xray-install (не Xray-core!),
    ветка main, путь /install-release.sh. Это НЕ релизный ассет.

Пути ручного размещения:
  /root/  ← РЕКОМЕНДУЕТСЯ (WinSCP-friendly)
  /tmp/   ← альтернатива

Точки входа:
    from chimera.modules.xray_mirrors import (
        get_xray_zip_mirrors,
        get_xray_checksums_mirrors,
        get_xray_installer_mirrors,
        XRAY_ZIP_MIRRORS_COUNT,
        XRAY_INSTALLER_MIRRORS_COUNT,
        MANUAL_UPLOAD_PATHS_XRAY,
        recommended_manual_path,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from pathlib import Path

from chimera.modules.github_mirrors import build_mirror_urls


# ============================================================================
#  ПУБЛИЧНЫЕ КОНСТАНТЫ — репозитории
# ============================================================================
_XRAY_CORE_OWNER = "XTLS"
_XRAY_CORE_REPO  = "Xray-core"

# Xray-install — отдельный репозиторий с установочным скриптом.
_XRAY_INSTALL_OWNER = "XTLS"
_XRAY_INSTALL_REPO  = "Xray-install"
_XRAY_INSTALL_BRANCH = "main"
_XRAY_INSTALL_FILENAME = "install-release.sh"


# ============================================================================
#  СБОРЩИК URL — Xray zip
# ============================================================================
def get_xray_zip_mirrors(tag: str, arch: str = "64") -> list[str]:
    """Упорядоченный список URL для скачивания Xray-linux-{arch}.zip.

    Параметры:
      tag:  Release tag (например "v25.4.30"). Получается из GitHub API
            или hardcoded fallback.
      arch: Архитектура в схеме Xray ("64", "arm64-v8a", "arm32-v7a", "32").

    Возвращает:
      Упорядоченный список URL (через build_mirror_urls):
        1. jsDelivr CDN family (4 бэкенда) — /gh/XTLS/Xray-core@{tag}/...
        2. raw.githubusercontent.com/{tag}/Xray-linux-{arch}.zip
        3. release GitHub (/releases/download/{tag}/Xray-linux-{arch}.zip)
        4. 7 GitHub-прокси
        5. Statically CDN

    Примечание: jsDelivr/raw GitHub могут не иметь релизных zip'ов (они
    работают с файлами репозитория, не релизными ассетами). fetch_package
    перебирает URL и 404 пропускает. Рабочими остаются release GitHub и
    gh-proxy URLs.
    """
    if not tag:
        return []
    filename = f"Xray-linux-{arch}.zip"
    return build_mirror_urls(
        owner=_XRAY_CORE_OWNER,
        repo=_XRAY_CORE_REPO,
        filename=filename,
        tag=tag,
        # ref = tag. Тег "v25.4.30" без слешей — все зеркала принимают.
    )


# ============================================================================
#  СБОРЩИК URL — checksums.txt
# ============================================================================
def get_xray_checksums_mirrors(tag: str) -> list[str]:
    """Упорядоченный список URL для скачивания checksums.txt.

    Параметры:
      tag: Release tag (например "v25.4.30").

    Возвращает:
      Упорядоченный список URL (через build_mirror_urls с filename=
      "checksums.txt"). Та же структура что и для zip, но другой filename.
    """
    if not tag:
        return []
    return build_mirror_urls(
        owner=_XRAY_CORE_OWNER,
        repo=_XRAY_CORE_REPO,
        filename="checksums.txt",
        tag=tag,
    )


# ============================================================================
#  СБОРЩИК URL — install-release.sh
# ============================================================================
def get_xray_installer_mirrors() -> list[str]:
    """Упорядоченный список URL для скачивания install-release.sh.

    install-release.sh — это файл в репозитории XTLS/Xray-install (НЕ
    релизный ассет!). Поэтому используем build_mirror_urls с tag="main"
    (ветка), include_release_github=False (нет релиза).

    Возвращает:
      Упорядоченный список URL:
        1. jsDelivr CDN family (4 бэкенда) — /gh/XTLS/Xray-install@main/...
        2. raw.githubusercontent.com/main/install-release.sh
        3. 7 GitHub-прокси (оборачивают raw GitHub URL)
        4. Statically CDN
    """
    return build_mirror_urls(
        owner=_XRAY_INSTALL_OWNER,
        repo=_XRAY_INSTALL_REPO,
        filename=_XRAY_INSTALL_FILENAME,
        tag="main",  # ветка main, не релиз
        include_release_github=False,  # нет релизных ассетов для скрипта
    )


# Количество зеркал — вычисляется для отображения в TUI.
# XRAY_ZIP: 14 (4 jsDelivr + raw + release + 7 proxy + Statically).
# XRAY_CHK (checksums.txt): 14 (та же структура что и zip, другой filename).
# XRAY_INSTALLER: 13 (4 jsDelivr + raw + 7 proxy + Statically, без release).
XRAY_ZIP_MIRRORS_COUNT: int = 14
XRAY_CHK_MIRRORS_COUNT: int = 14
XRAY_INSTALLER_MIRRORS_COUNT: int = len(get_xray_installer_mirrors())


# ============================================================================
#  ПУТИ РУЧНОГО РАЗМЕЩЕНИЯ
# ============================================================================
# /root/ — РЕКОМЕНДУЕТСЯ (зелёным в TUI), WinSCP-friendly.
# /tmp/ — альтернатива.
# /usr/local/bin/xray НЕ включаем — это install_dest для бинарника,
# PackageSpec.__post_init__ assert требует manual_dir != install_dests.
MANUAL_UPLOAD_PATHS_XRAY: list[Path] = [
    Path("/root"),
    Path("/tmp"),
]


def recommended_manual_path() -> Path:
    """Возвращает рекомендуемый путь для ручного размещения."""
    return MANUAL_UPLOAD_PATHS_XRAY[0]

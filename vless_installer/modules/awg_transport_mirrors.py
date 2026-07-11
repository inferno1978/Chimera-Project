"""
vless_installer/modules/awg_transport_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Централизованный реестр зеркал для скачивания артефактов AWG transport:
  • amneziawg-tools prebuilt zip (amnezia-vpn/amneziawg-tools, release asset)
  • amneziawg-go source tarball (amnezia-vpn/amneziawg-go, branch master)
  • amneziawg-linux-kernel-module source tarball
    (amnezia-vpn/amneziawg-linux-kernel-module, branch master)

ПРОБЛЕМА (до миграции):
  awg_transport.py содержал ТРИ разных ad-hoc скачивания:
    1. amneziawg-tools zip — один прямой URL через curl (L194), без зеркал.
    2. amneziawg-go source — `git clone --depth=1` (L256, L298), без зеркал.
    3. amneziawg-linux-kernel-module source — `git clone --depth=1` внутри
       bash one-liner (L942), без зеркал.

  Все три — БЕЗ fallback, БЕЗ проверки ручного размещения.

РЕШЕНИЕ (Wave 6 — Variant A для git-clone случаев, согласно анализу):
  • amneziawg-tools zip: github_mirrors.build_mirror_urls() — 14 URL.
  • amneziawg-go source tarball: github_mirrors.build_source_archive_mirror_urls()
    — 9 URL (прямой GitHub + codeload + 7 gh-proxy).
  • amneziawg-linux-kernel-module source tarball: то же — 9 URL.

  Все три используют fetch_package() из download_manager.py с PackageSpec
  из awg_transport_packages.py. Variant A (HTTP tarball вместо git clone)
  применим ко всем трём случаям, т.к. ни один build-скрипт не требует
  .git/ metadata (см. анализ Wave 6).

Особенность amneziawg-tools:
  • Release asset, не source archive.
  • Asset name: "ubuntu-22.04-amneziawg-tools.zip" (amd64) или
    "ubuntu-22.04-arm64-amneziawg-tools.zip" (arm64).
  • Tag: динамический из GitHub API (latest).

Особенность amneziawg-go (source tarball):
  • Branch: master (default).
  • Build: `make` (Makefile tolerates missing .git/, см. анализ).
  • Tarball URL: /archive/refs/heads/master.tar.gz.

Особенность amneziawg-linux-kernel-module (source tarball):
  • Branch: master (default).
  • Build: `cd src && make dkms-install && dkms add/build/install` или
    fallback `make && make install` (из src/, не из root!).
  • Tarball URL: /archive/refs/heads/master.tar.gz.

Пути ручного размещения:
  /root/  ← РЕКОМЕНДУЕТСЯ (WinSCP-friendly)
  /tmp/   ← альтернатива

Точки входа:
    from vless_installer.modules.awg_transport_mirrors import (
        get_amneziawg_tools_mirrors,
        get_amneziawg_go_source_mirrors,
        get_amneziawg_kmod_source_mirrors,
        AWG_TOOLS_MIRRORS_COUNT,
        AWG_GO_SOURCE_MIRRORS_COUNT,
        AWG_KMOD_SOURCE_MIRRORS_COUNT,
        MANUAL_UPLOAD_PATHS_AWG,
        recommended_manual_path,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from pathlib import Path

from vless_installer.modules.github_mirrors import (
    build_mirror_urls, build_source_archive_mirror_urls,
)


# ============================================================================
#  ПУБЛИЧНЫЕ КОНСТАНТЫ — репозитории
# ============================================================================
_AWG_TOOLS_OWNER = "amnezia-vpn"
_AWG_TOOLS_REPO  = "amneziawg-tools"

_AWG_GO_OWNER = "amnezia-vpn"
_AWG_GO_REPO  = "amneziawg-go"
_AWG_GO_BRANCH = "master"

_AWG_KMOD_OWNER = "amnezia-vpn"
_AWG_KMOD_REPO  = "amneziawg-linux-kernel-module"
_AWG_KMOD_BRANCH = "master"


# ============================================================================
#  СБОРЩИК URL — amneziawg-tools zip (release asset)
# ============================================================================
def get_amneziawg_tools_mirrors(tag: str, arch: str = "amd64") -> list[str]:
    """Упорядоченный список URL для скачивания amneziawg-tools zip.

    Параметры:
      tag:  Release tag (например "v1.0.0"). Получается из GitHub API.
      arch: Архитектура — "amd64" или "arm64".
            Asset name: "ubuntu-22.04-amneziawg-tools.zip" (amd64) или
            "ubuntu-22.04-arm64-amneziawg-tools.zip" (arm64).

    Возвращает:
      14 URL через build_mirror_urls (jsDelivr + raw + release + 7 proxy +
      Statically).
    """
    if not tag:
        return []
    # Asset name зависит от архитектуры
    if arch == "arm64":
        filename = "ubuntu-22.04-arm64-amneziawg-tools.zip"
    else:
        filename = "ubuntu-22.04-amneziawg-tools.zip"

    return build_mirror_urls(
        owner=_AWG_TOOLS_OWNER,
        repo=_AWG_TOOLS_REPO,
        filename=filename,
        tag=tag,
    )


# ============================================================================
#  СБОРЩИК URL — amneziawg-go source tarball (branch master)
# ============================================================================
def get_amneziawg_go_source_mirrors() -> list[str]:
    """Упорядоченный список URL для скачивания amneziawg-go source tarball.

    Использует build_source_archive_mirror_urls (прямой GitHub + codeload +
    7 gh-proxy = 9 URL). Branch: master.

    Build: `make` (Makefile tolerates missing .git/ — см. анализ Wave 6).
    """
    return build_source_archive_mirror_urls(
        owner=_AWG_GO_OWNER,
        repo=_AWG_GO_REPO,
        branch=_AWG_GO_BRANCH,
    )


# ============================================================================
#  СБОРЩИК URL — amneziawg-linux-kernel-module source tarball (branch master)
# ============================================================================
def get_amneziawg_kmod_source_mirrors() -> list[str]:
    """Упорядоченный список URL для скачивания amneziawg-linux-kernel-module
    source tarball.

    Использует build_source_archive_mirror_urls (9 URL). Branch: master.

    Build: `cd src && make dkms-install && dkms add/build/install` или
    fallback `make && make install` (из src/, не из root!).
    """
    return build_source_archive_mirror_urls(
        owner=_AWG_KMOD_OWNER,
        repo=_AWG_KMOD_REPO,
        branch=_AWG_KMOD_BRANCH,
    )


# Количество зеркал — для отображения в TUI.
AWG_TOOLS_MIRRORS_COUNT: int = 14
AWG_GO_SOURCE_MIRRORS_COUNT: int = len(get_amneziawg_go_source_mirrors())
AWG_KMOD_SOURCE_MIRRORS_COUNT: int = len(get_amneziawg_kmod_source_mirrors())


# ============================================================================
#  ПУТИ РУЧНОГО РАЗМЕЩЕНИЯ
# ============================================================================
# /root/ — РЕКОМЕНДУЕТСЯ (зелёным в TUI), WinSCP-friendly.
# /tmp/ — альтернатива.
MANUAL_UPLOAD_PATHS_AWG: list[Path] = [
    Path("/root"),
    Path("/tmp"),
]


def recommended_manual_path() -> Path:
    """Возвращает рекомендуемый путь для ручного размещения."""
    return MANUAL_UPLOAD_PATHS_AWG[0]

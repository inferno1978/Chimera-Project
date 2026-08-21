"""
chimera/modules/singbox_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Централизованный реестр зеркал для скачивания sing-box бинарника
(SagerNet/sing-box) с GitHub Releases.

По образцу fptn_mirrors.py:
  1. Реестр зеркал через github_mirrors.build_mirror_urls():
     jsDelivr CDN (4 бэкенда) + raw GitHub + release GitHub + 7 gh-proxy +
     Statically — итого до 14 URL.
  2. fetch_package(SINGBOX_SPEC, tag=..., filename=...) из singbox_packages.py
     перебирает зеркала по очереди и проверяет /root/ для ручного размещения.
  3. При тотальном провале fetch_package() вызывает print_manual_hint().

Особенность sing-box:
  • Upstream репозиторий: SagerNet/sing-box.
  • Релизы: https://github.com/SagerNet/sing-box/releases
  • Бинарники: sing-box-{version}-linux-{arch}.tar.gz
    Например: sing-box-1.11.4-linux-amd64.tar.gz
  • Внутри tar.gz: директория sing-box-{version}-linux-{arch}/ с бинарником sing-box.
  • GitHub Releases API возвращает tag_name (например "1.11.4", без префикса "v")
    и список assets с browser_download_url.

Пути ручного размещения:
  /root/  ← РЕКОМЕНДУЕТСЯ (WinSCP-friendly)
  /tmp/   ← альтернатива

Точки входа:
    from chimera.modules.singbox_mirrors import (
        get_singbox_mirrors,
        SINGBOX_MIRRORS_COUNT,
        MANUAL_UPLOAD_PATHS_SINGBOX,
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
_SINGBOX_OWNER = "SagerNet"
_SINGBOX_REPO  = "sing-box"


# ============================================================================
#  СБОРЩИК URL
# ============================================================================
def get_singbox_mirrors(tag: str, filename: str) -> list[str]:
    """Упорядоченный список URL для скачивания sing-box бинарника.

    Параметры:
      tag:      Release tag (например "1.13.14", БЕЗ префикса "v").
                Получается из GitHub API в singbox_install.py.
      filename: Имя tar.gz файла (например "sing-box-1.13.14-linux-amd64.tar.gz").
                Получается из GitHub API assets в singbox_install.py.

    Возвращает:
      Упорядоченный список URL (через build_mirror_urls):
        1. release GitHub (/releases/download/{tag}/{filename})
        2. 7 GitHub-прокси

    ВАЖНО: jsDelivr (4 URL), raw.githubusercontent (1 URL), Statically (1 URL)
    ИСКЛЮЧЕНЫ, потому что они могут отдавать ТОЛЬКО файлы из repo tree, а не
    GitHub release assets. sing-box бинарник — это release asset. Включение
    этих зеркал приводило к 6 из 14 гарантированным 404, что замедляло
    скачивание и вводило в заблуждение (print_manual_hint показывал
    несуществующие URL).
    """
    if not tag or not filename:
        return []

    return build_mirror_urls(
        owner=_SINGBOX_OWNER,
        repo=_SINGBOX_REPO,
        filename=filename,
        tag=tag,
        # Release assets — исключаем зеркала, которые работают только с repo tree
        jsdelivr_hosts=(),           # исключаем все 4 jsDelivr URL
        include_raw_github=False,    # исключаем raw.githubusercontent.com
        include_statically=False,    # исключаем cdn.statically.io
    )


# Количество зеркал — 1 release GitHub + 3 gh-proxy = 4.
# jsDelivr/raw/Statically исключены — не могут отдавать release assets.
SINGBOX_MIRRORS_COUNT: int = 4  # константа для TUI


# ============================================================================
#  ПУТИ РУЧНОГО РАЗМЕЩЕНИЯ
# ============================================================================
# /root/ — РЕКОМЕНДУЕТСЯ (зелёным в TUI), WinSCP-friendly.
# /tmp/ — альтернатива.
# /usr/local/bin/sing-box НЕ включаем — это install_dest для распакованного
# бинарника, PackageSpec.__post_init__ assert требует manual_dir != install_dests.
MANUAL_UPLOAD_PATHS_SINGBOX: list[Path] = [
    Path("/root"),
    Path("/tmp"),
]


def recommended_manual_path() -> Path:
    """Возвращает рекомендуемый путь для ручного размещения."""
    return MANUAL_UPLOAD_PATHS_SINGBOX[0]

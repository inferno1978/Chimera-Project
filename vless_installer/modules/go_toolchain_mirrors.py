"""
vless_installer/modules/go_toolchain_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Централизованный реестр зеркал для скачивания официального Go toolchain
(golang tarball) с go.dev/dl/.

ПРОБЛЕМА (до миграции):
  • wdtt.py и webdav_tunnel.py содержали ДВЕ идентичные копии _http_download
    + _install_go_toolchain, которые качали Go через ОДИН прямой URL
    (https://go.dev/dl/{version}.linux-{arch}.tar.gz) БЕЗ зеркал, БЕЗ
    fallback, БЕЗ проверки ручного размещения.
  • olcrtc.py — третья копия той же логики (будет мигрирована в Wave 6).

  Если go.dev недоступен (что бывает в РФ из-за блокировок или geo-fencing),
  загрузка тихо падает, и пользователь получает невнятную ошибку сборки.

РЕШЕНИЕ (по аналогии с geo_mirrors.py / mieru_mirrors.py / turn_mirrors.py):
  1. Реестр зеркал: go.dev (официальный) + 3 региональных зеркал (Google CN,
     Aliyun, Tencent) — итого 4 URL на каждый tarball.
  2. fetch_package(GO_TOOLCHAIN_SPEC, version=..., arch=...) из
     go_toolchain_packages.py перебирает зеркала по очереди и проверяет
     /root/ для ручного размещения.
  3. При тотальном провале fetch_package() вызывает print_manual_hint() из
     download_manager.py.

Особенность Go toolchain:
  • Версия динамически разрешается через https://go.dev/VERSION?m=text
    (API metadata, non-migration — остаётся в вызывающем коде).
  • Архитектура: amd64 / arm64 (через _go_arch()).
  • Tarball-large (~60-70 MB) — min_size=10_000_000 (10 MB) защищает от
    HTML-страниц 404 и усечённых загрузок.

Региональные зеркала:
  • go.dev — официальный источник (Google-backed).
  • golang.google.cn/dl/ — официальное зеркало Google для Китая. Работает
    когда go.dev заблокирован или медленный из РФ/Азии.
  • mirrors.aliyun.com/golang/ — Aliyun (Alibaba Cloud) зеркало, популярно
    в Азии.
  • mirrors.tencent.com/golang/ — Tencent Cloud зеркало.

Пути ручного размещения:
  /root/  ← РЕКОМЕНДУЕТСЯ (WinSCP-friendly)
  /tmp/   ← альтернатива (tarball и так качается в /tmp/ по умолчанию)

Точки входа:
    from vless_installer.modules.go_toolchain_mirrors import (
        get_go_toolchain_mirrors,
        GO_TOOLCHAIN_MIRRORS_COUNT,
        MANUAL_UPLOAD_PATHS_GO,
        recommended_manual_path,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from pathlib import Path


# ============================================================================
#  ПУБЛИЧНЫЕ КОНСТАНТЫ — зеркала
# ============================================================================
# Каждый элемент — tuple (host, path_prefix, url_template).
# path_prefix — что идёт после https://{host}/ перед {version}.linux-{arch}.tar.gz.
#
# go.dev/dl/{version}.linux-{arch}.tar.gz
# golang.google.cn/dl/{version}.linux-{arch}.tar.gz
# mirrors.aliyun.com/golang/{version}.linux-{arch}.tar.gz
# mirrors.tencent.com/golang/{version}.linux-{arch}.tar.gz

#: Список зеркал Go toolchain. Порядок важен — первый (go.dev) самый быстрый
#: когда не заблокирован, остальные — fallback для РФ/Азии.
GO_MIRROR_HOSTS: list[tuple[str, str]] = [
    ("go.dev",                "dl"),
    ("golang.google.cn",      "dl"),
    ("mirrors.aliyun.com",    "golang"),
    ("mirrors.tencent.com",   "golang"),
]


# ============================================================================
#  СБОРЩИК URL
# ============================================================================
def get_go_toolchain_mirrors(version: str, arch: str = "amd64") -> list[str]:
    """Упорядоченный список URL для скачивания Go toolchain tarball'а.

    Параметры:
      version:  Полная версия Go с префиксом 'go' (например 'go1.23.4').
                 Возвращается как есть из go.dev/VERSION?m=text.
      arch:     Архитектура ('amd64' или 'arm64').

    Возвращает:
      Список URL в порядке приоритета:
        1. https://go.dev/dl/{version}.linux-{arch}.tar.gz
        2. https://golang.google.cn/dl/{version}.linux-{arch}.tar.gz
        3. https://mirrors.aliyun.com/golang/{version}.linux-{arch}.tar.gz
        4. https://mirrors.tencent.com/golang/{version}.linux-{arch}.tar.gz
    """
    if not version:
        return []
    # Нормализуем — убираем ведущий 'go' если пользователь передал '1.23.4'
    # вместо 'go1.23.4'. Все зеркала ожидают формат с 'go' префиксом.
    if not version.startswith("go"):
        version = f"go{version}"

    filename = f"{version}.linux-{arch}.tar.gz"

    urls: list[str] = []
    for host, prefix in GO_MIRROR_HOSTS:
        if not host:
            continue
        if prefix:
            urls.append(f"https://{host}/{prefix}/{filename}")
        else:
            urls.append(f"https://{host}/{filename}")
    return urls


# Количество зеркал — вычисляется из GO_MIRROR_HOSTS.
# Используется для отображения в TUI ("4 зеркала в fallback для Go toolchain").
GO_TOOLCHAIN_MIRRORS_COUNT: int = len(GO_MIRROR_HOSTS)


# ============================================================================
#  ПУТИ РУЧНОГО РАЗМЕЩЕНИЯ
# ============================================================================
# /root/ — РЕКОМЕНДУЕТСЯ (зелёным в TUI), WinSCP-friendly.
# /tmp/ — альтернатива (tarball и так обычно качается в /tmp/, но
# PackageSpec.__post_init__ assert требует manual_dir != install_dests, а
# install_dests для Go toolchain будет [/usr/local] — поэтому /tmp/ безопасен).
MANUAL_UPLOAD_PATHS_GO: list[Path] = [
    Path("/root"),
    Path("/tmp"),
]


def recommended_manual_path() -> Path:
    """Возвращает рекомендуемый путь для ручного размещения (первый в списке)."""
    return MANUAL_UPLOAD_PATHS_GO[0]

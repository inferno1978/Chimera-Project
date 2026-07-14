"""
chimera/modules/turn_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Централизованный реестр зеркал для скачивания бинарников:
  • vk-turn-proxy (cacggghp/vk-turn-proxy) — turntunnel.py
  • turnable (TheAirBlow/Turnable) — turnable.py

ПРОБЛЕМА (до миграции):
  • turntunnel.py качал бинарник через ОДИН прямой URL
    https://github.com/cacggghp/vk-turn-proxy/releases/latest/download/
    server-linux-amd64
    БЕЗ зеркал, БЕЗ fallback, БЕЗ проверки ручного размещения.
  • turnable.py — то же самое, через pinned tag
    https://github.com/TheAirBlow/Turnable/releases/download/0.4.1/
    turnable-linux-amd64

  Если github.com заблокирован (что часто бывает в РФ), urllib.request.
  urlretrieve() выбрасывает исключение, вся установка падает. У пользователя
  нет ни подсказки, ни второго зеркала, ни шанса положить файл через WinSCP.

РЕШЕНИЕ (по аналогии с geo_mirrors.py / mieru_mirrors.py):
  1. Реестр зеркал: jsDelivr CDN (4 бэкенда) + raw GitHub + release GitHub +
     7 GitHub-прокси + Statically CDN — итого до 14 URL на файл.
  2. MANUAL_UPLOAD_PATHS: /root/ (рекомендуется, WinSCP-friendly),
     /usr/local/bin/, /opt/vk-turn-proxy/, /opt/turnable/.
  3. turntunnel.py / turnable.py используют fetch_package() из
     download_manager.py с PackageSpec из turn_packages.py — он сам
     перебирает зеркала по очереди и проверяет /root/.
  4. При тотальном провале fetch_package() вызывает print_manual_hint() из
     download_manager.py (вместо собственной функции в каждом модуле).

Особенность версионирования:
  • vk-turn-proxy: использует /releases/latest/download/ — всегда последний
    релиз, без pinned tag. filename_builder всегда возвращает
    "server-linux-amd64" (архитектура amd64 захардкожена в upstream).
  • turnable: использует /releases/download/{version}/ — версия пинится
    в коде (_TURNABLE_VERSION = "0.4.1" в turnable.py). filename_builder
    возвращает "turnable-linux-amd64".

Оба бинарника — amd64-only. Защита _is_amd64() остаётся в вызывающем коде
(turntunnel.py / turnable.py) — это бизнес-логика, не ответственность
зеркал-реестра.

Точки входа:
    from chimera.modules.turn_mirrors import (
        get_turntunnel_mirrors, get_turnable_mirrors,
        MANUAL_UPLOAD_PATHS_TURNTUNNEL, MANUAL_UPLOAD_PATHS_TURNABLE,
        TURNTUNNEL_MIRRORS_COUNT, TURNABLE_MIRRORS_COUNT,
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

# vk-turn-proxy — всегда /releases/latest/download/, без pinned tag.
# Upstream не использует semver-префикс "v" в именах релизов, но это не
# критично: build_mirror_urls(tag="latest") формирует
# /releases/latest/download/ URL для release-GitHub и gh-proxy веток.
_TURNTUNNEL_OWNER = "cacggghp"
_TURNTUNNEL_REPO  = "vk-turn-proxy"
_TURNTUNNEL_FILENAME = "server-linux-amd64"

# turnable — pinned tag (версия в коде turnable.py: _TURNABLE_VERSION).
# build_mirror_urls(tag="0.4.1") формирует /releases/download/0.4.1/... URL.
_TURNABLE_OWNER = "TheAirBlow"
_TURNABLE_REPO  = "Turnable"
_TURNABLE_FILENAME = "turnable-linux-amd64"


# ============================================================================
#  СБОРЩИКИ URL
# ============================================================================

def get_turntunnel_mirrors() -> list[str]:
    """Упорядоченный список URL для скачивания vk-turn-proxy binary.

    Порядок (через build_mirror_urls из github_mirrors.py):
      1. jsDelivr CDN family (4 бэкенда)
      2. raw.githubusercontent.com (HEAD default branch)
      3. github.com/.../releases/latest/download/
      4. 7 GitHub-прокси
      5. Statically CDN
    """
    return build_mirror_urls(
        owner=_TURNTUNNEL_OWNER,
        repo=_TURNTUNNEL_REPO,
        filename=_TURNTUNNEL_FILENAME,
        tag="latest",            # release-GitHub и gh-proxy: /latest/download/
        # ref по умолчанию = tag ("latest") — но jsDelivr/raw GitHub не имеют
        # ветки "latest". Для них build_mirror_urls формирует
        # /gh/.../...@latest/... и /latest/<filename> URL, которые ВЕДУТ в 404.
        # Это нормально: fetch_package() перебирает URL и первый же 404
        # пропускает, переходя к следующему. Рабочими остаются release-GitHub
        # и gh-proxy URLs (которые и составляют основу fallback).
        include_raw_github=False,   # нет ветки "latest" в raw GitHub
        include_statically=False,   # нет ветки "latest" в Statically
    )


def get_turnable_mirrors(version: str) -> list[str]:
    """Упорядоченный список URL для скачивания turnable binary.

    version — pinned tag из turnable.py (_TURNABLE_VERSION).

    Порядок (через build_mirror_urls):
      1. jsDelivr CDN family (4 бэкенда) — /gh/.../...@{version}/...
      2. raw.githubusercontent.com (branch {version} — обычно 404, но
         дёшево попробовать)
      3. github.com/.../releases/download/{version}/...
      4. 7 GitHub-прокси — /releases/download/{version}/...
      5. Statically CDN — /gh/.../.../{version}/...
    """
    return build_mirror_urls(
        owner=_TURNABLE_OWNER,
        repo=_TURNABLE_REPO,
        filename=_TURNABLE_FILENAME,
        tag=version,             # release-GitHub и gh-proxy: /download/{version}/
        # ref = tag = version — корректно для jsDelivr / Statically.
        # raw GitHub ветка {version} обычно не существует (теги ≠ ветки),
        # поэтому include_raw_github=False — пропускаем заведомо 404.
        include_raw_github=False,
    )


# ============================================================================
#  СЧЁТЧИКИ И ПУТИ РУЧНОГО РАЗМЕЩЕНИЯ
# ============================================================================

# Количество зеркал на каждый файл — вычисляется через build_mirror_urls.
# Используется для отображения в TUI ("14 зеркал в fallback").
# Ленивая инициализация (не дёргаем _is_amd64 на module-load).
TURNTUNNEL_MIRRORS_COUNT: int = len(get_turntunnel_mirrors())
TURNABLE_MIRRORS_COUNT: int = len(get_turnable_mirrors("0.4.1"))


# Пути ручного размещения для vk-turn-proxy.
# /root/ — РЕКОМЕНДУЕТСЯ (зелёным в TUI), WinSCP-friendly.
# /opt/vk-turn-proxy/ — альтернатива (совпадает с install_dest, поэтому
#   НЕ добавляется сюда: PackageSpec.__post_init__ assert запрещает
#   совпадение manual_incoming_dir с install_dest).
MANUAL_UPLOAD_PATHS_TURNTUNNEL: list[Path] = [
    Path("/root"),                       # ← РЕКОМЕНДУЕТСЯ (зелёным в TUI)
    Path("/usr/local/bin"),              # системная директория бинарников
]

# Пути ручного размещения для turnable.
# Аналогично: /opt/turnable/ — install_dest, не включаем сюда.
MANUAL_UPLOAD_PATHS_TURNABLE: list[Path] = [
    Path("/root"),
    Path("/usr/local/bin"),
]


def recommended_manual_path() -> Path:
    """Возвращает рекомендуемый путь для ручного размещения (первый в списке).

    Для обоих модулей это /root/ — WinSCP-friendly, не совпадает ни с одним
    install_dest.
    """
    return Path("/root")

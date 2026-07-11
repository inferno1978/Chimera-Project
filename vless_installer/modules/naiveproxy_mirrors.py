"""
vless_installer/modules/naiveproxy_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Централизованный реестр зеркал для скачивания caddy-forwardproxy-naive binary
(Michaol/caddy-naive) с GitHub Releases.

ПРОБЛЕМА (до миграции):
  naiveproxy.py::_download_binary() качал бинарник через ОДИН прямой URL
  (https://github.com/Michaol/caddy-naive/releases/latest/download/caddy-linux-amd64)
  БЕЗ зеркал, БЕЗ fallback, БЕЗ проверки ручного размещения.

  Если github.com заблокирован (что часто бывает в РФ), urllib.request.
  urlretrieve() выбрасывает исключение, вся установка падает.

РЕШЕНИЕ (по аналогии с turn_mirrors.py / hysteria2_mirrors.py):
  1. Реестр зеркал через github_mirrors.build_mirror_urls():
     jsDelivr CDN (4 бэкенда) + raw GitHub + release GitHub + 7 gh-proxy +
     Statically — итого до 14 URL.
  2. fetch_package(NAIVEPROXY_SPEC) из naiveproxy_packages.py перебирает
     зеркала по очереди и проверяет /root/ для ручного размещения.
  3. При тотальном провале fetch_package() вызывает print_manual_hint() из
     download_manager.py.

Особенность caddy-naive:
  • Upstream репозиторий: Michaol/caddy-naive (форк klzgrad/naiveproxy с
    предсобранным caddy-binary).
  • Бинарник в релизах: "caddy-linux-amd64" (без расширения).
  • Только amd64 (модуль naiveproxy.py явно отказывает на других arch).
  • /releases/latest/download/ — всегда последний релиз, без pinned tag.

Пути ручного размещения:
  /root/  ← РЕКОМЕНДУЕТСЯ (WinSCP-friendly)
  /tmp/   ← альтернатива

Точки входа:
    from vless_installer.modules.naiveproxy_mirrors import (
        get_naiveproxy_mirrors,
        NAIVEPROXY_MIRRORS_COUNT,
        MANUAL_UPLOAD_PATHS_NAIVEPROXY,
        recommended_manual_path,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from pathlib import Path

from vless_installer.modules.github_mirrors import build_mirror_urls


# ============================================================================
#  ПУБЛИЧНЫЕ КОНСТАНТЫ — репозиторий
# ============================================================================
_NAIVEPROXY_OWNER = "Michaol"
_NAIVEPROXY_REPO  = "caddy-naive"
_NAIVEPROXY_FILENAME = "caddy-linux-amd64"  # amd64 only, без расширения


# ============================================================================
#  СБОРЩИК URL
# ============================================================================
def get_naiveproxy_mirrors() -> list[str]:
    """Упорядоченный список URL для скачивания caddy-naive binary.

    Порядок (через build_mirror_urls из github_mirrors.py):
      1. jsDelivr CDN family (4 бэкенда)
      2. raw.githubusercontent.com (HEAD default branch — НЕ РАБОТАЕТ для
         release-assets, но дёшево попробовать; для tag="latest" отключаем)
      3. github.com/.../releases/latest/download/
      4. 7 GitHub-прокси
      5. Statically CDN (для tag="latest" — нет ветки, отключаем)

    Итого 12 URL: 4 jsDelivr + release + 7 gh-proxy (raw и Statically
    отключены для tag="latest", т.к. ветки "latest" не существует).
    """
    return build_mirror_urls(
        owner=_NAIVEPROXY_OWNER,
        repo=_NAIVEPROXY_REPO,
        filename=_NAIVEPROXY_FILENAME,
        tag="latest",            # release-GitHub и gh-proxy: /latest/download/
        # ref = "latest" — нет такой ветки, jsDelivr/raw/Statically дадут 404.
        # fetch_package перебирает URL и первый 404 пропускает.
        include_raw_github=False,   # нет ветки "latest"
        include_statically=False,   # нет ветки "latest"
    )


# Количество зеркал — 4 jsDelivr + release + 7 прокси = 12.
NAIVEPROXY_MIRRORS_COUNT: int = len(get_naiveproxy_mirrors())


# ============================================================================
#  ПУТИ РУЧНОГО РАЗМЕЩЕНИЯ
# ============================================================================
# /root/ — РЕКОМЕНДУЕТСЯ (зелёным в TUI), WinSCP-friendly.
# /tmp/ — альтернатива.
# /usr/local/bin/caddy-naive НЕ включаем — это install_dest (_BIN_PATH),
# PackageSpec.__post_init__ assert требует manual_dir != install_dests.
MANUAL_UPLOAD_PATHS_NAIVEPROXY: list[Path] = [
    Path("/root"),
    Path("/tmp"),
]


def recommended_manual_path() -> Path:
    """Возвращает рекомендуемый путь для ручного размещения."""
    return MANUAL_UPLOAD_PATHS_NAIVEPROXY[0]

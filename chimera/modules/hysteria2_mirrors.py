"""
chimera/modules/hysteria2_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Централизованный реестр зеркал для скачивания бинарника Hysteria2
(apernet/hysteria).

ПРОБЛЕМА (до миграции):
  • hysteria2_exit_mgr.py::_install_h2_binary() использовал inline список
    из 3 зеркал (прямой GitHub + ghproxy.net + mirror.ghproxy.com) через
    subprocess curl, БЕЗ проверки ручного размещения.
  • hysteria2_auto_update.py::h2_update_apply() использовал ОДИН прямой
    URL через curl, БЕЗ зеркал, БЕЗ проверки ELF magic (только запуск
    бинарника с `version`), БЕЗ проверки ручного размещения.

  Два модуля качали один и тот же бинарник двумя независимыми путями с
  разным поведением при сбое сети.

РЕШЕНИЕ (по аналогии с turn_mirrors.py / mieru_mirrors.py):
  1. Реестр зеркал через github_mirrors.build_mirror_urls():
     jsDelivr CDN (4 бэкенда) + raw GitHub + release GitHub + 7 gh-proxy +
     Statically — итого до 14 URL.
  2. fetch_package(HYSTERIA2_SPEC, arch=...) из hysteria2_packages.py
     перебирает зеркала по очереди и проверяет /root/ для ручного
     размещения.
  3. При тотальном провале fetch_package() вызывает print_manual_hint() из
     download_manager.py.

Особенность версионирования Hysteria2:
  • Upstream использует теги вида "app/v2.9.3" (с префиксом "app/").
  • GitHub Releases API возвращает tag_name="app/v2.9.3" и список assets.
  • Имя бинарника в релизах: "hysteria-linux-{arch}" (без расширения).
  • Asset URL: https://github.com/apernet/hysteria/releases/download/app/v2.9.3/hysteria-linux-amd64

  Проблема: build_mirror_urls(tag="app/v2.9.3") формирует:
    /releases/download/app/v2.9.3/hysteria-linux-amd64 — корректно
    /gh/apernet/hysteria@app/v2.9.3/hysteria-linux-amd64 — НЕ корректно,
      т.к. jsDelivr использует синтаксис @{ref}, но "app/v2.9.3" содержит
      слеш, jsDelivr не примет такой ref.
  Решение: для jsDelivr/raw GitHub/Statically используем branch "app"
    (по умолчанию в репо apernet/hysteria), а release GitHub и gh-proxy —
    полный tag "app/v2.9.3". Это даёт корректные URL для обоих случаев.
    Альтернатива: отключить jsDelivr/raw/Statically (как в turn_mirrors
    для tag="latest") — но тогда теряется CDN-fallback, что плохо для РФ.

Архитектура:
  • _h2_latest_url() в hysteria2_exit_mgr.py ОСТАЁТСЯ — это API metadata
    (читает tag_name из GitHub Releases API), не install artifact. Non-
    migration согласно правилам задачи.
  • Зеркала для самого бинарника строятся здесь, в hysteria2_mirrors.py.

Пути ручного размещения:
  /root/  ← РЕКОМЕНДУЕТСЯ (WinSCP-friendly)
  /tmp/   ← альтернатива

Точки входа:
    from chimera.modules.hysteria2_mirrors import (
        get_hysteria2_mirrors,
        HYSTERIA2_MIRRORS_COUNT,
        MANUAL_UPLOAD_PATHS_HYSTERIA2,
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
_H2_OWNER = "apernet"
_H2_REPO  = "hysteria"

# Имя файла бинарника в релизах (без расширения — upstream так решил).
# Архитектура подставляется в get_hysteria2_mirrors(arch=...).
_H2_FILENAME_TEMPLATE = "hysteria-linux-{arch}"


# ============================================================================
#  СБОРЩИК URL
# ============================================================================
def get_hysteria2_mirrors(
    tag: str = "latest",
    arch: str = "amd64",
) -> list[str]:
    """Упорядоченный список URL для скачивания Hysteria2 binary.

    Параметры:
      tag:  Release tag. Возможные значения:
              "latest" — для /releases/latest/download/ URL (по умолчанию,
                          используется когда версия неизвестна).
              "app/v2.9.3" — конкретный тег для /releases/download/{tag}/.
      arch: Архитектура ('amd64', 'arm64', 'arm').

    Возвращает:
      Упорядоченный список URL:
        1. jsDelivr CDN family (4 бэкенда) — через @app ветку (jsDelivr не
           принимает ref со слешем).
        2. raw.githubusercontent.com/app/{filename} — branch "app".
        3. release GitHub (/releases/latest/download/ или /releases/download/{tag}/).
        4. 7 GitHub-прокси — с полным tag.
        5. Statically CDN — через /app/ ветку.

    Особенность: для tag="app/vX.Y.Z" jsDelivr/raw/Statically используют
    branch "app" (без версии), что может отдать устаревший бинарник.
    Поэтому основной путь — release GitHub (URL #6 в общем порядке),
    jsDelivr/raw/Statically — fallback для случаев когда github.com
    заблокирован, но CDN доступны.
    """
    filename = _H2_FILENAME_TEMPLATE.format(arch=arch)

    # Для jsDelivr/raw/Statically используем ref="app" (имя default branch
    # в репо apernet/hysteria). Это НЕ версия, а branch — jsDelivr принимает
    # @branch-name без слешей.
    return build_mirror_urls(
        owner=_H2_OWNER,
        repo=_H2_REPO,
        filename=filename,
        tag=tag,
        ref="app",  # branch для jsDelivr/raw/Statically
    )


# Количество зеркал — вычисляется через build_mirror_urls.
# Для tag="latest": 4 jsDelivr + raw + release + 7 proxy + Statically = 14.
HYSTERIA2_MIRRORS_COUNT: int = len(get_hysteria2_mirrors())


# ============================================================================
#  ПУТИ РУЧНОГО РАЗМЕЩЕНИЯ
# ============================================================================
# /root/ — РЕКОМЕНДУЕТСЯ (зелёным в TUI), WinSCP-friendly.
# /tmp/ — альтернатива.
# /usr/local/bin/hysteria НЕ включаем — это install_dest (H2_BINARY из
# hysteria2_common), PackageSpec.__post_init__ assert требует
# manual_dir != install_dests.
MANUAL_UPLOAD_PATHS_HYSTERIA2: list[Path] = [
    Path("/root"),
    Path("/tmp"),
]


def recommended_manual_path() -> Path:
    """Возвращает рекомендуемый путь для ручного размещения."""
    return MANUAL_UPLOAD_PATHS_HYSTERIA2[0]

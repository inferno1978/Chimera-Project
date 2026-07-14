"""
chimera/modules/olcrtc_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Централизованный реестр зеркал для скачивания olcrtc source tarball
(openlibrecommunity/olcrtc, branch master).

ПРОБЛЕМА (до миграции):
  olcrtc.py::_olcrtc_clone_or_update() использовал `git clone --depth 1`
  (или `git pull --ff-only` для обновления), БЕЗ зеркал, БЕЗ fallback.

  Если github.com заблокирован, установка olcrtc невозможна.

РЕШЕНИЕ (Wave 6 — Variant A согласно анализу):
  • HTTP tarball через github_mirrors.build_source_archive_mirror_urls():
    прямой GitHub + codeload + 7 gh-proxy = 9 URL.
  • Build: `go build` (pure Go, не требует .git/).
  • Commit SHA для state file: получается через отдельный GitHub API call
    к /commits/master (вместо `git rev-parse --short HEAD`).

Особенность olcrtc:
  • Branch: master (НЕ main — подтверждено через GitHub API).
  • Build: `go build -trimpath -ldflags "-s -w" -o /usr/local/bin/olcrtc
    ./cmd/olcrtc` (env: CGO_ENABLED=0, GOOS=linux, GOARCH={amd64,arm64}).
  • go.mod требует Go 1.26.3+.
  • Commit SHA ранее получался через `git rev-parse --short HEAD` — теперь
    через отдельный API call (см. olcrtc.py::_olcrtc_fetch_commit_sha).

Пути ручного размещения:
  /root/  ← РЕКОМЕНДУЕТСЯ (WinSCP-friendly)
  /tmp/   ← альтернатива

Точки входа:
    from chimera.modules.olcrtc_mirrors import (
        get_olcrtc_source_mirrors,
        OLCRTC_SOURCE_MIRRORS_COUNT,
        MANUAL_UPLOAD_PATHS_OLCRTC,
        recommended_manual_path,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from pathlib import Path

from chimera.modules.github_mirrors import build_source_archive_mirror_urls


# ============================================================================
#  ПУБЛИЧНЫЕ КОНСТАНТЫ — репозиторий
# ============================================================================
_OLCRTC_OWNER = "openlibrecommunity"
_OLCRTC_REPO  = "olcrtc"
_OLCRTC_BRANCH = "master"   # подтверждено через GitHub API (НЕ main)

# GitHub API endpoint для получения SHA последнего коммита.
# Используется вместо `git rev-parse --short HEAD` (т.к. .git/ отсутствует
# при Variant A — HTTP tarball).
_OLCRTC_COMMITS_API = (
    f"https://api.github.com/repos/{_OLCRTC_OWNER}/{_OLCRTC_REPO}/commits/{_OLCRTC_BRANCH}"
)


# ============================================================================
#  СБОРЩИК URL
# ============================================================================
def get_olcrtc_source_mirrors() -> list[str]:
    """Упорядоченный список URL для скачивания olcrtc source tarball.

    Использует build_source_archive_mirror_urls (прямой GitHub + codeload +
    7 gh-proxy = 9 URL). Branch: master.

    Build: `go build` (pure Go, не требует .git/).
    """
    return build_source_archive_mirror_urls(
        owner=_OLCRTC_OWNER,
        repo=_OLCRTC_REPO,
        branch=_OLCRTC_BRANCH,
    )


def get_olcrtc_commits_api_url() -> str:
    """Возвращает URL GitHub API для получения SHA последнего коммита.

    Используется вместо `git rev-parse --short HEAD` при Variant A.
    """
    return _OLCRTC_COMMITS_API


# Количество зеркал — 1 прямой + 1 codeload + 7 прокси = 9.
OLCRTC_SOURCE_MIRRORS_COUNT: int = len(get_olcrtc_source_mirrors())


# ============================================================================
#  ПУТИ РУЧНОГО РАЗМЕЩЕНИЯ
# ============================================================================
# /root/ — РЕКОМЕНДУЕТСЯ (зелёным в TUI), WinSCP-friendly.
# /tmp/ — альтернатива.
MANUAL_UPLOAD_PATHS_OLCRTC: list[Path] = [
    Path("/root"),
    Path("/tmp"),
]


def recommended_manual_path() -> Path:
    """Возвращает рекомендуемый путь для ручного размещения."""
    return MANUAL_UPLOAD_PATHS_OLCRTC[0]

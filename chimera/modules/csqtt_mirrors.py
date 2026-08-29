#!/usr/bin/env python3
"""
chimera/modules/csqtt_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Зеркала для скачивания исходников CSQTT с GitHub.

CSQTT — сервер на Rust (io_uring + TUN + Web Panel), маскирующий
туннельный трафик под зашифрованный RTP/TURN медиатрафик.

Репозиторий: https://github.com/amurcanov/csqtt
Ветка: main
"""
from pathlib import Path

from chimera.modules.github_mirrors import build_source_archive_mirror_urls

_CSQTT_OWNER   = "amurcanov"
_CSQTT_REPO    = "csqtt"
_CSQTT_BRANCH  = "main"
_CSQTT_FILENAME = "csqtt-main.tar.gz"


def get_csqtt_source_mirrors() -> list[str]:
    """Возвращает список зеркал для скачивания исходников CSQTT."""
    return build_source_archive_mirror_urls(
        owner=_CSQTT_OWNER, repo=_CSQTT_REPO, branch=_CSQTT_BRANCH,
    )


CSQTT_SOURCE_MIRRORS_COUNT: int = len(get_csqtt_source_mirrors())

MANUAL_UPLOAD_PATHS_CSQTT: list[Path] = [Path("/root"), Path("/tmp")]


def recommended_manual_path() -> Path:
    return MANUAL_UPLOAD_PATHS_CSQTT[0]

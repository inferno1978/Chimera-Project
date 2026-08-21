"""
chimera/modules/dnscrypt_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Централизованный реестр зеркал для скачивания dnscrypt-proxy binary
(DNSCrypt/dnscrypt-proxy) как tar.gz-архива из GitHub Releases.

ПРОБЛЕМА (до миграции):
  dnscrypt_setup.py::install_dnscrypt() качал tar.gz через ОДИН прямой URL
  (https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/{tag}/
  dnscrypt-proxy-{arch}-{tag}.tar.gz) БЕЗ зеркал, БЕЗ fallback, БЕЗ
  проверки ручного размещения. Только curl с --retry 3 (повтор того же URL).

  Если github.com заблокирован (что часто бывает в РФ), установка
  DNSCrypt-proxy тихо падает, и Xray использует публичные DNS (1.1.1.1 /
  8.8.8.8) — что раскрывает запросы провайдеру.

РЕШЕНИЕ (по аналогии с mieru_mirrors.py):
  1. Реестр зеркал через github_mirrors.build_mirror_urls():
     jsDelivr CDN (4 бэкенда) + raw GitHub + release GitHub + 3 gh-proxy +
     Statically — итого до 10 URL.
  2. fetch_package(DNSCRYPT_SPEC, tag=..., arch=...) из dnscrypt_packages.py
     перебирает зеркала по очереди и проверяет /root/ для ручного размещения.
  3. При тотальном провале fetch_package() вызывает print_manual_hint() из
     download_manager.py.

Особенность версионирования dnscrypt-proxy:
  • GitHub Releases API возвращает tag_name="2.1.5" (без префикса "v").
  • Asset URL: /releases/download/2.1.5/dnscrypt-proxy-linux_x86_64-2.1.5.tar.gz
  • Имя файла ВКЛЮЧАЕТ версию: "dnscrypt-proxy-{arch}-{tag}.tar.gz"
    (в отличие от mieru, где версия только в пути, не в имени).
  • build_mirror_urls(tag=tag) формирует /releases/download/{tag}/... —
    корректно.
  • jsDelivr/raw/Statically используют ref=tag — но тег "2.1.5" без префикса
    "v" принимается всеми зеркалами корректно (в отличие от "app/v2.9.3"
    в hysteria2).

Архитектура:
  • Запрос tag_name через GitHub API ОСТАЁТСЯ в dnscrypt_setup.py — это
    API metadata (non-migration). Если API недоступен, dnscrypt_setup
    возвращает warn и пропускает установку.
  • Зеркала для самого tarball'а строятся здесь, в dnscrypt_mirrors.py.

Пути ручного размещения:
  /root/  ← РЕКОМЕНДУЕТСЯ (WinSCP-friendly)
  /tmp/   ← альтернатива

Точки входа:
    from chimera.modules.dnscrypt_mirrors import (
        get_dnscrypt_mirrors,
        DNSCRYPT_MIRRORS_COUNT,
        MANUAL_UPLOAD_PATHS_DNSCRYPT,
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
_DNSCRYPT_OWNER = "DNSCrypt"
_DNSCRYPT_REPO  = "dnscrypt-proxy"


# ============================================================================
#  СБОРЩИК URL
# ============================================================================
def get_dnscrypt_mirrors(tag: str, arch: str = "linux_x86_64") -> list[str]:
    """Упорядоченный список URL для скачивания dnscrypt-proxy tar.gz.

    Параметры:
      tag:  Release tag (например "2.1.5", БЕЗ префикса "v").
            Получается из GitHub API в dnscrypt_setup.py.
      arch: Архитектура в формате dnscrypt (например "linux_x86_64",
            "linux_arm64", "linux_arm", "linux_386").

    Возвращает:
      Упорядоченный список URL (через build_mirror_urls):
        1. jsDelivr CDN family (4 бэкенда) — /gh/DNSCrypt/dnscrypt-proxy@{tag}/...
        2. raw.githubusercontent.com/{tag}/{filename}
        3. release GitHub (/releases/download/{tag}/{filename})
        4. 7 GitHub-прокси — /releases/download/{tag}/{filename}
        5. Statically CDN — /gh/DNSCrypt/dnscrypt-proxy/{tag}/{filename}

    Имя файла: "dnscrypt-proxy-{arch}-{tag}.tar.gz" (версия ВКЛЮЧЕНА в имя).
    """
    if not tag:
        return []
    filename = f"dnscrypt-proxy-{arch}-{tag}.tar.gz"

    return build_mirror_urls(
        owner=_DNSCRYPT_OWNER,
        repo=_DNSCRYPT_REPO,
        filename=filename,
        tag=tag,
        # ref по умолчанию = tag. Для dnscrypt это работает корректно —
        # тег "2.1.5" без слешей, jsDelivr/raw/Statically принимают его.
    )


# Количество зеркал — вычисляется через build_mirror_urls.
# Для tag="2.1.5": 4 jsDelivr + raw + release + 3 proxy + Statically = 10.
DNSCRYPT_MIRRORS_COUNT: int = 10  # константа для TUI (не дёргаем API при import)


# ============================================================================
#  ПУТИ РУЧНОГО РАЗМЕЩЕНИЯ
# ============================================================================
# /root/ — РЕКОМЕНДУЕТСЯ (зелёным в TUI), WinSCP-friendly.
# /tmp/ — альтернатива.
# /usr/local/bin/dnscrypt-proxy НЕ включаем — это install_dest для извлечённого
# бинарника, PackageSpec.__post_init__ assert требует manual_dir != install_dests.
MANUAL_UPLOAD_PATHS_DNSCRYPT: list[Path] = [
    Path("/root"),
    Path("/tmp"),
]


def recommended_manual_path() -> Path:
    """Возвращает рекомендуемый путь для ручного размещения."""
    return MANUAL_UPLOAD_PATHS_DNSCRYPT[0]

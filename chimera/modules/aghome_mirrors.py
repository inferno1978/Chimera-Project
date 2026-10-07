"""
chimera/modules/aghome_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Централизованный реестр зеркал для скачивания AdGuard Home binary
(AdguardTeam/AdGuardHome) как tar.gz-архива из GitHub Releases.

ОТЛИЧИЕ от dnscrypt_mirrors.py:
  Релизные asset'ы AdGuardHome НЕ лежат в git-дереве репозитория, поэтому
  jsDelivr CDN / raw.githubusercontent.com / Statically CDN БЕСПОЛЕЗНЫ —
  они отдают только файлы репозитория, а не release-ассеты (404).
  Вместо них используется официальный CDN AdGuard — static.adtidy.org,
  который хостит release-канал независимо от GitHub (важно для РФ,
  где github.com часто блокируется).

Порядок зеркал:
  1. GitHub Releases (/releases/download/{tag}/{filename}) — version-pinned
  2. GitHub-прокси family (GITHUB_PROXY_HOSTS) — version-pinned
  3. static.adtidy.org — официальный CDN AdGuard (release-канал, latest)
  4. GitHub Releases latest (/releases/latest/download/{filename}) — latest

Особенности версионирования AdGuardHome:
  • GitHub API возвращает tag_name="v0.107.62" (С префиксом "v").
  • Asset URL: /releases/download/v0.107.62/AdGuardHome_linux_amd64.tar.gz
  • Имя файла НЕ включает версию: "AdGuardHome_{goos}_{goarch}.tar.gz"
    (в отличие от dnscrypt-proxy, где версия в имени файла).
  • Архитектуры: amd64 / arm64 / armv7 / armv6 / armv5 / 386 / mips*.
    Маппинг uname -m → GOARCH делает aghome_setup.py.

Архитектура:
  • Запрос tag_name через GitHub API ОСТАЁТСЯ в aghome_setup.py — это
    API metadata. При недоступности API используется pinned-версия
    (AGH_FALLBACK_TAG) + зеркало static.adtidy.org (latest-канал).
  • Зеркала для самого tarball'а строятся здесь, в aghome_mirrors.py.

Пути ручного размещения:
  /root/  ← РЕКОМЕНДУЕТСЯ (WinSCP-friendly)
  /tmp/   ← альтернатива

Точки входа:
    from chimera.modules.aghome_mirrors import (
        get_aghome_mirrors,
        AGHOME_FALLBACK_TAG,
        MANUAL_UPLOAD_PATHS_AGHOME,
        recommended_manual_path,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from pathlib import Path

from chimera.modules.github_mirrors import GITHUB_PROXY_HOSTS


# ============================================================================
#  ПУБЛИЧНЫЕ КОНСТАНТЫ — репозиторий
# ============================================================================
AGHOME_OWNER = "AdguardTeam"
AGHOME_REPO  = "AdGuardHome"

# Pinned-версия: используется когда GitHub API недоступен (rate-limit /
# блокировка). static.adtidy.org отдаёт latest — тег используется только
# для GitHub-зеркал; при провале всех version-pinned URL fallback-канал
# отдаст актуальный release.
# (2026-08-28): v0.107.62 → v0.107.79 — синхронизировано с release-
# каналом static.adtidy.org (проверено: отдаёт v0.107.79 от 2026-08-18;
# инцидент переустановки <ip> ставил устаревший v0.107.62).
AGHOME_FALLBACK_TAG = "v0.107.79"

#: Дополнительные GitHub-прокси, проверенные для release-ассетов
#: AdGuardHome (2026-08-28, HTTP 200 + корректный Content-Length).
#: НЕ входят в общий GITHUB_PROXY_HOSTS — тот список общесетевой и
#: консервативен; AGH-специфичные хосты не должны влиять на загрузки
#: других пакетов. ghproxy.net из общего списка в августе 2026 был
#: недоступен — независимый набор повышает шансы на автоскачивание.
_AGHOME_EXTRA_PROXY_HOSTS: tuple[str, ...] = (
    "ghfast.top",
    "gh.ddlc.top",
)


# ============================================================================
#  СБОРЩИК URL
# ============================================================================
def get_aghome_mirrors(tag: str, arch: str = "amd64") -> list[str]:
    """Упорядоченный список URL для скачивания AdGuardHome tar.gz.

    Параметры:
      tag:  Release tag (например "v0.107.62", С префиксом "v").
            Получается из GitHub API в aghome_setup.py.
      arch: GOARCH (например "amd64", "arm64", "armv7", "386").

    Возвращает:
      Упорядоченный список URL:
        1. GitHub Releases (/releases/download/{tag}/{filename})
        2. GitHub-прокси family (GITHUB_PROXY_HOSTS) — те же URL через прокси
        3. static.adtidy.org — официальный CDN AdGuard (release-канал, latest)
        4. GitHub Releases latest (/releases/latest/download/{filename})

    Имя файла: "AdGuardHome_linux_{arch}.tar.gz" (версия НЕ в имени файла).
    """
    if not tag or not arch:
        return []
    filename = f"AdGuardHome_linux_{arch}.tar.gz"

    urls: list[str] = []

    # 1) GitHub Releases — version-pinned
    urls.append(
        f"https://github.com/{AGHOME_OWNER}/{AGHOME_REPO}/"
        f"releases/download/{tag}/{filename}"
    )

    # 2) GitHub-прокси family — version-pinned
    for proxy_host in GITHUB_PROXY_HOSTS:
        if not proxy_host:
            continue
        urls.append(
            f"https://{proxy_host}/https://github.com/{AGHOME_OWNER}/{AGHOME_REPO}/"
            f"releases/download/{tag}/{filename}"
        )

    # 2.5) AGH-специфичные доп. прокси (проверены 2026-08-28,
    #      отдают корректный tarball того же размера, что github.com)
    for proxy_host in _AGHOME_EXTRA_PROXY_HOSTS:
        if not proxy_host:
            continue
        urls.append(
            f"https://{proxy_host}/https://github.com/{AGHOME_OWNER}/{AGHOME_REPO}/"
            f"releases/download/{tag}/{filename}"
        )

    # 3) Официальный CDN AdGuard — latest release-канал.
    #    Не зависит от GitHub вообще (главный fallback для РФ).
    # поднят на позицию выше GitHub-latest — быстрее и стабильнее
    #    прокси-хостов (Qrator CDN, Франкфурт).
    urls.append(f"https://static.adtidy.org/adguardhome/release/{filename}")

    # 4) GitHub Releases latest (без тега — редирект на последний release)
    urls.append(
        f"https://github.com/{AGHOME_OWNER}/{AGHOME_REPO}/"
        f"releases/latest/download/{filename}"
    )

    return urls


# ============================================================================
#  ПУТИ РУЧНОГО РАЗМЕЩЕНИЯ
# ============================================================================
# /root/ — РЕКОМЕНДУЕТСЯ (зелёным в TUI), WinSCP-friendly.
# /tmp/ — альтернатива.
# /usr/local/bin/AdGuardHome НЕ включаем — это install_dest для извлечённого
# бинарника, PackageSpec.__post_init__ assert требует manual_dir != install_dests.
MANUAL_UPLOAD_PATHS_AGHOME: list[Path] = [
    Path("/root"),
    Path("/tmp"),
]


def recommended_manual_path() -> Path:
    """Возвращает рекомендуемый путь для ручного размещения."""
    return MANUAL_UPLOAD_PATHS_AGHOME[0]

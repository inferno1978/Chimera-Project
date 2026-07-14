"""
chimera/modules/github_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Параметризованный генератор GitHub-зеркал.

Архитектурно решает проблему 3+ независимых копий одной и той же логики
зеркал (geo_mirrors.py, mieru_mirrors.py, telemt_mirrors.py). Вместо
хардкода owner/repo в замыканиях — параметризованные фабрики URL,
принимающие owner/repo/ref/tag/filename как аргументы.

Все существующие *_mirrors.py модули НЕ трогаются на этом этапе —
миграция будет отдельным шагом. Этот модуль живёт рядом и готов к
использованию через download_manager.py.

Порядок зеркал в build_mirror_urls():
  1. jsDelivr CDN family (4 бэкенда по умолчанию)
  2. raw GitHub (raw.githubusercontent.com)
  3. release GitHub (releases/latest/download или releases/download/{tag}/)
  4. GitHub-прокси (7 хостов по умолчанию)
  5. Statically CDN

Этот порядок совпадает с geo_mirrors.py — для эквивалентных входных
параметров build_mirror_urls() даёт БИТ-В-БИТ те же URL, что
geo_mirrors.get_geosite_urls().

Для mieru_mirrors и telemt_mirrors порядок отличается (release GitHub
первый, jsDelivr последний/отсутствует) — это будет reconciliровано
при миграции. На этом этапе важна корректность URL-форматов, не порядок.

Точки входа:
    from chimera.modules.github_mirrors import (
        jsdelivr_url, raw_github_url, release_github_url,
        gh_proxy_url, statically_url,
        GITHUB_PROXY_HOSTS,
        build_mirror_urls,
    )
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from typing import Optional


# ============================================================================
#  ПУБЛИЧНЫЕ КОНСТАНТЫ
# ============================================================================

#: Список GitHub-прокси-хостов (китайские + комьюнити CDN).
#: Порядок важен — соответствует порядку в существующих *_mirrors.py модулях.
GITHUB_PROXY_HOSTS: list[str] = [
    "ghproxy.net",
    "ghproxy.com",
    "mirror.ghproxy.com",
    "gh.con.sh",
    "hub.gitmirror.com",
    "github.moeyy.xyz",
    "ghps.cc",
]

#: jsDelivr CDN бэкенды (4 хоста). У каждого свои рейт-лимиты и доступность.
JSDELIVR_HOSTS: tuple[str, ...] = (
    "cdn.jsdelivr.net",
    "gcore.jsdelivr.net",
    "fastly.jsdelivr.net",
    "testingcf.jsdelivr.net",
)


# ============================================================================
#  ПАРАМЕТРИЗОВАННЫЕ ФАБРИКИ URL
# ============================================================================
# Каждая фабрика принимает owner/repo/ref-or-tag/filename как аргументы
# и возвращает полный URL. НЕ хардкодят owner/repo в замыкании — в отличие
# от существующих *_mirrors.py где _jsdelivr("cdn.jsdelivr.net") возвращает
# лямбду с захваченным owner/repo.

def jsdelivr_url(owner: str, repo: str, ref: str, filename: str) -> str:
    """jsDelivr CDN URL.

    ref — это branch name (например "release", "main") или tag (например
    "v1.2.3"). jsDelivr использует синтаксис @ref.

    Пример: jsdelivr_url("runetfreedom", "russia-v2ray-rules-dat", "release", "geosite.dat")
        → https://cdn.jsdelivr.net/gh/runetfreedom/russia-v2ray-rules-dat@release/geosite.dat
    """
    return f"https://cdn.jsdelivr.net/gh/{owner}/{repo}@{ref}/{filename}"


def raw_github_url(owner: str, repo: str, branch: str, filename: str) -> str:
    """raw.githubusercontent.com URL.

    branch — это branch name (например "release", "main").

    Пример: raw_github_url("runetfreedom", "russia-v2ray-rules-dat", "release", "geosite.dat")
        → https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat
    """
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{filename}"


def release_github_url(owner: str, repo: str, tag: str, filename: str) -> str:
    """GitHub release-assets URL.

    tag может быть:
      "latest"  → releases/latest/download/{filename}
      "v1.2.3"  → releases/download/v1.2.3/{filename}

    Пример: release_github_url("runetfreedom", "russia-v2ray-rules-dat", "latest", "geosite.dat")
        → https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat
    """
    if tag == "latest":
        return f"https://github.com/{owner}/{repo}/releases/latest/download/{filename}"
    return f"https://github.com/{owner}/{repo}/releases/download/{tag}/{filename}"


def gh_proxy_url(proxy_host: str, owner: str, repo: str, tag: str, filename: str) -> str:
    """GitHub-прокси URL.

    Прокси принимает полный GitHub release-assets URL после своего домена.
    tag работает так же как в release_github_url().

    Пример: gh_proxy_url("ghproxy.net", "runetfreedom", "russia-v2ray-rules-dat", "latest", "geosite.dat")
        → https://ghproxy.net/https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat
    """
    if tag == "latest":
        return (
            f"https://{proxy_host}/https://github.com/{owner}/{repo}/"
            f"releases/latest/download/{filename}"
        )
    return (
        f"https://{proxy_host}/https://github.com/{owner}/{repo}/"
        f"releases/download/{tag}/{filename}"
    )


def statically_url(owner: str, repo: str, ref: str, filename: str) -> str:
    """Statically CDN URL.

    ref — это branch name или tag. Statically использует синтаксис /ref/.

    Пример: statically_url("runetfreedom", "russia-v2ray-rules-dat", "release", "geosite.dat")
        → https://cdn.statically.io/gh/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat
    """
    return f"https://cdn.statically.io/gh/{owner}/{repo}/{ref}/{filename}"


# ============================================================================
#  СБОРЩИК URL
# ============================================================================

def build_mirror_urls(
    owner: str,
    repo: str,
    filename: str,
    tag: str = "latest",
    *,
    ref: Optional[str] = None,
    jsdelivr_hosts: tuple[str, ...] = JSDELIVR_HOSTS,
    include_raw_github: bool = True,
    include_release_github: bool = True,
    include_statically: bool = True,
    proxy_hosts: list[str] | None = None,
) -> list[str]:
    """Собирает упорядоченный список URL для скачивания.

    Порядок (совпадает с geo_mirrors.py):
      1. jsDelivr CDN family (4 бэкенда по умолчанию)
      2. raw GitHub (raw.githubusercontent.com) — если include_raw_github
      3. release GitHub (releases/latest/download или releases/download/{tag}/)
         — если include_release_github
      4. GitHub-прокси family (7 хостов по умолчанию)
      5. Statically CDN — если include_statically

    Параметры:
      owner:           GitHub owner (например "runetfreedom")
      repo:            GitHub repo (например "russia-v2ray-rules-dat")
      filename:        Имя файла (например "geosite.dat")
      tag:             Release tag — "latest" или конкретная версия ("v1.2.3").
                       Используется для release GitHub и gh-proxy URLs.
      ref:             Branch/tag для jsDelivr/raw GitHub/Statically.
                       По умолчанию = tag. Для geo: ref="release", tag="latest".
      jsdelivr_hosts:  Кортеж jsDelivr CDN хостов (по умолчанию 4).
      include_raw_github:    Включать raw.githubusercontent.com URL.
      include_release_github: Включать GitHub release-assets URL.
      include_statically:    Включать Statically CDN URL.
      proxy_hosts:     Список GitHub-прокси хостов (по умолчанию GITHUB_PROXY_HOSTS).

    Возвращает:
      Упорядоченный список URL для скачивания по очереди.

    Бит-в-бит совместимость с geo_mirrors.py:
      build_mirror_urls(
          owner="runetfreedom",
          repo="russia-v2ray-rules-dat",
          filename="geosite.dat",
          tag="latest",
          ref="release",
      )
      даёт ТОТ ЖЕ список URL что geo_mirrors.get_geosite_urls().
    """
    if ref is None:
        ref = tag
    if proxy_hosts is None:
        proxy_hosts = GITHUB_PROXY_HOSTS

    # Валидация — разумное поведение для пустых/некорректных входов
    if not owner or not repo or not filename:
        return []

    urls: list[str] = []

    # 1) jsDelivr CDN family
    for host in jsdelivr_hosts:
        if not host:
            continue
        urls.append(f"https://{host}/gh/{owner}/{repo}@{ref}/{filename}")

    # 2) raw GitHub
    if include_raw_github:
        urls.append(f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{filename}")

    # 3) release GitHub
    if include_release_github:
        if tag == "latest":
            urls.append(f"https://github.com/{owner}/{repo}/releases/latest/download/{filename}")
        else:
            urls.append(f"https://github.com/{owner}/{repo}/releases/download/{tag}/{filename}")

    # 4) GitHub-прокси family
    for proxy_host in proxy_hosts:
        if not proxy_host:
            continue
        if tag == "latest":
            urls.append(
                f"https://{proxy_host}/https://github.com/{owner}/{repo}/"
                f"releases/latest/download/{filename}"
            )
        else:
            urls.append(
                f"https://{proxy_host}/https://github.com/{owner}/{repo}/"
                f"releases/download/{tag}/{filename}"
            )

    # 5) Statically CDN
    if include_statically:
        urls.append(f"https://cdn.statically.io/gh/{owner}/{repo}/{ref}/{filename}")

    return urls


# ============================================================================
#  СБОРЩИК URL ДЛЯ SOURCE-АРХИВОВ (archive/refs/heads/{branch}.tar.gz)
# ============================================================================
# Отдельная функция от build_mirror_urls(), т.к. source-архивы живут по
# другому пути (archive/refs/heads/...) и поддерживаются другим набором
# зеркал. jsDelivr CDN НЕ поддерживает выдачу tarball'а репозитория целиком
# (только отдельные файлы через /gh/...), поэтому здесь отсутствует.
# Statically CDN аналогично — только отдельные файлы.
#
# Применение: wdtt.py (proxy-turn-vk-android-master.tar.gz),
# webdav_tunnel.py (webdav-tunnel-main.tar.gz), а также потенциально
# git-clone случаи (Wave 6) — Variant A (HTTP tarball вместо git clone).

def build_source_archive_mirror_urls(
    owner: str,
    repo: str,
    branch: str = "main",
    *,
    include_codeload: bool = True,
    proxy_hosts: list[str] | None = None,
) -> list[str]:
    """Собирает упорядоченный список URL для скачивания исходников репозитория
    как tar.gz-архива ветки.

    Порядок:
      1. Прямой GitHub: https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.tar.gz
      2. Codeload (отдельный домен GitHub для tarball'ов, чуть быстрее):
         https://codeload.github.com/{owner}/{repo}/tar.gz/refs/heads/{branch}
      3. GitHub-прокси family (7 хостов по умолчанию) — каждый оборачивает
         прямой GitHub URL.

    Параметры:
      owner:           GitHub owner (например "SpaceNeuroX")
      repo:            GitHub repo (например "proxy-turn-vk-android")
      branch:          Ветка для архива (например "master", "main").
      include_codeload: Включать codeload.github.com URL (по умолчанию True).
      proxy_hosts:     Список GitHub-прокси хостов (по умолчанию GITHUB_PROXY_HOSTS).

    Возвращает:
      Упорядоченный список URL.

    Пример:
      build_source_archive_mirror_urls("SpaceNeuroX", "proxy-turn-vk-android", "master")
        → [
            "https://github.com/SpaceNeuroX/proxy-turn-vk-android/archive/refs/heads/master.tar.gz",
            "https://codeload.github.com/SpaceNeuroX/proxy-turn-vk-android/tar.gz/refs/heads/master",
            "https://ghproxy.net/https://github.com/SpaceNeuroX/proxy-turn-vk-android/archive/refs/heads/master.tar.gz",
            ...
          ]

    Отличия от build_mirror_urls():
      • jsDelivr/Statically НЕ поддерживают tarball целиком — отсутствуют.
      • raw GitHub неприменим (это для отдельных файлов, не архивов).
      • release-assets неприменим (это для релизных артефактов, не исходников
        ветки).
      • Добавлен codeload.github.com — официальный домен GitHub для tarball'ов,
        работает быстрее основного домена на больших архивах.
    """
    if proxy_hosts is None:
        proxy_hosts = GITHUB_PROXY_HOSTS

    # Валидация
    if not owner or not repo or not branch:
        return []

    urls: list[str] = []

    # 1) Прямой GitHub
    urls.append(
        f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.tar.gz"
    )

    # 2) Codeload (альтернативный домен GitHub)
    if include_codeload:
        urls.append(
            f"https://codeload.github.com/{owner}/{repo}/tar.gz/refs/heads/{branch}"
        )

    # 3) GitHub-прокси family — каждый прокси оборачивает полный GitHub URL
    for proxy_host in proxy_hosts:
        if not proxy_host:
            continue
        urls.append(
            f"https://{proxy_host}/https://github.com/{owner}/{repo}/"
            f"archive/refs/heads/{branch}.tar.gz"
        )

    return urls

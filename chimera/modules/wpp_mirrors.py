#!/usr/bin/env python3
"""
chimera/modules/wpp_mirrors.py
────────────────────────────────────────────────────────────────────────────────
Mirror ladder для скачивания тарбола WPP-фронтенда.

Источники (в порядке приоритета):
  1. GitLab raw (chimera-v5 branch) — fastest, no auth, public CDN, works in RU
  2. jsDelivr CDN (serves files from our GitHub repo) — global edge cache
  3. GitHub raw — public, may have CDN delay for large binary files
  4. GitHub release asset (release wpp-v2.4.2)
  5. canonical codeload tarball endpoint (upstream POLESNIESOVETI12) — DEAD
     since upstream repo was deleted from GitHub, kept as legacy fallback
  6-11. gh-proxy зеркала upstream'а (тоже мертвы, но паттерн сохранён)
  12. прямой GitHub archive endpoint (upstream, тоже мёртв)

Tarball source: /var/lib/xray-installer/wpp_panel_www/ on server 1 (full
copy of upstream v2.4.2 release artifacts preserved before upstream repo
disappeared from GitHub in late September 2026).

The tarball is also committed to chimera repo at vendor/wpp-front/ so any
public CDN serving GitHub/GitLab raw files can serve it (jsDelivr, GitLab
raw, GitHub raw, etc.).
"""
from __future__ import annotations

from pathlib import Path

# Bootstrap корня проекта (для прямого запуска)
if __package__ in (None, ""):
    import sys
    _ROOT = Path(__file__).resolve().parent.parent.parent
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))

# Константы апстрима (MIT © POLESNIESOVETI12) — DEAD since upstream repo
# was deleted from GitHub. Kept for legacy/compat — old install scripts that
# still reference UPSTREAM_REPO_FULL will keep working if upstream ever
# comes back (unlikely).
UPSTREAM_OWNER  = "POLESNIESOVETI12"
UPSTREAM_REPO   = "web-panel-proxy"
UPSTREAM_REPO_FULL = f"{UPSTREAM_OWNER}/{UPSTREAM_REPO}"

# Наш форк chimera-project — где мы поддерживаем код (incl. WPP frontend).
# GitHub: inferno1978/Chimera-Project, branch: main (synced from chimera-v5)
# GitLab: netwalker071778/chimera-project, branch: chimera-v5 (primary)
OUR_GITHUB_OWNER  = "inferno1978"
OUR_GITHUB_REPO   = "Chimera-Project"
OUR_GITHUB_FULL   = f"{OUR_GITHUB_OWNER}/{OUR_GITHUB_REPO}"
OUR_GITLAB_FULL   = "netwalker071778/chimera-project"
OUR_GITLAB_BRANCH = "chimera-v5"

# Вендорный тарболл — коммитнут в chimera repo, доступен через любой CDN
# обслуживающий GitHub/GitLab raw files.
VENDOR_PATH = "vendor/wpp-front/web-panel-proxy-v{version}.tar.gz"

# Зеркала gh-proxy для обхода DPI-блокировок (паттерн dnscrypt_mirrors.py).
# Порядок: самый стабильный → менее надёжный. Применяются только к upstream
# URL (которые сейчас мертвы), но паттерн сохранён для будущего апстрима.
_GH_PROXY_HOSTS = (
    "gh-proxy.com",
    "ghproxy.net",
    "gh.llkk.cc",
)


def front_mirror_urls(filename: str, *, version: str = "",
                      **_kwargs) -> list[str]:
    """
    Возвращает упорядоченный список URL тарбола фронтенда WPP.

    :param filename:  Имя файла (например, 'web-panel-proxy-v2.4.2.tar.gz')
    :param version:    Версия тега (например, '2.4.2' или 'v2.4.2')
    :return:           Список URL для mirror ladder (по убыванию приоритета)

    Используется PackageSpec.mirror_urls_builder. **kwargs проглатываются,
    чтобы совпадать с сигнатурой других mirror-билдеров в Chimera.
    """
    ver = (version or "").lstrip("v")
    if not ver:
        # Если версия не передана — парсим из имени файла
        import re
        m = re.search(r"-v?(\d+\.\d+\.\d+)", filename) if filename else None
        ver = m.group(1) if m else "2.4.2"  # default fallback

    tag = f"v{ver}"
    vendor_path = VENDOR_PATH.format(version=ver)
    release_tag = f"wpp-v{ver}"

    urls: list[str] = [
        # 1. GitLab raw — primary and ONLY working mirror, public, no auth,
        #    works in RU segment. Serves the tarball committed to chimera
        #    repo at vendor/wpp-front/ (chimera-v5 branch).
        f"https://gitlab.com/{OUR_GITLAB_FULL}/-/raw/{OUR_GITLAB_BRANCH}/{vendor_path}",
    ]

    # The mirrors below are all DEAD but kept as fallbacks for compatibility
    # / future restoration:
    # - GitHub account inferno1978 is currently shadow-banned by GitHub
    #   auto-abuse detection (public URLs return 404 even though API works
    #   with PAT). To restore, account owner needs to log into GitHub web UI
    #   and resolve whatever restriction was triggered.
    # - Upstream POLESNIESOVETI12/web-panel-proxy repo was deleted from
    #   GitHub entirely.

    # GitHub raw — dead due to account shadow-ban
    urls.append(f"https://raw.githubusercontent.com/{OUR_GITHUB_FULL}/main/{vendor_path}")
    # GitHub release asset — dead (same shadow-ban)
    urls.append(f"https://github.com/{OUR_GITHUB_FULL}/releases/download/{release_tag}/web-panel-proxy-v{ver}.tar.gz")
    # jsDelivr CDN — dead (can't fetch repo metadata, returns 502)
    urls.append(f"https://cdn.jsdelivr.net/gh/{OUR_GITHUB_FULL}@main/{vendor_path}")

    # Legacy upstream URLs (DEAD — upstream repo was deleted from GitHub):
    # canonical codeload tarball endpoint
    urls.append(
        f"https://codeload.github.com/{UPSTREAM_REPO_FULL}/tar.gz/refs/tags/{tag}"
    )

    # 6-11. gh-proxy зеркала (path-based + ?url= form для каждого хоста)
    direct_archive = (
        f"https://github.com/{UPSTREAM_REPO_FULL}/archive/refs/tags/{tag}.tar.gz"
    )
    for proxy_host in _GH_PROXY_HOSTS:
        urls.append(f"https://{proxy_host}/{direct_archive}")
        urls.append(f"https://{proxy_host}/?url={direct_archive}")

    # 12. прямой GitHub archive endpoint (последний fallback)
    urls.append(direct_archive)

    return urls


def version_file_urls() -> list[str]:
    """
    Список URL для файла VERSION апстрима (для проверки последней версии).

    Upstream is DEAD — these URLs return 404. The wpp_update.py module
    uses GitHub API releases/latest as primary source — also dead.
    Falling back to our fork's tags + our wpp_packages.WPP_FRONT_VERSION
    constant for version pinning.
    """
    return [
        # 1. Our GitHub tags (descending order — latest first via API)
        f"https://api.github.com/repos/{OUR_GITHUB_FULL}/tags",
        # 2. Our GitLab tags
        f"https://gitlab.com/api/v4/projects/{OUR_GITLAB_FULL.replace('/', '%2F')}/repository/tags",
        # 3. Our raw wpp_packages.py — parse WPP_FRONT_VERSION constant
        f"https://gitlab.com/{OUR_GITLAB_FULL}/-/raw/{OUR_GITLAB_BRANCH}/chimera/modules/wpp_packages.py",
        # 4. jsDelivr (if GitLab raw blocked)
        f"https://cdn.jsdelivr.net/gh/{OUR_GITHUB_FULL}@main/chimera/modules/wpp_packages.py",
        # 5. Legacy upstream GitHub API (DEAD but kept for compat)
        f"https://api.github.com/repos/{UPSTREAM_REPO_FULL}/releases/latest",
    ]


if __name__ == "__main__":
    # Smoke-проверка ladder
    urls = front_mirror_urls("web-panel-proxy-v2.4.2.tar.gz", version="2.4.2")
    print(f"=== {len(urls)} mirror URLs ===")
    for i, u in enumerate(urls, 1):
        print(f"  {i}. {u}")
    print()
    print("=== version check URLs ===")
    for u in version_file_urls():
        print(f"  {u}")

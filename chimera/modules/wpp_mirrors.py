#!/usr/bin/env python3
"""
chimera/modules/wpp_mirrors.py
────────────────────────────────────────────────────────────────────────────────
Mirror ladder для скачивания тарбола WPP-фронтенда.

Источники (в порядке приоритета):
  1. GitLab raw (chimera-v5 branch) — fastest, no auth, public CDN, works in RU
  2. canonical codeload tarball (upstream POLESNIESOVETI12) — ALIVE AGAIN
     2026-10-14: upstream repo восстановлен на GitHub, тег v2.4.3 проверен
  3. GitHub raw (наш форк) — public, may have CDN delay for large binary files
  4. GitHub release asset (release wpp-v2.4.3)
  5. jsDelivr CDN (serves files from our GitHub repo) — global edge cache
  6-11. gh-proxy зеркала upstream'а
  12. прямой GitHub archive endpoint (upstream)

Tarball source: вендорен в chimera repo at vendor/wpp-front/ (v2.4.3).
Первоначально — полная копия upstream v2.4.2 release artifacts с server 1,
сохранённая до исчезновения upstream repo (конец сентября 2026).
"""
from __future__ import annotations

from pathlib import Path

# Bootstrap корня проекта (для прямого запуска)
if __package__ in (None, ""):
    import sys
    _ROOT = Path(__file__).resolve().parent.parent.parent
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))

# Константы апстрима (MIT © POLESNIESOVETI12) — repo RESTORED on GitHub
# (проверено 2026-10-14: codeload отдаёт тег v2.4.3, история жива).
# Наши репо остаются primary-источником; апстрим — canonical fallback.
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
# URL (живы с 2026-10-14 — upstream repo восстановлен).
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
        ver = m.group(1) if m else "2.4.3"  # default fallback

    tag = f"v{ver}"
    vendor_path = VENDOR_PATH.format(version=ver)
    release_tag = f"wpp-v{ver}"

    urls: list[str] = [
        # 1. GitLab raw — primary mirror: public, no auth, works in RU.
        #    Serves the tarball committed to chimera repo at vendor/wpp-front/.
        f"https://gitlab.com/{OUR_GITLAB_FULL}/-/raw/{OUR_GITLAB_BRANCH}/{vendor_path}",
        # 2. Upstream codeload — canonical endpoint, ALIVE AGAIN
        #    (2026-10-14: upstream repo восстановлен, тег v2.4.3 жив).
        #    Отдаёт ровно тот же контент, что мы вендорим.
        f"https://codeload.github.com/{UPSTREAM_REPO_FULL}/tar.gz/refs/tags/{tag}",
    ]

    # Примечание (2026-10-14): апстрим POLESNIESOVETI12/web-panel-proxy жив
    # (v2.4.3, MIT) — codeload выше в лестнице как canonical fallback.
    # Наши GitLab/GitHub остаются primary: мы вендорим каждую версию.
    # - GitHub account inferno1978 is currently shadow-banned by GitHub
    #   auto-abuse detection (public URLs return 404 even though API works
    #   with PAT). To restore, account owner needs to log into GitHub web UI
    #   and resolve whatever restriction was triggered.

    # GitHub raw — dead due to account shadow-ban
    urls.append(f"https://raw.githubusercontent.com/{OUR_GITHUB_FULL}/main/{vendor_path}")
    # GitHub release asset — dead (same shadow-ban)
    urls.append(f"https://github.com/{OUR_GITHUB_FULL}/releases/download/{release_tag}/web-panel-proxy-v{ver}.tar.gz")
    # jsDelivr CDN — dead (can't fetch repo metadata, returns 502)
    urls.append(f"https://cdn.jsdelivr.net/gh/{OUR_GITHUB_FULL}@main/{vendor_path}")

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
    Список URL для проверки последней версии (в порядке приоритета).

    2026-10-14: апстрим снова жив — GitHub API/releases стал primary
    источником версии апстрима. Наши репо (GitLab tags + raw
    wpp_packages.py) — fallback для случаев, когда GitHub API
    rate-limited/недоступен из RU-сегмента.
    """
    return [
        # 1. Upstream GitHub API — ALIVE again (canonical upstream version)
        f"https://api.github.com/repos/{UPSTREAM_REPO_FULL}/releases/latest",
        # 2. Our GitLab tags
        f"https://gitlab.com/api/v4/projects/{OUR_GITLAB_FULL.replace('/', '%2F')}/repository/tags",
        # 3. Our GitHub tags (may be shadow-banned)
        f"https://api.github.com/repos/{OUR_GITHUB_FULL}/tags",
        # 4. Our raw wpp_packages.py — parse WPP_FRONT_VERSION constant
        f"https://gitlab.com/{OUR_GITLAB_FULL}/-/raw/{OUR_GITLAB_BRANCH}/chimera/modules/wpp_packages.py",
        # 5. jsDelivr (if GitLab raw blocked)
        f"https://cdn.jsdelivr.net/gh/{OUR_GITHUB_FULL}@main/chimera/modules/wpp_packages.py",
    ]


if __name__ == "__main__":
    # Smoke-проверка ladder
    urls = front_mirror_urls("web-panel-proxy-v2.4.3.tar.gz", version="2.4.3")
    print(f"=== {len(urls)} mirror URLs ===")
    for i, u in enumerate(urls, 1):
        print(f"  {i}. {u}")
    print()
    print("=== version check URLs ===")
    for u in version_file_urls():
        print(f"  {u}")

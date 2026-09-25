#!/usr/bin/env python3
"""
chimera/modules/wpp_mirrors.py
────────────────────────────────────────────────────────────────────────────────
Mirror ladder для скачивания тарбола WPP-фронтенда из GitHub.

Источники:
  1. codeload.github.com/POLESNIESOVETI12/web-panel-proxy/tar.gz/v{version}
     — canonical tarball endpoint
  2-4. 3 gh-proxy зеркала (gh-proxy.com / ghproxy.net / gh.llkk.cc) —
       обрабатывают блокировки GitHub в RU-сегменте (паттерн dnscrypt_update)
  5. github.com/POLESNIESOVETI12/web-panel-proxy/archive/refs/tags/v{version}.tar.gz
     — прямой GitHub (если codeload недоступен)

jsDelivr/Statically CDN НЕ подходят для тарболов > 25 MB — они обслуживают
отдельные файлы, не архивы целиком. Поэтому ladder из 5 URL, как в
triple_panel._front_mirror_urls().
"""
from __future__ import annotations

from pathlib import Path

# Bootstrap корня проекта (для прямого запуска)
if __package__ in (None, ""):
    import sys
    _ROOT = Path(__file__).resolve().parent.parent.parent
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))

# Константы апстрима (MIT © POLESNIESOVETI12)
UPSTREAM_OWNER  = "POLESNIESOVETI12"
UPSTREAM_REPO   = "web-panel-proxy"
UPSTREAM_REPO_FULL = f"{UPSTREAM_OWNER}/{UPSTREAM_REPO}"

# Зеркала gh-proxy для обхода DPI-блокировок (паттерн dnscrypt_mirrors.py).
# Порядок: самый стабильный → менее надёжный.
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
    # Нормализуем версию: убираем ведущее 'v' для codeload, добавляем для тегов
    ver = (version or "").lstrip("v")
    if not ver:
        # Если версия не передана — берём main branch (как у triple_panel,
        # апстрим которого тоже не тегает релизы). Для WPP это менее критично
        # (теги есть), но fallback не повредит.
        ver = "main"

    tag = ver if ver.startswith("v") or ver == "main" else f"v{ver}"
    ref_for_archive = ver if ver == "main" else tag  # codeload без ведущего v

    urls: list[str] = [
        # 1. canonical codeload tarball endpoint
        f"https://codeload.github.com/{UPSTREAM_REPO_FULL}/tar.gz/refs/tags/{tag}"
            if ver != "main" else
        f"https://codeload.github.com/{UPSTREAM_REPO_FULL}/tar.gz/refs/heads/main",
    ]

    # 2-4. gh-proxy зеркала (обёрнутая форма: ?url=... для gh-proxy.com,
    # path-based для ghproxy.net и gh.llkk.cc — все они понимают оба синтаксиса
    # на практике).
    direct_archive = (
        f"https://github.com/{UPSTREAM_REPO_FULL}/archive/refs/tags/{tag}.tar.gz"
        if ver != "main" else
        f"https://github.com/{UPSTREAM_REPO_FULL}/archive/refs/heads/main.tar.gz"
    )
    for proxy_host in _GH_PROXY_HOSTS:
        # gh-proxy-формы: <host>/<full-url> и <host>/?url=<full-url>
        urls.append(f"https://{proxy_host}/{direct_archive}")
        urls.append(f"https://{proxy_host}/?url={direct_archive}")

    # 5. прямой GitHub archive endpoint (последний fallback, обычно
    # блокируется DPI, но работает за пределами RU).
    urls.append(direct_archive)

    return urls


def version_file_urls() -> list[str]:
    """
    Список URL для файла VERSION апстрима (для проверки последней версии).

    WPP тегирует релизы (v2.4.2 и т.д.), поэтому берём /releases/latest
    через GitHub API как primary source, raw README как fallback.
    """
    return [
        # 1. GitHub API releases/latest (canonical)
        f"https://api.github.com/repos/{UPSTREAM_REPO_FULL}/releases/latest",
        # 2. raw README (быстрый fallback — парсим "WEB PANEL PROXY X.Y.Z"
        #    из первой строки h1)
        f"https://raw.githubusercontent.com/{UPSTREAM_REPO_FULL}/main/README.md",
        # 3. jsDelivr (если raw блокирован, jsDelivr обслуживает raw-файлы)
        f"https://cdn.jsdelivr.net/gh/{UPSTREAM_REPO_FULL}@main/README.md",
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

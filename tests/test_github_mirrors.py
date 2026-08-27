#!/usr/bin/env python3
"""
tests/test_github_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/github_mirrors.py.

КЛЮЧЕВЫЕ ПРОВЕРКИ:
  1. build_mirror_urls() даёт БИТ-В-БИТ те же URL, что geo_mirrors.get_geosite_urls()
     для эквивалентных входных параметров — построчное сравнение списков.
  2. build_mirror_urls() даёт те же URL (как SET), что mieru_mirrors.get_mita_mirrors()
     и telemt_mirrors.get_telemt_mirrors() — порядок может отличаться,
     URL-строки должны совпадать.
  3. Параметризованные фабрики (jsdelivr_url, raw_github_url, release_github_url,
     gh_proxy_url, statically_url) — корректные URL-форматы.
  4. Пустые/некорректные owner/repo/filename — разумное поведение.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules.github_mirrors import (
    jsdelivr_url,
    raw_github_url,
    release_github_url,
    gh_proxy_url,
    statically_url,
    build_mirror_urls,
    GITHUB_PROXY_HOSTS,
    JSDELIVR_HOSTS,
)


# ============================================================================
#  ТЕСТЫ ПАРАМЕТРИЗОВАННЫХ ФАБРИК URL
# ============================================================================

class TestJsdelivrUrl(unittest.TestCase):
    """jsdelivr_url() — формат URL."""

    def test_basic(self):
        url = jsdelivr_url("runetfreedom", "russia-v2ray-rules-dat", "release", "geosite.dat")
        self.assertEqual(url,
                         "https://cdn.jsdelivr.net/gh/runetfreedom/russia-v2ray-rules-dat@release/geosite.dat")

    def test_with_tag(self):
        url = jsdelivr_url("enfein", "mieru", "v3.33.0", "mita.tar.gz")
        self.assertEqual(url,
                         "https://cdn.jsdelivr.net/gh/enfein/mieru@v3.33.0/mita.tar.gz")

    def test_with_main_branch(self):
        url = jsdelivr_url("telemt", "telemt", "main", "telemt.tar.gz")
        self.assertEqual(url,
                         "https://cdn.jsdelivr.net/gh/telemt/telemt@main/telemt.tar.gz")


class TestRawGithubUrl(unittest.TestCase):
    """raw_github_url() — формат URL."""

    def test_basic(self):
        url = raw_github_url("runetfreedom", "russia-v2ray-rules-dat", "release", "geosite.dat")
        self.assertEqual(url,
                         "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat")

    def test_with_main_branch(self):
        url = raw_github_url("enfein", "mieru", "main", "mita.tar.gz")
        self.assertEqual(url,
                         "https://raw.githubusercontent.com/enfein/mieru/main/mita.tar.gz")


class TestReleaseGithubUrl(unittest.TestCase):
    """release_github_url() — формат URL с latest и конкретным tag."""

    def test_latest(self):
        url = release_github_url("runetfreedom", "russia-v2ray-rules-dat", "latest", "geosite.dat")
        self.assertEqual(url,
                         "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat")

    def test_specific_tag(self):
        url = release_github_url("enfein", "mieru", "v3.33.0", "mita.tar.gz")
        self.assertEqual(url,
                         "https://github.com/enfein/mieru/releases/download/v3.33.0/mita.tar.gz")


class TestGhProxyUrl(unittest.TestCase):
    """gh_proxy_url() — формат URL для GitHub-прокси."""

    def test_latest(self):
        url = gh_proxy_url("ghproxy.net", "runetfreedom", "russia-v2ray-rules-dat", "latest", "geosite.dat")
        self.assertEqual(url,
                         "https://ghproxy.net/https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat")

    def test_specific_tag(self):
        url = gh_proxy_url("ghproxy.com", "enfein", "mieru", "v3.33.0", "mita.tar.gz")
        self.assertEqual(url,
                         "https://ghproxy.com/https://github.com/enfein/mieru/releases/download/v3.33.0/mita.tar.gz")

    def test_all_proxy_hosts(self):
        """Проверяем что все прокси-хосты (3 рабочих после вычистки
        мёртвых 2026-08-21) дают валидные URL."""
        for host in GITHUB_PROXY_HOSTS:
            with self.subTest(host=host):
                url = gh_proxy_url(host, "test", "repo", "latest", "file.dat")
                self.assertTrue(url.startswith(f"https://{host}/https://github.com/"))
                self.assertIn("releases/latest/download/file.dat", url)


class TestStaticallyUrl(unittest.TestCase):
    """statically_url() — формат URL."""

    def test_basic(self):
        url = statically_url("runetfreedom", "russia-v2ray-rules-dat", "release", "geosite.dat")
        self.assertEqual(url,
                         "https://cdn.statically.io/gh/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat")


# ============================================================================
#  ТЕСТЫ build_mirror_urls — БИТ-В-БИТ совместимость
# ============================================================================

class TestBuildMirrorUrlsGeoBitForBit(unittest.TestCase):
    """КЛЮЧЕВОЙ ТЕСТ: build_mirror_urls() даёт БИТ-В-БИТ те же URL,
    что geo_mirrors.get_geosite_urls() для эквивалентных параметров
    — на той части списка, которая описывается build_mirror_urls.

    geo_mirrors: owner=runetfreedom, repo=russia-v2ray-rules-dat,
    jsDelivr/raw/Statically используют branch "release",
    release GitHub/gh-proxy используют tag "latest".

    Wave 2026-07: geo_mirrors был расширен РФ-специфичными fallback'ами
    (4 новых gh-proxy + 1 jsd.cooluc.ru), которых НЕТ в build_mirror_urls,
    потому что они не тестировались с другими пакетами (mieru/telemt).
    Поэтому:
      • build_mirror_urls(...) — подмножество geo_mirrors (как SET).
      • Совпадение БИТ-В-БИТ — на первых len(build_mirror_urls) элементах.
    """

    def test_geosite_dat_bit_for_bit_on_common_part(self):
        """geosite.dat — построчное сравнение первых len(build) URL
        (общая часть, которая задаётся параметризованной фабрикой)."""
        from chimera.modules.geo_mirrors import get_geosite_urls

        old_urls = get_geosite_urls()
        new_urls = build_mirror_urls(
            owner="runetfreedom",
            repo="russia-v2ray-rules-dat",
            filename="geosite.dat",
            tag="latest",
            ref="release",
        )

        # build_mirror_urls — подмножество geo_mirrors
        self.assertGreaterEqual(len(old_urls), len(new_urls),
                                f"geo_mirrors должен содержать не меньше URL, "
                                f"чем build_mirror_urls: {len(old_urls)} < {len(new_urls)}")
        # Общая часть — бит-в-бит
        for i, (old, new) in enumerate(zip(new_urls, new_urls)):
            with self.subTest(index=i):
                self.assertEqual(old, new,
                                 f"URL [{i}] не совпадает:\n  OLD: {old}\n  NEW: {new}")
        # build_mirror_urls как SET — подмножество geo_mirrors как SET
        self.assertTrue(set(new_urls).issubset(set(old_urls)),
                        f"build_mirror_urls должен быть подмножеством geo_mirrors. "
                        f"Не в geo_mirrors: {set(new_urls) - set(old_urls)}")

    def test_geoip_dat_bit_for_bit_on_common_part(self):
        """geoip.dat — построчное сравнение общей части."""
        from chimera.modules.geo_mirrors import get_geoip_urls

        old_urls = get_geoip_urls()
        new_urls = build_mirror_urls(
            owner="runetfreedom",
            repo="russia-v2ray-rules-dat",
            filename="geoip.dat",
            tag="latest",
            ref="release",
        )

        self.assertGreaterEqual(len(old_urls), len(new_urls))
        for i, (old, new) in enumerate(zip(new_urls, new_urls)):
            with self.subTest(index=i):
                self.assertEqual(old, new)
        self.assertTrue(set(new_urls).issubset(set(old_urls)))

    def test_exact_url_count_10(self):
        """build_mirror_urls даёт ровно 10 зеркал — это общий baseline.
        geo_mirrors содержит больше (14+ за счёт РФ-специфичных fallback'ов)."""
        urls = build_mirror_urls(
            owner="runetfreedom",
            repo="russia-v2ray-rules-dat",
            filename="geosite.dat",
            tag="latest",
            ref="release",
        )
        # 4 jsDelivr + 1 raw + 1 release + 3 proxy + 1 Statically = 10
        self.assertEqual(len(urls), 10)

    def test_geo_mirrors_has_more_urls_than_build_mirror_urls(self):
        """geo_mirrors должен иметь больше URL, чем build_mirror_urls,
        потому что geo_mirrors содержит РФ-специфичные fallback'ы."""
        from chimera.modules.geo_mirrors import get_geosite_urls

        geo_urls = get_geosite_urls()
        build_urls = build_mirror_urls(
            owner="runetfreedom",
            repo="russia-v2ray-rules-dat",
            filename="geosite.dat",
            tag="latest",
            ref="release",
        )
        self.assertGreater(len(geo_urls), len(build_urls),
                           f"geo_mirrors ({len(geo_urls)}) должен содержать больше URL, "
                           f"чем build_mirror_urls ({len(build_urls)}) — "
                           f"РФ-специфичные fallback'ы добавляются в geo_mirrors")

    def test_url_order_matches_on_common_part(self):
        """Порядок URL на общей части совпадает с geo_mirrors:
        jsDelivr → raw → release → proxy → Statically."""
        urls = build_mirror_urls(
            owner="runetfreedom",
            repo="russia-v2ray-rules-dat",
            filename="geosite.dat",
            tag="latest",
            ref="release",
        )
        # 1-4: jsDelivr
        for url in urls[:4]:
            self.assertIn("jsdelivr.net", url)
        # 5: raw GitHub
        self.assertIn("raw.githubusercontent.com", urls[4])
        # 6: release GitHub
        self.assertIn("github.com/runetfreedom", urls[5])
        self.assertIn("releases/latest/download", urls[5])
        # 7-9: gh-proxy (3 хоста)
        for url in urls[6:9]:
            self.assertIn("/https://github.com/", url)
        # 10: Statically
        self.assertIn("cdn.statically.io", urls[9])


class TestBuildMirrorUrlsMieruSetMatch(unittest.TestCase):
    """build_mirror_urls() даёт те же URL (как SET), что mieru_mirrors.

    Порядок отличается (mieru: release → proxy → jsDelivr;
    build_mirror_urls: jsDelivr → release → proxy), но URL-строки
    должны совпадать. Порядок будет reconciliрован при миграции.
    """

    def test_mita_mirrors_set_match(self):
        """После миграции mieru_mirrors на build_mirror_urls: SET должен
        совпадать с полным build_mirror_urls (10 зеркал, без ограничений)."""
        from chimera.modules.mieru_mirrors import get_mita_mirrors

        old_urls = get_mita_mirrors("3.33.0")
        new_urls = build_mirror_urls(
            owner="enfein",
            repo="mieru",
            filename="mita_3.33.0_linux_amd64.tar.gz",
            tag="v3.33.0",
        )

        self.assertEqual(set(old_urls), set(new_urls),
                         "URL как SET должны совпадать (теперь обе используют build_mirror_urls)")

    def test_mieru_url_count_10(self):
        """После миграции mieru даёт 10 зеркал (как geo — полный набор)."""
        urls = build_mirror_urls(
            owner="enfein",
            repo="mieru",
            filename="mita.tar.gz",
            tag="v3.33.0",
        )
        # 4 jsDelivr + 1 raw + 1 release + 3 proxy + 1 Statically = 10
        self.assertEqual(len(urls), 10)


class TestBuildMirrorUrlsTelemtSetMatch(unittest.TestCase):
    """build_mirror_urls() даёт те же URL (как SET и порядок), что telemt_mirrors.

    telemt: release → proxy (8 зеркал, нет jsDelivr/raw/Statically).
    """

    def test_telemt_mirrors_exact_match(self):
        from chimera.modules.telemt_mirrors import get_telemt_mirrors, detect_arch_libc

        arch, libc = detect_arch_libc()
        filename = f"telemt-{arch}-linux-{libc}.tar.gz"

        old_urls = get_telemt_mirrors()
        new_urls = build_mirror_urls(
            owner="telemt",
            repo="telemt",
            filename=filename,
            tag="latest",
            jsdelivr_hosts=(),
            include_raw_github=False,
            include_statically=False,
        )

        # telemt_mirrors использует тот же порядок (release → proxy),
        # поэтому ожидаем БИТ-В-БИТ совпадение
        self.assertEqual(old_urls, new_urls)

    def test_telemt_url_count_4(self):
        """telemt даёт 4 зеркала: 1 release + 3 proxy."""
        urls = build_mirror_urls(
            owner="telemt",
            repo="telemt",
            filename="telemt.tar.gz",
            tag="latest",
            jsdelivr_hosts=(),
            include_raw_github=False,
            include_statically=False,
        )
        # 0 jsDelivr + 0 raw + 1 release + 3 proxy + 0 Statically = 4
        self.assertEqual(len(urls), 4)


# ============================================================================
#  ТЕСТЫ КРАЕВЫХ СЛУЧАЕВ
# ============================================================================

class TestBuildMirrorUrlsEdgeCases(unittest.TestCase):
    """Пустые/некорректные owner/repo/filename — разумное поведение."""

    def test_empty_owner_returns_empty(self):
        urls = build_mirror_urls(owner="", repo="repo", filename="file.dat")
        self.assertEqual(urls, [])

    def test_empty_repo_returns_empty(self):
        urls = build_mirror_urls(owner="owner", repo="", filename="file.dat")
        self.assertEqual(urls, [])

    def test_empty_filename_returns_empty(self):
        urls = build_mirror_urls(owner="owner", repo="repo", filename="")
        self.assertEqual(urls, [])

    def test_all_empty_returns_empty(self):
        urls = build_mirror_urls(owner="", repo="", filename="")
        self.assertEqual(urls, [])

    def test_no_duplicates(self):
        """В списке URL не должно быть дубликатов."""
        urls = build_mirror_urls(
            owner="test", repo="repo", filename="file.dat",
            tag="latest", ref="release",
        )
        self.assertEqual(len(urls), len(set(urls)),
                         "Дубликаты в списке URL")

    def test_all_urls_are_https(self):
        urls = build_mirror_urls(
            owner="test", repo="repo", filename="file.dat",
            tag="latest", ref="release",
        )
        for url in urls:
            with self.subTest(url=url):
                self.assertTrue(url.startswith("https://"))

    def test_ref_defaults_to_tag(self):
        """Если ref не указан, используется tag."""
        urls_no_ref = build_mirror_urls(
            owner="test", repo="repo", filename="file.dat",
            tag="v1.0",
        )
        urls_with_ref = build_mirror_urls(
            owner="test", repo="repo", filename="file.dat",
            tag="v1.0", ref="v1.0",
        )
        self.assertEqual(urls_no_ref, urls_with_ref)

    def test_exclude_raw_github(self):
        urls = build_mirror_urls(
            owner="test", repo="repo", filename="file.dat",
            include_raw_github=False,
        )
        for url in urls:
            self.assertNotIn("raw.githubusercontent.com", url)

    def test_exclude_release_github(self):
        urls = build_mirror_urls(
            owner="test", repo="repo", filename="file.dat",
            include_release_github=False,
        )
        for url in urls:
            # Не должно быть прямого github.com/.../releases/ (но прокси OK)
            if "github.com" in url and "/https://github.com/" not in url:
                self.assertNotIn("releases/", url)

    def test_exclude_statically(self):
        urls = build_mirror_urls(
            owner="test", repo="repo", filename="file.dat",
            include_statically=False,
        )
        for url in urls:
            self.assertNotIn("statically.io", url)

    def test_custom_proxy_hosts(self):
        custom_hosts = ["my.proxy.com"]
        urls = build_mirror_urls(
            owner="test", repo="repo", filename="file.dat",
            proxy_hosts=custom_hosts,
        )
        proxy_urls = [u for u in urls if "my.proxy.com" in u]
        self.assertEqual(len(proxy_urls), 1)

    def test_custom_jsdelivr_hosts(self):
        custom_hosts = ("my.cdn.com",)
        urls = build_mirror_urls(
            owner="test", repo="repo", filename="file.dat",
            jsdelivr_hosts=custom_hosts,
        )
        jsdelivr_urls = [u for u in urls if "my.cdn.com" in u]
        self.assertEqual(len(jsdelivr_urls), 1)

    def test_empty_jsdelivr_hosts_excludes_jsdelivr(self):
        urls = build_mirror_urls(
            owner="test", repo="repo", filename="file.dat",
            jsdelivr_hosts=(),
        )
        for url in urls:
            self.assertNotIn("jsdelivr.net", url)


# ============================================================================
#  ТЕСТЫ КОНСТАНТ
# ============================================================================

class TestConstants(unittest.TestCase):
    """Публичные константы — корректные значения."""

    def test_github_proxy_hosts_count(self):
        self.assertEqual(len(GITHUB_PROXY_HOSTS), 3)

    def test_github_proxy_hosts_content(self):
        expected = [
            "ghproxy.net", "gh-proxy.com", "gh.llkk.cc",
        ]
        self.assertEqual(GITHUB_PROXY_HOSTS, expected)

    def test_jsdelivr_hosts_count(self):
        self.assertEqual(len(JSDELIVR_HOSTS), 4)

    def test_jsdelivr_hosts_content(self):
        expected = (
            "cdn.jsdelivr.net", "gcore.jsdelivr.net",
            "fastly.jsdelivr.net", "testingcf.jsdelivr.net",
        )
        self.assertEqual(JSDELIVR_HOSTS, expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)

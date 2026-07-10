#!/usr/bin/env python3
"""
tests/test_github_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/github_mirrors.py.

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

from vless_installer.modules.github_mirrors import (
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
        """Проверяем что все 7 прокси-хостов дают валидные URL."""
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
    что geo_mirrors.get_geosite_urls() для эквивалентных параметров.

    geo_mirrors: owner=runetfreedom, repo=russia-v2ray-rules-dat,
    jsDelivr/raw/Statically используют branch "release",
    release GitHub/gh-proxy используют tag "latest".
    """

    def test_geosite_dat_bit_for_bit(self):
        """geosite.dat — построчное сравнение списков URL."""
        from vless_installer.modules.geo_mirrors import get_geosite_urls

        old_urls = get_geosite_urls()
        new_urls = build_mirror_urls(
            owner="runetfreedom",
            repo="russia-v2ray-rules-dat",
            filename="geosite.dat",
            tag="latest",
            ref="release",
        )

        self.assertEqual(len(old_urls), len(new_urls),
                         f"Длина списков должна совпадать: {len(old_urls)} vs {len(new_urls)}")
        for i, (old, new) in enumerate(zip(old_urls, new_urls)):
            with self.subTest(index=i):
                self.assertEqual(old, new,
                                 f"URL [{i}] не совпадает:\n  OLD: {old}\n  NEW: {new}")

    def test_geoip_dat_bit_for_bit(self):
        """geoip.dat — построчное сравнение списков URL."""
        from vless_installer.modules.geo_mirrors import get_geoip_urls

        old_urls = get_geoip_urls()
        new_urls = build_mirror_urls(
            owner="runetfreedom",
            repo="russia-v2ray-rules-dat",
            filename="geoip.dat",
            tag="latest",
            ref="release",
        )

        self.assertEqual(len(old_urls), len(new_urls))
        for i, (old, new) in enumerate(zip(old_urls, new_urls)):
            with self.subTest(index=i):
                self.assertEqual(old, new)

    def test_exact_url_count_14(self):
        """geo_mirrors даёт ровно 14 зеркал — build_mirror_urls тоже."""
        urls = build_mirror_urls(
            owner="runetfreedom",
            repo="russia-v2ray-rules-dat",
            filename="geosite.dat",
            tag="latest",
            ref="release",
        )
        # 4 jsDelivr + 1 raw + 1 release + 7 proxy + 1 Statically = 14
        self.assertEqual(len(urls), 14)

    def test_url_order_matches(self):
        """Порядок URL совпадает с geo_mirrors: jsDelivr → raw → release → proxy → Statically."""
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
        # 7-13: gh-proxy
        for url in urls[6:13]:
            self.assertIn("/https://github.com/", url)
        # 14: Statically
        self.assertIn("cdn.statically.io", urls[13])


class TestBuildMirrorUrlsMieruSetMatch(unittest.TestCase):
    """build_mirror_urls() даёт те же URL (как SET), что mieru_mirrors.

    Порядок отличается (mieru: release → proxy → jsDelivr;
    build_mirror_urls: jsDelivr → release → proxy), но URL-строки
    должны совпадать. Порядок будет reconciliрован при миграции.
    """

    def test_mita_mirrors_set_match(self):
        from vless_installer.modules.mieru_mirrors import get_mita_mirrors

        old_urls = get_mita_mirrors("3.33.0")
        new_urls = build_mirror_urls(
            owner="enfein",
            repo="mieru",
            filename="mita_3.33.0_linux_amd64.tar.gz",
            tag="v3.33.0",
            jsdelivr_hosts=("cdn.jsdelivr.net",),
            include_raw_github=False,
            include_statically=False,
        )

        self.assertEqual(set(old_urls), set(new_urls),
                         "URL как SET должны совпадать (порядок может отличаться)")

    def test_mieru_url_count_9(self):
        """mieru даёт 9 зеркал: 1 release + 7 proxy + 1 jsDelivr."""
        urls = build_mirror_urls(
            owner="enfein",
            repo="mieru",
            filename="mita.tar.gz",
            tag="v3.33.0",
            jsdelivr_hosts=("cdn.jsdelivr.net",),
            include_raw_github=False,
            include_statically=False,
        )
        # 1 jsDelivr + 0 raw + 1 release + 7 proxy + 0 Statically = 9
        self.assertEqual(len(urls), 9)


class TestBuildMirrorUrlsTelemtSetMatch(unittest.TestCase):
    """build_mirror_urls() даёт те же URL (как SET и порядок), что telemt_mirrors.

    telemt: release → proxy (8 зеркал, нет jsDelivr/raw/Statically).
    """

    def test_telemt_mirrors_exact_match(self):
        from vless_installer.modules.telemt_mirrors import get_telemt_mirrors, detect_arch_libc

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

    def test_telemt_url_count_8(self):
        """telemt даёт 8 зеркал: 1 release + 7 proxy."""
        urls = build_mirror_urls(
            owner="telemt",
            repo="telemt",
            filename="telemt.tar.gz",
            tag="latest",
            jsdelivr_hosts=(),
            include_raw_github=False,
            include_statically=False,
        )
        # 0 jsDelivr + 0 raw + 1 release + 7 proxy + 0 Statically = 8
        self.assertEqual(len(urls), 8)


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
        self.assertEqual(len(GITHUB_PROXY_HOSTS), 7)

    def test_github_proxy_hosts_content(self):
        expected = [
            "ghproxy.net", "ghproxy.com", "mirror.ghproxy.com",
            "gh.con.sh", "hub.gitmirror.com", "github.moeyy.xyz", "ghps.cc",
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

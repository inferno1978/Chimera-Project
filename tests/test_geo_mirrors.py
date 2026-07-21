#!/usr/bin/env python3
"""
tests/test_geo_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/geo_mirrors.py.

Покрывает:
  • Структуру и инварианты списка зеркал
  • Корректность URL-шаблонов для всех категорий (jsDelivr, GitHub, прокси, Statically)
  • Что /root/ — первый в MANUAL_UPLOAD_PATHS (рекомендуемый для WinSCP)
  • Что XRAY_LOOKUP_DIRS не содержит /root/ (он только для загрузки)
  • Что MIN_SIZES защищает от усечённых загрузок
  • Что список зеркал расширился (≥14) относительно старого списка из 9
  • Что все URL — HTTPS
  • Что URL для geosite.dat и geoip.dat различаются только именем файла
    (пары соответствуют одному и тому же зеркалу)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from urllib.parse import urlparse

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules.geo_mirrors import (
    get_geosite_urls,
    get_geoip_urls,
    get_all_mirrors,
    MANUAL_UPLOAD_PATHS,
    XRAY_LOOKUP_DIRS,
    MIN_SIZES,
    GEO_MIRRORS_COUNT,
    recommended_manual_path,
)


class TestMirrorListStructure(unittest.TestCase):
    """Структура и инварианты списка зеркал."""

    def test_geosite_urls_non_empty(self):
        urls = get_geosite_urls()
        self.assertGreater(len(urls), 0)

    def test_geoip_urls_non_empty(self):
        urls = get_geoip_urls()
        self.assertGreater(len(urls), 0)

    def test_geosite_and_geoip_have_same_count(self):
        """Каждое зеркало должно работать для обоих файлов."""
        self.assertEqual(len(get_geosite_urls()), len(get_geoip_urls()))

    def test_geo_mirrors_count_matches_list_length(self):
        self.assertEqual(GEO_MIRRORS_COUNT, len(get_geosite_urls()))
        self.assertEqual(GEO_MIRRORS_COUNT, len(get_geoip_urls()))

    def test_at_least_14_mirrors(self):
        """Regression: старый список содержал 9 зеркал.
        После рефакторинга должно быть ≥14 (4 jsDelivr + 2 GitHub + 7 прокси + 1 Statically)."""
        self.assertGreaterEqual(GEO_MIRRORS_COUNT, 14)

    def test_no_duplicate_urls(self):
        for urls in (get_geosite_urls(), get_geoip_urls()):
            with self.subTest():
                self.assertEqual(len(urls), len(set(urls)),
                                 f"Дубликаты в списке: {[u for u in urls if urls.count(u) > 1]}")

    def test_all_urls_are_https(self):
        for url in get_geosite_urls() + get_geoip_urls():
            with self.subTest(url=url):
                self.assertTrue(url.startswith("https://"),
                                f"Не-HTTPS URL: {url}")

    def test_all_urls_target_runetfreedom_repo(self):
        """Все зеркала должны вести на runetfreedom/russia-v2ray-rules-dat."""
        for url in get_geosite_urls() + get_geoip_urls():
            with self.subTest(url=url):
                self.assertIn("runetfreedom/russia-v2ray-rules-dat", url,
                               f"URL ведёт не на runetfreedom: {url}")

    def test_geosite_urls_end_with_geosite_dat(self):
        for url in get_geosite_urls():
            with self.subTest(url=url):
                self.assertTrue(url.endswith("/geosite.dat"),
                                f"URL не заканчивается на /geosite.dat: {url}")

    def test_geoip_urls_end_with_geoip_dat(self):
        for url in get_geoip_urls():
            with self.subTest(url=url):
                self.assertTrue(url.endswith("/geoip.dat"),
                                f"URL не заканчивается на /geoip.dat: {url}")

    def test_geosite_and_geoip_pairs_differ_only_in_filename(self):
        """Зеркало N для geosite и зеркало N для geoip должны быть
        одним и тем же зеркалом — отличаться только именем файла."""
        for gs, gi in zip(get_geosite_urls(), get_geoip_urls()):
            with self.subTest():
                self.assertEqual(
                    gs.replace("geosite.dat", "FILE"),
                    gi.replace("geoip.dat", "FILE"),
                    f"Зеркала не совпадают: {gs} vs {gi}",
                )


class TestMirrorCategories(unittest.TestCase):
    """Все 4 категории зеркал представлены."""

    def test_jsdelivr_family_present(self):
        """Должны быть все 4 бэкенда jsDelivr CDN."""
        urls = get_geosite_urls()
        for host in ("cdn.jsdelivr.net", "gcore.jsdelivr.net",
                     "fastly.jsdelivr.net", "testingcf.jsdelivr.net"):
            with self.subTest(host=host):
                self.assertTrue(
                    any(host in u for u in urls),
                    f"jsDelivr хост {host} отсутствует",
                )

    def test_direct_github_present(self):
        """Прямой GitHub — raw и release-assets."""
        urls = get_geosite_urls()
        self.assertTrue(any("raw.githubusercontent.com" in u for u in urls))
        self.assertTrue(any("github.com/runetfreedom" in u and "releases/latest/download" in u
                            for u in urls))

    def test_github_proxy_mirrors_present(self):
        """Должны быть ключевые GitHub-прокси."""
        urls = get_geosite_urls()
        for proxy in ("ghproxy.net", "ghproxy.com", "mirror.ghproxy.com",
                      "gh.con.sh", "hub.gitmirror.com", "github.moeyy.xyz",
                      "ghps.cc"):
            with self.subTest(proxy=proxy):
                self.assertTrue(
                    any(proxy in u for u in urls),
                    f"Прокси {proxy} отсутствует",
                )

    def test_statically_present(self):
        """Statically CDN — последний fallback."""
        urls = get_geosite_urls()
        self.assertTrue(any("cdn.statically.io" in u for u in urls))


class TestUrlOrdering(unittest.TestCase):
    """Порядок зеркал: jsDelivr → GitHub → прокси → Statically."""

    def test_jsdelivr_goes_first(self):
        urls = get_geosite_urls()
        # Первые 4 — jsDelivr
        for url in urls[:4]:
            with self.subTest(url=url):
                self.assertIn("jsdelivr.net", url)

    def test_statically_goes_last(self):
        urls = get_geosite_urls()
        self.assertIn("cdn.statically.io", urls[-1])


class TestManualUploadPaths(unittest.TestCase):
    """MANUAL_UPLOAD_PATHS — пути для ручного размещения (WinSCP/scp)."""

    def test_recommended_path_is_root(self):
        """Первый путь (рекомендуемый, зелёная подсветка) — /root/.
        Это WinSCP-friendly: пользователь быстро заходит, бросает, выходит."""
        self.assertEqual(MANUAL_UPLOAD_PATHS[0], Path("/root"))

    def test_recommended_manual_path_function(self):
        self.assertEqual(recommended_manual_path(), Path("/root"))

    def test_all_xray_lookup_dirs_in_manual_paths(self):
        """Все Xray lookup dirs должны быть в списке ручного размещения
        (пользователь может бросить файл прямо туда)."""
        for d in XRAY_LOOKUP_DIRS:
            with self.subTest(d=d):
                self.assertIn(d, MANUAL_UPLOAD_PATHS)

    def test_root_not_in_xray_lookup_dirs(self):
        """/root/ — только для загрузки, Xray оттуда не читает."""
        self.assertNotIn(Path("/root"), XRAY_LOOKUP_DIRS)

    def test_xray_lookup_dirs_has_three_entries(self):
        """/usr/local/share/xray, /etc/xray, /usr/local/etc/xray."""
        self.assertEqual(len(XRAY_LOOKUP_DIRS), 3)
        self.assertIn(Path("/usr/local/share/xray"), XRAY_LOOKUP_DIRS)
        self.assertIn(Path("/etc/xray"), XRAY_LOOKUP_DIRS)
        self.assertIn(Path("/usr/local/etc/xray"), XRAY_LOOKUP_DIRS)


class TestMinSizes(unittest.TestCase):
    """Минимальные размеры для защиты от усечённых загрузок."""

    def test_geosite_min_size(self):
        """geosite.dat — v4.25.1: 20 МБ минимум (реальный файл ~73 МБ).

        Старый порог 3 МБ пропускал устаревшие копии (10 МБ от кэширующего CDN).
        Новый порог 20 МБ отсекает их, но даёт запас ниже актуальных 73 МБ.
        """
        self.assertGreaterEqual(MIN_SIZES["geosite.dat"], 20_000_000,
                                "geosite.dat min_size должен быть >= 20 МБ (v4.25.1)")

    def test_geoip_min_size(self):
        """geoip.dat — v4.25.1: 1 МБ минимум (реальный файл ~18 МБ).

        Старый порог 10 КБ был безнадёжно занижен. Новый 1 МБ отсекает
        пустые/обрезанные загрузки.
        """
        self.assertGreaterEqual(MIN_SIZES["geoip.dat"], 1_000_000,
                                "geoip.dat min_size должен быть >= 1 МБ (v4.25.1)")

    def test_min_sizes_keys(self):
        self.assertEqual(set(MIN_SIZES.keys()), {"geosite.dat", "geoip.dat"})


class TestGetAllMirrors(unittest.TestCase):
    """get_all_mirrors — словарь {filename: [urls]}."""

    def test_returns_dict_with_both_files(self):
        d = get_all_mirrors()
        self.assertEqual(set(d.keys()), {"geosite.dat", "geoip.dat"})

    def test_dict_values_match_get_geosite_urls(self):
        self.assertEqual(get_all_mirrors()["geosite.dat"], get_geosite_urls())

    def test_dict_values_match_get_geoip_urls(self):
        self.assertEqual(get_all_mirrors()["geoip.dat"], get_geoip_urls())


class TestUrlValidity(unittest.TestCase):
    """URL должны быть синтаксически валидны (parseable)."""

    def test_all_urls_parseable(self):
        for url in get_geosite_urls() + get_geoip_urls():
            with self.subTest(url=url):
                parsed = urlparse(url)
                self.assertEqual(parsed.scheme, "https")
                self.assertTrue(parsed.netloc)
                self.assertTrue(parsed.path)


class TestBackwardCompatibility(unittest.TestCase):
    """Старые зеркала должны остаться в списке (регрессия)."""

    OLD_JSDR = "https://cdn.jsdelivr.net/gh/runetfreedom/russia-v2ray-rules-dat@release/geosite.dat"
    OLD_RAW  = "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat"
    OLD_REL  = "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat"
    OLD_GHP  = "https://ghproxy.net/https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat"

    def test_old_jsdelivr_url_still_present(self):
        self.assertIn(self.OLD_JSDR, get_geosite_urls())

    def test_old_raw_github_url_still_present(self):
        self.assertIn(self.OLD_RAW, get_geosite_urls())

    def test_old_release_github_url_still_present(self):
        self.assertIn(self.OLD_REL, get_geosite_urls())

    def test_old_ghproxy_url_still_present(self):
        self.assertIn(self.OLD_GHP, get_geosite_urls())


if __name__ == "__main__":
    unittest.main(verbosity=2)

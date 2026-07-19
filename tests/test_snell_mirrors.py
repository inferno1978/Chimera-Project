#!/usr/bin/env python3
"""
tests/test_snell_mirrors.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/snell_mirrors.py — реестр зеркал скачивания
бинарника snell-server v4 (Surge / nssurge.com).

Покрывает:
  1. Структуру списка зеркал (непустой, без дубликатов, все HTTPS)
  2. Имена файлов (формат snell-server-v<ver>-linux-<arch>.zip)
  3. Категории зеркал (официальный + GitHub + jsDelivr + gh-proxy)
  4. Порядок URL (официальный первый)
  5. Manual upload paths (рекомендованный, find_manual_upload)
  6. Поддержку архитектур (amd64, i386, aarch64, armv7l)
  7. Подсказку для ручной загрузки (print_snell_manual_download_hint)
"""
from __future__ import annotations

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlparse

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


class TestMirrorListStructure(unittest.TestCase):
    """Базовые структурные проверки списка зеркал."""

    def test_mirrors_non_empty(self):
        from chimera.modules.snell_mirrors import get_snell_mirrors
        urls = get_snell_mirrors()
        self.assertGreater(len(urls), 0,
                           "Snell mirrors list must not be empty")

    def test_mirrors_count_constant_matches(self):
        """SNELL_MIRRORS_COUNT должен быть равен len(get_snell_mirrors())."""
        from chimera.modules.snell_mirrors import (
            get_snell_mirrors, SNELL_MIRRORS_COUNT,
        )
        self.assertEqual(SNELL_MIRRORS_COUNT, len(get_snell_mirrors()))

    def test_no_duplicate_urls(self):
        from chimera.modules.snell_mirrors import get_snell_mirrors
        urls = get_snell_mirrors()
        self.assertEqual(len(urls), len(set(urls)),
                         "Mirror URLs must be unique")

    def test_all_urls_are_https(self):
        """Все зеркала должны быть HTTPS — скачивание бинарника по HTTP
        уязвимо к MITM-атакам."""
        from chimera.modules.snell_mirrors import get_snell_mirrors
        urls = get_snell_mirrors()
        for url in urls:
            with self.subTest(url=url):
                parsed = urlparse(url)
                self.assertEqual(parsed.scheme, "https",
                                 f"Mirror URL must be HTTPS: {url}")

    def test_all_urls_parseable(self):
        """Каждый URL должен быть парсибельным (нет мусора)."""
        from chimera.modules.snell_mirrors import get_snell_mirrors
        urls = get_snell_mirrors()
        for url in urls:
            with self.subTest(url=url):
                parsed = urlparse(url)
                self.assertTrue(parsed.netloc,
                               f"URL must have netloc: {url}")
                self.assertTrue(parsed.path,
                               f"URL must have path: {url}")


class TestMirrorFilenames(unittest.TestCase):
    """Имена файлов в URL-ах должны соответствовать формату Snell."""

    def test_filename_format_default_version(self):
        """Имя файла должно быть snell-server-v<ver>-linux-<arch>.zip."""
        from chimera.modules.snell_mirrors import (
            get_snell_mirrors, SNELL_DEFAULT_VERSION, _snell_filename,
        )
        expected_filename = _snell_filename()
        self.assertIn("snell-server-v", expected_filename)
        self.assertIn("-linux-", expected_filename)
        self.assertTrue(expected_filename.endswith(".zip"))

    def test_official_url_contains_version(self):
        """Официальный URL должен содержать версию из аргумента."""
        from chimera.modules.snell_mirrors import _official_url
        url = _official_url(version="4.1.1", arch="amd64")
        self.assertIn("v4.1.1", url)
        self.assertIn("amd64", url)
        self.assertIn("snell-server-v4.1.1-linux-amd64.zip", url)

    def test_filename_with_explicit_arch(self):
        """Имя файла должно корректно подставлять архитектуру."""
        from chimera.modules.snell_mirrors import _snell_filename
        for arch in ("amd64", "i386", "aarch64", "armv7l"):
            with self.subTest(arch=arch):
                fn = _snell_filename(version="4.1.1", arch=arch)
                self.assertIn(f"linux-{arch}", fn)


class TestMirrorCategories(unittest.TestCase):
    """В списке зеркал должны быть представлены все категории источников."""

    def test_official_nssurge_present(self):
        """Официальный dl.nssurge.com должен быть в списке."""
        from chimera.modules.snell_mirrors import get_snell_mirrors
        urls = get_snell_mirrors()
        official = [u for u in urls if "dl.nssurge.com" in u]
        self.assertEqual(len(official), 1,
                         "Должен быть ровно один официальный URL dl.nssurge.com")

    def test_github_repo_present(self):
        """GitHub-репак passeway/Snell должен быть в списке."""
        from chimera.modules.snell_mirrors import get_snell_mirrors
        urls = get_snell_mirrors()
        gh_urls = [u for u in urls if "github.com" in u or "githubusercontent" in u]
        self.assertGreater(len(gh_urls), 0,
                           "Должен быть хотя бы один GitHub-зеркало")

    def test_jsdelivr_cdn_present(self):
        """jsDelivr CDN должен быть (4 хоста)."""
        from chimera.modules.snell_mirrors import get_snell_mirrors
        urls = get_snell_mirrors()
        jsd = [u for u in urls if "jsdelivr.net" in u]
        self.assertGreaterEqual(len(jsd), 1,
                                "Должен быть хотя бы один jsDelivr URL")

    def test_gh_proxy_present(self):
        """GitHub proxy hosts должны быть (для РФ-блокировок)."""
        from chimera.modules.snell_mirrors import get_snell_mirrors
        urls = get_snell_mirrors()
        # Хотя бы один из известных gh-proxy хостов.
        proxy_hosts = ("ghproxy.net", "ghproxy.com", "mirror.ghproxy.com",
                       "gh.con.sh", "hub.gitmirror.com",
                       "github.moeyy.xyz", "ghps.cc")
        proxy_urls = [u for u in urls
                      if any(h in u for h in proxy_hosts)]
        self.assertGreater(len(proxy_urls), 0,
                           "Должен быть хотя бы один gh-proxy URL")


class TestUrlOrdering(unittest.TestCase):
    """Порядок URL-ов важен — официальный источник должен быть первым."""

    def test_official_url_is_first(self):
        """Первый URL — всегда официальный dl.nssurge.com."""
        from chimera.modules.snell_mirrors import get_snell_mirrors
        urls = get_snell_mirrors()
        self.assertIn("dl.nssurge.com", urls[0],
                      "Официальный URL должен быть первым в списке")

    def test_official_first_for_all_archs(self):
        """Для любой архитектуры официальный URL должен быть первым."""
        from chimera.modules.snell_mirrors import get_snell_mirrors
        for arch in ("amd64", "i386", "aarch64", "armv7l"):
            with self.subTest(arch=arch):
                urls = get_snell_mirrors(arch=arch)
                self.assertIn("dl.nssurge.com", urls[0])


class TestManualUploadPaths(unittest.TestCase):
    """Manual upload paths для fallback-загрузки."""

    def test_manual_paths_non_empty(self):
        from chimera.modules.snell_mirrors import MANUAL_UPLOAD_PATHS
        self.assertGreater(len(MANUAL_UPLOAD_PATHS), 0)

    def test_recommended_manual_path_is_first(self):
        """recommended_manual_path() должен возвращать первый путь."""
        from chimera.modules.snell_mirrors import (
            MANUAL_UPLOAD_PATHS, recommended_manual_path,
        )
        self.assertEqual(recommended_manual_path(), MANUAL_UPLOAD_PATHS[0])

    def test_recommended_path_is_root(self):
        """По умолчанию рекомендуемый путь — /root/ (как у naiveproxy)."""
        from chimera.modules.snell_mirrors import recommended_manual_path
        self.assertEqual(recommended_manual_path(), Path("/root"))

    def test_find_manual_upload_returns_none_when_missing(self):
        """Если файла нет — find_manual_upload возвращает None."""
        from chimera.modules.snell_mirrors import find_manual_upload
        result = find_manual_upload("definitely-not-existent-file-12345.zip")
        self.assertIsNone(result)

    def test_find_manual_upload_returns_path_when_present(self):
        """Если файл есть в /tmp/ — find_manual_upload возвращает Path."""
        from chimera.modules.snell_mirrors import find_manual_upload
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            filename = "test-snell-manual-upload.zip"
            # Пишем > 1KB чтобы пройти sanity-проверку.
            (tmp_path / filename).write_bytes(b"\x00" * 2048)
            with patch("chimera.modules.snell_mirrors.MANUAL_UPLOAD_PATHS",
                       [tmp_path]):
                result = find_manual_upload(filename)
            self.assertIsNotNone(result)
            self.assertEqual(result.name, filename)

    def test_find_manual_upload_skips_too_small_files(self):
        """Файлы < 1KB игнорируются (отсекает пустые/placeholder)."""
        from chimera.modules.snell_mirrors import find_manual_upload
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            filename = "tiny.zip"
            (tmp_path / filename).write_bytes(b"\x00" * 100)  # < 1KB
            with patch("chimera.modules.snell_mirrors.MANUAL_UPLOAD_PATHS",
                       [tmp_path]):
                result = find_manual_upload(filename)
            self.assertIsNone(result)


class TestArchitectureSupport(unittest.TestCase):
    """Поддержка архитектур Snell-бинарника."""

    def test_amd64_supported(self):
        from chimera.modules.snell_mirrors import _arch_suffix
        self.assertEqual(_arch_suffix("x86_64"), "amd64")
        self.assertEqual(_arch_suffix("amd64"), "amd64")

    def test_i386_supported(self):
        from chimera.modules.snell_mirrors import _arch_suffix
        self.assertEqual(_arch_suffix("i386"), "i386")
        self.assertEqual(_arch_suffix("i686"), "i386")

    def test_aarch64_supported(self):
        from chimera.modules.snell_mirrors import _arch_suffix
        self.assertEqual(_arch_suffix("aarch64"), "aarch64")
        self.assertEqual(_arch_suffix("arm64"), "aarch64")

    def test_armv7l_supported(self):
        from chimera.modules.snell_mirrors import _arch_suffix
        self.assertEqual(_arch_suffix("armv7l"), "armv7l")

    def test_armv6_falls_back_to_armv7l(self):
        """armv6 не выпускается — fallback на armv7l."""
        from chimera.modules.snell_mirrors import _arch_suffix
        self.assertEqual(_arch_suffix("armv6l"), "armv7l")

    def test_unsupported_arch_raises(self):
        from chimera.modules.snell_mirrors import _arch_suffix
        with self.assertRaises(ValueError):
            _arch_suffix("mips")


class TestPrintManualHint(unittest.TestCase):
    """print_snell_manual_download_hint() — подсказка для ручной загрузки."""

    def test_hint_contains_filename(self):
        from chimera.modules.snell_mirrors import print_snell_manual_download_hint
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_snell_manual_download_hint(version="4.1.1", arch="amd64")
        output = buf.getvalue()
        self.assertIn("snell-server-v4.1.1-linux-amd64.zip", output)

    def test_hint_contains_recommended_path(self):
        from chimera.modules.snell_mirrors import print_snell_manual_download_hint
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_snell_manual_download_hint()
        output = buf.getvalue()
        # Подсказка должна упоминать /root/ как рекомендованный путь.
        self.assertIn("/root", output)

    def test_hint_lists_multiple_mirrors(self):
        """В подсказке должно быть перечислено несколько зеркал."""
        from chimera.modules.snell_mirrors import print_snell_manual_download_hint
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_snell_manual_download_hint()
        output = buf.getvalue()
        # Должно быть минимум 5 зеркал (или "и ещё N зеркал").
        self.assertTrue(
            output.count("https://") >= 5 or "ещё" in output,
            "Подсказка должна содержать минимум 5 зеркал или сообщение 'ещё N'"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

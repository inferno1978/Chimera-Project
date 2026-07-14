#!/usr/bin/env python3
"""
tests/test_warp_curated_lists.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/warp_curated_lists.py.

Покрывает:
  1. _parse_list_body — парсинг списка доменов
  2. _cache_load — чтение кэша
  3. get_enabled_curated_domains — получение включённых доменов
  4. _fmt_ts — форматирование timestamp
  5. _manage_cron — управление cron
  6. CURATED_SOURCES — структура
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core


class TestParseListBody(unittest.TestCase):
    """_parse_list_body — парсинг списка доменов."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_empty_text(self):
        from chimera.modules.warp_curated_lists import _parse_list_body
        self.assertEqual(_parse_list_body(""), [])

    def test_skips_comments_and_empty(self):
        from chimera.modules.warp_curated_lists import _parse_list_body
        text = "# comment\n\n  \nexample.com\n"
        result = _parse_list_body(text)
        self.assertEqual(result, ["example.com"])

    def test_strips_wildcard_prefix(self):
        from chimera.modules.warp_curated_lists import _parse_list_body
        text = "*.example.com\n"
        result = _parse_list_body(text)
        self.assertIn("example.com", result)

    def test_lowercases(self):
        from chimera.modules.warp_curated_lists import _parse_list_body
        text = "EXAMPLE.COM\n"
        result = _parse_list_body(text)
        self.assertIn("example.com", result)

    def test_deduplicates(self):
        from chimera.modules.warp_curated_lists import _parse_list_body
        text = "example.com\nexample.com\n"
        result = _parse_list_body(text)
        self.assertEqual(len(result), 1)

    def test_returns_sorted(self):
        from chimera.modules.warp_curated_lists import _parse_list_body
        text = "zebra.com\napple.com\n"
        result = _parse_list_body(text)
        self.assertEqual(result, ["apple.com", "zebra.com"])

    def test_takes_first_word_only(self):
        from chimera.modules.warp_curated_lists import _parse_list_body
        text = "example.com extra stuff\n"
        result = _parse_list_body(text)
        self.assertEqual(result, ["example.com"])


class TestCacheLoad(unittest.TestCase):
    """_cache_load — чтение кэша."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cache = self._tmpdir / "cache.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.warp_curated_lists.CACHE_FILE", self._cache)

    def test_returns_default_when_no_file(self):
        from chimera.modules.warp_curated_lists import _cache_load
        with self._patch():
            result = _cache_load()
        self.assertIn("lists", result)
        self.assertIn("enabled", result)
        self.assertEqual(result["lists"], {})
        self.assertEqual(result["enabled"], [])

    def test_returns_default_on_corrupt(self):
        from chimera.modules.warp_curated_lists import _cache_load
        self._cache.write_text("{invalid")
        with self._patch():
            result = _cache_load()
        self.assertEqual(result["lists"], {})

    def test_returns_cache_when_valid(self):
        from chimera.modules.warp_curated_lists import _cache_load
        self._cache.write_text(json.dumps({
            "lists": {"ru": {"domains": ["x.com"]}},
            "enabled": ["ru"],
        }))
        with self._patch():
            result = _cache_load()
        self.assertIn("ru", result["lists"])
        self.assertIn("ru", result["enabled"])


class TestGetEnabledCuratedDomains(unittest.TestCase):
    """get_enabled_curated_domains — получение включённых доменов."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cache = self._tmpdir / "cache.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.warp_curated_lists.CACHE_FILE", self._cache)

    def test_returns_empty_when_no_cache(self):
        from chimera.modules.warp_curated_lists import get_enabled_curated_domains
        with self._patch():
            self.assertEqual(get_enabled_curated_domains(), [])

    def test_returns_empty_when_nothing_enabled(self):
        from chimera.modules.warp_curated_lists import get_enabled_curated_domains
        self._cache.write_text(json.dumps({
            "lists": {"ru": {"domains": ["x.com"]}},
            "enabled": [],
        }))
        with self._patch():
            self.assertEqual(get_enabled_curated_domains(), [])

    def test_returns_domains_for_enabled_key(self):
        from chimera.modules.warp_curated_lists import get_enabled_curated_domains
        self._cache.write_text(json.dumps({
            "lists": {"ru": {"domains": ["a.com", "b.com"]}},
            "enabled": ["ru"],
        }))
        with self._patch():
            result = get_enabled_curated_domains()
        self.assertIn("a.com", result)
        self.assertIn("b.com", result)

    def test_unions_multiple_enabled_keys(self):
        from chimera.modules.warp_curated_lists import get_enabled_curated_domains
        self._cache.write_text(json.dumps({
            "lists": {
                "ru": {"domains": ["a.com"]},
                "geoblock": {"domains": ["b.com"]},
            },
            "enabled": ["ru", "geoblock"],
        }))
        with self._patch():
            result = get_enabled_curated_domains()
        self.assertIn("a.com", result)
        self.assertIn("b.com", result)

    def test_skips_enabled_key_without_entry(self):
        from chimera.modules.warp_curated_lists import get_enabled_curated_domains
        self._cache.write_text(json.dumps({
            "lists": {"ru": {"domains": ["a.com"]}},
            "enabled": ["ru", "nonexistent"],
        }))
        with self._patch():
            result = get_enabled_curated_domains()
        self.assertEqual(len(result), 1)
        self.assertIn("a.com", result)


class TestFmtTs(unittest.TestCase):
    """_fmt_ts — форматирование timestamp."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_never_loaded_when_none(self):
        from chimera.modules.warp_curated_lists import _fmt_ts
        result = _fmt_ts(None)
        self.assertIn("не загружен", result)

    def test_returns_never_loaded_when_empty(self):
        from chimera.modules.warp_curated_lists import _fmt_ts
        result = _fmt_ts("")
        self.assertIn("не загружен", result)

    def test_formats_iso_timestamp(self):
        from chimera.modules.warp_curated_lists import _fmt_ts
        result = _fmt_ts("2024-01-15T03:17:00+00:00")
        self.assertIn("2024-01-15", result)
        self.assertIn("03:17:00", result)
        self.assertIn("UTC", result)


class TestCuratedSources(unittest.TestCase):
    """CURATED_SOURCES — структура."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_has_ru_geoblock_google_ai(self):
        from chimera.modules.warp_curated_lists import CURATED_SOURCES
        for key in ("ru", "geoblock", "google_ai"):
            self.assertIn(key, CURATED_SOURCES)

    def test_each_source_has_url_label_hint(self):
        from chimera.modules.warp_curated_lists import CURATED_SOURCES
        for key, src in CURATED_SOURCES.items():
            with self.subTest(key=key):
                self.assertIn("url", src)
                self.assertIn("label", src)
                self.assertIn("hint", src)


class TestManageCron(unittest.TestCase):
    """_manage_cron — управление cron."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cron = self._tmpdir / "cron"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.warp_curated_lists.CRON_FILE", self._cron)

    def test_disable_removes_file(self):
        from chimera.modules.warp_curated_lists import _manage_cron
        self._cron.write_text("cron content")
        with self._patch():
            _manage_cron(False)
        self.assertFalse(self._cron.exists())

    def test_enable_creates_file(self):
        import stat
        from chimera.modules.warp_curated_lists import _manage_cron
        with self._patch():
            _manage_cron(True)
        self.assertTrue(self._cron.exists())
        content = self._cron.read_text()
        self.assertIn("--sync-lists", content)
        mode = stat.S_IMODE(os.stat(self._cron).st_mode)
        self.assertEqual(mode, 0o644)


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""
tests/test_ru_subnets.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/ru_subnets.py.

Покрывает:
  1. _ru_subnets_save — запись файла подсетей
  2. _ru_subnets_load_from_file — чтение файла
  3. _fetch_ru_subnets_from_ripe — парсинг delegated-файла (mocked urllib)
"""
from __future__ import annotations

import json
import math
import os
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("vless_installer._core")
    fake_core.__dict__.update(g)
    sys.modules["vless_installer._core"] = fake_core


class TestRuSubnetsSave(unittest.TestCase):
    """_ru_subnets_save — запись файла."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._file = self._tmpdir / "ru_subnets.txt"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.ru_subnets.RU_SUBNETS_FILE",
                     self._file)

    def test_writes_file_with_header(self):
        from vless_installer.modules.ru_subnets import _ru_subnets_save
        with self._patch():
            _ru_subnets_save(["10.0.0.0/8", "192.168.0.0/16"])
        content = self._file.read_text()
        self.assertIn("10.0.0.0/8", content)
        self.assertIn("192.168.0.0/16", content)

    def test_sorts_cidrs(self):
        from vless_installer.modules.ru_subnets import _ru_subnets_save
        with self._patch():
            _ru_subnets_save(["192.168.0.0/16", "10.0.0.0/8"])
        content = self._file.read_text()
        # 10.0.0.0/8 должно быть раньше 192.168.0.0/16
        self.assertLess(content.index("10.0.0.0/8"), content.index("192.168.0.0/16"))


class TestRuSubnetsLoadFromFile(unittest.TestCase):
    """_ru_subnets_load_from_file — чтение файла."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._file = self._tmpdir / "ru_subnets.txt"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.ru_subnets.RU_SUBNETS_FILE",
                     self._file)

    def test_returns_empty_when_no_file(self):
        from vless_installer.modules.ru_subnets import _ru_subnets_load_from_file
        with self._patch():
            self.assertEqual(_ru_subnets_load_from_file(), [])

    def test_loads_cidrs(self):
        from vless_installer.modules.ru_subnets import _ru_subnets_load_from_file
        self._file.write_text(
            "# header comment\n"
            "10.0.0.0/8\n"
            "192.168.0.0/16\n"
        )
        with self._patch():
            result = _ru_subnets_load_from_file()
        self.assertEqual(len(result), 2)
        self.assertIn("10.0.0.0/8", result)

    def test_filters_comments(self):
        from vless_installer.modules.ru_subnets import _ru_subnets_load_from_file
        self._file.write_text("# only comments\n# another\n")
        with self._patch():
            self.assertEqual(_ru_subnets_load_from_file(), [])


class TestFetchRuSubnetsFromRipe(unittest.TestCase):
    """_fetch_ru_subnets_from_ripe — парсинг delegated-файла (mocked)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _mock_urlopen(self, content: str):
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None
        mock_resp.read.return_value = content.encode()
        return mock_resp

    def _mock_core(self):
        """Мок core с нужными атрибутами."""
        core = MagicMock()
        core.ASN_CACHE_DB = None
        core.ASN_CACHE_MAX_AGE_DAYS = 30
        core._asn_cache_load = MagicMock(return_value=([], None))
        core._asn_cache_save = MagicMock()
        core.warn = MagicMock()
        core.info = MagicMock()
        return core

    def test_parses_ipv4_delegated_line(self):
        """RIPE delegated формат: registry|CC|type|start|value|date|status.
        value=256 → prefix = 32 - log2(256) = 32 - 8 = 24 → /24."""
        from vless_installer.modules import ru_subnets
        content = (
            "2.0|ripencc|20260701|KV\n"
            "ripencc|RU|ipv4|10.0.0.0|256|20260101|allocated\n"
        )
        with patch.object(ru_subnets, "_core_module", return_value=self._mock_core()), \
             patch("urllib.request.urlopen", return_value=self._mock_urlopen(content)):
            result = ru_subnets._fetch_ru_subnets_from_ripe()
        self.assertIn("10.0.0.0/24", result)

    def test_parses_ipv6_delegated_line(self):
        """IPv6: value = prefixlen напрямую."""
        from vless_installer.modules import ru_subnets
        content = (
            "2.0|ripencc|20260701|KV\n"
            "ripencc|RU|ipv6|2001:db8::|48|20260101|allocated\n"
        )
        with patch.object(ru_subnets, "_core_module", return_value=self._mock_core()), \
             patch("urllib.request.urlopen", return_value=self._mock_urlopen(content)):
            result = ru_subnets._fetch_ru_subnets_from_ripe()
        self.assertIn("2001:db8::/48", result)

    def test_skips_non_ru(self):
        from vless_installer.modules import ru_subnets
        content = (
            "2.0|ripencc|20260701|KV\n"
            "ripencc|US|ipv4|1.0.0.0|256|20260101|allocated\n"
            "ripencc|RU|ipv4|10.0.0.0|256|20260101|allocated\n"
        )
        with patch.object(ru_subnets, "_core_module", return_value=self._mock_core()), \
             patch("urllib.request.urlopen", return_value=self._mock_urlopen(content)):
            result = ru_subnets._fetch_ru_subnets_from_ripe()
        self.assertNotIn("1.0.0.0/24", result)
        self.assertIn("10.0.0.0/24", result)

    def test_returns_empty_on_network_error(self):
        from vless_installer.modules import ru_subnets
        with patch.object(ru_subnets, "_core_module", return_value=self._mock_core()), \
             patch("urllib.request.urlopen", side_effect=Exception("network error")):
            result = ru_subnets._fetch_ru_subnets_from_ripe()
        # fallback на _asn_cache_load возвращает ([], None) → пустой список
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

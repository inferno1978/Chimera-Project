#!/usr/bin/env python3
"""
tests/test_asn_cache.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/asn_cache.py.

Покрывает:
  1. _asn_cache_save / _asn_cache_load / _asn_cache_delete — SQLite CRUD
  2. _asn_cache_info — список всех записей
  3. _fmt_asn_short — форматирование ASN
  4. _lookup_asn — HTTP lookup (mocked urllib)
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


class TestAsnCacheSaveLoad(unittest.TestCase):
    """_asn_cache_save / _asn_cache_load — SQLite CRUD."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._db = self._tmpdir / "asn_cache.sqlite3"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.asn_cache.ASN_CACHE_DB", self._db)

    def test_load_returns_empty_when_no_db(self):
        from chimera.modules.asn_cache import _asn_cache_load
        with self._patch():
            cidrs, age = _asn_cache_load("AS123")
        self.assertEqual(cidrs, [])
        self.assertIsNone(age)

    def test_save_then_load(self):
        from chimera.modules.asn_cache import (
            _asn_cache_save, _asn_cache_load,
        )
        with self._patch():
            _asn_cache_save("AS123", ["1.2.3.0/24", "5.6.7.0/24"])
            cidrs, age = _asn_cache_load("AS123")
        self.assertEqual(len(cidrs), 2)
        self.assertIn("1.2.3.0/24", cidrs)
        self.assertIsNotNone(age)
        self.assertGreaterEqual(age, 0)

    def test_load_returns_empty_for_missing_key(self):
        from chimera.modules.asn_cache import (
            _asn_cache_save, _asn_cache_load,
        )
        with self._patch():
            _asn_cache_save("AS123", ["1.0.0.0/8"])
            cidrs, age = _asn_cache_load("AS999")
        self.assertEqual(cidrs, [])

    def test_overwrites_existing_key(self):
        from chimera.modules.asn_cache import (
            _asn_cache_save, _asn_cache_load,
        )
        with self._patch():
            _asn_cache_save("AS123", ["1.0.0.0/8"])
            _asn_cache_save("AS123", ["2.0.0.0/8", "3.0.0.0/8"])
            cidrs, _ = _asn_cache_load("AS123")
        self.assertEqual(len(cidrs), 2)


class TestAsnCacheDelete(unittest.TestCase):
    """_asn_cache_delete."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._db = self._tmpdir / "asn_cache.sqlite3"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.asn_cache.ASN_CACHE_DB", self._db)

    def test_deletes_existing_key(self):
        from chimera.modules.asn_cache import (
            _asn_cache_save, _asn_cache_load, _asn_cache_delete,
        )
        with self._patch():
            _asn_cache_save("AS123", ["1.0.0.0/8"])
            _asn_cache_delete("AS123")
            cidrs, _ = _asn_cache_load("AS123")
        self.assertEqual(cidrs, [])

    def test_does_not_raise_for_missing_key(self):
        from chimera.modules.asn_cache import _asn_cache_delete
        with self._patch():
            _asn_cache_delete("nonexistent")  # не должно бросать


class TestAsnCacheInfo(unittest.TestCase):
    """_asn_cache_info — список всех записей."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._db = self._tmpdir / "asn_cache.sqlite3"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.asn_cache.ASN_CACHE_DB", self._db)

    def test_returns_empty_when_no_db(self):
        from chimera.modules.asn_cache import _asn_cache_info
        with self._patch():
            result = _asn_cache_info()
        self.assertEqual(result, [])

    def test_returns_list_of_dicts(self):
        from chimera.modules.asn_cache import (
            _asn_cache_save, _asn_cache_info,
        )
        with self._patch():
            _asn_cache_save("AS123", ["1.0.0.0/8"])
            _asn_cache_save("AS456", ["2.0.0.0/8", "3.0.0.0/8"])
            info = _asn_cache_info()
        self.assertEqual(len(info), 2)
        for entry in info:
            self.assertIn("key", entry)
            self.assertIn("count", entry)
            self.assertIn("age_days", entry)


class TestFmtAsnShort(unittest.TestCase):
    """_fmt_asn_short — форматирование ASN."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_empty_dict_returns_empty(self):
        from chimera.modules.asn_cache import _fmt_asn_short
        self.assertEqual(_fmt_asn_short({}), "")

    def test_only_asn(self):
        from chimera.modules.asn_cache import _fmt_asn_short
        result = _fmt_asn_short({"asn": "AS12345"})
        self.assertEqual(result, "AS12345")

    def test_asn_with_isp(self):
        from chimera.modules.asn_cache import _fmt_asn_short
        result = _fmt_asn_short({"asn": "AS12345 Cloudflare", "isp": "Cloudflare Inc."})
        self.assertIn("AS12345", result)
        self.assertIn("Cloudflare Inc.", result)
        self.assertIn(" · ", result)

    def test_only_isp(self):
        from chimera.modules.asn_cache import _fmt_asn_short
        result = _fmt_asn_short({"isp": "Some ISP"})
        self.assertIn("Some ISP", result)


class TestLookupAsn(unittest.TestCase):
    """_lookup_asn — HTTP lookup (mocked urllib)."""

    def setUp(self):
        _setup_core_in_sysmodules()
        # сбрасываем in-memory кеш
        from chimera.modules import asn_cache
        asn_cache._asn_cache.clear()

    def test_returns_dict_on_success(self):
        from chimera.modules import asn_cache
        mock_response = MagicMock()
        mock_response.__enter__.return_value = mock_response
        mock_response.__exit__.return_value = None
        mock_response.read.return_value = json.dumps({
            "as": "AS12345 Cloudflare",
            "org": "Cloudflare",
            "isp": "Cloudflare Inc.",
            "status": "success",
        }).encode()
        with patch("urllib.request.urlopen", return_value=mock_response):
            result = asn_cache._lookup_asn("1.1.1.1")
        self.assertEqual(result["asn"], "AS12345 Cloudflare")
        self.assertEqual(result["isp"], "Cloudflare Inc.")

    def test_caches_result(self):
        """Повторный запрос не идёт в сеть."""
        from chimera.modules import asn_cache
        mock_response = MagicMock()
        mock_response.__enter__.return_value = mock_response
        mock_response.__exit__.return_value = None
        mock_response.read.return_value = json.dumps({
            "as": "AS123", "org": "X", "isp": "Y", "status": "success",
        }).encode()
        with patch("urllib.request.urlopen", return_value=mock_response) as mock_urlopen:
            asn_cache._lookup_asn("1.1.1.1")
            asn_cache._lookup_asn("1.1.1.1")
        self.assertEqual(mock_urlopen.call_count, 1)

    def test_returns_empty_on_network_error(self):
        from chimera.modules import asn_cache
        with patch("urllib.request.urlopen", side_effect=Exception("network error")):
            result = asn_cache._lookup_asn("1.1.1.1")
        self.assertEqual(result, {})

    def test_returns_empty_on_failure_status(self):
        from chimera.modules import asn_cache
        mock_response = MagicMock()
        mock_response.__enter__.return_value = mock_response
        mock_response.__exit__.return_value = None
        mock_response.read.return_value = json.dumps({"status": "fail"}).encode()
        with patch("urllib.request.urlopen", return_value=mock_response):
            result = asn_cache._lookup_asn("1.1.1.1")
        self.assertEqual(result, {})


if __name__ == "__main__":
    unittest.main(verbosity=2)

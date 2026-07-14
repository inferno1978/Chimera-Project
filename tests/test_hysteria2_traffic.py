#!/usr/bin/env python3
"""
tests/test_hysteria2_traffic.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/hysteria2_traffic.py.

Покрывает:
  1. _bytes_to_human — форматирование байт
  2. _load_cache / _save_cache — JSON I/O
"""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    m = types.ModuleType("chimera._core")
    m.__dict__.update(g)
    sys.modules["chimera._core"] = m


class TestH2TrafficBytesToHuman(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_zero(self):
        from chimera.modules.hysteria2_traffic import _bytes_to_human
        self.assertIn("B", _bytes_to_human(0))
    def test_kb(self):
        from chimera.modules.hysteria2_traffic import _bytes_to_human
        self.assertIn("KB", _bytes_to_human(1024))
    def test_mb(self):
        from chimera.modules.hysteria2_traffic import _bytes_to_human
        self.assertIn("MB", _bytes_to_human(1024**2))
    def test_pb(self):
        from chimera.modules.hysteria2_traffic import _bytes_to_human
        self.assertIn("PB", _bytes_to_human(1024**5))


class TestH2TrafficCache(unittest.TestCase):
    def setUp(self):
        _setup_core()
        self._tmp = Path(tempfile.mkdtemp()); self._c = self._tmp / "cache.json"
    def tearDown(self):
        import shutil; shutil.rmtree(self._tmp, ignore_errors=True)
    def _patch(self):
        return patch("chimera.modules.hysteria2_traffic._STATS_CACHE", self._c)
    def test_load_empty(self):
        from chimera.modules.hysteria2_traffic import _load_cache
        with self._patch(): self.assertEqual(_load_cache(), {})
    def test_save_load(self):
        from chimera.modules.hysteria2_traffic import _load_cache, _save_cache
        with self._patch():
            _save_cache({"bytes":100}); self.assertEqual(_load_cache()["bytes"], 100)

# ── hysteria2_backup ───────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)

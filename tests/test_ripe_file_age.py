#!/usr/bin/env python3
"""
tests/test_ripe_file_age.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/ripe_file_age.py.

Покрывает:
  1. get_ripe_file_info — проверка exists/stale/critical
  2. ripe_file_age_banner — форматирование
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


class TestRipeFileAge(unittest.TestCase):
    def setUp(self):
        _setup_core()
        self._tmp = Path(tempfile.mkdtemp()); self._f = self._tmp / "ru.txt"
    def tearDown(self):
        import shutil; shutil.rmtree(self._tmp, ignore_errors=True)
    def _write_file(self, age_days=0):
        self._f.write_text("10.0.0.0/8\n" * 20); t = time.time() - age_days * 86400
        os.utime(self._f, (t, t))
    def test_get_info_no_file(self):
        from chimera.modules.ripe_file_age import get_ripe_file_info
        info = get_ripe_file_info(Path("/tmp/nonexistent_ripe_xyz.txt"))
        self.assertFalse(info["exists"])
    def test_get_info_fresh(self):
        from chimera.modules.ripe_file_age import get_ripe_file_info
        self._write_file(0)
        info = get_ripe_file_info(self._f)
        self.assertTrue(info["exists"])
        self.assertFalse(info["stale"])
        self.assertFalse(info["critical"])
    def test_get_info_stale(self):
        from chimera.modules.ripe_file_age import get_ripe_file_info, WARN_DAYS
        self._write_file(WARN_DAYS + 5)
        info = get_ripe_file_info(self._f)
        self.assertTrue(info["stale"])
    def test_get_info_critical(self):
        from chimera.modules.ripe_file_age import get_ripe_file_info, CRITICAL_DAYS
        self._write_file(CRITICAL_DAYS + 5)
        info = get_ripe_file_info(self._f)
        self.assertTrue(info["critical"])
    def test_banner_returns_string(self):
        from chimera.modules.ripe_file_age import ripe_file_age_banner
        self.assertIsInstance(ripe_file_age_banner(Path("/tmp/nonexistent.txt")), str)

# ── fingerprint_manager ────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)

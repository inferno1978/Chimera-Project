#!/usr/bin/env python3
"""
tests/test_config_backup.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/config_backup.py.

Покрывает:
  1. _parse_backup_ts — парсинг timestamp
  2. _backup_filename — формат имени
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


class TestConfigBackup(unittest.TestCase):
    def setUp(self):
        _setup_core()
        self._tmp = Path(tempfile.mkdtemp())
    def tearDown(self):
        import shutil; shutil.rmtree(self._tmp, ignore_errors=True)
    def test_parse_backup_ts_valid(self):
        from chimera.modules.config_backup import _parse_backup_ts
        ts = _parse_backup_ts("config-20260710-120000.json")
        self.assertGreater(ts, 0)
    def test_parse_backup_ts_invalid(self):
        from chimera.modules.config_backup import _parse_backup_ts
        self.assertEqual(_parse_backup_ts("invalid.json"), 0.0)
    def test_backup_filename_format(self):
        from chimera.modules.config_backup import _backup_filename, BACKUP_PREFIX, BACKUP_SUFFIX
        name = _backup_filename()
        self.assertTrue(name.startswith(BACKUP_PREFIX))
        self.assertTrue(name.endswith(BACKUP_SUFFIX))

# ── awg_hw_tuning ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)

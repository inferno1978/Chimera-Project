#!/usr/bin/env python3
"""
tests/test_awg_backup.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/awg_backup.py.

Покрывает:
  1. awgs_backup_list — список бэкапов (sorted by mtime)
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


class TestAwgBackup(unittest.TestCase):
    def setUp(self):
        _setup_core()
        self._tmp = Path(tempfile.mkdtemp())
    def tearDown(self):
        import shutil; shutil.rmtree(self._tmp, ignore_errors=True)
    def test_backup_list_empty(self):
        from chimera.modules.awg_backup import awgs_backup_list
        with patch("chimera.modules.awg_backup.AWGS_BACKUP_DIR", self._tmp):
            self.assertEqual(awgs_backup_list(), [])
    def test_backup_list_sorted(self):
        from chimera.modules.awg_backup import awgs_backup_list
        f1 = self._tmp / "h2_backup_1.tar.gz"; f1.write_text("x")
        time.sleep(0.01)
        f2 = self._tmp / "h2_backup_2.tar.gz"; f2.write_text("x")
        with patch("chimera.modules.awg_backup.AWGS_BACKUP_DIR", self._tmp):
            result = awgs_backup_list()
        self.assertEqual(len(result), 2)
        # newer first
        self.assertEqual(result[0].name, "h2_backup_2.tar.gz")

# ── cold_boot_restore ──────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""
tests/test_cold_boot_restore.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/cold_boot_restore.py.

Покрывает:
  1. _is_installed — проверка установки
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


class TestColdBootRestore(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_is_installed_false(self):
        from chimera.modules import cold_boot_restore
        with patch("pathlib.Path.exists", return_value=False):
            self.assertFalse(cold_boot_restore._is_installed())
    def test_is_installed_true(self):
        from chimera.modules import cold_boot_restore
        with patch("pathlib.Path.exists", return_value=True):
            self.assertTrue(cold_boot_restore._is_installed())

# ── connection_audit ───────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)

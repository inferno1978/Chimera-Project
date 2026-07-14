#!/usr/bin/env python3
"""
tests/test_scheduler.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/scheduler.py.

Покрывает:
  1. _cron_exists — проверка файла
  2. _pad — форматирование
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


class TestScheduler(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_cron_exists_true(self):
        from chimera.modules.scheduler import _cron_exists
        with patch("pathlib.Path.exists", return_value=True):
            self.assertTrue(_cron_exists("/some/path"))
    def test_cron_exists_false(self):
        from chimera.modules.scheduler import _cron_exists
        with patch("pathlib.Path.exists", return_value=False):
            self.assertFalse(_cron_exists("/some/path"))
    def test_pad_short_string(self):
        from chimera.modules.scheduler import _pad
        result = _pad("hi", 10)
        self.assertEqual(len(result), 10)

# ── logrotate ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)

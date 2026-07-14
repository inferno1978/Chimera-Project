#!/usr/bin/env python3
"""
tests/test_fingerprint_manager.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/fingerprint_manager.py.

Покрывает:
  1. XRAY_FP_LIST — список fingerprint'ов
  2. DEFAULT_FP — дефолт
  3. _FP_MENU — структура меню
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


class TestFingerprintManager(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_xray_fp_list_has_11_entries(self):
        from chimera.modules.fingerprint_manager import XRAY_FP_LIST
        self.assertGreaterEqual(len(XRAY_FP_LIST), 11)
        self.assertIn("chrome", XRAY_FP_LIST)
        self.assertIn("firefox", XRAY_FP_LIST)
        self.assertIn("safari", XRAY_FP_LIST)
    def test_default_fp_is_chrome(self):
        from chimera.modules.fingerprint_manager import DEFAULT_FP
        self.assertEqual(DEFAULT_FP, "chrome")
    def test_fp_menu_keys_are_numeric(self):
        from chimera.modules.fingerprint_manager import _FP_MENU
        for key in _FP_MENU:
            self.assertTrue(key.isdigit())

# ── config_backup ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)

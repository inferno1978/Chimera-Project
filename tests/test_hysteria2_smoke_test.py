#!/usr/bin/env python3
"""
tests/test_hysteria2_smoke_test.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/hysteria2_smoke_test.py.

Покрывает:
  1. _check — возвращает bool, печатает результат
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


class TestH2SmokeTest(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_check_returns_bool(self):
        from chimera.modules.hysteria2_smoke_test import _check
        import io
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            self.assertTrue(_check("test", True))
            self.assertFalse(_check("test", False))

# ── hysteria2_watchdog ─────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)

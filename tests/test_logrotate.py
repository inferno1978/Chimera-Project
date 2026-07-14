#!/usr/bin/env python3
"""
tests/test_logrotate.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/logrotate.py.

Покрывает:
  1. _detect_colors — tty/non-tty
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


class TestLogrotate(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_detect_colors_non_tty(self):
        from chimera.modules.logrotate import _detect_colors
        with patch("sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = False
            c = _detect_colors()
            for v in c.values(): self.assertEqual(v, "")

# ── nginx_watchdog ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)

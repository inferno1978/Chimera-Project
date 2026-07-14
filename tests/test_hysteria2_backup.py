#!/usr/bin/env python3
"""
tests/test_hysteria2_backup.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/hysteria2_backup.py.

Покрывает:
  1. _fmt_size — форматирование байт
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


class TestH2BackupFmtSize(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_zero(self):
        from chimera.modules.hysteria2_backup import _fmt_size
        self.assertIn("B", _fmt_size(0))
    def test_kb(self):
        from chimera.modules.hysteria2_backup import _fmt_size
        self.assertIn("KB", _fmt_size(1024))
    def test_mb(self):
        from chimera.modules.hysteria2_backup import _fmt_size
        self.assertIn("MB", _fmt_size(1024**2))

if __name__ == "__main__":
    unittest.main(verbosity=2)

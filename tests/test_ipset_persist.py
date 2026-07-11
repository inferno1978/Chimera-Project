#!/usr/bin/env python3
"""
tests/test_ipset_persist.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/ipset_persist.py.

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
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    m = types.ModuleType("vless_installer._core")
    m.__dict__.update(g)
    sys.modules["vless_installer._core"] = m


class TestIpsetPersist(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_detect_colors_non_tty(self):
        from vless_installer.modules.ipset_persist import _detect_colors
        with patch("sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = False
            c = _detect_colors()
            for v in c.values(): self.assertEqual(v, "")

# ── hysteria2_smoke_test ───────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)

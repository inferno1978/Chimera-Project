#!/usr/bin/env python3
"""
tests/test_awg_hw_tuning.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/awg_hw_tuning.py.

Покрывает:
  1. awgs_detect_ram_mb — чтение /proc/meminfo
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


class TestAwgHwTuning(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_detect_ram_mb(self):
        from vless_installer.modules import awg_hw_tuning
        content = "MemTotal:       16384000 kB\n"
        with patch("pathlib.Path.read_text", return_value=content):
            with patch("pathlib.Path.exists", return_value=True):
                ram = awg_hw_tuning.awgs_detect_ram_mb()
        self.assertEqual(ram, 16000)
    def test_detect_ram_no_file(self):
        from vless_installer.modules import awg_hw_tuning
        orig_read = Path.read_text
        def _fake_read(self):
            raise OSError("no file")
        with patch("pathlib.Path.read_text", _fake_read):
            self.assertEqual(awg_hw_tuning.awgs_detect_ram_mb(), 0)

# ── xray_safe_apply ────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)

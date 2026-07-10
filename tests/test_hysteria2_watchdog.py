#!/usr/bin/env python3
"""
tests/test_hysteria2_watchdog.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/hysteria2_watchdog.py.

Покрывает:
  1. _RESTART_LIMIT — константа
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


class TestH2Watchdog(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_restart_limit_constant(self):
        from vless_installer.modules.hysteria2_watchdog import _RESTART_LIMIT
        self.assertGreater(_RESTART_LIMIT, 0)

# ── hysteria2_cluster ──────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)

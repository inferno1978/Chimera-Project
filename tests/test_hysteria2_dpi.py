#!/usr/bin/env python3
"""
tests/test_hysteria2_dpi.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/hysteria2_dpi.py.

Покрывает:
  1. _best_port — выбор незаблокированного порта с мин rtt
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


class TestH2DpiBestPort(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_returns_none_when_empty(self):
        from vless_installer.modules.hysteria2_dpi import _best_port
        self.assertIsNone(_best_port([]))
    def test_returns_unblocked_with_min_rtt(self):
        from vless_installer.modules.hysteria2_dpi import _best_port
        results = [
            {"port":443,"blocked":True,"rtt_ms":10},
            {"port":8443,"blocked":False,"rtt_ms":20},
            {"port":2083,"blocked":False,"rtt_ms":50},
        ]
        self.assertEqual(_best_port(results), 8443)
    def test_fallback_to_timeout_ok(self):
        from vless_installer.modules.hysteria2_dpi import _best_port
        results = [{"port":443,"blocked":True,"rtt_ms":0},{"port":8443,"blocked":False,"rtt_ms":0}]
        self.assertEqual(_best_port(results), 8443)

# ── hysteria2_traffic ──────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""
tests/test_xray_safe_apply.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/xray_safe_apply.py.

Покрывает:
  1. xray_apply_with_smoke — DI stubs (ok/fail/smoke)
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


class TestXraySafeApply(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_returns_false_when_apply_fails(self):
        from chimera.modules.xray_safe_apply import xray_apply_with_smoke
        result = xray_apply_with_smoke(_core_apply_fn=lambda **kw: False)
        self.assertFalse(result)
    def test_returns_true_when_apply_ok_no_smoke(self):
        from chimera.modules.xray_safe_apply import xray_apply_with_smoke
        result = xray_apply_with_smoke(_core_apply_fn=lambda **kw: True)
        self.assertTrue(result)
    def test_calls_smoke_when_provided(self):
        from chimera.modules.xray_safe_apply import xray_apply_with_smoke
        smoke_called = []
        def _smoke(_do_emergency_restore_fn=None):
            smoke_called.append(True)
            return True
        result = xray_apply_with_smoke(
            _core_apply_fn=lambda **kw: True, _smoke_fn=_smoke)
        self.assertTrue(result)
        self.assertEqual(len(smoke_called), 1)

# ── scheduler ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)

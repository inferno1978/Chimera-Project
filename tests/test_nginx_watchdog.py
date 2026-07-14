#!/usr/bin/env python3
"""
tests/test_nginx_watchdog.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/nginx_watchdog.py.

Покрывает:
  1. _protocol_mode — чтение из state.json
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


class TestNginxWatchdog(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_protocol_mode_reality(self):
        from chimera.modules import nginx_watchdog
        import tempfile as tf
        tmpdir = Path(tf.mkdtemp())
        try:
            state = tmpdir / "state.json"
            state.write_text(json.dumps({"protocol_mode": "reality"}))
            with patch.object(nginx_watchdog, "_STATE", state):
                self.assertEqual(nginx_watchdog._protocol_mode(), "reality")
        finally:
            import shutil; shutil.rmtree(tmpdir, ignore_errors=True)
    def test_protocol_mode_default(self):
        from chimera.modules import nginx_watchdog
        import tempfile as tf
        tmpdir = Path(tf.mkdtemp())
        try:
            state = tmpdir / "state.json"
            state.write_text(json.dumps({"other": "x"}))
            with patch.object(nginx_watchdog, "_STATE", state):
                self.assertEqual(nginx_watchdog._protocol_mode(), "reality")
        finally:
            import shutil; shutil.rmtree(tmpdir, ignore_errors=True)

# ── system_deps ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)

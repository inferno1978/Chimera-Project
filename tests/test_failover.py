#!/usr/bin/env python3
"""
tests/test_failover.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/failover.py.

Покрывает:
  1. _failover_load / _failover_save — JSON I/O
  2. _auto_fallback_set_flag — установка флага авто-fallback
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("vless_installer._core")
    fake_core.__dict__.update(g)
    sys.modules["vless_installer._core"] = fake_core


class TestFailoverLoadSave(unittest.TestCase):
    """_failover_load / _failover_save — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "failover.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.failover._FAILOVER_STATE", self._state)

    def test_load_returns_empty_when_no_file(self):
        from vless_installer.modules.failover import _failover_load
        with self._patch():
            self.assertEqual(_failover_load(), {})

    def test_load_returns_empty_on_corrupt(self):
        from vless_installer.modules.failover import _failover_load
        self._state.write_text("{invalid")
        with self._patch():
            self.assertEqual(_failover_load(), {})

    def test_save_then_load(self):
        from vless_installer.modules.failover import _failover_load, _failover_save
        data = {"enabled": True, "last_fallback": "2026-07-10"}
        with self._patch():
            _failover_save(data)
            loaded = _failover_load()
        self.assertTrue(loaded["enabled"])
        self.assertEqual(loaded["last_fallback"], "2026-07-10")


class TestAutoFallbackSetFlag(unittest.TestCase):
    """_auto_fallback_set_flag — установка флага."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_sets_flag_true(self):
        from vless_installer.modules import failover
        self._state.write_text(json.dumps({"uuid": "abc"}))
        mock_core = MagicMock()
        mock_core.STATE_FILE = self._state
        mock_core.warn = MagicMock()
        with patch.object(failover, "_core_module", return_value=mock_core):
            failover._auto_fallback_set_flag(True)
        state = json.loads(self._state.read_text())
        self.assertTrue(state["auto_fallback_to_direct"])
        self.assertEqual(state["uuid"], "abc")

    def test_sets_flag_false(self):
        from vless_installer.modules import failover
        self._state.write_text(json.dumps({"uuid": "abc", "auto_fallback_to_direct": True}))
        mock_core = MagicMock()
        mock_core.STATE_FILE = self._state
        mock_core.warn = MagicMock()
        with patch.object(failover, "_core_module", return_value=mock_core):
            failover._auto_fallback_set_flag(False)
        state = json.loads(self._state.read_text())
        self.assertFalse(state["auto_fallback_to_direct"])

    def test_warns_when_no_state_file(self):
        from vless_installer.modules import failover
        mock_core = MagicMock()
        mock_core.STATE_FILE = Path("/tmp/nonexistent_failover_state.json")
        mock_core.warn = MagicMock()
        with patch.object(failover, "_core_module", return_value=mock_core):
            failover._auto_fallback_set_flag(True)
        mock_core.warn.assert_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)

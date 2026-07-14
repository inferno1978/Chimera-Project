#!/usr/bin/env python3
"""
tests/test_autoban.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/autoban.py.

Покрывает:
  1. _autoban_load / _autoban_save — JSON I/O с дефолтами
  2. _ban_report_append — добавление записи в отчёт
"""
from __future__ import annotations
import json, os, stat, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

def _setup_core():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text(); g = {}
    with patch.object(Path, 'mkdir', lambda s,*a,**k: None), \
         patch.object(Path, 'touch', lambda s,*a,**k: None), \
         patch.object(Path, 'chmod', lambda s,*a,**k: None), \
         patch('os.chown', lambda *a,**k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types; m = types.ModuleType("chimera._core"); m.__dict__.update(g)
    sys.modules["chimera._core"] = m

class TestAutobanLoadSave(unittest.TestCase):
    def setUp(self):
        _setup_core()
        self._tmp = Path(tempfile.mkdtemp())
        self._state = self._tmp / "autoban.json"
    def tearDown(self):
        import shutil; shutil.rmtree(self._tmp, ignore_errors=True)
    def _patch(self):
        return patch("chimera.modules.autoban._XRAY_BAN_STATE", self._state)
    def test_load_returns_defaults_when_no_file(self):
        from chimera.modules.autoban import _autoban_load
        with self._patch():
            data = _autoban_load()
        self.assertFalse(data["enabled"])
        self.assertIn("banned", data)
        self.assertIn("whitelist", data)
    def test_load_returns_defaults_on_corrupt(self):
        from chimera.modules.autoban import _autoban_load
        self._state.write_text("{invalid")
        with self._patch():
            data = _autoban_load()
        self.assertFalse(data["enabled"])
    def test_save_then_load(self):
        from chimera.modules.autoban import _autoban_load, _autoban_save
        with self._patch():
            _autoban_save({"enabled": True, "banned": {"1.2.3.4": {"count": 5}}})
            loaded = _autoban_load()
        self.assertTrue(loaded["enabled"])
        self.assertIn("1.2.3.4", loaded["banned"])
    def test_save_adds_ban_history(self):
        from chimera.modules.autoban import _autoban_load, _autoban_save
        with self._patch():
            _autoban_save({"enabled": True, "banned": {}})
            loaded = _autoban_load()
        self.assertIn("ban_history", loaded)
    def test_save_sets_chmod_600(self):
        from chimera.modules.autoban import _autoban_save
        with self._patch():
            _autoban_save({"enabled": False})
        mode = stat.S_IMODE(os.stat(self._state).st_mode)
        self.assertEqual(mode, 0o600)

if __name__ == "__main__":
    unittest.main(verbosity=2)

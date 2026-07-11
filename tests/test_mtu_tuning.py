#!/usr/bin/env python3
"""
tests/test_mtu_tuning.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/mtu_tuning.py.

Покрывает:
  1. _mtu_state_load / _mtu_state_save — JSON I/O
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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


class TestMtuStateLoadSave(unittest.TestCase):
    """_mtu_state_load / _mtu_state_save — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "mtu_tuning.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.mtu_tuning._MTU_STATE_FILE", self._state)

    def test_load_returns_empty_when_no_file(self):
        from vless_installer.modules.mtu_tuning import _mtu_state_load
        with self._patch():
            self.assertEqual(_mtu_state_load(), {})

    def test_load_returns_empty_on_corrupt(self):
        from vless_installer.modules.mtu_tuning import _mtu_state_load
        self._state.write_text("{invalid")
        with self._patch():
            self.assertEqual(_mtu_state_load(), {})

    def test_save_then_load(self):
        from vless_installer.modules.mtu_tuning import _mtu_state_load, _mtu_state_save
        data = {"mtu": 1280, "iface": "eth0"}
        with self._patch():
            _mtu_state_save(data)
            loaded = _mtu_state_load()
        self.assertEqual(loaded["mtu"], 1280)
        self.assertEqual(loaded["iface"], "eth0")


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""
tests/test_honeypot.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/honeypot.py.

Покрывает:
  1. _honeypot_state_load / _honeypot_state_save — JSON I/O
  2. _honeypot_write_script — генерация Python-скрипта
"""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("chimera._core")
    fake_core.__dict__.update(g)
    sys.modules["chimera._core"] = fake_core


class TestHoneypotStateLoadSave(unittest.TestCase):
    """_honeypot_state_load / _honeypot_state_save — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "honeypot.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.honeypot._HONEYPOT_STATE_FILE",
                     self._state)

    def test_load_returns_default_when_no_file(self):
        from chimera.modules.honeypot import _honeypot_state_load
        with self._patch():
            result = _honeypot_state_load()
        self.assertFalse(result["enabled"])
        self.assertEqual(result["port"], 9999)
        self.assertIn("127.0.0.1", result["whitelist"])
        self.assertIn("::1", result["whitelist"])
        self.assertEqual(result["banned"], {})

    def test_load_returns_default_on_corrupt(self):
        from chimera.modules.honeypot import _honeypot_state_load
        self._state.write_text("{invalid")
        with self._patch():
            result = _honeypot_state_load()
        self.assertFalse(result["enabled"])

    def test_save_then_load(self):
        from chimera.modules.honeypot import (
            _honeypot_state_load, _honeypot_state_save,
        )
        data = {"enabled": True, "port": 2222, "whitelist": ["1.2.3.4"], "banned": {}}
        with self._patch():
            _honeypot_state_save(data)
            loaded = _honeypot_state_load()
        self.assertTrue(loaded["enabled"])
        self.assertEqual(loaded["port"], 2222)
        self.assertIn("1.2.3.4", loaded["whitelist"])

    def test_save_sets_chmod_600(self):
        from chimera.modules.honeypot import _honeypot_state_save
        with self._patch():
            _honeypot_state_save({"enabled": False})
        mode = stat.S_IMODE(os.stat(self._state).st_mode)
        self.assertEqual(mode, 0o600)


class TestHoneypotWriteScript(unittest.TestCase):
    """_honeypot_write_script — генерация Python-скрипта."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._script = self._tmpdir / "honeypot.py"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.honeypot._HONEYPOT_SCRIPT", self._script)

    def test_writes_script_with_port(self):
        from chimera.modules.honeypot import _honeypot_write_script
        with self._patch():
            _honeypot_write_script(port=2222, whitelist=["127.0.0.1"])
        content = self._script.read_text()
        self.assertIn("2222", content)
        self.assertIn("127.0.0.1", content)

    def test_script_is_executable(self):
        from chimera.modules.honeypot import _honeypot_write_script
        with self._patch():
            _honeypot_write_script(port=9999, whitelist=[])
        mode = stat.S_IMODE(os.stat(self._script).st_mode)
        self.assertTrue(mode & 0o100)  # executable bit

    def test_script_contains_ufw_ban_logic(self):
        from chimera.modules.honeypot import _honeypot_write_script
        with self._patch():
            _honeypot_write_script(port=9999, whitelist=["127.0.0.1"])
        content = self._script.read_text()
        self.assertIn("ufw", content)
        self.assertIn("deny", content)

    def test_script_contains_socket_bind(self):
        from chimera.modules.honeypot import _honeypot_write_script
        with self._patch():
            _honeypot_write_script(port=9999, whitelist=[])
        content = self._script.read_text()
        self.assertIn("bind", content)


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""
tests/test_port_hopping.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/port_hopping.py.

Покрывает:
  1. _load_ph / _save_ph — JSON I/O port_hopping.json
  2. _load_state — чтение state.json
  3. _real_port — реальный порт из state
  4. _log — запись в лог-файл
"""
from __future__ import annotations

import json
import os
import re
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


class TestLoadSavePh(unittest.TestCase):
    """_load_ph / _save_ph — JSON I/O port_hopping.json."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._ph = self._tmpdir / "port_hopping.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.port_hopping._PH_FILE", self._ph)

    def test_load_returns_default_when_no_file(self):
        from chimera.modules.port_hopping import _load_ph
        with self._patch():
            result = _load_ph()
        self.assertFalse(result["enabled"])

    def test_load_returns_default_on_corrupt(self):
        from chimera.modules.port_hopping import _load_ph
        self._ph.write_text("{invalid")
        with self._patch():
            result = _load_ph()
        self.assertFalse(result["enabled"])

    def test_save_then_load(self):
        from chimera.modules.port_hopping import _load_ph, _save_ph
        with self._patch():
            _save_ph({"enabled": True, "port_start": 10000, "port_end": 10050})
            loaded = _load_ph()
        self.assertTrue(loaded["enabled"])
        self.assertEqual(loaded["port_start"], 10000)

    def test_save_sets_chmod_600(self):
        import stat
        from chimera.modules.port_hopping import _save_ph
        with self._patch():
            _save_ph({"enabled": False})
        mode = stat.S_IMODE(os.stat(self._ph).st_mode)
        self.assertEqual(mode, 0o600)


class TestLoadState(unittest.TestCase):
    """_load_state — чтение state.json."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.port_hopping._STATE_FILE", self._state)

    def test_returns_empty_when_no_file(self):
        from chimera.modules.port_hopping import _load_state
        with self._patch():
            self.assertEqual(_load_state(), {})

    def test_returns_empty_on_corrupt(self):
        from chimera.modules.port_hopping import _load_state
        self._state.write_text("{invalid")
        with self._patch():
            self.assertEqual(_load_state(), {})

    def test_returns_state(self):
        from chimera.modules.port_hopping import _load_state
        self._state.write_text(json.dumps({"server_port": 8443}))
        with self._patch():
            st = _load_state()
        self.assertEqual(st["server_port"], 8443)


class TestRealPort(unittest.TestCase):
    """_real_port — реальный порт из state."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.port_hopping._STATE_FILE", self._state)

    def test_returns_port_from_state(self):
        from chimera.modules.port_hopping import _real_port
        self._state.write_text(json.dumps({"server_port": 8443}))
        with self._patch():
            self.assertEqual(_real_port(), 8443)

    def test_returns_443_when_no_state(self):
        from chimera.modules.port_hopping import _real_port
        with self._patch():
            self.assertEqual(_real_port(), 443)

    def test_returns_443_when_no_server_port(self):
        from chimera.modules.port_hopping import _real_port
        self._state.write_text(json.dumps({"other": "x"}))
        with self._patch():
            self.assertEqual(_real_port(), 443)


class TestLog(unittest.TestCase):
    """_log — запись в лог-файл."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._log = self._tmpdir / "vless-install.log"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.port_hopping._LOG_FILE", self._log)

    def test_writes_timestamped_line(self):
        from chimera.modules.port_hopping import _log
        with self._patch():
            _log("INFO", "test message")
        content = self._log.read_text()
        self.assertIn("INFO", content)
        self.assertIn("test message", content)

    def test_strips_ansi_codes(self):
        """ANSI-коды удаляются из лог-файла."""
        from chimera.modules.port_hopping import _log
        with self._patch():
            _log("INFO", "\033[1;31mred text\033[0m")
        content = self._log.read_text()
        self.assertNotIn("\033[", content)
        self.assertIn("red text", content)


if __name__ == "__main__":
    unittest.main(verbosity=2)

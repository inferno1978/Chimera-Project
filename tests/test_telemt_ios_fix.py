#!/usr/bin/env python3
"""
tests/test_telemt_ios_fix.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/telemt_ios_fix.py.

Покрывает:
  1. _get_telemt_port — чтение порта
  2. _get_current_mss — чтение client_mss
  3. _strip_client_mss — удаление client_mss из TOML
  4. _pick_free_port — поиск свободного порта (mocked _port_in_use)
  5. IosFixConfig — dataclass
  6. _load_state / _save_state — JSON I/O
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


class TestGetTelemtPort(unittest.TestCase):
    """_get_telemt_port — чтение порта из TOML."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "telemt.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.telemt_ios_fix._CONFIG_FILE",
                     self._cfg)

    def test_returns_zero_when_no_file(self):
        from chimera.modules.telemt_ios_fix import _get_telemt_port
        with self._patch():
            self.assertEqual(_get_telemt_port(), 0)

    def test_returns_port(self):
        from chimera.modules.telemt_ios_fix import _get_telemt_port
        self._cfg.write_text('port = 443\n')
        with self._patch():
            self.assertEqual(_get_telemt_port(), 443)


class TestGetCurrentMss(unittest.TestCase):
    """_get_current_mss."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "telemt.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.telemt_ios_fix._CONFIG_FILE",
                     self._cfg)

    def test_returns_empty_when_no_file(self):
        from chimera.modules.telemt_ios_fix import _get_current_mss
        with self._patch():
            self.assertEqual(_get_current_mss(), "")

    def test_returns_value_with_quotes(self):
        from chimera.modules.telemt_ios_fix import _get_current_mss
        self._cfg.write_text('client_mss = "92"\n')
        with self._patch():
            self.assertEqual(_get_current_mss(), "92")

    def test_returns_empty_when_no_setting(self):
        from chimera.modules.telemt_ios_fix import _get_current_mss
        self._cfg.write_text('port = 443\n')
        with self._patch():
            self.assertEqual(_get_current_mss(), "")


class TestStripClientMss(unittest.TestCase):
    """_strip_client_mss — удаление client_mss из TOML."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "telemt.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.telemt_ios_fix._CONFIG_FILE",
                     self._cfg)

    def test_returns_false_when_no_file(self):
        from chimera.modules.telemt_ios_fix import _strip_client_mss
        with self._patch():
            self.assertFalse(_strip_client_mss())

    def test_returns_false_when_no_mss(self):
        from chimera.modules.telemt_ios_fix import _strip_client_mss
        self._cfg.write_text('port = 443\n')
        with self._patch():
            self.assertFalse(_strip_client_mss())

    def test_removes_mss_line(self):
        from chimera.modules.telemt_ios_fix import _strip_client_mss
        self._cfg.write_text('port = 443\nclient_mss = "92"\nother = "x"\n')
        with self._patch():
            self.assertTrue(_strip_client_mss())
        content = self._cfg.read_text()
        self.assertNotIn("client_mss", content)
        self.assertIn("port = 443", content)
        self.assertIn('other = "x"', content)


class TestPickFreePort(unittest.TestCase):
    """_pick_free_port — поиск свободного порта."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_start_when_free(self):
        from chimera.modules import telemt_ios_fix
        with patch.object(telemt_ios_fix, "_port_in_use", return_value=False):
            self.assertEqual(telemt_ios_fix._pick_free_port(8443, 0), 8443)

    def test_skips_exclude(self):
        from chimera.modules import telemt_ios_fix
        with patch.object(telemt_ios_fix, "_port_in_use", return_value=False):
            self.assertEqual(telemt_ios_fix._pick_free_port(8443, 8443), 8444)

    def test_skips_used_ports(self):
        from chimera.modules import telemt_ios_fix
        # 8443 занят, 8444 свободен
        with patch.object(telemt_ios_fix, "_port_in_use",
                          side_effect=[True, False]):
            self.assertEqual(telemt_ios_fix._pick_free_port(8443, 0), 8444)

    def test_returns_zero_when_all_taken(self):
        from chimera.modules import telemt_ios_fix
        with patch.object(telemt_ios_fix, "_port_in_use", return_value=True):
            self.assertEqual(telemt_ios_fix._pick_free_port(8443, 0), 0)


class TestIosFixConfig(unittest.TestCase):
    """IosFixConfig — dataclass."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_defaults(self):
        from chimera.modules.telemt_ios_fix import IosFixConfig
        cfg = IosFixConfig()
        self.assertFalse(cfg.enabled)
        self.assertEqual(cfg.ext_port, 0)
        self.assertEqual(cfg.target_port, 0)
        self.assertEqual(cfg.mss, 92)


class TestLoadSaveState(unittest.TestCase):
    """_load_state / _save_state."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "ios_fix.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.telemt_ios_fix._STATE_FILE",
                     self._state)

    def test_load_returns_default_when_no_file(self):
        from chimera.modules.telemt_ios_fix import _load_state
        with self._patch():
            cfg = _load_state()
        self.assertFalse(cfg.enabled)

    def test_load_filters_unknown_keys(self):
        from chimera.modules.telemt_ios_fix import _load_state
        self._state.write_text(json.dumps({
            "enabled": True, "ext_port": 8443, "target_port": 443,
            "mss": 92, "unknown_key": "ignored",
        }))
        with self._patch():
            cfg = _load_state()
        self.assertTrue(cfg.enabled)
        self.assertEqual(cfg.ext_port, 8443)

    def test_save_then_load(self):
        from chimera.modules.telemt_ios_fix import (
            _load_state, _save_state, IosFixConfig,
        )
        cfg = IosFixConfig(enabled=True, ext_port=8443, target_port=443, mss=92)
        with self._patch():
            _save_state(cfg)
            loaded = _load_state()
        self.assertTrue(loaded.enabled)
        self.assertEqual(loaded.ext_port, 8443)


if __name__ == "__main__":
    unittest.main(verbosity=2)

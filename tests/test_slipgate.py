#!/usr/bin/env python3
"""
tests/test_slipgate.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/slipgate.py.

Покрывает:
  1. _load_state / _save_state — JSON I/O
  2. _is_installed — проверка установки
  3. _get_latest_version — получение версии (mocked urllib)
  4. _plain / _wlen — unicode helpers
"""
from __future__ import annotations

import json
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


class TestLoadSaveState(unittest.TestCase):
    """_load_state / _save_state — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "slipgate.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.slipgate._MODULE_STATE_FILE", self._state)

    def test_load_returns_empty_when_no_file(self):
        from vless_installer.modules.slipgate import _load_state
        with self._patch():
            self.assertEqual(_load_state(), {})

    def test_load_returns_empty_on_corrupt(self):
        from vless_installer.modules.slipgate import _load_state
        self._state.write_text("{invalid")
        with self._patch():
            self.assertEqual(_load_state(), {})

    def test_save_then_load(self):
        from vless_installer.modules.slipgate import _load_state, _save_state
        with self._patch():
            _save_state({"version": "1.0", "installed": True})
            loaded = _load_state()
        self.assertTrue(loaded["installed"])
        self.assertEqual(loaded["version"], "1.0")


class TestIsInstalled(unittest.TestCase):
    """_is_installed."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._bin = self._tmpdir / "slipgate"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.slipgate._SLIPGATE_BIN", self._bin)

    def test_returns_false_when_no_binary(self):
        from vless_installer.modules.slipgate import _is_installed
        with self._patch():
            self.assertFalse(_is_installed())

    def test_returns_true_when_binary_exists(self):
        from vless_installer.modules.slipgate import _is_installed
        self._bin.write_text("x")
        with self._patch():
            self.assertTrue(_is_installed())


class TestGetLatestVersion(unittest.TestCase):
    """_get_latest_version — mocked urllib."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_version_on_success(self):
        from vless_installer.modules.slipgate import _get_latest_version
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None
        mock_resp.read.return_value = json.dumps({"tag_name": "v1.2.3"}).encode()
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = _get_latest_version()
        self.assertEqual(result, "1.2.3")

    def test_returns_unknown_on_error(self):
        from vless_installer.modules.slipgate import _get_latest_version
        with patch("urllib.request.urlopen", side_effect=Exception("network error")):
            result = _get_latest_version()
        self.assertEqual(result, "unknown")


class TestPlain(unittest.TestCase):
    """_plain — strip ANSI."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_plain_string_unchanged(self):
        from vless_installer.modules.slipgate import _plain
        self.assertEqual(_plain("hello"), "hello")

    def test_strips_ansi(self):
        from vless_installer.modules.slipgate import _plain
        self.assertEqual(_plain("\033[1;31mhi\033[0m"), "hi")


class TestWlen(unittest.TestCase):
    """_wlen — display width."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ascii(self):
        from vless_installer.modules.slipgate import _wlen
        self.assertEqual(_wlen("hello"), 5)

    def test_cjk_two_columns(self):
        from vless_installer.modules.slipgate import _wlen
        self.assertEqual(_wlen("中文"), 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""
tests/test_telemt_panel.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/telemt_panel.py.

Покрывает:
  1. _now_str — текущая дата/время
  2. _is_installed — проверка установки
  3. _telemt_is_installed — проверка telemt
  4. _plain / _wlen — unicode helpers
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

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


class TestNowStr(unittest.TestCase):
    """_now_str — текущая дата/время."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_formatted_string(self):
        from chimera.modules.telemt_panel import _now_str
        result = _now_str()
        self.assertRegex(result, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
        datetime.strptime(result, "%Y-%m-%d %H:%M:%S")


class TestIsInstalled(unittest.TestCase):
    """_is_installed — проверка установки панели."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._bin = self._tmpdir / "telemt-panel"
        self._cfg = self._tmpdir / "config.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("chimera.modules.telemt_panel.BIN_PATH", self._bin),
            patch("chimera.modules.telemt_panel.CONFIG_FILE", self._cfg),
        )

    def test_returns_false_when_neither(self):
        from chimera.modules.telemt_panel import _is_installed
        with self._patch()[0], self._patch()[1]:
            self.assertFalse(_is_installed())

    def test_returns_true_when_both(self):
        from chimera.modules.telemt_panel import _is_installed
        self._bin.write_text("x")
        self._cfg.write_text("x")
        with self._patch()[0], self._patch()[1]:
            self.assertTrue(_is_installed())


class TestTelemTIsInstalled(unittest.TestCase):
    """_telemt_is_installed — проверка telemt."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_false_when_mp_is_none(self):
        from chimera.modules.telemt_panel import _telemt_is_installed
        self.assertFalse(_telemt_is_installed(None))

    def test_returns_false_when_files_missing(self):
        from chimera.modules.telemt_panel import _telemt_is_installed
        mp = MagicMock()
        mp.CONFIG_FILE = Path("/tmp/nonexistent_telemt_cfg")
        mp.BIN_PATH = Path("/tmp/nonexistent_telemt_bin")
        self.assertFalse(_telemt_is_installed(mp))

    def test_returns_true_when_files_exist(self):
        import tempfile as tf
        from chimera.modules.telemt_panel import _telemt_is_installed
        tmpdir = Path(tf.mkdtemp())
        try:
            cfg = tmpdir / "telemt.toml"
            bin_path = tmpdir / "telemt"
            cfg.write_text("x")
            bin_path.write_text("x")
            mp = MagicMock()
            mp.CONFIG_FILE = cfg
            mp.BIN_PATH = bin_path
            self.assertTrue(_telemt_is_installed(mp))
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestPlain(unittest.TestCase):
    """_plain — strip ANSI."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_plain_string_unchanged(self):
        from chimera.modules.telemt_panel import _plain
        self.assertEqual(_plain("hello"), "hello")

    def test_strips_ansi(self):
        from chimera.modules.telemt_panel import _plain
        self.assertEqual(_plain("\033[1;31mhi\033[0m"), "hi")


class TestWlen(unittest.TestCase):
    """_wlen — display width."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ascii(self):
        from chimera.modules.telemt_panel import _wlen
        self.assertEqual(_wlen("hello"), 5)

    def test_cjk_two_columns(self):
        from chimera.modules.telemt_panel import _wlen
        self.assertEqual(_wlen("中文"), 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)

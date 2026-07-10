#!/usr/bin/env python3
"""
tests/test_turntunnel.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/turntunnel.py.

Покрывает:
  1. _plain / _wlen — unicode helpers
  2. _is_amd64 — определение архитектуры
  3. _is_installed — проверка установки
  4. _log — запись в лог-файл
"""
from __future__ import annotations

import json
import os
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


class TestPlain(unittest.TestCase):
    """_plain — strip ANSI."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_plain_string_unchanged(self):
        from vless_installer.modules.turntunnel import _plain
        self.assertEqual(_plain("hello"), "hello")

    def test_strips_ansi(self):
        from vless_installer.modules.turntunnel import _plain
        self.assertEqual(_plain("\033[1;31mhi\033[0m"), "hi")


class TestWlen(unittest.TestCase):
    """_wlen — display width."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ascii(self):
        from vless_installer.modules.turntunnel import _wlen
        self.assertEqual(_wlen("hello"), 5)

    def test_cjk_two_columns(self):
        from vless_installer.modules.turntunnel import _wlen
        self.assertEqual(_wlen("中文"), 4)

    def test_ansi_zero_width(self):
        from vless_installer.modules.turntunnel import _wlen
        self.assertEqual(_wlen("\033[1mhi\033[0m"), 2)


class TestIsAmd64(unittest.TestCase):
    """_is_amd64."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_x86_64(self):
        from vless_installer.modules.turntunnel import _is_amd64
        with patch("platform.machine", return_value="x86_64"):
            self.assertTrue(_is_amd64())

    def test_aarch64(self):
        from vless_installer.modules.turntunnel import _is_amd64
        with patch("platform.machine", return_value="aarch64"):
            self.assertFalse(_is_amd64())


class TestIsInstalled(unittest.TestCase):
    """_is_installed."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._bin = self._tmpdir / "server"
        self._svc = self._tmpdir / "vk-turn-proxy.service"
        self._state = self._tmpdir / "turntunnel.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("vless_installer.modules.turntunnel._BIN_PATH", self._bin),
            patch("vless_installer.modules.turntunnel._SERVICE_FILE", self._svc),
            patch("vless_installer.modules.turntunnel._MODULE_STATE", self._state),
        )

    def test_returns_false_when_neither(self):
        from vless_installer.modules.turntunnel import _is_installed
        with self._patch()[0], self._patch()[1], self._patch()[2]:
            self.assertFalse(_is_installed())

    def test_returns_true_when_all(self):
        from vless_installer.modules.turntunnel import _is_installed
        self._bin.write_text("x")
        self._svc.write_text("x")
        self._state.write_text(json.dumps({"installed": True}))
        with self._patch()[0], self._patch()[1], self._patch()[2]:
            self.assertTrue(_is_installed())


class TestLog(unittest.TestCase):
    """_log — запись в лог-файл."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._log = self._tmpdir / "install.log"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.turntunnel._LOG_FILE", self._log)

    def test_writes_plain_text(self):
        from vless_installer.modules.turntunnel import _log
        with self._patch():
            _log("test message")
        content = self._log.read_text()
        self.assertIn("test message", content)

    def test_strips_ansi(self):
        from vless_installer.modules.turntunnel import _log
        with self._patch():
            _log("\033[1;31mred text\033[0m")
        content = self._log.read_text()
        self.assertNotIn("\033[", content)
        self.assertIn("red text", content)


if __name__ == "__main__":
    unittest.main(verbosity=2)

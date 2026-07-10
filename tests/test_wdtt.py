#!/usr/bin/env python3
"""
tests/test_wdtt.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/wdtt.py.

Покрывает:
  1. _plain / _wlen — unicode helpers
  2. _ver_tuple — парсинг версии
  3. _go_required_version — чтение go.mod
  4. _is_installed — проверка установки
  5. _load_cfg / _save_cfg / _load_passwords / _save_passwords — JSON I/O
  6. _save_link_file — сохранение ссылки
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
        from vless_installer.modules.wdtt import _plain
        self.assertEqual(_plain("hello"), "hello")

    def test_strips_ansi(self):
        from vless_installer.modules.wdtt import _plain
        self.assertEqual(_plain("\033[1;31mhi\033[0m"), "hi")


class TestWlen(unittest.TestCase):
    """_wlen — display width."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ascii(self):
        from vless_installer.modules.wdtt import _wlen
        self.assertEqual(_wlen("hello"), 5)

    def test_cjk_two_columns(self):
        from vless_installer.modules.wdtt import _wlen
        self.assertEqual(_wlen("中文"), 4)

    def test_ansi_zero_width(self):
        from vless_installer.modules.wdtt import _wlen
        self.assertEqual(_wlen("\033[1mhi\033[0m"), 2)


class TestVerTuple(unittest.TestCase):
    """_ver_tuple — парсинг версии."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_full_version(self):
        from vless_installer.modules.wdtt import _ver_tuple
        self.assertEqual(_ver_tuple("1.21.0"), (1, 21, 0))

    def test_two_part(self):
        from vless_installer.modules.wdtt import _ver_tuple
        self.assertEqual(_ver_tuple("1.21"), (1, 21, 0))

    def test_with_v_prefix(self):
        from vless_installer.modules.wdtt import _ver_tuple
        self.assertEqual(_ver_tuple("v1.21.5"), (1, 21, 5))

    def test_invalid_returns_zeros(self):
        from vless_installer.modules.wdtt import _ver_tuple
        self.assertEqual(_ver_tuple("abc"), (0, 0, 0))

    def test_long_version_truncates(self):
        from vless_installer.modules.wdtt import _ver_tuple
        self.assertEqual(_ver_tuple("1.2.3.4.5"), (1, 2, 3))


class TestGoRequiredVersion(unittest.TestCase):
    """_go_required_version — чтение go.mod."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._gomod = self._tmpdir / "go.mod"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_returns_default_when_no_file(self):
        from vless_installer.modules.wdtt import _go_required_version
        self.assertEqual(_go_required_version(self._gomod), "1.21.0")

    def test_returns_version_from_file(self):
        from vless_installer.modules.wdtt import _go_required_version
        self._gomod.write_text("module wdtt\ngo 1.22.5\n")
        self.assertEqual(_go_required_version(self._gomod), "1.22.5")

    def test_returns_default_when_no_directive(self):
        from vless_installer.modules.wdtt import _go_required_version
        self._gomod.write_text("module wdtt\n")
        self.assertEqual(_go_required_version(self._gomod), "1.21.0")


class TestIsInstalled(unittest.TestCase):
    """_is_installed."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._bin = self._tmpdir / "wdtt"
        self._svc = self._tmpdir / "wdtt.service"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("vless_installer.modules.wdtt._BIN_PATH", self._bin),
            patch("vless_installer.modules.wdtt._SERVICE_FILE", self._svc),
        )

    def test_returns_false_when_neither(self):
        from vless_installer.modules.wdtt import _is_installed
        with self._patch()[0], self._patch()[1]:
            self.assertFalse(_is_installed())

    def test_returns_true_when_both(self):
        from vless_installer.modules.wdtt import _is_installed
        self._bin.write_text("x")
        self._svc.write_text("x")
        with self._patch()[0], self._patch()[1]:
            self.assertTrue(_is_installed())


class TestLoadSaveCfg(unittest.TestCase):
    """_load_cfg / _save_cfg — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "config.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("vless_installer.modules.wdtt._CFG_FILE", self._cfg),
            patch("vless_installer.modules.wdtt._CFG_DIR", self._tmpdir),
        )

    def test_load_returns_empty_when_no_file(self):
        from vless_installer.modules.wdtt import _load_cfg
        with self._patch()[0], self._patch()[1]:
            self.assertEqual(_load_cfg(), {})

    def test_load_returns_empty_on_corrupt(self):
        from vless_installer.modules.wdtt import _load_cfg
        self._cfg.write_text("{invalid")
        with self._patch()[0], self._patch()[1]:
            self.assertEqual(_load_cfg(), {})

    def test_save_then_load(self):
        from vless_installer.modules.wdtt import _load_cfg, _save_cfg
        with self._patch()[0], self._patch()[1]:
            _save_cfg({"port": 56000, "users": []})
            loaded = _load_cfg()
        self.assertEqual(loaded["port"], 56000)


class TestLoadSavePasswords(unittest.TestCase):
    """_load_passwords / _save_passwords — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._pw = self._tmpdir / "passwords.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return (
            patch("vless_installer.modules.wdtt._PASSWORDS_FILE", self._pw),
            patch("vless_installer.modules.wdtt._CFG_DIR", self._tmpdir),
        )

    def test_load_returns_default_when_no_file(self):
        from vless_installer.modules.wdtt import _load_passwords
        with self._patch()[0], self._patch()[1]:
            result = _load_passwords()
        self.assertIn("main_password", result)
        self.assertIn("passwords", result)
        self.assertEqual(result["passwords"], {})

    def test_save_then_load(self):
        from vless_installer.modules.wdtt import _load_passwords, _save_passwords
        with self._patch()[0], self._patch()[1]:
            _save_passwords({"main_password": "secret", "passwords": {"dev1": "pw1"}})
            loaded = _load_passwords()
        self.assertEqual(loaded["main_password"], "secret")
        self.assertIn("dev1", loaded["passwords"])


class TestSaveLinkFile(unittest.TestCase):
    """_save_link_file — сохранение ссылки."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg_dir = self._tmpdir / "cfg"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("vless_installer.modules.wdtt._CFG_DIR", self._cfg_dir)

    def test_writes_file_with_link(self):
        import stat
        from vless_installer.modules.wdtt import _save_link_file
        with self._patch():
            path = _save_link_file("wdtt://link", "test.link")
        self.assertTrue(path.exists())
        content = path.read_text()
        self.assertIn("wdtt://link", content)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode, 0o600)


if __name__ == "__main__":
    unittest.main(verbosity=2)

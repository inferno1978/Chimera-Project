#!/usr/bin/env python3
"""
tests/test_dpi_censor_check.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/dpi_censor_check.py.

Покрывает:
  1. _deps_missing — проверка отсутствующих Python-модулей
  2. _build_args — сборка CLI аргументов
  3. _REQUIRED_MODULES — список зависимостей
"""
from __future__ import annotations

import importlib.util
import sys
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


class TestRequiredModules(unittest.TestCase):
    """_REQUIRED_MODULES — список."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_has_httpx_rich_yaml(self):
        from vless_installer.modules.dpi_censor_check import _REQUIRED_MODULES
        for mod in ("httpx", "rich", "yaml"):
            self.assertIn(mod, _REQUIRED_MODULES)


class TestDepsMissing(unittest.TestCase):
    """_deps_missing — проверка отсутствующих модулей."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_empty_when_all_present(self):
        from vless_installer.modules.dpi_censor_check import _deps_missing
        with patch("importlib.util.find_spec", return_value=MagicMock()):
            self.assertEqual(_deps_missing(), [])

    def test_returns_missing_modules(self):
        from vless_installer.modules.dpi_censor_check import (
            _deps_missing, _REQUIRED_MODULES,
        )
        # find_spec возвращает None для всех → все missing
        with patch("importlib.util.find_spec", return_value=None):
            result = _deps_missing()
        for mod in _REQUIRED_MODULES:
            self.assertIn(mod, result)

    def test_partial_missing(self):
        from vless_installer.modules.dpi_censor_check import _deps_missing
        # httpx есть, остальные нет
        def _fake_find(mod):
            return MagicMock() if mod == "httpx" else None
        with patch("importlib.util.find_spec", side_effect=_fake_find):
            result = _deps_missing()
        self.assertNotIn("httpx", result)
        self.assertIn("rich", result)
        self.assertIn("yaml", result)


class TestBuildArgs(unittest.TestCase):
    """_build_args — pure CLI args builder."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_all_none_returns_empty(self):
        from vless_installer.modules.dpi_censor_check import _build_args
        self.assertEqual(_build_args(None, None, None), [])

    def test_domains_only(self):
        from vless_installer.modules.dpi_censor_check import _build_args
        result = _build_args(["a.com", "b.com"], None, None)
        self.assertEqual(result, ["-d", "a.com", "-d", "b.com"])

    def test_proxy_only(self):
        from vless_installer.modules.dpi_censor_check import _build_args
        result = _build_args(None, "socks5://127.0.0.1:1080", None)
        self.assertEqual(result, ["-p", "socks5://127.0.0.1:1080"])

    def test_output_only(self):
        from vless_installer.modules.dpi_censor_check import _build_args
        result = _build_args(None, None, "/tmp/report.json")
        self.assertEqual(result, ["-o", "/tmp/report.json"])

    def test_all_combined(self):
        from vless_installer.modules.dpi_censor_check import _build_args
        result = _build_args(["x.com"], "proxy", "out.json")
        self.assertIn("-d", result)
        self.assertIn("x.com", result)
        self.assertIn("-p", result)
        self.assertIn("proxy", result)
        self.assertIn("-o", result)
        self.assertIn("out.json", result)

    def test_empty_domains_list(self):
        from vless_installer.modules.dpi_censor_check import _build_args
        result = _build_args([], None, None)
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

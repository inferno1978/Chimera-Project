#!/usr/bin/env python3
"""
tests/test_geo_files.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/geo_files.py.

Модуль geo_files.py в основном требует curl/wget/systemctl — тестируем только
_core_module() (importlib dispatcher).
"""
from __future__ import annotations

import sys
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


class TestCoreModule(unittest.TestCase):
    """_core_module — importlib dispatcher."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_module(self):
        from vless_installer.modules.geo_files import _core_module
        result = _core_module()
        self.assertIsNotNone(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)

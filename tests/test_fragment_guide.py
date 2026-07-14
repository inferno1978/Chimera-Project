#!/usr/bin/env python3
"""
tests/test_fragment_guide.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/fragment_guide.py.

Покрывает:
  1. _h / _p / _step / _bullet — форматирование вывода
"""
from __future__ import annotations

import io
import sys
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


class TestH(unittest.TestCase):
    """_h — заголовок раздела."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_prints_header_with_underline(self):
        from chimera.modules.fragment_guide import _h
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            _h("Test Header")
        output = buf.getvalue()
        self.assertIn("Test Header", output)
        self.assertIn("─", output)


class TestStep(unittest.TestCase):
    """_step — нумерованный шаг."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_prints_step_number_and_text(self):
        from chimera.modules.fragment_guide import _step
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            _step(1, "Do something")
        output = buf.getvalue()
        self.assertIn("1.", output)
        self.assertIn("Do something", output)


class TestBullet(unittest.TestCase):
    """_bullet — bullet point."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_prints_bullet_with_text(self):
        from chimera.modules.fragment_guide import _bullet
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            _bullet("Item text")
        output = buf.getvalue()
        self.assertIn("Item text", output)
        self.assertIn("•", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)

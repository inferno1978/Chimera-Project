#!/usr/bin/env python3
"""
tests/test_tui.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/tui.py.

Покрывает:
  1. _is_tty — проверка TTY
  2. _ansi_strip — удаление ANSI-кодов
  3. _vis_len — вычисление видимой ширины строки
"""
from __future__ import annotations
import sys, unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

def _setup_core():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text(); g = {}
    with patch.object(Path, 'mkdir', lambda s,*a,**k: None), \
         patch.object(Path, 'touch', lambda s,*a,**k: None), \
         patch.object(Path, 'chmod', lambda s,*a,**k: None), \
         patch('os.chown', lambda *a,**k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types; m = types.ModuleType("chimera._core"); m.__dict__.update(g)
    sys.modules["chimera._core"] = m

class TestIsTty(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_returns_bool(self):
        from chimera.modules.tui import _is_tty
        self.assertIsInstance(_is_tty(), bool)

class TestAnsiStrip(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_plain_string(self):
        from chimera.modules.tui import _ansi_strip
        self.assertEqual(_ansi_strip("hello"), "hello")
    def test_strips_ansi(self):
        from chimera.modules.tui import _ansi_strip
        self.assertEqual(_ansi_strip("\033[1;31mhi\033[0m"), "hi")
    def test_empty(self):
        from chimera.modules.tui import _ansi_strip
        self.assertEqual(_ansi_strip(""), "")

class TestVisLen(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_ascii(self):
        from chimera.modules.tui import _vis_len
        self.assertEqual(_vis_len("hello"), 5)
    def test_cjk(self):
        from chimera.modules.tui import _vis_len
        self.assertEqual(_vis_len("中文"), 4)
    def test_ansi_zero_width(self):
        from chimera.modules.tui import _vis_len
        self.assertEqual(_vis_len("\033[1mhi\033[0m"), 2)
    def test_empty(self):
        from chimera.modules.tui import _vis_len
        self.assertEqual(_vis_len(""), 0)

if __name__ == "__main__":
    unittest.main(verbosity=2)

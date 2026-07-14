#!/usr/bin/env python3
"""
tests/test_system_deps.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/system_deps.py.

Покрывает:
  1. _CMD_TO_PKG — структура таблицы команд
"""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    m = types.ModuleType("chimera._core")
    m.__dict__.update(g)
    sys.modules["chimera._core"] = m


class TestSystemDeps(unittest.TestCase):
    def setUp(self): _setup_core()
    def test_cmd_to_pkg_has_common_commands(self):
        from chimera.modules.system_deps import _CMD_TO_PKG
        for cmd in ("curl", "wget", "tar"):
            self.assertIn(cmd, _CMD_TO_PKG)
    def test_cmd_to_pkg_values_are_tuples(self):
        from chimera.modules.system_deps import _CMD_TO_PKG
        for cmd, pkg in _CMD_TO_PKG.items():
            with self.subTest(cmd=cmd):
                self.assertIsInstance(pkg, (tuple, list))
                self.assertEqual(len(pkg), 2)

# ── awg_backup ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""
tests/test_hysteria2_quality.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/hysteria2_quality.py.

Покрывает:
  1. _load_history / _save_history — JSON I/O
  2. _append_history — trim до _MAX_HISTORY
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
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda s, *a, **k: None), \
         patch.object(Path, 'touch', lambda s, *a, **k: None), \
         patch.object(Path, 'chmod', lambda s, *a, **k: None), \
         patch('os.chown', lambda *a, **k: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    m = types.ModuleType("vless_installer._core")
    m.__dict__.update(g)
    sys.modules["vless_installer._core"] = m


class TestH2QualityHistory(unittest.TestCase):
    def setUp(self):
        _setup_core()
        self._tmp = Path(tempfile.mkdtemp()); self._f = self._tmp / "h2q.json"
    def tearDown(self):
        import shutil; shutil.rmtree(self._tmp, ignore_errors=True)
    def _patch(self):
        return patch("vless_installer.modules.hysteria2_quality._HISTORY_FILE", self._f)
    def test_load_empty(self):
        from vless_installer.modules.hysteria2_quality import _load_history
        with self._patch(): self.assertEqual(_load_history(), {})
    def test_save_load(self):
        from vless_installer.modules.hysteria2_quality import _load_history, _save_history
        with self._patch():
            _save_history({"1.2.3.4": [{"ts":"x"}]}); self.assertTrue(_load_history()["1.2.3.4"])
    def test_append_trims(self):
        from vless_installer.modules.hysteria2_quality import _append_history, _load_history, _MAX_HISTORY
        with self._patch():
            for i in range(_MAX_HISTORY + 20):
                _append_history("1.2.3.4", {"ts": str(i)})
            h = _load_history()
        self.assertLessEqual(len(h["1.2.3.4"]), _MAX_HISTORY)

# ── hysteria2_dpi ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)

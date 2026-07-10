#!/usr/bin/env python3
"""
tests/test_diagnostics.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/diagnostics.py.

Покрывает:
  1. _diag_fmt_bytes — форматирование байт
  2. _diag_make_counters — создание счётчиков
  3. _diag_chk — валидатор с счётчиками
  4. _diag_resolve_config — поиск и чтение config.json
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


class TestDiagFmtBytes(unittest.TestCase):
    """_diag_fmt_bytes — форматирование байт."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_zero(self):
        from vless_installer.modules.diagnostics import _diag_fmt_bytes
        self.assertEqual(_diag_fmt_bytes(0), "0 Б")

    def test_less_than_kib(self):
        from vless_installer.modules.diagnostics import _diag_fmt_bytes
        self.assertEqual(_diag_fmt_bytes(500), "500 Б")

    def test_kib(self):
        from vless_installer.modules.diagnostics import _diag_fmt_bytes
        self.assertEqual(_diag_fmt_bytes(1024), "1.0 КБ")

    def test_mib(self):
        from vless_installer.modules.diagnostics import _diag_fmt_bytes
        self.assertEqual(_diag_fmt_bytes(1024 ** 2), "1.0 МБ")

    def test_gib(self):
        from vless_installer.modules.diagnostics import _diag_fmt_bytes
        self.assertIn("ГБ", _diag_fmt_bytes(1024 ** 3))


class TestDiagMakeCounters(unittest.TestCase):
    """_diag_make_counters — создание счётчиков."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_list_of_four_zeros(self):
        from vless_installer.modules.diagnostics import _diag_make_counters
        counters = _diag_make_counters()
        self.assertEqual(counters, [0, 0, 0, 0])


class TestDiagChk(unittest.TestCase):
    """_diag_chk — валидатор с счётчиками."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _mock_core(self):
        core = MagicMock()
        core._box_wrap_msg = MagicMock()
        core._box_row = MagicMock()
        core._box_warn = MagicMock()
        core.CYAN = ""
        core.GREEN = ""
        core.RED = ""
        core.YELLOW = ""
        core.DIM = ""
        core.NC = ""
        core.BOLD = ""
        return core

    def test_returns_true_and_increments_passed(self):
        from vless_installer.modules import diagnostics
        counters = diagnostics._diag_make_counters()
        with patch.object(diagnostics, "_core_module", return_value=self._mock_core()), \
             patch.object(diagnostics, "_diag_ok") as mock_ok:
            result = diagnostics._diag_chk(counters, True, "ok", "fail")
        self.assertTrue(result)
        self.assertEqual(counters[0], 1)  # total
        self.assertEqual(counters[1], 1)  # passed
        mock_ok.assert_called_once_with("ok")

    def test_returns_false_and_increments_err(self):
        from vless_installer.modules import diagnostics
        counters = diagnostics._diag_make_counters()
        with patch.object(diagnostics, "_core_module", return_value=self._mock_core()), \
             patch.object(diagnostics, "_diag_err") as mock_err:
            result = diagnostics._diag_chk(counters, False, "ok", "fail")
        self.assertFalse(result)
        self.assertEqual(counters[0], 1)  # total
        self.assertEqual(counters[3], 1)  # err
        mock_err.assert_called_once_with("fail")

    def test_warn_increments_warn_not_err(self):
        from vless_installer.modules import diagnostics
        counters = diagnostics._diag_make_counters()
        with patch.object(diagnostics, "_core_module", return_value=self._mock_core()), \
             patch.object(diagnostics, "_diag_err") as mock_err:
            result = diagnostics._diag_chk(counters, False, "ok", "fail", is_warn=True)
        self.assertFalse(result)
        self.assertEqual(counters[2], 1)  # warn
        self.assertEqual(counters[3], 0)  # err not incremented
        mock_err.assert_not_called()


class TestDiagResolveConfig(unittest.TestCase):
    """_diag_resolve_config — поиск и чтение config.json."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "config.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _mock_core(self):
        core = MagicMock()
        core.DIAG_CONFIG_FILE = self._cfg
        core.DIAG_ALT_CONFIG_FILE = Path("/tmp/nonexistent_alt_cfg.json")
        core._box_wrap_msg = MagicMock()
        core._box_row = MagicMock()
        core.CYAN = ""
        core.DIM = ""
        core.NC = ""
        return core

    def test_returns_none_when_no_config(self):
        from vless_installer.modules import diagnostics
        core = self._mock_core()
        core.DIAG_CONFIG_FILE = Path("/tmp/nonexistent_main_cfg.json")
        with patch.object(diagnostics, "_core_module", return_value=core), \
             patch.object(diagnostics, "_diag_err"):
            path, cfg = diagnostics._diag_resolve_config()
        self.assertIsNone(path)
        self.assertEqual(cfg, {})

    def test_returns_config_when_valid(self):
        from vless_installer.modules import diagnostics
        self._cfg.write_text(json.dumps({"inbounds": []}))
        with patch.object(diagnostics, "_core_module", return_value=self._mock_core()):
            path, cfg = diagnostics._diag_resolve_config()
        self.assertIsNotNone(path)
        self.assertIn("inbounds", cfg)

    def test_returns_empty_on_corrupt(self):
        from vless_installer.modules import diagnostics
        self._cfg.write_text("{invalid json")
        with patch.object(diagnostics, "_core_module", return_value=self._mock_core()), \
             patch.object(diagnostics, "_diag_err"):
            path, cfg = diagnostics._diag_resolve_config()
        self.assertIsNotNone(path)
        self.assertEqual(cfg, {})


if __name__ == "__main__":
    unittest.main(verbosity=2)

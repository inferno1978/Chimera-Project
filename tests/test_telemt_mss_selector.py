#!/usr/bin/env python3
"""
tests/test_telemt_mss_selector.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/telemt_mss_selector.py.

Покрывает:
  1. mss_status_line — форматирование строки статуса MSS
  2. get_current_mss — чтение client_mss из TOML
  3. _PRESETS — структура пресетов
"""
from __future__ import annotations

import sys
import tempfile
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


class TestMssStatusLine(unittest.TestCase):
    """mss_status_line — форматирование."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_empty_mss_shows_ne_zadan(self):
        from chimera.modules.telemt_mss_selector import mss_status_line
        result = mss_status_line("")
        self.assertIn("не задан", result)

    def test_known_preset_shows_label(self):
        from chimera.modules.telemt_mss_selector import mss_status_line
        # "tspu" — первый пресет (recommended)
        result = mss_status_line("tspu")
        self.assertIn("tspu", result)
        # должна быть метка пресета
        self.assertTrue(any(label in result for label in ("TSPU", "tspu")))

    def test_custom_numeric_shows_custom(self):
        from chimera.modules.telemt_mss_selector import mss_status_line
        result = mss_status_line("9999")
        self.assertIn("custom", result)
        self.assertIn("9999", result)

    def test_known_preset_shows_mss_value(self):
        from chimera.modules.telemt_mss_selector import (
            mss_status_line, _PRESETS,
        )
        # берём второй пресет (ключ "2") — структура (key, value, mss_int, label, detail, recommended)
        preset = _PRESETS[1]
        result = mss_status_line(preset[1])  # value
        self.assertIn(preset[1], result)

    def test_recommended_preset_has_star(self):
        from chimera.modules.telemt_mss_selector import mss_status_line
        # tspu — recommended
        result = mss_status_line("tspu")
        # ★ присутствует для recommended
        self.assertIn("★", result)


class TestGetCurrentMss(unittest.TestCase):
    """get_current_mss — чтение из TOML."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "telemt.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.telemt_mss_selector._CONFIG_FILE",
                     self._cfg)

    def test_returns_empty_when_no_file(self):
        from chimera.modules.telemt_mss_selector import get_current_mss
        with self._patch():
            self.assertEqual(get_current_mss(), "")

    def test_returns_value_with_quotes(self):
        from chimera.modules.telemt_mss_selector import get_current_mss
        self._cfg.write_text('client_mss = "tspu"\n')
        with self._patch():
            self.assertEqual(get_current_mss(), "tspu")

    def test_returns_value_without_quotes(self):
        from chimera.modules.telemt_mss_selector import get_current_mss
        self._cfg.write_text('client_mss = tspu\n')
        with self._patch():
            self.assertEqual(get_current_mss(), "tspu")

    def test_returns_empty_when_no_setting(self):
        from chimera.modules.telemt_mss_selector import get_current_mss
        self._cfg.write_text('port = 443\n')
        with self._patch():
            self.assertEqual(get_current_mss(), "")

    def test_accepts_custom_config_file(self):
        from chimera.modules.telemt_mss_selector import get_current_mss
        self._cfg.write_text('client_mss = "512"\n')
        self.assertEqual(get_current_mss(self._cfg), "512")


class TestPresets(unittest.TestCase):
    """_PRESETS — структура."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_has_at_least_9_presets(self):
        from chimera.modules.telemt_mss_selector import _PRESETS
        self.assertGreaterEqual(len(_PRESETS), 9)

    def test_only_one_recommended(self):
        """Структура: (key, value, mss_int, label, detail, recommended)."""
        from chimera.modules.telemt_mss_selector import _PRESETS
        recommended = [p for p in _PRESETS if len(p) > 5 and p[5]]
        self.assertEqual(len(recommended), 1)

    def test_values_unique(self):
        """Все значения пресетов уникальны."""
        from chimera.modules.telemt_mss_selector import _PRESETS
        values = [p[1] for p in _PRESETS if p[1]]  # исключаем пустое значение
        self.assertEqual(len(values), len(set(values)))


if __name__ == "__main__":
    unittest.main(verbosity=2)

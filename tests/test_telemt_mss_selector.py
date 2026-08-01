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


# ══════════════════════════════════════════════════════════════════════════════
#  BULK MSS — двухуровневый режим (handshake-only fragmentation)
# ══════════════════════════════════════════════════════════════════════════════
class TestBulkPresets(unittest.TestCase):
    """_BULK_PRESETS — структура."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_has_at_least_5_bulk_presets(self):
        from chimera.modules.telemt_mss_selector import _BULK_PRESETS
        self.assertGreaterEqual(len(_BULK_PRESETS), 5)

    def test_only_one_recommended(self):
        from chimera.modules.telemt_mss_selector import _BULK_PRESETS
        recommended = [p for p in _BULK_PRESETS if len(p) > 5 and p[5]]
        self.assertEqual(len(recommended), 1)

    def test_recommended_is_near_mtu(self):
        """Recommended bulk-пресет — Near-MTU (1400), самое близкое к MTU."""
        from chimera.modules.telemt_mss_selector import _BULK_PRESETS
        recommended = [p for p in _BULK_PRESETS if len(p) > 5 and p[5]]
        self.assertEqual(len(recommended), 1)
        self.assertEqual(recommended[0][1], "1400")
        self.assertEqual(recommended[0][2], 1400)

    def test_has_zero_key_for_opt_out(self):
        """Должен быть ключ '0' для отказа от bulk (прежнее поведение)."""
        from chimera.modules.telemt_mss_selector import _BULK_PRESETS, MSS_PRESET_NONE
        zero_presets = [p for p in _BULK_PRESETS if p[0] == "0"]
        self.assertEqual(len(zero_presets), 1)
        self.assertEqual(zero_presets[0][1], MSS_PRESET_NONE)

    def test_values_unique(self):
        from chimera.modules.telemt_mss_selector import _BULK_PRESETS
        values = [p[1] for p in _BULK_PRESETS if p[1]]
        self.assertEqual(len(values), len(set(values)))


class TestMssBulkStatusLine(unittest.TestCase):
    """mss_bulk_status_line — форматирование."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_empty_bulk_with_handshake_shows_hint(self):
        """Если bulk не задан, но handshake задан — подсказка про handshake-MSS."""
        from chimera.modules.telemt_mss_selector import mss_bulk_status_line
        result = mss_bulk_status_line("", client_mss="tspu")
        self.assertIn("не задан", result)
        self.assertIn("handshake", result.lower())

    def test_empty_bulk_without_handshake_shows_just_ne_zadan(self):
        from chimera.modules.telemt_mss_selector import mss_bulk_status_line
        result = mss_bulk_status_line("", client_mss="")
        self.assertIn("не задан", result)
        # без handshake-MSS нет смысла говорить про handshake
        self.assertNotIn("handshake", result.lower())

    def test_known_bulk_preset_shows_label(self):
        from chimera.modules.telemt_mss_selector import mss_bulk_status_line
        result = mss_bulk_status_line("1400")
        self.assertIn("1400", result)
        self.assertIn("Near-MTU", result)

    def test_recommended_bulk_has_star(self):
        from chimera.modules.telemt_mss_selector import mss_bulk_status_line
        result = mss_bulk_status_line("1400")  # Near-MTU — recommended
        self.assertIn("★", result)

    def test_custom_numeric_bulk_shows_custom(self):
        from chimera.modules.telemt_mss_selector import mss_bulk_status_line
        result = mss_bulk_status_line("9999")
        self.assertIn("custom", result)
        self.assertIn("9999", result)


class TestGetCurrentMssBulk(unittest.TestCase):
    """get_current_mss_bulk — чтение из TOML."""

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
        from chimera.modules.telemt_mss_selector import get_current_mss_bulk
        with self._patch():
            self.assertEqual(get_current_mss_bulk(), "")

    def test_returns_value_with_quotes(self):
        from chimera.modules.telemt_mss_selector import get_current_mss_bulk
        self._cfg.write_text('client_mss_bulk = "1400"\n')
        with self._patch():
            self.assertEqual(get_current_mss_bulk(), "1400")

    def test_returns_value_without_quotes(self):
        from chimera.modules.telemt_mss_selector import get_current_mss_bulk
        self._cfg.write_text('client_mss_bulk = 1400\n')
        with self._patch():
            self.assertEqual(get_current_mss_bulk(), "1400")

    def test_returns_empty_when_no_bulk_setting(self):
        from chimera.modules.telemt_mss_selector import get_current_mss_bulk
        self._cfg.write_text('port = 443\nclient_mss = "tspu"\n')
        with self._patch():
            self.assertEqual(get_current_mss_bulk(), "")

    def test_does_not_match_handshake_mss(self):
        """КРИТИЧНО: get_current_mss_bulk не должен сматчить просто client_mss."""
        from chimera.modules.telemt_mss_selector import get_current_mss_bulk
        # В файле только client_mss (handshake), без _bulk
        self._cfg.write_text('client_mss = "tspu"\n')
        with self._patch():
            self.assertEqual(get_current_mss_bulk(), "")

    def test_accepts_custom_config_file(self):
        from chimera.modules.telemt_mss_selector import get_current_mss_bulk
        self._cfg.write_text('client_mss_bulk = "1280"\n')
        self.assertEqual(get_current_mss_bulk(self._cfg), "1280")


class TestGetCurrentMssNoFalseMatchBulk(unittest.TestCase):
    """РЕГРЕССИЯ: get_current_mss не должен сматчить client_mss_bulk."""

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

    def test_get_current_mss_ignores_bulk_line(self):
        """Если в файле есть только client_mss_bulk (без client_mss),
        get_current_mss должен вернуть пустую строку, не '1400'."""
        from chimera.modules.telemt_mss_selector import get_current_mss
        self._cfg.write_text('client_mss_bulk = "1400"\n')
        with self._patch():
            self.assertEqual(get_current_mss(), "")

    def test_get_current_mss_returns_handshake_not_bulk(self):
        """Если в файле есть оба параметра — get_current_mss возвращает handshake."""
        from chimera.modules.telemt_mss_selector import get_current_mss
        self._cfg.write_text(
            'port = 443\n'
            'client_mss = "tspu"\n'
            'client_mss_bulk = "1400"\n'
        )
        with self._patch():
            self.assertEqual(get_current_mss(), "tspu")


class TestMssBulkSelectInteractive(unittest.TestCase):
    """mss_bulk_select_interactive — логика выбора."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_empty_when_no_handshake_mss(self):
        """Если handshake-MSS пустой — bulk не имеет смысла, возвращаем ''."""
        from chimera.modules.telemt_mss_selector import (
            mss_bulk_select_interactive, MSS_PRESET_NONE,
        )
        # Никакого input() не должно быть — функция выходит сразу.
        with patch("builtins.input", side_effect=AssertionError(
                "input() не должен вызываться при пустом handshake-MSS")):
            result = mss_bulk_select_interactive("")
        self.assertEqual(result, MSS_PRESET_NONE)

    def test_returns_value_for_known_preset_key(self):
        from chimera.modules.telemt_mss_selector import mss_bulk_select_interactive
        # Пользователь вводит "1" → Near-MTU (1400)
        with patch("builtins.input", return_value="1"):
            result = mss_bulk_select_interactive("tspu")
        self.assertEqual(result, "1400")

    def test_returns_empty_for_zero_key(self):
        from chimera.modules.telemt_mss_selector import (
            mss_bulk_select_interactive, MSS_PRESET_NONE,
        )
        with patch("builtins.input", return_value="0"):
            result = mss_bulk_select_interactive("tspu")
        self.assertEqual(result, MSS_PRESET_NONE)

    def test_empty_input_returns_recommended_bulk(self):
        """Пустой ввод (Enter) = default = recommended bulk (Near-MTU 1400).

        Это UX-соглашение, как в mss_select_interactive (там Enter = tspu).
        Отказ от bulk — явный '0'.
        """
        from chimera.modules.telemt_mss_selector import mss_bulk_select_interactive
        with patch("builtins.input", return_value=""):
            result = mss_bulk_select_interactive("tspu")
        self.assertEqual(result, "1400")  # Near-MTU — recommended

    def test_custom_numeric_input(self):
        from chimera.modules.telemt_mss_selector import mss_bulk_select_interactive
        # "c" → затем "999"
        inputs = iter(["c", "999"])
        with patch("builtins.input", side_effect=lambda *a, **kw: next(inputs)):
            result = mss_bulk_select_interactive("tspu")
        self.assertEqual(result, "999")

    def test_custom_out_of_range_retries(self):
        from chimera.modules.telemt_mss_selector import mss_bulk_select_interactive
        # "c" → "5000" (out of range) → "c" → "1200" (ok)
        inputs = iter(["c", "5000", "c", "1200"])
        with patch("builtins.input", side_effect=lambda *a, **kw: next(inputs)):
            result = mss_bulk_select_interactive("tspu")
        self.assertEqual(result, "1200")


if __name__ == "__main__":
    unittest.main(verbosity=2)

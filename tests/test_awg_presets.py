#!/usr/bin/env python3
"""
tests/test_awg_presets.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/awg_presets.py.

Покрывает:
  1. AWGS_CARRIER_PRESETS — структура пресетов
  2. awgs_presets_list / awgs_presets_get
  3. awgs_presets_generate — генерация параметров по пресету
  4. awgs_presets_validate_params — валидация
  5. awgs_presets_compare_with_carrier — сравнение с профилем оператора
"""
from __future__ import annotations

import random
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


class TestCarrierPresetsStructure(unittest.TestCase):
    """AWGS_CARRIER_PRESETS — внутренняя структура."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_has_default_preset(self):
        from chimera.modules.awg_presets import AWGS_CARRIER_PRESETS
        self.assertIn("default", AWGS_CARRIER_PRESETS)

    def test_has_mobile_preset(self):
        from chimera.modules.awg_presets import AWGS_CARRIER_PRESETS
        self.assertIn("mobile", AWGS_CARRIER_PRESETS)

    def test_all_presets_have_required_keys(self):
        from chimera.modules.awg_presets import AWGS_CARRIER_PRESETS
        required = {
            "label", "jc_min", "jc_max", "jmin_min", "jmin_max",
            "jmax_delta_min", "jmax_delta_max", "i1_mode", "description",
        }
        for name, preset in AWGS_CARRIER_PRESETS.items():
            with self.subTest(preset=name):
                missing = required - set(preset.keys())
                self.assertEqual(missing, set(),
                                 f"preset {name}: missing keys {missing}")

    def test_i1_mode_is_valid_value(self):
        from chimera.modules.awg_presets import AWGS_CARRIER_PRESETS
        for name, preset in AWGS_CARRIER_PRESETS.items():
            with self.subTest(preset=name):
                self.assertIn(preset["i1_mode"], ("random", "absent", "binary"))

    def test_jc_min_le_jc_max(self):
        from chimera.modules.awg_presets import AWGS_CARRIER_PRESETS
        for name, preset in AWGS_CARRIER_PRESETS.items():
            with self.subTest(preset=name):
                self.assertLessEqual(preset["jc_min"], preset["jc_max"])

    def test_jmin_min_le_jmin_max(self):
        from chimera.modules.awg_presets import AWGS_CARRIER_PRESETS
        for name, preset in AWGS_CARRIER_PRESETS.items():
            with self.subTest(preset=name):
                self.assertLessEqual(preset["jmin_min"], preset["jmin_max"])


class TestPresetsList(unittest.TestCase):
    """awgs_presets_list."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_list(self):
        from chimera.modules.awg_presets import awgs_presets_list
        result = awgs_presets_list()
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)

    def test_includes_default(self):
        from chimera.modules.awg_presets import awgs_presets_list
        self.assertIn("default", awgs_presets_list())


class TestPresetsGet(unittest.TestCase):
    """awgs_presets_get."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_preset_for_known_name(self):
        from chimera.modules.awg_presets import awgs_presets_get
        p = awgs_presets_get("default")
        self.assertIsNotNone(p)
        self.assertEqual(p["label"], "Default (проводной интернет)")

    def test_returns_none_for_unknown_name(self):
        from chimera.modules.awg_presets import awgs_presets_get
        self.assertIsNone(awgs_presets_get("nonexistent_operator_xyz"))


class TestPresetsGenerate(unittest.TestCase):
    """awgs_presets_generate — генерация параметров."""

    def setUp(self):
        _setup_core_in_sysmodules()
        random.seed(42)

    def test_raises_on_unknown_preset(self):
        from chimera.modules.awg_presets import awgs_presets_generate
        with self.assertRaises(ValueError):
            awgs_presets_generate("nonexistent")

    def test_returns_dict_with_required_keys(self):
        from chimera.modules.awg_presets import awgs_presets_generate
        params = awgs_presets_generate("default")
        required = {"jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
                    "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"}
        self.assertEqual(set(params.keys()), required)

    def test_jc_in_range(self):
        from chimera.modules.awg_presets import (
            awgs_presets_generate, AWGS_CARRIER_PRESETS,
        )
        for name in AWGS_CARRIER_PRESETS:
            with self.subTest(preset=name):
                random.seed(42)
                p = awgs_presets_generate(name)
                self.assertGreaterEqual(p["jc"], AWGS_CARRIER_PRESETS[name]["jc_min"])
                self.assertLessEqual(p["jc"], AWGS_CARRIER_PRESETS[name]["jc_max"])

    def test_jmax_ge_jmin(self):
        """Jmax = Jmin + delta, delta >= 0 — должно быть >= Jmin."""
        from chimera.modules.awg_presets import (
            awgs_presets_generate, AWGS_CARRIER_PRESETS,
        )
        for name in AWGS_CARRIER_PRESETS:
            with self.subTest(preset=name):
                random.seed(42)
                p = awgs_presets_generate(name)
                self.assertGreaterEqual(p["jmax"], p["jmin"])

    def test_s_values_are_zero(self):
        """S1-S4 всегда 0 (как в bivlked default)."""
        from chimera.modules.awg_presets import awgs_presets_generate
        p = awgs_presets_generate("default")
        for k in ("s1", "s2", "s3", "s4"):
            self.assertEqual(p[k], 0)

    def test_h_values_are_1_2_3_4(self):
        """H1-H4 — magic headers 1,2,3,4."""
        from chimera.modules.awg_presets import awgs_presets_generate
        p = awgs_presets_generate("default")
        self.assertEqual(p["h1"], 1)
        self.assertEqual(p["h2"], 2)
        self.assertEqual(p["h3"], 3)
        self.assertEqual(p["h4"], 4)

    def test_i1_random_mode_generates_hex(self):
        from chimera.modules.awg_presets import awgs_presets_generate
        random.seed(42)
        p = awgs_presets_generate("default")  # i1_mode=random
        self.assertTrue(p["i1"])
        self.assertTrue(all(c in "0123456789abcdef" for c in p["i1"]))

    def test_i1_absent_mode_returns_empty(self):
        """Пресет tele2_krasnoyarsk использует i1_mode='absent'."""
        from chimera.modules.awg_presets import awgs_presets_generate
        random.seed(42)
        p = awgs_presets_generate("tele2_krasnoyarsk")
        self.assertEqual(p["i1"], "")

    def test_i1_binary_mode_generates_short_hex(self):
        """T-Mobile US использует i1_mode='binary' — 16 hex символов."""
        from chimera.modules.awg_presets import awgs_presets_generate
        random.seed(42)
        p = awgs_presets_generate("tmobile_us")
        self.assertEqual(len(p["i1"]), 16)

    def test_i2_to_i5_are_empty(self):
        from chimera.modules.awg_presets import awgs_presets_generate
        p = awgs_presets_generate("default")
        for k in ("i2", "i3", "i4", "i5"):
            self.assertEqual(p[k], "")


class TestPresetsValidateParams(unittest.TestCase):
    """awgs_presets_validate_params."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _valid(self):
        return {
            "jc": 4, "jmin": 40, "jmax": 70,
            "s1": 0, "s2": 0, "s3": 0, "s4": 0,
            "h1": 1, "h2": 2, "h3": 3, "h4": 4,
            "i1": "", "i2": "", "i3": "", "i4": "", "i5": "",
        }

    def test_valid_params_returns_true(self):
        from chimera.modules.awg_presets import (
            awgs_presets_validate_params,
        )
        ok, err = awgs_presets_validate_params(self._valid())
        self.assertTrue(ok, msg=err)
        self.assertEqual(err, "")

    def test_jc_too_high(self):
        from chimera.modules.awg_presets import (
            awgs_presets_validate_params,
        )
        p = self._valid()
        p["jc"] = 999
        ok, err = awgs_presets_validate_params(p)
        self.assertFalse(ok)
        self.assertIn("Jc", err)

    def test_jc_zero_invalid(self):
        from chimera.modules.awg_presets import (
            awgs_presets_validate_params,
        )
        p = self._valid()
        p["jc"] = 0
        ok, err = awgs_presets_validate_params(p)
        self.assertFalse(ok)

    def test_jmax_less_than_jmin(self):
        from chimera.modules.awg_presets import (
            awgs_presets_validate_params,
        )
        p = self._valid()
        p["jmin"] = 100
        p["jmax"] = 50
        ok, err = awgs_presets_validate_params(p)
        self.assertFalse(ok)
        self.assertIn("Jmax", err)

    def test_s3_too_high(self):
        from chimera.modules.awg_presets import (
            awgs_presets_validate_params,
        )
        p = self._valid()
        p["s3"] = 999
        ok, err = awgs_presets_validate_params(p)
        self.assertFalse(ok)
        self.assertIn("S3", err)

    def test_s4_too_high(self):
        from chimera.modules.awg_presets import (
            awgs_presets_validate_params,
        )
        p = self._valid()
        p["s4"] = 999
        ok, err = awgs_presets_validate_params(p)
        self.assertFalse(ok)
        self.assertIn("S4", err)

    def test_h_value_too_high(self):
        from chimera.modules.awg_presets import (
            awgs_presets_validate_params,
        )
        p = self._valid()
        p["h1"] = 999
        ok, err = awgs_presets_validate_params(p)
        self.assertFalse(ok)
        self.assertIn("H1", err)

    def test_i1_with_non_hex_chars(self):
        from chimera.modules.awg_presets import (
            awgs_presets_validate_params,
        )
        p = self._valid()
        p["i1"] = "xyz123"
        ok, err = awgs_presets_validate_params(p)
        self.assertFalse(ok)
        self.assertIn("I1", err)

    def test_i1_with_valid_hex(self):
        from chimera.modules.awg_presets import (
            awgs_presets_validate_params,
        )
        p = self._valid()
        p["i1"] = "deadbeef"
        ok, err = awgs_presets_validate_params(p)
        self.assertTrue(ok, msg=err)

    def test_jc_non_int(self):
        from chimera.modules.awg_presets import (
            awgs_presets_validate_params,
        )
        p = self._valid()
        p["jc"] = "four"
        ok, err = awgs_presets_validate_params(p)
        self.assertFalse(ok)


class TestPresetsCompareWithCarrier(unittest.TestCase):
    """awgs_presets_compare_with_carrier."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_unknown_carrier_returns_error(self):
        from chimera.modules.awg_presets import (
            awgs_presets_compare_with_carrier,
        )
        result = awgs_presets_compare_with_carrier({}, "nonexistent")
        self.assertFalse(result["ok"])
        self.assertIn("error", result)

    def test_matching_params_returns_ok(self):
        from chimera.modules.awg_presets import (
            awgs_presets_compare_with_carrier,
        )
        # mobile preset: jc=3, jmin=30-50, jmax_delta=20-80
        params = {"jc": 3, "jmin": 40, "jmax": 80, "i1": "deadbeef"}
        result = awgs_presets_compare_with_carrier(params, "mobile")
        self.assertEqual(result["status"], "OK")
        self.assertTrue(result["ok"])

    def test_jc_fail_when_wrong(self):
        from chimera.modules.awg_presets import (
            awgs_presets_compare_with_carrier,
        )
        # tele2_msk требует jc=3 — передаём 5
        params = {"jc": 5, "jmin": 40, "jmax": 80, "i1": "deadbeef"}
        result = awgs_presets_compare_with_carrier(params, "tele2_msk")
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "FAIL")

    def test_i1_warn_when_absent_expected_but_present(self):
        """tele2_krasnoyarsk требует I1 absent — warn если он есть."""
        from chimera.modules.awg_presets import (
            awgs_presets_compare_with_carrier,
        )
        params = {"jc": 3, "jmin": 40, "jmax": 80, "i1": "deadbeef"}
        result = awgs_presets_compare_with_carrier(params, "tele2_krasnoyarsk")
        self.assertEqual(result["status"], "WARN")

    def test_i1_ok_when_absent_expected_and_absent(self):
        from chimera.modules.awg_presets import (
            awgs_presets_compare_with_carrier,
        )
        params = {"jc": 3, "jmin": 40, "jmax": 80, "i1": ""}
        result = awgs_presets_compare_with_carrier(params, "tele2_krasnoyarsk")
        self.assertEqual(result["status"], "OK")

    def test_checks_list_present(self):
        from chimera.modules.awg_presets import (
            awgs_presets_compare_with_carrier,
        )
        result = awgs_presets_compare_with_carrier({}, "default")
        self.assertIn("checks", result)
        self.assertGreater(len(result["checks"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

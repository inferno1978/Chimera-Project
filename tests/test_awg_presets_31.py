#!/usr/bin/env python3
"""
tests/test_awg_presets_31.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты генерации/валидации параметров AmneziaWG 3.1 в awg_presets.py.

Покрывает:
  1. awgs_presets_generate(name, "3.1") — полный 25-ключевой набор,
     диапазоны GenerateObfuscation31 (S1-S4, Jmax, H-банды, I1)
  2. awgs_presets_validate_params(params, "3.1") — 3.1-инварианты
  3. awgs_generate_full_manual_params(protocol_version="3.1")
  4. РЕГРЕССИЯ 2.0: вызовы без версии — байт-в-байт прежний контракт
     (16 ключей, диапазоны 2.0, H-диапазоны 'N-M')
"""
from __future__ import annotations

import random
import sys
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules import awg_presets
from chimera.modules.awg_presets import (
    awgs_presets_generate, awgs_presets_validate_params,
    awgs_generate_full_manual_params, awgs_presets_list,
    _generate_non_overlapping_h_values_31,
)
from chimera.modules.awg_protocol import AWG31_EXTRA_KEYS

_BASE16 = ("jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
           "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5")


class TestPresetsGenerate31(unittest.TestCase):
    """Генерация по пресету с protocol_version='3.1'."""

    def test_full_key_set_25(self):
        p = awgs_presets_generate("default", "3.1")
        self.assertEqual(len(p), 25)  # 16 базовых + 9 транспортных
        for k in _BASE16:
            self.assertIn(k, p)
        for k in AWG31_EXTRA_KEYS:
            self.assertIn(k, p)

    def test_s_ranges_31(self):
        # GenerateObfuscation31: S1/S2 15-150, S3 12-55, S4 12-27
        for _ in range(20):
            p = awgs_presets_generate("default", "3.1")
            self.assertTrue(15 <= p["s1"] <= 150, p["s1"])
            self.assertTrue(15 <= p["s2"] <= 150, p["s2"])
            self.assertTrue(12 <= p["s3"] <= 55, p["s3"])
            self.assertTrue(12 <= p["s4"] <= 27, p["s4"])
            # Правило S1+56 != S2 сохраняется
            self.assertNotEqual(p["s1"] + 56, p["s2"])

    def test_jmax_limit_31(self):
        # Jmin 40-89, Jmax = Jmin + ≤ 250 → ≤ 339
        for _ in range(20):
            p = awgs_presets_generate("default", "3.1")
            self.assertGreaterEqual(p["jmin"], 40)
            self.assertLessEqual(p["jmin"], 89)
            self.assertGreaterEqual(p["jmax"], p["jmin"])
            self.assertLessEqual(p["jmax"], 339)

    def test_h_values_int_bands_31(self):
        # 3.1: одиночные int в бандах от 5 (НЕ диапазоны 'N-M')
        for _ in range(10):
            p = awgs_presets_generate("default", "3.1")
            hs = [p[f"h{i}"] for i in range(1, 5)]
            for h in hs:
                # 3.1: одиночные int (GenerateObfuscation31/wpp-стиль),
                # НЕ диапазоны 'N-M' как в 2.0
                self.assertIsInstance(h, int, msg=repr(h))
                self.assertGreaterEqual(h, 5)
                self.assertLessEqual(h, 2147483647)
            # Непересекающиеся банда → все разные
            self.assertEqual(len(set(hs)), 4)

    def test_i1_always_r_tag_31(self):
        # 3.1: I1 всегда «<r N>» (N 32-256), даже для absent-пресетов
        for preset in awgs_presets_list():
            p = awgs_presets_generate(preset, "3.1")
            self.assertTrue(p["i1"].startswith("<r "), msg=f"{preset}: {p['i1']}")
            self.assertTrue(p["i1"].endswith(">"))
            n = int(p["i1"][3:-1])
            self.assertTrue(32 <= n <= 256, n)

    def test_all_presets_valid_31(self):
        for preset in awgs_presets_list():
            for _ in range(3):
                p = awgs_presets_generate(preset, "3.1")
                ok, err = awgs_presets_validate_params(p, "3.1")
                self.assertTrue(ok, msg=f"{preset}: {err}")

    def test_extra_params_present(self):
        p = awgs_presets_generate("mobile", "3.1")
        self.assertEqual(p["random_trailers"], "on")
        self.assertEqual(p["disable_cookies"], "on")
        self.assertEqual(len(p["header_protection_key"]), 44)


class TestPresetsValidate31(unittest.TestCase):
    def _valid_31(self):
        return awgs_presets_generate("default", "3.1")

    def test_valid_ok(self):
        ok, err = awgs_presets_validate_params(self._valid_31(), "3.1")
        self.assertTrue(ok, msg=err)

    def test_s_too_small_rejected(self):
        p = self._valid_31()
        p["s1"] = 5  # < 15
        ok, err = awgs_presets_validate_params(p, "3.1")
        self.assertFalse(ok)
        self.assertIn("S1", err)

    def test_jmax_over_339_rejected(self):
        p = self._valid_31()
        p["jmax"] = 500
        ok, err = awgs_presets_validate_params(p, "3.1")
        self.assertFalse(ok)
        self.assertIn("339", err)

    def test_i1_binary_rejected_for_31(self):
        # binary-blob — 2.0-специфика, в 3.1 I1 обязан быть «<r N>»
        p = self._valid_31()
        p["i1"] = "<b 0xdeadbeef>"
        ok, err = awgs_presets_validate_params(p, "3.1")
        self.assertFalse(ok)
        self.assertIn("I1", err)

    def test_missing_31_params_rejected(self):
        p = self._valid_31()
        del p["header_protection_key"]
        ok, err = awgs_presets_validate_params(p, "3.1")
        self.assertFalse(ok)

    def test_same_params_pass_20_validation_except_31(self):
        # 3.1-набор валиден и как 2.0 (доп. ключи игнорируются
        # 2.0-валидатором — обратная совместимость чтения state)
        p = self._valid_31()
        ok, err = awgs_presets_validate_params(p, "2.0")
        self.assertTrue(ok, msg=err)


class TestFullManualParams31(unittest.TestCase):
    def test_full_set(self):
        p = awgs_generate_full_manual_params(None, "3.1")
        self.assertEqual(len(p), 25)
        ok, err = awgs_presets_validate_params(p, "3.1")
        self.assertTrue(ok, msg=err)

    def test_ranges(self):
        for _ in range(15):
            p = awgs_generate_full_manual_params(None, "3.1")
            self.assertTrue(15 <= p["s1"] <= 150)
            self.assertTrue(12 <= p["s3"] <= 55)
            self.assertTrue(12 <= p["s4"] <= 27)
            self.assertLessEqual(p["jmax"], 339)
            self.assertTrue(32 <= int(p["i1"][3:-1]) <= 256)

    def test_overrides_respected_31(self):
        p = awgs_generate_full_manual_params(
            {"jc": 5, "s1": 100}, "3.1")
        self.assertEqual(p["jc"], 5)
        self.assertEqual(p["s1"], 100)

    def test_31_extra_override_respected(self):
        p = awgs_generate_full_manual_params(
            {"random_trailers": "on"}, "3.1")
        self.assertEqual(p["random_trailers"], "on")
        self.assertTrue(p["header_protection_key"])  # сгенерирован


class TestRegression20(unittest.TestCase):
    """РЕГРЕССИЯ: вызовы без версии — прежний 2.0-контракт байт-в-байт."""

    def test_generate_default_16_keys(self):
        p = awgs_presets_generate("default")
        self.assertEqual(len(p), 16)
        self.assertEqual(sorted(p.keys()), sorted(_BASE16))

    def test_generate_20_s_ranges(self):
        # 2.0: S1/S2 0-32, S3 0-64, S4 0-32
        for _ in range(15):
            p = awgs_presets_generate("default")
            self.assertTrue(0 <= p["s1"] <= 32)
            self.assertTrue(0 <= p["s2"] <= 32)
            self.assertTrue(0 <= p["s3"] <= 64)
            self.assertTrue(0 <= p["s4"] <= 32)

    def test_generate_20_h_ranges_nm(self):
        # 2.0: H1-H4 — диапазоны 'N-M' (v5.4.2+)
        p = awgs_presets_generate("default")
        for i in range(1, 5):
            self.assertIn("-", p[f"h{i}"])

    def test_absent_preset_20_i1_empty(self):
        # 2.0: absent-пресеты дают пустой I1 (в 3.1 он бы был <r N>)
        p = awgs_presets_generate("tele2_krasnoyarsk")
        self.assertEqual(p["i1"], "")

    def test_full_manual_20_16_keys(self):
        p = awgs_generate_full_manual_params()
        self.assertEqual(len(p), 16)
        ok, err = awgs_presets_validate_params(p)
        self.assertTrue(ok, msg=err)

    def test_validate_20_no_31_checks(self):
        # 2.0-валидатор не требует 3.1-параметров
        p = awgs_presets_generate("default")
        ok, err = awgs_presets_validate_params(p, "2.0")
        self.assertTrue(ok)


class TestHValues31(unittest.TestCase):
    def test_bands_do_not_overlap(self):
        for _ in range(15):
            hs = _generate_non_overlapping_h_values_31()
            self.assertEqual(len(hs), 4)
            h_low, h_band = 5, (2147483647 - 5 + 1) // 4
            for i, h in enumerate(hs):
                self.assertGreaterEqual(h, h_low + i * h_band)
                self.assertLessEqual(h, h_low + (i + 1) * h_band - 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)

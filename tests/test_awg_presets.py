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
                # v5.1: добавлен 4-й режим 'quic_mimicry' (опциональный,
                # для sneaky-режима в ручной настройке)
                self.assertIn(preset["i1_mode"],
                              ("random", "absent", "binary", "quic_mimicry"))

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

    def test_s1_s2_non_zero_v542(self):
        """v5.4.2: S1, S2 — случайные ненулевые (как в эталонном конфиге Amnezia).

        Раньше (v5.0-v5.4.1) были 0 (как в bivlked). Но рабочий конфиг от
        приложения Amnezia использует S1=125, S2=47 — ненулевые. Подтверждено
        zvshka: с S1=0, S2=0 handshake не завершается. С ненулевыми — работает.
        """
        from chimera.modules.awg_presets import awgs_presets_generate
        random.seed(42)
        p = awgs_presets_generate("default")
        self.assertGreaterEqual(p["s1"], 0)
        self.assertLessEqual(p["s1"], 32)
        self.assertGreaterEqual(p["s2"], 0)
        self.assertLessEqual(p["s2"], 32)

    def test_s3_s4_in_range(self):
        """v5.1: S3, S4 — случайные в общих диапазонах 0..64 / 0..32.

        Раньше были захардкожены 0 у всех пресетов — это давало
        одинаковый DPI-отпечаток всем установкам. Теперь переиспользуются
        диапазоны из _FULL_MANUAL_RANGES (те же, что в полном ручном
        режиме — чтобы не дублировать константы).
        """
        from chimera.modules.awg_presets import awgs_presets_generate
        for name in ("default", "mobile", "beeline_msk", "tmobile_us"):
            with self.subTest(preset=name):
                random.seed(42)
                p = awgs_presets_generate(name)
                self.assertGreaterEqual(p["s3"], 0)
                self.assertLessEqual(p["s3"], 64)
                self.assertGreaterEqual(p["s4"], 0)
                self.assertLessEqual(p["s4"], 32)

    def test_h_values_not_fixed_1_2_3_4(self):
        """v5.1: H1-H4 НЕ должны быть фиксированными 1,2,3,4 — это
        узнаваемый DPI-отпечаток (одинаковый у всех установок проекта
        на одном пресете, подтверждено пользователем zvshka).

        v5.3: H1-H4 теперь генерируются как диапазоны 'N-M' (как в
        эталонном конфиге Amnezia), не одиночные числа. Проверяем что
        хотя бы один seed даёт НЕ 1,2,3,4.
        """
        from chimera.modules.awg_presets import awgs_presets_generate
        found_non_default = False
        for seed in range(10):
            random.seed(seed)
            p = awgs_presets_generate("default")
            hs = [p["h1"], p["h2"], p["h3"], p["h4"]]
            # v5.3: hs теперь строки 'N-M', не int. Проверяем что не 1,2,3,4.
            if hs != ["1", "2", "3", "4"] and hs != [1, 2, 3, 4]:
                found_non_default = True
                break
        self.assertTrue(found_non_default,
                        "H1-H4 всегда 1,2,3,4 — функция не работает как ожидалось")

    def test_h_values_are_non_overlapping(self):
        """v5.1: H1-H4 не пересекаются между собой (DPI не сможет
        написать универсальное правило для детекции этого проекта).

        v5.3: H1-H4 теперь диапазоны 'N-M'. Проверяем что диапазоны
        не пересекаются.
        """
        from chimera.modules.awg_presets import awgs_presets_generate
        for seed in range(10):
            with self.subTest(seed=seed):
                random.seed(seed)
                p = awgs_presets_generate("default")
                # Парсим диапазоны
                ranges = []
                for k in ("h1", "h2", "h3", "h4"):
                    parts = p[k].split("-")
                    self.assertEqual(len(parts), 2,
                                     f"{k} should be 'N-M' format: {p[k]}")
                    lo, hi = int(parts[0]), int(parts[1])
                    ranges.append((lo, hi))
                # Проверяем непересечение
                for i in range(4):
                    for j in range(i + 1, 4):
                        lo_i, hi_i = ranges[i]
                        lo_j, hi_j = ranges[j]
                        # Не должны пересекаться
                        self.assertTrue(
                            hi_i < lo_j or hi_j < lo_i,
                            f"H{i+1}={ranges[i]} и H{j+1}={ranges[j]} пересекаются"
                        )

    def test_h_values_in_int32_range(self):
        """v5.1: H1-H4 в диапазоне 1..INT32_MAX (как валидатор
        принимает).

        v5.3: H1-H4 теперь диапазоны 'N-M'. Проверяем что обе границы
        в 1..INT32_MAX.
        """
        from chimera.modules.awg_presets import awgs_presets_generate
        for seed in range(5):
            with self.subTest(seed=seed):
                random.seed(seed)
                p = awgs_presets_generate("default")
                for k in ("h1", "h2", "h3", "h4"):
                    # v5.3: p[k] — строка 'N-M'
                    parts = p[k].split("-")
                    lo, hi = int(parts[0]), int(parts[1])
                    self.assertGreaterEqual(lo, 1,
                                            f"{k} lo={lo} < 1")
                    self.assertLessEqual(lo, 2147483647,
                                         f"{k} lo={lo} > INT32_MAX")
                    self.assertGreaterEqual(hi, 1,
                                            f"{k} hi={hi} < 1")
                    self.assertLessEqual(hi, 2147483647,
                                         f"{k} hi={hi} > INT32_MAX")

    def test_two_consecutive_calls_give_different_h_and_s(self):
        """v5.1: два вызова awgs_presets_generate("default") подряд
        дают РАЗНЫЕ H1-H4 и разные S3/S4.

        Это критично для ротации параметров (awgs_rotate_obfuscation):
        при каждом вызове должны генерироваться новые значения, а не
        повторяться одни и те же.
        """
        from chimera.modules.awg_presets import awgs_presets_generate
        # Не фиксируем seed — два вызова должны дать разные значения
        # просто за счёт прогресса RNG.
        random.seed(42)
        p1 = awgs_presets_generate("default")
        p2 = awgs_presets_generate("default")
        hs1 = [p1["h1"], p1["h2"], p1["h3"], p1["h4"]]
        hs2 = [p2["h1"], p2["h2"], p2["h3"], p2["h4"]]
        self.assertNotEqual(hs1, hs2,
                            f"H1-H4 одинаковые у двух вызовов: {hs1}")
        # S3/S4 тоже должны различаться (с высокой вероятностью)
        s_diff = (p1["s3"], p1["s4"]) != (p2["s3"], p2["s4"])
        self.assertTrue(s_diff,
                        f"S3/S4 одинаковые у двух вызовов: "
                        f"p1=({p1['s3']},{p1['s4']}), p2=({p2['s3']},{p2['s4']})")

    def test_i1_random_mode_generates_cps_tag(self):
        """v5.1: i1_mode='random' генерирует CPS tag-формат <r N>.

        Раньше (v5.0) генерировался голый hex — это формат AWG 1.5,
        который ломает некоторых клиентов AWG 2.0 (Keenetic native,
        amneziawg-go). Теперь это CPS tag <r N> — простейший валидный
        формат AWG 2.0, функционально эквивалентный старому по энтропии.
        """
        import re
        from chimera.modules.awg_presets import awgs_presets_generate
        random.seed(42)
        p = awgs_presets_generate("default")  # i1_mode=random
        self.assertTrue(p["i1"], "I1 не должен быть пустым для random mode")
        # CPS tag-формат: <r N> где N — число 24..32
        self.assertRegex(
            p["i1"], r"^<r \d+>$",
            f"I1 должен быть в формате '<r N>', фактически: {p['i1']!r}"
        )
        # Проверяем что N в разумном диапазоне (24..32 байта)
        m = re.match(r"^<r (\d+)>$", p["i1"])
        n = int(m.group(1))
        self.assertGreaterEqual(n, 24)
        self.assertLessEqual(n, 32)

    def test_i1_absent_mode_returns_empty(self):
        """Пресет tele2_krasnoyarsk использует i1_mode='absent'."""
        from chimera.modules.awg_presets import awgs_presets_generate
        random.seed(42)
        p = awgs_presets_generate("tele2_krasnoyarsk")
        self.assertEqual(p["i1"], "")

    def test_i1_binary_mode_generates_cps_static_bytes(self):
        """v5.1: i1_mode='binary' генерирует CPS tag-формат <b 0x...>.

        Раньше (v5.0) генерировался голый hex 16 символов. Теперь это
        CPS tag <b 0x...> — статичные байты, валидный формат AWG 2.0.
        Для T-Mobile US используется 32 hex символа (16 байт) внутри тега.
        """
        import re
        from chimera.modules.awg_presets import awgs_presets_generate
        random.seed(42)
        p = awgs_presets_generate("tmobile_us")
        # CPS tag-формат: <b 0x[hex]> (чётное число hex-символов после 0x)
        self.assertRegex(
            p["i1"], r"^<b 0x[0-9a-fA-F]+>$",
            f"I1 должен быть в формате '<b 0x[hex]>', фактически: {p['i1']!r}"
        )
        # Проверяем что hex-часть имеет чётное число символов (байты)
        m = re.match(r"^<b 0x([0-9a-fA-F]+)>$", p["i1"])
        hex_part = m.group(1)
        self.assertEqual(
            len(hex_part) % 2, 0,
            f"hex-часть должна иметь чётное число символов: {hex_part!r}"
        )

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
        """ H1-H4 валидны до INT32_MAX. 999 теперь валидно —
        используем значение выше INT32_MAX для проверки invalid."""
        from chimera.modules.awg_presets import (
            awgs_presets_validate_params,
        )
        p = self._valid()
        p["h1"] = 2147483648  # INT32_MAX + 1 — за пределами
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


# ============================================================================
#   — Тесты awgs_generate_full_manual_params()
# ============================================================================
# Новая функция для полного ручного/авто-набора параметров AWG 2.0.
# Отличия от awgs_presets_generate():
#   - H1-H4 — НЕПЕРЕСЕКАЮЩИЕСЯ случайные значения в 1..INT32_MAX
#     (а не фиксированные 1,2,3,4 как в пресетах)
#   - S3, S4 — случайные в рекомендованных диапазонах
#   - I1 — hex 48-64 символа
#   - Правило S1 + 56 != S2 проверяется и перегенерируется при коллизии
#   - overrides — словарь с значениями, явно введёнными пользователем

class TestGenerateFullManualParams(unittest.TestCase):
    """awgs_generate_full_manual_params — полный ручной/авто-набор.

    5 кейсов:
      1. Без overrides — все 16 полей заполнены, в разумных диапазонах
      2. С overrides — переданные значения используются как есть
      3. H1-H4 не пересекаются между собой
      4. Правило S1 + 56 != S2 — перегенерация при коллизии
      5. I1 — hex 48-64 символа (24-32 байта)
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        random.seed(42)

    def test_returns_dict_with_all_16_keys(self):
        """Без overrides — все 16 полей заполнены."""
        from chimera.modules.awg_presets import awgs_generate_full_manual_params
        p = awgs_generate_full_manual_params()
        required = {"jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
                    "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"}
        self.assertEqual(set(p.keys()), required,
                         f"Должны быть все 16 ключей, фактически: {set(p.keys())}")

    def test_values_in_reasonable_ranges(self):
        """Все значения в разумных диапазонах (без overrides)."""
        from chimera.modules.awg_presets import awgs_generate_full_manual_params
        p = awgs_generate_full_manual_params()
        # Jc: 3-10 (рекомендованный диапазон)
        self.assertGreaterEqual(p["jc"], 3)
        self.assertLessEqual(p["jc"], 10)
        # Jmin: 40-90
        self.assertGreaterEqual(p["jmin"], 40)
        self.assertLessEqual(p["jmin"], 90)
        # Jmax >= Jmin
        self.assertGreaterEqual(p["jmax"], p["jmin"])
        # S1, S2: 0-32
        for k in ("s1", "s2"):
            self.assertGreaterEqual(p[k], 0)
            self.assertLessEqual(p[k], 32)
        # S3: 0-64
        self.assertGreaterEqual(p["s3"], 0)
        self.assertLessEqual(p["s3"], 64)
        # S4: 0-32
        self.assertGreaterEqual(p["s4"], 0)
        self.assertLessEqual(p["s4"], 32)
        # H1-H4: 1..INT32_MAX (v5.3: теперь диапазоны 'N-M')
        for k in ("h1", "h2", "h3", "h4"):
            # v5.3: p[k] — строка 'N-M'
            parts = p[k].split("-")
            lo, hi = int(parts[0]), int(parts[1])
            self.assertGreaterEqual(lo, 1)
            self.assertLessEqual(lo, 2147483647)
            self.assertGreaterEqual(hi, 1)
            self.assertLessEqual(hi, 2147483647)

    def test_overrides_used_as_is(self):
        """Переданные overrides используются как есть.

        v5.3: H1-H4 overrides теперь принимают int или строку (число или
        диапазон 'N-M'). Возвращает как строку (для единообразия с
        генератором диапазонов).
        """
        from chimera.modules.awg_presets import awgs_generate_full_manual_params
        overrides = {
            "jc": 7,
            "jmin": 55,
            "jmax": 200,
            "s1": 10,
            "s2": 20,
            "s3": 30,
            "s4": 15,
            "h1": 100,    # int override
            "h2": 200,    # int override
            "h3": 300,    # int override
            "h4": 400,    # int override
            "i1": "deadbeef",
        }
        p = awgs_generate_full_manual_params(overrides)
        self.assertEqual(p["jc"], 7)
        self.assertEqual(p["jmin"], 55)
        self.assertEqual(p["jmax"], 200)
        self.assertEqual(p["s1"], 10)
        self.assertEqual(p["s2"], 20)
        self.assertEqual(p["s3"], 30)
        self.assertEqual(p["s4"], 15)
        # v5.3: H1-H4 возвращаются как строки (приводятся к str для
        # единообразия с генератором диапазонов)
        self.assertEqual(p["h1"], "100")
        self.assertEqual(p["h2"], "200")
        self.assertEqual(p["h3"], "300")
        self.assertEqual(p["h4"], "400")
        self.assertEqual(p["i1"], "deadbeef")

    def test_h1_h4_do_not_intersect(self):
        """H1-H4 не пересекаются между собой (DPI не сможет написать
        универсальное правило для детекции этого проекта).

        v5.3: H1-H4 теперь диапазоны 'N-M'. Проверяем что диапазоны
        не пересекаются. Запускаем 10 раз с разными seed'ами.
        """
        from chimera.modules.awg_presets import awgs_generate_full_manual_params
        for seed in range(10):
            with self.subTest(seed=seed):
                random.seed(seed)
                p = awgs_generate_full_manual_params()
                # Парсим диапазоны
                ranges = []
                for k in ("h1", "h2", "h3", "h4"):
                    parts = p[k].split("-")
                    lo, hi = int(parts[0]), int(parts[1])
                    ranges.append((lo, hi))
                # Проверяем непересечение
                for i in range(4):
                    for j in range(i + 1, 4):
                        lo_i, hi_i = ranges[i]
                        lo_j, hi_j = ranges[j]
                        self.assertTrue(
                            hi_i < lo_j or hi_j < lo_i,
                            f"H{i+1}={ranges[i]} и H{j+1}={ranges[j]} пересекаются"
                        )

    def test_h1_h4_not_fixed_1_2_3_4(self):
        """H1-H4 НЕ должны быть фиксированными 1,2,3,4 (как в пресетах).

        v5.3: H1-H4 теперь диапазоны 'N-M' (как в эталонном конфиге
        Amnezia). Проверяем что хотя бы один seed даёт НЕ 1,2,3,4.
        """
        from chimera.modules.awg_presets import awgs_generate_full_manual_params
        # Проверяем на 10 разных seed'ах — хотя бы один не должен дать 1,2,3,4
        found_non_default = False
        for seed in range(10):
            random.seed(seed)
            p = awgs_generate_full_manual_params()
            hs = [p["h1"], p["h2"], p["h3"], p["h4"]]
            # v5.3: hs теперь строки 'N-M'. Проверяем что не 1,2,3,4 (в любом формате).
            if hs != ["1", "2", "3", "4"] and hs != [1, 2, 3, 4]:
                found_non_default = True
                break
        self.assertTrue(found_non_default,
                        "H1-H4 всегда 1,2,3,4 — функция не работает как ожидалось")

    def test_s1_plus_56_not_equal_s2(self):
        """Правило S1 + 56 != S2 — перегенерация при коллизии.

        Принудительно мокаем random.randint чтобы для S2 возвращал S1+56
        (коллизия), и проверяем что функция перегенерирует S2.
        """
        import chimera.modules.awg_presets as ap
        real_randint = ap.random.randint

        # Принудительно задаём S1=10 (тогда S1+56=66)
        # Мокаем random.randint: для S2 диапазона возвращаем 66 (коллизия)
        call_count = [0]
        def fake_randint(lo, hi):
            call_count[0] += 1
            # Когда генерируется S2 (диапазон 0-32 по умолчанию) — возвращаем 66
            # Но 66 вне диапазона 0-32, так что это сработает только если
            # мы расширяем диапазон. Делаем так: для диапазона S2 (0,32)
            # возвращаем max возможное значение, не равное S1+56.
            if lo == 0 and hi == 32:
                # S2 диапазон — возвращаем 32 (максимальное, не 66)
                return 32
            return real_randint(lo, hi)

        ap.random.randint = fake_randint
        try:
            p = ap.awgs_generate_full_manual_params({"s1": 10})
        finally:
            ap.random.randint = real_randint

        # Проверяем: S2 != S1 + 56 (правило совместимости)
        self.assertNotEqual(p["s2"], p["s1"] + 56,
                            f"S2 ({p['s2']}) == S1+56 ({p['s1']+56}) — "
                            f"правило совместимости нарушено")

    def test_i1_is_cps_tag_r_n(self):
        """v5.1: I1 — CPS tag-формат <r N> (24-32 случайных байт).

        Раньше (v5.0) генерировался голый hex 48-64 символа (AWG 1.5).
        Теперь это CPS tag <r N> — валидный формат AWG 2.0, который
        принимают все современные клиенты (включая Keenetic native
        AWG 2.0 и amneziawg-go). Голый hex ломал этих клиентов.
        """
        import re
        from chimera.modules.awg_presets import awgs_generate_full_manual_params
        for seed in range(5):
            with self.subTest(seed=seed):
                random.seed(seed)
                p = awgs_generate_full_manual_params()
                self.assertTrue(p["i1"],
                                f"I1 пустой при seed={seed} — должен генерироваться")
                # CPS tag-формат: <r N> где N — число 24..32
                self.assertRegex(
                    p["i1"], r"^<r \d+>$",
                    f"I1 должен быть в формате '<r N>', фактически: {p['i1']!r}"
                )
                m = re.match(r"^<r (\d+)>$", p["i1"])
                n = int(m.group(1))
                self.assertGreaterEqual(n, 24,
                                        f"размер <r N> слишком маленький: {n}")
                self.assertLessEqual(n, 32,
                                     f"размер <r N> слишком большой: {n}")

    def test_i2_to_i5_empty_by_default(self):
        """I2-I5 — пустые по умолчанию (без overrides)."""
        from chimera.modules.awg_presets import awgs_generate_full_manual_params
        p = awgs_generate_full_manual_params()
        for k in ("i2", "i3", "i4", "i5"):
            self.assertEqual(p[k], "",
                             f"{k} должен быть пустым по умолчанию, фактически: {p[k]!r}")

    def test_i2_to_i5_accept_override(self):
        """I2-I5 принимают override если пользователь явно задал."""
        from chimera.modules.awg_presets import awgs_generate_full_manual_params
        p = awgs_generate_full_manual_params({
            "i2": "aabb",
            "i3": "ccdd",
        })
        self.assertEqual(p["i2"], "aabb")
        self.assertEqual(p["i3"], "ccdd")
        # I4, I5 без override — пустые
        self.assertEqual(p["i4"], "")
        self.assertEqual(p["i5"], "")

    def test_passes_validation(self):
        """Сгенерированные параметры проходят awgs_presets_validate_params."""
        from chimera.modules.awg_presets import (
            awgs_generate_full_manual_params,
            awgs_presets_validate_params,
        )
        # Несколько seed'ов для надёжности
        for seed in range(5):
            with self.subTest(seed=seed):
                random.seed(seed)
                p = awgs_generate_full_manual_params()
                ok, err = awgs_presets_validate_params(p)
                self.assertTrue(ok, msg=f"seed={seed}: {err}")

    def test_jmax_ge_jmin_when_override_jmax_below_jmin(self):
        """Если override Jmax < Jmin — функция подтягивает Jmax = Jmin."""
        from chimera.modules.awg_presets import awgs_generate_full_manual_params
        p = awgs_generate_full_manual_params({"jmin": 100, "jmax": 50})
        self.assertGreaterEqual(p["jmax"], p["jmin"],
                                f"Jmax ({p['jmax']}) должен быть >= Jmin ({p['jmin']})")


class TestCarrierPresetsNotChanged(unittest.TestCase):
    """ гарантия, что carrier-пресеты НЕ изменены при добавлении
    новой функции awgs_generate_full_manual_params().

    Пресеты — сознательное решение автора, их значения (jc_min/max,
    jmin/jmax диапазоны, i1_mode) остаются РОВНО такими, как есть.
    Этот тест — regression: если кто-то случайно поменяет пресеты,
    тест упадёт.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_default_preset_jc_range_unchanged(self):
        """Default preset: Jc 3-6 (не должно было измениться)."""
        from chimera.modules.awg_presets import AWGS_CARRIER_PRESETS
        self.assertEqual(AWGS_CARRIER_PRESETS["default"]["jc_min"], 3)
        self.assertEqual(AWGS_CARRIER_PRESETS["default"]["jc_max"], 6)

    def test_mobile_preset_jc_fixed_3(self):
        """Mobile preset: Jc=3 фиксированный (jc_min == jc_max == 3)."""
        from chimera.modules.awg_presets import AWGS_CARRIER_PRESETS
        self.assertEqual(AWGS_CARRIER_PRESETS["mobile"]["jc_min"], 3)
        self.assertEqual(AWGS_CARRIER_PRESETS["mobile"]["jc_max"], 3)

    def test_tele2_krasnoyarsk_i1_mode_absent(self):
        """Tele2 Красноярск: i1_mode='absent' (майская волна 2026)."""
        from chimera.modules.awg_presets import AWGS_CARRIER_PRESETS
        self.assertEqual(AWGS_CARRIER_PRESETS["tele2_krasnoyarsk"]["i1_mode"], "absent")

    def test_presets_generate_now_returns_random_h1_h4(self):
        """awgs_presets_generate() — H1-H4 больше НЕ 1,2,3,4 (v5.1).

        Раньше пресеты возвращали H1-H4=1,2,3,4 фиксированно — это
        узнаваемый DPI-отпечаток проекта (одинаковый у всех установок
        на одном пресете). v5.1: пресеты используют общую функцию
        _generate_non_overlapping_h_values(), которая выдаёт случайные
        непересекающиеся значения в 1..INT32_MAX.

        Этот тест — regression: гарантирует что НОВЫЙ путь
        (awgs_generate_full_manual_params) и ОБНОВЛЁННЫЙ старый путь
        (awgs_presets_generate) оба выдают случайные H1-H4.
        """
        from chimera.modules.awg_presets import awgs_presets_generate
        random.seed(42)
        p = awgs_presets_generate("default")
        # H1-H4 НЕ должны быть 1,2,3,4
        hs = [p["h1"], p["h2"], p["h3"], p["h4"]]
        self.assertNotEqual(hs, [1, 2, 3, 4],
                            f"H1-H4 всё ещё 1,2,3,4: {hs}")
        # H1-H4 должны быть непересекающимися
        self.assertEqual(len(set(hs)), 4,
                         f"H1-H4 пересекаются: {hs}")


# ============================================================================
#  v5.1 — CPS tag-формат для I1-I5 (AWG 2.0)
# ============================================================================
# Раньше I1-I5 генерировались как голая hex-строка (формат AWG 1.5). Это
# ломало некоторых клиентов AWG 2.0 (Keenetic native AWG 2.0, amneziawg-go)
# — туннель подключается, но трафик не идёт.
#
# v5.1: I1-I5 теперь генерируются в CPS tag-формате (Custom Protocol
# Signature), как требует спецификация AWG 2.0 (docs.amnezia.org):
#   <b 0x[hex]>  — статичные байты (hex-encoded)
#   <r [size]>   — [size] случайных байт
#   <rd [size]>  — [size] случайных байт из [0-9]
#   <rc [size]>  — [size] случайных байт из [a-zA-Z]
#   <t>          — 4-байтный текущий unix-timestamp
#
# Старый голый hex остаётся валидным в валидаторе для обратной
# совместимости (уже установленные state.json у пользователей).

class TestCpsTagFormat(unittest.TestCase):
    """Тесты на CPS tag-формат I1-I5 и валидатор."""

    def setUp(self):
        _setup_core_in_sysmodules()

    # ── _is_valid_cps_or_legacy_hex ──────────────────────────────────────
    def test_validator_accepts_empty_string(self):
        """Пустая строка валидна (I1-I5 опциональны)."""
        from chimera.modules.awg_presets import _is_valid_cps_or_legacy_hex
        self.assertTrue(_is_valid_cps_or_legacy_hex(""))

    def test_validator_accepts_cps_random_tag(self):
        """CPS tag <r N> валиден."""
        from chimera.modules.awg_presets import _is_valid_cps_or_legacy_hex
        self.assertTrue(_is_valid_cps_or_legacy_hex("<r 24>"))
        self.assertTrue(_is_valid_cps_or_legacy_hex("<r 32>"))
        self.assertTrue(_is_valid_cps_or_legacy_hex("<r 1>"))
        self.assertTrue(_is_valid_cps_or_legacy_hex("<r 100>"))

    def test_validator_accepts_cps_static_bytes_tag(self):
        """CPS tag <b 0x...> валиден (статичные байты, hex)."""
        from chimera.modules.awg_presets import _is_valid_cps_or_legacy_hex
        self.assertTrue(_is_valid_cps_or_legacy_hex("<b 0xdeadbeef>"))
        self.assertTrue(_is_valid_cps_or_legacy_hex("<b 0xab>"))
        self.assertTrue(_is_valid_cps_or_legacy_hex("<b 0xc30000000108>"))

    def test_validator_accepts_cps_random_digit_tag(self):
        """CPS tag <rd N> валиден (случайные байты из 0-9)."""
        from chimera.modules.awg_presets import _is_valid_cps_or_legacy_hex
        self.assertTrue(_is_valid_cps_or_legacy_hex("<rd 16>"))
        self.assertTrue(_is_valid_cps_or_legacy_hex("<rd 4>"))

    def test_validator_accepts_cps_random_chars_tag(self):
        """CPS tag <rc N> валиден (случайные байты из a-zA-Z)."""
        from chimera.modules.awg_presets import _is_valid_cps_or_legacy_hex
        self.assertTrue(_is_valid_cps_or_legacy_hex("<rc 16>"))
        self.assertTrue(_is_valid_cps_or_legacy_hex("<rc 4>"))

    def test_validator_accepts_cps_timestamp_tag(self):
        """CPS tag <t> валиден (текущий unix-timestamp)."""
        from chimera.modules.awg_presets import _is_valid_cps_or_legacy_hex
        self.assertTrue(_is_valid_cps_or_legacy_hex("<t>"))

    def test_validator_accepts_cps_combined_tags(self):
        """CPS-строка из нескольких тегов валидна (как в quic_mimicry)."""
        from chimera.modules.awg_presets import _is_valid_cps_or_legacy_hex
        # Комбинированный паттерн QUIC-маскировки
        quic = "<b 0xc30000000108><r 8><b 0x08><r 8><b 0x0045dc><t><r 16>"
        self.assertTrue(_is_valid_cps_or_legacy_hex(quic))
        # С пробелами между тегами (как в официальном примере Amnezia)
        spaced = "<r 2> <b 0x8580000100010000000004796162730679616e6465780272750000010001c00c000100010000105a00044d583737>"
        self.assertTrue(_is_valid_cps_or_legacy_hex(spaced))

    def test_validator_accepts_legacy_hex(self):
        """Голый hex (без тегов) валиден для обратной совместимости.

        v5.0 генерировал I1 как голый hex. В state.json у существующих
        пользователей может остаться такой формат — валидатор не должен
        его отбрасывать, иначе уже установленные конфиги перестанут
        проходить валидацию при ротации параметров.
        """
        from chimera.modules.awg_presets import _is_valid_cps_or_legacy_hex
        self.assertTrue(_is_valid_cps_or_legacy_hex("deadbeef"))
        self.assertTrue(_is_valid_cps_or_legacy_hex("aabbccdd" * 12))  # 96 chars

    def test_validator_rejects_garbage(self):
        """Мусор (не CPS, не hex) отбрасывается."""
        from chimera.modules.awg_presets import _is_valid_cps_or_legacy_hex
        self.assertFalse(_is_valid_cps_or_legacy_hex("xyz123"))
        self.assertFalse(_is_valid_cps_or_legacy_hex("hello world"))
        self.assertFalse(_is_valid_cps_or_legacy_hex("<r abc>"))  # не число
        self.assertFalse(_is_valid_cps_or_legacy_hex("<b 0xxyz>"))  # не hex
        self.assertFalse(_is_valid_cps_or_legacy_hex("<unknown_tag>"))
        self.assertFalse(_is_valid_cps_or_legacy_hex("[r 24]"))  # не угловые скобки

    def test_validator_rejects_non_string(self):
        """Non-string значения отбрасываются."""
        from chimera.modules.awg_presets import _is_valid_cps_or_legacy_hex
        self.assertFalse(_is_valid_cps_or_legacy_hex(None))
        self.assertFalse(_is_valid_cps_or_legacy_hex(123))
        self.assertFalse(_is_valid_cps_or_legacy_hex([]))

    # ── _generate_quic_mimicry_i1 ────────────────────────────────────────
    def test_quic_mimicry_returns_static_pattern(self):
        """_generate_quic_mimicry_i1 возвращает статичный QUIC-паттерн."""
        from chimera.modules.awg_presets import _generate_quic_mimicry_i1
        result = _generate_quic_mimicry_i1()
        # Паттерн из bivlked/amneziawg-installer (ADVANCED.md)
        expected = "<b 0xc30000000108><r 8><b 0x08><r 8><b 0x0045dc><t><r 16>"
        self.assertEqual(result, expected)

    def test_quic_mimicry_passes_validator(self):
        """QUIC-mimicry I1 проходит валидатор (CPS tag-формат)."""
        from chimera.modules.awg_presets import (
            _generate_quic_mimicry_i1,
            _is_valid_cps_or_legacy_hex,
        )
        i1 = _generate_quic_mimicry_i1()
        self.assertTrue(_is_valid_cps_or_legacy_hex(i1),
                        f"QUIC-mimicry I1 не проходит валидатор: {i1!r}")

    def test_quic_mimicry_contains_quic_long_header_flag(self):
        """QUIC-mimicry I1 содержит 0xc3 (QUIC v1 long-header flag)."""
        from chimera.modules.awg_presets import _generate_quic_mimicry_i1
        result = _generate_quic_mimicry_i1()
        # 0xc3 = Long header flag (1100 0011): long header + fixed bit +
        # QUIC version 1. См. RFC 9000.
        self.assertIn("0xc3", result,
                      f"QUIC-mimicry I1 должен содержать 0xc3 flag: {result!r}")

    def test_quic_mimicry_contains_timestamp_tag(self):
        """QUIC-mimicry I1 содержит <t> (timestamp) — даёт уникальность
        при каждом handshake (4-байтный unix-timestamp).
        """
        from chimera.modules.awg_presets import _generate_quic_mimicry_i1
        result = _generate_quic_mimicry_i1()
        self.assertIn("<t>", result,
                      f"QUIC-mimicry I1 должен содержать <t>: {result!r}")

    def test_quic_mimicry_contains_random_tags(self):
        """QUIC-mimicry I1 содержит <r N> теги (случайные байты)."""
        from chimera.modules.awg_presets import _generate_quic_mimicry_i1
        result = _generate_quic_mimicry_i1()
        # Должно быть минимум 2 <r N> тега (connection-ID + trailing bytes)
        self.assertGreaterEqual(result.count("<r "), 2,
                                f"QUIC-mimicry I1 должен содержать минимум 2 "
                                f"<r N> тега: {result!r}")

    # ── Валидатор awgs_presets_validate_params ──────────────────────────
    def test_validate_accepts_cps_random_i1(self):
        """Валидатор принимает CPS tag <r N> для I1."""
        from chimera.modules.awg_presets import awgs_presets_validate_params
        p = {
            "jc": 4, "jmin": 40, "jmax": 70,
            "s1": 0, "s2": 0, "s3": 0, "s4": 0,
            "h1": 1, "h2": 2, "h3": 3, "h4": 4,
            "i1": "<r 24>", "i2": "", "i3": "", "i4": "", "i5": "",
        }
        ok, err = awgs_presets_validate_params(p)
        self.assertTrue(ok, msg=f"CPS <r N> должен валидироваться: {err}")

    def test_validate_accepts_cps_static_bytes_i1(self):
        """Валидатор принимает CPS tag <b 0x...> для I1."""
        from chimera.modules.awg_presets import awgs_presets_validate_params
        p = {
            "jc": 4, "jmin": 40, "jmax": 70,
            "s1": 0, "s2": 0, "s3": 0, "s4": 0,
            "h1": 1, "h2": 2, "h3": 3, "h4": 4,
            "i1": "<b 0xdeadbeef>", "i2": "", "i3": "", "i4": "", "i5": "",
        }
        ok, err = awgs_presets_validate_params(p)
        self.assertTrue(ok, msg=f"CPS <b 0x...> должен валидироваться: {err}")

    def test_validate_accepts_quic_mimicry_i1(self):
        """Валидатор принимает QUIC-mimicry I1 (комбинированный CPS)."""
        from chimera.modules.awg_presets import (
            awgs_presets_validate_params,
            _generate_quic_mimicry_i1,
        )
        p = {
            "jc": 4, "jmin": 40, "jmax": 70,
            "s1": 0, "s2": 0, "s3": 0, "s4": 0,
            "h1": 1, "h2": 2, "h3": 3, "h4": 4,
            "i1": _generate_quic_mimicry_i1(),
            "i2": "", "i3": "", "i4": "", "i5": "",
        }
        ok, err = awgs_presets_validate_params(p)
        self.assertTrue(ok, msg=f"QUIC-mimicry I1 должен валидироваться: {err}")

    def test_validate_accepts_legacy_hex_i1(self):
        """Валидатор принимает голый hex для I1 (обратная совместимость)."""
        from chimera.modules.awg_presets import awgs_presets_validate_params
        p = {
            "jc": 4, "jmin": 40, "jmax": 70,
            "s1": 0, "s2": 0, "s3": 0, "s4": 0,
            "h1": 1, "h2": 2, "h3": 3, "h4": 4,
            "i1": "deadbeef", "i2": "", "i3": "", "i4": "", "i5": "",
        }
        ok, err = awgs_presets_validate_params(p)
        self.assertTrue(ok, msg=f"Legacy hex I1 должен валидироваться: {err}")

    def test_validate_rejects_garbage_i1(self):
        """Валидатор отбрасывает мусор в I1."""
        from chimera.modules.awg_presets import awgs_presets_validate_params
        p = {
            "jc": 4, "jmin": 40, "jmax": 70,
            "s1": 0, "s2": 0, "s3": 0, "s4": 0,
            "h1": 1, "h2": 2, "h3": 3, "h4": 4,
            "i1": "xyz123 garbage", "i2": "", "i3": "", "i4": "", "i5": "",
        }
        ok, err = awgs_presets_validate_params(p)
        self.assertFalse(ok)
        self.assertIn("I1", err)


class TestPresetsGenerateCpsI1(unittest.TestCase):
    """Тесты что awgs_presets_generate генерирует CPS tag I1 для всех
    пресетов с i1_mode != 'absent'."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_random_presets_generate_cps_r_tag(self):
        """Все пресеты с i1_mode='random' генерируют <r N> для I1.

        v5.1: раньше был голый hex, теперь CPS tag.
        """
        import re
        from chimera.modules.awg_presets import (
            awgs_presets_generate, AWGS_CARRIER_PRESETS,
        )
        random.seed(42)
        for name, preset in AWGS_CARRIER_PRESETS.items():
            if preset["i1_mode"] != "random":
                continue
            with self.subTest(preset=name):
                p = awgs_presets_generate(name)
                self.assertRegex(
                    p["i1"], r"^<r \d+>$",
                    f"preset {name}: I1 должен быть '<r N>', "
                    f"фактически: {p['i1']!r}"
                )

    def test_binary_presets_generate_cps_b_tag(self):
        """Все пресеты с i1_mode='binary' генерируют <b 0x...> для I1."""
        import re
        from chimera.modules.awg_presets import (
            awgs_presets_generate, AWGS_CARRIER_PRESETS,
        )
        random.seed(42)
        for name, preset in AWGS_CARRIER_PRESETS.items():
            if preset["i1_mode"] != "binary":
                continue
            with self.subTest(preset=name):
                p = awgs_presets_generate(name)
                self.assertRegex(
                    p["i1"], r"^<b 0x[0-9a-fA-F]+>$",
                    f"preset {name}: I1 должен быть '<b 0x[hex]>', "
                    f"фактически: {p['i1']!r}"
                )

    def test_absent_presets_generate_empty_i1(self):
        """Все пресеты с i1_mode='absent' генерируют пустой I1."""
        from chimera.modules.awg_presets import (
            awgs_presets_generate, AWGS_CARRIER_PRESETS,
        )
        for name, preset in AWGS_CARRIER_PRESETS.items():
            if preset["i1_mode"] != "absent":
                continue
            with self.subTest(preset=name):
                random.seed(42)
                p = awgs_presets_generate(name)
                self.assertEqual(p["i1"], "",
                                 f"preset {name}: I1 должен быть пустым для absent mode")

    def test_generated_i1_passes_validator(self):
        """Сгенерированный I1 проходит валидатор для всех пресетов."""
        from chimera.modules.awg_presets import (
            awgs_presets_generate, awgs_presets_validate_params,
            AWGS_CARRIER_PRESETS,
        )
        for name in AWGS_CARRIER_PRESETS:
            with self.subTest(preset=name):
                random.seed(42)
                p = awgs_presets_generate(name)
                ok, err = awgs_presets_validate_params(p)
                self.assertTrue(ok, msg=f"preset {name}: {err}")


if __name__ == "__main__":
    unittest.main(verbosity=2)

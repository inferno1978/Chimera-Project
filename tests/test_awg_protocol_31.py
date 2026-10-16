#!/usr/bin/env python3
"""
tests/test_awg_protocol_31.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/awg_protocol.py — версионное ядро AWG 2.0/3.1.

Покрывает:
  1. awg_normalize_version — толерантная нормализация обозначений версии
  2. awg_is_31 / awg_protocol_label / awg_vpn_uri_protocol_version
  3. awg31_generate_extra_params — генерация 9 параметров (диапазоны
     GenerateObfuscation31, те же констрейнты что в wpp_awg)
  4. awg31_validate_extra_params — валидация (успех/все классы ошибок)
  5. awg_render_31_lines — рендер директив (правило пустые «# K = »)
  6. awg31_merge_into_params — слияние 2.0-базы с 3.1-дополнением
  7. awg_state_protocol_version — чтение версии из state-словаря
"""
from __future__ import annotations

import random
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules.awg_protocol import (
    AWG_VERSION_20, AWG_VERSION_31, AWG_VERSIONS,
    AWG31_DIRECTIVE_NAMES, AWG31_EXTRA_KEYS, AWG31_FLAG_KEYS,
    AWG31_RANGE_KEYS,
    awg_normalize_version, awg_is_31, awg_protocol_label,
    awg_vpn_uri_protocol_version, awg31_generate_header_protection_key,
    awg31_generate_extra_params, awg31_validate_extra_params,
    awg_render_31_lines, awg31_merge_into_params, awg_state_protocol_version,
)


class TestNormalizeVersion(unittest.TestCase):
    """Толерантная нормализация: «31», «3.1», «awg31», «3» → «3.1»."""

    def test_20_forms(self):
        for v in ("2.0", "2", "20", "awg20", "AmneziaWG 2.0", ""):
            self.assertEqual(awg_normalize_version(v), "2.0", msg=repr(v))

    def test_31_forms(self):
        for v in ("3.1", "3", "31", "awg31", "AmneziaWG 3.1", "3,1"):
            self.assertEqual(awg_normalize_version(v), "3.1", msg=repr(v))

    def test_unknown_garbage_falls_back_to_20(self):
        # Нераспознанное — безопасный дефолт 2.0 (не ломаем установку)
        for v in ("4.0", "abc", "1.5", "??"):
            self.assertEqual(awg_normalize_version(v), "2.0", msg=repr(v))

    def test_non_string_safe(self):
        # MagicMock из тестов transport / None / int — не падаем, дефолт 2.0
        self.assertEqual(awg_normalize_version(MagicMock()), "2.0")
        self.assertEqual(awg_normalize_version(None), "2.0")
        self.assertEqual(awg_normalize_version(31), "2.0")

    def test_constants(self):
        self.assertEqual(AWG_VERSION_20, "2.0")
        self.assertEqual(AWG_VERSION_31, "3.1")
        self.assertEqual(AWG_VERSIONS, ("2.0", "3.1"))


class TestVersionHelpers(unittest.TestCase):
    def test_is_31(self):
        self.assertTrue(awg_is_31("3.1"))
        self.assertTrue(awg_is_31("awg31"))
        self.assertFalse(awg_is_31("2.0"))
        self.assertFalse(awg_is_31(""))
        self.assertFalse(awg_is_31(MagicMock()))

    def test_protocol_label(self):
        self.assertEqual(awg_protocol_label("3.1"), "AmneziaWG 3.1")
        self.assertEqual(awg_protocol_label("2.0"), "AmneziaWG 2.0")
        self.assertEqual(awg_protocol_label(""), "AmneziaWG 2.0")

    def test_vpn_uri_protocol_version(self):
        # vpn:// URI — «2» для 2.0 (историческое), «3» для 3.1
        self.assertEqual(awg_vpn_uri_protocol_version("2.0"), "2")
        self.assertEqual(awg_vpn_uri_protocol_version("3.1"), "3")
        self.assertEqual(awg_vpn_uri_protocol_version(""), "2")


class TestGenerate31ExtraParams(unittest.TestCase):
    """Генерация 9 параметров 3.1 — констрейнты GenerateObfuscation31."""

    def test_full_key_set(self):
        p = awg31_generate_extra_params()
        self.assertEqual(set(p.keys()), set(AWG31_EXTRA_KEYS))
        self.assertEqual(len(p), 9)

    def test_ranges(self):
        for _ in range(25):
            p = awg31_generate_extra_params()
            # ContentPaddingAddition: 8-24 + 8..40
            lo, hi = map(int, p["content_padding_addition"].split("-"))
            self.assertGreaterEqual(lo, 8)
            self.assertLessEqual(hi, 64)
            self.assertLessEqual(lo, hi)
            # RekeyAfterTime: 100-160
            lo, hi = map(int, p["rekey_after_time"].split("-"))
            self.assertGreaterEqual(lo, 100)
            self.assertLessEqual(hi, 200)
            # RekeyTimeout: 3-10
            lo, hi = map(int, p["rekey_timeout"].split("-"))
            self.assertGreaterEqual(lo, 3)
            self.assertLessEqual(hi, 10)
            # RejectAfterTime >= rekey_high (согласованность таймеров)
            rl, _ = map(int, p["rekey_after_time"].split("-"))
            dl, _ = map(int, p["reject_after_time"].split("-"))
            self.assertGreaterEqual(dl, rl)
            # KeepaliveTimeout: 8-20
            lo, hi = map(int, p["keepalive_timeout"].split("-"))
            self.assertGreaterEqual(lo, 8)
            self.assertLessEqual(hi, 20)
            # MaxHandshakeAttempts: 15-50
            lo, hi = map(int, p["max_handshake_attempts"].split("-"))
            self.assertGreaterEqual(lo, 15)
            self.assertLessEqual(hi, 50)

    def test_flags_on(self):
        p = awg31_generate_extra_params()
        self.assertEqual(p["random_trailers"], "on")
        self.assertEqual(p["disable_cookies"], "on")

    def test_header_protection_key_format(self):
        # 44-символьный base64 (32 байта) — как awg genkey
        for _ in range(10):
            k = awg31_generate_header_protection_key()
            self.assertEqual(len(k), 44)
            import base64
            self.assertEqual(len(base64.b64decode(k)), 32)

    def test_generated_params_pass_validation(self):
        for _ in range(25):
            ok, err = awg31_validate_extra_params(
                awg31_generate_extra_params())
            self.assertTrue(ok, msg=err)

    def test_deterministic_with_rng(self):
        rng = random.Random(42)
        a = awg31_generate_extra_params(rng)
        rng = random.Random(42)
        b = awg31_generate_extra_params(rng)
        # HeaderProtectionKey — os.urandom, не rng; сравниваем диапазоны
        self.assertEqual(a["content_padding_addition"],
                         b["content_padding_addition"])
        self.assertEqual(a["rekey_after_time"], b["rekey_after_time"])


class TestValidate31ExtraParams(unittest.TestCase):
    def _valid(self):
        return awg31_generate_extra_params()

    def test_valid_ok(self):
        ok, err = awg31_validate_extra_params(self._valid())
        self.assertTrue(ok, msg=err)

    def test_missing_header_protection_key(self):
        p = self._valid()
        del p["header_protection_key"]
        ok, err = awg31_validate_extra_params(p)
        self.assertFalse(ok)
        self.assertIn("HeaderProtectionKey", err)

    def test_short_header_protection_key(self):
        p = self._valid()
        p["header_protection_key"] = "abc"
        ok, err = awg31_validate_extra_params(p)
        self.assertFalse(ok)
        self.assertIn("HeaderProtectionKey", err)

    def test_non_base64_header_protection_key(self):
        p = self._valid()
        # «!» не входит в base64-алфавит — декодирование обязано упасть
        p["header_protection_key"] = "!" * 44
        ok, err = awg31_validate_extra_params(p)
        self.assertFalse(ok)
        self.assertIn("HeaderProtectionKey", err)

    def test_range_format_garbage(self):
        p = self._valid()
        p["rekey_after_time"] = "abc"
        ok, err = awg31_validate_extra_params(p)
        self.assertFalse(ok)
        self.assertIn("RekeyAfterTime", err)

    def test_range_out_of_bounds(self):
        p = self._valid()
        p["rekey_after_time"] = "999-1000"
        ok, err = awg31_validate_extra_params(p)
        self.assertFalse(ok)
        self.assertIn("RekeyAfterTime", err)

    def test_range_n_greater_than_m(self):
        p = self._valid()
        p["keepalive_timeout"] = "12-8"
        ok, err = awg31_validate_extra_params(p)
        self.assertFalse(ok)
        self.assertIn("KeepaliveTimeout", err)

    # ── официальные формы «N» (одиночное число, amneziawg-tools
    # type.c u16_range_from_string) + кросс-валидации таймеров ──────────

    def test_single_number_forms_accepted(self):
        # Официально все диапазонные директивы принимают и «N», и «N-M»
        p = self._valid()
        p["content_padding_addition"] = "5"
        p["rekey_after_time"] = "110"
        p["rekey_timeout"] = "5"
        p["reject_after_time"] = "200"
        p["keepalive_timeout"] = "10"
        p["max_handshake_attempts"] = "20"
        ok, err = awg31_validate_extra_params(p)
        self.assertTrue(ok, msg=err)

    def test_single_number_int_type_accepted(self):
        p = self._valid()
        p["content_padding_addition"] = 3   # int из state/JSON
        ok, err = awg31_validate_extra_params(p)
        self.assertTrue(ok, msg=err)

    def test_content_padding_zero_allowed(self):
        # ContentPaddingAddition = 0 — доп. паддинг отключён (валидно)
        p = self._valid()
        p["content_padding_addition"] = "0"
        ok, err = awg31_validate_extra_params(p)
        self.assertTrue(ok, msg=err)

    def test_reject_vs_keepalive_plus_rekey_crosscheck(self):
        # ARCHITECT: RejectAfterTime должен быть > Keepalive + RekeyTimeout.
        # При текущих границах (reject ≥ 130 > keep_hi+rkey_hi ≤ 30) конфликт
        # внутри bounds невозможен — но проверка защищает при расширении
        # границ в будущем. Тест: недостижимые значения reject ниже окна
        # keepalive+rekey отбрасываются (хотя бы границами).
        p = self._valid()
        p["keepalive_timeout"] = "18-20"
        p["rekey_timeout"] = "8-10"
        p["reject_after_time"] = "25-30"   # вне bounds и ниже keep+rekey
        ok, err = awg31_validate_extra_params(p)
        self.assertFalse(ok)
        self.assertIn("RejectAfterTime", err)

    def test_rekey_after_time_not_less_than_reject_rejected(self):
        # ARCHITECT: RekeyAfterTime < RejectAfterTime
        p = self._valid()
        p["rekey_after_time"] = "180-200"
        p["reject_after_time"] = "160-170"   # rekey_hi(200) >= rej_lo(160)
        ok, err = awg31_validate_extra_params(p)
        self.assertFalse(ok)
        self.assertIn("RekeyAfterTime", err)

    def test_default_generation_passes_cross_validation(self):
        # Сгенерированный по умолчанию набор проходит кросс-валидации
        for _ in range(20):
            ok, err = awg31_validate_extra_params(awg31_generate_extra_params())
            self.assertTrue(ok, msg=err)

    def test_flag_official_bool_forms_accepted(self):
        # parse_bool amneziawg-tools — официально «on»/«off»/«0»/«1»
        # (генерация пишет «on», но конфиги с off/0/1 — валидные)
        for v in ("on", "off", "0", "1", "ON", "Off"):
            p = self._valid()
            p["random_trailers"] = v
            ok, err = awg31_validate_extra_params(p)
            self.assertTrue(ok, msg=f"{v}: {err}")

    def test_flag_invalid_rejected(self):
        p = self._valid()
        p["random_trailers"] = "maybe"
        ok, err = awg31_validate_extra_params(p)
        self.assertFalse(ok)
        self.assertIn("RandomTrailers", err)

    def test_flag_empty_rejected(self):
        p = self._valid()
        p["disable_cookies"] = ""
        ok, err = awg31_validate_extra_params(p)
        self.assertFalse(ok)
        self.assertIn("DisableCookies", err)

    def test_non_dict_rejected(self):
        ok, err = awg31_validate_extra_params("not-a-dict")
        self.assertFalse(ok)

    def test_all_range_keys_covered(self):
        # Контракт: каждый диапазонный ключ проверяется
        self.assertEqual(
            set(AWG31_RANGE_KEYS.keys()) | set(AWG31_FLAG_KEYS),
            set(AWG31_EXTRA_KEYS) - {"header_protection_key"})


class TestRender31Lines(unittest.TestCase):
    def test_render_full(self):
        p = awg31_generate_extra_params()
        rendered = awg_render_31_lines(p)
        lines = rendered.splitlines()
        self.assertEqual(len(lines), 9)
        # Порядок директив — GenerateObfuscation31 (после I1-I5)
        self.assertEqual(
            [l.split(" =")[0] for l in lines],
            [AWG31_DIRECTIVE_NAMES[k] for k in AWG31_EXTRA_KEYS])
        for k in AWG31_EXTRA_KEYS:
            self.assertIn(f"{AWG31_DIRECTIVE_NAMES[k]} = {p[k]}", rendered)

    def test_empty_params_all_commented(self):
        # Пустые параметры → «# Key = » (правило голое «Key = »
        # валит awg setconf)
        rendered = awg_render_31_lines({})
        for d in AWG31_DIRECTIVE_NAMES.values():
            self.assertIn(f"# {d} = ", rendered)
            self.assertNotIn(f"\n{d} = \n", rendered)

    def test_partial_params(self):
        rendered = awg_render_31_lines({"random_trailers": "on"})
        self.assertIn("RandomTrailers = on", rendered)
        self.assertIn("# HeaderProtectionKey = ", rendered)

    def test_non_dict_params_safe(self):
        rendered = awg_render_31_lines(None)
        self.assertIn("# HeaderProtectionKey = ", rendered)


class TestMergeIntoParams(unittest.TestCase):
    def test_merge_adds_all_31_keys(self):
        base = {"jc": 4, "jmin": 40, "jmax": 70, "i1": "<r 32>"}
        merged = awg31_merge_into_params(base)
        for k in AWG31_EXTRA_KEYS:
            self.assertTrue(merged[k], msg=k)
        # База не мутирована
        self.assertNotIn("header_protection_key", base)
        # База сохранена
        self.assertEqual(merged["jc"], 4)

    def test_merge_respects_existing(self):
        base = {"jc": 4}
        extra = awg31_generate_extra_params()
        merged = awg31_merge_into_params(base, dict(extra))
        self.assertEqual(merged["header_protection_key"],
                         extra["header_protection_key"])

    def test_merge_fills_only_empty(self):
        base = {"jc": 4, "random_trailers": "on"}
        extra = {"random_trailers": "on", "disable_cookies": "on"}
        merged = awg31_merge_into_params(base, extra)
        self.assertEqual(merged["random_trailers"], "on")


class TestStateProtocolVersion(unittest.TestCase):
    def test_missing_key_is_20(self):
        # Старые state без ключа = 2.0 — миграция не нужна
        self.assertEqual(awg_state_protocol_version({}), "2.0")
        self.assertEqual(awg_state_protocol_version(
            {"installed": True, "params": {}}), "2.0")

    def test_31_state(self):
        self.assertEqual(
            awg_state_protocol_version({"protocol_version": "3.1"}), "3.1")

    def test_garbage_state_is_20(self):
        self.assertEqual(
            awg_state_protocol_version({"protocol_version": "???"}), "2.0")

    def test_non_dict_state_is_20(self):
        self.assertEqual(awg_state_protocol_version(None), "2.0")
        self.assertEqual(awg_state_protocol_version("x"), "2.0")


if __name__ == "__main__":
    unittest.main(verbosity=2)

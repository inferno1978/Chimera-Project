#!/usr/bin/env python3
"""
tests/test_awg_i2i5_mimicry.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты расширений v5.5.5 (сверка с генератором ARCHITECT, Task 31):

  1. I2-I5 — автозаполнение decoy-цепочек в 3.1 (awgs_presets_generate,
     awgs_generate_full_manual_params): дефолт 3.1 = заполнены все 5,
     дефолт 2.0 = пустые (прежний контракт), i_chain_fill управляет явно,
     override пользователя приоритетнее, якорь I1 обязателен.
  2. Строгий кросс-движковый режим валидатора (strict_cross_engine):
     <c> (kernel-only) и <d>/<ds>/<dz N> (go-only, no-op) блокируются;
     мягкий режим (импорт внешних конфигов) принимает всё официальное.
  3. Реестр профилей мимикрии — 13 профилей: структурная валидность CPS,
     кросс-движковые теги, full-chain quic_burst, host-база HTTP/3
     (DNS-wire кодировка), размерные подсказки S1-S4 с клампом под 3.1.
  4. WPP-мир: _parameters("awg31") выдаёт I2-I5, awg20 — без I-полей.
  5. Интерактивный ввод (awgs_prompt_custom_params): блокировка
     одно-движковых тегов с переспросом, шорткаты профилей, burst
     заполняет I1-I5 целиком, дефолты 3.1 проходят финальную валидацию.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules.awg_presets import (
    AWG_I1_MIMICRY_PROFILES, AWG_HTTP3_MIMICRY_HOSTS,
    AWG_I1_MIMICRY_S_HINTS, I_CHAIN_FILL_SIZES,
    awgs_presets_generate, awgs_presets_validate_params,
    awgs_generate_full_manual_params, awgs_presets_list,
    awg_i1_mimicry_generate, awg_i_chain_mimicry_generate,
    awg_mimicry_s_hint, awg_generate_i2_i5,
    awg_is_valid_cps_chain, _cps_has_kernel_only_tags, _cps_has_go_only_tags,
    _dns_wire_host_hex, _generate_neutral_i_chain,
)

_I_KEYS = ("i1", "i2", "i3", "i4", "i5")


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


def _mock_core():
    core = MagicMock()
    for attr in ("GREEN", "NC", "RED", "YELLOW", "CYAN", "BLUE", "DIM", "BOLD"):
        setattr(core, attr, "")
    for attr in ("_box_top", "_box_row", "_box_sep", "_box_bottom",
                 "_box_item", "_box_desc", "_box_wrap_msg"):
        setattr(core, attr, MagicMock())
    for attr in ("info", "success", "warn", "error", "log_to_file"):
        setattr(core, attr, MagicMock())
    return core


# ─────────────────────────────────────────────────────────────────────────────
#  1. I2-I5 автозаполнение
# ─────────────────────────────────────────────────────────────────────────────
class TestI2I5AutoFill(unittest.TestCase):
    """Генерация I2-I5: 3.1 — заполнены, 2.0 — прежний контракт (пустые)."""

    def test_31_default_fills_all_five(self):
        for preset in awgs_presets_list():
            for _ in range(5):
                p = awgs_presets_generate(preset, "3.1")
                for k in ("i2", "i3", "i4", "i5"):
                    self.assertTrue(p[k], msg=f"{preset}/{k}: пусто в 3.1")
                    self.assertTrue(awg_is_valid_cps_chain(p[k]),
                                    msg=f"{preset}/{k}: {p[k]}")
                    self.assertFalse(_cps_has_kernel_only_tags(p[k]))
                    self.assertFalse(_cps_has_go_only_tags(p[k]))

    def test_31_generated_params_valid(self):
        for preset in awgs_presets_list():
            p = awgs_presets_generate(preset, "3.1")
            ok, err = awgs_presets_validate_params(p, "3.1")
            self.assertTrue(ok, msg=f"{preset}: {err}")

    def test_31_nofill_disables(self):
        p = awgs_presets_generate("default", "3.1", i_chain_fill=False)
        self.assertTrue(p["i1"])
        for k in ("i2", "i3", "i4", "i5"):
            self.assertEqual(p[k], "")

    def test_20_default_empty_regression(self):
        # Прежний контракт 2.0 — байт-в-байт: I2-I5 пустые
        for preset in awgs_presets_list():
            p = awgs_presets_generate(preset)
            for k in ("i2", "i3", "i4", "i5"):
                self.assertEqual(p[k], "")

    def test_20_explicit_fill(self):
        p = awgs_presets_generate("default", "2.0", i_chain_fill=True)
        self.assertTrue(p["i1"])
        for k in ("i2", "i3", "i4", "i5"):
            self.assertTrue(p[k])

    def test_absent_anchor_20(self):
        # I1 пуст (absent) → I2-I5 не заполняются даже с fill=True
        # (движок пропускает I2-I5 без якоря I1)
        p = awgs_presets_generate("tele2_krasnoyarsk", "2.0", i_chain_fill=True)
        self.assertEqual(p["i1"], "")
        for k in ("i2", "i3", "i4", "i5"):
            self.assertEqual(p[k], "")

    def test_manual_31_filled(self):
        p = awgs_generate_full_manual_params(None, "3.1")
        for k in ("i2", "i3", "i4", "i5"):
            self.assertTrue(p[k])
        ok, err = awgs_presets_validate_params(p, "3.1")
        self.assertTrue(ok, msg=err)

    def test_manual_20_empty_regression(self):
        p = awgs_generate_full_manual_params(None, "2.0")
        for k in ("i2", "i3", "i4", "i5"):
            self.assertEqual(p[k], "")

    def test_manual_20_explicit_fill(self):
        p = awgs_generate_full_manual_params(None, "2.0", i_chain_fill=True)
        for k in ("i2", "i3", "i4", "i5"):
            self.assertTrue(p[k])

    def test_manual_overrides_win_both_versions(self):
        for pv in ("2.0", "3.1"):
            p = awgs_generate_full_manual_params(
                {"i2": "<r 11>", "i3": "<b 0xdeadbeef>"}, pv)
            self.assertEqual(p["i2"], "<r 11>")
            self.assertEqual(p["i3"], "<b 0xdeadbeef>")

    def test_neutral_chain_forms(self):
        # Три формы: <r N> | <b 0x...><r N> | <r N><b 0x...>
        forms = set()
        for _ in range(200):
            s = _generate_neutral_i_chain()
            self.assertTrue(awg_is_valid_cps_chain(s), s)
            self.assertFalse(_cps_has_kernel_only_tags(s))
            self.assertFalse(_cps_has_go_only_tags(s))
            if s.startswith("<r") and s.endswith(">") and s.count("<") == 1:
                forms.add("r")
            elif "<b" in s and s.index("<r") < s.index("<b"):
                forms.add("r-b")
            elif "<b" in s:
                forms.add("b-r")
        self.assertGreaterEqual(forms, {"r", "r-b", "b-r"},
                                msg=f"форм цепочек меньше трёх: {forms}")

    def test_generate_i2_i5_sizes(self):
        for _ in range(50):
            d = awg_generate_i2_i5()
            for idx, k in enumerate(("i2", "i3", "i4", "i5")):
                lo, hi = I_CHAIN_FILL_SIZES[idx]
                # <r N> задаёт основной размер; N в [lo, hi] для формы <r N>
                # (для форм с <b> суммарный размер больше — проверяем нижнюю
                # границу энтропии)
                self.assertIn(k, d)
                self.assertGreaterEqual(len(d[k]), len(f"<r {lo}>"))


# ─────────────────────────────────────────────────────────────────────────────
#  2. Строгий кросс-движковый валидатор
# ─────────────────────────────────────────────────────────────────────────────
class TestStrictCrossEngineValidator(unittest.TestCase):
    """strict_cross_engine: блок <c>/<d>/<ds>/<dz>, мягкий режим — импорт."""

    def _valid_31(self):
        return awgs_presets_generate("default", "3.1")

    def test_kernel_only_c_blocked_strict(self):
        p = self._valid_31()
        p["i2"] = "<c>"
        ok, err = awgs_presets_validate_params(p, "3.1", strict_cross_engine=True)
        self.assertFalse(ok)
        self.assertIn("<c>", err)

    def test_go_only_tags_blocked_strict(self):
        for bad in ("<d>", "<ds>", "<dz 12>", "<r 8><dz 4>"):
            p = self._valid_31()
            p["i3"] = bad
            ok, err = awgs_presets_validate_params(p, "3.1", strict_cross_engine=True)
            self.assertFalse(ok, msg=bad)
            self.assertIn("go", err.lower())

    def test_soft_mode_accepts_official_tags(self):
        # Мягкий режим (импорт ARCHITECT/3x-ui/ручных конфигов) принимает
        # весь официальный словарь тегов
        for good in ("<c>", "<d>", "<ds>", "<dz 12>", "<r 8><dz 4>"):
            p = self._valid_31()
            p["i3"] = good
            ok, err = awgs_presets_validate_params(p, "3.1")
            self.assertTrue(ok, msg=f"{good}: {err}")

    def test_cross_engine_tags_pass_strict(self):
        for good in ("<b 0xdeadbeef>", "<t>", "<r 42>", "<rc 16>",
                     "<rd 8><t><r 4>", "<b 0xc30000000108><r 8>"):
            p = self._valid_31()
            p["i1"] = good
            ok, err = awgs_presets_validate_params(p, "3.1", strict_cross_engine=True)
            self.assertTrue(ok, msg=f"{good}: {err}")

    def test_go_only_regex_no_false_positive(self):
        # <b>/<rd> содержат 'd' в hex/имени — не должны ловиться
        self.assertFalse(_cps_has_go_only_tags("<b 0xd3d3d3>"))
        self.assertFalse(_cps_has_go_only_tags("<rd 5>"))
        self.assertFalse(_cps_has_go_only_tags("<r 8><b 0x00dd>"))
        self.assertTrue(_cps_has_go_only_tags("<d>"))
        self.assertTrue(_cps_has_go_only_tags("<ds>"))
        self.assertTrue(_cps_has_go_only_tags("<dz 3>"))
        self.assertTrue(_cps_has_go_only_tags("<r 2><dz 8>"))


# ─────────────────────────────────────────────────────────────────────────────
#  3. Реестр профилей мимикрии (13)
# ─────────────────────────────────────────────────────────────────────────────
class TestMimicryRegistry(unittest.TestCase):
    """13 профилей: структурная валидность + кросс-движковость."""

    EXPECTED = {
        "random", "quic_mimicry", "quic_0rtt", "quic_burst", "dns_mimicry",
        "tls_mimicry", "tls_altsvc", "dtls12", "dtls13", "noise_ik",
        "http3_host", "sip", "binary",
    }

    def test_registry_count_and_names(self):
        self.assertEqual(set(AWG_I1_MIMICRY_PROFILES), self.EXPECTED)
        self.assertEqual(len(AWG_I1_MIMICRY_PROFILES), 13)

    def test_all_profiles_valid_cross_engine(self):
        for mode in AWG_I1_MIMICRY_PROFILES:
            for _ in range(20):
                chain = awg_i_chain_mimicry_generate(mode)
                for s in chain:
                    if s:
                        self.assertTrue(awg_is_valid_cps_chain(s),
                                        msg=f"{mode}: {s}")
                        self.assertFalse(_cps_has_kernel_only_tags(s),
                                         msg=f"{mode}: kernel-only в {s}")
                        self.assertFalse(_cps_has_go_only_tags(s),
                                         msg=f"{mode}: go-only в {s}")

    def test_all_profiles_pass_strict_validator(self):
        for mode in AWG_I1_MIMICRY_PROFILES:
            p = awgs_presets_generate("default", "3.1")
            i1, i2, i3, i4, i5 = awg_i_chain_mimicry_generate(mode)
            p.update({"i1": i1, "i2": i2, "i3": i3, "i4": i4, "i5": i5})
            ok, err = awgs_presets_validate_params(p, "3.1",
                                                   strict_cross_engine=True)
            self.assertTrue(ok, msg=f"{mode}: {err}")

    def test_burst_full_chain(self):
        chain = awg_i_chain_mimicry_generate("quic_burst")
        self.assertEqual(len(chain), 5)
        self.assertTrue(all(chain))
        # QUIC-типы пакетов: Initial 0xc3, 0-RTT 0xd3, Handshake 0xe3,
        # 1-RTT short header 0x40-0x7f
        self.assertTrue(chain[0].startswith("<b 0xc3"))
        self.assertTrue(chain[1].startswith("<b 0xd3"))
        self.assertTrue(chain[2].startswith("<b 0xe3"))
        self.assertTrue(chain[3].startswith("<b 0x4"))
        self.assertTrue(chain[4].startswith("<b 0x5"))

    def test_i1_mimicry_generate_burst_returns_str(self):
        val = awg_i1_mimicry_generate("quic_burst")
        self.assertIsInstance(val, str)
        self.assertTrue(val.startswith("<b 0xc3"))

    def test_i1_mimicry_generate_unknown_neutral(self):
        val = awg_i1_mimicry_generate("no_such_profile")
        self.assertTrue(val.startswith("<r "))

    def test_http3_host_wire_encoding(self):
        # <b 0x...> после <t> — DNS-wire SNI одного из хостов базы
        import re
        for _ in range(30):
            chain = awg_i1_mimicry_generate("http3_host")
            m = re.search(r"<t><b 0x([0-9a-f]+)>", chain)
            self.assertIsNotNone(m, msg=chain)
            wire = bytes.fromhex(m.group(1))
            # Разбор DNS-wire: последовательность (len, label...) до 0x00
            labels, i = [], 0
            while wire[i] != 0:
                n = wire[i]
                labels.append(wire[i + 1:i + 1 + n].decode("ascii"))
                i += 1 + n
            self.assertEqual(wire[-1], 0)
            host = ".".join(labels)
            self.assertIn(host, AWG_HTTP3_MIMICRY_HOSTS, msg=host)

    def test_dns_wire_host_hex(self):
        self.assertEqual(_dns_wire_host_hex("www.google.com"),
                         "0377777706676f6f676c6503636f6d00")
        self.assertEqual(_dns_wire_host_hex("t.me"), "0174026d6500")

    def test_sip_ascii_prefix(self):
        chain = awg_i1_mimicry_generate("sip")
        # "INVITE sip:" и " SIP/2.0\r\n" — реальные ASCII-байты SIP
        self.assertIn("<b 0x494e56495445207369703a>", chain)
        self.assertIn("<b 0x205349502f322e300d0a>", chain)
        self.assertIn("<rc 8>", chain)   # user
        self.assertIn("<rd 5>", chain)   # port

    def test_dtls12_selfconsistent_length(self):
        chain = awg_i1_mimicry_generate("dtls12")
        # length 0x0033 = 51 == тело (1 байт типа + 50 рандома)
        self.assertIn("<b 0x0033><b 0x01><r 50>", chain)

    def test_s_hints_clamped_31(self):
        # QUIC-подсказки клампятся к верхней границе 3.1 (150/55/27)
        h31 = awg_mimicry_s_hint("quic_mimicry", "3.1")
        self.assertEqual(h31["s1"], (150, 150))
        self.assertEqual(h31["s3"], (55, 55))
        self.assertEqual(h31["s4"], (27, 27))
        # 2.0 — полный размерный диапазон QUIC Initial (>= 1200)
        h20 = awg_mimicry_s_hint("quic_mimicry", "2.0")
        self.assertEqual(h20["s1"], (1150, 1250))

    def test_s_hint_dns_20_within_validator(self):
        h = awg_mimicry_s_hint("dns_mimicry", "2.0")
        self.assertEqual(h["s1"], (30, 80))
        self.assertEqual(h["s3"], (12, 40))
        self.assertEqual(h["s4"], (12, 27))
        # Все подсказки — в пределах валидатора 2.0
        base = awgs_presets_generate("default")
        base.update({"s1": h["s1"][0], "s2": h["s2"][0],
                     "s3": h["s3"][0], "s4": h["s4"][0]})
        ok, err = awgs_presets_validate_params(base, "2.0")
        self.assertTrue(ok, msg=err)

    def test_s_hint_empty_for_neutral_profiles(self):
        self.assertEqual(awg_mimicry_s_hint("random"), {})
        self.assertEqual(awg_mimicry_s_hint("binary", "3.1"), {})
        self.assertEqual(awg_mimicry_s_hint("no_such"), {})

    def test_s_hints_registry_covers_all_mimicry_profiles(self):
        for mode in AWG_I1_MIMICRY_PROFILES:
            if mode in ("random", "binary"):
                continue
            self.assertIn(mode, AWG_I1_MIMICRY_S_HINTS,
                          msg=f"у профиля {mode} нет S-подсказки")


# ─────────────────────────────────────────────────────────────────────────────
#  4. WPP-мир
# ─────────────────────────────────────────────────────────────────────────────
class TestWppI2I5(unittest.TestCase):
    """wpp_awg._parameters: awg31 — I2-I5 заполнены, awg20 — без I-полей."""

    def test_wpp_31_i2_i5(self):
        from chimera.modules import wpp_awg
        with patch.object(wpp_awg, "_key",
                          return_value="MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="):
            p = wpp_awg._parameters("awg31")
        for k in ("I1", "I2", "I3", "I4", "I5"):
            self.assertTrue(p[k], msg=k)
            self.assertTrue(awg_is_valid_cps_chain(p[k]), msg=f"{k}: {p[k]}")
            self.assertFalse(_cps_has_kernel_only_tags(p[k]))
            self.assertFalse(_cps_has_go_only_tags(p[k]))
        # Все 25 параметров рендерятся в конфиг
        lines = wpp_awg._parameter_lines(p)
        for k in ("I1", "I2", "I3", "I4", "I5"):
            self.assertTrue(any(l.startswith(f"{k} =") for l in lines))

    def test_wpp_20_no_i_fields_regression(self):
        from chimera.modules import wpp_awg
        with patch.object(wpp_awg, "_key",
                          return_value="MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="):
            p = wpp_awg._parameters("awg20")
        for k in ("I1", "I2", "I3", "I4", "I5"):
            self.assertNotIn(k, p)


# ─────────────────────────────────────────────────────────────────────────────
#  5. Интерактивный ввод (awgs_prompt_custom_params)
# ─────────────────────────────────────────────────────────────────────────────
class TestPromptCustomParams(unittest.TestCase):
    """Мок input(): блокировки одно-движковых тегов, шорткаты, burst."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _run_prompt(self, inputs):
        from chimera.modules import awg_standalone
        with patch.object(awg_standalone, "_core_module",
                          return_value=_mock_core()), \
             patch("builtins.input",
                   side_effect=[*inputs, StopIteration()]):
            try:
                return awg_standalone.awgs_prompt_custom_params("3.1")
            except StopIteration:
                self.fail("prompt запросил больше значений, чем передано")

    def test_defaults_31_pass_validation(self):
        # «Всё по Enter»: 7 числовых + H auto + I1 auto + I2-I5 Enter + 9×3.1
        inputs = [""] * 7 + ["auto"] + ["auto"] + [""] * 4 + [""] * 9
        p = self._run_prompt(inputs)
        self.assertIsNotNone(p)
        self.assertTrue(p["i1"].startswith("<r "))
        for k in ("i2", "i3", "i4", "i5"):
            self.assertEqual(p[k], "")

    def test_kernel_only_c_rejected_then_reasked(self):
        # <c> блокируется с переспросом → пользователь вводит auto
        inputs = [""] * 7 + ["auto"] + ["<c>", "auto"] + [""] * 4 + [""] * 9
        p = self._run_prompt(inputs)
        self.assertIsNotNone(p)
        self.assertNotIn("<c>", p["i1"])

    def test_go_only_dz_rejected_then_reasked(self):
        inputs = [""] * 7 + ["auto"] + ["<dz 8>", "auto"] + [""] * 4 + [""] * 9
        p = self._run_prompt(inputs)
        self.assertIsNotNone(p)
        self.assertNotIn("<dz", p["i1"])

    def test_burst_fills_all_five(self):
        # burst на I1 → I1-I5 заполнены, промпты I2-I5 пропускаются
        inputs = [""] * 7 + ["auto"] + ["burst"] + [""] * 9
        p = self._run_prompt(inputs)
        self.assertIsNotNone(p)
        for k in _I_KEYS:
            self.assertTrue(p[k], msg=k)
        self.assertTrue(p["i1"].startswith("<b 0xc3"))
        self.assertTrue(p["i2"].startswith("<b 0xd3"))
        self.assertTrue(p["i5"].startswith("<b 0x5f"))

    def test_fill_shortcut_on_i2(self):
        inputs = [""] * 7 + ["auto"] + ["auto"] + ["fill"] + [""] * 3 + [""] * 9
        p = self._run_prompt(inputs)
        self.assertIsNotNone(p)
        self.assertTrue(p["i2"])
        self.assertTrue(awg_is_valid_cps_chain(p["i2"]))

    def test_all_profile_shortcuts_resolve(self):
        from chimera.modules.awg_standalone import AWGS_MIMICRY_SHORTCUTS
        for shortcut, profile in AWGS_MIMICRY_SHORTCUTS.items():
            self.assertIn(profile, AWG_I1_MIMICRY_PROFILES,
                          msg=f"шорткат {shortcut} → неизвестный профиль")
        # Ключевые шорткаты нового набора присутствуют
        for s in ("quic0rtt", "burst", "dtls12", "dtls13", "noise",
                  "http3", "sip", "altsvc"):
            self.assertIn(s, AWGS_MIMICRY_SHORTCUTS)


if __name__ == "__main__":
    unittest.main(verbosity=2)

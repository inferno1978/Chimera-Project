#!/usr/bin/env python3
"""
tests/test_text_width.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/text_width.py.

Покрывает:
  • wlen() — визуальная ширина строки
  • plain() — удаление ANSI escape sequences
  • Регрессия на баг «правая рамка ║ съезжала из-за ⚠ emoji»:
    раньше ⚠ (U+26A0) считался за 1 колонку (east_asian_width='N'),
    но терминалы рендерят его как 2 — рамка ломалась.
  • Emoji_Presentation-default символы (⚠ ❌ ✅ ⭐ и т.д.) — 2 колонки
  • CJK / Wide / Fullwidth — 2 колонки
  • Variation Selector-16 (U+FE0F) — делает предшествующий символ wide
  • Zero-Width Joiner (U+200D) и combining marks — 0 колонок
  • ANSI escape sequences — не считаются
  • None / non-string — graceful handling
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from chimera.modules.text_width import wlen, plain, _plain, _wlen


class TestPlain(unittest.TestCase):
    """plain() — удаление ANSI escape sequences."""

    def test_strips_sgr_sequences(self):
        self.assertEqual(plain("\033[0;33m⚠\033[0m текст"), "⚠ текст")

    def test_strips_multiple_sequences(self):
        self.assertEqual(plain("\033[1m\033[31mRED\033[0m"), "RED")

    def test_no_sequences_unchanged(self):
        self.assertEqual(plain("plain text"), "plain text")

    def test_empty_string(self):
        self.assertEqual(plain(""), "")

    def test_backward_compat_alias(self):
        """_plain — alias для plain (совместимость со старым API)."""
        self.assertEqual(_plain("\033[31mX\033[0m"), "X")
        self.assertIs(_plain, plain)


class TestWlenAscii(unittest.TestCase):
    """wlen() — ASCII / базовые случаи."""

    def test_empty_string(self):
        self.assertEqual(wlen(""), 0)

    def test_ascii_single_char(self):
        self.assertEqual(wlen("a"), 1)

    def test_ascii_word(self):
        self.assertEqual(wlen("hello"), 5)

    def test_ascii_sentence(self):
        self.assertEqual(wlen("hello world"), 11)

    def test_spaces_count(self):
        self.assertEqual(wlen("   "), 3)

    def test_digits(self):
        self.assertEqual(wlen("12345"), 5)


class TestWlenCyrillic(unittest.TestCase):
    """wlen() — кириллица (узкие символы, 1 колонка)."""

    def test_cyrillic_word(self):
        # Кириллица — east_asian_width='N' (Neutral), ширина 1
        self.assertEqual(wlen("привет"), 6)

    def test_cyrillic_sentence(self):
        self.assertEqual(wlen("Привет, мир!"), 12)

    def test_mixed_cyrillic_ascii(self):
        self.assertEqual(wlen("hello мир"), 9)


class TestWlenCJK(unittest.TestCase):
    """wlen() — CJK иероглифы (ширина 2)."""

    def test_chinese(self):
        # 世界 — 2 иероглифа, каждый шириной 2
        self.assertEqual(wlen("世界"), 4)

    def test_japanese_hiragana(self):
        # ひらがな — Wide
        self.assertEqual(wlen("ひらがな"), 8)

    def test_korean_hangul(self):
        # 한글 — Wide
        self.assertEqual(wlen("한글"), 4)

    def test_mixed_cjk_ascii(self):
        # "hello世界" = 5 (ASCII) + 4 (CJK) = 9
        self.assertEqual(wlen("hello世界"), 9)


class TestWlenEmojiPresentation(unittest.TestCase):
    """wlen() — Emoji_Presentation-default символы (регрессия на ⚠).

    Баг: ⚠ (U+26A0) имеет east_asian_width='N' (Neutral), но терминалы
    рендерят его как 2 колонки из-за Emoji_Presentation property.
    Старая реализация считала его за 1 — правая рамка ║ съезжала.
    """

    def test_warning_sign_alone(self):
        """⚠ (U+26A0) — ДОЛЖНО быть 2 колонки, не 1."""
        self.assertEqual(wlen("⚠"), 2,
                         "⚠ должен быть шириной 2 (Emoji_Presentation)")

    def test_warning_sign_in_sentence(self):
        """Регрессия: '⚠ возможен блок' — рамка не должна съезжать."""
        # ⚠(2) + " "(1) + "возможен"(8) + " "(1) + "блок"(4) = 16
        # Старый (баганый) расчёт: ⚠=1 → 15 (рамка съезжала на 1 колонку)
        text = "⚠ возможен блок"
        self.assertEqual(wlen(text), 16)
        # Проверяем что длина не равна старому (баганому) значению 15
        self.assertNotEqual(wlen(text), len(text),
                            "wlen() должен отличаться от len() для строк с ⚠")

    def test_cross_mark(self):
        """❌ (U+274C) — 2 колонки."""
        self.assertEqual(wlen("❌"), 2)

    def test_check_mark_emoji(self):
        """✅ (U+2705) — 2 колонки."""
        self.assertEqual(wlen("✅"), 2)

    def test_star(self):
        """⭐ (U+2B50) — 2 колонки."""
        self.assertEqual(wlen("⭐"), 2)

    def test_no_entry(self):
        """⛔ (U+26D4) — 2 колонки."""
        self.assertEqual(wlen("⛔"), 2)

    def test_high_voltage(self):
        """⚡ (U+26A1) — 2 колонки."""
        self.assertEqual(wlen("⚡"), 2)

    def test_warning_with_fe0f(self):
        """⚠️ (U+26A0 + U+FE0F) — 2 колонки (VS16 явно запрашивает emoji)."""
        self.assertEqual(wlen("⚠️"), 2)

    def test_warning_vs_plain_checkmark(self):
        """⚠ (2 кол.) vs ✓ (1 кол.) — важное различие для TUI выравнивания."""
        # ✓ (U+2713) — CHECK MARK, не Emoji_Presentation, ширина 1
        # ⚠ (U+26A0) — WARNING SIGN, Emoji_Presentation, ширина 2
        self.assertEqual(wlen("✓"), 1)
        self.assertEqual(wlen("⚠"), 2)


class TestWlenEmojiBMP(unittest.TestCase):
    """wlen() — emoji вне BMP (суррогатные пары)."""

    def test_grinning_face(self):
        """😀 (U+1F600) — 2 колонки."""
        self.assertEqual(wlen("😀"), 2)

    def test_rocket(self):
        """🚀 (U+1F680) — 2 колонки."""
        self.assertEqual(wlen("🚀"), 2)

    def test_multiple_emoji(self):
        """😀🚀 — 4 колонки."""
        self.assertEqual(wlen("😀🚀"), 4)


class TestWlenAnsiSequences(unittest.TestCase):
    """wlen() — ANSI escape sequences не считаются."""

    def test_sgr_color(self):
        # \033[31m = RED, \033[0m = reset
        self.assertEqual(wlen("\033[31mX\033[0m"), 1)

    def test_multiple_sgr(self):
        self.assertEqual(wlen("\033[1m\033[33m⚠\033[0m"), 2)

    def test_mixed_ansi_and_text(self):
        # Реальный пример из mtproto.py _box_warn:
        # f"  {YELLOW}⚠{NC}  {msg}"
        text = "  \033[1;33m⚠\033[0m  предупреждение"
        # 2 пробела + ⚠(2) + 2 пробела + "предупреждение"(14) = 20
        self.assertEqual(wlen(text), 20)


class TestWlenZWJAndCombining(unittest.TestCase):
    """wlen() — Zero-Width Joiner и combining marks."""

    def test_zwj_zero_width(self):
        # U+200D — Zero-Width Joiner, 0 колонок
        self.assertEqual(wlen("a\u200Db"), 2)

    def test_combining_marks_zero_width(self):
        # U+0301 — combining acute accent, 0 колонок
        # "а" + combining acute = 1 колонка (а́)
        self.assertEqual(wlen("а\u0301"), 1)

    def test_variation_selector_15_zero_width(self):
        # U+FE00 — Variation Selector-1, 0 колонок
        self.assertEqual(wlen("a\ufe00"), 1)


class TestWlenEdgeCases(unittest.TestCase):
    """wlen() — краевые случаи."""

    def test_none_input(self):
        self.assertEqual(wlen(None), 0)

    def test_non_string_input(self):
        """Не-строка → str() преобразование."""
        self.assertEqual(wlen(123), 3)  # "123"
        self.assertEqual(wlen(0), 1)    # "0"

    def test_backward_compat_alias(self):
        """_wlen — alias для wlen (совместимость со старым API)."""
        self.assertEqual(_wlen("⚠"), 2)
        self.assertIs(_wlen, wlen)


class TestRegressionBoxRowWidth(unittest.TestCase):
    """Регрессия: _box_row с ⚠ должен давать корректную ширину для рамки.

    Сценарий из mtproto.py строки 1497:
        _box_row(f"  {DIM}{RED}⚠{NC}{DIM} возможен блок iOS без OpenSSL 3.5+, "
                 f"{GREEN}✓{NC}{DIM} подтверждено (не проверено нами){NC}")

    Старый баг: wlen считал ⚠ за 1, реально 2 → pad = _BOX_W - w
    был на 1 больше нужного → правая ║ смещена на 1 влево.
    """

    def test_warning_row_width_calculation(self):
        """Проверяем что ширина строки с ⚠ и ✓ считается правильно."""
        # Имитируем строку из mtproto.py (без ANSI для простоты)
        text = "  ⚠ возможен блок iOS без OpenSSL 3.5+, ✓ подтверждено (не проверено нами)"
        w = wlen(text)
        # Старый (баганый) расчёт: ⚠=1 → 74 (рамка съезжала на 1 колонку)
        # Новый (правильный):      ⚠=2 → 75
        # Разница ровно в 1 колонку — это и есть смещение правой ║
        self.assertEqual(w, 75,
                         "Ширина строки с ⚠ должна быть 75 (новый расчёт)")
        self.assertEqual(w - len(text), 1,
                         "Разница wlen - len должна быть 1 (один ⚠ как 2 вместо 1)")

    def test_box_width_consistency(self):
        """Если _BOX_W = 66, то строка длиннее бокса — нужна обрезка.
        Проверяем что pad считается правильно (отрицательный → обрезка)."""
        _BOX_W = 66
        text = "  ⚠ возможен блок iOS без OpenSSL 3.5+, ✓ подтверждено (не проверено нами)"
        w = wlen(text)
        pad = _BOX_W - w
        # При правильном расчёте pad = 66 - 75 = -9 (строка длиннее, нужна обрезка)
        self.assertEqual(pad, -9)
        # При баге (w=74) pad был бы -8 — обрезка на 1 символ меньше
        self.assertNotEqual(pad, -8, "pad не должен быть -8 (старый баг с ⚠=1)")


class TestModulesImportWlen(unittest.TestCase):
    """Все 19 модулей должны импортировать _wlen из text_width."""

    MODULES = [
        "chimera.modules.wdtt",
        "chimera.modules.mtproto",
        "chimera.modules.vkturn_menu",
        "chimera.modules.webdav_tunnel",
        "chimera.modules.telemt_panel",
        "chimera.modules.fptn",
        "chimera.modules.mtproto_stats",
        "chimera.modules.turnable",
        "chimera.modules.mieru_stats",
        "chimera.modules.mieru",
        "chimera.modules.telemt_syn_limiter",
        "chimera.modules.telemt_fallback",
        "chimera.modules.turntunnel_links",
        "chimera.modules.naiveproxy",
        "chimera.modules.naiveproxy_stats",
        "chimera.modules.turntunnel",
        "chimera.modules.telemt_mss_selector",
        "chimera.modules.telemt_ios_fix",
        "chimera.modules.slipgate",
    ]

    def setUp(self):
        """Загружаем _core.py в sys.modules как fake module."""
        core_path = _PROJECT_ROOT / "chimera" / "_core.py"
        src = core_path.read_text()
        g = {}
        from unittest.mock import patch
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

    def test_all_modules_have_wlen(self):
        """Каждый из 19 модулей должен иметь _wlen (через импорт из text_width)."""
        import importlib
        for modname in self.MODULES:
            with self.subTest(module=modname):
                mod = importlib.import_module(modname)
                self.assertTrue(hasattr(mod, '_wlen'),
                                f"{modname} должен иметь _wlen")
                self.assertTrue(callable(mod._wlen),
                                f"{modname}._wlen должен быть callable")

    def test_all_modules_use_centralized_wlen(self):
        """Все модули используют ту же функцию wlen из text_width (не копию)."""
        import importlib
        for modname in self.MODULES:
            with self.subTest(module=modname):
                mod = importlib.import_module(modname)
                # _wlen в модуле должен быть тем же объектом что и wlen из text_width
                self.assertIs(mod._wlen, wlen,
                              f"{modname}._wlen должен быть тем же объектом что и text_width.wlen")

    def test_all_modules_wlen_correct_for_warning_sign(self):
        """В каждом модуле _wlen('⚠') должен возвращать 2 (не 1)."""
        import importlib
        for modname in self.MODULES:
            with self.subTest(module=modname):
                mod = importlib.import_module(modname)
                self.assertEqual(mod._wlen("⚠"), 2,
                                 f"{modname}._wlen('⚠') должен вернуть 2, не 1")


if __name__ == "__main__":
    unittest.main(verbosity=2)

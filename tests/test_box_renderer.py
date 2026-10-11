#!/usr/bin/env python3
"""
tests/test_box_renderer.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/box_renderer.py.

Модуль автономен (не зависит от _core). Тестируем:
  1. _detect_colors — TTY/non-TTY/light
  2. _get_box_width — clamped [64, 100], fallback на COLUMNS/PTY
  3. _plain — strip ANSI
  4. _wcslen — подсчёт видимой ширины (emoji, CJK, флаги, ANSI)
  5. _box_line_* / _box_row / _box_top / _box_sep / _box_bottom — рендер в stdout
"""
from __future__ import annotations

import io
import os
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


class TestDetectColors(unittest.TestCase):
    """_detect_colors."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_empty_when_not_tty(self):
        from chimera.modules import box_renderer
        with patch("sys.stdout") as mock_stdout, \
             patch.dict(os.environ, {}, clear=True):
            mock_stdout.isatty.return_value = False
            c = box_renderer._detect_colors()
            for k in ("RED", "GREEN", "NC"):
                self.assertEqual(c[k], "")

    def test_returns_ansi_when_tty(self):
        from chimera.modules import box_renderer
        with patch("sys.stdout") as mock_stdout, \
             patch.dict(os.environ, {"VLESS_THEME": ""}, clear=True):
            mock_stdout.isatty.return_value = True
            c = box_renderer._detect_colors()
            self.assertTrue(c["RED"].startswith("\033["))
            self.assertTrue(c["NC"].startswith("\033["))

    def test_light_theme_when_env_set(self):
        from chimera.modules import box_renderer
        with patch("sys.stdout") as mock_stdout, \
             patch.dict(os.environ, {"VLESS_THEME": "light"}, clear=True):
            mock_stdout.isatty.return_value = True
            c = box_renderer._detect_colors()
            # в light-теме YELLOW = '\033[0;33m' (не bold), в dark = '\033[1;33m'
            self.assertEqual(c["YELLOW"], '\033[0;33m')


class TestGetBoxWidth(unittest.TestCase):
    """_get_box_width — динамическая ширина рамки."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_clamped_to_minimum_64(self):
        """Узкий терминал → минимум 64."""
        from chimera.modules import box_renderer
        with patch.dict(os.environ, {"COLUMNS": "40"}, clear=True), \
             patch("os.get_terminal_size", side_effect=OSError):
            w = box_renderer._get_box_width()
            self.assertEqual(w, 64)

    def test_clamped_to_maximum_100(self):
        """Широкий терминал → максимум 100 (cols - 2)."""
        from chimera.modules import box_renderer
        with patch.dict(os.environ, {"COLUMNS": "300"}, clear=True), \
             patch("os.get_terminal_size",
                   return_value=os.terminal_size((300, 80))):
            w = box_renderer._get_box_width()
            self.assertEqual(w, 100)

    def test_fallback_80_when_columns_not_set(self):
        from chimera.modules import box_renderer
        with patch.dict(os.environ, {}, clear=True), \
             patch("os.get_terminal_size", side_effect=OSError):
            w = box_renderer._get_box_width()
            # cols=80 → 80-2=78, но минимум 64 → 78
            self.assertEqual(w, 78)

    def test_uses_columns_env_when_numeric(self):
        from chimera.modules import box_renderer
        with patch.dict(os.environ, {"COLUMNS": "120"}, clear=True), \
             patch("os.get_terminal_size", side_effect=OSError):
            w = box_renderer._get_box_width()
            self.assertEqual(w, 100)  # min(120-2, 100) = 100

    def test_falls_back_when_columns_not_numeric(self):
        from chimera.modules import box_renderer
        with patch.dict(os.environ, {"COLUMNS": "auto"}, clear=True), \
             patch("os.get_terminal_size", side_effect=OSError):
            w = box_renderer._get_box_width()
            self.assertGreaterEqual(w, 64)


class TestPlain(unittest.TestCase):
    """_plain — strip ANSI escape codes."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_plain_string_unchanged(self):
        from chimera.modules.box_renderer import _plain
        self.assertEqual(_plain("hello"), "hello")

    def test_strips_simple_color(self):
        from chimera.modules.box_renderer import _plain
        self.assertEqual(_plain("\033[1;31mhello\033[0m"), "hello")

    def test_strips_multiple_codes(self):
        from chimera.modules.box_renderer import _plain
        self.assertEqual(_plain("\033[1m\033[31mhi\033[0m\033[0m"), "hi")

    def test_empty_string(self):
        from chimera.modules.box_renderer import _plain
        self.assertEqual(_plain(""), "")

    def test_preserves_non_ansi_escape_chars(self):
        """Символы вне ANSI — не трогаются."""
        from chimera.modules.box_renderer import _plain
        self.assertEqual(_plain("привет мир"), "привет мир")


class TestWcslen(unittest.TestCase):
    """_wcslen — подсчёт видимой ширины."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_ascii_one_per_char(self):
        from chimera.modules.box_renderer import _wcslen
        self.assertEqual(_wcslen("hello"), 5)

    def test_empty_string(self):
        from chimera.modules.box_renderer import _wcslen
        self.assertEqual(_wcslen(""), 0)

    def test_ansi_codes_zero_width(self):
        from chimera.modules.box_renderer import _wcslen
        self.assertEqual(_wcslen("\033[1;31mhi\033[0m"), 2)

    def test_cjk_two_columns(self):
        """CJK символы — 2 колонки каждый."""
        from chimera.modules.box_renderer import _wcslen
        self.assertEqual(_wcslen("中文"), 4)

    def test_cyrillic_one_per_char(self):
        """Кириллица — 1 колонка (eaw='N', не emoji)."""
        from chimera.modules.box_renderer import _wcslen
        self.assertEqual(_wcslen("привет"), 6)

    def test_box_drawing_one_column(self):
        from chimera.modules.box_renderer import _wcslen
        self.assertEqual(_wcslen("─│┌┐└┘"), 6)

    def test_block_elements_one_column(self):
        from chimera.modules.box_renderer import _wcslen
        self.assertEqual(_wcslen("█░▓▒"), 4)

    def test_emoji_outside_bmp_two_columns(self):
        from chimera.modules.box_renderer import _wcslen
        self.assertEqual(_wcslen("🚀"), 2)

    def test_force_width2_emoji(self):
        """❌ (U+274C) — явно 2 колонки."""
        from chimera.modules.box_renderer import _wcslen
        self.assertEqual(_wcslen("❌"), 2)

    def test_vs16_zero_width(self):
        """VS16 (U+FE0F) — нулевая ширина."""
        from chimera.modules.box_renderer import _wcslen
        self.assertEqual(_wcslen("⚡\ufe0f"), 2)  # ⚡ U+26A1 eaw='W' = 2, VS16 = 0

    def test_zwj_zero_width(self):
        """ZWJ (U+200D) — нулевая ширина."""
        from chimera.modules.box_renderer import _wcslen
        # 🇷🇺 — региональный индикатор пара = 2 колонки
        self.assertEqual(_wcslen("🇷🇺"), 2)

    def test_combining_mark_zero_width(self):
        """Combining mark (Mn) — нулевая ширина."""
        from chimera.modules.box_renderer import _wcslen
        # 'a' + combining acute = 1 колонка
        self.assertEqual(_wcslen("a\u0301"), 1)

    def test_mixed_string(self):
        from chimera.modules.box_renderer import _wcslen
        # "hi ❤" = 2 + 1 + 2 = 5 (пробел=1, ❤ = 2)
        self.assertEqual(_wcslen("hi ❤"), 5)


class TestBoxLineRender(unittest.TestCase):
    """_box_line_top / _box_line_sep / _box_line_bot."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _capture(self, fn):
        from chimera.modules import box_renderer
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            fn()
        return buf.getvalue()

    def test_top_has_corners(self):
        from chimera.modules import box_renderer
        # фиксируем ширину
        with patch.object(box_renderer, "_BOX_W", 64):
            out = self._capture(box_renderer._box_line_top)
        self.assertIn("╔", out)
        self.assertIn("╗", out)

    def test_sep_has_corners(self):
        from chimera.modules import box_renderer
        with patch.object(box_renderer, "_BOX_W", 64):
            out = self._capture(box_renderer._box_line_sep)
        self.assertIn("╠", out)
        self.assertIn("║", out)

    def test_bot_has_corners(self):
        from chimera.modules import box_renderer
        with patch.object(box_renderer, "_BOX_W", 64):
            out = self._capture(box_renderer._box_line_bot)
        self.assertIn("╚", out)
        self.assertIn("╝", out)


class TestBoxRow(unittest.TestCase):
    """_box_row — основная строка в рамке."""

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import box_renderer
        self._box_renderer = box_renderer
        self._patch_w = patch.object(box_renderer, "_BOX_W", 64)
        self._patch_w.start()

    def tearDown(self):
        self._patch_w.stop()

    def _capture(self, text):
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            self._box_renderer._box_row(text)
        return buf.getvalue()

    def test_empty_row_full_padding(self):
        out = self._capture("")
        # должна быть строка с 64 пробелами между ║ ║
        self.assertIn("║", out)
        self.assertIn(" " * 64, out)

    def test_short_row_padded(self):
        out = self._capture("hi")
        # 64 - 2 = 62 пробела после 'hi'
        self.assertIn("hi" + " " * 62, out)

    def test_exact_fit(self):
        """Строка ровно 64 символа — без паддинга."""
        out = self._capture("A" * 64)
        # 'A' * 64 + 0 пробелов
        self.assertIn("║" + "A" * 64 + "║", out)

    def test_long_row_wraps(self):
        """Длинная строка переносится — вывод содержит несколько строк."""
        out = self._capture("word " * 30)  # 150 chars
        # Должно быть несколько строк вывода (хотя бы 2)
        # Каждая строка содержит ║
        self.assertGreater(out.count("║"), 2)  # как минимум 2 строки = 4 ║

    def test_preserves_ansi_color(self):
        """Цвет в начале не должен ломать отступ."""
        from chimera.modules.box_renderer import RED, NC
        out = self._capture(f"{RED}hi{NC}")
        # результат должен содержать 'hi' и не содержать ANSI внутри паддинга
        self.assertIn("hi", out)
        self.assertIn(RED, out)


class TestBoxTop(unittest.TestCase):
    """_box_top — верхняя граница с опциональным заголовком."""

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import box_renderer
        self._box_renderer = box_renderer
        self._patch_w = patch.object(box_renderer, "_BOX_W", 64)
        self._patch_w.start()

    def tearDown(self):
        self._patch_w.stop()

    def _capture(self, title=""):
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            self._box_renderer._box_top(title)
        return buf.getvalue()

    def test_top_without_title(self):
        out = self._capture("")
        self.assertIn("╔", out)
        self.assertIn("╗", out)

    def test_top_with_title(self):
        out = self._capture("MENU")
        # заголовок должен присутствовать в выводе
        self.assertIn("MENU", out)
        self.assertIn("╔", out)


class TestBoxItem(unittest.TestCase):
    """_box_item / _box_item_exit / _box_back."""

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import box_renderer
        self._box_renderer = box_renderer
        self._patch_w = patch.object(box_renderer, "_BOX_W", 64)
        self._patch_w.start()

    def tearDown(self):
        self._patch_w.stop()

    def _capture(self, fn, *args, **kwargs):
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            fn(*args, **kwargs)
        return buf.getvalue()

    def test_box_item_shows_key_and_label(self):
        out = self._capture(self._box_renderer._box_item, "1", "Option One")
        self.assertIn("1", out)
        self.assertIn("Option One", out)

    def test_box_item_exit_shows_key_and_label(self):
        out = self._capture(self._box_renderer._box_item_exit, "Q", "Quit")
        self.assertIn("Q", out)
        self.assertIn("Quit", out)

    def test_box_back_has_arrow(self):
        out = self._capture(self._box_renderer._box_back)
        self.assertIn("←", out) or self.assertIn("Назад", out)


class TestBoxWrapMsg(unittest.TestCase):
    """_box_wrap_msg — перенос длинного сообщения."""

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import box_renderer
        self._box_renderer = box_renderer
        self._patch_w = patch.object(box_renderer, "_BOX_W", 64)
        self._patch_w.start()

    def tearDown(self):
        self._patch_w.stop()

    def _capture(self, *args, **kwargs):
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            self._box_renderer._box_wrap_msg(*args, **kwargs)
        return buf.getvalue()

    def test_short_message_one_line(self):
        from chimera.modules.box_renderer import GREEN, NC
        out = self._capture(f"{GREEN}OK{NC}", 2, "all good")
        self.assertIn("OK", out)
        self.assertIn("all good", out)

    def test_long_message_wraps(self):
        from chimera.modules.box_renderer import GREEN, NC
        long_msg = "word " * 30
        out = self._capture(f"{GREEN}OK{NC}", 2, long_msg)
        # должно быть несколько строк
        self.assertGreater(out.count("║"), 2)

    def test_empty_message_only_prefix(self):
        from chimera.modules.box_renderer import GREEN, NC
        out = self._capture(f"{GREEN}OK{NC}", 2, "")
        self.assertIn("OK", out)


# ══════════════════════════════════════════════════════════════════════════════
#  _box_narrow — замена ambiguous-ширины (—, →, ·, «», ≈, ×, …) на ASCII.
#  Живой кейс окт.2026 №7: часть терминалов рендерит эти символы в 2
#  клетки при _wcslen=1 → правая граница рамки [T]/HM «лесенкой».
# ══════════════════════════════════════════════════════════════════════════════
class TestBoxNarrow(unittest.TestCase):
    """_box_narrow — узкие ASCII-заместители для ambiguous-символов."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_dashes_to_hyphen(self):
        from chimera.modules.box_renderer import _box_narrow
        self.assertEqual(_box_narrow("ноды — уведомление"), "ноды - уведомление")
        self.assertEqual(_box_narrow("1–2"), "1-2")

    def test_arrows_to_ascii(self):
        from chimera.modules.box_renderer import _box_narrow
        self.assertEqual(_box_narrow("хоп→нода"), "хоп->нода")
        self.assertEqual(_box_narrow("← Назад"), "<- Назад")

    def test_middot_guillemets_math(self):
        from chimera.modules.box_renderer import _box_narrow
        self.assertEqual(_box_narrow("165 мс · RTT"), "165 мс | RTT")
        self.assertEqual(_box_narrow("«сеть есть»"), '"сеть есть"')
        self.assertEqual(_box_narrow("≈ 3-4×RTT"), "~ 3-4xRTT")
        self.assertEqual(_box_narrow("нода…"), "нода...")

    def test_noop_for_clean_strings(self):
        from chimera.modules.box_renderer import _box_narrow
        # кириллица/ASCII/флаги — 1-клеточные и так, не трогаем
        s = "  [1] total-shadows.ru:443  \U0001F1F3\U0001F1F1  ->  199 мс  |  RTT 43 мс"
        self.assertEqual(_box_narrow(s), s)

    def test_ansi_untouched(self):
        from chimera.modules.box_renderer import _box_narrow, RED, NC
        s = f"{RED}недоступна (хоп→нода){NC}"
        out = _box_narrow(s)
        self.assertIn(RED, out)
        self.assertIn(NC, out)
        self.assertIn("хоп->нода", out)

    def test_result_width_matches_wcslen(self):
        """После замены _wcslen(строки) == len(plain) по клеткам: паддинг
        _box_row совпадает с реальной шириной в любом терминале."""
        from chimera.modules.box_renderer import _box_narrow, _wcslen, _plain
        s = _box_narrow("full-path - полный зонд · RTT ≈ 3-4×RTT → норма")
        plain = _plain(s)
        self.assertEqual(_wcslen(plain), len(plain))


class TestPingBoxUniformRender(unittest.TestCase):
    """Регрессия «лесенка правой границы» (кейс №7): рендер [T]-бокса
    «Пинг Exit Node» — все строки ОДНОЙ видимой ширины (_BOX_W+2),
    без ambiguous-символов и без авто-переноса строк."""

    def setUp(self):
        _setup_core_in_sysmodules()
        from chimera.modules import box_renderer
        self._br = box_renderer
        self._patch_w = patch.object(box_renderer, "_BOX_W", 78)
        self._patch_w.start()

    def tearDown(self):
        self._patch_w.stop()

    def _render(self, lines):
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            self._br._box_top("Пинг Exit Node")
            for ln in lines:
                self._br._box_row(self._br._box_narrow(ln))
            self._br._box_bottom()
        return [l for l in buf.getvalue().splitlines() if l.strip()]

    def test_ping_box_uniform(self):
        # видимый текст [T]-строк (ANSI в тестах пустой — non-tty импорт)
        lines = [
            "  full-path - полный зонд: TCP + REALITY-хендшейк +",
            "  DNS на exit + HTTP-проба через туннель (via-ноды -",
            "  через хоп-цепочку); RTT - прямой сетевой ICMP до",
            "  хоста ноды. Вердикт (UP/DOWN) решает full-path;",
            "  RTT - эталон чистой сети: full-path ~ 3-4 x RTT -",
            "  норма, DOWN при живом RTT = \"сеть есть, туннеля нет\".",
            "  Зонды не палит нас анти-DPI, ноды без ключей - TCP.",
            "  [1] total-shadows.ru:443  ->  измеряю...",
            "  [1] total-shadows.ru:443  \U0001F1F3\U0001F1F1  ->  199 мс (full-path)  |  RTT 43 мс",
            "  [2] totalshadows.online:443  \U0001F1E9\U0001F1EA  ->  163 мс (full-path)  |  RTT 43 мс",
            "  [3] fi.total-shadows.online:443  \U0001F1EB\U0001F1EE  ->  115 мс (full-path)  |  RTT 29 мс",
            "  [5] ee.total-shadows.online:443  \U0001F1EA\U0001F1EA  ->  175 мс (via hop-fi)  |  RTT 26 мс",
        ]
        out = self._render(lines)
        # _box_top: рамка + заголовок + сепаратор (3) + 12 строк + низ (1) = 16
        self.assertEqual(len(out), 16,
                         f"строки перенеслись/слились: {len(out)} != 16")
        widths = {self._br._wcslen(self._br._plain(l)) for l in out}
        self.assertEqual(widths, {80},
                         f"правая граница гуляет: ширины {sorted(widths)}")
        # ни одной ambiguous-строки: замена не оставила «широких» символов
        for l in out:
            for ch in self._br._BOX_NARROW_MAP:
                self.assertNotIn(ch, l, f"ambiguous {ch!r} в строке бокса")
        # строки с результатом — по ОДНОЙ строке на ноду (без переноса)
        self.assertEqual(
            sum(1 for l in out if "мс (full-path)" in l or "мс (via" in l), 4)


class TestBoxNarrowWrappersInPlace(unittest.TestCase):
    """Source-гарант: [T]-блок chain_nodes и таблица/[C] HM обязаны
    прогонять строки через _box_narrow, а их СТРОКОВЫЕ литералы —
    без ambiguous-символов (кейс №7 — лесенка рамки). Проверяем только
    литералы: комментарии имеют право объяснять проблему «— → ·»."""

    _DANGER = ("—", "–", "→", "←", "·", "•", "«", "»", "≈", "×", "…")

    def _string_literals(self, src: str) -> str:
        """Только ОДНОстрочные литералы (UI-строки). Тройные кавычки —
        докстринги, им можно объяснять проблему «— → ·» — пропускаем."""
        import io as _io
        import tokenize as _tk
        parts = []
        try:
            for tok in _tk.generate_tokens(_io.StringIO(src).readline):
                if tok.type == _tk.STRING and not tok.string.startswith(('"""', "'''")):
                    parts.append(tok.string)
        except _tk.TokenizeError:
            pass
        return "\n".join(parts)

    def test_t_block_uses_narrow(self):
        src = (_PROJECT_ROOT / "chimera" / "modules" / "chain_nodes.py").read_text()
        block = src.split('elif ch == "t" and CHAIN_NODES:', 1)[1] \
                   .split('elif ch == "p" and CHAIN_NODES:', 1)[0]
        self.assertIn("_box_narrow", block,
                      "[T]-блок обязан оборачивать строки в _box_narrow")
        lits = self._string_literals(block)
        for danger in self._DANGER:
            self.assertNotIn(danger, lits,
                             f"ambiguous {danger!r} в литералах [T]-блока")

    def test_speed_test_note_narrow(self):
        """Пометка via-ноды «(via ... выключен - напрямую)» — в [T]-строке."""
        src = (_PROJECT_ROOT / "chimera" / "modules" / "chain_nodes.py").read_text()
        block = src.split("def _speed_test_node_latency", 1)[1] \
                   .split("def _speed_test_node_geo", 1)[0]
        lits = self._string_literals(block)
        for danger in self._DANGER:
            self.assertNotIn(danger, lits,
                             f"ambiguous {danger!r} в литералах _speed_test_node_latency")

    def test_hm_menu_literals_narrow(self):
        src = (_PROJECT_ROOT / "chimera" / "modules" / "node_health_monitor.py").read_text()
        menu = src.split("def do_health_monitor_menu", 1)[1]
        lits = self._string_literals(menu)
        for danger in self._DANGER:
            self.assertNotIn(danger, lits,
                             f"ambiguous {danger!r} в литералах меню HM")
        self.assertIn("_box_narrow", menu)

    def test_chain_relay_reasons_narrow(self):
        """reason-строки зондов попадают в [T]-строку «недоступна (...)» —
        обязаны быть узкими (fmt_icmp_rtt возвращает «-»)."""
        import chimera.modules.chain_relay as cr
        from chimera.modules.box_renderer import _box_narrow
        self.assertEqual(_box_narrow(cr.fmt_icmp_rtt(None)), "-")
        # словарь причин диагностики ног (хоп->нода) — узкие
        for reason in ("хоп не отвечает", "хоп->нода недостижима",
                       "хоп->нода не доставляет", "хоп и нода не отвечают"):
            self.assertEqual(_box_narrow(reason), reason,
                             f"reason {reason!r} несёт ambiguous-символ")


if __name__ == "__main__":
    unittest.main(verbosity=2)

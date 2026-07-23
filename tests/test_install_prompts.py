#!/usr/bin/env python3
"""
tests/test_install_prompts.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/install_prompts.py — _prompt_h1_h4_unique().

v5.0.8: проверка коллизий H1-H4 в ручном вводе обфускации AWG (пункт "3"
в prompt_awg_exit_mode). Раньше каждое H вводилось независимо, дубликат
между ними никак не ловился — хотя весь смысл фичи — уникальность H1-H4
(DPI-отпечаток).

_prompt_h1_h4_unique() выделена в отдельную функцию для тестопригодности.
Тесты мокают builtins.input через side_effect (как в test_xray_install.py,
test_ios_shadow_client.py) и вызывают helper напрямую.

Кейсы:
  1. Пользователь вводит H1=H2=100 (дубликат) первой попыткой, второй
     попыткой — все четыре уникальные → функция принимает вторую попытку
  2. 5 попыток подряд с дубликатами → срабатывает fallback на _rec
  3. Первая попытка сразу уникальна → без лишних перезапросов (mock
     input вызывается ровно 4 раза для H1-H4, не 8+)
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core_in_sysmodules():
    """Создаёт фейковый chimera._core (как в test_awg_presets.py)."""
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


def _make_ask_int():
    """Создаёт _ask_int callback, который использует builtins.input.

    Возвращает функцию с сигнатурой (prompt, default, lo, hi) -> int.
    При пустом вводе (Enter) возвращает default, иначе пытается распарсить
    int и проверить диапазон — точно как в prompt_awg_exit_mode().
    """
    def _ask_int(prompt: str, default: int, lo: int, hi: int) -> int:
        try:
            raw2 = input(f"  {prompt} [{default}]: ").strip()
            v = int(raw2)
            if lo <= v <= hi:
                return v
        except (ValueError, KeyboardInterrupt):
            pass
        return default
    return _ask_int


class TestPromptH1H4Unique(unittest.TestCase):
    """_prompt_h1_h4_unique — проверка коллизий H1-H4 (v5.0.8).

    3 кейса:
      1. Дубликат первой попыткой → уникальные второй попыткой → успех
      2. 5 попыток с дубликатами → fallback на _rec
      3. Сразу уникальны → без перезапросов (4 вызова input)
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        # _rec с уникальными рекомендованными H1-H4
        self._rec = {"h1": 1001, "h2": 2002, "h3": 3003, "h4": 4004}
        self._warn = MagicMock()
        self._info = MagicMock()

    def test_duplicate_first_attempt_unique_second(self):
        """Кейс 1: H1=H2=100 первой попыткой (дубликат), второй попыткой
        все четыре уникальные → функция принимает вторую попытку.

        input side_effect:
          Попытка 1: "100", "100", "" (default 3003), "" (default 4004)
          → H1=100, H2=100 — дубликат, перезапрос
          Попытка 2: "100", "200", "300", "400" — все уникальны
        """
        from chimera.modules.install_prompts import _prompt_h1_h4_unique
        _ask_int = _make_ask_int()

        # 8 ответов: 4 для первой попытки + 4 для второй
        inputs = iter([
            "100", "100", "", "",       # попытка 1: H1=100, H2=100 (dup), H3=3003, H4=4004
            "100", "200", "300", "400",  # попытка 2: H1=100, H2=200, H3=300, H4=400 — уникальны
        ])

        with patch("builtins.input", side_effect=lambda *a, **kw: next(inputs)):
            h1, h2, h3, h4 = _prompt_h1_h4_unique(
                self._rec, _ask_int, self._warn, self._info
            )

        # Вторая попытка принята — значения уникальны
        self.assertEqual(h1, 100)
        self.assertEqual(h2, 200)
        self.assertEqual(h3, 300)
        self.assertEqual(h4, 400)
        # Все 4 уникальны
        self.assertEqual(len({h1, h2, h3, h4}), 4,
                         f"H1-H4 должны быть уникальны: {h1},{h2},{h3},{h4}")
        # warn был вызван (предупреждение о дубликате)
        self._warn.assert_called()
        # info был вызван (пояснение про DPI)
        self._info.assert_called()

    def test_five_attempts_with_duplicates_fallback_to_rec(self):
        """Кейс 2: 5 попыток подряд с дубликатами → fallback на _rec.

        input side_effect: 5 раз по 4 ответа, каждый раз H1=H2=100 (dup).
        После 5 попыток функция берёт _rec значения (уникальные) и не
        зависает/не падает.
        """
        from chimera.modules.install_prompts import _prompt_h1_h4_unique
        _ask_int = _make_ask_int()

        # 6 раз по 4 ответа = 24: первая попытка (4) + 5 повторных (5×4=20)
        # После 5 повторных попыток _attempts=6 > 5 → fallback, break
        inputs = iter(["100", "100", "", ""] * 6)  # 24 ответа

        with patch("builtins.input", side_effect=lambda *a, **kw: next(inputs)):
            h1, h2, h3, h4 = _prompt_h1_h4_unique(
                self._rec, _ask_int, self._warn, self._info
            )

        # Fallback на _rec — значения из рекомендованных
        self.assertEqual(h1, self._rec["h1"])
        self.assertEqual(h2, self._rec["h2"])
        self.assertEqual(h3, self._rec["h3"])
        self.assertEqual(h4, self._rec["h4"])
        # Все 4 уникальны (т.к. _rec гарантированно уникальны)
        self.assertEqual(len({h1, h2, h3, h4}), 4)
        # warn был вызван (и про дубликаты, и про fallback)
        self._warn.assert_called()
        # Не упали, не зависли

    def test_first_attempt_unique_no_retry(self):
        """Кейс 3: первая попытка сразу уникальна → без перезапросов.

        input должен быть вызван ровно 4 раза (по одному на H1-H4),
        не 8+. Проверяем через подсчёт вызовов mock input.
        """
        from chimera.modules.install_prompts import _prompt_h1_h4_unique
        _ask_int = _make_ask_int()

        # 4 ответа — все уникальные
        inputs = iter(["100", "200", "300", "400"])
        call_count = [0]

        def _input_side_effect(*a, **kw):
            call_count[0] += 1
            return next(inputs)

        with patch("builtins.input", side_effect=_input_side_effect):
            h1, h2, h3, h4 = _prompt_h1_h4_unique(
                self._rec, _ask_int, self._warn, self._info
            )

        # Значения из первой попытки
        self.assertEqual(h1, 100)
        self.assertEqual(h2, 200)
        self.assertEqual(h3, 300)
        self.assertEqual(h4, 400)
        # Ровно 4 вызова input — не было перезапроса
        self.assertEqual(call_count[0], 4,
                         f"input должен быть вызван 4 раза (без перезапроса), "
                         f"фактически: {call_count[0]}")
        # warn НЕ вызывался — не было дубликатов
        self._warn.assert_not_called()
        # info НЕ вызывался
        self._info.assert_not_called()

    def test_three_duplicates_fourth_unique(self):
        """Доп. кейс: 3 попытки с дубликатами, 4-я уникальна → успех.

        Проверяет что цикл корректно продолжает работу после нескольких
        неудачных попыток (не только после первой).
        """
        from chimera.modules.install_prompts import _prompt_h1_h4_unique
        _ask_int = _make_ask_int()

        # 4 попытки: 3 с dup + 4-я уникальная
        inputs = iter([
            "100", "100", "", "",       # попытка 1: dup
            "200", "200", "", "",       # попытка 2: dup
            "300", "300", "", "",       # попытка 3: dup
            "100", "200", "300", "400",  # попытка 4: уникальны
        ])

        with patch("builtins.input", side_effect=lambda *a, **kw: next(inputs)):
            h1, h2, h3, h4 = _prompt_h1_h4_unique(
                self._rec, _ask_int, self._warn, self._info
            )

        self.assertEqual(h1, 100)
        self.assertEqual(h2, 200)
        self.assertEqual(h3, 300)
        self.assertEqual(h4, 400)
        self.assertEqual(len({h1, h2, h3, h4}), 4)
        # warn вызывался 3 раза (по разу на каждую неудачную попытку)
        self.assertGreaterEqual(self._warn.call_count, 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)

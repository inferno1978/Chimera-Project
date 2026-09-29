#!/usr/bin/env python3
"""
tests/test_install_prompts.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/install_prompts.py — _prompt_h1_h4_unique().

 проверка коллизий H1-H4 в ручном вводе обфускации AWG (пункт "3"
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
    """_prompt_h1_h4_unique — проверка коллизий H1-H4 .

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


class TestPromptProtocolModeRenders(unittest.TestCase):
    """Регрессия живого теста 29.09.2026 (DE-стенд): prompt_protocol_mode
    падал с NameError('YELLOW') при рендере пункта [3] xhttp_reality —
    YELLOW не был импортирован из core. Тест рендерит бокс протокола для
    ВСЕХ трёх вариантов, чтобы ловить undefined-имена на этапе CI.
    """

    def _run_choice(self, choice: str) -> None:
        _setup_core_in_sysmodules()
        import chimera.modules.install_prompts as ip
        import chimera._core as core_mod
        with patch("builtins.input", side_effect=[choice, "2"]), \
             patch.object(core_mod, "_prompt_xhttp_options") as _mxhr, \
             patch.object(core_mod, "success"), \
             patch.object(core_mod, "warn"), \
             patch.object(ip, "_check_vless_server_port",
                          return_value=(True, [], [], None)):
            ip.prompt_protocol_mode()
        return core_mod

    def test_choice1_reality_renders(self):
        core_mod = self._run_choice("1")
        self.assertEqual(core_mod.PROTOCOL_MODE, "reality")

    def test_choice2_xhttp_renders(self):
        core_mod = self._run_choice("2")
        self.assertEqual(core_mod.PROTOCOL_MODE, "xhttp")

    def test_choice3_xhttp_reality_renders_no_nameerror(self):
        """Главный регрессионный кейс: [3] xhttp_reality (баг YELLOW)."""
        core_mod = self._run_choice("3")
        self.assertEqual(core_mod.PROTOCOL_MODE, "xhttp_reality")
        self.assertEqual(core_mod.SERVER_PORT, 8443)


class TestServerPortVerdict(unittest.TestCase):
    """_server_port_verdict — классификация конфликтов порта VLESS.

    Ключевой кейс: переустановка поверх живого стека — собственный
    слушатель xray на порту НЕ блокирующий (иначе переустановка на тот
    же порт была бы невозможна)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_xray_listener_not_blocking_on_reinstall(self):
        from chimera.modules.install_prompts import _server_port_verdict
        conflicts = [{
            "type": "system",
            "service": "xray (pid=123)",
            "detail": "Порт уже слушается процессом: xray (pid=123)",
        }]
        has_blocking, blocking, notes = _server_port_verdict(conflicts, True)
        self.assertFalse(has_blocking)
        self.assertEqual(blocking, [])
        self.assertEqual(len(notes), 1)
        self.assertIn("не конфликт", notes[0])

    def test_xray_listener_blocking_on_fresh_install(self):
        from chimera.modules.install_prompts import _server_port_verdict
        conflicts = [{
            "type": "system",
            "service": "xray (pid=123)",
            "detail": "Порт уже слушается процессом: xray (pid=123)",
        }]
        has_blocking, blocking, notes = _server_port_verdict(conflicts, False)
        self.assertTrue(has_blocking)
        self.assertEqual(len(blocking), 1)

    def test_foreign_listener_always_blocking(self):
        from chimera.modules.install_prompts import _server_port_verdict
        conflicts = [{
            "type": "system",
            "service": "nginx (pid=5)",
            "detail": "Порт уже слушается процессом: nginx (pid=5)",
        }]
        # Даже при переустановке чужой nginx — блокирующий конфликт.
        has_blocking, _, _ = _server_port_verdict(conflicts, True)
        self.assertTrue(has_blocking)

    def test_registry_conflict_blocking(self):
        from chimera.modules.install_prompts import _server_port_verdict
        conflicts = [{
            "type": "registry",
            "service": "web_panel",
            "detail": "Зарегистрирован за сервисом 'web_panel'",
        }]
        has_blocking, blocking, _ = _server_port_verdict(conflicts, True)
        self.assertTrue(has_blocking)
        self.assertIn("web_panel", blocking[0])

    def test_no_conflicts(self):
        from chimera.modules.install_prompts import _server_port_verdict
        has_blocking, blocking, notes = _server_port_verdict([], True)
        self.assertFalse(has_blocking)
        self.assertEqual((blocking, notes), ([], []))


class TestSuggestVlessAltPort(unittest.TestCase):
    """_suggest_vless_alt_port — первая свободная альтернатива."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_first_free_candidate(self):
        import chimera.modules.install_prompts as ip
        occupied = {443, 8443}
        def fake_is_free(port, proto="tcp", exclude_service=None):
            return (port not in occupied, [])
        with patch.object(ip, "_VLESS_ALT_PORT_CANDIDATES",
                          [443, 8443, 2053, 2083]):
            # Мокаем port_registry.port_is_free по месту импорта.
            import chimera.modules.port_registry as pr
            with patch.object(pr, "port_is_free", side_effect=fake_is_free):
                self.assertEqual(ip._suggest_vless_alt_port(8443), 2053)

    def test_none_if_all_occupied(self):
        import chimera.modules.install_prompts as ip
        with patch.object(ip, "_VLESS_ALT_PORT_CANDIDATES", [443, 8443]):
            import chimera.modules.port_registry as pr
            with patch.object(pr, "port_is_free",
                              side_effect=lambda p, *_a, **_k: (False, [])):
                self.assertIsNone(ip._suggest_vless_alt_port(443))


class TestPromptXrayListenPort(unittest.TestCase):
    """_prompt_xray_listen_port — интерактивный выбор порта с port_registry.

    Сценарии (мок _check_vless_server_port):
      - свободный порт принимается сразу
      - конфликт + альтернатива → «1» переключает на альтернативу
      - конфликт + «всё равно» → остаёмся на выбранном порту
      - конфликт + перевыбор → повторный выбор порта
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def _run(self, inputs, check_fn):
        import chimera.modules.install_prompts as ip
        import chimera._core as core_mod
        with patch("builtins.input", side_effect=inputs), \
             patch.object(ip, "_check_vless_server_port", side_effect=check_fn), \
             patch.object(core_mod, "success"), \
             patch.object(core_mod, "warn"):
            port = ip._prompt_xray_listen_port(core_mod)
        return port, core_mod

    def test_free_port_accepted(self):
        port, core_mod = self._run(
            ["2"], lambda p, reinstall: (True, [], [], None))
        self.assertEqual(port, 8443)
        self.assertEqual(core_mod.SERVER_PORT, 8443)
        self.assertEqual(core_mod.XHTTP_PORT, 8443)

    def test_conflict_alt_accepted(self):
        def check(port, reinstall):
            if port == 8443:
                return (False, ["Зарегистрирован за 'web_panel'"], [], 2053)
            return (True, [], [], None)
        # «2» выбираем 8443 → конфликт → «1» = альтернатива 2053
        port, core_mod = self._run(["2", "1"], check)
        self.assertEqual(port, 2053)
        self.assertEqual(core_mod.SERVER_PORT, 2053)

    def test_conflict_keep_anyway(self):
        def check(port, reinstall):
            if port == 8443:
                return (False, ["Порт уже слушается nginx"], [], 2053)
            return (True, [], [], None)
        # «2» → 8443; конфликт; «2» = всё равно использовать 8443
        port, _ = self._run(["2", "2"], check)
        self.assertEqual(port, 8443)

    def test_conflict_rechoose(self):
        def check(port, reinstall):
            if port == 8443:
                return (False, ["Занят"], [], 2053)
            return (True, [], [], None)
        # «2» → 8443; конфликт; «3» = выбрать другой; «1» → 443 (свободен)
        port, _ = self._run(["2", "3", "1"], check)
        self.assertEqual(port, 443)

    def test_manual_port_then_conflict_alt(self):
        def check(port, reinstall):
            if port == 9443:
                return (False, ["Зарегистрирован за 'telemt'"], [], 2087)
            return (True, [], [], None)
        # «3» ручной ввод → 9443 → конфликт → «1» = 2087
        port, _ = self._run(["3", "9443", "1"], check)
        self.assertEqual(port, 2087)


if __name__ == "__main__":
    unittest.main(verbosity=2)

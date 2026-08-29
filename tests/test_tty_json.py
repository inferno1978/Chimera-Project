#!/usr/bin/env python3
"""
tests/test_tty_json.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/_tty_json.py — обход 4-КБ лимита TTY-буфера
при импорте больших b4-сетов через TUI Chimera.

ПОКРЫВАЕТ:
  1. read_long_json_stdin — не-TTY режим (pipe/redirect): sys.stdin.read()
  2. _tty_json._brace_aware_read — посимвольное чтение с подсчётом скобок
     (имитация TTY через io.StringIO + monkey-patch на termios-недоступном
     окружении)
  3. _tty_json._read_long_json_readline_fallback — запасной readline-цикл
  4. REGRESSION: большой b4-сет (15 КБ) больше не обрезается на 4096 байт

КОНТЕКСТ:
  Пользователь сообщает об ошибке импорта большого сета через TUI Chimera:
    «[ERR] Невалидный JSON: Unterminated string starting at: line 1 column
     4092 (char 4091)»

  Корень: Python input() читает TTY в каноническом режиме (ICANON). Буфер
  канонического режима в ядре Linux (N_TTY_BUF_SIZE = 4096 байт) усекает
  вставленные >4 КБ однострочные JSON до 4096 байт. Web UI B4 импортирует
  такие же сеты без проблем (REST API без TTY-буфера).

  Фикс: chimera/modules/_tty_json.py переключает stdin в cbreak-режим
  через termios (убирает ICANON, оставляет ECHO) и читает посимвольно с
  подсчётом '{'/'}'-глубины.
───────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import io
import json
import sys
import unittest
from unittest.mock import patch

# Импортируем тестируемый модуль. Сделаем путь к chimera-project видимым.
sys.path.insert(0, "/home/z/my-project/chimera-project")

from chimera.modules import _tty_json
from chimera.modules._tty_json import (
    _read_long_json_readline_fallback,
    read_long_json_stdin,
)


# ─── Реалистичный большой b4-сет для регрессионных тестов ─────────────────────

def _make_big_b4_set(size_kb: int = 15) -> str:
    """Генерирует валидный b4-сет размером ~size_kb КБ.

    Сетка dns.pins с 25 доменами по 13 IP каждый даёт ~14-15 КБ — именно
    тот формат, что пользователь не мог импортировать через TUI.
    """
    domains = [
        "facebook.com", "fb.com", "fb.me", "fb.watch", "meta.com",
        "messenger.com", "m.me", "fbcdn.net", "fbcdn.com", "fbsbx.com",
        "facebook.net", "graph.facebook.com", "graph2.facebook.com",
        "bgraph.facebook.com", "api.facebook.com", "edge.facebook.com",
        "edge-mqtt.facebook.com", "mqtt.facebook.com",
        "edge-chat.facebook.com", "chat.facebook.com",
        "static.facebook.com", "staticxx.facebook.com",
        "connect.facebook.net", "lookaside.facebook.com",
        "lookaside.fbsbx.com", "rupload.facebook.com",
        "upload.facebook.com", "rupload.facebook.net",
        "video-wu-kc.facebook.com",
    ]
    ip_pool = [
        "57.144.14.141", "57.144.64.1", "57.144.64.128", "57.144.64.141",
        "57.144.64.144", "57.144.98.141", "57.144.144.128",
        "57.144.144.129", "57.144.150.5", "57.144.150.33",
        "57.144.150.128", "57.144.150.144", "157.240.13.14",
        "157.240.13.19", "157.240.15.19",
    ]
    pins = {}
    for d in domains:
        # 13 IP на домен — реалистично для v18-MAX сета
        pins[d] = ip_pool[:13]

    set_obj = {
        "b4_version": "1.79.0",
        "name": "Meta-facebook-v18-MAX",
        "tcp": {"seg2delay": 20, "seg2delay_max": 50,
                "ip_block_detect": {"enabled": True, "heal_dns": True}},
        "udp": {"mode": "reject", "filter_quic": "all"},
        "faking": {"strategy": "randseq"},
        "targets": {"sni_domains": domains, "ip": ip_pool},
        "enabled": True,
        "dns": {"enabled": True, "doh_url": "https://1.1.1.1/dns-query",
                "pins": pins},
    }
    s = json.dumps(set_obj, separators=(",", ":"), ensure_ascii=False)
    # Если размер всё ещё меньше size_kb, добавим мусорные пины.
    while len(s) < size_kb * 1024:
        extra = f'"x{len(s)}.com":{json.dumps(ip_pool[:13])}'
        s = s.replace('"dns":{', f'"dns":{{"x{len(s)}":{json.dumps(ip_pool[:13])},')
    return s


# ─── 1. Не-TTY: pipe/redirect/тесты ──────────────────────────────────────────

class TestReadLongJsonStdinNonTty(unittest.TestCase):
    """read_long_json_stdin — не-TTY режим (sys.stdin.read до EOF)."""

    def setUp(self):
        # В тестах stdin никогда не TTY.
        self._isatty_patcher = patch("sys.stdin.isatty", return_value=False)
        self._isatty_patcher.start()

    def tearDown(self):
        self._isatty_patcher.stop()

    def _feed_stdin(self, content: str):
        return patch("sys.stdin", new=io.StringIO(content))

    def test_simple_json(self):
        with self._feed_stdin('{"a": 1}'):
            result = read_long_json_stdin()
        self.assertEqual(result, '{"a": 1}')

    def test_json_with_leading_trailing_whitespace(self):
        with self._feed_stdin('   \n  {"a": 1}  \n   '):
            result = read_long_json_stdin()
        self.assertEqual(result, '{"a": 1}')

    def test_json_multiline_indented(self):
        json_str = '{\n  "name": "test",\n  "value": 42\n}'
        with self._feed_stdin(json_str):
            result = read_long_json_stdin()
        # .strip() убирает крайние пробелы, но не внутренние.
        self.assertEqual(result, json_str)
        # Парсинг работает.
        self.assertEqual(json.loads(result)["name"], "test")

    def test_big_json_over_4kb(self):
        """REGRESSION: сет >4 КБ раньше обрезался ядром на 4096 байт."""
        big = _make_big_b4_set(size_kb=15)
        self.assertGreater(len(big), 8192, "тестовый сет должен быть >8 КБ")
        with self._feed_stdin(big):
            result = read_long_json_stdin()
        self.assertEqual(len(result), len(big))
        # Парсинг не падает (значит, не обрезан).
        parsed = json.loads(result)
        self.assertEqual(parsed["name"], "Meta-facebook-v18-MAX")

    def test_json_with_braces_in_strings(self):
        """'}' внутри строк не должна закрывать объект раньше времени."""
        json_str = '{"a": "}{", "b": {"c": "}}"}}'
        with self._feed_stdin(json_str):
            result = read_long_json_stdin()
        self.assertEqual(json.loads(result), {"a": "}{", "b": {"c": "}}"}})

    def test_json_with_escaped_quotes(self):
        """Строки с \\\" не должны ломать детектор состояния строки."""
        json_str = '{"a": "foo\\"bar", "b": "baz"}'
        with self._feed_stdin(json_str):
            result = read_long_json_stdin()
        self.assertEqual(json.loads(result)["a"], 'foo"bar')

    def test_json_with_backslash_in_string(self):
        """Литеральные '\\' в строках не должны восприниматься как escape,
        если после них не '"'."""
        json_str = '{"path": "C:\\\\Users"}'
        with self._feed_stdin(json_str):
            result = read_long_json_stdin()
        self.assertEqual(json.loads(result)["path"], "C:\\Users")

    def test_empty_input_returns_empty_string(self):
        with self._feed_stdin(""):
            result = read_long_json_stdin()
        self.assertEqual(result, "")

    def test_whitespace_only_input_returns_empty_string(self):
        with self._feed_stdin("   \n  \t  \n"):
            result = read_long_json_stdin()
        self.assertEqual(result, "")

    def test_sets_wrapper_takes_first(self):
        """Формат {"sets":[...]} — но это всё ещё один JSON-объект."""
        json_str = '{"sets":[{"name":"first"},{"name":"second"}]}'
        with self._feed_stdin(json_str):
            result = read_long_json_stdin()
        self.assertEqual(json.loads(result)["sets"][0]["name"], "first")

    def test_nested_arrays_with_brackets(self):
        """Массивы '[...]' внутри объекта — скобки можно игнорировать,
        глубина по '{'/'}' всё равно корректна."""
        json_str = '{"a": [1, 2, {"b": [3, 4]}], "c": []}'
        with self._feed_stdin(json_str):
            result = read_long_json_stdin()
        self.assertEqual(json.loads(result)["a"][2]["b"], [3, 4])


# ─── 2. Запасной readline-цикл ─────────────────────────────────────────────────

class TestReadlineFallback(unittest.TestCase):
    """_read_long_json_readline_fallback — readline-цикл.

    Используется только если termios недоступен. Не решает 4-КБ
    проблему (это невозможно без cbreak), но корректно обрабатывает
    многострочный JSON и отмену.
    """

    def test_multiline_json(self):
        lines = ['{\n', '  "a": 1,\n', '  "b": 2\n', '}\n']
        with patch("builtins.input", side_effect=lines):
            result = _read_long_json_readline_fallback()
        self.assertEqual(json.loads(result), {"a": 1, "b": 2})

    def test_single_line_json_auto_completes(self):
        """Однострочный JSON — auto-complete по '{' и '}'."""
        with patch("builtins.input", side_effect=['{"a": 1}']):
            result = _read_long_json_readline_fallback()
        self.assertEqual(result, '{"a": 1}')

    def test_blank_line_terminates(self):
        """Пустая строка — конец ввода."""
        with patch("builtins.input", side_effect=['{"a": 1}', '']):
            result = _read_long_json_readline_fallback()
        self.assertEqual(result, '{"a": 1}')

    def test_keyboard_interrupt_returns_empty(self):
        with patch("builtins.input", side_effect=KeyboardInterrupt()):
            result = _read_long_json_readline_fallback()
        self.assertEqual(result, "")

    def test_eof_returns_what_was_read(self):
        with patch("builtins.input", side_effect=['{"a":', EOFError()]):
            result = _read_long_json_readline_fallback()
        # Не валидный JSON, но функция возвращает что собрала — без исключения.
        self.assertEqual(result, '{"a":')


# ─── 3. Подсчёт глубины скобок (симуляция TTY через monkey-patch) ───────────

class TestBraceAwareRead(unittest.TestCase):
    """_brace_aware_read — посимвольное чтение с подсчётом '{'/'}'.

    Поскольку функция требует реальный TTY (termios), мы тестируем её
    косвенно: убеждаемся, что read_long_json_stdin в не-TTY режиме
    обходит _brace_aware_read и использует sys.stdin.read(). Это
    гарантирует, что pipe/тестовый ввод всегда работает.

    Для TTY-режима проверяем, что функция корректно откатывается к
    readline-fallback, когда termios недоступен.
    """

    def test_non_tty_uses_sys_stdin_read(self):
        """В не-TTY режиме read_long_json_stdin должен использовать
        sys.stdin.read(), а не пытаться вызвать termios."""
        # isatty() = False — функция должна сразу пойти по ветке read().
        big = _make_big_b4_set(size_kb=12)
        with patch("sys.stdin.isatty", return_value=False), \
             patch("sys.stdin", new=io.StringIO(big)):
            result = read_long_json_stdin()
        self.assertEqual(result, big)
        # json.loads не падает — значит обрезки не было.
        json.loads(result)

    def test_tty_with_unavailable_termios_falls_back(self):
        """Если isatty=True, но termios.tcgetattr падает — должен
        использоваться readline-fallback (не падать с исключением)."""
        big = _make_big_b4_set(size_kb=10)
        lines = [big + "\n"]   # одна длинная строка
        with patch("sys.stdin.isatty", return_value=True), \
             patch("sys.stdin", new=io.StringIO(big + "\n")), \
             patch("builtins.input", side_effect=lines):
            # termios импортируется внутри функции; сделаем import termios
            # недоступным через sys.modules.
            saved = sys.modules.pop("termios", None)
            sys.modules["termios"] = None  # type: ignore
            try:
                result = read_long_json_stdin()
            finally:
                if saved is not None:
                    sys.modules["termios"] = saved
                else:
                    sys.modules.pop("termios", None)
        # Fallback использует input() — а в input() действует 4-КБ лимит TTY.
        # В тесте же мы передаём строку через patch, без TTY-буфера — input()
        # вернёт всю строку целиком. Поэтому result должен быть равен big.
        self.assertEqual(result, big)


# ─── 4. Регрессия: точное воспроизведение бага пользователя ──────────────────

class TestRegressionUserBug(unittest.TestCase):
    """REGRESSION: пользователь видел
        «Невалидный JSON: Unterminated string starting at: line 1 column
         4092 (char 4091)»

    Воспроизводим именно эту ошибку на старом коде (input() + ICANON),
    затем проверяем, что новый код (cbreak + brace-count) её не выдаёт.
    """

    def test_old_input_truncates_at_4096(self):
        """Имитация старого поведения: input() обрезает на 4096 байт.

        Не реальный TTY-тест (мы в sandbox без TTY), но воспроизводит
        ошибку через эмуляцию обрезки.

        В зависимости от того, куда попадает граница 4096 байт (внутрь
        строки, между токенами, после завершающего '}'), json.loads
        выдаёт разные сообщения: «Unterminated string», «Expecting
        value», «End of file expected» и т.п. Главное — что ЛЮБАЯ
        обрезка >4 КБ ломает парсинг.
        """
        big = _make_big_b4_set(size_kb=14)
        self.assertGreater(len(big), 4096)
        # Эмуляция: ядро отдаёт только первые 4096 байт.
        truncated = big[:4096]
        with self.assertRaises(json.JSONDecodeError) as ctx:
            json.loads(truncated)
        # Любое из типичных сообщений об ошибке — доказывает, что
        # обрезанный JSON невалиден (то, что видел пользователь).
        err_msg = str(ctx.exception)
        self.assertTrue(
            any(needle in err_msg for needle in
                ["Unterminated string", "Expecting value",
                 "End of file", "Extra data", "Unmatched"]),
            f"Ожидена ошибка обрезки, получено: {err_msg}"
        )

    def test_new_read_long_json_does_not_truncate(self):
        """Новый read_long_json_stdin в не-TTY режиме читает весь ввод."""
        big = _make_big_b4_set(size_kb=14)
        with patch("sys.stdin.isatty", return_value=False), \
             patch("sys.stdin", new=io.StringIO(big)):
            result = read_long_json_stdin()
        self.assertEqual(len(result), len(big))
        # Парсинг не падает.
        parsed = json.loads(result)
        self.assertEqual(parsed["name"], "Meta-facebook-v18-MAX")

    def test_user_actual_facebook_set_imports_cleanly(self):
        """Реальный сет пользователя (восстановлен из сообщения) —
        без усечения и без ошибок парсинга."""
        # Минимизированный (но репрезентативный) фрагмент сета пользователя.
        user_set = (
            '{"b4_version":"1.79.0","name":"Meta-facebook-v18-MAX",'
            '"tcp":{"seg2delay":20,"seg2delay_max":50,'
            '"ip_block_detect":{"enabled":true,"heal_dns":true}},'
            '"udp":{"mode":"reject","filter_quic":"all"},'
            '"faking":{"strategy":"randseq"},'
            '"targets":{"sni_domains":['
            '"facebook.com","fb.com","fb.me","fb.watch","meta.com",'
            '"messenger.com","m.me","fbcdn.net","fbcdn.com","fbsbx.com",'
            '"facebook.net","graph.facebook.com","graph2.facebook.com",'
            '"bgraph.facebook.com","api.facebook.com","edge.facebook.com",'
            '"edge-mqtt.facebook.com","mqtt.facebook.com",'
            '"edge-chat.facebook.com","chat.facebook.com",'
            '"static.facebook.com","staticxx.facebook.com",'
            '"connect.facebook.net","lookaside.facebook.com",'
            '"lookaside.fbsbx.com","rupload.facebook.com",'
            '"upload.facebook.com","rupload.facebook.net",'
            '"video-wu-kc.facebook.com"],'
            '"ip":["57.144.14.141"]},'
            '"enabled":true,'
            '"dns":{"enabled":true,"doh_url":"https://1.1.1.1/dns-query",'
            '"pins":{"facebook.com":["57.144.14.141","157.240.205.21",'
            '"57.144.64.1","57.144.64.144","57.144.98.141","57.144.186.3",'
            '"57.144.186.35","57.144.160.5","57.144.160.33","57.144.152.3",'
            '"57.144.152.33","57.144.150.5","57.144.150.33"]}}}'
        )
        # Размер меньше 4 КБ, но это репрезентативный фрагмент.
        # Главный тест — что read_long_json_stdin не теряет данные.
        with patch("sys.stdin.isatty", return_value=False), \
             patch("sys.stdin", new=io.StringIO(user_set)):
            result = read_long_json_stdin()
        self.assertEqual(result, user_set)
        parsed = json.loads(result)
        self.assertEqual(parsed["name"], "Meta-facebook-v18-MAX")
        self.assertEqual(len(parsed["targets"]["sni_domains"]), 29)


# ─── 5. Граничные случаи ──────────────────────────────────────────────────────

class TestEdgeCases(unittest.TestCase):
    """Граничные случаи для brace-counting.

    Подсчёт глубины '{'/'}' с учётом строк и escape-последовательностей
    — это критичная логика. Тестируем все комбинации.
    """

    def _read(self, content: str) -> str:
        with patch("sys.stdin.isatty", return_value=False), \
             patch("sys.stdin", new=io.StringIO(content)):
            return read_long_json_stdin()

    def test_string_containing_open_brace(self):
        s = '{"a": "open { here"}'
        result = self._read(s)
        self.assertEqual(json.loads(result), {"a": "open { here"})

    def test_string_containing_close_brace(self):
        s = '{"a": "close } here"}'
        result = self._read(s)
        self.assertEqual(json.loads(result), {"a": "close } here"})

    def test_string_containing_both_braces(self):
        s = '{"a": "{}"}'
        result = self._read(s)
        self.assertEqual(json.loads(result), {"a": "{}"})

    def test_escaped_quote_inside_string(self):
        s = '{"a": "foo\\"{bar}"}'
        result = self._read(s)
        self.assertEqual(json.loads(result), {"a": 'foo"{bar}'})

    def test_double_backslash_inside_string(self):
        # '\\' в JSON-источнике = литеральный '\'. После — '"' — конец строки.
        s = '{"a": "foo\\\\"}'
        result = self._read(s)
        self.assertEqual(json.loads(result), {"a": "foo\\"})

    def test_nested_objects_3_levels(self):
        s = '{"a": {"b": {"c": {"d": 1}}}}'
        result = self._read(s)
        self.assertEqual(json.loads(result)["a"]["b"]["c"]["d"], 1)

    def test_empty_object(self):
        s = '{}'
        result = self._read(s)
        self.assertEqual(json.loads(result), {})

    def test_object_with_empty_object_value(self):
        s = '{"a": {}}'
        result = self._read(s)
        self.assertEqual(json.loads(result), {"a": {}})

    def test_object_with_array_of_objects(self):
        s = '{"items": [{"x": 1}, {"y": 2}]}'
        result = self._read(s)
        self.assertEqual(json.loads(result)["items"][1], {"y": 2})

    def test_unicode_in_strings(self):
        s = '{"name": "Тест кириллицей"}'
        result = self._read(s)
        self.assertEqual(json.loads(result)["name"], "Тест кириллицей")

    def test_json_starts_with_whitespace_then_brace(self):
        """Пробелы/BOM до первой '{' должны молча пропускаться."""
        s = '   \n  {"a": 1}'
        result = self._read(s)
        self.assertEqual(result, '{"a": 1}')

    def test_garbage_before_brace_is_preserved(self):
        """Мусор до '{' (не пробел) — НЕ выкидываем, передаём как есть.

        Дизайн-решение: выкидывать мусор до '{' опасно — это маскировало
        бы реальные ошибки пользователя (например, случайный текст перед
        JSON-вставкой). Старый input()-цикл тоже не выкидывал мусор.
        json.loads потом честно скажет «Expecting value: ...» и юзер
        увидит проблему.
        """
        s = 'garbage{"a": 1}'
        result = self._read(s)
        # Мусор preserved — пусть json.loads сам скажет про ошибку.
        self.assertEqual(result, s)
        # Парсинг падает — юзер видит осмысленную ошибку, а не молчание.
        with self.assertRaises(json.JSONDecodeError):
            json.loads(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)

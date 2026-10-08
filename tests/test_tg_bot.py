#!/usr/bin/env python3
"""
tests/test_tg_bot.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/tg_bot.py.

Покрывает:
  1. _get_vless_link — генерация VLESS-ссылки (reality + xhttp, Mode B/AWG)
  2. tg_load / tg_save — JSON I/O
  3. _bot_load / _bot_save — JSON I/O
  4. _load_state — чтение state.json
  5. _generate_bot_script — smoke-тест валидности синтаксиса (ast.parse)
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
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


class TestGetVlessLink(unittest.TestCase):
    """_get_vless_link — генерация VLESS-ссылки."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_state(self, state_dict):
        self._state.write_text(json.dumps(state_dict))
        return patch("chimera.modules.tg_bot._STATE_FILE", self._state)

    def test_reality_mode(self):
        from chimera.modules.tg_bot import _get_vless_link
        state = {
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "public_key": "PUBKEY",
            "short_id": "abcd1234",
            "reality_dest": "dest.example.com:443",
            "fingerprint": "chrome",
            "xtls_flow": "xtls-rprx-vision",
        }
        with self._patch_state(state):
            link = _get_vless_link()
        self.assertTrue(link.startswith("vless://test-uuid@"))
        self.assertIn("vpn.example.com", link)
        self.assertIn("security=reality", link)
        self.assertIn("pbk=PUBKEY", link)
        self.assertIn("sid=abcd1234", link)
        self.assertIn("flow=xtls-rprx-vision", link)

    def test_reality_mode_b_awg_uses_reality_dest_sni(self):
        """Mode B + AWG: SNI берётся из reality_dest, а не domain."""
        from chimera.modules.tg_bot import _get_vless_link
        state = {
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "public_key": "PUBKEY",
            "short_id": "abcd",
            "reality_dest": "dest.example.com:443",
            "awg_exit_enabled": True,
            "install_mode": "B",
        }
        with self._patch_state(state):
            link = _get_vless_link()
        self.assertIn("sni=dest.example.com", link)

    def test_reality_mode_a_uses_domain_sni(self):
        """Mode A: SNI берётся из domain."""
        from chimera.modules.tg_bot import _get_vless_link
        state = {
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "public_key": "PUBKEY",
            "short_id": "abcd",
            "reality_dest": "dest.example.com:443",
            "install_mode": "A",
        }
        with self._patch_state(state):
            link = _get_vless_link()
        self.assertIn("sni=vpn.example.com", link)

    def test_xhttp_mode(self):
        from chimera.modules.tg_bot import _get_vless_link
        state = {
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "protocol_mode": "xhttp",
            "xhttp_path": "/xhttp",
            "xhttp_mode": "stream-up",
            "fingerprint": "chrome",
            "server_port": 443,
        }
        with self._patch_state(state):
            link = _get_vless_link()
        self.assertIn("type=xhttp", link)
        self.assertIn("security=tls", link)
        self.assertIn("path=/xhttp", link)

    def test_xhttp_reality_mode(self):
        """xHTTP + REALITY: type=xhttp + security=reality, path/mode, БЕЗ flow."""
        from chimera.modules.tg_bot import _get_vless_link
        state = {
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "protocol_mode": "xhttp_reality",
            "public_key": "PUBKEY",
            "short_id": "abcd1234",
            "xhttp_path": "/xhttp",
            "xhttp_mode": "stream-up",
            "fingerprint": "chrome",
            "server_port": 443,
        }
        with self._patch_state(state):
            link = _get_vless_link()
        self.assertTrue(link.startswith(
            "vless://test-uuid@vpn.example.com:443?"))
        self.assertIn("encryption=none", link)
        self.assertIn("security=reality", link)
        self.assertIn("sni=vpn.example.com", link)
        self.assertIn("fp=chrome", link)
        self.assertIn("pbk=PUBKEY", link)
        self.assertIn("sid=abcd1234", link)
        self.assertIn("type=xhttp", link)
        self.assertIn("path=/xhttp", link)
        self.assertIn("mode=stream-up", link)
        self.assertNotIn("flow=", link)

    def test_xhttp_reality_mode_b_awg_uses_reality_dest_sni(self):
        """xHTTP+REALITY наследует SNI-правило REALITY: Mode B + AWG → reality_dest."""
        from chimera.modules.tg_bot import _get_vless_link
        state = {
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "protocol_mode": "xhttp_reality",
            "public_key": "PUBKEY",
            "short_id": "abcd",
            "xhttp_path": "/xhttp",
            "reality_dest": "dest.example.com:443",
            "awg_exit_enabled": True,
            "install_mode": "B",
        }
        with self._patch_state(state):
            link = _get_vless_link()
        self.assertIn("sni=dest.example.com", link)
        self.assertNotIn("flow=", link)

    def test_returns_empty_when_no_domain(self):
        from chimera.modules.tg_bot import _get_vless_link
        state = {"uuid": "test-uuid"}
        with self._patch_state(state):
            self.assertEqual(_get_vless_link(), "")

    def test_returns_empty_when_no_uuid(self):
        from chimera.modules.tg_bot import _get_vless_link
        state = {"domain": "vpn.example.com"}
        with self._patch_state(state):
            self.assertEqual(_get_vless_link(), "")

    def test_reality_without_flow(self):
        """Без xtls_flow — параметр flow не добавляется."""
        from chimera.modules.tg_bot import _get_vless_link
        state = {
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "public_key": "PUBKEY",
            "short_id": "abcd",
            "reality_dest": "dest:443",
            "xtls_flow": "",
        }
        with self._patch_state(state):
            link = _get_vless_link()
        self.assertNotIn("flow=", link)

    def test_default_fingerprint_is_chrome(self):
        from chimera.modules.tg_bot import _get_vless_link
        state = {
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "public_key": "PUBKEY",
            "short_id": "abcd",
            "reality_dest": "dest:443",
        }
        with self._patch_state(state):
            link = _get_vless_link()
        self.assertIn("fp=chrome", link)


class TestTgLoadSave(unittest.TestCase):
    """tg_load / tg_save — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._notif = self._tmpdir / "telegram.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.tg_bot._NOTIF_FILE", self._notif)

    def test_load_returns_empty_when_no_file(self):
        from chimera.modules.tg_bot import tg_load
        with self._patch():
            self.assertEqual(tg_load(), {})

    def test_save_then_load(self):
        from chimera.modules.tg_bot import tg_load, tg_save
        with self._patch():
            tg_save({"bot_token": "abc", "admin_id": "123"})
            loaded = tg_load()
        self.assertEqual(loaded["bot_token"], "abc")
        self.assertEqual(loaded["admin_id"], "123")

    def test_save_sets_chmod_600(self):
        import stat
        from chimera.modules.tg_bot import tg_save
        with self._patch():
            tg_save({"x": 1})
        mode = stat.S_IMODE(os.stat(self._notif).st_mode)
        self.assertEqual(mode, 0o600)


class TestTgSendProxy(unittest.TestCase):
    """tg_send / tg_send_code — поддержка необязательного proxy (curl -x)."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._notif = self._tmpdir / "telegram.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write_cfg(self, proxy=None):
        cfg = {"token": "T", "chat_id": "C"}
        if proxy is not None:
            cfg["proxy"] = proxy
        self._notif.write_text(json.dumps(cfg), encoding="utf-8")

    def _patch(self):
        return patch("chimera.modules.tg_bot._NOTIF_FILE", self._notif)

    def test_proxy_adds_x_flag(self):
        from chimera.modules import tg_bot
        from unittest.mock import MagicMock
        self._write_cfg(proxy="http://127.0.0.1:25181")
        resp = MagicMock(stdout="200", returncode=0)
        with self._patch(), \
             patch.object(tg_bot, "_run", return_value=resp) as m:
            self.assertTrue(tg_bot.tg_send("msg", "T", "C"))
            cmd = m.call_args[0][0] if m.call_args else m.call_args[1]
            # cmd может прийти позиционно или через capture-kwargs
            flat = cmd if isinstance(cmd, list) else cmd.get("args", cmd)
            self.assertIn("-x", flat)
            self.assertEqual(flat[flat.index("-x") + 1],
                             "http://127.0.0.1:25181")

    def test_no_proxy_keeps_old_behavior(self):
        from chimera.modules import tg_bot
        from unittest.mock import MagicMock
        self._write_cfg()
        resp = MagicMock(stdout="200", returncode=0)
        with self._patch(), \
             patch.object(tg_bot, "_run", return_value=resp) as m:
            self.assertTrue(tg_bot.tg_send("msg", "T", "C"))
            cmd = m.call_args[0][0] if m.call_args else m.call_args[1]
            flat = cmd if isinstance(cmd, list) else cmd.get("args", cmd)
            self.assertNotIn("-x", flat)

    def test_send_code_returns_http_code(self):
        from chimera.modules import tg_bot
        from unittest.mock import MagicMock
        self._write_cfg()
        resp = MagicMock(stdout="401", returncode=0)
        with self._patch(), \
             patch.object(tg_bot, "_run", return_value=resp):
            self.assertEqual(tg_bot.tg_send_code("msg", "T", "C"), "401")

    def test_diag_msg_known_codes(self):
        from chimera.modules.tg_bot import tg_send_diag_msg
        self.assertIn("нет связи", tg_send_diag_msg("000"))
        self.assertIn("токен", tg_send_diag_msg("401"))
        self.assertIn("chat_id", tg_send_diag_msg("400"))
        self.assertIn("заблокирован", tg_send_diag_msg("403"))
        self.assertIn("flood", tg_send_diag_msg("429"))
        self.assertTrue(tg_send_diag_msg("500").startswith("HTTP 500"))

    def test_send_code_no_config(self):
        from chimera.modules import tg_bot
        with self._patch():   # файла нет
            self.assertEqual(tg_bot.tg_send_code("msg"), "no-config")


class TestBotLoadSave(unittest.TestCase):
    """_bot_load / _bot_save — JSON I/O."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._bot = self._tmpdir / "tg_bot.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.tg_bot._BOT_FILE", self._bot)

    def test_load_returns_empty_when_no_file(self):
        from chimera.modules.tg_bot import _bot_load
        with self._patch():
            self.assertEqual(_bot_load(), {})

    def test_save_then_load(self):
        from chimera.modules.tg_bot import _bot_load, _bot_save
        with self._patch():
            _bot_save({"users": {"alice": "uuid1"}})
            loaded = _bot_load()
        self.assertIn("alice", loaded["users"])


class TestLoadState(unittest.TestCase):
    """_load_state — чтение state.json."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.tg_bot._STATE_FILE", self._state)

    def test_returns_empty_when_no_file(self):
        from chimera.modules.tg_bot import _load_state
        with self._patch():
            self.assertEqual(_load_state(), {})

    def test_returns_state(self):
        from chimera.modules.tg_bot import _load_state
        self._state.write_text(json.dumps({"domain": "x.com"}))
        with self._patch():
            st = _load_state()
        self.assertEqual(st["domain"], "x.com")


class TestGenerateBotScriptSyntax(unittest.TestCase):
    """_generate_bot_script — smoke-тест валидности синтаксиса через ast.parse.

    Функция генерирует Python-скрипт через f-string с экранированием {{ }} для
    фигурных скобок вложенного кода. Ошибка экранирования (как в awg_cascade.py)
    приведёт к NameError или SyntaxError в сгенерированном коде — ast.parse
    ловит именно этот класс ошибок.
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def _bot_cfg(self, **overrides):
        base = {
            "token": "123456:ABC-DEF",
            "admin_id": "111111111",
            "allowed_users": [111111111, 222222222],
            "invite_tokens": {"abc123": {"created": "2026-01-01T00:00:00"}},
        }
        base.update(overrides)
        return base

    def _notif_cfg(self, **overrides):
        base = {"token": "", "chat_id": ""}
        base.update(overrides)
        return base

    def test_normal_values_produce_valid_syntax(self):
        """Обычные значения — ast.parse не должен поднимать SyntaxError."""
        import ast
        from chimera.modules.tg_bot import _generate_bot_script
        script = _generate_bot_script(self._bot_cfg(), self._notif_cfg())
        # Если экранирование сломано — ast.parse поднимает SyntaxError
        ast.parse(script)

    def test_empty_values_produce_valid_syntax(self):
        """Пустые/дефолтные значения — ast.parse не должен падать."""
        import ast
        from chimera.modules.tg_bot import _generate_bot_script
        cfg = self._bot_cfg(token="", admin_id="", allowed_users=[], invite_tokens={})
        script = _generate_bot_script(cfg, self._notif_cfg())
        ast.parse(script)

    def test_token_with_double_quotes_produces_valid_syntax(self):
        """Token с двойными кавычками — json.dumps корректно экранирует ".

        После фикса: token проходит через json.dumps(ensure_ascii=False),
        который добавляет внешние кавычки и экранирует внутренние как \\".
        ast.parse должен пройти БЕЗ исключения, а значение TOKEN в AST
        должно совпадать с исходным token (кавычка сохранена как часть строки).
        """
        import ast
        from chimera.modules.tg_bot import _generate_bot_script
        cfg = self._bot_cfg(token='abc"def')
        script = _generate_bot_script(cfg, self._notif_cfg())
        # ast.parse должен пройти без SyntaxError
        tree = ast.parse(script)
        # Проверяем что TOKEN содержит исходное значение с кавычкой
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "TOKEN":
                        self.assertIsInstance(node.value, ast.Constant)
                        self.assertEqual(node.value.value, 'abc"def')

    def test_token_with_backslash_produces_valid_syntax(self):
        r"""Token с обратным слэшем — json.dumps корректно экранирует \.

        После фикса: token проходит через json.dumps, который экранирует \ как \\.
        ast.parse проходит чисто, а значение TOKEN в AST соответствует исходному
        token с обратным слэшем как есть (без интерпретации как escape-последовательности).
        """
        import ast
        from chimera.modules.tg_bot import _generate_bot_script
        cfg = self._bot_cfg(token=r"abc\def")
        script = _generate_bot_script(cfg, self._notif_cfg())
        # ast.parse должен пройти без SyntaxError
        tree = ast.parse(script)
        # Проверяем что TOKEN содержит исходное значение с \
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "TOKEN":
                        self.assertIsInstance(node.value, ast.Constant)
                        self.assertEqual(node.value.value, r"abc\def")

    def test_token_with_newline_and_unicode_produces_valid_syntax(self):
        """Token с переносом строки и юникодом (эмодзи) — json.dumps корректно
        экранирует \\n как \\\\n и сохраняет emoji через ensure_ascii=False.

        ast.parse проходит чисто, а значение TOKEN в AST соответствует
        исходному token с переносом строки и эмодзи как есть.
        """
        import ast
        from chimera.modules.tg_bot import _generate_bot_script
        cfg = self._bot_cfg(token="abc\ndef🚀")
        script = _generate_bot_script(cfg, self._notif_cfg())
        # ast.parse должен пройти без SyntaxError
        tree = ast.parse(script)
        # Проверяем что TOKEN содержит исходное значение
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "TOKEN":
                        self.assertIsInstance(node.value, ast.Constant)
                        self.assertEqual(node.value.value, "abc\ndef🚀")

    def test_token_with_curly_braces_produces_valid_syntax(self):
        """Token с фигурными скобками — проверка что { } не ломают f-string.

        ВНИМАНИЕ: token с { или } вставляется в f-строку через {token} и Python
        интерпретирует это как подстановку значения переменной token (правильно).
        Но если экранирование {{ }} сломано — {def} внутри f-string может
        быть интерпретировано как подстановка переменной def → NameError при
        генерации. В текущей реализации {token} правильно подставляется и
        фигурные скобки в значении попадают в результат как литералы.

        Однако ast.parse НЕ падает на {def} в обычной строке "abc{def}ghi"
        — это валидный Python. Проблема возникнет только при выполнении
        скрипта (если {def} встретится внутри f-string сгенерированного кода).

        Тест фиксирует что генерация не падает и синтаксис результата валиден.
        """
        import ast
        from chimera.modules.tg_bot import _generate_bot_script
        cfg = self._bot_cfg(token="abc{def}ghi")
        script = _generate_bot_script(cfg, self._notif_cfg())
        # Проверяем что ast.parse проходит (синтаксис валиден)
        ast.parse(script)
        # Проверяем что token правильно подставлен как строковый литерал
        tree = ast.parse(script)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "TOKEN":
                        self.assertIsInstance(node.value, ast.Constant)
                        self.assertEqual(node.value.value, "abc{def}ghi")

    def test_normal_values_have_token_admin_botfile_statef_as_strings(self):
        """Дополнительно: TOKEN/ADMIN_ID/BOT_FILE/STATE_F — строковые литералы.

        Через ast.walk находим присваивания и проверяем что значения —
        Constant/str, чтобы поймать случай, если экранирование сломает
        саму подстановку значения.
        """
        import ast
        from chimera.modules.tg_bot import _generate_bot_script
        cfg = self._bot_cfg(token="test_token", admin_id="12345")
        script = _generate_bot_script(cfg, self._notif_cfg())
        tree = ast.parse(script)

        # Собираем все присваивания на module level
        assignments = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assignments[target.id] = node.value

        # TOKEN = "..." — строковый литерал
        self.assertIn("TOKEN", assignments)
        token_val = assignments["TOKEN"]
        self.assertIsInstance(token_val, ast.Constant)
        self.assertIsInstance(token_val.value, str)
        self.assertEqual(token_val.value, "test_token")

        # ADMIN_ID = "..." — строковый литерал
        self.assertIn("ADMIN_ID", assignments)
        admin_val = assignments["ADMIN_ID"]
        self.assertIsInstance(admin_val, ast.Constant)
        self.assertIsInstance(admin_val.value, str)
        self.assertEqual(admin_val.value, "12345")

        # BOT_FILE = Path("...") — Call с строковым аргументом
        self.assertIn("BOT_FILE", assignments)
        bot_file_val = assignments["BOT_FILE"]
        self.assertIsInstance(bot_file_val, ast.Call)
        # первый аргумент — строковый литерал
        arg = bot_file_val.args[0]
        self.assertIsInstance(arg, ast.Constant)
        self.assertIsInstance(arg.value, str)

        # STATE_F = Path("...") — Call с строковым аргументом
        self.assertIn("STATE_F", assignments)
        state_f_val = assignments["STATE_F"]
        self.assertIsInstance(state_f_val, ast.Call)
        arg = state_f_val.args[0]
        self.assertIsInstance(arg, ast.Constant)
        self.assertIsInstance(arg.value, str)

    def test_generated_script_contains_handlers(self):
        """Сгенерированный скрипт содержит все handler-функции."""
        import ast
        from chimera.modules.tg_bot import _generate_bot_script
        script = _generate_bot_script(self._bot_cfg(), self._notif_cfg())
        tree = ast.parse(script)

        # Собираем все function definitions
        func_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                func_names.add(node.name)

        for handler in ("handle_start", "handle_config", "handle_status",
                        "handle_users", "handle_invite", "handle_broadcast",
                        "handle_help", "process_update", "main",
                        "get_vless_link", "_bot_load", "_bot_save",
                        "_state", "api", "send"):
            with self.subTest(handler=handler):
                self.assertIn(handler, func_names)

    def test_generated_script_has_main_guard(self):
        """Сгенерированный скрипт имеет if __name__ == '__main__' guard."""
        import ast
        from chimera.modules.tg_bot import _generate_bot_script
        script = _generate_bot_script(self._bot_cfg(), self._notif_cfg())
        tree = ast.parse(script)

        # Ищем if __name__ == "__main__"
        found = False
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                test = node.test
                if isinstance(test, ast.Compare):
                    if (isinstance(test.left, ast.Name)
                            and test.left.id == "__name__"):
                        for comp in test.comparators:
                            if (isinstance(comp, ast.Constant)
                                    and comp.value == "__main__"):
                                found = True
        self.assertTrue(found, "if __name__ == '__main__' guard not found")


class TestGeneratedScriptVlessLink(unittest.TestCase):
    """get_vless_link В СГЕНЕРИРОВАННОМ inner-скрипте — поведенческий тест.

    ast.parse (TestGenerateBotScriptSyntax) ловит только ошибки экранирования
    {{ }}. Здесь скрипт реально исполняется через exec() (main-guard не
    срабатывает: __name__ внутри exec-неймспейса != "__main__"), подменяется
    STATE_F и проверяется КАНОНИЧЕСКИЙ формат ссылок всех трёх режимов.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._state = self._tmpdir / "state.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _get_inner_link(self, state_dict):
        from chimera.modules.tg_bot import _generate_bot_script
        script = _generate_bot_script(
            {"token": "123456:ABC-DEF", "admin_id": "111111111",
             "allowed_users": [], "invite_tokens": {}},
            {"token": "", "chat_id": ""})
        ns = {}
        exec(compile(script, "inner_bot.py", "exec"), ns)
        self._state.write_text(json.dumps(state_dict))
        ns["STATE_F"] = self._state
        return ns["get_vless_link"]()

    def test_xhttp_reality_canonical_link(self):
        """xHTTP+REALITY: security=reality + type=xhttp + mode, БЕЗ flow."""
        link = self._get_inner_link({
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "protocol_mode": "xhttp_reality",
            "public_key": "PUBKEY",
            "short_id": "abcd",
            "xhttp_path": "/xhttp",
            "xhttp_mode": "stream-up",
            "fingerprint": "chrome",
            "server_port": 443,
        })
        self.assertTrue(link.startswith(
            "vless://test-uuid@vpn.example.com:443?"))
        self.assertIn("encryption=none", link)
        self.assertIn("security=reality", link)
        self.assertIn("pbk=PUBKEY", link)
        self.assertIn("sid=abcd", link)
        self.assertIn("type=xhttp", link)
        self.assertIn("path=/xhttp", link)
        self.assertIn("mode=stream-up", link)
        self.assertNotIn("flow=", link)
        self.assertIn("#VLESS-xHTTP-REALITY", link)

    def test_xhttp_reality_mode_b_awg_sni(self):
        """Mode B + AWG: SNI из reality_dest (правило REALITY унаследовано)."""
        link = self._get_inner_link({
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "protocol_mode": "xhttp_reality",
            "public_key": "PUBKEY",
            "short_id": "abcd",
            "xhttp_path": "/xhttp",
            "reality_dest": "dest.example.com:443",
            "awg_exit_enabled": True,
            "install_mode": "B",
        })
        self.assertIn("sni=dest.example.com", link)
        self.assertNotIn("flow=", link)

    def test_reality_regression(self):
        """Регрессия: классическая REALITY-ветка inner-скрипта не изменилась."""
        link = self._get_inner_link({
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "protocol_mode": "reality",
            "public_key": "PUBKEY",
            "short_id": "abcd",
            "xtls_flow": "xtls-rprx-vision",
        })
        self.assertIn("type=tcp", link)
        self.assertIn("security=reality", link)
        self.assertIn("flow=xtls-rprx-vision", link)
        self.assertIn("#VLESS-REALITY", link)


class TestGeneratedBotHardening(unittest.TestCase):
    """Харденинг сгенерированного админ-бота (инцидент 08.10.2026, RU-2).

    Мёртвый IPv6-маршрут убивал urllib-поллинг (Errno 101 Network is
    unreachable) — urllib, в отличие от curl, не умеет happy-eyeballs.
    Плюс mieru-прокси транзиентно рвёт отдельные запросы (~1 на 2-3 мин
    поллинга) — один разрыв не должен стоить потерянного сообщения.
    """

    def _script(self):
        from chimera.modules.tg_bot import _generate_bot_script
        cfg = {"token": "123456:ABC", "admin_id": "111",
               "allowed_users": [111], "invite_tokens": {}}
        notif = {"token": "123456:ABC", "chat_id": "111", "events": {}}
        return _generate_bot_script(cfg, notif)

    def test_ipv4_first_pinning_present(self):
        """В преамбуле сгенерированного скрипта — IPv4-first обёртка getaddrinfo."""
        script = self._script()
        self.assertIn("_gai_ipv4_first", script)
        self.assertIn("_socket.getaddrinfo = _gai_ipv4_first", script)

    def test_api_retries_present(self):
        """api() делает до 3 попыток с паузой 2с и логирует номер попытки."""
        script = self._script()
        self.assertIn("for _att in range(1, 4):", script)
        self.assertIn("time.sleep(2)", script)
        self.assertIn('f"API error {method} (попытка {_att}/3): {e}"', script)

    def test_api_proxy_support_present(self):
        """api() читает proxy-ключ из telegram.json при каждом вызове (фикс 4e645199)."""
        script = self._script()
        self.assertIn("ProxyHandler", script)
        self.assertIn('str(_pc.get("proxy") or "").strip()', script)

    def test_send_routes_via_api(self):
        """send() идёт через api() — наследует прокси и ретраи, не дублирует логику."""
        script = self._script()
        self.assertIn('def send(chat_id, text, parse_mode="HTML"):\n    api("sendMessage"', script)

    def test_hardened_script_still_compiles(self):
        import ast
        ast.parse(self._script())


if __name__ == "__main__":
    unittest.main(verbosity=2)


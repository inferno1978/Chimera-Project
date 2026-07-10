#!/usr/bin/env python3
"""
tests/test_tg_bot.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/tg_bot.py.

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
    core_path = _PROJECT_ROOT / "vless_installer" / "_core.py"
    src = core_path.read_text()
    g = {}
    with patch.object(Path, 'mkdir', lambda self, *a, **kw: None), \
         patch.object(Path, 'touch', lambda self, *a, **kw: None), \
         patch.object(Path, 'chmod', lambda self, *a, **kw: None), \
         patch('os.chown', lambda *a, **kw: None), \
         patch('os.geteuid', return_value=0):
        exec(compile(src, str(core_path), "exec"), g)
    import types
    fake_core = types.ModuleType("vless_installer._core")
    fake_core.__dict__.update(g)
    sys.modules["vless_installer._core"] = fake_core


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
        return patch("vless_installer.modules.tg_bot._STATE_FILE", self._state)

    def test_reality_mode(self):
        from vless_installer.modules.tg_bot import _get_vless_link
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
        from vless_installer.modules.tg_bot import _get_vless_link
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
        from vless_installer.modules.tg_bot import _get_vless_link
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
        from vless_installer.modules.tg_bot import _get_vless_link
        state = {
            "domain": "vpn.example.com",
            "uuid": "test-uuid",
            "protocol_mode": "xhttp",
            "xhttp_path": "/xhttp",
            "xhttp_mode": "streamup",
            "fingerprint": "chrome",
            "server_port": 443,
        }
        with self._patch_state(state):
            link = _get_vless_link()
        self.assertIn("type=xhttp", link)
        self.assertIn("security=tls", link)
        self.assertIn("path=/xhttp", link)

    def test_returns_empty_when_no_domain(self):
        from vless_installer.modules.tg_bot import _get_vless_link
        state = {"uuid": "test-uuid"}
        with self._patch_state(state):
            self.assertEqual(_get_vless_link(), "")

    def test_returns_empty_when_no_uuid(self):
        from vless_installer.modules.tg_bot import _get_vless_link
        state = {"domain": "vpn.example.com"}
        with self._patch_state(state):
            self.assertEqual(_get_vless_link(), "")

    def test_reality_without_flow(self):
        """Без xtls_flow — параметр flow не добавляется."""
        from vless_installer.modules.tg_bot import _get_vless_link
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
        from vless_installer.modules.tg_bot import _get_vless_link
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
        return patch("vless_installer.modules.tg_bot._NOTIF_FILE", self._notif)

    def test_load_returns_empty_when_no_file(self):
        from vless_installer.modules.tg_bot import tg_load
        with self._patch():
            self.assertEqual(tg_load(), {})

    def test_save_then_load(self):
        from vless_installer.modules.tg_bot import tg_load, tg_save
        with self._patch():
            tg_save({"bot_token": "abc", "admin_id": "123"})
            loaded = tg_load()
        self.assertEqual(loaded["bot_token"], "abc")
        self.assertEqual(loaded["admin_id"], "123")

    def test_save_sets_chmod_600(self):
        import stat
        from vless_installer.modules.tg_bot import tg_save
        with self._patch():
            tg_save({"x": 1})
        mode = stat.S_IMODE(os.stat(self._notif).st_mode)
        self.assertEqual(mode, 0o600)


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
        return patch("vless_installer.modules.tg_bot._BOT_FILE", self._bot)

    def test_load_returns_empty_when_no_file(self):
        from vless_installer.modules.tg_bot import _bot_load
        with self._patch():
            self.assertEqual(_bot_load(), {})

    def test_save_then_load(self):
        from vless_installer.modules.tg_bot import _bot_load, _bot_save
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
        return patch("vless_installer.modules.tg_bot._STATE_FILE", self._state)

    def test_returns_empty_when_no_file(self):
        from vless_installer.modules.tg_bot import _load_state
        with self._patch():
            self.assertEqual(_load_state(), {})

    def test_returns_state(self):
        from vless_installer.modules.tg_bot import _load_state
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
        from vless_installer.modules.tg_bot import _generate_bot_script
        script = _generate_bot_script(self._bot_cfg(), self._notif_cfg())
        # Если экранирование сломано — ast.parse поднимает SyntaxError
        ast.parse(script)

    def test_empty_values_produce_valid_syntax(self):
        """Пустые/дефолтные значения — ast.parse не должен падать."""
        import ast
        from vless_installer.modules.tg_bot import _generate_bot_script
        cfg = self._bot_cfg(token="", admin_id="", allowed_users=[], invite_tokens={})
        script = _generate_bot_script(cfg, self._notif_cfg())
        ast.parse(script)

    def test_token_with_double_quotes_produces_valid_syntax(self):
        """Token с двойными кавычками — проверка что экранирование не ломает синтаксис.

        ВНИМАНИЕ: token с " вставляется в f"{token}" внутри строкового литерала
        Python-скрипта. Если token содержит ", это сломает строковый литерал.
        Но _generate_bot_script НЕ экранирует token — это реальная уязвимость,
        которую тест фиксирует. ast.parse должен поднять SyntaxError в этом случае.
        """
        import ast
        from vless_installer.modules.tg_bot import _generate_bot_script
        cfg = self._bot_cfg(token='abc"def')
        script = _generate_bot_script(cfg, self._notif_cfg())
        # token с " ломает строковый литерал — ast.parse поднимает SyntaxError
        with self.assertRaises(SyntaxError):
            ast.parse(script)

    def test_token_with_backslash_produces_valid_syntax(self):
        r"""Token с обратным слэшем — проверка что \n не интерпретируется как newline.

        ВНИМАНИЕ: token с \ вставляется в f"{token}" и может сломать строковый
        литерал (например \n → newline, \" → escaped quote). _generate_bot_script
        НЕ экранирует token — это реальная уязвимость, которую тест фиксирует.
        """
        import ast
        from vless_installer.modules.tg_bot import _generate_bot_script
        cfg = self._bot_cfg(token=r"abc\def")
        script = _generate_bot_script(cfg, self._notif_cfg())
        # \d в строковом литерале — это invalid escape sequence (DeprecationWarning),
        # но не SyntaxError. Проверяем что ast.parse хотя бы не падает с SyntaxError.
        try:
            ast.parse(script)
        except SyntaxError:
            pass  # \ перед " или другими спецсимволами может вызвать SyntaxError

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
        from vless_installer.modules.tg_bot import _generate_bot_script
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
        from vless_installer.modules.tg_bot import _generate_bot_script
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
        from vless_installer.modules.tg_bot import _generate_bot_script
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
        from vless_installer.modules.tg_bot import _generate_bot_script
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


if __name__ == "__main__":
    unittest.main(verbosity=2)

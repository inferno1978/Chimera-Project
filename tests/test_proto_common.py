#!/usr/bin/env python3
"""
tests/test_proto_common.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для vless_installer/modules/proto_common.py — общие хелперы
для 8 протокольных модулей (wdtt, turnable, mieru, fptn, naiveproxy,
turntunnel, mtproto, webdav_tunnel).

Покрывает:
  1. proto_load_state — чтение JSON state
  2. proto_save_state — запись + chmod 0o600
  3. proto_ask — интерактивный ввод (mocked input)
  4. ProtoCancelled — exception при Ctrl+C
  5. proto_gen_password — генерация пароля
"""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

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


class TestProtoLoadState(unittest.TestCase):
    """proto_load_state — чтение JSON state-файла."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_loads_valid_json(self):
        from vless_installer.modules.proto_common import proto_load_state
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"installed": True, "port": 56000}, f)
            f.flush()
            state = proto_load_state(Path(f.name))
        os.unlink(f.name)
        self.assertTrue(state["installed"])
        self.assertEqual(state["port"], 56000)

    def test_returns_empty_dict_when_file_missing(self):
        from vless_installer.modules.proto_common import proto_load_state
        state = proto_load_state(Path("/tmp/nonexistent_proto_state.json"))
        self.assertEqual(state, {})

    def test_returns_defaults_when_file_missing(self):
        from vless_installer.modules.proto_common import proto_load_state
        defaults = {"installed": False, "port": 443}
        state = proto_load_state(Path("/tmp/nonexistent_proto_state.json"), defaults)
        self.assertEqual(state["installed"], False)
        self.assertEqual(state["port"], 443)

    def test_returns_empty_dict_when_corrupt_json(self):
        from vless_installer.modules.proto_common import proto_load_state
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{invalid json!!!")
            f.flush()
            state = proto_load_state(Path(f.name))
        os.unlink(f.name)
        self.assertEqual(state, {})

    def test_merges_defaults_with_existing_state(self):
        """При наличии defaults — missing keys заполняются из defaults."""
        from vless_installer.modules.proto_common import proto_load_state
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"installed": True}, f)
            f.flush()
            defaults = {"installed": False, "port": 443, "name": ""}
            state = proto_load_state(Path(f.name), defaults)
        os.unlink(f.name)
        # installed из файла (True), port/name из defaults
        self.assertTrue(state["installed"])
        self.assertEqual(state["port"], 443)
        self.assertEqual(state["name"], "")


class TestProtoSaveState(unittest.TestCase):
    """proto_save_state — запись JSON state с chmod 0o600."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_writes_valid_json(self):
        from vless_installer.modules.proto_common import proto_save_state
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test_state.json"
            proto_save_state(path, {"installed": True, "port": 56000})
            data = json.loads(path.read_text())
            self.assertTrue(data["installed"])
            self.assertEqual(data["port"], 56000)

    def test_sets_chmod_600(self):
        """proto_save_state должен устанавливать права 0o600."""
        from vless_installer.modules.proto_common import proto_save_state
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test_state.json"
            proto_save_state(path, {"test": True})
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(mode, 0o600,
                             f"State file should have 0o600 permissions, got {oct(mode)}")

    def test_creates_parent_dir(self):
        """Создаёт родительскую директорию если не существует."""
        from vless_installer.modules.proto_common import proto_save_state
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "subdir" / "test_state.json"
            proto_save_state(path, {"test": True})
            self.assertTrue(path.exists())

    def test_overwrites_existing(self):
        """Перезаписывает существующий файл."""
        from vless_installer.modules.proto_common import proto_save_state
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test_state.json"
            proto_save_state(path, {"version": 1})
            proto_save_state(path, {"version": 2})
            data = json.loads(path.read_text())
            self.assertEqual(data["version"], 2)


class TestProtoAsk(unittest.TestCase):
    """proto_ask — интерактивный ввод."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_returns_input_value(self):
        from vless_installer.modules.proto_common import proto_ask
        with patch("builtins.input", return_value="hello"):
            result = proto_ask("Enter something: ")
        self.assertEqual(result, "hello")

    def test_returns_default_on_empty(self):
        from vless_installer.modules.proto_common import proto_ask
        with patch("builtins.input", return_value=""):
            result = proto_ask("Enter: ", default="fallback")
        self.assertEqual(result, "fallback")

    def test_raises_on_ctrl_c(self):
        """Ctrl+C → ProtoCancelled exception."""
        from vless_installer.modules.proto_common import proto_ask, ProtoCancelled
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            with self.assertRaises(ProtoCancelled):
                proto_ask("Enter: ", c=True)

    def test_returns_default_on_ctrl_c_without_c_flag(self):
        """Без c=True — Ctrl+C возвращает default, не exception."""
        from vless_installer.modules.proto_common import proto_ask
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            result = proto_ask("Enter: ", default="safe")
        self.assertEqual(result, "safe")


class TestProtoGenPassword(unittest.TestCase):
    """proto_gen_password — генерация пароля."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_generates_correct_length(self):
        from vless_installer.modules.proto_common import proto_gen_password
        pw = proto_gen_password(16)
        self.assertEqual(len(pw), 16)

    def test_generates_different_passwords(self):
        from vless_installer.modules.proto_common import proto_gen_password
        pw1 = proto_gen_password(20)
        pw2 = proto_gen_password(20)
        self.assertNotEqual(pw1, pw2)

    def test_default_length(self):
        from vless_installer.modules.proto_common import proto_gen_password
        pw = proto_gen_password()
        self.assertTrue(len(pw) >= 12)  # default should be reasonable

    def test_contains_only_safe_chars(self):
        """Пароль содержит только печатные ASCII без неоднозначных символов."""
        from vless_installer.modules.proto_common import proto_gen_password
        pw = proto_gen_password(50)
        # Не должно содержать пробелы, кавычки, обратный слеш
        for ch in pw:
            self.assertNotIn(ch, ' \'"\\`|;')


class TestProtoCancelled(unittest.TestCase):
    """ProtoCancelled — exception class."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_is_exception(self):
        from vless_installer.modules.proto_common import ProtoCancelled
        self.assertTrue(issubclass(ProtoCancelled, Exception))

    def test_can_be_raised_and_caught(self):
        from vless_installer.modules.proto_common import ProtoCancelled
        with self.assertRaises(ProtoCancelled):
            raise ProtoCancelled()


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""
tests/test_proto_common.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/proto_common.py — общие хелперы
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


class TestProtoLoadState(unittest.TestCase):
    """proto_load_state — чтение JSON state-файла."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_loads_valid_json(self):
        from chimera.modules.proto_common import proto_load_state
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"installed": True, "port": 56000}, f)
            f.flush()
            state = proto_load_state(Path(f.name))
        os.unlink(f.name)
        self.assertTrue(state["installed"])
        self.assertEqual(state["port"], 56000)

    def test_returns_empty_dict_when_file_missing(self):
        from chimera.modules.proto_common import proto_load_state
        state = proto_load_state(Path("/tmp/nonexistent_proto_state.json"))
        self.assertEqual(state, {})

    def test_returns_defaults_when_file_missing(self):
        from chimera.modules.proto_common import proto_load_state
        defaults = {"installed": False, "port": 443}
        state = proto_load_state(Path("/tmp/nonexistent_proto_state.json"), defaults)
        self.assertEqual(state["installed"], False)
        self.assertEqual(state["port"], 443)

    def test_returns_empty_dict_when_corrupt_json(self):
        from chimera.modules.proto_common import proto_load_state
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{invalid json!!!")
            f.flush()
            state = proto_load_state(Path(f.name))
        os.unlink(f.name)
        self.assertEqual(state, {})

    def test_merges_defaults_with_existing_state(self):
        """При наличии defaults — missing keys заполняются из defaults."""
        from chimera.modules.proto_common import proto_load_state
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
        from chimera.modules.proto_common import proto_save_state
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test_state.json"
            proto_save_state(path, {"installed": True, "port": 56000})
            data = json.loads(path.read_text())
            self.assertTrue(data["installed"])
            self.assertEqual(data["port"], 56000)

    def test_sets_chmod_600(self):
        """proto_save_state должен устанавливать права 0o600."""
        from chimera.modules.proto_common import proto_save_state
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test_state.json"
            proto_save_state(path, {"test": True})
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(mode, 0o600,
                             f"State file should have 0o600 permissions, got {oct(mode)}")

    def test_creates_parent_dir(self):
        """Создаёт родительскую директорию если не существует."""
        from chimera.modules.proto_common import proto_save_state
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "subdir" / "test_state.json"
            proto_save_state(path, {"test": True})
            self.assertTrue(path.exists())

    def test_overwrites_existing(self):
        """Перезаписывает существующий файл."""
        from chimera.modules.proto_common import proto_save_state
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
        from chimera.modules.proto_common import proto_ask
        with patch("builtins.input", return_value="hello"):
            result = proto_ask("Enter something: ")
        self.assertEqual(result, "hello")

    def test_returns_default_on_empty(self):
        from chimera.modules.proto_common import proto_ask
        with patch("builtins.input", return_value=""):
            result = proto_ask("Enter: ", default="fallback")
        self.assertEqual(result, "fallback")

    def test_raises_on_ctrl_c(self):
        """Ctrl+C → ProtoCancelled exception."""
        from chimera.modules.proto_common import proto_ask, ProtoCancelled
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            with self.assertRaises(ProtoCancelled):
                proto_ask("Enter: ", c=True)

    def test_returns_default_on_ctrl_c_without_c_flag(self):
        """Без c=True — Ctrl+C возвращает default, не exception."""
        from chimera.modules.proto_common import proto_ask
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            result = proto_ask("Enter: ", default="safe")
        self.assertEqual(result, "safe")


class TestProtoGenPassword(unittest.TestCase):
    """proto_gen_password — генерация пароля."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_generates_correct_length(self):
        from chimera.modules.proto_common import proto_gen_password
        pw = proto_gen_password(16)
        self.assertEqual(len(pw), 16)

    def test_generates_different_passwords(self):
        from chimera.modules.proto_common import proto_gen_password
        pw1 = proto_gen_password(20)
        pw2 = proto_gen_password(20)
        self.assertNotEqual(pw1, pw2)

    def test_default_length(self):
        from chimera.modules.proto_common import proto_gen_password
        pw = proto_gen_password()
        self.assertTrue(len(pw) >= 12)  # default should be reasonable

    def test_contains_only_safe_chars(self):
        """Пароль содержит только печатные ASCII без неоднозначных символов."""
        from chimera.modules.proto_common import proto_gen_password
        pw = proto_gen_password(50)
        # Не должно содержать пробелы, кавычки, обратный слеш
        for ch in pw:
            self.assertNotIn(ch, ' \'"\\`|;')


class TestProtoCancelled(unittest.TestCase):
    """ProtoCancelled — exception class."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_is_exception(self):
        from chimera.modules.proto_common import ProtoCancelled
        self.assertTrue(issubclass(ProtoCancelled, Exception))

    def test_can_be_raised_and_caught(self):
        from chimera.modules.proto_common import ProtoCancelled
        with self.assertRaises(ProtoCancelled):
            raise ProtoCancelled()


# ══════════════════════════════════════════════════════════════════════════════
#  proto_ipt_rule_exists — проверка наличия iptables-правила через -C
# ══════════════════════════════════════════════════════════════════════════════
class TestProtoIptRuleExists(unittest.TestCase):
    """proto_ipt_rule_exists — проверка наличия iptables-правила.

    РЕГРЕССИЯ: iptables -C возвращает exit status 1 когда правило НЕ существует
    — это норма (man iptables: "If the rule does not exist, the exit code is 1").
    _core._run по умолчанию имеет check=True и бросает CalledProcessError на
    rc=1. Без явного check=False функция падала при открытии TUI-меню Telemt
    если хоть одна TG-подсеть не имела правила (что нормально когда Telemt
    остановлен).

    Тесты проверяют:
      • rc=0 → True (правило существует)
      • rc=1 → False (правило не существует, НЕ бросает исключение)
      • _run бросает исключение → False (defensive, не роняет вызывателя)
      • импорт core падает → False (defensive)
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def _make_completed(self, returncode: int):
        """Создаёт mock CompletedProcess."""
        import subprocess
        return subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout="", stderr="",
        )

    def test_returns_true_when_rule_exists(self):
        """rc=0 → True (правило существует)."""
        from chimera.modules import proto_common
        fake_run = MagicMock(return_value=self._make_completed(0))
        fake_core = MagicMock()
        fake_core._run = fake_run
        with patch.object(proto_common, "_core_module", return_value=fake_core):
            result = proto_common.proto_ipt_rule_exists(
                "nat", "OUTPUT",
                ["-d", "91.105.192.0/23", "-p", "tcp", "-j", "REDIRECT",
                 "--to-port", "10811"],
            )
        self.assertTrue(result)
        # Проверяем что check=False был передан (это ключевая часть фикса).
        fake_run.assert_called_once()
        kwargs = fake_run.call_args.kwargs
        self.assertFalse(kwargs.get("check", True),
                         "check=False ДОЛЖЕН быть передан — иначе rc=1 бросает")

    def test_returns_false_when_rule_not_exists(self):
        """РЕГРЕССИЯ: rc=1 → False (правило не существует), НЕ бросает исключение.

        До фикса _run с check=True бросал CalledProcessError на rc=1.
        """
        from chimera.modules import proto_common
        fake_run = MagicMock(return_value=self._make_completed(1))
        fake_core = MagicMock()
        fake_core._run = fake_run
        with patch.object(proto_common, "_core_module", return_value=fake_core):
            # Не должно бросать — должно вернуть False.
            result = proto_common.proto_ipt_rule_exists(
                "nat", "OUTPUT",
                ["-d", "91.105.192.0/23", "-p", "tcp", "-j", "REDIRECT",
                 "--to-port", "10811"],
            )
        self.assertFalse(result)

    def test_returns_false_on_other_nonzero_rc(self):
        """rc=2 (iptables error) → False, не бросает."""
        from chimera.modules import proto_common
        fake_run = MagicMock(return_value=self._make_completed(2))
        fake_core = MagicMock()
        fake_core._run = fake_run
        with patch.object(proto_common, "_core_module", return_value=fake_core):
            result = proto_common.proto_ipt_rule_exists(
                "filter", "INPUT", ["-p", "udp", "--dport", "56000", "-j", "ACCEPT"],
            )
        self.assertFalse(result)

    def test_returns_false_on_run_exception(self):
        """Если _run бросает исключение (например, iptables не установлен) —
        возвращаем False, не пробрасываем исключение."""
        from chimera.modules import proto_common
        fake_run = MagicMock(side_effect=Exception("iptables not found"))
        fake_core = MagicMock()
        fake_core._run = fake_run
        with patch.object(proto_common, "_core_module", return_value=fake_core):
            # Не должно бросать — defensive try/except.
            result = proto_common.proto_ipt_rule_exists(
                "filter", "INPUT", ["-p", "udp", "--dport", "56000"],
            )
        self.assertFalse(result)

    def test_returns_false_on_core_import_failure(self):
        """Если _core_module() бросает исключение — возвращаем False."""
        from chimera.modules import proto_common
        with patch.object(proto_common, "_core_module",
                          side_effect=Exception("core unavailable")):
            result = proto_common.proto_ipt_rule_exists(
                "filter", "INPUT", ["-p", "udp"],
            )
        self.assertFalse(result)

    def test_passes_correct_args_to_run(self):
        """Проверяем что аргументы передаются корректно: iptables -t <table>
        -C <chain> + args."""
        from chimera.modules import proto_common
        fake_run = MagicMock(return_value=self._make_completed(0))
        fake_core = MagicMock()
        fake_core._run = fake_run
        with patch.object(proto_common, "_core_module", return_value=fake_core):
            proto_common.proto_ipt_rule_exists(
                "nat", "OUTPUT",
                ["-d", "10.0.0.0/8", "-p", "tcp", "-j", "ACCEPT"],
            )
        args = fake_run.call_args.args[0]
        self.assertEqual(args[0], "iptables")
        self.assertEqual(args[1], "-t")
        self.assertEqual(args[2], "nat")
        self.assertEqual(args[3], "-C")
        self.assertEqual(args[4], "OUTPUT")
        self.assertIn("-d", args)
        self.assertIn("10.0.0.0/8", args)

    def test_does_not_crash_telemt_menu_scenario(self):
        """Интеграционный тест: имитируем сценарий из баг-репорта —
        _xray_tproxy_status вызывает _ipt_rule_exists для 19 TG-подсетей,
        ни одна не имеет правила (Telemt остановлен). Раньше первый же
        rc=1 валил весь TUI-меню. Теперь — должно работать."""
        from chimera.modules import proto_common
        # 19 TG-подсетей, ни одной нет правила.
        fake_run = MagicMock(return_value=self._make_completed(1))
        fake_core = MagicMock()
        fake_core._run = fake_run
        with patch.object(proto_common, "_core_module", return_value=fake_core):
            for i in range(19):
                result = proto_common.proto_ipt_rule_exists(
                    "nat", "OUTPUT",
                    ["-d", f"91.105.{i}.0/23", "-p", "tcp",
                     "-j", "REDIRECT", "--to-port", "10811"],
                )
                self.assertFalse(result,
                                 f"Подсеть {i}: должно быть False (правила нет)")
        # 19 вызовов, ни один не бросил — тест прошёл.


if __name__ == "__main__":
    unittest.main(verbosity=2)

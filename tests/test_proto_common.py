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
  6. proto_ipt_persist — делегирование в nft_persist (этап 1.7 миграции)
  7. proto_ipt_rule_exists — извлечение comment и делегирование в nft_rule_exists
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
#  proto_ipt_persist — миграция на nft_persist (этап 1.7)
# ══════════════════════════════════════════════════════════════════════════════
class TestProtoIptPersistNftMigration(unittest.TestCase):
    """proto_ipt_persist — после миграции на nftables (этап 1.7).

    Раньше вызывала `netfilter-persistent save` или `iptables-save > rules.v4`.
    Теперь делегирует в `nft_persist()` из nft_common — сохраняет весь ruleset
    в /etc/nftables.conf через `nft list ruleset`. Также включает
    nftables.service через `nft_persist_enable_systemd`.

    Тесты проверяют:
      • Делегирование в nft_persist (а не в subprocess netfilter-persistent)
      • Делегирование в nft_persist_enable_systemd
      • Silent fallback при ошибке (историческая best-effort семантика)
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_delegates_to_nft_persist(self):
        """proto_ipt_persist вызывает nft_persist из nft_common."""
        from chimera.modules import proto_common
        with patch("chimera.modules.nft_common.nft_persist",
                   return_value=True) as mock_nft_persist, \
             patch("chimera.modules.nft_common.nft_persist_enable_systemd",
                   return_value=True):
            proto_common.proto_ipt_persist()
        mock_nft_persist.assert_called_once()

    def test_delegates_to_nft_persist_enable_systemd(self):
        """proto_ipt_persist также включает nftables.service."""
        from chimera.modules import proto_common
        with patch("chimera.modules.nft_common.nft_persist",
                   return_value=True), \
             patch("chimera.modules.nft_common.nft_persist_enable_systemd",
                   return_value=True) as mock_enable:
            proto_common.proto_ipt_persist()
        mock_enable.assert_called_once()

    def test_silent_on_exception(self):
        """При ошибке nft_persist — не бросает, историческая best-effort семантика."""
        from chimera.modules import proto_common
        with patch("chimera.modules.nft_common.nft_persist",
                   side_effect=Exception("nft not found")):
            # Не должно бросить
            proto_common.proto_ipt_persist()

    def test_does_not_call_netfilter_persistent(self):
        """РЕГРЕССИЯ: proto_ipt_persist больше НЕ вызывает netfilter-persistent."""
        from chimera.modules import proto_common
        with patch("chimera.modules.nft_common.nft_persist",
                   return_value=True), \
             patch("chimera.modules.nft_common.nft_persist_enable_systemd",
                   return_value=True), \
             patch("subprocess.run") as mock_subprocess:
            proto_common.proto_ipt_persist()
        # subprocess.run не должен вызываться для netfilter-persistent.
        for call in mock_subprocess.call_args_list:
            args = call.args[0] if call.args else []
            if args and "netfilter-persistent" in args:
                self.fail("proto_ipt_persist не должен вызывать netfilter-persistent")


# ══════════════════════════════════════════════════════════════════════════════
#  proto_ipt_rule_exists — миграция на nft_rule_exists (этап 1.7)
# ══════════════════════════════════════════════════════════════════════════════
class TestProtoIptRuleExistsNftMigration(unittest.TestCase):
    """proto_ipt_rule_exists — после миграции на nftables (этап 1.7).

    Раньше вызывала `iptables -t {table} -C {chain} {args}` (rc==0 → True).
    Теперь извлекает --comment (или строит comment из proto/port pattern)
    и делегирует в nft_rule_exists(comment=...).

    Тесты проверяют:
      • OPEN_PORT pattern: args=`-p tcp --dport 443 -j ACCEPT` → comment=chimera-open-port-tcp-443
      • --comment explicit: args=`... --comment my-tag` → comment=my-tag
      • NAT REDIRECT pattern: args=`-d NET -p tcp -j REDIRECT --to-port X` → comment=mtproto-tproxy
      • UID RETURN pattern: args=`-m owner --uid-owner 999 -j RETURN` → comment=telemt-tproxy-bypass
      • Unknown pattern → False (defensive)
      • Map iptables chain → nft chain (INPUT → input, OUTPUT → output, etc.)
    """

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_open_port_pattern_builds_comment(self):
        """OPEN_PORT pattern: `-p tcp --dport 443 -j ACCEPT` → comment chimera-open-port-tcp-443."""
        from chimera.modules import proto_common
        with patch("chimera.modules.nft_common.nft_rule_exists",
                   return_value=True) as mock_exists:
            result = proto_common.proto_ipt_rule_exists(
                "filter", "INPUT",
                ["-p", "tcp", "--dport", "443", "-j", "ACCEPT"],
            )
        self.assertTrue(result)
        kwargs = mock_exists.call_args.kwargs
        self.assertEqual(kwargs.get("comment"), "chimera-open-port-tcp-443")
        self.assertEqual(kwargs.get("chain"), "input")
        self.assertEqual(kwargs.get("table"), "chimera")

    def test_open_port_pattern_udp(self):
        """OPEN_PORT UDP pattern: `-p udp --dport 56000 -j ACCEPT` → comment chimera-open-port-udp-56000."""
        from chimera.modules import proto_common
        with patch("chimera.modules.nft_common.nft_rule_exists",
                   return_value=True) as mock_exists:
            proto_common.proto_ipt_rule_exists(
                "filter", "INPUT",
                ["-p", "udp", "--dport", "56000", "-j", "ACCEPT"],
            )
        kwargs = mock_exists.call_args.kwargs
        self.assertEqual(kwargs.get("comment"), "chimera-open-port-udp-56000")

    def test_explicit_comment_extracted(self):
        """Если args содержит `--comment my-tag` — используем именно его."""
        from chimera.modules import proto_common
        with patch("chimera.modules.nft_common.nft_rule_exists",
                   return_value=True) as mock_exists:
            proto_common.proto_ipt_rule_exists(
                "filter", "INPUT",
                ["-p", "tcp", "--dport", "443", "-j", "ACCEPT",
                 "-m", "comment", "--comment", "my-custom-tag"],
            )
        kwargs = mock_exists.call_args.kwargs
        self.assertEqual(kwargs.get("comment"), "my-custom-tag")

    def test_nat_redirect_pattern(self):
        """NAT REDIRECT: `-d NET -p tcp -j REDIRECT --to-port 10811` → comment mtproto-tproxy."""
        from chimera.modules import proto_common
        with patch("chimera.modules.nft_common.nft_rule_exists",
                   return_value=True) as mock_exists:
            proto_common.proto_ipt_rule_exists(
                "nat", "OUTPUT",
                ["-d", "91.108.0.0/16", "-p", "tcp",
                 "-j", "REDIRECT", "--to-port", "10811"],
            )
        kwargs = mock_exists.call_args.kwargs
        self.assertEqual(kwargs.get("comment"), "mtproto-tproxy")
        self.assertEqual(kwargs.get("chain"), "output")

    def test_uid_owner_return_pattern(self):
        """UID RETURN: `-m owner --uid-owner 999 -j RETURN` → comment telemt-tproxy-bypass."""
        from chimera.modules import proto_common
        with patch("chimera.modules.nft_common.nft_rule_exists",
                   return_value=True) as mock_exists:
            proto_common.proto_ipt_rule_exists(
                "nat", "OUTPUT",
                ["-m", "owner", "--uid-owner", "999", "-j", "RETURN"],
            )
        kwargs = mock_exists.call_args.kwargs
        self.assertEqual(kwargs.get("comment"), "telemt-tproxy-bypass")

    def test_me_port_return_pattern(self):
        """ME-port RETURN: `-p tcp --dport 8888 -j RETURN` → comment mtproto-me-return-8888."""
        from chimera.modules import proto_common
        with patch("chimera.modules.nft_common.nft_rule_exists",
                   return_value=True) as mock_exists:
            proto_common.proto_ipt_rule_exists(
                "nat", "OUTPUT",
                ["-p", "tcp", "--dport", "8888", "-j", "RETURN"],
            )
        kwargs = mock_exists.call_args.kwargs
        self.assertEqual(kwargs.get("comment"), "mtproto-me-return-8888")

    def test_unknown_pattern_returns_false(self):
        """Если паттерн не распознан — возвращает False (defensive)."""
        from chimera.modules import proto_common
        with patch("chimera.modules.nft_common.nft_rule_exists",
                   return_value=True) as mock_exists:
            result = proto_common.proto_ipt_rule_exists(
                "filter", "INPUT",
                ["--something-weird", "x"],
            )
        self.assertFalse(result)
        mock_exists.assert_not_called()

    def test_chain_mapping_filter_input(self):
        """Map filter/INPUT → input."""
        from chimera.modules import proto_common
        with patch("chimera.modules.nft_common.nft_rule_exists",
                   return_value=True) as mock_exists:
            proto_common.proto_ipt_rule_exists(
                "filter", "INPUT",
                ["-p", "tcp", "--dport", "443", "-j", "ACCEPT"],
            )
        self.assertEqual(mock_exists.call_args.kwargs.get("chain"), "input")

    def test_chain_mapping_nat_prerouting(self):
        """Map nat/PREROUTING → prerouting."""
        from chimera.modules import proto_common
        with patch("chimera.modules.nft_common.nft_rule_exists",
                   return_value=True) as mock_exists:
            proto_common.proto_ipt_rule_exists(
                "nat", "PREROUTING",
                ["-p", "tcp", "--dport", "8443", "-j", "REDIRECT", "--to-port", "443"],
            )
        self.assertEqual(mock_exists.call_args.kwargs.get("chain"), "prerouting")

    def test_chain_mapping_mangle_prerouting(self):
        """Map mangle/PREROUTING → mangle_forward."""
        from chimera.modules import proto_common
        with patch("chimera.modules.nft_common.nft_rule_exists",
                   return_value=True) as mock_exists:
            proto_common.proto_ipt_rule_exists(
                "mangle", "PREROUTING",
                ["-p", "tcp", "--dport", "8443", "-j", "ACCEPT"],
            )
        self.assertEqual(mock_exists.call_args.kwargs.get("chain"), "mangle_forward")

    def test_returns_false_on_nft_rule_exists_exception(self):
        """Если nft_rule_exists бросает — proto_ipt_rule_exists возвращает False."""
        from chimera.modules import proto_common
        with patch("chimera.modules.nft_common.nft_rule_exists",
                   side_effect=Exception("nft not installed")):
            result = proto_common.proto_ipt_rule_exists(
                "filter", "INPUT",
                ["-p", "tcp", "--dport", "443", "-j", "ACCEPT"],
            )
        self.assertFalse(result)

    def test_returns_false_when_nft_says_not_exists(self):
        """nft_rule_exists возвращает False — проброс False."""
        from chimera.modules import proto_common
        with patch("chimera.modules.nft_common.nft_rule_exists",
                   return_value=False):
            result = proto_common.proto_ipt_rule_exists(
                "filter", "INPUT",
                ["-p", "tcp", "--dport", "443", "-j", "ACCEPT"],
            )
        self.assertFalse(result)

    def test_telemt_menu_scenario_no_crash(self):
        """Интеграционный тест: 19 TG-подсетей, ни одной нет правила.
        Раньше первый же rc=1 валил весь TUI-меню Telemt. Теперь — должно работать
        (nft_rule_exists сам по себе не бросает, returns False)."""
        from chimera.modules import proto_common
        with patch("chimera.modules.nft_common.nft_rule_exists",
                   return_value=False):
            for i in range(19):
                result = proto_common.proto_ipt_rule_exists(
                    "nat", "OUTPUT",
                    ["-d", f"91.105.{i}.0/23", "-p", "tcp",
                     "-j", "REDIRECT", "--to-port", "10811"],
                )
                self.assertFalse(result,
                                 f"Подсеть {i}: должно быть False (правила нет)")
        # 19 вызовов, ни один не бросил — тест прошёл.

    def test_does_not_call_iptables_subprocess(self):
        """РЕГРЕССИЯ: proto_ipt_rule_exists больше НЕ вызывает iptables subprocess."""
        from chimera.modules import proto_common
        with patch("chimera.modules.nft_common.nft_rule_exists",
                   return_value=True), \
             patch("subprocess.run") as mock_subprocess:
            proto_common.proto_ipt_rule_exists(
                "filter", "INPUT",
                ["-p", "tcp", "--dport", "443", "-j", "ACCEPT"],
            )
        # subprocess.run не должен вызываться для iptables -C.
        for call in mock_subprocess.call_args_list:
            args = call.args[0] if call.args else []
            if args and "iptables" in args:
                self.fail("proto_ipt_rule_exists не должен вызывать iptables")


if __name__ == "__main__":
    unittest.main(verbosity=2)

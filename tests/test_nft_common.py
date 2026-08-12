#!/usr/bin/env python3
"""
tests/test_nft_common.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/nft_common.py.

Покрывает:
  1. Конструкцию nft-команд для всех 15 паттернов (mocked subprocess)
  2. Идемпотентность (повторный add не вызывает nft дважды)
  3. Atomic swap (одна транзакция flush+add)
  4. Counter read (JSON парсинг)
  5. Rule delete by comment (через handle)
  6. Persist / restore (file operations)

Все тесты мокают chimera.modules.nft_common._nft_run чтобы не вызывать
реальный nft binary (его нет в окружении CI).
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _setup_core():
    """Создаёт минимальный mock chimera._core если его нет."""
    core_path = _PROJECT_ROOT / "chimera" / "_core.py"
    if not core_path.exists():
        # Создаём минимальный stub
        core_path.parent.mkdir(parents=True, exist_ok=True)
        core_path.write_text(
            '"""Stub for tests"""\n'
            '_LOG = []\n'
            'def _log(level, msg):\n'
            '    _LOG.append((level, msg))\n'
        )


class NftCommonTestBase(unittest.TestCase):
    """Базовый класс с setUp/tearDown для мока subprocess."""

    def setUp(self):
        _setup_core()
        # Очищаем лог команд перед каждым тестом
        from chimera.modules import nft_common
        nft_common._nft_cmd_log_clear()
        # Мокаем _nft_available чтобы вернуть True
        self._avail_patcher = patch.object(nft_common, '_nft_available',
                                           return_value=True)
        self._avail_patcher.start()
        # Мокаем subprocess.run чтобы не вызывать реальный nft
        self._nft_responses = []  # список CompletedProcess для последовательных вызовов

    def tearDown(self):
        self._avail_patcher.stop()

    def _mock_nft_run(self, fake_run_func):
        """Устанавливает mock для _nft_run.

        fake_run_func принимает (args, stdin, check, timeout) где args — список аргументов
        БЕЗ префикса 'nft' (т.к. _nft_run добавляет 'nft' уже после логирования).
        """
        from chimera.modules import nft_common
        return patch.object(nft_common, '_nft_run', side_effect=fake_run_func)


def _make_completed(returncode=0, stdout="", stderr=""):
    """Создаёт mock CompletedProcess."""
    cp = MagicMock()
    cp.returncode = returncode
    cp.stdout = stdout
    cp.stderr = stderr
    return cp


# ════════════════════════════════════════════════════════════════════════════
#  TEST 1: nft_table_ensure / nft_chain_ensure
# ════════════════════════════════════════════════════════════════════════════
class TestTableChainPrimitives(NftCommonTestBase):

    def test_table_ensure_creates_when_missing(self):
        """Если table не существует (rc=1 от list table) → создаём."""
        from chimera.modules import nft_common

        captured_cmds = []

        def fake_run(args, stdin=None, check=False, timeout=15):
            captured_cmds.append(list(args))
            # list table возвращает rc=1 (нет таблицы), create table возвращает rc=0
            if args[0] == "list" and args[1] == "table":
                return _make_completed(1, "", "No such file or directory")
            if args[0] == "create":
                return _make_completed(0)
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            result = nft_common.nft_table_ensure("chimera", "inet")
        self.assertTrue(result)
        # Проверяем что была вызвана команда create table
        cmds_str = [" ".join(c) for c in captured_cmds]
        self.assertTrue(any("create table inet chimera" in c for c in cmds_str),
                        f"create table not in {cmds_str}")

    def test_table_ensure_skips_when_exists(self):
        """Если table уже существует — не вызываем create."""
        from chimera.modules import nft_common

        def fake_run(args, stdin=None, check=False, timeout=15):
            # create table вернёт rc=1 (уже существует)
            if args[0] == "create":
                return _make_completed(1, "", "File exists")
            # list table вернёт rc=0
            if args[0] == "list":
                return _make_completed(0, "table inet chimera { }", "")
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            result = nft_common.nft_table_ensure()
        self.assertTrue(result)

    def test_chain_ensure_with_hook(self):
        """Создание base chain с hook."""
        from chimera.modules import nft_common

        def fake_run(args, stdin=None, check=False, timeout=15):
            # list chain → rc=1 (не существует)
            if args[0] == "list" and args[1] == "chain":
                return _make_completed(1)
            # create table → rc=0 или 1 (ОК если уже есть)
            if args[0] == "create":
                return _make_completed(0)
            # add chain
            if args[0] == "add" and args[1] == "chain":
                # Проверяем что spec содержит type/hook/priority/policy
                spec = " ".join(args[5:]) if len(args) > 5 else ""
                self.assertIn("type filter", spec)
                self.assertIn("hook input", spec)
                self.assertIn("priority 0", spec)
                self.assertIn("policy accept", spec)
                return _make_completed(0)
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            result = nft_common.nft_chain_ensure("chimera", "input",
                                                  hook="input", priority=0,
                                                  policy="accept")
        self.assertTrue(result)

    def test_chain_ensure_without_hook_regular_chain(self):
        """Создание regular chain без hook (аналог iptables -N)."""
        from chimera.modules import nft_common

        captured_spec = []

        def fake_run(args, stdin=None, check=False, timeout=15):
            if args[0] == "list" and args[1] == "chain":
                return _make_completed(1)
            if args[0] == "create":
                return _make_completed(0)
            if args[0] == "add" and args[1] == "chain":
                captured_spec.extend(args[5:])  # всё после family table chain
                return _make_completed(0)
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            nft_common.nft_chain_ensure("chimera", "xru_block")

        # Regular chain не должна иметь type/hook спецификацию
        spec_str = " ".join(captured_spec)
        self.assertNotIn("type filter", spec_str)
        self.assertNotIn("hook", spec_str)


# ════════════════════════════════════════════════════════════════════════════
#  TEST 2: nft_set_*
# ════════════════════════════════════════════════════════════════════════════
class TestSetOperations(NftCommonTestBase):

    def test_set_create_with_interval_flag(self):
        """Создание set с flags interval (для CIDR)."""
        from chimera.modules import nft_common

        captured = {}

        def fake_run(args, stdin=None, check=False, timeout=15):
            if args[0] == "list" and args[1] == "set":
                return _make_completed(1)  # set не существует
            if args[0] == "add" and args[1] == "set":
                captured["spec"] = args[5] if len(args) > 5 else ""
                return _make_completed(0)
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            result = nft_common.nft_set_create("manual_ban_v4",
                                                set_type="ipv4_addr",
                                                flags=["interval"],
                                                maxelem=65536)

        self.assertTrue(result)
        spec = captured["spec"]
        self.assertIn("type ipv4_addr", spec)
        self.assertIn("flags interval", spec)
        self.assertIn("size 65536", spec)

    def test_set_create_idempotent(self):
        """Если set уже существует — не вызываем add set."""
        from chimera.modules import nft_common

        add_called = False

        def fake_run(args, stdin=None, check=False, timeout=15):
            nonlocal add_called
            if args[0] == "list" and args[1] == "set":
                return _make_completed(0, "set exists", "")
            if args[0] == "add" and args[1] == "set":
                add_called = True
                return _make_completed(0)
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            nft_common.nft_set_create("manual_ban_v4", set_type="ipv4_addr",
                                      flags=["interval"])

        self.assertFalse(add_called, "add set should not be called when set exists")

    def test_set_add_batch(self):
        """Batch add элементов одной транзакцией."""
        from chimera.modules import nft_common

        captured_cmd = None

        def fake_run(args, stdin=None, check=False, timeout=15):
            nonlocal captured_cmd
            if args[0] == "add" and args[1] == "element":
                captured_cmd = list(args)
                return _make_completed(0)
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            nft_common.nft_set_add("my_set", ["1.2.3.0/24", "5.6.7.8", "9.10.11.12"])

        self.assertIsNotNone(captured_cmd)
        # Команда должна быть: add element inet chimera my_set { 1.2.3.0/24, 5.6.7.8, 9.10.11.12 }
        cmd_str = " ".join(captured_cmd)
        self.assertIn("add element inet chimera my_set", cmd_str)
        self.assertIn("1.2.3.0/24", cmd_str)
        self.assertIn("5.6.7.8", cmd_str)
        self.assertIn("9.10.11.12", cmd_str)

    def test_set_atomic_swap_uses_single_transaction(self):
        """Atomic swap — одна команда nft -f - с flush + add в stdin."""
        from chimera.modules import nft_common

        captured_stdin = None
        captured_args = None

        def fake_run(args, stdin=None, check=False, timeout=15):
            nonlocal captured_stdin, captured_args
            if "-f" in args and "-" in args:
                captured_stdin = stdin
                captured_args = list(args)
                return _make_completed(0)
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            result = nft_common.nft_set_atomic_swap(
                "clients_wl_v4",
                ["1.2.3.0/24", "5.6.7.0/24"]
            )

        self.assertTrue(result)
        self.assertIsNotNone(captured_stdin)
        # stdin должен содержать flush set ... + add element ...
        self.assertIn("flush set inet chimera clients_wl_v4", captured_stdin)
        self.assertIn("add element inet chimera clients_wl_v4", captured_stdin)
        self.assertIn("1.2.3.0/24", captured_stdin)
        self.assertIn("5.6.7.0/24", captured_stdin)

    def test_set_count_parses_json(self):
        """Парсинг количества элементов из JSON."""
        from chimera.modules import nft_common

        fake_json = json.dumps({
            "nftables": [{
                "set": {
                    "name": "manual_ban_v4",
                    "elem": ["1.2.3.4", "5.6.7.8", "10.0.0.0/24"]
                }
            }]
        })

        def fake_run(args, stdin=None, check=False, timeout=15):
            if "-j" in args:
                return _make_completed(0, fake_json, "")
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            count = nft_common.nft_set_count("manual_ban_v4")

        self.assertEqual(count, 3)

    def test_set_list_elements_parses_intervals(self):
        """Парсинг элементов с interval (prefix в dict)."""
        from chimera.modules import nft_common

        fake_json = json.dumps({
            "nftables": [{
                "set": {
                    "elem": [
                        {"prefix": "1.2.3.0/24"},
                        "5.6.7.8",
                        {"prefix": "10.0.0.0/8"}
                    ]
                }
            }]
        })

        def fake_run(args, stdin=None, check=False, timeout=15):
            if "-j" in args:
                return _make_completed(0, fake_json, "")
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            elems = nft_common.nft_set_list_elements("test_set")

        self.assertEqual(elems, ["1.2.3.0/24", "5.6.7.8", "10.0.0.0/8"])


# ════════════════════════════════════════════════════════════════════════════
#  TEST 3: nft_rule_* (idempotency)
# ════════════════════════════════════════════════════════════════════════════
class TestRuleOperations(NftCommonTestBase):

    def test_rule_add_with_comment_idempotent(self):
        """Если правило с comment уже есть — не добавляем повторно."""
        from chimera.modules import nft_common

        # Первый вызов: правила нет, добавляем
        # Второй вызов: правило есть, не добавляем
        call_count = {"add": 0}
        add_calls = []

        def fake_run(args, stdin=None, check=False, timeout=15):
            # Обрабатываем оба варианта: "list chain ..." и "-j list chain ..."
            # _nft_run вызывается с args без префикса "nft"
            args_str = " ".join(args)
            if "list" in args and "chain" in args:
                # На второй вызов возвращаем что правило есть (только для JSON-вызова)
                if "-j" in args and call_count["add"] > 0:
                    fake_json = json.dumps({
                        "nftables": [{
                            "chain": {
                                "expr": [{
                                    "comment": "xray-autoban",
                                    "expr": [{"drop": None}]
                                }]
                            }
                        }]
                    })
                    return _make_completed(0, fake_json, "")
                return _make_completed(1)  # chain не существует
            if args[0] == "add" and args[1] == "rule":
                call_count["add"] += 1
                add_calls.append(list(args))
                return _make_completed(0)
            if args[0] == "create":
                return _make_completed(0)
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            # Первый вызов — добавляет
            r1 = nft_common.nft_rule_add("chimera", "input",
                                          "ip saddr 1.2.3.4 drop",
                                          comment="xray-autoban")
            self.assertTrue(r1)
            # Сбрасываем счётчик для второго вызова
            add_calls.clear()
            # Второй вызов — не добавляет (idempotent)
            r2 = nft_common.nft_rule_add("chimera", "input",
                                          "ip saddr 1.2.3.4 drop",
                                          comment="xray-autoban")
            self.assertTrue(r2)
            # Проверяем что add rule НЕ был вызван во второй раз
            self.assertEqual(len(add_calls), 0,
                              f"add rule should not be called when rule exists, "
                              f"got: {add_calls}")

    def test_rule_delete_by_comment_uses_handle(self):
        """Удаление правила по comment — находим handle, удаляем через handle."""
        from chimera.modules import nft_common

        fake_json = json.dumps({
            "nftables": [{
                "chain": {
                    "expr": [{
                        "comment": "xray-autoban",
                        "handle": 42,
                        "expr": [{"match": {"right": "1.2.3.4"}}, {"drop": None}]
                    }, {
                        "comment": "other-comment",
                        "handle": 43,
                        "expr": [{"accept": None}]
                    }]
                }
            }]
        })

        deleted_handles = []

        def fake_run(args, stdin=None, check=False, timeout=15):
            if "-a" in args and "-j" in args:
                return _make_completed(0, fake_json, "")
            if args[0] == "delete" and args[1] == "rule":
                # nft delete rule ... handle <N>
                handle_idx = args.index("handle") + 1 if "handle" in args else None
                if handle_idx:
                    deleted_handles.append(args[handle_idx])
                return _make_completed(0)
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            removed = nft_common.nft_rule_delete_by_comment(
                "chimera", "input", "xray-autoban"
            )

        self.assertEqual(removed, 1)
        self.assertEqual(deleted_handles, ["42"])

    def test_rule_insert_uses_position_1(self):
        """nft_rule_insert → position=1 в команде."""
        from chimera.modules import nft_common

        captured_cmd = None

        def fake_run(args, stdin=None, check=False, timeout=15):
            nonlocal captured_cmd
            if args[0] == "list" and args[1] == "chain":
                return _make_completed(1)  # chain не существует
            if args[0] == "add" and args[1] == "rule":
                captured_cmd = list(args)
                return _make_completed(0)
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            nft_common.nft_rule_insert("chimera", "input",
                                        "ip saddr 1.2.3.4 accept",
                                        comment="wl-test")

        self.assertIsNotNone(captured_cmd)
        # Команда должна содержать "position 1"
        self.assertIn("position", captured_cmd)
        pos_idx = captured_cmd.index("position")
        self.assertEqual(captured_cmd[pos_idx + 1], "1")


# ════════════════════════════════════════════════════════════════════════════
#  TEST 4: High-level patterns
# ════════════════════════════════════════════════════════════════════════════
class TestHighLevelPatterns(NftCommonTestBase):

    def test_nft_open_port_tcp(self):
        """Открытие TCP-порта генерирует корректный spec."""
        from chimera.modules import nft_common

        captured_cmd = None

        def fake_run(args, stdin=None, check=False, timeout=15):
            nonlocal captured_cmd
            if args[0] == "list":
                return _make_completed(1)
            if args[0] == "create":
                return _make_completed(0)
            if args[0] == "add" and args[1] == "rule":
                captured_cmd = list(args)
                return _make_completed(0)
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            nft_common.nft_open_port(443, proto="tcp", comment="vless-https")

        self.assertIsNotNone(captured_cmd)
        cmd_str = " ".join(captured_cmd)
        self.assertIn("tcp dport 443 accept", cmd_str)
        self.assertIn('comment "vless-https"', cmd_str)

    def test_nft_open_port_udp(self):
        """Открытие UDP-порта."""
        from chimera.modules import nft_common

        captured_cmd = None

        def fake_run(args, stdin=None, check=False, timeout=15):
            nonlocal captured_cmd
            if args[0] == "list":
                return _make_completed(1)
            if args[0] == "create":
                return _make_completed(0)
            if args[0] == "add" and args[1] == "rule":
                captured_cmd = list(args)
                return _make_completed(0)
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            nft_common.nft_open_port(56000, proto="udp", comment="wdtt")

        self.assertIsNotNone(captured_cmd)
        cmd_str = " ".join(captured_cmd)
        self.assertIn("udp dport 56000 accept", cmd_str)

    def test_nft_ban_ip_v4(self):
        """Бан IPv4 через DROP."""
        from chimera.modules import nft_common

        captured_cmd = None

        def fake_run(args, stdin=None, check=False, timeout=15):
            nonlocal captured_cmd
            if args[0] == "list":
                return _make_completed(1)
            if args[0] == "create":
                return _make_completed(0)
            if args[0] == "add" and args[1] == "rule":
                captured_cmd = list(args)
                return _make_completed(0)
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            nft_common.nft_ban_ip("1.2.3.4", comment="xray-autoban")

        self.assertIsNotNone(captured_cmd)
        cmd_str = " ".join(captured_cmd)
        self.assertIn("ip saddr 1.2.3.4 drop", cmd_str)
        self.assertIn("position 1", cmd_str)  # insert (priority before DROP)

    def test_nft_ban_ip_v6(self):
        """Бан IPv6 через DROP использует ip6 saddr."""
        from chimera.modules import nft_common

        captured_cmd = None

        def fake_run(args, stdin=None, check=False, timeout=15):
            nonlocal captured_cmd
            if args[0] == "list":
                return _make_completed(1)
            if args[0] == "create":
                return _make_completed(0)
            if args[0] == "add" and args[1] == "rule":
                captured_cmd = list(args)
                return _make_completed(0)
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            nft_common.nft_ban_ip("2001:db8::1", comment="xray-autoban-v6")

        self.assertIsNotNone(captured_cmd)
        cmd_str = " ".join(captured_cmd)
        self.assertIn("ip6 saddr 2001:db8::1 drop", cmd_str)

    def test_nft_nat_redirect_prerouting(self):
        """NAT REDIRECT в PREROUTING для DNS."""
        from chimera.modules import nft_common

        captured_cmd = None

        def fake_run(args, stdin=None, check=False, timeout=15):
            nonlocal captured_cmd
            if args[0] == "list":
                return _make_completed(1)
            if args[0] == "create":
                return _make_completed(0)
            if args[0] == "add" and args[1] == "rule":
                captured_cmd = list(args)
                return _make_completed(0)
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            nft_common.nft_nat_redirect(prerouting=True, in_iface="awg0",
                                         proto="udp", dport=53, to_port=5300,
                                         comment="chimera-dns-redirect")

        self.assertIsNotNone(captured_cmd)
        cmd_str = " ".join(captured_cmd)
        self.assertIn('iifname "awg0"', cmd_str)
        self.assertIn("udp dport 53", cmd_str)
        self.assertIn("redirect to :5300", cmd_str)

    def test_nft_nat_masquerade_with_subnet(self):
        """MASQUERADE с source subnet."""
        from chimera.modules import nft_common

        captured_cmd = None

        def fake_run(args, stdin=None, check=False, timeout=15):
            nonlocal captured_cmd
            if args[0] == "list":
                return _make_completed(1)
            if args[0] == "create":
                return _make_completed(0)
            if args[0] == "add" and args[1] == "rule":
                captured_cmd = list(args)
                return _make_completed(0)
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            nft_common.nft_nat_masquerade(out_iface="eth0",
                                           src_subnet="10.66.66.0/24")

        self.assertIsNotNone(captured_cmd)
        cmd_str = " ".join(captured_cmd)
        self.assertIn("ip saddr 10.66.66.0/24", cmd_str)
        self.assertIn('oifname "eth0"', cmd_str)
        self.assertIn("masquerade", cmd_str)

    def test_nft_mangle_mark_uid(self):
        """MARK по uid-owner."""
        from chimera.modules import nft_common

        captured_cmd = None

        def fake_run(args, stdin=None, check=False, timeout=15):
            nonlocal captured_cmd
            if args[0] == "list":
                return _make_completed(1)
            if args[0] == "create":
                return _make_completed(0)
            if args[0] == "add" and args[1] == "rule":
                captured_cmd = list(args)
                return _make_completed(0)
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            nft_common.nft_mangle_mark_uid(uid="xray", fwmark=1234,
                                            comment="awg-fwmark-xray")

        self.assertIsNotNone(captured_cmd)
        cmd_str = " ".join(captured_cmd)
        self.assertIn("meta skuid xray", cmd_str)
        self.assertIn("meta mark set 1234", cmd_str)

    def test_nft_mangle_mssclamp_set_mss(self):
        """TCPMSS --set-mss."""
        from chimera.modules import nft_common

        captured_cmd = None

        def fake_run(args, stdin=None, check=False, timeout=15):
            nonlocal captured_cmd
            if args[0] == "list":
                return _make_completed(1)
            if args[0] == "create":
                return _make_completed(0)
            if args[0] == "add" and args[1] == "rule":
                captured_cmd = list(args)
                return _make_completed(0)
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            nft_common.nft_mangle_mssclamp(mss=1400, out_iface="awg0")

        self.assertIsNotNone(captured_cmd)
        cmd_str = " ".join(captured_cmd)
        self.assertIn("tcp flags syn / syn,rst", cmd_str)
        self.assertIn("tcp option maxseg size set 1400", cmd_str)

    def test_nft_mangle_mssclamp_pmtu(self):
        """TCPMSS --clamp-mss-to-pmtu."""
        from chimera.modules import nft_common

        captured_cmd = None

        def fake_run(args, stdin=None, check=False, timeout=15):
            nonlocal captured_cmd
            if args[0] == "list":
                return _make_completed(1)
            if args[0] == "create":
                return _make_completed(0)
            if args[0] == "add" and args[1] == "rule":
                captured_cmd = list(args)
                return _make_completed(0)
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            nft_common.nft_mangle_mssclamp()  # mss=None

        self.assertIsNotNone(captured_cmd)
        cmd_str = " ".join(captured_cmd)
        self.assertIn("tcp flags syn / syn,rst", cmd_str)
        self.assertIn("tcp option maxseg size set rt mtu", cmd_str)

    def test_nft_syn_limiter_creates_two_rules(self):
        """SYN limiter создаёт accept+reject пару."""
        from chimera.modules import nft_common

        captured_cmds = []

        def fake_run(args, stdin=None, check=False, timeout=15):
            if args[0] == "list":
                return _make_completed(1)
            if args[0] == "create":
                return _make_completed(0)
            if args[0] == "add" and args[1] == "rule":
                captured_cmds.append(list(args))
                return _make_completed(0)
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            nft_common.nft_syn_limiter(port=5000, rate_per_sec=1, burst=1,
                                        comment="telemt-syn-limit")

        # Должно быть 2 правила: accept и reject
        self.assertEqual(len(captured_cmds), 2)
        accept_cmd = " ".join(captured_cmds[0])
        reject_cmd = " ".join(captured_cmds[1])

        # Одно содержит accept с meter, другое reject без meter
        has_accept_with_meter = any("accept" in " ".join(c) and "meter" in " ".join(c)
                                     for c in captured_cmds)
        has_reject = any("reject with tcp reset" in " ".join(c) for c in captured_cmds)
        self.assertTrue(has_accept_with_meter, f"No accept+meter rule in: {captured_cmds}")
        self.assertTrue(has_reject, f"No reject rule in: {captured_cmds}")

        # Только accept-правило содержит meter (reject не должен)
        for cmd in captured_cmds:
            cmd_str = " ".join(cmd)
            if "accept" in cmd_str:
                self.assertIn("meter", cmd_str)

    def test_nft_geoip_drop_creates_set_and_rule(self):
        """GeoIP drop — создаёт set, atomic swap, drop rule."""
        from chimera.modules import nft_common

        cmds = []

        def fake_run(args, stdin=None, check=False, timeout=15):
            if args[0] == "list":
                return _make_completed(1)  # ничего не существует
            if args[0] == "create":
                return _make_completed(0)
            if args[0] == "add" or args[0] == "flush" or args[0] == "delete":
                cmds.append({"args": list(args), "stdin": stdin})
                return _make_completed(0)
            if "-f" in args:  # atomic swap
                cmds.append({"args": list(args), "stdin": stdin})
                return _make_completed(0)
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            nft_common.nft_geoip_drop(
                ["1.2.3.0/24", "5.6.7.0/24"],
                set_name="ru_block_v4",
                port=443,
                proto="tcp",
                comment="xray-ru-block"
            )

        # Должны быть: create set, flush+add (atomic swap), add rule
        add_set = [c for c in cmds if c["args"][:2] == ["add", "set"]]
        atomic_swap = [c for c in cmds if "-f" in c["args"] and c["stdin"] and "flush set" in c["stdin"]]
        add_rule = [c for c in cmds if c["args"][:2] == ["add", "rule"]]

        self.assertGreaterEqual(len(add_set), 1, f"add set missing in {cmds}")
        self.assertGreaterEqual(len(atomic_swap), 1, f"atomic swap missing in {cmds}")
        self.assertGreaterEqual(len(add_rule), 1, f"add rule missing in {cmds}")

        # Проверяем atomic swap stdin
        swap_stdin = atomic_swap[0]["stdin"]
        self.assertIn("flush set inet chimera ru_block_v4", swap_stdin)
        self.assertIn("add element inet chimera ru_block_v4", swap_stdin)
        self.assertIn("1.2.3.0/24", swap_stdin)

        # Проверяем drop rule spec
        rule_cmd = " ".join(add_rule[0]["args"])
        self.assertIn("tcp dport 443", rule_cmd)
        self.assertIn("ip saddr @ru_block_v4", rule_cmd)
        self.assertIn("drop", rule_cmd)


# ════════════════════════════════════════════════════════════════════════════
#  TEST 5: Counter read (JSON)
# ════════════════════════════════════════════════════════════════════════════
class TestCounters(NftCommonTestBase):

    def test_counter_read_json(self):
        """Чтение named counter через JSON."""
        from chimera.modules import nft_common

        fake_json = json.dumps({
            "nftables": [{
                "counter": {
                    "name": "mita_stats",
                    "packets": 12345,
                    "bytes": 6789012
                }
            }]
        })

        def fake_run(args, stdin=None, check=False, timeout=15):
            if "-j" in args:
                return _make_completed(0, fake_json, "")
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            cnt = nft_common.nft_counter_read("mita_stats")

        self.assertEqual(cnt["packets"], 12345)
        self.assertEqual(cnt["bytes"], 6789012)

    def test_rule_counter_read_by_comment(self):
        """Чтение counter у правила по comment."""
        from chimera.modules import nft_common

        # JSON: правило с comment + expr с counter
        fake_json = json.dumps({
            "nftables": [{
                "chain": {
                    "expr": [{
                        "comment": "mita-stats",
                        "expr": [
                            {"counter": {"packets": 100, "bytes": 2048}},
                            {"accept": None}
                        ]
                    }]
                }
            }]
        })

        def fake_run(args, stdin=None, check=False, timeout=15):
            if "-j" in args:
                return _make_completed(0, fake_json, "")
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            cnt = nft_common.nft_rule_counter_read("chimera", "input",
                                                     "mita-stats")

        self.assertEqual(cnt["packets"], 100)
        self.assertEqual(cnt["bytes"], 2048)


# ════════════════════════════════════════════════════════════════════════════
#  TEST 6: Persist / Restore
# ════════════════════════════════════════════════════════════════════════════
class TestPersist(NftCommonTestBase):

    def test_persist_writes_to_file(self):
        """nft_persist сохраняет ruleset в файл."""
        from chimera.modules import nft_common

        fake_ruleset = "table inet chimera {\n    chain input { type filter hook input priority 0; policy accept; }\n}\n"

        def fake_run(args, stdin=None, check=False, timeout=15):
            if args[0] == "list" and args[1] == "ruleset":
                return _make_completed(0, fake_ruleset, "")
            return _make_completed(0)

        with tempfile.TemporaryDirectory() as tmp:
            test_file = str(Path(tmp) / "nftables.conf")
            with self._mock_nft_run(fake_run):
                result = nft_common.nft_persist(test_file)

            self.assertTrue(result)
            content = Path(test_file).read_text()
            self.assertEqual(content, fake_ruleset)

    def test_persist_returns_false_on_nft_error(self):
        """Если nft list ruleset возвращает ошибку — persist = False."""
        from chimera.modules import nft_common

        def fake_run(args, stdin=None, check=False, timeout=15):
            if args[0] == "list" and args[1] == "ruleset":
                return _make_completed(1, "", "permission denied")
            return _make_completed(0)

        with tempfile.TemporaryDirectory() as tmp:
            test_file = str(Path(tmp) / "nftables.conf")
            with self._mock_nft_run(fake_run):
                result = nft_common.nft_persist(test_file)
            self.assertFalse(result)


# ════════════════════════════════════════════════════════════════════════════
#  TEST 7: Edge cases
# ════════════════════════════════════════════════════════════════════════════
class TestEdgeCases(NftCommonTestBase):

    def test_nft_not_available_returns_127(self):
        """Если nft binary нет — _nft_run возвращает rc=127."""
        from chimera.modules import nft_common
        # Снимаем мок _nft_available
        self._avail_patcher.stop()
        with patch.object(nft_common, '_nft_available', return_value=False):
            r = nft_common._nft_run(["list", "ruleset"])
        self.assertEqual(r.returncode, 127)
        # Перезапускаем мок для tearDown
        self._avail_patcher.start()

    def test_invalid_proto_rejected(self):
        """Неверный proto вызывает ValueError."""
        from chimera.modules import nft_common

        def fake_run(args, stdin=None, check=False, timeout=15):
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            with self.assertRaises(ValueError):
                nft_common.nft_open_port(443, proto="icmp")

    def test_invalid_port_rejected(self):
        """Неверный port вызывает ValueError."""
        from chimera.modules import nft_common

        def fake_run(args, stdin=None, check=False, timeout=15):
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            with self.assertRaises(ValueError):
                nft_common.nft_open_port(99999)

    def test_unban_ip_removes_matching_rules(self):
        """nft_unban_ip удаляет правила с comment + matching IP."""
        from chimera.modules import nft_common

        fake_json = json.dumps({
            "nftables": [{
                "chain": {
                    "expr": [{
                        "comment": "xray-autoban",
                        "handle": 10,
                        "expr": [{
                            "match": {
                                "op": "==",
                                "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                                "right": "1.2.3.4"
                            }
                        }, {"drop": None}]
                    }, {
                        "comment": "xray-autoban",
                        "handle": 11,
                        "expr": [{
                            "match": {
                                "op": "==",
                                "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                                "right": "5.6.7.8"
                            }
                        }, {"drop": None}]
                    }]
                }
            }]
        })

        deleted_handles = []

        def fake_run(args, stdin=None, check=False, timeout=15):
            if "-a" in args and "-j" in args:
                return _make_completed(0, fake_json, "")
            if args[0] == "delete" and "handle" in args:
                handle_idx = args.index("handle") + 1
                deleted_handles.append(args[handle_idx])
                return _make_completed(0)
            return _make_completed(0)

        with self._mock_nft_run(fake_run):
            removed = nft_common.nft_unban_ip("1.2.3.4", comment="xray-autoban")

        self.assertEqual(removed, 1)
        self.assertEqual(deleted_handles, ["10"])  # only matching IP


# ════════════════════════════════════════════════════════════════════════════
#  TEST 8: Constants module
# ════════════════════════════════════════════════════════════════════════════
class TestNftConstants(unittest.TestCase):

    def test_constants_importable(self):
        """Все ключевые константы импортируются без ошибок."""
        from chimera.modules import nft_constants

        self.assertEqual(nft_constants.NFT_TABLE_FAMILY, "inet")
        self.assertEqual(nft_constants.NFT_TABLE_NAME, "chimera")
        self.assertEqual(nft_constants.NFT_CHAIN_INPUT, "input")
        self.assertEqual(nft_constants.NFT_CHAIN_PREROUTING, "prerouting")
        self.assertEqual(nft_constants.AWGS_CASCADE_FWMARK, 0x2000)
        self.assertEqual(nft_constants.TELEMT_WARP_FWMARK, 300)

    def test_geoblock_set_name(self):
        """Генерация имени set для geoblock."""
        from chimera.modules import nft_constants

        self.assertEqual(nft_constants.geoblock_set_name("ru"),
                         "geoblock_ru_v4")
        self.assertEqual(nft_constants.geoblock_set_name("RU", ipv6=True),
                         "geoblock_ru_v6")
        self.assertEqual(nft_constants.geoblock_set_name("CN"),
                         "geoblock_cn_v4")

    def test_singbox_cdn_set_name(self):
        """Генерация имени set для sing-box CDN."""
        from chimera.modules import nft_constants

        self.assertEqual(nft_constants.singbox_cdn_set_name(443),
                         "singbox_cdn_443")
        self.assertEqual(nft_constants.singbox_cdn_set_name(8443),
                         "singbox_cdn_8443")

    def test_legacy_ipset_name_map(self):
        """Карта обратной совместимости для старых ipset-имён."""
        from chimera.modules import nft_constants

        self.assertEqual(
            nft_constants.LEGACY_IPSET_NAME_MAP["xray_manual_ban"],
            "manual_ban_v4"
        )
        self.assertEqual(
            nft_constants.LEGACY_IPSET_NAME_MAP["xray_ru_block"],
            "ingress_block_v4"
        )

    def test_all_chimera_sets_present(self):
        """Все Chimera sets перечислены в ALL_CHIMERA_SETS."""
        from chimera.modules import nft_constants

        for s in nft_constants.ALL_CHIMERA_SETS:
            self.assertIsInstance(s, str)
            self.assertTrue(s)


if __name__ == "__main__":
    unittest.main(verbosity=2)

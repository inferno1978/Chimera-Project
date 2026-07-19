#!/usr/bin/env python3
"""
tests/test_snell_stats.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/snell_stats.py — per-user traffic accounting
через iptables chains SNELL_STATS_IN / SNELL_STATS_OUT.

Покрывает:
  1. Константы (CHAIN_IN, CHAIN_OUT, COMMENT_PREFIX_RX, etc.)
  2. _run — локальный subprocess.run wrapper
  3. _ipt_chain_exists, _ensure_chains — управление цепочками
  4. _rule_exists, _add_user_rule, _del_user_rule — per-user правила
  5. setup_user_accounting, teardown_user_accounting, teardown_all_accounting
  6. get_user_traffic, get_all_users_traffic — чтение счётчиков
  7. Snapshot в JSON (snapshot_to_file, load_snapshot)

Все тесты мокают subprocess.run чтобы не запускать реальные iptables.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


def _make_completed(stdout: str = "", returncode: int = 0):
    """Создаёт mock CompletedProcess для имитации iptables-вывода."""
    return subprocess.CompletedProcess(
        args=[], returncode=returncode,
        stdout=stdout, stderr="",
    )


class TestConstants(unittest.TestCase):
    """Константы модуля — имена цепочек, префиксы."""

    def test_chain_names(self):
        from chimera.modules import snell_stats
        self.assertEqual(snell_stats.CHAIN_IN, "SNELL_STATS_IN")
        self.assertEqual(snell_stats.CHAIN_OUT, "SNELL_STATS_OUT")

    def test_comment_prefix(self):
        from chimera.modules import snell_stats
        self.assertEqual(snell_stats.COMMENT_PREFIX_RX, "snell-")
        self.assertEqual(snell_stats.COMMENT_SUFFIX_RX, "-rx")
        self.assertEqual(snell_stats.COMMENT_SUFFIX_TX, "-tx")

    def test_stats_file_path(self):
        from chimera.modules import snell_stats
        self.assertEqual(snell_stats.STATS_FILE,
                         Path("/var/lib/xray-installer/snell_stats.json"))

    def test_cron_file_path(self):
        from chimera.modules import snell_stats
        self.assertEqual(snell_stats.CRON_FILE,
                         Path("/etc/cron.d/snell-stats"))


class TestRunHelper(unittest.TestCase):
    """_run — локальный subprocess.run wrapper."""

    def test_returns_completed_process(self):
        from chimera.modules.snell_stats import _run
        with patch("subprocess.run",
                   return_value=_make_completed("ok", 0)):
            r = _run(["echo", "ok"], capture=True)
        self.assertEqual(r.stdout, "ok")
        self.assertEqual(r.returncode, 0)

    def test_returns_127_on_file_not_found(self):
        """Если команды нет (FileNotFoundError) — returncode=127."""
        from chimera.modules.snell_stats import _run
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            r = _run(["nonexistent-cmd"], capture=True)
        self.assertEqual(r.returncode, 127)


class TestChainManagement(unittest.TestCase):
    """_ipt_chain_exists, _ensure_chains — управление цепочками."""

    def test_chain_exists_true_when_iptables_succeeds(self):
        from chimera.modules import snell_stats
        with patch("subprocess.run",
                   return_value=_make_completed("Chain SNELL_STATS_IN", 0)):
            self.assertTrue(snell_stats._ipt_chain_exists("SNELL_STATS_IN"))

    def test_chain_exists_false_when_iptables_fails(self):
        from chimera.modules import snell_stats
        with patch("subprocess.run",
                   return_value=_make_completed("", 1)):
            self.assertFalse(snell_stats._ipt_chain_exists("SNELL_STATS_IN"))

    def test_ensure_chains_creates_missing(self):
        """Если цепочки нет — _ensure_chains создаёт через iptables -N."""
        from chimera.modules import snell_stats
        calls = []
        def fake_run(cmd, **kw):
            calls.append(cmd)
            # Первый вызов (-L) — не существует (rc=1), второй (-N) — успех.
            if "-L" in cmd:
                return _make_completed("", 1)
            return _make_completed("", 0)
        with patch("subprocess.run", side_effect=fake_run):
            snell_stats._ensure_chains()
        # Должно быть 4 вызова: -L + -N для каждой из 2 цепочек.
        self.assertEqual(len(calls), 4)
        # Проверяем что были -N вызовы.
        n_calls = [c for c in calls if "-N" in c]
        self.assertEqual(len(n_calls), 2)

    def test_ensure_chains_skips_existing(self):
        """Если цепочка уже есть — не создаём повторно."""
        from chimera.modules import snell_stats
        calls = []
        def fake_run(cmd, **kw):
            calls.append(cmd)
            return _make_completed("Chain exists", 0)  # -L успешно
        with patch("subprocess.run", side_effect=fake_run):
            snell_stats._ensure_chains()
        # Только 2 вызова -L (по одной на цепочку), без -N.
        self.assertEqual(len(calls), 2)
        self.assertTrue(all("-L" in c for c in calls))


class TestUserRules(unittest.TestCase):
    """_rule_exists, _add_user_rule, _del_user_rule — per-user правила."""

    def test_rule_exists_true(self):
        from chimera.modules import snell_stats
        with patch("subprocess.run",
                   return_value=_make_completed("", 0)):
            self.assertTrue(snell_stats._rule_exists(
                "SNELL_STATS_IN", 30001, "in", "alice"))

    def test_rule_exists_false(self):
        from chimera.modules import snell_stats
        with patch("subprocess.run",
                   return_value=_make_completed("", 1)):
            self.assertFalse(snell_stats._rule_exists(
                "SNELL_STATS_IN", 30001, "in", "alice"))

    def test_add_user_rule_skips_existing(self):
        """Если правило уже есть — не добавляем повторно."""
        from chimera.modules import snell_stats
        with patch("subprocess.run",
                   return_value=_make_completed("", 0)):  # exists
            with patch.object(snell_stats, "_rule_exists", return_value=True):
                with patch.object(snell_stats, "_run") as mock_run:
                    snell_stats._add_user_rule(
                        "SNELL_STATS_IN", 30001, "in", "alice")
        mock_run.assert_not_called()  # не должно быть iptables -A

    def test_add_user_rule_adds_when_missing(self):
        """Если правила нет — добавляем через iptables -A."""
        from chimera.modules import snell_stats
        with patch.object(snell_stats, "_rule_exists", return_value=False):
            with patch.object(snell_stats, "_run") as mock_run:
                snell_stats._add_user_rule(
                    "SNELL_STATS_IN", 30001, "in", "alice")
        mock_run.assert_called_once()
        cmd = mock_run.call_args.args[0]
        self.assertIn("-A", cmd)
        self.assertIn("SNELL_STATS_IN", cmd)
        self.assertIn("30001", cmd)
        self.assertIn("snell-alice-rx", cmd)  # comment tag

    def test_del_user_rule_loops_until_gone(self):
        """_del_user_rule удаляет в цикле — на случай дубликатов."""
        from chimera.modules import snell_stats
        call_count = [0]
        def fake_run(cmd, **kw):
            call_count[0] += 1
            # Первые 2 вызова — успех (rc=0, удалили), 3-й — неудача (правил больше нет).
            if call_count[0] <= 2:
                return _make_completed("", 0)
            return _make_completed("", 1)
        with patch.object(snell_stats, "_run", side_effect=fake_run):
            snell_stats._del_user_rule(
                "SNELL_STATS_IN", 30001, "in", "alice")
        # Должно быть 3 вызова (2 успеха + 1 неудача для выхода из цикла).
        self.assertEqual(call_count[0], 3)

    def test_del_user_rule_no_loop_when_never_existed(self):
        """Если правила не было — один вызов -D с неудачей, выход."""
        from chimera.modules import snell_stats
        with patch.object(snell_stats, "_run",
                          return_value=_make_completed("", 1)):
            snell_stats._del_user_rule(
                "SNELL_STATS_IN", 30001, "in", "alice")
        # Один вызов -D, rc=1 → выход из цикла.


class TestSetupUserAccounting(unittest.TestCase):
    """setup_user_accounting — публичная функция для регистрации юзера."""

    def test_returns_true_on_success(self):
        from chimera.modules import snell_stats
        with patch.object(snell_stats, "_ensure_chains"), \
             patch.object(snell_stats, "_ensure_jumps"), \
             patch.object(snell_stats, "_add_user_rule"), \
             patch.object(snell_stats, "_setup_cron"), \
             patch.object(snell_stats, "_persist_accounting_rules"):
            result = snell_stats.setup_user_accounting("alice", 30001)
        self.assertTrue(result)

    def test_returns_false_on_exception(self):
        from chimera.modules import snell_stats
        with patch.object(snell_stats, "_ensure_chains",
                          side_effect=Exception("test")):
            result = snell_stats.setup_user_accounting("alice", 30001)
        self.assertFalse(result)


class TestTeardownUserAccounting(unittest.TestCase):
    """teardown_user_accounting — удаление per-user правил."""

    def test_returns_true_on_success(self):
        from chimera.modules import snell_stats
        with patch.object(snell_stats, "_del_user_rule"), \
             patch.object(snell_stats, "_persist_accounting_rules"):
            result = snell_stats.teardown_user_accounting("alice", 30001)
        self.assertTrue(result)

    def test_returns_true_even_if_no_rules(self):
        """Если правил не было — это не ошибка, возвращаем True."""
        from chimera.modules import snell_stats
        with patch.object(snell_stats, "_del_user_rule"), \
             patch.object(snell_stats, "_persist_accounting_rules"):
            result = snell_stats.teardown_user_accounting("alice", 30001)
        self.assertTrue(result)


class TestTeardownAllAccounting(unittest.TestCase):
    """teardown_all_accounting — полный демонтаж при удалении Snell."""

    def test_removes_jumps_and_chains(self):
        from chimera.modules import snell_stats
        with patch.object(snell_stats, "_jump_exists", return_value=True), \
             patch.object(snell_stats, "_ipt_chain_exists", return_value=True), \
             patch.object(snell_stats, "_run", return_value=_make_completed("", 0)), \
             patch.object(snell_stats, "_persist_accounting_rules"), \
             patch("pathlib.Path.exists", return_value=False):
            result = snell_stats.teardown_all_accounting()
        self.assertTrue(result)

    def test_removes_cron_file_if_exists(self):
        from chimera.modules import snell_stats
        with patch.object(snell_stats, "_jump_exists", return_value=False), \
             patch.object(snell_stats, "_ipt_chain_exists", return_value=False), \
             patch.object(snell_stats, "_persist_accounting_rules"), \
             patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.unlink") as mock_unlink:
                snell_stats.teardown_all_accounting()
                mock_unlink.assert_called_once()


class TestGetUserTraffic(unittest.TestCase):
    """get_user_traffic — чтение per-user счётчиков."""

    def test_returns_zero_when_chain_empty(self):
        from chimera.modules import snell_stats
        with patch.object(snell_stats, "_read_chain_bytes", return_value=0):
            result = snell_stats.get_user_traffic("alice")
        self.assertEqual(result["bytes_in"], 0)
        self.assertEqual(result["bytes_out"], 0)
        self.assertEqual(result["total_bytes"], 0)

    def test_returns_correct_values(self):
        from chimera.modules import snell_stats
        # Мокаем: для rx-тега возвращаем 1024, для tx — 2048.
        def fake_read(chain, comment):
            if "rx" in comment:
                return 1024
            if "tx" in comment:
                return 2048
            return 0
        with patch.object(snell_stats, "_read_chain_bytes",
                          side_effect=fake_read):
            result = snell_stats.get_user_traffic("alice")
        self.assertEqual(result["bytes_in"], 1024)
        self.assertEqual(result["bytes_out"], 2048)
        self.assertEqual(result["total_bytes"], 3072)

    def test_handles_exception_gracefully(self):
        """Если iptables падает — возвращаем нули, не пробрасываем exception."""
        from chimera.modules import snell_stats
        with patch.object(snell_stats, "_read_chain_bytes",
                          side_effect=Exception("test")):
            result = snell_stats.get_user_traffic("alice")
        self.assertEqual(result["bytes_in"], 0)
        self.assertEqual(result["bytes_out"], 0)
        self.assertEqual(result["total_bytes"], 0)


class TestReadChainBytes(unittest.TestCase):
    """_read_chain_bytes — парсинг вывода iptables -L."""

    def test_parses_bytes_from_correct_comment(self):
        from chimera.modules import snell_stats
        # Реальный пример вывода iptables -L -v -n -x:
        iptables_output = (
            "Chain SNELL_STATS_IN (1 references)\n"
            "    pkts      bytes target     prot opt in     out     source               destination\n"
            "      10     1024 RETURN     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:30001 /* snell-alice-rx */\n"
            "      20     2048 RETURN     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:30002 /* snell-bob-rx */\n"
        )
        with patch.object(snell_stats, "_run",
                          return_value=_make_completed(iptables_output, 0)):
            bytes_alice = snell_stats._read_chain_bytes(
                "SNELL_STATS_IN", "snell-alice-rx")
            bytes_bob = snell_stats._read_chain_bytes(
                "SNELL_STATS_IN", "snell-bob-rx")
        self.assertEqual(bytes_alice, 1024)
        self.assertEqual(bytes_bob, 2048)

    def test_returns_zero_when_comment_not_found(self):
        from chimera.modules import snell_stats
        iptables_output = (
            "Chain SNELL_STATS_IN (1 references)\n"
            "    pkts      bytes target     prot opt in     out     source               destination\n"
            "      10     1024 RETURN     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:30001 /* snell-alice-rx */\n"
        )
        with patch.object(snell_stats, "_run",
                          return_value=_make_completed(iptables_output, 0)):
            result = snell_stats._read_chain_bytes(
                "SNELL_STATS_IN", "snell-charlie-rx")
        self.assertEqual(result, 0)

    def test_returns_zero_on_iptables_failure(self):
        from chimera.modules import snell_stats
        with patch.object(snell_stats, "_run",
                          return_value=_make_completed("", 1)):
            result = snell_stats._read_chain_bytes(
                "SNELL_STATS_IN", "snell-alice-rx")
        self.assertEqual(result, 0)


class TestGetAllUsersTraffic(unittest.TestCase):
    """get_all_users_traffic — чтение всех счётчиков одним проходом."""

    def test_returns_dict_with_all_users(self):
        from chimera.modules import snell_stats
        with patch.object(snell_stats, "_read_chain_all",
                          side_effect=lambda chain, suffix: {
                              "alice": 1024, "bob": 2048,
                          } if "IN" in chain else {
                              "alice": 512, "bob": 1024,
                          }):
            result = snell_stats.get_all_users_traffic()
        self.assertIn("alice", result)
        self.assertIn("bob", result)
        self.assertEqual(result["alice"]["bytes_in"], 1024)
        self.assertEqual(result["alice"]["bytes_out"], 512)
        self.assertEqual(result["alice"]["total_bytes"], 1536)
        self.assertEqual(result["bob"]["total_bytes"], 3072)

    def test_handles_exception_gracefully(self):
        from chimera.modules import snell_stats
        with patch.object(snell_stats, "_read_chain_all",
                          side_effect=Exception("test")):
            result = snell_stats.get_all_users_traffic()
        self.assertEqual(result, {})


class TestSnapshotFile(unittest.TestCase):
    """snapshot_to_file / load_snapshot — долгосрочное хранение."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_snapshot_writes_json(self):
        from chimera.modules import snell_stats
        snapshot_path = self._tmpdir / "snell_stats.json"
        with patch.object(snell_stats, "STATS_FILE", snapshot_path), \
             patch.object(snell_stats, "get_all_users_traffic",
                          return_value={"alice": {"bytes_in": 1024,
                                                  "bytes_out": 512,
                                                  "total_bytes": 1536}}):
            ok = snell_stats.snapshot_to_file()
        self.assertTrue(ok)
        self.assertTrue(snapshot_path.exists())
        data = json.loads(snapshot_path.read_text())
        self.assertIn("alice", data)

    def test_load_snapshot_returns_dict(self):
        from chimera.modules import snell_stats
        snapshot_path = self._tmpdir / "snell_stats.json"
        snapshot_path.write_text(json.dumps({"alice": {"bytes_in": 100}}))
        with patch.object(snell_stats, "STATS_FILE", snapshot_path):
            result = snell_stats.load_snapshot()
        self.assertEqual(result["alice"]["bytes_in"], 100)

    def test_load_snapshot_returns_empty_when_no_file(self):
        from chimera.modules import snell_stats
        snapshot_path = self._tmpdir / "nonexistent.json"
        with patch.object(snell_stats, "STATS_FILE", snapshot_path):
            result = snell_stats.load_snapshot()
        self.assertEqual(result, {})

    def test_load_snapshot_handles_corrupt_json(self):
        from chimera.modules import snell_stats
        snapshot_path = self._tmpdir / "corrupt.json"
        snapshot_path.write_text("{invalid json}")
        with patch.object(snell_stats, "STATS_FILE", snapshot_path):
            result = snell_stats.load_snapshot()
        self.assertEqual(result, {})


class TestSetupCron(unittest.TestCase):
    """_setup_cron — создание cron-файла для ночного сброса."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_creates_cron_file(self):
        from chimera.modules import snell_stats
        cron_path = self._tmpdir / "snell-stats"
        with patch.object(snell_stats, "CRON_FILE", cron_path), \
             patch("pathlib.Path.exists", return_value=False):
            snell_stats._setup_cron()
        self.assertTrue(cron_path.exists())
        content = cron_path.read_text()
        self.assertIn("iptables -Z", content)
        self.assertIn("SNELL_STATS_IN", content)
        self.assertIn("SNELL_STATS_OUT", content)

    def test_skips_if_already_exists(self):
        from chimera.modules import snell_stats
        cron_path = self._tmpdir / "snell-stats"
        cron_path.write_text("existing cron content")
        with patch.object(snell_stats, "CRON_FILE", cron_path), \
             patch("pathlib.Path.exists", return_value=True):
            snell_stats._setup_cron()
        # Содержимое не должно измениться.
        self.assertEqual(cron_path.read_text(), "existing cron content")


if __name__ == "__main__":
    unittest.main(verbosity=2)

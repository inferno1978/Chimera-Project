#!/usr/bin/env python3
"""
tests/test_mtproto_stats.py
───────────────────────────────────────────────────────────────────────────────
Unit-тесты для chimera/modules/mtproto_stats.py.

Модуль имеет try/except ImportError для импорта из mtproto.py —
если mtproto.py недоступен, использует собственные fallback-реализации.
Тестируем через public API независимо от ветки (parent vs fallback).

Покрывает:
  1. _fmt_bytes — форматирование байт (KiB/MiB/...)
  2. _today / _now_str — дата/время
  3. _get_port — чтение порта из telemt.toml
  4. _load_users — парсинг TOML [access.users]
  5. _load_stats / _save_stats — JSON I/O
  6. _parse_journal — парсинг journalctl (mocked _run)
  7. _collect — обновление статистики (mocked iptables + journalctl)
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime
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


class TestFmtBytes(unittest.TestCase):
    """_fmt_bytes — форматирование (B, KiB, MiB, ...)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_zero(self):
        from chimera.modules.mtproto_stats import _fmt_bytes
        self.assertEqual(_fmt_bytes(0), "0 B")

    def test_less_than_kib(self):
        from chimera.modules.mtproto_stats import _fmt_bytes
        self.assertEqual(_fmt_bytes(500), "500 B")

    def test_kib(self):
        from chimera.modules.mtproto_stats import _fmt_bytes
        self.assertEqual(_fmt_bytes(1024), "1.0 KiB")

    def test_mib(self):
        from chimera.modules.mtproto_stats import _fmt_bytes
        self.assertEqual(_fmt_bytes(1024 ** 2), "1.0 MiB")

    def test_gib(self):
        from chimera.modules.mtproto_stats import _fmt_bytes
        self.assertEqual(_fmt_bytes(1024 ** 3), "1.0 GiB")

    def test_petabytes_fallback(self):
        from chimera.modules.mtproto_stats import _fmt_bytes
        result = _fmt_bytes(1024 ** 5)
        self.assertIn("PiB", result)


class TestTodayNowStr(unittest.TestCase):
    """_today / _now_str."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def test_today_format(self):
        from chimera.modules.mtproto_stats import _today
        result = _today()
        # YYYY-MM-DD
        self.assertRegex(result, r"^\d{4}-\d{2}-\d{2}$")
        # парсится
        datetime.strptime(result, "%Y-%m-%d")

    def test_now_str_format(self):
        from chimera.modules.mtproto_stats import _now_str
        result = _now_str()
        # YYYY-MM-DD HH:MM:SS
        self.assertRegex(result, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
        datetime.strptime(result, "%Y-%m-%d %H:%M:%S")


class TestGetPort(unittest.TestCase):
    """_get_port — чтение порта из CONFIG_FILE."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "telemt.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.mtproto_stats.CONFIG_FILE",
                     self._cfg)

    def test_returns_default_when_no_file(self):
        from chimera.modules.mtproto_stats import _get_port
        with self._patch():
            self.assertEqual(_get_port(), 8443)

    def test_returns_port_from_file(self):
        from chimera.modules.mtproto_stats import _get_port
        self._cfg.write_text('port = 9999\n')
        with self._patch():
            self.assertEqual(_get_port(), 9999)

    def test_returns_default_when_no_port_in_file(self):
        from chimera.modules.mtproto_stats import _get_port
        self._cfg.write_text('other_setting = "x"\n')
        with self._patch():
            self.assertEqual(_get_port(), 8443)

    def test_handles_internal_whitespace(self):
        r"""Regex ^port\s*=\s*(\d+) — допускает пробелы вокруг =, но не в начале строки."""
        from chimera.modules.mtproto_stats import _get_port
        self._cfg.write_text('port   =   7777\n')
        with self._patch():
            self.assertEqual(_get_port(), 7777)


class TestLoadUsers(unittest.TestCase):
    """_load_users — парсинг TOML [access.users] секции."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "telemt.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.mtproto_stats.CONFIG_FILE",
                     self._cfg)

    def test_returns_empty_when_no_file(self):
        from chimera.modules.mtproto_stats import _load_users
        with self._patch():
            self.assertEqual(_load_users(), {})

    def test_parses_users_section(self):
        from chimera.modules.mtproto_stats import _load_users
        self._cfg.write_text(
            'port = 8443\n'
            '\n'
            '[access.users]\n'
            'alice = "abcdef0123456789abcdef0123456789"\n'
            'bob = "fedcba9876543210fedcba9876543210"\n'
        )
        with self._patch():
            users = _load_users()
        self.assertEqual(len(users), 2)
        self.assertIn("alice", users)
        self.assertIn("bob", users)

    def test_ignores_other_sections(self):
        """Только [access.users] парсится, не другие секции."""
        from chimera.modules.mtproto_stats import _load_users
        self._cfg.write_text(
            '[other]\n'
            'alice = "abcdef0123456789abcdef0123456789"\n'
            '\n'
            '[access.users]\n'
            'bob = "fedcba9876543210fedcba9876543210"\n'
        )
        with self._patch():
            users = _load_users()
        self.assertEqual(len(users), 1)
        self.assertIn("bob", users)
        self.assertNotIn("alice", users)

    def test_stops_at_next_section(self):
        from chimera.modules.mtproto_stats import _load_users
        self._cfg.write_text(
            '[access.users]\n'
            'alice = "abcdef0123456789abcdef0123456789"\n'
            '[another.section]\n'
            'bob = "fedcba9876543210fedcba9876543210"\n'
        )
        with self._patch():
            users = _load_users()
        self.assertEqual(len(users), 1)
        self.assertIn("alice", users)

    def test_invalid_username_skipped(self):
        """Имя должно начинаться с буквы [a-zA-Z]."""
        from chimera.modules.mtproto_stats import _load_users
        self._cfg.write_text(
            '[access.users]\n'
            'alice = "abcdef0123456789abcdef0123456789"\n'
            '123bad = "fedcba9876543210fedcba9876543210"\n'
        )
        with self._patch():
            users = _load_users()
        self.assertEqual(len(users), 1)
        self.assertIn("alice", users)


class TestLoadSaveStats(unittest.TestCase):
    """_load_stats / _save_stats."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._stats = self._tmpdir / "stats.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch(self):
        return patch("chimera.modules.mtproto_stats.STATS_FILE",
                     self._stats)

    def test_load_returns_default_when_no_file(self):
        from chimera.modules.mtproto_stats import _load_stats
        with self._patch():
            stats = _load_stats()
        self.assertIn("total", stats)
        self.assertIn("daily", stats)
        self.assertIn("users", stats)
        self.assertFalse(stats["ipt_ok"])

    def test_load_returns_default_when_corrupt(self):
        from chimera.modules.mtproto_stats import _load_stats
        self._stats.write_text("{invalid")
        with self._patch():
            stats = _load_stats()
        self.assertIn("total", stats)

    def test_save_then_load(self):
        from chimera.modules.mtproto_stats import _load_stats, _save_stats
        data = {
            "total": {"rx": 1000, "tx": 2000, "updated": "x", "since": "y"},
            "daily": {"2026-07-09": {"rx": 1000, "tx": 2000}},
            "users": {"alice": {"sessions": 5, "rx": 100, "tx": 200, "last_seen": "z"}},
            "ipt_ok": True,
        }
        with self._patch():
            _save_stats(data)
            loaded = _load_stats()
        self.assertEqual(loaded["total"]["rx"], 1000)
        self.assertTrue(loaded["ipt_ok"])
        self.assertIn("alice", loaded["users"])


class TestParseJournal(unittest.TestCase):
    """_parse_journal — парсинг journalctl (mocked _run)."""

    def setUp(self):
        _setup_core_in_sysmodules()

    def _mock_run(self, stdout: str):
        m = MagicMock()
        m.stdout = stdout
        m.returncode = 0
        m.stderr = ""
        return m

    def test_empty_journal(self):
        from chimera.modules import mtproto_stats
        with patch.object(mtproto_stats, "_run",
                          return_value=self._mock_run("")):
            result = mtproto_stats._parse_journal()
        self.assertEqual(result, {})

    def test_parses_user_sessions(self):
        from chimera.modules import mtproto_stats
        lines = "\n".join([
            "2026-07-10T12:00:00 INFO user=alice connect from 1.2.3.4",
            "2026-07-10T12:00:05 INFO user=bob connect from 5.6.7.8",
            "2026-07-10T12:00:10 INFO user=alice auth.ok",
        ])
        with patch.object(mtproto_stats, "_run",
                          return_value=self._mock_run(lines)):
            result = mtproto_stats._parse_journal()
        self.assertIn("alice", result)
        self.assertIn("bob", result)
        # alice — 2 сессии (connect + auth.ok)
        self.assertEqual(result["alice"]["sessions"], 2)
        self.assertEqual(result["bob"]["sessions"], 1)

    def test_filters_system_users(self):
        """root/telemt/system/service — игнорируются."""
        from chimera.modules import mtproto_stats
        lines = "\n".join([
            "2026-07-10T12:00:00 INFO user=root connect",
            "2026-07-10T12:00:01 INFO user=telemt service start",
            "2026-07-10T12:00:02 INFO user=alice connect",
        ])
        with patch.object(mtproto_stats, "_run",
                          return_value=self._mock_run(lines)):
            result = mtproto_stats._parse_journal()
        self.assertNotIn("root", result)
        self.assertNotIn("telemt", result)
        self.assertIn("alice", result)

    def test_last_seen_extracted_from_timestamp(self):
        from chimera.modules import mtproto_stats
        lines = "2026-07-10T12:34:56 INFO user=alice connect"
        with patch.object(mtproto_stats, "_run",
                          return_value=self._mock_run(lines)):
            result = mtproto_stats._parse_journal()
        self.assertEqual(result["alice"]["last_seen"], "2026-07-10 12:34:56")

    def test_since_filter_passed_to_run(self):
        from chimera.modules import mtproto_stats
        with patch.object(mtproto_stats, "_run",
                          return_value=self._mock_run("")) as mock_run:
            mtproto_stats._parse_journal(since="2026-07-09")
        # проверяем что --since присутствует в аргументах
        cmd = mock_run.call_args.args[0]
        self.assertIn("--since", cmd)
        self.assertIn("2026-07-09", cmd)


class TestCollect(unittest.TestCase):
    """_collect — обновление статистики (mocked iptables + journalctl)."""

    def setUp(self):
        _setup_core_in_sysmodules()
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cfg = self._tmpdir / "telemt.toml"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_cfg(self):
        return patch("chimera.modules.mtproto_stats.CONFIG_FILE",
                     self._cfg)

    def test_writes_daily_and_total(self):
        from chimera.modules import mtproto_stats
        d = {
            "total": {"rx": 0, "tx": 0, "updated": "", "since": ""},
            "daily": {},
            "users": {},
            "ipt_ok": False,
        }
        # iptables возвращает 1000 rx, 2000 tx
        with self._patch_cfg(), \
             patch.object(mtproto_stats, "_read_chain_bytes",
                          side_effect=[1000, 2000]), \
             patch.object(mtproto_stats, "_parse_journal", return_value={}), \
             patch.object(mtproto_stats, "_load_users", return_value={}):
            result = mtproto_stats._collect(d)
        self.assertTrue(result["ipt_ok"])
        # за сегодня записано
        today = mtproto_stats._today()
        self.assertIn(today, result["daily"])
        self.assertEqual(result["daily"][today]["rx"], 1000)
        self.assertEqual(result["daily"][today]["tx"], 2000)
        # total = сумма всех дней
        self.assertEqual(result["total"]["rx"], 1000)
        self.assertEqual(result["total"]["tx"], 2000)

    def test_ipt_failure_sets_ipt_ok_false(self):
        from chimera.modules import mtproto_stats
        d = {"total": {"rx": 0, "tx": 0, "updated": "", "since": ""},
             "daily": {}, "users": {}, "ipt_ok": True}
        with self._patch_cfg(), \
             patch.object(mtproto_stats, "_read_chain_bytes",
                          side_effect=Exception("iptables err")), \
             patch.object(mtproto_stats, "_parse_journal", return_value={}), \
             patch.object(mtproto_stats, "_load_users", return_value={}):
            result = mtproto_stats._collect(d)
        self.assertFalse(result["ipt_ok"])

    def test_distributes_bytes_proportional_to_sessions(self):
        """3 сессии у alice, 1 у bob → 75%/25% распределение."""
        from chimera.modules import mtproto_stats
        d = {
            "total": {"rx": 0, "tx": 0, "updated": "", "since": ""},
            "daily": {},
            "users": {},
            "ipt_ok": False,
        }
        sessions = {
            "alice": {"sessions": 3, "last_seen": "2026-07-10 12:00:00"},
            "bob": {"sessions": 1, "last_seen": "2026-07-10 12:01:00"},
        }
        with self._patch_cfg(), \
             patch.object(mtproto_stats, "_read_chain_bytes",
                          side_effect=[1000, 2000]), \
             patch.object(mtproto_stats, "_parse_journal", return_value=sessions), \
             patch.object(mtproto_stats, "_load_users", return_value={"alice": "x", "bob": "y"}):
            result = mtproto_stats._collect(d)
        # alice 3/4 от 1000 = 750, bob 1/4 = 250
        self.assertEqual(result["users"]["alice"]["rx"], 750)
        self.assertEqual(result["users"]["bob"]["rx"], 250)

    def test_distributes_evenly_when_no_sessions(self):
        """0 сессий у всех → равномерно по active users."""
        from chimera.modules import mtproto_stats
        d = {
            "total": {"rx": 0, "tx": 0, "updated": "", "since": ""},
            "daily": {},
            "users": {
                "alice": {"sessions": 0, "rx": 0, "tx": 0, "last_seen": "x"},
                "bob": {"sessions": 0, "rx": 0, "tx": 0, "last_seen": "y"},
            },
            "ipt_ok": False,
        }
        with self._patch_cfg(), \
             patch.object(mtproto_stats, "_read_chain_bytes",
                          side_effect=[1000, 2000]), \
             patch.object(mtproto_stats, "_parse_journal", return_value={}), \
             patch.object(mtproto_stats, "_load_users", return_value={"alice": "x", "bob": "y"}):
            result = mtproto_stats._collect(d)
        # 1000 / 2 = 500 каждый, но последний получает остаток
        # alice = 500, bob = 1000 - 500*1 = 500
        self.assertEqual(result["users"]["alice"]["rx"], 500)
        self.assertEqual(result["users"]["bob"]["rx"], 500)

    def test_preserves_accumulated_total_across_days(self):
        """Total = сумма всех дней в daily, не только сегодня."""
        from chimera.modules import mtproto_stats
        d = {
            "total": {"rx": 0, "tx": 0, "updated": "", "since": ""},
            "daily": {
                "2026-07-08": {"rx": 5000, "tx": 6000},
                "2026-07-09": {"rx": 3000, "tx": 4000},
            },
            "users": {},
            "ipt_ok": False,
        }
        with self._patch_cfg(), \
             patch.object(mtproto_stats, "_read_chain_bytes",
                          side_effect=[1000, 2000]), \
             patch.object(mtproto_stats, "_parse_journal", return_value={}), \
             patch.object(mtproto_stats, "_load_users", return_value={}):
            result = mtproto_stats._collect(d)
        # total = 5000 + 3000 + 1000 (today) = 9000
        self.assertEqual(result["total"]["rx"], 9000)
        self.assertEqual(result["total"]["tx"], 12000)


# =============================================================================
#  setup_iptables_accounting: постфактум-верификация + парсинг -n + идемпотентность
# =============================================================================
class TestSetupIptablesAccountingVerification(unittest.TestCase):
    """Проверка что setup_iptables_accounting() реально верифицирует факт
    создания цепочек и jump-правил, а не возвращает всегда True.

    До фикса функция возвращала None (implicit) и не проверяла результат —
    все iptables-команды идут с check=False и не бросают исключений при
    провале. Поэтому mtproto._setup_accounting() почти никогда не падал
    через try/except, и установщик рапортовал «Учёт трафика активирован»
    даже когда цепочки физически не создались (контейнер без CAP_NET_ADMIN,
    ядро без netfilter, iptables-nft vs iptables-legacy конфликт, и т.п.).

    Также покрыты:
      • парсинг числового протокола "6" (IPPROTO_TCP) в выводе iptables -n
        (старый код ждал буквально "tcp" и всегда возвращал False на реальном
        выводе с сервера, хотя jump-правило реально стояло и работало).
      • идемпотентность при повторных вызовах (пункт [3] может нажиматься
        многократно) — через _ipt_remove_all_jumps() с циклом до исчерпания,
        гарантирующим ровно 0 jump-правил перед созданием ровно 1 нового.
    """

    def setUp(self):
        _setup_core_in_sysmodules()
        # Патчим CRON_FILE чтобы не трогать реальный /etc/cron.d/
        self._tmpdir = Path(tempfile.mkdtemp())
        self._cron = self._tmpdir / "telemt-stats"

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _patch_cron(self):
        return patch("chimera.modules.mtproto_stats.CRON_FILE", self._cron)

    def _make_run_mock(self, *, chains_exist: set = None,
                       initial_jumps: dict = None,
                       proto_token: str = "tcp"):
        """Создаёт STATEFUL mock для _run — отслеживает «реально
        установленные» цепочки и jump-правила в mock-state.

        Args:
          chains_exist: set chain-имён, которые «существуют» изначально.
            Команда `-N chain` добавляет chain в этот set.
          initial_jumps: dict {(parent, chain, port, direction): count} —
            сколько jump-правил изначально установлено (может быть >1 для
            эмуляции копившегося дублирования). Команда `-D` декрементирует,
            `-I` инкрементирует (но только если count=0 — `-I` добавляет
            ровно одно). Словарь мутируется в реальном времени, что
            позволяет _ipt_jump_exists() и _ipt_remove_all_jumps()
            корректно взаимодействовать.
          proto_token: "tcp" (текстовый) или "6" (числовой, как при -n) —
            какой токен протокола возвращать в stdout iptables -L -v -n.

        Возвращаемый fake_run умеет:
          • iptables -L CHAIN -n → проверка существования цепочки
          • iptables -L INPUT/OUTPUT -v -n → возвращаем stdout со всеми
            «установленными» jump-правилами (с proto_token в колонке prot)
          • iptables -D parent ... -j chain → декремент jump-count
          • iptables -I parent 1 ... -j chain → инкремент jump-count (до 1)
          • iptables -N chain → добавить chain в chains_exist
          • iptables -F/-A/-Z, netfilter-persistent, iptables-save → no-op success
        """
        from unittest.mock import MagicMock
        from chimera.modules.mtproto_stats import CHAIN_IN, CHAIN_OUT

        chains_exist = set(chains_exist or [])
        # jumps: {(parent, chain, port, direction): count}
        jumps = dict(initial_jumps or {})

        # Карта: parent → (target_chain, port_label)
        # INPUT → CHAIN_IN, dport (входящий — destination port)
        # OUTPUT → CHAIN_OUT, sport (исходящий — source port)
        parent_map = {
            "INPUT":  (CHAIN_IN,  "dpt"),
            "OUTPUT": (CHAIN_OUT, "spt"),
        }
        direction_to_label = {"dport": "dpt", "sport": "spt"}

        def fake_run(cmd, capture=False, check=False):
            cmd = list(cmd)

            # ── iptables -L ... ──────────────────────────────────────────────
            if len(cmd) >= 3 and cmd[0] == "iptables" and cmd[1] == "-L":
                chain_or_parent = cmd[2]
                # iptables -L CHAIN -n  (проверка существования цепочки)
                if "-n" in cmd and "-v" not in cmd:
                    exists = chain_or_parent in chains_exist
                    return MagicMock(returncode=0 if exists else 1,
                                     stdout="chain" if exists else "",
                                     stderr="")
                # iptables -L INPUT/OUTPUT -v -n  (для jump-проверки)
                if "-v" in cmd and "-n" in cmd:
                    # Собираем stdout со всеми установленными jump-правилами
                    # для этого parent.
                    lines = [f"Chain {chain_or_parent} (policy ACCEPT)"]
                    for (parent, chain, port, direction), count in jumps.items():
                        if parent != chain_or_parent or count <= 0:
                            continue
                        target, _ = parent_map.get(
                            parent, (chain, "dpt"))
                        port_label = direction_to_label.get(direction, "dpt")
                        # Генерируем `count` строк — по одной на каждое
                        # «установленное» jump-правило (эмуляция дублей).
                        for _i in range(count):
                            line = (f"  0  0  {target}  "
                                    f"{proto_token}  --  *  *  0.0.0.0/0  0.0.0.0/0  "
                                    f"tcp {port_label}:{port}")
                            lines.append(line)
                    return MagicMock(returncode=0,
                                     stdout="\n".join(lines) + "\n",
                                     stderr="")

            # ── iptables -N chain  (создание цепочки) ────────────────────────
            if len(cmd) >= 3 and cmd[0] == "iptables" and cmd[1] == "-N":
                chains_exist.add(cmd[2])
                return MagicMock(returncode=0, stdout="", stderr="")

            # ── iptables -D parent -p tcp --dport/--sport PORT -j chain ──────
            # Декремент jump-count на 1. returncode 1 если count=0 (ничего
            # нечего удалять).
            if len(cmd) >= 3 and cmd[0] == "iptables" and cmd[1] == "-D":
                parent = cmd[2]
                # Парсим -p tcp --dport PORT -j CHAIN из остальных аргументов
                port = None
                chain = None
                direction = None
                i = 3
                while i < len(cmd):
                    if cmd[i] == "--dport" and i + 1 < len(cmd):
                        port = int(cmd[i + 1]); direction = "dport"; i += 2; continue
                    if cmd[i] == "--sport" and i + 1 < len(cmd):
                        port = int(cmd[i + 1]); direction = "sport"; i += 2; continue
                    if cmd[i] == "-j" and i + 1 < len(cmd):
                        chain = cmd[i + 1]; i += 2; continue
                    i += 1
                if port is not None and chain is not None and direction is not None:
                    key = (parent, chain, port, direction)
                    if jumps.get(key, 0) > 0:
                        jumps[key] = jumps.get(key, 0) - 1
                        return MagicMock(returncode=0, stdout="", stderr="")
                    return MagicMock(returncode=1, stdout="", stderr="not found")

            # ── iptables -I parent 1 -p tcp --dport/--sport PORT -j chain ────
            # Инкремент jump-count (добавляет ровно одно правило).
            if len(cmd) >= 3 and cmd[0] == "iptables" and cmd[1] == "-I":
                parent = cmd[2]
                port = None
                chain = None
                direction = None
                i = 3
                while i < len(cmd):
                    if cmd[i] == "--dport" and i + 1 < len(cmd):
                        port = int(cmd[i + 1]); direction = "dport"; i += 2; continue
                    if cmd[i] == "--sport" and i + 1 < len(cmd):
                        port = int(cmd[i + 1]); direction = "sport"; i += 2; continue
                    if cmd[i] == "-j" and i + 1 < len(cmd):
                        chain = cmd[i + 1]; i += 2; continue
                    i += 1
                if port is not None and chain is not None and direction is not None:
                    key = (parent, chain, port, direction)
                    jumps[key] = jumps.get(key, 0) + 1
                    return MagicMock(returncode=0, stdout="", stderr="")

            # ── Все остальные команды (-F/-A/-Z, netfilter-persistent,
            #    iptables-save) — no-op success.
            return MagicMock(returncode=0, stdout="", stderr="")

        return fake_run, chains_exist, jumps

    # ── Тест 1: chains+jumps "успешно" создались, но _ipt_chain_exists
    #    возвращает False → функция должна вернуть False ─────────────────────
    def test_returns_false_when_chains_did_not_actually_appear(self):
        """Сценарий: iptables -N/-I отработали с returncode 0, но цепочки
        реально не появились (например, контейнер без CAP_NET_ADMIN
        молча игнорирует команды — мокируем через пустой chains_exist,
        -N добавляет в set, но мы проверяем БЕЗ -N в начальном состоянии).

        Конкретнее: мокируем так, что -N НЕ добавляет цепочку (симуляция
        того, что iptables молча проигнорировал команду). Тогда
        _ipt_chain_exists() после -N всё равно вернёт False, и вся
        функция должна вернуть False.
        """
        from chimera.modules import mtproto_stats
        # Используем специальный mock где -N не работает (цепочки не
        # добавляются в chains_exist).
        from unittest.mock import MagicMock

        def fake_run_no_create(cmd, capture=False, check=False):
            cmd = list(cmd)
            # iptables -L CHAIN -n → всегда returncode 1 (цепочки нет)
            if len(cmd) >= 3 and cmd[0] == "iptables" and cmd[1] == "-L":
                if "-n" in cmd and "-v" not in cmd:
                    return MagicMock(returncode=1, stdout="", stderr="")
                if "-v" in cmd and "-n" in cmd:
                    return MagicMock(returncode=0, stdout=f"Chain {cmd[2]}\n",
                                     stderr="")
            # -N и все остальные → returncode 0, но состояние НЕ меняем
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch.object(mtproto_stats, "_run", fake_run_no_create), \
             self._patch_cron(), \
             patch.object(mtproto_stats, "_persist_accounting_rules",
                          return_value=None):
            result = mtproto_stats.setup_iptables_accounting(8443)
        self.assertFalse(result,
                         "expected False when chains did not actually appear")

    # ── Тест 2: полный успех — chains+jumps подтверждаются → True ───────────
    def test_returns_true_when_all_chains_and_jumps_confirmed(self):
        """Сценарий: iptables-команды отработали И постфактум-верификация
        подтверждает существование цепочек и jump-правил → True.

        Использует stateful mock: -N добавляет цепочку, -I добавляет
        jump-правило, после чего _ipt_chain_exists/_ipt_jump_exists
        подтверждают их наличие.
        """
        from chimera.modules import mtproto_stats
        fake_run, _chains, _jumps = self._make_run_mock(
            chains_exist=set(),  # начально пусто — -N создаст
            initial_jumps={},     # начально пусто — -I создаст
            proto_token="tcp",   # текстовый "tcp"
        )
        with patch.object(mtproto_stats, "_run", fake_run), \
             self._patch_cron(), \
             patch.object(mtproto_stats, "_persist_accounting_rules",
                          return_value=None):
            result = mtproto_stats.setup_iptables_accounting(8443)
        self.assertTrue(result,
                        "expected True when all chains and jumps confirmed")

    # ── Тест 2b: полный успех с числовым "6" вместо "tcp" (как при -n) ──────
    def test_returns_true_with_numeric_proto_token_from_dash_n(self):
        """Тот же сценарий что тест 2, но с proto_token="6" — как реально
        выводит `iptables -L -n` (IPPROTO_TCP = 6). Старый код ждал
        буквально "tcp" и всегда возвращал False на этом выводе.
        """
        from chimera.modules import mtproto_stats
        fake_run, _chains, _jumps = self._make_run_mock(
            chains_exist=set(),
            initial_jumps={},
            proto_token="6",  # числовой IPPROTO_TCP
        )
        with patch.object(mtproto_stats, "_run", fake_run), \
             self._patch_cron(), \
             patch.object(mtproto_stats, "_persist_accounting_rules",
                          return_value=None):
            result = mtproto_stats.setup_iptables_accounting(8443)
        self.assertTrue(result,
                        "expected True with numeric proto token '6' from -n")

    # ── Тест 3: регрессия — РЕАЛЬНЫЙ вывод с сервера (telemt dpt:5000) ──────
    def test_recognizes_numeric_tcp_protocol_from_dash_n_output(self):
        """Регрессия: -n делает протокол числовым (6 вместо tcp) — реальный
        вывод с сервера fast-cheetah подтвердил, что jump-правило реально
        стоит и работает (счётчики 119 пакетов / 15936 байт), но старый
        код всегда возвращал False из-за строгого сравнения с "tcp".

        Тест берёт реальную строку вывода один в один из диагностики
        на сервере (не абстрактный пример), и убеждается что
        _ipt_jump_exists распознаёт jump-правило.
        """
        from chimera.modules import mtproto_stats
        from unittest.mock import MagicMock

        # Реальный вывод с сервера (один в один из диагностики)
        mock_output = (
            "Chain INPUT (policy DROP 0 packets, 0 bytes)\n"
            " pkts bytes target     prot opt in     out     source               destination\n"
            "  119 15936 TELEMT_STATS_IN  6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:5000\n"
        )

        def fake_run(cmd, capture=False, check=False):
            if len(cmd) >= 3 and cmd[0] == "iptables" and cmd[1] == "-L":
                if "-v" in cmd and "-n" in cmd and cmd[2] == "INPUT":
                    return MagicMock(returncode=0, stdout=mock_output, stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch.object(mtproto_stats, "_run", fake_run):
            result = mtproto_stats._ipt_jump_exists(
                "INPUT", mtproto_stats.CHAIN_IN, 5000, "dport")
        self.assertTrue(result,
                        "expected True for real server output with proto=6 "
                        "and dpt:5000 — regression check for the -n numeric "
                        "protocol bug")

    # ── Тест 4: _ipt_remove_all_jumps с 3 дублями → 3 -D вызова ─────────────
    def test_remove_all_jumps_with_three_duplicates_calls_D_three_times(self):
        """Сценарий: в INPUT скопилось 3 дубля jump-правила на CHAIN_IN
        (из-за ранней версии кода без -D, или ручного вмешательства).
        _ipt_remove_all_jumps должен вызвать -D ровно 3 раза (не 1, не
        бесконечно) и вернуть removed=3.
        """
        from chimera.modules import mtproto_stats

        fake_run, _chains, jumps = self._make_run_mock(
            chains_exist={mtproto_stats.CHAIN_IN, mtproto_stats.CHAIN_OUT},
            initial_jumps={
                ("INPUT", mtproto_stats.CHAIN_IN, 8443, "dport"): 3,
            },
            proto_token="tcp",
        )
        with patch.object(mtproto_stats, "_run", fake_run):
            removed = mtproto_stats._ipt_remove_all_jumps(
                "INPUT", mtproto_stats.CHAIN_IN, 8443, "dport")
        self.assertEqual(removed, 3,
                         f"expected removed=3 for 3 duplicates, got {removed}")
        # Все 3 дубля удалены
        self.assertEqual(jumps.get(("INPUT", mtproto_stats.CHAIN_IN, 8443, "dport"), 0), 0,
                         "expected 0 jump-rules remaining after _ipt_remove_all_jumps")

    # ── Тест 4b: _ipt_remove_all_jumps с 0 правил → 0 -D вызовов ────────────
    def test_remove_all_jumps_with_zero_rules_calls_D_zero_times(self):
        """Сценарий: jump-правил нет изначально. _ipt_remove_all_jumps
        должен сразу выйти с removed=0, не делая ни одного -D.
        """
        from chimera.modules import mtproto_stats

        fake_run, _chains, _jumps = self._make_run_mock(
            chains_exist={mtproto_stats.CHAIN_IN, mtproto_stats.CHAIN_OUT},
            initial_jumps={},  # ничего не установлено
            proto_token="tcp",
        )
        with patch.object(mtproto_stats, "_run", fake_run):
            removed = mtproto_stats._ipt_remove_all_jumps(
                "INPUT", mtproto_stats.CHAIN_IN, 8443, "dport")
        self.assertEqual(removed, 0,
                         f"expected removed=0 for no rules, got {removed}")

    # ── Тест 5: идемпотентность — два вызова → ровно одно jump-правило ──────
    def test_setup_called_twleve_leaves_exactly_one_jump_rule(self):
        """Интеграционный тест: setup_iptables_accounting() вызван ДВАЖДЫ
        подряд (эмулируя два нажатия [3] в меню статистики). После
        второго вызова в финальном состоянии (mock iptables -L -v -n)
        присутствует РОВНО ОДНО jump-правило на CHAIN_IN, не два.

        До фикса (одиночный -D перед -I) — если по какой-то причине
        правило встретилось дважды, одно из дублей осталось, а после
        -I добавилось ещё одно → копление с каждым нажатием [3].
        После фикса (_ipt_remove_all_jumps с циклом до исчерпания) —
        гарантированно 0 перед -I, ровно 1 после.
        """
        from chimera.modules import mtproto_stats

        # Используем SHARED state между двумя вызовами — мок и jumps-словарь
        # должны пережить первый вызов и передать состояние во второй.
        fake_run, _chains, jumps = self._make_run_mock(
            chains_exist=set(),
            initial_jumps={},
            proto_token="tcp",
        )
        with patch.object(mtproto_stats, "_run", fake_run), \
             self._patch_cron(), \
             patch.object(mtproto_stats, "_persist_accounting_rules",
                          return_value=None):
            # Первый вызов
            result1 = mtproto_stats.setup_iptables_accounting(8443)
            self.assertTrue(result1, "first call should succeed")
            # Проверяем: ровно 1 jump-правило на CHAIN_IN после первого вызова
            self.assertEqual(
                jumps.get(("INPUT", mtproto_stats.CHAIN_IN, 8443, "dport"), 0),
                1,
                "after first call: exactly 1 INPUT jump-rule expected"
            )
            # Второй вызов (эмуляция повторного нажатия [3])
            result2 = mtproto_stats.setup_iptables_accounting(8443)
            self.assertTrue(result2, "second call should also succeed")
            # Проверяем: ВСЁ ЕЩЁ ровно 1 jump-правило (не 2!)
            self.assertEqual(
                jumps.get(("INPUT", mtproto_stats.CHAIN_IN, 8443, "dport"), 0),
                1,
                "after second call: still exactly 1 INPUT jump-rule expected "
                "(no duplication from repeated [3] presses)"
            )
            # То же для OUTPUT
            self.assertEqual(
                jumps.get(("OUTPUT", mtproto_stats.CHAIN_OUT, 8443, "sport"), 0),
                1,
                "after second call: still exactly 1 OUTPUT jump-rule expected"
            )

    # ── Тест 5b: идемпотентность с предсуществующими дублями ────────────────
    def test_setup_cleans_up_preexisting_duplicates(self):
        """Сценарий: до вызова в INPUT уже скопилось 3 jump-правила (из-за
        ранней версии кода). setup_iptables_accounting должен все их
        удалить через _ipt_remove_all_jumps и оставить ровно 1 после.
        """
        from chimera.modules import mtproto_stats

        fake_run, _chains, jumps = self._make_run_mock(
            chains_exist={mtproto_stats.CHAIN_IN, mtproto_stats.CHAIN_OUT},
            initial_jumps={
                ("INPUT", mtproto_stats.CHAIN_IN, 8443, "dport"): 3,
                ("OUTPUT", mtproto_stats.CHAIN_OUT, 8443, "sport"): 2,
            },
            proto_token="tcp",
        )
        with patch.object(mtproto_stats, "_run", fake_run), \
             self._patch_cron(), \
             patch.object(mtproto_stats, "_persist_accounting_rules",
                          return_value=None):
            result = mtproto_stats.setup_iptables_accounting(8443)
        self.assertTrue(result, "should succeed despite pre-existing duplicates")
        # После вызова: ровно 1 (3 удалено, 1 добавлено)
        self.assertEqual(
            jumps.get(("INPUT", mtproto_stats.CHAIN_IN, 8443, "dport"), 0),
            1,
            "after setup with 3 preexisting duplicates: exactly 1 expected"
        )
        self.assertEqual(
            jumps.get(("OUTPUT", mtproto_stats.CHAIN_OUT, 8443, "sport"), 0),
            1,
            "after setup with 2 preexisting duplicates: exactly 1 expected"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

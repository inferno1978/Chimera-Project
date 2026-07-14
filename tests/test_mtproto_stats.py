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


if __name__ == "__main__":
    unittest.main(verbosity=2)
